import os, sqlite3, hashlib, secrets, time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, abort
from flask_wtf import FlaskForm, CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from wtforms import StringField, PasswordField, TextAreaField, FileField, SelectField
from wtforms.validators import DataRequired, Length, Email, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "instance" / "portal.db"
UPLOAD_DIR = BASE_DIR / "uploads"
LOG_PATH = BASE_DIR / "logs" / "audit.log"
ALLOWED_EXTENSIONS = {"pdf", "docx", "pptx", "mp4", "txt"}
MAX_UPLOAD_SIZE = 10 * 1024 * 1024

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    WTF_CSRF_TIME_LIMIT=3600,
    MAX_CONTENT_LENGTH=MAX_UPLOAD_SIZE,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # set True when served over HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=128)])

class UploadForm(FlaskForm):
    title = StringField("Assignment title", validators=[DataRequired(), Length(max=100)])
    file = FileField("Assignment file", validators=[DataRequired()])

class MessageForm(FlaskForm):
    recipient = SelectField("Recipient", validators=[DataRequired()])
    body = TextAreaField("Message", validators=[DataRequired(), Length(min=1, max=1000)])

class ProfileForm(FlaskForm):
    name = StringField("Full name", validators=[DataRequired(), Length(max=80)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    phone = StringField("Phone", validators=[Optional(), Length(max=20)])
    current_password = PasswordField("Current password", validators=[DataRequired(), Length(min=8, max=128)])


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    UPLOAD_DIR.mkdir(exist_ok=True)
    LOG_PATH.parent.mkdir(exist_ok=True)
    with db() as conn:
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT CHECK(role IN ('student','lecturer')) NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(student_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            recipient_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            read_at TEXT,
            FOREIGN KEY(sender_id) REFERENCES users(id),
            FOREIGN KEY(recipient_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS failed_logins (
            username TEXT NOT NULL,
            ip TEXT NOT NULL,
            attempted_at INTEGER NOT NULL
        );
        ''')
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            demo_users = [
                ("student1", "Student@12345", "student", "Demo Student", "student1@university.edu", "0123456789"),
                ("lecturer1", "Lecturer@12345", "lecturer", "Demo Lecturer", "lecturer1@university.edu", "0198765432"),
            ]
            for username, pw, role, name, email, phone in demo_users:
                conn.execute("INSERT INTO users(username,password_hash,role,name,email,phone) VALUES (?,?,?,?,?,?)",
                             (username, generate_password_hash(pw), role, name, email, phone))
        conn.commit()


def audit(action, detail=""):
    user = session.get("username", "anonymous")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    line = f"{datetime.utcnow().isoformat()}Z | user={user} | ip={ip} | action={action} | {detail}\n"
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line)


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def role_required(*roles):
    def dec(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user or user["role"] not in roles:
                audit("unauthorized_access", f"route={request.path}")
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return dec


def extension_allowed(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def basic_malware_check(file_storage):
    # Educational safeguard only. In production, call ClamAV/YARA and quarantine suspicious uploads.
    head = file_storage.stream.read(4096)
    file_storage.stream.seek(0)
    blocked = [b"<script", b"<?php", b"MZ", b"powershell", b"cmd.exe"]
    return not any(sig.lower() in head.lower() for sig in blocked)


def too_many_failed(username, ip):
    cutoff = int(time.time()) - 15 * 60
    with db() as conn:
        conn.execute("DELETE FROM failed_logins WHERE attempted_at < ?", (cutoff,))
        count = conn.execute("SELECT COUNT(*) FROM failed_logins WHERE username=? AND ip=? AND attempted_at>=?",
                             (username, ip, cutoff)).fetchone()[0]
        return count >= 5

@app.before_request
def refresh_session_timeout():
    session.permanent = True

@app.route("/")
def index():
    return redirect(url_for("dashboard") if session.get("user_id") else url_for("login"))

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip().lower()
        ip = request.remote_addr or "unknown"
        if too_many_failed(username, ip):
            audit("login_blocked", f"username={username}")
            flash("Too many failed attempts. Try again later.", "danger")
            return render_template("login.html", form=form)
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if user and check_password_hash(user["password_hash"], form.password.data):
                session.clear(); session["user_id"] = user["id"]; session["username"] = user["username"]; session["role"] = user["role"]
                audit("login_success", f"role={user['role']}")
                return redirect(url_for("dashboard"))
            conn.execute("INSERT INTO failed_logins VALUES (?,?,?)", (username, ip, int(time.time())))
            conn.commit()
        audit("login_failed", f"username={username}")
        flash("Invalid login details.", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    audit("logout")
    session.clear()
    flash("Logged out safely.", "success")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    return render_template("dashboard.html", user=user)

@app.route("/assignments/upload", methods=["GET", "POST"])
@login_required
@role_required("student")
def upload_assignment():
    form = UploadForm()
    if form.validate_on_submit():
        f = form.file.data
        if not f or not extension_allowed(f.filename):
            flash("Invalid file type. Allowed: PDF, DOCX, PPTX, MP4, TXT.", "danger")
            return render_template("upload.html", form=form)
        if not basic_malware_check(f):
            audit("upload_rejected", f"filename={f.filename}")
            flash("Upload rejected because the file looked unsafe.", "danger")
            return render_template("upload.html", form=form)
        safe = secure_filename(f.filename)
        stored = f"{session['user_id']}_{int(time.time())}_{secrets.token_hex(8)}_{safe}"
        path = UPLOAD_DIR / stored
        f.save(path)
        digest = file_sha256(path)
        with db() as conn:
            conn.execute("INSERT INTO assignments(student_id,title,original_name,stored_name,sha256,uploaded_at) VALUES (?,?,?,?,?,?)",
                         (session["user_id"], form.title.data.strip(), safe, stored, digest, datetime.utcnow().isoformat()+"Z"))
            conn.commit()
        audit("assignment_uploaded", f"file={safe} sha256={digest}")
        flash("Assignment uploaded successfully.", "success")
        return redirect(url_for("my_assignments"))
    return render_template("upload.html", form=form)

@app.route("/assignments")
@login_required
def my_assignments():
    user = current_user()
    with db() as conn:
        if user["role"] == "lecturer":
            rows = conn.execute("SELECT a.*, u.name student_name FROM assignments a JOIN users u ON a.student_id=u.id ORDER BY a.uploaded_at DESC").fetchall()
        else:
            rows = conn.execute("SELECT a.*, u.name student_name FROM assignments a JOIN users u ON a.student_id=u.id WHERE student_id=? ORDER BY a.uploaded_at DESC", (user["id"],)).fetchall()
    return render_template("assignments.html", rows=rows, user=user)

@app.route("/assignments/<int:assignment_id>/download")
@login_required
def download_assignment(assignment_id):
    user = current_user()
    with db() as conn:
        row = conn.execute("SELECT * FROM assignments WHERE id=?", (assignment_id,)).fetchone()
    if not row:
        abort(404)
    if user["role"] != "lecturer" and row["student_id"] != user["id"]:
        audit("download_denied", f"assignment_id={assignment_id}")
        abort(403)
    path = UPLOAD_DIR / row["stored_name"]
    if not path.exists() or file_sha256(path) != row["sha256"]:
        audit("download_integrity_failed", f"assignment_id={assignment_id}")
        abort(409, "File integrity check failed")
    audit("assignment_downloaded", f"assignment_id={assignment_id}")
    return send_file(path, as_attachment=True, download_name=row["original_name"])

@app.route("/messages", methods=["GET", "POST"])
@login_required
def messages():
    user = current_user()
    form = MessageForm()
    with db() as conn:
        if user["role"] == "lecturer":
            recipients = conn.execute("SELECT id, name, username FROM users WHERE role='student' ORDER BY name").fetchall()
        else:
            recipients = conn.execute("SELECT id, name, username FROM users WHERE role='lecturer' ORDER BY name").fetchall()
    form.recipient.choices = [(str(r["id"]), f"{r['name']} ({r['username']})") for r in recipients]
    if form.validate_on_submit():
        rid = int(form.recipient.data)
        if rid not in [r["id"] for r in recipients]:
            abort(403)
        with db() as conn:
            conn.execute("INSERT INTO messages(sender_id,recipient_id,body,created_at) VALUES (?,?,?,?)",
                         (user["id"], rid, form.body.data.strip(), datetime.utcnow().isoformat()+"Z"))
            conn.commit()
        audit("message_sent", f"recipient_id={rid}")
        flash("Message sent.", "success")
        return redirect(url_for("messages"))
    with db() as conn:
        inbox = conn.execute("SELECT m.*, s.name sender_name FROM messages m JOIN users s ON m.sender_id=s.id WHERE m.recipient_id=? ORDER BY m.created_at DESC", (user["id"],)).fetchall()
        sent = conn.execute("SELECT m.*, r.name recipient_name FROM messages m JOIN users r ON m.recipient_id=r.id WHERE m.sender_id=? ORDER BY m.created_at DESC", (user["id"],)).fetchall()
    return render_template("messages.html", form=form, inbox=inbox, sent=sent, user=user)

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    form = ProfileForm(name=user["name"], email=user["email"], phone=user["phone"])
    if form.validate_on_submit():
        if not check_password_hash(user["password_hash"], form.current_password.data):
            audit("profile_update_failed", "bad_password")
            flash("Current password is required for profile changes.", "danger")
            return render_template("profile.html", form=form, user=user)
        with db() as conn:
            conn.execute("UPDATE users SET name=?, email=?, phone=? WHERE id=?",
                         (form.name.data.strip(), form.email.data.strip(), form.phone.data.strip(), user["id"]))
            conn.commit()
        audit("profile_updated")
        flash("Profile updated securely.", "success")
        return redirect(url_for("profile"))
    return render_template("profile.html", form=form, user=user)

@app.route("/audit")
@login_required
@role_required("lecturer")
def audit_view():
    lines = []
    if LOG_PATH.exists():
        lines = LOG_PATH.read_text(encoding="utf-8").splitlines()[-100:]
    return render_template("audit.html", lines=lines)

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Access denied."), 403

@app.errorhandler(404)
def missing(e):
    return render_template("error.html", code=404, message="Page not found."), 404

@app.errorhandler(409)
def conflict(e):
    return render_template("error.html", code=409, message=str(e)), 409

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
