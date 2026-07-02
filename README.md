# Secure Student Portal

A Flask web application based on the attached Level 1 DFD and security requirements lab. It includes:

- Student/Lecturer login
- Student assignment upload
- Lecturer assignment review/download
- Lecturer-student messaging
- Profile update
- Lecturer audit log view

## Implemented security mechanisms

- Password hashing using Werkzeug security helpers
- Login throttling and failed-login audit logging
- CSRF protection on all forms
- Role-based access control for student and lecturer functions
- Session protection with HTTPOnly and SameSite cookies, timeout, and logout invalidation
- Upload allowlist, secure filenames, max upload size, basic unsafe-content rejection
- SHA-256 file integrity check before download
- Authorization check before every download
- Profile re-authentication before updates
- Escaped template output to reduce XSS risk
- Audit logging for login, upload, download, messaging, and profile update actions

## How to run

```bash
python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

Demo accounts:

- Student: `student1` / `Student@12345`
- Lecturer: `lecturer1` / `Lecturer@12345`

## Production notes

Set `SESSION_COOKIE_SECURE=True` when running behind HTTPS. Replace the basic upload scan with ClamAV/YARA for production malware scanning.
