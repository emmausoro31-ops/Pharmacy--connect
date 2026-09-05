# PharmacyConnect MVP

A connector-first pharmacy discovery MVP for Nigeria.

## Included
- User registration/login
- Argon2 password hashing
- CSRF protection
- Rate limiting
- Security headers
- Pharmacy verification workflow
- Informational drug listings
- Private prescription uploads with access checks
- Audit logging
- No payments, cart, checkout, delivery, or platform drug sales

## Run in VS Code

Windows:
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python app.py
```

Then open http://127.0.0.1:5000

## Important
This is a development MVP, not a production-ready medical platform. Before real deployment, add production-grade private object storage, malware/file scanning, stronger identity/OTP, PostgreSQL, HTTPS, backups, monitoring, and a Nigerian regulatory/legal review.
