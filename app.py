import os, uuid
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

load_dotenv()
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "development-only-change-this")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///pharmacy_connect.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

UPLOAD_FOLDER = os.path.join(app.root_path, "uploads", "prescriptions")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
csrf = CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
ph = PasswordHasher()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Pharmacy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    address = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(30))
    whatsapp = db.Column(db.String(50))
    license_number = db.Column(db.String(100))
    license_document = db.Column(db.String(255))
    verification_status = db.Column(db.String(30), default="pending", nullable=False)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class DrugInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)
    warnings = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Prescription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    pharmacy_id = db.Column(db.Integer, db.ForeignKey("pharmacy.id"), nullable=True)
    stored_filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(100))
    resource_id = db.Column(db.String(100))
    ip_address = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(self)"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:;"
    return response

def audit(action, resource_type=None, resource_id=None):
    db.session.add(AuditLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action, resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        ip_address=request.remote_addr
    ))
    db.session.commit()

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if current_user.role != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

@app.route("/")
def index():
    pharmacies = Pharmacy.query.filter_by(verification_status="verified").limit(10).all()
    return render_template("index.html", pharmacies=pharmacies)

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not email or not password:
            flash("All fields are required.", "error"); return redirect(url_for("register"))
        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error"); return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error"); return redirect(url_for("register"))
        user = User(name=name, email=email, password_hash=ph.hash(password), role="user")
        db.session.add(user); db.session.commit()
        audit("USER_REGISTERED", "user", user.id)
        flash("Account created successfully.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Invalid email or password.", "error"); return redirect(url_for("login"))
        try:
            ph.verify(user.password_hash, password)
        except VerifyMismatchError:
            flash("Invalid email or password.", "error"); return redirect(url_for("login"))
        login_user(user, remember=False)
        audit("USER_LOGIN", "user", user.id)
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    audit("USER_LOGOUT", "user", current_user.id)
    logout_user()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    prescriptions = Prescription.query.filter_by(user_id=current_user.id).order_by(Prescription.uploaded_at.desc()).all()
    return render_template("dashboard.html", prescriptions=prescriptions)

@app.route("/pharmacies")
def pharmacies():
    search = request.args.get("search", "").strip()
    query = Pharmacy.query.filter_by(verification_status="verified")
    if search:
        query = query.filter(Pharmacy.name.ilike(f"%{search}%"))
    return render_template("pharmacies.html", pharmacies=query.order_by(Pharmacy.name).all(), search=search)

@app.route("/pharmacy/<int:pharmacy_id>")
def pharmacy(pharmacy_id):
    obj = Pharmacy.query.filter_by(id=pharmacy_id, verification_status="verified").first_or_404()
    return render_template("pharmacy.html", pharmacy=obj)

@app.route("/drugs")
def drugs():
    search = request.args.get("search", "").strip()
    query = DrugInfo.query
    if search:
        query = query.filter(DrugInfo.name.ilike(f"%{search}%"))
    return render_template("drugs.html", drugs=query.order_by(DrugInfo.name).all(), search=search)

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "pdf"}
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/prescription/upload", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def upload_prescription():
    file = request.files.get("prescription")
    if not file or not file.filename:
        flash("Please select a file.", "error"); return redirect(url_for("dashboard"))
    if not allowed_file(file.filename):
        flash("Only PDF, JPG, JPEG and PNG files are allowed.", "error"); return redirect(url_for("dashboard"))
    ext = file.filename.rsplit(".", 1)[1].lower()
    stored = f"{uuid.uuid4()}.{ext}"
    file.save(os.path.join(UPLOAD_FOLDER, stored))
    p = Prescription(user_id=current_user.id, stored_filename=stored, original_filename=file.filename)
    db.session.add(p); db.session.commit()
    audit("PRESCRIPTION_UPLOADED", "prescription", p.id)
    flash("Prescription uploaded securely.", "success")
    return redirect(url_for("dashboard"))

@app.route("/prescription/<int:prescription_id>")
@login_required
def view_prescription(prescription_id):
    p = db.session.get(Prescription, prescription_id)
    if not p: abort(404)
    if p.user_id != current_user.id and current_user.role != "admin": abort(403)
    audit("PRESCRIPTION_ACCESSED", "prescription", p.id)
    return send_from_directory(UPLOAD_FOLDER, p.stored_filename)

@app.route("/admin")
@admin_required
def admin():
    pharmacies = Pharmacy.query.order_by(Pharmacy.created_at.desc()).all()
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(100).all()
    return render_template("admin.html", pharmacies=pharmacies, logs=logs)

@app.route("/admin/pharmacy/<int:pharmacy_id>/verify", methods=["POST"])
@admin_required
def verify_pharmacy(pharmacy_id):
    p = db.session.get(Pharmacy, pharmacy_id)
    if not p: abort(404)
    p.verification_status = "verified"
    db.session.commit()
    audit("PHARMACY_VERIFIED", "pharmacy", pharmacy_id)
    flash("Pharmacy verified.", "success")
    return redirect(url_for("admin"))

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
