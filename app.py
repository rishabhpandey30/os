from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    send_file,
    jsonify,
    session,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
import os
from config import Config
from models import db, User, File
from flask_mail import Mail, Message
from forms import RegisterForm, LoginForm
from utils import encrypt_file, decrypt_file
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
import random
import secrets
from datetime import datetime, timedelta, timezone

app = Flask(__name__)
app.config.from_object("config.Config")

migrate = Migrate(app, db)
mail = Mail(app)

UPLOAD_FOLDER = "uploads"
TEMP_FOLDER = "temp"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["TEMP_FOLDER"] = TEMP_FOLDER

for folder in [UPLOAD_FOLDER, TEMP_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "Sixteen byte key").encode()

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/send_otp/<token>", methods=["POST"])
def send_otp(token):
    file = File.query.filter_by(token=token).first()
    if not file:
        flash("Invalid or expired link!", "danger")
        return redirect(url_for("login"))

    email = request.form.get("email")
    if not email:
        flash("Please enter a valid email!", "danger")
        return redirect(url_for("access_file", token=token))

    otp = random.randint(100000, 999999)
    session["otp"] = otp
    session["email"] = email
    session["file_token"] = token

    # Send OTP via email
    msg = Message(
        "Your Secure File Access OTP", sender="your_email@gmail.com", recipients=[email]
    )
    msg.body = f"Your OTP for file access is {otp}. It is valid for 5 minutes."
    mail.send(msg)

    flash("An OTP has been sent to your email.", "info")
    return redirect(url_for("access_file", token=token))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        username = form.username.data
        password = generate_password_hash(form.password.data, method="pbkdf2:sha256")

        otp = random.randint(100000, 999999)
        session["otp"] = otp
        session["email"] = email
        session["username"] = username
        session["password"] = password

        msg = Message(
            "Your OTP for Secure File Management Signup",
            sender="your_email@gmail.com",
            recipients=[email],
        )
        msg.body = f"Your OTP is {otp}. It is valid for 5 minutes."
        mail.send(msg)

        flash("An OTP has been sent to your email. Please enter it below.", "info")
        return redirect(url_for("verify_otp"))  # ✅ FIXED HERE

    return render_template("register.html", form=form)


@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        entered_otp = request.form.get("otp")

        if "otp" in session and int(entered_otp) == session["otp"]:
            new_user = User(
                username=session["username"],
                email=session["email"],
                password=session["password"],
            )
            db.session.add(new_user)
            db.session.commit()

            session.pop("otp", None)
            session.pop("email", None)
            session.pop("username", None)
            session.pop("password", None)

            flash("Account created successfully!", "success")
            return redirect(url_for("login"))
        else:
            flash("Invalid OTP. Please try again.", "danger")

    return render_template("verify_otp.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Invalid email or password", "danger")
    return render_template("login.html", form=form)


@app.route("/dashboard")
@login_required
def dashboard():
    files = File.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", files=files)


@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    if "file" not in request.files:
        flash("No file uploaded!", "danger")
        return redirect(url_for("dashboard"))

    file = request.files["file"]
    if file.filename == "":
        flash("No selected file!", "danger")
        return redirect(url_for("dashboard"))

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(file_path)

    encrypted_path = encrypt_file(file_path, ENCRYPTION_KEY)

    # ✅ Generate secure token for file
    token = secrets.token_hex(32)

    new_file = File(
        filename=filename,
        encrypted_filename=encrypted_path,
        user_id=current_user.id,
        token=token,  # ✅ Added token
        token_expiration=datetime.now(timezone.utc).replace(tzinfo=None)
        + timedelta(minutes=15),  # ✅ Expiration
    )
    db.session.add(new_file)
    db.session.commit()

    return redirect(url_for("share_file", file_id=new_file.id))


@app.route("/share/<int:file_id>")
@login_required
def share_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        return "Unauthorized access", 403

    secure_link = url_for("access_file", token=file.token, _external=True)
    flash(
        f"Secure Shareable Link: <a href='{secure_link}' target='_blank'>{secure_link}</a>",
        "info",
    )
    return redirect(url_for("dashboard"))


@app.route("/access_file/<token>", methods=["GET", "POST"])
def access_file(token):
    file = File.query.filter_by(token=token).first()

    if not file:
        flash("Invalid or expired link!", "danger")
        return redirect(url_for("login"))

    # Check if token has expired
    if datetime.now(timezone.utc).replace(tzinfo=None) > file.token_expiration:
        flash("This link has expired. Please request a new one.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":  # User submits OTP
        email = request.form.get("email")
        otp = request.form.get("otp")

        if (
            "otp" in session
            and "email" in session
            and "file_token" in session
            and session["file_token"]==token
            and int(otp) == session["otp"]
            and session["email"] == email
        ):
            return redirect(url_for("download_file", file_id=file.id))

        flash("Invalid email or OTP!", "danger")

    return render_template("verify_otp.html", token=token)


@app.route("/download/<int:file_id>", methods=["GET"])
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    decrypted_path = os.path.join(app.config["TEMP_FOLDER"], file.filename)

    try:
        if not os.path.exists(decrypted_path):
            decrypted_path = decrypt_file(file.encrypted_filename, ENCRYPTION_KEY)

        return send_file(decrypted_path, as_attachment=True)

    except ValueError:
        flash("Decryption failed. Invalid key or file corrupted.", "danger")
        return redirect(url_for("dashboard"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
