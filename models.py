from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timezone ,timedelta

db = SQLAlchemy()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id", name="fk_file_user"), nullable=False
    )
    encrypted_filename = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Secure sharing fields
    token = db.Column(
        db.String(64), unique=True, nullable=True
    )  # Unique token for access
    # token_expiration = db.Column(db.DateTime, nullable=True)  # Expiration time
    token_expiration = db.Column(
        db.DateTime(timezone=True), nullable=True
    )  # ✅ Fixed (Aware)
