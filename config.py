import os

class Config:
    SECRET_KEY = 'your_secret_key'  # Change this for production
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'uploads/'
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'docx'}
    MAIL_SERVER = 'smtp.gmail.com'  # Change if using another service
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = 'nikhilchaubey269@gmail.com'
    MAIL_PASSWORD = "bdka llgg vnnx zalz"  # Use an App Password for Gmail
