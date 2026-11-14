import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    WTF_CSRF_ENABLED = True

    # Database
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_USER = os.environ.get('DB_USER', 'root')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
    DB_NAME = os.environ.get('DB_NAME', 'honeytoken_db')

    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)

    # Alert System
    EMAIL_HOST = os.environ.get('EMAIL_HOST', 'smtp.gmail.com')
    EMAIL_PORT = int(os.environ.get('EMAIL_PORT', 587))
    EMAIL_USER = os.environ.get('EMAIL_USER', '')
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', '')

    TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
    TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')

    # ML Configuration
    ML_MODEL_PATH = 'models/anomaly_detector.pkl'
    ML_SAFE_THRESHOLD = 0.3
    ML_SUSPICIOUS_THRESHOLD = 0.7

    # Security
    MAX_LOGIN_ATTEMPTS = 5
    AUTO_BLOCK_IPS = True
    BLOCK_DURATION_DAYS = 7

    # Logging
    LOG_RETENTION_DAYS = 90
    DEFAULT_TOKEN_EXPIRY = 30