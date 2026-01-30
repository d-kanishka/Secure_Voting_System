import os
from dotenv import load_dotenv
load_dotenv()

class Config:
    # Database & JWT
    MONGO_URI = os.environ.get("MONGO_URI")
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "change-me-to-a-strong-secret")
    JWT_ACCESS_TOKEN_EXPIRES = int(os.environ.get("JWT_EXPIRES_SECONDS", 3600))

    # Key protection
    KEY_PASSPHRASE = os.environ.get("KEY_PASSPHRASE", "change-me")

    # Behavior toggles
    ANONYMIZE_ON_CAST = os.environ.get("ANONYMIZE_ON_CAST", "true").lower() in ("1", "true", "yes")

    # TOTP / MFA
    TOTP_ISSUER_NAME = os.environ.get("TOTP_ISSUER_NAME", "Student E-Voting")
    MFA_WINDOW_SECONDS = int(os.environ.get("MFA_WINDOW_SECONDS", "300"))  # 5 minutes

    # Password reset / one-time codes
    RESET_CODE_TTL_SECONDS = int(os.environ.get("RESET_CODE_TTL_SECONDS", "600"))  # 10 minutes

    # SMTP for sending reset codes (configure in .env for real emails)
    SMTP_SERVER = os.environ.get("SMTP_SERVER", "")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USER = os.environ.get("SMTP_USER", "")
    SMTP_PASS = os.environ.get("SMTP_PASS", "")
    FROM_EMAIL = os.environ.get("FROM_EMAIL", "no-reply@example.com")