import smtplib
import ssl
from email.message import EmailMessage
from config import Config
from models import log_audit, db
import datetime
import ssl
import certifi

def send_email(to_email: str, subject: str, body: str):
    try:
        db.outbox.insert_one({
            "to": to_email,
            "subject": subject,
            "body": body,
            "timestamp": datetime.datetime.utcnow()
        })
    except Exception as e:
        log_audit("outbox_store_failed", "system", {"to": to_email, "error": str(e)})

    if not Config.SMTP_SERVER or not Config.SMTP_USER or not Config.SMTP_PASS:
        log_audit("email_send_skipped", "system", {"to": to_email, "reason": "smtp_not_configured"})
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = Config.FROM_EMAIL
    msg["To"] = to_email
    msg.set_content(body)
    context = ssl.create_default_context(cafile=certifi.where())
    try:
        with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT, timeout=10) as server:
            server.starttls(context=context)
            server.login(Config.SMTP_USER, Config.SMTP_PASS)
            server.send_message(msg)
        log_audit("email_sent", "system", {"to": to_email, "subject": subject})
        return True
    except Exception as e:
        log_audit("email_send_failed", "system", {"to": to_email, "error": str(e)})
        return False