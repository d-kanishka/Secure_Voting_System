import os
import secrets
import base64
import csv
import io
import json
import traceback
from flask import Flask, request, jsonify
from flask_cors import CORS
from config import Config
from auth import jwt, hash_password, check_password, create_temp_jwt, create_final_jwt, role_and_mfa_required
from models import users, elections, tokens, votes, audit_logs, log_audit, hash_token, hash_reset_code, db
from crypto_utils import (
    generate_rsa_keypair, serialize_private_key, serialize_public_key,
    load_private_key, load_public_key, generate_aes_key, aes_encrypt, aes_decrypt,
    rsa_encrypt_with_public_key, rsa_decrypt_with_private_key, sign_with_private_key,
    verify_signature
)
import pyotp
import datetime
from bson.objectid import ObjectId
from validators import role_from_email
from mail_utils import send_email
import qrcode
from PIL import Image
from flask_jwt_extended import jwt_required, get_jwt_identity

app = Flask(__name__)
app.config.from_object(Config)
app.config["JWT_SECRET_KEY"] = Config.JWT_SECRET_KEY
CORS(app)
jwt.init_app(app)

#  qr generation from the url
def provisioning_qr_data_uri(provisioning_uri: str) -> str:
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    return f"data:image/png;base64,{b64}"
#encode and send, browser decodes it
# img -> txt , txt -> img

# ---------------------------
# Register / login / TOTP
# ---------------------------
@app.route("/register", methods=["POST"])
def register():
    # details of the user
    data = request.json or {}
    full_name = (data.get("full_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password")
    if not (full_name and email and password):
        return jsonify({"msg": "missing fields"}), 400
    
# role verification
    role = role_from_email(email)
    if not role:
        return jsonify({"msg": "invalid email domain for registration"}), 400

    if users.find_one({"email": email}):
        return jsonify({"msg": "email already registered"}), 400

    username = email.split("@")[0]
    pw_hash = hash_password(password) # pass will be hashed and salted
    totp_secret = pyotp.random_base32() # t-otp, random shared secret

    user_doc = {
        "username": username,
        "full_name": full_name,
        "email": email,
        "password_hash": pw_hash,
        "role": role,
        "totp_secret": totp_secret,
        "active": True,
        "created_at": datetime.datetime.utcnow()
    }
    users.insert_one(user_doc)
    # uri
    provisioning_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(f"{Config.TOTP_ISSUER_NAME}:{username}", issuer_name=Config.TOTP_ISSUER_NAME)
    # qr code
    qr_data_uri = provisioning_qr_data_uri(provisioning_uri)
    log_audit("user_register", username, {"role": role, "email": email})
    return jsonify({
        "msg": "registered",
        "username": username,
        "role": role,
        "provisioning_uri": provisioning_uri,
        "qr_data_uri": qr_data_uri
    }), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    email_or_username = (data.get("email") or data.get("username") or "").strip().lower()
    password = data.get("password")
    if not (email_or_username and password):
        return jsonify({"msg": "missing"}), 400

    u = users.find_one({"$or": [{"username": email_or_username}, {"email": email_or_username}]})
    if not u or not check_password(password, u["password_hash"]):
        log_audit("login_failed", email_or_username)
        return jsonify({"msg": "invalid credentials"}), 401

    temp_token = create_temp_jwt(u)
    log_audit("login_password_ok", u["username"])
    return jsonify({"temp_token": temp_token, "mfa_required": True, "username": u["username"], "role": u["role"]}), 200

@app.route("/verify_totp", methods=["POST"])
@jwt_required()
def verify_totp():
    try:
        identity = get_jwt_identity()
        if not identity:
            return jsonify({"msg": "invalid session"}), 401
        username = identity
        data = request.json or {}
        code = data.get("code")
        if not code:
            return jsonify({"msg": "missing code"}), 400

        u = users.find_one({"username": username})
        if not u:
            return jsonify({"msg": "user not found"}), 404

        totp = pyotp.TOTP(u["totp_secret"])
        ok = totp.verify(code, valid_window=1)
        if not ok:
            log_audit("totp_failed", username)
            return jsonify({"msg": "invalid TOTP"}), 401

        final_jwt = create_final_jwt(u)
        users.update_one({"username": username}, {"$set": {"last_mfa": datetime.datetime.utcnow()}})
        log_audit("totp_verified", username)
        return jsonify({"access_token": final_jwt, "username": username, "role": u["role"]}), 200
    except Exception as e:
        tb = traceback.format_exc()
        log_audit("verify_totp_exception", "system", {"error": str(e), "trace": tb})
        return jsonify({"msg": "internal error", "error": str(e), "trace": tb}), 500

# ---------------------------
# Reset password
# ---------------------------
@app.route("/forgot_password", methods=["POST"])
def forgot_password():
    data = request.json or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"msg": "ok"}), 200
    u = users.find_one({"email": email})
    if not u:
        return jsonify({"msg": "If the email exists, a reset code was sent"}), 200

    code = "{:06d}".format(secrets.randbelow(1000000))
    salt = secrets.token_hex(16)
    code_hash = hash_reset_code(code, salt)
    expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=Config.RESET_CODE_TTL_SECONDS)
    users.update_one({"email": email}, {"$set": {"reset_code_hash": code_hash, "reset_salt": salt, "reset_expires": expires}})
    subject = "Password reset code - Student E-Voting"
    body = f"Your password reset code is: {code}\nIt will expire in {Config.RESET_CODE_TTL_SECONDS//60} minutes."
    sent = send_email(email, subject, body)
    log_audit("reset_code_issued", u["username"])
    if not sent and (not Config.SMTP_SERVER or not Config.SMTP_USER):
        return jsonify({"msg": "If the email exists, a reset code was sent (dev).", "debug_code": code}), 200
    return jsonify({"msg": "If the email exists, a reset code was sent"}), 200

@app.route("/reset_password", methods=["POST"])
def reset_password():
    data = request.json or {}
    email = (data.get("email") or "").strip().lower()
    code = data.get("code")
    new_pw = data.get("new_password")
    if not (email and code and new_pw):
        return jsonify({"msg": "missing fields"}), 400
    u = users.find_one({"email": email})
    if not u:
        return jsonify({"msg": "invalid"}), 400
    if u.get("reset_expires") is None or datetime.datetime.utcnow() > u.get("reset_expires"):
        return jsonify({"msg": "expired or invalid"}), 400
    if hash_reset_code(code, u.get("reset_salt", "")) != u.get("reset_code_hash"):
        log_audit("reset_code_failed", u["username"])
        return jsonify({"msg": "invalid code"}), 401
    new_hash = hash_password(new_pw)
    users.update_one({"email": email}, {"$set": {"password_hash": new_hash}, "$unset": {"reset_code_hash": "", "reset_salt": "", "reset_expires": ""}})
    final_jwt = create_final_jwt(u)
    log_audit("password_reset", u["username"])
    return jsonify({"access_token": final_jwt}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=True)