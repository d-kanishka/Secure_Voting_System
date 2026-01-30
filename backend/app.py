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

from dotenv import load_dotenv
load_dotenv()

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

# ---------------------------
# Admin endpoints (users management/audit logs/mail outbox/create elections)
# ---------------------------
@app.route("/admin/users", methods=["GET"])
@role_and_mfa_required("admin", require_mfa=False)
def admin_list_users():
    out = []
    for u in users.find({}, {"password_hash": 0, "totp_secret": 0}):
        out.append({
            "username": u.get("username"),
            "email": u.get("email"),
            "role": u.get("role"),
            "full_name": u.get("full_name"),
            "active": u.get("active", True),
            "created_at": u.get("created_at")
        })
    return jsonify({"users": out}), 200

@app.route("/admin/import_users", methods=["POST"])
@role_and_mfa_required("admin", require_mfa=False)
def admin_import_users():
    if 'file' not in request.files:
        return jsonify({"msg": "file required"}), 400
    f = request.files['file']
    try:
        stream = io.StringIO(f.stream.read().decode("utf-8"))
        reader = csv.DictReader(stream)
    except Exception as e:
        return jsonify({"msg": "invalid csv", "error": str(e)}), 400
    created = []
    errors = []
    for row in reader:
        full_name = (row.get("full_name") or "").strip()
        email = (row.get("email") or "").strip().lower()
        role = (row.get("role") or "").strip().lower()
        password = row.get("password") or None
        if not (full_name and email):
            errors.append({"row": row, "error": "missing full_name or email"})
            continue
        if users.find_one({"email": email}):
            errors.append({"row": row, "error": "email exists"})
            continue
        if role not in ("voter", "admin", "auditor"):
            role = role_from_email(email) or "voter"
        if not password:
            password = secrets.token_urlsafe(8)
        pw_hash = hash_password(password)
        username = email.split("@")[0]
        udoc = {
            "username": username,
            "full_name": full_name,
            "email": email,
            "password_hash": pw_hash,
            "role": role,
            "totp_secret": pyotp.random_base32(),
            "created_at": datetime.datetime.utcnow()
        }
        users.insert_one(udoc)
        log_audit("admin_import_user", get_jwt_identity() or "admin", {"email": email, "username": username})
        created.append({"username": username, "email": email, "password": password, "role": role})
    return jsonify({"created": created, "errors": errors}), 200

@app.route("/admin/audit_logs", methods=["GET"])
@role_and_mfa_required("admin", require_mfa=False)
def admin_audit_logs():
    limit = int(request.args.get("limit", "200"))
    out = []
    for a in audit_logs.find().sort("timestamp", -1).limit(limit):
        out.append({
            "action": a.get("action"),
            "actor": a.get("actor"),
            "details": a.get("details"),
            "timestamp": a.get("timestamp").isoformat() if a.get("timestamp") else None
        })
    return jsonify({"audit_logs": out}), 200

@app.route("/audit_logs", methods=["GET"])
@role_and_mfa_required(["admin","auditor"], require_mfa=False)
def audit_logs_readonly():
    limit = int(request.args.get("limit", "200"))
    out = []
    for a in audit_logs.find().sort("timestamp", -1).limit(limit):
        out.append({
            "action": a.get("action"),
            "actor": a.get("actor"),
            "details": a.get("details"),
            "timestamp": a.get("timestamp").isoformat() if a.get("timestamp") else None
        })
    return jsonify({"audit_logs": out}), 200

@app.route("/admin/outbox", methods=["GET"])
@role_and_mfa_required("admin", require_mfa=False)
def admin_outbox():
    out = []
    for m in db.outbox.find().sort("timestamp", -1).limit(500):
        out.append({
            "to": m.get("to"),
            "subject": m.get("subject"),
            "body": m.get("body"),
            "timestamp": m.get("timestamp").isoformat() if m.get("timestamp") else None
        })
    return jsonify({"outbox": out}), 200

# ---------------------------
# Election management
# ---------------------------
@app.route("/create_election", methods=["POST"])
@role_and_mfa_required("admin", require_mfa=False)
def create_election():
    data = request.json or {}
    name = data.get("name")
    description = data.get("description", "")
    start = data.get("start")
    end = data.get("end")
    candidates = data.get("candidates") or []
    anonymize = bool(data.get("anonymize", True))
    if not name:
        return jsonify({"msg": "name required"}), 400
    if elections.find_one({"name": name}):
        return jsonify({"msg": "election with that name exists"}), 400
    priv, pub = generate_rsa_keypair()
    priv_pem = serialize_private_key(priv, passphrase=Config.KEY_PASSPHRASE.encode('utf-8'))
    pub_pem = serialize_public_key(pub)
    election = {
        "name": name,
        "description": description,
        "start": start,
        "end": end,
        "candidates": candidates,
        "anonymize": anonymize,
        "created_at": datetime.datetime.utcnow(),
        "public_key": pub_pem.decode('utf-8'),
        "private_key_enc": priv_pem.decode('utf-8'),
        "status": "created",
        "eligible_voters": []
    }
    res = elections.insert_one(election)
    log_audit("election_created", get_jwt_identity() or "admin", {"election_id": str(res.inserted_id), "name": name})
    return jsonify({"msg": "election_created", "election_id": str(res.inserted_id)}), 201

@app.route("/list_elections", methods=["GET"])
@jwt_required()
def list_elections():
    try:
        identity = get_jwt_identity() or None
        username = identity
    except Exception:
        username = None
    out = []
    for e in elections.find({}).sort("created_at", -1):
        out.append({
            "election_id": str(e["_id"]),
            "name": e.get("name"),
            "description": e.get("description", ""),
            "status": e.get("status", "created"),
            "eligible": username in e.get("eligible_voters", [])
        })
    return jsonify({"elections": out}), 200

@app.route("/election/<election_id>", methods=["GET"])
@role_and_mfa_required(["admin","auditor","voter"], require_mfa=False)
def get_election(election_id):
    e = elections.find_one({"_id": ObjectId(election_id)})
    if not e:
        return jsonify({"msg": "not found"}), 404
    votes_count = votes.count_documents({"election_id": ObjectId(election_id)})
    return jsonify({
        "election_id": str(e["_id"]),
        "name": e.get("name"),
        "description": e.get("description", ""),
        "status": e.get("status"),
        "start": e.get("start"),
        "end": e.get("end"),
        "candidates": e.get("candidates", []),
        "eligible_count": len(e.get("eligible_voters", [])),
        "votes_count": votes_count,
        "anonymize": e.get("anonymize", True),
        "public_key": e.get("public_key"),
        "published_results": e.get("published_results")
    }), 200

@app.route("/edit_election/<election_id>", methods=["PUT"])
@role_and_mfa_required("admin", require_mfa=False)
def edit_election(election_id):
    data = request.json or {}
    e = elections.find_one({"_id": ObjectId(election_id)})
    if not e:
        return jsonify({"msg": "not found"}), 404
    if e.get("status") == "published":
        return jsonify({"msg": "cannot edit published election"}), 400
    updates = {}
    for f in ("name", "description", "start", "end", "candidates", "anonymize"):
        if f in data:
            updates[f] = data[f]
    if updates:
        elections.update_one({"_id": ObjectId(election_id)}, {"$set": updates})
        log_audit("election_edited", get_jwt_identity() or "admin", {"election_id": election_id, "updates": updates})
    return jsonify({"msg": "updated"}), 200

@app.route("/delete_election/<election_id>", methods=["DELETE"])
@role_and_mfa_required("admin", require_mfa=False)
def delete_election(election_id):
    e = elections.find_one({"_id": ObjectId(election_id)})
    if not e:
        return jsonify({"msg": "not found"}), 404
    if e.get("status") == "published":
        return jsonify({"msg": "cannot delete published election"}), 400
    elections.delete_one({"_id": ObjectId(election_id)})
    tokens.delete_many({"election_id": ObjectId(election_id)})
    votes.delete_many({"election_id": ObjectId(election_id)})
    db.has_voted.delete_many({"election_id": ObjectId(election_id)})
    log_audit("election_deleted", get_jwt_identity() or "admin", {"election_id": election_id})
    return jsonify({"msg": "deleted"}), 200

@app.route("/start_election/<election_id>", methods=["POST"])
@role_and_mfa_required("admin", require_mfa=False)
def start_election(election_id):
    e = elections.find_one({"_id": ObjectId(election_id)})
    if not e:
        return jsonify({"msg": "not found"}), 404
    elections.update_one({"_id": ObjectId(election_id)}, {"$set": {"status": "ongoing"}})
    log_audit("election_started", get_jwt_identity() or "admin", {"election_id": election_id})
    return jsonify({"msg": "started"}), 200

@app.route("/stop_election/<election_id>", methods=["POST"])
@role_and_mfa_required("admin", require_mfa=False)
def stop_election(election_id):
    e = elections.find_one({"_id": ObjectId(election_id)})
    if not e:
        return jsonify({"msg": "not found"}), 404
    elections.update_one({"_id": ObjectId(election_id)}, {"$set": {"status": "completed"}})
    log_audit("election_stopped", get_jwt_identity() or "admin", {"election_id": election_id})
    return jsonify({"msg": "stopped"}), 200

@app.route("/add_eligible_voter", methods=["POST"])
@role_and_mfa_required("admin", require_mfa=False)
def add_eligible_voter():
    data = request.json or {}
    election_id = data.get("election_id")
    username = data.get("username")
    if not (election_id and username):
        return jsonify({"msg": "missing"}), 400
    e = elections.find_one({"_id": ObjectId(election_id)})
    if not e:
        return jsonify({"msg": "election not found"}), 404
    if not users.find_one({"username": username}):
        return jsonify({"msg": "user not found"}), 404
    elections.update_one({"_id": ObjectId(election_id)}, {"$addToSet": {"eligible_voters": username}})
    log_audit("added_eligible_voter", get_jwt_identity() or "admin", {"election_id": election_id, "username": username})
    return jsonify({"msg": "added"}), 200

@app.route("/remove_eligible_voter", methods=["POST"])
@role_and_mfa_required("admin", require_mfa=False)
def remove_eligible_voter():
    data = request.json or {}
    election_id = data.get("election_id")
    username = data.get("username")
    if not (election_id and username):
        return jsonify({"msg": "missing"}), 400
    elections.update_one({"_id": ObjectId(election_id)}, {"$pull": {"eligible_voters": username}})
    log_audit("removed_eligible_voter", get_jwt_identity() or "admin", {"election_id": election_id, "username": username})
    return jsonify({"msg": "removed"}), 200

# ---------------------------
# Token / Vote / Publish results
# ---------------------------
@app.route("/issue_token", methods=["POST"])
@role_and_mfa_required(["admin", "voter"], require_mfa=True) # votes must be authenticated
#votes must be in eligivle votes list
def issue_token():
    from auth import _get_claims_from_jwt
    identity = get_jwt_identity()
    claims = _get_claims_from_jwt()
    role = claims.get("role")
    data = request.json or {}
    election_id = data.get("election_id")
    if not election_id:
        return jsonify({"msg": "election_id required"}), 400
    election = elections.find_one({"_id": ObjectId(election_id)})
    if not election:
        return jsonify({"msg": "election not found"}), 404

    if role == "admin":
        username = data.get("username")
        if not username:
            return jsonify({"msg": "username required for admin-issued token"}), 400
        if username not in election.get("eligible_voters", []):
            return jsonify({"msg": "user not eligible"}), 400
        if db.has_voted.find_one({"election_id": ObjectId(election_id), "username": username}):
            return jsonify({"msg": "user already voted"}), 403
    else:
        username = identity
        if username not in election.get("eligible_voters", []):
            return jsonify({"msg": "you are not eligible for this election"}), 403
        u = users.find_one({"username": username})
        last_mfa = u.get("last_mfa")
        if not last_mfa or (datetime.datetime.utcnow() - last_mfa).total_seconds() > Config.MFA_WINDOW_SECONDS:
            return jsonify({"msg": "MFA required (recent) before requesting token)"}), 403
        if db.has_voted.find_one({"election_id": ObjectId(election_id), "username": username}):
            return jsonify({"msg": "you have already voted in this election"}), 403
        
# token we hash it with salt, aes key generated, encrypt with pub key of election
    token_plain = secrets.token_urlsafe(32)
    salt = secrets.token_hex(16)
    token_hash = hash_token(token_plain, salt)
    aes_key = generate_aes_key()
    pub_key = load_public_key(election["public_key"].encode('utf-8'))
    aes_key_enc = rsa_encrypt_with_public_key(pub_key, aes_key)

    token_doc = {
        "election_id": ObjectId(election_id),
        "token_hash": token_hash,
        "salt": salt,
        "aes_key_enc": aes_key_enc,
        "issued_to": username,
        "used": False,
        "issued_at": datetime.datetime.utcnow()
    }
    tokens.insert_one(token_doc)
    log_audit("token_issued", identity, {"election_id": election_id, "issued_to": username})
    return jsonify({"token": token_plain, "election_id": election_id}), 201

@app.route("/cast_vote", methods=["POST"])
@role_and_mfa_required("voter", require_mfa=True)
# token is verified via hash comparison
def cast_vote():
    data = request.json or {}
    election_id = data.get("election_id")
    token_plain = data.get("token")
    choice = data.get("choice")
    if not (election_id and token_plain and choice):
        return jsonify({"msg": "missing fields"}), 400
    election = elections.find_one({"_id": ObjectId(election_id)})
    if not election:
        return jsonify({"msg": "election not found"}), 404

    token_doc = None
    for t in tokens.find({"election_id": ObjectId(election_id), "used": False}):
        if hash_token(token_plain, t["salt"]) == t["token_hash"]:
            token_doc = t
            break
    if not token_doc:
        return jsonify({"msg": "invalid or used token"}), 403

    username = get_jwt_identity()
    if token_doc.get("issued_to") != username:
        return jsonify({"msg": "token not issued to you"}), 403

    if db.has_voted.find_one({"election_id": ObjectId(election_id), "username": username}):
        return jsonify({"msg": "you have already voted in this election"}), 403

    priv_key = load_private_key(election["private_key_enc"].encode('utf-8'), passphrase=Config.KEY_PASSPHRASE.encode('utf-8'))
    aes_key = rsa_decrypt_with_private_key(priv_key, token_doc["aes_key_enc"])
    vote_plain_bytes = json.dumps({"choice": choice, "timestamp": datetime.datetime.utcnow().isoformat()}).encode('utf-8')
    encrypted_vote_b64 = aes_encrypt(aes_key, vote_plain_bytes)
    vote_hash = __import__('hashlib').sha256(encrypted_vote_b64.encode('utf-8')).digest()
    signature_b64 = sign_with_private_key(priv_key, vote_hash)

    vote_doc = {
        "election_id": ObjectId(election_id),
        "encrypted_vote": encrypted_vote_b64,
        "signature": signature_b64,
        "cast_at": datetime.datetime.utcnow(),
        "token_ref": token_doc["_id"]
    }
    vres = votes.insert_one(vote_doc)

    update = {"$set": {"used": True, "used_at": datetime.datetime.utcnow()}}
    if Config.ANONYMIZE_ON_CAST:
        update["$unset"] = {"issued_to": ""}
    tokens.update_one({"_id": token_doc["_id"]}, update)

    db.has_voted.insert_one({"election_id": ObjectId(election_id), "username": username, "voted_at": datetime.datetime.utcnow()})

    # Cleanup remaining unused tokens for this user/election
    result = tokens.delete_many({"election_id": ObjectId(election_id), "issued_to": username, "used": False})
    log_audit("cleanup_unused_tokens", username, {"election_id": election_id, "deleted_count": result.deleted_count})

    log_audit("vote_cast", username, {"election_id": election_id, "vote_id": str(vres.inserted_id)})
    return jsonify({"msg": "vote recorded", "vote_id": str(vres.inserted_id)}), 200

@app.route("/publish_results", methods=["POST"])
@role_and_mfa_required("admin", require_mfa=False)
def publish_results():
    data = request.json or {}
    election_id = data.get("election_id")
    if not election_id:
        return jsonify({"msg": "election_id required"}), 400
    election = elections.find_one({"_id": ObjectId(election_id)})
    if not election:
        return jsonify({"msg": "election not found"}), 404
    priv_key = load_private_key(election["private_key_enc"].encode('utf-8'), passphrase=Config.KEY_PASSPHRASE.encode('utf-8'))
    tally = {}
    decrypted_votes = []
    for v in votes.find({"election_id": ObjectId(election_id)}):
        token_doc = tokens.find_one({"_id": v["token_ref"]})
        if not token_doc:
            continue
        try:
            aes_key = rsa_decrypt_with_private_key(priv_key, token_doc["aes_key_enc"])
            decrypted = aes_decrypt(aes_key, v["encrypted_vote"])
            vote_hash = __import__('hashlib').sha256(v["encrypted_vote"].encode('utf-8')).digest()
            pub_key = load_public_key(election["public_key"].encode('utf-8'))
            sig_ok = verify_signature(pub_key, vote_hash, v["signature"])
            if not sig_ok:
                log_audit("signature_failed", "system", {"vote_id": str(v["_id"])})
                continue
            vote_json = json.loads(decrypted.decode('utf-8'))
            choice = json.dumps(vote_json["choice"], sort_keys=True)
            tally[choice] = tally.get(choice, 0) + 1
            decrypted_votes.append({"vote_id": str(v["_id"]), "choice": vote_json["choice"], "cast_at": v["cast_at"].isoformat()})
        except Exception as e:
            log_audit("tally_decrypt_error", "system", {"vote_id": str(v["_id"]), "error": str(e)})
            continue

    results_doc = {
        "election_id": ObjectId(election_id),
        "tally": tally,
        "decrypted_votes": decrypted_votes,
        "published_at": datetime.datetime.utcnow()
    }
    elections.update_one({"_id": ObjectId(election_id)}, {"$set": {"published_results": results_doc, "status": "published"}})
    log_audit("results_published", get_jwt_identity() or "admin", {"election_id": election_id})
    return jsonify({"results": results_doc}), 200

@app.route("/audit/verify_vote", methods=["POST"])
@role_and_mfa_required("auditor", require_mfa=False)
def audit_verify_vote():
    data = request.json or {}
    election_id = data.get("election_id")
    vote_id = data.get("vote_id")
    if not (election_id and vote_id):
        return jsonify({"msg": "missing"}), 400
    election = elections.find_one({"_id": ObjectId(election_id)})
    if not election:
        return jsonify({"msg": "election not found"}), 404
    v = votes.find_one({"_id": ObjectId(vote_id)})
    if not v:
        return jsonify({"msg": "vote not found"}), 404
    priv_key = load_private_key(election["private_key_enc"].encode('utf-8'), passphrase=Config.KEY_PASSPHRASE.encode('utf-8'))
    token_doc = tokens.find_one({"_id": v["token_ref"]})
    if not token_doc:
        return jsonify({"msg": "token missing"}), 404
    try:
        aes_key = rsa_decrypt_with_private_key(priv_key, token_doc["aes_key_enc"])
        decrypted = aes_decrypt(aes_key, v["encrypted_vote"])
        vote_hash = __import__('hashlib').sha256(v["encrypted_vote"].encode('utf-8')).digest()
        pub_key = load_public_key(election["public_key"].encode('utf-8'))
        sig_ok = verify_signature(pub_key, vote_hash, v["signature"])
        return jsonify({"signature_valid": sig_ok, "decrypted_vote": json.loads(decrypted.decode('utf-8'))}), 200
    except Exception as e:
        return jsonify({"msg": "verification failed", "error": str(e)}), 500

@app.route("/public_election_info/<election_id>", methods=["GET"])
def public_election_info(election_id):
    e = elections.find_one({"_id": ObjectId(election_id)})
    if not e:
        return jsonify({"msg": "not found"}), 404
    return jsonify({
        "name": e["name"],
        "description": e.get("description", ""),
        "public_key": e["public_key"],
        "published_results": e.get("published_results")
    }), 200

# ---------------------------
# New: Auditor/Admin tally endpoint (returns per-candidate counts)
# ---------------------------
@app.route("/audit/election_tally/<election_id>", methods=["GET"])
@role_and_mfa_required(["admin", "auditor"], require_mfa=False)
def audit_election_tally(election_id):
    """
    Return per-candidate tally for the election.
    If published_results exists, use it; otherwise attempt to decrypt votes (requires server-held private key).
    Response:
    {
      "election_id": "...",
      "name": "...",
      "tally": [{"candidate":"John","count": 5}, ...],
      "decrypted_votes": [... optional list ...]
    }
    """
    e = elections.find_one({"_id": ObjectId(election_id)})
    if not e:
        return jsonify({"msg": "election not found"}), 404

    # If published results exist, use them
    if e.get("published_results"):
        pub = e["published_results"]
        tally_map = {}
        for choice_key, cnt in pub.get("tally", {}).items():
            # choice_key is typically a JSON string (canonicalized)
            try:
                parsed = json.loads(choice_key)
                if isinstance(parsed, dict):
                    # Try common field names
                    candidate = parsed.get("candidate") or next(iter(parsed.values()))
                else:
                    candidate = parsed
            except Exception:
                candidate = choice_key
            tally_map[candidate] = cnt
        tally_list = [{"candidate": k, "count": v} for k, v in tally_map.items()]
        return jsonify({
            "election_id": election_id,
            "name": e.get("name"),
            "tally": tally_list,
            "published": True,
            "published_at": pub.get("published_at")
        }), 200

    # Else attempt to decrypt votes on the fly
    try:
        priv_key = load_private_key(e["private_key_enc"].encode('utf-8'), passphrase=Config.KEY_PASSPHRASE.encode('utf-8'))
    except Exception as ex:
        return jsonify({"msg": "cannot load private key on server", "error": str(ex)}), 500

    tally_map = {}
    decrypted_votes = []
    for v in votes.find({"election_id": ObjectId(election_id)}):
        token_doc = tokens.find_one({"_id": v["token_ref"]})
        if not token_doc:
            # if token mapping was anonymized and aes key not stored with vote, cannot decrypt
            continue
        try:
            aes_key = rsa_decrypt_with_private_key(priv_key, token_doc["aes_key_enc"])
            decrypted = aes_decrypt(aes_key, v["encrypted_vote"])
            vote_json = json.loads(decrypted.decode('utf-8'))
            choice_value = vote_json.get("choice")
            # normalize candidate name
            if isinstance(choice_value, dict):
                candidate = choice_value.get("candidate") or next(iter(choice_value.values()))
            elif isinstance(choice_value, str):
                candidate = choice_value
            else:
                candidate = json.dumps(choice_value, sort_keys=True)
            tally_map[candidate] = tally_map.get(candidate, 0) + 1
            decrypted_votes.append({"vote_id": str(v["_id"]), "choice": choice_value, "cast_at": v["cast_at"].isoformat()})
        except Exception as e:
            log_audit("audit_tally_decrypt_error", "system", {"vote_id": str(v["_id"]), "error": str(e)})
            continue

    tally_list = [{"candidate": k, "count": v} for k, v in tally_map.items()]
    return jsonify({
        "election_id": election_id,
        "name": e.get("name"),
        "tally": tally_list,
        "published": False,
        "decrypted_votes": decrypted_votes
    }), 200

@app.route("/whoami", methods=["GET"])
@jwt_required()
def whoami():
    return jsonify(get_jwt_identity())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=True)