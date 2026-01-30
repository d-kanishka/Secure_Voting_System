from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from functools import wraps
from flask import jsonify
import datetime
from models import log_audit

jwt = JWTManager()

# bcrypt + salt -> single auth -> hashing
def hash_password(plain_password: str) -> bytes:
    import bcrypt
    return bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt())

def check_password(plain_password: str, pw_hash: bytes) -> bool:
    import bcrypt
    return bcrypt.checkpw(plain_password.encode('utf-8'), pw_hash)
#extracts the salt from the stored hash

# Token => proof that the user is authenticated and authorized
# creates JWT with claims about role and mfa status
def _create_access_token_with_claims(identity_str: str, claims: dict, expires_delta):
    try:
        return create_access_token(identity=identity_str, additional_claims=claims, expires_delta=expires_delta)
    except TypeError:
        return create_access_token(identity=identity_str, user_claims=claims, expires_delta=expires_delta)

# temp token: after user/pass, before mfa, expires in 5mins, in btw they need to activate mfa
def create_temp_jwt(user_doc, expires_minutes=5):
    identity = user_doc["username"]
    claims = {"role": user_doc["role"], "mfa": False}
    expires = datetime.timedelta(minutes=expires_minutes)
    return _create_access_token_with_claims(identity, claims, expires)

# after mfa done, create final token, login 
def create_final_jwt(user_doc, expires_hours=8):
    identity = user_doc["username"]
    claims = {"role": user_doc["role"], "mfa": True}
    expires = datetime.timedelta(hours=expires_hours)
    return _create_access_token_with_claims(identity, claims, expires)


def _get_claims_from_jwt():
    try:
        from flask_jwt_extended import get_jwt
        return get_jwt() or {}
    except Exception:
        try:
            from flask_jwt_extended import get_jwt_claims
            return get_jwt_claims() or {}
        except Exception:
            return {}

def role_and_mfa_required(required_roles, require_mfa=False):
    if not isinstance(required_roles, (list, tuple, set)):
        required_roles = [required_roles]
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            from flask_jwt_extended import get_jwt_identity
            username = get_jwt_identity()
            claims = _get_claims_from_jwt()
            role = claims.get("role")
            mfa_flag = claims.get("mfa", False)
            if role not in required_roles:
                log_audit("unauthorized_access_attempt", username or "unknown", {"required_roles": required_roles, "actual_role": role})
                return jsonify({"msg": "Forbidden: insufficient role"}), 403
            if require_mfa and not mfa_flag:
                log_audit("access_requires_mfa", username or "unknown", {"endpoint": fn.__name__})
                return jsonify({"msg": "MFA required"}), 401
            return fn(*args, **kwargs)
        return wrapper
    return decorator



@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    # token expired (sub field present in payload). Return 401 and a clear JSON.
    return jsonify({"msg": "token_expired", "description": "Your session has expired. Please login again."}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error_string):
    return jsonify({"msg": "invalid_token", "description": error_string}), 401

@jwt.unauthorized_loader
def missing_token_callback(error_string):
    return jsonify({"msg": "missing_token", "description": error_string}), 401

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({"msg": "revoked_token", "description": "Token has been revoked"}), 401