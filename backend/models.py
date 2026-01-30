import certifi
from pymongo import MongoClient, ASCENDING
from bson.objectid import ObjectId
import datetime
from config import Config
import hashlib

import os
from urllib.parse import quote_plus
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv() 

user = os.getenv("MONGO_USER")
pw = quote_plus(os.getenv("MONGO_PASSWORD"))
uri = f"mongodb+srv://{user}:{pw}@cluster0.xdxdrm1.mongodb.net/voting_db?authSource=admin&retryWrites=true&w=majority"

client = MongoClient(uri, tls=True, tlsCAFile=certifi.where())
try:
    print("server_info OK:", client.server_info())
except Exception as e:
    print("connect failed:", type(e), e)
    
db = client["voting_db"]


# Collections
users = db.users
elections = db.elections
tokens = db.tokens
votes = db.votes
audit_logs = db.audit_logs

users.create_index([("username", ASCENDING)], unique=True)
users.create_index([("email", ASCENDING)], unique=True, sparse=True)
tokens.create_index([("token_hash", ASCENDING)], unique=True)
elections.create_index([("name", ASCENDING)], unique=True)
# store tokens in hash with salt value
def hash_token(token: str, salt: str):
    h = hashlib.sha256() # one-way cryptographic func. , can't reverse it, protects db
    h.update(salt.encode('utf-8'))
    h.update(token.encode('utf-8'))
    return h.hexdigest()

def hash_reset_code(code: str, salt: str):
    h = hashlib.sha256()
    h.update(salt.encode('utf-8'))
    h.update(code.encode('utf-8'))
    return h.hexdigest()

# generates token,code-> hash+salt -> store in db & 
# send token to user -> hash _salt -> compare both and approves

# Audit logger
def log_audit(action: str, actor: str, details: dict = None):
    audit_logs.insert_one({
        "action": action,
        "actor": actor,
        "details": details or {},
        "timestamp": datetime.datetime.utcnow()
    })