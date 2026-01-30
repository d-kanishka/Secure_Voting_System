import base64
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.exceptions import InvalidSignature

# RSA helpers
# generates both public key & private key
def generate_rsa_keypair(key_size=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pub = private_key.public_key()
    return private_key, pub

# convert key to txt file and send  to db of the admin
def serialize_private_key(private_key, passphrase: bytes = None):
    if passphrase:
        enc_algorithm = serialization.BestAvailableEncryption(passphrase)
    else:
        enc_algorithm = serialization.NoEncryption()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_algorithm
    )

# send  to db of the user 
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# to load keys from db
def load_private_key(pem_bytes: bytes, passphrase: bytes = None):
    return serialization.load_pem_private_key(pem_bytes, password=passphrase)

def load_public_key(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)

# Hybrid encryption: AES for data, RSA for AES key
def generate_aes_key(length=32):
    return os.urandom(length)  # 32 bytes = 256-bit key -> randomly generated

def aes_encrypt(aes_key: bytes, plaintext: bytes): # encrypt the vote data
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12) 
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    payload = base64.b64encode(nonce + ct).decode('utf-8')
    return payload

def aes_decrypt(aes_key: bytes, b64_payload: str):
    raw = base64.b64decode(b64_payload)
    nonce = raw[:12]
    ct = raw[12:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ct, associated_data=None)

def rsa_encrypt_with_public_key(public_key, data: bytes):
    ct = public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(ct).decode('utf-8')

def rsa_decrypt_with_private_key(private_key, b64_ciphertext: str):
    ct = base64.b64decode(b64_ciphertext)
    pt = private_key.decrypt(ct, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return pt

# digi Signing (RSA-PSS)
# Probabilistic Signature Scheme
# extra: salt add to msg to make secure(add randomness)
# prevent signature replay attacks
# sign : (vote_data + election_id + token_id)
# vote cant be edited. if verification fails vote is rejected.
# Extracts the salt from inside the signature
def sign_with_private_key(private_key, data: bytes):
    signer = private_key.sign(
        data,
        asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return base64.b64encode(signer).decode('utf-8')

def verify_signature(public_key, data: bytes, b64_signature: str):
    sig = base64.b64decode(b64_signature)
    try:
        public_key.verify(
            sig,
            data,
            asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# encryption and decryption :
  
# encrypt the vote data info with sym key
# encrypt the sym key with rsa pub key
# decrypts the sym key with rsa private key
# decrypts the vote data with sym key
# with this it main confidentiality(secure,nobody can see the data infos)
# aes + rsa
# Public → encrypt, Private → decrypt

# Digi Sign
# encrypt the vote data info with sym key
# hash the encrypted vote
# sign the hash with private key 
# for verification uses, public key, check if matches with the hash
# integrity(data edited?) & authenticity(u sent?)
# hash + rsa-pss
# Public → encrypt, Private → decrypt