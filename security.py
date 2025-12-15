import os
import json
import bcrypt
import secrets
from hashlib import pbkdf2_hmac
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet, InvalidToken

VAULT_FILE = "vault.enc"
MASTER_FILE = "master.hash"
SALT_FILE = "salt.bin"

PBKDF2_ITERATIONS = 200_000
KEY_LENGTH = 32

# ---------------------------
# Salt handling
# ---------------------------
def ensure_salt():
    if not os.path.exists(SALT_FILE):
        salt = secrets.token_bytes(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        return salt
    with open(SALT_FILE, "rb") as f:
        return f.read()

# ---------------------------
# PBKDF2 Key Derivation
# ---------------------------
def derive_key_pbkdf2(master_password: str, salt: bytes) -> bytes:
    key = pbkdf2_hmac("sha256",
                      master_password.encode(),
                      salt,
                      PBKDF2_ITERATIONS,
                      dklen=KEY_LENGTH)
    return urlsafe_b64encode(key)

# ---------------------------
# Master password functions
# ---------------------------
def create_master_password(password: str):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    with open(MASTER_FILE, "wb") as f:
        f.write(hashed)

def verify_master_password(password: str) -> bool:
    if not os.path.exists(MASTER_FILE):
        return False
    with open(MASTER_FILE, "rb") as f:
        stored_hash = f.read()
    return bcrypt.checkpw(password.encode(), stored_hash)

# ---------------------------
# Vault encryption/decryption
# ---------------------------
def encrypt_data(key: bytes, data: dict) -> bytes:
    f = Fernet(key)
    return f.encrypt(json.dumps(data).encode())

def decrypt_data(key: bytes, encrypted: bytes) -> dict:
    f = Fernet(key)
    decrypted = f.decrypt(encrypted)
    return json.loads(decrypted.decode())

def load_vault(key: bytes) -> dict:
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, "rb") as f:
        encrypted = f.read()
    try:
        return decrypt_data(key, encrypted)
    except InvalidToken:
        raise ValueError("Vault integrity failed or incorrect key.")

def save_vault(key: bytes, vault: dict):
    encrypted = encrypt_data(key, vault)
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)

# Make sure all functions are available
__all__ = [
    'ensure_salt',
    'derive_key_pbkdf2',
    'create_master_password',
    'verify_master_password',
    'load_vault',
    'save_vault'
]