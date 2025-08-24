# sec.py
import os, json, base64, hmac, hashlib
from typing import Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Derive two keys from a passphrase so you don't store secrets in Git.
# Set env var: SHARED_PASSPHRASE="something-strong-same-on-both-sides"
# WARNING: For coursework/demo only. Use a random per-deploy salt in real systems.
SALT = b"demo-static-salt-change-me"

def _derive_keys(passphrase: str) -> Tuple[Fernet, bytes]:
    if not passphrase:
        raise ValueError("Set SHARED_PASSPHRASE env var on both client and server")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,           # 32 bytes for Fernet key, 32 for HMAC key
        salt=SALT,
        iterations=200_000,
    )
    raw = kdf.derive(passphrase.encode())
    enc_key = base64.urlsafe_b64encode(raw[:32])  # Fernet expects base64 key
    hmac_key = raw[32:]
    return Fernet(enc_key), hmac_key

def get_crypto():
    return _derive_keys(os.getenv("SHARED_PASSPHRASE", ""))

def prepare_outbound(plaintext: str) -> bytes:
    """Return bytes: HMAC(sha512) || CIPHERTEXT
    - Compute sha512 of plaintext
    - Build JSON {msg, sha512}
    - Encrypt JSON with Fernet (AES128-CBC + HMAC-SHA256 inside Fernet)
    - Compute external HMAC-SHA512 over ciphertext (assignment requirement)
    - Send HMAC(hex, 128 bytes) + ciphertext
    """
    cipher, hkey = get_crypto()
    sha = hashlib.sha512(plaintext.encode()).hexdigest()
    blob = json.dumps({"msg": plaintext, "sha512": sha}).encode()
    ciph = cipher.encrypt(blob)
    tag = hmac.new(hkey, ciph, hashlib.sha512).hexdigest().encode()  # 128-byte hex
    return tag + ciph

def process_inbound(packet: bytes) -> str:
    """Verify HMAC, decrypt, and verify inner SHA-512 integrity."""
    cipher, hkey = get_crypto()
    recv_tag, ciph = packet[:128], packet[128:]   # first 128 bytes is hex HMAC
    calc_tag = hmac.new(hkey, ciph, hashlib.sha512).hexdigest().encode()
    if not hmac.compare_digest(recv_tag, calc_tag):
        raise ValueError("HMAC verification failed (message not authentic)")
    blob = cipher.decrypt(ciph)
    obj = json.loads(blob.decode())
    msg = obj["msg"]
    sha_ok = hashlib.sha512(msg.encode()).hexdigest()
    if sha_ok != obj["sha512"]:
        raise ValueError("SHA-512 integrity check failed")
    return msg
