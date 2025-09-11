# sec.py
# Security layer used by client.py and server.py
# - Derives keys from a shared passphrase (PBKDF2)
# - Encrypts messages (Fernet)
# - Adds HMAC-SHA512 over ciphertext
# - Adds SHA-512 of plaintext inside encrypted payload for integrity

import os, json, base64, hmac, hashlib
from typing import Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ----------------------
# WARNING: demo-only salt.

# ----------------------
SALT = b"demo-static-salt-change-me"

def _derive_keys(passphrase: str) -> Tuple[Fernet, bytes]:
    """
    Derive two keys from a passphrase:
      - 32 bytes -> Fernet (base64-encoded)
      - 32 bytes -> HMAC-SHA512 key
    """
    if not passphrase:
        raise ValueError("Set SHARED_PASSPHRASE env var on both client and server")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,           # 32 bytes for Fernet key, 32 for HMAC key
        salt=SALT,
        iterations=200_000,
    )
    raw = kdf.derive(passphrase.encode())
    enc_key = base64.urlsafe_b64encode(raw[:32])  # Fernet expects base64-key
    hmac_key = raw[32:]
    return Fernet(enc_key), hmac_key

def get_crypto():
    """Read passphrase from env var and derive keys."""
    return _derive_keys(os.getenv("SHARED_PASSPHRASE", ""))

def prepare_outbound(plaintext: str) -> bytes:
    """
    Prepare secure outbound bytes:
      - compute SHA-512(plaintext)
      - build JSON {msg, sha512}
      - encrypt JSON using Fernet (provides AES + internal HMAC)
      - compute external HMAC-SHA512 over ciphertext (assignment requirement)
      - return: HMAC_HEX(128 bytes) || ciphertext
    """
    cipher, hkey = get_crypto()

    # SHA-512 for plaintext integrity (kept inside encrypted blob)
    sha = hashlib.sha512(plaintext.encode()).hexdigest()
    blob = json.dumps({"msg": plaintext, "sha512": sha}).encode()

    # Encrypt the JSON blob
    ciph = cipher.encrypt(blob)

    # Compute external HMAC-SHA512 over ciphertext (hex string)
    tag = hmac.new(hkey, ciph, hashlib.sha512).hexdigest().encode()  # 128 bytes hex
    return tag + ciph

def process_inbound(packet: bytes) -> str:
    """
    Process inbound packet:
      - split HMAC (first 128 bytes) and ciphertext
      - verify HMAC (authenticity)
      - decrypt ciphertext (confidentiality)
      - verify inner SHA-512 (integrity)
      - return plaintext message
    """
    cipher, hkey = get_crypto()
    recv_tag, ciph = packet[:128], packet[128:]

    # Verify external HMAC
    calc_tag = hmac.new(hkey, ciph, hashlib.sha512).hexdigest().encode()
    if not hmac.compare_digest(recv_tag, calc_tag):
        raise ValueError("HMAC verification failed (message not authentic)")

    # Decrypt and parse JSON
    blob = cipher.decrypt(ciph)
    obj = json.loads(blob.decode())
    msg = obj["msg"]

    # Verify inner SHA-512
    sha_ok = hashlib.sha512(msg.encode()).hexdigest()
    if sha_ok != obj["sha512"]:
        raise ValueError("SHA-512 integrity check failed")

    return msg
