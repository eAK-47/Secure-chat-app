# 🔒 Secure Chat Application (Python Sockets + Crypto)

Two-process chat (Client ↔ Server) with:
- *Confidentiality*: symmetric encryption (Fernet/AES)
- *Integrity: **SHA-512* over plaintext (verified after decrypt)
- *Authentication: **HMAC-SHA512* over ciphertext

## Quick start
```bash
git clone https://github.com/<your-username>/secure-chat-app.git
cd secure-chat-app
python -m venv .venv
# Windows: . .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

# Set the same passphrase on both client and server terminals:
# PowerShell
$env:SHARED_PASSPHRASE="change-this-strong-secret"
# bash/zsh
export SHARED_PASSPHRASE="change-this-strong-secret"

# Terminal 1
python server.py
# Terminal 2 (change HOST in client.py if server is remote)
python client.py
