# 📄 Report – Secure Chat Application (Python Sockets + Crypto)

## 1. Objective  
The goal of this project is to build a *secure chat application* using Python sockets, where two processes (Client ↔ Server) can exchange messages with *confidentiality, integrity, and authentication* guaranteed.  

---

## 2. System Design  

### Components
- *Client* (client.py)  
  - Connects to the server.  
  - Encrypts and signs outgoing messages.  
  - Decrypts and verifies incoming messages.  

- *Server* (server.py)  
  - Waits for connections.  
  - Decrypts and verifies incoming messages.  
  - Encrypts and signs responses.  

- *Crypto Helper* (sec.py)  
  - Handles *key derivation, **encryption/decryption, **SHA-512 integrity check, and **HMAC authentication*.  

---

## 3. Security Features  

1. *Confidentiality*  
   - Achieved using *Fernet symmetric encryption* (AES + CBC + HMAC internally).  
   - Ensures messages cannot be read by an attacker.  

2. *Integrity*  
   - Each plaintext message is hashed with *SHA-512* before encryption.  
   - After decryption, the hash is recomputed and verified.  

3. *Authentication*  
   - Each ciphertext is protected by an *HMAC (SHA-512)*.  
   - Prevents attackers from tampering or injecting fake messages.  

---

## 4. Implementation Flow  

### Sending a Message
1. User enters plaintext.  
2. A *SHA-512 hash* of the plaintext is computed.  
3. JSON object {msg, sha512} is created.  
4. JSON is encrypted with *Fernet (AES)*.  
5. HMAC-SHA512 is computed over the ciphertext.  
6. Final packet = HMAC + Ciphertext.  

### Receiving a Message
1. Split received packet into HMAC and Ciphertext.  
2. Verify HMAC with the shared secret key.  
   - If fails → reject message.  
3. Decrypt ciphertext to get JSON {msg, sha512}.  
4. Recompute SHA-512 over msg and compare with received hash.  
   - If mismatch → reject message.  
5. Deliver plaintext to user.  

---

## 5. Execution Instructions  

### Requirements
- Python 3.10+  
- cryptography library  

### Setup
```bash
git clone https://github.com/<your-username>/Secure-chat-app.git
cd Secure-chat-app
python -m venv .venv
source .venv/bin/activate   # (Linux/Mac)
. .venv\Scripts\Activate.ps1  # (Windows)
pip install -r requirements.txt
