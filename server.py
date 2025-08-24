# client.py
import socket
from sec import process_inbound, prepare_outbound

HOST = "127.0.0.1"  # change to server IP if needed
PORT = 9999

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print(f"[Client] Connected to {HOST}:{PORT}")
    while True:
        text = input("[Client > ] ").strip()
        if not text:
            text = "(empty)"
        s.sendall(prepare_outbound(text))
        data = s.recv(65536)
        if not data:
            break
        try:
            msg = process_inbound(data)
            print(f"[Server]: {msg}")
        except Exception as e:
            print(f"[Client] Security error: {e}")

import socket

HOST = '127.0.0.1'   # Localhost (same machine)
PORT = 5555          # Free port (can be any unused number)

# Create socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind and listen
server.bind((HOST, PORT))
server.listen()

print(f"✅ Server started. Listening on {HOST}:{PORT}")

# Accept client connection
conn, addr = server.accept()
print(f"🔗 Connected by {addr}")

while True:
    data = conn.recv(1024).decode()
    if not data:
        break
    print(f"Client: {data}")

    msg = input("You: ")
    conn.send(msg.encode())

conn.close()
