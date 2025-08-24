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
