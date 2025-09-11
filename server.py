# server.py
import socket
from sec import process_inbound, prepare_outbound

HOST = "0.0.0.0"#listens all avai network
PORT = 9999#random port is good


def recv_all(conn):
    # naive framing:--read whats available its a limitation no sturctred way
    chunk = conn.recv(65536)
    return chunk


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:#AF_INET--for ipv4 addressing,sock_stream--tcp
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[Server] Listening on {HOST}:{PORT}")
    conn, addr = s.accept()
    with conn:
        print(f"[Server] Connected by {addr}")
        while True:
            data = recv_all(conn)
            if not data:
                break
            try:
                msg = process_inbound(data)#where we check keys and all for security
                print(f"[Client]: {msg}")
            except Exception as e:
                print(f"[Server] Security error: {e}")
                continue
            # respond
            out = input("[Server > ] ").strip()
            if not out:
                out = "(empty)"
            conn.sendall(prepare_outbound(out))# ensure full secure message is transffered

