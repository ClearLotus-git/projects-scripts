import socket

HOST = "0.0.0.0"
PORT = 3389  # fake RDP port

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"[+] Honeyport listening on {PORT}")
    while True:
        conn, addr = s.accept()
        print(f"[ALERT] Connection attempt from {addr} on port {PORT}")
        conn.sendall(b"RDP negotiation failed.\n")  # fake banner
        conn.close()
