import socket
import argparse

def scan_port(host, port):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((host, port))
    except:
        return False
    else:
        sock.close()
        return True

def main():
    parser = argparse.ArgumentParser(description="Simple Vulnerability Scanner")
    parser.add_argument("host", help="Target host to scan")
    args = parser.parse_args()

    host = args.host
    common_ports = [22, 80, 443, 3389]

    print(f"Scanning {host} for common open ports...")
    for port in common_ports:
        if scan_port(host, port):
            print(f"[+] Port {port} is OPEN")
        else:
            print(f"[-] Port {port} is closed")

if __name__ == "__main__":
    main()
