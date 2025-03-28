import socket
import threading
import time
from collections import defaultdict
import logging
import random

# Configuration
HONEYPOT_PORTS = {
    22: 'SSH',
    80: 'HTTP',
    21: 'FTP'
}
LOG_FILE = 'honeypot_log.txt'
attack_log = []
FAKE_BANNERS = {
    22: "SSH-2.0-OpenSSH_7.4\n",
    80: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.1 (Unix)\r\n\r\n<html><body><h1>It works!</h1></body></html>",
    21: "220 (vsFTPd 3.0.3)\r\n"
}

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

def log_attempt(ip, port, data):
    entry = f"Connection from {ip} on port {port} (service: {HONEYPOT_PORTS.get(port, 'Unknown')}): {data}"
    print(entry)
    logging.info(entry)
    attack_log.append((ip, port, data))

def send_fake_response(client_socket, port):
    banner = FAKE_BANNERS.get(port, "Service Ready\n")
    client_socket.send(banner.encode())

def handle_connection(client_socket, address, port):
    try:
        client_socket.settimeout(10)
        send_fake_response(client_socket, port)
        data = client_socket.recv(1024).decode(errors='ignore')
        if not data:
            data = '<No Data>'
        log_attempt(address[0], port, data.strip())
        client_socket.send(b"Access Denied\n")
    except socket.timeout:
        log_attempt(address[0], port, '<Timeout>')
    except Exception as e:
        logging.error(f"Error handling connection from {address[0]} on port {port}: {e}")
    finally:
        client_socket.close()

def honeypot_listener(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    print(f"[+] Listening on port {port} ({HONEYPOT_PORTS.get(port, 'Unknown')})")

    while True:
        client_socket, address = server.accept()
        threading.Thread(target=handle_connection, args=(client_socket, address, port), daemon=True).start()

def analyze_attacks():
    ip_count = defaultdict(int)
    port_count = defaultdict(int)
    for ip, port, _ in attack_log:
        ip_count[ip] += 1
        port_count[port] += 1

    print("\n--- Honeypot Attack Summary ---")
    print("Top Source IPs:")
    for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip}: {count} attempts")

    print("\nPort Activity:")
    for port, count in sorted(port_count.items(), key=lambda x: x[1], reverse=True):
        print(f"Port {port} ({HONEYPOT_PORTS.get(port, 'Unknown')}): {count} attempts")

if __name__ == '__main__':
    try:
        for port in HONEYPOT_PORTS:
            threading.Thread(target=honeypot_listener, args=(port,), daemon=True).start()

        print("[*] Honeypot is running. Press Ctrl+C to stop and see analysis.")
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[!] Stopping honeypot and analyzing logs...")
        analyze_attacks()
