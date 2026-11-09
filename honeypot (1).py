#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Honeypot
Coded by: Cyber Security Engineer Mr. Sabaz Ali Khan

A lightweight, multi-service low-interaction honeypot. It listens on fake
SSH / FTP / Telnet / HTTP ports, presents believable banners, captures
login attempts and payloads, and logs everything for analysis.

It NEVER executes anything the attacker sends. All data is only logged.

Use only on networks and systems you own or are authorised to monitor.

Usage:
    python3 honeypot.py                       # default safe ports (2222, 2121, 2323, 8080)
    python3 honeypot.py --ports 22,21,23,80   # real ports (needs root/admin)
    python3 honeypot.py --host 0.0.0.0 --log-dir ./logs
"""

import argparse
import json
import os
import socket
import threading
import time
from datetime import datetime, timezone

BANNER = r"""
⠀⠀⠀⠀⢿⣟⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢸⣿⢾⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣿⣼⣇⠀⠀⠀⠀⢀⢠⣤⣄⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢀⣤⣄⣿⡿⢿⠀⢠⣲⡜⠢⢘⣿⣟⣠⠑⢴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠘⣿⡟⣷⡟⣾⡄⠻⣿⣷⣾⡛⢳⡛⠛⣷⣾⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣿⣿⣽⣻⣻⣷⡂⠹⣿⡟⠚⣿⣗⠒⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠔⠀
⠀⠀⠀⠉⢩⣿⣿⣿⢿⣷⡀⡸⣿⣬⣝⡛⣯⣻⠀⠀⠀⠀⠀⠀⠀⢀⠊⠀⠀
⠀⠀⠀⣤⣷⣟⡿⣻⣿⣿⣋⣗⣿⣮⠛⢿⢿⣳⣂⡀⠀⠀⠀⠀⢀⠂⠀⠀⠀
⠀⠀⢸⣿⣿⡿⡇⡿⣽⣏⣥⣬⢿⣏⡿⢛⣚⡛⢾⣙⣑⣢⠼⡏⠕⢄⠀⠀⠀
⠀⠀⢈⣿⠉⢀⣼⣧⡝⢏⢻⡜⣼⠒⢢⠃⠠⣬⠟⣧⢫⣣⣳⣻⠀⠸⠀⠀⠀
⠀⠀⢸⠿⡴⢟⣾⣿⣿⡷⣞⣿⣿⣁⣨⣖⡊⢡⢞⣿⣗⣿⠫⣼⠰⢢⠄⠀⠀
⠀⠀⢨⢞⣾⠯⣿⣯⣿⣷⣧⢩⣿⠿⠛⣽⣟⣁⢸⣿⣛⣷⠀⢉⣧⠛⠀⠀⠀
⠀⠀⢸⣞⣩⢠⣿⡇⣿⢣⣿⢬⣿⡷⠿⢵⠋⠿⣿⣿⡿⡿⡳⣾⡿⠏⠄⠀⠀
⠀⠀⠻⣽⣼⣿⣿⣷⣷⣸⢻⣾⣿⣍⣥⣜⡁⣮⣎⢬⡿⢿⣗⡛⣿⣛⡀⠀⠀
⠐⣶⣶⣼⣿⣿⣿⣯⣿⣋⢿⢼⡿⣅⢸⡜⡟⢽⣯⣽⣃⢛⣿⢳⢿⣹⣣⠀⠀
⠀⠒⠒⠛⠛⠿⠿⠛⡏⣹⣸⣾⣻⣻⢟⢹⢯⣿⠧⠾⣾⣿⣿⣿⣝⡆⢻⡂⠀
⠀⠀⠀⠀⠀⠀⠀⢰⣿⣟⣝⣻⣿⣿⣿⠿⣝⣒⣢⠤⢤⣾⣿⣿⣿⣧⣈⣅⠀
⠀⠀⠀⠀⠀⠀⠀⠸⣿⢸⣿⣿⣿⣿⣿⢫⠿⣾⣭⣿⣿⣿⣿⣿⣿⠿⢿⣳⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⣿⣿⣫⡗⣺⣿⡗⣟⢛⣿⢿⡏⠟⣿⣰⣳⡶⢬⠆
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣌⡿⣹⡾⢿⣿⣷⢿⡾⠧⡚⣷⣍⢿⢉⡋⣠⠘⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣾⡟⣩⢞⣽⣹⣧⣵⣟⠋⢩⣹⣦⣿⣏⣾⣑⣀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠽⢿⢷⣀⣉⡿⢿⣿⣮⣋⢍⡽⢿⠟⢱⣿⠆⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⡿⢶⣷⣾⠲⡿⣇⡆⠈⢿⣿⣏⣿⣴⡖⣿⡭⠁⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣟⣻⣟⡒⠚⠉⡟⢇⡄⠘⣿⣿⣿⣋⣿⣿⡗⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣻⣧⡗⢿⣿⡟⣁⠌⠁⢻⣿⣿⣯⣇⣼⡗⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠂⢘⣿⣿⣿⣷⣿⣁⣒⠀⠀⠀⢿⣿⣿⣿⣿⡇⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⡜⣾⣿⣿⣿⠁⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⠋⠀⠄⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢠⠇⣹⢿⣿⠇⡆⠀⠀⠀⠀⠀⣿⣿⡿⣯⡬⡇⠲⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣸⠸⡅⢿⢿⠀⡇⠀⠀⠀⠄⣤⣿⣿⣧⠏⢰⢃⠀⡄⠀
"""

CREDIT = (
    "  ╔══════════════════════════════════════════════════════╗\n"
    "  ║            NETWORK  HONEYPOT  v1.0                   ║\n"
    "  ║   Coded by Cyber Security Engineer                   ║\n"
    "  ║              Mr. Sabaz Ali Khan                      ║\n"
    "  ╚══════════════════════════════════════════════════════╝\n"
)

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
SERVICES = {
    # port: (service name, banner sent on connect)
    2222: ("ssh", b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n"),
    2121: ("ftp", b"220 FTP server (vsftpd 3.0.3) ready.\r\n"),
    2323: ("telnet", b"\r\nUbuntu 18.04.6 LTS\r\n"),
    8080: ("http", b""),
}
# Map for real/standard ports so --ports 22,21,23,80 keeps the right behaviour
STANDARD_PORT_SERVICE = {22: "ssh", 21: "ftp", 23: "telnet", 80: "http",
                         8080: "http", 2222: "ssh", 2121: "ftp", 2323: "telnet"}
SERVICE_BANNERS = {
    "ssh": b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n",
    "ftp": b"220 FTP server (vsftpd 3.0.3) ready.\r\n",
    "telnet": b"\r\nUbuntu 18.04.6 LTS\r\n",
    "http": b"",
}

MAX_BYTES_PER_CONN = 4096       # never read more than this per connection
CONN_TIMEOUT = 15               # seconds of inactivity before closing
MAX_CONCURRENT = 100            # global concurrent connection limit

FAKE_HTTP_PAGE = (
    b"<html><head><title>Router Login</title></head><body>"
    b"<h2>Administration Panel</h2>"
    b"<form method='POST' action='/login'>"
    b"User: <input name='user'><br>Pass: <input type='password' name='pass'><br>"
    b"<input type='submit' value='Login'></form></body></html>"
)

_log_lock = threading.Lock()
_conn_slots = threading.BoundedSemaphore(MAX_CONCURRENT)


# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------
class Logger:
    def __init__(self, log_dir):
        os.makedirs(log_dir, exist_ok=True)
        self.text_path = os.path.join(log_dir, "honeypot.log")
        self.json_path = os.path.join(log_dir, "events.jsonl")

    def event(self, kind, src_ip, src_port, service, dst_port, **data):
        record = {
            "time": datetime.now(timezone.utc).isoformat(),
            "event": kind,
            "src_ip": src_ip,
            "src_port": src_port,
            "service": service,
            "dst_port": dst_port,
        }
        record.update(data)
        line = (f"[{record['time']}] {kind.upper():<10} "
                f"{src_ip}:{src_port} -> {service}/{dst_port}  "
                + " ".join(f"{k}={v!r}" for k, v in data.items()))
        with _log_lock:
            print(line, flush=True)
            with open(self.text_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            with open(self.json_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def safe_text(raw: bytes, limit=300) -> str:
    """Printable, length-limited representation of attacker-supplied bytes."""
    text = raw.decode("utf-8", errors="replace")
    text = "".join(ch if ch.isprintable() else "." for ch in text)
    return text[:limit]


def read_line(conn, budget):
    """Read one CRLF/LF terminated line, bounded by the remaining byte budget."""
    buf = b""
    while len(buf) < budget["left"]:
        chunk = conn.recv(1)
        if not chunk:
            break
        budget["left"] -= 1
        if chunk in (b"\n",):
            break
        buf += chunk
    return buf.strip(b"\r\n")


# ----------------------------------------------------------------------------
# Service handlers (all low-interaction: nothing is ever executed)
# ----------------------------------------------------------------------------
def handle_ssh(conn, addr, port, log, budget):
    conn.sendall(SERVICE_BANNERS["ssh"])
    data = conn.recv(min(1024, budget["left"]))
    if data:
        log.event("data", addr[0], addr[1], "ssh", port, client_banner=safe_text(data))


def handle_ftp(conn, addr, port, log, budget):
    conn.sendall(SERVICE_BANNERS["ftp"])
    user = None
    while budget["left"] > 0:
        line = read_line(conn, budget)
        if not line:
            break
        cmd, _, arg = line.decode("utf-8", "replace").partition(" ")
        cmd = cmd.upper()
        if cmd == "USER":
            user = arg
            conn.sendall(b"331 Please specify the password.\r\n")
        elif cmd == "PASS":
            log.event("login", addr[0], addr[1], "ftp", port,
                      username=safe_text(user.encode() if user else b""),
                      password=safe_text(arg.encode()))
            conn.sendall(b"530 Login incorrect.\r\n")
        elif cmd == "QUIT":
            conn.sendall(b"221 Goodbye.\r\n")
            break
        else:
            log.event("command", addr[0], addr[1], "ftp", port, cmd=safe_text(line))
            conn.sendall(b"530 Please login with USER and PASS.\r\n")


def handle_telnet(conn, addr, port, log, budget):
    conn.sendall(SERVICE_BANNERS["telnet"])
    for _ in range(3):  # three login attempts, then disconnect
        conn.sendall(b"login: ")
        user = read_line(conn, budget)
        if not user:
            return
        conn.sendall(b"Password: ")
        pwd = read_line(conn, budget)
        log.event("login", addr[0], addr[1], "telnet", port,
                  username=safe_text(user), password=safe_text(pwd))
        time.sleep(1)  # slow brute-forcers down a little
        conn.sendall(b"\r\nLogin incorrect\r\n")


def handle_http(conn, addr, port, log, budget):
    data = conn.recv(min(MAX_BYTES_PER_CONN, budget["left"]))
    if not data:
        return
    head, _, body = data.partition(b"\r\n\r\n")
    request_line = safe_text(head.split(b"\r\n", 1)[0])
    headers = safe_text(head, 600)
    ua = ""
    for h in head.split(b"\r\n")[1:]:
        if h.lower().startswith(b"user-agent:"):
            ua = safe_text(h.split(b":", 1)[1].strip())
    log.event("request", addr[0], addr[1], "http", port,
              request=request_line, user_agent=ua,
              body=safe_text(body), headers=headers)
    response = (b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.29 (Ubuntu)\r\n"
                b"Content-Type: text/html\r\nContent-Length: "
                + str(len(FAKE_HTTP_PAGE)).encode() + b"\r\nConnection: close\r\n\r\n"
                + FAKE_HTTP_PAGE)
    conn.sendall(response)


HANDLERS = {"ssh": handle_ssh, "ftp": handle_ftp,
            "telnet": handle_telnet, "http": handle_http}


# ----------------------------------------------------------------------------
# Server core
# ----------------------------------------------------------------------------
def client_thread(conn, addr, port, service, log):
    if not _conn_slots.acquire(blocking=False):
        conn.close()
        return
    try:
        conn.settimeout(CONN_TIMEOUT)
        log.event("connect", addr[0], addr[1], service, port)
        budget = {"left": MAX_BYTES_PER_CONN}
        HANDLERS[service](conn, addr, port, log, budget)
    except (socket.timeout, ConnectionError, OSError):
        pass
    except Exception as exc:  # never let a bad client crash the honeypot
        log.event("error", addr[0], addr[1], service, port, error=repr(exc))
    finally:
        try:
            conn.close()
        except OSError:
            pass
        log.event("disconnect", addr[0], addr[1], service, port)
        _conn_slots.release()


def listener(host, port, service, log, stop):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
    except OSError as exc:
        print(f"[!] Cannot bind {host}:{port} ({service}): {exc}")
        return
    srv.listen(50)
    srv.settimeout(1.0)
    print(f"[+] Listening on {host}:{port}  ({service})")
    while not stop.is_set():
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=client_thread,
                         args=(conn, addr, port, service, log),
                         daemon=True).start()
    srv.close()


def parse_ports(value):
    ports = []
    for p in value.split(","):
        p = int(p.strip())
        if not 1 <= p <= 65535:
            raise argparse.ArgumentTypeError(f"invalid port {p}")
        ports.append(p)
    return ports


def main():
    ap = argparse.ArgumentParser(description="Network Honeypot by Mr. Sabaz Ali Khan")
    ap.add_argument("--host", default="0.0.0.0", help="interface to bind (default 0.0.0.0)")
    ap.add_argument("--ports", type=parse_ports, default=[2222, 2121, 2323, 8080],
                    help="comma separated ports (default 2222,2121,2323,8080)")
    ap.add_argument("--log-dir", default="honeypot_logs", help="directory for log files")
    args = ap.parse_args()

    print(BANNER)
    print(CREDIT)

    log = Logger(args.log_dir)
    stop = threading.Event()
    threads = []
    for port in args.ports:
        service = STANDARD_PORT_SERVICE.get(port)
        if service is None:
            print(f"[!] Port {port} has no known service profile, defaulting to telnet.")
            service = "telnet"
        t = threading.Thread(target=listener, args=(args.host, port, service, log, stop),
                             daemon=True)
        t.start()
        threads.append(t)

    print(f"[*] Logs: {log.text_path} and {log.json_path}")
    print("[*] Press Ctrl+C to stop.\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down honeypot...")
        stop.set()
        for t in threads:
            t.join(timeout=2)


if __name__ == "__main__":
    main()
