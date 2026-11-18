"""
Secure FTP-like Server with Encrypted Transfer
Syllabus Project – Secure LAN File Transfer

Features:
- User login with hashed passwords
- SSL/TLS encrypted channel
- Commands: LIST, UPLOAD, DOWNLOAD, MKDIR, DELETE, QUIT
- Audit log of all operations
"""

import socket
import ssl
import threading
import os
import hashlib
import json
import logging
import datetime
import shutil
from pathlib import Path

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR      = Path(__file__).parent
SERVER_FILES  = BASE_DIR / "server_files"   # file storage root
CERT_FILE     = BASE_DIR / "certs" / "server.crt"
KEY_FILE      = BASE_DIR / "certs" / "server.key"
USERS_FILE    = BASE_DIR / "users.json"
AUDIT_LOG     = BASE_DIR / "audit.log"

SERVER_HOST   = "0.0.0.0"
SERVER_PORT   = 9000
BUFFER_SIZE   = 4096

# ─── Logging / Audit ──────────────────────────────────────────────────────────
logging.basicConfig(
    filename=AUDIT_LOG,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger("").addHandler(console)

def audit(user: str, action: str, detail: str = "", addr: str = ""):
    msg = f"USER={user:<12} ACTION={action:<10} {detail}"
    if addr:
        msg += f" [from {addr}]"
    logging.info(msg)


# ─── User Management ──────────────────────────────────────────────────────────
def load_users() -> dict:
    if USERS_FILE.exists():
        with open(USERS_FILE) as f:
            return json.load(f)
    return {}

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def authenticate(username: str, password: str) -> bool:
    users = load_users()
    return users.get(username) == hash_password(password)


# ─── Client Handler ───────────────────────────────────────────────────────────
class ClientHandler(threading.Thread):
    def __init__(self, conn: ssl.SSLSocket, addr):
        super().__init__(daemon=True)
        self.conn   = conn
        self.addr   = f"{addr[0]}:{addr[1]}"
        self.user   = None
        self.cwd    = SERVER_FILES   # current working dir (server-side)

    # helpers
    def send(self, msg: str):
        self.conn.sendall((msg + "\r\n").encode())

    def recv(self) -> str:
        data = b""
        while not data.endswith(b"\n"):
            chunk = self.conn.recv(BUFFER_SIZE)
            if not chunk:
                break
            data += chunk
        return data.decode().strip()

    # ── login sequence ────────────────────────────────────────────────────────
    def do_login(self) -> bool:
        self.send("220 Secure-FTP Server Ready. Enter username:")
        username = self.recv()
        self.send("331 Password required. Enter password:")
        password = self.recv()
        if authenticate(username, password):
            self.user = username
            # each user gets their own directory
            user_dir = SERVER_FILES / username
            user_dir.mkdir(parents=True, exist_ok=True)
            self.cwd = user_dir
            self.send("230 Login successful.")
            audit(username, "LOGIN", "SUCCESS", self.addr)
            return True
        else:
            self.send("530 Login failed.")
            audit(username or "?", "LOGIN", "FAILED", self.addr)
            return False

    # ── command dispatch ──────────────────────────────────────────────────────
    def handle_list(self, _arg):
        entries = []
        for p in sorted(self.cwd.iterdir()):
            kind = "DIR " if p.is_dir() else "FILE"
            size = p.stat().st_size if p.is_file() else 0
            entries.append(f"  {kind}  {p.name:<40}  {size:>12} bytes")
        if entries:
            listing = "\n".join(entries)
        else:
            listing = "  (empty)"
        self.send(f"150 Directory listing:\n{listing}\n250 Done.")
        audit(self.user, "LIST", str(self.cwd))

    def handle_upload(self, filename):
        if not filename:
            self.send("501 Filename required.")
            return
        dest = self.cwd / Path(filename).name
        self.send(f"150 Ready to receive '{filename}'. Send file size then data.")
        # receive file size
        try:
            size = int(self.recv())
        except ValueError:
            self.send("501 Invalid file size.")
            return
        self.send("150 Send data now.")
        received = 0
        with open(dest, "wb") as f:
            while received < size:
                chunk = self.conn.recv(min(BUFFER_SIZE, size - received))
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)
        self.send(f"226 Upload complete. {received} bytes received.")
        audit(self.user, "UPLOAD", f"file={dest.name} size={received}")

    def handle_download(self, filename):
        if not filename:
            self.send("501 Filename required.")
            return
        src = self.cwd / Path(filename).name
        if not src.exists() or not src.is_file():
            self.send("550 File not found.")
            audit(self.user, "DOWNLOAD", f"FAILED file={filename}")
            return
        size = src.stat().st_size
        self.send(f"150 Sending '{src.name}' ({size} bytes).")
        # wait for client ready signal
        self.recv()
        with open(src, "rb") as f:
            sent = 0
            while chunk := f.read(BUFFER_SIZE):
                self.conn.sendall(chunk)
                sent += len(chunk)
        self.send(f"226 Download complete. {sent} bytes sent.")
        audit(self.user, "DOWNLOAD", f"file={src.name} size={sent}")

    def handle_mkdir(self, dirname):
        if not dirname:
            self.send("501 Directory name required.")
            return
        new_dir = self.cwd / dirname
        new_dir.mkdir(parents=True, exist_ok=True)
        self.send(f"257 Directory '{dirname}' created.")
        audit(self.user, "MKDIR", dirname)

    def handle_delete(self, name):
        if not name:
            self.send("501 Name required.")
            return
        target = self.cwd / name
        if not target.exists():
            self.send("550 Not found.")
            return
        if target.is_file():
            target.unlink()
        else:
            shutil.rmtree(target)
        self.send(f"250 '{name}' deleted.")
        audit(self.user, "DELETE", name)

    def handle_pwd(self, _arg):
        rel = self.cwd.relative_to(SERVER_FILES)
        self.send(f"257 /{rel}")

    def handle_cwd(self, dirname):
        if not dirname:
            self.send("501 Directory name required.")
            return
        if dirname == "..":
            if self.cwd != SERVER_FILES / self.user:
                self.cwd = self.cwd.parent
        else:
            target = self.cwd / dirname
            if target.exists() and target.is_dir():
                self.cwd = target
            else:
                self.send("550 Directory not found.")
                return
        self.send(f"250 Changed to /{self.cwd.relative_to(SERVER_FILES)}")

    # ── main loop ─────────────────────────────────────────────────────────────
    def run(self):
        try:
            if not self.do_login():
                return
            self.send("214 Commands: LIST UPLOAD DOWNLOAD MKDIR DELETE PWD CWD QUIT HELP")
            COMMANDS = {
                "LIST":     self.handle_list,
                "UPLOAD":   self.handle_upload,
                "DOWNLOAD": self.handle_download,
                "MKDIR":    self.handle_mkdir,
                "DELETE":   self.handle_delete,
                "PWD":      self.handle_pwd,
                "CWD":      self.handle_cwd,
            }
            while True:
                raw = self.recv()
                if not raw:
                    break
                parts = raw.split(None, 1)
                cmd   = parts[0].upper()
                arg   = parts[1] if len(parts) > 1 else ""

                if cmd == "QUIT":
                    self.send("221 Goodbye.")
                    audit(self.user, "QUIT", "", self.addr)
                    break
                elif cmd == "HELP":
                    self.send("214 Commands: LIST UPLOAD DOWNLOAD MKDIR DELETE PWD CWD QUIT")
                elif cmd in COMMANDS:
                    COMMANDS[cmd](arg)
                else:
                    self.send(f"502 Unknown command '{cmd}'.")
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError) as e:
            logging.warning(f"Connection lost from {self.addr}: {e}")
        finally:
            self.conn.close()


# ─── Server Bootstrap ─────────────────────────────────────────────────────────
def run_server():
    SERVER_FILES.mkdir(exist_ok=True)

    if not CERT_FILE.exists() or not KEY_FILE.exists():
        print("[!] TLS certificates not found. Run:  python setup.py  first.")
        return

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_sock:
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind((SERVER_HOST, SERVER_PORT))
        raw_sock.listen(5)
        with ctx.wrap_socket(raw_sock, server_side=True) as srv:
            print(f"[*] Secure-FTP Server listening on port {SERVER_PORT} (TLS)")
            print(f"[*] Files stored in: {SERVER_FILES}")
            print(f"[*] Audit log: {AUDIT_LOG}")
            while True:
                conn, addr = srv.accept()
                print(f"[+] Connection from {addr[0]}:{addr[1]}")
                ClientHandler(conn, addr).start()

if __name__ == "__main__":
    run_server()

