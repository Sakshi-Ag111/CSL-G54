"""
Secure FTP Client – interactive CLI
Connects to the Secure-FTP server over TLS and provides a shell-like interface.
"""

import socket
import ssl
import os
import sys
from pathlib import Path

BASE_DIR  = Path(__file__).parent
CERT_FILE = BASE_DIR / "certs" / "server.crt"   # server's self-signed cert (for verification)
BUFFER    = 4096

HELP_TEXT = """
╔══════════════════════════════════════════════╗
║        Secure-FTP Client Commands            ║
╠══════════════════════════════════════════════╣
║  LIST                – list remote files     ║
║  UPLOAD  <localfile> – upload a file         ║
║  DOWNLOAD <name>     – download a file       ║
║  MKDIR   <dirname>   – create directory      ║
║  DELETE  <name>      – delete file/dir       ║
║  PWD                 – print remote dir      ║
║  CWD     <dirname>   – change remote dir     ║
║  HELP                – show this help        ║
║  QUIT                – disconnect & exit     ║
╚══════════════════════════════════════════════╝
"""

class SecureFTPClient:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.conn: ssl.SSLSocket | None = None

    # ── connection ────────────────────────────────────────────────────────────
    def connect(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # Self-signed cert: disable hostname check, load cert only for encryption
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        if CERT_FILE.exists():
            try:
                ctx.load_verify_locations(CERT_FILE)
                ctx.verify_mode = ssl.CERT_REQUIRED
                print(f"[*] Using certificate: {CERT_FILE}")
            except ssl.SSLError:
                ctx.verify_mode = ssl.CERT_NONE
                print("[!] Could not load cert, running without verification.")
        else:
            print("[!] Warning: TLS certificate not verified (certs/server.crt not found).")

        raw = socket.create_connection((self.host, self.port))
        self.conn = ctx.wrap_socket(raw, server_hostname=self.host)
        print(f"[*] Connected to {self.host}:{self.port} (TLS {self.conn.version()})")

    # ── helpers ───────────────────────────────────────────────────────────────
    def send(self, msg: str):
        self.conn.sendall((msg + "\n").encode())

    def recv(self) -> str:
        data = b""
        while not data.endswith(b"\n"):
            chunk = self.conn.recv(BUFFER)
            if not chunk:
                break
            data += chunk
        return data.decode().strip()

    def recv_response(self) -> str:
        """Read one full server response (may span multiple lines ending with a 2xx/3xx/5xx line)."""
        lines = []
        self.conn.settimeout(10.0)
        try:
            while True:
                try:
                    chunk = self.conn.recv(BUFFER)
                except socket.timeout:
                    break
                if not chunk:
                    break
                lines.append(chunk.decode(errors="replace"))
                text = "".join(lines)
                # stop when last non-empty line starts with a 3-digit code
                last = text.rstrip().split("\n")[-1].strip()
                if len(last) >= 3 and last[:3].isdigit():
                    return text.strip()
        finally:
            self.conn.settimeout(None)
        return "".join(lines).strip()

    # ── login ─────────────────────────────────────────────────────────────────
    def login(self):
        # Server sends "220 ... Enter username:" in one message
        banner = self.recv_response()
        print(banner)
        username = input("Username: ").strip()
        self.send(username)

        # Server sends "331 Password required..."
        pw_prompt = self.recv_response()
        print(pw_prompt)
        import getpass
        password = getpass.getpass("Password: ")
        self.send(password)

        resp = self.recv_response()
        print(resp)
        if not resp.startswith("230"):
            print("[!] Login failed. Exiting.")
            sys.exit(1)

        # Server sends command hint
        hint = self.recv_response()
        if hint:
            print(hint)

    # ── commands ──────────────────────────────────────────────────────────────
    def cmd_list(self):
        self.send("LIST")
        print(self.recv_response())

    def cmd_upload(self, local_path: str):
        src = Path(local_path)
        if not src.exists():
            print(f"[!] Local file not found: {src}")
            return
        self.send(f"UPLOAD {src.name}")
        resp = self.recv_response()          # 150 Ready
        print(resp)
        if not resp.startswith("150"):
            return
        # send file size
        size = src.stat().st_size
        self.send(str(size))
        self.recv_response()                 # 150 Send data now
        with open(src, "rb") as f:
            while chunk := f.read(BUFFER):
                self.conn.sendall(chunk)
        print(self.recv_response())          # 226 Done

    def cmd_download(self, filename: str):
        self.send(f"DOWNLOAD {filename}")
        resp = self.recv_response()
        print(resp)
        if not resp.startswith("150"):
            return
        # parse size from "150 Sending 'x' (NNN bytes)."
        try:
            size = int(resp.split("(")[1].split(" ")[0])
        except Exception:
            size = None
        self.send("READY")                   # signal server
        dest = Path(filename).name
        received = 0
        with open(dest, "wb") as f:
            while True:
                try:
                    chunk = self.conn.recv(BUFFER)
                except Exception:
                    break
                if not chunk:
                    break
                # strip trailing "226 …\r\n" from last chunk
                if b"226 " in chunk:
                    idx = chunk.find(b"226 ")
                    f.write(chunk[:idx])
                    received += idx
                    print(chunk[idx:].decode().strip())
                    break
                f.write(chunk)
                received += len(chunk)
                if size and received >= size:
                    break
        print(f"[*] Saved '{dest}' ({received} bytes)")

    def cmd_mkdir(self, dirname: str):
        self.send(f"MKDIR {dirname}")
        print(self.recv_response())

    def cmd_delete(self, name: str):
        confirm = input(f"Delete '{name}'? [y/N] ").strip().lower()
        if confirm != "y":
            print("Cancelled.")
            return
        self.send(f"DELETE {name}")
        print(self.recv_response())

    def cmd_pwd(self):
        self.send("PWD")
        print(self.recv_response())

    def cmd_cwd(self, dirname: str):
        self.send(f"CWD {dirname}")
        print(self.recv_response())

    # ── interactive shell ────────────────────────────────────────────────────
    def shell(self):
        print(HELP_TEXT)
        while True:
            try:
                raw = input("sftp> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nDisconnecting…")
                self.send("QUIT")
                break
            if not raw:
                continue
            parts  = raw.split(None, 1)
            cmd    = parts[0].upper()
            arg    = parts[1] if len(parts) > 1 else ""

            if cmd == "QUIT":
                self.send("QUIT")
                print(self.recv_response())
                break
            elif cmd == "HELP":
                print(HELP_TEXT)
            elif cmd == "LIST":
                self.cmd_list()
            elif cmd == "UPLOAD":
                self.cmd_upload(arg)
            elif cmd == "DOWNLOAD":
                self.cmd_download(arg)
            elif cmd == "MKDIR":
                self.cmd_mkdir(arg)
            elif cmd == "DELETE":
                self.cmd_delete(arg)
            elif cmd == "PWD":
                self.cmd_pwd()
            elif cmd == "CWD":
                self.cmd_cwd(arg)
            else:
                print(f"[!] Unknown command '{cmd}'. Type HELP.")

        self.conn.close()


# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Secure-FTP Client")
    parser.add_argument("host", nargs="?", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=9000, help="Server port")
    args = parser.parse_args()

    client = SecureFTPClient(args.host, args.port)
    client.connect()
    client.login()
    client.shell()

