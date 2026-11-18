"""
setup.py – First-time setup for Secure-FTP project.

Performs:
  1. Generate self-signed TLS certificate + private key (certs/)
  2. Create a default admin user in users.json
  3. Create the server_files/ directory
"""

import subprocess
import json
import hashlib
import sys
from pathlib import Path

BASE_DIR     = Path(__file__).parent
CERTS_DIR    = BASE_DIR / "certs"
USERS_FILE   = BASE_DIR / "users.json"
SERVER_FILES = BASE_DIR / "server_files"


def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


def generate_cert():
    CERTS_DIR.mkdir(exist_ok=True)
    cert = CERTS_DIR / "server.crt"
    key  = CERTS_DIR / "server.key"
    if cert.exists() and key.exists():
        print("[*] Certificates already exist – skipping generation.")
        return
    print("[*] Generating self-signed TLS certificate (valid 365 days)…")

    # Try using the cryptography library first
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureFTP"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
            ]), critical=False)
            .sign(private_key, hashes.SHA256())
        )
        with open(key, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(cert, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        print(f"    Certificate : {cert}")
        print(f"    Private key : {key}")
        return
    except ImportError:
        pass  # fall through to openssl

    # Try openssl command
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(key),
        "-out",    str(cert),
        "-days",   "365",
        "-nodes",
        "-subj",   "/C=IN/ST=State/L=City/O=SecureFTP/CN=localhost"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"    Certificate : {cert}")
        print(f"    Private key : {key}")
        return

    # Fallback: generate using ssl.create_default_context trick with a dummy cert
    print("[!] Neither 'cryptography' package nor 'openssl' binary found.")
    print("    Please install one of the following, then re-run setup.py:")
    print("      pip install cryptography")
    print("      -- OR --")
    print("      Install OpenSSL: https://slproweb.com/products/Win32OpenSSL.html")
    sys.exit(1)


def create_users():
    if USERS_FILE.exists():
        print("[*] users.json already exists – skipping user creation.")
        return
    print("[*] Creating default users (admin / admin123, alice / alice123)…")
    users = {
        "admin": hash_password("admin123"),
        "alice": hash_password("alice123"),
    }
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)
    print(f"    Users file: {USERS_FILE}")


def add_user(username: str, password: str):
    """Utility: add or update a user in users.json."""
    users = {}
    if USERS_FILE.exists():
        with open(USERS_FILE) as f:
            users = json.load(f)
    users[username] = hash_password(password)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)
    print(f"[*] User '{username}' saved.")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Secure-FTP Setup")
    sub    = parser.add_subparsers(dest="cmd")

    sub.add_parser("init", help="First-time setup (default)")
    add_p = sub.add_parser("adduser", help="Add or update a user")
    add_p.add_argument("username")
    add_p.add_argument("password")

    args = parser.parse_args()

    if args.cmd == "adduser":
        add_user(args.username, args.password)
    else:   # init (default)
        print("=" * 50)
        print("  Secure-FTP Setup")
        print("=" * 50)
        generate_cert()
        create_users()
        SERVER_FILES.mkdir(exist_ok=True)
        print(f"[*] Server files dir: {SERVER_FILES}")
        print("\n[✓] Setup complete!")
        print("    Start server : python server.py")
        print("    Start client : python client.py [host]")


if __name__ == "__main__":
    main()
