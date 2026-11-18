# Secure FTP-like Server with Encrypted Transfer
**Cyber Security Lab (7CS4-22) — Mini Project**  
*Department of Computer Science & Engineering*  
*Swami Keshvanand Institute of Technology, Management & Gramothan (SKIT), Jaipur*  
*(Affiliated to Rajasthan Technical University, Kota)*  

---

## 👨‍💻 Student Details
- **Student Name:** Sakshi Agarwal
- **Roll Number:** 23ESKCS196
- **Class / Batch:** CS-D-G1 (VII Semester)
- **Academic Session:** 2026–27
- **Project Code:** CSL-G09
- **Project Title:** Secure FTP-like Server with Encrypted Transfer
- **Faculty Supervisor:** Mr. Vikash Dhankar, Assistant Professor, Dept. of CSE, SKIT Jaipur

---

## 📌 Project Overview
Traditional File Transfer Protocol (FTP, RFC 959) transmits commands, credentials, and payload data in plaintext, exposing LAN environments to eavesdropping and Man-in-the-Middle (MitM) packet-sniffing attacks.

This project delivers a **secure, lightweight client-server file transfer system** built in Python that guarantees confidentiality, integrity, non-repudiation, and user authentication across local area networks.

### Key Security Features
- 🔒 **End-to-End Encryption:** Transport Layer Security (**TLS 1.3**) powered by the `ssl` module with **AES-256-GCM** symmetric cipher.
- 🔑 **Password Protection:** SHA-256 cryptographic one-way hashing for user authentication; plaintext credentials are never saved on disk.
- 📜 **Security Audit Logging:** All operations (authentication attempts, file transfers, directory changes) are recorded into `audit.log` with timestamps and client IP addresses.
- 📁 **User Isolation:** Each authenticated user is jailed within their own server storage directory (`server_files/<username>/`).
- ⚡ **Multi-Client Concurrency:** Threaded server design (`threading.Thread`) allowing multiple users to transfer files simultaneously.
- 🖥️ **Interactive Terminal & GUI:** Interactive terminal client with command shell (`sftp>`) plus an unslop-inspired Desktop Dashboard (`dashboard.py`) and Web Monitor (`dashboard.html`).

---

## 📁 Repository Structure

```text
├── server.py              # Multi-threaded TLS file server (Port 9000)
├── client.py              # Secure interactive CLI client with TLS
├── setup.py               # First-time initialization (RSA-2048 certs & user hashing)
├── dashboard.py           # Clean Tkinter desktop audit log & status dashboard
├── dashboard.html         # Web-based monitoring UI with live audit trail
├── users.json             # SHA-256 hashed user credentials store
├── audit.log              # Real-time security audit log
├── certs/                 # TLS Certificates directory
│   ├── server.crt         # X.509 self-signed certificate (RSA-2048)
│   └── server.key         # Server private key
├── server_files/          # Server storage directory (per-user isolation)
│   ├── admin/             # Admin storage space
│   └── alice/             # Alice storage space
├── Project_Report.pdf     # Complete Academic Mini-Project Report (20+ pages)
└── README.md              # Project documentation
```

---

## 🛠️ Cryptographic Architecture

| Security Property | Implementation Mechanism | Purpose |
| :--- | :--- | :--- |
| **Channel Encryption** | **TLS 1.3 / TLS 1.2** | Safeguards all traffic against LAN packet sniffing (e.g. Wireshark). |
| **Symmetric Cipher** | **AES-256-GCM** | Authenticated encryption providing data confidentiality & tampering prevention. |
| **Key Exchange** | **ECDHE** | Ephemeral Diffie-Hellman ensuring Forward Secrecy. |
| **Certificate** | **RSA-2048 (X.509)** | Server identity verification (valid 365 days). |
| **Credential Storage** | **SHA-256 Digest** | 256-bit one-way hash stored in `users.json`; zero plaintext passwords. |

---

## 🚀 Getting Started & Execution

### Prerequisites
- Python 3.10+ installed
- `cryptography` library installed:
  ```bash
  pip install cryptography
  ```

### Step 1: Run Initial Setup (One-time)
Generates the RSA-2048 certificates and creates default test accounts:
```bash
python setup.py
```
*Default Credentials:*
- `admin` / `admin123`
- `alice` / `alice123`

To add a custom user:
```bash
python setup.py adduser <username> <password>
```

---

### Step 2: Start the Secure Server
Open **Terminal 1** and start the listener on port 9000:
```bash
python server.py
```
*Output:*
```text
[*] Secure-FTP Server listening on port 9000 (TLS)
[*] Files stored in: ...\server_files
[*] Audit log: ...\audit.log
```

---

### Step 3: Launch the Client
Open **Terminal 2** and connect:
```bash
# Connect locally
python client.py

# Or connect to another machine on LAN
python client.py 192.168.1.50
```

Login with username and password, then execute commands:

| Command | Description | Example |
| :--- | :--- | :--- |
| `LIST` | List files on remote server | `sftp> LIST` |
| `UPLOAD <path>` | Send a file securely to server | `sftp> UPLOAD testfile.txt` |
| `DOWNLOAD <file>` | Download a file from server | `sftp> DOWNLOAD testfile.txt` |
| `MKDIR <name>` | Create a remote directory | `sftp> MKDIR project_backup` |
| `DELETE <name>` | Delete a remote file or folder | `sftp> DELETE old_log.txt` |
| `PWD` | Print current remote directory | `sftp> PWD` |
| `CWD <name>` | Change remote directory | `sftp> CWD project_backup` |
| `QUIT` | Disconnect and close session | `sftp> QUIT` |

---

### Step 4: Inspect Live Audit Logs
Open **`audit.log`** or run the dashboard:
```bash
python dashboard.py
```
*Sample Audit Record:*
```text
2026-11-16 00:41:08 | INFO | USER=admin        ACTION=UPLOAD     file=testfile.txt size=205
2026-11-16 00:41:13 | INFO | USER=admin        ACTION=LIST       D:\csminiporject\server_files\admin
2026-11-16 00:54:24 | INFO | USER=admin        ACTION=DOWNLOAD   file=testfile.txt size=205
```

---

## 📑 Project Report
The complete 20-page formal academic report adhering strictly to the SKIT/RTU Kota guidelines is included in this repository:
- 📄 **[Project_Report.pdf](Project_Report.pdf)**

---

## ⚖️ Ethical & Legal Disclaimer
This project was developed strictly for academic and educational purposes under the Cyber Security Lab (7CS4-22) course curriculum. All experiments and transfer tests were conducted exclusively in an isolated, private laboratory environment. Unauthorised access to computer systems or networks is punishable under Sections 43 and 66 of the **Information Technology Act, 2000**.
