"""
Secure FTP Dashboard — Python Tkinter GUI
Run: python dashboard.py
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import json, hashlib, os, threading, time
from pathlib import Path
from datetime import datetime

BASE_DIR     = Path(__file__).parent
USERS_FILE   = BASE_DIR / "users.json"
AUDIT_LOG    = BASE_DIR / "audit.log"
SERVER_FILES = BASE_DIR / "server_files"

# ── Color palette ──────────────────────────────────────────────────────────────
BG       = "#0f1117"
SURFACE  = "#1a1d27"
BORDER   = "#2a2d3a"
FG       = "#e2e8f0"
MUTED    = "#64748b"
PRIMARY  = "#3b82f6"
SUCCESS  = "#22c55e"
WARNING  = "#f59e0b"
ERROR    = "#ef4444"
ACCENT   = "#a78bfa"
MONO     = ("Courier New", 10)
MONO_SM  = ("Courier New", 9)
SANS     = ("Segoe UI", 10)
SANS_SM  = ("Segoe UI", 9)
SANS_LG  = ("Segoe UI", 13, "bold")

ACTION_COLORS = {
    "LOGIN":    SUCCESS,
    "LOGOUT":   MUTED,
    "QUIT":     MUTED,
    "UPLOAD":   PRIMARY,
    "DOWNLOAD": ACCENT,
    "LIST":     FG,
    "MKDIR":    WARNING,
    "DELETE":   ERROR,
    "PWD":      FG,
    "CWD":      FG,
}

# ── Helpers ────────────────────────────────────────────────────────────────────
def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def load_users() -> dict:
    if USERS_FILE.exists():
        with open(USERS_FILE) as f:
            return json.load(f)
    return {}

def load_logs() -> list[str]:
    if AUDIT_LOG.exists():
        return AUDIT_LOG.read_text().splitlines()
    return []

def walk_files():
    result = []
    if SERVER_FILES.exists():
        for p in sorted(SERVER_FILES.rglob("*")):
            rel = p.relative_to(SERVER_FILES)
            owner = str(rel).split(os.sep)[0] if str(rel) != "." else ""
            kind = "DIR" if p.is_dir() else "FILE"
            size = f"{p.stat().st_size} B" if p.is_file() else "-"
            result.append((str(rel), owner, kind, size))
    return result

# ── Main App ───────────────────────────────────────────────────────────────────
class Dashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure FTP Dashboard")
        self.geometry("1000x680")
        self.configure(bg=BG)
        self.resizable(True, True)
        self._build()
        self._auto_refresh()

    def _build(self):
        # ── Header ────────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=SURFACE, pady=10)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🔐  Secure FTP Dashboard", font=SANS_LG,
                 bg=SURFACE, fg=FG).pack(side="left", padx=16)
        self.status_dot = tk.Label(hdr, text="●", font=("Segoe UI", 12),
                                   bg=SURFACE, fg=SUCCESS)
        self.status_dot.pack(side="right", padx=4)
        tk.Label(hdr, text="Server Online · Port 9000", font=SANS_SM,
                 bg=SURFACE, fg=MUTED).pack(side="right")

        # ── Stats row ─────────────────────────────────────────────────────────
        stats = tk.Frame(self, bg=BORDER, height=1)
        stats.pack(fill="x")
        srow = tk.Frame(self, bg=SURFACE)
        srow.pack(fill="x")
        for label, val, sub in [
            ("Encryption",   "TLS 1.3",         "AES-256-GCM"),
            ("Auth Hashing", "SHA-256",          "256-bit digest"),
            ("Active Users", f"{len(load_users())} accounts", "admin · alice"),
            ("Audit Events", f"{len(load_logs())} entries", "all ops logged"),
        ]:
            f = tk.Frame(srow, bg=SURFACE, padx=18, pady=10)
            f.pack(side="left", expand=True, fill="x")
            tk.Label(f, text=label, font=SANS_SM, bg=SURFACE, fg=MUTED).pack(anchor="w")
            tk.Label(f, text=val,   font=("Segoe UI", 11, "bold"), bg=SURFACE, fg=FG).pack(anchor="w")
            tk.Label(f, text=sub,   font=SANS_SM, bg=SURFACE, fg=MUTED).pack(anchor="w")
            tk.Frame(srow, bg=BORDER, width=1).pack(side="left", fill="y")

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # ── Notebook tabs ─────────────────────────────────────────────────────
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("TNotebook",       background=BG, borderwidth=0)
        style.configure("TNotebook.Tab",   background=SURFACE, foreground=MUTED,
                        padding=[14, 7], font=SANS_SM, borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", BG)],
                  foreground=[("selected", FG)])

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=0, pady=0)

        self._tab_logs(nb)
        self._tab_files(nb)
        self._tab_users(nb)
        self._tab_enc(nb)
        self._tab_howto(nb)

    # ── Audit Log tab ──────────────────────────────────────────────────────────
    def _tab_logs(self, nb):
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text="  Audit Log  ")

        toolbar = tk.Frame(frame, bg=BG, pady=8)
        toolbar.pack(fill="x", padx=16)
        tk.Label(toolbar, text="audit.log — record of all operations",
                 font=SANS_SM, bg=BG, fg=MUTED).pack(side="left")

        self.filter_var = tk.StringVar(value="ALL")
        for f in ["ALL", "LOGIN", "UPLOAD", "DOWNLOAD", "MKDIR", "DELETE"]:
            b = tk.Radiobutton(toolbar, text=f, variable=self.filter_var,
                               value=f, command=self._refresh_logs,
                               bg=BG, fg=MUTED, selectcolor=BG,
                               activebackground=BG, font=SANS_SM,
                               indicatoron=False, relief="flat", padx=8, pady=3,
                               cursor="hand2")
            b.pack(side="right", padx=2)

        # Table header
        hdr = tk.Frame(frame, bg=SURFACE, pady=5)
        hdr.pack(fill="x", padx=16)
        for text, w in [("Timestamp", 18), ("User", 10), ("Action", 10), ("Detail", 44)]:
            tk.Label(hdr, text=text, font=MONO_SM, bg=SURFACE, fg=MUTED,
                     width=w, anchor="w").pack(side="left", padx=4)

        # Scrollable log area
        self.log_text = scrolledtext.ScrolledText(
            frame, bg=BG, fg=FG, font=MONO_SM,
            relief="flat", borderwidth=0,
            state="disabled", wrap="none", cursor="arrow",
            highlightthickness=1, highlightbackground=BORDER,
        )
        self.log_text.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        # Tag colors
        for action, color in ACTION_COLORS.items():
            self.log_text.tag_configure(action, foreground=color)
        self.log_text.tag_configure("muted", foreground=MUTED)

        self._refresh_logs()

    def _refresh_logs(self):
        lines = load_logs()
        f = self.filter_var.get()
        if f != "ALL":
            lines = [l for l in lines if f"ACTION={f}" in l]

        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        for line in lines:
            parts = line.split("|")
            if len(parts) >= 4:
                ts     = parts[0].strip()
                rest   = parts[2].strip() if len(parts) > 2 else ""
                # parse USER= ACTION= detail
                user   = ""
                action = ""
                detail = ""
                for seg in rest.split():
                    if seg.startswith("USER="):   user   = seg[5:]
                    if seg.startswith("ACTION="): action = seg[7:]
                after = rest.split(action)[-1].strip() if action else rest
                detail = after.replace(action, "").strip()

                self.log_text.insert("end", f"  {ts:<22}", "muted")
                self.log_text.insert("end", f" {user:<14}", ())
                self.log_text.insert("end", f" {action:<12}", action if action in ACTION_COLORS else ())
                self.log_text.insert("end", f" {detail}\n", "muted")
            else:
                self.log_text.insert("end", line + "\n", "muted")

        self.log_text.configure(state="disabled")
        self.log_text.see("end")

    # ── Files tab ─────────────────────────────────────────────────────────────
    def _tab_files(self, nb):
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text="  Files  ")

        tk.Label(frame, text="server_files/ — per-user isolated storage",
                 font=SANS_SM, bg=BG, fg=MUTED).pack(anchor="w", padx=16, pady=8)

        cols = ("Path", "Owner", "Type", "Size")
        tv = ttk.Treeview(frame, columns=cols, show="headings", height=20)
        style = ttk.Style()
        style.configure("Treeview",           background=BG,      fieldbackground=BG,
                        foreground=FG,         font=MONO_SM,       rowheight=26, borderwidth=0)
        style.configure("Treeview.Heading",   background=SURFACE, foreground=MUTED,
                        font=SANS_SM,          relief="flat")
        style.map("Treeview",                 background=[("selected", SURFACE)],
                  foreground=[("selected", FG)])

        widths = [420, 100, 80, 100]
        for col, w in zip(cols, widths):
            tv.heading(col, text=col)
            tv.column(col, width=w, anchor="w")

        tv.tag_configure("DIR",  foreground=WARNING)
        tv.tag_configure("FILE", foreground=PRIMARY)

        for path, owner, kind, size in walk_files():
            tv.insert("", "end", values=(path, owner, kind, size), tags=(kind,))

        sb = ttk.Scrollbar(frame, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=sb.set)
        tv.pack(side="left", fill="both", expand=True, padx=16, pady=(0,12))
        sb.pack(side="left", fill="y", pady=(0,12))

        self.file_tv = tv

    # ── Users tab ─────────────────────────────────────────────────────────────
    def _tab_users(self, nb):
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text="  Users  ")

        tk.Label(frame, text="users.json — SHA-256 hashed passwords",
                 font=SANS_SM, bg=BG, fg=MUTED).pack(anchor="w", padx=16, pady=8)

        # Users table
        users = load_users()
        for uname, uhash in users.items():
            row = tk.Frame(frame, bg=SURFACE, pady=10, padx=16)
            row.pack(fill="x", padx=16, pady=2)
            tk.Label(row, text=uname, font=("Segoe UI", 10, "bold"),
                     bg=SURFACE, fg=FG, width=10, anchor="w").pack(side="left")
            tk.Label(row, text=uhash, font=MONO_SM, bg=SURFACE,
                     fg=MUTED, anchor="w").pack(side="left", fill="x", expand=True)
            tk.Label(row, text="● active", font=SANS_SM,
                     bg=SURFACE, fg=SUCCESS).pack(side="right")

        # Live hash tool
        tk.Frame(frame, bg=BORDER, height=1).pack(fill="x", padx=16, pady=12)
        tk.Label(frame, text="Live SHA-256 verifier — type any password:",
                 font=SANS_SM, bg=BG, fg=MUTED).pack(anchor="w", padx=16)

        inp_row = tk.Frame(frame, bg=BG)
        inp_row.pack(fill="x", padx=16, pady=6)
        self.pw_entry = tk.Entry(inp_row, font=MONO, bg=SURFACE, fg=FG,
                                  insertbackground=FG, relief="flat", bd=8)
        self.pw_entry.pack(side="left", fill="x", expand=True)
        self.pw_entry.bind("<Return>", lambda e: self._do_hash())
        tk.Button(inp_row, text="Hash →", font=SANS_SM, bg=PRIMARY, fg="white",
                  relief="flat", padx=12, command=self._do_hash,
                  cursor="hand2").pack(side="left", padx=(8, 0))

        self.hash_out = tk.Label(frame, text="", font=MONO_SM, bg=BG, fg=MUTED,
                                  wraplength=800, justify="left")
        self.hash_out.pack(anchor="w", padx=16, pady=4)

    def _do_hash(self):
        pw = self.pw_entry.get().strip()
        if not pw:
            return
        h = sha256(pw)
        users = load_users()
        match = next((u for u, v in users.items() if v == h), None)
        result = f'sha256("{pw}") =\n{h}'
        if match:
            result += f'\n✓ Matches stored hash for user: {match}'
            self.hash_out.configure(fg=SUCCESS)
        else:
            result += "\n✗ No matching user (password not registered)"
            self.hash_out.configure(fg=MUTED)
        self.hash_out.configure(text=result)

    # ── Encryption tab ────────────────────────────────────────────────────────
    def _tab_enc(self, nb):
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text="  Encryption  ")

        content = tk.Frame(frame, bg=BG)
        content.pack(fill="both", expand=True, padx=16, pady=12)

        # Left card — TLS
        left = tk.Frame(content, bg=SURFACE, padx=16, pady=12)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        tk.Label(left, text="Channel Encryption", font=("Segoe UI", 10, "bold"),
                 bg=SURFACE, fg=FG).pack(anchor="w", pady=(0, 8))
        for label, val, color in [
            ("Protocol",    "TLS 1.3",        FG),
            ("Cipher",      "AES-256-GCM",    FG),
            ("Key Exchange","ECDHE",           FG),
            ("Certificate", "RSA-2048",        FG),
            ("Same as",     "HTTPS (websites)",SUCCESS),
        ]:
            r = tk.Frame(left, bg=SURFACE)
            r.pack(fill="x", pady=2)
            tk.Label(r, text=label, font=SANS_SM, bg=SURFACE, fg=MUTED, width=14, anchor="w").pack(side="left")
            tk.Label(r, text=val,   font=("Segoe UI", 9, "bold"), bg=SURFACE, fg=color).pack(side="left")

        # Right card — SHA-256
        right = tk.Frame(content, bg=SURFACE, padx=16, pady=12)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        tk.Label(right, text="Password Hashing", font=("Segoe UI", 10, "bold"),
                 bg=SURFACE, fg=FG).pack(anchor="w", pady=(0, 8))
        for label, val, color in [
            ("Algorithm",       "SHA-256",      FG),
            ("Output size",     "256 bits",     FG),
            ("Hex chars",       "64 characters",FG),
            ("One-way?",        "Yes — cannot be reversed", SUCCESS),
            ("Plaintext stored?","Never",        SUCCESS),
        ]:
            r = tk.Frame(right, bg=SURFACE)
            r.pack(fill="x", pady=2)
            tk.Label(r, text=label, font=SANS_SM, bg=SURFACE, fg=MUTED, width=16, anchor="w").pack(side="left")
            tk.Label(r, text=val,   font=("Segoe UI", 9, "bold"), bg=SURFACE, fg=color).pack(side="left")

        content.columnconfigure(0, weight=1)
        content.columnconfigure(1, weight=1)

        # TLS flow
        flow = tk.Frame(frame, bg=SURFACE, padx=16, pady=14)
        flow.pack(fill="x", padx=16, pady=(4, 12))
        tk.Label(flow, text="TLS Handshake Flow", font=("Segoe UI", 9, "bold"),
                 bg=SURFACE, fg=FG).pack(anchor="w", pady=(0, 8))
        steps = [
            ("Client → Server", "ClientHello  (propose TLS 1.3)",         MUTED),
            ("Server → Client", "ServerHello + Certificate (RSA-2048)",   PRIMARY),
            ("Client → Server", "Finished  (ECDHE shared key agreed)",    MUTED),
            ("↕ Both",          "All data encrypted with AES-256-GCM",    SUCCESS),
        ]
        for direction, detail, color in steps:
            r = tk.Frame(flow, bg=SURFACE)
            r.pack(fill="x", pady=1)
            tk.Label(r, text=direction, font=MONO_SM, bg=SURFACE,
                     fg=color, width=18, anchor="w").pack(side="left")
            tk.Label(r, text=detail,   font=MONO_SM, bg=SURFACE, fg=MUTED).pack(side="left")

    # ── How to Run tab ────────────────────────────────────────────────────────
    def _tab_howto(self, nb):
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text="  How to Run  ")

        steps = [
            ("Step 1 — Setup (run once)", "python setup.py",
             "Generates TLS certificate + creates default users"),
            ("Step 2 — Start the Server", "python server.py",
             "Listens on port 9000 · handles multiple clients · logs everything"),
            ("Step 3 — Connect a Client", "python client.py\npython client.py 192.168.x.x",
             "Run on same PC or any PC on the same WiFi/LAN"),
        ]

        for title, cmd, desc in steps:
            card = tk.Frame(frame, bg=SURFACE, padx=16, pady=12)
            card.pack(fill="x", padx=16, pady=6)
            tk.Label(card, text=title, font=("Segoe UI", 9, "bold"),
                     bg=SURFACE, fg=MUTED).pack(anchor="w")
            tk.Label(card, text=cmd, font=("Courier New", 11),
                     bg=BG, fg=PRIMARY, padx=12, pady=8, justify="left").pack(fill="x", pady=6)
            tk.Label(card, text=desc, font=SANS_SM,
                     bg=SURFACE, fg=MUTED).pack(anchor="w")

        # Commands reference
        ref = tk.Frame(frame, bg=SURFACE, padx=16, pady=12)
        ref.pack(fill="x", padx=16, pady=6)
        tk.Label(ref, text="Commands at the sftp> prompt", font=("Segoe UI", 9, "bold"),
                 bg=SURFACE, fg=MUTED).pack(anchor="w", pady=(0, 8))

        cmds = [
            ("LIST",              "List files on server"),
            ("UPLOAD <file>",     "Send a file to the server"),
            ("DOWNLOAD <file>",   "Get a file from the server"),
            ("MKDIR <dirname>",   "Create a directory"),
            ("DELETE <name>",     "Delete a file or directory"),
            ("PWD",               "Show current directory"),
            ("CWD <dirname>",     "Change directory"),
            ("QUIT",              "Disconnect"),
        ]
        grid = tk.Frame(ref, bg=SURFACE)
        grid.pack(fill="x")
        for i, (cmd, desc) in enumerate(cmds):
            col = (i % 2) * 2
            row = i // 2
            tk.Label(grid, text=cmd, font=MONO_SM, bg=SURFACE, fg=PRIMARY,
                     width=22, anchor="w").grid(row=row, column=col,   sticky="w", pady=2)
            tk.Label(grid, text=desc, font=SANS_SM, bg=SURFACE, fg=MUTED,
                     anchor="w").grid(row=row, column=col+1, sticky="w", padx=(0, 40))

    # ── Auto refresh logs every 3s ─────────────────────────────────────────────
    def _auto_refresh(self):
        try:
            self._refresh_logs()
        except Exception:
            pass
        self.after(3000, self._auto_refresh)


# ── Run ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = Dashboard()
    app.mainloop()

