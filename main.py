from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from pathlib import Path
from datetime import datetime, timezone
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
import hashlib
import json
import mimetypes
import os
import shutil
import uuid
from typing import Optional

import requests
import csv
import os
import requests
import os
print("RUNNING FILE:", os.path.abspath(__file__))

import requests

import requests

app = FastAPI(title="PreClear Pilot")
app.add_middleware(SessionMiddleware, secret_key="preclear-demo-secret-key")

# -----------------------------
# Config
# -----------------------------
BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
STATIC_DIR = BASE_DIR / "static"
LOG_FILE = BASE_DIR / "inspection_log.json"

UPLOAD_DIR.mkdir(exist_ok=True)
STATIC_DIR.mkdir(exist_ok=True)

ALERT_FILE = BASE_DIR / "alerts.json"

REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

CUSTOMER_USERS = {
    "acme_admin": {
        "password": "demo123",
        "display_name": "ACME Corp",
        "client_slug": "acme",
        "role": "admin",
    },
    "acme_analyst": {
        "password": "demo123",
        "display_name": "ACME Corp",
        "client_slug": "acme",
        "role": "analyst",
    },
    "acme_viewer": {
        "password": "demo123",
        "display_name": "ACME Corp",
        "client_slug": "acme",
        "role": "viewer",
    },
    "notion_admin": {
        "password": "demo123",
        "display_name": "Notion",
        "client_slug": "notion",
        "role": "admin",
    },
    "mercury_admin": {
        "password": "demo123",
        "display_name": "Mercury",
        "client_slug": "mercury",
        "role": "admin",
    },
}

# Optional: set this in your environment later
VT_API_KEY = "10200de678ff9930e1b0400145fe7ceb8d6b00bbe70335d063cef3d681d6966e"
VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{file_hash}"

# If you already have a logo in /static, keep this
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

ALLOWED_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv",
    ".txt", ".png", ".jpg", ".jpeg", ".zip"
}

HIGH_RISK_EXTENSIONS = {
    ".exe", ".dll", ".js", ".vbs", ".bat", ".cmd", ".scr",
    ".ps1", ".msi", ".jar"
}

MAX_FILE_SIZE_MB = 25

# -----------------------------
# Helpers
# -----------------------------
def load_logs() -> list:
    if not LOG_FILE.exists():
        return []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def is_demo_block_file(filename: str) -> bool:
    blocked_names = {
        "demo_block_sample.txt",
        "demo_quarantine_sample.txt",
    }
    return filename.lower() in blocked_names

def save_log(entry: dict) -> None:
    logs = load_logs()
    logs.insert(0, entry)
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs[:200], f, indent=2)


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def guess_mime_type(filename: str) -> str:
    mime_type, _ = mimetypes.guess_type(filename)
    return mime_type or "application/octet-stream"

def is_eicar_file(path: Path) -> bool:
    try:
        content = path.read_bytes()
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        return eicar in content
    except Exception:
        return False

def get_extension(filename: str) -> str:
    return Path(filename).suffix.lower()

def get_all_audit_logs(limit: int = 200) -> list:
    logs = load_logs()
    return logs[:limit]

def load_alerts() -> list:
    if not ALERT_FILE.exists():
        return []
    try:
        with open(ALERT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_alert(alert: dict) -> None:
    alerts = load_alerts()
    alerts.insert(0, alert)
    with open(ALERT_FILE, "w", encoding="utf-8") as f:
        json.dump(alerts[:200], f, indent=2)


def get_customer_alerts(customer_name: str, limit: int = 10) -> list:
    alerts = load_alerts()
    target = customer_name.strip().lower()
    return [
        alert for alert in alerts
        if str(alert.get("customer_name", "")).strip().lower() == target
    ][:limit]

def send_slack_alert(message: str) -> bool:
    if not SLACK_WEBHOOK_URL:
        return False

    payload = {
        "text": message
    }

    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        print("Slack status code:", response.status_code)
        print("Slack response text:", response.text[:200])
        return response.status_code == 200
    except requests.RequestException as e:
        print("Slack request failed:", str(e))
        return False

def generate_pdf_report(
    result: dict,
    report_path: Path,
    customer_name: str = "Demo Organization",
    environment: str = "Unknown",
    report_id: str = "N/A",
    generated_at: str = "N/A",
    uploaded_by: str = "unknown_user",
    uploaded_by_role: str = "viewer",
):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(report_path))
    elements = []

    # Add logo if available
    logo_path = STATIC_DIR / "Blue.png"
    if logo_path.exists():
        logo = Image(str(logo_path), width=1.2 * inch, height=1.2 * inch)
        elements.append(logo)
        elements.append(Spacer(1, 0.15 * inch))

    elements.append(
        Paragraph(f"PreClear Pilot Report — {customer_name}", styles["Title"])
    )
    elements.append(Spacer(1, 0.15 * inch))

    elements.append(Paragraph(f"Report ID: {report_id}", styles["Normal"]))
    elements.append(Paragraph(f"Generated At: {generated_at}", styles["Normal"]))
    elements.append(Paragraph(f"Environment: {environment}", styles["Normal"]))
    elements.append(Paragraph(f"Uploaded By: {uploaded_by}", styles["Normal"]))
    elements.append(Paragraph(f"Uploader Role: {uploaded_by_role.title()}", styles["Normal"]))
    elements.append(Spacer(1, 0.2 * inch))

    elements.append(Paragraph(f"Filename: {result['filename']}", styles["Normal"]))
    elements.append(Paragraph(f"SHA-256: {result['sha256']}", styles["Normal"]))
    elements.append(Paragraph(f"MIME Type: {result['mime_type']}", styles["Normal"]))
    elements.append(Paragraph(f"File Size: {result['size_mb']} MB", styles["Normal"]))
    elements.append(Paragraph(f"Risk: {result['risk']}", styles["Normal"]))
    elements.append(Paragraph(f"Decision: {result['decision']}", styles["Normal"]))
    elements.append(Spacer(1, 0.2 * inch))

    elements.append(Paragraph("Reasons", styles["Heading2"]))
    elements.append(Spacer(1, 0.08 * inch))
    for reason in result["reasons"]:
        elements.append(Paragraph(f"- {reason}", styles["Normal"]))

    elements.append(Spacer(1, 0.25 * inch))

    if result.get("vt_result"):
        vt = result["vt_result"]
        elements.append(Paragraph("VirusTotal Hash Lookup", styles["Heading2"]))
        elements.append(Spacer(1, 0.08 * inch))
        elements.append(Paragraph(f"Malicious: {vt.get('malicious', 0)}", styles["Normal"]))
        elements.append(Paragraph(f"Suspicious: {vt.get('suspicious', 0)}", styles["Normal"]))
        elements.append(Paragraph(f"Harmless: {vt.get('harmless', 0)}", styles["Normal"]))
        elements.append(Paragraph(f"Undetected: {vt.get('undetected', 0)}", styles["Normal"]))
        elements.append(Spacer(1, 0.2 * inch))

    elements.append(
        Paragraph(
            "This enforcement decision was made prior to system ingress, reducing potential risk before internal exposure.",
            styles["Italic"],
        )
    )

    doc.build(elements)

def vt_hash_lookup(file_hash: str) -> Optional[dict]:
    """
    Look up an existing file hash in VirusTotal.
    Returns a simplified result dict or None if:
    - no API key is configured
    - the hash is unknown to VT
    - the request fails
    """
    if not VT_API_KEY:
        print("VT API key loaded:", False)
        return None

    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY,
    }

    url = VT_FILE_URL.format(file_hash=file_hash)

    try:
        response = requests.get(url, headers=headers, timeout=10)
        print("VT API key loaded:", bool(VT_API_KEY))
        print("Looking up hash:", file_hash)
        print("VT status code:", response.status_code)
        print("VT response preview:", response.text[:200])

        if response.status_code == 200:
            data = response.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attrs.get("reputation"),
                "times_submitted": attrs.get("times_submitted"),
                "meaningful_name": attrs.get("meaningful_name"),
            }

        if response.status_code == 404:
            return None

        return None

    except requests.RequestException:
        return None
    
def get_customer_logs(customer_name: str, limit: int = 20) -> list:
    logs = load_logs()
    target = customer_name.strip().lower()
    return [
        log for log in logs
        if str(log.get("customer_name", "")).strip().lower() == target
    ][:limit]

def inspect_file(path: Path, original_name: str) -> dict:
    file_size_bytes = path.stat().st_size
    file_size_mb = round(file_size_bytes / (1024 * 1024), 2)
    extension = get_extension(original_name)
    mime_type = guess_mime_type(original_name)
    file_hash = sha256_file(path)

    # Rule 0: safe demo file simulation (FINAL DECISION)
    if original_name.lower() == "demo_block_sample.txt":
        return {
           "filename": original_name,
           "extension": extension or "none",
           "mime_type": mime_type,
           "size_mb": file_size_mb,
           "sha256": file_hash,
           "risk": "HIGH",
           "decision": "BLOCK",
           "reasons": ["Demo threat signature detected (safe simulated sample)",
                       "Detected prior to system ingress - enforcement applied"],
           "vt_result": None,
        }

    elif original_name.lower() == "demo_quarantine_sample.txt":
        return {
            "filename": original_name,
            "extension": extension or "none",
            "mime_type": mime_type,
            "size_mb": file_size_mb,
            "sha256": file_hash,
            "risk": "MEDIUM",
            "decision": "QUARANTINE",
            "reasons": ["Demo suspicious signature detected (safe simulated sample)",
                        "Detected prior to system ingress - enforcement applied"],
            "vt_result": None,
        }

    reasons = []
    risk = "LOW"
    decision = "ALLOW"

    # Rule 1: high-risk executable/script types
    if extension in HIGH_RISK_EXTENSIONS:
        risk = "HIGH"
        decision = "BLOCK"
        reasons.append(f"High-risk file extension detected: {extension}")

    # Rule 2: disallowed unknown types
    elif extension not in ALLOWED_EXTENSIONS:
        risk = "MEDIUM"
        decision = "QUARANTINE"
        reasons.append(f"Unknown or unsupported file type: {extension or 'none'}")

    # Rule 3: very large file
    if file_size_mb > MAX_FILE_SIZE_MB and decision != "BLOCK":
        risk = "MEDIUM" if risk == "LOW" else risk
        decision = "QUARANTINE"
        reasons.append(f"File exceeds size threshold: {file_size_mb} MB")

    # Rule 4: suspicious extension mismatch
    # very simple version: filename says one thing, mime says another
    if extension == ".pdf" and "pdf" not in mime_type.lower() and decision != "BLOCK":
        risk = "MEDIUM"
        decision = "QUARANTINE"
        reasons.append("File extension and MIME type do not appear to match")

    # VirusTotal hash lookup
    vt_result = vt_hash_lookup(file_hash)
    if vt_result:
        malicious_count = vt_result.get("malicious", 0)
        suspicious_count = vt_result.get("suspicious", 0)

        if malicious_count > 0:
            risk = "HIGH"
            decision = "BLOCK"
            reasons.append(f"VirusTotal flagged hash as malicious by {malicious_count} engines")
        elif suspicious_count > 0 and decision != "BLOCK":
            risk = "MEDIUM"
            decision = "QUARANTINE"
            reasons.append(f"VirusTotal flagged hash as suspicious by {suspicious_count} engines")

    if not reasons:
        reasons.append("No high-risk indicators detected")

    return {
        "filename": original_name,
        "extension": extension or "none",
        "mime_type": mime_type,
        "size_mb": file_size_mb,
        "sha256": file_hash,
        "risk": risk,
        "decision": decision,
        "reasons": reasons,
        "vt_result": vt_result,
    }


def logo_html() -> str:
    blue_logo = STATIC_DIR / "Blue.png"
    logo = STATIC_DIR / "logo.png"

    if blue_logo.exists():
        return '<img src="/static/Blue.png" style="height:56px; border-radius:10px;">'
    if logo.exists():
        return '<img src="/static/logo.png" style="height:56px; border-radius:10px;">'
    return '<div style="font-weight:700;font-size:28px;">PreClear</div>'

def save_audit_event(
    event_type: str,
    customer_name: str = "",
    client_slug: str = "",
    username: str = "",
    role: str = "",
    environment: str = "",
    filename: str = "",
    risk: str = "",
    decision: str = "",
    sha256: str = "",
    report_filename: str = "",
    reasons: list | None = None,
):
    entry = {
        "id": uuid.uuid4().hex[:10],
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "event_type": event_type,
        "customer_name": customer_name,
        "client_slug": client_slug,
        "environment": environment,
        "uploaded_by": username,
        "uploaded_by_role": role,
        "filename": filename,
        "risk": risk,
        "decision": decision,
        "sha256": sha256,
        "report_filename": report_filename,
        "reasons": reasons or [],
    }
    save_log(entry)

def page_shell(content: str, title: str = "PreClear Pilot") -> str:
    return f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{title}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {{
      font-family: Arial, sans-serif;
      background: #f5f7fb;
      color: #1a1a1a;
      margin: 0;
      padding: 0;
    }}

    .container {{
      max-width: 980px;
      margin: 40px auto;
      padding: 0 20px;
    }}

    .header {{
      display: flex;
      align-items: center;
      gap: 16px;
      margin-bottom: 24px;
    }}

    .card {{
      background: white;
      border: 1px solid #e3e7ef;
      border-radius: 14px;
      padding: 20px;
      margin-bottom: 20px;
    }}

    h1, h2, h3 {{
      margin-top: 0;
    }}

    .btn {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 12px 16px;
      border-radius: 10px;
      background: #0a3278;
      color: white;
      text-decoration: none;
      border: none;
      cursor: pointer;
      font-weight: 600;
    }}

    .btn-secondary {{
      background: #e9edf7;
      color: #1a1a1a;
    }}

    .btn-sm {{
        padding: 6px 10px;
        font-size: 12px;
        border-radius: 6px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
    }}

    td {{
       vertical-align: middle;
    }}

    .badge {{
      display: inline-block;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
    }}

    .low {{ background: #dff5e8; color: #135c32; }}
    .medium {{ background: #fff2d6; color: #8a5a00; }}
    .high {{ background: #fde0e0; color: #8d1111; }}
    .grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }}

    th, td {{
      text-align: left;
      padding: 10px;
      border-bottom: 1px solid #e8ebf2;
      vertical-align: top;
    }}

    code {{
      background: #f2f4f8;
      padding: 2px 6px;
      border-radius: 6px;
    }}

    tr:hover {{
        background: #f5f7fb;
        transition: background 0.2s ease;
    }}

    .sort-indicator {{
        font-size: 10px;
         margin-left: 4px;
        color: #6b7280;
    }}

    canvas {{
        margin-top: 10px;
    }}

    .decision-allow {{
        background: #dff5e8;
        color: #135c32;
    }}

    .decision-quarantine {{
        background: #fff2d6;
        color: #8a5a00;
    }}

    .decision-block {{
        background: #fde0e0;
        color: #8d1111;
    }}

    .summary-bar {{
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 14px;
         margin-bottom: 20px;
    }}

    .summary-card {{
        background: white;
        border: 1px solid #e3e7ef;
        border-radius: 14px;
        padding: 16px;
    }}

    .summary-label {{
        font-size: 12px;
        color: #6b7280;
        margin-bottom: 6px;
    }}

    th {{
        user-select: none;
    }}

    th:hover {{
        background: #f5f7fb;
    }}

    .summary-value {{
        font-size: 24px;
        font-weight: 700;
    }}

    @media (max-width: 800px) {{
       .summary-bar {{
         grid-template-columns: 1fr 1fr;
       }}
    }}

    @media (max-width: 800px) {{
      .grid {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      {logo_html()}
      <div>
        <h1 style="margin-bottom:6px;">PreClear Pilot</h1>
        <div>Pre-ingress file inspection and decisioning</div>
      </div>
    </div>
    {content}
  </div>
</body>
</html>
"""


# -----------------------------
# Routes
# -----------------------------
@app.get("/login", response_class=HTMLResponse)
async def login_page():
    content = """
    <div class="card">
      <h2>Customer Login</h2>
      <form action="/login" method="post">
        <label><b>Username</b></label><br>
        <input
          type="text"
          name="username"
          required
          style="margin-bottom:14px; padding:10px; width:100%; max-width:420px; border:1px solid #d8deea; border-radius:8px;"
        ><br>

        <label><b>Password</b></label><br>
        <input
          type="password"
          name="password"
          required
          style="margin-bottom:14px; padding:10px; width:100%; max-width:420px; border:1px solid #d8deea; border-radius:8px;"
        ><br>

        <button class="btn" type="submit">Log In</button>
      </form>
    </div>
    """
    return page_shell(content, title="Customer Login")

@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    username = username.lower().strip()

    user = CUSTOMER_USERS.get(username)

    if not user or user["password"] != password:
        content = """
        <div class="card">
          <h2>Login Failed</h2>
          <p>Invalid username or password.</p>
          <p><a class="btn btn-secondary" href="/login">Try Again</a></p>
        </div>
        """
        return HTMLResponse(page_shell(content, title="Login Failed"))

    request.session["username"] = username
    request.session["display_name"] = user["display_name"]
    request.session["client_slug"] = user["client_slug"]
    request.session["role"] = user["role"]

    save_audit_event(
        event_type="LOGIN",
        customer_name=user["display_name"],
        client_slug=user["client_slug"],
        username=username,
        role=user["role"],
    )

    return RedirectResponse(url=f"/client/{user['client_slug']}", status_code=302)

@app.post("/client/{client_name}/export-filtered")
async def export_filtered_customer_history(
    client_name: str,
    request: Request,
    filtered_rows_json: str = Form(...),
):
    session_user = request.session.get("username")
    client_slug = request.session.get("client_slug")
    role = request.session.get("role", "viewer")

    if not session_user:
        return RedirectResponse(url="/login", status_code=302)

    if client_slug != client_name:
        content = """
        <div class="card">
            <h2>Access Denied</h2>
            <p>You are not authorized to export this customer history.</p>
            <p><a class="btn btn-secondary" href="/login">Return to Login</a></p>
        </div>
        """
        return HTMLResponse(page_shell(content, title="Access Denied"))

    if role not in ["admin", "analyst"]:
        content = f"""
        <div class="card">
            <h2>Access Denied</h2>
            <p>Your account does not have permission to export data.</p>
            <p><a class="btn btn-secondary" href="/client/{client_name}">Return to Portal</a></p>
        </div>
        """
        return HTMLResponse(page_shell(content, title="Access Denied"))

    try:
        rows = json.loads(filtered_rows_json)
    except json.JSONDecodeError:
        rows = []

    export_filename = f"{client_name}_filtered_history_export.csv"
    export_path = REPORT_DIR / export_filename

    with open(export_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "Timestamp",
            "Filename",
            "Environment",
            "Uploaded By",
            "Risk",
            "Decision",
            "SHA-256",
            "Reasons",
        ])

        for row in rows:
            writer.writerow([
                row.get("timestamp", ""),
                row.get("filename", ""),
                row.get("environment", ""),
                row.get("uploaded_by", ""),
                row.get("risk", ""),
                row.get("decision", ""),
                row.get("sha256", ""),
                row.get("reasons", ""),
            ])

    save_audit_event(
        event_type="EXPORT_FILTERED_CSV",
        customer_name=request.session.get("display_name", ""),
        client_slug=request.session.get("client_slug", ""),
        username=request.session.get("username", ""),
        role=request.session.get("role", "viewer"),
    )

    return FileResponse(
        path=export_path,
        filename=export_filename,
        media_type="text/csv",
    )

@app.get("/", response_class=HTMLResponse)
async def home():
    content = """
    <div class="card">
      <h2>PreClear — Pre-Ingress Security Infrastructure</h2>
      <p>Stopping threats before they reach your systems.</p>

      <p style="margin-top:20px;">
        <a class="btn" href="/login">Customer Login</a>
      </p>
    </div>
    """
    return page_shell(content)

@app.get("/client/{client_name}", response_class=HTMLResponse)
async def client_portal(client_name: str, request: Request):
    session_user = request.session.get("username")
    display_name = request.session.get("display_name")
    client_slug = request.session.get("client_slug")
    role = request.session.get("role", "viewer")

    if not session_user:
        return RedirectResponse(url="/login", status_code=302)

    if client_slug != client_name:
        content = """
        <div class="card">
          <h2>Access Denied</h2>
          <p>You are not authorized to access this customer portal.</p>
          <p><a class="btn btn-secondary" href="/login">Return to Login</a></p>
        </div>
        """
        return HTMLResponse(page_shell(content, title="Access Denied"))

    customer_logs = get_customer_logs(display_name)

    customer_alerts = get_customer_alerts(display_name, limit=5)

    total_count = len(customer_logs)
    allow_count = sum(1 for log in customer_logs if log.get("decision") == "ALLOW")
    quarantine_count = sum(1 for log in customer_logs if log.get("decision") == "QUARANTINE")
    block_count = sum(1 for log in customer_logs if log.get("decision") == "BLOCK")
    alert_count = len(customer_alerts) if 'customer_alerts' in locals() else 0

    latest_blocked = next(
        (log for log in customer_logs if log.get("decision") == "BLOCK"),
        None
    )

    latest_blocked_html = """
    <div class="summary-card">
        <div class="summary-label">Latest Blocked File</div>
        <div class="summary-value" style="font-size:18px;">No blocked files yet</div>
        <div style="margin-top:8px; color:#6b7280; font-size:13px;">
            No blocked events recorded for this customer.
        </div>
    </div>
    """

    if latest_blocked:
        latest_blocked_html = f"""
        <div class="summary-card">
            <div class="summary-label">Latest Blocked File</div>
            <div class="summary-value" style="font-size:18px; color:#8d1111;">
                {latest_blocked.get("filename", "Unknown")}
            </div>
            <div style="margin-top:8px; color:#6b7280; font-size:13px;">
                Time: {latest_blocked.get("timestamp", "Unknown")}<br>
                Environment: {latest_blocked.get("environment", "Unknown")}
            </div>
        </div>
        """

    recent_activity_logs = customer_logs[:5]

    recent_activity_html = """
    <div class="summary-card">
        <div class="summary-label">Recent Activity</div>
        <div style="color:#6b7280; font-size:13px;">No recent activity yet.</div>
    </div>
    """

    if recent_activity_logs:
        activity_items = ""
        for log in recent_activity_logs:
            decision = log.get("decision", "UNKNOWN")
            decision_color = {
                "ALLOW": "#135c32",
                "QUARANTINE": "#8a5a00",
                "BLOCK": "#8d1111",
            }.get(decision, "#444")

            activity_items += f"""
            <div style="padding:10px 0; border-bottom:1px solid #e8ebf2;">
                <div style="font-weight:600;">{log.get("filename", "Unknown file")}</div>
                <div style="font-size:13px; color:#6b7280;">
                    {log.get("timestamp", "Unknown time")} · {log.get("environment", "Unknown")}
                </div>
                <div style="font-size:13px; font-weight:700; color:{decision_color}; margin-top:4px;">
                {decision}
            </div>
        </div>
        """

    recent_activity_html = f"""
    <div class="summary-card">
      <div class="summary-label">Recent Activity</div>
      {activity_items}
    </div>
    """     

    recent_logs = list(reversed(customer_logs[:10]))
    chart_labels = [log["timestamp"] for log in recent_logs]
    chart_values = []
    for log in recent_logs:
        decision = log.get("decision", "ALLOW")
        if decision == "BLOCK":
            chart_values.append(3)
        elif decision == "QUARANTINE":
            chart_values.append(2)
        else:
            chart_values.append(1)

    rows = ""
    for log in customer_logs:
        risk_class = log["risk"].lower()

        decision = log.get("decision", "UNKNOWN")
        decision_class = {
            "ALLOW": "decision-allow",
            "QUARANTINE": "decision-quarantine",
            "BLOCK": "decision-block",
        }.get(decision, "")

        report_buttons = ""
        if log.get("report_filename"):
            report_buttons = f'''
            <div style="display:flex; gap:8px; align-items:center;">
                <a class="btn btn-sm" href="/report/{log["report_filename"]}" target="_blank">View</a>
                <a class="btn btn-secondary btn-sm" href="/report/{log["report_filename"]}/download">Download</a>
            </div>
            '''

        report_url = f'/report/{log.get("report_filename")}' if log.get("report_filename") else "#"

    
        risk_score = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
        }.get(log.get("risk", "LOW"), 1)

        environment_value = log.get("environment", "Unknown")

        rows += f"""
        <tr
            onclick="window.open('{report_url}', '_blank')"
            style="cursor:pointer;"
            data-filename="{log["filename"].lower()}"
            data-filename-display="{log["filename"]}"
            data-decision="{decision}"
            data-environment="{environment_value}"
            data-timestamp="{log["timestamp"]}"
            data-riskscore="{risk_score}"
            data-risk="{log["risk"]}"
            data-sha256="{log.get("sha256", "")}"
            data-reasons="{' | '.join(log.get('reasons', []))}"
            data-uploaded-by="{log.get("uploaded_by", "Unknown")}"
        >
            <td>{log["timestamp"]}</td>
            <td>{log["filename"]}</td>
            <td>{environment_value}</td>
            <td>{log.get("uploaded_by", "Unknown")}</td>
            <td><span class="badge {risk_class}">{log["risk"]}</span></td>
            <td><span class="badge {decision_class}">{decision}</span></td>
            <td>{report_buttons}</td>
        </tr>
        """
    upload_form_html = ""

    if role in ["admin", "analyst"]:
        upload_form_html = f"""
        <form action="/upload" enctype="multipart/form-data" method="post">
            <input type="hidden" name="customer_name" value="{display_name}">

            <label><b>Environment</b></label><br>
            <input
                type="text"
                name="environment"
                value="Production"
                required
                style="margin-bottom:14px; padding:10px; width:100%; max-width:420px; border:1px solid #d8deea; border-radius:8px;"
            ><br>

            <input type="file" name="file" required style="margin-bottom:14px;"><br>

            <button class="btn" type="submit">Inspect File</button>
        </form>
        """
    else:
        upload_form_html = """
        <div style="padding:12px; background:#f5f7fb; border-radius:10px; color:#6b7280;">
            Your account has view-only access.
        </div>
        """

    admin_tools_html = ""

    if role == "admin":
        admin_tools_html = """
        <p style="margin-top:16px;">
            <a class="btn btn-secondary" href="/audit">Admin Audit Log</a>
        </p>
        """
    alerts_html = """
    <div class="card">
        <h2>Recent Alerts</h2>
        <div style="color:#6b7280; font-size:13px;">No recent alerts.</div>
    </div>
    """

    if customer_alerts:
        alert_items = ""
        for alert in customer_alerts:
            alert_items += f"""
            <div style="padding:10px 0; border-bottom:1px solid #e8ebf2;">
                <div style="font-weight:700; color:#8d1111;">{alert.get("decision", "BLOCK")}</div>
                <div style="margin-top:4px;">{alert.get("message", "")}</div>
                <div style="font-size:13px; color:#6b7280; margin-top:4px;">
                    {alert.get("timestamp", "")} · {alert.get("environment", "")} · {alert.get("uploaded_by", "")}
                </div>
            </div>
            """

        alerts_html = f"""
        <div class="card">
            <h2>Recent Alerts</h2>
            {alert_items}
        </div>
        """

    content = f"""
    <div class="card">
      <h2>{display_name} — PreClear Portal</h2>

      <p style="color:#6b7280; margin-top:-8px;">
        Logged in as <b>{session_user}</b> · Role: <b>{role.title()}</b>
      </p>

      <p style="color:#6b7280; font-size:13px; margin-top:6px;">
        Dashboard auto-refreshes every 15 seconds.
      </p>

      {upload_form_html}

      {admin_tools_html}

      {alerts_html}

      <p style="margin-top:16px;">
        <a class="btn btn-secondary" href="/logout">Log Out</a>
      </p>
    </div>

    <div class="summary-bar">
        <div class="summary-card">
            <div class="summary-label">Total Inspections</div>
            <div class="summary-value">{total_count}</div>
        </div>

        <div class="summary-card">
            <div class="summary-label">Allowed</div>
            <div class="summary-value">{allow_count}</div>
        </div>

        <div class="summary-card">
            <div class="summary-label">Quarantined</div>
            <div class="summary-value">{quarantine_count}</div>
        </div>

        <div class="summary-card">
            <div class="summary-label">Blocked</div>
            <div class="summary-value">{block_count}</div>
        </div>
    </div>

    <div class="card">
        <h2>{display_name} Risk Trend</h2>
        <canvas id="riskTrendChart" height="100"></canvas>
    </div>

    <div class="grid" style="margin-bottom: 20px;">
        {latest_blocked_html}
        {recent_activity_html}
    </div>

    <div class="card">
      <h2>{display_name} Inspection History</h2>
      <div style="display:flex; gap:12px; flex-wrap:wrap; margin-bottom:16px;">
        <input
            type="text"
            id="historySearch"
            placeholder="Search by filename..."
            style="padding:10px; width:260px; border:1px solid #d8deea; border-radius:8px;"
            onkeyup="filterHistoryTable()"
        >

        <select
            id="decisionFilter"
            style="padding:10px; border:1px solid #d8deea; border-radius:8px;"
            onchange="filterHistoryTable()"
        >
            <option value="">All Decisions</option>
            <option value="ALLOW">Allow</option>
            <option value="QUARANTINE">Quarantine</option>
            <option value="BLOCK">Block</option>
        </select>

        <select
            id="environmentFilter"
            style="padding:10px; border:1px solid #d8deea; border-radius:8px;"
            onchange="filterHistoryTable()"
        >
            <option value="">All Environments</option>
            <option value="Production">Production</option>
            <option value="Staging">Staging</option>
            <option value="Shared Intake">Shared Intake</option>
        </select>

        <select
            id="sortFilter"
            style="padding:10px; border:1px solid #d8deea; border-radius:8px;"
            onchange="filterHistoryTable()"
        >
            <option value="newest">Newest First</option>
            <option value="oldest">Oldest First</option>
            <option value="risk_high">Highest Risk First</option>
            <option value="risk_low">Lowest Risk First</option>
            <option value="filename_az">Filename A-Z</option>
            <option value="filename_za">Filename Z-A</option>
        </select>

        <button
            class="btn btn-secondary btn-sm"
            type="button"
            onclick="
                document.getElementById('historySearch').value='';
                document.getElementById('decisionFilter').value='';
                document.getElementById('environmentFilter').value='';
                document.getElementById('sortFilter').value='newest';
                filterHistoryTable();
            "
        >
            Clear Filters
        </button>

        <button
            class="btn btn-secondary btn-sm"
            type="button"
            onclick="exportFilteredRows()"
        >
            Export CSV
        </button>
        </div>

        <form id="filteredExportForm" action="/client/{client_name}/export-filtered" method="post" style="display:none;">
            <input type="hidden" name="filtered_rows_json" id="filteredRowsJson">
        </form>    

      <table>
        <thead>
            <tr>
                <th>Time</th>
                <th>File</th>
                <th>Environment</th>
                <th>Uploaded By</th>
                <th>Risk</th>
                <th>Decision</th>
                <th>Report</th>
            </tr>
        </thead>
        <tbody id="historyTableBody">
            {rows if rows else '<tr><td colspan="7">No inspection history yet.</td></tr>'}
        </tbody>
      </table>
    </div>

    <script>
        function exportFilteredRows() {{
            const rows = Array.from(document.querySelectorAll("#historyTableBody tr"))
                .filter(row => row.style.display !== "none" && row.getAttribute("data-filename-display"));

            const data = rows.map(row => {{
                return {{
                    timestamp: row.getAttribute("data-timestamp"),
                    filename: row.getAttribute("data-filename-display"),
                    environment: row.getAttribute("data-environment"),
                    uploaded_by: row.getAttribute("data-uploaded-by"),
                    risk: row.getAttribute("data-risk"),
                    decision: row.getAttribute("data-decision"),
                    sha256: row.getAttribute("data-sha256"),
                    reasons: row.getAttribute("data-reasons"),
                }};
            }});

            document.getElementById("filteredRowsJson").value = JSON.stringify(data);
            document.getElementById("filteredExportForm").submit();
        }}
    </script>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        const ctx = document.getElementById('riskTrendChart').getContext('2d');

        const riskTrendChart = new Chart(ctx, {{
            type: 'line',
            data: {{
                labels: {chart_labels},
                datasets: [{{
                    label: 'Risk Trend',
                    data: {chart_values},
                    tension: 0.3,
                    fill: false,
                    borderWidth: 2
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    y: {{
                        min: 1,
                        max: 3,
                        ticks: {{
                            stepSize: 1,
                            callback: function(value) {{
                                if (value === 1) return 'Allow';
                                if (value === 2) return 'Quarantine';
                                if (value === 3) return 'Block';
                                return value;
                            }}
                        }}
                    }},
                    x: {{
                        ticks: {{
                            maxRotation: 45,
                            minRotation: 45
                        }}
                    }}
                }}
            }}
        }});
    </script>

    <script>
        function filterHistoryTable() {{
            const searchValue = document.getElementById("historySearch").value.toLowerCase();
            const decisionValue = document.getElementById("decisionFilter").value;
            const environmentValue = document.getElementById("environmentFilter").value;
            const sortValue = document.getElementById("sortFilter").value;

            const tbody = document.getElementById("historyTableBody");
            const rows = Array.from(tbody.querySelectorAll("tr"));

                const filteredRows = rows.filter(row => {{
                const filename = row.getAttribute("data-filename");
                const decision = row.getAttribute("data-decision");
                const environment = row.getAttribute("data-environment");

                if (!filename || !decision || !environment) {{
                    return false;
                }}

                const matchesSearch = filename.includes(searchValue);
                const matchesDecision = decisionValue === "" || decision === decisionValue;
                const matchesEnvironment = environmentValue === "" || environment === environmentValue;

                return matchesSearch && matchesDecision && matchesEnvironment;
            }});
        }}

        filteredRows.sort((a, b) => {{
            if (sortValue === "oldest") {{
                return a.getAttribute("data-timestamp").localeCompare(b.getAttribute("data-timestamp"));
            }}

            if (sortValue === "risk_high") {{
                return Number(b.getAttribute("data-riskscore")) - Number(a.getAttribute("data-riskscore"));
            }}

            if (sortValue === "risk_low") {{
                return Number(a.getAttribute("data-riskscore")) - Number(b.getAttribute("data-riskscore"));
            }}

            if (sortValue === "filename_az") {{
                return a.getAttribute("data-filename").localeCompare(b.getAttribute("data-filename"));
            }}

            if (sortValue === "filename_za") {{
                return b.getAttribute("data-filename").localeCompare(a.getAttribute("data-filename"));
            }}

            return b.getAttribute("data-timestamp").localeCompare(a.getAttribute("data-timestamp"));
        }});

        rows.forEach(row => {{
            row.style.display = "none";
        }});
    </script>

    <script>
        let userActive = false;

        document.addEventListener("mousemove", () => userActive = true);
        document.addEventListener("keydown", () => userActive = true);

        setInterval(() => {{
            if (!userActive) {{
                window.location.reload();
            }}
            userActive = false;
        }}, 15000);
    </script>
    """
    return page_shell(content, title=f"{display_name} Portal")

@app.get("/logout")
async def logout(request: Request):
    username = request.session.get("username", "")
    display_name = request.session.get("display_name", "")
    client_slug = request.session.get("client_slug", "")
    role = request.session.get("role", "viewer")

    if username:
        save_audit_event(
            event_type="LOGOUT",
            customer_name=display_name,
            client_slug=client_slug,
            username=username,
            role=role,
        )

    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)

@app.get("/report/{filename}")
async def view_report(filename: str):
    file_path = REPORT_DIR / filename
    if file_path.exists():
        return FileResponse(
            path=file_path,
            media_type="application/pdf",
            headers={"Content-Disposition": "inline"}
        )
    return {"error": "File not found"}

@app.get("/report/{filename}/download")
async def download_report(filename: str):
    file_path = REPORT_DIR / filename
    if file_path.exists():
        return FileResponse(
            path=file_path,
            filename="PreClear_Report.pdf",
            media_type="application/pdf"
        )
    return {"error": "File not found"}

@app.post("/upload", response_class=HTMLResponse)
async def upload_file(
    request: Request,
    customer_name: str = Form(...),
    environment: str = Form(...),
    file: UploadFile = File(...)
):
    session_user = request.session.get("username", "unknown_user")
    role = request.session.get("role", "viewer")
    client_slug = request.session.get("client_slug", "unknown_client")

    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    safe_name = f"{uuid.uuid4().hex}_{file.filename}"
    save_path = UPLOAD_DIR / safe_name

    with open(save_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    result = inspect_file(save_path, file.filename)

    report_id = uuid.uuid4().hex[:10].upper()
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    report_filename = f"{uuid.uuid4().hex}.pdf"
    report_path = REPORT_DIR / report_filename

    generate_pdf_report(
        result,
        report_path,
        customer_name=customer_name,
        environment=environment,
        report_id=report_id,
        generated_at=generated_at,
        uploaded_by=session_user,
        uploaded_by_role=role,
    )

    session_user = request.session.get("username", "unknown_user")
    role = request.session.get("role", "viewer")
    client_slug = request.session.get("client_slug", "unknown_client")

    log_entry = {
        "id": uuid.uuid4().hex[:10],
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "event_type": "UPLOAD_INSPECTION",
        "customer_name": customer_name,
        "client_slug": client_slug,
        "environment": environment,
        "uploaded_by": session_user,
        "uploaded_by_role": role,
        "report_filename": report_filename,
        **result,
    }
    save_log(log_entry)

    if result["decision"] == "BLOCK":
        alert_entry = {
            "id": uuid.uuid4().hex[:10],
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "customer_name": customer_name,
            "client_slug": client_slug,
            "environment": environment,
            "uploaded_by": session_user,
            "uploaded_by_role": role,
            "filename": result["filename"],
            "risk": result["risk"],
            "decision": result["decision"],
            "message": f"Blocked file detected before system ingress: {result['filename']}",
        }

        slack_message = (
            f"🚫 *PreClear Pilot BLOCK Alert*\n"
            f"*Customer:* {customer_name}\n"
            f"*Environment:* {environment}\n"
            f"*File:* {result['filename']}\n"
            f"*Risk:* {result['risk']}\n"
            f"*Decision:* {result['decision']}\n"
            f"*Uploaded By:* {session_user} ({role})\n"
            f"*Time:* {alert_entry['timestamp']}"
        )

        slack_sent = send_slack_alert(slack_message)
        alert_entry["external_alert_sent"] = slack_sent

        save_alert(alert_entry)

    session_user = str(session_user)

    client_slug = request.session.get("client_slug")
    back_link = f"/client/{client_slug}" if client_slug else "/"
    back_label = "Back to Portal" if session_user else "Back to Dashboard"

    risk_class = result["risk"].lower()
    reasons_html = "".join(f"<li>{reason}</li>" for reason in result["reasons"])

    banner_html = ""
    if result["decision"] == "BLOCK":
        banner_html = """
        <div style="background:#fde0e0; color:#8d1111; padding:16px; border-radius:12px; font-weight:700; margin-bottom:16px; border:1px solid #f3b5b5;">
          BLOCKED BEFORE ENTERING SYSTEM
        </div>
      """
    elif result["decision"] == "QUARANTINE":
        banner_html = """
        <div style="background:#fff2d6; color:#8a5a00; padding:16px; border-radius:12px; font-weight:700; margin-bottom:16px; border:1px solid #f0d08a;">
          QUARANTINED BEFORE INTERNAL ACCESS
        </div>
        """

    vt_html = """
    <div class="card">
      <h3>VirusTotal Hash Lookup</h3>
      <p>
        No existing VirusTotal record was found for this file hash.
        Local inspection rules were used for the decision.
      </p>
    </div>
    """

    if result["vt_result"]:
        vt = result["vt_result"]
        vt_html = f"""
        <div class="card">
          <h3>VirusTotal Hash Lookup</h3>
          <p>
            Malicious: <b>{vt.get("malicious", 0)}</b><br>
            Suspicious: <b>{vt.get("suspicious", 0)}</b><br>
            Harmless: <b>{vt.get("harmless", 0)}</b><br>
            Undetected: <b>{vt.get("undetected", 0)}</b>
          </p>
        </div>
        """

    content = f"""
    <div class="card">
      {banner_html}
      <h2>Inspection Result</h2>
      <p><b>Filename:</b> {result["filename"]}</p>
      <p><b>Customer:</b> {customer_name}</p>
      <p><b>Environment:</b> {environment}</p>
      <p><b>Report ID:</b> {report_id}</p>
      <p><b>Generated At:</b> {generated_at}</p>
      <p><b>SHA-256:</b> <code>{result["sha256"]}</code></p>
      <p><b>MIME Type:</b> {result["mime_type"]}</p>
      <p><b>Size:</b> {result["size_mb"]} MB</p>

      <p>
        <b>Risk:</b>
        <span class="badge {risk_class}">{result["risk"]}</span>
      </p>

      <p><b>Decision:</b> {result["decision"]}</p>

      <h3>Reasons</h3>
      <ul>{reasons_html}</ul>

      <p style="margin-top:20px;">
        <a class="btn" href="/report/{report_filename}">Download Inspection Report (PDF)</a>
      </p>

      <p style="margin-top:10px;">
        <a class="btn btn-secondary" href="{back_link}">{back_label}</a>
      </p>
    </div>

    {vt_html}
    """
    return page_shell(content, title="Inspection Result")


@app.post("/api/upload")
async def api_upload_file(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    safe_name = f"{uuid.uuid4().hex}_{file.filename}"
    save_path = UPLOAD_DIR / safe_name

    with open(save_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    result = inspect_file(save_path, file.filename)

    customer_name = str(customer_name)
    environment = str(environment)

    log_entry = {
        "id": uuid.uuid4().hex[:10],
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "customer_name": customer_name,
        "environment": environment,
        **result,
    }
    save_log(log_entry)

    return JSONResponse(log_entry)

@app.get("/client/{client_name}/export")
async def export_customer_history(client_name: str, request: Request):
    session_user = request.session.get("username")
    display_name = request.session.get("display_name")
    client_slug = request.session.get("client_slug")
    role = request.session.get("role", "viewer")

    if not session_user:
        return RedirectResponse(url="/login", status_code=302)

    if client_slug != client_name:
        content = """
        <div class="card">
            <h2>Access Denied</h2>
            <p>You are not authorized to export this customer history.</p>
            <p><a class="btn btn-secondary" href="/login">Return to Login</a></p>
        </div>
        """
        return HTMLResponse(page_shell(content, title="Access Denied"))

    if role not in ["admin", "analyst"]:
        content = f"""
        <div class="card">
            <h2>Access Denied</h2>
            <p>Your account does not have permission to export data.</p>
            <p><a class="btn btn-secondary" href="/client/{client_name}">Return to Portal</a></p>
        </div>
        """
        return HTMLResponse(page_shell(content, title="Access Denied"))

    logs = get_customer_logs(display_name, limit=500)

    export_filename = f"{client_name}_history_export.csv"
    export_path = REPORT_DIR / export_filename

    with open(export_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "Timestamp",
            "Customer",
            "Environment",
            "Filename",
            "Risk",
            "Decision",
            "SHA-256",
            "Reasons",
        ])

        for log in logs:
            writer.writerow([
                log.get("timestamp", ""),
                log.get("customer_name", ""),
                log.get("environment", ""),
                log.get("filename", ""),
                log.get("risk", ""),
                log.get("decision", ""),
                log.get("sha256", ""),
                " | ".join(log.get("reasons", [])),
            ])

    save_audit_event(
        event_type="EXPORT_FULL_CSV",
        customer_name=request.session.get("display_name", ""),
        client_slug=request.session.get("client_slug", ""),
        username=request.session.get("username", ""),
        role=request.session.get("role", "viewer"),
    )

    return FileResponse(
        path=export_path,
        filename=export_filename,
        media_type="text/csv",
    )

@app.get("/api/history")
async def api_history():
    return load_logs()[:50]

@app.get("/audit", response_class=HTMLResponse)
async def audit_log_page(request: Request):
    session_user = request.session.get("username")
    display_name = request.session.get("display_name")
    role = request.session.get("role", "viewer")

    if not session_user:
        return RedirectResponse(url="/login", status_code=302)

    if role != "admin":
        content = """
        <div class="card">
          <h2>Access Denied</h2>
          <p>Only admin users can access the audit log.</p>
          <p><a class="btn btn-secondary" href="/">Return</a></p>
        </div>
        """
        return HTMLResponse(page_shell(content, title="Access Denied"))

    audit_logs = get_all_audit_logs()

    rows = ""
    for log in audit_logs:
        decision = log.get("decision", "-")
        decision_class = {
            "ALLOW": "decision-allow",
            "QUARANTINE": "decision-quarantine",
            "BLOCK": "decision-block",
        }.get(decision, "")

        event_type = log.get("event_type", "UNKNOWN")
        event_type = log.get("event_type", "UNKNOWN")
        customer_name = log.get("customer_name", "Unknown")
        filename = log.get("filename", "—")
        uploaded_by = log.get("uploaded_by", "Unknown")

        rows += f"""
        <tr
            data-event="{event_type}"
            data-user="{str(uploaded_by).lower()}"
            data-search="{str(customer_name).lower()} {str(filename).lower()}"
        >
            <td>{log.get("timestamp", "Unknown")}</td>
            <td>{event_type}</td>
            <td>{customer_name}</td>
            <td>{log.get("environment", "—")}</td>
            <td>{uploaded_by}</td>
            <td>{str(log.get("uploaded_by_role", "Unknown")).title()}</td>
            <td>{filename}</td>
            <td><span class="badge {decision_class}">{decision}</span></td>
        </tr>
        """

    content = f"""
    <div class="card">
      <h2>Admin Audit Log</h2>
      <p style="color:#6b7280; margin-top:-8px;">
        Logged in as <b>{session_user}</b> · Customer: <b>{display_name}</b> · Role: <b>{role.title()}</b>
      </p>

      <p style="color:#6b7280; font-size:13px; margin-top:6px;">
        Audit log auto-refreshes every 20 seconds.
      </p>

      <p style="margin-top:16px; display:flex; gap:10px; flex-wrap:wrap;">
        <a class="btn btn-secondary" href="/client/{request.session.get('client_slug')}">Back to Portal</a>
        <a class="btn btn-secondary" href="/audit/export">Export Audit CSV</a>
      </p>
    </div>

    <div class="card">
      <h2>Inspection Audit Trail</h2>

      <div style="display:flex; gap:12px; flex-wrap:wrap; margin-bottom:16px;">
        <input
            type="text"
            id="auditSearch"
            placeholder="Search by file or customer..."
            style="padding:10px; width:260px; border:1px solid #d8deea; border-radius:8px;"
            onkeyup="filterAuditTable()"
        >

        <select
            id="auditEventFilter"
            style="padding:10px; border:1px solid #d8deea; border-radius:8px;"
            onchange="filterAuditTable()"
        >
            <option value="">All Events</option>
            <option value="LOGIN">LOGIN</option>
            <option value="LOGOUT">LOGOUT</option>
            <option value="UPLOAD_INSPECTION">UPLOAD_INSPECTION</option>
            <option value="EXPORT_FULL_CSV">EXPORT_FULL_CSV</option>
            <option value="EXPORT_FILTERED_CSV">EXPORT_FILTERED_CSV</option>
            <option value="EXPORT_AUDIT_CSV">EXPORT_AUDIT_CSV</option>
        </select>

        <input
            type="text"
            id="auditUserFilter"
            placeholder="Filter by username..."
            style="padding:10px; width:220px; border:1px solid #d8deea; border-radius:8px;"
            onkeyup="filterAuditTable()"
        >

        <button
            class="btn btn-secondary btn-sm"
            type="button"
            onclick="
                document.getElementById('auditSearch').value='';
                document.getElementById('auditEventFilter').value='';
                document.getElementById('auditUserFilter').value='';
                filterAuditTable();
            "
        >
         Clear Filters
        </button>
    </div>

      <table id="auditTable">
        <thead>
            <tr>
                <th onclick="sortAuditTable(0, this)" style="cursor:pointer;">Time <span class="sort-indicator"></span></th>
                <th onclick="sortAuditTable(1, this)" style="cursor:pointer;">Event <span class="sort-indicator"></span></th>
                <th onclick="sortAuditTable(2, this)" style="cursor:pointer;">Customer <span class="sort-indicator"></span></th>
                <th onclick="sortAuditTable(3, this)" style="cursor:pointer;">Environment <span class="sort-indicator"></span></th>
                <th onclick="sortAuditTable(4, this)" style="cursor:pointer;">User <span class="sort-indicator"></span></th>
                <th onclick="sortAuditTable(5, this)" style="cursor:pointer;">Role <span class="sort-indicator"></span></th>
                <th onclick="sortAuditTable(6, this)" style="cursor:pointer;">File <span class="sort-indicator"></span></th>
                <th onclick="sortAuditTable(7, this)" style="cursor:pointer;">Decision <span class="sort-indicator"></span></th>
            </tr>
        </thead>
        <tbody id="auditTableBody">
          {rows if rows else '<tr><td colspan="8">No audit entries found.</td></tr>'}
        </tbody>
      </table>

     <script>
        function filterAuditTable() {{
            const searchValue = document.getElementById("auditSearch").value.toLowerCase();
            const eventValue = document.getElementById("auditEventFilter").value;
            const userValue = document.getElementById("auditUserFilter").value.toLowerCase();

            const rows = document.querySelectorAll("#auditTableBody tr");

            rows.forEach(row => {{
                const eventType = row.getAttribute("data-event");
                const username = row.getAttribute("data-user");
                const searchText = row.getAttribute("data-search");

                if (!eventType || !username || !searchText) {{
                    return;
                }}

                const matchesSearch = searchText.includes(searchValue);
                const matchesEvent = eventValue === "" || eventType === eventValue;
                const matchesUser = username.includes(userValue);

                if (matchesSearch && matchesEvent && matchesUser) {{
                    row.style.display = "";
                }} else {{
                     row.style.display = "none";
                }}
            }});
        }}
    </script>

    <script>
        let auditSortDirection = {{}};

            function sortAuditTable(columnIndex, headerElement) {{
            const table = document.getElementById("auditTable");
            const tbody = document.getElementById("auditTableBody");
            const rows = Array.from(tbody.querySelectorAll("tr"));

            const currentDirection = auditSortDirection[columnIndex] || "asc";
            const newDirection = currentDirection === "asc" ? "desc" : "asc";
            auditSortDirection = {{}}; // reset all
            auditSortDirection[columnIndex] = newDirection;

            rows.sort((a, b) => {{
                const aText = a.children[columnIndex]?.innerText.trim().toLowerCase() || "";
                const bText = b.children[columnIndex]?.innerText.trim().toLowerCase() || "";

                return newDirection === "asc"
                    ? aText.localeCompare(bText)
                    : bText.localeCompare(aText);
            }});

            rows.forEach(row => tbody.appendChild(row));

            // 🔥 Update indicators
            document.querySelectorAll(".sort-indicator").forEach(el => el.innerText = "");

            const indicator = headerElement.querySelector(".sort-indicator");
            if (indicator) {{
                indicator.innerText = newDirection === "asc" ? " ▲" : " ▼";
            }}
        }}
    </script>

    <script>
        let userActive = false;

        document.addEventListener("mousemove", () => userActive = true);
        document.addEventListener("keydown", () => userActive = true);

        setInterval(() => {{
            if (!userActive) {{
                window.location.reload();
            }}
            userActive = false;
        }}, 20000);
    </script>
    </div>
    """

    return page_shell(content, title="Admin Audit Log")

@app.get("/audit/export")
async def export_audit_log(request: Request):
    session_user = request.session.get("username")
    role = request.session.get("role", "viewer")

    if not session_user:
        return RedirectResponse(url="/login", status_code=302)

    if role != "admin":
        content = """
        <div class="card">
          <h2>Access Denied</h2>
          <p>Only admin users can export the audit log.</p>
          <p><a class="btn btn-secondary" href="/login">Return</a></p>
        </div>
        """
        return HTMLResponse(page_shell(content, title="Access Denied"))

    audit_logs = get_all_audit_logs(limit=1000)

    export_filename = "preclear_audit_log.csv"
    export_path = REPORT_DIR / export_filename

    with open(export_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "Timestamp",
            "Customer",
            "Client Slug",
            "Environment",
            "Uploaded By",
            "Uploader Role",
            "Filename",
            "Risk",
            "Decision",
            "SHA-256",
            "Report Filename",
            "Reasons",
        ])

        for log in audit_logs:
            writer.writerow([
                log.get("timestamp", ""),
                log.get("customer_name", ""),
                log.get("client_slug", ""),
                log.get("environment", ""),
                log.get("uploaded_by", ""),
                log.get("uploaded_by_role", ""),
                log.get("filename", ""),
                log.get("risk", ""),
                log.get("decision", ""),
                log.get("sha256", ""),
                log.get("report_filename", ""),
                " | ".join(log.get("reasons", [])),
            ])

    save_audit_event(
        event_type="EXPORT_AUDIT_CSV",
        customer_name=request.session.get("display_name", ""),
        client_slug=request.session.get("client_slug", ""),
        username=request.session.get("username", ""),
        role=request.session.get("role", "viewer"),
    )

    return FileResponse(
        path=export_path,
        filename=export_filename,
        media_type="text/csv",
    )