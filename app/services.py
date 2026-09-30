"""Integrations: remote device queries, directory discovery, warranty lookup,
service health checks and outbound webhook events.

Each integration has a demo implementation, so the console works end to end
with fictional data and without access to a real network.
"""

import hashlib
import hmac
import json
import os
import random
import re
import subprocess
import tempfile
import threading
import time
import urllib.request
from datetime import date, timedelta
from pathlib import Path

from flask import current_app

from . import db

HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "Get-DeviceInfo.ps1"


# --------------------------------------------------------------------- webhooks

def emit(event: str, payload: dict) -> None:
    """Send an event to the configured webhook in the background.

    The console only says *what happened*; the automation tool on the other side
    (for example n8n) decides who gets notified and how.
    """
    url = current_app.config.get("WEBHOOK_URL")
    if not url:
        return
    body = json.dumps({"event": event, "at": db.now(), "data": payload}, default=str).encode()
    headers = {"Content-Type": "application/json"}
    secret = current_app.config.get("WEBHOOK_SECRET")
    if secret:
        headers["X-Signature-SHA256"] = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    logger = current_app.logger

    def send():
        try:
            urllib.request.urlopen(urllib.request.Request(url, data=body, headers=headers), timeout=5)
        except Exception as exc:  # a failed notification must never break the user's action
            logger.warning("Webhook %s failed: %s", event, exc)

    threading.Thread(target=send, daemon=True).start()


# --------------------------------------------------------------- remote queries

def _demo_device_info(hostname: str, kind: str) -> dict:
    rng = random.Random(hostname)
    if kind == "serial":
        return {"serial": "DEMO" + hashlib.sha1(hostname.encode()).hexdigest()[:8].upper()}
    if kind == "software":
        catalogue = [("Microsoft 365 Apps", "16.0", "Microsoft"), ("Google Chrome", "129.0", "Google"),
                     ("Zoom Workplace", "6.2", "Zoom"), ("7-Zip", "24.08", "Igor Pavlov"),
                     ("Adobe Acrobat Reader", "24.3", "Adobe"), ("Notepad++", "8.6", "Notepad++"),
                     ("Python", "3.12", "Python Software Foundation"), ("VLC media player", "3.0", "VideoLAN")]
        return {"software": [dict(zip(("name", "version", "publisher"), s))
                             for s in rng.sample(catalogue, rng.randint(4, len(catalogue)))]}
    return {"cpu_percent": rng.randint(3, 60), "free_disk_gb": rng.randint(12, 180),
            "uptime_days": rng.randint(0, 40)}


def query_device(hostname: str, kind: str, username: str | None = None, password: str | None = None) -> dict:
    """Run a remote query ("serial", "software" or "health") against one Windows device."""
    if not HOSTNAME_RE.match(hostname or ""):
        raise ValueError("Invalid hostname")
    if kind not in ("serial", "software", "health"):
        raise ValueError("Unknown query")
    if current_app.config["REMOTE_MODE"] != "powershell":
        return _demo_device_info(hostname, kind)

    # Credentials go through stdin, never argv: command lines are visible to other
    # users of the host in the process list. The result is written to a temp file
    # instead of stdout, so module banners and warnings cannot corrupt the JSON.
    fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        creds = json.dumps({"username": username or "", "password": password or ""})
        proc = subprocess.run(
            [current_app.config["POWERSHELL"], "-NoProfile", "-NonInteractive", "-File", str(SCRIPT),
             "-ComputerName", hostname, "-Query", kind, "-OutFile", out_path],
            input=creds, capture_output=True, text=True, timeout=90)
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or "PowerShell failed").strip()[:300])
        return json.loads(Path(out_path).read_text(encoding="utf-8-sig"))
    finally:
        Path(out_path).unlink(missing_ok=True)


# ------------------------------------------------------------ directory discovery

def discover_computers() -> list[dict]:
    """Phase 1 of the warranty flow: which machines exist.

    LDAP mode reads computer objects from the configured OU with a service
    account (OPS_LDAP_BIND_USER / OPS_LDAP_BIND_PASSWORD). Demo mode returns the
    assets already in the database.
    """
    if current_app.config["AUTH_MODE"] != "ldap" or not current_app.config["LDAP_SEARCH_BASE"]:
        return [dict(r) for r in db.query("SELECT hostname, os FROM assets")]
    from ldap3 import SUBTREE, Connection, Server

    conn = Connection(Server(current_app.config["LDAP_URL"], connect_timeout=5),
                      user=os.environ.get("OPS_LDAP_BIND_USER"),
                      password=os.environ.get("OPS_LDAP_BIND_PASSWORD"), auto_bind=True)
    conn.search(current_app.config["LDAP_SEARCH_BASE"], "(objectClass=computer)", SUBTREE,
                attributes=["dNSHostName", "operatingSystem"], paged_size=500)
    found = [{"hostname": str(e.dNSHostName), "os": str(e.operatingSystem)}
             for e in conn.entries if e.dNSHostName.value]
    conn.unbind()
    return found


# --------------------------------------------------------------------- warranty

def lookup_warranty(manufacturer: str, serial: str) -> str | None:
    """Phase 2: warranty end date (ISO) for one machine.

    Every vendor exposes warranty data differently (API keys, portals, CSV), so
    this is the extension point. The demo provider derives a stable fake date
    from the serial number.
    """
    if not serial:
        return None
    seed = int(hashlib.sha1(serial.encode()).hexdigest()[:8], 16)
    return (date.today() + timedelta(days=seed % 1300 - 300)).isoformat()


def warranty_status(expires_on: str | None, warn_days: int) -> str:
    if not expires_on:
        return "unknown"
    days = (date.fromisoformat(expires_on) - date.today()).days
    return "expired" if days < 0 else "expiring" if days <= warn_days else "active"


# ---------------------------------------------------------------- health checks

def check_endpoint(url: str, timeout: float = 5.0, slow_ms: int = 1500) -> tuple[str, int | None, str]:
    """Return (status, latency_ms, detail) where status is up, degraded or down."""
    if url.startswith("demo://"):  # simulated endpoint used by the demo data
        rng = random.Random(f"{url}{int(time.time() // 300)}")  # stable for 5 minutes
        roll = rng.random()
        if roll < 0.08:
            return "down", None, "Connection timed out"
        latency = rng.randint(1600, 3000) if roll < 0.2 else rng.randint(40, 600)
        return ("degraded" if latency > slow_ms else "up"), latency, "HTTP 200"
    start = time.monotonic()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            latency = int((time.monotonic() - start) * 1000)
            return ("degraded" if latency > slow_ms else "up"), latency, f"HTTP {resp.status}"
    except Exception as exc:
        return "down", None, str(exc)[:200]


def run_health_checks() -> list[dict]:
    results = []
    for ep in db.query("SELECT * FROM endpoints ORDER BY name"):
        status, latency, detail = check_endpoint(ep["url"])
        db.execute("UPDATE endpoints SET status = ?, latency_ms = ?, detail = ?, checked_at = ? WHERE name = ?",
                   (status, latency, detail, db.now(), ep["name"]))
        if status != ep["status"] and status in ("down", "degraded"):
            emit("service.status_changed", {"service": ep["name"], "severity": ep["severity"],
                                             "from": ep["status"], "to": status, "detail": detail})
        results.append({"name": ep["name"], "status": status})
    return results
