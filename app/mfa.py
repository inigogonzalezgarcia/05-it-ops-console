"""Second factor and account activation.

- Activation codes: 6 characters, sent by email, used once to prove the person
  controls the mailbox before an account becomes active.
- TOTP (RFC 6238): the daily second factor, from any authenticator app.
- Email delivery: an in-app outbox (demo), SMTP with STARTTLS, or the webhook.

Standard library only; `segno` is optional and only used to draw the QR code.
"""

import base64
import hashlib
import hmac
import secrets
import smtplib
import struct
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from urllib.parse import quote

from flask import current_app

from . import db

CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O or 1/I to avoid typos
CODE_LENGTH = 6
CODE_TTL_MINUTES = 10
CODE_MAX_ATTEMPTS = 5
CODE_MIN_INTERVAL_SECONDS = 60  # at most one new code per minute per user
TOTP_STEP = 30
TOTP_DIGITS = 6


# ------------------------------------------------------------ activation codes

def _hash_code(code: str) -> str:
    key = current_app.config["SECRET_KEY"].encode()
    return hmac.new(key, code.upper().encode(), hashlib.sha256).hexdigest()


def _utc(dt: str) -> datetime:
    return datetime.strptime(dt, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


def issue_activation_code(username: str, email: str) -> bool:
    """Create a code, store only its hash and email it. False if one was sent too recently."""
    last = db.query("SELECT created_at FROM one_time_codes WHERE username = ? ORDER BY id DESC LIMIT 1",
                    (username,), one=True)
    if last and (datetime.now(timezone.utc) - _utc(last["created_at"])).total_seconds() < CODE_MIN_INTERVAL_SECONDS:
        return False
    code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
    expires = (datetime.now(timezone.utc) + timedelta(minutes=CODE_TTL_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
    db.execute("UPDATE one_time_codes SET used = 1 WHERE username = ? AND used = 0", (username,))
    db.execute("INSERT INTO one_time_codes (username, code_hash, expires_at, created_at) VALUES (?, ?, ?, ?)",
               (username, _hash_code(code), expires, db.now()))
    send_email(email, "Your IT Ops Console activation code",
               f"Your activation code is: {code}\n\nIt expires in {CODE_TTL_MINUTES} minutes and can be used once.\n"
               "If you did not try to sign in, tell your IT administrator.")
    db.audit("mfa.code_sent", {"user": username})
    return True


def verify_activation_code(username: str, code: str) -> bool:
    row = db.query("SELECT * FROM one_time_codes WHERE username = ? AND used = 0 ORDER BY id DESC LIMIT 1",
                   (username,), one=True)
    if not row:
        return False
    if _utc(row["expires_at"]) < datetime.now(timezone.utc) or row["attempts"] >= CODE_MAX_ATTEMPTS:
        db.execute("UPDATE one_time_codes SET used = 1 WHERE id = ?", (row["id"],))
        return False
    db.execute("UPDATE one_time_codes SET attempts = attempts + 1 WHERE id = ?", (row["id"],))
    if hmac.compare_digest(row["code_hash"], _hash_code((code or "").strip())):
        db.execute("UPDATE one_time_codes SET used = 1 WHERE id = ?", (row["id"],))
        return True
    return False


# ------------------------------------------------------------------------ TOTP

def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_at(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** TOTP_DIGITS).zfill(TOTP_DIGITS)


def current_step(now: float | None = None) -> int:
    return int((now if now is not None else time.time()) // TOTP_STEP)


def verify_totp(secret: str, code: str, last_step: int | None = None, now: float | None = None) -> int | None:
    """Return the matched time step, or None. Accepts one step of clock drift and
    rejects a step that was already used (no replay)."""
    code = (code or "").strip().replace(" ", "")
    if not secret or len(code) != TOTP_DIGITS or not code.isdigit():
        return None
    step = current_step(now)
    for candidate in (step - 1, step, step + 1):
        if (last_step is None or candidate > last_step) and hmac.compare_digest(totp_at(secret, candidate), code):
            return candidate
    return None


def provisioning_uri(username: str, secret: str, issuer: str = "IT Ops Console") -> str:
    return (f"otpauth://totp/{quote(issuer)}:{quote(username)}?secret={secret}"
            f"&issuer={quote(issuer)}&digits={TOTP_DIGITS}&period={TOTP_STEP}")


def qr_svg(uri: str) -> str | None:
    """Inline SVG QR code if `segno` is installed; otherwise the page shows the key to type in."""
    try:
        import segno
    except ImportError:
        return None
    return segno.make(uri, error="m").svg_inline(scale=5, dark="#0b0b0b", light="#ffffff")


# ----------------------------------------------------------------------- email

def send_email(to: str, subject: str, body: str) -> None:
    mode = current_app.config["EMAIL_MODE"]
    if mode == "smtp":
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = current_app.config["SMTP_FROM"], to, subject
        msg.set_content(body)
        with smtplib.SMTP(current_app.config["SMTP_HOST"], int(current_app.config["SMTP_PORT"]), timeout=15) as smtp:
            smtp.starttls()
            if current_app.config["SMTP_USER"]:
                smtp.login(current_app.config["SMTP_USER"], current_app.config["SMTP_PASSWORD"])
            smtp.send_message(msg)
    elif mode == "webhook":
        from .services import emit
        emit("email.send", {"to": to, "subject": subject, "body": body})
    else:  # outbox: kept in the database so the demo works without a mail server
        db.execute("INSERT INTO outbox (recipient, subject, body, created_at) VALUES (?, ?, ?, ?)",
                   (to, subject, body, db.now()))
