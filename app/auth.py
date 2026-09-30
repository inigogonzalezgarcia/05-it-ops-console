"""Authentication, account status, section permissions and CSRF protection.

Sign-in has two steps:
1. Password: LDAPS pass-through bind (never stored). Demo mode accepts "demo".
   Only accounts an administrator has invited can get past this step.
2. Second factor: an emailed activation code the first time, then a TOTP code
   from an authenticator app on every sign-in (see mfa.py).
"""

import hmac
import re
import secrets
import time
from functools import wraps

from flask import abort, current_app, flash, redirect, request, session, url_for

from . import db

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def ldap_bind(username: str, password: str) -> bool:
    """Try a simple bind with the user's own credentials. Returns True on success."""
    try:
        from ldap3 import Connection, Server  # optional dependency
    except ImportError:
        current_app.logger.error("AUTH_MODE=ldap needs the ldap3 package")
        return False
    url = current_app.config["LDAP_URL"]
    if not url.startswith("ldaps://"):
        current_app.logger.error("Refusing to send credentials over plain LDAP; use ldaps://")
        return False
    user = current_app.config["LDAP_USER_TEMPLATE"].format(username=username)
    try:
        conn = Connection(Server(url, connect_timeout=5), user=user, password=password, receive_timeout=10)
        ok = conn.bind()
        conn.unbind()
        return bool(ok)
    except Exception:  # network or TLS errors must not leak details to the login page
        current_app.logger.exception("LDAP bind failed")
        return False


def authenticate(username: str, password: str) -> bool:
    if not USERNAME_RE.match(username or "") or not password:
        return False
    if current_app.config["AUTH_MODE"] == "ldap":
        return ldap_bind(username, password)
    # demo mode: fixed demo password, no directory needed
    return hmac.compare_digest(password, "demo")


PENDING_TTL_SECONDS = 600
PENDING_MAX_ATTEMPTS = 5


def start_pending(username: str) -> None:
    """Password accepted; the second factor is still missing. Nothing is granted yet."""
    session.clear()
    session["pending_user"] = username
    session["pending_since"] = int(time.time())
    session["pending_attempts"] = 0
    session["csrf"] = secrets.token_hex(16)


def pending_user() -> str | None:
    username = session.get("pending_user")
    if not username or time.time() - session.get("pending_since", 0) > PENDING_TTL_SECONDS \
            or session.get("pending_attempts", 0) >= PENDING_MAX_ATTEMPTS:
        return None
    return username


def count_attempt() -> None:
    session["pending_attempts"] = session.get("pending_attempts", 0) + 1


def allowed_sections(username: str | None) -> set[str]:
    if not username:
        return set()
    rows = db.query("SELECT rs.section FROM users u JOIN role_sections rs ON rs.role = u.role "
                    "WHERE u.username = ? AND u.status = 'active'", (username,))
    return {r["section"] for r in rows}


def login_user(username: str) -> None:
    """Both factors passed: start a real session (new session id and CSRF token)."""
    session.clear()
    session["username"] = username
    session["csrf"] = secrets.token_hex(16)
    db.execute("UPDATE users SET last_login = ? WHERE username = ?", (db.now(), username))
    db.audit("login")


def require_section(section: str):
    """Decorator: the user must be signed in and their role must include `section`."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            username = session.get("username")
            user = db.query("SELECT status FROM users WHERE username = ?", (username,), one=True) if username else None
            if not user or user["status"] != "active":  # disabled mid-session: out at the next click
                session.clear()
                return redirect(url_for("views.login", next=request.path))
            if section not in allowed_sections(username):
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def csrf_protect() -> None:
    """Reject state-changing requests that do not carry the session's CSRF token."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.endpoint != "views.login":
        sent = request.form.get("csrf") or request.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Invalid or missing CSRF token")


def init_app(app) -> None:
    app.before_request(csrf_protect)

    @app.context_processor
    def inject_user():
        username = session.get("username")
        return {"current_user": username, "csrf_token": session.get("csrf", ""),
                "nav": [(k, v) for k, v in db.SECTIONS.items() if k in allowed_sections(username)]}

    @app.errorhandler(403)
    def forbidden(_e):
        flash("You do not have access to that section.")
        return redirect(url_for("views.dashboard")) if session.get("username") else redirect(url_for("views.login"))
