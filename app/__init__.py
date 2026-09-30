"""IT Ops Console: a lightweight operations dashboard for on-site IT teams."""

import os
import secrets
from pathlib import Path

from flask import Flask

from . import auth, db, views

DEFAULTS = {
    # "demo" uses seeded users and simulated remote queries; "ldap" uses a real directory.
    "AUTH_MODE": "demo",
    "DATABASE": "instance/console.db",
    "LDAP_URL": "",                  # e.g. ldaps://dc01.example.internal
    "LDAP_USER_TEMPLATE": "{username}@example.internal",
    "LDAP_SEARCH_BASE": "",          # OU to discover computers, e.g. OU=Workstations,DC=example,DC=internal
    "REMOTE_MODE": "demo",           # "demo" or "powershell"
    "POWERSHELL": "pwsh",
    "WEBHOOK_URL": "",               # outbound events, e.g. an n8n webhook
    "WEBHOOK_SECRET": "",            # HMAC key used to sign webhook payloads
    "WARRANTY_WARN_DAYS": 90,
    "EMAIL_MODE": "outbox",          # "outbox" (demo, stored in the app), "smtp" or "webhook"
    "SMTP_HOST": "", "SMTP_PORT": 587, "SMTP_USER": "", "SMTP_PASSWORD": "",
    "SMTP_FROM": "it-ops-console@example.internal",
    "SESSION_COOKIE_HTTPONLY": True,
    "SESSION_COOKIE_SAMESITE": "Lax",
}


def _local_secret_key() -> str:
    """Development fallback: one key shared by all workers, stored next to the database.
    In production set OPS_SECRET_KEY instead."""
    path = Path("instance/.secret_key")
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(secrets.token_hex(32))
        path.chmod(0o600)
    return path.read_text().strip()


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=False)
    app.config.update(DEFAULTS)
    # Every setting can come from the environment with the prefix OPS_, e.g. OPS_AUTH_MODE=ldap.
    for key in DEFAULTS:
        if f"OPS_{key}" in os.environ:
            app.config[key] = os.environ[f"OPS_{key}"]
    app.config["SECRET_KEY"] = os.environ.get("OPS_SECRET_KEY") or _local_secret_key()
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("OPS_COOKIE_SECURE", "0") == "1"
    if overrides:
        app.config.update(overrides)

    db.init_app(app)
    auth.init_app(app)
    app.register_blueprint(views.bp)
    return app
