"""SQLite storage. Plain SQL, no ORM.

All state lives in the database (not in process memory), so several gunicorn
workers always see the same data.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import click
from flask import current_app, g, session
from flask.cli import with_appcontext

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY, display_name TEXT, email TEXT, role TEXT NOT NULL DEFAULT 'viewer',
    status TEXT NOT NULL DEFAULT 'invited',          -- invited | active | disabled
    totp_secret TEXT, totp_last_step INTEGER, invited_by TEXT, invited_at TEXT,
    activated_at TEXT, last_login TEXT);
CREATE TABLE IF NOT EXISTS one_time_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, code_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT, subject TEXT, body TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS role_sections (
    role TEXT NOT NULL, section TEXT NOT NULL, PRIMARY KEY (role, section));
CREATE TABLE IF NOT EXISTS assets (
    hostname TEXT PRIMARY KEY, serial TEXT, manufacturer TEXT, model TEXT, os TEXT,
    assigned_user TEXT, site TEXT, floor INTEGER, status TEXT DEFAULT 'unknown',
    compliant INTEGER, last_seen TEXT);
CREATE TABLE IF NOT EXISTS warranties (
    hostname TEXT PRIMARY KEY, manufacturer TEXT, expires_on TEXT, checked_at TEXT, source TEXT);
CREATE TABLE IF NOT EXISTS software (
    hostname TEXT NOT NULL, name TEXT NOT NULL, version TEXT, publisher TEXT);
CREATE TABLE IF NOT EXISTS people (
    username TEXT PRIMARY KEY, display_name TEXT, department TEXT, site TEXT, floor INTEGER, desk TEXT);
CREATE TABLE IF NOT EXISTS desks (
    id TEXT PRIMARY KEY, floor INTEGER NOT NULL, x INTEGER NOT NULL, y INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rooms (
    name TEXT PRIMARY KEY, floor INTEGER, capacity INTEGER);
CREATE TABLE IF NOT EXISTS checklist_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, room TEXT NOT NULL, run_at TEXT NOT NULL,
    run_by TEXT, results TEXT NOT NULL, failures INTEGER NOT NULL, notes TEXT);
CREATE TABLE IF NOT EXISTS lifecycle (
    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, person_name TEXT NOT NULL,
    department TEXT, effective_date TEXT, tasks TEXT NOT NULL, created_by TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS visitors (
    id INTEGER PRIMARY KEY AUTOINCREMENT, visitor_name TEXT NOT NULL, company TEXT, host TEXT,
    visit_date TEXT, location TEXT, signed_in TEXT, signed_out TEXT);
CREATE TABLE IF NOT EXISTS shifts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, engineer TEXT NOT NULL, shift_date TEXT NOT NULL,
    start_time TEXT, end_time TEXT, region TEXT, on_call INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS endpoints (
    name TEXT PRIMARY KEY, url TEXT NOT NULL, severity TEXT NOT NULL, status TEXT DEFAULT 'unknown',
    latency_ms INTEGER, detail TEXT, checked_at TEXT);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, username TEXT, action TEXT NOT NULL, detail TEXT);
CREATE INDEX IF NOT EXISTS idx_software_host ON software(hostname);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);
"""

SECTIONS = {
    "dashboard": "Dashboard",
    "assets": "Assets",
    "warranty": "Warranty",
    "software": "Software",
    "people": "People",
    "floors": "Floor map",
    "checklists": "Room checklists",
    "lifecycle": "Joiners & leavers",
    "visitors": "Visitors",
    "shifts": "Shifts",
    "incidents": "Incident centre",
    "admin": "Admin",
    "audit": "Audit log",
}

DEFAULT_ROLES = {
    "admin": list(SECTIONS),
    "engineer": [s for s in SECTIONS if s not in ("admin", "audit")],
    "viewer": ["dashboard", "assets", "warranty", "people", "floors", "incidents"],
}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        path = current_app.config["DATABASE"]
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(path, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")  # readers do not block the writer
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql: str, args=(), one: bool = False):
    rows = get_db().execute(sql, args).fetchall()
    return (rows[0] if rows else None) if one else rows


def execute(sql: str, args=()) -> int:
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    return cur.lastrowid


def audit(action: str, detail=None) -> None:
    """Record who did what. Every state-changing action calls this."""
    if not isinstance(detail, str) and detail is not None:
        detail = json.dumps(detail, default=str)
    execute("INSERT INTO audit_log (at, username, action, detail) VALUES (?, ?, ?, ?)",
            (now(), session.get("username", "system"), action, detail))


def init_schema() -> None:
    db = get_db()
    db.executescript(SCHEMA)
    for role, sections in DEFAULT_ROLES.items():
        for section in sections:
            db.execute("INSERT OR IGNORE INTO role_sections (role, section) VALUES (?, ?)", (role, section))
    db.commit()


@click.command("init-db")
@with_appcontext
def init_db_command() -> None:
    """Create the tables and default roles."""
    init_schema()
    click.echo("Database ready.")


@click.command("bootstrap-admin")
@with_appcontext
@click.option("--username", required=True, help="directory username of the first administrator")
@click.option("--email", required=True, help="where the activation code will be sent")
def bootstrap_admin_command(username: str, email: str) -> None:
    """Create the first administrator. Refuses to run once any admin exists."""
    init_schema()
    if query("SELECT 1 FROM users WHERE role = 'admin'", one=True):
        raise click.ClickException("An administrator already exists. Invite new admins from the Admin page.")
    execute("INSERT INTO users (username, display_name, email, role, status, invited_by, invited_at) "
            "VALUES (?, ?, ?, 'admin', 'invited', 'bootstrap', ?)", (username.lower(), username, email, now()))
    execute("INSERT INTO audit_log (at, username, action, detail) VALUES (?, 'system', 'admin.bootstrap', ?)",
            (now(), username.lower()))
    click.echo(f"{username} created as the first administrator. Sign in to receive the activation code at {email}.")


@click.command("seed-demo")
@with_appcontext
def seed_demo_command() -> None:
    """Load fictional demo data."""
    from .demo_data import seed

    init_schema()
    seed()
    click.echo("Demo data loaded.")


def init_app(app) -> None:
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
    app.cli.add_command(seed_demo_command)
    app.cli.add_command(bootstrap_admin_command)
