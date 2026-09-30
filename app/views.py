"""Pages and actions. Every state-changing action is audited."""

import csv
import io
import json
import os
from collections import Counter, defaultdict
from datetime import date

from flask import (Blueprint, Response, current_app, flash, redirect, render_template, request,
                   session, url_for)

from . import auth, db, mfa, services

bp = Blueprint("views", __name__)


def _warranty_rows():
    warn = int(current_app.config["WARRANTY_WARN_DAYS"])
    rows = db.query("SELECT a.hostname, a.manufacturer, a.model, a.serial, a.assigned_user, w.expires_on, "
                    "w.checked_at FROM assets a LEFT JOIN warranties w ON w.hostname = a.hostname "
                    "ORDER BY w.expires_on IS NULL, w.expires_on")
    out = []
    for r in rows:
        d = dict(r)
        d["status"] = services.warranty_status(d["expires_on"], warn)
        d["days_left"] = (date.fromisoformat(d["expires_on"]) - date.today()).days if d["expires_on"] else None
        out.append(d)
    return out


def _summary() -> dict:
    today = str(date.today())
    assets = db.query("SELECT status, compliant FROM assets")
    status = Counter(a["status"] for a in assets)
    warranty = Counter(r["status"] for r in _warranty_rows())
    endpoints = db.query("SELECT * FROM endpoints ORDER BY CASE severity WHEN 'critical' THEN 0 "
                         "WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, name")
    checked_rooms = {r["room"]: r for r in db.query(
        "SELECT room, failures FROM checklist_runs WHERE run_at LIKE ? ", (today + "%",))}
    rooms = db.query("SELECT name FROM rooms")
    lifecycle = [dict(r, tasks=json.loads(r["tasks"])) for r in db.query(
        "SELECT * FROM lifecycle ORDER BY effective_date")]
    open_items = [l for l in lifecycle if not all(t["done"] for t in l["tasks"])]
    return {
        "total_assets": len(assets),
        "online": status["online"],
        "offline": status["offline"] + status["unknown"],
        "noncompliant": sum(1 for a in assets if a["compliant"] == 0),
        "warranty_expired": warranty["expired"],
        "warranty_expiring": warranty["expiring"],
        "services_down": sum(1 for e in endpoints if e["status"] == "down"),
        "services_degraded": sum(1 for e in endpoints if e["status"] == "degraded"),
        "endpoints": endpoints,
        "rooms_not_checked": [r["name"] for r in rooms if r["name"] not in checked_rooms],
        "rooms_failing": [n for n, r in checked_rooms.items() if r["failures"]],
        "visitors_today": db.query("SELECT * FROM visitors WHERE visit_date = ? ORDER BY visitor_name", (today,)),
        "lifecycle_open": open_items,
        "on_call": db.query("SELECT * FROM shifts WHERE shift_date = ? AND on_call = 1", (today,)),
    }


# ----------------------------------------------------------------------- auth

GENERIC_FAIL = "Sign-in failed. Check your username and password, or ask an administrator for access."


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        user = db.query("SELECT * FROM users WHERE username = ?", (username,), one=True)
        # Same message whether the account is unknown, disabled or the password is wrong,
        # so the page cannot be used to find out which accounts exist.
        if not user or user["status"] == "disabled" or not auth.authenticate(username, request.form.get("password", "")):
            db.audit("login.failed", {"user": username})
            flash(GENERIC_FAIL)
            return render_template("login.html", demo=current_app.config["AUTH_MODE"] == "demo")
        auth.start_pending(username)
        session["next"] = request.args.get("next", "")
        if user["status"] == "invited":
            if not mfa.issue_activation_code(username, user["email"]):
                flash("A code was sent less than a minute ago. Use that one or wait a moment.")
            return redirect(url_for("views.activate"))
        return redirect(url_for("views.verify"))
    return render_template("login.html", demo=current_app.config["AUTH_MODE"] == "demo")


def _finish_login(username: str):
    nxt = session.get("next", "")
    auth.login_user(username)
    return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("views.dashboard"))


@bp.route("/activate", methods=["GET", "POST"])
def activate():
    """First sign-in: prove control of the mailbox with the emailed code."""
    username = auth.pending_user()
    if not username:
        flash("Your sign-in expired. Please start again.")
        return redirect(url_for("views.login"))
    user = db.query("SELECT * FROM users WHERE username = ?", (username,), one=True)
    if request.method == "POST":
        auth.count_attempt()
        if mfa.verify_activation_code(username, request.form.get("code", "")):
            session["activation_ok"] = True
            session["new_totp"] = mfa.new_totp_secret()
            db.audit("mfa.activation_code_ok", {"user": username})
            return redirect(url_for("views.mfa_setup"))
        db.audit("mfa.activation_code_failed", {"user": username})
        flash("That code is not valid or has expired.")
    masked = user["email"][:2] + "***" + user["email"][user["email"].find("@"):] if user["email"] else "your email"
    demo_mail = None
    if current_app.config["AUTH_MODE"] == "demo" and current_app.config["EMAIL_MODE"] == "outbox":
        demo_mail = db.query("SELECT body FROM outbox WHERE recipient = ? ORDER BY id DESC LIMIT 1",
                             (user["email"],), one=True)  # demo only: no real mailbox to read it from
    return render_template("activate.html", email=masked, demo_mail=demo_mail)


@bp.route("/mfa/setup", methods=["GET", "POST"])
def mfa_setup():
    """Right after activation: register an authenticator app."""
    username = auth.pending_user()
    if not username or not session.get("activation_ok") or not session.get("new_totp"):
        return redirect(url_for("views.login"))
    secret = session["new_totp"]
    if request.method == "POST":
        auth.count_attempt()
        step = mfa.verify_totp(secret, request.form.get("code", ""))
        if step is not None:
            db.execute("UPDATE users SET totp_secret = ?, totp_last_step = ?, status = 'active', activated_at = ? "
                       "WHERE username = ?", (secret, step, db.now(), username))
            db.audit("account.activated", {"user": username})
            services.emit("account.activated", {"user": username})
            return _finish_login(username)
        flash("That code does not match. Check the time on your phone and try the next code.")
    uri = mfa.provisioning_uri(username, secret)
    return render_template("mfa_setup.html", secret=secret, qr=mfa.qr_svg(uri), uri=uri)


@bp.route("/mfa/verify", methods=["GET", "POST"])
def verify():
    """Every later sign-in: code from the authenticator app."""
    username = auth.pending_user()
    if not username:
        flash("Your sign-in expired. Please start again.")
        return redirect(url_for("views.login"))
    user = db.query("SELECT * FROM users WHERE username = ?", (username,), one=True)
    if request.method == "POST":
        auth.count_attempt()
        step = mfa.verify_totp(user["totp_secret"], request.form.get("code", ""), user["totp_last_step"])
        if step is not None:
            db.execute("UPDATE users SET totp_last_step = ? WHERE username = ?", (step, username))
            return _finish_login(username)
        db.audit("mfa.totp_failed", {"user": username})
        flash("That code is not valid.")
    demo_code = mfa.totp_at(user["totp_secret"], mfa.current_step()) \
        if current_app.config["AUTH_MODE"] == "demo" and user["totp_secret"] else None
    return render_template("verify.html", demo_code=demo_code)


@bp.route("/logout", methods=["POST"])
def logout():
    db.audit("logout")
    session.clear()
    return redirect(url_for("views.login"))


@bp.route("/healthz")
def healthz():
    db.query("SELECT 1")
    return {"status": "ok"}


# ------------------------------------------------------------------ dashboard

@bp.route("/")
@auth.require_section("dashboard")
def dashboard():
    return render_template("dashboard.html", s=_summary())


@bp.route("/export/daily-summary.csv")
@auth.require_section("dashboard")
def export_summary():
    s = _summary()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["metric", "value"])
    for key in ("total_assets", "online", "offline", "noncompliant", "warranty_expired", "warranty_expiring",
                "services_down", "services_degraded"):
        w.writerow([key, s[key]])
    w.writerow(["rooms_not_checked", "; ".join(s["rooms_not_checked"])])
    w.writerow(["rooms_failing", "; ".join(s["rooms_failing"])])
    w.writerow(["visitors_today", len(s["visitors_today"])])
    w.writerow(["joiners_leavers_open", len(s["lifecycle_open"])])
    db.audit("export.daily_summary")
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=daily-summary-{date.today()}.csv"})


# --------------------------------------------------------------------- assets

@bp.route("/assets")
@auth.require_section("assets")
def assets():
    view = request.args.get("view", "all")
    rows = [dict(r) for r in db.query("SELECT * FROM assets ORDER BY hostname")]
    serials = Counter(r["serial"] for r in rows if r["serial"])
    for r in rows:
        r["duplicate"] = bool(r["serial"]) and serials[r["serial"]] > 1
    filters = {
        "offline": lambda r: r["status"] != "online",
        "noncompliant": lambda r: r["compliant"] == 0,
        "unassigned": lambda r: not r["assigned_user"],
        "duplicates": lambda r: r["duplicate"],
    }
    counts = {k: sum(1 for r in rows if f(r)) for k, f in filters.items()}
    if view in filters:
        rows = [r for r in rows if filters[view](r)]
    return render_template("assets.html", rows=rows, view=view, counts=counts)


@bp.route("/assets/<hostname>/query/<kind>", methods=["POST"])
@auth.require_section("assets")
def asset_query(hostname, kind):
    if not db.query("SELECT 1 FROM assets WHERE hostname = ?", (hostname,), one=True):
        flash("Unknown device.")
        return redirect(url_for("views.assets"))
    try:
        result = services.query_device(hostname, kind, os.environ.get("OPS_REMOTE_USER"),
                                       os.environ.get("OPS_REMOTE_PASSWORD"))
    except Exception as exc:
        db.audit("device.query_failed", {"hostname": hostname, "query": kind, "error": str(exc)})
        flash(f"{hostname}: query failed ({exc}).")
        return redirect(request.referrer or url_for("views.assets"))

    if kind == "serial":
        db.execute("UPDATE assets SET serial = ?, last_seen = ?, status = 'online' WHERE hostname = ?",
                   (result.get("serial"), db.now(), hostname))
        flash(f"{hostname}: serial {result.get('serial')}.")
    elif kind == "software":
        conn = db.get_db()
        conn.execute("DELETE FROM software WHERE hostname = ?", (hostname,))
        conn.executemany("INSERT INTO software VALUES (?, ?, ?, ?)",
                         [(hostname, s.get("name"), s.get("version"), s.get("publisher"))
                          for s in result.get("software", [])])
        conn.commit()
        flash(f"{hostname}: {len(result.get('software', []))} applications found.")
    else:
        flash(f"{hostname}: CPU {result.get('cpu_percent')}%, free disk {result.get('free_disk_gb')} GB, "
              f"uptime {result.get('uptime_days')} days.")
    db.audit("device.query", {"hostname": hostname, "query": kind})
    return redirect(request.referrer or url_for("views.assets"))


# ------------------------------------------------------------------- warranty

@bp.route("/warranty")
@auth.require_section("warranty")
def warranty():
    rows = _warranty_rows()
    return render_template("warranty.html", rows=rows, counts=Counter(r["status"] for r in rows),
                           warn_days=current_app.config["WARRANTY_WARN_DAYS"])


@bp.route("/warranty/discover", methods=["POST"])
@auth.require_section("warranty")
def warranty_discover():
    found = services.discover_computers()
    added = 0
    for c in found:
        added += db.get_db().execute("INSERT OR IGNORE INTO assets (hostname, os) VALUES (?, ?)",
                                     (c["hostname"], c.get("os"))).rowcount
    db.get_db().commit()
    db.audit("warranty.discover", {"found": len(found), "added": added})
    flash(f"Discovery: {len(found)} machines found, {added} new.")
    return redirect(url_for("views.warranty"))


@bp.route("/warranty/check", methods=["POST"])
@auth.require_section("warranty")
def warranty_check():
    host = request.form.get("hostname")
    sql = "SELECT a.hostname, a.manufacturer, a.serial FROM assets a LEFT JOIN warranties w ON w.hostname = a.hostname"
    rows = db.query(sql + " WHERE a.hostname = ?", (host,)) if host else db.query(sql + " WHERE w.hostname IS NULL")
    checked = 0
    for r in rows:
        expires = services.lookup_warranty(r["manufacturer"], r["serial"])
        if expires:
            db.execute("INSERT OR REPLACE INTO warranties VALUES (?, ?, ?, ?, 'demo')",
                       (r["hostname"], r["manufacturer"], expires, db.now()))
            checked += 1
    db.audit("warranty.check", {"hostname": host or "all-missing", "checked": checked})
    flash(f"Warranty checked for {checked} machine(s).")
    return redirect(url_for("views.warranty"))


# ------------------------------------------------------------------- software

@bp.route("/software")
@auth.require_section("software")
def software():
    host = request.args.get("host", "")
    q = request.args.get("q", "").strip()
    if host:
        rows = db.query("SELECT * FROM software WHERE hostname = ? ORDER BY name", (host,))
    elif q:
        rows = db.query("SELECT * FROM software WHERE name LIKE ? ORDER BY name, hostname", (f"%{q}%",))
    else:
        rows = db.query("SELECT name, publisher, COUNT(*) AS installs FROM software GROUP BY name, publisher "
                        "ORDER BY installs DESC, name")
    return render_template("software.html", rows=rows, host=host, q=q,
                           hosts=db.query("SELECT hostname FROM assets ORDER BY hostname"))


# ------------------------------------------------------------ people & floors

@bp.route("/people")
@auth.require_section("people")
def people():
    q = request.args.get("q", "").strip()
    like = f"%{q}%"
    rows = db.query("SELECT p.*, a.hostname FROM people p LEFT JOIN assets a ON a.assigned_user = p.username "
                    "WHERE p.display_name LIKE ? OR p.department LIKE ? OR p.desk LIKE ? ORDER BY p.display_name",
                    (like, like, like))
    return render_template("people.html", rows=rows, q=q)


@bp.route("/floors")
@auth.require_section("floors")
def floors():
    floor = request.args.get("floor", 1, type=int)
    desks = db.query("SELECT d.*, p.display_name, p.department FROM desks d "
                     "LEFT JOIN people p ON p.desk = d.id WHERE d.floor = ? ORDER BY d.y, d.x", (floor,))
    by_floor = defaultdict(Counter)
    for p in db.query("SELECT floor, department FROM people"):
        by_floor[p["floor"]][p["department"]] += 1
    departments = sorted({d for c in by_floor.values() for d in c})
    return render_template("floors.html", floor=floor, desks=desks, by_floor=dict(sorted(by_floor.items())),
                           departments=departments, highlight=request.args.get("desk", ""),
                           floors=[r["floor"] for r in db.query("SELECT DISTINCT floor FROM desks ORDER BY floor")])


# ----------------------------------------------------------------- checklists

@bp.route("/checklists")
@auth.require_section("checklists")
def checklists():
    from .demo_data import CHECKLIST_ITEMS
    rooms = db.query("SELECT * FROM rooms ORDER BY floor, name")
    last = {r["room"]: dict(r, results=json.loads(r["results"])) for r in db.query(
        "SELECT * FROM checklist_runs WHERE id IN (SELECT MAX(id) FROM checklist_runs GROUP BY room)")}
    history = db.query("SELECT * FROM checklist_runs ORDER BY id DESC LIMIT 30")
    return render_template("checklists.html", rooms=rooms, last=last, items=CHECKLIST_ITEMS,
                           history=history, today=str(date.today()))


@bp.route("/checklists/<room>", methods=["POST"])
@auth.require_section("checklists")
def checklist_submit(room):
    from .demo_data import CHECKLIST_ITEMS
    if not db.query("SELECT 1 FROM rooms WHERE name = ?", (room,), one=True):
        flash("Unknown room.")
        return redirect(url_for("views.checklists"))
    results = {item: ("ok" if request.form.get(item) == "ok" else "fail") for item in CHECKLIST_ITEMS}
    failures = [i for i, v in results.items() if v == "fail"]
    db.execute("INSERT INTO checklist_runs (room, run_at, run_by, results, failures, notes) VALUES (?, ?, ?, ?, ?, ?)",
               (room, db.now(), session["username"], json.dumps(results), len(failures),
                request.form.get("notes", "")[:500]))
    db.audit("checklist.submit", {"room": room, "failures": failures})
    if failures:
        services.emit("room.check_failed", {"room": room, "failed_items": failures})
    flash(f"{room}: {'all checks OK' if not failures else str(len(failures)) + ' item(s) failed'}.")
    return redirect(url_for("views.checklists"))


# ------------------------------------------------------------------ lifecycle

@bp.route("/lifecycle", methods=["GET", "POST"])
@auth.require_section("lifecycle")
def lifecycle():
    from .demo_data import JOIN_TASKS, LEAVE_TASKS
    if request.method == "POST":
        kind = request.form.get("kind")
        name = request.form.get("person_name", "").strip()
        if kind in ("join", "leave") and name:
            tasks = [{"task": t, "done": False} for t in (JOIN_TASKS if kind == "join" else LEAVE_TASKS)]
            db.execute("INSERT INTO lifecycle (kind, person_name, department, effective_date, tasks, created_by, "
                       "created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (kind, name, request.form.get("department"), request.form.get("effective_date"),
                        json.dumps(tasks), session["username"], db.now()))
            db.audit("lifecycle.create", {"kind": kind, "person": name})
            services.emit(f"employee.{kind}", {"person": name, "date": request.form.get("effective_date")})
            flash(f"{'Joiner' if kind == 'join' else 'Leaver'} checklist created for {name}.")
        return redirect(url_for("views.lifecycle"))
    rows = [dict(r, tasks=json.loads(r["tasks"])) for r in db.query("SELECT * FROM lifecycle ORDER BY effective_date")]
    return render_template("lifecycle.html", rows=rows)


@bp.route("/lifecycle/<int:item_id>/task/<int:index>", methods=["POST"])
@auth.require_section("lifecycle")
def lifecycle_task(item_id, index):
    row = db.query("SELECT * FROM lifecycle WHERE id = ?", (item_id,), one=True)
    if row:
        tasks = json.loads(row["tasks"])
        if 0 <= index < len(tasks):
            tasks[index]["done"] = not tasks[index]["done"]
            db.execute("UPDATE lifecycle SET tasks = ? WHERE id = ?", (json.dumps(tasks), item_id))
            db.audit("lifecycle.task", {"person": row["person_name"], "task": tasks[index]["task"],
                                        "done": tasks[index]["done"]})
    return redirect(url_for("views.lifecycle"))


# ------------------------------------------------------------------- visitors

@bp.route("/visitors", methods=["GET", "POST"])
@auth.require_section("visitors")
def visitors():
    if request.method == "POST":
        name = request.form.get("visitor_name", "").strip()
        if name:
            db.execute("INSERT INTO visitors (visitor_name, company, host, visit_date, location) VALUES (?, ?, ?, ?, ?)",
                       (name, request.form.get("company"), request.form.get("host"),
                        request.form.get("visit_date") or str(date.today()), request.form.get("location")))
            db.audit("visitor.register", {"visitor": name})
            flash(f"Visitor {name} registered.")
        return redirect(url_for("views.visitors"))
    rows = db.query("SELECT * FROM visitors WHERE visit_date >= ? ORDER BY visit_date, visitor_name",
                    (str(date.today()),))
    return render_template("visitors.html", rows=rows, today=str(date.today()),
                           rooms=db.query("SELECT name FROM rooms ORDER BY name"))


@bp.route("/visitors/<int:visitor_id>/<action>", methods=["POST"])
@auth.require_section("visitors")
def visitor_sign(visitor_id, action):
    column = {"sign-in": "signed_in", "sign-out": "signed_out"}.get(action)
    if column:
        db.execute(f"UPDATE visitors SET {column} = ? WHERE id = ?", (db.now(), visitor_id))
        db.audit(f"visitor.{action}", {"id": visitor_id})
    return redirect(url_for("views.visitors"))


# --------------------------------------------------------------------- shifts

@bp.route("/shifts", methods=["GET", "POST"])
@auth.require_section("shifts")
def shifts():
    if request.method == "POST":
        engineer = request.form.get("engineer", "").strip()
        if engineer and request.form.get("shift_date"):
            db.execute("INSERT INTO shifts (engineer, shift_date, start_time, end_time, region, on_call) "
                       "VALUES (?, ?, ?, ?, ?, ?)",
                       (engineer, request.form["shift_date"], request.form.get("start_time"),
                        request.form.get("end_time"), request.form.get("region"),
                        int(request.form.get("on_call") == "1")))
            db.audit("shift.create", {"engineer": engineer, "date": request.form["shift_date"]})
        return redirect(url_for("views.shifts"))
    rows = db.query("SELECT * FROM shifts WHERE shift_date >= ? ORDER BY shift_date, start_time",
                    (str(date.today()),))
    by_day = defaultdict(list)
    for r in rows:
        by_day[r["shift_date"]].append(r)
    return render_template("shifts.html", by_day=dict(by_day))


@bp.route("/shifts/<int:shift_id>/delete", methods=["POST"])
@auth.require_section("shifts")
def shift_delete(shift_id):
    db.execute("DELETE FROM shifts WHERE id = ?", (shift_id,))
    db.audit("shift.delete", {"id": shift_id})
    return redirect(url_for("views.shifts"))


# ------------------------------------------------------------------ incidents

@bp.route("/incidents")
@auth.require_section("incidents")
def incidents():
    return render_template("incidents.html", endpoints=_summary()["endpoints"])


@bp.route("/incidents/run", methods=["POST"])
@auth.require_section("incidents")
def incidents_run():
    results = services.run_health_checks()
    db.audit("health.run", {"checked": len(results)})
    down = [r["name"] for r in results if r["status"] == "down"]
    flash(f"{len(results)} services checked" + (f"; down: {', '.join(down)}." if down else "; none down."))
    return redirect(url_for("views.incidents"))


# ---------------------------------------------------------------- admin/audit

def _active_admins() -> int:
    return db.query("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND status = 'active'", one=True)["n"]


@bp.route("/admin", methods=["GET", "POST"])
@auth.require_section("admin")
def admin():
    roles = ["admin", "engineer", "viewer"]
    me = session["username"]
    if request.method == "POST":
        form = request.form.get("form")
        username = request.form.get("username", "").strip().lower()
        target = db.query("SELECT * FROM users WHERE username = ?", (username,), one=True) if username else None
        if form == "roles":
            conn = db.get_db()
            conn.execute("DELETE FROM role_sections WHERE role != 'admin'")  # admin always keeps full access
            for role in roles[1:]:
                for section in db.SECTIONS:
                    if request.form.get(f"{role}:{section}"):
                        conn.execute("INSERT INTO role_sections VALUES (?, ?)", (role, section))
            conn.commit()
            db.audit("admin.roles_updated")
            flash("Access saved.")
        elif form == "invite":
            email, role = request.form.get("email", "").strip(), request.form.get("role")
            if not auth.USERNAME_RE.match(username) or "@" not in email or role not in roles:
                flash("Enter a valid username, email and role.")
            elif target:
                flash(f"{username} already exists.")
            else:
                db.execute("INSERT INTO users (username, display_name, email, role, status, invited_by, invited_at) "
                           "VALUES (?, ?, ?, ?, 'invited', ?, ?)",
                           (username, request.form.get("display_name") or username, email, role, me, db.now()))
                mfa.send_email(email, "You have been invited to the IT Ops Console",
                               f"{me} has given you {role} access to the IT Ops Console.\n\n"
                               "Sign in with your usual username and password. We will then email you an "
                               "activation code and ask you to set up an authenticator app.")
                db.audit("admin.invite", {"user": username, "role": role})
                flash(f"{username} invited as {role}.")
        elif target and username == me:
            flash("You cannot change your own account here.")  # avoids locking yourself out
        elif target and form in ("role", "disable", "reset_mfa") and target["role"] == "admin" \
                and target["status"] == "active" and _active_admins() <= 1 and request.form.get("role") != "admin":
            flash("There must always be at least one active administrator.")
        elif target and form == "role" and request.form.get("role") in roles:
            db.execute("UPDATE users SET role = ? WHERE username = ?", (request.form["role"], username))
            db.audit("admin.user_role", {"user": username, "role": request.form["role"]})
            flash(f"{username} is now {request.form['role']}.")
        elif target and form == "disable":
            db.execute("UPDATE users SET status = 'disabled' WHERE username = ?", (username,))
            db.audit("admin.user_disabled", {"user": username})
            flash(f"{username} disabled.")
        elif target and form == "enable":
            status = "active" if target["totp_secret"] else "invited"
            db.execute("UPDATE users SET status = ? WHERE username = ?", (status, username))
            db.audit("admin.user_enabled", {"user": username})
            flash(f"{username} enabled.")
        elif target and form == "reset_mfa":
            # lost phone: back to "invited", the next sign-in repeats email activation + app setup
            db.execute("UPDATE users SET status = 'invited', totp_secret = NULL, totp_last_step = NULL "
                       "WHERE username = ?", (username,))
            db.audit("admin.mfa_reset", {"user": username})
            flash(f"{username} will set up MFA again at the next sign-in.")
        return redirect(url_for("views.admin"))
    matrix = defaultdict(set)
    for r in db.query("SELECT * FROM role_sections"):
        matrix[r["role"]].add(r["section"])
    outbox = db.query("SELECT * FROM outbox ORDER BY id DESC LIMIT 10") \
        if current_app.config["EMAIL_MODE"] == "outbox" else []
    return render_template("admin.html", roles=roles, matrix=matrix, sections=db.SECTIONS, outbox=outbox,
                           users=db.query("SELECT * FROM users ORDER BY status, username"))


@bp.route("/audit")
@auth.require_section("audit")
def audit_log():
    q = request.args.get("q", "").strip()
    rows = db.query("SELECT * FROM audit_log WHERE action LIKE ? OR username LIKE ? OR detail LIKE ? "
                    "ORDER BY id DESC LIMIT 500", (f"%{q}%",) * 3)
    return render_template("audit.html", rows=rows, q=q)
