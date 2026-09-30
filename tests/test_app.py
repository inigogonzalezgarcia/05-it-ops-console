import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app, db, mfa  # noqa: E402
from app.demo_data import seed  # noqa: E402
from app.services import HOSTNAME_RE, warranty_status  # noqa: E402


def make_client(tmp_path):
    app = create_app({"DATABASE": str(tmp_path / "test.db"), "TESTING": True, "SECRET_KEY": "test"})
    with app.app_context():
        db.init_schema()
        seed()
    return app, app.test_client()


def csrf(client, page="/"):
    html = client.get(page).get_data(as_text=True)
    return re.search(r'name="csrf" value="([0-9a-f]+)"', html).group(1)


def login(client, username="alex.admin", password="demo", app=None):
    """Password, then the TOTP code of the seeded user (computed from the stored secret)."""
    resp = client.post("/login", data={"username": username, "password": password})
    if app is None or "/mfa/verify" not in resp.headers.get("Location", ""):
        return resp
    with app.app_context():
        secret = db.query("SELECT totp_secret FROM users WHERE username = ?", (username,), one=True)["totp_secret"]
    code = mfa.totp_at(secret, mfa.current_step())
    return client.post("/mfa/verify", data={"csrf": csrf(client, "/mfa/verify"), "code": code})


def test_login_required_and_wrong_password(tmp_path):
    app, client = make_client(tmp_path)
    assert client.get("/").status_code == 302
    login(client, password="wrong", app=app)
    assert client.get("/").status_code == 302


def test_every_section_renders_for_admin(tmp_path):
    app, client = make_client(tmp_path)
    login(client, app=app)
    for page in ("/", "/assets", "/assets?view=duplicates", "/warranty", "/software", "/people", "/floors",
                 "/checklists", "/lifecycle", "/visitors", "/shifts", "/incidents", "/admin", "/audit"):
        assert client.get(page).status_code == 200, page


def test_viewer_cannot_open_admin(tmp_path):
    app, client = make_client(tmp_path)
    login(client, "jo.viewer", app=app)
    assert client.get("/admin").status_code == 302  # redirected with a message
    assert client.get("/assets").status_code == 200


def test_post_without_csrf_is_rejected(tmp_path):
    app, client = make_client(tmp_path)
    login(client, app=app)
    assert client.post("/incidents/run").status_code == 400


def test_checklist_submission_is_saved_and_audited(tmp_path):
    app, client = make_client(tmp_path)
    login(client, "sam.engineer", app=app)
    token = csrf(client, "/checklists")
    client.post("/checklists/Room Atlas", data={"csrf": token, "Display": "ok"})
    with app.app_context():
        run = db.query("SELECT * FROM checklist_runs ORDER BY id DESC LIMIT 1", one=True)
        assert run["room"] == "Room Atlas" and run["failures"] == 7
        assert db.query("SELECT 1 FROM audit_log WHERE action = 'checklist.submit'", one=True)


def test_duplicate_serials_are_detected(tmp_path):
    app, client = make_client(tmp_path)
    login(client, app=app)
    page = client.get("/assets?view=duplicates").get_data(as_text=True)
    assert page.count("WKS-100") >= 2


def test_demo_remote_query_fills_software(tmp_path):
    app, client = make_client(tmp_path)
    login(client, "sam.engineer", app=app)
    token = csrf(client, "/assets")
    client.post("/assets/WKS-1000/query/software", data={"csrf": token})
    with app.app_context():
        assert db.query("SELECT COUNT(*) AS n FROM software WHERE hostname = 'WKS-1000'", one=True)["n"] >= 4


def test_hostname_validation_blocks_injection():
    assert HOSTNAME_RE.match("WKS-1000.example.internal")
    assert not HOSTNAME_RE.match("WKS-1; Remove-Item C:\\")


def test_warranty_status_thresholds():
    assert warranty_status(None, 90) == "unknown"
    assert warranty_status("2000-01-01", 90) == "expired"
    assert warranty_status("2999-01-01", 90) == "active"


# --------------------------------------------------------------- access and MFA

def test_totp_matches_rfc6238_vector():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # base32 of "12345678901234567890"
    assert mfa.totp_at(secret, 1) == "287082"      # RFC 6238, T = 59 s
    assert mfa.verify_totp(secret, "287082", now=59) == 1
    assert mfa.verify_totp(secret, "287082", last_step=1, now=59) is None  # no replay


def test_password_alone_is_not_enough(tmp_path):
    app, client = make_client(tmp_path)
    resp = client.post("/login", data={"username": "alex.admin", "password": "demo"})
    assert "/mfa/verify" in resp.headers["Location"]
    assert client.get("/").status_code == 302


def test_uninvited_user_cannot_sign_in(tmp_path):
    app, client = make_client(tmp_path)
    resp = client.post("/login", data={"username": "someone.else", "password": "demo"})
    assert resp.status_code == 200 and b"Sign-in failed" in resp.data


def test_invited_user_activates_with_email_code_and_authenticator(tmp_path):
    app, client = make_client(tmp_path)
    resp = client.post("/login", data={"username": "new.tech", "password": "demo"})
    assert "/activate" in resp.headers["Location"]
    with app.app_context():
        body = db.query("SELECT body FROM outbox WHERE recipient = 'new.tech@example.internal' "
                        "ORDER BY id DESC LIMIT 1", one=True)["body"]
    code = re.search(r"code is: ([A-Z0-9]{6})", body).group(1)
    resp = client.post("/activate", data={"csrf": csrf(client, "/activate"), "code": code})
    assert "/mfa/setup" in resp.headers["Location"]
    page = client.get("/mfa/setup").get_data(as_text=True)
    secret = re.search(r"<code[^>]*>([A-Z2-7]+)</code>", page).group(1)
    client.post("/mfa/setup", data={"csrf": csrf(client, "/mfa/setup"),
                                    "code": mfa.totp_at(secret, mfa.current_step())})
    assert client.get("/").status_code == 200
    with app.app_context():
        assert db.query("SELECT status FROM users WHERE username = 'new.tech'", one=True)["status"] == "active"


def test_activation_code_locks_after_five_wrong_attempts(tmp_path):
    app, client = make_client(tmp_path)
    client.post("/login", data={"username": "new.tech", "password": "demo"})
    token = csrf(client, "/activate")
    for _ in range(5):
        client.post("/activate", data={"csrf": token, "code": "AAAAAA"})
    assert "/login" in client.get("/activate").headers["Location"]


def test_admin_invites_and_disabled_user_is_signed_out(tmp_path):
    app, client = make_client(tmp_path)
    login(client, app=app)
    token = csrf(client, "/admin")
    client.post("/admin", data={"csrf": token, "form": "invite", "username": "helpdesk.one",
                                "email": "helpdesk.one@example.internal", "role": "engineer"})
    client.post("/admin", data={"csrf": token, "form": "disable", "username": "sam.engineer"})
    with app.app_context():
        assert db.query("SELECT status FROM users WHERE username = 'helpdesk.one'", one=True)["status"] == "invited"
        assert db.query("SELECT status FROM users WHERE username = 'sam.engineer'", one=True)["status"] == "disabled"
    other = app.test_client()
    resp = other.post("/login", data={"username": "sam.engineer", "password": "demo"})
    assert b"Sign-in failed" in resp.data


def test_bootstrap_only_works_without_an_admin(tmp_path):
    app, _ = make_client(tmp_path)
    runner = app.test_cli_runner()
    result = runner.invoke(args=["bootstrap-admin", "--username", "second.admin", "--email", "x@example.internal"])
    assert result.exit_code != 0 and "already exists" in result.output
    with app.app_context():
        db.execute("DELETE FROM users")
    result = runner.invoke(args=["bootstrap-admin", "--username", "first.admin", "--email", "x@example.internal"])
    assert result.exit_code == 0
