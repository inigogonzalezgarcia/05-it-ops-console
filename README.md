# IT Ops Console

A lightweight operations console for an on-site IT team: device inventory and warranty, software, people and desks, daily room checks, joiners and leavers, visitors, shifts, service health, role-based access and a full audit log, in one web app.

Built with Python (Flask + SQLite), plain HTML/CSS and PowerShell. It runs with **fictional demo data** out of the box, and connects to a real directory (LDAPS) and real Windows devices when you configure it.

## Why

On-site IT work is spread across many small sources of truth: a spreadsheet of laptops, a vendor portal for warranties, a paper checklist for meeting rooms, an email thread for each new joiner, a shared calendar for shifts. Each one is simple; together they cost time every morning and make it easy to miss something.

This console puts the day in one place. You open it at the start of the day, see what needs attention, and act on it from the same screen:

- Which devices are offline, non-compliant, unassigned, or share a serial number?
- Which warranties have expired or are about to, so hardware can be replaced before it fails?
- Is every meeting room ready before the first important meeting?
- Which joiners and leavers still have open IT tasks?
- Who is visiting today, and who is on shift or on call?
- Are the core internal services up right now?

## Features

| Section | What it does |
|---|---|
| Dashboard | The day at a glance: services down, devices offline, compliance, warranty, rooms not checked, visitors, on call, open joiner/leaver tasks. Daily summary export (CSV). |
| Assets | Device inventory with status and basic compliance. Views for offline, non-compliant, unassigned and duplicate serials. Remote queries per device: serial number, installed software, health. |
| Warranty | Two-phase flow: discover machines from the directory, then check each machine's warranty. Active / expiring / expired, with days left. |
| Software | Installed applications per device, and how many devices have each application. |
| People | Directory of who sits where, linked to their device and desk. |
| Floor map | Desk layout per floor (fictional) and headcount per department and floor. |
| Room checklists | Daily structured check of each meeting room (display, camera, audio, network, booking panel, etc.) with OK/fail per item and history. |
| Joiners & leavers | IT task checklist for each person starting or leaving. |
| Visitors | Register visitors, sign them in and out. |
| Shifts | Who covers which hours, per region, and who is on call. |
| Incident centre | Health checks of internal services with severity, status and latency. |
| Admin | Invite users, set their role, disable them or reset their MFA. Which role can open which section, editable from the UI. |
| Audit log | Who did what and when, across the whole console. |

## Access: invite-only with MFA

Nobody gets in just because they have a directory account. An administrator invites each person, and every account is activated in two steps:

1. **First administrator.** Created once from the server: `flask --app app bootstrap-admin --username you --email you@company`. The command refuses to run if an admin already exists.
2. **Invitations.** From the Admin page, an administrator invites technicians or helpdesk staff with their directory username, email and role (admin, engineer or viewer).
3. **Activation.** At their first sign-in, after the directory password, the console emails a one-time code (6 characters, valid for 10 minutes, single use, 5 attempts). The code proves the person controls that mailbox.
4. **Authenticator app.** Right after activation they scan a QR code with Microsoft Authenticator, Google Authenticator or similar. From then on every sign-in is **directory password + 6-digit TOTP code**.

Administrators can disable an account (the user is signed out at the next click), re-enable it, or reset MFA when someone loses their phone (the next sign-in repeats the email activation). The console always keeps at least one active administrator and nobody can change their own account, so it cannot be locked out by mistake.

Why an authenticator and not an email code on every sign-in: in most organisations the mailbox uses the same directory password, so whoever steals the password can also read the code. An authenticator app is a separate device.

Anything that changes state is written to the audit log. Key events (a service goes down, a room check fails, a new joiner or leaver) are also sent to a webhook, so an automation tool such as n8n can notify the right people by email, Teams or anything else.

## Try it

Requires Python 3.10 or later.

```bash
git clone https://github.com/inigogonzalezgarcia/05-it-ops-console.git
cd 05-it-ops-console
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
flask --app app seed-demo         # creates instance/console.db with fictional data
flask --app app run
```

Open http://127.0.0.1:5000 and sign in with the password `demo`:

- `alex.admin`, `sam.engineer` or `jo.viewer`: already active, each with a different role. In demo mode the verification page shows the current authenticator code.
- `new.tech`: invited but not activated yet, to try the first-time flow. In demo mode emails go to an in-app outbox, and the activation page shows the code.

## Connect it to a real environment

All settings are environment variables (see [`.env.example`](.env.example)):

- **Sign-in**: `OPS_AUTH_MODE=ldap` with `OPS_LDAP_URL=ldaps://...`. Authentication is pass-through: the console binds to the directory with the user's own credentials over LDAPS and never stores passwords. Plain `ldap://` is refused.
- **Device discovery**: `OPS_LDAP_SEARCH_BASE` points to the OU with your computers; a read-only service account lists them.
- **Remote queries**: `OPS_REMOTE_MODE=powershell` runs [`scripts/Get-DeviceInfo.ps1`](scripts/Get-DeviceInfo.ps1) against the device over WinRM/CIM. This works out of the box when the console host is Windows; on Linux, PowerShell remoting needs extra setup.
- **Warranty**: `lookup_warranty()` in `app/services.py` is the extension point for your vendors' warranty APIs. The demo provider returns stable fake dates.
- **Email** (activation codes and invitations): `OPS_EMAIL_MODE=smtp` with `OPS_SMTP_HOST`, `OPS_SMTP_PORT`, `OPS_SMTP_USER`, `OPS_SMTP_PASSWORD` and `OPS_SMTP_FROM` (STARTTLS), or `OPS_EMAIL_MODE=webhook` to let your automation tool send them.
- **QR code** for the authenticator: `pip install segno`. Without it the setup page shows the key to type in manually.
- **Notifications**: `OPS_WEBHOOK_URL` and `OPS_WEBHOOK_SECRET` (payloads are signed with HMAC-SHA256).

For production, run it with gunicorn behind TLS. An example systemd unit is in [`deploy/`](deploy/it-ops-console.service).

## Design notes

- [ARCHITECTURE.md](ARCHITECTURE.md): layers, data flow and the database.
- [docs/decisions.md](docs/decisions.md): the non-obvious choices, including the PowerShell/WMI pitfalls found along the way (CIM sessions for credentials, `Win32_Product`, `Sort-Object -Unique` with hashtables, credentials on stdin, results in a file).
- [docs/security.md](docs/security.md): security controls and a hardening checklist.

It also follows the lessons that apply to any internal tool that starts as a side project and becomes something the team relies on: version control from the first commit, automated tests, all state in the database so several workers can run safely, TLS, and a clear integration point for the ITSM tool.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

## Roadmap

- ITSM integration: show open incidents and scheduled changes from the ticketing tool next to service health.
- Change calendar with a warning when a change overlaps business-critical hours.
- Scheduled health checks and warranty refresh (currently on demand).
- Login rate limiting and optional SSO (OIDC).

## Background

Inspired by years of on-site IT operations and team leadership in fast-paced, regulated, multi-site environments. Built from scratch with fictional data; no employer code, data, names or designs are used.

## Customisation and contact

Need a version adapted to your environment (your own sections and checklists, a vendor warranty API, ITSM integration, SSO or deployment help)? Get in touch:

- Email: [inigogonzalezgarcia@yahoo.es](mailto:inigogonzalezgarcia@yahoo.es)
- LinkedIn: [linkedin.com/in/igonzalez93](https://www.linkedin.com/in/igonzalez93)

## License

MIT
