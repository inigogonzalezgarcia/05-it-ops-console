# Security

## Controls in the code

| Area | Control |
|---|---|
| Authentication | LDAPS pass-through bind; passwords are never stored or logged. Plain LDAP refused. |
| Access | Invite-only accounts; first admin only via server command; at least one active admin always kept; users cannot change their own account. |
| Second factor | Emailed activation code (hashed, 10 min, single use, 5 attempts, rate-limited), then TOTP on every sign-in with replay protection. |
| Account enumeration | Same message for unknown, disabled and wrong-password sign-ins. |
| Sessions | Signed Flask session cookies, `HttpOnly`, `SameSite=Lax`, `Secure` when `OPS_COOKIE_SECURE=1`. |
| Authorisation | Every page and action checks the user's role against `role_sections`. |
| CSRF | Every POST must carry the per-session token (form field or `X-CSRF-Token` header). |
| Open redirects | The `next` parameter after sign-in only accepts local paths. |
| SQL injection | Parameterised queries everywhere; the only dynamic column name is chosen from a fixed map. |
| XSS | Jinja2 autoescaping; no user input is marked safe. |
| Command injection | Hostnames validated against a strict pattern in Python and again in PowerShell (`ValidatePattern`); the query type is a fixed set; arguments are passed as a list, never through a shell. |
| Secrets on the host | Credentials passed on stdin, not in the process list; results in a temp file that is always deleted. |
| Webhooks | Payloads signed with HMAC-SHA256 so the receiver can verify them. |
| Accountability | Every state-changing action is written to the audit log with user and time. |

## Hardening checklist for a real deployment

- [ ] Set a long random `OPS_SECRET_KEY` and keep it out of the repository (it also keys the activation-code hashes).
- [ ] Create the first administrator with `bootstrap-admin`, then invite everyone else from the Admin page.
- [ ] Configure SMTP with TLS (or the webhook) so activation codes reach real mailboxes; never use the demo outbox in production.
- [ ] Protect the database file: it contains the TOTP secrets.
- [ ] Serve over TLS only (gunicorn `--certfile/--keyfile` or a reverse proxy) and set `OPS_COOKIE_SECURE=1`.
- [ ] Run on a server, not a workstation, under a dedicated service account with only the rights it needs.
- [ ] Use a read-only directory account for discovery and a least-privilege account for remote queries.
- [ ] Restrict network access to the console to the IT team's networks.
- [ ] Back up the database file and the audit log.
- [ ] Add login rate limiting at the reverse proxy.
- [ ] Review role permissions on the Admin page after the first users sign in.
