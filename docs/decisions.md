# Design decisions and lessons learned

Short records of the choices that are not obvious from the code.

## 1. Credentials go to PowerShell on stdin, never as arguments

**Problem.** The easy way to call a script is `pwsh -File script.ps1 -User x -Password y`. On any multi-user host, command lines are visible in the process list (`ps`, Task Manager, EDR telemetry, crash dumps).

**Decision.** `services.query_device` sends `{"username": ..., "password": ...}` as JSON on stdin. The script reads it with `[Console]::In.ReadToEnd()` and builds a `PSCredential` in memory.

## 2. Results come back in a file, not on stdout

**Problem.** PowerShell writes more than your output to stdout: warnings, progress, module import banners, the occasional `Write-Host`. Parsing stdout as JSON breaks as soon as any of those appears.

**Decision.** The app passes `-OutFile <temp path>`; the script writes only the JSON result there. stdout and stderr are kept for error messages. The temp file is always deleted afterwards.

## 3. Alternate credentials need a CIM session

**Problem.** `Get-CimInstance -ComputerName X -Credential $cred` fails: `Get-CimInstance` has no `-Credential` parameter. The old `Get-WmiObject` had one, which is why many examples still use it, but `Get-WmiObject` does not exist in PowerShell 7.

**Decision.** Create a session with `New-CimSession -ComputerName X -Credential $cred`, pass it with `-CimSession`, and remove it in a `finally` block.

## 4. Software inventory from the registry, not `Win32_Product`

**Problem.** `Win32_Product` looks like the natural class for installed software, but querying it is slow and makes Windows Installer run a consistency check on every MSI package, which can trigger repairs.

**Decision.** Read the two `Uninstall` registry keys (64-bit and 32-bit) through `Invoke-Command`, skipping system components.

## 5. `Sort-Object -Unique` needs objects, not hashtables

**Problem.** Building each result as a `@{ name = ...; version = ... }` hashtable and piping to `Sort-Object -Unique` does not remove duplicates: hashtables are compared as objects, not by their keys.

**Decision.** Emit `[pscustomobject]` records and sort with explicit properties: `Sort-Object -Property name, version -Unique`.

## 6. Pass-through authentication over LDAPS only

**Decision.** The console never stores passwords. At sign-in it binds to the directory with the user's own credentials; if the bind succeeds, the user is who they say they are. Plain `ldap://` is refused so credentials never cross the network in clear text. Discovery of computers uses a separate read-only service account.

## 7. All state in SQLite

**Problem.** Keeping things like "last health check" or caches in Python globals works with one process and silently breaks with several gunicorn workers: each worker has its own copy.

**Decision.** Everything lives in SQLite with WAL mode enabled. It is enough for a team-sized tool and keeps deployment to a single file. The data layer is plain SQL, so moving to PostgreSQL later is straightforward.

## 8. Events out through webhooks

**Decision.** The console does not send notifications itself (the one exception is account activation email, see 10). It emits events (`service.status_changed`, `room.check_failed`, `employee.join`, `employee.leave`) to one webhook, signed with HMAC-SHA256. The automation tool on the other side decides who is told and how. Changing a notification channel never requires changing the console, and a failed notification never blocks the user's action.

## 9. Permissions are data, not code

**Decision.** Which role can open which section is stored in `role_sections` and edited from the Admin page. The `admin` role always keeps full access, and an admin cannot change their own role, so nobody can lock everyone out.

## 10. Invite-only access with email activation and TOTP

**Problem.** "Anyone with a directory account can sign in" is too broad for a tool that can query devices and see people's desks. And a password alone is one phishing email away from misuse.

**Decision.**
- The first administrator is created with a server-side command (`bootstrap-admin`) that refuses to run once an admin exists, so no web page can be raced to claim admin rights.
- Administrators invite each user. Unknown, invited-but-wrong-password and disabled accounts all get the same failure message, so the login page does not reveal which accounts exist.
- First sign-in: a 6-character code by email (alphabet without 0/O and 1/I, generated with `secrets`, stored only as an HMAC, 10-minute expiry, single use, 5 attempts, at most one new code per minute).
- Then the user registers an authenticator app, and every later sign-in uses a TOTP code (RFC 6238, 30-second steps, one step of clock drift, a used step cannot be replayed).
- Email codes are not used for daily sign-in because the mailbox is usually protected by the same directory password; the authenticator is a second, separate factor.
- TOTP is implemented with the standard library (about 20 lines, tested against the RFC test vector), so there is no extra dependency for the security-critical part.
