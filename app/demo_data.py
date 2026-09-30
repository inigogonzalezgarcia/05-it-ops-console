"""Fictional demo data: people, devices, rooms, visitors, shifts and services.

Every name, hostname and serial number here is invented.
"""

import json
import random
from datetime import date, datetime, timedelta, timezone

from . import db
from .mfa import new_totp_secret
from .services import lookup_warranty, run_health_checks

FIRST = ["Alex", "Maria", "Jon", "Laura", "David", "Sara", "Pablo", "Elena", "Marco", "Julia",
         "Omar", "Ines", "Lucas", "Nora", "Hugo", "Clara", "Leo", "Ana", "Tom", "Eva"]
LAST = ["Garcia", "Rossi", "Martin", "Dubois", "Smith", "Yilmaz", "Silva", "Jansen", "Lopez",
        "Moreau", "Bianchi", "Kaya", "Novak", "Fischer", "Costa", "Weber"]
DEPARTMENTS = ["Operations", "Finance", "Sales", "Legal", "HR", "Technology", "Risk"]
HARDWARE = [("Dell", "Latitude 7440"), ("Lenovo", "ThinkPad T14"), ("HP", "EliteBook 840")]
ROOMS = [("Room Atlas", 1, 12), ("Room Boreal", 1, 6), ("Room Cedar", 2, 8), ("Room Delta", 2, 4),
         ("Room Ember", 3, 16), ("Room Fjord", 3, 6)]
CHECKLIST_ITEMS = ["Display", "Camera", "Microphone and speakers", "Room PC", "Wired network",
                   "Wi-Fi", "Booking panel", "Cables and cleanliness"]
JOIN_TASKS = ["Create directory account", "Assign licences", "Prepare laptop", "Enrol MFA",
              "Add to groups and mailing lists", "Desk and phone ready"]
LEAVE_TASKS = ["Disable account", "Revoke remote access", "Collect hardware", "Transfer mailbox and files",
               "Remove from groups", "Remove licences"]
ENDPOINTS = [("Directory (LDAPS)", "critical"), ("Email gateway", "critical"), ("Remote access VPN", "high"),
             ("File services", "high"), ("Video conferencing", "high"), ("Intranet", "medium"),
             ("Print service", "low"), ("Ticketing portal", "medium")]


def seed(seed_value: int = 42) -> None:
    rng = random.Random(seed_value)
    today = date.today()
    conn = db.get_db()
    for table in ("one_time_codes", "outbox", "users", "assets", "warranties", "software", "people", "desks", "rooms", "checklist_runs",
                  "lifecycle", "visitors", "shifts", "endpoints", "audit_log"):
        conn.execute(f"DELETE FROM {table}")

    # Active demo users already have an authenticator; the verify page shows the
    # current code in demo mode. new.tech is invited and goes through activation.
    for username, name, role, status in (("alex.admin", "Alex Admin", "admin", "active"),
                                         ("sam.engineer", "Sam Engineer", "engineer", "active"),
                                         ("jo.viewer", "Jo Viewer", "viewer", "active"),
                                         ("new.tech", "New Tech", "engineer", "invited")):
        conn.execute("INSERT INTO users (username, display_name, email, role, status, totp_secret, invited_by, "
                     "invited_at, activated_at) VALUES (?, ?, ?, ?, ?, ?, 'alex.admin', ?, ?)",
                     (username, name, f"{username}@example.internal", role, status,
                      new_totp_secret() if status == "active" else None, db.now(),
                      db.now() if status == "active" else None))

    # Floors 1-3: four desk clusters of 2 x 5 desks each.
    desks = []
    for floor in (1, 2, 3):
        for cluster in range(4):
            for row in range(2):
                for col in range(5):
                    desk_id = f"{floor}-{'ABCD'[cluster]}{row * 5 + col + 1:02d}"
                    desks.append((desk_id, floor, cluster * 6 + col, row))
    conn.executemany("INSERT INTO desks (id, floor, x, y) VALUES (?, ?, ?, ?)", desks)

    free_desks = [d[0] for d in desks]
    rng.shuffle(free_desks)
    people = []
    for i in range(96):
        name = f"{rng.choice(FIRST)} {rng.choice(LAST)}"
        username = name.lower().replace(" ", ".")
        if any(p[0] == username for p in people):  # keep usernames unique, like a real directory
            username += str(i)
        desk = free_desks.pop()
        people.append((username, name, rng.choice(DEPARTMENTS), "Main office", int(desk[0]), desk))
    conn.executemany("INSERT INTO people VALUES (?, ?, ?, ?, ?, ?)", people)

    assets = []
    for i, person in enumerate(people + [None] * 10):
        manufacturer, model = rng.choice(HARDWARE)
        hostname = f"WKS-{1000 + i}"
        serial = f"SN{rng.randint(10**7, 10**8 - 1)}"
        status = rng.choices(["online", "offline", "unknown"], weights=[0.8, 0.15, 0.05])[0]
        last_seen = datetime.now(timezone.utc) - timedelta(hours=rng.randint(0, 2) if status == "online"
                                                           else rng.randint(24, 900))
        assets.append((hostname, serial, manufacturer, model, "Windows 11", person[0] if person else None,
                       "Main office", person[4] if person else None, status,
                       rng.choices([1, 0, None], weights=[0.86, 0.1, 0.04])[0],
                       last_seen.strftime("%Y-%m-%d %H:%M:%S")))
    # two machines sharing a serial number: typical after a motherboard swap or a re-image
    assets[5] = assets[5][:1] + (assets[4][1],) + assets[5][2:]
    conn.executemany("INSERT INTO assets VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", assets)

    for a in assets[:80]:  # warranty already checked for most, not all, machines
        conn.execute("INSERT INTO warranties VALUES (?, ?, ?, ?, 'demo')",
                     (a[0], a[2], lookup_warranty(a[2], a[1]), db.now()))

    conn.executemany("INSERT INTO rooms VALUES (?, ?, ?)", ROOMS)
    for day in range(5, 0, -1):
        for room, _floor, _cap in ROOMS:
            results = {item: ("fail" if rng.random() < 0.06 else "ok") for item in CHECKLIST_ITEMS}
            conn.execute("INSERT INTO checklist_runs (room, run_at, run_by, results, failures, notes) "
                         "VALUES (?, ?, ?, ?, ?, ?)",
                         (room, f"{today - timedelta(days=day)} 08:{rng.randint(0, 45):02d}:00", "sam.engineer",
                          json.dumps(results), list(results.values()).count("fail"), ""))

    for kind, tasks, offset in (("join", JOIN_TASKS, 3), ("join", JOIN_TASKS, 10), ("join", JOIN_TASKS, 1),
                                ("leave", LEAVE_TASKS, 2), ("leave", LEAVE_TASKS, -1)):
        done = rng.randint(0, len(tasks))
        conn.execute("INSERT INTO lifecycle (kind, person_name, department, effective_date, tasks, created_by, "
                     "created_at) VALUES (?, ?, ?, ?, ?, 'sam.engineer', ?)",
                     (kind, f"{rng.choice(FIRST)} {rng.choice(LAST)}", rng.choice(DEPARTMENTS),
                      str(today + timedelta(days=offset)),
                      json.dumps([{"task": t, "done": n < done} for n, t in enumerate(tasks)]), db.now()))

    for i in range(7):
        host = rng.choice(people)
        visit_day = today + timedelta(days=rng.choice([0, 0, 0, 1, 2]))
        conn.execute("INSERT INTO visitors (visitor_name, company, host, visit_date, location) VALUES (?, ?, ?, ?, ?)",
                     (f"{rng.choice(FIRST)} {rng.choice(LAST)}", rng.choice(["Northwind", "Fabrikam", "Contoso", "Tailspin"]),
                      host[1], str(visit_day), rng.choice(ROOMS)[0]))

    engineers = [("Sam Engineer", "EMEA"), ("Riley Tech", "EMEA"), ("Kai Support", "AMER"), ("Mina Ops", "APAC")]
    monday = today - timedelta(days=today.weekday())
    for d in range(14):
        day = monday + timedelta(days=d)
        if day.weekday() >= 5:
            continue
        for engineer, region in engineers:
            start, end = {"EMEA": ("07:00", "16:00"), "AMER": ("13:00", "22:00"), "APAC": ("00:00", "09:00")}[region]
            if region == "EMEA" and engineer == "Riley Tech":
                start, end = "10:00", "19:00"
            conn.execute("INSERT INTO shifts (engineer, shift_date, start_time, end_time, region, on_call) "
                         "VALUES (?, ?, ?, ?, ?, ?)", (engineer, str(day), start, end, region,
                                                       int(engineer == engineers[d % 4][0])))

    conn.executemany("INSERT INTO endpoints (name, url, severity) VALUES (?, ?, ?)",
                     [(name, f"demo://{name.lower().replace(' ', '-')}", sev) for name, sev in ENDPOINTS])
    conn.commit()
    run_health_checks()  # start with a real status instead of "unknown"
