"""Prepare the Sock Shop lab for a ZombieShield demo. Run inside the backend container:

    docker compose exec backend python scripts/demo_seed.py

1. Registers a SYNTHETIC history of ordinary Sock Shop traffic (clearly labelled "synthetic" in the
   source name). It stands in for the days of gateway logs a real deployment would already have: 24
   shoppers, an old mobile client that still calls PUT /cart/{id} (a route the front-end removed in
   2017), and the orders service's internal Spring Data REST calls that are in no code or spec.
   Sock Shop's own load generator image crashes on current Docker, so it cannot produce this.
2. Sends REAL requests through the Sock Shop gateway as an anonymous attacker who enumerates
   customer records and probes the catalogue with injection payloads.
3. Runs the full pipeline and prints what was found.

Safe to run again: the synthetic history is registered once, and every run adds fresh live traffic.
"""

import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

API = os.environ.get("DEMO_API_URL", "http://localhost:8000")
GATEWAY = os.environ.get("DEMO_GATEWAY_URL", "http://gateway")
HISTORY_DIR = Path(os.environ.get("DEMO_DATA_DIR", "/app/data/demo"))


def say(text: str) -> None:
    print(text, flush=True)


# ---------------------------------------------------------------- 1. synthetic history

def _line(ts, client, method, uri, status, service, auth=True):
    return json.dumps({"ts": ts.isoformat(), "client": client, "method": method, "uri": uri, "status": status,
                       "bytes": random.randint(200, 4000), "latency": round(0.02 + random.random() * 0.05, 3),
                       "host": "front-end", "service": service, "auth": "1" if auth else "0", "ua": "synthetic-history"})


def write_history(minutes: int = 45) -> tuple[Path, Path]:
    """Ordinary shopper traffic ending a few minutes ago (same generator as the test fixture)."""
    random.seed(7)
    items = [str(uuid.UUID(int=random.getrandbits(128))) for _ in range(9)]
    customers = [f"57a98d98e4b00679b4a830a{i}" for i in range(6)]
    end = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=3)
    start = end - timedelta(minutes=minutes)
    gateway, orders = [], []
    clients = [f"10.0.{i // 50}.{i % 50 + 10}" for i in range(24)]
    for minute in range(minutes):
        for client in random.sample(clients, 10):
            ts = start + timedelta(minutes=minute, seconds=random.randint(0, 50))
            customer = random.choice(customers)
            journey = [("GET", "/catalogue?size=6&page=1", 200, False), ("GET", "/tags", 200, False),
                       ("GET", f"/catalogue/{random.choice(items)}", 200, False), ("GET", "/login", 200, True),
                       ("GET", "/cart", 200, True), ("POST", "/cart", 201, True), ("GET", f"/customers/{customer}", 200, True),
                       ("GET", "/orders", 200, True)]
            for step, (method, uri, status, auth) in enumerate(journey[: random.randint(3, len(journey))]):
                gateway.append(_line(ts + timedelta(seconds=step * 2), client, method, uri, status, "front-end", auth))
            orders.append(_line(ts + timedelta(seconds=20), "10.9.0.5", "GET", f"/orders/search/customerId?custId={customer}", 200, "orders"))
        if minute % 3 == 0:  # legacy mobile client still using the retired cart-update route
            gateway.append(_line(start + timedelta(minutes=minute, seconds=40), "10.7.7.7", "PUT", f"/cart/{random.choice(items)}", 200, "front-end"))
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    paths = (HISTORY_DIR / "gateway-history.log", HISTORY_DIR / "orders-history.log")
    for path, lines in zip(paths, (gateway, orders)):
        lines.sort(key=lambda value: json.loads(value)["ts"])
        path.write_text("\n".join(lines) + "\n")
    return paths


# ---------------------------------------------------------------- 2. live traffic through the gateway

def live_traffic() -> dict:
    """An anonymous attacker: customer-record enumeration and injection probes.

    Only the attacker runs live. Every request from this script reaches the gateway from the same
    container address, so a scripted "shopper" would look like the same client as the attacker and
    drag ordinary endpoints into the attack findings. Logged-in shoppers are in the history; during
    the demo, log in to Sock Shop yourself to show that real shoppers are unaffected by the rules.
    """
    stats = {"enumeration": 0, "enumeration_ok": 0, "injection": 0}
    with httpx.Client(base_url=GATEWAY, timeout=10) as attacker:  # no credentials
        for i in range(45):
            response = attacker.get(f"/customers/57a98d98e4b00679b4a8{i:04d}")
            stats["enumeration"] += 1
            stats["enumeration_ok"] += 200 <= response.status_code < 300
        for payload in ("' OR 1=1--", "<script>alert(1)</script>", "1 UNION SELECT password FROM users",
                        "../../etc/passwd", "'; DROP TABLE sock;--", "${jndi:ldap://x/a}"):
            for _ in range(2):
                attacker.get("/catalogue", params={"tags": payload})
                stats["injection"] += 1
    return stats


# ---------------------------------------------------------------- 3. pipeline

def main() -> int:
    say("ZombieShield demo setup")
    api = httpx.Client(base_url=API, timeout=30)
    for _ in range(60):
        try:
            if api.get("/health").status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(2)
    else:
        say("The backend did not become healthy. Check: docker compose logs backend")
        return 1
    login = api.post("/auth/login", json={"username": os.environ.get("ADMIN_USERNAME", "admin"), "password": os.environ.get("ADMIN_PASSWORD", "")})
    if login.status_code != 200:
        say(f"Could not sign in as the admin user ({login.status_code}). Check ADMIN_USERNAME / ADMIN_PASSWORD in .env")
        return 1
    api.headers["Authorization"] = f"Bearer {login.json()['access_token']}"

    existing = {s["name"]: s for s in api.get("/sources").json()}
    # APIs are identified per organisation: the history must use the same one as the Sock Shop sources,
    # otherwise its requests would become separate (shadow) endpoints instead of joining the real ones.
    organization = next((s["organization"] for s in existing.values() if s["kind"] == "runtime_log"),
                        next((s["organization"] for s in existing.values() if s["kind"] == "git"), "sockshop"))
    if "demo-history-gateway (synthetic)" not in existing:
        gateway_log, orders_log = write_history()
        for name, path, service, host in (("demo-history-gateway (synthetic)", gateway_log, "front-end", "front-end"),
                                          ("demo-history-orders (synthetic)", orders_log, "orders", "orders")):
            api.post("/sources", json={"name": name, "kind": "runtime_log", "location": str(path), "service_name": service,
                                       "host": host, "organization": organization, "options": {}}).raise_for_status()
        say("- Registered 45 minutes of synthetic shopper history (24 clients, one legacy mobile app, internal orders calls)")
    else:
        say("- Synthetic history already registered")

    try:
        stats = live_traffic()
        say(f"- Live attacker through the gateway: {stats['enumeration']} anonymous customer lookups "
            f"({stats['enumeration_ok']} answered with data), {stats['injection']} injection probes")
    except httpx.HTTPError as exc:
        say(f"- Could not reach the Sock Shop gateway at {GATEWAY} ({exc}); continuing with the history only")
    time.sleep(3)  # let nginx flush the access log

    started = api.post("/pipeline/run", json={"logs_from_start": False})
    if started.status_code == 409:
        say("- A pipeline run is already in progress; waiting for it")
        run_id = api.get("/pipeline/runs").json()[0]["id"]
    else:
        started.raise_for_status()
        run_id = started.json()["id"]
    say("- Pipeline running (git history mining takes a few minutes)...")
    shown = set()
    while True:
        run = api.get(f"/pipeline/runs/{run_id}").json()
        for stage in run["stages"]:
            if stage["status"] not in ("PENDING", "RUNNING") and stage["key"] not in shown:
                shown.add(stage["key"])
                say(f"    {stage['name']}: {stage['status'].lower()}")
        if run["status"] in ("SUCCEEDED", "FAILED"):
            break
        time.sleep(3)
    if run["status"] != "SUCCEEDED":
        say(f"Pipeline failed: {(run.get('error') or '').splitlines()[0] if run.get('error') else 'see the Pipeline page'}")
        return 1

    summary = api.get("/dashboard/summary").json()
    life = summary["lifecycle"]
    say(f"\nInventory: {summary['total_apis']} endpoints. Active {life['ACTIVE']}, deprecated {life['DEPRECATED']}, "
        f"shadow {life['SHADOW']}, zombie {life['ZOMBIE']}, decommissioned {life['DECOMMISSIONED']}")
    say("Needs attention:")
    for item in summary["attention"][:6]:
        risk = f"risk {item['risk_score']:.0f}" if item.get("risk_score") is not None else "not scored"
        say(f"    {item['state']:<8} {item['method']:<6} {item['path']:<32} {item['service']:<10} {risk}")
    proposals = api.get("/remediation", params={"status": "PROPOSED"}).json()
    say(f"Gateway rules waiting for approval: {len(proposals)}")
    for action in proposals:
        say(f"    {action['priority']:<8} {action['title']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
