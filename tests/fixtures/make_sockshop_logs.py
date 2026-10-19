"""Generate a small, normal-traffic access-log fixture for Sock Shop in the gateway's JSON format.

Represents ordinary shoppers plus one old mobile client that still calls a route the front-end
removed in 2017 (PUT /cart/{id}), and internal calls the orders service answers through Spring
Data REST endpoints that never appear in its source code or spec. Used by the tests only.
"""

import json
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(7)
ITEMS = [str(uuid.UUID(int=random.getrandbits(128))) for _ in range(9)]
CUSTOMERS = [f"57a98d98e4b00679b4a830a{i}" for i in range(6)]


def line(ts, client, method, uri, status, service, auth=True, latency=0.02):
    return json.dumps({"ts": ts.isoformat(), "client": client, "method": method, "uri": uri, "status": status, "bytes": random.randint(200, 4000),
                       "latency": round(latency + random.random() * 0.05, 3), "host": "front-end", "service": service, "auth": "1" if auth else "0",
                       "ua": "Mozilla/5.0"})


def main(out_dir: Path, minutes: int = 40) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = now - timedelta(minutes=minutes)
    gateway, orders = [], []
    clients = [f"10.0.{i // 50}.{i % 50 + 10}" for i in range(24)]
    for minute in range(minutes):
        for client in random.sample(clients, 10):
            ts = start + timedelta(minutes=minute, seconds=random.randint(0, 50))
            customer = random.choice(CUSTOMERS)
            journey = [("GET", "/catalogue?size=6&page=1", 200, False), ("GET", "/tags", 200, False), ("GET", f"/catalogue/{random.choice(ITEMS)}", 200, False),
                       ("GET", "/login", 200, True), ("GET", "/cart", 200, True), ("POST", "/cart", 201, True), ("GET", f"/customers/{customer}", 200, True),
                       ("GET", "/orders", 200, True)]
            for step, (method, uri, status, auth) in enumerate(journey[: random.randint(3, len(journey))]):
                gateway.append(line(ts + timedelta(seconds=step * 2), client, method, uri, status, "front-end", auth))
            if random.random() < 0.15:
                gateway.append(line(ts + timedelta(seconds=30), client, "GET", "/favicon-old.ico", 404, "front-end", False))
            orders.append(line(ts + timedelta(seconds=20), "10.9.0.5", "GET", f"/orders/search/customerId?custId={customer}", 200, "orders"))
        if minute % 3 == 0:  # legacy mobile client still using the retired cart-update route
            ts = start + timedelta(minutes=minute, seconds=40)
            gateway.append(line(ts, "10.7.7.7", "PUT", f"/cart/{random.choice(ITEMS)}", 200, "front-end", True))
    for name, lines in (("sockshop_gateway.log", gateway), ("sockshop_orders.log", orders)):
        lines.sort(key=lambda value: json.loads(value)["ts"])
        (out_dir / name).write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent)
