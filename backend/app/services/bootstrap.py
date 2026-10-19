"""Startup tasks: default users, sources from the lab config file, and the background log follower."""

import logging
import shutil
import threading
from pathlib import Path

import yaml
from sqlalchemy import select

from app.core.config import BACKEND_ROOT, get_settings
from app.core.security import hash_password
from app.db.session import SessionLocal
from app.models import Source, User
from app.services import traffic
from app.services.discovery.runner import run_log_source
from app.services.inventory import InventoryWriter

log = logging.getLogger(__name__)
_stop = threading.Event()


def seed_users() -> None:
    settings = get_settings()
    with SessionLocal() as db:
        if db.scalar(select(User).limit(1)) is not None:
            return
        db.add(User(username=settings.admin_username, password_hash=hash_password(settings.admin_password), role="admin"))
        db.add(User(username=settings.analyst_username, password_hash=hash_password(settings.analyst_password), role="analyst"))
        db.commit()
        if settings.admin_password == "zombieshield-admin":
            log.warning("Default admin password in use; set ADMIN_PASSWORD in .env")


def seed_threat_cache() -> None:
    """Copy the bundled offline cache (OSV index for the reference repos + CISA KEV) into the cache volume."""
    bundled = BACKEND_ROOT / "data" / "threat_cache"
    target = Path(get_settings().threat_cache_dir)
    if not bundled.is_dir() or bundled.resolve() == target.resolve():
        return
    target.mkdir(parents=True, exist_ok=True)
    for file in bundled.glob("*.json"):
        if not (target / file.name).exists():
            shutil.copyfile(file, target / file.name)


def seed_sources() -> None:
    path = get_settings().lab_config_path
    if not path or not Path(path).is_file():
        return
    config = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    with SessionLocal() as db:
        existing = set(db.scalars(select(Source.name)))
        defaults = config.get("defaults", {})
        for item in config.get("sources", []):
            if item["name"] in existing:
                continue
            db.add(Source(
                name=item["name"], kind=item["kind"], location=item["location"],
                organization=item.get("organization", defaults.get("organization", "zombieshield-lab")),
                host=item.get("host", defaults.get("host", "api.local")).lower(), service_name=item.get("service_name"),
                options=item.get("options", {}), enabled=item.get("enabled", True),
            ))
        db.commit()


def _follow_logs() -> None:
    interval = get_settings().log_follow_interval_seconds
    while not _stop.wait(interval):
        try:
            with SessionLocal() as db:
                sources = list(db.scalars(select(Source).where(Source.enabled.is_(True), Source.kind == "runtime_log")))
                followed = [s for s in sources if (s.options or {}).get("follow")]
                if not followed:
                    continue
                writer = InventoryWriter(db)
                for source in followed:
                    run_log_source(db, writer, source)
                writer.commit()
                traffic.refresh_aggregates(db)
                db.commit()
        except Exception:  # keep following even if one pass fails
            log.exception("Log follower pass failed")


def start_log_follower() -> threading.Thread | None:
    if not get_settings().log_follow_enabled:
        return None
    _stop.clear()
    thread = threading.Thread(target=_follow_logs, name="log-follower", daemon=True)
    thread.start()
    return thread


def stop_log_follower() -> None:
    _stop.set()
