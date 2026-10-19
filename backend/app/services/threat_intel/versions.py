"""Ecosystem-aware version comparison and OSV range evaluation."""

import re

from packaging.version import InvalidVersion, Version

_NUM = re.compile(r"\d+|[A-Za-z]+")


def _generic_key(value: str) -> tuple:
    value = value.strip().lstrip("vV").split("+", 1)[0]
    main, _, pre = value.partition("-")
    parts = []
    for token in _NUM.findall(main):
        parts.append((0, int(token)) if token.isdigit() else (1, token.lower()))
    while parts and parts[-1] == (0, 0):
        parts.pop()
    # a pre-release sorts before the release it precedes
    return (tuple(parts), 0 if pre else 1, tuple((0, int(t)) if t.isdigit() else (1, t.lower()) for t in _NUM.findall(pre)))


def version_key(ecosystem: str, value: str):
    if ecosystem == "PyPI":
        try:
            return (0, Version(value))
        except InvalidVersion:
            pass
    return (1, _generic_key(value))


def compare(ecosystem: str, a: str, b: str) -> int:
    ka, kb = version_key(ecosystem, a), version_key(ecosystem, b)
    if ka[0] != kb[0]:  # mixed parse modes: fall back to generic comparison for both
        ka, kb = (1, _generic_key(a)), (1, _generic_key(b))
    return (ka > kb) - (ka < kb)


def is_affected(ecosystem: str, version: str, affected: dict) -> bool:
    """Evaluate one OSV `affected` entry against an installed version."""
    if version in (affected.get("versions") or []):
        return True
    for range_ in affected.get("ranges") or []:
        if range_.get("type") not in {"ECOSYSTEM", "SEMVER"}:
            continue
        events = range_.get("events") or []
        introduced = None
        for event in events:
            if "introduced" in event:
                introduced = event["introduced"]
            elif introduced is not None and "fixed" in event:
                if (introduced == "0" or compare(ecosystem, version, introduced) >= 0) and compare(ecosystem, version, event["fixed"]) < 0:
                    return True
                introduced = None
            elif introduced is not None and "last_affected" in event:
                if (introduced == "0" or compare(ecosystem, version, introduced) >= 0) and compare(ecosystem, version, event["last_affected"]) <= 0:
                    return True
                introduced = None
        if introduced is not None and (introduced == "0" or compare(ecosystem, version, introduced) >= 0):
            return True  # introduced with no fix yet
    return False


def fixed_versions(affected: dict) -> list[str]:
    out = []
    for range_ in affected.get("ranges") or []:
        for event in range_.get("events") or []:
            if "fixed" in event:
                out.append(event["fixed"])
    return out
