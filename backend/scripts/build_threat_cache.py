"""Build the offline vulnerability cache used when OSV.dev is unreachable (e.g. during a demo).

Inputs:
  --ghsa   path to a clone of github.com/github/advisory-database (advisories/github-reviewed is enough;
           the files are already in OSV format)
  --repos  directory whose sub-folders are the repositories ZombieShield will scan; only advisories for
           packages found in their manifests are kept, which keeps the cache small
  --kev    optional path to known_exploited_vulnerabilities.json (github.com/cisagov/kev-data)

Usage:
  python scripts/build_threat_cache.py --ghsa advisory-database --repos ../discovery-repositories --kev kev-data/known_exploited_vulnerabilities.json
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.services.threat_intel.feeds import package_key  # noqa: E402
from app.services.threat_intel.sbom import scan_directory  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ghsa", type=Path, required=True)
    parser.add_argument("--repos", type=Path, required=True)
    parser.add_argument("--kev", type=Path)
    parser.add_argument("--out", type=Path, default=ROOT / "data" / "threat_cache")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    wanted = set()
    for repo in sorted(p for p in args.repos.iterdir() if p.is_dir()):
        for dep in scan_directory(repo):
            wanted.add(package_key(dep.ecosystem, dep.name))
    print(f"{len(wanted)} distinct packages found in manifests under {args.repos}")

    index: dict[str, list[dict]] = {}
    scanned = 0
    for file in (args.ghsa / "advisories" / "github-reviewed").rglob("GHSA-*.json"):
        scanned += 1
        try:
            record = json.loads(file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        keys = {package_key((a.get("package") or {}).get("ecosystem", ""), (a.get("package") or {}).get("name", "")) for a in record.get("affected") or []}
        for key in keys & wanted:
            index.setdefault(key, []).append(record)
    (args.out / "osv_index.json").write_text(json.dumps(index))
    print(f"{scanned} advisories scanned; {sum(len(v) for v in index.values())} kept for {len(index)} packages")
    if args.kev and args.kev.is_file():
        shutil.copyfile(args.kev, args.out / "kev.json")
        print("KEV catalogue copied")


if __name__ == "__main__":
    main()
