"""Build a labelled endpoint dataset from real public OpenAPI/Swagger documents (APIs.guru).

Each row is one documented operation from a real API, with labels that come from the
publishers themselves rather than from ZombieShield's own rules:
  * deprecated  - the operation (or its path item) is marked `deprecated: true` by the publisher
  * sensitive   - the operation's request/response schema or parameters contain personal-data or
                  secret fields (email, password, card, ssn, token, ...); a weak label derived from
                  the documented schema
Features later used for training are computed from METHOD + PATH only, because that is all
ZombieShield can observe for an undocumented runtime-only endpoint.

Usage:
  git clone --depth 1 https://github.com/APIs-guru/openapi-directory
  python scripts/build_endpoint_dataset.py --directory openapi-directory/APIs --out data/endpoint_dataset.csv.gz
"""

import argparse
import csv
import gzip
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.services.discovery.openapi import SpecError, parse_spec  # noqa: E402
from app.services.ml.text_features import is_sensitive_name  # noqa: E402
from app.services.normalization import normalize_path, resource_key, version_from_path, version_number  # noqa: E402

Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
FIELDS = ["provider", "api", "spec_version", "method", "path", "deprecated", "sensitive", "has_security", "newer_version_exists", "n_ops",
          "path_version", "versions_in_spec", "resource_versions", "spec_deprecated_share_excl"]


def rows_for(path: str) -> list[list]:
    file = Path(path)
    try:
        if file.stat().st_size > 6_000_000:
            return []
        document = yaml.load(file.read_text(encoding="utf-8"), Loader=Loader)
        spec = parse_spec(document, include_properties=True)
    except (SpecError, yaml.YAMLError, UnicodeDecodeError, OSError, RecursionError, ValueError, TypeError, AttributeError):
        return []
    parts = file.parts
    try:
        index = parts.index("APIs")
        provider = parts[index + 1]
        api_name = "/".join(parts[index + 1:-2]) or provider
    except ValueError:
        provider, api_name = file.parent.name, file.parent.name
    # newest version observed per resource inside this document
    newest: dict[str, float] = {}
    for op in spec.operations:
        key = resource_key(op.path)
        newest[key] = max(newest.get(key, -1.0), version_number(version_from_path(op.path)))
    versions_in_spec = len({version_from_path(op.path) for op in spec.operations if version_from_path(op.path) != "unversioned"})
    per_resource: dict[str, set] = {}
    for op in spec.operations:
        per_resource.setdefault(resource_key(op.path), set()).add(version_from_path(op.path))
    total_deprecated = sum(int(op.deprecated) for op in spec.operations)
    rows = []
    for op in spec.operations:
        sensitive = any(is_sensitive_name(name) for name in [*op.property_names, *op.parameter_names])
        current = version_number(version_from_path(op.path))
        newer = int(current >= 0 and newest.get(resource_key(op.path), -1.0) > current)
        rows.append([provider, api_name, spec.version, op.method, normalize_path(op.path), int(op.deprecated), int(sensitive),
                     int(bool(op.security) and op.security != ["(not declared)"]), newer, len(spec.operations),
                     current, versions_in_spec, len(per_resource[resource_key(op.path)]),
                     round((total_deprecated - int(op.deprecated)) / max(1, len(spec.operations) - 1), 4)])
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=ROOT / "data" / "endpoint_dataset.csv.gz")
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    files = sorted(str(p) for p in args.directory.rglob("*") if p.name in {"openapi.yaml", "swagger.yaml", "openapi.json", "swagger.json"})
    print(f"{len(files)} specification files")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    total = specs = 0
    with gzip.open(args.out, "wt", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(FIELDS)
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            for rows in pool.map(rows_for, files, chunksize=8):
                if rows:
                    specs += 1
                    total += len(rows)
                    writer.writerows(rows)
    print(f"{specs} specifications parsed, {total} operations written to {args.out}")


if __name__ == "__main__":
    main()
