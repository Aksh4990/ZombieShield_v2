# ZombieShield v2

ZombieShield builds a single inventory of every API operation an organisation exposes. It combines published specifications, source code with its **Git history**, and gateway access logs, then classifies each operation:

| State | Meaning |
|---|---|
| ACTIVE | in the current specification or code |
| DEPRECATED | marked deprecated by the publisher or the owner |
| **ZOMBIE** | retired (removed from code or spec, or superseded by a newer version) **but still receiving traffic** |
| **SHADOW** | receiving traffic, but never seen in any specification or code |
| DECOMMISSIONED | retired, with no recent traffic |

Each classification records its evidence, for example: *"Removed from source in commit 12317157 by A. Giurgiu on 2017-03-07 … runtime traffic continues (14 requests)"*.
ZombieShield works only from evidence it is given. It never sends requests to the APIs it inventories.

## Quick demo (Windows)
Install and start **Docker Desktop** (and Git), then double-click **`demo.cmd`**. It creates `.env`, downloads the Sock Shop repositories, builds and starts everything, generates demo traffic, runs the pipeline and opens the dashboard at http://localhost:5173. The walkthrough is in [`docs/DEMO.md`](docs/DEMO.md). `demo-stop.cmd` stops it.

## What is in v2
* **Discovery:**
  * OpenAPI 3 and Swagger 2.0 (including `deprecated` and `security`)
  * routes from FastAPI, Flask, Express, Spring and Go (gorilla/mux, gin/echo/chi, net/http)
  * Git history mining for introduced and retired routes
  * gateway JSON, nginx and Apache logs, with continuous log following
  * 404 probes are kept out of the inventory
* **Threat intelligence:** dependency manifests (requirements, npm, go.mod, Maven, CycloneDX) are matched against OSV.dev with real version ranges. CVSS 3.x scores are computed, and results are enriched with CISA KEV and FIRST EPSS. An offline cache is used for demos.
* **Machine learning, trained on real public data** (see `backend/ml_artifacts/*_metrics.json`):
  * payload-attack classifier (HTTP CSIC 2010 + HttpParamsDataset)
  * endpoint "legacy" and "sensitive data" models (84,471 operations from 682 public API providers, evaluated on providers held out of training)
  * traffic anomaly detector (Isolation Forest on per-client behaviour windows)
* **Platform:**
  * JWT login with viewer, analyst and admin roles, plus an audit log
  * batched writes and Alembic migrations
  * one-click pipeline with live progress (server-sent events)
  * recommendation-only decision engine
* **Validation:** `POST /validation/run` scores the lifecycle classifications against a hand-written ground truth (`sockshop/ground_truth.template.json`).
* **Security controls, risk and remediation** (`docs/EXTENSIONS.md`): per-API control evidence mapped to the OWASP API Top 10 (2023), an explainable 0–100 risk score, and nginx gateway rules (block, require credentials, rate limit, deprecation headers) that a person approves, applies, verifies and can roll back.
* **Dashboard** (React): inventory, endpoint evidence, pipeline, remediation workflow, vulnerabilities, traffic, sources, model cards and validation, users and audit log.

## Run it
```powershell
Copy-Item .env.example .env        # then edit every CHANGE-ME value
docker compose up --build          # platform only
```
To run against the Sock Shop reference deployment as well:
```powershell
.\scripts\setup_sockshop.ps1                    # clones the 7 service repositories with history
docker compose --profile sockshop up --build
```
* Dashboard: http://localhost:5173 (log in with the admin or analyst account from `.env`)
* API and interactive docs: http://localhost:8000/docs
* Sock Shop through the logging gateway: http://localhost:8079
* Start a run: `POST /pipeline/run`, then follow `GET /pipeline/runs/{id}/stream`

## Tests
```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r backend\requirements.txt
.\.venv\Scripts\python -m pytest -q
```

## Retraining the models
See `backend/scripts/`. Each script names its public data source and writes a metrics JSON next to the model.

## Known limitations
* Route extraction uses regular expressions. Dynamically registered routes (for example Spring Data REST repositories) are not visible in code, so they show up as SHADOW when they receive traffic. That is the intended behaviour.
* Go projects using the old `glide` or `govendor` dependency managers are not scanned for dependencies. Only `go.mod` is.
* The CSIC 2010 recall of the payload classifier is 0.44 at the precision-oriented threshold (precision 1.00).
* The gateway logs only see traffic that passes through it, so internal service-to-service calls are not observed.
