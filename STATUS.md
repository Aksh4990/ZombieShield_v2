# ZombieShield v2: work-in-progress snapshot

Your original project in `zombieshield_fyp` is untouched. The **backend runs end to end** (API, pipeline, migrations, Docker) and the **new React frontend** covers every backend feature.

## Done
- `backend/app/models/`: new data model (APIs with evidence flags, evidence timeline, users, audit log, sources, pipeline runs, components, vulnerabilities, findings, request log, anomalies, decisions, remediation actions, validation runs)
- `backend/app/core/`: settings, password hashing (scrypt), JWT tokens, client-address pseudonymisation
- `backend/app/services/normalization.py`: canonical endpoint identity (all parameter syntaxes become `{id}`, version taken from the path, prefix/wildcard routes)
- `backend/app/services/discovery/`
  - `openapi.py`: OpenAPI 3.x **and Swagger 2.0**, reads `deprecated: true` and security declarations
  - `code_routes.py`: FastAPI, Flask, Express (cross-file mounts), Spring, Go (gorilla/mux, gin/echo/chi, net/http); comments ignored
  - `git_history.py`: finds when each route / documented operation was added and **removed** (tested on Sock Shop's real history)
  - `logs.py`: gateway JSON, nginx/Apache combined, legacy simple format
  - `runner.py`: runs configured sources into the inventory (batched writes)
- `backend/app/services/inventory.py`: batched upserts with provenance; fixes the old "documented flag never updates" bug
- `backend/app/services/traffic.py`: data-minimised traffic ingestion; 404 probes are kept out of the inventory
- `backend/app/services/lifecycle.py`: ACTIVE / DEPRECATED / SHADOW / ZOMBIE / DECOMMISSIONED with strict definitions
- `backend/app/services/threat_intel/`: dependency scanning (requirements, package-lock/package.json, go.mod, pom.xml, CycloneDX), OSV version-range matching, CVSS 3.x calculator, CISA KEV, FIRST EPSS, offline cache fallback
- `backend/app/services/ml/`: runtime code for the three models
- `backend/ml_artifacts/`: trained models + metrics JSON (scikit-learn 1.9.1)
- `backend/scripts/`: reproducible training scripts

## Trained models (real public data, held-out evaluation)
| Model | Data | Result |
|---|---|---|
| Payload-attack classifier | HTTP CSIC 2010 + HttpParamsDataset | precision 1.00 / recall 0.44 (CSIC test), F1 0.998 (HttpParams test), cross-dataset F1 0.89, at threshold 0.85 |
| Endpoint "legacy" model | 84,471 operations, 682 providers (APIs.guru) | ROC-AUC 0.72 on unseen providers |
| Endpoint "sensitive data" model | same | ROC-AUC 0.67 on unseen providers |

Negative result worth reporting: path wording alone does not predict deprecation for unseen providers (ROC-AUC 0.42).
Real-data finding: operations with a newer path version are deprecated 32.8% of the time vs 1.2% overall.

## To retrain
```
cd backend
python scripts/train_payload_model.py --csic <csic_final.csv> --httpparams <HttpParamsDataset dir>
python scripts/build_endpoint_dataset.py --directory <openapi-directory/APIs>
python scripts/train_endpoint_model.py
```

## Also done (stages 8, 10, 11)
- Decision engine (`services/decision.py`), one-click pipeline with live progress and extension slots (`services/pipeline.py`)
- API routes (`api/routers/`), `main.py`, startup seeding, background log follower
- Alembic migration `0001`, Dockerfile, `docker-compose.yml` with an optional Sock Shop profile (logging gateway + official load generator)
- Offline vulnerability cache for the Sock Shop repos (`backend/data/threat_cache`)
- Validation scoring (stage 13): `POST /validation/run` with your ground-truth JSON (template: `sockshop/ground_truth.template.json`) returns accuracy, macro-F1, per-class and zombie-or-shadow precision/recall/F1 and a confusion matrix; `GET /validation/runs` lists past runs
- Paper revision guide with all final figures: `docs/PAPER_REVISION.md`

## Verified on real Sock Shop code (7 repos, ~350 commits mined)
- 9 retired routes traced to the commit and author that removed them
- With a normal-traffic log fixture: front-end `PUT /cart/{id}` (removed 2017) classified **ZOMBIE**, orders `GET /orders/search/customerId` (Spring Data REST, in no code or spec) classified **SHADOW**
- Real CVEs matched in front-end's npm dependencies (e.g. morgan 1.7.0, CVSS 9.8)

## Stages 6, 7 and 9 (security controls, risk, remediation)
- `services/controls.py` (stage 6): per-API control evidence (authentication, object-level authorization, input validation, rate limiting, inventory, gateway rules) with statuses ENFORCED / DECLARED / NOT_ENFORCED / NOT_OBSERVED / NOT_REQUIRED / UNKNOWN, each backed by evidence, mapped to OWASP API Top 10 (2023). Public endpoints (anonymous by design) are told apart from protected ones that leak.
- `services/risk.py` (stage 7): additive, capped 0-100 score; every point is a `{factor, points, evidence}` entry (lifecycle exposure, access control, ML sensitivity, KEV/CVSS/EPSS, accepted attacks, suspicious clients, reach) with discounts for decommissioned endpoints and verified gateway rules. Levels align with the decision engine (>=75 CRITICAL/ESCALATE, >=50 HIGH/REMEDIATE).
- `services/remediation.py` + `services/gateway.py` (stage 9): proposes BLOCK_ROUTE (410), REQUIRE_AUTH (401), RATE_LIMIT (429, rate derived from normal clients) and DEPRECATION_HEADERS; approval workflow PROPOSED -> APPROVED -> APPLIED -> VERIFIED (or REJECTED / ROLLED_BACK); applying renders nginx rules into `GATEWAY_RULES_DIR`; verification checks traffic seen after applying.
- API: `GET /remediation`, `GET /remediation/{id}`, `GET /remediation/gateway-config`, `POST /remediation/{id}/{approve|reject|apply|verify|rollback|reopen}` (approve/apply/rollback: admin). Dashboard summary now includes `risk_levels` and `remediation` counts.
- Sock Shop gateway reloads itself when rules change (`sockshop/gateway/reload-on-change.sh`, guarded by `nginx -t`).
- Verified on the real Sock Shop repos plus the log fixture with an added attacker: unauthenticated BOLA enumeration on `GET /customers/{id}` scores CRITICAL (REQUIRE_AUTH + RATE_LIMIT proposed), zombie `PUT /cart/{id}` scores HIGH (BLOCK_ROUTE proposed), public catalogue is not asked to require auth; generated rules pass `nginx -t` and were exercised in a live nginx (410 / 401 / 429 as expected).
- Threat intel online calls have a wall-clock budget (`THREAT_INTEL_TIMEOUT_SECONDS`, default 90 s) and fall back to the offline cache, so a slow feed cannot stall the pipeline; runs left RUNNING by a backend restart are marked FAILED at startup instead of blocking new runs.
- First Docker run (PostgreSQL) found two bugs SQLite tests could not: threat findings were inserted before their vulnerability rows (foreign-key violation), and a failed stage whose error text exceeded 4,000 characters left the run stuck in RUNNING. Both fixed; tests now run SQLite with foreign keys enforced.
- End-to-end on Docker (Windows, PostgreSQL, live Sock Shop, 19 Oct 2026): all 9 stages succeed (threat intel via live OSV.dev in seconds). Anonymous enumeration of `GET /customers/{id}` (41 IDs/minute) is flagged as API1/API3 and scores HIGH; a rate-limit rule was approved, applied, reloaded by the gateway (213 of 300 burst requests got 429), verified from traffic and rolled back, all audited. Rate-limit baselines now exclude enumerating/flooding clients.
- Tests: `python -m pytest -q` (44 passing)

## Frontend (stage 12)
React 19 + TypeScript + Vite, no UI or chart libraries (inline SVG). Pages: sign-in, overview (inventory-by-lifecycle strip, needs-attention list, risk and remediation status, per-service mix), API inventory with filters, endpoint detail (classification evidence, risk breakdown, security controls + OWASP, evidence timeline, vulnerabilities, gateway rules, ownership edits), pipeline (start runs, live stage progress, history), remediation approval workflow with nginx rule previews and the live gateway config, vulnerabilities and dependencies, traffic (time series, anomalies, live request tail), sources (add/read/disable, one-off OpenAPI or log upload), models & validation (model cards, ground-truth comparison with confusion matrix), users & audit log. Actions follow the backend roles (viewer / analyst / admin). Checked against a seeded backend at desktop and phone widths, including approve → apply through the UI.
Static files and web pages are no longer recorded as APIs (they are still logged for payload and anomaly analysis).

## Still to do
- Sock Shop's load generator image (`weaveworksdemos/load-test:0.1.1`) exits with code 139 on Docker Desktop, so there is no authenticated shopper traffic; without it `REQUIRE_AUTH` cannot be inferred for `/customers/{id}` (by design, credentials must be seen as normal first).
- The traffic anomaly model (IsolationForest, contamination "auto") flags every client in the Sock Shop fixture as UNUSUAL_BEHAVIOUR at least once; stages 6-9 therefore only treat named attack patterns as suspicious. Tuning the anomaly baseline/contamination would make `anomalous_client_count` meaningful again.
- Write `sockshop/ground_truth.json` by hand and run the validation
- Run the Docker setup on your machine (not tested here: no Docker in my workspace)
- Apply the paper revisions
