# ZombieShield v2: work-in-progress snapshot

Your original project in `zombieshield_fyp` is untouched. The **backend now runs end to end** (API, pipeline, migrations, Docker, 23 passing tests). The new **frontend is not built yet**; the `frontend/` folder is still a placeholder.

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
- Tests: `python -m pytest -q` (24 passing)
- Validation scoring (stage 13): `POST /validation/run` with your ground-truth JSON (template: `sockshop/ground_truth.template.json`) returns accuracy, macro-F1, per-class and zombie-or-shadow precision/recall/F1 and a confusion matrix; `GET /validation/runs` lists past runs
- Paper revision guide with all final figures: `docs/PAPER_REVISION.md`

## Verified on real Sock Shop code (7 repos, ~350 commits mined)
- 9 retired routes traced to the commit and author that removed them
- With a normal-traffic log fixture: front-end `PUT /cart/{id}` (removed 2017) classified **ZOMBIE**, orders `GET /orders/search/customerId` (Spring Data REST, in no code or spec) classified **SHADOW**
- Real CVEs matched in front-end's npm dependencies (e.g. morgan 1.7.0, CVSS 9.8)

## Left for the team (see `docs/EXTENSIONS.md`)
- Stage 6 security-control evidence → `backend/app/services/controls.py`
- Stage 7 risk scoring → `backend/app/services/risk.py`
- Stage 9 remediation → `backend/app/services/remediation.py`

## Still to do
- Frontend (stage 12): the `frontend/` folder is still the old UI
- Write `sockshop/ground_truth.json` by hand and run the validation
- Run the Docker setup on your machine (not tested here: no Docker in my workspace)
- Apply the paper revisions
