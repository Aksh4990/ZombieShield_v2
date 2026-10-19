# Team-implemented pipeline stages (6, 7, 9)

The pipeline (`backend/app/services/pipeline.py`) runs these stages in order:

```
discovery → endpoint ML → lifecycle → threat intel → anomaly ML → [controls] → [risk] → decisions → [remediation]
```

The three bracketed stages are **slots**. A slot is filled by creating a module that exposes one function:

```python
from sqlalchemy.orm import Session

def run(db: Session) -> dict:
    ...                      # read and update rows through the session
    return {"updated": 42}   # any JSON-serialisable summary; shown in the pipeline view
```

| Slot | Module to create | Runs after | Typical outputs (columns already on `API`) |
|---|---|---|---|
| Stage 6, security-control evidence | `backend/app/services/controls.py` | anomaly detection | `security_controls` (dict), `owasp_categories` (list) |
| Stage 7, risk assessment | `backend/app/services/risk.py` | controls | `risk_score` (0-100), `risk_level`, `risk_breakdown` (list of `{factor, points, evidence}`), `risk_explanation`, `risk_assessed_at` |
| Stage 9, remediation | `backend/app/services/remediation.py` | decisions | rows in `RemediationAction` (`backend/app/models/security.py`) |

Rules the pipeline enforces:
* If the module is missing, the stage is reported as `SKIPPED`. Nothing else changes.
* The pipeline commits after each stage. If `run` raises, the run stops and is marked `FAILED`, with the error shown in the UI.
* `GET /pipeline/extensions` reports which slots are implemented.
* The decision engine (stage 8) already uses `risk_score` when it is present (≥75 ESCALATE, ≥50 REMEDIATE). Without it, the engine decides from lifecycle and vulnerability evidence alone.

## Data available to your stages
Per API (`app.models.API`): lifecycle state and reason; evidence flags (`in_current_spec`, `in_current_code`, `in_runtime`, `previously_in_spec`, `previously_in_code`, `spec_deprecated`, `superseded_by`, `spec_security`); traffic aggregates (`request_count`, `error_count`, `unauth_success_count`, `unique_clients`, `attack_request_count`, `anomalous_client_count`); ML scores (`ml_legacy_score`, `ml_sensitivity_score`, `ml_explanation`); threat-intel counts (`vulnerability_count`, `kev_count`); and the evidence timeline (`api.evidence`).

Related tables: `RequestLog` (data-minimised requests), `AnomalyEvent`, `Component`, `Vulnerability` (CVSS, KEV, EPSS), `ThreatFinding`.

Settings that may help: `gateway_rules_dir` (mounted at `/workspace/gateway/rules` in the backend and `/etc/nginx/zombieshield/` in the Sock Shop gateway, which includes `*.conf` from it).

## Testing a slot
Add a test under `tests/` that creates an `API` row, calls your `run(db)` and checks the columns. `tests/test_api.py::test_full_pipeline_finds_zombie_shadow_and_deprecated` shows a complete pipeline run you can extend.
