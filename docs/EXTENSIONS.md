# Pipeline stages 6, 7 and 9 (security controls, risk, remediation)

The pipeline (`backend/app/services/pipeline.py`) runs these stages in order:

```
discovery → endpoint ML → lifecycle → threat intel → anomaly ML → [controls] → [risk] → decisions → [remediation]
```

The three bracketed stages are **slots**, now implemented (see "Implemented behaviour" below). A slot is a module that exposes one function:

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

## Implemented behaviour

### Stage 6: `controls.py`
Writes `API.security_controls` and `API.owasp_categories`. Each control has a `status`, a one-line `summary` and the raw `evidence`:

| Control | Evidence used | Statuses |
|---|---|---|
| `authentication` | `spec_security`; unauthenticated requests in `RequestLog` and how they were answered; share of calls that normally carry credentials | ENFORCED (401/403 to anonymous calls), NOT_ENFORCED (anonymous 2xx where credentials are expected), NOT_REQUIRED (public by design), DECLARED, UNKNOWN |
| `authorization` (BOLA) | distinct object IDs one client read with 2xx **within one minute** on a `{id}` endpoint (threshold 8, same as the anomaly model) | NOT_ENFORCED, UNKNOWN |
| `input_validation` | answers to requests the payload classifier flagged | ENFORCED (4xx), NOT_ENFORCED (2xx), UNKNOWN |
| `rate_limiting` | 429s; peak requests per client minute (>= 60 unthrottled); clients with a *named* anomaly pattern | ENFORCED, NOT_ENFORCED, NOT_OBSERVED, UNKNOWN |
| `inventory` | lifecycle state, documented / in code, owner | ENFORCED, DECLARED, NOT_ENFORCED, UNKNOWN |
| `gateway` | ZombieShield remediation actions for the API | ENFORCED (verified), DECLARED (approved/applied), UNKNOWN |

Credentials count as *expected* when the specification declares security, at least 50% of calls carry credentials, or the path names a privileged function (admin, internal, export, ...). This keeps public endpoints such as a product catalogue from being reported as broken authentication.
OWASP API Top 10 (2023) mapping: API1 BOLA, API2 authentication, API3 sensitive fields (endpoint ML) without access control, API4 no throttling, API5 anonymous privileged/write calls, API8 accepted attack payloads / vulnerable components / declared-but-unenforced auth, API9 zombie, shadow, undocumented or deprecated-in-use endpoints.

### Stage 7: `risk.py`
A capped sum of points; `risk_breakdown` lists every factor with its evidence and `risk_explanation` names the top three. The full policy is the `POINTS` table at the top of the module:
lifecycle (zombie 30, shadow 25, deprecated in use 12, undocumented 8); authentication not enforced 20 (+5 privileged/write); BOLA 15; ML-sensitive 10 (x1.5 without access control); KEV 25 or worst CVSS 15/10/5, +5 for EPSS >= 0.1; accepted attack payloads 15 (5 if only targeted); suspicious clients 5 + 2 each (max 12); unthrottled heavy use 5; reach up to 5 (log of distinct clients).
Discounts: decommissioned -80%, verified gateway block -60%, applied block -40%, other verified gateway rule -20%.
Levels: >= 75 CRITICAL, >= 50 HIGH, >= 25 MEDIUM, else LOW; the decision engine's ESCALATE/REMEDIATE thresholds use the same cut-offs.

### Stage 9: `remediation.py` and `gateway.py`
For APIs whose decision is REMEDIATE or ESCALATE the stage proposes (one row per API and kind):

| Kind | When | Gateway behaviour |
|---|---|---|
| `BLOCK_ROUTE` | ZOMBIE | `return 410` for that method and path |
| `REQUIRE_AUTH` | authentication NOT_ENFORCED (not for blocked routes) | `return 401` when `$zs_has_auth` is "0" |
| `RATE_LIMIT` | throttling NOT_ENFORCED/NOT_OBSERVED, or BOLA | per-client `limit_req`, 429; rate = 2 x the 95th percentile of normal clients' requests per minute (min 30) |
| `DEPRECATION_HEADERS` | DEPRECATED and still called | `Deprecation`, `Sunset` (now + `DEPRECATION_SUNSET_DAYS`) and successor `Link` headers |

Nothing reaches the gateway automatically. Workflow: `PROPOSED -> approve (admin) -> APPROVED -> apply (admin) -> APPLIED -> verify (analyst) -> VERIFIED`, plus `reject`, `rollback` (admin) and `reopen`. Every step is written to the audit log. Re-running the pipeline refreshes untouched proposals, withdraws proposals whose evidence has gone, and never changes an action a person has acted on.
`apply` and `rollback` regenerate two files from all APPLIED/VERIFIED actions: `zombieshield.conf` (`location` blocks, included in `server {}`) and `http/zombieshield-maps.conf` (`map` / `limit_req_zone`, included in `http {}`). Paths are converted to anchored regexes (`{id}` -> `[^/]+`, trailing `*` -> prefix) and anything that cannot be expressed safely is refused. `verify` checks traffic logged after `applied_at` (no 2xx on a blocked route, every anonymous call refused, no client above rate + burst). Response headers are not in access logs, so deprecation headers are confirmed by the approver.
The Sock Shop gateway runs `sockshop/gateway/reload-on-change.sh`, which reloads nginx within ~5 s of a rule change and refuses rule sets that fail `nginx -t`.

Settings: `GATEWAY_RULES_DIR`, `GATEWAY_UPSTREAM` (where rule locations proxy allowed requests), `GATEWAY_HOSTS` (render only these API hosts), `GATEWAY_AUTH_VARIABLE`, `DEPRECATION_SUNSET_DAYS`.

Endpoints: `GET /remediation` (filters `status`, `kind`, `api_id`), `GET /remediation/{id}`, `GET /remediation/gateway-config`, `POST /remediation/{id}/{approve|reject|apply|verify|rollback|reopen}` with optional `{"note": "..."}`.

Tests: `tests/test_controls_risk_remediation.py` (includes an `nginx -t` check of the rendered rules when nginx is installed).
