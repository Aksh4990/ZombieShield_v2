# ZombieShield demo guide

A 12–15 minute walkthrough on the Sock Shop lab. It tells one story: *find the APIs nobody is
managing, show why they are dangerous with evidence, and fix them safely at the gateway.*

## Before the demo (10–20 minutes ahead)

1. Start **Docker Desktop**.
2. Double-click **`demo.cmd`** in the repository root and answer **Y** (clean slate).
   It creates `.env` if needed, downloads the Sock Shop repositories, builds and starts every
   container, generates demo traffic, runs the pipeline and opens the dashboard. The first run
   downloads several GB; later runs take about 5 minutes.
3. Note the admin password the script prints (it is also in `.env`).
4. Open these tabs:
   - ZombieShield: <http://localhost:5173> (sign in as admin)
   - Sock Shop through the gateway: <http://localhost:8079>
   - A **private/incognito window** for the anonymous-attacker demo
5. Optional backup: take screenshots of each step below in case the network or laptop misbehaves.

**What is real and what is synthetic.** The 7 Sock Shop services, their source code and full git
history, the gateway, the live requests, the vulnerability feeds and the ML models are real. The
45-minute *shopper history* is synthetic (its source is labelled so on the Sources page) because
Sock Shop's own load generator no longer runs on current Docker. Say this if asked; it is a fair
lab setup.

## The walkthrough

### 1. The problem (30 s, no clicks)
"Teams ship APIs faster than they document or retire them. Old routes keep answering
(**zombie** APIs), and services expose routes nobody declared (**shadow** APIs). Attackers find
them before the inventory does. ZombieShield builds that inventory from evidence."

### 2. Overview: the whole API surface (1.5 min)
- The coloured strip: **86 endpoints** merged from **specs, source code, git history and live
  traffic**, one record each, coloured by lifecycle.
- Point at the **zombie** and **shadow** counts, then the **Needs attention** list.
- "Nothing here is configured by hand; every label comes from evidence we can show."

### 3. A zombie API, with proof (2 min)
Click **PUT /cart/{id}** (Zombie).
- **Summary:** removed from the front-end in **2017, commit and author named**, commit message
  quoted, yet still receiving traffic from a legacy client.
- **Evidence** tab: the timeline from *added*, to *removed in git*, to *still seen in traffic*.
- **Risk** tab: every point of the score with the evidence behind it (zombie +30, vulnerable
  dependencies, sensitive-data model). "No black box."

### 4. A shadow API (1 min)
Back to Overview, click **GET /orders/search/customerId** (Shadow).
- Spring Data REST exposes it automatically; it is in **no source file and no spec**, but it is
  called hundreds of times. Nobody owns it, so nobody secures it.

### 5. A live attack (2 min)
- In the **private window**, open
  <http://localhost:8079/customers/57a98d98e4b00679b4a830af>: Sock Shop returns a customer record
  **without any login**. (The demo script already enumerated 45 of these as an "attacker".)
- In ZombieShield, open **GET /customers/{id}**:
  - **Controls** tab: authentication *not enforced* (although most callers send credentials),
    object-level authorization *not enforced* (one client read 45 records in a minute), mapped to
    **OWASP API1, API2, API3**.
  - **Risk**: high/critical, with the reasons.
- **Traffic** page: the request chart and the attacker in the recent requests.

### 6. Known vulnerabilities (1 min)
**Vulnerabilities** page: dependencies read from the services' manifests, matched against OSV;
e.g. **morgan 1.7.0, CVSS 9.8** in the front-end. EPSS and CISA KEV are checked too; KEV hits
escalate automatically.

### 7. Fix it safely at the gateway (3 min, the highlight)
**Remediation** page, *To review*:
1. **Require credentials for GET /customers/{id}** → **Approve** (add a note) → **Apply to gateway**.
2. **Retire PUT /cart/{id} (410 Gone)** → Approve → Apply.
3. Click **Show gateway config**: the exact nginx rules ZombieShield wrote. The gateway reloads in
   about 5 seconds, after `nginx -t` checks them.
4. Prove it: reload the customer URL in the **private window**: now **401**. In the normal tab,
   log in to Sock Shop (user `user`, password `password`) and browse: shoppers are unaffected.
5. Back in ZombieShield: **Verify** on the require-credentials rule → *Verified* (checked against
   the requests logged after applying).
6. **Roll back** one rule to show it is reversible.

"Nothing is changed automatically. A person approves, applies and verifies, and every step is
audited."

### 8. How it works (1 min)
**Pipeline** page: the nine stages, from discovery to remediation, with each stage's result. Mention
it reruns on demand and the gateway log is followed live between runs.

### 9. Honest evaluation (1.5 min)
**Models & validation** page:
- Model cards with **held-out** results and stated limitations (e.g. payload classifier precision
  100% / recall 44% on CSIC 2010; endpoint model ROC-AUC 0.72 on providers never seen in training).
- **Lifecycle validation** against a hand-labelled ground truth: accuracy, F1, confusion matrix.
  *(Paste the team's `sockshop/ground_truth.json` here before the demo.)*

### 10. Accountability (30 s)
**Users & audit**: every sign-in, pipeline run, approval, apply, verify and rollback, with who and
when. Roles: viewer, analyst (runs pipeline, verifies), admin (approves and applies).

## Likely questions

| Question | Short answer |
|---|---|
| Does it block things on its own? | No. It recommends and proposes; an admin approves and applies, an analyst verifies. |
| Where does the data come from? | OpenAPI/Swagger files, route definitions in code (Express, Spring, Go, Flask, FastAPI), git history, gateway logs, dependency manifests. |
| What about privacy? | Client addresses are pseudonymised, query strings and headers are not stored. |
| Why is the ML recall low / ROC-AUC 0.72? | Evaluated on unseen providers and datasets, not the training data; the cards state the limitations. The risk score does not depend on ML alone. |
| What is synthetic? | Only the 45-minute shopper history. Code, git history, live requests, vulnerabilities and models are real. |
| Could this run on a real company? | Point it at their repos and gateway logs; the gateway rules are plain nginx. |

## If something goes wrong

- **A page shows "Can't reach the backend"**: Docker Desktop stopped or the backend is restarting.
  Wait 30 s; otherwise run `demo.cmd` again and answer **N** (keeps the data).
- **The gateway still answers after Apply**: wait 5–10 s for the reload, then retry.
- **No internet**: set `THREAT_INTEL_MODE=offline` in `.env`; the bundled vulnerability cache is used.
- **Stop everything** after the demo: `demo-stop.cmd` (data is kept).
