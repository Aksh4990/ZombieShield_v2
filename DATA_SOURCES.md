# Third-party data used by ZombieShield

| Data | Used for | Where | Licence / terms |
|---|---|---|---|
| CISA Known Exploited Vulnerabilities catalogue | KEV enrichment (bundled offline copy) | `backend/data/threat_cache/kev.json` | Public domain (U.S. Government work), https://github.com/cisagov/kev-data |
| GitHub Advisory Database (OSV format) | Offline vulnerability cache for the Sock Shop dependencies | `backend/data/threat_cache/osv_index.json` | CC-BY 4.0, © GitHub, https://github.com/github/advisory-database |
| APIs.guru openapi-directory | Training data for the endpoint models (derived table of methods, paths and labels) | `backend/data/endpoint_dataset.csv.gz`, `backend/ml_artifacts/endpoint_model.joblib` | Directory CC0 1.0, https://github.com/APIs-guru/openapi-directory |
| HTTP CSIC 2010 dataset | Training/evaluation of the payload classifier (not redistributed) | `backend/ml_artifacts/payload_model.joblib` | Spanish National Research Council (CSIC); obtain from the original source |
| HttpParamsDataset | Training/evaluation of the payload classifier (not redistributed) | `backend/ml_artifacts/payload_model.joblib` | MIT, https://github.com/Morzeux/HttpParamsDataset |
| Sock Shop | Reference target application (cloned by `scripts/setup_sockshop.*`, not redistributed) | `discovery-repositories/` | Apache 2.0, https://github.com/microservices-demo |
