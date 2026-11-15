# JSON API

The demo server serves this API. All paths are relative to the public URL. The API of the issuer page and the scenarios is in [Scenarios](scenarios.md#json-api).

| Request | Result |
| --- | --- |
| `GET /api/config` | Cases, verifiers and client identifiers |
| `GET /api/trust` | Loaded trusted lists and their issuers |
| `POST /api/trust/reload` | Loads the trust anchors again |
| `POST /api/mandates` with `{"case": "supplier"}` | New mandate request with `request.wallet_url` for a browser, `request.openid4vp_uri` for the wallet API and the signed `request.request_object` |
| `GET /api/mandates/{id}` | Status `pending`, `granted` or `refused`, the dSD-JWT and the chain report. A refused mandate carries `error` and `error_description` |
| `POST /api/mandates/{id}/runs` with `{"variant": "ok"}` | Runs the agent. Variants: `ok`, `over_limit`, `expired`, `wrong_verifier`, `tampered`, `revoked` |
| `GET /api/runs/{id}` | Steps, outcome, dSD-JWT+KB and the chain report of the verifier |
| `POST /agent/response` | Response endpoint for the wallet's answer to a mandate request (`direct_post`) |
| `POST /verifier/{verifier}/requests` with `{"action": "order.create", "amount": "1200.00", "currency": "EUR"}` | Business request of the agent. The answer carries an OpenID4VP 1.0 authorization request in `authorization_request` |
| `POST /verifier/{verifier}/response` | Response endpoint for the dSD-JWT+KB of the agent (`direct_post`). The verifier takes one response for each request |
| `GET /verifier/{verifier}/requests/{id}` | Status `presentation_required`, `accepted` or `refused`, the reasons and the chain report |
| `GET /api/wallet/credentials` | The credentials in the wallet. See [Scenarios](scenarios.md#json-api) |
| `GET /healthz` | Health check of the demo server |

[Architecture](architecture.md) describes the flow behind these requests.
