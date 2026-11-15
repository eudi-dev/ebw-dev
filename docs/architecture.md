# Architecture

## Parts

| Part | Location | Role |
| --- | --- | --- |
| Business wallet | eudi-dev binary with `wallet-config/` and `brand/theme/` | Holder. It stores the authority credentials, asks for consent and signs the mandate with the holder key. It also acts as the issuer of the credentials and publishes the trusted lists |
| Agent service | `internal/demo/agent.go`, `internal/demo/registration.go` | Relying party in the registrar of the wallet. Creates a P-256 agent key for each mandate, signs the mandate request, verifies the answer and keeps up to 200 mandates in memory until they expire |
| Agent | `internal/demo/agent.go` | Delegate Holder. A fixed script that sends a business request to a verifier and answers the proof request with a dSD-JWT+KB |
| Verifiers | `internal/demo/verifier.go` | Bolt Supplies supplier portal, Acme internal procurement API and Crate Trading portal (the verifier of the wrong verifier run) |
| Chain library | `internal/dsdjwt` | Own implementation of [chain-format.md](chain-format.md): agent side, verifier side and the chain report |
| Trust store | `internal/trust` | Loads the wallet CA, the trusted lists and the status list over HTTP |
| Pages | `internal/demo/web` | Map of the demo, one page for each case, the scenario pages and the issuer page. They use the JSON API |

The agent service, the agent and the verifiers share one process. They talk over HTTP paths of the public URL. Each party sees only the wire messages of the other.

## Credentials

The wallet issues 3 SD-JWT VC credentials at start. All 3 carry a Token Status List entry.

| Credential | Type (`vct`) | Trusted list | Source |
| --- | --- | --- | --- |
| EBWOID of Acme Logistics GmbH | `uri:eu.ebw.oid.1` | `pub-eaa` | WE BUILD EBWOID rulebook 1.1.0 |
| EU power of attorney for Alice | `uri:eu.eudi.eu-poa.1` | `pub-eaa` | WE BUILD EU power of attorney rulebook 0.2 |
| Employee authorisation for Bob | `urn:eudi-test:business:employee-authorisation:1` | `eaa` | WE BUILD Power of X rulebook 1.2 with `authority_source` `proxy_employee_authorisation` |

Deviations from the JSON schemas of the rulebooks:

- The schemas of the EBWOID and the EU power of attorney describe `status` with the members `type`, `status_list_credential`, `status_list_index` and `status_purpose`. The wallet writes a Token Status List reference (`status.status_list` with `idx` and `uri`).
- The 6 powers of the EU power of attorney rulebook do not cover procurement. The credential uses the substitution value `limited` and adds a power in free text.
- The Power of X rulebook fixes no `vct` and leaves the content of a `proxy_employee_authorisation` open. The type name and the members `employee_role`, `authorisation_scope`, `constraints.limit` and `service_access` are choices of this project.
- `credential_metadata` of the employee authorisation holds the issuer and the schema only.

## Trust

A verifier holds no pinned certificate. At start and on demand it loads from the wallet:

1. The wallet CA from `/api/certificates/ca`.
2. The index of trusted lists from `/api/trustlists` and each list. Every list is a JWT in the JSON binding of ETSI TS 119 602. Its signature must chain to the wallet CA.
3. The issuance certificates and the revocation certificates of each list.

A credential counts as trusted when its `x5c` chain ends at an issuance certificate of an accepted list. The supplier portal accepts `pub-eaa` and `qeaa`. The procurement API accepts `eaa`.

The status check loads the Status List Token of the credential. The token must be signed under a revocation certificate of an accepted list. A verifier fetches status lists only from the origin of the wallet and does not follow redirects.

The demo fetches the wallet CA over plain HTTP on the local machine. A production verifier gets its trust anchors over an authenticated channel.

## Registration

The registrar of the wallet lists Acme Logistics (`DETEST.00000471`) with the service `agent-service` and the intended uses `supplier-mandate` and `internal-mandate`. `wallet-config/relying-parties.yaml` holds the registration.

The agent service gets its certificates from the registrar over HTTP:

1. Before its first request it creates a P-256 key and sends a certificate signing request to `/api/registrar/access-certificates`. The registrar answers with an access certificate under the relying party access CA.
2. For each intended use it asks `/api/registrar/registration-certificates` for a registration certificate. The answer holds the `verifier_info` of the request.

The client identifier is `x509_hash:` with the SHA-256 hash of the access certificate. The agent service keeps the key and the certificates in memory. `POST api/trust/reload` drops them, and the next request asks the registrar again.

The wallet shows the service name Acme agent service and the purpose of the intended use in the consent.

The 2 verifiers send unsigned requests with the client identifier prefix `redirect_uri`. Their requests go to the agent and never reach the wallet.

## Delegation flow

Both cases follow the same steps. They differ in the credential, the verifier, the action and the limit.

### Step 1: mandate

1. The agent service creates an agent key, a nonce and a state.
2. It builds the delegate payload: agent key in `cnf`, agent name, purpose, the action of the case, the limit, an end time and 2 audiences. Each audience is its own disclosure.
3. It sends an OpenID4VP 1.0 authorization request to the wallet. The request is a signed request object passed by value. Its `x5c` header holds the access certificate. It has the client identifier `x509_hash:<hash>`, `response_mode=direct_post`, the `verifier_info` of the intended use, a DCQL query for the authority credential and one `transaction_data` entry of type `delegate`.
4. The wallet shows the request and asks for consent.
5. The wallet signs the KB-SD-JWT with the holder key and posts the dSD-JWT to the agent service.
6. The agent service runs checks 1 to 4 of chain-format.md. It also checks that the wallet signed the requested delegate payload.

A refusal of the wallet arrives as an OpenID4VP error response. The mandate then has the status `refused` with the `error` and the `error_description` of the wallet.

A wallet without the transaction data type `delegate` answers with an SD-JWT and a Key Binding JWT. The agent service refuses this answer with the error `wallet_without_delegation`.

### Step 2: agent run

1. The agent sends the business request (action, amount, currency, reference) to the verifier.
2. The verifier answers with an OpenID4VP 1.0 authorization request. Its DCQL query lists the accepted credential type.
3. The agent drops the audience disclosures of other verifiers.
4. The agent signs a Key Binding JWT with the agent key over the audience and the nonce of the verifier.
5. The agent posts the dSD-JWT+KB to the `response_uri`.

### Step 3: chain check

The verifier runs checks 1 to 5 of chain-format.md and then its policy:

| Policy check | Supplier portal | Procurement API |
| --- | --- | --- |
| Credential type | `uri:eu.eudi.eu-poa.1` | `urn:eudi-test:business:employee-authorisation:1` |
| Issuer | On `pub-eaa` or `qeaa` | On `eaa` |
| Action in `mandate.actions` | `order.create` | `invoice.approve` |
| Amount | At most `mandate.limit` in the same currency | At most `mandate.limit` in the same currency |
| Audience | A disclosed audience equals the client identifier of the verifier | The same |

The policy reads the limit and the actions from the mandate. It does not compare the claims of the authority credential with the mandate. A production verifier also checks that the powers of the credential cover the mandate.

The procurement API accepts every issuer on the `eaa` list as the issuer of the company.

The verifier answers with a report of 3 links: authority credential, mandate and presentation. Each link shows its signer, the thumbprint of its key and the result of every check.

### Refusal runs

| Run | Change | Failed check |
| --- | --- | --- |
| Amount above the limit | The agent asks for 7500.00 EUR | `policy_limit` |
| Expired mandate | The demo sets the clock of the agent and the verifier past the end of the mandate. The member `simulate_clock_shift_seconds` of the business request carries the shift | `mandate_validity` |
| Wrong verifier | The agent presents the mandate to Crate Trading. The mandate has no audience for this verifier | `policy_audience` |
| Tampered chain | The agent raises the limit inside the delegate payload disclosure | `one_delegate_payload` |
| Revoked credential | The demo revokes the credential under the mandate in the wallet before the run | `status` |

The clock shift is a control of the demo. A real verifier has no such parameter.

After the revoked run the demo has the wallet issue a fresh credential of the same type. The mandate on the revoked credential stays refused.

## Specifications

[Specifications](specifications.md) lists the pinned version of every specification of this flow.
