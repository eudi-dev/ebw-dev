# Scenarios

The demo server has 4 kinds of scenarios with the business wallet of Acme Logistics GmbH. The map on the start page shows them all.

| Scenario | Page | Protocol | Credentials |
| --- | --- | --- | --- |
| Business issuer | `/issuer` | OpenID4VCI 1.0 | Owner identification data, EU power of attorney, employee authorisation |
| Power of attorney at a notary | `/scenarios/poa` | OpenID4VP 1.0 | EU power of attorney |
| Know your business at a bank | `/scenarios/kyb` | OpenID4VP 1.0 | Owner identification data and EU power of attorney |
| AI agent with a delegation | `/cases/supplier`, `/cases/internal` | OpenID4VP 1.0 with Delegate SD-JWT | See [AI agent demo](agent-demo.md) |

Everything is test data. Delta Notaries B.V., Example Bank AB and all people are made up.

## Business issuer

The page asks the issuer of the wallet for a pre-authorized credential offer by reference (OpenID4VCI 1.0 §4.1). It offers 3 credential configurations.

| Configuration | Credential | Type | Rulebook |
| --- | --- | --- | --- |
| `ebwoid` | Business wallet owner identification data | `uri:eu.ebw.oid.1` | WE BUILD EBWOID rulebook |
| `eu-poa` | EU power of attorney | `uri:eu.eudi.eu-poa.1` | WE BUILD EU PoA rulebook |
| `employee-authorisation` | Employee authorisation | `urn:eudi-test:business:employee-authorisation:1` | Test type of ebw-dev |

The server returns each offer in 3 forms:

- **Wallet URL.** `/credential-offer?credential_offer_uri=...` on the wallet starts the issuance with consent.
- **Offer URI.** The offer in the `openid-credential-offer` scheme works with any wallet.
- **Decoder URL.** The decoder of the wallet shows the offer by value.

Each issued credential gets an entry in the status list.

## Power of attorney at a notary

Alice registers a Rotterdam branch of Acme Logistics GmbH. The notary office Delta Notaries asks the wallet for the EU power of attorney. The notary checks the credential and then its policy.

| Variant | Task | Expected result | Failed check |
| --- | --- | --- | --- |
| `ok` | Registration of a branch | Accepted | None |
| `wrong_scope` | Cross border merger | Refused | `policy_poa_scope` |
| `expired` | Registration of a branch on the day after the end date | Refused | `policy_poa_validity` |
| `revoked` | Registration of a branch | Refused | `status` |

The policy has 2 checks:

- **Scope.** Each task needs a power from the list of the EU PoA rulebook. `scope_of_representation_powers` must contain this power word for word.
- **Validity.** The task date must lie between `validity_period_valid_from` and `validity_period_valid_until`. Without `validity_period_valid_until` the power of attorney has no end (EU PoA rulebook v0.2, IR-02).

## Know your business at a bank

Acme Logistics GmbH opens a business account at Example Bank. The bank asks for the owner identification data and the EU power of attorney in one DCQL query with 2 credential queries. The bank checks both credentials and then its policy.

- **Identifier.** The `id` of the owner identification data must equal the `euid_reference` of the power of attorney.
- **Name.** The `name` of the owner identification data must equal the `company_statutory_full_name` of the power of attorney.

After an accepted answer the server returns the data sent to the bank: company, identifier, register, country, representative, powers and validity.

## Request and answer

Both presentation scenarios work the same way.

1. The page asks the demo server for a request. The server makes sure the wallet holds a valid credential for each query. It issues a fresh one from the wallet template when none is valid.
2. The verifier signs the request object with its access certificate. The client identifier uses the prefix `x509_hash` (OpenID4VP 1.0 §5.9.3). The request object carries `verifier_info` with the registration certificate for the intended use.
3. The wallet receives the request by value and asks the person to approve the presentation.
4. The wallet posts the answer with `direct_post` to the verifier. The verifier checks each presentation and answers with a `redirect_uri` back to the scenario page.
5. The status of the request holds the request, the answer, every check and the verdict. Each token comes with a link to the decoder of the wallet.

A request is valid for one answer. The server keeps it for one hour and holds up to 200 requests. When it is full, it drops the oldest.

## JSON API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/wallet/credentials` | The credentials in the wallet for each configuration of the issuer. Each credential has `valid`, `issued_at` and `expires_at` |
| `POST` | `/api/offers` | Creates an offer. Body: `{"configuration": "eu-poa"}` |
| `POST` | `/api/scenarios/{scenario}/requests` | Creates a request. Body: `{"variant": "expired"}`. Without a variant the server uses `ok` |
| `GET` | `/api/scenarios/{scenario}/requests/{id}` | Status, presentations, checks and reasons of a request |
| `POST` | `/scenarios/{scenario}/response` | Response endpoint for the wallet (`direct_post`) |

## Differences from real verifiers

[Differences from a real business wallet](differences.md#scenarios) lists where the scenarios are laxer than a real notary, bank or issuer.
