# Chain format

This page defines the wire format of a delegation. The wallet, the agent and the verifiers all follow it.

## Specifications

| Specification | Version | Use |
| --- | --- | --- |
| [Delegate SD-JWT](https://datatracker.ietf.org/doc/draft-ietf-oauth-delegate-sd-jwt/00/) | draft-ietf-oauth-delegate-sd-jwt-00 (26 October 2026) | The delegation chain and the `delegate` transaction data type |
| [SD-JWT](https://www.rfc-editor.org/rfc/rfc9901) | RFC 9901 (November 2025) | Disclosures, `sd_hash`, Key Binding JWT |
| [SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/19/) | draft-ietf-oauth-sd-jwt-vc-19 | Credential format `dc+sd-jwt` |
| [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) | 1.0 (9 July 2025) | Both presentation steps, `transaction_data` (§5.1, Appendix B.3.3) |

Section numbers below refer to the Delegate SD-JWT draft unless another specification is named.

## Roles

| Role | Party | Key |
| --- | --- | --- |
| Issuer | Demo issuer of the business wallet | Provider key under a trusted list |
| Holder | Business wallet | `cnf` key of the authority credential |
| Delegate Holder | Agent | Agent key (P-256), created by the agent service |
| Verifier | Supplier portal or internal API | None |

## Step 1: mandate

The agent service asks the business wallet for a mandate. It sends an OpenID4VP 1.0 authorization request. The request has one DCQL credential query for the authority credential and one `transaction_data` entry of type `delegate` (§7.1).

Decoded transaction data entry:

```json
{
  "type": "delegate",
  "credential_ids": ["authority"],
  "format": "dSD-JWT+KB",
  "delegate_payload_disclosure": "<base64url of [salt, delegate payload]>",
  "delegate_disclosures": ["<disclosure>", "<disclosure>"]
}
```

The delegate payload:

```json
{
  "vct": "urn:eudi-test:business:agent-mandate:1",
  "iat": 1794571200,
  "exp": 1794574800,
  "cnf": { "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." } },
  "agent": { "id": "urn:eudi-test:agent:procurement-1", "name": "Procurement agent", "operator": "Acme Logistics GmbH" },
  "mandate": {
    "purpose": "Order packaging material",
    "actions": ["order.create"],
    "limit": { "amount": "5000.00", "currency": "EUR" },
    "audiences": [ { "...": "<digest>" }, { "...": "<digest>" } ]
  }
}
```

Each element of `mandate.audiences` is an array element disclosure (RFC 9901 §4.2.2). Its value is the client identifier of one verifier. The agent shows a verifier only its own entry.

The wallet asks for consent. Then it answers with a dSD-JWT in `vp_token`:

```
<Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~~<KB-SD-JWT>~<delegate payload disclosure>~<delegate disclosure 1>~...~<delegate disclosure M>~
```

The KB-SD-JWT is signed with the `cnf` key of the authority credential.

Header:

```json
{ "typ": "kb-sd-jwt+kb", "alg": "ES256" }
```

Payload:

```json
{
  "iat": 1794571200,
  "aud": "<client_id of the agent service>",
  "nonce": "<nonce of the request>",
  "sd_hash": "<digest over the SD-JWT part, RFC 9901 §4.3.1>",
  "_sd_alg": "sha-256",
  "delegate_payload": [ { "...": "<digest of delegate_payload_disclosure>" } ],
  "transaction_data_hashes": ["<hash of the transaction data entry>"]
}
```

Rules:

- `sd_hash` covers `<Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~` (§5.1.4).
- The digest in `delegate_payload` is the base64url SHA-256 of the ASCII bytes of `delegate_payload_disclosure`, as for any disclosure (RFC 9901 §4.2.3).
- `_sd_alg` is `sha-256`.
- `transaction_data_hashes` follows OpenID4VP 1.0 Appendix B.3.3.1.
- The wallet copies `delegate_payload_disclosure` and `delegate_disclosures` unchanged into the answer.
- A `kb-sd-jwt+kb` delegation needs `cnf` in the delegate payload (§5.1.4). The wallet refuses a request without it in strict mode. In debug mode it reports a warning and signs.

## Step 2: presentation by the agent

A verifier sends the agent an OpenID4VP 1.0 authorization request with `response_mode=direct_post`. Its DCQL query asks for the authority credential type in the format `dc+sd-jwt`.

The agent drops the audience disclosures of other verifiers. It appends a Key Binding JWT signed with the agent key. The result is a dSD-JWT+KB (§5.1.1):

```
<Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~~<KB-SD-JWT>~<delegate payload disclosure>~<kept delegate disclosures>~<delegate KB-JWT>
```

Delegate KB-JWT header:

```json
{ "typ": "kb+jwt", "alg": "ES256" }
```

Payload:

```json
{
  "iat": 1794571300,
  "aud": "<client_id of the verifier>",
  "nonce": "<nonce of the verifier>",
  "sd_hash": "<digest over <KB-SD-JWT>~<delegate payload disclosure>~<kept delegate disclosures>~>"
}
```

The agent posts `vp_token={"<query id>": ["<dSD-JWT+KB>"]}` and `state` to the `response_uri`.

## Verifier checks

A verifier runs the steps of §6 and then its own policy.

1. Split the string on `~`. Exactly one empty component separates the SD-JWT from the KB-SD-JWT.
2. Verify the Issuer-signed JWT (RFC 9901 §7.1). The `x5c` chain must end at a certificate on a trusted list of the business wallet. No disclosure may carry `iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity`, `aka_vcts` or `status` (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3). Read `exp`, `cnf` and the status list entry from the signed payload. Check `exp`. When the credential has a status list entry, check it too.
3. Verify the KB-SD-JWT with the `cnf` key of the credential. Its `typ` is `kb-sd-jwt+kb`. Check its `iat`, and its `exp` and `nbf` when present. Its `sd_hash` matches the SD-JWT part. Exactly one element of `delegate_payload` is disclosed.
4. Read the delegate payload. Check `exp` and `cnf`.
5. Verify the delegate KB-JWT with the `cnf` key of the delegate payload. Check `aud`, `nonce`, `iat` and `sd_hash`.
6. Policy: the credential type is accepted, its issuer is trusted for this verifier, `mandate.actions` contains the requested action, the amount stays within `mandate.limit`, and a disclosed audience equals the verifier's client identifier.

The verifier reports each link of the chain with its signer, its key and the result of each check.

## Own choices

The specifications leave these points open. This project decides them as follows.

| Open point | Choice |
| --- | --- |
| Format identifier of a delegated presentation in DCQL | `dc+sd-jwt`. A verifier detects the chain by the empty component. |
| Content of the delegate payload | The claims above. `vct` is `urn:eudi-test:business:agent-mandate:1`. |
| Agent as proxy in a power of attorney | The rulebooks cover only natural and legal persons. The agent appears only in the delegate payload. |
| `exp` in the credential | Required in the Issuer-signed payload. A holder can withhold a disclosure, so a verifier cannot rely on a disclosed end time. |
| `exp` in the delegate payload | Required. A verifier refuses a delegate payload without `exp`. |
| Revocation of a mandate (§8.3) | Short `exp` (one hour). Revoking the authority credential ends every mandate under it when the credential has a status list entry. |
| `transaction_data_hashes` next to `delegate_payload` | Both are present. OpenID4VP requires the first and the draft requires the second. |
| Identification of the agent itself | Agent key in `cnf` and descriptive `agent` claims. No attestation of the agent software. |

## Golden test vector

[testdata/golden-chain.json](../testdata/golden-chain.json) holds a complete dSD-JWT+KB in this format. Another implementation can verify it and compare its result.

| Member | Content |
| --- | --- |
| `token` | The dSD-JWT+KB of step 2 |
| `keys.issuer` | Public JWK of the credential issuer. The vector has no `x5c` chain, so a verifier takes this key as trusted |
| `keys.holder` | Public JWK of the wallet. It equals `cnf.jwk` of the credential |
| `keys.agent` | Public JWK of the agent. It equals `cnf.jwk` of the delegate payload |
| `verifier.audience` | Client identifier of the verifier |
| `verifier.nonce` | Nonce of the verifier |
| `verifier.time` | Verification time in seconds since the epoch. The token is valid at this time |
| `expected.valid` | Result of checks 1 to 5 |
| `expected.links` | The 3 links with the RFC 7638 thumbprint of the signing key and the result of each check |
| `expected.credential` | Disclosed claims of the authority credential |
| `expected.mandate` | Content of the delegate payload with the disclosed audiences |

The mandate of the vector has 2 audiences. The token discloses the audience of the supplier portal only. The credential has no status list entry, so the status check is `skipped`.

`go test ./internal/dsdjwt -run TestGoldenVector` verifies the vector. `UPDATE_GOLDEN=1 go test ./internal/dsdjwt -run TestGoldenVector` writes a new vector with new keys.
