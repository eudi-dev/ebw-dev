# Specifications

The specifications behind a business wallet are not final. This page lists the version ebw-dev implements for each one.

## Status

- The European Business Wallet regulation is a proposal (COM(2025) 838).
- There is no Architecture and Reference Framework for business wallets.
- The credential formats come from the WE BUILD pilot.
- Delegate SD-JWT is at draft-ietf-oauth-delegate-sd-jwt-00.

## Pinned versions

| Standard | Version | Purpose here | Link |
| --- | --- | --- | --- |
| Delegate SD-JWT | draft-ietf-oauth-delegate-sd-jwt-00 (26 October 2026) | Delegation chain, KB-SD-JWT, `delegate` transaction data type | https://datatracker.ietf.org/doc/draft-ietf-oauth-delegate-sd-jwt/00/ |
| SD-JWT | RFC 9901 (November 2025) | Disclosures, `sd_hash`, Key Binding JWT | https://www.rfc-editor.org/rfc/rfc9901 |
| SD-JWT VC | draft-ietf-oauth-sd-jwt-vc-19 | Credential format `dc+sd-jwt` of the authority credentials | https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/19/ |
| OpenID for Verifiable Presentations | 1.0 (9 July 2025) | Mandate request, proof request and the requests of the scenarios: DCQL, `transaction_data`, `direct_post`, signed request object, client identifier prefixes `x509_hash` and `redirect_uri` | https://openid.net/specs/openid-4-verifiable-presentations-1_0.html |
| OpenID for Verifiable Credential Issuance | 1.0 Final | Issuance protocol of the wallet. This setup issues its credentials from the configuration at start. The business issuer page offers them with pre-authorized offers | https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html |
| OpenID4VC High Assurance Interoperability Profile | 1.0 Final | Profile behind the credential shape: SD-JWT VC, ES256 and the `x5c` header. The mandate request and the requests of the scenarios are signed with the client identifier prefix `x509_hash` of the profile. The requests of the 2 verifiers in the agent cases are unsigned and stay outside the profile | https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html |
| Token Status List | draft-ietf-oauth-status-list-21 | Status check of the authority credential | https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/21/ |
| ETSI TS 119 602 | V1.1.1 (November 2025) | Trusted lists of the wallet (JSON binding) as source of the trust anchors | https://www.etsi.org/deliver/etsi_TS/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf |
| JSON Web Key Thumbprint | RFC 7638 | Key thumbprints in the chain report | https://www.rfc-editor.org/rfc/rfc7638 |
| Proposal for a regulation on European Business Wallets | COM(2025) 838 final of 19 November 2025. Proposal. The regulation is not adopted | Legal terms only, such as European Business Wallet | https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:52025PC0838 |
| WE BUILD EBWOID rulebook | 1.1.0 at commit adae9cb | EBWOID template and schema | https://github.com/webuild-consortium/webuild-attestation-rulebooks-catalog |
| WE BUILD EU power of attorney rulebook | 0.2 at commit adae9cb | Template and schema of the EU power of attorney | https://github.com/webuild-consortium/webuild-attestation-rulebooks-catalog |
| WE BUILD Power of X rulebook | 1.2 at commit adae9cb | Schema of the employee authorisation | https://github.com/webuild-consortium/webuild-attestation-rulebooks-catalog |

The commit is adae9cb41c603724f68462ef23a653190d65c08f of 13 November 2026.

## Scenarios

The [scenarios](scenarios.md) use these pinned versions.

| Scenario | Specifications |
| --- | --- |
| Business issuer | OpenID4VCI 1.0 Final §4.1 (pre-authorized offer by reference), SD-JWT VC draft 19, Token Status List draft 21, WE BUILD EBWOID rulebook 1.1.0 and EU PoA rulebook 0.2 at commit adae9cb |
| Power of attorney at a notary | OpenID4VP 1.0 (DCQL, `direct_post`, signed request object with `x509_hash` and `verifier_info`), SD-JWT RFC 9901 with Key Binding JWT, SD-JWT VC draft 19, Token Status List draft 21, ETSI TS 119 602 V1.1.1, EU PoA rulebook 0.2 |
| Know your business at a bank | Like the notary, plus the EBWOID rulebook 1.1.0 for the owner identification data |
| AI agent with a delegation | Like the notary, plus Delegate SD-JWT draft 00 and `transaction_data` of OpenID4VP 1.0 |

[Differences](differences.md#scenarios) lists each place where a scenario is laxer than a real verifier.

## eudi-dev

| Part | Version | Use |
| --- | --- | --- |
| Wallet binary | 3.11.0 | The business wallet with Delegate SD-JWT, the theme, the demo links and the business configuration |
| Public packages | 3.11.0 | `internal/dsdjwt` parses SD-JWTs with `pkg/sdjwt` and reads the delegate payload with `pkg/sdjwt/delegate`. A test compares its chain check with `pkg/sdjwt/delegate`. See [ADR 0002](adr/0002-eudi-dev-code-is-reused-through-public-packages.md) |

`internal/dsdjwt` builds its chain report on `pkg/sdjwt`. `internal/trust` is the trusted list reader of this repository.
