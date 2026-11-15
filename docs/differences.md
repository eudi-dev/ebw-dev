# Differences from a real business wallet

ebw-dev is a test tool. Where it helps testing, it is laxer than a real business wallet. This page lists every such place.

## Wallet and agent demo

| Place | ebw-dev | A real business wallet |
| --- | --- | --- |
| Wallet API | Anyone who reaches the wallet port controls the wallet ([eudi-dev ADR 0002](https://github.com/eudi-dev/eudi-dev/blob/main/docs/adr/0002-the-wallet-http-api-is-unauthenticated.md)) | Authenticates its users |
| Keys and credentials | Stored unencrypted in the state directory ([eudi-dev ADR 0003](https://github.com/eudi-dev/eudi-dev/blob/main/docs/adr/0003-keys-and-credentials-are-stored-unencrypted.md)) | Kept in protected key storage |
| Approval | Every person with access to the wallet page approves a request. The auto-accept button approves without a person | A member with the right role approves after a proof of identity |
| Validation mode | Debug mode by default. The wallet reports the mistakes of an issuer or verifier and continues | Refuses a faulty request |
| Issuers | One test issuer in the wallet issues all 3 credentials. The wallet CA signs the trusted lists | Each credential comes from its own provider under real trusted lists |
| Trust anchors | The verifiers fetch the wallet CA over plain HTTP on the local machine | A verifier gets its trust anchors over an authenticated channel |
| Refresh of the trusted lists | The demo server loads the trusted lists once. It loads them again on `POST /api/trust/reload` or after a failed load. It ignores `NextUpdate` | A verifier loads each list again before its next update |
| Issuer of a credential | A credential is trusted when its `x5c` chain ends at an issuer of a trusted list of the verifier. The verifier does not compare `iss` with the leaf certificate and does not check its extended key usage. So any issuer on these lists can sign any credential type | A verifier binds `iss` to the certificate and accepts each credential type only from its competent issuer |
| Clock | The demo shifts the clock of the agent and the verifier for the expired mandate run | A verifier uses its own clock |
| Policy of the verifiers | The verifiers read the limit and the actions from the mandate alone. The procurement API accepts every issuer on the `eaa` list as the issuer of the company | A verifier also checks that the powers of the credential cover the mandate, and it knows the issuer of the company |

## Scenarios

These places concern the [scenarios](scenarios.md).

| Place | ebw-dev | A real setup |
| --- | --- | --- |
| Shared wallet | All visitors of the demo use one business wallet. Each run changes the credentials for every visitor | Each organisation has its own wallet |
| Changes to the wallet | The demo issues a fresh credential into the wallet when none is valid. The revoked variant revokes the presented EU power of attorney and issues a fresh one after the answer when none is valid | The issuer and the organisation decide about issuance and revocation |
| Power of attorney without an end date | The notary accepts a power of attorney without `validity_period_valid_until` as valid without an end, as the EU PoA rulebook v0.2 allows. The claim is selectively disclosable, so the notary can't tell an open end from an end date the holder left out | A notary can insist on the end date or check it in a register |
| Expired power of attorney | The notary moves the registration to the day after the end date. The clock stays the same | The notary checks against the real date of the registration |
| Credential offers | The offer has a pre-authorized code without a transaction code. Anyone with the offer gets the credential | The issuer authenticates the organisation or asks for a transaction code |
| Answer of the wallet | The verifier answers the `direct_post` with a `redirect_uri` without a response code. The page reads the result by the request id in the address | A verifier binds the result to the browser session with a response code (OpenID4VP 1.0 §8.2 and §14.2) |
| Issuers | The notary and the bank accept every issuer on the trusted lists `pub-eaa` and `qeaa`. The bank does not ask a business register | A bank knows the competent issuer of each credential and may check the register |

## Planned

These differences come with the planned organisation service.

| Place | ebw-dev | A real business wallet |
| --- | --- | --- |
| Access to an organisation | The link with the organisation identifier | Authenticated users |
| Proof of identity | A PID from a shared test wallet | A PID of the real person |
| Business flows | Debug mode reports a missing or failed proof of identity as a finding and continues | Refuses the approval |
| Demo shortcut | A marked shortcut with a test PID for quick runs | None |
