# AI agent demo

A test business wallet gives a scripted agent a mandate. The agent acts at 2 verifiers. Each verifier checks the whole delegation chain.

Everything is test data. Acme Logistics GmbH, Bolt Supplies B.V., Crate Trading ApS and all people are made up.

## Parts

- **Business wallet.** The test wallet [eudi-dev](https://github.com/eudi-dev/eudi-dev) with the configuration in `wallet-config/` and the theme in `brand/theme/`. Its name is EUDI Dev Wallet, with the BUSINESS tag. It holds the credentials of Acme Logistics GmbH.
- **Agent service.** A registered relying party of the wallet. It creates an agent key for each mandate and asks the wallet for the mandate over OpenID4VP 1.0 with a signed request.
- **Agent.** A fixed script without a language model. It carries out one task for each case.
- **Verifiers.** The supplier portal of Bolt Supplies B.V. and the internal procurement API of Acme Logistics GmbH.

The agent service, the agent and the verifiers run in the `ebw-dev` binary. [Architecture](architecture.md) describes the parts and the flow. [Chain format](chain-format.md) defines the wire format.

## Cases

| Case | Verifier | Authority credential | Action | Limit |
| --- | --- | --- | --- | --- |
| Order at a supplier | Bolt Supplies supplier portal (another organisation) | EU power of attorney from an issuer on the trusted list `pub-eaa` or `qeaa` | `order.create` | 5000.00 EUR |
| Invoice approval inside the company | Acme internal procurement API (same organisation) | Employee authorisation from the company's own issuer on the trusted list `eaa` | `invoice.approve` | 2500.00 EUR |

Each case has 5 refusals. The verifier refuses an amount above the limit, an expired delegation, a delegation shown to the wrong verifier, a tampered chain and a revoked credential.

A mandate is the delegation signed by the wallet for one task of the agent. The pages call it a delegation. The API and the code call it a mandate.

A later version replaces the internal case with a case where the company IAM checks the delegation.

## Pages

The start page is a map. It shows the business wallet, the issuer, the 2 cases of the agent and the scenarios at the notary and the bank. Case 1 is the start for a first visit. The wallet box shows the credentials in the wallet. A click on it opens the wallet.

Each case page guides through 3 steps:

1. The agent asks the wallet for a delegation.
2. You approve the delegation in the wallet. After a decline the agent has no delegation. "Ask again" starts a new request.
3. The agent acts at the verifier.

The 5 refusals follow the steps. Each one states the expected result and the result of the server. A progress rail shows the state, for example "5 refusals" before the first run and "1 of 5 done" after it. The run with a revoked credential revokes the credential in the wallet. The page then asks for a new delegation. The public demo protects its Acme credentials. A delegation that rests on one of them stops the run before the agent acts. The demo issues a new credential. The page then asks for a new delegation and a second run.

Breadcrumbs lead back to the map. A box at the end of each page points to the next stop on the map.
