# Plan

This page is the plan for ebw-dev. The name stands for European Business Wallet. The repository is `github.com/eudi-dev/ebw-dev`.

## Principles

The plan follows 3 principles.

1. **Built on eudi-dev, free to differ.** ebw-dev uses the fundamentals of eudi-dev: formats, protocols, trust and debug tooling. Where a business wallet needs something else, ebw-dev does it differently. It is a product of its own with flows that eudi-dev lacks.
2. **Faithful to the standards.** ebw-dev follows the real rules and every standard involved: the European Business Wallet proposal COM(2025) 838, Delegate SD-JWT, OpenID4VC, HAIP, the ARF and others. These standards change. The docs and the disclaimer in the UI name the implemented version of each one. The code for each specification sits in one place, so a new draft changes one place.
3. **Made for testing and debugging.** ebw-dev brings the activity log, the decoder, the findings and the debug and strict modes of eudi-dev. It adds the same insight for the flows of a business wallet: organisation onboarding, member approval and delegation chains. Where it helps testing, ebw-dev is laxer than a real wallet, for example on security. The docs name every such difference.

## Goals

| # | Goal |
| --- | --- |
| 1 | Delegate SD-JWT is a feature of eudi-dev. It works with personal wallets and with business wallets. It stays behind the experimental switch. |
| 2 | The business wallet is a product of its own in this repository. It is a test tool. People create organisations. Each organisation has its own business wallet with its own credentials, keys and log, and its own members and roles. Members prove who they are with their personal PID. On a public instance every visitor can create a test organisation. |
| 3 | This repository reuses eudi-dev code as Go packages where that is cleaner than running the binary. |
| 4 | Documentation and UI say that the specifications behind a business wallet are not final. |
| 5 | A realistic case replaces the internal case. The company IAM checks the delegation once and gives the agent normal tokens. |
| 6 | Colours and logo get a separate design pass. |

## Scope

- eudi-dev has no members, roles or organisations. They live in this repository.
- Every visitor creates an organisation, and every organisation has its own wallet.
- The eudi-dev branch `feat/delegate-sd-jwt` holds users and roles code. It is reference material for this repository until the organisation service exists.
- The AI agent demo becomes one example inside the business wallet.

## Goal 1: Delegate SD-JWT in eudi-dev

eudi-dev 3.11.0 has Delegate SD-JWT with the decoder view behind the experimental switch. It also has 4 generic options: the wallet name and the page description in the theme, the issuer display name and `--no-builtins`. It has no organisation, member or business wallet code.

The decoder explains a pasted Delegate SD-JWT without the switch. That stays.

### Personal delegation example in the eudi-dev demo

A person delegates a credential to their own agent. The example extends the demo verifier of eudi-dev. It appears only with `--experimental-delegate-sd-jwt`.

| Step | Content |
| --- | --- |
| 1 | The demo page offers the request "Let a demo agent prove your age". The demo creates an agent key for this run. |
| 2 | The request asks for the PID with `delegate` transaction data. The delegation holds the agent key, the claim `age_over_18` alone, the demo verifier as audience and an end time 10 minutes later. |
| 3 | The wallet shows the delegation in the consent dialog and answers with a dSD-JWT+KB. |
| 4 | The demo agent presents the chain to the demo verifier. The agent is a fixed script. |
| 5 | The result page lists the checks of the chain and links to the decoder with the chain filled in. |

A second request can use an employee credential from the demo issuer. The steps are the same.

## Goal 2: Business wallet as a product

### Parts

| Part | Content |
| --- | --- |
| Organisation service | Creates, lists and deletes organisations. Holds members and roles. New code in this repository. |
| Wallet instance | One business wallet for each organisation with its own credentials, keys and activity log. eudi-dev wallet code with its decoder, findings and debug and strict modes. |
| Identity check | A verifier for the PID of a member. It asks the personal wallet of the member over OpenID4VP and matches the PID to a member. New code on top of eudi-dev packages. |
| Examples | The AI agent demo with its agent service and verifiers. Further examples can follow. |
| Pages | Pages of this repository for the start, the organisation, its members and roles, member approval and delegations. Pages of the eudi-dev wallet where they fit a business wallet, such as the credential list and the decoder. |
| Debug view | The activity log covers the business flows: organisation onboarding, member approval and every link of a delegation chain. Each check is a finding with its rule, as in eudi-dev. |

### Organisations

- Onboarding follows COM(2025) 838 as far as the proposal defines it. Step 8 of the plan lists the articles and what a test tool shortens.
- An organisation has an identifier that cannot be guessed, a name, members and one wallet instance.
- A new organisation can start from a template. The first template is Acme Logistics GmbH with its 3 credentials and 3 members.
- The wallet API of eudi-dev has no authentication (eudi-dev ADR-0002). The link with the organisation identifier is the access to an organisation. A real business wallet authenticates its users. The list of differences from a real wallet states this.
- The browser remembers the organisations of a visitor. The link also works in another browser.

### Members and proof of identity

- A member has a name, a role and the PID attributes for the match.
- A role lists the credential types for presenting and for delegating.
- A person approves a request by presenting their PID. The identity check matches the PID to a member and checks the role.
- Debug mode and strict mode apply to the business flows too. In strict mode an approval needs the PID of a member with the right role. In debug mode the wallet reports a missing or failed proof as a finding and continues, so a tester sees the whole flow.
- The consent dialog and the activity log show the approving member and the kind of proof.
- The demo pages keep a marked shortcut with a test PID for quick runs. The list of differences lists it.

### Public instance

- The proof of identity is demo grade. A PID from a shared test wallet proves nothing about a real person. The pages say so.
- The instance limits the number of organisations and deletes an organisation after a period without use.
- The operator sets the PID issuers accepted by the identity check. The default is the PID provider of the eudi-dev test infrastructure.

## Goal 3: Reuse of eudi-dev code

### Findings of the code survey

All eudi-dev packages are under `internal/` (eudi-dev ADR-0007). The numbers count lines without tests.

| Package | Lines | Internal imports | Finding |
| --- | --- | --- | --- |
| `wallet` | 26400 | 36 packages | Holder, issuer, HTTP API and web UI. `Server.Handler()` returns the HTTP handler. State is keyed by the wallet directory. |
| `cmd/wallet_serve.go` | 540 for the start | | `runWalletServe` wires flags, storage, trust, registrar and theme into a wallet. An importing program would repeat this. |
| `sdjwt` | 1500 | 6 small packages | Includes `ParseDelegation`, `VerifyDelegation` and `Delegate`. This repository duplicates it in `internal/dsdjwt` (990 lines). |
| `mdoc` | 1300 | 3 | Self-contained |
| `statuslist` | 1400 | 10, among them `mock` | Needs untangling before it can be public |
| `lote`, `trustedlists` | 900 and 1500 | 4 and 13 | `lote` reads a trusted list and is small. `trustedlists` depends on registrar, provider and templates. This repository duplicates the reading side in `internal/trust` (370 lines). |
| `dcql` | 2300 | 9, among them `consent` | Mixed with consent types |
| `oid4vp` | 3400 | 13 | Holder side. The verifier side sits in `demorp`, which imports `wallet`. |
| `storage` | 1100 | 0 | Clean. The memory backend is one store for the process, and the wallet directory separates wallets inside it. |
| `webui` | 370 | | The active theme is one value for the process. |

2 wallets in one process look possible from the code. No test proves it.

### Options

| | A: binary and configuration | B: all needed packages public | C: libraries and a narrow wallet facade |
| --- | --- | --- | --- |
| Shape | One `eudi` process for each organisation, started and proxied by this repository | `wallet`, `oid4vp`, `registrar`, `storage` and the rest move to `pkg/` | The format packages move to `pkg/`. A small package starts a wallet instance and returns its handler. The wallet itself stays internal. |
| Work in eudi-dev | A hook for the approval by a member | Very large. 36 packages with their types become public. | Medium. See the steps. |
| Isolation of organisations | Strong, by process | By storage prefix | By storage prefix |
| Public instance with many organisations | Process supervision, one port for each organisation, memory for each process | Fine | Fine |
| Public API promise of eudi-dev | None | Very large | Small: a few format packages and one options type |
| Risk for eudi-dev | Low | High. Refactors of the wallet break importers. | Medium. Limited to the public surface. |
| Duplicated code here | Stays (chain check, trusted list reader) | Gone | Gone |

### Recommendation

Option C, in 2 layers. Option A runs the wallet until the facade exists.

1. **Libraries.** eudi-dev 3.11.0 publishes `pkg/sdjwt`, `pkg/sdjwt/delegate` and `pkg/mdoc`. The trusted list reader and the status list check follow after an API review of their own. The verifiers, the agent and the identity check of this repository import the public packages. `internal/dsdjwt` keeps its report with one result for each check, because `delegate.Verify` returns one error. A test compares both verdicts on every case. `internal/trust` stays until the trusted list reader is public.
2. **Wallet facade.** One public package starts a wallet instance from an options value and returns an `http.Handler`. Its exported signatures use only standard library types and its own types. The organisation service mounts one instance for each organisation under a path prefix. `wallet`, `oid4vp`, `registrar` and `storage` stay internal.
3. **Until then.** This repository runs the binary behind a small Go interface for a wallet instance. The facade replaces the process behind the same interface.

Option B is not recommended. It turns the whole wallet into a public API and blocks refactoring in eudi-dev.

The eudi-dev ADR is `docs/adr/0034-the-credential-format-packages-are-public.md` in eudi-dev 3.11.0. It replaces ADR-0007 and leaves the wallet facade for later.

### What stays internal

`wallet`, `oid4vp`, `registrar`, `storage`, `demorp`, `web`, `proxy`, `validate`, `dcql`, `provider`, `mock`, `consent`, `credtemplate`, `txtemplate`, `remote`, `urlhandler` and all small helpers that the public packages do not need.

### Risks for eudi-dev

- A public package is a promise. ADR-0034 puts `pkg/` under semantic versioning with the module version. Only the Delegate SD-JWT functions can change in a minor version, because they follow a draft.
- Findings and warning strings are part of some signatures today. A library caller needs typed results. `pkg/sdjwt` and `pkg/mdoc` return errors. The trusted list reader and the status list check need that review.
- The facade can drift from `eudi wallet serve`. `runWalletServe` should call the facade so both stay the same.
- Process-wide state (theme, memory store, wallet runtime registry) limits several instances in one process. A test has to prove 2 isolated instances before the facade is built.

## Goal 4: Disclaimers

The facts:

- The European Business Wallet regulation is a proposal (COM(2025) 838).
- There is no Architecture and Reference Framework for business wallets.
- The credential formats come from the WE BUILD pilot.
- Delegate SD-JWT is at draft-ietf-oauth-delegate-sd-jwt-00.

| Place | Form |
| --- | --- |
| README | A section "Status of the specifications" near the top with the 4 facts |
| Business wallet pages | A permanent banner below the header with one sentence and a link to the status page |
| Start page and example pages | The same banner and a status section with the 4 facts |
| Consent dialog | The existing note about the experimental Delegate SD-JWT stays |
| Credential templates | Each template description states its source and says that the format can change |
| `docs/` | A status page with the 4 facts and the table of pinned versions. The table in `docs/architecture.md` is the start. It gains the proposal, the ARF version and every specification of eudi-dev that a business flow uses |
| Disclaimer in the UI | The banner links to the same table of pinned versions |
| `docs/` | A page "Differences from a real business wallet" that lists every place where ebw-dev is laxer: access by link, PID from a test wallet, debug mode, the shortcut with a test PID, unencrypted keys |

## Goal 5: Replacement of the internal case

The internal case lets an API of the same company check the delegation chain. Inside a company the IAM gives agents their rights. The replacement:

| Step | Content |
| --- | --- |
| 1 | A member approves a delegation for the agent in the business wallet, as in case 1. |
| 2 | The agent presents the chain once to Keycloak, the IAM of the company. |
| 3 | Keycloak checks the chain and maps the delegation to a token: the agent as client, the member as the person behind it, the action and the limit as claims, the end time as the upper bound of the token lifetime. |
| 4 | The agent calls the internal API with this access token. The API checks a normal token and knows nothing about the delegation. |
| 5 | Refusals: an expired delegation gets no token, a revoked credential gets no token, a token cannot outlive the delegation. |

The way the agent presents the chain to Keycloak is open. Candidates are an OpenID4VP presentation to a verifier endpoint in Keycloak, a token exchange with the chain as the subject token, and an assertion grant. Each needs a Keycloak extension that checks a dSD-JWT+KB. The choice needs a check against the current Keycloak release and the existing OpenID4VP verifier work for Keycloak. Nothing of this is built.

## Goal 6: Design pass

Direction for the pass:

- The look stays close to eudi-dev: same layout, type, components and logo family.
- One clear signal marks the business wallet at first sight, for example a distinct accent colour and a business marker in the logo and header.
- It reads as the business version of eudi-dev.

## Steps

The effort values are rough estimates in working days of an agent session with review.

| # | Step | Repository | Effort | Depends on |
| --- | --- | --- | --- | --- |
| 1 | Delegate SD-JWT and the generic options. Released in eudi-dev 3.11.0 | eudi-dev | Done | |
| 2 | Personal delegation example in the demo verifier | eudi-dev | 1 to 2 | 1 |
| 3 | Disclaimers in README, pages and banner, the table of pinned versions and the page of differences from a real business wallet | here | 1 | |
| 4 | Test with 2 wallet instances in one process, and the list of process-wide state to fix | eudi-dev | 0.5 to 1 | |
| 5 | Public `sdjwt` with delegation and public `mdoc`. Released in eudi-dev 3.11.0 | eudi-dev | Done | |
| 6 | Public trusted list reader and status list check, each with a move commit and an API commit | eudi-dev | 2 to 3 | 5 |
| 7 | This repository builds its chain report on `pkg/sdjwt` and drops `internal/trust` | here | 1 to 2 | 5, 6 |
| 8 | Organisation service with members and roles, one wallet process for each organisation behind the instance interface. Before it: a survey of COM(2025) 838 for onboarding and representation, with the articles in the docs | here | 4 to 6 | |
| 9 | Identity check with the PID and the approval by a member, with the hook in the wallet, findings for each check and the debug and strict behaviour | here and eudi-dev | 4 to 6 | 8 |
| 10 | Wallet facade, used by `eudi wallet serve` and by this repository | eudi-dev and here | 3 to 6 | 4 |
| 11 | Limits and expiry for the public instance | here | 1 | 8 |
| 11a | Activity log and findings for onboarding, member approval and delegation chains. One package for each specification | here | 2 to 3 | 8, 9 |
| 12 | AI agent demo as an example inside an organisation | here | 1 to 2 | 8, 9 |
| 13 | IAM case with Keycloak | here | 4 to 8 | 12, decision on the mechanism |
| 14 | Design pass | here | 1 to 2 | |
| 15 | Deployment at business.eudi-test.dev | here | 1 | |

Steps 3 and 4 can start at once. Steps 8 and 9 do not wait for the public packages.

The test of `internal/dsdjwt` compares each verdict with `pkg/sdjwt/delegate` of eudi-dev 3.11.0.

## Open questions

1. Which PID attributes identify a member: family name, given name and birth date, or another set?
2. Which PID issuers does the identity check accept on the public instance?
3. Which pages of the eudi-dev wallet stay as they are inside the business wallet? Principle 1 gives the business flows pages of their own.
4. Is the link with the organisation identifier enough as access on the public instance?
5. Which mechanism carries the delegation to Keycloak, and does the Keycloak part live in this repository or in an extension repository?
6. Does the wallet stay one process for each organisation in the first version, or does the first version wait for the facade?
