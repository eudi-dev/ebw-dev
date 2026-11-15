# ebw-dev

A test tool for the European Business Wallet, built on eudi-dev. This glossary covers terms with a different or narrower meaning in this project than in the implemented specifications.

## Language

### Wallet and organisation

**Business wallet**:
The wallet of a legal person. It runs as the eudi-dev wallet with the configuration in `wallet-config/` and the theme in `brand/theme/`. Its name is EUDI Dev Wallet, with the BUSINESS tag.
_Avoid_: Organisation wallet, company wallet

**Organisation**:
The legal person that owns a business wallet. Planned: every organisation has its own business wallet with its own members and roles ([ADR 0001](docs/adr/0001-every-organisation-has-its-own-business-wallet.md)).
_Avoid_: Tenant, company

**Member**:
A person who acts for an organisation. Planned: a member has a name, a role and the PID attributes for the identity check.
_Avoid_: User

**Role**:
The credential types a member may present and delegate.

**Identity check**:
Planned: the check that matches the PID of a person to a member of an organisation.

### Delegation

**Authority credential**:
The credential of the organisation behind a delegation: the EU power of attorney or the employee authorisation.

**Mandate**:
The delegation signed by the wallet for one task of the agent. The pages call it a delegation. The API and the code call it a mandate.

**Agent**:
The Delegate Holder of Delegate SD-JWT. In the demo it is a fixed script without a language model.
_Avoid_: Bot, assistant

**Agent service**:
The registered relying party that creates an agent key and asks the wallet for a mandate.

**Verifier**:
A service that checks the delegation chain before it accepts a request of the agent.

**dSD-JWT and dSD-JWT+KB**:
The delegation chain of Delegate SD-JWT. The wallet returns a dSD-JWT. The agent presents a dSD-JWT+KB.

**Chain report**:
The result of a verifier for the 3 links of a chain: authority credential, mandate and presentation. Each link shows its signer, the thumbprint of its key and the result of every check.

### Demo

**Case**:
One task of the agent at one verifier. The demo has 2: an order at a supplier and an invoice approval inside the company.

**Refusal**:
A run that a verifier or the wallet has to refuse, such as an amount above the limit.
_Avoid_: Rejection case, negative test, failure case
