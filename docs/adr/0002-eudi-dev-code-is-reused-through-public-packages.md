# eudi-dev code is reused through public packages

Most eudi-dev packages are under `internal/` (eudi-dev ADR 0007). This repository needs the credential formats, the trust checks and a wallet for each organisation. There are 3 options:

- **A.** Run the eudi-dev binary with a configuration.
- **B.** Make all needed eudi-dev packages public. That is 36 packages with their types.
- **C.** Make a few libraries public and add a narrow wallet facade.

## Decision

Option C, in 2 layers. Option A runs the wallet until the facade exists.

1. **Libraries.** eudi-dev 3.11.0 publishes `pkg/sdjwt`, `pkg/sdjwt/delegate` and `pkg/mdoc`. `internal/dsdjwt` parses SD-JWTs and resolves their disclosures with `pkg/sdjwt`. It keeps its own report with one result for each check, because `delegate.Verify` returns one error. It also keeps the checks that differ from eudi-dev: only sha-256 and ES256, and its own clock skew for `iat`, `exp` and `nbf`. A test compares both verdicts on every case. `internal/trust` reads trusted lists and status lists until eudi-dev publishes a reader for them.
2. **Wallet facade.** One public package starts a wallet instance from an options value and returns an `http.Handler`. Its exported signatures use only standard library types and its own types. The organisation service mounts one instance for each organisation under a path prefix. `wallet`, `oid4vp`, `registrar` and `storage` stay internal.
3. **Until then.** This repository runs the wallet binary behind a small Go interface for a wallet instance. The facade replaces the process behind the same interface.

The whole wallet stays internal. eudi-dev can then refactor the wallet without breaking this repository.

## Consequences

The eudi-dev ADR is `docs/adr/0034-the-credential-format-packages-are-public.md`. It replaces eudi-dev ADR 0007 and leaves the wallet facade for later.

2 wallet instances in one process need a test before the facade is built. The theme, the memory store and the wallet runtime registry are process-wide state in eudi-dev.
