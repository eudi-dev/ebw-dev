# Contributing

## Prerequisites

- **Go 1.27**
- An `eudi` wallet binary with Delegate SD-JWT for the scripts. The [README](README.md#install) shows how to build it
- **Node.js** and Playwright for `scripts/browser-check.sh` only

## Setup

```sh
go build ./...
go test ./...
```

## Running tests

```sh
go test ./...                     # unit tests and both cases against a test wallet
scripts/e2e.sh                    # cases, refusals, scenarios, offers and wallet holdings against the running setup
scripts/browser-check.sh shots    # wallet and demo in Chromium, screenshots in shots/
```

`scripts/e2e.sh` and `scripts/browser-check.sh` need the setup of `scripts/run-local.sh`. `scripts/browser-check.sh` uses the same port variables. `scripts/e2e.sh` reads the addresses from `EBW_DEV_PUBLIC_URL` and `EBW_DEV_WALLET_URL`. [Local run](docs/local-run.md) has the details.

`scripts/e2e.sh` fails with a clear message when the wallet returns no dSD-JWT.

`scripts/browser-check.sh` needs Node.js and Playwright. `PLAYWRIGHT_MODULE` sets the path of the Playwright module. The check registers a verifier, reads the catalogue, fetches every download of the trust dialog, requests a credential and runs both cases with consent in the wallet. It also revokes a credential in the wallet and runs the agent. It fails on a console error and on an HTTP error status. Each run leaves one more EBWOID and some revoked credentials in the wallet.

## Before a commit

```sh
gofmt -l .
golangci-lint run
```

## Documentation

[docs/README.md](docs/README.md) is the index. New terms go into [CONTEXT.md](CONTEXT.md) and decisions into [docs/adr/](docs/adr/). [docs/agents/comments.md](docs/agents/comments.md) describes when code needs a comment.
