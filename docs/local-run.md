# Local run

`scripts/run-local.sh` starts the business wallet and the demo server on the local machine. Ctrl+C stops both.

## Requirements

Go 1.27 and an `eudi` wallet binary. The delegation needs a wallet with the flags `--transaction-data` and `--delegate-sd-jwt`. The flag `--delegate-sd-jwt` comes with eudi-dev 3.11.0. A wallet without these flags answers the mandate request with a plain SD-JWT presentation. The agent service then reports that the wallet does not support delegation.

`WALLET_BIN` defaults to `bin/eudi`. The [README](../README.md#install) shows how to install it.

```sh
WALLET_BIN=/path/to/eudi scripts/run-local.sh
```

## Steps of the script

1. It copies `brand/theme/` and `brand/logo.svg` into the theme directory of the wallet. [Theme](theme.md) describes these files. It adds the demo links of the wallet page to the copy of `theme.yaml`. They lead to the issuer page and the scenarios of the demo server. See [Demo links](theme.md#demo-links).
2. It builds `bin/ebw-dev`.
3. It starts the wallet with `--no-builtins`. The wallet serves the content of `wallet-config` alone and issues the 3 credentials of `wallet-config/credentials.yaml`. `--issuer-name` sets the name of the issuer. All 3 credentials come from this one test issuer.
4. It starts the demo server.

The script sets `EUDI_DEV_HOME` to a directory below the state directory. The wallet then never reads the eudi-dev configuration of the user.

## Services

| Service | Address |
| --- | --- |
| Demo pages and JSON API | http://localhost:28090 |
| Business wallet | http://localhost:28085 |
| HTTPS issuer of the wallet | https://localhost:28091 |

The wallet keeps its state in `.state/`. Git ignores this directory. Delete it for a fresh wallet. The wallet log is `.state/wallet.log`.

## Environment variables

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `EBW_DEV_WALLET_PORT` | `28085` | HTTP port of the wallet |
| `EBW_DEV_WALLET_TLS_PORT` | `28091` | HTTPS port of the wallet |
| `EBW_DEV_DEMO_PORT` | `28090` | Port of the demo server |
| `EBW_DEV_STATE` | `.state` | State directory |
| `EBW_DEV_PUBLIC_URL` | `http://localhost:$EBW_DEV_DEMO_PORT` | Public URL of the demo server. The demo links of the wallet page use it as well |
| `EBW_DEV_VERSION` | The output of `git describe` | Version in the footers of the wallet and the demo |
| `WALLET_BIN` | `bin/eudi` | Wallet binary |

## Wallet configuration

| File in `wallet-config/` | Content |
| --- | --- |
| `credentials.yaml` and `templates/` | The 3 credentials of the test organisation |
| `catalog.yaml` | The 3 credential types of the catalogue |
| `relying-parties.yaml` | The test organisation with the agent service and its 2 intended uses, the supplier with its portal, the notary (Delta Notaries) and the bank (Example Bank) |

## Flags

The flags of `bin/ebw-dev`:

| Flag | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `--listen` | `EBW_DEV_LISTEN` | `127.0.0.1:28090` | Listen address |
| `--public-url` | `EBW_DEV_PUBLIC_URL` | `http://localhost:28090` | Base URL for browsers and the wallet. It may carry a path prefix such as `/agents` |
| `--wallet-url` | `EBW_DEV_WALLET_URL` | `http://localhost:28085` | Base URL of the wallet for the server |
| `--wallet-public-url` | `EBW_DEV_WALLET_PUBLIC_URL` | The wallet URL | Base URL of the wallet for browsers. Every link to the wallet uses it |
| `--brand-dir` | `EBW_DEV_BRAND_DIR` | `brand` | Directory with `logo.svg` |

The server answers with and without the path prefix of the public URL. Every page link is relative.

A deployment sets `--wallet-public-url` to the address of the wallet on the internet, such as `https://wallet.example`. `--wallet-url` stays the address of the wallet inside the deployment. When `--wallet-public-url` is set, pages and API answers never show `--wallet-url`.
