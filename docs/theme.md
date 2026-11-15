# Theme

The business wallet is the eudi-dev wallet with the theme of this repository. The theme keeps the layout and type of eudi-dev. An ink band in the header and the BUSINESS tag mark the business wallet. The logo is the eudi-dev logo in petrol, and links, primary buttons, focus rings and selections use the same petrol. The status colours stay those of eudi-dev.

## Files

| File | Content |
| --- | --- |
| `brand/logo.svg` | The logo. The wallet and the demo pages both use it |
| `brand/theme/theme.yaml` | Wallet name, page description, BUSINESS tag, the hidden menu entry and ebw-dev in the footer |
| `brand/theme/theme.css` | Ink band, petrol accent, the colours of the BUSINESS tag and the hidden parts of the wallet UI |
| `brand/theme/favicon.svg` | The logo with the square frame of the eudi-dev favicon |

`scripts/run-local.sh` copies `brand/theme/` and `brand/logo.svg` into one directory and passes it to `eudi wallet serve --theme`. The wallet reads the theme on every request. The [eudi-dev theme guide](https://github.com/eudi-dev/eudi-dev/blob/main/docs/wallet/themes.md) describes the format.

The theme keys `name`, `description`, `edition`, `nav`, `product` and `demo` need eudi-dev 3.11.0 or later.

## Petrol accent

| Token | Light | Dark |
| --- | --- | --- |
| `--accent` | `#1d5f68` | `#4fc1c6` |
| `--on-accent` | `#ffffff` | `#10282b` |
| `--link` | `#1d5f68` | `#7fd3d6` |

Text on a primary button has a contrast of more than 7:1 in both themes. In the header the accent is the light petrol in both themes, because the band is dark.

## BUSINESS tag

The name in `theme.yaml` replaces the wallet name in the page title and the header. `edition: Business` in `theme.yaml` adds the tag next to the name in the header of the wallet page and the decoder page. The wallet shows it in capitals. `theme.css` gives the tag white on the ink band.

## Footer

`product` in `theme.yaml` puts ebw-dev into the footer of every wallet page. It also points the GitHub entry of the header menu to the ebw-dev repository. `scripts/run-local.sh` adds `product.version` with the ebw-dev version, so the wallet footer and the demo footer show the same version.

## Demo links

The wallet page has the hint "Try the business wallet demo". The how-to dialog links to the demo issuer and the demo verifier. The theme keys under `demo` set the texts and where the links lead.

| Key | Page of the demo server |
| --- | --- |
| `demo.issuer` | `/issuer`, the business issuer |
| `demo.verifier` | `/#scenarios`, the verifiers on the map of the demo |
| `demo.hint.links` | `/`, the start page of the demo |

The address depends on where the demo server runs, so `brand/theme/theme.yaml` leaves the keys out. `scripts/run-local.sh` adds them to the copy in the state directory with the public URL of the demo server:

```yaml
demo:
  issuer: http://localhost:28090/issuer
  verifier: http://localhost:28090/#scenarios
  hint:
    text: Try the
    links:
      - label: business wallet demo
        url: http://localhost:28090/
```

`EBW_DEV_PUBLIC_URL` changes the public URL. A deployment such as business.eudi-test.dev writes the same keys with its own public URL. A path relative to the wallet page works as well when the demo server runs under the same host.

## Hidden parts

The business wallet leaves out the parts of the wallet UI that belong to the personal test wallet. `nav.hide` in `theme.yaml` removes the CLI entry of the header menu. `theme.css` hides the browser extension tab and the PID trusted list of the how-to page.

## Demo pages

The demo pages of `internal/demo/web` use the logo from `brand/logo.svg`. They have the same ink band and BUSINESS tag as the wallet, with petrol links and buttons. Their colours are in `internal/demo/web/static/app.css`. The wallet sets light and dark with an attribute, and the demo pages follow the system setting. So `app.css` repeats the values of `brand/theme/theme.css`. A colour change goes into both files.

The footer of the demo pages shows the version of ebw-dev, for example `ebw-dev 0.0.1`. It comes from the build, with `-ldflags "-X main.version=0.0.1"`, and is `dev` without it.
