#!/usr/bin/env bash
# Starts the business wallet on port 28085 and the demo server on port 28090.
# EBW_DEV_WALLET_PORT, EBW_DEV_WALLET_TLS_PORT, EBW_DEV_DEMO_PORT
# and EBW_DEV_STATE change the ports and the state directory.
# EBW_DEV_PUBLIC_URL is the address of the demo server in the browser.
# EBW_DEV_VERSION sets the version in both footers (default: git describe).
# Ctrl+C stops both.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="${EBW_DEV_STATE:-$ROOT/.state}"
WALLET_BIN="${WALLET_BIN:-$ROOT/bin/eudi}"
WALLET_PORT="${EBW_DEV_WALLET_PORT:-28085}"
WALLET_TLS_PORT="${EBW_DEV_WALLET_TLS_PORT:-28091}"
DEMO_PORT="${EBW_DEV_DEMO_PORT:-28090}"
PUBLIC_URL="${EBW_DEV_PUBLIC_URL:-http://localhost:$DEMO_PORT}"
VERSION="${EBW_DEV_VERSION:-$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)}"
VERSION="${VERSION#v}"

if [ ! -x "$WALLET_BIN" ]; then
  echo "No wallet binary at $WALLET_BIN. Build eudi-dev and set WALLET_BIN to the eudi binary." >&2
  exit 1
fi

mkdir -p "$STATE/theme" "$ROOT/bin"
# The wallet reads the logo from its theme directory. brand/logo.svg is the
# one copy that the demo pages use as well.
cp "$ROOT"/brand/theme/* "$ROOT/brand/logo.svg" "$STATE/theme/"
# The wallet footer shows the same ebw-dev version as the demo footer.
sed -i.bak "s|^product:\$|product:\\
  version: \"$VERSION\"|" "$STATE/theme/theme.yaml"
rm -f "$STATE/theme/theme.yaml.bak"
# The demo hints of the wallet page lead to the issuer page, the scenarios
# and the start page of the demo server. Their address depends on the public URL of
# the demo.
cat >>"$STATE/theme/theme.yaml" <<EOF
demo:
  issuer: $PUBLIC_URL/issuer
  verifier: $PUBLIC_URL/#scenarios
  hint:
    text: Try the
    links:
      - label: business wallet demo
        url: $PUBLIC_URL/
EOF
(cd "$ROOT" && go build -ldflags "-X main.version=$VERSION" -o bin/ebw-dev ./cmd/ebw-dev)

wallet_pid=""
stop() {
  if [ -n "$wallet_pid" ]; then
    kill "$wallet_pid" 2>/dev/null || true
    wait "$wallet_pid" 2>/dev/null || true
  fi
  rm -f "$STATE/wallet.pid"
}
trap stop EXIT

# Without EUDI_DEV_HOME the wallet CLI uses the configuration of the user,
# and that configuration can point at a public instance.
export EUDI_DEV_HOME="$STATE/eudi"

cd "$ROOT"
"$WALLET_BIN" wallet serve \
  --port "$WALLET_PORT" \
  --base-url "https://localhost:$WALLET_TLS_PORT" --serve-tls \
  --config wallet-config --no-builtins \
  --issuer-name "ebw-dev Test Issuer" \
  --theme "$STATE/theme" \
  --status-list \
  --transaction-data --delegate-sd-jwt \
  --no-register >"$STATE/wallet.log" 2>&1 &
wallet_pid=$!
echo "$wallet_pid" >"$STATE/wallet.pid"

for _ in $(seq 1 50); do
  if curl -fsS "http://localhost:$WALLET_PORT/api/trustlists" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$wallet_pid" 2>/dev/null; then
    echo "The wallet exited during startup. Log:" >&2
    tail -n 20 "$STATE/wallet.log" >&2
    exit 1
  fi
  sleep 0.2
done

echo "Business wallet: http://localhost:$WALLET_PORT (log in $STATE/wallet.log)"
echo "Demo:            http://localhost:$DEMO_PORT"

"$ROOT/bin/ebw-dev" \
  --listen "127.0.0.1:$DEMO_PORT" \
  --public-url "$PUBLIC_URL" \
  --wallet-url "http://localhost:$WALLET_PORT" \
  --brand-dir "$ROOT/brand"
