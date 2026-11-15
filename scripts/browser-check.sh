#!/usr/bin/env bash
# Walks the wallet and the demo of a running setup (scripts/run-local.sh) in
# Chromium. The argument is the directory for the screenshots.
# PLAYWRIGHT_MODULE sets the path of the Playwright module. The ports follow
# EBW_DEV_WALLET_PORT and EBW_DEV_DEMO_PORT.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export EBW_DEV_WALLET_URL="${EBW_DEV_WALLET_URL:-http://localhost:${EBW_DEV_WALLET_PORT:-28085}}"
export EBW_DEV_PUBLIC_URL="${EBW_DEV_PUBLIC_URL:-http://localhost:${EBW_DEV_DEMO_PORT:-28090}}"
exec node "$ROOT/scripts/browser-check.cjs" "${1:-$ROOT/.state/browser-check}"
