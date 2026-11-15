#!/usr/bin/env bash
# Runs both cases, the refusal cases, the revoked credential, the scenarios,
# the issuer offers and the holdings of the wallet against a running setup
# (scripts/run-local.sh). It fails when the wallet returns no dSD-JWT.
set -euo pipefail

cd "$(dirname "$0")/.."
exec go test -tags e2e -count=1 -v ./internal/e2e "$@"
