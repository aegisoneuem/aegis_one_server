#!/usr/bin/env bash
# Start the Aegis One server for end-to-end tests (docs/e2e-testing.md).
# Reads e2e.env, refuses to run with an unfilled placeholder, logs to server.log.
set -euo pipefail
cd "$(dirname "$0")"

[ -f e2e.env ] || { echo "e2e.env not found (copy e2e.env.example and fill it in)" >&2; exit 1; }
if grep -q '<[A-Z_]*>' e2e.env; then
  echo "e2e.env still has <PLACEHOLDER> values:" >&2
  grep -n '<[A-Z_]*>' e2e.env >&2
  exit 1
fi
# shellcheck disable=SC1091
set -a; . ./e2e.env; set +a

echo "server log: $(pwd)/server.log  (Ctrl+C stops the server)"
./server 2>&1 | tee -a server.log
