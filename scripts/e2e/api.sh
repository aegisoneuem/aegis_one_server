#!/usr/bin/env bash
# Call the Aegis One internal API during end-to-end tests (docs/e2e-testing.md).
#
#   ./api.sh <admin|op> <METHOD> <path> [json-body]
#   ./api.sh admin GET /internal/devices
#   ./api.sh admin POST /internal/actions '{"action":"scan_now","device_ids":["<DEVICE_ID>"]}'
#
# The token is read from tokens/<name> (one line, chmod 600), never from the
# command line, so it does not land in shell history.
set -euo pipefail
cd "$(dirname "$0")"

if [ $# -lt 3 ]; then
  echo "usage: $0 <admin|op> <METHOD> <path> [json-body]" >&2
  exit 2
fi
name=$1 method=$2 path=$3 body=${4:-}

[ -f e2e.env ] || { echo "e2e.env not found (copy e2e.env.example)" >&2; exit 1; }
# shellcheck disable=SC1091
set -a; . ./e2e.env; set +a
tokfile="tokens/$name"
[ -f "$tokfile" ] || { echo "$tokfile not found (see docs/e2e-testing.md, step 3)" >&2; exit 1; }

args=(-sS --cacert "${AEGIS_CA_CERT:-certs/ca.crt}" -X "$method"
      -H "Authorization: Bearer $(tr -d '\r\n' < "$tokfile")"
      -w '\n[%{http_code}]\n')
if [ -n "$body" ]; then
  args+=(-H "Content-Type: application/json" -d "$body")
fi
# The server certificate names aegis-server; resolve it to localhost here.
curl "${args[@]}" --resolve "aegis-server:8080:127.0.0.1" "https://aegis-server:8080${path}"
