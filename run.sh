#!/usr/bin/env bash
# Usage: ./run.sh <domain> [baseline.pdf|baseline.txt]
set -euo pipefail
cd "$(dirname "$0")"

DOMAIN="${1:?usage: ./run.sh <domain> [baseline.pdf|baseline.txt]}"
BASELINE="${2:-}"

ARGS=(-d "$DOMAIN")
if [[ -n "$BASELINE" ]]; then
  ARGS+=(--baseline "$BASELINE")
fi

exec .venv/bin/python subdive.py "${ARGS[@]}"
