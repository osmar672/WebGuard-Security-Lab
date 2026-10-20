#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -x "$ROOT/.venv/bin/uvicorn" || ! -d "$ROOT/frontend/node_modules" ]]; then
  echo "Primera ejecución: abre una terminal en esta carpeta y ejecuta ./setup.sh" >&2
  exit 1
fi
exec "$ROOT/scripts/dev.sh" "$@"
