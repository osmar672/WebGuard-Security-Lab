#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x .venv/bin/python || ! -x .venv/bin/uvicorn || ! -d frontend/node_modules ]]; then
  echo "Faltan dependencias. Ejecuta primero: ./scripts/setup.sh" >&2
  exit 1
fi

(
  cd frontend
  npm run lint
  npm run typecheck
  npm test
  npm run build
)
(
  cd backend
  ../.venv/bin/python -m pytest -q
)
(
  cd security
  ../.venv/bin/python -m pytest -q
)
