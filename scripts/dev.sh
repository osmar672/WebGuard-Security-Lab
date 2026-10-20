#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x .venv/bin/uvicorn || ! -d frontend/node_modules ]]; then
  echo "Faltan dependencias. Ejecuta primero: ./setup.sh" >&2
  exit 1
fi
[[ -f backend/.env ]] || { echo "Falta backend/.env. Ejecuta ./setup.sh" >&2; exit 1; }
[[ -f frontend/.env.local ]] || cp frontend/.env.example frontend/.env.local

cleanup() {
  trap - EXIT INT TERM
  for pid in "${FRONTEND_PID:-}" "${BACKEND_PID:-}" "${WORKER_PID:-}"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

(
  cd backend
  ../.venv/bin/alembic upgrade head
  exec ../.venv/bin/uvicorn app.asgi:app --host 127.0.0.1 --port 8000
) &
BACKEND_PID=$!
(
  cd frontend
  exec ./node_modules/.bin/vite --host 127.0.0.1
) &
FRONTEND_PID=$!
WORKER_PID=""
if grep -qx 'WEBGUARD_TOOL_EXECUTION_ENABLED=true' backend/.env; then
  (
    cd backend
    exec ../.venv/bin/python -m app.tooling.worker
  ) &
  WORKER_PID=$!
  echo "Tool worker: enabled (external engines still require separate explicit configuration)."
else
  echo "Tool worker: disabled (set WEBGUARD_TOOL_EXECUTION_ENABLED=true after reviewing docs/TOOL_CENTER.md)."
fi
echo "WebGuard UI:  http://127.0.0.1:5173"
echo "WebGuard API: http://127.0.0.1:8000/api/health"
echo "API docs:     http://127.0.0.1:8000/docs"
echo "Pulsa Ctrl+C para detener ambos servicios."
if [[ -n "$WORKER_PID" ]]; then
  wait -n "$BACKEND_PID" "$FRONTEND_PID" "$WORKER_PID"
else
  wait -n "$BACKEND_PID" "$FRONTEND_PID"
fi
