#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

for command in python3 npm; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Error: no se encontró '$command'. En Arch/CachyOS: sudo pacman -S --needed python python-pip nodejs npm" >&2
    exit 1
  fi
done
python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("WebGuard necesita Python 3.11 o superior.")
PY

[[ -d .venv ]] || python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r backend/requirements.txt -r backend/requirements-dev.txt
python -m pip install -e ./security

if [[ ! -f backend/.env ]]; then
  cp backend/.env.example backend/.env
fi
if grep -q '^WEBGUARD_SECRET_KEY=replace-this-with-a-random-secret-generated-by-setup$' backend/.env; then
  SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(48))')"
  sed -i "s/^WEBGUARD_SECRET_KEY=.*/WEBGUARD_SECRET_KEY=${SECRET}/" backend/.env
  chmod 600 backend/.env
  echo "Se generó una clave secreta aleatoria en backend/.env (no la compartas ni la subas a Git)."
fi
if [[ ! -f frontend/.env.local ]]; then
  cp frontend/.env.example frontend/.env.local
fi

npm --prefix frontend ci --no-audit --no-fund
(
  cd backend
  ../.venv/bin/alembic upgrade head
)

if [[ -t 0 ]]; then
  echo
  read -r -p "¿Crear el primer usuario administrador ahora? [S/n] " answer
  if [[ ! "$answer" =~ ^[Nn]$ ]]; then
    (cd backend && ../.venv/bin/python -m app.cli create-user --role admin)
  fi
fi

echo
echo "Configuración terminada. Ejecuta ./start.sh para iniciar WebGuard."
if [[ ! -t 0 ]]; then
  echo "Para crear un administrador: cd backend && ../.venv/bin/python -m app.cli create-user --role admin"
fi
