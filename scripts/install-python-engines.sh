#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHON="$ROOT/.venv/bin/python"
[[ -x "$PYTHON" ]] || { echo "Run ./setup.sh first." >&2; exit 2; }
"$PYTHON" -m pip install -r backend/requirements-tools.txt
PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}" "$PYTHON" -m playwright install chromium
cat <<'MSG'
Optional Python engines installed: Playwright/Chromium, Schemathesis, Semgrep.
This does NOT install Nuclei, k6, Trivy, Gitleaks, testssl.sh, or a dedicated ZAP server.
Install those from their official vendor documentation in docs/TOOL_CENTER.md, then ensure the binaries are on PATH.
Do not enable external engines until an outbound network policy blocks loopback/private/link-local/reserved/metadata destinations.
MSG
