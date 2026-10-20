#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHON="$ROOT/.venv/bin/python"
command_status() {
  local name="$1" command_name="$2"
  if command -v "$command_name" >/dev/null 2>&1; then printf 'AVAILABLE\t%s\t%s\n' "$name" "$(command -v "$command_name")"; else printf 'MISSING\t%s\t%s\n' "$name" "$command_name"; fi
}
echo -e "STATUS\tENGINE\tDETAIL"
command_status "Nuclei" "nuclei"
command_status "k6" "k6"
command_status "Trivy" "trivy"
command_status "Gitleaks" "gitleaks"
command_status "testssl.sh" "testssl.sh"
command_status "Semgrep" "semgrep"
command_status "Schemathesis" "schemathesis"
if "$PYTHON" -c 'import playwright' >/dev/null 2>&1; then echo -e "AVAILABLE\tPlaywright Python\tinstalled"; else echo -e "MISSING\tPlaywright Python\tinstall with scripts/install-python-engines.sh"; fi
if command -v curl >/dev/null 2>&1; then echo -e "AVAILABLE\tcurl\t$(command -v curl)"; else echo -e "MISSING\tcurl\tcurl"; fi
if [[ -f backend/.env ]] && grep -qx 'WEBGUARD_TOOL_EXECUTION_ENABLED=true' backend/.env; then echo "NOTE: queue worker configured to start when ./start.sh runs."; else echo "NOTE: tool execution remains disabled by default."; fi
