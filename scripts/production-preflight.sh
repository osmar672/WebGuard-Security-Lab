#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
FILE=".env.production"
[[ -f "$FILE" ]] || { echo "Falta $FILE. Copia .env.production.example y complétalo." >&2; exit 2; }

fail() { echo "PRECHECK FAILED: $*" >&2; exit 2; }

# Parse a restricted dotenv format. Do not `source` this file: production config must
# never be able to execute shell commands when a deployment helper is run.
declare -A cfg=()
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -z "$line" || "$line" == \#* ]] && continue
  [[ "$line" == *=* ]] || fail "Línea inválida en $FILE. Usa KEY=VALUE sin comillas ni espacios."
  key="${line%%=*}"
  value="${line#*=}"
  [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] || fail "Nombre de variable no válido en $FILE."
  [[ "$value" =~ ^[A-Za-z0-9._,:/+@_~%=-]*$ ]] || fail "Valor con caracteres no permitidos para $key; usa valores sencillos y no incluyas expansiones de shell."
  cfg["$key"]="$value"
done < "$FILE"

mode="$(stat -c '%a' "$FILE")"
[[ "$mode" =~ ^[0-7]{3,4}$ ]] || fail "No se pudieron comprobar los permisos de $FILE."
(( (8#$mode & 077) == 0 )) || fail "$FILE contiene secretos: ejecuta chmod 600 $FILE."

WEBGUARD_DOMAIN="${cfg[WEBGUARD_DOMAIN]:-}"
WEBGUARD_ALLOWED_HOSTS="${cfg[WEBGUARD_ALLOWED_HOSTS]:-}"
WEBGUARD_ENV="${cfg[WEBGUARD_ENV]:-production}"
WEBGUARD_SECRET_KEY="${cfg[WEBGUARD_SECRET_KEY]:-}"
WEBGUARD_ALLOW_LAB_TARGETS="${cfg[WEBGUARD_ALLOW_LAB_TARGETS]:-false}"
POSTGRES_USER="${cfg[POSTGRES_USER]:-}"
POSTGRES_DB="${cfg[POSTGRES_DB]:-}"
POSTGRES_PASSWORD="${cfg[POSTGRES_PASSWORD]:-}"
WEBGUARD_BACKUP_AGE_RECIPIENT="${cfg[WEBGUARD_BACKUP_AGE_RECIPIENT]:-}"
WEBGUARD_CORS_ORIGINS="${cfg[WEBGUARD_CORS_ORIGINS]:-}"
WEBGUARD_ACCESS_TOKEN_TTL_MINUTES="${cfg[WEBGUARD_ACCESS_TOKEN_TTL_MINUTES]:-15}"
WEBGUARD_MAX_REQUEST_BODY_BYTES="${cfg[WEBGUARD_MAX_REQUEST_BODY_BYTES]:-1048576}"
WEBGUARD_MAX_PAGE_SIZE="${cfg[WEBGUARD_MAX_PAGE_SIZE]:-100}"
WEBGUARD_DEFAULT_PAGE_SIZE="${cfg[WEBGUARD_DEFAULT_PAGE_SIZE]:-20}"
WEBGUARD_LOG_LEVEL="${cfg[WEBGUARD_LOG_LEVEL]:-INFO}"
WEBGUARD_AI_BASE_URL="${cfg[WEBGUARD_AI_BASE_URL]:-https://api.groq.com/openai/v1}"
WEBGUARD_AI_API_KEY="${cfg[WEBGUARD_AI_API_KEY]:-}"
WEBGUARD_AI_MODEL="${cfg[WEBGUARD_AI_MODEL]:-openai/gpt-oss-120b}"
WEBGUARD_AI_RATE_LIMIT_REQUESTS="${cfg[WEBGUARD_AI_RATE_LIMIT_REQUESTS]:-10}"

[[ "$WEBGUARD_DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ && "$WEBGUARD_DOMAIN" == *.* ]] || fail "Configura WEBGUARD_DOMAIN con un dominio DNS válido."
[[ "$WEBGUARD_DOMAIN" != "your-domain.example.com" ]] || fail "Configura WEBGUARD_DOMAIN con tu dominio real."
[[ "$WEBGUARD_SECRET_KEY" =~ ^[a-fA-F0-9]{96}$ ]] || fail "WEBGUARD_SECRET_KEY debe contener 48 bytes hexadecimales (openssl rand -hex 48)."
[[ "$POSTGRES_USER" =~ ^[A-Za-z0-9_]{1,63}$ && "$POSTGRES_DB" =~ ^[A-Za-z0-9_]{1,63}$ ]] || fail "POSTGRES_USER y POSTGRES_DB deben contener solo letras, números y guiones bajos."
[[ "$POSTGRES_PASSWORD" =~ ^[a-fA-F0-9]{64}$ ]] || fail "POSTGRES_PASSWORD debe contener 32 bytes hexadecimales (openssl rand -hex 32)."
[[ "$WEBGUARD_BACKUP_AGE_RECIPIENT" =~ ^age1[0-9a-z]+$ ]] || fail "Configura WEBGUARD_BACKUP_AGE_RECIPIENT para habilitar backups cifrados con age."
[[ "$WEBGUARD_LOG_LEVEL" =~ ^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$ ]] || fail "WEBGUARD_LOG_LEVEL debe ser DEBUG, INFO, WARNING, ERROR o CRITICAL."
[[ "$WEBGUARD_ACCESS_TOKEN_TTL_MINUTES" =~ ^[0-9]+$ ]] && (( WEBGUARD_ACCESS_TOKEN_TTL_MINUTES >= 5 && WEBGUARD_ACCESS_TOKEN_TTL_MINUTES <= 60 )) || fail "WEBGUARD_ACCESS_TOKEN_TTL_MINUTES debe estar entre 5 y 60."
[[ "$WEBGUARD_MAX_REQUEST_BODY_BYTES" =~ ^[0-9]+$ ]] && (( WEBGUARD_MAX_REQUEST_BODY_BYTES >= 16384 && WEBGUARD_MAX_REQUEST_BODY_BYTES <= 10485760 )) || fail "WEBGUARD_MAX_REQUEST_BODY_BYTES fuera del rango permitido."
[[ "$WEBGUARD_MAX_PAGE_SIZE" =~ ^[0-9]+$ ]] && (( WEBGUARD_MAX_PAGE_SIZE >= 1 && WEBGUARD_MAX_PAGE_SIZE <= 500 )) || fail "WEBGUARD_MAX_PAGE_SIZE debe estar entre 1 y 500."
[[ "$WEBGUARD_DEFAULT_PAGE_SIZE" =~ ^[0-9]+$ ]] && (( WEBGUARD_DEFAULT_PAGE_SIZE >= 1 && WEBGUARD_DEFAULT_PAGE_SIZE <= 100 )) || fail "WEBGUARD_DEFAULT_PAGE_SIZE debe estar entre 1 y 100."
if [[ -n "$WEBGUARD_CORS_ORIGINS" ]]; then
  IFS=',' read -r -a cors_origins <<< "$WEBGUARD_CORS_ORIGINS"
  for origin in "${cors_origins[@]}"; do
    [[ "$origin" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || fail "Cada WEBGUARD_CORS_ORIGINS debe ser origen HTTPS sin rutas ni espacios."
    [[ "$origin" != *localhost* && "$origin" != *127.0.0.1* ]] || fail "CORS de producción no puede permitir localhost."
    rest="${origin#https://}"
    if [[ "$rest" == *:* ]]; then
      port="${rest##*:}"
      (( 10#$port >= 1 && 10#$port <= 65535 )) || fail "Puerto CORS fuera de rango."
    fi
  done
fi
[[ "$WEBGUARD_ALLOW_LAB_TARGETS" == "false" ]] || fail "WEBGUARD_ALLOW_LAB_TARGETS debe permanecer false en producción."
if [[ -n "$WEBGUARD_AI_API_KEY" ]]; then
  [[ "$WEBGUARD_AI_BASE_URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~%/+:-]*)?$ ]] || fail "Con AI remota habilitada, WEBGUARD_AI_BASE_URL debe ser HTTPS y no incluir credenciales, query o fragmento."
  ai_authority="${WEBGUARD_AI_BASE_URL#https://}"
  ai_authority="${ai_authority%%/*}"
  ai_host="${ai_authority%%:*}"
  [[ "$ai_host" != "localhost" && "$ai_host" != *.localhost && "$ai_host" != *.local && "$ai_host" != *.internal && "$ai_host" != 127.* && "$ai_host" != 10.* && "$ai_host" != 192.168.* ]] || fail "WEBGUARD_AI_BASE_URL no puede apuntar a un destino local o privado."
  [[ ! "$ai_host" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] || fail "WEBGUARD_AI_BASE_URL no puede apuntar a un rango privado 172.16/12."
  [[ "$ai_host" != 169.254.* ]] || fail "WEBGUARD_AI_BASE_URL no puede apuntar a una dirección link-local."
  [[ "$WEBGUARD_AI_RATE_LIMIT_REQUESTS" =~ ^[0-9]+$ ]] && (( WEBGUARD_AI_RATE_LIMIT_REQUESTS >= 1 && WEBGUARD_AI_RATE_LIMIT_REQUESTS <= 100 )) || fail "WEBGUARD_AI_RATE_LIMIT_REQUESTS debe estar entre 1 y 100."
  [[ -n "$WEBGUARD_AI_MODEL" ]] || fail "WEBGUARD_AI_MODEL es obligatorio si AI remota está habilitada."
  if [[ "$ai_authority" == *:* ]]; then
    ai_port="${ai_authority##*:}"
    [[ "$ai_port" =~ ^[0-9]{1,5}$ ]] && (( 10#$ai_port >= 1 && 10#$ai_port <= 65535 )) || fail "Puerto de WEBGUARD_AI_BASE_URL fuera de rango."
  fi
fi
[[ "$WEBGUARD_ENV" == "production" ]] || fail "WEBGUARD_ENV debe ser production."
[[ "$WEBGUARD_ALLOWED_HOSTS" == "$WEBGUARD_DOMAIN" ]] || fail "WEBGUARD_ALLOWED_HOSTS debe contener exactamente el dominio público configurado."
command -v docker >/dev/null 2>&1 || fail "Instala Docker Engine."
docker compose version >/dev/null 2>&1 || fail "Instala Docker Compose v2."
docker compose --env-file "$FILE" -f compose.yaml config --quiet || fail "La configuración de Docker Compose no es válida."
echo "PRECHECK OK: formato de configuración, dominio, secretos y Compose validados."
echo "Esto no valida DNS público, certificados TLS, firewall, backups/restauración ni auditoría externa."
