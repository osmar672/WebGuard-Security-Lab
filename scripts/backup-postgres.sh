#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
FILE=".env.production"
[[ -f "$FILE" ]] || { echo "Falta $FILE" >&2; exit 2; }
command -v age >/dev/null 2>&1 || { echo "Instala age para crear backups cifrados (Arch/CachyOS: sudo pacman -S age)." >&2; exit 2; }
RECIPIENT="$(sed -n 's/^WEBGUARD_BACKUP_AGE_RECIPIENT=//p' "$FILE" | head -n1 | tr -d '\r')"
[[ "$RECIPIENT" =~ ^age1[0-9a-z]+$ ]] || { echo "Define WEBGUARD_BACKUP_AGE_RECIPIENT con la clave pública de age en $FILE." >&2; exit 2; }
mkdir -p backups
chmod 700 backups
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="backups/webguard-${STAMP}.sql.gz.age"
# Encrypt the stream before it reaches disk; no plaintext dump is written locally.
docker compose --env-file "$FILE" -f compose.yaml exec -T db \
  sh -ec 'pg_dump --no-owner --no-privileges -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  | gzip -9 \
  | age --recipient "$RECIPIENT" --output "$OUT"
sha256sum "$OUT" > "${OUT}.sha256"
chmod 600 "$OUT" "${OUT}.sha256"
find backups -type f \( -name 'webguard-*.sql.gz.age' -o -name 'webguard-*.sql.gz.age.sha256' \) -mtime +14 -delete
echo "Backup cifrado creado: $OUT"
echo "Almacena una copia cifrada fuera del servidor y prueba la restauración periódicamente."
