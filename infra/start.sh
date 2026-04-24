#!/usr/bin/env bash
# infra/start.sh — Infrastructure bootstrap
# Starts: Garage → sqld (wrapped by Litestream)
# The application itself must be started manually (e.g., cargo run).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# ── Load environment ──────────────────────────────────────────────────────────
if [[ -f "$ROOT_DIR/.env" ]]; then
  # shellcheck disable=SC2046
  export $(grep -v '^#' "$ROOT_DIR/.env" | xargs)
fi

: "${JWT_SECRET:?JWT_SECRET must be set}"
: "${GARAGE_ACCESS_KEY_ID:?GARAGE_ACCESS_KEY_ID must be set}"
: "${GARAGE_SECRET_ACCESS_KEY:?GARAGE_SECRET_ACCESS_KEY must be set}"

SQLD_DB_PATH="${SQLD_DB_PATH:-/var/lib/sqld/pqwaas.db}"
SQLD_ADDR="${SQLD_ADDR:-0.0.0.0:8080}"

# ── 1. Garage S3 ──────────────────────────────────────────────────────────────
echo "▶ Starting Garage S3 object store…"
garage -c "$SCRIPT_DIR/garage.toml" server &
GARAGE_PID=$!

until curl -sf http://127.0.0.1:3900/ &>/dev/null; do
  echo "  Waiting for Garage…"; sleep 1
done
echo "  Garage ready (PID $GARAGE_PID)"

# One-time bucket + key setup (idempotent — fails silently if already exists)
garage -c "$SCRIPT_DIR/garage.toml" bucket create pqwaas-db-backups 2>/dev/null || true

# ── 2. sqld under Litestream supervision ─────────────────────────────────────
echo "▶ Starting sqld via Litestream (WAL → Garage)…"
mkdir -p "$(dirname "$SQLD_DB_PATH")"

litestream replicate -config "$SCRIPT_DIR/litestream.yml" \
  -- sqld \
       --db-path "$SQLD_DB_PATH" \
       --http-listen-addr "$SQLD_ADDR" &
SQLD_PID=$!

until curl -sf "http://${SQLD_ADDR}/health" &>/dev/null; do
  echo "  Waiting for sqld…"; sleep 0.5
done
echo "  sqld ready (PID $SQLD_PID)"

# ── Wait & Supervision ────────────────────────────────────────────────────────
echo ""
echo "✅ Infrastructure layer is running locally."
echo "▶ You can now run the native application in another terminal:"
echo "    export SQLD_URL=\"http://${SQLD_ADDR}\""
echo "    export SQLD_TOKEN=\"${SQLD_TOKEN:-}\""
echo "    cargo run"
echo ""
echo "Press Ctrl+C to stop the infrastructure."

trap "echo 'Stopping infrastructure...'; kill $SQLD_PID $GARAGE_PID 2>/dev/null" EXIT

# Wait for background processes to exit or user interrupt
wait -n $SQLD_PID $GARAGE_PID || true
