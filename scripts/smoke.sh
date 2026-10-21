#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

PORT="${PORT:-18083}"
export PORT
export ISSUER_ID="${ISSUER_ID:-did:mesh:smoke}"
export ISSUER_KEY="${ISSUER_KEY:-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f}"

cargo build -q
./target/debug/credential-audit-mesh >/tmp/credential-mesh-smoke.log 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
  if curl -fsS "http://localhost:$PORT/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

ISSUER=$(curl -fsS "http://localhost:$PORT/v1/issuer")
CREDENTIAL=$(curl -fsS -X POST "http://localhost:$PORT/v1/credentials" \
  -H "content-type: application/json" \
  -d '{"subject":"did:mesh:holder","claims":{"role":"supplier","tier":2},"ttl_seconds":60}')
VERIFY_BODY=$(printf '%s' "$CREDENTIAL" | python3 -c 'import json,sys; print(json.dumps({"credential": json.load(sys.stdin)}))')
VERIFIED=$(curl -fsS -X POST "http://localhost:$PORT/v1/credentials/verify" \
  -H "content-type: application/json" \
  -d "$VERIFY_BODY")

printf '%s\n' "$ISSUER"
printf '%s\n' "$VERIFIED"

printf '%s' "$ISSUER" | python3 -c 'import json,sys; data=json.load(sys.stdin); assert data["issuer"] and data["public_key"] and data["key_id"]'
printf '%s' "$VERIFIED" | python3 -c 'import json,sys; data=json.load(sys.stdin); assert data["valid"] is True and data["subject"] == "did:mesh:holder" and data["claims"]["role"] == "supplier"'

echo "credential smoke: ok"
