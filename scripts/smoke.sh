#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

PORT="${PORT:-18083}"
STATE_DIR="$(mktemp -d)"
export PORT
export ISSUER_ID="${ISSUER_ID:-did:mesh:smoke}"
export ISSUER_KEY="${ISSUER_KEY:-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f}"
export LOG_PATH="${LOG_PATH:-$STATE_DIR/transparency.log}"

pid=""
cleanup() {
  if [ -n "$pid" ]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$STATE_DIR"
}
trap cleanup EXIT

cargo build -q
./target/debug/credential-audit-mesh >/tmp/credential-mesh-smoke.log 2>&1 &
pid=$!

for _ in $(seq 1 50); do
  if curl -fsS "http://localhost:$PORT/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

ISSUER=$(curl -fsS "http://localhost:$PORT/v1/issuer")
FIRST=$(curl -fsS -X POST "http://localhost:$PORT/v1/credentials" \
  -H "content-type: application/json" \
  -d '{"subject":"did:mesh:holder","claims":{"role":"supplier","tier":2},"ttl_seconds":60}')
SECOND=$(curl -fsS -X POST "http://localhost:$PORT/v1/credentials" \
  -H "content-type: application/json" \
  -d '{"subject":"did:mesh:holder-2","claims":{"role":"buyer"},"ttl_seconds":60}')

CREDENTIAL=$(printf '%s' "$FIRST" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["credential"]))')
VERIFY_BODY=$(printf '%s' "$CREDENTIAL" | python3 -c 'import json,sys; print(json.dumps({"credential": json.load(sys.stdin)}))')
VERIFIED=$(curl -fsS -X POST "http://localhost:$PORT/v1/credentials/verify" \
  -H "content-type: application/json" \
  -d "$VERIFY_BODY")
HEAD=$(curl -fsS "http://localhost:$PORT/v1/log")
ENTRY=$(curl -fsS "http://localhost:$PORT/v1/log/entries/1")
CONSISTENCY=$(curl -fsS "http://localhost:$PORT/v1/log/consistency?first=1&second=2")

printf '%s\n' "$ISSUER"
printf '%s\n' "$VERIFIED"
printf '%s\n' "$HEAD"

printf '%s' "$ISSUER" | python3 -c 'import json,sys; data=json.load(sys.stdin); assert data["issuer"] and data["public_key"] and data["key_id"]'
printf '%s' "$FIRST" | python3 -c 'import json,sys; data=json.load(sys.stdin); assert data["transparency"]["tree_head"]["tree_size"] == 1 and data["transparency"]["entry"]["index"] == 0'
printf '%s' "$VERIFIED" | python3 -c 'import json,sys; data=json.load(sys.stdin); assert data["valid"] is True and data["subject"] == "did:mesh:holder" and data["claims"]["role"] == "supplier"'
printf '%s' "$SECOND" | python3 -c 'import json,sys; data=json.load(sys.stdin); assert data["transparency"]["tree_head"]["tree_size"] == 2'
printf '%s' "$HEAD" | python3 -c 'import json,sys; data=json.load(sys.stdin); assert data["tree_size"] == 2 and len(data["root_hash"]) > 0 and len(data["signature"]) > 0'
printf '%s' "$ENTRY" | python3 -c 'import json,sys; data=json.load(sys.stdin); assert data["entry"]["index"] == 1 and data["tree_head"]["tree_size"] == 2 and isinstance(data["inclusion_proof"], list)'
printf '%s' "$CONSISTENCY" | python3 -c 'import json,sys; data=json.load(sys.stdin); assert data["first"]["tree_size"] == 1 and data["second"]["tree_size"] == 2 and isinstance(data["proof"], list)'

echo "credential smoke: ok"
