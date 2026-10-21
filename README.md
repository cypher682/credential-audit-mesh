# Enterprise Credential, Authorization & Audit Mesh

Identity, credential, authorization, and audit layer for B2B networks: signed credentials, selective disclosure, scalable revocation, transparency log, and attributable authorization decisions.

## Status

v0.2: Ed25519 credential issuance and deterministic verification over HTTP, backed by an append-only transparency log with signed tree heads, inclusion proofs, and prefix-consistency proofs. A built-in audit console at `/` exercises the full flow and verifies inclusion locally in the browser. Revocation, selective disclosure, and authorization are not implemented yet.

| Stage | Scope | State |
|-------|-------|-------|
| 0 | Service skeleton, config, health, CI-ready build | done |
| 1 | Signed credential issuance + verification | done |
| 2 | Transparency log + inclusion proofs | done |
| 3 | Revocation + verification integration | planned |
| 4 | Selective disclosure / predicates | planned |
| 5 | Authorization engine + audit records | planned |
| 6 | Offline presentation packages + freshness | planned |
| 7 | Key rotation / recovery | planned |
| 8 | Multi-issuer simulation + hardening | planned |

## Documents

- [Architecture](docs/architecture.md)
- [API reference](docs/api.md)

## Quick start

```sh
export ISSUER_ID=did:mesh:issuer
export ISSUER_KEY=$(openssl rand -hex 32)
cargo run
```

Open `http://localhost:8083` for the audit console. Without `ISSUER_KEY` the service generates an ephemeral key and logs a warning; issued credentials stop verifying after restart. The transparency log is appended to `LOG_PATH` (default `data/transparency.log`) and reloaded on startup. Configuration is environment-based; see `.env.example`.

```sh
curl localhost:8083/healthz
curl localhost:8083/v1/issuer

curl -sX POST localhost:8083/v1/credentials \
  -H 'content-type: application/json' \
  -d '{"subject":"did:mesh:holder-1","claims":{"role":"supplier"},"ttl_seconds":600}'
```

Send the returned `credential` object back as `{"credential": ...}` to `POST /v1/credentials/verify`. The response also contains a transparency entry, inclusion proof, and signed tree head. Current heads and historical proofs are available from `/v1/log`.

## What works

- Ed25519 issuance with issuer identity, key id, subject, claims, issue time, and expiry.
- RFC 8785 canonical payloads, so JSON key order and whitespace do not affect verification.
- Verification rejects tampering, unknown issuers or keys, future-issued credentials, and expired credentials.
- TTL limits (1 second to 30 days), subject validation, and a 64-claim cap.
- Public key discovery through `GET /v1/issuer`.
- Append-only, durable transparency log with hashed subject and credential entries.
- Signed tree heads, `O(log n)` inclusion proofs, and prefix-consistency proofs.
- Public key discovery and local proof verification without trusting the service at query time.
- Embedded browser console: issue and verify credentials, inspect recent entries, check inclusion proofs locally with WebCrypto, verify tree-head signatures, and request consistency proofs. No build step or third-party assets.

## Limits

- No revocation, selective disclosure, or authorization decisions yet.
- One active issuer key per process. `ISSUER_KEY` is required for credentials that survive restart.
- The log is a single-writer JSONL file. There is no replica gossip, witness cosigning, or multi-writer coordination.
- Claims are not logged. Only credential and subject hashes are published, so the log cannot resolve a holder without the credential.
- The issuance endpoint and the console are unauthenticated. Keep both behind an operator-controlled network boundary.
- Verification trusts the configured issuer identity and key id; multi-issuer key resolution comes later.

## Layout

```
src/main.rs        service entrypoint and issuer setup
src/api.rs         HTTP API
src/credential.rs  signing, canonicalization, verification
src/transparency.rs Merkle log, inclusion and consistency proofs
src/ui.rs          embedded audit console and static assets
src/config.rs      env config
src/health.rs      liveness/readiness
ui                 HTML, CSS, and browser verification logic
docs               architecture and API reference
deploy             local dependencies (Postgres)
migrations         schema migrations
```

## Development

```sh
make test
make clippy
make fmt
./scripts/smoke.sh
```
