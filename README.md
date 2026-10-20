# Enterprise Credential, Authorization & Audit Mesh

Identity, credential, authorization, and audit layer for B2B networks: signed credentials, selective disclosure, scalable revocation, transparency log, and attributable authorization decisions.

## Status

Scaffold. Issuance, verification, revocation, transparency log, and authorization are not implemented yet.

| Stage | Scope | State |
|-------|-------|-------|
| 0 | Service skeleton, config, health, CI-ready build | done |
| 1 | Signed credential issuance + verification | next |
| 2 | Transparency log + inclusion proofs | planned |
| 3 | Revocation + verification integration | planned |
| 4 | Selective disclosure / predicates | planned |
| 5 | Authorization engine + audit records | planned |
| 6 | Offline presentation packages + freshness | planned |
| 7 | Key rotation / recovery | planned |
| 8 | Multi-issuer simulation + hardening | planned |

## Documents

- [Architecture](docs/architecture.md)

## Quick start

```sh
cargo test
cargo run
curl localhost:8083/healthz
```

Configuration is environment-based; see `.env.example`.

## Layout

```
src/main.rs        service entrypoint
src/config.rs      env config
src/health.rs      liveness/readiness
src/lib.rs         library surface
docs               architecture and decisions
deploy             local dependencies (Postgres)
migrations         schema migrations
```
