# Architecture

## Service shape

Implemented in v0.1:

```
src/main.rs          service lifecycle and issuer setup
src/api.rs           issuer, issuance, and verification endpoints
src/credential.rs    Ed25519 signatures, canonical payloads, verification
src/config.rs        env config
src/health.rs        liveness/readiness
```

Planned:

```
src/revocation       status list / accumulator
src/translog         append-only log + proofs
src/authorization    policy evaluation + audit record
src/keys             key hierarchy + rotation
src/store            persistence
```

## Cryptographic decisions

| Concern | v1 choice | Rationale |
|---------|-----------|-----------|
| Signatures | ed25519 | small keys, deterministic verification, well-reviewed Rust crates |
| Credential format | compact signed JSON, RFC 8785 JCS payload | easy to audit, deterministic, no premature W3C VC complexity |
| Revocation | bitstring status list | simple, scalable, privacy-preserving enough for v1 |
| Transparency | append-only Merkle tree with signed tree heads | inclusion + consistency proofs without gossip |
| Offline verification | presentation bundle + signed status list snapshot + freshness window | verifier can work disconnected and reject stale revocation data |

## Credential format (v0.1)

A credential is a versioned JSON object with `issuer`, `subject`, `claims`, `issued_at`, `expires_at`, `key_id`, and `signature`. Timestamps are Unix seconds. The signature covers the RFC 8785 canonical bytes of every other field, so reordering JSON keys or reformatting whitespace does not change the signature.

The issuer derives `key_id` from the first 12 bytes of `SHA-256(public_key)` and exposes the raw public key at `GET /v1/issuer`. `CredentialVerifier` can verify with only that public key, without holding issuer key material. Verification rejects unknown issuers, unknown key ids, signatures from another key, future-issued credentials, and credentials at or past `expires_at`.

Key material comes from `ISSUER_KEY` (32 bytes as hex or base64). If it is unset the service generates an ephemeral key at startup and logs a warning, which is useful for local demos but invalidates credentials on restart.

## Security invariants

1. Verification returns the same result for the same (credential, presentation, status snapshot, key set).
2. A revoked credential never verifies as valid after the issuer's revocation epoch.
3. Every authorization decision stores the credential hash, policy version, inputs, and outcome.
4. Key rotation never silently invalidates credentials; each credential names its verification key id.
5. Transparency log entries are append-only; any rewrite is detectable by consistency proof.

Invariants 2, 3, and 5 describe target behavior; v0.1 does not yet implement revocation, authorization audit, or the transparency log.

## v0.1 boundaries

- One active issuer key and one issuer identity per process. Rotation and key history are stage 7.
- Credentials are stateless. There is no persistence, issuance audit, revocation, or transparency proof yet.
- The issuance endpoint is unauthenticated; it must run behind an operator-controlled network boundary.
- Claims are opaque JSON values. Schema validation and selective disclosure are later stages.

## Consistency model

| Domain | Guarantee |
|--------|-----------|
| Credential signing | strong, single-writer per issuer key |
| Credential verification | deterministic for a credential, key set, and clock |
| Revocation visibility | bounded staleness (`freshness_window`) |
| Transparency log | linearizable append per log, externally verifiable |
| Authorization audit | strong, immutable append |
