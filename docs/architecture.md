# Architecture

## Service shape

Implemented in v0.2:

```
src/main.rs          service lifecycle, issuer setup, log recovery
src/api.rs           issuer, issuance, verification, and log endpoints
src/credential.rs    Ed25519 signatures, canonical payloads, verification
src/transparency.rs  append-only Merkle log, journal, proofs
src/ui.rs            embedded audit console and static assets
src/config.rs        env config
src/health.rs        liveness/readiness
ui/                  browser console: HTML, CSS, WebCrypto verification
```

Planned:

```
src/revocation       status list / accumulator
src/authorization    policy evaluation + audit record
src/keys             key hierarchy + rotation
```

## Cryptographic decisions

| Concern | v1 choice | Rationale |
|---------|-----------|-----------|
| Signatures | ed25519 | small keys, deterministic verification, well-reviewed Rust crates |
| Credential format | compact signed JSON, RFC 8785 JCS payload | easy to audit, deterministic, no premature W3C VC complexity |
| Revocation | bitstring status list | simple, scalable, privacy-preserving enough for v1 |
| Transparency | append-only Merkle tree with signed tree heads | inclusion + consistency proofs without gossip |
| Offline verification | presentation bundle + signed status list snapshot + freshness window | verifier can work disconnected and reject stale revocation data |

## Credential format

A credential is a versioned JSON object with `issuer`, `subject`, `claims`, `issued_at`, `expires_at`, `key_id`, and `signature`. Timestamps are Unix seconds. The signature covers the RFC 8785 canonical bytes of every other field, so reordering JSON keys or reformatting whitespace does not change the signature.

The issuer derives `key_id` from the first 12 bytes of `SHA-256(public_key)` and exposes the raw public key at `GET /v1/issuer`. `CredentialVerifier` can verify with only that public key, without holding issuer key material. Verification rejects unknown issuers, unknown key ids, signatures from another key, future-issued credentials, and credentials at or past `expires_at`.

Key material comes from `ISSUER_KEY` (32 bytes as hex or base64). If it is unset the service generates an ephemeral key at startup and logs a warning, which is useful for local demos but invalidates credentials on restart.

## Transparency log (v0.2)

Issuance produces a `LogEntry` containing the entry index, full credential hash, issuer, subject hash, issue/expiry times, and key id. Claims are never written to the log, and the subject is hashed.

The log uses RFC 6962-style Merkle hashing: leaf data is the JCS canonical entry, `leaf_hash = SHA-256(0x00 || leaf_data)`, and `node_hash = SHA-256(0x01 || left || right)`. The empty root is `SHA-256("")`. Inclusion and consistency proofs are `O(log n)`.

Every tree head is signed with the issuer key over the JCS bytes of `{tree_size, root_hash}`. A verifier can pin a signed head, fetch a later head, and use a consistency proof to show that the earlier history is a prefix of the later one. Inclusion proofs bind a credential to a signed head without revealing claims.

Entries are appended to a JSONL journal before they become visible in memory. On startup the journal is replayed, every index must be contiguous, and roots are rebuilt. A failed journal write rejects the issuance response rather than returning an unlogged credential. The journal is single-writer and not replicated; gossip is out of scope for v0.2.

## Audit console

`GET /` serves an operator and auditor console embedded into the binary with `include_str!`. It uses no frontend framework, build step, or external assets. The browser calls the same public API as any other client: `/v1/issuer`, `/v1/credentials`, `/v1/credentials/verify`, `/v1/log`, and the proof endpoints.

Local proof checking is deliberately independent of server responses: the console canonicalizes the entry as JCS, rebuilds the RFC 6962 inclusion path with WebCrypto SHA-256, compares the root to the signed head, and verifies the Ed25519 head signature when WebCrypto exposes Ed25519. This gives the operator a second implementation of the proof logic and demonstrates that trusting the service at query time is unnecessary. Asset responses are locked down with a restrictive CSP, `nosniff`, `no-referrer`, and `no-store`.

## Security invariants

1. Verification returns the same result for the same (credential, presentation, status snapshot, key set).
2. A revoked credential never verifies as valid after the issuer's revocation epoch.
3. Every authorization decision stores the credential hash, policy version, inputs, and outcome.
4. Key rotation never silently invalidates credentials; each credential names its verification key id.
5. Transparency log entries are append-only; any rewrite is detectable by consistency proof.

Invariant 5 is implemented for single-writer logs: any rewrite of a journaled entry changes its root and fails consistency with a previously trusted head. An operator who rewrites both the journal and every retained head can still equivocate; witness cosigning is a later hardening step. Invariants 2 and 3 describe target behavior; v0.2 does not yet implement revocation or authorization audit.

## v0.2 boundaries

- One active issuer key and one issuer identity per process. Rotation and key history are stage 7.
- Credentials are stateless, but issuance goes through the transparency journal and the log is replayed on startup.
- The log is a single-writer local file. It has no replication, gossip, witness signatures, or multi-writer fencing.
- The issuance endpoint and the audit console are unauthenticated; both must run behind an operator-controlled network boundary.
- Claims are opaque JSON values and are not logged. Schema validation and selective disclosure are later stages.

## Consistency model

| Domain | Guarantee |
|--------|-----------|
| Credential signing | strong, single-writer per issuer key |
| Credential verification | deterministic for a credential, key set, and clock |
| Revocation visibility | bounded staleness (`freshness_window`) |
| Transparency log | durable single-writer append, externally verifiable inclusion and consistency |
| Authorization audit | strong, immutable append |
