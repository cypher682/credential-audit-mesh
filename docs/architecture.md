# Architecture

## Service shape (v1)

```
src/main.rs          HTTP API + lifecycle
src/credential       schemas, issuance, verification
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
| Credential format | compact signed JSON with JCS canonicalization | easy to audit, no premature W3C VC complexity |
| Revocation | bitstring status list | simple, scalable, privacy-preserving enough for v1 |
| Transparency | append-only Merkle tree with signed tree heads | inclusion + consistency proofs without gossip |
| Offline verification | presentation bundle + signed status list snapshot + freshness window | verifier can work disconnected and reject stale revocation data |

## Security invariants

1. Verification returns the same result for the same (credential, presentation, status snapshot, key set).
2. A revoked credential never verifies as valid after the issuer's revocation epoch.
3. Every authorization decision stores the credential hash, policy version, inputs, and outcome.
4. Key rotation never silently invalidates credentials; each credential names its verification key id.
5. Transparency log entries are append-only; any rewrite is detectable by consistency proof.

## Consistency model

| Domain | Guarantee |
|--------|-----------|
| Credential signing | strong, single-writer per issuer key |
| Revocation visibility | bounded staleness (`freshness_window`) |
| Transparency log | linearizable append per log, externally verifiable |
| Authorization audit | strong, immutable append |
