# API Reference

Base path: `/v1`. The service is stateless for verification: credentials are self-contained signed JSON. Issuance also appends a privacy-preserving entry to an append-only transparency log and returns an inclusion proof.

## Audit console

`GET /` serves an embedded HTML console with `GET /ui/styles.css`, `GET /ui/app.js`, and `GET /ui/favicon.svg`. It is plain HTML/CSS/JS: no build pipeline, package manager, or third-party assets. The console issues and verifies credentials, lists recent log entries, fetches inclusion and consistency proofs, recomputes inclusion paths with WebCrypto SHA-256, and verifies the Ed25519 tree-head signature when the browser supports it.

The console and all three asset routes send `Content-Security-Policy: default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`, plus `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store`. The console has no authentication and inherits the deployment boundary of the issuance API.

## Errors

```json
{"error":{"code":"invalid_subject","message":"subject must be 1-256 characters"}}
```

| Status | Code | Meaning |
|--------|------|---------|
| 400 | `invalid_json` | body is not valid JSON or has unknown fields |
| 400 | `invalid_subject` | subject is empty or longer than 256 characters |
| 400 | `invalid_ttl` | TTL is outside 1 second to 30 days |
| 400 | `too_many_claims` | more than 64 claim entries |
| 400 | `invalid_range` | consistency range is reversed or exceeds the tree |
| 404 | `not_found` | log entry does not exist |
| 500 | `clock` | system clock is before the Unix epoch |
| 500 | `log_unavailable` | transparency log is locked or cannot be written |
| 500 | `signing_failed` | tree head could not be signed |

## GET /healthz, GET /readyz

Liveness and readiness. Both return `200` with service name and version.

## GET /v1/issuer

```json
{
  "issuer": "did:mesh:issuer",
  "algorithm": "Ed25519",
  "key_id": "q3b0m...",
  "public_key": "9xQ..."
}
```

`public_key` is the raw 32-byte Ed25519 public key in unpadded base64url. `key_id` is the first 12 bytes of `SHA-256(public_key)` in unpadded base64url.

## POST /v1/credentials

```json
{
  "subject": "did:mesh:holder-1",
  "claims": {"role": "supplier", "tier": 2},
  "ttl_seconds": 3600
}
```

`claims` defaults to `{}`; `ttl_seconds` defaults to 3600 and must be between 1 and 2592000. Returns `201` with the credential and its transparency record:

```json
{
  "credential": {
    "version": 1,
    "issuer": "did:mesh:issuer",
    "subject": "did:mesh:holder-1",
    "claims": {"role": "supplier", "tier": 2},
    "issued_at": 1792590000,
    "expires_at": 1792593600,
    "key_id": "q3b0m...",
    "signature": "5Kd..."
  },
  "transparency": {
    "entry": {
      "index": 0,
      "credential_hash": "2fM...",
      "issuer": "did:mesh:issuer",
      "subject_hash": "V8q...",
      "issued_at": 1792590000,
      "expires_at": 1792593600,
      "key_id": "q3b0m..."
    },
    "leaf_hash": "wJc...",
    "inclusion_proof": [],
    "tree_head": {
      "tree_size": 1,
      "root_hash": "wJc...",
      "key_id": "q3b0m...",
      "signature": "X9..."
    }
  }
}
```

`signature` is Ed25519 over the RFC 8785 (JCS) canonical bytes of all credential fields except `signature`, encoded as unpadded base64url. The log stores hashes of the credential and subject, not claims.

The issuance endpoint has no operator authentication in v0.2. Do not expose it to untrusted networks; run it behind your control plane.

## POST /v1/credentials/verify

```json
{"credential": {"version": 1, "...": "..."}}
```

Verification is deterministic for a credential and the current clock. A valid credential returns `200`:

```json
{
  "valid": true,
  "issuer": "did:mesh:issuer",
  "subject": "did:mesh:holder-1",
  "claims": {"role": "supplier", "tier": 2},
  "issued_at": 1792590000,
  "expires_at": 1792593600,
  "key_id": "q3b0m..."
}
```

An invalid credential still returns `200` so callers get a structured reason:

```json
{"valid":false,"code":"invalid_signature","reason":"credential signature is invalid"}
```

Invalid codes: `invalid_credential`, `unsupported_version`, `unknown_issuer`, `unknown_key`, `invalid_signature`, `expired`, `not_yet_valid`.

## GET /v1/log

Returns the signed tree head:

```json
{
  "tree_size": 3,
  "root_hash": "kL2...",
  "key_id": "q3b0m...",
  "signature": "R4..."
}
```

`signature` covers the JCS canonical bytes of `{"tree_size":3,"root_hash":"kL2..."}`. The empty tree has size `0` and root `SHA-256("")`.

## GET /v1/log/entries/{index}

Returns the entry plus a proof against the current tree head:

```json
{
  "entry": {
    "index": 1,
    "credential_hash": "2fM...",
    "issuer": "did:mesh:issuer",
    "subject_hash": "V8q...",
    "issued_at": 1792590005,
    "expires_at": 1792593605,
    "key_id": "q3b0m..."
  },
  "leaf_hash": "dQ1...",
  "inclusion_proof": ["wJc...", "8aP..."],
  "tree_head": {
    "tree_size": 3,
    "root_hash": "kL2...",
    "key_id": "q3b0m...",
    "signature": "R4..."
  }
}
```

Unknown indexes return `404`.

## GET /v1/log/consistency?first=1&second=3

Returns a proof that the tree of size `first` is a prefix of the tree of size `second`:

```json
{
  "first": {"tree_size": 1, "root_hash": "wJc..."},
  "second": {
    "tree_size": 3,
    "root_hash": "kL2...",
    "key_id": "q3b0m...",
    "signature": "R4..."
  },
  "proof": ["8aP...", "N01..."]
}
```

The first root is supplied by the caller from a previously trusted signed head. The second head is signed by the current issuer key. A `first` of `0` yields an empty proof.

## Browser verification notes

The console's local check does not trust `/v1/log/entries/{index}` for the proof result. It parses the returned entry, canonicalizes it as JCS, computes the RFC 6962 leaf and root hashes with WebCrypto SHA-256, and compares the result to the signed tree head. It then imports the raw Ed25519 key from `/v1/issuer` and verifies the head signature over `{"tree_size":...,"root_hash":...}`. Browsers without Ed25519 in WebCrypto still get local inclusion verification, with an explicit warning that the signature was not checked.

## Merkle construction

Entries use RFC 6962-style domain-separated hashing:

- leaf data is the JCS canonical form of the log entry;
- `leaf_hash = SHA-256(0x00 || leaf_data)`;
- `node_hash = SHA-256(0x01 || left || right)`;
- the empty tree root is `SHA-256("")`.

Inclusion paths and consistency proofs follow the RFC 6962 tree layout, so proofs are `O(log n)`. Clients can validate proofs locally with the public key from `GET /v1/issuer`; the service does not need to be online for that check.
