# API Reference

Base path: `/v1`. The service is stateless: credentials are self-contained signed JSON, and verification only needs the issuer's public key.

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
| 500 | `clock` | system clock is before the Unix epoch |

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

`claims` defaults to `{}`; `ttl_seconds` defaults to 3600 and must be between 1 and 2592000. Returns `201` with the signed credential:

```json
{
  "version": 1,
  "issuer": "did:mesh:issuer",
  "subject": "did:mesh:holder-1",
  "claims": {"role": "supplier", "tier": 2},
  "issued_at": 1792590000,
  "expires_at": 1792593600,
  "key_id": "q3b0m...",
  "signature": "5Kd..."
}
```

`signature` is Ed25519 over the RFC 8785 (JCS) canonical bytes of all fields except `signature`, encoded as unpadded base64url.

The issuance endpoint has no operator authentication in v0.1. Do not expose it to untrusted networks; run it behind your control plane.

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
