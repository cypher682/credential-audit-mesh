use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const CREDENTIAL_VERSION: u8 = 1;
const MAX_SUBJECT_LENGTH: usize = 256;
const MAX_CLAIMS: usize = 64;
const DEFAULT_TTL_SECONDS: i64 = 3600;
const MAX_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    Malformed(String),
    UnsupportedVersion(u8),
    InvalidSubject,
    InvalidTTL,
    TooManyClaims,
    UnknownIssuer,
    UnknownKey,
    InvalidSignature,
    Expired,
    NotYetValid,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(message) => write!(f, "malformed credential: {message}"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported credential version {version}")
            }
            Self::InvalidSubject => write!(f, "subject must be 1-{MAX_SUBJECT_LENGTH} characters"),
            Self::InvalidTTL => write!(f, "ttl_seconds must be between 1 and {MAX_TTL_SECONDS}"),
            Self::TooManyClaims => write!(f, "claims must contain at most {MAX_CLAIMS} entries"),
            Self::UnknownIssuer => write!(f, "credential issuer is not trusted"),
            Self::UnknownKey => write!(f, "credential key id is not known"),
            Self::InvalidSignature => write!(f, "credential signature is invalid"),
            Self::Expired => write!(f, "credential has expired"),
            Self::NotYetValid => write!(f, "credential is not valid yet"),
        }
    }
}

impl std::error::Error for CredentialError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub version: u8,
    pub issuer: String,
    pub subject: String,
    #[serde(default)]
    pub claims: BTreeMap<String, Value>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub key_id: String,
    pub signature: String,
}

#[derive(Serialize)]
struct SigningPayload<'a> {
    version: u8,
    issuer: &'a str,
    subject: &'a str,
    claims: &'a BTreeMap<String, Value>,
    issued_at: i64,
    expires_at: i64,
    key_id: &'a str,
}

impl Credential {
    fn signing_payload(&self) -> Result<Vec<u8>, CredentialError> {
        serde_jcs::to_vec(&SigningPayload {
            version: self.version,
            issuer: &self.issuer,
            subject: &self.subject,
            claims: &self.claims,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            key_id: &self.key_id,
        })
        .map_err(|err| CredentialError::Malformed(err.to_string()))
    }

    pub fn digest(&self) -> Result<String, CredentialError> {
        let bytes =
            serde_jcs::to_vec(self).map_err(|err| CredentialError::Malformed(err.to_string()))?;
        Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Verification {
    pub issuer: String,
    pub subject: String,
    pub claims: BTreeMap<String, Value>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub key_id: String,
}

#[derive(Clone)]
pub struct Issuer {
    id: String,
    signing_key: SigningKey,
    key_id: String,
    public_key: String,
}

impl fmt::Debug for Issuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Issuer")
            .field("id", &self.id)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl Issuer {
    pub fn from_seed(id: impl Into<String>, seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        let digest = Sha256::digest(verifying_key.as_bytes());
        let key_id = URL_SAFE_NO_PAD.encode(&digest[..12]);
        let public_key = URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());
        Self {
            id: id.into(),
            signing_key,
            key_id,
            public_key,
        }
    }

    pub fn from_encoded_seed(id: impl Into<String>, encoded: &str) -> Result<Self, String> {
        let encoded = encoded.trim();
        let seed = if encoded.len() == 64 && encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
            let mut seed = [0u8; 32];
            for (index, chunk) in encoded.as_bytes().chunks_exact(2).enumerate() {
                let text = std::str::from_utf8(chunk).map_err(|_| "invalid hex key".to_string())?;
                seed[index] =
                    u8::from_str_radix(text, 16).map_err(|_| "invalid hex key".to_string())?;
            }
            seed
        } else {
            URL_SAFE_NO_PAD
                .decode(encoded)
                .or_else(|_| URL_SAFE.decode(encoded))
                .or_else(|_| STANDARD_NO_PAD.decode(encoded))
                .or_else(|_| STANDARD.decode(encoded))
                .map_err(|_| "issuer key must be 32 bytes as hex or base64".to_string())?
                .try_into()
                .map_err(|_| "issuer key must be 32 bytes".to_string())?
        };
        Ok(Self::from_seed(id, &seed))
    }

    pub fn generate(id: impl Into<String>) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let digest = Sha256::digest(verifying_key.as_bytes());
        let key_id = URL_SAFE_NO_PAD.encode(&digest[..12]);
        let public_key = URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());
        Self {
            id: id.into(),
            signing_key,
            key_id,
            public_key,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    pub fn verifier(&self) -> CredentialVerifier {
        CredentialVerifier {
            issuer: self.id.clone(),
            key_id: self.key_id.clone(),
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    pub fn sign_jcs<T: Serialize>(&self, value: &T) -> Result<String, CredentialError> {
        let payload =
            serde_jcs::to_vec(value).map_err(|err| CredentialError::Malformed(err.to_string()))?;
        Ok(URL_SAFE_NO_PAD.encode(self.signing_key.sign(&payload).to_bytes()))
    }

    pub fn issue(
        &self,
        subject: impl AsRef<str>,
        claims: BTreeMap<String, Value>,
        ttl_seconds: Option<i64>,
    ) -> Result<Credential, CredentialError> {
        self.issue_at(subject, claims, ttl_seconds, unix_now())
    }

    pub fn issue_at(
        &self,
        subject: impl AsRef<str>,
        claims: BTreeMap<String, Value>,
        ttl_seconds: Option<i64>,
        now: i64,
    ) -> Result<Credential, CredentialError> {
        let subject = subject.as_ref().trim();
        if subject.is_empty() || subject.chars().count() > MAX_SUBJECT_LENGTH {
            return Err(CredentialError::InvalidSubject);
        }
        if claims.len() > MAX_CLAIMS {
            return Err(CredentialError::TooManyClaims);
        }
        let ttl = ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
        if !(1..=MAX_TTL_SECONDS).contains(&ttl) {
            return Err(CredentialError::InvalidTTL);
        }
        let expires_at = now.checked_add(ttl).ok_or(CredentialError::InvalidTTL)?;

        let mut credential = Credential {
            version: CREDENTIAL_VERSION,
            issuer: self.id.clone(),
            subject: subject.to_string(),
            claims,
            issued_at: now,
            expires_at,
            key_id: self.key_id.clone(),
            signature: String::new(),
        };
        let payload = credential.signing_payload()?;
        credential.signature = URL_SAFE_NO_PAD.encode(self.signing_key.sign(&payload).to_bytes());
        Ok(credential)
    }

    pub fn verify(
        &self,
        credential: &Credential,
        now: i64,
    ) -> Result<Verification, CredentialError> {
        self.verifier().verify(credential, now)
    }
}

#[derive(Clone)]
pub struct CredentialVerifier {
    issuer: String,
    key_id: String,
    verifying_key: VerifyingKey,
}

impl CredentialVerifier {
    pub fn from_public_key(issuer: impl Into<String>, encoded: &str) -> Result<Self, String> {
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded.trim())
            .or_else(|_| URL_SAFE.decode(encoded.trim()))
            .map_err(|_| "public key must be base64url".to_string())?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "public key must be 32 bytes".to_string())?;
        let verifying_key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| "invalid Ed25519 public key".to_string())?;
        let digest = Sha256::digest(verifying_key.as_bytes());
        let key_id = URL_SAFE_NO_PAD.encode(&digest[..12]);
        Ok(Self {
            issuer: issuer.into(),
            key_id,
            verifying_key,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn verify_jcs<T: Serialize>(
        &self,
        value: &T,
        signature: &str,
    ) -> Result<(), CredentialError> {
        let payload =
            serde_jcs::to_vec(value).map_err(|err| CredentialError::Malformed(err.to_string()))?;
        let signature = decode_signature(signature)?;
        self.verifying_key
            .verify(&payload, &signature)
            .map_err(|_| CredentialError::InvalidSignature)
    }

    pub fn verify(
        &self,
        credential: &Credential,
        now: i64,
    ) -> Result<Verification, CredentialError> {
        if credential.version != CREDENTIAL_VERSION {
            return Err(CredentialError::UnsupportedVersion(credential.version));
        }
        if credential.issuer != self.issuer {
            return Err(CredentialError::UnknownIssuer);
        }
        if credential.key_id != self.key_id {
            return Err(CredentialError::UnknownKey);
        }
        if credential.issued_at > now {
            return Err(CredentialError::NotYetValid);
        }
        if credential.expires_at <= now {
            return Err(CredentialError::Expired);
        }

        let signature = decode_signature(&credential.signature)?;
        self.verifying_key
            .verify(&credential.signing_payload()?, &signature)
            .map_err(|_| CredentialError::InvalidSignature)?;

        Ok(Verification {
            issuer: credential.issuer.clone(),
            subject: credential.subject.clone(),
            claims: credential.claims.clone(),
            issued_at: credential.issued_at,
            expires_at: credential.expires_at,
            key_id: credential.key_id.clone(),
        })
    }
}

fn decode_signature(encoded: &str) -> Result<Signature, CredentialError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| CredentialError::Malformed("signature is not base64url".into()))?;
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| CredentialError::Malformed("signature must be 64 bytes".into()))?;
    Ok(Signature::from_bytes(&bytes))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn issuer() -> Issuer {
        Issuer::from_seed("did:mesh:acme", &[7u8; 32])
    }

    fn claims() -> BTreeMap<String, Value> {
        BTreeMap::from([
            ("role".to_string(), json!("supplier")),
            ("tier".to_string(), json!(2)),
        ])
    }

    #[test]
    fn issues_and_verifies() {
        let issuer = issuer();
        let credential = issuer
            .issue_at("did:mesh:holder", claims(), Some(600), 1_000)
            .expect("issue");
        assert_eq!(credential.version, 1);
        assert_eq!(credential.issued_at, 1_000);
        assert_eq!(credential.expires_at, 1_600);

        let verified = issuer.verify(&credential, 1_100).expect("verify");
        assert_eq!(verified.subject, "did:mesh:holder");
        assert_eq!(verified.claims, claims());
        assert_eq!(verified.key_id, issuer.key_id());
    }

    #[test]
    fn verifies_with_only_the_public_key() {
        let issuer = issuer();
        let credential = issuer
            .issue_at("holder", claims(), None, 1_000)
            .expect("issue");
        let verifier = CredentialVerifier::from_public_key(issuer.id(), issuer.public_key())
            .expect("verifier");

        assert_eq!(verifier.key_id(), issuer.key_id());
        let verified = verifier.verify(&credential, 1_100).expect("verify");
        assert_eq!(verified.subject, "holder");
        assert_eq!(verified.claims, claims());
        assert!(CredentialVerifier::from_public_key("did:mesh:acme", "not-a-key").is_err());
    }

    #[test]
    fn rejects_tampered_claims() {
        let issuer = issuer();
        let mut credential = issuer
            .issue_at("holder", claims(), None, 1_000)
            .expect("issue");
        credential.claims.insert("tier".into(), json!(99));

        assert_eq!(
            issuer.verify(&credential, 1_100),
            Err(CredentialError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_expired_and_future_credentials() {
        let issuer = issuer();
        let credential = issuer
            .issue_at("holder", BTreeMap::new(), Some(60), 1_000)
            .expect("issue");

        assert_eq!(
            issuer.verify(&credential, 1_060),
            Err(CredentialError::Expired)
        );
        assert_eq!(
            issuer.verify(&credential, 999),
            Err(CredentialError::NotYetValid)
        );
    }

    #[test]
    fn rejects_unknown_issuer_and_key() {
        let issuer = issuer();
        let mut credential = issuer
            .issue_at("holder", BTreeMap::new(), None, 1_000)
            .expect("issue");

        credential.issuer = "did:mesh:other".into();
        assert_eq!(
            issuer.verify(&credential, 1_100),
            Err(CredentialError::UnknownIssuer)
        );

        let mut credential = issuer
            .issue_at("holder", BTreeMap::new(), None, 1_000)
            .expect("issue");
        credential.key_id = "unknown".into();
        assert_eq!(
            issuer.verify(&credential, 1_100),
            Err(CredentialError::UnknownKey)
        );
    }

    #[test]
    fn rejects_signature_from_another_key() {
        let signer = issuer();
        let verifier = Issuer::from_seed("did:mesh:acme", &[9u8; 32]);
        let credential = signer
            .issue_at("holder", BTreeMap::new(), None, 1_000)
            .expect("issue");

        assert_eq!(credential.key_id, signer.key_id());
        assert_ne!(credential.key_id, verifier.key_id());
        assert_eq!(
            verifier.verify(&credential, 1_100),
            Err(CredentialError::UnknownKey)
        );
    }

    #[test]
    fn parses_hex_and_base64_seeds() {
        let seed = [7u8; 32];
        let expected = Issuer::from_seed("issuer", &seed);
        let hex = seed
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let from_hex = Issuer::from_encoded_seed("issuer", &hex).expect("hex");
        let from_base64 =
            Issuer::from_encoded_seed("issuer", &URL_SAFE_NO_PAD.encode(seed)).expect("base64");

        assert_eq!(from_hex.key_id(), expected.key_id());
        assert_eq!(from_base64.key_id(), expected.key_id());
        assert!(Issuer::from_encoded_seed("issuer", "too-short").is_err());
        assert!(Issuer::from_encoded_seed("issuer", &"zz".repeat(32)).is_err());
    }

    #[test]
    fn validates_issue_input() {
        let issuer = issuer();
        assert_eq!(
            issuer.issue_at("  ", BTreeMap::new(), None, 1_000),
            Err(CredentialError::InvalidSubject)
        );
        assert_eq!(
            issuer.issue_at("holder", BTreeMap::new(), Some(0), 1_000),
            Err(CredentialError::InvalidTTL)
        );
        assert_eq!(
            issuer.issue_at("holder", BTreeMap::new(), Some(MAX_TTL_SECONDS + 1), 1_000),
            Err(CredentialError::InvalidTTL)
        );
    }
}
