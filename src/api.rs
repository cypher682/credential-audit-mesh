use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::credential::{Credential, CredentialError, Issuer};
use crate::health::Health;
use crate::transparency::{TransparencyLog, TreeHead};

#[derive(Clone)]
struct ApiState {
    issuer: Arc<Issuer>,
    log: Arc<Mutex<TransparencyLog>>,
}

pub struct Api {
    issuer: Arc<Issuer>,
    log: Arc<Mutex<TransparencyLog>>,
    service: String,
    version: String,
}

impl Api {
    pub fn new(issuer: Issuer, service: impl Into<String>, version: impl Into<String>) -> Self {
        Self::with_log(issuer, TransparencyLog::new(), service, version)
    }

    pub fn with_log(
        issuer: Issuer,
        log: TransparencyLog,
        service: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            issuer: Arc::new(issuer),
            log: Arc::new(Mutex::new(log)),
            service: service.into(),
            version: version.into(),
        }
    }

    pub fn router(self) -> Router {
        let state = ApiState {
            issuer: Arc::clone(&self.issuer),
            log: Arc::clone(&self.log),
        };
        let health = Health::new(self.service, self.version).router();
        Router::new()
            .route("/v1/issuer", get(issuer_info))
            .route("/v1/credentials", post(issue_credential))
            .route("/v1/credentials/verify", post(verify_credential))
            .route("/v1/log", get(log_head))
            .route("/v1/log/entries/{index}", get(log_entry))
            .route("/v1/log/consistency", get(log_consistency))
            .with_state(state)
            .merge(health)
            .merge(crate::ui::router())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueRequest {
    subject: String,
    #[serde(default)]
    claims: BTreeMap<String, Value>,
    #[serde(default)]
    ttl_seconds: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyRequest {
    credential: Credential,
}

#[derive(Debug, Deserialize)]
struct ConsistencyQuery {
    first: u64,
    second: u64,
}

async fn issuer_info(State(state): State<ApiState>) -> Json<Value> {
    Json(json!({
        "issuer": state.issuer.id(),
        "algorithm": "Ed25519",
        "key_id": state.issuer.key_id(),
        "public_key": state.issuer.public_key(),
    }))
}

async fn issue_credential(
    State(state): State<ApiState>,
    payload: Result<Json<IssueRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match payload {
        Ok(payload) => payload,
        Err(rejection) => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_json",
                rejection.body_text(),
            );
        }
    };
    let credential = match state
        .issuer
        .issue(request.subject, request.claims, request.ttl_seconds)
    {
        Ok(credential) => credential,
        Err(err) => {
            return error(StatusCode::BAD_REQUEST, error_code(&err), err.to_string());
        }
    };

    let proof = match state.log.lock() {
        Ok(mut log) => log.append(&credential),
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "log_unavailable",
                "transparency log is unavailable",
            );
        }
    };
    let proof = match proof {
        Ok(proof) => proof,
        Err(err) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "log_unavailable",
                err.to_string(),
            );
        }
    };
    let tree_head = match signed_head(
        &state.issuer,
        TreeHead {
            tree_size: proof.tree_size,
            root_hash: proof.root_hash.clone(),
        },
    ) {
        Ok(head) => head,
        Err(err) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "signing_failed",
                err.to_string(),
            );
        }
    };

    (
        StatusCode::CREATED,
        Json(json!({
            "credential": credential,
            "transparency": {
                "entry": proof.entry,
                "leaf_hash": proof.leaf_hash,
                "inclusion_proof": proof.inclusion_proof,
                "tree_head": tree_head,
            }
        })),
    )
        .into_response()
}

async fn log_head(State(state): State<ApiState>) -> Response {
    let head = match state.log.lock() {
        Ok(log) => log.head(),
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "log_unavailable",
                "transparency log is unavailable",
            );
        }
    };
    match signed_head(&state.issuer, head) {
        Ok(head) => Json(head).into_response(),
        Err(err) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "signing_failed",
            err.to_string(),
        ),
    }
}

async fn log_entry(State(state): State<ApiState>, Path(index): Path<u64>) -> Response {
    let proof = match state.log.lock() {
        Ok(log) => log.inclusion(index),
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "log_unavailable",
                "transparency log is unavailable",
            );
        }
    };
    let Some(proof) = proof else {
        return error(StatusCode::NOT_FOUND, "not_found", "log entry not found");
    };
    let tree_head = match signed_head(
        &state.issuer,
        TreeHead {
            tree_size: proof.tree_size,
            root_hash: proof.root_hash.clone(),
        },
    ) {
        Ok(head) => head,
        Err(err) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "signing_failed",
                err.to_string(),
            );
        }
    };

    Json(json!({
        "entry": proof.entry,
        "leaf_hash": proof.leaf_hash,
        "inclusion_proof": proof.inclusion_proof,
        "tree_head": tree_head,
    }))
    .into_response()
}

async fn log_consistency(
    State(state): State<ApiState>,
    Query(query): Query<ConsistencyQuery>,
) -> Response {
    let proof = match state.log.lock() {
        Ok(log) => log.consistency(query.first, query.second),
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "log_unavailable",
                "transparency log is unavailable",
            );
        }
    };
    let proof = match proof {
        Ok(proof) => proof,
        Err(err) => return error(StatusCode::BAD_REQUEST, "invalid_range", err),
    };
    let second_head = match signed_head(
        &state.issuer,
        TreeHead {
            tree_size: proof.second_size,
            root_hash: proof.second_root.clone(),
        },
    ) {
        Ok(head) => head,
        Err(err) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "signing_failed",
                err.to_string(),
            );
        }
    };

    Json(json!({
        "first": {
            "tree_size": proof.first_size,
            "root_hash": proof.first_root,
        },
        "second": second_head,
        "proof": proof.proof,
    }))
    .into_response()
}

fn signed_head(issuer: &Issuer, head: TreeHead) -> Result<Value, CredentialError> {
    let signature = issuer.sign_jcs(&head)?;
    Ok(json!({
        "tree_size": head.tree_size,
        "root_hash": head.root_hash,
        "key_id": issuer.key_id(),
        "signature": signature,
    }))
}

async fn verify_credential(
    State(state): State<ApiState>,
    payload: Result<Json<VerifyRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match payload {
        Ok(payload) => payload,
        Err(rejection) => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_json",
                rejection.body_text(),
            );
        }
    };
    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "clock",
                "system clock before epoch",
            );
        }
    };

    match state.issuer.verify(&request.credential, now) {
        Ok(verified) => Json(json!({
            "valid": true,
            "issuer": verified.issuer,
            "subject": verified.subject,
            "claims": verified.claims,
            "issued_at": verified.issued_at,
            "expires_at": verified.expires_at,
            "key_id": verified.key_id,
        }))
        .into_response(),
        Err(err) => Json(json!({
            "valid": false,
            "code": error_code(&err),
            "reason": err.to_string(),
        }))
        .into_response(),
    }
}

fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({
            "error": {
                "code": code,
                "message": message.into(),
            }
        })),
    )
        .into_response()
}

fn error_code(err: &CredentialError) -> &'static str {
    match err {
        CredentialError::Malformed(_) => "invalid_credential",
        CredentialError::UnsupportedVersion(_) => "unsupported_version",
        CredentialError::InvalidSubject => "invalid_subject",
        CredentialError::InvalidTTL => "invalid_ttl",
        CredentialError::TooManyClaims => "too_many_claims",
        CredentialError::UnknownIssuer => "unknown_issuer",
        CredentialError::UnknownKey => "unknown_key",
        CredentialError::InvalidSignature => "invalid_signature",
        CredentialError::Expired => "expired",
        CredentialError::NotYetValid => "not_yet_valid",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    use crate::transparency::{LogEntry, verify_consistency, verify_inclusion};

    fn app() -> Router {
        Api::new(
            Issuer::from_seed("did:mesh:acme", &[3u8; 32]),
            "credential-mesh",
            "test",
        )
        .router()
    }

    async fn call(app: Router, request: Request<Body>) -> (StatusCode, Value) {
        let response = app.oneshot(request).await.expect("response");
        let status = response.status();
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body");
        (status, serde_json::from_slice(&body).expect("json"))
    }

    fn post(uri: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request")
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request")
    }

    async fn issue(app: Router, subject: &str) -> Value {
        let (status, body) = call(
            app,
            post(
                "/v1/credentials",
                json!({
                    "subject": subject,
                    "claims": {"role": "supplier", "tier": 2},
                    "ttl_seconds": 600
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        body
    }

    #[tokio::test]
    async fn issues_and_verifies_credentials_over_http() {
        let app = app();
        let issued = issue(app.clone(), "did:mesh:holder").await;
        let credential = issued["credential"].clone();
        assert_eq!(credential["issuer"], "did:mesh:acme");
        assert_eq!(issued["transparency"]["entry"]["index"], 0);
        assert_eq!(issued["transparency"]["tree_head"]["tree_size"], 1);

        let (status, verified) = call(
            app,
            post("/v1/credentials/verify", json!({"credential": credential})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(verified["valid"], true);
        assert_eq!(verified["subject"], "did:mesh:holder");
        assert_eq!(verified["claims"]["role"], "supplier");
    }

    #[tokio::test]
    async fn verify_reports_tampering_as_invalid() {
        let app = app();
        let issued = issue(app.clone(), "holder").await;
        let mut credential = issued["credential"].clone();
        credential["claims"]["tier"] = json!(99);

        let (status, verified) = call(
            app,
            post("/v1/credentials/verify", json!({"credential": credential})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(verified["valid"], false);
        assert_eq!(verified["code"], "invalid_signature");
    }

    #[tokio::test]
    async fn transparency_log_endpoints_expose_verifiable_proofs() {
        let app = app();
        let first = issue(app.clone(), "holder-0").await;
        let first_head = first["transparency"]["tree_head"].clone();
        issue(app.clone(), "holder-1").await;
        let third = issue(app.clone(), "holder-2").await;

        let (status, head) = call(app.clone(), get("/v1/log")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(head["tree_size"], 3);
        assert_eq!(
            head["root_hash"],
            third["transparency"]["tree_head"]["root_hash"]
        );
        assert_eq!(head["key_id"], third["transparency"]["tree_head"]["key_id"]);

        let verifier = Issuer::from_seed("did:mesh:acme", &[3u8; 32]).verifier();
        let signed_payload = json!({
            "tree_size": head["tree_size"],
            "root_hash": head["root_hash"],
        });
        verifier
            .verify_jcs(
                &signed_payload,
                head["signature"].as_str().expect("signature"),
            )
            .expect("valid tree head signature");

        let (status, entry) = call(app.clone(), get("/v1/log/entries/1")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(entry["entry"]["index"], 1);
        assert_eq!(entry["tree_head"]["tree_size"], 3);

        let log_entry: LogEntry = serde_json::from_value(entry["entry"].clone()).expect("entry");
        let leaf_payload = serde_jcs::to_vec(&log_entry).expect("canonical entry");
        let mut hasher = Sha256::new();
        hasher.update([0]);
        hasher.update(leaf_payload);
        let leaf_hash = URL_SAFE_NO_PAD.encode(hasher.finalize());
        assert_eq!(leaf_hash, entry["leaf_hash"]);

        let root: [u8; 32] = URL_SAFE_NO_PAD
            .decode(entry["tree_head"]["root_hash"].as_str().expect("root"))
            .expect("root base64")
            .try_into()
            .expect("root hash");
        let leaf: [u8; 32] = URL_SAFE_NO_PAD
            .decode(leaf_hash)
            .expect("leaf base64")
            .try_into()
            .expect("leaf hash");
        let proof = entry["inclusion_proof"]
            .as_array()
            .expect("proof")
            .iter()
            .map(|value| {
                URL_SAFE_NO_PAD
                    .decode(value.as_str().expect("hash"))
                    .expect("hash base64")
                    .try_into()
                    .expect("hash")
            })
            .collect::<Vec<[u8; 32]>>();
        assert!(verify_inclusion(1, 3, &leaf, &proof, &root));

        let (status, consistency) =
            call(app.clone(), get("/v1/log/consistency?first=1&second=3")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(consistency["first"]["root_hash"], first_head["root_hash"]);
        assert_eq!(consistency["second"]["root_hash"], head["root_hash"]);
        let first_root: [u8; 32] = URL_SAFE_NO_PAD
            .decode(consistency["first"]["root_hash"].as_str().expect("root"))
            .expect("root base64")
            .try_into()
            .expect("root hash");
        let second_root: [u8; 32] = URL_SAFE_NO_PAD
            .decode(consistency["second"]["root_hash"].as_str().expect("root"))
            .expect("root base64")
            .try_into()
            .expect("root hash");
        let consistency_proof = consistency["proof"]
            .as_array()
            .expect("proof")
            .iter()
            .map(|value| {
                URL_SAFE_NO_PAD
                    .decode(value.as_str().expect("hash"))
                    .expect("hash base64")
                    .try_into()
                    .expect("hash")
            })
            .collect::<Vec<[u8; 32]>>();
        assert!(verify_consistency(
            1,
            3,
            &first_root,
            &second_root,
            &consistency_proof
        ));

        let (status, _) = call(app.clone(), get("/v1/log/entries/99")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = call(app, get("/v1/log/consistency?first=4&second=2")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn rejects_bad_issue_requests() {
        let (status, body) = call(
            app(),
            post("/v1/credentials", json!({"subject": "", "ttl_seconds": 60})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_subject");
    }

    #[tokio::test]
    async fn exposes_issuer_public_key() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/v1/issuer")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body");
        let body: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(body["algorithm"], "Ed25519");
        assert_eq!(body["issuer"], "did:mesh:acme");
        assert!(
            body["public_key"]
                .as_str()
                .is_some_and(|key| !key.is_empty())
        );
    }
}
