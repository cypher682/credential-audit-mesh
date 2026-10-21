use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::credential::{Credential, CredentialError, Issuer};
use crate::health::Health;

#[derive(Clone)]
struct ApiState {
    issuer: Arc<Issuer>,
}

pub struct Api {
    issuer: Arc<Issuer>,
    service: String,
    version: String,
}

impl Api {
    pub fn new(issuer: Issuer, service: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            issuer: Arc::new(issuer),
            service: service.into(),
            version: version.into(),
        }
    }

    pub fn router(self) -> Router {
        let state = ApiState {
            issuer: Arc::clone(&self.issuer),
        };
        let health = Health::new(self.service, self.version).router();
        Router::new()
            .route("/v1/issuer", get(issuer_info))
            .route("/v1/credentials", post(issue_credential))
            .route("/v1/credentials/verify", post(verify_credential))
            .with_state(state)
            .merge(health)
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
    match state
        .issuer
        .issue(request.subject, request.claims, request.ttl_seconds)
    {
        Ok(credential) => (StatusCode::CREATED, Json(credential)).into_response(),
        Err(err) => error(StatusCode::BAD_REQUEST, error_code(&err), err.to_string()),
    }
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
    use serde_json::json;
    use tower::ServiceExt;

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

    #[tokio::test]
    async fn issues_and_verifies_credentials_over_http() {
        let app = app();
        let (status, credential) = call(
            app.clone(),
            post(
                "/v1/credentials",
                json!({
                    "subject": "did:mesh:holder",
                    "claims": {"role": "supplier", "tier": 2},
                    "ttl_seconds": 600
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(credential["issuer"], "did:mesh:acme");

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
        let (_, mut credential) = call(
            app.clone(),
            post(
                "/v1/credentials",
                json!({"subject": "holder", "claims": {"tier": 1}}),
            ),
        )
        .await;
        credential["claims"]["tier"] = json!(99);

        let (status, verified) = call(
            app.clone(),
            post("/v1/credentials/verify", json!({"credential": credential})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(verified["valid"], false);
        assert_eq!(verified["code"], "invalid_signature");
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
