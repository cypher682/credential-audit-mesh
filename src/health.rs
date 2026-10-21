use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde_json::{Value, json};

#[derive(Clone)]
pub struct Health {
    service: String,
    version: String,
}

impl Health {
    pub fn new(service: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            version: version.into(),
        }
    }

    pub fn router(self) -> Router {
        Router::new()
            .route("/healthz", get(liveness))
            .route("/readyz", get(readiness))
            .with_state(self)
    }
}

async fn liveness(State(h): State<Health>) -> Json<Value> {
    Json(json!({
        "service": h.service,
        "version": h.version,
        "status": "ok",
    }))
}

async fn readiness(State(h): State<Health>) -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "service": h.service,
            "version": h.version,
            "status": "ok",
            "checks": {},
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_endpoints_respond_ok() {
        let app = Health::new("test", "dev").router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
