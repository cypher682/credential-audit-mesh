use axum::Router;
use axum::http::header::{self, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

const INDEX: &str = include_str!("../ui/index.html");
const STYLES: &str = include_str!("../ui/styles.css");
const APP: &str = include_str!("../ui/app.js");
const FAVICON: &str = include_str!("../ui/favicon.svg");

const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

pub fn router() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/ui/styles.css", get(styles))
        .route("/ui/app.js", get(app))
        .route("/ui/favicon.svg", get(favicon))
}

async fn index() -> Response {
    asset(INDEX, "text/html; charset=utf-8")
}

async fn styles() -> Response {
    asset(STYLES, "text/css; charset=utf-8")
}

async fn app() -> Response {
    asset(APP, "application/javascript; charset=utf-8")
}

async fn favicon() -> Response {
    asset(FAVICON, "image/svg+xml")
}

fn asset(body: &'static str, content_type: &'static str) -> Response {
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn get(uri: &str) -> Response {
        router()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .expect("response")
    }

    #[tokio::test]
    async fn serves_the_console_and_assets() {
        let response = get("/").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        assert_eq!(
            response.headers()[header::CONTENT_SECURITY_POLICY],
            CONTENT_SECURITY_POLICY
        );
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body");
        let html = std::str::from_utf8(&body).expect("utf8");
        assert!(html.contains("Credential Mesh"));
        assert!(html.contains("/ui/app.js"));

        let response = get("/ui/app.js").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/javascript; charset=utf-8"
        );

        let response = get("/ui/styles.css").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/css; charset=utf-8"
        );

        let response = get("/ui/favicon.svg").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "image/svg+xml");
    }
}
