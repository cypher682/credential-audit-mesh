use credential_audit_mesh::api::Api;
use credential_audit_mesh::config::Config;
use credential_audit_mesh::credential::Issuer;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::load().map_err(std::io::Error::other)?;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_new(&cfg.log_level).unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let issuer = match cfg.issuer_key.as_deref() {
        Some(seed) => {
            Issuer::from_encoded_seed(cfg.issuer_id.clone(), seed).map_err(std::io::Error::other)?
        }
        None => {
            tracing::warn!(
                issuer = %cfg.issuer_id,
                "ISSUER_KEY is not set; using an ephemeral signing key, credentials will not survive restart"
            );
            Issuer::generate(cfg.issuer_id.clone())
        }
    };
    tracing::info!(
        issuer = issuer.id(),
        key_id = issuer.key_id(),
        "credential issuer ready"
    );

    let addr = cfg.addr();
    let app = Api::new(issuer, cfg.service_name.clone(), env!("CARGO_PKG_VERSION")).router();

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, version = env!("CARGO_PKG_VERSION"), "server started");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("server stopped");
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
