use crate::{
    config::Loaded,
    ledger::{Job, Ledger, job_id},
};
use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};
#[derive(Clone)]
struct App {
    loaded: Arc<Loaded>,
    ledger: Ledger,
    webhook: Arc<zeroize::Zeroizing<Vec<u8>>>,
}
async fn webhook(
    State(app): State<App>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<(StatusCode, Json<Value>), (StatusCode, &'static str)> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let supplied = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("sha256="))
        .and_then(|v| hex::decode(v).ok())
        .ok_or((StatusCode::UNAUTHORIZED, "webhook authentication failed"))?;
    let mut hmac = Hmac::<Sha256>::new_from_slice(&app.webhook).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "authentication unavailable",
        )
    })?;
    hmac.update(&body);
    hmac.verify_slice(&supplied)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "webhook authentication failed"))?;
    if headers.get("x-github-event").and_then(|h| h.to_str().ok()) == Some("ping") {
        return Ok((StatusCode::OK, Json(json!({"ok":true}))));
    }
    if headers.get("x-github-event").and_then(|h| h.to_str().ok()) != Some("workflow_run") {
        return Ok((StatusCode::OK, Json(json!({"ignored":true}))));
    }
    let value: Value =
        serde_json::from_slice(&body).map_err(|_| (StatusCode::BAD_REQUEST, "invalid JSON"))?;
    if value["action"] != "completed" || value["workflow_run"]["conclusion"] != "success" {
        return Ok((StatusCode::OK, Json(json!({"ignored":true}))));
    }
    let repo_id = value["repository"]["id"]
        .as_u64()
        .ok_or((StatusCode::BAD_REQUEST, "repository ID missing"))?;
    let repo = app
        .loaded
        .config
        .repositories
        .iter()
        .find(|r| r.id == repo_id)
        .ok_or((StatusCode::FORBIDDEN, "repository not eligible"))?;
    if value["repository"]["full_name"] != repo.name || value["workflow"]["path"] != repo.workflow {
        return Err((StatusCode::FORBIDDEN, "workflow not eligible"));
    }
    let run = &value["workflow_run"];
    let run_id = run["id"]
        .as_u64()
        .ok_or((StatusCode::BAD_REQUEST, "run ID missing"))?;
    let attempt = run["run_attempt"]
        .as_u64()
        .ok_or((StatusCode::BAD_REQUEST, "run attempt missing"))?;
    let commit = run["head_sha"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "commit missing"))?
        .to_string();
    let policy = app
        .loaded
        .policy_hash(repo)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "policy unavailable"))?;
    let job = Job {
        id: job_id(repo.id, run_id, attempt, &policy),
        repository_id: repo.id,
        run_id,
        attempt,
        commit,
        policy_hash: policy,
        revision: repo.revision,
    };
    app.ledger.enqueue(&job).await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "durable ledger unavailable",
        )
    })?;
    Ok((StatusCode::ACCEPTED, Json(json!({"job_id":job.id}))))
}
pub async fn serve_tls(
    router: Router,
    listen: &str,
    certificate: &Path,
    private_key: &Path,
) -> Result<()> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(
        certificate,
    )?))
    .collect::<std::result::Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(
        private_key,
    )?))?
    .ok_or_else(|| anyhow::anyhow!("TLS key missing"))?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let limit = Arc::new(tokio::sync::Semaphore::new(64));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Ok(Ok(tls)) =
                tokio::time::timeout(std::time::Duration::from_secs(10), acceptor.accept(stream))
                    .await
            {
                let service = hyper_util::service::TowerToHyperService::new(router);
                let mut http = hyper::server::conn::http1::Builder::new();
                http.timer(hyper_util::rt::TokioTimer::new())
                    .header_read_timeout(std::time::Duration::from_secs(10));
                // Bound incomplete request bodies and idle keep-alive connections too.
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(60),
                    http.serve_connection(hyper_util::rt::TokioIo::new(tls), service),
                )
                .await;
            }
        });
    }
}
pub async fn run(loaded: Loaded) -> Result<()> {
    use rand::RngCore;
    let mut entropy = [0; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut entropy)?;
    ensure!(entropy.iter().any(|b| *b != 0), "entropy unavailable");
    let ledger = Ledger::new(&loaded.config)?;
    crate::pipeline::activate(&loaded, &ledger).await?;
    let webhook_secret = Arc::new(crate::config::read_secret(&loaded.config.webhook_secret)?);
    let loaded = Arc::new(loaded);
    let state = App {
        loaded: loaded.clone(),
        ledger: ledger.clone(),
        webhook: webhook_secret,
    };
    let worker = state.clone();
    tokio::spawn(async move {
        loop {
            match worker.ledger.claim().await {
                Ok(Some(claim)) => {
                    let heartbeat_ledger = worker.ledger.clone();
                    let heartbeat_claim = claim.clone();
                    let heartbeat = tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                            if heartbeat_ledger
                                .event(&heartbeat_claim, "lease.renewed", json!({}))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    });
                    let result =
                        crate::pipeline::process(&worker.loaded, &worker.ledger, &claim).await;
                    heartbeat.abort();
                    match result {
                        Ok(()) => {
                            let _ = worker.ledger.finish(&claim, "complete").await;
                        }
                        Err(error) => {
                            // Signed download URLs and API credentials never enter logs or audit errors.
                            let retry = error.chain().any(|e| {
                                e.is::<reqwest::Error>()
                                    || e.is::<std::io::Error>()
                                    || e.downcast_ref::<crate::github::HttpFailure>()
                                        .is_some_and(|h| h.retryable())
                            });
                            let kind = if retry {
                                "transient"
                            } else {
                                "policy-or-verification"
                            };
                            tracing::warn!(job=%claim.job.id,kind,"job did not complete");
                            if worker
                                .ledger
                                .event(&claim, "job.failed", json!({"kind":kind}))
                                .await
                                .is_ok()
                            {
                                let _ = worker
                                    .ledger
                                    .finish(&claim, if retry { "retry" } else { "rejected" })
                                    .await;
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(_) => tracing::warn!("audit collector unavailable; signing paused"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
    let router = Router::new()
        .route("/webhooks/github", post(webhook))
        .route("/healthz", get(|| async { Json(json!({"ok":true})) }))
        .route(
            "/readyz",
            get(|State(app): State<App>| async move {
                if app.loaded.config.trust_roots.values().any(|t| {
                    crate::config::now().is_err()
                        || t.valid_until <= crate::config::now().unwrap_or(u64::MAX)
                }) {
                    return StatusCode::SERVICE_UNAVAILABLE;
                }
                if app.ledger.ping().await.is_ok() {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                }
            }),
        )
        .layer(DefaultBodyLimit::max(256 * 1024))
        .with_state(state);
    serve_tls(
        router,
        &loaded.config.listen,
        &loaded.config.tls_certificate,
        &loaded.config.tls_private_key,
    )
    .await
}
