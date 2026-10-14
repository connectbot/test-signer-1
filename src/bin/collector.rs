#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    android_signer::initialize_crypto()?;
    let path = std::env::var_os("AUDIT_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "collector.json".into());
    let config: android_signer::collector::CollectorConfig =
        serde_json::from_slice(&std::fs::read(path)?)?;
    let token = android_signer::config::read_secret(&config.token_file)?;
    let store = android_signer::collector::Store::open(
        &config.database,
        std::str::from_utf8(&token)?.trim().as_bytes(),
    )?;
    android_signer::server::serve_tls(
        android_signer::collector::router(store),
        &config.listen,
        &config.tls_certificate,
        &config.tls_private_key,
    )
    .await
}
