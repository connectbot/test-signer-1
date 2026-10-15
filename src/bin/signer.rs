#[cfg(target_os = "hermit")]
use hermit as _;
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    android_signer::initialize_crypto()?;
    tracing_subscriber::fmt()
        .with_env_filter("android_signer=info")
        .init();
    tracing::info!("Android signer: strict entropy profile v1");
    let path = std::env::var_os("SIGNER_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/root/config.json".into());
    if !path.try_exists()? && std::path::Path::new("/root/bootstrap.json").try_exists()? {
        return android_signer::server::provisioning(std::path::Path::new("/root/bootstrap.json"))
            .await;
    }
    let loaded = android_signer::config::Loaded::read(&path)?;
    android_signer::server::run(loaded).await
}
