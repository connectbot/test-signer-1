pub mod apk;
pub mod archive;
pub mod attestation;
#[cfg(feature = "collector")]
pub mod collector;
pub mod config;
pub mod crypto;
pub mod github;
pub mod jar;
pub mod ledger;
pub mod lineage;
pub mod manifest;
pub mod pipeline;
pub mod server;
pub mod transparency;
pub mod wire;

pub fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

pub fn initialize_crypto() -> anyhow::Result<()> {
    // Hermit 0.13 seeds its entropy pool with RDSEED. Without it the kernel
    // falls back to a predictable PRNG; never use that fallback for signing.
    #[cfg(all(target_os = "hermit", target_arch = "x86_64"))]
    {
        // The Rust Hermit target enables rdseed at compile time, so the usual
        // is_x86_feature_detected! macro folds to true. Check real CPUID.
        // CPUID is available on every x86_64 CPU; these leaves read no memory.
        let maximum = std::arch::x86_64::__cpuid(0).eax;
        let rdseed = maximum >= 7 && std::arch::x86_64::__cpuid_count(7, 0).ebx & (1 << 18) != 0;
        anyhow::ensure!(rdseed, "RDSEED is required for secure Hermit entropy");
    }
    use rand::RngCore;
    let mut entropy = zeroize::Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.try_fill_bytes(entropy.as_mut())?;
    anyhow::ensure!(
        entropy.iter().any(|b| *b != 0),
        "secure entropy unavailable"
    );
    rustls_rustcrypto::provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("TLS crypto provider already installed"))?;
    sigstore_crypto::install_default_provider(&crypto::RustCryptoProvider)
        .map_err(|_| anyhow::anyhow!("Sigstore crypto provider already installed"))?;
    Ok(())
}
