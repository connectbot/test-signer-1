use android_signer::{
    crypto::SigningKey,
    lineage::{DEFAULT_FLAGS, DEFAULT_LIMIT, Lineage, validate_hybrid},
};
use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    about = "Offline Android signing administration and release-policy export. No network access or key generation."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    ExportReleasePolicy {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        repository: String,
        #[arg(long)]
        signer_revision: String,
        #[arg(long)]
        out: PathBuf,
    },
    VerifyReceipt {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        certificate_der: PathBuf,
        #[arg(long)]
        fingerprint: String,
    },
    Init {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Inspect {
        #[arg(long)]
        input: PathBuf,
        #[arg(long,default_value_t=DEFAULT_LIMIT)]
        max_bytes: usize,
    },
    Import {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        expected_root: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        allow_rollback: bool,
        #[arg(long,default_value_t=DEFAULT_LIMIT)]
        max_bytes: usize,
    },
    Append {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        old_key: PathBuf,
        #[arg(long)]
        old_cert: PathBuf,
        #[arg(long)]
        new_key: PathBuf,
        #[arg(long)]
        new_cert: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long,default_value_t=DEFAULT_FLAGS)]
        flags: u32,
        #[arg(long)]
        allow_rollback: bool,
        #[arg(long,default_value_t=DEFAULT_LIMIT)]
        max_bytes: usize,
    },
    Hybrid {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        old_key: PathBuf,
        #[arg(long)]
        old_cert: PathBuf,
        #[arg(long)]
        rsa_key: PathBuf,
        #[arg(long)]
        rsa_cert: PathBuf,
        #[arg(long)]
        pqc_key: PathBuf,
        #[arg(long)]
        pqc_cert: PathBuf,
        #[arg(long)]
        out_directory: PathBuf,
        #[arg(long)]
        allow_rollback: bool,
        #[arg(long,default_value_t=DEFAULT_LIMIT)]
        max_bytes: usize,
    },
}
fn read(path: &std::path::Path, max: usize) -> Result<Lineage> {
    ensure!(
        std::fs::metadata(path)?.len() <= max as u64,
        "lineage exceeds byte limit"
    );
    Lineage::read(&std::fs::read(path)?, max)
}
fn write(path: &std::path::Path, lineage: &Lineage, max: usize) -> Result<()> {
    use std::io::Write;
    let bytes = lineage.file()?;
    ensure!(bytes.len() <= max, "lineage exceeds byte limit");
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    out.write_all(&bytes)?;
    out.sync_all()?;
    report(lineage)
}
fn report(lineage: &Lineage) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"sha256":lineage.digest()?,"certificates":lineage.fingerprints(),"capabilities":lineage.nodes.iter().map(|n|n.flags).collect::<Vec<_>>(),"verified":"cryptographic links only; authorize the root separately"})
        )?
    );
    Ok(())
}
fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ExportReleasePolicy {
            config,
            repository,
            signer_revision,
            out,
        } => {
            use std::io::Write;
            let loaded = android_signer::config::Loaded::read(&config)?;
            let repo = loaded
                .config
                .repositories
                .iter()
                .find(|r| r.name == repository)
                .ok_or_else(|| anyhow::anyhow!("repository not configured"))?;
            let policy = loaded.release_policy(repo, &signer_revision)?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(out)?;
            file.write_all(&serde_json::to_vec_pretty(&policy)?)?;
            file.sync_all()?;
            Ok(())
        }
        Command::VerifyReceipt {
            input,
            certificate_der,
            fingerprint,
        } => {
            ensure!(
                std::fs::metadata(&input)?.len() <= 8 * 1024 * 1024
                    && std::fs::metadata(&certificate_der)?.len() <= 65536,
                "receipt/certificate too large"
            );
            let receipt = android_signer::receipt::verify(
                &std::fs::read(input)?,
                &std::fs::read(certificate_der)?,
                &fingerprint,
            )?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
            Ok(())
        }
        Command::Init { key, cert, out } => write(
            &out,
            &Lineage::root(&SigningKey::load(&key, &cert)?),
            DEFAULT_LIMIT,
        ),
        Command::Inspect { input, max_bytes } => report(&read(&input, max_bytes)?),
        Command::Import {
            input,
            expected_root,
            out,
            allow_rollback,
            max_bytes,
        } => {
            let lineage = read(&input, max_bytes)?;
            lineage.validate(allow_rollback)?;
            ensure!(
                lineage.fingerprints()[0] == expected_root,
                "lineage root is not trusted"
            );
            write(&out, &lineage, max_bytes)
        }
        Command::Append {
            input,
            old_key,
            old_cert,
            new_key,
            new_cert,
            out,
            flags,
            allow_rollback,
            max_bytes,
        } => {
            let lineage = read(&input, max_bytes)?;
            let out_lineage = lineage.append(
                &SigningKey::load(&old_key, &old_cert)?,
                &SigningKey::load(&new_key, &new_cert)?,
                flags,
            )?;
            out_lineage.validate(allow_rollback)?;
            write(&out, &out_lineage, max_bytes)
        }
        Command::Hybrid {
            input,
            old_key,
            old_cert,
            rsa_key,
            rsa_cert,
            pqc_key,
            pqc_cert,
            out_directory,
            allow_rollback,
            max_bytes,
        } => {
            use rsa::traits::PublicKeyParts;
            let ancestry = read(&input, max_bytes)?;
            let old = SigningKey::load(&old_key, &old_cert)?;
            let rsa = SigningKey::load(&rsa_key, &rsa_cert)?;
            let pqc = SigningKey::load(&pqc_key, &pqc_cert)?;
            let android_signer::crypto::PrivateKey::Rsa(k) = &rsa.private else {
                anyhow::bail!("hybrid classical key must be RSA")
            };
            ensure!(
                k.n().bits() == 4096 && pqc.algorithm() == android_signer::crypto::ML_DSA,
                "hybrid requires RSA-4096 and ML-DSA-65"
            );
            ensure!(
                ancestry
                    .nodes
                    .iter()
                    .all(|n| n.certificate != rsa.certificate && n.certificate != pqc.certificate),
                "hybrid keys already appear in ancestry"
            );
            let classical = ancestry.append(&old, &rsa, DEFAULT_FLAGS)?;
            let post_quantum = ancestry.append(&old, &pqc, DEFAULT_FLAGS)?;
            validate_hybrid(&classical, &post_quantum, allow_rollback)?;
            // A real RSA->PQC link makes the effective lineage independently verifiable
            // and usable as shared ancestry during the next hybrid rotation.
            let effective = classical.append(&rsa, &pqc, DEFAULT_FLAGS)?;
            std::fs::create_dir(&out_directory)?;
            write(
                &out_directory.join("rsa-lineage.bin"),
                &classical,
                max_bytes,
            )?;
            write(
                &out_directory.join("pqc-lineage.bin"),
                &post_quantum,
                max_bytes,
            )?;
            write(
                &out_directory.join("effective-lineage.bin"),
                &effective,
                max_bytes,
            )
        }
    }
}
