use crate::{
    crypto::{PrivateKey, SigningKey},
    lineage::{DEFAULT_LIMIT, Lineage, validate_hybrid},
    transparency::ArchiveResource,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: String,
    pub tls_certificate: PathBuf,
    pub tls_private_key: PathBuf,
    pub github_app_id: u64,
    pub github_app_private_key: PathBuf,
    pub webhook_secret: PathBuf,
    pub audit_url: String,
    pub audit_token: PathBuf,
    pub audit_ca_certificate: PathBuf,
    pub keys: BTreeMap<String, KeySpec>,
    pub trust_roots: BTreeMap<String, TrustRoot>,
    pub repositories: Vec<Repository>,
    #[serde(default = "default_limit")]
    pub max_artifact_bytes: usize,
    #[serde(default = "lineage_limit")]
    pub max_lineage_bytes: usize,
}
fn default_limit() -> usize {
    64 * 1024 * 1024
}
fn lineage_limit() -> usize {
    DEFAULT_LIMIT
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySpec {
    pub private_key: PathBuf,
    pub certificate: PathBuf,
    pub fingerprint: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRoot {
    pub file: PathBuf,
    pub sha256: String,
    pub valid_until: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    pub id: u64,
    pub name: String,
    pub workflow: String,
    pub refs: Vec<String>,
    pub events: Vec<String>,
    pub runners: Vec<String>,
    pub visibility: String,
    pub package: String,
    pub apk_artifact: String,
    pub aab_artifact: String,
    pub apk_file: String,
    pub aab_file: String,
    pub revision: u64,
    pub signing: Signing,
    pub archive_resource: Option<ArchiveResource>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signing {
    pub original_key: String,
    pub current_key: String,
    pub upload_key: String,
    pub transparency_key: String,
    pub lineage: PathBuf,
    pub lineage_sha256: String,
    #[serde(default = "rotation_sdk")]
    pub rotation_min_sdk: u32,
    #[serde(default)]
    pub allow_rollback: bool,
    pub hybrid: Option<HybridConfig>,
}
fn rotation_sdk() -> u32 {
    33
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridConfig {
    pub classical_key: String,
    pub pqc_key: String,
    pub classical_lineage: PathBuf,
    pub classical_lineage_sha256: String,
    pub pqc_lineage: PathBuf,
    pub pqc_lineage_sha256: String,
    pub effective_lineage: PathBuf,
    pub effective_lineage_sha256: String,
}

pub type RepositoryLineages = (Lineage, Option<(Lineage, Lineage, Lineage)>);
pub struct Loaded {
    pub config: Config,
    pub keys: BTreeMap<String, SigningKey>,
    pub lineages: BTreeMap<u64, RepositoryLineages>,
}
pub fn now() -> Result<u64> {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    ensure!(n >= 1_700_000_000, "guest clock is invalid");
    Ok(n)
}
pub fn read_secret(path: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let meta = std::fs::metadata(path)?;
    ensure!(
        meta.is_file() && meta.len() <= 1024 * 1024,
        "invalid secret file"
    );
    Ok(zeroize::Zeroizing::new(std::fs::read(path)?))
}
fn read_lineage(path: &Path, hash: &str, limit: usize) -> Result<Lineage> {
    ensure!(
        std::fs::metadata(path)?.len() <= limit as u64,
        "lineage too large"
    );
    let b = std::fs::read(path)?;
    ensure!(crate::sha256(&b) == hash, "lineage hash differs");
    Lineage::read(&b, limit)
}
impl Loaded {
    pub fn read(path: &Path) -> Result<Self> {
        let config: Config = serde_json::from_slice(&std::fs::read(path)?)?;
        ensure!(
            !config.repositories.is_empty(),
            "no repositories configured"
        );
        ensure!(
            config.audit_url.starts_with("https://") && !config.audit_url.ends_with('/'),
            "audit URL must be HTTPS without trailing slash"
        );
        ensure!(
            config.max_artifact_bytes > 0 && config.max_artifact_bytes <= 512 * 1024 * 1024,
            "invalid artifact size limit"
        );
        ensure!(
            config.max_lineage_bytes >= 1024 && config.max_lineage_bytes <= 16 * 1024 * 1024,
            "invalid lineage size limit"
        );
        let mut keys = BTreeMap::new();
        for (id, spec) in &config.keys {
            let k = SigningKey::load(&spec.private_key, &spec.certificate)?;
            ensure!(
                k.fingerprint() == spec.fingerprint,
                "key fingerprint differs: {id}"
            );
            keys.insert(id.clone(), k);
        }
        for t in config.trust_roots.values() {
            ensure!(t.valid_until > now()?, "trust material expired");
            ensure!(
                crate::sha256(&std::fs::read(&t.file)?) == t.sha256,
                "trust-root hash differs"
            );
        }
        let mut lineages = BTreeMap::new();
        let mut names = std::collections::BTreeSet::new();
        for repo in &config.repositories {
            ensure!(
                repo.id > 0 && repo.revision > 0 && names.insert(repo.name.clone()),
                "invalid repository identity/revision"
            );
            let parts: Vec<_> = repo.name.split('/').collect();
            ensure!(
                parts.len() == 2
                    && parts.iter().all(|p| !p.is_empty()
                        && p.chars()
                            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))),
                "invalid repository name"
            );
            ensure!(
                repo.workflow.starts_with(".github/workflows/") && !repo.workflow.contains(".."),
                "invalid workflow path"
            );
            ensure!(
                !repo.refs.is_empty()
                    && repo
                        .refs
                        .iter()
                        .all(|r| r.starts_with("refs/heads/") || r.starts_with("refs/tags/")),
                "explicit refs required"
            );
            ensure!(
                !repo.events.is_empty()
                    && !repo.runners.is_empty()
                    && repo
                        .runners
                        .iter()
                        .all(|r| r == "github-hosted" || r == "self-hosted"),
                "explicit build event/runner policy required"
            );
            ensure!(
                ["public", "private"].contains(&repo.visibility.as_str())
                    && config.trust_roots.contains_key(&repo.visibility),
                "trust profile missing"
            );
            let s = &repo.signing;
            ensure!(
                [28, 33].contains(&s.rotation_min_sdk),
                "rotation SDK must be 28 or 33"
            );
            let key = |id: &str| {
                keys.get(id)
                    .ok_or_else(|| anyhow::anyhow!("key reference missing: {id}"))
            };
            let original = key(&s.original_key)?;
            let current = key(&s.current_key)?;
            let upload = key(&s.upload_key)?;
            let transparency = key(&s.transparency_key)?;
            ensure!(
                [original, current, upload, transparency]
                    .iter()
                    .all(|k| k.algorithm() == crate::crypto::RSA_SHA256),
                "classical, upload and transparency keys must be RSA"
            );
            let lineage = read_lineage(&s.lineage, &s.lineage_sha256, config.max_lineage_bytes)?;
            lineage.validate(s.allow_rollback)?;
            ensure!(
                lineage.nodes[0].certificate == original.certificate
                    && lineage.last()?.certificate == current.certificate,
                "lineage key roles differ"
            );
            let hybrid = if let Some(h) = &s.hybrid {
                let c = key(&h.classical_key)?;
                let p = key(&h.pqc_key)?;
                let PrivateKey::Rsa(rsa) = &c.private else {
                    anyhow::bail!("hybrid classical signer must be RSA")
                };
                use rsa::traits::PublicKeyParts;
                ensure!(
                    rsa.n().bits() == 4096 && p.algorithm() == crate::crypto::ML_DSA,
                    "hybrid requires RSA-4096 and ML-DSA-65"
                );
                let cl = read_lineage(
                    &h.classical_lineage,
                    &h.classical_lineage_sha256,
                    config.max_lineage_bytes,
                )?;
                let pl = read_lineage(
                    &h.pqc_lineage,
                    &h.pqc_lineage_sha256,
                    config.max_lineage_bytes,
                )?;
                let effective = read_lineage(
                    &h.effective_lineage,
                    &h.effective_lineage_sha256,
                    config.max_lineage_bytes,
                )?;
                validate_hybrid(&cl, &pl, s.allow_rollback)?;
                effective.validate(s.allow_rollback)?;
                ensure!(
                    cl.last()?.certificate == c.certificate
                        && pl.last()?.certificate == p.certificate,
                    "hybrid key mismatch"
                );
                let mut ancestry = cl.nodes[..cl.nodes.len() - 1].iter();
                ensure!(
                    lineage
                        .nodes
                        .iter()
                        .all(|n| ancestry.by_ref().any(|a| a.certificate == n.certificate)),
                    "hybrid history lacks ordered classical fallback ancestry"
                );
                ensure!(
                    effective.extends(&cl)
                        && effective.nodes.len() == cl.nodes.len() + 1
                        && effective.last()?.certificate == p.certificate,
                    "hybrid effective lineage mismatch"
                );
                ensure!(
                    c.spki()? != current.spki()? && c.spki()? != original.spki()?,
                    "hybrid key material reused"
                );
                for old in &cl.nodes[..cl.nodes.len() - 1] {
                    use der::{Decode, Encode};
                    let old = x509_cert::Certificate::from_der(&old.certificate)?
                        .tbs_certificate
                        .subject_public_key_info
                        .to_der()?;
                    ensure!(
                        old != c.spki()? && old != p.spki()?,
                        "hybrid key material reused from signing history"
                    );
                }
                Some((cl, pl, effective))
            } else {
                None
            };
            let transparency_spki = transparency.spki()?;
            for node in lineage.nodes.iter().chain(
                hybrid
                    .iter()
                    .flat_map(|(c, p, _)| c.nodes.iter().chain(&p.nodes)),
            ) {
                use der::{Decode, Encode};
                let cert = x509_cert::Certificate::from_der(&node.certificate)?;
                ensure!(
                    transparency_spki != cert.tbs_certificate.subject_public_key_info.to_der()?,
                    "transparency key shares APK key material"
                );
            }
            ensure!(
                transparency_spki != upload.spki()?,
                "transparency key shares upload key material"
            );
            ensure!(
                lineages.insert(repo.id, (lineage, hybrid)).is_none(),
                "duplicate repository ID"
            );
        }
        ensure!(
            read_secret(&config.webhook_secret)?.len() >= 32,
            "webhook secret must be at least 32 bytes"
        );
        Ok(Self {
            config,
            keys,
            lineages,
        })
    }
    pub fn policy_hash(&self, repo: &Repository) -> Result<String> {
        let signing = &repo.signing;
        let mut roles = vec![
            &signing.original_key,
            &signing.current_key,
            &signing.upload_key,
            &signing.transparency_key,
        ];
        if let Some(hybrid) = &signing.hybrid {
            roles.extend([&hybrid.classical_key, &hybrid.pqc_key]);
        }
        let pins = roles
            .into_iter()
            .map(|id| {
                let key = self
                    .config
                    .keys
                    .get(id)
                    .ok_or_else(|| anyhow::anyhow!("policy key missing"))?;
                Ok((id, &key.fingerprint))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let trust = self
            .config
            .trust_roots
            .get(&repo.visibility)
            .ok_or_else(|| anyhow::anyhow!("policy trust missing"))?;
        Ok(crate::sha256(&serde_json::to_vec(&serde_json::json!({
            "version": 2, "repository": repo, "key_certificate_pins": pins,
            "trust_root": trust, "max_artifact_bytes": self.config.max_artifact_bytes,
            "max_lineage_bytes": self.config.max_lineage_bytes,
        }))?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replacing_role_key_or_trust_pin_requires_new_policy_revision() {
        let mut config: Config =
            serde_json::from_str(include_str!("../config/signer.example.json")).unwrap();
        for (name, key) in &mut config.keys {
            key.fingerprint = crate::sha256(name.as_bytes());
        }
        let mut loaded = Loaded {
            config,
            keys: BTreeMap::new(),
            lineages: BTreeMap::new(),
        };
        let original = loaded.policy_hash(&loaded.config.repositories[0]).unwrap();
        loaded
            .config
            .keys
            .get_mut("transparency")
            .unwrap()
            .fingerprint = "e".repeat(64);
        let changed_key = loaded.policy_hash(&loaded.config.repositories[0]).unwrap();
        assert_ne!(original, changed_key);
        loaded.config.trust_roots.get_mut("public").unwrap().sha256 = "f".repeat(64);
        let changed_trust = loaded.policy_hash(&loaded.config.repositories[0]).unwrap();
        assert_ne!(changed_key, changed_trust);
        #[cfg(feature = "collector")]
        {
            let temporary = tempfile::tempdir().unwrap();
            let store = crate::collector::Store::open(
                &temporary.path().join("audit.sqlite"),
                b"01234567890123456789012345678901",
            )
            .unwrap();
            let mut activation = crate::ledger::Activation {
                repository_id: 1,
                revision: 1,
                policy_hash: original,
                classical_history: vec!["a".repeat(64)],
                hybrid_history: vec![],
            };
            store.activate(&activation).unwrap();
            activation.policy_hash = changed_trust;
            assert!(store.activate(&activation).is_err());
            activation.revision = 2;
            store.activate(&activation).unwrap();
        }
    }
}
