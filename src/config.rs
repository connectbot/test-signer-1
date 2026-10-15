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
    pub version: u32,
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
    pub callers: BTreeMap<String, Vec<String>>,
    pub builder: Builder,
    pub receipt_key: String,
    pub refs: Vec<String>,
    pub events: Vec<String>,
    pub runners: Vec<String>,
    pub visibility: String,
    pub revision: u64,
    pub profiles: BTreeMap<String, ArtifactProfile>,
    #[serde(default)]
    pub migrate_legacy_profile: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Builder {
    pub repository: String,
    pub repository_id: u64,
    pub workflow: String,
    pub refs: Vec<String>,
    pub sha256: Vec<String>,
    #[serde(default)]
    pub helpers: BTreeMap<String, Vec<String>>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactProfile {
    pub package: String,
    pub apk_artifact: String,
    pub aab_artifact: String,
    pub apk_file: String,
    pub aab_file: String,
    pub signing: Signing,
    pub archive_resource: Option<ArchiveResource>,
}
impl Repository {
    pub fn allows_ref(&self, value: &str) -> bool {
        ref_allowed(&self.refs, value)
    }
}
pub fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn valid_profile(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub fn ref_allowed(patterns: &[String], value: &str) -> bool {
    patterns.iter().any(|p| {
        p == value
            || (p.starts_with("refs/tags/")
                && p.ends_with('*')
                && !p[..p.len() - 1].contains('*')
                && value.starts_with(&p[..p.len() - 1]))
    })
}
fn workflow_path(value: &str) -> bool {
    value.starts_with(".github/workflows/") && safe_path(value)
}
pub fn safe_path(value: &str) -> bool {
    !value.is_empty()
        && value.split('/').all(|s| {
            !s.is_empty()
                && s != "."
                && s != ".."
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
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
    pub lineages: BTreeMap<(u64, String), RepositoryLineages>,
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
            config.version == 2,
            "configuration version 2 required; run scripts/migrate-config.py"
        );
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
        use rsa::pkcs8::EncodePublicKey;
        let app_spki = crate::crypto::github_app_key(&config.github_app_private_key)?
            .to_public_key()
            .to_public_key_der()?;
        let mut lineages = BTreeMap::new();
        let mut names = std::collections::BTreeSet::new();
        let mut ids = std::collections::BTreeSet::new();
        for repo in &config.repositories {
            ensure!(
                repo.id > 0
                    && repo.revision > 0
                    && names.insert(repo.name.clone())
                    && ids.insert(repo.id),
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
                !repo.callers.is_empty()
                    && repo.callers.iter().all(|(path, pins)| workflow_path(path)
                        && !pins.is_empty()
                        && pins.iter().all(|p| valid_hash(p))),
                "explicit caller workflow content pins required"
            );
            ensure!(
                repo.builder.repository_id > 0
                    && safe_path(&repo.builder.repository)
                    && repo.builder.repository.split('/').count() == 2
                    && workflow_path(&repo.builder.workflow)
                    && !repo.builder.sha256.is_empty()
                    && repo.builder.sha256.iter().all(|p| valid_hash(p))
                    && !repo.builder.refs.is_empty(),
                "invalid builder policy"
            );
            ensure!(
                repo.builder
                    .helpers
                    .iter()
                    .all(|(path, pins)| safe_path(path)
                        && !pins.is_empty()
                        && pins.iter().all(|p| valid_hash(p))),
                "invalid helper pins"
            );
            let receipt = keys
                .get(&repo.receipt_key)
                .ok_or_else(|| anyhow::anyhow!("receipt key missing"))?;
            ensure!(
                receipt.spki()?.as_slice() != app_spki.as_bytes(),
                "receipt key shares GitHub App key material"
            );
            ensure!(
                receipt.algorithm() == crate::crypto::RSA_SHA256,
                "receipt key must be RSA"
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
                    && repo.runners.iter().all(|r| r == "github-hosted"),
                "explicit build event/runner policy required"
            );
            ensure!(
                ["public", "private"].contains(&repo.visibility.as_str())
                    && config.trust_roots.contains_key(&repo.visibility),
                "trust profile missing"
            );
            ensure!(!repo.profiles.is_empty(), "signing profiles missing");
            if let Some(name) = &repo.migrate_legacy_profile {
                ensure!(
                    repo.profiles.contains_key(name),
                    "legacy migration profile missing"
                );
            }
            for (profile_id, profile) in &repo.profiles {
                ensure!(valid_profile(profile_id), "invalid profile ID");
                ensure!(
                    [&profile.apk_artifact, &profile.aab_artifact]
                        .iter()
                        .all(|s| !s.is_empty()
                            && s.len() <= 200
                            && s.bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"-_{}.".contains(&b)))
                        && safe_path(&profile.apk_file)
                        && safe_path(&profile.aab_file),
                    "invalid artifact selector"
                );
                let s = &profile.signing;
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
                let receipt_spki = receipt.spki()?;
                ensure!(
                    [original, current, upload, transparency]
                        .iter()
                        .all(|k| k.spki().is_ok_and(|s| s != receipt_spki)),
                    "receipt key shares Android signing material"
                );
                let lineage =
                    read_lineage(&s.lineage, &s.lineage_sha256, config.max_lineage_bytes)?;
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
                    let history_spki = cert.tbs_certificate.subject_public_key_info.to_der()?;
                    ensure!(
                        receipt_spki != history_spki,
                        "receipt key shares Android signing history"
                    );
                    ensure!(
                        transparency_spki != history_spki,
                        "transparency key shares APK key material"
                    );
                }
                ensure!(
                    transparency_spki != upload.spki()?,
                    "transparency key shares upload key material"
                );
                ensure!(
                    lineages
                        .insert((repo.id, profile_id.clone()), (lineage, hybrid))
                        .is_none(),
                    "duplicate signing profile"
                );
            }
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
    pub fn release_policy(
        &self,
        repo: &Repository,
        signer_revision: &str,
    ) -> Result<serde_json::Value> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        ensure!(
            signer_revision.len() == 40 && signer_revision.bytes().all(|b| b.is_ascii_hexdigit()),
            "full deployed signer commit required"
        );
        let receipt = &self.keys[&repo.receipt_key];
        let profiles = repo.profiles.iter().map(|(name,p)| {
            let s = &p.signing;
            let (lineage, _) = &self.lineages[&(repo.id, name.clone())];
            Ok((name.clone(), serde_json::json!({"package":p.package,"lineage_sha256":lineage.digest()?,"rotation_min_sdk":s.rotation_min_sdk,"hybrid_min_sdk":s.hybrid.as_ref().map(|_|37),"keys":{"original":self.keys[&s.original_key].fingerprint(),"classical":self.keys[&s.current_key].fingerprint(),"upload":self.keys[&s.upload_key].fingerprint(),"transparency":self.keys[&s.transparency_key].fingerprint(),"hybrid":s.hybrid.as_ref().map(|h|serde_json::json!({"rsa":self.keys[&h.classical_key].fingerprint(),"pqc":self.keys[&h.pqc_key].fingerprint()}))}})))
        }).collect::<Result<BTreeMap<_,_>>>()?;
        Ok(
            serde_json::json!({"version":2,"repository":repo.name,"repository_id":repo.id,"visibility":repo.visibility,"policy_hash":self.policy_hash(repo)?,"revision":repo.revision,"refs":repo.refs,"callers":repo.callers,"builder":repo.builder,"receipt_keys":{receipt.fingerprint():STANDARD.encode(&receipt.certificate)},"profiles":profiles,"signer_revision":signer_revision}),
        )
    }
    pub fn policy_hash(&self, repo: &Repository) -> Result<String> {
        let mut roles = vec![&repo.receipt_key];
        for p in repo.profiles.values() {
            let signing = &p.signing;
            roles.extend([
                &signing.original_key,
                &signing.current_key,
                &signing.upload_key,
                &signing.transparency_key,
            ]);
            if let Some(hybrid) = &signing.hybrid {
                roles.extend([&hybrid.classical_key, &hybrid.pqc_key]);
            }
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
            "version": 3, "repository": repo, "key_certificate_pins": pins,
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
                version: 2,
                profiles: std::collections::BTreeMap::from([(
                    "default".into(),
                    crate::ledger::History {
                        classical_history: vec!["a".repeat(64)],
                        hybrid_history: vec![],
                    },
                )]),
                migrate_legacy_profile: None,
            };
            store.activate(&activation).unwrap();
            activation.policy_hash = changed_trust;
            assert!(store.activate(&activation).is_err());
            activation.revision = 2;
            store.activate(&activation).unwrap();
        }
    }
}
