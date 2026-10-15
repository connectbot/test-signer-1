use crate::config::{Repository, TrustRoot, now, ref_allowed};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use sigstore_trust_root::TrustedRoot;
use sigstore_types::{Bundle, SignatureContent};
use sigstore_verify::{VerificationPolicy, Verifier};

pub fn verify(
    bytes: &[u8],
    bundle_json: &Value,
    repo: &Repository,
    trust: &TrustRoot,
    commit: &str,
    run_id: u64,
    attempt: u64,
) -> Result<Value> {
    verify_digest(
        &crate::sha256(bytes),
        bundle_json,
        repo,
        trust,
        commit,
        run_id,
        attempt,
    )
}
/// Verify an independently obtained SHA-256 subject digest. Callers accepting
/// files should use verify(), which hashes the actual bytes itself.
pub fn verify_digest(
    digest: &str,
    bundle_json: &Value,
    repo: &Repository,
    trust: &TrustRoot,
    commit: &str,
    run_id: u64,
    attempt: u64,
) -> Result<Value> {
    ensure!(crate::config::valid_hash(digest), "invalid subject digest");
    ensure!(trust.valid_until > now()?, "trust material expired");
    let root_bytes = std::fs::read(&trust.file)?;
    ensure!(
        crate::sha256(&root_bytes) == trust.sha256,
        "trust-root hash differs"
    );
    let root = TrustedRoot::from_json(std::str::from_utf8(&root_bytes)?)?;
    let bundle = Bundle::from_json(&serde_json::to_string(bundle_json)?)?;
    let SignatureContent::DsseEnvelope(envelope) = &bundle.content else {
        anyhow::bail!("GitHub provenance requires DSSE")
    };
    let statement: Value = serde_json::from_slice(envelope.payload.as_bytes())?;
    ensure!(
        statement["_type"] == "https://in-toto.io/Statement/v1"
            && statement["predicateType"] == "https://slsa.dev/provenance/v1",
        "unsupported provenance statement"
    );
    ensure!(
        statement["subject"]
            .as_array()
            .is_some_and(|subjects| subjects.iter().any(|s| s["digest"]["sha256"] == digest)),
        "attestation subject digest differs"
    );
    let repository_uri = format!("https://github.com/{}", repo.name);
    let predicate = &statement["predicate"];
    ensure!(
        predicate["buildDefinition"]["buildType"]
            == "https://actions.github.io/buildtypes/workflow/v1",
        "unsupported build type"
    );
    let workflow = &predicate["buildDefinition"]["externalParameters"]["workflow"];
    let ref_name = workflow["ref"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("workflow ref missing"))?;
    ensure!(repo.allows_ref(ref_name), "build ref is not allowed");
    let caller = workflow["path"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("caller path missing"))?;
    ensure!(
        workflow["repository"] == repository_uri && repo.callers.contains_key(caller),
        "caller workflow differs"
    );
    let identity = predicate["runDetails"]["builder"]["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("builder identity missing"))?;
    let prefix = format!(
        "https://github.com/{}/{}@",
        repo.builder.repository, repo.builder.workflow
    );
    let builder_ref = identity
        .strip_prefix(&prefix)
        .ok_or_else(|| anyhow::anyhow!("builder identity differs"))?;
    ensure!(
        ref_allowed(&repo.builder.refs, builder_ref),
        "builder ref is not allowed"
    );
    let mut policy = VerificationPolicy::new(
        identity.to_string(),
        "https://token.actions.githubusercontent.com",
    );
    if repo.visibility == "private" {
        ensure!(
            !bundle
                .verification_material
                .timestamp_verification_data
                .rfc3161_timestamps
                .is_empty(),
            "private attestation requires trusted timestamp evidence"
        );
        policy = policy.skip_tlog_unsafe().skip_sct();
    }
    let result = Verifier::new(&root)?.verify(
        sigstore_types::Sha256Hash::from_hex(digest)?,
        &bundle,
        &policy,
    )?;
    ensure!(
        result.certificate_verified() && !result.verified_timestamps().is_empty(),
        "attestation lacks verified certificate/time"
    );
    let cert = result
        .certificate()
        .ok_or_else(|| anyhow::anyhow!("attestation certificate missing"))?;
    let claims = &cert.ci_claims;
    let require = |value: &Option<String>, expected: &str| -> Result<()> {
        ensure!(
            value.as_deref() == Some(expected),
            "GitHub certificate claim differs or is missing"
        );
        Ok(())
    };
    require(&claims.source_repository_identifier, &repo.id.to_string())?;
    require(&claims.source_repository_uri, &repository_uri)?;
    require(&claims.source_repository_digest, commit)?;
    require(&claims.source_repository_ref, ref_name)?;
    let invocation = format!("{repository_uri}/actions/runs/{run_id}/attempts/{attempt}");
    require(&claims.run_invocation_uri, &invocation)?;
    let runner = claims
        .runner_environment
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("runner claim missing"))?;
    ensure!(
        repo.runners.iter().any(|r| r == runner),
        "runner is not eligible"
    );
    let trigger = claims
        .build_trigger
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("event claim missing"))?;
    ensure!(
        repo.events.iter().any(|r| r == trigger),
        "event is not eligible"
    );
    require(
        &claims.source_repository_visibility_at_signing,
        &repo.visibility,
    )?;
    validate_claims(&statement, claims, repo, commit, run_id, attempt)?;
    Ok(
        json!({"bundle_sha256":crate::sha256(&serde_json::to_vec(bundle_json)?),"subject_sha256":digest,"caller":caller,"ref":ref_name,"commit":commit,"run":invocation,"runner":runner,"event":trigger,"builder":identity,"builder_commit":claims.build_signer_digest,"caller_commit":claims.build_config_digest,"trust_root_sha256":trust.sha256}),
    )
}

// Called only after cryptographic verification in verify(). Kept separate so
// every authorization branch can also be exercised with adversarial claims.
pub fn validate_claims(
    statement: &Value,
    claims: &sigstore_crypto::FulcioCiClaims,
    repo: &Repository,
    commit: &str,
    run_id: u64,
    attempt: u64,
) -> Result<()> {
    let predicate = &statement["predicate"];
    let definition = &predicate["buildDefinition"];
    ensure!(
        definition["buildType"] == "https://actions.github.io/buildtypes/workflow/v1",
        "unsupported build type"
    );
    let external = definition["externalParameters"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("external parameters missing"))?;
    ensure!(
        external.len() == 1 && external.contains_key("workflow"),
        "unexpected external parameters"
    );
    let workflow = &external["workflow"];
    let path = workflow["path"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("caller missing"))?;
    let source_ref = workflow["ref"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("ref missing"))?;
    let source_uri = format!("https://github.com/{}", repo.name);
    ensure!(
        workflow["repository"] == source_uri
            && repo.callers.contains_key(path)
            && repo.allows_ref(source_ref),
        "caller policy differs"
    );
    let require = |actual: &Option<String>, expected: &str| -> Result<()> {
        ensure!(
            actual.as_deref() == Some(expected),
            "certificate claim differs or is missing"
        );
        Ok(())
    };
    require(&claims.source_repository_uri, &source_uri)?;
    require(&claims.source_repository_identifier, &repo.id.to_string())?;
    require(&claims.source_repository_digest, commit)?;
    require(&claims.source_repository_ref, source_ref)?;
    require(
        &claims.build_config_uri,
        &format!("{source_uri}/{path}@{source_ref}"),
    )?;
    require(&claims.build_config_digest, commit)?;
    require(
        &claims.source_repository_visibility_at_signing,
        &repo.visibility,
    )?;
    let invocation = format!("{source_uri}/actions/runs/{run_id}/attempts/{attempt}");
    require(&claims.run_invocation_uri, &invocation)?;
    ensure!(
        predicate["runDetails"]["metadata"]["invocationId"] == invocation,
        "invocation differs"
    );
    let builder = predicate["runDetails"]["builder"]["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("builder missing"))?;
    require(&claims.build_signer_uri, builder)?;
    let prefix = format!(
        "https://github.com/{}/{}@",
        repo.builder.repository, repo.builder.workflow
    );
    let builder_ref = builder
        .strip_prefix(&prefix)
        .ok_or_else(|| anyhow::anyhow!("builder identity differs"))?;
    ensure!(
        ref_allowed(&repo.builder.refs, builder_ref),
        "builder ref differs"
    );
    let builder_commit = claims
        .build_signer_digest
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("builder commit missing"))?;
    ensure!(
        builder_commit.len() == 40 && builder_commit.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid builder commit"
    );
    ensure!(
        claims.runner_environment.as_deref() == Some("github-hosted")
            && repo
                .runners
                .iter()
                .any(|r| Some(r) == claims.runner_environment.as_ref()),
        "runner differs"
    );
    ensure!(
        repo.events
            .iter()
            .any(|e| Some(e) == claims.build_trigger.as_ref()),
        "event differs"
    );
    let internal = &definition["internalParameters"]["github"];
    let repository_id = repo.id.to_string();
    ensure!(
        internal["repository_id"].as_str() == Some(repository_id.as_str())
            && internal["runner_environment"] == "github-hosted"
            && internal["event_name"].as_str() == claims.build_trigger.as_deref(),
        "internal parameters differ"
    );
    let dependency = format!("git+{source_uri}@{source_ref}");
    ensure!(
        definition["resolvedDependencies"]
            .as_array()
            .is_some_and(|rows| rows
                .iter()
                .any(|r| r["uri"] == dependency && r["digest"]["gitCommit"] == commit)),
        "source dependency differs"
    );
    Ok(())
}
