use crate::config::{Repository, TrustRoot, now};
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
    let digest = crate::sha256(bytes);
    ensure!(
        statement["subject"]
            .as_array()
            .is_some_and(|subjects| subjects.iter().any(|s| s["digest"]["sha256"] == digest)),
        "attestation subject digest differs"
    );
    let repository_uri = format!("https://github.com/{}", repo.name);
    // The SAN is configured independently of caller-controlled provenance fields.
    let workflow = &statement["predicate"]["buildDefinition"]["externalParameters"]["workflow"];
    let ref_name = workflow["ref"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("workflow ref missing"))?;
    ensure!(
        repo.refs.iter().any(|r| r == ref_name),
        "build ref is not allowed"
    );
    ensure!(
        workflow["repository"] == repository_uri && workflow["path"] == repo.workflow,
        "provenance workflow differs"
    );
    let identity = format!("{repository_uri}/{}@{ref_name}", repo.workflow);
    let mut policy =
        VerificationPolicy::new(identity, "https://token.actions.githubusercontent.com");
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
    let result = Verifier::new(&root)?.verify(bytes, &bundle, &policy)?;
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
    Ok(
        json!({"bundle_sha256":crate::sha256(&serde_json::to_vec(bundle_json)?),"subject_sha256":digest,"workflow":repo.workflow,"ref":ref_name,"commit":commit,"run":invocation,"runner":runner,"event":trigger,"trust_root_sha256":trust.sha256}),
    )
}
