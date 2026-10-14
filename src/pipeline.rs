use crate::{
    apk, archive,
    config::{Loaded, Repository},
    github::Github,
    jar,
    ledger::{Activation, Claimed, Ledger},
    manifest, transparency,
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub async fn activate(loaded: &Loaded, ledger: &Ledger) -> Result<()> {
    for repo in &loaded.config.repositories {
        let (classical, hybrid) = &loaded.lineages[&repo.id];
        ledger
            .activate(&Activation {
                repository_id: repo.id,
                revision: repo.revision,
                policy_hash: loaded.policy_hash(repo)?,
                classical_history: classical.fingerprints(),
                hybrid_history: hybrid
                    .as_ref()
                    .map(|(_, _, e)| e.fingerprints())
                    .unwrap_or_default(),
            })
            .await?;
    }
    Ok(())
}
async fn artifact(
    github: &Github,
    repo: &Repository,
    run: &Value,
    artifact_name: &str,
    file_name: &str,
    cache: &mut BTreeMap<String, archive::Entries>,
) -> Result<(Vec<u8>, Value)> {
    let list = github
        .list(
            &format!(
                "/repos/{}/actions/runs/{}/artifacts",
                repo.name,
                run["id"]
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("run ID missing"))?
            ),
            Some("artifacts"),
        )
        .await?;
    let rows: Vec<_> = list
        .into_iter()
        .filter(|a| a["name"] == artifact_name && a["expired"] == false)
        .collect();
    ensure!(rows.len() == 1, "artifact missing, expired or ambiguous");
    let meta = &rows[0];
    ensure!(
        meta["workflow_run"]["id"] == run["id"]
            && meta["workflow_run"]["head_sha"] == run["head_sha"]
            && meta["workflow_run"]["repository_id"].as_u64() == Some(repo.id),
        "artifact belongs to another build"
    );
    if !cache.contains_key(artifact_name) {
        let id = meta["id"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("artifact ID missing"))?;
        let zip = github.download(repo, id).await?;
        ensure!(
            meta["digest"] == format!("sha256:{}", crate::sha256(&zip)),
            "GitHub artifact archive digest differs"
        );
        cache.insert(
            artifact_name.into(),
            archive::read_limited(&zip, github.max_bytes as u64)?,
        );
    }
    let entry = cache[artifact_name]
        .get(file_name)
        .ok_or_else(|| anyhow::anyhow!("configured artifact file missing"))?;
    ensure!(
        entry.bytes.len() <= github.max_bytes,
        "artifact file too large"
    );
    Ok((entry.bytes.clone(), meta.clone()))
}
async fn provenance(
    github: &Github,
    loaded: &Loaded,
    repo: &Repository,
    job: &Claimed,
    bytes: &[u8],
) -> Result<Value> {
    let bundles = github
        .list(
            &format!(
                "/repos/{}/attestations/sha256:{}",
                repo.name,
                crate::sha256(bytes)
            ),
            Some("attestations"),
        )
        .await?;
    let trust = &loaded.config.trust_roots[&repo.visibility];
    for b in bundles {
        if let Ok(result) = crate::attestation::verify(
            bytes,
            &b["bundle"],
            repo,
            trust,
            &job.job.commit,
            job.job.run_id,
            job.job.attempt,
        ) {
            return Ok(result);
        }
    }
    anyhow::bail!("no valid attestation satisfies signing policy")
}
pub async fn process(loaded: &Loaded, ledger: &Ledger, claim: &Claimed) -> Result<()> {
    let repo = loaded
        .config
        .repositories
        .iter()
        .find(|r| r.id == claim.job.repository_id)
        .ok_or_else(|| anyhow::anyhow!("repository is not allowed"))?;
    ensure!(
        claim.job.policy_hash == loaded.policy_hash(repo)? && claim.job.revision == repo.revision,
        "stale signing policy"
    );
    let github = Github::connect(&loaded.config)
        .await?
        .installation(repo)
        .await?;
    let metadata = github.get(&format!("/repos/{}", repo.name)).await?;
    ensure!(
        metadata["id"].as_u64() == Some(repo.id),
        "repository ID changed"
    );
    ensure!(
        metadata["visibility"] == repo.visibility,
        "repository visibility changed"
    );
    let run = github
        .get(&format!(
            "/repos/{}/actions/runs/{}/attempts/{}",
            repo.name, claim.job.run_id, claim.job.attempt
        ))
        .await?;
    ensure!(
        run["id"].as_u64() == Some(claim.job.run_id)
            && run["run_attempt"].as_u64() == Some(claim.job.attempt)
            && run["status"] == "completed"
            && run["conclusion"] == "success"
            && run["head_sha"] == claim.job.commit,
        "run attempt is not an eligible successful build"
    );
    ensure!(
        run["head_repository"]["id"].as_u64() == Some(repo.id),
        "fork builds are forbidden"
    );
    ensure!(
        repo.events.iter().any(|e| run["event"] == *e),
        "run event is not eligible"
    );
    let workflow = github
        .get(&format!(
            "/repos/{}/actions/workflows/{}",
            repo.name,
            run["workflow_id"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("workflow missing"))?
        ))
        .await?;
    ensure!(
        workflow["path"] == repo.workflow,
        "workflow differs from policy"
    );
    let mut cache = BTreeMap::new();
    let (apk_bytes, apk_meta) = artifact(
        &github,
        repo,
        &run,
        &repo.apk_artifact,
        &repo.apk_file,
        &mut cache,
    )
    .await?;
    let (aab_bytes, aab_meta) = artifact(
        &github,
        repo,
        &run,
        &repo.aab_artifact,
        &repo.aab_file,
        &mut cache,
    )
    .await?;
    drop(cache);
    let apk_provenance = provenance(&github, loaded, repo, claim, &apk_bytes).await?;
    let aab_provenance = provenance(&github, loaded, repo, claim, &aab_bytes).await?;
    apk::ensure_unsigned(&apk_bytes)?;
    let mut apk_entries = archive::read_limited(&apk_bytes, github.max_bytes as u64)?;
    let mut aab_entries = archive::read_limited(&aab_bytes, github.max_bytes as u64)?;
    archive::unsigned(&apk_entries)?;
    archive::unsigned(&aab_entries)?;
    let aab_manifest = &aab_entries
        .get("base/manifest/AndroidManifest.xml")
        .ok_or_else(|| anyhow::anyhow!("bundle manifest missing"))?
        .bytes;
    let apk_manifest = &apk_entries
        .get("AndroidManifest.xml")
        .ok_or_else(|| anyhow::anyhow!("APK manifest missing"))?
        .bytes;
    let aab_id = manifest::identity(aab_manifest, true)?;
    let apk_id = manifest::identity(apk_manifest, false)?;
    ensure!(
        apk_id.package == repo.package
            && aab_id.package == repo.package
            && apk_id.version == aab_id.version,
        "package or version differs"
    );
    ensure!(
        apk_id.min_sdk >= 24 && aab_id.min_sdk >= 24 && !apk_id.shared_uid && !aab_id.shared_uid,
        "unsupported SDK or sharedUserId"
    );
    let statement = transparency::statement(&aab_entries, repo.archive_resource.as_ref())?;
    transparency::check_apk(&statement, &apk_entries)?;
    let signing = &repo.signing;
    let key = |id: &str| {
        loaded
            .keys
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("signing key missing"))
    };
    let transparency_key = key(&signing.transparency_key)?;
    let upload_key = key(&signing.upload_key)?;
    let (lineage, hybrid_lineages) = &loaded.lineages[&repo.id];
    let hybrid = if let (Some(h), Some((c, p, _))) = (&signing.hybrid, hybrid_lineages) {
        Some(apk::Hybrid {
            classical: key(&h.classical_key)?,
            pqc: key(&h.pqc_key)?,
            classical_lineage: c,
            pqc_lineage: p,
        })
    } else {
        None
    };
    let profile = apk::Profile {
        original: key(&signing.original_key)?,
        current: key(&signing.current_key)?,
        lineage,
        rotation_min_sdk: signing.rotation_min_sdk,
        hybrid,
    };
    ledger.event(claim,"inputs.verified",json!({"apk":apk_provenance,"aab":aab_provenance,"apk_artifact_id":apk_meta["id"],"aab_artifact_id":aab_meta["id"],"package":repo.package,"version_code":apk_id.version})).await?;
    let intent = |operation: &str, k: &crate::crypto::SigningKey| json!({"operation":operation,"key_fingerprint":k.fingerprint(),"policy_hash":claim.job.policy_hash,"lineage_sha256":signing.lineage_sha256,"apk_input_sha256":crate::sha256(&apk_bytes),"aab_input_sha256":crate::sha256(&aab_bytes)});
    ledger
        .event(
            claim,
            "sign.intent",
            intent("code-transparency", transparency_key),
        )
        .await?;
    let jwt = transparency::sign(&statement, transparency_key)?;
    archive::add(&mut aab_entries, transparency::BUNDLE_PATH, jwt.clone())?;
    archive::add(&mut apk_entries, transparency::APK_PATH, jwt.clone())?;
    ledger
        .event(
            claim,
            "sign.result",
            json!({"operation":"code-transparency","sha256":crate::sha256(&jwt)}),
        )
        .await?;
    ledger
        .event(claim, "sign.intent", intent("aab-cms", upload_key))
        .await?;
    jar::sign(&mut aab_entries, upload_key)?;
    let signed_aab = archive::write(&aab_entries, false)?;
    ledger
        .event(
            claim,
            "sign.result",
            json!({"operation":"aab-cms","sha256":crate::sha256(&signed_aab)}),
        )
        .await?;
    for operation in apk::planned_operations(&profile)? {
        ledger.event(claim, "sign.intent", operation).await?;
    }
    let aligned = archive::write(&apk_entries, true)?;
    let signed_apk = apk::sign(&aligned, &profile)?;
    let final_apk = archive::read(&signed_apk)?;
    let final_aab = archive::read(&signed_aab)?;
    transparency::verify(
        &final_apk[transparency::APK_PATH].bytes,
        &statement,
        &transparency_key.certificate,
    )?;
    transparency::verify(
        &final_aab[transparency::BUNDLE_PATH].bytes,
        &statement,
        &transparency_key.certificate,
    )?;
    transparency::check_apk(&statement, &final_apk)?;
    jar::verify_output(&final_aab, upload_key)?;
    let final_statement = transparency::statement(&final_aab, repo.archive_resource.as_ref())?;
    ensure!(
        final_statement == statement,
        "AAB code changed during signing"
    );
    ledger.event(claim,"sign.result",json!({"operation":"apk","sha256":crate::sha256(&signed_apk),"operations":apk::planned_operations(&profile)?,"lineage_sha256":lineage.digest()?})).await?;
    let mut outputs = BTreeMap::from([
        ("app-signed.apk".to_string(), signed_apk),
        ("app-signed.aab".to_string(), signed_aab),
        ("code_transparency_signed.jwt".into(), jwt),
        (
            "transparency-certificate.der".into(),
            transparency_key.certificate.clone(),
        ),
        ("apk-lineage.bin".into(), lineage.file()?),
    ]);
    if let Some((c, p, e)) = hybrid_lineages {
        outputs.insert("apk-hybrid-rsa-lineage.bin".into(), c.file()?);
        outputs.insert("apk-hybrid-pqc-lineage.bin".into(), p.file()?);
        outputs.insert("apk-effective-lineage.bin".into(), e.file()?);
    }
    let receipt = json!({"version":1,"job":claim.job,"package":repo.package,"version_code":apk_id.version,"provenance":{"apk":apk_provenance,"aab":aab_provenance},"inputs":{"apk":crate::sha256(&apk_bytes),"aab":crate::sha256(&aab_bytes)},"outputs":outputs.iter().map(|(n,b)|json!({"name":n,"sha256":crate::sha256(b),"bytes":b.len()})).collect::<Vec<_>>(),"keys":{"upload":upload_key.fingerprint(),"transparency":transparency_key.fingerprint(),"original":profile.original.fingerprint(),"classical":profile.current.fingerprint(),"hybrid":profile.hybrid.as_ref().map(|h|json!({"rsa":h.classical.fingerprint(),"pqc":h.pqc.fingerprint()}))},"rotation_min_sdk":signing.rotation_min_sdk,"hybrid_min_sdk":profile.hybrid.as_ref().map(|_|37),"lineage":{"sha256":lineage.digest()?,"certificates":lineage.fingerprints(),"capabilities":lineage.nodes.iter().map(|n|n.flags).collect::<Vec<_>>()}});
    outputs.insert(
        "signing-receipt.json".into(),
        serde_json::to_vec_pretty(&receipt)?,
    );
    ledger.event(claim, "outputs.verified", receipt).await?;
    let release = github
        .release(repo, &claim.job.id, &claim.job.commit)
        .await?;
    let release_id = release["id"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("release ID missing"))?;
    for (name, bytes) in outputs {
        let asset = github.upload(repo, release_id, &name, &bytes).await?;
        ledger.event(claim,"upload.receipt",json!({"release_id":release_id,"asset_id":asset["id"],"name":name,"sha256":crate::sha256(&bytes)})).await?;
    }
    Ok(())
}
