use crate::{
    archive::Entries,
    crypto::{RSA_SHA256, SigningKey},
    manifest::{bytes_field, fields, number_field},
};
use anyhow::{Result, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
pub const BUNDLE_PATH: &str =
    "BUNDLE-METADATA/com.android.tools.build.bundletool/code_transparency_signed.jwt";
pub const APK_PATH: &str = "META-INF/code_transparency_signed.jwt";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundletool_repo_path: Option<String>,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apk_path: Option<String>,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Statement {
    pub code_related_file: Vec<CodeFile>,
    pub version: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveResource {
    pub bundletool_version: String,
    pub resource_path: String,
    pub sha256: String,
    pub file: std::path::PathBuf,
}
pub fn statement(aab: &Entries, archive: Option<&ArchiveResource>) -> Result<Statement> {
    let mut code = vec![];
    let mut native = BTreeMap::new();
    for (name, entry) in aab {
        let Some((module, path)) = name.split_once('/') else {
            continue;
        };
        if !aab.contains_key(&format!("{module}/manifest/AndroidManifest.xml")) {
            continue;
        }
        let kind = if path.starts_with("dex/") {
            "DEX"
        } else if path.starts_with("lib/") && path.ends_with(".so") {
            "NATIVE_LIBRARY"
        } else {
            continue;
        };
        if kind == "NATIVE_LIBRARY" {
            ensure!(
                native
                    .insert(path.to_string(), crate::sha256(&entry.bytes))
                    .is_none(),
                "duplicate native-library APK path"
            );
        }
        code.push(CodeFile {
            path: Some(name.clone()),
            bundletool_repo_path: None,
            kind: kind.into(),
            apk_path: if kind == "NATIVE_LIBRARY" {
                Some(path.into())
            } else {
                None
            },
            sha256: crate::sha256(&entry.bytes),
        });
    }
    ensure!(!code.is_empty(), "bundle contains no code");
    let config = fields(
        &aab.get("BundleConfig.pb")
            .ok_or_else(|| anyhow::anyhow!("BundleConfig missing"))?
            .bytes,
    )?;
    let optim = bytes_field(&config, 2)?
        .map(fields)
        .transpose()?
        .unwrap_or_default();
    let store = bytes_field(&optim, 6)?.map(fields).transpose()?;
    let enabled = match store {
        Some(f) => number_field(&f, 1)?.unwrap_or(0) != 0,
        None => true,
    };
    if enabled {
        let resource = archive.ok_or_else(|| {
            anyhow::anyhow!("archiving enabled; provision matching bundletool archive resource")
        })?;
        let bundletool = fields(
            bytes_field(&config, 1)?
                .ok_or_else(|| anyhow::anyhow!("bundletool version missing"))?,
        )?;
        ensure!(
            std::str::from_utf8(bytes_field(&bundletool, 2)?.unwrap_or_default())?
                == resource.bundletool_version,
            "archive resource bundletool version differs"
        );
        let bytes = std::fs::read(&resource.file)?;
        ensure!(
            crate::sha256(&bytes) == resource.sha256,
            "archive resource hash differs"
        );
        code.push(CodeFile {
            path: None,
            bundletool_repo_path: Some(resource.resource_path.clone()),
            kind: "DEX".into(),
            apk_path: None,
            sha256: resource.sha256.clone(),
        });
    }
    code.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Statement {
        code_related_file: code,
        version: 1,
    })
}
pub fn check_apk(statement: &Statement, apk: &Entries) -> Result<()> {
    let dex: BTreeSet<_> = statement
        .code_related_file
        .iter()
        .filter(|f| f.kind == "DEX")
        .map(|f| f.sha256.as_str())
        .collect();
    let native: BTreeMap<_, _> = statement
        .code_related_file
        .iter()
        .filter_map(|f| f.apk_path.as_ref().map(|p| (p.as_str(), f.sha256.as_str())))
        .collect();
    let mut code_count = 0;
    for (path, entry) in apk {
        if path.ends_with(".dex") {
            ensure!(
                dex.contains(crate::sha256(&entry.bytes).as_str()),
                "APK DEX does not match AAB: {path}"
            );
            code_count += 1;
        }
        if path.ends_with(".so") {
            ensure!(
                native.get(path.as_str()).copied() == Some(crate::sha256(&entry.bytes).as_str()),
                "APK native code does not match AAB: {path}"
            );
            code_count += 1;
        }
    }
    ensure!(code_count > 0, "APK contains no code");
    Ok(())
}
pub fn sign(statement: &Statement, key: &SigningKey) -> Result<Vec<u8>> {
    ensure!(
        key.algorithm() == RSA_SHA256,
        "transparency key must be RSA"
    );
    let header = serde_json::json!({"alg":"RS256","x5c":[STANDARD.encode(&key.certificate)]});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(statement)?)
    );
    let signature = key.sign(RSA_SHA256, input.as_bytes())?;
    let jwt = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)).into_bytes();
    verify(&jwt, statement, &key.certificate)?;
    Ok(jwt)
}
pub fn verify(jwt: &[u8], expected: &Statement, cert: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(jwt)?;
    let parts: Vec<_> = text.split('.').collect();
    ensure!(parts.len() == 3, "invalid transparency JWT");
    let header: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    ensure!(
        header["alg"] == "RS256" && header["x5c"].as_array().is_some_and(|a| a.len() == 1),
        "invalid transparency algorithm/certificate chain"
    );
    ensure!(
        STANDARD.decode(
            header["x5c"][0]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("transparency certificate missing"))?
        )? == cert,
        "untrusted transparency certificate"
    );
    let input = format!("{}.{}", parts[0], parts[1]);
    crate::crypto::verify(
        cert,
        RSA_SHA256,
        input.as_bytes(),
        &URL_SAFE_NO_PAD.decode(parts[2])?,
    )?;
    let actual: Statement = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
    ensure!(&actual == expected, "transparency metadata differs");
    Ok(())
}
