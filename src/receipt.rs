//! Authenticated signing transactions. These are inputs to final provenance,
//! not a claim that the appliance independently meets a SLSA level.
use crate::crypto::{self, RSA_SHA256, SigningKey};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const PREDICATE_TYPE: &str = "urn:android-signer:receipt:v2";
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    payload_type: String,
    payload: String,
    signatures: Vec<Signature>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signature {
    keyid: String,
    sig: String,
}
pub fn pae(payload: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "DSSEv1 {} {} {} ",
        PAYLOAD_TYPE.len(),
        PAYLOAD_TYPE,
        payload.len()
    )
    .into_bytes();
    out.extend_from_slice(payload);
    out
}
pub fn sign(receipt: &Value, key: &SigningKey) -> Result<Vec<u8>> {
    ensure!(key.algorithm() == RSA_SHA256, "receipt key must be RSA");
    let outputs = receipt["outputs"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("receipt outputs missing"))?;
    let statement = serde_json::json!({"_type":"https://in-toto.io/Statement/v1", "predicateType":PREDICATE_TYPE,
        "subject": outputs.iter().map(|o| serde_json::json!({"name":o["name"],"digest":{"sha256":o["sha256"]}})).collect::<Vec<_>>(), "predicate":receipt});
    let payload = serde_json::to_vec(&statement)?;
    Ok(serde_json::to_vec_pretty(&Envelope {
        payload_type: PAYLOAD_TYPE.into(),
        payload: STANDARD.encode(&payload),
        signatures: vec![Signature {
            keyid: key.fingerprint(),
            sig: STANDARD.encode(key.sign(RSA_SHA256, &pae(&payload))?),
        }],
    })?)
}
pub fn verify(envelope: &[u8], certificate: &[u8], fingerprint: &str) -> Result<Value> {
    ensure!(
        crate::config::valid_hash(fingerprint) && crate::sha256(certificate) == fingerprint,
        "receipt certificate is not pinned"
    );
    let envelope: Envelope = serde_json::from_slice(envelope)?;
    ensure!(
        envelope.payload_type == PAYLOAD_TYPE && envelope.signatures.len() == 1,
        "unsupported receipt envelope"
    );
    let payload = STANDARD.decode(&envelope.payload)?;
    let signature = &envelope.signatures[0];
    ensure!(signature.keyid == fingerprint, "receipt key ID differs");
    crypto::verify(
        certificate,
        RSA_SHA256,
        &pae(&payload),
        &STANDARD.decode(&signature.sig)?,
    )?;
    let statement: Value = serde_json::from_slice(&payload)?;
    ensure!(
        statement["_type"] == "https://in-toto.io/Statement/v1"
            && statement["predicateType"] == PREDICATE_TYPE
            && statement["predicate"]["version"] == 2,
        "unsupported receipt statement"
    );
    let outputs = statement["predicate"]["outputs"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("receipt outputs missing"))?;
    let subjects: Vec<Value> = outputs
        .iter()
        .map(|o| serde_json::json!({"name":o["name"],"digest":{"sha256":o["sha256"]}}))
        .collect();
    ensure!(
        statement["subject"] == serde_json::json!(subjects),
        "receipt subjects differ"
    );
    Ok(statement["predicate"].clone())
}
