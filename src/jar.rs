use crate::{
    archive::{Entries, add},
    crypto::{RSA_SHA256, SigningKey},
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use der::{Decode, Encode};
use sha2::{Digest, Sha256};

fn header(name: &str, value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let line = format!("{name}: {value}");
    for (i, chunk) in line.as_bytes().chunks(70).enumerate() {
        if i > 0 {
            out.push(b' ');
        }
        out.extend(chunk);
        out.extend(b"\r\n");
    }
    out
}
fn digest_section(name: &str, contents: &[u8]) -> Vec<u8> {
    let mut section = header("Name", name);
    section.extend(header(
        "SHA-256-Digest",
        &STANDARD.encode(Sha256::digest(contents)),
    ));
    section.extend(b"\r\n");
    section
}
fn der_tlv(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if data.len() < 128 {
        out.push(data.len() as u8);
    } else {
        let bytes = data.len().to_be_bytes();
        let first = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend(&bytes[first..]);
    }
    out.extend(data);
    out
}
fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    der_tlv(0x30, &parts.concat())
}
fn oid(bytes: &[u8]) -> Vec<u8> {
    der_tlv(6, bytes)
}
const DATA_OID: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 7, 1];
const SIGNED_OID: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 7, 2];
const SHA256_OID: &[u8] = &[96, 134, 72, 1, 101, 3, 4, 2, 1];
const RSA_OID: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 1, 1];
fn algorithm(oid_bytes: &[u8]) -> Vec<u8> {
    seq(&[oid(oid_bytes), vec![5, 0]])
}
fn cms(sf: &[u8], key: &SigningKey) -> Result<Vec<u8>> {
    let cert = x509_cert::Certificate::from_der(&key.certificate)?;
    let version = vec![2, 1, 1];
    let signer = seq(&[
        version.clone(),
        seq(&[
            cert.tbs_certificate.issuer.to_der()?,
            cert.tbs_certificate.serial_number.to_der()?,
        ]),
        algorithm(SHA256_OID),
        algorithm(RSA_OID),
        der_tlv(4, &key.sign(RSA_SHA256, sf)?),
    ]);
    let signed = seq(&[
        version,
        der_tlv(0x31, &algorithm(SHA256_OID)),
        seq(&[oid(DATA_OID)]),
        der_tlv(0xa0, &key.certificate),
        der_tlv(0x31, &signer),
    ]);
    Ok(seq(&[oid(SIGNED_OID), der_tlv(0xa0, &signed)]))
}
pub fn sign(entries: &mut Entries, key: &SigningKey) -> Result<()> {
    ensure!(key.algorithm() == RSA_SHA256, "AAB upload key must be RSA");
    let mut manifest = b"Manifest-Version: 1.0\r\n\r\n".to_vec();
    let mut signature_sections = Vec::new();
    for (name, entry) in entries.iter() {
        ensure!(!name.contains(['\r', '\n']), "invalid JAR entry name");
        let section = digest_section(name, &entry.bytes);
        manifest.extend(&section);
        // Java assigns signers to payload entries listed in the .SF file.
        // A whole-manifest digest alone leaves every payload entry unsigned.
        signature_sections.extend(digest_section(name, &section));
    }
    let mut sf = b"Signature-Version: 1.0\r\n".to_vec();
    sf.extend(header(
        "SHA-256-Digest-Manifest",
        &STANDARD.encode(Sha256::digest(&manifest)),
    ));
    sf.extend(b"\r\n");
    sf.extend(signature_sections);
    let signature = cms(&sf, key)?;
    // Verify the signature operation independently before publishing the envelope.
    let envelope = cms::content_info::ContentInfo::from_der(&signature)?;
    let signed = envelope
        .content
        .decode_as::<cms::signed_data::SignedData>()?;
    ensure!(
        signed.signer_infos.0.len() == 1,
        "unexpected CMS signer count"
    );
    let signer = signed
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("CMS signer missing"))?;
    ensure!(
        signer.signed_attrs.is_none()
            && signer.digest_alg.oid.to_string() == "2.16.840.1.101.3.4.2.1",
        "unexpected CMS algorithm"
    );
    crate::crypto::verify(
        &key.certificate,
        RSA_SHA256,
        &sf,
        signer.signature.as_bytes(),
    )?;
    add(entries, "META-INF/MANIFEST.MF", manifest)?;
    add(entries, "META-INF/SIGNER.SF", sf)?;
    add(entries, "META-INF/SIGNER.RSA", signature)?;
    Ok(())
}

pub fn verify_output(entries: &Entries, key: &SigningKey) -> Result<()> {
    let read = |name: &str| -> Result<&[u8]> {
        Ok(&entries
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("JAR signing entry missing"))?
            .bytes)
    };
    let manifest = read("META-INF/MANIFEST.MF")?;
    let sf = read("META-INF/SIGNER.SF")?;
    let mut expected = b"Manifest-Version: 1.0\r\n\r\n".to_vec();
    let mut expected_sections = Vec::new();
    for (name, entry) in entries {
        if [
            "META-INF/MANIFEST.MF",
            "META-INF/SIGNER.SF",
            "META-INF/SIGNER.RSA",
        ]
        .contains(&name.as_str())
        {
            continue;
        }
        let section = digest_section(name, &entry.bytes);
        expected.extend(&section);
        expected_sections.extend(digest_section(name, &section));
    }
    ensure!(manifest == expected, "JAR manifest content digests differ");
    let mut expected_sf = b"Signature-Version: 1.0\r\n".to_vec();
    expected_sf.extend(header(
        "SHA-256-Digest-Manifest",
        &STANDARD.encode(Sha256::digest(manifest)),
    ));
    expected_sf.extend(b"\r\n");
    expected_sf.extend(expected_sections);
    ensure!(sf == expected_sf, "JAR signature file digest differs");
    let envelope = cms::content_info::ContentInfo::from_der(read("META-INF/SIGNER.RSA")?)?;
    ensure!(
        envelope.content_type.to_string() == "1.2.840.113549.1.7.2",
        "unexpected CMS content type"
    );
    let signed = envelope
        .content
        .decode_as::<cms::signed_data::SignedData>()?;
    ensure!(
        signed.signer_infos.0.len() == 1,
        "unexpected CMS signer count"
    );
    let signer = signed
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("CMS signer missing"))?;
    ensure!(
        signer.signed_attrs.is_none()
            && signer.digest_alg.oid.to_string() == "2.16.840.1.101.3.4.2.1"
            && signer.signature_algorithm.oid.to_string() == "1.2.840.113549.1.1.1",
        "unexpected CMS algorithm or attributes"
    );
    let certs = signed
        .certificates
        .ok_or_else(|| anyhow::anyhow!("CMS certificate missing"))?;
    ensure!(certs.0.len() == 1, "unexpected CMS certificate count");
    let cert = certs
        .0
        .iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("CMS certificate missing"))?;
    let cms::cert::CertificateChoices::Certificate(cert) = cert else {
        anyhow::bail!("unsupported CMS certificate")
    };
    ensure!(cert.to_der()? == key.certificate, "CMS certificate differs");
    crate::crypto::verify(
        &key.certificate,
        RSA_SHA256,
        sf,
        signer.signature.as_bytes(),
    )?;
    Ok(())
}
