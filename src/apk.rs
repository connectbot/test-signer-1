//! APK v2, v3, v3.1 and v3.2 encoding. Constants match android-17.0.0_r1.
use crate::{
    crypto::{ML_DSA, RSA_SHA256, RSA_SHA512, SigningKey, verify},
    lineage::{Lineage, validate_hybrid},
    wire::{Reader, lp, u32le},
};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256, Sha512};
const V2: u32 = 0x7109871a;
const V3: u32 = 0xf05368c0;
const V31: u32 = 0x1b93ad61;
const V32: u32 = 0x70e1c89f;
const POR: u32 = 0x3ba06f8c;
const ROTATION_MIN: u32 = 0x559f8b02;
const HYBRID_MIN: u32 = 0xbf940529;
const STRIPPING: u32 = 0xbeeff00d;
const MAX_SDK: u32 = i32::MAX as u32;
const MAGIC: &[u8] = b"APK Sig Block 42";

pub struct Profile<'a> {
    pub original: &'a SigningKey,
    pub current: &'a SigningKey,
    pub lineage: &'a Lineage,
    pub rotation_min_sdk: u32,
    pub hybrid: Option<Hybrid<'a>>,
}
pub struct Hybrid<'a> {
    pub classical: &'a SigningKey,
    pub pqc: &'a SigningKey,
    pub classical_lineage: &'a Lineage,
    pub pqc_lineage: &'a Lineage,
}
pub fn planned_operations(profile: &Profile<'_>) -> Result<Vec<serde_json::Value>> {
    Ok(specs(profile)?.iter().map(|s| serde_json::json!({"scheme_id":s.id,"key_fingerprint":s.key.fingerprint(),"algorithm":s.alg,"min_sdk":s.min,"max_sdk":s.max})).collect())
}
struct Layout {
    central: usize,
    eocd: usize,
}
fn layout(bytes: &[u8]) -> Result<Layout> {
    ensure!(bytes.len() >= 22, "truncated ZIP");
    let start = bytes.len().saturating_sub(22 + 65535);
    let eocd = (start..=bytes.len() - 22)
        .rev()
        .find(|&p| {
            bytes[p..p + 4] == [0x50, 0x4b, 0x05, 0x06]
                && p + 22 + u16::from_le_bytes([bytes[p + 20], bytes[p + 21]]) as usize
                    == bytes.len()
        })
        .ok_or_else(|| anyhow::anyhow!("ZIP EOCD missing"))?;
    ensure!(
        bytes[eocd + 4..eocd + 8] == [0, 0, 0, 0],
        "multi-disk ZIP forbidden"
    );
    ensure!(
        bytes[eocd + 8..eocd + 10] == bytes[eocd + 10..eocd + 12],
        "ZIP entry count mismatch"
    );
    let central = u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into()?) as usize;
    let size = u32::from_le_bytes(bytes[eocd + 12..eocd + 16].try_into()?) as usize;
    ensure!(
        central.checked_add(size) == Some(eocd),
        "ZIP64 or inconsistent central directory"
    );
    Ok(Layout { central, eocd })
}
pub fn ensure_unsigned(bytes: &[u8]) -> Result<()> {
    let l = layout(bytes)?;
    ensure!(
        l.central < 16 || &bytes[l.central - 16..l.central] != MAGIC,
        "APK already has signing block"
    );
    Ok(())
}
fn content_digest<D: Digest>(parts: &[&[u8]]) -> Result<Vec<u8>> {
    let count: usize = parts.iter().map(|p| p.len().div_ceil(1024 * 1024)).sum();
    let mut root = D::new();
    root.update([0x5a]);
    root.update(u32le(u32::try_from(count)?));
    for part in parts {
        for chunk in part.chunks(1024 * 1024) {
            let mut hash = D::new();
            hash.update([0xa5]);
            hash.update(u32le(u32::try_from(chunk.len())?));
            hash.update(chunk);
            root.update(hash.finalize());
        }
    }
    Ok(root.finalize().to_vec())
}
fn attribute(id: u32, bytes: &[u8]) -> Result<Vec<u8>> {
    let mut value = u32le(id);
    value.extend_from_slice(bytes);
    lp(&value)
}
struct Spec<'a> {
    id: u32,
    key: &'a SigningKey,
    alg: u32,
    min: u32,
    max: u32,
    attrs: Vec<u8>,
}
fn specs<'a>(p: &'a Profile<'a>) -> Result<Vec<Spec<'a>>> {
    p.lineage.validate(true)?;
    ensure!(
        [28, 33].contains(&p.rotation_min_sdk),
        "rotation SDK must be 28 or 33"
    );
    ensure!(
        p.lineage
            .nodes
            .first()
            .is_some_and(|n| n.certificate == p.original.certificate),
        "wrong original signer"
    );
    ensure!(
        p.lineage.last()?.certificate == p.current.certificate,
        "wrong current signer"
    );
    ensure!(
        p.original.algorithm() == RSA_SHA256 && p.current.algorithm() == RSA_SHA256,
        "classical APK keys must be RSA"
    );
    let rotated = p.original.certificate != p.current.certificate;
    let mut old_attrs = attribute(
        POR,
        &p.lineage.prefix_for(&p.original.certificate)?.proof()?,
    )?;
    let mut new_attrs = attribute(POR, &p.lineage.proof()?)?;
    if p.hybrid.is_some() {
        old_attrs.extend(attribute(HYBRID_MIN, &u32le(37))?);
        new_attrs.extend(attribute(HYBRID_MIN, &u32le(37))?);
    }
    let mut out = vec![Spec {
        id: V2,
        key: p.original,
        alg: RSA_SHA256,
        min: 24,
        max: MAX_SDK,
        attrs: attribute(STRIPPING, &u32le(3))?,
    }];
    if rotated && p.rotation_min_sdk == 33 {
        old_attrs.extend(attribute(ROTATION_MIN, &u32le(33))?);
        out.push(Spec {
            id: V3,
            key: p.original,
            alg: RSA_SHA256,
            min: 28,
            max: 32,
            attrs: old_attrs,
        });
        out.push(Spec {
            id: V31,
            key: p.current,
            alg: RSA_SHA256,
            min: 33,
            max: MAX_SDK,
            attrs: new_attrs,
        });
    } else {
        out.push(Spec {
            id: V3,
            key: p.current,
            alg: RSA_SHA256,
            min: 28,
            max: MAX_SDK,
            attrs: new_attrs,
        });
    }
    if let Some(h) = &p.hybrid {
        validate_hybrid(h.classical_lineage, h.pqc_lineage, true)?;
        ensure!(
            h.classical.algorithm() == RSA_SHA256 && h.pqc.algorithm() == ML_DSA,
            "hybrid requires RSA and ML-DSA-65"
        );
        ensure!(
            h.classical_lineage.last()?.certificate == h.classical.certificate
                && h.pqc_lineage.last()?.certificate == h.pqc.certificate,
            "hybrid lineage heads differ from keys"
        );
        ensure!(
            h.classical_lineage.nodes[..h.classical_lineage.nodes.len() - 1]
                .iter()
                .any(|n| n.certificate == p.current.certificate),
            "hybrid ancestry lacks classical fallback"
        );
        out.push(Spec {
            id: V32,
            key: h.classical,
            alg: RSA_SHA512,
            min: 37,
            max: MAX_SDK,
            attrs: attribute(POR, &h.classical_lineage.proof()?)?,
        });
        out.push(Spec {
            id: V32,
            key: h.pqc,
            alg: ML_DSA,
            min: 37,
            max: MAX_SDK,
            attrs: attribute(POR, &h.pqc_lineage.proof()?)?,
        });
    }
    Ok(out)
}
fn signed_data(spec: &Spec<'_>, digest: &[u8]) -> Result<Vec<u8>> {
    let mut record = u32le(spec.alg);
    record.extend(lp(digest)?);
    let mut out = lp(&lp(&record)?)?;
    out.extend(lp(&lp(&spec.key.certificate)?)?);
    if spec.id != V2 {
        out.extend(u32le(spec.min));
        out.extend(u32le(spec.max));
    }
    out.extend(lp(&spec.attrs)?);
    Ok(out)
}
fn signer(spec: &Spec<'_>, digest: &[u8]) -> Result<Vec<u8>> {
    let data = signed_data(spec, digest)?;
    let mut sig = u32le(spec.alg);
    sig.extend(lp(&spec.key.sign(spec.alg, &data)?)?);
    let mut out = lp(&data)?;
    if spec.id != V2 {
        out.extend(u32le(spec.min));
        out.extend(u32le(spec.max));
    }
    out.extend(lp(&lp(&sig)?)?);
    out.extend(lp(&spec.key.spki()?)?);
    lp(&out)
}
pub fn sign(bytes: &[u8], profile: &Profile<'_>) -> Result<Vec<u8>> {
    ensure_unsigned(bytes)?;
    let l = layout(bytes)?;
    let parts = [
        &bytes[..l.central],
        &bytes[l.central..l.eocd],
        &bytes[l.eocd..],
    ];
    let d256 = content_digest::<Sha256>(&parts)?;
    let d512 = content_digest::<Sha512>(&parts)?;
    let specs = specs(profile)?;
    let mut values = std::collections::BTreeMap::<u32, Vec<u8>>::new();
    for spec in &specs {
        values.entry(spec.id).or_default().extend(signer(
            spec,
            if spec.alg == RSA_SHA256 { &d256 } else { &d512 },
        )?);
    }
    let mut pairs = vec![];
    for (id, signers) in values {
        let value = lp(&signers)?;
        pairs.extend(u64::try_from(4 + value.len())?.to_le_bytes());
        pairs.extend(u32le(id));
        pairs.extend(value);
    }
    let size = u64::try_from(pairs.len() + 24)?;
    let mut block = size.to_le_bytes().to_vec();
    block.extend(pairs);
    block.extend(size.to_le_bytes());
    block.extend(MAGIC);
    let mut out = Vec::new();
    out.try_reserve_exact(
        bytes
            .len()
            .checked_add(block.len())
            .ok_or_else(|| anyhow::anyhow!("APK size overflow"))?,
    )?;
    out.extend_from_slice(&bytes[..l.central]);
    out.extend(&block);
    out.extend_from_slice(&bytes[l.central..]);
    let offset = l.eocd + block.len() + 16;
    out[offset..offset + 4].copy_from_slice(&u32::try_from(l.central + block.len())?.to_le_bytes());
    verify_output(&out, profile)?;
    Ok(out)
}
pub fn verify_output(bytes: &[u8], profile: &Profile<'_>) -> Result<()> {
    let l = layout(bytes)?;
    ensure!(
        l.central >= 32 && &bytes[l.central - 16..l.central] == MAGIC,
        "signing block missing"
    );
    let size = usize::try_from(u64::from_le_bytes(
        bytes[l.central - 24..l.central - 16].try_into()?,
    ))?;
    let block_start = l
        .central
        .checked_sub(size + 8)
        .ok_or_else(|| anyhow::anyhow!("invalid block size"))?;
    ensure!(
        u64::from_le_bytes(bytes[block_start..block_start + 8].try_into()?) == size as u64,
        "block size mismatch"
    );
    let mut eocd = bytes[l.eocd..].to_vec();
    eocd[16..20].copy_from_slice(&u32::try_from(block_start)?.to_le_bytes());
    let parts = [&bytes[..block_start], &bytes[l.central..l.eocd], &eocd];
    let d256 = content_digest::<Sha256>(&parts)?;
    let d512 = content_digest::<Sha512>(&parts)?;
    let expected = specs(profile)?;
    let mut seen = std::collections::BTreeSet::new();
    let mut r = Reader::new(&bytes[block_start + 8..l.central - 24]);
    while !r.remaining.is_empty() {
        let len = usize::try_from(u64::from_le_bytes(r.take(8)?.try_into()?))?;
        let mut pair = Reader::new(r.take(len)?);
        let id = pair.u32()?;
        let mut signers = Reader::new(pair.lp()?);
        pair.finish()?;
        let mut count = 0;
        while !signers.remaining.is_empty() {
            let mut signer = Reader::new(signers.lp()?);
            let data = signer.lp()?;
            let spec = expected
                .iter()
                .filter(|s| s.id == id)
                .nth(count)
                .ok_or_else(|| anyhow::anyhow!("unexpected signer"))?;
            ensure!(
                data == signed_data(spec, if spec.alg == RSA_SHA256 { &d256 } else { &d512 })?,
                "APK digest, lineage or SDK attributes differ"
            );
            if id != V2 {
                ensure!(
                    signer.u32()? == spec.min && signer.u32()? == spec.max,
                    "SDK ranges differ"
                );
            }
            let mut sigs = Reader::new(signer.lp()?);
            let mut sig = Reader::new(sigs.lp()?);
            sigs.finish()?;
            ensure!(sig.u32()? == spec.alg, "signature algorithm differs");
            let value = sig.lp()?;
            sig.finish()?;
            verify(&spec.key.certificate, spec.alg, data, value)?;
            ensure!(
                signer.lp()? == spec.key.spki()?,
                "signer public key mismatch"
            );
            signer.finish()?;
            count += 1;
        }
        ensure!(
            count == expected.iter().filter(|s| s.id == id).count(),
            "missing signer"
        );
        ensure!(seen.insert(id), "duplicate signing block");
    }
    ensure!(
        seen == expected.iter().map(|s| s.id).collect(),
        "missing signature scheme"
    );
    Ok(())
}
