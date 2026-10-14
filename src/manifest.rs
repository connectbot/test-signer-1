//! Bounded parsing of Android binary XML and AAPT2 protobuf XML.
use anyhow::{Result, ensure};
use std::collections::BTreeMap;
type Element = (String, BTreeMap<(String, String), String>);
const ANDROID: &str = "http://schemas.android.com/apk/res/android";
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub package: String,
    pub version: u64,
    pub min_sdk: u32,
    pub shared_uid: bool,
}
#[derive(Clone)]
pub enum Field<'a> {
    Bytes(&'a [u8]),
    Number(u64),
}
pub fn fields(mut bytes: &[u8]) -> Result<Vec<(u32, Field<'_>)>> {
    fn varint(bytes: &mut &[u8]) -> Result<u64> {
        let mut value = 0u64;
        for i in 0..10 {
            ensure!(!bytes.is_empty(), "truncated protobuf");
            let b = bytes[0];
            *bytes = &bytes[1..];
            ensure!(i != 9 || b <= 1, "protobuf integer overflow");
            value |= u64::from(b & 127) << (i * 7);
            if b < 128 {
                return Ok(value);
            }
        }
        anyhow::bail!("invalid protobuf integer")
    }
    ensure!(bytes.len() <= 8 * 1024 * 1024, "protobuf too large");
    let mut out = vec![];
    while !bytes.is_empty() {
        ensure!(out.len() < 100_000, "too many protobuf fields");
        let tag = varint(&mut bytes)?;
        let num = u32::try_from(tag >> 3)?;
        ensure!(num > 0, "invalid protobuf field");
        let value = match tag & 7 {
            0 => Field::Number(varint(&mut bytes)?),
            2 => {
                let size = usize::try_from(varint(&mut bytes)?)?;
                ensure!(size <= bytes.len(), "truncated protobuf field");
                let (a, b) = bytes.split_at(size);
                bytes = b;
                Field::Bytes(a)
            }
            1 | 5 => {
                let size = if tag & 7 == 1 { 8 } else { 4 };
                ensure!(size <= bytes.len(), "truncated fixed protobuf field");
                bytes = &bytes[size..];
                continue;
            }
            _ => anyhow::bail!("unsupported protobuf wire type"),
        };
        out.push((num, value));
    }
    Ok(out)
}
pub fn bytes_field<'a>(fields: &[(u32, Field<'a>)], num: u32) -> Result<Option<&'a [u8]>> {
    let mut found = None;
    for (id, val) in fields {
        if *id == num {
            ensure!(found.is_none(), "duplicate protobuf field {num}");
            let Field::Bytes(b) = val else {
                anyhow::bail!("wrong protobuf field type")
            };
            found = Some(*b);
        }
    }
    Ok(found)
}
pub fn number_field(fields: &[(u32, Field<'_>)], num: u32) -> Result<Option<u64>> {
    let mut found = None;
    for (id, val) in fields {
        if *id == num {
            ensure!(found.is_none(), "duplicate protobuf field {num}");
            let Field::Number(n) = val else {
                anyhow::bail!("wrong protobuf field type")
            };
            found = Some(*n);
        }
    }
    Ok(found)
}
fn text(fields: &[(u32, Field<'_>)], num: u32) -> Result<String> {
    Ok(std::str::from_utf8(bytes_field(fields, num)?.unwrap_or_default())?.to_string())
}
fn collect_proto(bytes: &[u8], depth: usize, elements: &mut Vec<Element>) -> Result<()> {
    ensure!(
        depth < 100 && elements.len() < 10_000,
        "manifest nesting too deep"
    );
    let node = fields(bytes)?;
    let Some(element) = bytes_field(&node, 1)? else {
        return Ok(());
    };
    let e = fields(element)?;
    let name = text(&e, 3)?;
    let mut attrs = BTreeMap::new();
    for (id, val) in &e {
        if *id == 4 {
            let Field::Bytes(a) = val else {
                anyhow::bail!("invalid XML attribute")
            };
            let a = fields(a)?;
            let mut value = text(&a, 3)?;
            if value.is_empty()
                && let Some(compiled) = bytes_field(&a, 6)?
            {
                let item = fields(compiled)?;
                if let Some(primitive) = bytes_field(&item, 7)? {
                    value = number_field(&fields(primitive)?, 6)?
                        .or(number_field(&fields(primitive)?, 7)?)
                        .map(|n| n.to_string())
                        .unwrap_or_default();
                }
            }
            ensure!(
                attrs.insert((text(&a, 1)?, text(&a, 2)?), value).is_none(),
                "duplicate manifest attribute"
            );
        }
    }
    elements.push((name, attrs));
    for (id, val) in &e {
        if *id == 5 {
            let Field::Bytes(child) = val else {
                anyhow::bail!("invalid XML child")
            };
            collect_proto(child, depth + 1, elements)?;
        }
    }
    Ok(())
}
fn read_u16(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at + 2)
            .ok_or_else(|| anyhow::anyhow!("truncated AXML"))?
            .try_into()?,
    ))
}
fn read_u32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or_else(|| anyhow::anyhow!("truncated AXML"))?
            .try_into()?,
    ))
}
fn string_pool(bytes: &[u8]) -> Result<Vec<String>> {
    let count = read_u32(bytes, 8)? as usize;
    ensure!(count < 100_000, "large AXML string pool");
    let flags = read_u32(bytes, 16)?;
    let start = read_u32(bytes, 20)? as usize;
    let header = read_u16(bytes, 2)? as usize;
    let mut out = vec![];
    for i in 0..count {
        let offset = read_u32(bytes, header + i * 4)? as usize;
        let mut pos = start
            .checked_add(offset)
            .ok_or_else(|| anyhow::anyhow!("AXML overflow"))?;
        if flags & 0x100 != 0 {
            fn len(bytes: &[u8], pos: &mut usize) -> Result<usize> {
                let b = *bytes
                    .get(*pos)
                    .ok_or_else(|| anyhow::anyhow!("AXML string truncated"))?;
                *pos += 1;
                if b & 128 != 0 {
                    let c = *bytes
                        .get(*pos)
                        .ok_or_else(|| anyhow::anyhow!("AXML string truncated"))?;
                    *pos += 1;
                    Ok((((b & 127) as usize) << 8) | c as usize)
                } else {
                    Ok(b as usize)
                }
            }
            let _utf16 = len(bytes, &mut pos)?;
            let n = len(bytes, &mut pos)?;
            let value = bytes
                .get(pos..pos + n)
                .ok_or_else(|| anyhow::anyhow!("AXML string truncated"))?;
            ensure!(bytes.get(pos + n) == Some(&0), "AXML terminator missing");
            out.push(std::str::from_utf8(value)?.to_string());
        } else {
            let first = read_u16(bytes, pos)?;
            pos += 2;
            let n = if first & 0x8000 != 0 {
                let second = read_u16(bytes, pos)?;
                pos += 2;
                (((first & 0x7fff) as usize) << 16) | second as usize
            } else {
                first as usize
            };
            ensure!(n < 1024 * 1024, "AXML string too long");
            let mut units = vec![];
            for j in 0..n {
                units.push(read_u16(bytes, pos + j * 2)?);
            }
            ensure!(
                read_u16(bytes, pos + n * 2)? == 0,
                "AXML terminator missing"
            );
            out.push(String::from_utf16(&units)?);
        }
    }
    Ok(out)
}
fn collect_axml(bytes: &[u8]) -> Result<Vec<Element>> {
    ensure!(
        read_u16(bytes, 0)? == 3 && read_u32(bytes, 4)? as usize == bytes.len(),
        "invalid binary XML"
    );
    let mut pos = read_u16(bytes, 2)? as usize;
    let mut strings = vec![];
    let mut elements = vec![];
    fn string(strings: &[String], n: u32) -> Result<String> {
        if n == u32::MAX {
            return Ok(String::new());
        }
        strings
            .get(n as usize)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("AXML invalid string index"))
    }
    while pos < bytes.len() {
        let typ = read_u16(bytes, pos)?;
        let size = read_u32(bytes, pos + 4)? as usize;
        ensure!(size >= 8 && size <= bytes.len() - pos, "invalid AXML chunk");
        let chunk = &bytes[pos..pos + size];
        if typ == 1 {
            ensure!(strings.is_empty(), "duplicate string pool");
            strings = string_pool(chunk)?;
        }
        if typ == 0x102 {
            let name = string(&strings, read_u32(chunk, 20)?)?;
            let start = 16 + read_u16(chunk, 24)? as usize;
            let step = read_u16(chunk, 26)? as usize;
            let count = read_u16(chunk, 28)? as usize;
            ensure!(step >= 20, "invalid AXML attribute size");
            let mut attrs = BTreeMap::new();
            for i in 0..count {
                let a = start + i * step;
                let ns = string(&strings, read_u32(chunk, a)?)?;
                let name = string(&strings, read_u32(chunk, a + 4)?)?;
                let raw = read_u32(chunk, a + 8)?;
                let val = if raw != u32::MAX {
                    string(&strings, raw)?
                } else {
                    let typ = *chunk
                        .get(a + 15)
                        .ok_or_else(|| anyhow::anyhow!("truncated attribute"))?;
                    let v = read_u32(chunk, a + 16)?;
                    match typ {
                        3 => string(&strings, v)?,
                        16..=18 => v.to_string(),
                        _ => String::new(),
                    }
                };
                ensure!(
                    attrs.insert((ns, name), val).is_none(),
                    "duplicate manifest attribute"
                );
            }
            elements.push((name, attrs));
        }
        pos += size;
    }
    Ok(elements)
}
pub fn identity(bytes: &[u8], protobuf: bool) -> Result<Identity> {
    ensure!(bytes.len() <= 8 * 1024 * 1024, "manifest too large");
    let mut elements = vec![];
    if protobuf {
        collect_proto(bytes, 0, &mut elements)?;
    } else {
        elements = collect_axml(bytes)?;
    }
    let manifests: Vec<_> = elements.iter().filter(|(n, _)| n == "manifest").collect();
    ensure!(manifests.len() == 1, "manifest root missing or duplicated");
    let attrs = &manifests[0].1;
    let package = attrs
        .get(&(String::new(), "package".into()))
        .ok_or_else(|| anyhow::anyhow!("package missing"))?
        .clone();
    let minor: u32 = attrs
        .get(&(ANDROID.into(), "versionCode".into()))
        .ok_or_else(|| anyhow::anyhow!("versionCode missing"))?
        .parse()?;
    let major: u32 = attrs
        .get(&(ANDROID.into(), "versionCodeMajor".into()))
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(0);
    let version = (u64::from(major) << 32) | u64::from(minor);
    let uses: Vec<_> = elements.iter().filter(|(n, _)| n == "uses-sdk").collect();
    ensure!(uses.len() <= 1, "duplicate uses-sdk");
    let min_sdk = uses
        .first()
        .and_then(|e| e.1.get(&(ANDROID.into(), "minSdkVersion".into())))
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(1);
    Ok(Identity {
        package,
        version,
        min_sdk,
        shared_uid: attrs.contains_key(&(ANDROID.into(), "sharedUserId".into())),
    })
}
