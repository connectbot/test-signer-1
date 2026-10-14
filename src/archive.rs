use anyhow::{Result, ensure};
use std::{
    collections::BTreeMap,
    io::{Cursor, Read, Write},
};
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};
pub const MAX_TOTAL: u64 = 1024 * 1024 * 1024;
pub const MAX_ENTRY: u64 = 256 * 1024 * 1024;
#[derive(Clone)]
pub struct Entry {
    pub bytes: Vec<u8>,
    pub stored: bool,
}
pub type Entries = BTreeMap<String, Entry>;

pub fn read(bytes: &[u8]) -> Result<Entries> {
    read_limited(bytes, MAX_TOTAL)
}
pub fn read_limited(bytes: &[u8], limit: u64) -> Result<Entries> {
    ensure!(limit > 0 && limit <= MAX_TOTAL, "invalid ZIP limit");
    let mut zip = ZipArchive::new(Cursor::new(bytes))?;
    ensure!(zip.len() <= 20_000, "too many ZIP entries");
    let mut entries = BTreeMap::new();
    let mut total = 0u64;
    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        let name = file.name().to_string();
        ensure!(
            !name.starts_with('/')
                && !name.contains('\\')
                && !name
                    .split('/')
                    .any(|p| p == ".." || p == "." || p.is_empty() && !file.is_dir()),
            "unsafe ZIP path"
        );
        ensure!(file.enclosed_name().is_some(), "unsafe ZIP path");
        ensure!(
            file.unix_mode().unwrap_or(0) & 0o170000 != 0o120000,
            "ZIP symlink forbidden"
        );
        if file.is_dir() {
            continue;
        }
        ensure!(file.size() <= MAX_ENTRY, "ZIP entry too large");
        total = total
            .checked_add(file.size())
            .ok_or_else(|| anyhow::anyhow!("ZIP size overflow"))?;
        ensure!(total <= limit, "ZIP decompression limit exceeded");
        let stored = file.compression() == CompressionMethod::Stored;
        let mut data = Vec::new();
        file.by_ref().take(MAX_ENTRY + 1).read_to_end(&mut data)?;
        ensure!(data.len() as u64 == file.size(), "invalid ZIP size");
        ensure!(
            entries
                .insert(
                    name,
                    Entry {
                        bytes: data,
                        stored
                    }
                )
                .is_none(),
            "duplicate ZIP entry"
        );
    }
    Ok(entries)
}
pub fn unsigned(entries: &Entries) -> Result<()> {
    for name in entries.keys() {
        let upper = name.to_ascii_uppercase();
        ensure!(
            !(upper.starts_with("META-INF/")
                && (upper.ends_with(".SF")
                    || upper.ends_with(".RSA")
                    || upper.ends_with(".DSA")
                    || upper.ends_with(".EC")
                    || upper == "META-INF/MANIFEST.MF")),
            "input already contains a JAR signature"
        );
        ensure!(
            !name.ends_with("code_transparency_signed.jwt"),
            "pre-existing transparency is forbidden"
        );
    }
    Ok(())
}
pub fn write(entries: &Entries, apk: bool) -> Result<Vec<u8>> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    // JarInputStream only recognizes a manifest at the start and reads signing
    // metadata before payloads. Bundle metadata sorts before META-INF, so the
    // map's lexical order alone produces inconsistent streaming verification.
    let mut ordered: Vec<_> = entries.iter().collect();
    if !apk {
        ordered.sort_by_key(|(name, _)| {
            if name.as_str() == "META-INF/MANIFEST.MF" {
                0
            } else if name.starts_with("META-INF/") {
                1
            } else {
                2
            }
        });
    }
    for (name, entry) in ordered {
        let mut options = SimpleFileOptions::default()
            .compression_method(if entry.stored {
                CompressionMethod::Stored
            } else {
                CompressionMethod::Deflated
            })
            .unix_permissions(0o644);
        if apk && entry.stored {
            options =
                options.with_alignment(if name.starts_with("lib/") && name.ends_with(".so") {
                    16384
                } else {
                    4
                });
        }
        writer.start_file(name, options)?;
        writer.write_all(&entry.bytes)?;
    }
    Ok(writer.finish()?.into_inner())
}
pub fn add(entries: &mut Entries, name: &str, bytes: Vec<u8>) -> Result<()> {
    ensure!(
        entries
            .insert(
                name.to_string(),
                Entry {
                    bytes,
                    stored: false
                }
            )
            .is_none(),
        "entry already exists: {name}"
    );
    Ok(())
}
