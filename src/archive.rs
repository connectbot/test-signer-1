use anyhow::{Result, ensure};
use std::{
    collections::BTreeMap,
    io::{Cursor, Read, Seek, SeekFrom, Write},
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
        let size = usize::try_from(file.size())?;
        let mut data = Vec::new();
        data.try_reserve_exact(size)?;
        data.resize(size, 0);
        file.read_exact(&mut data)?;
        ensure!(file.read(&mut [0u8; 1])? == 0, "invalid ZIP size");
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
    write_limited(entries, apk, MAX_TOTAL)
}

pub fn write_limited(entries: &Entries, apk: bool, limit: u64) -> Result<Vec<u8>> {
    ensure!(limit > 0 && limit <= MAX_TOTAL, "invalid ZIP output limit");
    let mut writer = ZipWriter::new(LimitedBuffer {
        inner: Cursor::new(Vec::new()),
        limit: usize::try_from(limit)?,
    });
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
    Ok(writer.finish()?.inner.into_inner())
}

/// ZIP alignment, names, and compression overhead can enlarge an output. Enforce
/// its budget while writing, rather than after an unbounded allocation.
struct LimitedBuffer {
    inner: Cursor<Vec<u8>>,
    limit: usize,
}
impl Write for LimitedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let end = self
            .inner
            .position()
            .checked_add(buf.len() as u64)
            .and_then(|v| usize::try_from(v).ok())
            .filter(|&v| v <= self.limit)
            .ok_or_else(|| std::io::Error::other("ZIP output limit exceeded"))?;
        let bytes = self.inner.get_mut();
        if end > bytes.capacity() {
            let capacity = end.max(bytes.capacity().saturating_mul(2).min(self.limit));
            bytes
                .try_reserve_exact(capacity - bytes.len())
                .map_err(std::io::Error::other)?;
        }
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Seek for LimitedBuffer {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        let prior = self.inner.position();
        let next = self.inner.seek(position)?;
        if next > self.limit as u64 {
            self.inner.set_position(prior);
            return Err(std::io::Error::other("ZIP output limit exceeded"));
        }
        Ok(next)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_budgets_cover_expansion_and_apk_alignment() {
        let entries = BTreeMap::from([
            (
                "lib/arm64-v8a/a.so".into(),
                Entry {
                    bytes: vec![1],
                    stored: true,
                },
            ),
            (
                "lib/arm64-v8a/b.so".into(),
                Entry {
                    bytes: vec![2],
                    stored: true,
                },
            ),
        ]);
        // Two tiny native libraries require separate 16 KiB aligned offsets.
        assert!(write_limited(&entries, true, 20_000).is_err());
        // ZIP also repeats alignment extra fields in its central directory.
        let bytes = write_limited(&entries, true, 80_000).unwrap();
        assert!(read_limited(&bytes, 1).is_err());
        let decoded = read_limited(&bytes, 2).unwrap();
        assert_eq!(decoded["lib/arm64-v8a/a.so"].bytes, [1]);
        assert_eq!(decoded["lib/arm64-v8a/b.so"].bytes, [2]);
    }
}
