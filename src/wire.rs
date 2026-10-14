//! Checked Android little-endian length-prefixed encoding.
use anyhow::{Result, ensure};
pub fn u32le(n: u32) -> Vec<u8> {
    n.to_le_bytes().to_vec()
}
pub fn lp(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut out = u32le(u32::try_from(bytes.len())?);
    out.extend_from_slice(bytes);
    Ok(out)
}
pub fn sequence(parts: &[Vec<u8>]) -> Result<Vec<u8>> {
    lp(&parts.concat())
}
pub struct Reader<'a> {
    pub remaining: &'a [u8],
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(n <= self.remaining.len(), "truncated Android structure");
        let (a, b) = self.remaining.split_at(n);
        self.remaining = b;
        Ok(a)
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
    }
    pub fn lp(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    pub fn finish(self) -> Result<()> {
        ensure!(self.remaining.is_empty(), "trailing Android data");
        Ok(())
    }
}
