//! Android SigningCertificateLineage v1 and APK proof-of-rotation v1.
use crate::{
    crypto::{SigningKey, verify},
    wire::{Reader, lp, u32le},
};
use anyhow::{Result, ensure};
use der::Decode;
use std::collections::BTreeSet;

pub const DEFAULT_FLAGS: u32 = 1 | 2 | 4 | 16; // installed-data, shared-UID, permissions, auth; no rollback
pub const ROLLBACK: u32 = 8;
pub const DEFAULT_LIMIT: usize = 1024 * 1024;
const MAGIC: u32 = 0x3eff39d1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub certificate: Vec<u8>,
    pub parent_algorithm: u32,
    pub flags: u32,
    pub next_algorithm: u32,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lineage {
    pub nodes: Vec<Node>,
}
impl Node {
    fn signed_data(&self) -> Result<Vec<u8>> {
        let mut data = lp(&self.certificate)?;
        data.extend(u32le(self.parent_algorithm));
        Ok(data)
    }
    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = lp(&self.signed_data()?)?;
        out.extend(u32le(self.flags));
        out.extend(u32le(self.next_algorithm));
        out.extend(lp(&self.signature)?);
        Ok(out)
    }
}
impl Lineage {
    pub fn root(key: &SigningKey) -> Self {
        Self {
            nodes: vec![Node {
                certificate: key.certificate.clone(),
                parent_algorithm: 0,
                flags: DEFAULT_FLAGS,
                next_algorithm: key.algorithm(),
                signature: vec![],
            }],
        }
    }
    pub fn read(bytes: &[u8], limit: usize) -> Result<Self> {
        ensure!(bytes.len() <= limit, "lineage exceeds byte limit");
        let mut r = Reader::new(bytes);
        ensure!(
            r.u32()? == MAGIC && r.u32()? == 1,
            "invalid lineage file version or magic"
        );
        let proof = r.lp()?;
        r.finish()?;
        Self::from_proof(proof, limit)
    }
    pub fn from_proof(bytes: &[u8], limit: usize) -> Result<Self> {
        ensure!(bytes.len() <= limit, "lineage exceeds byte limit");
        let mut r = Reader::new(bytes);
        ensure!(r.u32()? == 1, "unsupported proof-of-rotation version");
        let mut nodes = vec![];
        while !r.remaining.is_empty() {
            let mut node = Reader::new(r.lp()?);
            let mut signed = Reader::new(node.lp()?);
            let certificate = signed.lp()?.to_vec();
            let parent_algorithm = signed.u32()?;
            signed.finish()?;
            let flags = node.u32()?;
            let next_algorithm = node.u32()?;
            let signature = node.lp()?.to_vec();
            node.finish()?;
            nodes.push(Node {
                certificate,
                parent_algorithm,
                flags,
                next_algorithm,
                signature,
            });
        }
        let lineage = Self { nodes };
        lineage.validate(true)?;
        Ok(lineage)
    }
    pub fn validate(&self, allow_rollback: bool) -> Result<()> {
        ensure!(!self.nodes.is_empty(), "empty lineage");
        let mut identities = BTreeSet::new();
        for (i, node) in self.nodes.iter().enumerate() {
            x509_cert::Certificate::from_der(&node.certificate)?;
            ensure!(
                identities.insert(crate::sha256(&node.certificate)),
                "repeated lineage identity"
            );
            ensure!(node.flags & !31 == 0, "unknown lineage capabilities");
            ensure!(
                allow_rollback || node.flags & ROLLBACK == 0,
                "rollback not permitted by policy"
            );
            if i == 0 {
                ensure!(
                    node.parent_algorithm == 0 && node.signature.is_empty(),
                    "invalid lineage root"
                );
            } else {
                let prev = &self.nodes[i - 1];
                ensure!(
                    prev.next_algorithm == node.parent_algorithm,
                    "lineage algorithm mismatch"
                );
                verify(
                    &prev.certificate,
                    node.parent_algorithm,
                    &node.signed_data()?,
                    &node.signature,
                )?;
            }
        }
        Ok(())
    }
    pub fn append(&self, old: &SigningKey, new: &SigningKey, flags: u32) -> Result<Self> {
        self.validate(true)?;
        ensure!(
            self.last()?.certificate == old.certificate,
            "old signer is not the lineage head"
        );
        let mut out = self.clone();
        let last = out
            .nodes
            .last_mut()
            .ok_or_else(|| anyhow::anyhow!("empty lineage"))?;
        if last.next_algorithm == 0 {
            last.next_algorithm = old.algorithm();
        }
        let mut node = Node {
            certificate: new.certificate.clone(),
            parent_algorithm: last.next_algorithm,
            flags,
            next_algorithm: new.algorithm(),
            signature: vec![],
        };
        node.signature = old.sign(node.parent_algorithm, &node.signed_data()?)?;
        out.nodes.push(node);
        out.validate(true)?;
        Ok(out)
    }
    pub fn last(&self) -> Result<&Node> {
        self.nodes
            .last()
            .ok_or_else(|| anyhow::anyhow!("empty lineage"))
    }
    pub fn proof(&self) -> Result<Vec<u8>> {
        let mut out = u32le(1);
        for node in &self.nodes {
            out.extend(lp(&node.encode()?)?);
        }
        Ok(out)
    }
    pub fn file(&self) -> Result<Vec<u8>> {
        let mut out = u32le(MAGIC);
        out.extend(u32le(1));
        out.extend(lp(&self.proof()?)?);
        Ok(out)
    }
    pub fn digest(&self) -> Result<String> {
        Ok(crate::sha256(&self.file()?))
    }
    pub fn fingerprints(&self) -> Vec<String> {
        self.nodes
            .iter()
            .map(|n| crate::sha256(&n.certificate))
            .collect()
    }
    pub fn extends(&self, old: &Self) -> bool {
        if old.nodes.len() > self.nodes.len() {
            return false;
        }
        old.nodes
            .iter()
            .zip(&self.nodes)
            .enumerate()
            .all(|(i, (a, b))| {
                a.certificate == b.certificate
                    && a.flags == b.flags
                    && a.parent_algorithm == b.parent_algorithm
                    && a.signature == b.signature
                    && (a.next_algorithm == b.next_algorithm
                        || (i + 1 == old.nodes.len() && a.next_algorithm == 0))
            })
    }
    pub fn prefix_for(&self, cert: &[u8]) -> Result<Self> {
        let i = self
            .nodes
            .iter()
            .position(|n| n.certificate == cert)
            .ok_or_else(|| anyhow::anyhow!("signer absent from lineage"))?;
        Ok(Self {
            nodes: self.nodes[..=i].to_vec(),
        })
    }
}

pub fn validate_hybrid(classical: &Lineage, pqc: &Lineage, allow_rollback: bool) -> Result<()> {
    classical.validate(allow_rollback)?;
    pqc.validate(allow_rollback)?;
    ensure!(
        classical.nodes.len() >= 2 && classical.nodes.len() == pqc.nodes.len(),
        "hybrid signers require matching ancestry"
    );
    let n = classical.nodes.len() - 1;
    ensure!(
        classical.nodes[..n] == pqc.nodes[..n],
        "hybrid ancestry or capabilities differ"
    );
    ensure!(
        classical.last()?.certificate != pqc.last()?.certificate,
        "hybrid identities must differ"
    );
    let mut seen = BTreeSet::new();
    for node in &classical.nodes[..n] {
        seen.insert(crate::sha256(&node.certificate));
    }
    ensure!(
        !seen.contains(&crate::sha256(&classical.last()?.certificate))
            && !seen.contains(&crate::sha256(&pqc.last()?.certificate)),
        "hybrid key reused"
    );
    Ok(())
}
