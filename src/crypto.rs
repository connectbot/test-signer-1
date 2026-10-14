use anyhow::{Result, bail, ensure};
use der::{Decode, DecodePem, Encode};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, EncodePublicKey},
    traits::PublicKeyParts,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature_traits_placeholder::*;
mod signature_traits_placeholder {
    pub use rsa::signature::{
        RandomizedSigner, SignatureEncoding, Verifier, hazmat::PrehashVerifier,
    };
}
use x509_cert::Certificate;
use zeroize::Zeroizing;

pub const RSA_SHA256: u32 = 0x0103;
pub const RSA_SHA512: u32 = 0x0104;
pub const ML_DSA: u32 = 0x0501;

pub enum PrivateKey {
    Rsa(Box<RsaPrivateKey>),
    MlDsa65(Box<ml_dsa::SigningKey<ml_dsa::MlDsa65>>),
}
pub struct SigningKey {
    pub private: PrivateKey,
    pub certificate: Vec<u8>,
}
impl SigningKey {
    pub fn load(key_path: &std::path::Path, cert_path: &std::path::Path) -> Result<Self> {
        let bytes = Zeroizing::new(std::fs::read(key_path)?);
        let cert_bytes = std::fs::read(cert_path)?;
        let certificate = if cert_bytes.starts_with(b"-----BEGIN") {
            Certificate::from_pem(&cert_bytes)?.to_der()?
        } else {
            Certificate::from_der(&cert_bytes)?.to_der()?
        };
        let cert = Certificate::from_der(&certificate)?;
        let private = if cert
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid
            .to_string()
            == "1.2.840.113549.1.1.1"
        {
            let key = if bytes.starts_with(b"-----BEGIN") {
                RsaPrivateKey::from_pkcs8_pem(std::str::from_utf8(&bytes)?)?
            } else {
                RsaPrivateKey::from_pkcs8_der(&bytes)?
            };
            ensure!(key.n().bits() >= 2048, "RSA key smaller than 2048 bits");
            key.validate()?;
            PrivateKey::Rsa(Box::new(key))
        } else {
            use ml_dsa::pkcs8::DecodePrivateKey as _;
            ensure!(
                cert.tbs_certificate
                    .subject_public_key_info
                    .algorithm
                    .oid
                    .to_string()
                    == "2.16.840.1.101.3.4.3.18",
                "unsupported signing key algorithm"
            );
            ensure!(
                !bytes.starts_with(b"-----BEGIN"),
                "ML-DSA keys must use DER PKCS#8"
            );
            let key = match ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_pkcs8_der(&bytes) {
                Ok(key) => key,
                Err(_) => {
                    // OpenSSL emits the RFC 9881 "both" form: seed + expanded key.
                    // Derive from the seed; never decode unchecked expanded material.
                    let info = rsa::pkcs8::PrivateKeyInfo::from_der(&bytes)?;
                    ensure!(
                        info.algorithm.oid.to_string() == "2.16.840.1.101.3.4.3.18",
                        "wrong ML-DSA private-key algorithm"
                    );
                    let pair = Vec::<der::asn1::OctetStringRef<'_>>::from_der(info.private_key)?;
                    ensure!(
                        pair.len() == 2
                            && pair[0].as_bytes().len() == 32
                            && pair[1].as_bytes().len() == 4032,
                        "ML-DSA key must contain a seed"
                    );
                    let mut seed = ml_dsa::Seed::try_from(pair[0].as_bytes())?;
                    let key = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed);
                    use zeroize::Zeroize;
                    seed.zeroize();
                    #[allow(deprecated)]
                    let expanded = Zeroizing::new(key.expanded_key().to_expanded());
                    use subtle::ConstantTimeEq;
                    ensure!(
                        bool::from(expanded.as_slice().ct_eq(pair[1].as_bytes())),
                        "ML-DSA seed and expanded key differ"
                    );
                    key
                }
            };
            PrivateKey::MlDsa65(Box::new(key))
        };
        let key = Self {
            private,
            certificate,
        };
        ensure!(
            key.spki()? == cert.tbs_certificate.subject_public_key_info.to_der()?,
            "private key and certificate differ"
        );
        Ok(key)
    }
    pub fn algorithm(&self) -> u32 {
        match self.private {
            PrivateKey::Rsa(_) => RSA_SHA256,
            PrivateKey::MlDsa65(_) => ML_DSA,
        }
    }
    pub fn fingerprint(&self) -> String {
        crate::sha256(&self.certificate)
    }
    pub fn spki(&self) -> Result<Vec<u8>> {
        match &self.private {
            PrivateKey::Rsa(k) => Ok(k.to_public_key().to_public_key_der()?.as_bytes().to_vec()),
            PrivateKey::MlDsa65(k) => {
                // ml-dsa uses the newer spki/der generation. Compare the wire encoding.
                let cert = Certificate::from_der(&self.certificate)?;
                let mut spki = cert.tbs_certificate.subject_public_key_info.clone();
                spki.subject_public_key =
                    der::asn1::BitString::from_bytes(&k.expanded_key().verifying_key().encode())?;
                Ok(spki.to_der()?)
            }
        }
    }
    pub fn sign(&self, algorithm: u32, message: &[u8]) -> Result<Vec<u8>> {
        match (&self.private, algorithm) {
            (PrivateKey::Rsa(k), RSA_SHA256) => {
                Ok(rsa::pkcs1v15::SigningKey::<Sha256>::new((**k).clone())
                    .try_sign_with_rng(&mut rand::rngs::OsRng, message)?
                    .to_vec())
            }
            (PrivateKey::Rsa(k), RSA_SHA512) => {
                Ok(rsa::pkcs1v15::SigningKey::<Sha512>::new((**k).clone())
                    .try_sign_with_rng(&mut rand::rngs::OsRng, message)?
                    .to_vec())
            }
            (PrivateKey::MlDsa65(k), ML_DSA) => Ok(k
                .expanded_key()
                .sign_deterministic(message, &[])?
                .encode()
                .to_vec()),
            _ => bail!("key does not support requested signature algorithm"),
        }
    }
}

pub fn verify(certificate: &[u8], algorithm: u32, message: &[u8], sig: &[u8]) -> Result<()> {
    use rsa::pkcs8::DecodePublicKey;
    let cert = Certificate::from_der(certificate)?;
    let spki = cert.tbs_certificate.subject_public_key_info.to_der()?;
    match algorithm {
        0x0101 => rsa::pss::VerifyingKey::<Sha256>::new(RsaPublicKey::from_public_key_der(&spki)?)
            .verify(message, &rsa::pss::Signature::try_from(sig)?)?,
        0x0102 => rsa::pss::VerifyingKey::<Sha512>::new(RsaPublicKey::from_public_key_der(&spki)?)
            .verify(message, &rsa::pss::Signature::try_from(sig)?)?,
        RSA_SHA256 => {
            rsa::pkcs1v15::VerifyingKey::<Sha256>::new(RsaPublicKey::from_public_key_der(&spki)?)
                .verify(message, &rsa::pkcs1v15::Signature::try_from(sig)?)?
        }
        RSA_SHA512 => {
            rsa::pkcs1v15::VerifyingKey::<Sha512>::new(RsaPublicKey::from_public_key_der(&spki)?)
                .verify(message, &rsa::pkcs1v15::Signature::try_from(sig)?)?
        }
        ML_DSA => {
            ensure!(
                cert.tbs_certificate
                    .subject_public_key_info
                    .algorithm
                    .oid
                    .to_string()
                    == "2.16.840.1.101.3.4.3.18",
                "wrong ML-DSA certificate"
            );
            let bytes = cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                .ok_or_else(|| anyhow::anyhow!("invalid public key bit string"))?;
            let enc = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(bytes)?;
            let key = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&enc);
            let signature = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(sig)?;
            ensure!(
                key.verify_with_context(message, &[], &signature),
                "invalid ML-DSA signature"
            );
        }
        _ => bail!("unsupported Android signature algorithm {algorithm:#x}"),
    }
    Ok(())
}

#[derive(Debug)]
pub struct RustCryptoProvider;
struct Hash<D: Digest + Send>(D);
impl<D: Digest + Send> sigstore_crypto::HashContext for Hash<D> {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.0.finalize().to_vec()
    }
}
impl sigstore_crypto::CryptoProvider for RustCryptoProvider {
    fn hash(
        &self,
        algorithm: sigstore_types::HashAlgorithm,
    ) -> sigstore_crypto::Result<Box<dyn sigstore_crypto::HashContext>> {
        use sigstore_types::HashAlgorithm::*;
        match algorithm {
            Sha2256 => Ok(Box::new(Hash(Sha256::new()))),
            Sha2384 => Ok(Box::new(Hash(Sha384::new()))),
            Sha2512 => Ok(Box::new(Hash(Sha512::new()))),
            _ => Err(sigstore_crypto::Error::UnsupportedAlgorithm("hash".into())),
        }
    }
    fn verify_raw(
        &self,
        scheme: sigstore_crypto::SigningScheme,
        key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> sigstore_crypto::Result<()> {
        use sigstore_crypto::SigningScheme::*;
        let result: Result<()> = (|| {
            if scheme == Ed25519 {
                ed25519_dalek::VerifyingKey::from_bytes(key.try_into()?)?
                    .verify_strict(data, &ed25519_dalek::Signature::try_from(signature)?)?;
                return Ok(());
            }
            let hash = match scheme.hash_algorithm() {
                Some(sigstore_types::HashAlgorithm::Sha2256) => Sha256::digest(data).to_vec(),
                Some(sigstore_types::HashAlgorithm::Sha2384) => Sha384::digest(data).to_vec(),
                Some(sigstore_types::HashAlgorithm::Sha2512) => Sha512::digest(data).to_vec(),
                _ => bail!("unsupported Sigstore algorithm"),
            };
            self.verify_prehashed(scheme, key, &hash, signature)
                .map_err(anyhow::Error::msg)
        })();
        result.map_err(|e| sigstore_crypto::Error::UnsupportedAlgorithm(e.to_string()))
    }
    fn verify_prehashed(
        &self,
        scheme: sigstore_crypto::SigningScheme,
        key: &[u8],
        digest: &[u8],
        signature: &[u8],
    ) -> sigstore_crypto::Result<()> {
        use rsa::pkcs1::DecodeRsaPublicKey;
        use sigstore_crypto::SigningScheme::*;
        let result: Result<()> = (|| {
            match scheme {
                EcdsaP256Sha256 | EcdsaP256Sha384 => {
                    p256::ecdsa::VerifyingKey::from_sec1_bytes(key)?
                        .verify_prehash(digest, &p256::ecdsa::Signature::from_der(signature)?)?
                }
                EcdsaP384Sha256 | EcdsaP384Sha384 => {
                    p384::ecdsa::VerifyingKey::from_sec1_bytes(key)?
                        .verify_prehash(digest, &p384::ecdsa::Signature::from_der(signature)?)?
                }
                RsaPkcs1Sha256 => {
                    rsa::pkcs1v15::VerifyingKey::<Sha256>::new(RsaPublicKey::from_pkcs1_der(key)?)
                        .verify_prehash(digest, &rsa::pkcs1v15::Signature::try_from(signature)?)?
                }
                RsaPkcs1Sha384 => {
                    rsa::pkcs1v15::VerifyingKey::<Sha384>::new(RsaPublicKey::from_pkcs1_der(key)?)
                        .verify_prehash(digest, &rsa::pkcs1v15::Signature::try_from(signature)?)?
                }
                RsaPkcs1Sha512 => {
                    rsa::pkcs1v15::VerifyingKey::<Sha512>::new(RsaPublicKey::from_pkcs1_der(key)?)
                        .verify_prehash(digest, &rsa::pkcs1v15::Signature::try_from(signature)?)?
                }
                RsaPssSha256 => {
                    rsa::pss::VerifyingKey::<Sha256>::new(RsaPublicKey::from_pkcs1_der(key)?)
                        .verify_prehash(digest, &rsa::pss::Signature::try_from(signature)?)?
                }
                RsaPssSha384 => {
                    rsa::pss::VerifyingKey::<Sha384>::new(RsaPublicKey::from_pkcs1_der(key)?)
                        .verify_prehash(digest, &rsa::pss::Signature::try_from(signature)?)?
                }
                RsaPssSha512 => {
                    rsa::pss::VerifyingKey::<Sha512>::new(RsaPublicKey::from_pkcs1_der(key)?)
                        .verify_prehash(digest, &rsa::pss::Signature::try_from(signature)?)?
                }
                _ => bail!("unsupported Sigstore algorithm"),
            }
            Ok(())
        })();
        result.map_err(|e| sigstore_crypto::Error::UnsupportedAlgorithm(e.to_string()))
    }
}
