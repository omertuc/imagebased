use crate::locations::Location;
use pem::Pem;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    hash::{Hash, Hasher},
};
use x509_parser::{
    certificate::X509Certificate,
    public_key::{PublicKey::RSA, RSAPublicKey},
    x509::SubjectPublicKeyInfo,
};

#[derive(Hash, Eq, PartialEq, Clone)]
pub(crate) enum PrivateKey {
    Rsa(RsaPrivateKey),
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa(_) => write!(f, "<rsa_priv>"),
        }
    }
}

#[derive(Hash, Eq, PartialEq, Clone)]
pub(crate) enum PublicKey {
    Rsa(RsaPublicKey),
    Dummy,
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa(_) => write!(f, "<rsa_pub>"),
            Self::Dummy => write!(f, "Dummy"),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Certificate<'a> {
    pub(crate) issuer: String,
    pub(crate) subject: String,
    pub(crate) public_key: PublicKey,
    pub(crate) original: X509Certificate<'a>,
}

impl PartialEq for Certificate<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.issuer == other.issuer
            && self.subject == other.subject
            && self.public_key == other.public_key
    }
}

impl Eq for Certificate<'_> {}

impl Hash for Certificate<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.issuer.hash(state);
        self.subject.hash(state);
        self.public_key.hash(state);
    }
}

impl<'a> From<X509Certificate<'a>> for Certificate<'a> {
    fn from(cert: X509Certificate<'a>) -> Self {
        Certificate {
            issuer: cert.tbs_certificate.issuer.to_string(),
            subject: cert.tbs_certificate.subject.to_string(),
            public_key: PublicKey::from(cert.public_key().clone()),
            original: cert.clone(),
        }
    }
}

impl Display for CryptoGraph<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (root_cert, signed_certs) in &self.root_certs {
            for signed_cert in signed_certs {
                writeln!(f, "  \"{}\" -> \"{}\" ", root_cert, signed_cert,)?;
            }
        }
        Ok(())
    }
}

impl PublicKey {
    pub(crate) fn from_rsa(rsa_public_key: &RSAPublicKey) -> PublicKey {
        let modulus = rsa::BigUint::from_bytes_be(rsa_public_key.modulus);
        let exponent = rsa::BigUint::from_bytes_be(rsa_public_key.exponent);

        PublicKey::Rsa(RsaPublicKey::new(modulus, exponent).unwrap())
    }
}

impl From<SubjectPublicKeyInfo<'_>> for PublicKey {
    fn from(value: SubjectPublicKeyInfo) -> Self {
        match value.parsed().unwrap() {
            RSA(key) => PublicKey::from_rsa(&key),
            _ => PublicKey::Dummy,
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum Key {
    PrivateKey(Location, PrivateKey),
    PublicKey(Location, String),
}

type Locations = HashSet<Location>;
type CertAuthor = String;

#[derive(Clone, Debug)]
pub(crate) struct DistributedPrivateKey {
    pub(crate) private_key: PrivateKey,
    pub(crate) locations: Locations,
}

#[derive(Clone, Debug)]
pub(crate) struct DistributedCert<'a> {
    pub(crate) certificate: Certificate<'a>,
    pub(crate) locations: Locations,
}

#[derive(Debug)]
pub(crate) struct CertKeyPair<'a> {
    pub(crate) distributed_private_key: DistributedPrivateKey,
    pub(crate) distributed_cert: DistributedCert<'a>,
    pub(crate) signer: Box<Option<Certificate<'a>>>,
}

pub(crate) struct CryptoGraph<'a> {
    pub(crate) public_to_private: HashMap<PublicKey, PrivateKey>,
    pub(crate) identity_to_public: HashMap<String, String>,
    pub(crate) ca_certs: HashSet<String>,

    pub(crate) cert_key_pairs: HashMap<Certificate<'a>, CertKeyPair<'a>>,

    pub(crate) private_keys: HashMap<PrivateKey, DistributedPrivateKey>,
    pub(crate) certs: HashMap<Certificate<'a>, DistributedCert<'a>>,

    // Maps root cert to a list of certificates signed by it
    pub(crate) root_certs: HashMap<String, Vec<String>>,
}
