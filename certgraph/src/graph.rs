use crate::locations::Location;
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::{collections::{HashMap, HashSet}, fmt::Display};
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

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub(crate) struct Certificate {
    pub(crate) issuer: String,
    pub(crate) subject: String,
    pub(crate) public_key: PublicKey,
}

impl From<X509Certificate<'_>> for Certificate {
    fn from(cert: X509Certificate<'_>) -> Self {
        Certificate {
            issuer: cert.tbs_certificate.issuer.to_string(),
            subject: cert.tbs_certificate.subject.to_string(),
            public_key: PublicKey::from(cert.public_key().clone()),
        }
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
pub(crate) struct DistributedCert {
    pub(crate) certificate: Certificate,
    pub(crate) locations: Locations,
}

#[derive(Debug)]
pub(crate) struct CertKeyPair {
    pub(crate) distributed_private_key: DistributedPrivateKey,
    pub(crate) distributed_cert: DistributedCert,
}

pub(crate) struct CryptoGraph {
    pub(crate) public_to_private: HashMap<PublicKey, PrivateKey>,
    pub(crate) identity_to_public: HashMap<String, String>,
    pub(crate) ca_certs: HashSet<String>,

    pub(crate) cert_key_pairs: HashMap<Certificate, CertKeyPair>,

    pub(crate) private_keys: HashMap<PrivateKey, DistributedPrivateKey>,
    pub(crate) certs: HashMap<CertAuthor, DistributedCert>,

    // Maps root cert to a list of certificates signed by it
    pub(crate) root_certs: HashMap<String, Vec<String>>,
}
