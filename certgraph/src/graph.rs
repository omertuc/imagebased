use crate::locations::Location;
use bytes::Bytes;
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    hash::{Hash, Hasher},
};
use x509_certificate::CapturedX509Certificate;

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
    Raw(Bytes),
    // Dummy,
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa(_) => write!(f, "<rsa_pub>"),
            Self::Raw(x) => write!(f, "<raw_pub: {:?}>", x),
            // Self::Dummy => write!(f, "Dummy"),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Certificate {
    pub(crate) issuer: String,
    pub(crate) subject: String,
    pub(crate) public_key: PublicKey,
    pub(crate) original: CapturedX509Certificate,
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.issuer == other.issuer
            && self.subject == other.subject
            && self.public_key == other.public_key
    }
}

impl Eq for Certificate {}

impl Hash for Certificate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.issuer.hash(state);
        self.subject.hash(state);
        self.public_key.hash(state);
    }
}

impl From<CapturedX509Certificate> for Certificate {
    fn from(cert: CapturedX509Certificate) -> Self {
        Certificate {
            issuer: cert
                .issuer_name()
                .user_friendly_str()
                .unwrap_or_else(|_error| "undecodable".to_string()),
            subject: cert
                .subject_name()
                .user_friendly_str()
                .unwrap_or_else(|_error| {
                    return "undecodable".to_string();
                }),
            public_key: PublicKey::from(cert.public_key_data()),
            original: cert,
        }
    }
}

impl Display for CryptoGraph {
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
    // pub(crate) fn from_rsa(rsa_public_key: &RSAPublicKey) -> PublicKey {
    //     let modulus = rsa::BigUint::from_bytes_be(rsa_public_key.modulus);
    //     let exponent = rsa::BigUint::from_bytes_be(rsa_public_key.exponent);

    //     PublicKey::Rsa(RsaPublicKey::new(modulus, exponent).unwrap())
    // }

    pub(crate) fn from_bytes(bytes: &Bytes) -> PublicKey {
        PublicKey::Raw(bytes.clone())
    }
}

impl From<Bytes> for PublicKey {
    fn from(value: Bytes) -> Self {
        PublicKey::from_bytes(&value)
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

#[derive(Debug, Clone)]
pub(crate) struct CertKeyPair {
    pub(crate) distributed_private_key: Option<DistributedPrivateKey>,
    pub(crate) distributed_cert: DistributedCert,
    pub(crate) signer: Box<Option<Certificate>>,
    pub(crate) signees: Vec<CertKeyPair>,
}

impl Display for CertKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(signer) = &self.signer.as_ref() {
            if let Some(distributed_private_key) = &self.distributed_private_key {
                write!(
                    f,
                    "Cert {:03} locations, priv {:03} locations | {} ---> {}",
                    self.distributed_cert.locations.len(),
                    distributed_private_key.locations.len(),
                    self.distributed_cert.certificate.subject,
                    self.distributed_cert.certificate.issuer
                        == signer.clone().issuer,
                )?;
            } else {
                write!(
                    f,
                    "Cert {:03} locations, NO PRIV | {} ---> {}",
                    self.distributed_cert.locations.len(),
                    self.distributed_cert.certificate.subject,
                    self.distributed_cert.certificate.issuer
                        == signer.clone().issuer,
                )?;
            }
        } else {
            if let Some(distributed_private_key) = &self.distributed_private_key {
                write!(
                    f,
                    "Cert {:03} locations, priv {:03} locations | {} ---> SELF SIGNED",
                    self.distributed_cert.locations.len(),
                    distributed_private_key.locations.len(),
                    self.distributed_cert.certificate.subject,
                )?;
            } else {
                write!(
                    f,
                    "Cert {:03} locations, NO PRIV | {} ---> SELF SIGNED",
                    self.distributed_cert.locations.len(),
                    self.distributed_cert.certificate.subject,
                )?;
            }
        }

        // for signee in self.signees.iter() {
        //     writeln!(f, "  {}", signee)?;
        // }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CryptoGraph {
    pub(crate) public_to_private: HashMap<PublicKey, PrivateKey>,
    pub(crate) identity_to_public: HashMap<String, String>,
    pub(crate) ca_certs: HashSet<String>,

    pub(crate) cert_key_pairs: Vec<CertKeyPair>,

    pub(crate) private_keys: HashMap<PrivateKey, DistributedPrivateKey>,
    pub(crate) certs: HashMap<Certificate, DistributedCert>,

    // Maps root cert to a list of certificates signed by it
    pub(crate) root_certs: HashMap<String, Vec<String>>,
}
