use crate::{k8s_etcd, locations::Location, style_bar};
use base64::Engine as _;
use bcder::{encode::Values, BitString, Mode};
use bytes::Bytes;
use etcd_client::Client;
use indicatif::ProgressBar;
use rsa::RsaPrivateKey;
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    hash::{Hash, Hasher},
};
use x509_certificate::{
    rfc5280, CapturedX509Certificate, InMemorySigningKeyPair,
    KeyAlgorithm::{self, Ed25519},
    Sign, Signer, X509Certificate, X509CertificateBuilder, X509CertificateError,
};

#[derive(Hash, Eq, PartialEq, Clone)]
pub(crate) enum PrivateKey {
    Rsa(RsaPrivateKey),
    Raw(Bytes),
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa(_) => write!(f, "<rsa_priv>"),
            Self::Raw(_) => write!(f, "<raw_priv>"),
        }
    }
}

#[derive(Hash, Eq, PartialEq, Clone)]
pub(crate) enum PublicKey {
    // Rsa(RsaPublicKey),
    Raw(Bytes),
    // Dummy,
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Self::Rsa(_) => write!(f, "<rsa_pub>"),
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

#[derive(Debug, Clone)]
pub struct Locations(pub(crate) HashSet<Location>);

impl AsRef<HashSet<Location>> for Locations {
    fn as_ref(&self) -> &HashSet<Location> {
        &self.0
    }
}

impl AsMut<HashSet<Location>> for Locations {
    fn as_mut(&mut self) -> &mut HashSet<Location> {
        &mut self.0
    }
}

// we cannot do
impl Display for Locations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let locations = self.0.iter().collect::<Vec<_>>();
        write!(f, "[")?;
        for location in locations {
            write!(f, "{}, ", location)?;
        }
        write!(f, "]")
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DistributedPrivateKey {
    pub(crate) locations: Locations,
    pub(crate) key: PrivateKey,
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

impl CertKeyPair {
    pub fn regenerate(&mut self, sign_with: Option<&InMemorySigningKeyPair>) {
        let (key_pair, document) = InMemorySigningKeyPair::generate_random(Ed25519).unwrap();
        let key_pair_signature_algorithm = KeyAlgorithm::from(&key_pair);

        let cert: &X509Certificate = &self.distributed_cert.certificate.original;
        let certificate: &rfc5280::Certificate = cert.as_ref();
        let mut tbs_certificate = certificate.tbs_certificate.clone();

        tbs_certificate.subject_public_key_info = rfc5280::SubjectPublicKeyInfo {
            algorithm: key_pair_signature_algorithm.into(),
            subject_public_key: BitString::new(0, key_pair.public_key_data()),
        };

        let mut tbs_der = Vec::<u8>::new();
        tbs_certificate
            .encode_ref()
            .write_encoded(Mode::Der, &mut tbs_der)
            .unwrap();

        let signature = if let Some(key_pair) = &sign_with {
            key_pair
        } else {
            &key_pair
        }
        .try_sign(&tbs_der)
        .unwrap();

        let signature_algorithm = key_pair.signature_algorithm().unwrap();

        let cert = rfc5280::Certificate {
            tbs_certificate,
            signature_algorithm: signature_algorithm.into(),
            signature: BitString::new(0, Bytes::copy_from_slice(signature.as_ref())),
        };

        let cert = X509Certificate::from(cert);
        let cert_der = cert.encode_der().unwrap();

        let cert = CapturedX509Certificate::from_der(cert_der).unwrap();

        self.distributed_cert.certificate = Certificate::from(cert);

        // This condition exists because not all certs originally had a private key
        // associated with them (e.g. some private keys are discarded during install time),
        // so we only want to write the private key back into the graph incase there was
        // one there to begin with.
        if let Some(distributed_private_key) = &mut self.distributed_private_key {
            distributed_private_key.key = PrivateKey::Raw(Bytes::copy_from_slice(document.as_ref()))
        }

        for signee in self.signees.iter_mut() {
            signee.regenerate(Some(&key_pair));
        }
    }

    pub async fn commit(&self, client: &mut Client) {
        self.commit_pair_certificate(client).await;
        self.commit_pair_key(client).await;
    }

    async fn commit_pair_certificate(&self, client: &mut Client) {
        let bar = ProgressBar::new(self.distributed_cert.locations.0.len() as u64)
            .with_message("Processing pair certificate locations...");
        style_bar(&bar);
        for location in self.distributed_cert.locations.0.iter() {
            bar.inc(1);
            match location {
                Location::K8s(k8slocation) => {
                    self.commit_k8s_cert(client, k8slocation).await;
                }
                Location::Filesystem(_) => {}
            }
        }
    }

    async fn commit_k8s_cert(
        &self,
        client: &mut Client,
        k8slocation: &crate::locations::K8sLocation,
    ) {
        let mut value: Value = serde_yaml::from_str(&String::from_utf8_lossy(
            &(k8s_etcd::etcd_get(client, &k8s_etcd::k8slocation_to_etcd_key(k8slocation)).await),
        ))
        .unwrap();
        if let Some(subvalue) = value.pointer_mut(&k8slocation.yaml_location.json_pointer) {
            if let Value::String(subvalue_string) = subvalue {
                let decoded = if k8slocation.resource_location.kind == "Secret" {
                    String::from_utf8_lossy(
                        base64::engine::general_purpose::STANDARD
                            .decode(subvalue_string.as_bytes())
                            .unwrap()
                            .as_slice(),
                    )
                    .to_string()
                } else {
                    subvalue_string.to_string()
                }
                .clone();

                if let Some(pem_index) = k8slocation.yaml_location.pem_location.pem_bundle_index {
                    let pems = pem::parse_many(decoded.clone()).unwrap();
                    let newpem =
                        pem::parse(self.distributed_cert.certificate.original.encode_pem())
                            .unwrap();
                    let mut newpems = vec![];

                    for (i, pem) in pems.iter().enumerate() {
                        if i == usize::try_from(pem_index).unwrap() {
                            newpems.push(newpem.clone());
                        } else {
                            newpems.push(pem.clone());
                        }
                    }

                    let newbundle = pem::encode_many_config(
                        &newpems,
                        pem::EncodeConfig {
                            line_ending: pem::LineEnding::LF,
                        },
                    );

                    let encoded = if k8slocation.resource_location.kind == "Secret" {
                        base64::engine::general_purpose::STANDARD.encode(newbundle.as_bytes())
                    } else {
                        newbundle
                    };

                    *subvalue_string = encoded;
                } else {
                    panic!("shouldn't happen");
                }
            }
        } else {
            panic!("shouldn't happen");
        }
        let newcontents = serde_yaml::to_string(&value).unwrap();
        k8s_etcd::etcd_put(client, k8slocation, newcontents.as_bytes().to_vec()).await;
    }

    async fn commit_pair_key(&self, client: &mut Client) {
        let bar = ProgressBar::new(self.distributed_cert.locations.0.len() as u64)
            .with_message("Processing pair certificate locations...");
        if let Some(private_key) = &self.distributed_private_key {
            for location in private_key.locations.0.iter() {
                bar.inc(1);
                match location {
                    Location::K8s(k8slocation) => {
                        self.commit_k8s_key(client, k8slocation).await;
                    }
                    Location::Filesystem(_) => {}
                }
            }
        }
    }

    async fn commit_k8s_key(
        &self,
        client: &mut Client,
        k8slocation: &crate::locations::K8sLocation,
    ) {
    }
}

impl Display for CertKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cert {:03} locations {}, ",
            self.distributed_cert.locations.0.len(),
            "<>",
            // self.distributed_cert.locations,
        )?;
        write!(
            f,
            "{}",
            if self.distributed_private_key.is_some() {
                format!(
                    "priv {:03} locations {}",
                    self.distributed_private_key
                        .as_ref()
                        .unwrap()
                        .locations
                        .0
                        .len(),
                    // self.distributed_private_key.as_ref().unwrap().locations,
                    "<>",
                )
            } else {
                "NO PRIV".to_string()
            }
        )?;
        write!(f, " | {}", self.distributed_cert.certificate.subject,)?;

        if self.signees.len() > 0 {
            writeln!(f, "")?;
        }

        for signee in self.signees.iter() {
            writeln!(f, "- {}", signee)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CryptoGraph {
    pub(crate) public_to_private: HashMap<PublicKey, PrivateKey>,

    pub(crate) cert_key_pairs: Vec<CertKeyPair>,

    pub(crate) private_keys: HashMap<PrivateKey, DistributedPrivateKey>,
    pub(crate) certs: HashMap<Certificate, DistributedCert>,

    // Maps root cert to a list of certificates signed by it
    pub(crate) root_certs: HashMap<String, Vec<String>>,
}
