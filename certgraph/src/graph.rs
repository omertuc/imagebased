use crate::locations::Location;
use base64::Engine as _;
use bytes::Bytes;
use etcd_client::Client;
// use rsa::{RsaPublicKey};
use rsa::RsaPrivateKey;
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    hash::{Hash, Hasher},
    process::Stdio,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
use x509_certificate::CapturedX509Certificate;

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
    pub fn regenerate(&mut self) {
        let mut builder = x509_certificate::certificate::X509CertificateBuilder::new(
            x509_certificate::KeyAlgorithm::Ed25519,
        );

        builder
            .subject()
            .append_common_name_utf8_string("TODO: Copy subject from original cert")
            .unwrap();

        builder
            .issuer()
            .append_common_name_utf8_string("TODO: Copy issuer from originaal cert")
            .unwrap();

        let (cer, _keypair, document) = builder.create_with_random_keypair().unwrap();

        self.distributed_cert.certificate = Certificate::from(cer);

        if let Some(distributed_private_key) = &mut self.distributed_private_key {
            distributed_private_key.key = PrivateKey::Raw(Bytes::copy_from_slice(document.as_ref()))
        }
    }

    pub async fn commit(&self, client: &mut Client) {
        for location in self.distributed_cert.locations.0.iter() {
            match location {
                Location::K8s(k8slocation) => {
                    let decoded_etcd_value = etcd_get(client, k8slocation).await;

                    let path = &k8slocation.yaml_location.json_pointer;
                    let mut value: Value =
                        serde_yaml::from_str(&String::from_utf8_lossy(&decoded_etcd_value))
                            .expect("failed to parse yaml");
                    if let Some(subvalue) = value.pointer_mut(path) {
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

                            if let Some(pem_index) =
                                k8slocation.yaml_location.pem_location.pem_bundle_index
                            {
                                let pems = pem::parse_many(decoded.clone()).unwrap();
                                let newpem = pem::parse(
                                    self.distributed_cert.certificate.original.encode_pem(),
                                )
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
                                    base64::engine::general_purpose::STANDARD
                                        .encode(newbundle.as_bytes())
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

                    etcd_put(client, k8slocation, newcontents.as_bytes().to_vec()).await;
                }
                Location::Filesystem(_) => {}
            }
        }
    }
}

async fn etcd_get(client: &mut Client, k8slocation: &crate::locations::K8sLocation) -> Vec<u8> {
    let get_result = client
        .get(
            format!(
                "/kubernetes.io/{}s/{}/{}",
                k8slocation.resource_location.kind.to_lowercase(),
                k8slocation.resource_location.namespace,
                k8slocation.resource_location.name,
            ),
            None,
        )
        .await
        .unwrap();
    let raw_etcd_value = get_result.kvs().first().unwrap().value();

    let mut command = Command::new("auger")
        .arg("decode")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    command
        .stdin
        .take()
        .unwrap()
        .write_all(raw_etcd_value)
        .await
        .unwrap();

    command.wait_with_output().await.unwrap().stdout
}

async fn etcd_put(
    client: &mut Client,
    k8slocation: &crate::locations::K8sLocation,
    value: Vec<u8>,
) {
    let command = Command::new("auger")
        .arg("encode")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to execute auger");
    let mut encoded_etcd_value = vec![];
    command
        .stdin
        .unwrap()
        .write_all(value.as_slice())
        .await
        .unwrap();
    command
        .stdout
        .unwrap()
        .read_to_end(&mut encoded_etcd_value)
        .await
        .unwrap();

    client
        .put(
            format!(
                "/kubernetes.io/{}s/{}/{}",
                k8slocation.resource_location.kind.to_lowercase(),
                k8slocation.resource_location.namespace,
                k8slocation.resource_location.name,
            ),
            String::from_utf8_lossy(&encoded_etcd_value).to_string(),
            None,
        )
        .await
        .unwrap();
}

impl Display for CertKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cert {:03} locations {}, ",
            self.distributed_cert.locations.0.len(),
            self.distributed_cert.locations,
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
                    self.distributed_private_key.as_ref().unwrap().locations,
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
