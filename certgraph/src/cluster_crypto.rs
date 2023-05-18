use crate::{k8s_etcd, locations::Location, style_bar};
use base64::Engine as _;
use bcder::{encode::Values, BitString, Mode};
use bytes::Bytes;
use etcd_client::Client;
use indicatif::ProgressBar;
use rsa::RsaPrivateKey;
use serde_json::Value;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fmt::Display,
    hash::{Hash, Hasher},
    rc::Rc,
};
use tokio::io::AsyncReadExt;
use x509_certificate::{
    rfc5280, CapturedX509Certificate, InMemorySigningKeyPair,
    KeyAlgorithm::{self, Ed25519},
    Sign, Signer, X509Certificate,
};

#[derive(Hash, Eq, PartialEq, Clone)]
pub(crate) enum PrivateKey {
    Rsa(RsaPrivateKey),
    Ed25519(Bytes),
    Raw(Bytes),
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa(_) => write!(f, "<rsa_priv>"),
            Self::Raw(_) => write!(f, "<raw_priv>"),
            Self::Ed25519(_) => todo!(),
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
    pub(crate) distributed_cert: Rc<RefCell<DistributedCert>>,

    /// The signer is the cert that signed this cert. If this is a self-signed cert, then this will
    /// be None
    pub(crate) signer: Option<Rc<RefCell<DistributedCert>>>,
    /// The signees are the certs that this cert has signed
    pub(crate) signees: Vec<Rc<RefCell<CertKeyPair>>>,
}

impl CertKeyPair {
    pub fn regenerate(&mut self, sign_with: Option<&InMemorySigningKeyPair>) {
        let (new_cert_subject_key_pair, private_key_bytes, new_cert) = self.re_sign_cert(sign_with);
        (*self.distributed_cert).borrow_mut().certificate = Certificate::from(new_cert);

        // This condition exists because not all certs originally had a private key
        // associated with them (e.g. some private keys are discarded during install time),
        // so we only want to write the private key back into the graph incase there was
        // one there to begin with.
        if let Some(distributed_private_key) = &mut self.distributed_private_key {
            distributed_private_key.key =
                PrivateKey::Raw(Bytes::copy_from_slice(private_key_bytes.as_ref()))
        }

        for signee in &self.signees {
            (**signee)
                .borrow_mut()
                .regenerate(Some(&new_cert_subject_key_pair));
        }
    }

    fn re_sign_cert(
        &mut self,
        sign_with: Option<&InMemorySigningKeyPair>,
    ) -> (
        InMemorySigningKeyPair,
        ring::pkcs8::Document,
        CapturedX509Certificate,
    ) {
        let (key_pair, document) = InMemorySigningKeyPair::generate_random(Ed25519).unwrap();
        let key_pair_signature_algorithm = KeyAlgorithm::from(&key_pair);
        let cert: &X509Certificate = &(*self.distributed_cert).borrow().certificate.original;
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
        (key_pair, document, cert)
    }

    pub async fn commit(&self, client: &mut Client) {
        self.commit_pair_certificate(client).await;
        self.commit_pair_key(client).await;
    }

    async fn commit_pair_certificate(&self, client: &mut Client) {
        let bar = ProgressBar::new((*self.distributed_cert).borrow().locations.0.len() as u64)
            .with_message("Processing pair certificate locations...");
        style_bar(&bar);
        for location in (*self.distributed_cert).borrow().locations.0.iter() {
            bar.inc(1);
            match location {
                Location::K8s(k8slocation) => {
                    self.commit_k8s_cert(client, k8slocation).await;
                }
                Location::Filesystem(filelocation) => {
                    self.commit_filesystem_cert(filelocation).await;
                }
            }
        }
    }

    async fn commit_k8s_cert(
        &self,
        client: &mut Client,
        k8slocation: &crate::locations::K8sLocation,
    ) {
        let mut resource = get_etcd_yaml(client, k8slocation).await;
        if let Some(value_at_json_pointer) =
            resource.pointer_mut(&k8slocation.yaml_location.json_pointer)
        {
            if let Value::String(value_at_json_pointer) = value_at_json_pointer {
                let decoded = decode_resource_data_entry(k8slocation, &value_at_json_pointer);

                if let Some(pem_index) = k8slocation.yaml_location.pem_location.pem_bundle_index {
                    let newpem = pem::parse(
                        (*self.distributed_cert)
                            .borrow()
                            .certificate
                            .original
                            .encode_pem(),
                    )
                    .unwrap();
                    let newbundle = pem_bundle_replace_pem_at_index(decoded, pem_index, newpem);
                    let encoded = encode_resource_data_entry(k8slocation, newbundle);
                    *value_at_json_pointer = encoded;
                } else {
                    panic!("shouldn't happen");
                }
            }
        } else {
            panic!("shouldn't happen");
        }

        let newcontents = serde_yaml::to_string(&resource).unwrap();
        k8s_etcd::etcd_put(client, k8slocation, newcontents.as_bytes().to_vec()).await;
    }

    async fn commit_pair_key(&self, client: &mut Client) {
        let bar = ProgressBar::new((*self.distributed_cert).borrow().locations.0.len() as u64)
            .with_message("Processing pair certificate locations...");
        if let Some(private_key) = &self.distributed_private_key {
            for location in private_key.locations.0.iter() {
                bar.inc(1);
                match location {
                    Location::K8s(k8slocation) => {
                        self.commit_k8s_key(client, k8slocation, private_key).await;
                    }
                    Location::Filesystem(filelocation) => {
                        self.commit_filesystem_key(filelocation, private_key).await;
                    }
                }
            }
        }
    }

    async fn commit_k8s_key(
        &self,
        client: &mut Client,
        k8slocation: &crate::locations::K8sLocation,
        distributed_private_key: &DistributedPrivateKey,
    ) {
        let mut resource = get_etcd_yaml(client, k8slocation).await;
        if let Some(value_at_json_pointer) =
            resource.pointer_mut(&k8slocation.yaml_location.json_pointer)
        {
            if let Value::String(value_at_json_pointer) = value_at_json_pointer {
                let decoded = decode_resource_data_entry(k8slocation, &value_at_json_pointer);

                if let Some(pem_index) = k8slocation.yaml_location.pem_location.pem_bundle_index {
                    if let PrivateKey::Raw(bytes) = &distributed_private_key.key {
                        let newbundle = pem_bundle_replace_pem_at_index(
                            decoded,
                            pem_index,
                            pem::Pem::new("PRIVATE KEY", bytes.as_ref()),
                        );
                        let encoded = encode_resource_data_entry(k8slocation, newbundle);
                        *value_at_json_pointer = encoded;
                    }
                } else {
                    panic!("shouldn't happen");
                }
            }
        } else {
            panic!("shouldn't happen");
        }

        let newcontents = serde_yaml::to_string(&resource).unwrap();
        k8s_etcd::etcd_put(client, k8slocation, newcontents.as_bytes().to_vec()).await;
    }

    async fn commit_filesystem_key(
        &self,
        filelocation: &crate::locations::FileLocation,
        private_key: &DistributedPrivateKey,
    ) {
        let mut file = tokio::fs::File::open(&filelocation.file_path)
            .await
            .unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).await.unwrap();

        match &filelocation.content_location {
            crate::locations::FileContentLocation::Raw(pem_location_info) => {
                if let PrivateKey::Raw(bytes) = &private_key.key {
                    if let Some(pem_bundle_index) = pem_location_info.pem_bundle_index {
                        let newpem = pem::Pem::new("PRIVATE KEY", bytes.as_ref());
                        let newbundle = pem_bundle_replace_pem_at_index(
                            String::from_utf8(contents).unwrap(),
                            pem_bundle_index,
                            newpem,
                        );
                        tokio::fs::write(&filelocation.file_path, newbundle)
                            .await
                            .unwrap();
                    } else {
                        panic!("shouldn't happen");
                    }
                }
            }
        }
    }

    async fn commit_filesystem_cert(&self, filelocation: &crate::locations::FileLocation) {
        let mut file = tokio::fs::File::open(&filelocation.file_path)
            .await
            .unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).await.unwrap();

        match &filelocation.content_location {
            crate::locations::FileContentLocation::Raw(pem_location_info) => {
                if let Some(pem_bundle_index) = pem_location_info.pem_bundle_index {
                    let newpem = pem::parse(
                        (*self.distributed_cert)
                            .borrow()
                            .certificate
                            .original
                            .encode_pem(),
                    )
                    .unwrap();
                    let newbundle = pem_bundle_replace_pem_at_index(
                        String::from_utf8(contents).unwrap(),
                        pem_bundle_index,
                        newpem,
                    );
                    tokio::fs::write(&filelocation.file_path, newbundle)
                        .await
                        .unwrap();
                } else {
                    panic!("shouldn't happen");
                }
            }
        }
    }
}

fn encode_resource_data_entry(
    k8slocation: &crate::locations::K8sLocation,
    value: String,
) -> String {
    if k8slocation.resource_location.kind == "Secret" {
        base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
    } else {
        value
    }
}

fn decode_resource_data_entry(
    k8slocation: &crate::locations::K8sLocation,
    value_at_json_pointer: &&mut String,
) -> String {
    let decoded = if k8slocation.resource_location.kind == "Secret" {
        String::from_utf8_lossy(
            base64::engine::general_purpose::STANDARD
                .decode(value_at_json_pointer.as_bytes())
                .unwrap()
                .as_slice(),
        )
        .to_string()
    } else {
        value_at_json_pointer.to_string()
    }
    .clone();
    decoded
}

async fn get_etcd_yaml(client: &mut Client, k8slocation: &crate::locations::K8sLocation) -> Value {
    serde_yaml::from_str(&String::from_utf8_lossy(
        &(k8s_etcd::etcd_get(client, &k8s_etcd::k8slocation_to_etcd_key(k8slocation)).await),
    ))
    .unwrap()
}

fn pem_bundle_replace_pem_at_index(
    original_pem_bundle: String,
    pem_index: u64,
    newpem: pem::Pem,
) -> String {
    let pems = pem::parse_many(original_pem_bundle.clone()).unwrap();
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
    newbundle
}

impl Display for CertKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cert {:03} locations {}, ",
            (*self.distributed_cert).borrow().locations.0.len(),
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
        write!(
            f,
            " | {}",
            (*self.distributed_cert).borrow().certificate.subject,
        )?;

        if self.signees.len() > 0 {
            writeln!(f, "")?;
        }

        for signee in &self.signees {
            writeln!(f, "- {}", (**signee).borrow())?;
        }

        Ok(())
    }
}

/// This is the main struct that holds all the crypto objects we've found in the cluster
/// and the locations where we found them, and how they relate to each other.
#[derive(Debug, Clone)]
pub(crate) struct ClusterCryptoObjects {
    /// At the end of the day we're scanning the entire cluster for private keys and certificates,
    /// these two hashmaps is where we store all of them. The reason they're hashmaps and not
    /// vectors is because every certificate and every private key we encounter might be found in
    /// multiple locations. The value types here (Distributed*) hold a list of locations where the
    /// key/cert was found, and the list of locations for each cert/key grows as we scan more and
    /// more resources.
    pub(crate) private_keys: HashMap<PrivateKey, DistributedPrivateKey>,
    pub(crate) certs: HashMap<Certificate, Rc<RefCell<DistributedCert>>>,

    /// Every time we encounter a private key, we extract the public key
    /// from it and add to this mapping. This will later allow us to easily
    /// associate certificates with their matching private key
    pub(crate) public_to_private: HashMap<PublicKey, PrivateKey>,

    /// After collecting all certs and keys, we go through the list of certs and
    /// try to find a private key that matches the public key of the cert (with the
    /// help of public_to_private) and populate this list of pairs.
    pub(crate) cert_key_pairs: Vec<Rc<RefCell<CertKeyPair>>>,
}
