use crate::{
    file_utils,
    k8s_etcd::{self, InMemoryK8sEtcd},
    rules::{self, IGNORE_LIST_CONFIGMAP, KNOWN_MISSING_PRIVATE_KEY_CERTS},
};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use bcder::{encode::Values, Mode};
use bytes::Bytes;
use futures_util::future::join_all;
use jwt_simple::prelude::RSAPublicKeyLike;
use locations::K8sLocation;
use locations::{
    FileContentLocation, FileLocation, K8sResourceLocation, Location, LocationValueType,
    YamlLocation,
};
use pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::{pkcs8::EncodePrivateKey, RsaPrivateKey};
use serde_json::{Map, Value};
use std::{
    cell::RefCell,
    collections::HashMap,
    fmt::Display,
    fs,
    hash::{Hash, Hasher},
    io::Read,
    path::PathBuf,
    rc::Rc,
    sync::Arc,
};
use std::{
    collections::hash_map::Entry::{Occupied, Vacant},
    path::Path,
};
use tokio::sync::Mutex;
use x509_certificate::{rfc5280, CapturedX509Certificate, InMemorySigningKeyPair};

use self::locations::Locations;

mod cert_key_pair;
mod distributed_jwt;
mod distributed_private_key;
mod locations;

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
    Rsa(Bytes),
    Raw(Bytes),
    // Dummy,
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Self::Rsa(_) => write!(f, "<rsa_pub>"),
            Self::Raw(x) => write!(f, "<raw_pub: {:?}>", x),
            Self::Rsa(x) => write!(f, "<rsa_pub: {:?}>", x),
            // Self::Dummy => write!(f, "Dummy"),
        }
    }
}

#[derive(Eq, PartialEq, Clone, Debug, Hash)]
pub(crate) struct Jwt {
    pub(crate) str: String,
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
    pub(crate) fn from_bytes(bytes: &Bytes) -> PublicKey {
        PublicKey::Raw(bytes.clone())
    }

    pub(crate) fn from_rsa_der(der_bytes: &Bytes) -> PublicKey {
        PublicKey::Rsa(der_bytes.clone())
    }
}

impl From<Bytes> for PublicKey {
    fn from(value: Bytes) -> Self {
        PublicKey::from_bytes(&value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DistributedCert {
    pub(crate) certificate: Certificate,
    pub(crate) locations: Locations,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DistributedPublicKey {
    pub(crate) public_key: PublicKey,
    pub(crate) locations: Locations,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum JwtSigner {
    Unknown,
    CertKeyPair(Rc<RefCell<cert_key_pair::CertKeyPair>>),
    PrivateKey(Rc<RefCell<distributed_private_key::DistributedPrivateKey>>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Signee {
    CertKeyPair(Rc<RefCell<cert_key_pair::CertKeyPair>>),
    Jwt(Rc<RefCell<distributed_jwt::DistributedJwt>>),
}

impl Display for Signee {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Signee::CertKeyPair(cert_key_pair) => {
                write!(f, "CertKeyPair({})", (**cert_key_pair).borrow())
            }
            Signee::Jwt(jwt) => write!(f, "Jwt({})", (**jwt).borrow().locations),
        }
    }
}

impl Signee {
    fn regenerate(&mut self, sign_with: Option<&InMemorySigningKeyPair>) {
        match self {
            Self::CertKeyPair(cert_key_pair) => {
                (**cert_key_pair).borrow_mut().regenerate(sign_with);
            }
            Self::Jwt(jwt) => {
                match sign_with {
                    Some(key_pair) => (**jwt).borrow_mut().regenerate(key_pair),
                    None => panic!(
                    "Cannot regenerate a jwt without a signing key, regenerate may only be called on a signee that is a root cert-key-pair"
                ),
                }
            }
        }
    }
}

fn encode_tbs_cert_to_der(tbs_certificate: &rfc5280::TbsCertificate) -> Vec<u8> {
    let mut tbs_der = Vec::<u8>::new();
    tbs_certificate
        .encode_ref()
        .write_encoded(Mode::Der, &mut tbs_der)
        .unwrap();
    tbs_der
}

fn generate_rsa_key(rng: &mut rand::prelude::ThreadRng) -> (RsaPrivateKey, InMemorySigningKeyPair) {
    let rsa_private_key = rsa::RsaPrivateKey::new(rng, 2048).unwrap();
    let rsa_pkcs8_der_bytes: Vec<u8> = rsa_private_key.to_pkcs8_der().unwrap().as_bytes().into();
    let key_pair = InMemorySigningKeyPair::from_pkcs8_der(&rsa_pkcs8_der_bytes).unwrap();
    (rsa_private_key, key_pair)
}

fn encode_resource_data_entry(k8slocation: &locations::K8sLocation, value: &String) -> String {
    if k8slocation.resource_location.kind == "Secret" {
        STANDARD.encode(value.as_bytes())
    } else {
        value.to_string()
    }
}

fn decode_resource_data_entry(
    k8slocation: &locations::K8sLocation,
    value_at_json_pointer: &&mut String,
) -> String {
    let decoded = if k8slocation.resource_location.kind == "Secret" {
        String::from_utf8_lossy(
            STANDARD
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

async fn get_etcd_yaml(
    client: &mut InMemoryK8sEtcd,
    k8slocation: &locations::K8sLocation,
) -> Value {
    serde_yaml::from_str(&String::from_utf8_lossy(
        &(client
            .get(k8s_etcd::k8slocation_to_etcd_key(k8slocation))
            .await),
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

/// This is the main struct that holds all the crypto objects we've found in the cluster
/// and the locations where we found them, and how they relate to each other.
pub(crate) struct ClusterCryptoObjects {
    internal: Mutex<ClusterCryptoObjectsInternal>,
}

impl ClusterCryptoObjects {
    pub(crate) fn new() -> ClusterCryptoObjects {
        ClusterCryptoObjects {
            internal: Mutex::new(ClusterCryptoObjectsInternal::new()),
        }
    }

    pub(crate) async fn display(&self) {
        self.internal.lock().await.display();
    }

    pub(crate) async fn commit_to_etcd_and_disk(&self, etcd_client: &mut InMemoryK8sEtcd) {
        self.internal
            .lock()
            .await
            .commit_to_etcd_and_disk(etcd_client)
            .await;
    }

    pub(crate) async fn regenerate_certificates_and_keys(&self) {
        self.internal
            .lock()
            .await
            .regenerate_certificates_and_keys();
    }

    pub(crate) async fn fill_signees(&mut self) {
        self.internal.lock().await.fill_signees();
    }

    pub(crate) async fn pair_certs_and_keys(&mut self) {
        self.internal.lock().await.pair_certs_and_keys();
    }

    pub(crate) async fn fill_jwt_signers(&mut self) {
        self.internal.lock().await.fill_jwt_signers();
    }

    pub(crate) async fn process_k8s_static_resources(&mut self, k8s_dir: &Path) {
        self.internal
            .lock()
            .await
            .process_k8s_static_resources(k8s_dir);
    }

    pub(crate) async fn process_etcd_resources(
        &mut self,
        etcd_client: Arc<Mutex<InMemoryK8sEtcd>>,
    ) {
        self.internal
            .lock()
            .await
            .process_etcd_resources(etcd_client)
            .await;
    }
}

pub(crate) struct ClusterCryptoObjectsInternal {
    /// At the end of the day we're scanning the entire cluster for private keys, public keys
    /// certificates, and jwts. These four hashmaps is where we store all of them. The reason
    /// they're hashmaps and not vectors is because every one of those objects we encounter might
    /// be found in multiple locations. The value types here (Distributed*) hold a list of
    /// locations where the key/cert was found, and the list of locations for each cert/key grows
    /// as we scan more and more resources.
    pub(crate) private_keys:
        HashMap<PrivateKey, Rc<RefCell<distributed_private_key::DistributedPrivateKey>>>,
    pub(crate) public_keys: HashMap<PublicKey, Rc<RefCell<DistributedPublicKey>>>,
    pub(crate) certs: HashMap<Certificate, Rc<RefCell<DistributedCert>>>,
    pub(crate) jwts: HashMap<Jwt, Rc<RefCell<distributed_jwt::DistributedJwt>>>,

    /// Every time we encounter a private key, we extract the public key
    /// from it and add to this mapping. This will later allow us to easily
    /// associate certificates with their matching private key
    pub(crate) public_to_private: HashMap<PublicKey, PrivateKey>,

    /// After collecting all certs and private keys, we go through the list of certs and try to
    /// find a private key that matches the public key of the cert (with the help of
    /// public_to_private) and populate this list of pairs.
    pub(crate) cert_key_pairs: Vec<Rc<RefCell<cert_key_pair::CertKeyPair>>>,
}

impl ClusterCryptoObjectsInternal {
    pub(crate) fn new() -> Self {
        ClusterCryptoObjectsInternal {
            private_keys: HashMap::new(),
            public_keys: HashMap::new(),
            certs: HashMap::new(),
            jwts: HashMap::new(),
            public_to_private: HashMap::new(),
            cert_key_pairs: Vec::new(),
        }
    }

    pub(crate) fn display(&self) {
        for cert_key_pair in &self.cert_key_pairs {
            if (**cert_key_pair).borrow().signer.as_ref().is_none() {
                println!("{}", (**cert_key_pair).borrow());
            }
        }

        for private_key in self.private_keys.values() {
            println!("{}", (**private_key).borrow());
        }
    }

    async fn commit_to_etcd_and_disk(&mut self, etcd_client: &mut InMemoryK8sEtcd) {
        for cert_key_pair in &self.cert_key_pairs {
            (**cert_key_pair)
                .borrow()
                .commit_to_etcd_and_disk(etcd_client)
                .await;
        }

        for jwt in self.jwts.values() {
            (**jwt).borrow().commit_to_etcd_and_disk(etcd_client).await;
        }
    }

    fn regenerate_certificates_and_keys(&mut self) {
        for cert_key_pair in &self.cert_key_pairs {
            if (**cert_key_pair).borrow().signer.is_some() {
                continue;
            }

            (**cert_key_pair).borrow_mut().regenerate(None)
        }
    }

    fn fill_jwt_signers(&mut self) {
        for distributed_jwt in self.jwts.values() {
            let mut maybe_signer = JwtSigner::Unknown;

            for cert_key_pair in &self.cert_key_pairs {
                if let Some(distributed_private_key) =
                    &(**cert_key_pair).borrow().distributed_private_key
                {
                    match verify_jwt(
                        &(**distributed_private_key).borrow(),
                        &(**distributed_jwt).borrow(),
                    ) {
                        Ok(
                            _claims, /* We don't care about the claims, only that the signature is correct */
                        ) => {
                            maybe_signer = JwtSigner::CertKeyPair(Rc::clone(cert_key_pair));
                            break;
                        }
                        Err(_error) => {
                            // println!("Error verifying JWT: {}", error);
                        }
                    }
                }
            }

            match &maybe_signer {
                JwtSigner::Unknown => {
                    // Try free form private keys
                    for private_key in self.private_keys.values() {
                        match verify_jwt(&(**private_key).borrow(), &(**distributed_jwt).borrow()) {
                            Ok(
                                _claims, /* We don't care about the claims, only that the signature is correct */
                            ) => {
                                maybe_signer = JwtSigner::PrivateKey(Rc::clone(private_key));
                                break;
                            }
                            Err(_error) => {
                                // println!("Error verifying JWT: {}", error);
                            }
                        }
                    }
                }
                _ => {}
            }

            (**distributed_jwt).borrow_mut().signer = maybe_signer;
        }
    }

    fn fill_signees(&mut self) {
        for cert_key_pair in &self.cert_key_pairs {
            for potential_signee in &self.cert_key_pairs {
                if let Some(potential_signee_signer) = &(**potential_signee).borrow().signer {
                    if (**potential_signee_signer).borrow().certificate.original
                        == (*(**cert_key_pair).borrow().distributed_cert)
                            .borrow()
                            .certificate
                            .original
                    {
                        (**cert_key_pair)
                            .borrow_mut()
                            .signees
                            .push(Signee::CertKeyPair(Rc::clone(&potential_signee)));
                    }
                }
            }

            for potential_jwt_signee in self.jwts.values() {
                match &(**potential_jwt_signee).borrow_mut().signer {
                    JwtSigner::Unknown => panic!("JWT has unknown signer"),
                    JwtSigner::CertKeyPair(jwt_signer_cert_key_pair) => {
                        if jwt_signer_cert_key_pair == cert_key_pair {
                            (**cert_key_pair)
                                .borrow_mut()
                                .signees
                                .push(Signee::Jwt(Rc::clone(potential_jwt_signee)));
                        }
                    }
                    JwtSigner::PrivateKey(_) => {}
                }
            }
        }

        for distributed_private_key in self.private_keys.values() {
            for potential_jwt_signee in self.jwts.values() {
                match &(**potential_jwt_signee).borrow_mut().signer {
                    JwtSigner::Unknown => panic!("JWT has unknown signer"),
                    JwtSigner::CertKeyPair(_cert_key_pair) => {}
                    JwtSigner::PrivateKey(jwt_signer_distributed_private_key) => {
                        if jwt_signer_distributed_private_key == distributed_private_key {
                            (**distributed_private_key)
                                .borrow_mut()
                                .signees
                                .push(Signee::Jwt(Rc::clone(potential_jwt_signee)));
                        }
                    }
                }
            }
        }
    }

    fn pair_certs_and_keys(&mut self) {
        for (_hashable_cert, distributed_cert) in &self.certs {
            let mut true_signing_cert: Option<Rc<RefCell<DistributedCert>>> = None;
            if !(**distributed_cert)
                .borrow()
                .certificate
                .original
                .subject_is_issuer()
            {
                for potential_signing_cert in self.certs.values() {
                    if (**distributed_cert)
                        .borrow()
                        .certificate
                        .original
                        .verify_signed_by_certificate(
                            &(**potential_signing_cert).borrow().certificate.original,
                        )
                        .is_ok()
                    {
                        true_signing_cert = Some(Rc::clone(potential_signing_cert))
                    }
                }

                if true_signing_cert.is_none() {
                    println!(
                        "No signing cert found for {}",
                        (**distributed_cert).borrow().locations
                    );
                    panic!("No signing cert found");
                }
            }

            let pair = Rc::new(RefCell::new(cert_key_pair::CertKeyPair {
                distributed_private_key: None,
                distributed_cert: Rc::clone(distributed_cert),
                signer: true_signing_cert,
                signees: Vec::new(),
            }));

            if let Occupied(private_key) = self
                .public_to_private
                .entry((**distributed_cert).borrow().certificate.public_key.clone())
            {
                if let Occupied(distributed_private_key) =
                    self.private_keys.entry(private_key.get().clone())
                {
                    (*pair).borrow_mut().distributed_private_key =
                        Some(Rc::clone(distributed_private_key.get()));

                    // Remove the private key from the pool of private keys as it's now paired with a cert
                    self.private_keys.remove(&private_key.get());
                } else {
                    panic!("Private key not found");
                }
            } else if KNOWN_MISSING_PRIVATE_KEY_CERTS
                .contains(&(**distributed_cert).borrow().certificate.subject)
            {
                println!(
                    "Known no private key for {}",
                    (**distributed_cert).borrow().certificate.subject
                );
            } else {
                panic!(
                "Private key not found for key not in KNOWN_MISSING_PRIVATE_KEY_CERTS, cannot continue, {}",
                (**distributed_cert).borrow().certificate.subject
            );
            }

            self.cert_key_pairs.push(pair);
        }
    }

    async fn process_etcd_key(&mut self, contents: Vec<u8>) {
        let value: &Value =
            &serde_yaml::from_slice(contents.as_slice()).expect("failed to parse yaml");
        let location = K8sResourceLocation::from(value);
        match location.kind.as_str() {
            "Secret" => self.scan_k8s_secret(value, &location),
            "ConfigMap" => self.scan_configmap(value, &location),
            _ => (),
        }
    }

    fn scan_configmap(&mut self, value: &Value, k8s_resource_location: &K8sResourceLocation) {
        if let Some(data) = value.as_object().unwrap().get("data") {
            match data {
                Value::Object(data) => {
                    for (key, value) in data.iter() {
                        if IGNORE_LIST_CONFIGMAP.contains(key) {
                            continue;
                        }
                        if let Value::String(value) = value {
                            self.process_pem_bundle(
                                value,
                                &Location::K8s(K8sLocation {
                                    resource_location: k8s_resource_location.clone(),
                                    yaml_location: YamlLocation {
                                        json_pointer: format!("/data/{key}"),
                                        value: LocationValueType::Unknown,
                                    },
                                }),
                            );
                        }
                    }
                }
                _ => todo!(),
            }
        }
    }

    fn scan_k8s_secret(&mut self, value: &Value, k8s_resource_location: &K8sResourceLocation) {
        if let Some(data) = value.as_object().unwrap().get("data") {
            match data {
                Value::Object(data) => {
                    for (key, value) in data.iter() {
                        if rules::IGNORE_LIST_SECRET.contains(key) {
                            continue;
                        }

                        self.process_k8s_secret_data_entry(key, value, k8s_resource_location);
                    }
                }
                _ => todo!(),
            }
        }
    }

    fn process_k8s_secret_data_entry(
        &mut self,
        key: &str,
        value: &Value,
        k8s_resource_location: &K8sResourceLocation,
    ) {
        if let Value::String(string_value) = value {
            if let Ok(value) = STANDARD.decode(string_value.as_bytes()) {
                let value = String::from_utf8(value).unwrap_or_else(|_| {
                    panic!("Failed to decode base64 {}", key);
                });

                let location = &Location::K8s(K8sLocation {
                    resource_location: k8s_resource_location.clone(),
                    yaml_location: YamlLocation {
                        json_pointer: format!("/data/{key}"),
                        value: LocationValueType::Unknown,
                    },
                });

                if let Some(_) = self.process_pem_bundle(&value, location) {
                    return;
                };

                if let Some(_) = self.process_jwt(&value, location) {
                    return;
                }
            } else {
                panic!("Failed to decode base64 {}", string_value);
            }
        }
    }

    fn process_jwt(&mut self, value: &str, location: &Location) -> Option<()> {
        // Need a cheap way to detect jwts that doesn't involve parsing them because we run this
        // against every secret/configmap data entry
        let parts = value.split('.').collect::<Vec<_>>();
        if parts.len() != 3 {
            return None;
        }

        let header = parts[0];
        let payload = parts[1];
        let signature = parts[2];

        if let Err(_) = URL_SAFE_NO_PAD.decode(header.as_bytes()) {
            return None;
        }
        if let Err(_) = URL_SAFE_NO_PAD.decode(payload.as_bytes()) {
            return None;
        }
        if let Err(_) = URL_SAFE_NO_PAD.decode(signature.as_bytes()) {
            return None;
        }

        let jwt = Jwt {
            str: value.to_string(),
        };

        let location = location.with_jwt();

        match self.jwts.entry(jwt.clone()) {
            Vacant(distributed_jwt) => {
                distributed_jwt.insert(Rc::new(RefCell::new(distributed_jwt::DistributedJwt {
                    jwt,
                    locations: Locations(vec![location].into_iter().collect()),
                    signer: JwtSigner::Unknown,
                })));
            }
            Occupied(distributed_jwt) => {
                (**distributed_jwt.get())
                    .borrow_mut()
                    .locations
                    .0
                    .insert(location);
            }
        }

        Some(())
    }

    fn process_pem_bundle(&mut self, value: &str, location: &Location) -> Option<()> {
        let pems = pem::parse_many(value).unwrap();

        if pems.is_empty() {
            return None;
        }

        for (i, pem) in pems.iter().enumerate() {
            let location = location.with_pem_bundle_index(i.try_into().unwrap());

            self.process_single_pem(pem, &location);
        }

        Some(())
    }

    fn process_single_pem(&mut self, pem: &pem::Pem, location: &Location) {
        match pem.tag() {
            "CERTIFICATE" => {
                self.process_pem_cert(pem, location);
            }
            "RSA PRIVATE KEY" => {
                self.process_pem_private_key(pem, location);
            }
            "EC PRIVATE KEY" => {
                println!("Found EC key at {}", location);
            }
            "PRIVATE KEY" => {
                panic!("private pkcs8 unsupported at {}", location);
            }
            "PUBLIC KEY" => {
                panic!("public pkcs8 unsupported at {}", location);
            }
            "RSA PUBLIC KEY" => {
                self.process_pem_public_key(pem, location);
            }
            "ENTITLEMENT DATA" | "RSA SIGNATURE" => {
                // dbg!("TODO: Handle {} at {}", pem.tag(), location);
            }
            _ => {
                panic!("unknown pem tag {}", pem.tag());
            }
        }
    }

    fn process_pem_private_key(&mut self, pem: &pem::Pem, location: &Location) {
        let rsa_private_key = rsa::RsaPrivateKey::from_pkcs1_pem(&pem.to_string()).unwrap();

        let bytes = bytes::Bytes::copy_from_slice(
            rsa_private_key
                .to_public_key()
                .to_pkcs1_der()
                .unwrap()
                .as_bytes(),
        );

        let public_part = PublicKey::from_bytes(&bytes);
        let private_part = PrivateKey::Rsa(rsa_private_key);

        self.register_private_key_public_key_mapping(public_part, &private_part);
        self.register_private_key(private_part, location);
    }

    fn register_private_key_public_key_mapping(
        &mut self,
        public_part: PublicKey,
        private_part: &PrivateKey,
    ) {
        self.public_to_private
            .insert(public_part, private_part.clone());
    }

    fn register_private_key(&mut self, private_part: PrivateKey, location: &Location) {
        match self.private_keys.entry(private_part.clone()) {
            Vacant(distributed_private_key_entry) => {
                distributed_private_key_entry.insert(Rc::new(RefCell::new(
                    distributed_private_key::DistributedPrivateKey {
                        locations: Locations(vec![location.clone()].into_iter().collect()),
                        key: private_part,
                        signees: vec![],
                    },
                )));
            }

            Occupied(distributed_private_key_entry) => {
                (**distributed_private_key_entry.into_mut())
                    .borrow_mut()
                    .locations
                    .0
                    .insert(location.clone());
            }
        }
    }

    fn process_pem_cert(&mut self, pem: &pem::Pem, location: &Location) {
        self.register_cert(
            &x509_certificate::CapturedX509Certificate::from_der(pem.contents()).unwrap(),
            location,
        );
    }

    fn register_cert(
        &mut self,
        x509_certificate: &x509_certificate::CapturedX509Certificate,
        location: &Location,
    ) {
        let hashable_cert = Certificate::from(x509_certificate.clone());

        if rules::EXTERNAL_CERTS.contains(&hashable_cert.subject) {
            return;
        }

        match hashable_cert.original.key_algorithm().unwrap() {
            x509_certificate::KeyAlgorithm::Rsa => {}
            x509_certificate::KeyAlgorithm::Ecdsa(_) => {
                return;
            }
            x509_certificate::KeyAlgorithm::Ed25519 => {
                return;
            }
        }

        match self.certs.entry(hashable_cert.clone()) {
            Vacant(distributed_cert) => {
                distributed_cert.insert(Rc::new(RefCell::new(DistributedCert {
                    certificate: hashable_cert,
                    locations: Locations(vec![location.clone()].into_iter().collect()),
                })));
            }
            Occupied(distributed_cert) => {
                (**distributed_cert.get())
                    .borrow_mut()
                    .locations
                    .0
                    .insert(location.clone());
            }
        }
    }

    fn process_k8s_static_resources(&mut self, k8s_dir: &Path) {
        self.process_static_resource_pems(k8s_dir);
    }

    fn process_static_resource_pems(&mut self, k8s_dir: &Path) {
        file_utils::globvec(k8s_dir, "**/*.pem")
            .into_iter()
            .chain(file_utils::globvec(k8s_dir, "**/*.crt").into_iter())
            .chain(file_utils::globvec(k8s_dir, "**/*.key").into_iter())
            .chain(file_utils::globvec(k8s_dir, "**/*.pub").into_iter())
            .for_each(|pem_path| {
                self.process_static_resource_pem(&pem_path);
            });
    }

    fn process_static_resource_pem(&mut self, pem_file_path: &PathBuf) {
        let mut file = fs::File::open(pem_file_path).expect("failed to open file");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("failed to read file");
        self.process_pem_bundle(
            &contents,
            &Location::Filesystem(FileLocation {
                file_path: pem_file_path.to_string_lossy().to_string(),
                content_location: FileContentLocation::Raw(LocationValueType::Unknown),
            }),
        );
    }

    /// Read all relevant resources from etcd and register them in the cluster_crypto object
    async fn process_etcd_resources(&mut self, etcd_client: Arc<Mutex<InMemoryK8sEtcd>>) {
        println!("Obtaining keys");
        let key_lists = {
            let etcd_client = etcd_client.lock().await;
            [
                &(etcd_client.list_keys("secrets").await),
                &(etcd_client.list_keys("configmaps").await),
            ]
        };

        let all_keys = key_lists.into_iter().flatten();

        println!("Retrieving etcd resources...");
        let join_results = join_all(
            all_keys
                .into_iter()
                .map(|key| {
                    let key = key.clone();
                    let etcd_client = Arc::clone(&etcd_client);
                    tokio::spawn(async move { etcd_client.lock().await.get(key).await })
                })
                .collect::<Vec<_>>(),
        )
        .await;

        println!("Processing etcd resources...");
        for contents in join_results {
            self.process_etcd_key(contents.unwrap()).await;
        }
    }

    fn process_pem_public_key(&mut self, pem: &pem::Pem, location: &Location) {
        let rsa_public_key =
            PublicKey::from_rsa_der(&bytes::Bytes::copy_from_slice(pem.contents()));

        match self.public_keys.entry(rsa_public_key.clone()) {
            Vacant(distributed_public_key_entry) => {
                distributed_public_key_entry.insert(Rc::new(RefCell::new(DistributedPublicKey {
                    locations: Locations(vec![location.clone()].into_iter().collect()),
                    public_key: rsa_public_key,
                })));
            }

            Occupied(distributed_private_key_entry) => {
                (**distributed_private_key_entry.into_mut())
                    .borrow_mut()
                    .locations
                    .0
                    .insert(location.clone());
            }
        }
    }
}

fn verify_jwt(
    distributed_private_key: &distributed_private_key::DistributedPrivateKey,
    distributed_jwt: &distributed_jwt::DistributedJwt,
) -> Result<jwt_simple::prelude::JWTClaims<Map<String, Value>>, jwt_simple::Error> {
    match &distributed_private_key.key {
        PrivateKey::Rsa(rsa_private_key) => {
            // TODO: Use public to private map instead? Should be faster
            let public_key = rsa_private_key.to_public_key();

            jwt_simple::prelude::RS256PublicKey::from_der(
                public_key.to_pkcs1_der().unwrap().as_bytes(),
            )
            .unwrap()
        }
    }
    .verify_token::<Map<String, Value>>(&distributed_jwt.jwt.str, None)
}
