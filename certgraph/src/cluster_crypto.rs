use crate::{
    file_utils::{self, read_file_to_string},
    k8s_etcd::{self, EtcdResult, InMemoryK8sEtcd},
    rules::{self, IGNORE_LIST_CONFIGMAP, KNOWN_MISSING_PRIVATE_KEY_CERTS},
};
use base64::{
    engine::general_purpose::{STANDARD as base64_standard, URL_SAFE_NO_PAD},
    Engine as _,
};
use bcder::{encode::Values, Mode};
use bytes::Bytes;
use futures_util::future::join_all;
use jwt_simple::prelude::RSAPublicKeyLike;
use locations::{FileContentLocation, FileLocation, K8sLocation, K8sResourceLocation, Location, LocationValueType, YamlLocation};
use p256::SecretKey;
use pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use regex::Regex;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use rsa::{pkcs8::EncodePublicKey, RsaPrivateKey};
use serde_json::{Map, Value};
use std::{
    cell::RefCell,
    collections::HashMap,
    fmt::{Display, Formatter},
    hash::{Hash, Hasher},
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    rc::Rc,
    sync::Arc,
};
use std::{
    collections::hash_map::Entry::{Occupied, Vacant},
    path::Path,
};
use tokio::sync::Mutex;
use x509_certificate::{rfc5280, CapturedX509Certificate, InMemorySigningKeyPair, X509CertificateError};

use self::{
    cert_key_pair::CertKeyPair,
    distributed_jwt::DistributedJwt,
    distributed_private_key::DistributedPrivateKey,
    distributed_public_key::DistributedPublicKey,
    locations::{FieldEncoding, Locations},
};

pub(crate) mod cert_key_pair;
pub(crate) mod crypto_utils;
pub(crate) mod distributed_jwt;
pub(crate) mod distributed_private_key;
pub(crate) mod distributed_public_key;
pub(crate) mod locations;
pub(crate) mod pem_utils;

/// This is the main struct that holds all the crypto objects we've found in the cluster and the
/// locations where we found them, and how they relate to each other.
pub(crate) struct ClusterCryptoObjectsInternal {
    /// At the end of the day we're scanning the entire cluster for private keys, public keys
    /// certificates, and jwts. These four hashmaps is where we store all of them. The reason
    /// they're hashmaps and not vectors is because every one of those objects we encounter might
    /// be found in multiple locations. The value types here (Distributed*) hold a list of
    /// locations where the key/cert was found, and the list of locations for each cert/key grows
    /// as we scan more and more resources. The hashmap keys are of-course hashables so we can
    /// easily check if we already encountered the object before.
    pub(crate) private_keys: HashMap<PrivateKey, Rc<RefCell<DistributedPrivateKey>>>,
    pub(crate) public_keys: HashMap<PublicKey, Rc<RefCell<DistributedPublicKey>>>,
    pub(crate) certs: HashMap<Certificate, Rc<RefCell<DistributedCert>>>,
    pub(crate) jwts: HashMap<Jwt, Rc<RefCell<DistributedJwt>>>,

    /// Every time we encounter a private key, we extract the public key
    /// from it and add to this mapping. This will later allow us to easily
    /// associate certificates with their matching private key (which would
    /// otherwise require brute force search).
    pub(crate) public_to_private: HashMap<PublicKey, PrivateKey>,

    /// After collecting all certs and private keys, we go through the list of certs and try to
    /// find a private key that matches the public key of the cert (with the help of
    /// public_to_private) and populate this list of pairs.
    pub(crate) cert_key_pairs: Vec<Rc<RefCell<CertKeyPair>>>,
}

#[derive(Hash, Eq, PartialEq, Clone)]
pub(crate) enum PrivateKey {
    Rsa(RsaPrivateKey),
    Ec(Bytes),
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa(_) => write!(f, "<rsa_priv>"),
            Self::Ec(_) => write!(f, "<ec_priv>"),
        }
    }
}

impl PrivateKey {
    fn pem(&self) -> pem::Pem {
        match &self {
            PrivateKey::Rsa(rsa_private_key) => pem::Pem::new("RSA PRIVATE KEY", rsa_private_key.to_pkcs1_der().unwrap().as_bytes()),
            PrivateKey::Ec(ec_bytes) => pem::Pem::new("EC PRIVATE KEY", ec_bytes.as_ref()),
        }
    }
}

#[derive(Hash, Eq, PartialEq, Clone)]
pub(crate) enum PublicKey {
    Rsa(Bytes),
    Ec(Bytes),
}

impl From<&PrivateKey> for PublicKey {
    fn from(priv_key: &PrivateKey) -> Self {
        match priv_key {
            PrivateKey::Rsa(private_key) => PublicKey::from_rsa_bytes(&bytes::Bytes::copy_from_slice(
                private_key.to_public_key().to_public_key_der().unwrap().as_bytes(),
            )),
            PrivateKey::Ec(ec_bytes) => {
                let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, ec_bytes).unwrap();
                PublicKey::Ec(Bytes::copy_from_slice(pair.public_key().as_ref()))
            }
        }
    }
}

impl From<Bytes> for PublicKey {
    fn from(value: Bytes) -> Self {
        PublicKey::from_rsa_bytes(&value)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa(der_bytes) => write!(f, "<rsa_pub: {}>", base64_standard.encode(der_bytes.as_ref())),
            Self::Ec(x) => write!(f, "<ec_pub: {:?}>", x),
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
        self.issuer == other.issuer && self.subject == other.subject && self.public_key == other.public_key
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
            subject: cert.subject_name().user_friendly_str().unwrap_or_else(|_error| {
                return "undecodable".to_string();
            }),
            public_key: match cert.key_algorithm().unwrap() {
                x509_certificate::KeyAlgorithm::Rsa => PublicKey::from_rsa_bytes(&bytes::Bytes::copy_from_slice(
                    &bytes::Bytes::copy_from_slice(&cert.to_public_key_der().unwrap().as_bytes()),
                )),
                x509_certificate::KeyAlgorithm::Ecdsa(_) => {
                    PublicKey::from_ec_cert_bytes(&bytes::Bytes::copy_from_slice(cert.encode_pem().as_bytes()))
                }
                x509_certificate::KeyAlgorithm::Ed25519 => panic!("ed25519 not supported"),
            },
            original: cert,
        }
    }
}

impl PublicKey {
    pub(crate) fn from_rsa_bytes(der_bytes: &Bytes) -> PublicKey {
        PublicKey::Rsa(der_bytes.clone())
    }

    pub(crate) fn from_ec_cert_bytes(cert_bytes: &Bytes) -> PublicKey {
        // Need to shell out to openssl
        let mut command = Command::new("openssl")
            .arg("x509")
            .arg("-pubkey")
            .arg("-noout")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        command.stdin.take().unwrap().write_all(cert_bytes).unwrap();
        let output = command.wait_with_output().unwrap();
        if !output.status.success() {
            panic!("openssl failed: {:?}", output);
        }
        PublicKey::Ec(output.stdout.into())
    }

    fn pem(&self) -> pem::Pem {
        match &self {
            PublicKey::Rsa(rsa_der_bytes) => pem::Pem::new("RSA PUBLIC KEY", rsa_der_bytes.as_ref()),
            PublicKey::Ec(_) => todo!("Unsupported"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DistributedCert {
    pub(crate) certificate: Certificate,
    pub(crate) locations: Locations,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum JwtSigner {
    Unknown,
    CertKeyPair(Rc<RefCell<CertKeyPair>>),
    PrivateKey(Rc<RefCell<DistributedPrivateKey>>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Signee {
    CertKeyPair(Rc<RefCell<CertKeyPair>>),
    Jwt(Rc<RefCell<DistributedJwt>>),
}

impl Display for Signee {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Signee::CertKeyPair(cert_key_pair) => {
                write!(f, "{}", (**cert_key_pair).borrow())
            }
            Signee::Jwt(jwt) => write!(f, "Jwt({})", (**jwt).borrow().locations),
        }
    }
}

impl Signee {
    fn regenerate(&mut self, original_signing_public_key: &PublicKey, new_signing_key: Option<&InMemorySigningKeyPair>) {
        match self {
            Self::CertKeyPair(cert_key_pair) => {
                (**cert_key_pair).borrow_mut().regenerate(new_signing_key);
            }
            Self::Jwt(jwt) => match new_signing_key {
                Some(key_pair) => (**jwt).borrow_mut().regenerate(&original_signing_public_key, key_pair),
                None => {
                    panic!("Cannot regenerate a jwt without a signing key, regenerate may only be called on a signee that is a root cert-key-pair")
                }
            },
        }
    }
}

fn encode_tbs_cert_to_der(tbs_certificate: &rfc5280::TbsCertificate) -> Vec<u8> {
    let mut tbs_der = Vec::<u8>::new();
    tbs_certificate.encode_ref().write_encoded(Mode::Der, &mut tbs_der).unwrap();
    tbs_der
}

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
        self.internal.lock().await.commit_to_etcd_and_disk(etcd_client).await;
    }
    pub(crate) async fn regenerate_crypto(&self) {
        self.internal.lock().await.regenerate_crypto();
    }
    pub(crate) async fn fill_signees(&mut self) {
        self.internal.lock().await.fill_signees();
    }
    pub(crate) async fn pair_certs_and_keys(&mut self) {
        self.internal.lock().await.pair_certs_and_keys();
    }
    pub(crate) async fn associate_public_keys(&mut self) {
        self.internal.lock().await.associate_public_keys();
    }
    pub(crate) async fn fill_cert_key_signers(&mut self) {
        self.internal.lock().await.fill_cert_key_signers();
    }
    pub(crate) async fn fill_jwt_signers(&mut self) {
        self.internal.lock().await.fill_jwt_signers();
    }
    pub(crate) async fn process_k8s_static_resources(&mut self, k8s_dir: &Path) {
        self.internal.lock().await.process_filesystem_resources(k8s_dir).await;
    }
    pub(crate) async fn process_static_resource_yaml(&mut self, contents: String, yaml_path: &PathBuf) {
        self.internal.lock().await.process_static_resource_yaml(contents, yaml_path);
    }
    pub(crate) async fn process_etcd_resources(&mut self, etcd_client: Arc<Mutex<InMemoryK8sEtcd>>) {
        self.internal.lock().await.process_etcd_resources(etcd_client).await;
    }
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

    /// Convenience function to display all the crypto objects in the cluster,
    /// their relationships, and their locations.
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

    /// Commit all the crypto objects to etcd and disk. This is called after all the crypto
    /// objects have been regenerated so that the newly generated objects are persisted in
    /// etcd and on disk.
    async fn commit_to_etcd_and_disk(&mut self, etcd_client: &mut InMemoryK8sEtcd) {
        for cert_key_pair in &self.cert_key_pairs {
            (**cert_key_pair).borrow().commit_to_etcd_and_disk(etcd_client).await;
        }

        for jwt in self.jwts.values() {
            (**jwt).borrow().commit_to_etcd_and_disk(etcd_client).await;
        }

        for private_key in self.private_keys.values() {
            (**private_key).borrow().commit_to_etcd_and_disk(etcd_client).await;
        }

        for public_key in self.public_keys.values() {
            (**public_key).borrow().commit_to_etcd_and_disk(etcd_client).await;
        }
    }

    /// Recursively regenerate all the crypto objects. This is done by regenerating the top level
    /// cert-key pairs and standalone private keys, which will in turn regenerate all the objects
    /// that depend on them (signees). Requires that first the crypto objects have been paired and
    /// associated through the other methods.
    fn regenerate_crypto(&mut self) {
        for cert_key_pair in &self.cert_key_pairs {
            if (**cert_key_pair).borrow().signer.is_some() {
                continue;
            }

            (**cert_key_pair).borrow_mut().regenerate(None)
        }

        for private_key in self.private_keys.values() {
            (**private_key).borrow_mut().regenerate()
        }

        println!("Making sure everything was regenerated...");
        self.assert_regeneration();
    }

    fn assert_regeneration(&mut self) {
        // Assert all known objects have been regenerated.
        for cert_key_pair in &self.cert_key_pairs {
            let signer = &(*(**cert_key_pair).borrow()).signer;
            if let Some(signer) = signer {
                assert!(
                    (**signer).borrow().regenerated,
                    "Didn't seem to regenerate signer with cert at {} and keys at {} while I'm at {} with keys at {}",
                    (*(**signer).borrow().distributed_cert).borrow().locations,
                    if let Some(key) = &(**signer).borrow().distributed_private_key {
                        format!("{}", (*key).borrow().locations)
                    } else {
                        "None".to_string()
                    },
                    (*(**cert_key_pair).borrow().distributed_cert).borrow().locations,
                    if let Some(key) = &(**cert_key_pair).borrow().distributed_private_key {
                        format!("{}", (*key).borrow().locations)
                    } else {
                        "None".to_string()
                    },
                );

                assert!(
                    (**signer).borrow().signees.len() > 0,
                    "Zero signees signer with cert at {} and keys at {}",
                    (*(**signer).borrow().distributed_cert).borrow().locations,
                    if let Some(key) = &(**signer).borrow().distributed_private_key {
                        format!("{}", (*key).borrow().locations)
                    } else {
                        "None".to_string()
                    },
                );

                for signee in &(**signer).borrow().signees {
                    match signee {
                        Signee::CertKeyPair(pair) => {
                            assert!(
                                (**pair).borrow().regenerated,
                                "Didn't seem to regenerate cert-key pair {} signee of {}",
                                (**pair).borrow(),
                                (**signer).borrow(),
                            );
                        }
                        Signee::Jwt(jwt) => {
                            assert!(
                                (**jwt).borrow().regenerated,
                                "Didn't seem to regenerate jwt {:#?} signee of {}",
                                (**jwt).borrow(),
                                (**signer).borrow(),
                            );
                        }
                    }
                }

                // Assert our cert-key pair is in the signees of the signer.
                assert!(
                    (**signer).borrow().signees.contains(&Signee::CertKeyPair(cert_key_pair.clone())),
                    "Signer {} doesn't have cert-key pair {} as a signee",
                    (**signer).borrow(),
                    (**cert_key_pair).borrow(),
                );
            }

            assert!(
                (**cert_key_pair).borrow().regenerated,
                "Didn't seem to regenerate cert at {}",
                (*(**cert_key_pair).borrow().distributed_cert).borrow().locations,
            );
        }
        for distributed_public_key in self.public_keys.values() {
            assert!(
                (*distributed_public_key).borrow().regenerated,
                "Didn't seem to regenerate public key {}",
                (**distributed_public_key).borrow(),
            );
        }
        for distributed_jwt in self.jwts.values() {
            assert!(
                (*distributed_jwt).borrow().regenerated,
                "Didn't seem to regenerate jwt {:#?}",
                (*distributed_jwt).borrow(),
            );
        }
        for distributed_private_key in self.private_keys.values() {
            assert!(
                (*distributed_private_key).borrow().regenerated,
                "Didn't seem to regenerate private key {}",
                (*distributed_private_key).borrow(),
            );
        }
        assert_eq!(self.certs.len(), 0);
    }

    fn fill_cert_key_signers(&mut self) {
        for cert_key_pair in &self.cert_key_pairs {
            let mut true_signing_cert: Option<Rc<RefCell<CertKeyPair>>> = None;
            if !(*(**cert_key_pair).borrow().distributed_cert)
                .borrow()
                .certificate
                .original
                .subject_is_issuer()
            {
                for potential_signing_cert_key_pair in &self.cert_key_pairs {
                    match (*(**cert_key_pair).borrow().distributed_cert)
                        .borrow()
                        .certificate
                        .original
                        .verify_signed_by_certificate(
                            &(*(*potential_signing_cert_key_pair).borrow().distributed_cert)
                                .borrow()
                                .certificate
                                .original,
                        ) {
                        Ok(_) => true_signing_cert = Some(Rc::clone(&potential_signing_cert_key_pair)),
                        Err(err) => match err {
                            X509CertificateError::CertificateSignatureVerificationFailed => {}
                            X509CertificateError::UnsupportedSignatureVerification(..) => {
                                // This is a hack to get around the fact this lib doesn't support
                                // all signature algorithms yet.
                                if openssl_is_signed(&potential_signing_cert_key_pair, &cert_key_pair) {
                                    true_signing_cert = Some(Rc::clone(&potential_signing_cert_key_pair));
                                }
                            }
                            _ => panic!("Error verifying signed by certificate: {:?}", err),
                        },
                    }
                }

                if true_signing_cert.is_none() {
                    panic!(
                        "No signing cert found for {}",
                        (*(**cert_key_pair).borrow().distributed_cert).borrow().locations
                    );
                }
            }

            (**cert_key_pair).borrow_mut().signer = true_signing_cert;
        }
    }

    /// For every jwt, find the private key that signed it (or certificate key pair that signed it,
    /// although rare in OCP) and record it. This will later be used to know how to regenerate the
    /// jwt.
    fn fill_jwt_signers(&mut self) {
        // Usually it's just one private key signing all the jwts, so to speed things up, we record
        // the last signer and use that as the first guess for the next jwt. This dramatically
        // speeds up the process of finding the signer for each jwt, as trying all private keys is
        // very slow, especially in debug mode without optimizations.
        let mut last_signer: Option<Rc<RefCell<DistributedPrivateKey>>> = None;

        for distributed_jwt in self.jwts.values() {
            let mut maybe_signer = JwtSigner::Unknown;

            if let Some(last_signer) = &last_signer {
                match verify_jwt(&PublicKey::from(&(*last_signer).borrow().key), &(**distributed_jwt).borrow()) {
                    Ok(_claims /* We don't care about the claims, only that the signature is correct */) => {
                        maybe_signer = JwtSigner::PrivateKey(Rc::clone(&last_signer));
                    }
                    Err(_error) => {}
                }
            } else {
                for distributed_private_key in self.private_keys.values() {
                    match verify_jwt(
                        &PublicKey::from(&(**distributed_private_key).borrow().key),
                        &(**distributed_jwt).borrow(),
                    ) {
                        Ok(_claims /* We don't care about the claims, only that the signature is correct */) => {
                            maybe_signer = JwtSigner::PrivateKey(Rc::clone(distributed_private_key));
                            last_signer = Some(Rc::clone(&distributed_private_key));
                            break;
                        }
                        Err(_error) => {}
                    }
                }
            }

            match &maybe_signer {
                JwtSigner::Unknown => {
                    for cert_key_pair in &self.cert_key_pairs {
                        if let Some(distributed_private_key) = &(**cert_key_pair).borrow().distributed_private_key {
                            match verify_jwt(
                                &PublicKey::from(&(**distributed_private_key).borrow().key),
                                &(**distributed_jwt).borrow(),
                            ) {
                                Ok(_claims /* We don't care about the claims, only that the signature is correct */) => {
                                    maybe_signer = JwtSigner::CertKeyPair(Rc::clone(cert_key_pair));
                                    break;
                                }
                                Err(_error) => {}
                            }
                        }
                    }
                }
                _ => {}
            }

            if maybe_signer == JwtSigner::Unknown {
                panic!("JWT has unknown signer");
            }

            (**distributed_jwt).borrow_mut().signer = maybe_signer;
        }
    }

    /// For every cert-key pair or private key, find all the crypto objects that depend on it and
    /// record them. This will later be used to know how to regenerate the crypto objects.
    fn fill_signees(&mut self) {
        for cert_key_pair in &self.cert_key_pairs {
            let mut signees = Vec::new();
            for potential_signee in &self.cert_key_pairs {
                if let Some(potential_signee_signer) = &(**potential_signee).borrow().signer {
                    if (*(**potential_signee_signer).borrow().distributed_cert)
                        .borrow()
                        .certificate
                        .original
                        == (*(**cert_key_pair).borrow().distributed_cert).borrow().certificate.original
                    {
                        signees.push(Signee::CertKeyPair(Rc::clone(&potential_signee)));
                    }
                }
            }
            for potential_jwt_signee in self.jwts.values() {
                match &(**potential_jwt_signee).borrow_mut().signer {
                    JwtSigner::Unknown => panic!("JWT has unknown signer"),
                    JwtSigner::CertKeyPair(jwt_signer_cert_key_pair) => {
                        if jwt_signer_cert_key_pair == cert_key_pair {
                            signees.push(Signee::Jwt(Rc::clone(potential_jwt_signee)));
                        }
                    }
                    JwtSigner::PrivateKey(_) => {}
                }
            }

            (**cert_key_pair).borrow_mut().signees = signees;
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

    /// Find the private key associated with the subject of each certificate and combine them into
    /// a cert-key pair. Also remove the private key from the list of private keys as it is now
    /// part of a cert-key pair, the remaining private keys are considered standalone.
    fn pair_certs_and_keys(&mut self) {
        let mut paired_cers_to_remove = vec![];
        for (hashable_cert, distributed_cert) in &self.certs {
            let pair = Rc::new(RefCell::new(cert_key_pair::CertKeyPair {
                distributed_private_key: None,
                distributed_cert: Rc::clone(distributed_cert),
                signer: None,
                signees: Vec::new(),
                associated_public_key: None,
                regenerated: false,
            }));

            let subject_public_key = (**distributed_cert).borrow().certificate.public_key.clone();
            if let Occupied(private_key) = self.public_to_private.entry(subject_public_key.clone()) {
                if let Occupied(distributed_private_key) = self.private_keys.entry(private_key.get().clone()) {
                    (*pair).borrow_mut().distributed_private_key = Some(Rc::clone(distributed_private_key.get()));

                    // Remove the private key from the pool of private keys as it's now paired with a cert
                    self.private_keys.remove(&private_key.get());
                } else {
                    panic!("Private key not found");
                }
            } else if KNOWN_MISSING_PRIVATE_KEY_CERTS.contains(&(**distributed_cert).borrow().certificate.subject)
                || KNOWN_MISSING_PRIVATE_KEY_CERTS.iter().any(|known_missing_private_key_cert| {
                    let re = Regex::new(known_missing_private_key_cert).unwrap();
                    re.is_match(&(**distributed_cert).borrow().certificate.subject)
                })
            {
                println!("Known no private key for {}", (**distributed_cert).borrow().certificate.subject);
            } else {
                panic!(
                    "Private key not found for cert not in KNOWN_MISSING_PRIVATE_KEY_CERTS, cannot continue, {}. The cert was found in {}",
                    (**distributed_cert).borrow().certificate.subject,
                    (**distributed_cert).borrow().locations,
                );
            }

            paired_cers_to_remove.push(hashable_cert.clone());
            self.cert_key_pairs.push(pair);
        }

        for paired_cer_to_remove in paired_cers_to_remove {
            self.certs.remove(&paired_cer_to_remove);
        }
    }

    /// Associate public keys with their cert-key pairs or standalone private keys.
    fn associate_public_keys(&mut self) {
        for cert_key_pair in &self.cert_key_pairs {
            if let Occupied(public_key_entry) = self.public_keys.entry(
                (*(**cert_key_pair).borrow().distributed_cert)
                    .borrow()
                    .certificate
                    .public_key
                    .clone(),
            ) {
                (*cert_key_pair).borrow_mut().associated_public_key = Some(Rc::clone(public_key_entry.get()));
            }
        }

        for distributed_private_key in self.private_keys.values() {
            let public_part = PublicKey::from(&(*distributed_private_key).borrow().key);

            if let Occupied(public_key_entry) = self.public_keys.entry(public_part) {
                (*distributed_private_key).borrow_mut().associated_distributed_public_key = Some(Rc::clone(public_key_entry.get()));
            }
        }
    }

    /// Given an etcd key (not cryptographic key, just key as in key-value) and its contents, scan
    /// it for cryptographic keys and certificates and record them in the appropriate data
    /// structures.
    async fn process_etcd_result(&mut self, etcd_result: EtcdResult) {
        let value: &Value = &serde_yaml::from_slice(etcd_result.value.as_slice()).expect("failed to parse yaml");
        let location = K8sResourceLocation::from(value);

        // Ensure our as_etcd_key function generates the expected key, while we still have the key
        assert_eq!(etcd_result.key, location.as_etcd_key());

        match location.kind.as_str() {
            "Secret" => self.scan_k8s_secret(value, &location),
            "ConfigMap" => self.scan_k8s_configmap(value, &location),
            "ValidatingWebhookConfiguration" => self.scan_k8s_validatingwebhookconfiguration(value, &location),
            "APIService" => self.scan_k8s_apiservice(value, &location),
            "MachineConfig" => self.scan_k8s_machineconfig(value, &location),
            _ => {}
        }
    }

    /// Given a configmap taken from etcd, scan it for cryptographic keys and certificates and
    /// record them in the appropriate data structures.
    fn scan_k8s_configmap(&mut self, value: &Value, k8s_resource_location: &K8sResourceLocation) {
        if let Some(data) = value.as_object().unwrap().get("data") {
            match data {
                Value::Object(data) => {
                    for (key, value) in data.iter() {
                        if IGNORE_LIST_CONFIGMAP.contains(key) {
                            continue;
                        }
                        if let Value::String(value) = value {
                            let location = &Location::K8s(K8sLocation {
                                resource_location: k8s_resource_location.clone(),
                                yaml_location: YamlLocation {
                                    json_pointer: format!("/data/{key}"),
                                    value: LocationValueType::Unknown,
                                    encoding: FieldEncoding::None,
                                },
                            });

                            self.process_unknown_yaml_value(value.to_string(), location);
                        }
                    }
                }
                _ => todo!(),
            }
        }
    }

    /// Given a ValidatingWebhookConfiguration taken from etcd, scan it for cryptographic keys and
    /// certificates and record them in the appropriate data structures.
    fn scan_k8s_validatingwebhookconfiguration(&mut self, value: &Value, k8s_resource_location: &K8sResourceLocation) {
        if let Some(Value::Array(webhooks)) = value.as_object().unwrap().get("webhooks") {
            for (webhook_index, webhook_value) in webhooks.iter().enumerate() {
                if let Some(Value::Object(client_config)) = webhook_value.get("clientConfig") {
                    if let Some(ca_bundle) = client_config.get("caBundle") {
                        let location = &Location::K8s(K8sLocation {
                            resource_location: k8s_resource_location.clone(),
                            yaml_location: YamlLocation {
                                json_pointer: format!("/webhooks/{webhook_index}/clientConfig/caBundle"),
                                value: LocationValueType::Unknown,
                                encoding: FieldEncoding::Base64,
                            },
                        });

                        self.process_base64_value(ca_bundle, location);
                    }
                }
            }
        }
    }

    /// Given an APIService taken from etcd, scan it for cryptographic keys and certificates and
    /// record them in the appropriate data structures.
    fn scan_k8s_apiservice(&mut self, value: &Value, k8s_resource_location: &K8sResourceLocation) {
        if let Some(spec_object) = value.as_object().unwrap().get("spec") {
            match spec_object {
                Value::Object(spec) => {
                    if let Some(ca_bundle) = spec.get("caBundle") {
                        let location = &Location::K8s(K8sLocation {
                            resource_location: k8s_resource_location.clone(),
                            yaml_location: YamlLocation {
                                json_pointer: format!("/spec/caBundle"),
                                value: LocationValueType::Unknown,
                                encoding: FieldEncoding::Base64,
                            },
                        });

                        self.process_base64_value(ca_bundle, location);
                    }
                }
                _ => todo!(),
            }
        }
    }

    /// Given a MachineConfig taken from etcd, scan it for cryptographic keys and certificates and
    /// record them in the appropriate data structures.
    fn scan_k8s_machineconfig(&mut self, value: &Value, k8s_resource_location: &K8sResourceLocation) {
        if let Some(Value::Object(spec)) = value.as_object().unwrap().get("spec") {
            if let Some(Value::Object(config)) = spec.get("config") {
                if let Some(Value::Object(storage)) = config.get("storage") {
                    if let Some(Value::Array(files)) = storage.get("files") {
                        for (file_index, file) in files.iter().enumerate() {
                            if let Value::Object(file) = file {
                                if let Some(Value::String(path)) = file.get("path") {
                                    if path.ends_with(".pem") || path.ends_with(".crt") {
                                        if let Some(Value::Object(contents)) = file.get("contents") {
                                            if let Some(source) = contents.get("source") {
                                                let location = &Location::K8s(K8sLocation {
                                                    resource_location: k8s_resource_location.clone(),
                                                    yaml_location: YamlLocation {
                                                        json_pointer: format!("/spec/config/storage/files/{file_index}/contents/source"),
                                                        value: LocationValueType::Unknown,
                                                        encoding: FieldEncoding::DataUrl,
                                                    },
                                                });

                                                self.process_data_url_value(source, location);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Given a secret taken from etcd, scan it for cryptographic keys and certificates and
    /// record them in the appropriate data structures.
    fn scan_k8s_secret(&mut self, value: &Value, k8s_resource_location: &K8sResourceLocation) {
        if let Some(data) = value.as_object().unwrap().get("data") {
            match data {
                Value::Object(data) => {
                    for (key, value) in data.iter() {
                        if rules::IGNORE_LIST_SECRET.contains(key) {
                            continue;
                        }

                        self.process_base64_value(
                            value,
                            &Location::k8s(k8s_resource_location.clone(), "/data", key, FieldEncoding::Base64),
                        );
                    }
                }
                _ => todo!(),
            }
        }

        if let Some(metadata) = value.as_object().unwrap().get("metadata") {
            match metadata {
                Value::Object(metadata) => {
                    if let Some(annotations) = metadata.get("annotations") {
                        match annotations {
                            Value::Object(annotations) => {
                                for (key, value) in annotations.iter() {
                                    self.process_unknown_yaml_value(
                                        value.to_string(),
                                        &Location::k8s(k8s_resource_location.clone(), "/metadata/annotations", key, FieldEncoding::None),
                                    );
                                }
                            }
                            _ => todo!(),
                        }
                    }
                }
                _ => todo!(),
            }
        }
    }

    /// Given a data-url-encoded value taken from a YAML field, decode it and scan it for
    /// cryptographic keys and certificates and record them in the appropriate data structures.
    fn process_data_url_value(&mut self, value: &Value, location: &Location) {
        if let Value::String(string_value) = value {
            if let Ok(url) = data_url::DataUrl::process(string_value) {
                let (decoded, _fragment) = url.decode_to_vec().unwrap();
                if let Ok(decoded) = String::from_utf8(decoded) {
                    self.process_unknown_yaml_value(decoded, location);
                } else {
                    // We don't search for crypto objects inside binaries
                    return;
                }
            } else {
                panic!("Failed to decode data-url");
            }
        }
    }

    /// Given a base64-encoded value taken from a YAML field, decode it and scan it for
    /// cryptographic keys and certificates and record them in the appropriate data structures.
    fn process_base64_value(&mut self, value: &Value, location: &Location) {
        if let Value::String(string_value) = value {
            if let Ok(value) = base64_standard.decode(string_value.as_bytes()) {
                self.process_unknown_yaml_value(
                    String::from_utf8(value).unwrap_or_else(|_| {
                        panic!("Failed to decode base64");
                    }),
                    location,
                );
            } else {
                panic!("Failed to decode base64");
            }
        }
    }

    /// Given a value taken from a YAML field, scan it for cryptographic keys and certificates and
    /// record them in the appropriate data structures.
    fn process_unknown_yaml_value(&mut self, value: String, location: &Location) {
        if let Some(_) = self.process_pem_bundle(&value, location) {
            return;
        };

        if let Some(_) = self.process_jwt(&value, location) {
            return;
        }
    }

    /// Given a value taken from a YAML field, check if it looks like a JWT and record it in the
    /// appropriate data structures.
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

        let jwt = Jwt { str: value.to_string() };

        let location = location.with_jwt();

        match self.jwts.entry(jwt.clone()) {
            Vacant(distributed_jwt) => {
                distributed_jwt.insert(Rc::new(RefCell::new(distributed_jwt::DistributedJwt {
                    jwt,
                    locations: Locations(vec![location].into_iter().collect()),
                    signer: JwtSigner::Unknown,
                    regenerated: false,
                })));
            }
            Occupied(distributed_jwt) => {
                (**distributed_jwt.get()).borrow_mut().locations.0.insert(location);
            }
        }

        Some(())
    }

    /// Given a PEM bundle, scan it for cryptographic keys and certificates and record them in the
    /// appropriate data structures.
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

    /// Given a single PEM, scan it for cryptographic keys and certificates and record them in the
    /// appropriate data structures.
    fn process_single_pem(&mut self, pem: &pem::Pem, location: &Location) {
        match pem.tag() {
            "CERTIFICATE" => {
                self.process_pem_cert(pem, location);
            }
            "RSA PRIVATE KEY" => {
                self.process_pem_rsa_private_key(pem, location);
            }
            "EC PRIVATE KEY" => {
                self.process_pem_ec_private_key(pem, location);
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

    /// Given an RSA private key PEM, record it in the appropriate data structures.
    fn process_pem_rsa_private_key(&mut self, pem: &pem::Pem, location: &Location) {
        let rsa_private_key = rsa::RsaPrivateKey::from_pkcs1_pem(&pem.to_string()).unwrap();

        let private_part = PrivateKey::Rsa(rsa_private_key);
        let public_part = PublicKey::from(&private_part);

        self.register_private_key_public_key_mapping(public_part, &private_part);
        self.register_private_key(private_part, location);
    }

    /// Given an EC private key PEM, record it in the appropriate data structures.
    fn process_pem_ec_private_key(&mut self, pem: &pem::Pem, location: &Location) {
        // First convert to pkcs#8 by shelling out to openssl pkcs8 -topk8 -nocrypt:
        let mut command = Command::new("openssl")
            .arg("pkcs8")
            .arg("-topk8")
            .arg("-nocrypt")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        command.stdin.take().unwrap().write_all(pem.to_string().as_bytes()).unwrap();

        let output = command.wait_with_output().unwrap();
        let pem = pem::parse(output.stdout).unwrap();

        let key = pem.to_string().parse::<SecretKey>().unwrap();
        let public_key = key.public_key();

        let private_part = PrivateKey::Ec(Bytes::copy_from_slice(pem.contents()));
        let public_part = PublicKey::Ec(Bytes::copy_from_slice(public_key.to_string().as_bytes()));

        self.register_private_key_public_key_mapping(public_part, &private_part);
        self.register_private_key(private_part, location);
    }

    /// Associate a private key with the public key derived from it by us. This later helps
    /// us associate it with the certificate that contains the public key as the subject.
    fn register_private_key_public_key_mapping(&mut self, public_part: PublicKey, private_part: &PrivateKey) {
        self.public_to_private.insert(public_part, private_part.clone());
    }

    fn register_private_key(&mut self, private_part: PrivateKey, location: &Location) {
        match self.private_keys.entry(private_part.clone()) {
            Vacant(distributed_private_key_entry) => {
                distributed_private_key_entry.insert(Rc::new(RefCell::new(distributed_private_key::DistributedPrivateKey {
                    locations: Locations(vec![location.clone()].into_iter().collect()),
                    key: private_part,
                    signees: vec![],
                    // We don't set the public key here even though we just generated it because
                    // this field is for actual public keys that we find in the wild, not ones we
                    // generate ourselves.
                    associated_distributed_public_key: None,
                    regenerated: false,
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

    /// Given a certificate PEM, record it in the appropriate data structures.
    fn process_pem_cert(&mut self, pem: &pem::Pem, location: &Location) {
        self.register_cert(
            &x509_certificate::CapturedX509Certificate::from_der(pem.contents()).unwrap(),
            location,
        );
    }

    fn register_cert(&mut self, x509_certificate: &x509_certificate::CapturedX509Certificate, location: &Location) {
        let hashable_cert = Certificate::from(x509_certificate.clone());

        if rules::EXTERNAL_CERTS.contains(&hashable_cert.subject) {
            return;
        }

        match hashable_cert.original.key_algorithm().unwrap() {
            x509_certificate::KeyAlgorithm::Rsa => {}
            x509_certificate::KeyAlgorithm::Ecdsa(_) => {}
            x509_certificate::KeyAlgorithm::Ed25519 => {
                panic!("ed25519 unsupported at {}", location);
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
                (**distributed_cert.get()).borrow_mut().locations.0.insert(location.clone());
            }
        }
    }

    /// Recursively scans the filesystem for resources which might contain cryptographic objects
    /// and records them in the appropriate data structures
    async fn process_filesystem_resources(&mut self, dir: &Path) {
        self.process_filesystem_raw_pems(dir).await;
        self.process_filesystem_yamls(dir).await;
    }

    /// Recursively scans a directoy for files which exclusively contain a PEM bundle (as opposed
    /// to being embedded in a YAML file) and records them in the appropriate data structures.
    async fn process_filesystem_raw_pems(&mut self, dir: &Path) {
        for raw_pem_path in file_utils::globvec(dir, "**/*.pem")
            .into_iter()
            .chain(file_utils::globvec(dir, "**/*.crt").into_iter())
            .chain(file_utils::globvec(dir, "**/*.key").into_iter())
            .chain(file_utils::globvec(dir, "**/*.pub").into_iter())
            // Also scan for the .mcdorig versions of the above files, which are sometimes created
            // my machine-config-daemon
            .chain(file_utils::globvec(dir, "**/*.crt.mcdorig").into_iter())
            .chain(file_utils::globvec(dir, "**/*.key.mcdorig").into_iter())
            .chain(file_utils::globvec(dir, "**/*.pub.mcdorig").into_iter())
        {
            self.process_static_resource_raw_pem_bundle(read_file_to_string(raw_pem_path.clone()).await, &raw_pem_path);
        }
    }

    /// Recrusively scans a directory for yaml files which might contain cryptographic objects and
    /// records said objects in the appropriate data structures.
    async fn process_filesystem_yamls(&mut self, dir: &Path) {
        for yaml_path in file_utils::globvec(dir, "**/kubeconfig*").into_iter() {
            if self
                .process_static_resource_yaml(read_file_to_string(yaml_path.clone()).await, &yaml_path)
                .is_none()
            {
                println!("Failed to process {}", yaml_path.to_string_lossy());
            }
        }
    }

    // Processes a filesystem pem bundle for cryptographic objects and records them in the
    // appropriate data structures
    fn process_static_resource_raw_pem_bundle(&mut self, contents: String, pem_file_path: &PathBuf) {
        self.process_pem_bundle(
            &contents,
            &Location::Filesystem(FileLocation {
                path: pem_file_path.to_string_lossy().to_string(),
                content_location: FileContentLocation::Raw(LocationValueType::Unknown),
            }),
        );
    }

    /// Read all relevant resources from etcd, scan them for cryptographic objects and record them
    /// in the appropriate data structures.
    async fn process_etcd_resources(&mut self, etcd_client: Arc<Mutex<InMemoryK8sEtcd>>) {
        let key_lists = {
            let etcd_client = etcd_client.lock().await;
            [
                &(etcd_client.list_keys("secrets").await),
                &(etcd_client.list_keys("configmaps").await),
                &(etcd_client.list_keys("validatingwebhookconfigurations").await),
                &(etcd_client.list_keys("apiregistration.k8s.io/apiservices").await),
                &(etcd_client.list_keys("machineconfiguration.openshift.io/machineconfigs").await),
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
            self.process_etcd_result(contents.unwrap()).await;
        }
    }

    fn process_pem_public_key(&mut self, pem: &pem::Pem, location: &Location) {
        let rsa_public_key = PublicKey::from_rsa_bytes(&bytes::Bytes::copy_from_slice(pem.contents()));

        match self.public_keys.entry(rsa_public_key.clone()) {
            Vacant(distributed_public_key_entry) => {
                distributed_public_key_entry.insert(Rc::new(RefCell::new(distributed_public_key::DistributedPublicKey {
                    locations: Locations(vec![location.clone()].into_iter().collect()),
                    key: rsa_public_key,
                    regenerated: false,
                })));
            }

            Occupied(distributed_public_key_entry) => {
                (**distributed_public_key_entry.into_mut())
                    .borrow_mut()
                    .locations
                    .0
                    .insert(location.clone());
            }
        }
    }

    fn process_static_resource_yaml(&mut self, contents: String, yaml_path: &PathBuf) -> Option<()> {
        let value: &Value = &serde_yaml::from_str(contents.as_str()).ok().unwrap();

        for (i, user) in value["users"].as_array().unwrap().into_iter().enumerate() {
            for user_field in ["client-certificate-data", "client-key-data"].iter() {
                if let Some(field_value) = user.as_object().unwrap()["user"]
                    .as_object()
                    .unwrap()
                    .get(user_field.to_string().as_str())
                {
                    self.process_base64_value(
                        field_value,
                        &Location::file_yaml(
                            yaml_path.to_string_lossy().to_string().as_str(),
                            &format!("/users/{}/user", i),
                            user_field,
                            FieldEncoding::Base64,
                        ),
                    );
                }
            }
        }

        for (i, cluster) in value["clusters"].as_array().unwrap().into_iter().enumerate() {
            if let Some(cluster_cert) = cluster.as_object().unwrap()["cluster"]
                .as_object()
                .unwrap()
                .get("certificate-authority-data")
            {
                self.process_base64_value(
                    cluster_cert,
                    &Location::file_yaml(
                        yaml_path.to_string_lossy().to_string().as_str(),
                        &format!("/clusters/{}/cluster", i),
                        "certificate-authority-data",
                        FieldEncoding::Base64,
                    ),
                );
            }
        }

        Some(())
    }
}

/// Shell out to openssl to verify that a certificate is signed by a given signing certificate. We
/// use this when our certificate lib doesn't support the signature algorithm used by the
/// certificates.
fn openssl_is_signed(potential_signer: &Rc<RefCell<CertKeyPair>>, signee: &Rc<RefCell<CertKeyPair>>) -> bool {
    // TODO: This condition is a hack. We should trust the openssl command we run further down to
    // tell us this, but we don't because currently the way this openssl command works, if you pass
    // it the same cert in both arguments, even when said cert is not self-signed, openssl would
    // give it a green light and say it's valid. So we do this hack to avoid pretending
    // certificates are their own signer when they're not. This is a hack because it's possible
    // that a certificate is not self-signed and has the same issuer and subject and it would pass
    // here undetected. This is not a big deal in our use case because these certs are all coming
    // from our trusted installer/operators.
    if potential_signer == signee && !(*(**potential_signer).borrow().distributed_cert).borrow().certificate.original.subject_is_issuer() {
        return false;
    }

    let mut signing_cert_file = tempfile::NamedTempFile::new().unwrap();
    signing_cert_file
        .write_all(
            &(*(**potential_signer).borrow().distributed_cert)
                .borrow()
                .certificate
                .original
                .encode_pem()
                .as_bytes(),
        )
        .unwrap();
    let mut signed_cert_file = tempfile::NamedTempFile::new().unwrap();
    signed_cert_file
        .write_all(
            &(*(**signee).borrow().distributed_cert)
                .borrow()
                .certificate
                .original
                .encode_pem()
                .as_bytes(),
        )
        .unwrap();
    let mut openssl_verify_command = Command::new("openssl");
    openssl_verify_command
        .arg("verify")
        .arg("-no_check_time")
        .arg("-no-CAfile")
        .arg("-no-CApath")
        .arg("-partial_chain")
        .arg("-trusted")
        .arg(signing_cert_file.path())
        .arg(signed_cert_file.path());
    let openssl_verify_output = openssl_verify_command.output().unwrap();
    openssl_verify_output.status.success()
}

fn verify_jwt(
    public_key: &PublicKey,
    distributed_jwt: &distributed_jwt::DistributedJwt,
) -> Result<jwt_simple::prelude::JWTClaims<Map<String, Value>>, jwt_simple::Error> {
    match &public_key {
        PublicKey::Rsa(bytes) => jwt_simple::prelude::RS256PublicKey::from_der(bytes).unwrap(),
        PublicKey::Ec(_) => return Err(jwt_simple::Error::msg("EC public keys are not supported")),
    }
    .verify_token::<Map<String, Value>>(&distributed_jwt.jwt.str, None)
}
