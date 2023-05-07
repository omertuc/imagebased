use std::{
    collections::{
        hash_map::Entry::{Occupied, Vacant},
        HashMap, HashSet,
    },
    fmt::{Debug, Display},
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use base64::Engine as _;

use lazy_static::lazy_static;
use serde_json::Value;

use rsa::{pkcs1::DecodeRsaPrivateKey, RsaPrivateKey, RsaPublicKey};
use x509_parser::public_key::RSAPublicKey;

lazy_static! {
    static ref IGNORE_LIST_CONFIGMAP: HashSet<String> = vec![
        "verifier-public-key-redhat",
        "service-account-001.pub",
        "service-account-002.pub",
        // "ca-bundle.crt"
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    static ref IGNORE_LIST_SECRET: HashSet<String> = vec!["prometheus.yaml.gz", "alertmanager.yaml.gz"]
        .into_iter()
        .map(str::to_string)
        .collect();
}

fn main() {
    let root_dir = PathBuf::from(".");

    let mut graph = CryptoGraph {
        public_to_private: HashMap::new(),
        identity_to_public: HashMap::new(),
        ca_certs: HashSet::new(),
        root_certs: HashMap::new(),
        keys: HashSet::new(),
        cert_to_private_key: HashMap::new(),
    };

    for allow_incomplete in [true, false] {
        process_etcd_dump(
            &root_dir.join("gathers/first/etcd"),
            &mut graph,
            allow_incomplete,
        );
        process_k8s_dir_dump(
            &root_dir.join("gathers/first/kubernetes"),
            &mut graph,
            allow_incomplete,
        );
    }
}

fn globvec(location: &Path, globstr: &str) -> Vec<PathBuf> {
    let mut globoptions = glob::MatchOptions::new();
    globoptions.require_literal_leading_dot = true;

    glob::glob_with(location.join(globstr).to_str().unwrap(), globoptions)
        .unwrap()
        .map(|x| x.unwrap())
        .collect::<Vec<_>>()
}

fn process_etcd_dump(etcd_dump_dir: &PathBuf, graph: &mut CryptoGraph, allow_incomplete: bool) {
    process_k8s_yamls(etcd_dump_dir, graph, allow_incomplete);
}

fn process_k8s_dir_dump(k8s_dir: &PathBuf, graph: &mut CryptoGraph, allow_incomplete: bool) {
    // process_k8s_yamls(k8s_dir, graph, allow_incomplete);
    process_pems(k8s_dir, graph, allow_incomplete);
}

enum Location {
    K8s(K8sLocation),
    Filesystem(FileLocation),
}

impl Debug for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::K8s(arg0) => f.debug_tuple("K8s").field(arg0).finish(),
            Self::Filesystem(arg0) => f.debug_tuple("Filesystem").field(arg0).finish(),
        }
    }
}

impl Location {
    fn with_pem_bundle_index(&self, pem_bundle_index: u64) -> Self {
        match self {
            Self::K8s(k8s_location) => {
                let mut new_k8s_location = k8s_location.clone();
                new_k8s_location.yaml_location.pem_location.pem_bundle_index =
                    Some(pem_bundle_index);
                Self::K8s(new_k8s_location)
            }
            Self::Filesystem(file_location) => match file_location {
                FileLocation::Raw(pem_location_info) => {
                    let mut new_pem_location_info = pem_location_info.clone();
                    new_pem_location_info.pem_bundle_index = Some(pem_bundle_index);
                    Self::Filesystem(FileLocation::Raw(new_pem_location_info))
                }
                FileLocation::YAML(yaml_location) => {
                    let mut new_yaml_location = yaml_location.clone();
                    new_yaml_location.pem_location.pem_bundle_index = Some(pem_bundle_index);
                    Self::Filesystem(FileLocation::YAML(new_yaml_location))
                }
            },
        }
    }
}

#[derive(Debug, Clone)]
struct PemLocationInfo {
    pem_bundle_index: Option<u64>,
}

#[derive(Debug, Clone)]
enum FileLocation {
    Raw(PemLocationInfo),
    YAML(YamlLocation),
}

#[derive(Debug, Clone)]
struct YamlLocation {
    json_path: String,
    pem_location: PemLocationInfo,
}

#[derive(Debug, Clone)]
struct K8sResourceLocation {
    namespace: String,
    kind: String,
    name: String,
}

#[derive(Debug, Clone)]
struct K8sLocation {
    resource_location: K8sResourceLocation,
    yaml_location: YamlLocation,
}

#[derive(Clone)]
enum PrivateKey {
    Rsa(RsaPrivateKey),
}

#[derive(Hash, Eq, PartialEq)]
enum PublicKey {
    Rsa(RsaPublicKey),
}

impl PublicKey {
    fn from_rsa(rsa_public_key: &RSAPublicKey) -> PublicKey {
        let modulus = rsa::BigUint::from_bytes_be(&rsa_public_key.modulus);
        let exponent = rsa::BigUint::from_bytes_be(&rsa_public_key.exponent);

        PublicKey::Rsa(RsaPublicKey::new(modulus, exponent).unwrap())
    }
}

#[allow(clippy::large_enum_variant)]
enum Key {
    PrivateKey(Location, PrivateKey),
    PublicKey(Location, String),
}

struct CryptoGraph {
    public_to_private: HashMap<PublicKey, PrivateKey>,
    identity_to_public: HashMap<String, String>,
    ca_certs: HashSet<String>,
    keys: HashSet<Key>,
    cert_to_private_key: HashMap<String, PrivateKey>,

    // Maps root cert to a list of certificates signed by it
    root_certs: HashMap<String, Vec<String>>,
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

fn process_k8s_yamls(gather_dir: &PathBuf, graph: &mut CryptoGraph, allow_incomplete: bool) {
    let all_yaml_files = globvec(&gather_dir, "**/*.yaml");

    all_yaml_files.iter().for_each(|yaml_path| {
        process_k8s_yaml(yaml_path.to_path_buf(), graph, allow_incomplete);
    });
}

fn process_pems(gather_dir: &PathBuf, graph: &mut CryptoGraph, allow_incomplete: bool) {
    globvec(gather_dir, "**/*.pem")
        .into_iter()
        .chain(globvec(gather_dir, "**/*.crt").into_iter())
        .chain(globvec(gather_dir, "**/*.key").into_iter())
        .chain(globvec(gather_dir, "**/*.pub").into_iter())
        .for_each(|pem_path| {
            process_pem(&pem_path, graph, allow_incomplete);
        });
}

fn process_pem(pem_file_path: &PathBuf, graph: &mut CryptoGraph, allow_incomplete: bool) {
    let mut file = fs::File::open(pem_file_path).expect("failed to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("failed to read file");
    unpem(
        &contents,
        graph,
        true,
        &Location::Filesystem(FileLocation::Raw(PemLocationInfo {
            pem_bundle_index: None,
        })),
    );
}

fn process_k8s_yaml(yaml_path: PathBuf, crypto_graph: &mut CryptoGraph, allow_incomplete: bool) {
    let mut file = fs::File::open(yaml_path.clone()).expect("failed to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("failed to read file");
    let value: Value = serde_yaml::from_str(&contents).expect("failed to parse yaml");

    scan_k8s_resource(&value, crypto_graph, allow_incomplete);
}

fn scan_k8s_secret(
    value: &Value,
    graph: &mut CryptoGraph,
    allow_incomplete: bool,
    k8s_resource_location: &K8sResourceLocation,
) {
    if let Some(data) = value.as_object().unwrap().get("data") {
        match data {
            Value::Object(data) => {
                for (key, value) in data.iter() {
                    if IGNORE_LIST_SECRET.contains(key) {
                        continue;
                    }

                    if let Value::String(value) = value {
                        if let Ok(value) =
                            base64::engine::general_purpose::STANDARD.decode(value.as_bytes())
                        {
                            let value = String::from_utf8(value).unwrap_or_else(|_| {
                                panic!("Failed to decode base64 {}", key);
                            });

                            unpem(
                                &value,
                                graph,
                                allow_incomplete,
                                &Location::K8s(K8sLocation {
                                    resource_location: k8s_resource_location.clone(),
                                    yaml_location: YamlLocation {
                                        json_path: format!(".data.\"{key}\""),
                                        pem_location: PemLocationInfo {
                                            pem_bundle_index: None,
                                        },
                                    },
                                }),
                            );
                        } else {
                            dbg!("Failed to decode base64 {}", value);
                        }
                    }
                }
            }
            _ => todo!(),
        }
    }
}

fn unpem(value: &str, graph: &mut CryptoGraph, allow_incomplete: bool, location: &Location) {
    let pems = pem::parse_many(value).unwrap();
    for (i, pem) in pems.iter().enumerate() {
        let location = location.with_pem_bundle_index(i.try_into().unwrap());

        dbg!(location);

        match pem.tag() {
            "CERTIFICATE" => {
                let x509_certificate = x509_parser::parse_x509_certificate(pem.contents())
                    .unwrap()
                    .1;

                if is_self_signed(&x509_certificate) {
                    graph_root_ca(graph, &x509_certificate);
                }

                match x509_certificate.public_key().parsed().unwrap() {
                    x509_parser::public_key::PublicKey::RSA(key) => {
                        handle_cert_subject_rsa_public_key(
                            key,
                            &x509_certificate,
                            graph,
                            allow_incomplete,
                        );
                    }
                    x509_parser::public_key::PublicKey::EC(_key) => {
                        handle_cert_subject_ec_public_key();
                    }
                    _ => {
                        panic!("unknown public key type");
                    }
                }
            }
            "RSA PUBLIC KEY" => {
                // panic!("found pem raw public key");
            }
            "RSA PRIVATE KEY" => {
                let x = rsa::RsaPrivateKey::from_pkcs1_pem(&pem.to_string()).unwrap();

                let public = PublicKey::Rsa(x.to_public_key());
                let private = PrivateKey::Rsa(x.clone());

                graph.public_to_private.insert(public, private);

                dbg!("Found private key");
                // panic!("done");
                // panic!("found private key");
            }
            "PRIVATE KEY" => {
                dbg!("Non-RSA private key");
            }
            "ENTITLEMENT DATA" => {
                dbg!("Entitlement");
            }
            "EC PRIVATE KEY" => {
                dbg!("EC Private key");
            }
            "RSA SIGNATURE" => {
                dbg!("RSA Sig");
            }
            _ => {
                panic!("unknown pem tag {}", pem.tag());
            }
        }
    }
}

fn handle_cert_subject_ec_public_key() {}

fn handle_cert_subject_rsa_public_key(
    public_key: x509_parser::public_key::RSAPublicKey,
    x509_certificate: &x509_parser::prelude::X509Certificate,
    graph: &mut CryptoGraph,
    allow_incomplete: bool,
) {
    let issuer = &x509_certificate.issuer();
    if let Vacant(_entry) = graph.root_certs.entry(issuer.to_string()) {
        if !allow_incomplete {
            panic!("Encountered signed cert before encountering its root");
        }
    } else {
        graph
            .root_certs
            .get_mut(&issuer.to_string())
            .unwrap()
            .push(x509_certificate.subject().to_string());
    }

    if let Occupied(entry) = graph
        .public_to_private
        .entry(PublicKey::from_rsa(&public_key))
    {
        graph
            .cert_to_private_key
            .insert(x509_certificate.subject().to_string(), entry.get().clone());
    } else if !allow_incomplete {
        panic!(
            "Could not associate certificate subject public key with private key: {}",
            x509_certificate.subject()
        );
    }
}

fn graph_root_ca(
    graph: &mut CryptoGraph,
    x509_certificate: &x509_parser::prelude::X509Certificate,
) {
    if let Vacant(entry) = graph
        .root_certs
        .entry(x509_certificate.issuer().to_string())
    {
        entry.insert(vec![]);
    } else {
        graph
            .root_certs
            .get_mut(&x509_certificate.issuer().to_string())
            .unwrap()
            .push(x509_certificate.subject().to_string());
    }
}

fn is_self_signed(x509_certificate: &x509_parser::prelude::X509Certificate) -> bool {
    x509_certificate.verify_signature(None).is_ok()
}

fn scan_k8s_resource(value: &Value, graph: &mut CryptoGraph, allow_incomplete: bool) {
    let _path = get_resource_path(value);

    let location = K8sResourceLocation {
        namespace: value
            .as_object()
            .unwrap()
            .get("metadata")
            .unwrap()
            .get("namespace")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string(),
        kind: value
            .as_object()
            .unwrap()
            .get("kind")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string(),
        name: value
            .as_object()
            .unwrap()
            .get("metadata")
            .unwrap()
            .get("name")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string(),
    };

    match value
        .as_object()
        .unwrap()
        .get("kind")
        .unwrap()
        .as_str()
        .unwrap()
    {
        "Secret" => scan_k8s_secret(value, graph, allow_incomplete, &location),
        "ConfigMap" => scan_configmap(value, graph, allow_incomplete, &location),
        _ => (),
    }
}

fn scan_configmap(
    value: &Value,
    graph: &mut CryptoGraph,
    allow_incomplete: bool,
    k8s_resource_location: &K8sResourceLocation,
) {
    if let Some(data) = value.as_object().unwrap().get("data") {
        match data {
            Value::Object(data) => {
                for (key, value) in data.iter() {
                    if IGNORE_LIST_CONFIGMAP.contains(key) {
                        continue;
                    }
                    if let Value::String(value) = value {
                        unpem(
                            &value,
                            graph,
                            allow_incomplete,
                            &Location::K8s(K8sLocation {
                                resource_location: k8s_resource_location.clone(),
                                yaml_location: YamlLocation {
                                    json_path: format!(".data.\"{key}\""),
                                    pem_location: PemLocationInfo {
                                        pem_bundle_index: None,
                                    },
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

fn get_resource_path(value: &Value) -> std::string::String {
    if let Some(metadata) = value.as_object().unwrap().get("metadata") {
        let namespace = if let Some(namespace) = metadata.as_object().unwrap().get("namespace") {
            namespace.as_str().unwrap()
        } else {
            "cluster-scoped"
        };

        let api_version = value
            .as_object()
            .unwrap()
            .get("apiVersion")
            .unwrap()
            .as_str()
            .unwrap();

        let kind = value
            .as_object()
            .unwrap()
            .get("kind")
            .unwrap()
            .as_str()
            .unwrap();

        let name = if let Some(name) = metadata.as_object().unwrap().get("name") {
            name.as_str().unwrap()
        } else {
            "<list>"
        };

        return format!("{}/{}/{}/{}", api_version, kind, namespace, name);
    }

    panic!("no metadata found");
}
