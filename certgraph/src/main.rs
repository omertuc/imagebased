use std::{
    collections::{hash_map::Entry::Vacant, HashMap, HashSet},
    fmt::Display,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use base64::Engine as _;

use lazy_static::lazy_static;
use serde_json::Value;

use rsa::{
    pkcs1::DecodeRsaPrivateKey, signature::digest::typenum::Eq, traits::PublicKeyParts,
    RsaPrivateKey,
};
use rsa::{pkcs1::DecodeRsaPublicKey, RsaPublicKey};
use x509_parser::{num_bigint::BigUint, public_key::ECPoint};

lazy_static! {
    static ref IGNORE_LIST_CONFIGMAP: HashSet<String> = vec![
        "verifier-public-key-redhat",
        "service-account-001.pub",
        "service-account-002.pub",
        "ca-bundle.crt"
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    static ref IGNORE_LIST_SECRET: HashSet<String> = vec!["prometheus.yaml.gz"]
        .into_iter()
        .map(str::to_string)
        .collect();
}

fn main() {
    let root_dir = PathBuf::from(".");
    process_etcd_dump(root_dir.join("gathers/first"));
}

fn globvec(location: &Path, globstr: &str) -> Vec<PathBuf> {
    let mut globoptions = glob::MatchOptions::new();
    globoptions.require_literal_leading_dot = true;

    glob::glob_with(location.join(globstr).to_str().unwrap(), globoptions)
        .unwrap()
        .map(|x| x.unwrap())
        .collect::<Vec<_>>()
}

fn process_etcd_dump(etcd_dump_dir: PathBuf) {
    process_yamls(etcd_dump_dir);
}

enum Location {
    K8s(K8sLocation),
    Filesystem(PathBuf),
}

struct K8sLocation {
    namespace: String,
    kind: String,
    name: String,
}

enum PrivateKey {
    Rsa(RsaPrivateKey),
}

#[derive(Hash, Eq, PartialEq)]
enum PublicKey {
    Rsa(RsaPublicKey),
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

    // Maps root cert to a list of certificates signed by it
    root_certs: HashMap<String, Vec<String>>,
}

impl Display for CryptoGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "digraph {{")?;
        for (root_cert, signed_certs) in &self.root_certs {
            for signed_cert in signed_certs {
                writeln!(f, "  \"{}\" -> \"{}\" ", root_cert, signed_cert,)?;
            }
        }
        writeln!(f, "}}")?;
        Ok(())
    }
}

fn process_yamls(gather_dir: PathBuf) {
    let all_yaml_files = globvec(&gather_dir, "**/*.yaml");

    let mut graph = CryptoGraph {
        public_to_private: HashMap::new(),
        identity_to_public: HashMap::new(),
        ca_certs: HashSet::new(),
        root_certs: HashMap::new(),
    };

    all_yaml_files.iter().for_each(|yaml_path| {
        process_yaml(yaml_path.to_path_buf(), &mut graph);
    });

    dbg!("Again again again again ###########################");

    all_yaml_files.iter().for_each(|yaml_path| {
        process_yaml(yaml_path.to_path_buf(), &mut graph);
    });

    println!("{}", graph);
}

fn process_yaml(yaml_path: PathBuf, crypto_graph: &mut CryptoGraph) {
    let mut file = fs::File::open(yaml_path).expect("failed to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("failed to read file");
    let value: Value = serde_yaml::from_str(&contents).expect("failed to parse yaml");

    scan_resource(&value, crypto_graph);
}

fn scan_secret(value: &Value, graph: &mut CryptoGraph) {
    if let Some(data) = value.as_object().unwrap().get("data") {
        match data {
            Value::Object(data) => {
                for (key, value) in data.iter() {
                    if IGNORE_LIST_SECRET.contains(key) {
                        continue;
                    }

                    if let Value::String(value) = value {
                        if let Ok(value) = base64::engine::general_purpose::STANDARD_NO_PAD
                            .decode(value.as_bytes())
                        {
                            let value = String::from_utf8(value).unwrap();
                            println!("@@@@@@@@@@@@@@@@@ SECRET KEY {}:", key);
                            unpem(&value, graph);
                        }
                    }
                }
            }
            _ => todo!(),
        }
    }
}

fn unpem(value: &str, graph: &mut CryptoGraph) {
    let pems = pem::parse_many(value).unwrap();
    for pem in pems {
        match pem.tag() {
            "CERTIFICATE" => {
                let x509_certificate = x509_parser::parse_x509_certificate(pem.contents())
                    .unwrap()
                    .1;

                if is_self_signed(&x509_certificate) {
                    assert!(
                        x509_certificate.is_ca(),
                        "not a CA certificate but self signed?"
                    );

                    graph_root_ca(graph, &x509_certificate);
                } else {
                    match x509_certificate.public_key().parsed().unwrap() {
                        x509_parser::public_key::PublicKey::RSA(key) => {
                            handle_rsa(key, &x509_certificate, graph);
                        }
                        x509_parser::public_key::PublicKey::EC(_key) => {
                            handle_ec();
                        }
                        _ => {
                            panic!("unknown public key type");
                        }
                    }
                }
            }
            "RSA PUBLIC KEY" => {
                panic!("found pem raw public key");
            }
            "RSA PRIVATE KEY" => {
                let x = rsa::RsaPrivateKey::from_pkcs1_pem(&pem.to_string()).unwrap();
                dbg!(x.to_public_key().n().to_string());

                let public = PublicKey::Rsa(x.to_public_key());
                let private = PrivateKey::Rsa(x);

                graph.public_to_private.insert(public, private);
                // panic!("done");
                // panic!("found private key");
            }
            _ => {
                panic!("unknown pem tag {}", pem.tag());
            }
        }
    }
}

fn handle_ec() {
    // dbg!(key);
    // panic!("unknown public key type");
}

fn handle_rsa(
    key: x509_parser::public_key::RSAPublicKey,
    x509_certificate: &x509_parser::prelude::X509Certificate,
    graph: &mut CryptoGraph,
) {
    dbg!(BigUint::from_bytes_be(key.modulus).to_str_radix(10));
    let issuer = &x509_certificate.issuer();
    if let Vacant(_entry) = graph.root_certs.entry(issuer.to_string()) {
        dbg!("Encountered signed cert before encountering its root");
    } else {
        graph
            .root_certs
            .get_mut(&issuer.to_string())
            .unwrap()
            .push(x509_certificate.subject().to_string());
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

fn scan_resource(value: &Value, graph: &mut CryptoGraph) {
    let _path = get_resource_path(value);

    // dbg!(path);

    match value
        .as_object()
        .unwrap()
        .get("kind")
        .unwrap()
        .as_str()
        .unwrap()
    {
        "Secret" => scan_secret(value, graph),
        "ConfigMap" => scan_configmap(value, graph),
        _ => (),
    }
}

fn scan_configmap(value: &Value, graph: &mut CryptoGraph) {
    if let Some(data) = value.as_object().unwrap().get("data") {
        match data {
            Value::Object(data) => {
                for (key, value) in data.iter() {
                    if IGNORE_LIST_CONFIGMAP.contains(key) {
                        continue;
                    }
                    if let Value::String(value) = value {
                        println!("@@@@@@@@@@@@@@@@@ CONFIGMAP KEY {}:", key);
                        unpem(value, graph);
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
