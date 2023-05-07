use std::{
    collections::{
        hash_map::Entry::{Occupied, Vacant},
        HashMap, HashSet,
    },
    fmt::Display,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use base64::Engine as _;

use serde_json::Value;

use rsa::pkcs1::DecodeRsaPrivateKey;

mod graph;
mod locations;
mod rules;

fn main() {
    let root_dir = PathBuf::from(".");

    let mut graph = graph::CryptoGraph {
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

fn process_etcd_dump(
    etcd_dump_dir: &Path,
    graph: &mut graph::CryptoGraph,
    allow_incomplete: bool,
) {
    process_k8s_yamls(etcd_dump_dir, graph, allow_incomplete);
}

fn process_k8s_dir_dump(k8s_dir: &Path, graph: &mut graph::CryptoGraph, allow_incomplete: bool) {
    // process_k8s_yamls(k8s_dir, graph, allow_incomplete);
    process_pems(k8s_dir, graph, allow_incomplete);
}

impl Display for graph::CryptoGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (root_cert, signed_certs) in &self.root_certs {
            for signed_cert in signed_certs {
                writeln!(f, "  \"{}\" -> \"{}\" ", root_cert, signed_cert,)?;
            }
        }
        Ok(())
    }
}

fn process_k8s_yamls(gather_dir: &Path, graph: &mut graph::CryptoGraph, allow_incomplete: bool) {
    let all_yaml_files = globvec(gather_dir, "**/*.yaml");

    all_yaml_files.iter().for_each(|yaml_path| {
        process_k8s_yaml(yaml_path.to_path_buf(), graph, allow_incomplete);
    });
}

fn process_pems(gather_dir: &Path, graph: &mut graph::CryptoGraph, allow_incomplete: bool) {
    globvec(gather_dir, "**/*.pem")
        .into_iter()
        .chain(globvec(gather_dir, "**/*.crt").into_iter())
        .chain(globvec(gather_dir, "**/*.key").into_iter())
        .chain(globvec(gather_dir, "**/*.pub").into_iter())
        .for_each(|pem_path| {
            process_pem(&pem_path, graph, allow_incomplete);
        });
}

fn process_pem(pem_file_path: &PathBuf, graph: &mut graph::CryptoGraph, allow_incomplete: bool) {
    let mut file = fs::File::open(pem_file_path).expect("failed to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("failed to read file");
    unpem(
        &contents,
        graph,
        allow_incomplete,
        &locations::Location::Filesystem(locations::FileLocation::Raw(
            locations::PemLocationInfo {
                pem_bundle_index: None,
            },
        )),
    );
}

fn process_k8s_yaml(
    yaml_path: PathBuf,
    crypto_graph: &mut graph::CryptoGraph,
    allow_incomplete: bool,
) {
    let mut file = fs::File::open(yaml_path).expect("failed to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("failed to read file");
    let value: Value = serde_yaml::from_str(&contents).expect("failed to parse yaml");

    scan_k8s_resource(&value, crypto_graph, allow_incomplete);
}

fn scan_k8s_secret(
    value: &Value,
    graph: &mut graph::CryptoGraph,
    allow_incomplete: bool,
    k8s_resource_location: &locations::K8sResourceLocation,
) {
    if let Some(data) = value.as_object().unwrap().get("data") {
        match data {
            Value::Object(data) => {
                for (key, value) in data.iter() {
                    if rules::IGNORE_LIST_SECRET.contains(key) {
                        continue;
                    }

                    process_k8s_secret_data_entry(
                        key,
                        value,
                        graph,
                        allow_incomplete,
                        k8s_resource_location,
                    );
                }
            }
            _ => todo!(),
        }
    }
}

fn process_k8s_secret_data_entry(
    key: &str,
    value: &Value,
    graph: &mut graph::CryptoGraph,
    allow_incomplete: bool,
    k8s_resource_location: &locations::K8sResourceLocation,
) {
    if let Value::String(value) = value {
        if let Ok(value) = base64::engine::general_purpose::STANDARD.decode(value.as_bytes()) {
            let value = String::from_utf8(value).unwrap_or_else(|_| {
                panic!("Failed to decode base64 {}", key);
            });

            unpem(
                &value,
                graph,
                allow_incomplete,
                &locations::Location::K8s(locations::K8sLocation {
                    resource_location: k8s_resource_location.clone(),
                    yaml_location: locations::YamlLocation {
                        json_path: format!(".data.\"{key}\""),
                        pem_location: locations::PemLocationInfo {
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

fn unpem(
    value: &str,
    graph: &mut graph::CryptoGraph,
    allow_incomplete: bool,
    location: &locations::Location,
) {
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

                let public = graph::PublicKey::Rsa(x.to_public_key());
                let private = graph::PrivateKey::Rsa(x.clone());

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
    graph: &mut graph::CryptoGraph,
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
        .entry(graph::PublicKey::from_rsa(&public_key))
    {
        graph
            .cert_to_private_key
            .insert(x509_certificate.subject().to_string(), entry.get().clone());
    } else if !allow_incomplete
        && !rules::KNOWN_MISSING_PRIVATE_KEY_CERTS.contains(&x509_certificate.subject().to_string())
        && !rules::EXTERNAL_CERTS.contains(&x509_certificate.subject().to_string())
    {
        panic!(
            "Could not find private key for certificate subject public key: {}",
            x509_certificate.subject()
        );
    }
}

fn graph_root_ca(
    graph: &mut graph::CryptoGraph,
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

fn scan_k8s_resource(value: &Value, graph: &mut graph::CryptoGraph, allow_incomplete: bool) {
    let _path = get_resource_path(value);

    let location = locations::K8sResourceLocation {
        namespace: read_metadata_string_field(value, "namespace"),
        kind: read_string_field(value, "kind"),
        name: read_metadata_string_field(value, "name"),
    };

    match location.kind.as_str() {
        "Secret" => scan_k8s_secret(value, graph, allow_incomplete, &location),
        "ConfigMap" => scan_configmap(value, graph, allow_incomplete, &location),
        _ => (),
    }
}

fn scan_configmap(
    value: &Value,
    graph: &mut graph::CryptoGraph,
    allow_incomplete: bool,
    k8s_resource_location: &locations::K8sResourceLocation,
) {
    if let Some(data) = value.as_object().unwrap().get("data") {
        match data {
            Value::Object(data) => {
                for (key, value) in data.iter() {
                    if rules::IGNORE_LIST_CONFIGMAP.contains(key) {
                        continue;
                    }
                    if let Value::String(value) = value {
                        unpem(
                            value,
                            graph,
                            allow_incomplete,
                            &locations::Location::K8s(locations::K8sLocation {
                                resource_location: k8s_resource_location.clone(),
                                yaml_location: locations::YamlLocation {
                                    json_path: format!(".data.\"{key}\""),
                                    pem_location: locations::PemLocationInfo {
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

        let api_version = read_string_field(value, "apiVersion");
        let kind = read_string_field(value, "kind");

        let name = if let Some(name) = metadata.as_object().unwrap().get("name") {
            name.as_str().unwrap()
        } else {
            "<list>"
        };

        return format!("{}/{}/{}/{}", api_version, kind, namespace, name);
    }

    panic!("no metadata found");
}

fn read_string_field(value: &Value, field: &str) -> String {
    value
        .as_object()
        .unwrap()
        .get(field)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

fn read_metadata_string_field(value: &Value, field: &str) -> String {
    read_string_field(value.as_object().unwrap().get("metadata").unwrap(), field)
}
