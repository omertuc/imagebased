use base64::Engine as _;
use graph::{
    CertKeyPair, Certificate, CryptoGraph, DistributedCert, DistributedPrivateKey, PrivateKey,
    PublicKey,
};
use locations::{
    FileContentLocation, FileLocation, K8sLocation, K8sResourceLocation, Location, PemLocationInfo,
    YamlLocation,
};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rules::{EXTERNAL_CERTS, IGNORE_LIST_CONFIGMAP, KNOWN_MISSING_PRIVATE_KEY_CERTS};
use serde_json::Value;
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

mod graph;
mod json_tools;
mod locations;
mod rules;

fn main() {
    let root_dir = PathBuf::from(".");

    let mut graph = CryptoGraph {
        public_to_private: HashMap::new(),
        identity_to_public: HashMap::new(),
        ca_certs: HashSet::new(),
        root_certs: HashMap::new(),
        cert_key_pairs: HashMap::new(),
        private_keys: HashMap::new(),
        certs: HashMap::new(),
    };

    process_etcd_dump(&root_dir.join("gathers/first/etcd"), &mut graph);
    process_k8s_dir_dump(&root_dir.join("gathers/first/kubernetes"), &mut graph);
    pair_certs_and_key(&mut graph);

    for pair in graph.cert_key_pairs.values() {
        println!(
            "Cert {:03} locations, priv {:03} locations | {} ---> {}",
            pair.distributed_cert.locations.len(),
            pair.distributed_private_key.locations.len(),
            pair.distributed_cert.certificate.subject,
            pair.distributed_cert.certificate.issuer,
        );

        // for location in pair.distributed_cert.locations.iter() {
        //     println!("{:#?}", location);
        // }
        // for location in pair.distributed_private_key.locations.iter() {
        //     println!("{:#?}", location);
        // }
    }
}

fn pair_certs_and_key(graph: &mut CryptoGraph) {
    for (key, distributed_cert) in &graph.certs {
        if let Occupied(private_key) = graph
            .public_to_private
            .entry(distributed_cert.certificate.public_key.clone())
        {
            if let Occupied(distributed_private_key) =
                graph.private_keys.entry(private_key.get().clone())
            {
                graph.cert_key_pairs.insert(
                    distributed_cert.certificate.clone(),
                    CertKeyPair {
                        distributed_private_key: distributed_private_key.get().clone(),
                        distributed_cert: distributed_cert.clone(),
                    },
                );
            } else {
                panic!("Private key not found");
            }
        } else if !KNOWN_MISSING_PRIVATE_KEY_CERTS.contains(&distributed_cert.certificate.subject)
            && !EXTERNAL_CERTS.contains(&distributed_cert.certificate.subject)
        {
            match distributed_cert.certificate.public_key {
                PublicKey::Rsa(_) => {
                    for location in distributed_cert.locations.iter() {
                        println!("{:#?} {:#?}", key, location);
                    }
                    panic!("done");
                }
                PublicKey::Dummy => {}
            }
        }
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

fn process_etcd_dump(etcd_dump_dir: &Path, graph: &mut CryptoGraph) {
    process_k8s_yamls(etcd_dump_dir, graph);
}

fn process_k8s_dir_dump(k8s_dir: &Path, graph: &mut CryptoGraph) {
    // process_k8s_yamls(k8s_dir, graph, allow_incomplete);
    process_pems(k8s_dir, graph);
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

fn process_k8s_yamls(yamls_dir: &Path, graph: &mut CryptoGraph) {
    let all_yaml_files = globvec(yamls_dir, "**/*.yaml");

    all_yaml_files.iter().for_each(|yaml_path| {
        process_k8s_yaml(yaml_path.to_path_buf(), graph);
    });
}

fn process_pems(k8s_dir: &Path, graph: &mut CryptoGraph) {
    globvec(k8s_dir, "**/*.pem")
        .into_iter()
        .chain(globvec(k8s_dir, "**/*.crt").into_iter())
        .chain(globvec(k8s_dir, "**/*.key").into_iter())
        .chain(globvec(k8s_dir, "**/*.pub").into_iter())
        .for_each(|pem_path| {
            process_pem(&pem_path, graph);
        });
}

fn process_pem(pem_file_path: &PathBuf, graph: &mut CryptoGraph) {
    let mut file = fs::File::open(pem_file_path).expect("failed to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("failed to read file");
    process_pem_bundle(
        &contents,
        graph,
        &Location::Filesystem(FileLocation {
            file_path: pem_file_path.to_string_lossy().to_string(),
            content_location: FileContentLocation::Raw(PemLocationInfo {
                pem_bundle_index: None,
            }),
        }),
    );
}

fn process_k8s_yaml(yaml_path: PathBuf, crypto_graph: &mut CryptoGraph) {
    let mut file = fs::File::open(yaml_path).expect("failed to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("failed to read file");
    let value: Value = serde_yaml::from_str(&contents).expect("failed to parse yaml");

    scan_k8s_resource(&value, crypto_graph);
}

fn scan_k8s_secret(
    value: &Value,
    graph: &mut CryptoGraph,
    k8s_resource_location: &K8sResourceLocation,
) {
    if let Some(data) = value.as_object().unwrap().get("data") {
        match data {
            Value::Object(data) => {
                for (key, value) in data.iter() {
                    if rules::IGNORE_LIST_SECRET.contains(key) {
                        continue;
                    }

                    process_k8s_secret_data_entry(key, value, graph, k8s_resource_location);
                }
            }
            _ => todo!(),
        }
    }
}

fn process_k8s_secret_data_entry(
    key: &str,
    value: &Value,
    graph: &mut CryptoGraph,
    k8s_resource_location: &K8sResourceLocation,
) {
    if let Value::String(value) = value {
        if let Ok(value) = base64::engine::general_purpose::STANDARD.decode(value.as_bytes()) {
            let value = String::from_utf8(value).unwrap_or_else(|_| {
                panic!("Failed to decode base64 {}", key);
            });

            process_pem_bundle(
                &value,
                graph,
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
            panic!("Failed to decode base64 {}", value);
        }
    }
}

fn process_pem_bundle(value: &str, graph: &mut CryptoGraph, location: &Location) {
    let pems = pem::parse_many(value).unwrap();
    for (i, pem) in pems.iter().enumerate() {
        let location = location.with_pem_bundle_index(i.try_into().unwrap());

        process_single_pem(pem, graph, &location);
    }
}

fn process_single_pem(pem: &pem::Pem, graph: &mut CryptoGraph, location: &Location) {
    match pem.tag() {
        "CERTIFICATE" => {
            process_pem_cert(pem, graph, location);
        }
        "RSA PRIVATE KEY" => {
            process_pem_private_key(pem, graph, location);
        }
        "RSA PUBLIC KEY" | "PRIVATE KEY" | "ENTITLEMENT DATA" | "EC PRIVATE KEY"
        | "RSA SIGNATURE" => {
            // dbg!("TODO: Handle {} at {}", pem.tag(), location);
        }
        _ => {
            panic!("unknown pem tag {}", pem.tag());
        }
    }
}

fn process_pem_private_key(pem: &pem::Pem, graph: &mut CryptoGraph, location: &Location) {
    let rsa_private_key = rsa::RsaPrivateKey::from_pkcs1_pem(&pem.to_string()).unwrap();

    let public_part = PublicKey::Rsa(rsa_private_key.to_public_key());
    let private_part = PrivateKey::Rsa(rsa_private_key);

    register_private_key_public_key_mapping(graph, public_part, &private_part);
    register_private_key(graph, private_part, location);
}

fn register_private_key_public_key_mapping(
    graph: &mut CryptoGraph,
    public_part: PublicKey,
    private_part: &PrivateKey,
) {
    graph
        .public_to_private
        .insert(public_part, private_part.clone());
}

fn register_private_key(graph: &mut CryptoGraph, private_part: PrivateKey, location: &Location) {
    match graph.private_keys.entry(private_part.clone()) {
        Vacant(distributed_private_key) => {
            distributed_private_key.insert(DistributedPrivateKey {
                private_key: private_part,
                locations: vec![location.clone()].into_iter().collect(),
            });
        }
        Occupied(entry) => {
            entry.into_mut().locations.insert(location.clone());
        }
    }
}

fn process_pem_cert(pem: &pem::Pem, graph: &mut CryptoGraph, location: &Location) {
    register_cert(
        graph,
        &x509_parser::parse_x509_certificate(pem.contents())
            .unwrap()
            .1,
        location,
    );
}

fn register_cert(
    graph: &mut CryptoGraph,
    x509_certificate: &x509_parser::prelude::X509Certificate,
    location: &Location,
) {
    let hashable_cert = Certificate::from(x509_certificate.clone());
    match graph.certs.entry(hashable_cert.clone()) {
        Vacant(distributed_cert) => {
            distributed_cert.insert(DistributedCert {
                certificate: hashable_cert,
                locations: vec![location.clone()].into_iter().collect(),
            });
        }
        Occupied(distributed_cert) => {
            distributed_cert
                .into_mut()
                .locations
                .insert(location.clone());
        }
    }
}

fn scan_k8s_resource(value: &Value, graph: &mut CryptoGraph) {
    let _path = get_resource_path(value);

    let location = K8sResourceLocation {
        namespace: json_tools::read_metadata_string_field(value, "namespace"),
        kind: json_tools::read_string_field(value, "kind"),
        name: json_tools::read_metadata_string_field(value, "name"),
    };

    match location.kind.as_str() {
        "Secret" => scan_k8s_secret(value, graph, &location),
        "ConfigMap" => scan_configmap(value, graph, &location),
        _ => (),
    }
}

fn scan_configmap(
    value: &Value,
    graph: &mut CryptoGraph,
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
                        process_pem_bundle(
                            value,
                            graph,
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

        let api_version = json_tools::read_string_field(value, "apiVersion");
        let kind = json_tools::read_string_field(value, "kind");

        let name = if let Some(name) = metadata.as_object().unwrap().get("name") {
            name.as_str().unwrap()
        } else {
            "<list>"
        };

        return format!("{}/{}/{}/{}", api_version, kind, namespace, name);
    }

    panic!("no metadata found");
}
