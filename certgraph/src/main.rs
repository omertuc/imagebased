use base64::Engine as _;
use etcd_client::{Client, GetOptions};
use graph::{
    CertKeyPair, Certificate, CryptoGraph, DistributedCert, DistributedPrivateKey, Locations,
    PrivateKey, PublicKey,
};
use locations::{
    FileContentLocation, FileLocation, K8sLocation, K8sResourceLocation, Location, PemLocationInfo,
    YamlLocation,
};
use pkcs1::EncodeRsaPublicKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rules::{IGNORE_LIST_CONFIGMAP, KNOWN_MISSING_PRIVATE_KEY_CERTS};
use serde_json::Value;
use std::collections::{
    hash_map::Entry::{Occupied, Vacant},
    HashMap,
};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

mod graph;
mod json_tools;
mod k8s_etcd;
mod locations;
mod rules;

#[tokio::main]
async fn main() -> Result<(), ()> {
    let root_dir = PathBuf::from(".");

    let mut graph = CryptoGraph {
        public_to_private: HashMap::new(),
        root_certs: HashMap::new(),
        cert_key_pairs: Vec::new(),
        private_keys: HashMap::new(),
        certs: HashMap::new(),
    };
    let mut client = Client::connect(["localhost:2379"], None).await.unwrap();

    println!("Reading etcd...");
    process_etcd(&mut client, &mut graph).await;
    println!("Reading kubernetes dir...");
    process_k8s_dir_dump(&root_dir.join("gathers/first/kubernetes"), &mut graph);
    println!("Pairing certs and keys...");
    pair_certs_and_key(&mut graph);
    println!("Creating graph relationships...");
    create_graph(&mut graph);
    println!("Regenerating certs...");
    regenerate(&mut graph);
    println!("Committing changes...");
    commit(&mut client, &mut graph).await;

    for pair in graph.cert_key_pairs {
        if pair.signer.as_ref().is_none() {
            println!("{}", pair);
        }
    }

    Ok(())
}

async fn commit(client: &mut Client, graph: &mut CryptoGraph) {
    let mut pairs = graph.cert_key_pairs.clone();

    for pair in &mut pairs {
        if pair.signer.is_some() {
            continue;
        }

        pair.commit(client).await;
    }

    graph.cert_key_pairs = pairs;
}

fn regenerate(graph: &mut CryptoGraph) {
    let mut pairs = graph.cert_key_pairs.clone();

    for pair in &mut pairs {
        if pair.signer.is_some() {
            continue;
        }

        pair.regenerate()
    }

    graph.cert_key_pairs = pairs;
}

fn create_graph(graph: &mut CryptoGraph) {
    let mut pairs = graph.cert_key_pairs.clone();
    let pairs_copy = pairs.clone();

    for pair in &mut pairs {
        if pair.signer.is_some() {
            continue;
        }

        fill_signees(pair, pairs_copy.clone());
    }

    graph.cert_key_pairs = pairs;
}

fn fill_signees(pair: &mut CertKeyPair, pairs: Vec<CertKeyPair>) {
    let mut signees = Vec::new();
    let pairs_copy = pairs.clone();
    for potential_signee in &mut pairs.clone() {
        if let Some(potential_signee_signer) = &potential_signee.signer.as_ref() {
            if potential_signee_signer.original == pair.distributed_cert.certificate.original {
                fill_signees(potential_signee, pairs_copy.clone());
                signees.push(potential_signee.clone());
            }
        }
    }
    pair.signees = signees;
}

fn pair_certs_and_key(graph: &mut CryptoGraph) {
    for (_hashable_cert, distributed_cert) in &graph.certs {
        let mut true_signing_cert: Option<Certificate> = None;
        if !distributed_cert.certificate.original.subject_is_issuer() {
            for potential_signing_cert in graph.certs.values() {
                if distributed_cert
                    .certificate
                    .original
                    .verify_signed_by_certificate(&potential_signing_cert.certificate.original)
                    .is_ok()
                {
                    true_signing_cert = Some(potential_signing_cert.certificate.clone())
                }
            }

            if true_signing_cert.is_none() {
                panic!("No signing cert found");
            }
        }

        let mut pair = CertKeyPair {
            distributed_private_key: None,
            distributed_cert: distributed_cert.clone(),
            signer: Box::new(true_signing_cert),
            signees: Vec::new(),
        };

        if let Occupied(private_key) = graph
            .public_to_private
            .entry(distributed_cert.certificate.public_key.clone())
        {
            if let Occupied(distributed_private_key) =
                graph.private_keys.entry(private_key.get().clone())
            {
                pair.distributed_private_key = Some(distributed_private_key.get().clone());
            } else {
                panic!("Private key not found");
            }
        } else if KNOWN_MISSING_PRIVATE_KEY_CERTS.contains(&distributed_cert.certificate.subject) {
            println!(
                "Known no public key for {}",
                &distributed_cert.certificate.subject
            );
        } else {
            panic!("Public key not found for key not in KNOWN_MISSING_PRIVATE_KEY_CERTS, cannot continue, {}", &distributed_cert.certificate.subject);
        }

        graph.cert_key_pairs.push(pair);
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

async fn process_etcd(client: &mut Client, graph: &mut CryptoGraph) {
    let get_options = GetOptions::new()
        .with_prefix()
        .with_limit(0)
        .with_keys_only();

    let secret_keys = client
        .get("/kubernetes.io/secrets", Some(get_options.clone()))
        .await
        .expect("Couldn't get secrets list, is etcd down?");

    let configmap_keys = client
        .get("/kubernetes.io/configmaps", Some(get_options))
        .await
        .expect("Couldn't get configmaps list, is etcd down?");

    for key in configmap_keys.kvs() {
        process_etcd_key(client, key, graph).await;
    }

    for key in secret_keys.kvs() {
        process_etcd_key(client, key, graph).await;
    }

    // all_yaml_files.iter().for_each(|yaml_path| {
    //     process_k8s_etcd_key(yaml_path.to_path_buf(), graph);
    // });
}

async fn process_etcd_key(
    client: &mut Client,
    key: &etcd_client::KeyValue,
    graph: &mut CryptoGraph,
) {
    let contents = k8s_etcd::etcd_get(client, key.key_str().unwrap()).await;
    let value: Value = serde_yaml::from_slice(contents.as_slice()).expect("failed to parse yaml");
    let value = &value;
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

fn process_k8s_dir_dump(k8s_dir: &Path, graph: &mut CryptoGraph) {
    // process_k8s_yamls(k8s_dir, graph, allow_incomplete);
    process_pems(k8s_dir, graph);
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
    if let Value::String(string_value) = value {
        if let Ok(value) = base64::engine::general_purpose::STANDARD.decode(string_value.as_bytes())
        {
            let value = String::from_utf8(value).unwrap_or_else(|_| {
                panic!("Failed to decode base64 {}", key);
            });

            process_pem_bundle(
                &value,
                graph,
                &Location::K8s(K8sLocation {
                    resource_location: k8s_resource_location.clone(),
                    yaml_location: YamlLocation {
                        json_pointer: format!("/data/{key}"),
                        pem_location: PemLocationInfo {
                            pem_bundle_index: None,
                        },
                    },
                }),
            );
        } else {
            panic!("Failed to decode base64 {}", string_value);
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
        "EC PRIVATE KEY" => {
            println!("Found EC key at {}", location);
        }
        "RSA PUBLIC KEY" | "PRIVATE KEY" | "ENTITLEMENT DATA" | "RSA SIGNATURE" => {
            // dbg!("TODO: Handle {} at {}", pem.tag(), location);
        }
        _ => {
            panic!("unknown pem tag {}", pem.tag());
        }
    }
}

fn process_pem_private_key(pem: &pem::Pem, graph: &mut CryptoGraph, location: &Location) {
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
                locations: Locations(vec![location.clone()].into_iter().collect()),
                key: private_part,
            });
        }
        Occupied(entry) => {
            entry.into_mut().locations.0.insert(location.clone());
        }
    }
}

fn process_pem_cert(pem: &pem::Pem, graph: &mut CryptoGraph, location: &Location) {
    register_cert(
        graph,
        &x509_certificate::CapturedX509Certificate::from_der(pem.contents()).unwrap(),
        location,
    );
}

fn register_cert(
    graph: &mut CryptoGraph,
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

    match graph.certs.entry(hashable_cert.clone()) {
        Vacant(distributed_cert) => {
            distributed_cert.insert(DistributedCert {
                certificate: hashable_cert,
                locations: Locations(vec![location.clone()].into_iter().collect()),
            });
        }
        Occupied(distributed_cert) => {
            distributed_cert
                .into_mut()
                .locations
                .0
                .insert(location.clone());
        }
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
                                    json_pointer: format!("/data/{key}"),
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
