use base64::Engine as _;
use cluster_crypto::{
    CertKeyPair, Certificate, ClusterCryptoObjects, DistributedCert, DistributedPrivateKey,
    Locations, PrivateKey, PublicKey,
};
use etcd_client::Client as EtcdClient;
use k8s_etcd::etcd_list_keys;
use locations::{
    FileContentLocation, FileLocation, K8sLocation, K8sResourceLocation, Location, PemLocationInfo,
    YamlLocation,
};
use pkcs1::EncodeRsaPublicKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rules::{IGNORE_LIST_CONFIGMAP, KNOWN_MISSING_PRIVATE_KEY_CERTS};
use serde_json::Value;
use std::{
    cell::RefCell,
    collections::hash_map::Entry::{Occupied, Vacant},
    rc::Rc,
};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

mod cluster_crypto;
mod file_utils;
mod json_tools;
mod k8s_etcd;
mod locations;
mod progress;
mod rules;

#[tokio::main]
async fn main() -> Result<(), ()> {
    let cluster_crypto = ClusterCryptoObjects::new();
    let etcd_client = EtcdClient::connect(["localhost:2379"], None).await.unwrap();
    let static_resource_dir = &PathBuf::from(".").join("kubernetes");

    recertify(etcd_client, cluster_crypto, static_resource_dir).await;

    Ok(())
}

async fn recertify(
    mut etcd_client: EtcdClient,
    mut cluster_crypto: ClusterCryptoObjects,
    static_resource_dir: &PathBuf,
) {
    println!("Reading etcd...");
    process_etcd_resources(&mut etcd_client, &mut cluster_crypto).await;

    println!("Reading kubernetes dir...");
    process_k8s_static_resources(static_resource_dir, &mut cluster_crypto);

    println!("Pairing certs and keys...");
    pair_certs_and_key(&mut cluster_crypto);

    println!("Creating graph relationships...");
    fill_signees(&mut cluster_crypto);

    println!("Regenerating certs...");
    regenerate_certificates_and_keys(&mut cluster_crypto);

    println!("Committing changes...");
    commit_to_etcd_and_disk(&mut etcd_client, &mut cluster_crypto).await;

    println!("Crypto graph...");
    cluster_crypto.display();
}

async fn commit_to_etcd_and_disk(
    client: &mut EtcdClient,
    cluster_crypto: &mut ClusterCryptoObjects,
) {
    let mut cert_key_pairs = cluster_crypto.cert_key_pairs.clone();

    let progress =
        progress::create_progress_bar("Committing key/cert pairs...", cert_key_pairs.len());
    for pair in &mut cert_key_pairs {
        (*pair).borrow().commit(client).await;
        progress.inc(1);
    }

    cluster_crypto.cert_key_pairs = cert_key_pairs;
}

fn regenerate_certificates_and_keys(cluster_crypto: &mut ClusterCryptoObjects) {
    for cert_key_pair in &cluster_crypto.cert_key_pairs {
        if (**cert_key_pair).borrow().signer.is_some() {
            continue;
        }

        (**cert_key_pair).borrow_mut().regenerate(None)
    }
}

fn fill_signees(cluster_crypto: &mut ClusterCryptoObjects) {
    for cert_key_pair in &cluster_crypto.cert_key_pairs {
        for potential_signee in &cluster_crypto.cert_key_pairs {
            if let Some(potential_signee_signer) = &(**potential_signee).borrow().signer {
                if (*potential_signee_signer).borrow().certificate.original
                    == (*(*cert_key_pair).borrow().distributed_cert)
                        .borrow()
                        .certificate
                        .original
                {
                    (**cert_key_pair)
                        .borrow_mut()
                        .signees
                        .push(Rc::clone(&potential_signee));
                }
            }
        }
    }
}

fn pair_certs_and_key(cluster_crypto: &mut ClusterCryptoObjects) {
    for (_hashable_cert, distributed_cert) in &cluster_crypto.certs {
        let mut true_signing_cert: Option<Rc<RefCell<DistributedCert>>> = None;
        if !(*distributed_cert)
            .borrow()
            .certificate
            .original
            .subject_is_issuer()
        {
            for potential_signing_cert in cluster_crypto.certs.values() {
                if (*distributed_cert)
                    .borrow()
                    .certificate
                    .original
                    .verify_signed_by_certificate(
                        &(*potential_signing_cert).borrow().certificate.original,
                    )
                    .is_ok()
                {
                    true_signing_cert = Some(Rc::clone(potential_signing_cert))
                }
            }

            if true_signing_cert.is_none() {
                println!(
                    "No signing cert found for {}",
                    (*distributed_cert).borrow().locations
                );
                panic!("No signing cert found");
            }
        }

        let pair = Rc::new(RefCell::new(CertKeyPair {
            distributed_private_key: None,
            distributed_cert: Rc::clone(distributed_cert),
            signer: true_signing_cert,
            signees: Vec::new(),
        }));

        if let Occupied(private_key) = cluster_crypto
            .public_to_private
            .entry((*distributed_cert).borrow().certificate.public_key.clone())
        {
            if let Occupied(distributed_private_key) =
                cluster_crypto.private_keys.entry(private_key.get().clone())
            {
                (*pair).borrow_mut().distributed_private_key =
                    Some(distributed_private_key.get().clone());
            } else {
                panic!("Private key not found");
            }
        } else if KNOWN_MISSING_PRIVATE_KEY_CERTS
            .contains(&(*distributed_cert).borrow().certificate.subject)
        {
            println!(
                "Known no public key for {}",
                (*distributed_cert).borrow().certificate.subject
            );
        } else {
            panic!(
                "Public key not found for key not in KNOWN_MISSING_PRIVATE_KEY_CERTS, cannot continue, {}",
                (*distributed_cert).borrow().certificate.subject
            );
        }

        cluster_crypto.cert_key_pairs.push(pair);
    }
}

/// Read all relevant resources from etcd and register them in the cluster_crypto object
async fn process_etcd_resources(
    client: &mut EtcdClient,
    cluster_crypto: &mut ClusterCryptoObjects,
) {
    let key_lists = [
        &(etcd_list_keys(client, "secrets").await),
        &(etcd_list_keys(client, "configmaps").await),
    ];

    let total_keys = key_lists
        .into_iter()
        .map(|x| x.kvs().into_iter().len())
        .sum();

    let chain = key_lists
        .into_iter()
        .map(|x| x.kvs().into_iter())
        .flatten()
        .map(|x| x.key_str().unwrap());

    let progress = progress::create_progress_bar("Processing etcd resources", total_keys);
    for key in chain {
        process_etcd_key(client, key, cluster_crypto).await;
        progress.inc(1);
    }
}

async fn process_etcd_key(
    client: &mut EtcdClient,
    key: &str,
    cluster_crypto: &mut ClusterCryptoObjects,
) {
    let contents = k8s_etcd::etcd_get(client, key).await;
    let value: Value = serde_yaml::from_slice(contents.as_slice()).expect("failed to parse yaml");
    let value = &value;
    let location = K8sResourceLocation {
        namespace: json_tools::read_metadata_string_field(value, "namespace"),
        kind: json_tools::read_string_field(value, "kind"),
        name: json_tools::read_metadata_string_field(value, "name"),
    };
    match location.kind.as_str() {
        "Secret" => scan_k8s_secret(value, cluster_crypto, &location),
        "ConfigMap" => scan_configmap(value, cluster_crypto, &location),
        _ => (),
    }
}

fn process_k8s_static_resources(k8s_dir: &Path, cluster_crypto: &mut ClusterCryptoObjects) {
    process_pems(k8s_dir, cluster_crypto);
}

fn process_pems(k8s_dir: &Path, cluster_crypto: &mut ClusterCryptoObjects) {
    file_utils::globvec(k8s_dir, "**/*.pem")
        .into_iter()
        .chain(file_utils::globvec(k8s_dir, "**/*.crt").into_iter())
        .chain(file_utils::globvec(k8s_dir, "**/*.key").into_iter())
        .chain(file_utils::globvec(k8s_dir, "**/*.pub").into_iter())
        .for_each(|pem_path| {
            process_pem(&pem_path, cluster_crypto);
        });
}

fn process_pem(pem_file_path: &PathBuf, cluster_crypto: &mut ClusterCryptoObjects) {
    let mut file = fs::File::open(pem_file_path).expect("failed to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("failed to read file");
    process_pem_bundle(
        &contents,
        cluster_crypto,
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
    cluster_crypto: &mut ClusterCryptoObjects,
    k8s_resource_location: &K8sResourceLocation,
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
                        cluster_crypto,
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
    cluster_crypto: &mut ClusterCryptoObjects,
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
                cluster_crypto,
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

fn process_pem_bundle(value: &str, cluster_crypto: &mut ClusterCryptoObjects, location: &Location) {
    let pems = pem::parse_many(value).unwrap();

    for (i, pem) in pems.iter().enumerate() {
        let location = location.with_pem_bundle_index(i.try_into().unwrap());

        process_single_pem(pem, cluster_crypto, &location);
    }
}

fn process_single_pem(
    pem: &pem::Pem,
    cluster_crypto: &mut ClusterCryptoObjects,
    location: &Location,
) {
    match pem.tag() {
        "CERTIFICATE" => {
            process_pem_cert(pem, cluster_crypto, location);
        }
        "RSA PRIVATE KEY" => {
            process_pem_private_key(pem, cluster_crypto, location);
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

fn process_pem_private_key(
    pem: &pem::Pem,
    cluster_crypto: &mut ClusterCryptoObjects,
    location: &Location,
) {
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

    register_private_key_public_key_mapping(cluster_crypto, public_part, &private_part);
    register_private_key(cluster_crypto, private_part, location);
}

fn register_private_key_public_key_mapping(
    cluster_crypto: &mut ClusterCryptoObjects,
    public_part: PublicKey,
    private_part: &PrivateKey,
) {
    cluster_crypto
        .public_to_private
        .insert(public_part, private_part.clone());
}

fn register_private_key(
    cluster_crypto: &mut ClusterCryptoObjects,
    private_part: PrivateKey,
    location: &Location,
) {
    match cluster_crypto.private_keys.entry(private_part.clone()) {
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

fn process_pem_cert(
    pem: &pem::Pem,
    cluster_crypto: &mut ClusterCryptoObjects,
    location: &Location,
) {
    register_cert(
        cluster_crypto,
        &x509_certificate::CapturedX509Certificate::from_der(pem.contents()).unwrap(),
        location,
    );
}

fn register_cert(
    cluster_crypto: &mut ClusterCryptoObjects,
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

    match cluster_crypto.certs.entry(hashable_cert.clone()) {
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

fn scan_configmap(
    value: &Value,
    cluster_crypto: &mut ClusterCryptoObjects,
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
                            cluster_crypto,
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
