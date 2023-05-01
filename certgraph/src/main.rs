use std::{
    collections::HashSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use base64::Engine as _;

use lazy_static::lazy_static;
use serde_json::Value;

use rsa::{pkcs1::DecodeRsaPrivateKey, traits::PublicKeyParts, RsaPrivateKey};
use rsa::{pkcs1::DecodeRsaPublicKey, RsaPublicKey};
use x509_parser::{
    num_bigint::BigUint,
    public_key::{self, PublicKey},
};

// Ignore list
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
    process_gather(root_dir.join("gathers/first"));
}

fn globvec(location: &Path, globstr: &str) -> Vec<PathBuf> {
    let mut globoptions = glob::MatchOptions::new();
    globoptions.require_literal_leading_dot = true;

    glob::glob_with(location.join(globstr).to_str().unwrap(), globoptions)
        .unwrap()
        .map(|x| x.unwrap())
        .collect::<Vec<_>>()
}

fn process_gather(mg_dir: PathBuf) {
    process_yamls(mg_dir);
}

fn process_yamls(gather_dir: PathBuf) {
    let all_yaml_files = globvec(&gather_dir, "**/*.yaml");
    all_yaml_files.into_iter().for_each(|yaml_path| {
        process_yaml(dbg!(yaml_path));
    });
}

fn process_yaml(yaml_path: PathBuf) {
    let mut file = fs::File::open(yaml_path).expect("failed to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("failed to read file");
    let value: Value = serde_yaml::from_str(&contents).expect("failed to parse yaml");

    scan_resource(&value);
    scan_all_resources_in_list(&value);
}

fn scan_all_resources_in_list(value: &Value) {
    if let Some(items) = value.as_object().unwrap().get("items") {
        if !items.is_null() {
            items.as_array().unwrap().iter().for_each(scan_resource);
        }
    }
}

fn scan_secret(value: &Value) {
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
                            unpem(&value);
                        }
                    }
                }
            }
            _ => todo!(),
        }
    }
}

fn unpem(value: &str) {
    let pems = pem::parse_many(value).unwrap();
    for pem in pems {
        match pem.tag() {
            "CERTIFICATE" => {
                match x509_parser::parse_x509_certificate(pem.contents())
                    .unwrap()
                    .1
                    .tbs_certificate
                    .public_key()
                    .parsed()
                    .unwrap()
                {
                    PublicKey::RSA(key) => {
                        dbg!(BigUint::from_bytes_be(key.modulus).to_str_radix(10));
                    }
                    PublicKey::EC(key) => {
                        dbg!(key);
                        panic!("unknown public key type");
                    }
                    _ => {
                        panic!("unknown public key type");
                    }
                }
            }
            "RSA PUBLIC KEY" => {
                let x = rsa::RsaPublicKey::from_pkcs1_pem(&pem.to_string()).unwrap();
                dbg!(x);
                // panic!("found public key");
            }
            "RSA PRIVATE KEY" => {
                let x = rsa::RsaPrivateKey::from_pkcs1_pem(&pem.to_string()).unwrap();
                dbg!(x.to_public_key().n().to_string());
                // panic!("done");
                // panic!("found private key");
            }
            _ => {
                panic!("unknown pem tag {}", pem.tag());
            }
        }
    }
}

fn scan_resource(value: &Value) {
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
        "Secret" => scan_secret(value),
        "ConfigMap" => scan_configmap(value),
        _ => (),
    }
}

fn scan_configmap(value: &Value) {
    if let Some(data) = value.as_object().unwrap().get("data") {
        match data {
            Value::Object(data) => {
                for (key, value) in data.iter() {
                    if IGNORE_LIST_CONFIGMAP.contains(key) {
                        continue;
                    }
                    if let Value::String(value) = value {
                        println!("@@@@@@@@@@@@@@@@@ CONFIGMAP KEY {}:", key);
                        unpem(value);
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
