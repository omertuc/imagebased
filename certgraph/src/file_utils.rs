use crate::cluster_crypto::{
    locations::{FileLocation, LocationValueType, YamlLocation},
    pem_utils,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;

pub(crate) fn globvec(location: &Path, globstr: &str) -> Vec<PathBuf> {
    let mut globoptions = glob::MatchOptions::new();
    globoptions.require_literal_leading_dot = true;

    glob::glob_with(location.join(globstr).to_str().unwrap(), globoptions)
        .unwrap()
        .map(|x| x.unwrap())
        .filter(|x| !x.is_symlink())
        .collect::<Vec<_>>()
}

pub(crate) async fn read_file_to_string(file_path: PathBuf) -> String {
    let mut file = tokio::fs::File::open(file_path.clone())
        .await
        .expect(format!("failed to open file {:?}", file_path).as_str());
    let mut contents = String::new();
    file.read_to_string(&mut contents).await.expect("failed to read file");
    contents
}

pub(crate) async fn get_filesystem_yaml(file_location: &FileLocation) -> Value {
    serde_yaml::from_str(read_file_to_string(file_location.file_path.clone().into()).await.as_str()).expect("failed to parse yaml")
}

pub(crate) fn recreate_yaml_at_location_with_new_pem(mut resource: Value, yaml_location: &YamlLocation, new_pem: &pem::Pem) -> String {
    match resource.pointer_mut(&yaml_location.json_pointer) {
        Some(value_at_json_pointer) => {
            if let Value::String(value_at_json_pointer) = value_at_json_pointer {
                let decoded = decode_resource_data_entry(yaml_location, value_at_json_pointer);

                match &yaml_location.value {
                    LocationValueType::Pem(pem_location_info) => {
                        let newbundle = pem_utils::pem_bundle_replace_pem_at_index(decoded, pem_location_info.pem_bundle_index, &new_pem);
                        let encoded = encode_resource_data_entry(&yaml_location, &newbundle);
                        *value_at_json_pointer = encoded;
                    }
                    _ => {
                        panic!("shouldn't happen");
                    }
                }
            }
        }
        None => {
            panic!("shouldn't happen {} {:#?}", resource.to_string(), yaml_location);
        }
    }
    let newcontents = serde_yaml::to_string(&resource).unwrap();
    newcontents
}

pub(crate) fn encode_resource_data_entry(k8slocation: &YamlLocation, value: &String) -> String {
    if k8slocation.base64_encoded {
        STANDARD.encode(value.as_bytes())
    } else {
        value.to_string()
    }
}

pub(crate) fn decode_resource_data_entry(yaml_location: &YamlLocation, value_at_json_pointer: &mut String) -> String {
    let decoded = if yaml_location.base64_encoded {
        String::from_utf8_lossy(STANDARD.decode(value_at_json_pointer.as_bytes()).unwrap().as_slice()).to_string()
    } else {
        value_at_json_pointer.to_string()
    }
    .clone();
    decoded
}
