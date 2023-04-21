use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use serde_json::Value;

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
    process_yamls(get_internal_gather_dir(&mg_dir));
}

fn process_yamls(gather_dir: PathBuf) {
    let all_yaml_files = globvec(&gather_dir, "**/*.yaml");
    all_yaml_files.into_iter().for_each(|yaml_path| {
        process_yaml(yaml_path);
    });
}

fn process_yaml(yaml_path: PathBuf) {
    let mut file = fs::File::open(yaml_path).expect("failed to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("failed to read file");
    let mut value: Value = serde_yaml::from_str(&contents).expect("failed to parse yaml");

    scan_resource(&mut value);
    scan_all_resources_in_list(&mut value);
}

fn scan_all_resources_in_list(value: &mut Value) {
    if let Some(items) = value.as_object_mut().unwrap().get_mut("items") {
        if !items.is_null() {
            items
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .for_each(scan_resource);
        }
    }
}

fn get_internal_gather_dir(normalized_gather: &Path) -> PathBuf {
    let mg_image_dir = globvec(normalized_gather, "quay-io*").pop().unwrap();
    fs::rename(mg_image_dir, normalized_gather.join("gather")).expect("failed to rename");
    normalized_gather.join("gather")
}

fn scan_resource(value: &mut Value) {
    if let Some(data) = value.as_object_mut().unwrap().get_mut("data") {
        match data {
            Value::Null => todo!(),
            Value::Bool(_) => todo!(),
            Value::Number(_) => todo!(),
            Value::String(_) => todo!(),
            Value::Array(_) => todo!(),
            Value::Object(data) => {
                dbg!(data);
            },
        }
    }
}
