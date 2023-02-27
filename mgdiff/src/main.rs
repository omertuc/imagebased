use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::Value;

fn main() {
    let root_dir = PathBuf::from(".");
    let normalized_dir = root_dir.join("normalized");
    recreate_dir(&normalized_dir);

    let process_gather = |mg_dir| process_gather(&normalized_dir, mg_dir);
    let gathers = globvec(&root_dir, "gathers/*");

    if gathers.is_empty() {
        println!("No gathers found");
        return;
    }

    for gather in gathers {
        process_gather(gather);
    }
}

fn globvec(location: &Path, globstr: &str) -> Vec<PathBuf> {
    glob::glob(location.join(globstr).to_str().unwrap())
        .unwrap()
        .into_iter()
        .map(|x| x.unwrap())
        .collect::<Vec<_>>()
}

fn recreate_dir(normalized_dir: &PathBuf) {
    match fs::remove_dir_all(normalized_dir) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        r => r.expect("failed to remove repo dir"),
    }
    fs::create_dir(normalized_dir).expect("failed to create dir");
}

fn process_gather(normalized_dir: &Path, mg_dir: PathBuf) {
    let normalized_gather = normalized_dir.join(mg_dir.file_name().unwrap());
    duplicate_must_gather(mg_dir, &normalized_gather);
    let gather_dir = get_internal_gather_dir(&normalized_gather);
    cleanup_gather(&gather_dir, normalized_gather);
    process_yamls(gather_dir);
}

fn process_yamls(gather_dir: PathBuf) {
    let all_yaml_files = globvec(&gather_dir, "**/*.yaml");
    all_yaml_files.into_iter().for_each(|yaml_path| {
        process_yaml(yaml_path);
    });
}

fn process_yaml(yaml_path: PathBuf) {
    let mut file = fs::File::open(&yaml_path).expect("failed to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("failed to read file");
    let mut value: Value = serde_yaml::from_str(&contents).expect("failed to parse yaml");
    fix_resource(&mut value);
    if let Some(items) = value.as_object_mut().unwrap().get_mut("items") {
        if !items.is_null() {
            items
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .for_each(fix_resource);
        }
    }
    let mut file = fs::File::create(&yaml_path).expect("failed to open file");
    file.write_all(serde_yaml::to_string(&value).unwrap().as_bytes())
        .expect("failed to write file");
}

fn cleanup_gather(gather_dir: &Path, normalized_gather: PathBuf) {
    (vec![
        "etcd_info",
        "host_service_logs",
        "ingress_controllers",
        "insights-data",
        "monitoring",
        "network_logs",
        "pod_network_connectivity_check",
        "static-pods",
        "web_hooks",
    ])
    .into_iter()
    .for_each(|dir| match fs::remove_dir_all(gather_dir.join(dir)) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        r => r.expect("failed to remove repo dir"),
    });
    (vec!["version", "timestamp", "event-filter.html", "timestamp"])
        .into_iter()
        .for_each(|file| {
            remove_file(gather_dir.join(file));
            remove_file(normalized_gather.join(file));
        });
    // Delete all events files
    globvec(gather_dir, "**/events.yaml")
        .into_iter()
        .for_each(|events_file| {
            remove_file(events_file);
        });
    // Delete all pod directories
    globvec(gather_dir, "**/pods")
        .into_iter()
        .for_each(|pods_dir| {
            remove_dir(pods_dir);
        });
}

fn get_internal_gather_dir(normalized_gather: &Path) -> PathBuf {
    let mg_image_dir = globvec(normalized_gather, "quay-io*").pop().unwrap();
    fs::rename(mg_image_dir, normalized_gather.join("gather")).expect("failed to rename");
    normalized_gather.join("gather")
}

fn duplicate_must_gather(mg_dir: PathBuf, normalized_gather: &PathBuf) {
    let output = Command::new("cp")
        .arg("-r")
        .arg(mg_dir.to_str().unwrap())
        .arg(normalized_gather)
        .output()
        .expect("failed to execute command");
    if !output.status.success() {
        panic!(
            "failed to copy gather: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn fix_resource(value: &mut Value) {
    if let Some(metadata) = value.as_object_mut().unwrap().get_mut("metadata") {
        if let Some(managed_fields) = metadata.as_object_mut().unwrap().get_mut("managedFields") {
            managed_fields.as_array_mut().unwrap().clear();
        }

        metadata
            .as_object_mut()
            .unwrap()
            .remove("creationTimestamp");
        metadata.as_object_mut().unwrap().remove("resourceVersion");
        metadata.as_object_mut().unwrap().remove("uid");
        metadata.as_object_mut().unwrap().remove("generation");

        if let Some(owner_references) = metadata.as_object_mut().unwrap().get_mut("ownerReferences")
        {
            owner_references
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .for_each(|owner| {
                    owner.as_object_mut().unwrap().remove("uid");
                });
        }

        if let Some(annotations) = metadata.as_object_mut().unwrap().get_mut("annotations") {
            annotations
                .as_object_mut()
                .unwrap()
                .remove("openshift.io/image.dockerRepositoryCheck");
            annotations
                .as_object_mut()
                .unwrap()
                .remove("kubernetes.io/service-account.uid");
        }
    }

    if let Some(status) = value.as_object_mut().unwrap().get_mut("status") {
        status.as_object_mut().unwrap().clear();
    }
}

fn remove_file(path: PathBuf) {
    match fs::remove_file(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        r => r.expect("failed to remove repo file"),
    }
}

fn remove_dir(path: PathBuf) {
    match fs::remove_dir_all(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        r => r.expect("failed to remove repo file"),
    }
}
