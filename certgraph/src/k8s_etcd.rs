use etcd_client::{Client as EtcdClient, GetOptions};
use std::collections::HashMap;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

// An etcd client wrapper backed by an in-memory hashmap. All reads are served from memory, with
// fallback to actual etcd. All writes are strictly to memory. Also supports eventually committing
// to an actual etcd instance of kubernetes, transparently encoding and decoding YAMLs with auger.
// Used by certgraph as a cache to dramatically speed up the process of certificate and key
// regeneration, as we we don't have to go through Auger and etcd for every single certificate and
// key access.
pub struct InMemoryK8sEtcd {
    etcd_client: EtcdClient,
    map: HashMap<String, Vec<u8>>,
}

impl InMemoryK8sEtcd {
    pub(crate) fn new(etcd_client: EtcdClient) -> Self {
        InMemoryK8sEtcd {
            etcd_client,
            map: HashMap::new(),
        }
    }

    pub(crate) async fn commit_to_actual_etcd(&mut self) {
        let progress = crate::progress::create_progress_bar("Committing to etcd", self.map.len());
        for (key, value) in self.map.iter() {
            self.etcd_client
                .put(
                    key.as_bytes(),
                    run_auger("encode", value.as_slice()).await,
                    None,
                )
                .await
                .unwrap();
            progress.inc(1);
        }
    }

    pub(crate) async fn get(&mut self, key: &str) -> Vec<u8> {
        match self.map.get(key) {
            Some(value) => value.clone(),
            None => {
                let get_result = self.etcd_client.get(key, None).await.unwrap();
                let raw_etcd_value = get_result.kvs().first().unwrap().value();
                let decoded_value = run_auger("decode", raw_etcd_value).await;
                self.map.insert(key.to_string(), decoded_value.clone());
                decoded_value
            }
        }
    }

    pub(crate) async fn put(&mut self, key: &str, value: Vec<u8>) {
        self.map.insert(key.to_string(), value.clone());
    }

    pub(crate) async fn list_keys(&mut self, resource_kind: &str) -> Vec<String> {
        let etcd_get_options = GetOptions::new()
            .with_prefix()
            .with_limit(0)
            .with_keys_only();
        let keys = self
            .etcd_client
            .get(
                format!("/kubernetes.io/{}", resource_kind),
                Some(etcd_get_options.clone()),
            )
            .await
            .expect("Couldn't get secrets list, is etcd down?");
        keys.kvs()
            .into_iter()
            .map(|k| k.key_str().unwrap().to_string())
            .collect::<Vec<String>>()
    }
}

pub(crate) fn k8slocation_to_etcd_key(k8slocation: &crate::locations::K8sLocation) -> String {
    format!(
        "/kubernetes.io/{}s/{}/{}",
        k8slocation.resource_location.kind.to_lowercase(),
        k8slocation.resource_location.namespace,
        k8slocation.resource_location.name,
    )
}

async fn run_auger(auger_subcommand: &str, raw_etcd_value: &[u8]) -> Vec<u8> {
    let mut command = Command::new("auger")
        .arg(auger_subcommand)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    command
        .stdin
        .take()
        .unwrap()
        .write_all(raw_etcd_value)
        .await
        .unwrap();

    let result = command.wait_with_output().await.unwrap();

    if !result.status.success() {
        panic!(
            "auger failed on, error: {}",
            String::from_utf8(result.stderr).unwrap().to_string()
        );
    };

    result.stdout
}
