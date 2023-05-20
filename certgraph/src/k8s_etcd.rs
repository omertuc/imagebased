use etcd_client::{Client as EtcdClient, GetOptions};
use futures_util::future::join_all;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Mutex;
use crate::cluster_crypto::K8sLocation;

// An etcd client wrapper backed by an in-memory hashmap. All reads are served from memory, with
// fallback to actual etcd. All writes are strictly to memory. Also supports eventually committing
// to an actual etcd instance of kubernetes, transparently encoding and decoding YAMLs with auger.
// Used by certgraph as a cache to dramatically speed up the process of certificate and key
// regeneration, as we we don't have to go through Auger and etcd for every single certificate and
// key access.
pub struct InMemoryK8sEtcd {
    internal: Mutex<InMemoryK8sEtcdInternal>,
}

impl InMemoryK8sEtcd {
    pub(crate) fn new(etcd_client: EtcdClient) -> Self {
        InMemoryK8sEtcd {
            internal: Mutex::new(InMemoryK8sEtcdInternal::new(etcd_client)),
        }
    }
    pub(crate) async fn commit_to_actual_etcd(&mut self) {
        self.internal.lock().await.commit_to_actual_etcd().await;
    }
    pub(crate) async fn get(&self, key: String) -> Vec<u8> {
        self.internal.lock().await.get(&key).await
    }
    pub(crate) async fn put(&mut self, key: &str, value: Vec<u8>) {
        self.internal.lock().await.put(key, value).await;
    }
    pub(crate) async fn list_keys(&self, resource_kind: &str) -> Vec<String> {
        self.internal.lock().await.list_keys(resource_kind).await
    }
}

pub struct InMemoryK8sEtcdInternal {
    etcd_client: Arc<Mutex<EtcdClient>>,
    etcd_keyvalue_hashmap: Mutex<HashMap<String, Vec<u8>>>,
}

impl InMemoryK8sEtcdInternal {
    pub(crate) fn new(etcd_client: EtcdClient) -> Self {
        InMemoryK8sEtcdInternal {
            etcd_client: Arc::new(Mutex::new(etcd_client)),
            etcd_keyvalue_hashmap: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) async fn commit_to_actual_etcd(&mut self) {
        let futures = self
            .etcd_keyvalue_hashmap
            .lock()
            .await
            .iter()
            .map(|(key, value)| {
                let key = key.clone();
                let value = value.clone();
                let etcd_client = Arc::clone(&self.etcd_client);
                tokio::spawn(async move {
                    let auger_result = run_auger("encode", value.as_slice()).await;
                    etcd_client
                        .lock()
                        .await
                        .put(key.as_bytes(), auger_result, None)
                        .await
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();

        join_all(futures).await;
    }

    pub(crate) async fn get(&self, key: &str) -> Vec<u8> {
        {
            let hashmap = self.etcd_keyvalue_hashmap.lock().await;
            if let Some(value) = hashmap.get(key) {
                return value.clone();
            }
        }

        let get_result = self.etcd_client.lock().await.get(key, None).await.unwrap();
        let raw_etcd_value = get_result.kvs().first().unwrap().value();
        let decoded_value = run_auger("decode", raw_etcd_value).await;
        self.etcd_keyvalue_hashmap
            .lock()
            .await
            .insert(key.to_string(), decoded_value.clone());
        decoded_value
    }

    pub(crate) async fn put(&mut self, key: &str, value: Vec<u8>) {
        self.etcd_keyvalue_hashmap
            .lock()
            .await
            .insert(key.to_string(), value.clone());
    }

    pub(crate) async fn list_keys(&mut self, resource_kind: &str) -> Vec<String> {
        let etcd_get_options = GetOptions::new()
            .with_prefix()
            .with_limit(0)
            .with_keys_only();
        let keys = self
            .etcd_client
            .lock()
            .await
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

pub(crate) fn k8slocation_to_etcd_key(k8slocation: &K8sLocation) -> String {
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
