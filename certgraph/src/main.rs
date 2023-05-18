use cluster_crypto::ClusterCryptoObjects;
use etcd_client::Client as EtcdClient;
use futures_util::future::join_all;
use k8s_etcd::InMemoryK8sEtcd;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

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
    let in_memory_etcd = Arc::new(Mutex::new(InMemoryK8sEtcd::new(etcd_client)));

    recertify(in_memory_etcd, cluster_crypto, static_resource_dir).await;

    Ok(())
}

async fn recertify(
    in_memory_etcd_client: Arc<Mutex<InMemoryK8sEtcd>>,
    mut cluster_crypto: ClusterCryptoObjects,
    static_resource_dir: &PathBuf,
) {
    println!("Processing etcd...");
    process_etcd_resources(Arc::clone(&in_memory_etcd_client), &mut cluster_crypto).await;

    println!("Reading kubernetes dir...");
    cluster_crypto
        .process_k8s_static_resources(static_resource_dir)
        .await;

    println!("Pairing certs and keys...");
    cluster_crypto.pair_certs_and_key().await;

    println!("Creating graph relationships...");
    cluster_crypto.fill_signees().await;

    println!("Regenerating certs...");
    cluster_crypto.regenerate_certificates_and_keys().await;

    println!("Committing changes...");
    {
        let mut etcd_client = in_memory_etcd_client.lock().await;
        cluster_crypto
            .commit_to_etcd_and_disk(&mut etcd_client)
            .await;
    }

    println!("Committing to etcd...");
    in_memory_etcd_client
        .lock()
        .await
        .commit_to_actual_etcd()
        .await;

    println!("Crypto graph...");
    cluster_crypto.display().await;
}

/// Read all relevant resources from etcd and register them in the cluster_crypto object
async fn process_etcd_resources(
    etcd_client: Arc<Mutex<InMemoryK8sEtcd>>,
    cluster_crypto: &ClusterCryptoObjects,
) {
    println!("Obtaining keys");
    let key_lists = {
        let etcd_client = etcd_client.lock().await;
        [
            &(etcd_client.list_keys("secrets").await),
            &(etcd_client.list_keys("configmaps").await),
        ]
    };

    let all_keys = key_lists.into_iter().flatten();

    // let total_keys = key_lists.into_iter().map(|x| x.len()).sum();
    // let progress = progress::create_progress_bar("Processing etcd resources", total_keys);

    println!("Retrieving etcd resources...");
    let join_results = join_all(
        all_keys
            .into_iter()
            .map(|key| {
                let key = key.clone();
                let etcd_client = Arc::clone(&etcd_client);
                tokio::spawn(async move { etcd_client.lock().await.get(key).await })
            })
            .collect::<Vec<_>>(),
    )
    .await;

    println!("Processing etcd resources...");
    for contents in join_results {
        cluster_crypto.process_etcd_key(contents.unwrap()).await;
    }
}
