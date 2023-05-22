use cluster_crypto::ClusterCryptoObjects;
use etcd_client::Client as EtcdClient;
use k8s_etcd::InMemoryK8sEtcd;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

mod cluster_crypto;
mod file_utils;
mod json_tools;
mod k8s_etcd;
mod progress;
mod rules;

#[tokio::main]
async fn main() -> Result<(), ()> {
    let (static_dir, mut cluster_crypto, memory_etcd) = init().await;
    recertify(Arc::clone(&memory_etcd), &mut cluster_crypto, static_dir).await;
    finalize(memory_etcd).await;
    print_summary(cluster_crypto).await
}

async fn print_summary(cluster_crypto: ClusterCryptoObjects) -> Result<(), ()> {
    println!("Crypto graph...");
    cluster_crypto.display().await;
    Ok(())
}

async fn init() -> (PathBuf, ClusterCryptoObjects, Arc<Mutex<InMemoryK8sEtcd>>) {
    let etcd_client = EtcdClient::connect(["localhost:2379"], None).await.unwrap();
    let static_resource_dir = PathBuf::from(".").join("kubernetes");
    let cluster_crypto = ClusterCryptoObjects::new();
    let in_memory_etcd_client = Arc::new(Mutex::new(InMemoryK8sEtcd::new(etcd_client)));
    (static_resource_dir, cluster_crypto, in_memory_etcd_client)
}

async fn finalize(in_memory_etcd_client: Arc<Mutex<InMemoryK8sEtcd>>) {
    // Since we're using a fake etcd client, we need to also commit the changes to the real etcd
    // after we're done
    println!("Committing to etcd...");
    in_memory_etcd_client
        .lock()
        .await
        .commit_to_actual_etcd()
        .await;
}

async fn recertify(
    in_memory_etcd_client: Arc<Mutex<InMemoryK8sEtcd>>,
    cluster_crypto: &mut ClusterCryptoObjects,
    static_resource_dir: PathBuf,
) {
    collect_crypto_objects(cluster_crypto, &in_memory_etcd_client, static_resource_dir).await;
    establish_relationships(cluster_crypto).await;
    regenerate_cryptographic_objects(&cluster_crypto).await;
    commit_cryptographic_objects_back(&in_memory_etcd_client, &cluster_crypto).await;
}

async fn commit_cryptographic_objects_back(
    in_memory_etcd_client: &Arc<Mutex<InMemoryK8sEtcd>>,
    cluster_crypto: &ClusterCryptoObjects,
) {
    println!("Committing changes...");
    {
        let mut etcd_client = in_memory_etcd_client.lock().await;
        cluster_crypto
            .commit_to_etcd_and_disk(&mut etcd_client)
            .await;
    }
}

async fn regenerate_cryptographic_objects(cluster_crypto: &ClusterCryptoObjects) {
    println!("Regenerating certs...");
    cluster_crypto.regenerate_crypto().await;
}

async fn establish_relationships(cluster_crypto: &mut ClusterCryptoObjects) {
    println!("Pairing certs and keys...");
    cluster_crypto.pair_certs_and_keys().await;
    println!("Scanning jwt signers...");
    cluster_crypto.fill_jwt_signers().await;
    println!("Creating graph relationships...");
    cluster_crypto.fill_signees().await;
    println!("Associating public keys...");
    cluster_crypto.associate_public_keys().await;
}

async fn collect_crypto_objects(
    cluster_crypto: &mut ClusterCryptoObjects,
    in_memory_etcd_client: &Arc<Mutex<InMemoryK8sEtcd>>,
    static_resource_dir: PathBuf,
) {
    println!("Processing etcd...");
    cluster_crypto
        .process_etcd_resources(Arc::clone(in_memory_etcd_client))
        .await;
    println!("Reading kubernetes dir...");
    cluster_crypto
        .process_k8s_static_resources(&static_resource_dir)
        .await;
}
