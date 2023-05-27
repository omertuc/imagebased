use clap::Parser;
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

/// A program to regenerate cluster certificates, keys and tokens
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // etcd endpoint to recertify
    #[arg(short, long)]
    etcd_endpoint: String,

    /// /etc/kubernetes directory to recertifiy
    #[arg(short, long)]
    k8s_static_dir: PathBuf,

    /// /var/lib/kubelet directory to recertify
    #[arg(short, long)]
    kubelet_dir: PathBuf,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    main_internal(args).await;
}

async fn main_internal(args: Args) {
    let (kubelet_dir, kubernetes_dir, mut cluster_crypto, memory_etcd) = init(args).await;
    recertify(Arc::clone(&memory_etcd), &mut cluster_crypto, kubelet_dir, kubernetes_dir).await;
    finalize(memory_etcd, &mut cluster_crypto).await;
    print_summary(cluster_crypto).await;
}

async fn init(args: Args) -> (PathBuf, PathBuf, ClusterCryptoObjects, Arc<Mutex<InMemoryK8sEtcd>>) {
    let etcd_client = EtcdClient::connect([args.etcd_endpoint.as_str()], None).await.unwrap();

    let kubernetes_dir = args.k8s_static_dir;
    let kubelet_dir = args.kubelet_dir;
    let cluster_crypto = ClusterCryptoObjects::new();
    let in_memory_etcd_client = Arc::new(Mutex::new(InMemoryK8sEtcd::new(etcd_client)));

    (kubelet_dir, kubernetes_dir, cluster_crypto, in_memory_etcd_client)
}

async fn recertify(
    in_memory_etcd_client: Arc<Mutex<InMemoryK8sEtcd>>,
    cluster_crypto: &mut ClusterCryptoObjects,
    kubernetes_dir: PathBuf,
    kubelet_dir: PathBuf,
) {
    collect_crypto_objects(cluster_crypto, &in_memory_etcd_client, kubelet_dir, kubernetes_dir).await;
    establish_relationships(cluster_crypto).await;
    regenerate_cryptographic_objects(&cluster_crypto).await;
}

async fn finalize(in_memory_etcd_client: Arc<Mutex<InMemoryK8sEtcd>>, cluster_crypto: &mut ClusterCryptoObjects) {
    // Commit the cryptographic objects back to memory etcd and to disk
    commit_cryptographic_objects_back(&in_memory_etcd_client, &cluster_crypto).await;

    // Since we're using an in-memory fake etcd, we need to also commit the changes to the real
    // etcd after we're done
    println!("Committing to etcd...");
    in_memory_etcd_client.lock().await.commit_to_actual_etcd().await;
}

async fn print_summary(cluster_crypto: ClusterCryptoObjects) {
    println!("Crypto graph...");
    cluster_crypto.display().await;
}

async fn commit_cryptographic_objects_back(in_memory_etcd_client: &Arc<Mutex<InMemoryK8sEtcd>>, cluster_crypto: &ClusterCryptoObjects) {
    println!("Committing changes...");
    let mut etcd_client = in_memory_etcd_client.lock().await;
    cluster_crypto.commit_to_etcd_and_disk(&mut etcd_client).await;
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
    kubelet_dir: PathBuf,
    kubernetes_dir: PathBuf,
) {
    println!("Processing etcd...");
    cluster_crypto.process_etcd_resources(Arc::clone(in_memory_etcd_client)).await;
    println!("Reading kubelet dir...");
    cluster_crypto.process_k8s_static_resources(&kubelet_dir).await;
    println!("Reading kubernetes dir...");
    cluster_crypto.process_k8s_static_resources(&kubernetes_dir).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_init() {
        let args = super::Args {
            etcd_endpoint: "http://localhost:2379".to_string(),
            k8s_static_dir: "./kubernetes".into(),
            kubelet_dir: "./kubelet".into(),
        };

        main_internal(args).await;
    }
}
