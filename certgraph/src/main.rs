use clap::Parser;
use cluster_crypto::ClusterCryptoObjects;
use etcd_client::Client as EtcdClient;
use k8s_etcd::InMemoryK8sEtcd;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

mod cluster_crypto;
mod etcd_client_certs;
mod file_utils;
mod json_tools;
mod k8s_etcd;
mod progress;
mod rules;

/// A program to regenerate cluster certificates, keys and tokens
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long)]
    etcd_host: String,

    /// /etc/kubernetes directory
    #[arg(short, long)]
    k8s_static_dir: PathBuf,

    /// /var/lib/kubelet directory
    #[arg(short, long)]
    kubelet_dir: PathBuf,
}

async fn init() -> (
    PathBuf,
    PathBuf,
    ClusterCryptoObjects,
    Arc<Mutex<InMemoryK8sEtcd>>,
) {
    let args = Args::parse();

    let etcd_client = EtcdClient::connect([args.etcd_host.as_str()], None)
        .await
        .unwrap();

    let static_resource_dir = args.k8s_static_dir;
    let kubelet_dir = args.kubelet_dir;
    let cluster_crypto = ClusterCryptoObjects::new();
    let in_memory_etcd_client = Arc::new(Mutex::new(InMemoryK8sEtcd::new(etcd_client)));

    (
        kubelet_dir,
        static_resource_dir,
        cluster_crypto,
        in_memory_etcd_client,
    )
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    let (kubelet_dir, static_dir, mut cluster_crypto, memory_etcd) = init().await;

    // Collect and regenerate certs (doesn't write to disk/etcd)
    recertify(
        Arc::clone(&memory_etcd),
        &mut cluster_crypto,
        kubelet_dir,
        static_dir,
    )
    .await;

    // Actually write to disk/etcd
    finalize(memory_etcd, &mut cluster_crypto).await;

    print_summary(cluster_crypto).await
}

async fn print_summary(cluster_crypto: ClusterCryptoObjects) -> Result<(), ()> {
    println!("Crypto graph...");
    cluster_crypto.display().await;
    Ok(())
}

async fn recertify(
    in_memory_etcd_client: Arc<Mutex<InMemoryK8sEtcd>>,
    cluster_crypto: &mut ClusterCryptoObjects,
    static_resource_dir: PathBuf,
    kubelet_dir: PathBuf,
) {
    collect_crypto_objects(
        cluster_crypto,
        &in_memory_etcd_client,
        kubelet_dir,
        static_resource_dir,
    )
    .await;
    establish_relationships(cluster_crypto).await;
    regenerate_cryptographic_objects(&cluster_crypto).await;
}

async fn finalize(
    in_memory_etcd_client: Arc<Mutex<InMemoryK8sEtcd>>,
    cluster_crypto: &mut ClusterCryptoObjects,
) {
    // Commit the cryptographic objects back to memory etcd and to disk
    commit_cryptographic_objects_back(&in_memory_etcd_client, &cluster_crypto).await;

    // Since we're using an in-memory fake etcd, we need to also commit the changes to the real
    // etcd after we're done
    println!("Committing to etcd...");
    in_memory_etcd_client
        .lock()
        .await
        .commit_to_actual_etcd()
        .await;
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
    kubelet_dir: PathBuf,
    static_resource_dir: PathBuf,
) {
    println!("Processing etcd...");
    cluster_crypto
        .process_etcd_resources(Arc::clone(in_memory_etcd_client))
        .await;
    println!("Reading kubelet_dir dir...");
    cluster_crypto
        .process_k8s_static_resources(&kubelet_dir)
        .await;
    println!("Reading kubernetes dir...");
    cluster_crypto
        .process_k8s_static_resources(&static_resource_dir)
        .await;
}
