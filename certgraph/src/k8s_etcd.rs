use etcd_client::{Client as EtcdClient, GetOptions};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

pub(crate) async fn etcd_get(client: &mut EtcdClient, key: &str) -> Vec<u8> {
    let get_result = client.get(key, None).await.unwrap();
    let raw_etcd_value = get_result.kvs().first().unwrap().value();

    run_auger("decode", raw_etcd_value).await
}

pub(crate) async fn etcd_list_keys(
    client: &mut EtcdClient,
    resource_kind: &str,
) -> etcd_client::GetResponse {
    let etcd_get_options = GetOptions::new()
        .with_prefix()
        .with_limit(0)
        .with_keys_only();

    let keys = client
        .get(
            format!("/kubernetes.io/{}", resource_kind),
            Some(etcd_get_options.clone()),
        )
        .await
        .expect("Couldn't get secrets list, is etcd down?");
    keys
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

pub(crate) async fn etcd_put(
    client: &mut EtcdClient,
    k8slocation: &crate::locations::K8sLocation,
    value: Vec<u8>,
) {
    client
        .put(
            format!(
                "/kubernetes.io/{}s/{}/{}",
                k8slocation.resource_location.kind.to_lowercase(),
                k8slocation.resource_location.namespace,
                k8slocation.resource_location.name,
            ),
            run_auger("encode", value.as_slice()).await,
            None,
        )
        .await
        .unwrap();
}
