use std::process::Stdio;

use tokio::process::Command;

use etcd_client::Client;

use tokio::io::AsyncWriteExt;

pub(crate) async fn etcd_get(
    client: &mut Client,
    k8slocation: &crate::locations::K8sLocation,
) -> Vec<u8> {
    let get_result = client
        .get(
            format!(
                "/kubernetes.io/{}s/{}/{}",
                k8slocation.resource_location.kind.to_lowercase(),
                k8slocation.resource_location.namespace,
                k8slocation.resource_location.name,
            ),
            None,
        )
        .await
        .unwrap();
    let raw_etcd_value = get_result.kvs().first().unwrap().value();

    let mut command = Command::new("auger")
        .arg("decode")
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
            "auger failed on {}, error: {}",
            k8slocation,
            String::from_utf8(result.stderr).unwrap().to_string()
        );
    };

    result.stdout
}

pub(crate) async fn etcd_put(
    client: &mut Client,
    k8slocation: &crate::locations::K8sLocation,
    value: Vec<u8>,
) {
    let mut command = Command::new("auger")
        .arg("encode")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to execute auger");
    command
        .stdin
        .take()
        .unwrap()
        .write_all(value.as_slice())
        .await
        .unwrap();
    let result = command.wait_with_output().await.unwrap();

    if !result.status.success() {
        panic!(
            "auger failed on {}, error: {}",
            k8slocation,
            String::from_utf8(result.stderr).unwrap().to_string()
        );
    };

    // client
    //     .put(
    //         format!(
    //             "/kubernetes.io/{}s/{}/{}",
    //             k8slocation.resource_location.kind.to_lowercase(),
    //             k8slocation.resource_location.namespace,
    //             k8slocation.resource_location.name,
    //         ),
    //         result.stdout,
    //         None,
    //     )
    //     .await
    //     .unwrap();
}
