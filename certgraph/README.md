A tool to regenerate all certificates in a cluster (both in the etcd database
and static-pod resources) before it starts. Works by scanning the existing
certificates/keys/jwts, understanding how they relate, and replacing them in an
identical structure, but with newly randomly generated keys and sometimes
different configurable certificate CN/SAN.

# Why

Part of the effort to allow users to install a SNO cluster once in a lab, then
copy its disk image for immediate deployment in many different sites. The new
cluster will thus have its own independent secret keys and its certificates
will be valid for the correct CN/SAN.

## Usage example (local using qcow2)

### Requirements

* qemu-nbd
* podman 
* [auger](https://github.com/jpbetz/auger)

### Script

```bash
# Mount the disk 
cd /home/omer/Documents/model6
sudo modprobe nbd
sudo qemu-nbd --connect=/dev/nbd0 model.qcow2
mkdir -p sno_disk
sudo mount /dev/nbd0p4 sno_disk

# To disconnect use 
# sudo qemu-nbd --disconnect model.qcow2
# sudo qemu-nbd --disconnect /dev/nbd0 
# sudo umount sno_disk
# sudo rm -rf sno_disk

# Run etcd
RELEASE_IMAGE=quay.io/openshift-release-dev/ocp-release:4.13.0-x86_64
ETCD_IMAGE="$(oc adm release extract --from="$RELEASE_IMAGE" --file=image-references | jq '.spec.tags[] | select(.name == "etcd").from.name' -r)"
# sudo podman run --network=host --privileged -it --entrypoint etcd -v /var/lib/etcd:/store ${ETCD_IMAGE} --name editor --data-dir /store
sudo podman run --network=host -it --authfile ~/repos/bootstrap-in-place-poc/registry-config.json --entrypoint etcd -v $PWD/sno_disk/ostree/deploy/rhcos/var/lib/etcd:/store ${ETCD_IMAGE} --name editor --data-dir /store

sudo cp /home/omer/Documents/model6/sno_disk/ostree/deploy/rhcos/deploy/**/etc/kubernetes -r /home/omer/repos/imagebased/certgraph/
sudo chown -R omer:omer /home/omer/repos/imagebased/certgraph/kubernetes

sudo cp /home/omer/Documents/model6/sno_disk/ostree/deploy/rhcos/var/lib/kubelet -r /home/omer/repos/imagebased/certgraph/
sudo chown -R omer:omer /home/omer/repos/imagebased/certgraph/kubelet

cargo run --release -- --etcd-endpoint localhost:2379 --k8s-static-dir ./kubernetes --kubelet-dir ./kubelet
```

# Run on cluster

## Compile
```bash
RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --target x86_64-unknown-linux-gnu
```

## Reboot

```bash
ssh -o IdentityFile=./ssh-key/key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no core@192.168.126.10 sudo systemctl disable kubelet
ssh -o IdentityFile=./ssh-key/key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no core@192.168.126.10 sudo systemctl disable crio
ssh -o IdentityFile=./ssh-key/key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no core@192.168.126.10 sudo reboot 
```

## Run etcd

```bash
RELEASE_IMAGE=quay.io/openshift-release-dev/ocp-release:4.13.0-x86_64
ETCD_IMAGE="$(oc adm release extract --from="$RELEASE_IMAGE" --file=image-references | jq '.spec.tags[] | select(.name == "etcd").from.name' -r)"
ssh -o IdentityFile=./ssh-key/key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no core@192.168.126.10 sudo podman run --network=host --privileged --entrypoint etcd -v /var/lib/etcd:/store ${ETCD_IMAGE} --name editor --data-dir /store
```

## Copy things

```bash
ssh -o IdentityFile=./ssh-key/key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no core@192.168.126.10 sudo mkdir -p /root/.local/bin
scp -o IdentityFile=./ssh-key/key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no /home/omer/repos/imagebased/certgraph/target/x86_64-unknown-linux-gnu/release/certgraph core@192.168.126.10:certgraph
scp -o IdentityFile=./ssh-key/key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no /home/omer/repos/auger/auger core@192.168.126.10:
scp -o IdentityFile=./ssh-key/key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no /home/omer/repos/bootstrap-in-place-poc/sno-workdir/auth/kubeconfig core@192.168.126.10:

ssh -o IdentityFile=./ssh-key/key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no core@192.168.126.10 sudo cp /home/core/auger /root/.local/bin/
ssh -o IdentityFile=./ssh-key/key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no core@192.168.126.10 sudo cp /home/core/certgraph /root/.local/bin/
```

## Run utility

```bash
ssh -o IdentityFile=./ssh-key/key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no core@192.168.126.10 sudo ulimit -n 999999
ssh -o IdentityFile=./ssh-key/key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no core@192.168.126.10 sudo bash -ic "'certgraph --etcd-endpoint localhost:2379 --k8s-static-dir /etc/kubernetes --kubelet-dir /var/lib/kubelet --kubeconfig /home/core/kubeconfig'"
```

## Copy regenerated kubeconfig back to your machine
```bash
scp -o IdentityFile=./ssh-key/key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no core@192.168.126.10:kubeconfig /home/omer/repos/bootstrap-in-place-poc/sno-workdir/auth/kubeconfig2
```

## Reboot
```bash
ssh -o IdentityFile=./ssh-key/key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no core@192.168.126.10 sudo systemctl enable kubelet
ssh -o IdentityFile=./ssh-key/key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no core@192.168.126.10 sudo systemctl enable crio
ssh -o IdentityFile=./ssh-key/key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no core@192.168.126.10 sudo reboot 
```
