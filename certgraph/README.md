
# Goal

A tool to regenerate all certificates in a cluster (both in the etcd database and static-pod resources) before it starts. Works by scanning the existing certificates/keys, understanding how they relate, and replacing them in an identical structure, optionally with a different configurable certificate CN/SAN.

# Why

Part of the effort to allow users to install a cluster once in a lab, then copy its image for immediate deployment in many different sites.

# Currently

Currently it operates against a manually ran etcd server (backed by an etcd store from a cluster's mounted qcow2 disk image), along with a manually copied `/etc/kubernetes` from that same disk. It's still very buggy / work-in-progress

# Eventually

Eventually it (or a similar tool) will run during startup to re-configure the lab-cluster's image before kubelet and other k8s components start

## Generate dumps from qcow2

This script demonstates how you can create the dumps mentioned above from a freshly installed SNO disk qcow2 image

### Requirements

* qemu-nbd
* podman 
* [auger](https://github.com/jpbetz/auger)

### Script

```bash
# Mount the disk 
cd /home/omer/Documents/model2
sudo modprobe nbd
sudo qemu-nbd --connect=/dev/nbd0 model.qcow2
mkdir -p sno_disk
sudo mount /dev/nbd0p4 sno_disk

# sudo qemu-nbd --disconnect model.qcow2
# sudo qemu-nbd --disconnect /dev/nbd0 
# sudo umount sno_disk
# sudo rm -rf model.qcow2 sno_disk
# sudo cp ../model/model.qcow2 .

# Run etcd
RELEASE_IMAGE=quay.io/openshift-release-dev/ocp-release:4.12.2-x86_64
ETCD_IMAGE="$(oc adm release extract --from="$RELEASE_IMAGE" --file=image-references | jq '.spec.tags[] | select(.name == "etcd").from.name' -r)"
sudo podman run --network=host -it --authfile ~/repos/bootstrap-in-place-poc/registry-config.json --entrypoint etcd -v $PWD/sno_disk/ostree/deploy/rhcos/var/lib/etcd:/store ${ETCD_IMAGE} --name editor --data-dir /store

# Find the kube dir and copy it
cp /home/omer/Documents/model2/sno_disk/ostree/deploy/rhcos/deploy/dd62c369ad76ef06c72ef2d76da6578eeafe4022ef082b0dfe8171e4572a15e4.0/etc/kubernetes -r /home/omer/repos/imagebased/certgraph/gathers/first/
```
