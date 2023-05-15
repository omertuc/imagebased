
# Goal

A tool to regenerate all certificates in a cluster before it starts. Works by scanning the existing certificates/keys, understanding how they relate, and replacing them in an identical structure, optionally with a cert domain name.

# Why

Part of the effort to allow users to install a cluster once in a lab, then copy its image for immediate deployment in many different sites.

# Currently

Currently it operates offline on dumps generated from a cluster's disk image, it's still very buggy / work-in-progress

# Eventually

Eventually it (or a similar tool) will run during startup to re-configure the lab-cluster's image before kubelet and other k8s components start

## Generate dumps from qcow2

This script demonstates how you can create the dumps mentioned above from a freshly installed SNO disk qcow2 image

### Requirements

* qemu-nbd
* podman 
* etcdctl
* [auger](https://github.com/jpbetz/auger)

### Script

```bash
# Mount the disk 
cd /home/omer/Documents/model2
sudo modprobe nbd
sudo qemu-nbd --connect=/dev/nbd0 model.qcow2
mkdir -p sno_disk
sudo mount /dev/nbd0p4 sno_disk

# Run etcd
RELEASE_IMAGE=quay.io/openshift-release-dev/ocp-release:4.12.2-x86_64
ETCD_IMAGE="$(oc adm release extract --from="$RELEASE_IMAGE" --file=image-references | jq '.spec.tags[] | select(.name == "etcd").from.name' -r)"
sudo podman run --network=host -it --authfile ~/repos/bootstrap-in-place-poc/registry-config.json --entrypoint etcd -v $PWD/sno_disk/ostree/deploy/rhcos/var/lib/etcd:/store ${ETCD_IMAGE} --name editor --data-dir /store

# In a seperate terminal, dump etcd
rm -rf dump
mkdir -p dump
endpoints="--endpoints=127.0.0.1:2379"
for kind in secrets configmaps; do
    for key in $(etcdctl $endpoints get /kubernetes.io/"$kind"/ --prefix --keys-only); do
        echo $key
        mkdir -p $(dirname dump/$key)
        (etcdctl $endpoints get --print-value-only $key | auger decode > dump/$key.yaml)&
    done
done

# Find the kube dir and copy it
cp kubernetes/ -r /home/omer/repos/imagebased/certgraph/gathers/first/
```
