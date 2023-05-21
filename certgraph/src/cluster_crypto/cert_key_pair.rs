use super::{
    cyrpto_utils::generate_rsa_key,
    decode_resource_data_entry,
    distributed_public_key::DistributedPublicKey,
    locations::{FileContentLocation, FileLocation, K8sLocation, Location},
    pem_bundle_replace_pem_at_index,
};
use super::{
    distributed_private_key, encode_resource_data_entry, encode_tbs_cert_to_der, get_etcd_yaml,
    Certificate, DistributedCert, PrivateKey, Signee,
};
use crate::{cluster_crypto::locations::LocationValueType, k8s_etcd::InMemoryK8sEtcd};
use bcder::BitString;
use bytes::Bytes;
use pkcs1::EncodeRsaPrivateKey;
use rsa::{signature::Signer, RsaPrivateKey};
use serde_json::Value;
use std::{cell::RefCell, fmt::Display, rc::Rc};
use tokio::{self, io::AsyncReadExt};
use x509_certificate::{
    rfc5280, CapturedX509Certificate, InMemorySigningKeyPair, KeyAlgorithm, Sign, X509Certificate,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CertKeyPair {
    pub(crate) distributed_private_key:
        Option<Rc<RefCell<distributed_private_key::DistributedPrivateKey>>>,
    pub(crate) distributed_cert: Rc<RefCell<DistributedCert>>,

    /// The signer is the cert that signed this cert. If this is a self-signed cert, then this will
    /// be None
    pub(crate) signer: Option<Rc<RefCell<DistributedCert>>>,
    /// The signees are the certs or jwts that this cert has signed
    pub(crate) signees: Vec<Signee>,
    /// Sometimes cert public keys also appear on their own, outside the cert, so we need to track
    /// them
    pub(crate) associated_public_key: Option<Rc<RefCell<DistributedPublicKey>>>,
}

impl CertKeyPair {
    pub(crate) fn regenerate(&mut self, sign_with: Option<&InMemorySigningKeyPair>) {
        let (new_cert_subject_key_pair, rsa_private_key, new_cert) = self.re_sign_cert(sign_with);
        (*self.distributed_cert).borrow_mut().certificate = Certificate::from(new_cert);

        for signee in &mut self.signees {
            signee.regenerate(
                &(*self.distributed_cert).borrow().certificate.public_key,
                Some(&new_cert_subject_key_pair),
            );
        }

        // This condition exists because not all certs originally had a private key
        // associated with them (e.g. some private keys are discarded during install time),
        // so we only want to write the private key back into the graph incase there was
        // one there to begin with.
        if let Some(distributed_private_key) = &mut self.distributed_private_key {
            (**distributed_private_key).borrow_mut().key = PrivateKey::Rsa(rsa_private_key)
        }
    }

    pub(crate) fn re_sign_cert(
        &mut self,
        sign_with: Option<&InMemorySigningKeyPair>,
    ) -> (
        InMemorySigningKeyPair,
        RsaPrivateKey,
        CapturedX509Certificate,
    ) {
        let mut rng = rand::thread_rng();

        // Generate a new RSA key for this cert
        let (self_new_rsa_private_key, self_new_key_pair) = generate_rsa_key(&mut rng);

        // Copy the to-be-signed part of the certificate from the original certificate
        let cert: &X509Certificate = &(*self.distributed_cert).borrow().certificate.original;
        let certificate: &rfc5280::Certificate = cert.as_ref();
        let mut tbs_certificate = certificate.tbs_certificate.clone();

        // Replace just the public key info in the to-be-signed part with the newly generated RSA
        // key
        tbs_certificate.subject_public_key_info = rfc5280::SubjectPublicKeyInfo {
            algorithm: KeyAlgorithm::from(&self_new_key_pair).into(),
            subject_public_key: BitString::new(0, self_new_key_pair.public_key_data()),
        };

        // The to-be-signed ceritifcate, encoded to DER, is the bytes we sign
        let tbs_der = encode_tbs_cert_to_der(&tbs_certificate);

        // If we weren't given a key to sign with, we use the new key we just generated
        // as this is a root (self-signed) certificate
        let signing_key = if let Some(key_pair) = &sign_with {
            key_pair
        } else {
            &self_new_key_pair
        };

        // Generate the actual signature
        let signature = signing_key.try_sign(&tbs_der).unwrap();

        // Create a full certificate by combining the to-be-signed part with the signature itself
        let signature_algorithm = self_new_key_pair.signature_algorithm().unwrap();
        let cert = rfc5280::Certificate {
            tbs_certificate,
            signature_algorithm: signature_algorithm.into(),
            signature: BitString::new(0, Bytes::copy_from_slice(signature.as_ref())),
        };

        // Encode the entire cert as DER and reload it into a CapturedX509Certificate which is the
        // type we use in our structs
        let cert =
            CapturedX509Certificate::from_der(X509Certificate::from(cert).encode_der().unwrap())
                .unwrap();

        (self_new_key_pair, self_new_rsa_private_key, cert)
    }

    pub(crate) async fn commit_to_etcd_and_disk(&self, etcd_client: &mut InMemoryK8sEtcd) {
        self.commit_pair_certificate(etcd_client).await;
        self.commit_pair_key(etcd_client).await;
    }

    pub(crate) async fn commit_pair_certificate(&self, etcd_client: &mut InMemoryK8sEtcd) {
        for location in (*self.distributed_cert).borrow().locations.0.iter() {
            match location {
                Location::K8s(k8slocation) => {
                    self.commit_k8s_cert(etcd_client, &k8slocation).await;
                }
                Location::Filesystem(filelocation) => {
                    self.commit_filesystem_cert(&filelocation).await;
                }
            }
        }
    }

    pub(crate) async fn commit_k8s_cert(
        &self,
        etcd_client: &mut InMemoryK8sEtcd,
        k8slocation: &K8sLocation,
    ) {
        let mut resource = get_etcd_yaml(etcd_client, k8slocation).await;
        if let Some(value_at_json_pointer) =
            resource.pointer_mut(&k8slocation.yaml_location.json_pointer)
        {
            if let Value::String(value_at_json_pointer) = value_at_json_pointer {
                let decoded = decode_resource_data_entry(k8slocation, &value_at_json_pointer);

                if let LocationValueType::Pem(pem_location_info) = &k8slocation.yaml_location.value
                {
                    let newpem = pem::parse(
                        (*self.distributed_cert)
                            .borrow()
                            .certificate
                            .original
                            .encode_pem(),
                    )
                    .unwrap();
                    let newbundle = pem_bundle_replace_pem_at_index(
                        decoded,
                        pem_location_info.pem_bundle_index,
                        newpem,
                    );
                    let encoded = encode_resource_data_entry(k8slocation, &newbundle);
                    *value_at_json_pointer = encoded;
                } else {
                    panic!("shouldn't happen");
                }
            }
        } else {
            panic!("shouldn't happen");
        }

        let newcontents = serde_yaml::to_string(&resource).unwrap();
        etcd_client
            .put(&k8slocation.as_etcd_key(), newcontents.as_bytes().to_vec())
            .await;
    }

    pub(crate) async fn commit_pair_key(&self, etcd_client: &mut InMemoryK8sEtcd) {
        if let Some(private_key) = &self.distributed_private_key {
            for location in (**private_key).borrow().locations.0.iter() {
                match location {
                    Location::K8s(k8slocation) => {
                        self.commit_k8s_private_key(
                            etcd_client,
                            &k8slocation,
                            &(**private_key).borrow(),
                        )
                        .await;
                    }
                    Location::Filesystem(filelocation) => {
                        self.commit_filesystem_private_key(
                            &filelocation,
                            &(**private_key).borrow(),
                        )
                        .await;
                    }
                }
            }
        }
    }

    pub(crate) async fn commit_k8s_private_key(
        &self,
        etcd_client: &mut InMemoryK8sEtcd,
        k8slocation: &K8sLocation,
        distributed_private_key: &distributed_private_key::DistributedPrivateKey,
    ) {
        let mut resource = get_etcd_yaml(etcd_client, k8slocation).await;
        if let Some(value_at_json_pointer) =
            resource.pointer_mut(&k8slocation.yaml_location.json_pointer)
        {
            if let Value::String(value_at_json_pointer) = value_at_json_pointer {
                let decoded = decode_resource_data_entry(k8slocation, &value_at_json_pointer);

                if let LocationValueType::Pem(pem_location_info) = &k8slocation.yaml_location.value
                {
                    match &distributed_private_key.key {
                        PrivateKey::Rsa(rsa_private_key) => {
                            let newbundle = pem_bundle_replace_pem_at_index(
                                decoded,
                                pem_location_info.pem_bundle_index,
                                pem::Pem::new(
                                    "RSA PRIVATE KEY",
                                    rsa_private_key.to_pkcs1_der().unwrap().as_bytes(),
                                ),
                            );
                            let encoded = encode_resource_data_entry(k8slocation, &newbundle);
                            *value_at_json_pointer = encoded;
                        }
                    }
                } else {
                    panic!("shouldn't happen");
                }
            }
        } else {
            panic!("shouldn't happen");
        }

        let newcontents = serde_yaml::to_string(&resource).unwrap();
        etcd_client
            .put(&k8slocation.as_etcd_key(), newcontents.as_bytes().to_vec())
            .await;
    }

    pub(crate) async fn commit_filesystem_private_key(
        &self,
        filelocation: &FileLocation,
        private_key: &distributed_private_key::DistributedPrivateKey,
    ) {
        let mut file = tokio::fs::File::open(&filelocation.file_path)
            .await
            .unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).await.unwrap();

        match &filelocation.content_location {
            FileContentLocation::Raw(pem_location_info) => match &private_key.key {
                PrivateKey::Rsa(rsa_private_key) => {
                    if let LocationValueType::Pem(pem_location_info) = &pem_location_info {
                        let newpem = pem::Pem::new(
                            "RSA PRIVATE KEY",
                            rsa_private_key.to_pkcs1_der().unwrap().as_bytes(),
                        );
                        let newbundle = pem_bundle_replace_pem_at_index(
                            String::from_utf8(contents).unwrap(),
                            pem_location_info.pem_bundle_index,
                            newpem,
                        );
                        tokio::fs::write(&filelocation.file_path, newbundle)
                            .await
                            .unwrap();
                    } else {
                        panic!("shouldn't happen");
                    }
                }
            },
        }
    }

    pub(crate) async fn commit_filesystem_cert(&self, filelocation: &FileLocation) {
        let mut file = tokio::fs::File::open(&filelocation.file_path)
            .await
            .unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).await.unwrap();

        match &filelocation.content_location {
            FileContentLocation::Raw(location_value_type) => {
                if let LocationValueType::Pem(pem_location_info) = &location_value_type {
                    let newpem = pem::parse(
                        (*self.distributed_cert)
                            .borrow()
                            .certificate
                            .original
                            .encode_pem(),
                    )
                    .unwrap();
                    let newbundle = pem_bundle_replace_pem_at_index(
                        String::from_utf8(contents).unwrap(),
                        pem_location_info.pem_bundle_index,
                        newpem,
                    );
                    tokio::fs::write(&filelocation.file_path, newbundle)
                        .await
                        .unwrap();
                } else {
                    panic!("shouldn't happen");
                }
            }
        }
    }
}

impl Display for CertKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cert {:03} locations {}, ",
            (*self.distributed_cert).borrow().locations.0.len(),
            "<>",
            // (*self.distributed_cert).borrow().locations,
        )?;
        write!(
            f,
            "{}",
            if self.distributed_private_key.is_some() {
                format!(
                    "priv {:03} locations {}",
                    (**self.distributed_private_key.as_ref().unwrap())
                        .borrow()
                        .locations
                        .0
                        .len(),
                    // (**self.distributed_private_key.as_ref().unwrap())
                    //     .borrow()
                    //     .locations,
                    "<>",
                )
            } else {
                "NO PRIV".to_string()
            }
        )?;
        write!(
            f,
            " | {}",
            (*self.distributed_cert).borrow().certificate.subject,
        )?;

        if self.signees.len() > 0 {
            writeln!(f, "")?;
        }

        for signee in &self.signees {
            writeln!(f, "- {}", signee)?;
        }

        if let Some(associated_public_key) = &self.associated_public_key {
            writeln!(f, "* {}", (**associated_public_key).borrow())?;
        }

        Ok(())
    }
}
