use crate::k8s_etcd::InMemoryK8sEtcd;

use super::encode_resource_data_entry;
use super::get_etcd_yaml;
use super::locations::FileLocation;
use super::locations::K8sLocation;
use super::locations::Location;
use super::locations::LocationValueType;
use super::locations::Locations;
use super::verify_jwt;
use super::Jwt;
use super::JwtSigner;
use jwt_simple::prelude::RSAKeyPairLike;
use serde_json::Value;
use x509_certificate::InMemorySigningKeyPair;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DistributedJwt {
    pub(crate) jwt: Jwt,
    pub(crate) locations: Locations,
    pub(crate) signer: JwtSigner,
}

impl DistributedJwt {
    pub(crate) fn regenerate(&mut self, sign_with: &InMemorySigningKeyPair) {
        match &self.signer {
            JwtSigner::Unknown => panic!("Cannot regenerate JWT with unknown signer"),
            JwtSigner::CertKeyPair(cert_key_pair) => {
                match &(**cert_key_pair).borrow().distributed_private_key {
                    Some(private_key) => match verify_jwt(&(**private_key).borrow(), self) {
                        Ok(claims) => {
                            match sign_with {
                                InMemorySigningKeyPair::Ecdsa(_, _, _) => {
                                    panic!("Unsupported key type")
                                }
                                InMemorySigningKeyPair::Ed25519(_) => {
                                    panic!("Unsupported key type")
                                }
                                InMemorySigningKeyPair::Rsa(_rsa_key_pair, bytes) => {
                                    let key =
                                        jwt_simple::prelude::RS256KeyPair::from_der(bytes).unwrap();
                                    let token = key.sign(claims);
                                    self.jwt.str = token.unwrap().to_string();
                                }
                            };
                        }
                        Err(_) => panic!("Failed to parse token"),
                    },
                    None => panic!("Cannot regenerate JWT with unknown private key"),
                };
            }
            JwtSigner::PrivateKey(_) => panic!("Unsupported key type"),
        };
    }

    pub(crate) async fn commit_to_etcd_and_disk(&self, etcd_client: &mut InMemoryK8sEtcd) {
        for location in &self.locations.0 {
            match location {
                Location::K8s(k8slocation) => {
                    self.commit_to_etcd(etcd_client, &k8slocation).await;
                }
                Location::Filesystem(filelocation) => {
                    self.commit_to_filesystem(&filelocation).await;
                }
            }
        }
    }

    pub(crate) async fn commit_to_etcd(
        &self,
        etcd_client: &mut InMemoryK8sEtcd,
        k8slocation: &K8sLocation,
    ) {
        let mut resource = get_etcd_yaml(etcd_client, k8slocation).await;
        if let Some(value_at_json_pointer) =
            resource.pointer_mut(&k8slocation.yaml_location.json_pointer)
        {
            if let Value::String(value_at_json_pointer) = value_at_json_pointer {
                match &k8slocation.yaml_location.value {
                    LocationValueType::Pem(_pem_location_info) => {
                        panic!("JWT cannot be in PEM")
                    }
                    LocationValueType::Jwt => {
                        let encoded = encode_resource_data_entry(k8slocation, &self.jwt.str);

                        *value_at_json_pointer = encoded;
                    }
                    LocationValueType::Unknown => panic!("shouldn't happen"),
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

    pub(crate) async fn commit_to_filesystem(&self, _filelocation: &FileLocation) {
        todo!()
    }
}
