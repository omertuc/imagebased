use crate::locations::{self, Location};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::collections::{HashMap, HashSet};
use x509_parser::public_key::RSAPublicKey;

#[derive(Clone)]
pub(crate) enum PrivateKey {
    Rsa(RsaPrivateKey),
}

#[derive(Hash, Eq, PartialEq)]
pub(crate) enum PublicKey {
    Rsa(RsaPublicKey),
}

impl PublicKey {
    pub(crate) fn from_rsa(rsa_public_key: &RSAPublicKey) -> PublicKey {
        let modulus = rsa::BigUint::from_bytes_be(rsa_public_key.modulus);
        let exponent = rsa::BigUint::from_bytes_be(rsa_public_key.exponent);

        PublicKey::Rsa(RsaPublicKey::new(modulus, exponent).unwrap())
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum Key {
    PrivateKey(Location, PrivateKey),
    PublicKey(Location, String),
}

pub(crate) struct CryptoGraph {
    pub(crate) public_to_private: HashMap<PublicKey, PrivateKey>,
    pub(crate) identity_to_public: HashMap<String, String>,
    pub(crate) ca_certs: HashSet<String>,
    pub(crate) keys: HashSet<Key>,
    pub(crate) cert_to_private_key: HashMap<String, PrivateKey>,
    pub(crate) privat_key_locations: HashMap<PrivateKey, Vec<Location>>,

    // Maps root cert to a list of certificates signed by it
    pub(crate) root_certs: HashMap<String, Vec<String>>,
}
