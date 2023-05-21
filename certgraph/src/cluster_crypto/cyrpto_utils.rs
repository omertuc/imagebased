use rsa::{self, pkcs8::EncodePrivateKey};

use x509_certificate::InMemorySigningKeyPair;

use rsa::RsaPrivateKey;

pub(crate) fn generate_rsa_key(rng: &mut rand::prelude::ThreadRng) -> (RsaPrivateKey, InMemorySigningKeyPair) {
    let rsa_private_key = rsa::RsaPrivateKey::new(rng, 2048).unwrap();
    let rsa_pkcs8_der_bytes: Vec<u8> = rsa_private_key.to_pkcs8_der().unwrap().as_bytes().into();
    let key_pair = InMemorySigningKeyPair::from_pkcs8_der(&rsa_pkcs8_der_bytes).unwrap();
    (rsa_private_key, key_pair)
}

