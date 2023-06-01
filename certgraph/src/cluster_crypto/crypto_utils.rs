use rsa::{
    self,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    RsaPrivateKey,
};
use x509_certificate::InMemorySigningKeyPair;

pub(crate) fn generate_rsa_key() -> (RsaPrivateKey, InMemorySigningKeyPair) {
    let rsa_private_key = RsaPrivateKey::from_pkcs8_pem(
        String::from_utf8_lossy(
            &std::process::Command::new("openssl")
                .args(&["genrsa", "2048"])
                .output()
                .expect("failed to execute openssl")
                .stdout,
        )
        .to_string()
        .as_str(),
    )
    .unwrap();

    let rsa_pkcs8_der_bytes: Vec<u8> = rsa_private_key.to_pkcs8_der().unwrap().as_bytes().into();
    let key_pair = InMemorySigningKeyPair::from_pkcs8_der(&rsa_pkcs8_der_bytes).unwrap();
    (rsa_private_key, key_pair)
}
