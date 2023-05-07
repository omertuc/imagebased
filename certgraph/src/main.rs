use std::{
    collections::{
        hash_map::Entry::{Occupied, Vacant},
        HashMap, HashSet,
    },
    fmt::{Debug, Display},
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use base64::Engine as _;

use lazy_static::lazy_static;
use serde_json::Value;

use rsa::{pkcs1::DecodeRsaPrivateKey, RsaPrivateKey, RsaPublicKey};
use x509_parser::public_key::RSAPublicKey;

lazy_static! {
    static ref IGNORE_LIST_CONFIGMAP: HashSet<String> = vec![
        "verifier-public-key-redhat",
        "service-account-001.pub",
        "service-account-002.pub",
        // "ca-bundle.crt"
    ]
        .into_iter()
        .map(str::to_string)
        .collect();

    static ref IGNORE_LIST_SECRET: HashSet<String> = vec![
        "prometheus.yaml.gz",
        "alertmanager.yaml.gz",
        "entitlement.pem",
        "entitlement-key.pem",
    ]
        .into_iter()
        .map(str::to_string)
        .collect();

    // It's okay for some certs to not have a private key, because they are only used for signing a
    // single cert, and not for signing anything else, so their private key gets thrown away
    // sometime during installation. For us it just means we still have to recreate them, we just
    // don't have to record them back to the filesystem or etcd.
    static ref KNOWN_MISSING_PRIVATE_KEY_CERTS: HashSet<String> = vec![
        "OU=openshift, CN=admin-kubeconfig-signer",
        "OU=openshift, CN=kubelet-bootstrap-kubeconfig-signer", // TODO: Verify
        "OU=openshift, CN=root-ca" // TODO: Verify
    ]
        .into_iter()
        .map(str::to_string)
        .collect();

    static ref EXTERNAL_CERTS: HashSet<String> = vec![
        "CN=ACCVRAIZ1, OU=PKIACCV, O=ACCV, C=ES",
        "C=ES, O=FNMT-RCM, OU=AC RAIZ FNMT-RCM",
        "C=ES, O=FNMT-RCM, OU=Ceres/organizationIdentifier=VATES-Q2826004J, CN=AC RAIZ FNMT-RCM SERVIDORES SEGUROS",
        "serialNumber=G63287510, C=ES, O=ANF Autoridad de Certificacion, OU=ANF CA Raiz, CN=ANF Secure Server Root CA",
        "C=IT, L=Milan, O=Actalis S.p.A./03358520967, CN=Actalis Authentication Root CA",
        "C=US, O=AffirmTrust, CN=AffirmTrust Commercial",
        "C=US, O=AffirmTrust, CN=AffirmTrust Networking",
        "C=US, O=AffirmTrust, CN=AffirmTrust Premium",
        "C=US, O=AffirmTrust, CN=AffirmTrust Premium ECC",
        "C=US, O=Amazon, CN=Amazon Root CA 1",
        "C=US, O=Amazon, CN=Amazon Root CA 2",
        "C=US, O=Amazon, CN=Amazon Root CA 3",
        "C=US, O=Amazon, CN=Amazon Root CA 4",
        "CN=Atos TrustedRoot 2011, O=Atos, C=DE",
        "C=ES, CN=Autoridad de Certificacion Firmaprofesional CIF A62634068",
        "C=ES, CN=Autoridad de Certificacion Firmaprofesional CIF A62634068",
        "C=IE, O=Baltimore, OU=CyberTrust, CN=Baltimore CyberTrust Root",
        "C=NO, O=Buypass AS-983163327, CN=Buypass Class 2 Root CA",
        "C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 Root CA",
        "C=SK, L=Bratislava, O=Disig a.s., CN=CA Disig Root R2",
        "C=CN, O=China Financial Certification Authority, CN=CFCA EV ROOT",
        "C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO Certification Authority",
        "C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO ECC Certification Authority",
        "C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Certification Authority",
        "C=FR, O=Dhimyotis, CN=Certigna",
        "C=FR, O=Dhimyotis, OU=0002 48146308100036, CN=Certigna Root CA",
        "C=PL, O=Asseco Data Systems S.A., OU=Certum Certification Authority, CN=Certum EC-384 CA",
        "C=PL, O=Unizeto Technologies S.A., OU=Certum Certification Authority, CN=Certum Trusted Network CA",
        "C=PL, O=Unizeto Technologies S.A., OU=Certum Certification Authority, CN=Certum Trusted Network CA 2",
        "C=PL, O=Asseco Data Systems S.A., OU=Certum Certification Authority, CN=Certum Trusted Root CA",
        "C=GB, ST=Greater Manchester, L=Salford, O=Comodo CA Limited, CN=AAA Certificate Services",
        "C=DE, O=D-Trust GmbH, CN=D-TRUST BR Root CA 1 2020",
        "C=DE, O=D-Trust GmbH, CN=D-TRUST EV Root CA 1 2020",
        "C=DE, O=D-Trust GmbH, CN=D-TRUST Root Class 3 CA 2 2009",
        "C=DE, O=D-Trust GmbH, CN=D-TRUST Root Class 3 CA 2 EV 2009",
        "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root CA",
        "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root G2",
        "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root G3",
        "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root CA",
        "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2",
        "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G3",
        "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance EV Root CA",
        "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Trusted Root G4",
        "C=TR, L=Ankara, O=E-Tuğra EBG Bilişim Teknolojileri ve Hizmetleri A.Ş., OU=E-Tugra Sertifikasyon Merkezi, CN=E-Tugra Certification Authority",
        "C=ES, O=Agencia Catalana de Certificacio (NIF Q-0801176-I), OU=Serveis Publics de Certificacio, OU=Vegeu https://www.catcert.net/verarrel (c)03, OU=Jerarquia Entitats de Certificacio Catalanes, CN=EC-ACC",
        "O=Entrust.net, OU=www.entrust.net/CPS_2048 incorp. by ref. (limits liab.), OU=(c) 1999 Entrust.net Limited, CN=Entrust.net Certification Authority (2048)",
        "C=US, O=Entrust, Inc., OU=www.entrust.net/CPS is incorporated by reference, OU=(c) 2006 Entrust, Inc., CN=Entrust Root Certification Authority",
        "C=US, O=Entrust, Inc., OU=See www.entrust.net/legal-terms, OU=(c) 2012 Entrust, Inc. - for authorized use only, CN=Entrust Root Certification Authority - EC1",
        "C=US, O=Entrust, Inc., OU=See www.entrust.net/legal-terms, OU=(c) 2009 Entrust, Inc. - for authorized use only, CN=Entrust Root Certification Authority - G2",
        "C=US, O=Entrust, Inc., OU=See www.entrust.net/legal-terms, OU=(c) 2015 Entrust, Inc. - for authorized use only, CN=Entrust Root Certification Authority - G4",
        "C=ES, O=FNMT-RCM, OU=AC RAIZ FNMT-RCM",
        "C=CN, O=GUANG DONG CERTIFICATE AUTHORITY CO.,LTD., CN=GDCA TrustAUTH R5 ROOT",
        "C=AT, O=e-commerce monitoring GmbH, CN=GLOBALTRUST 2020",
        "C=US, O=Google Trust Services LLC, CN=GTS Root R1",
        "C=US, O=Google Trust Services LLC, CN=GTS Root R2",
        "C=US, O=Google Trust Services LLC, CN=GTS Root R3",
        "C=US, O=Google Trust Services LLC, CN=GTS Root R4",
        "OU=GlobalSign ECC Root CA - R5, O=GlobalSign, CN=GlobalSign",
        "C=BE, O=GlobalSign nv-sa, OU=Root CA, CN=GlobalSign Root CA",
        "OU=GlobalSign Root CA - R3, O=GlobalSign, CN=GlobalSign",
        "OU=GlobalSign Root CA - R6, O=GlobalSign, CN=GlobalSign",
        "C=BE, O=GlobalSign nv-sa, CN=GlobalSign Root E46",
        "C=BE, O=GlobalSign nv-sa, CN=GlobalSign Root R46",
        "C=US, O=The Go Daddy Group, Inc., OU=Go Daddy Class 2 Certification Authority",
        "C=US, ST=Arizona, L=Scottsdale, O=GoDaddy.com, Inc., CN=Go Daddy Root Certificate Authority - G2",
        "C=GR, O=Hellenic Academic and Research Institutions CA, CN=HARICA TLS ECC Root CA 2021",
        "C=GR, O=Hellenic Academic and Research Institutions CA, CN=HARICA TLS RSA Root CA 2021",
        "C=GR, L=Athens, O=Hellenic Academic and Research Institutions Cert. Authority, CN=Hellenic Academic and Research Institutions ECC RootCA 2015",
        "C=GR, O=Hellenic Academic and Research Institutions Cert. Authority, CN=Hellenic Academic and Research Institutions RootCA 2011",
        "C=GR, L=Athens, O=Hellenic Academic and Research Institutions Cert. Authority, CN=Hellenic Academic and Research Institutions RootCA 2015",
        "C=TW, O=Chunghwa Telecom Co., Ltd., CN=HiPKI Root CA - G1",
        "C=HK, O=Hongkong Post, CN=Hongkong Post Root CA 1",
        "C=HK, ST=Hong Kong, L=Hong Kong, O=Hongkong Post, CN=Hongkong Post Root CA 3",
        "C=US, O=Internet Security Research Group, CN=ISRG Root X1",
        "C=US, O=Internet Security Research Group, CN=ISRG Root X2",
        "C=US, O=IdenTrust, CN=IdenTrust Commercial Root CA 1",
        "C=US, O=IdenTrust, CN=IdenTrust Public Sector Root CA 1",
        "C=ES, O=IZENPE S.A., CN=Izenpe.com",
        "C=HU, L=Budapest, O=Microsec Ltd., CN=Microsec e-Szigno Root CA 2009, Email=info@e-szigno.hu",
        "C=US, O=Microsoft Corporation, CN=Microsoft ECC Root Certificate Authority 2017",
        "C=US, O=Microsoft Corporation, CN=Microsoft RSA Root Certificate Authority 2017",
        "C=KR, O=NAVER BUSINESS PLATFORM Corp., CN=NAVER Global Root Certification Authority",
        "C=HU, L=Budapest, O=NetLock Kft., OU=Tanúsítványkiadók (Certification Services), CN=NetLock Arany (Class Gold) Főtanúsítvány",
        "C=US, O=Network Solutions L.L.C., CN=Network Solutions Certificate Authority",
        "C=CH, O=WISeKey, OU=OISTE Foundation Endorsed, CN=OISTE WISeKey Global Root GB CA",
        "C=CH, O=WISeKey, OU=OISTE Foundation Endorsed, CN=OISTE WISeKey Global Root GC CA",
        "C=BM, O=QuoVadis Limited, CN=QuoVadis Root CA 1 G3",
        "C=BM, O=QuoVadis Limited, CN=QuoVadis Root CA 2",
        "C=BM, O=QuoVadis Limited, CN=QuoVadis Root CA 2 G3",
        "C=BM, O=QuoVadis Limited, CN=QuoVadis Root CA 3",
        "C=BM, O=QuoVadis Limited, CN=QuoVadis Root CA 3 G3",
        "C=US, ST=Texas, L=Houston, O=SSL Corporation, CN=SSL.com EV Root Certification Authority ECC",
        "C=US, ST=Texas, L=Houston, O=SSL Corporation, CN=SSL.com EV Root Certification Authority RSA R2",
        "C=US, ST=Texas, L=Houston, O=SSL Corporation, CN=SSL.com Root Certification Authority ECC",
        "C=US, ST=Texas, L=Houston, O=SSL Corporation, CN=SSL.com Root Certification Authority RSA",
        "C=PL, O=Krajowa Izba Rozliczeniowa S.A., CN=SZAFIR ROOT CA2",
        "C=JP, O=Japan Certification Services, Inc., CN=SecureSign RootCA11",
        "C=US, O=SecureTrust Corporation, CN=SecureTrust CA",
        "C=US, O=SecureTrust Corporation, CN=Secure Global CA",
        "C=JP, O=SECOM Trust Systems CO.,LTD., OU=Security Communication RootCA2",
        "C=JP, O=SECOM Trust.net, OU=Security Communication RootCA1",
        "C=NL, O=Staat der Nederlanden, CN=Staat der Nederlanden EV Root CA",
        "C=US, O=Starfield Technologies, Inc., OU=Starfield Class 2 Certification Authority",
        "C=US, ST=Arizona, L=Scottsdale, O=Starfield Technologies, Inc., CN=Starfield Root Certificate Authority - G2",
        "C=US, ST=Arizona, L=Scottsdale, O=Starfield Technologies, Inc., CN=Starfield Services Root Certificate Authority - G2",
        "C=CH, O=SwissSign AG, CN=SwissSign Gold CA - G2",
        "C=CH, O=SwissSign AG, CN=SwissSign Silver CA - G2",
        "C=DE, O=T-Systems Enterprise Services GmbH, OU=T-Systems Trust Center, CN=T-TeleSec GlobalRoot Class 2",
        "C=DE, O=T-Systems Enterprise Services GmbH, OU=T-Systems Trust Center, CN=T-TeleSec GlobalRoot Class 3",
        "C=TR, L=Gebze - Kocaeli, O=Turkiye Bilimsel ve Teknolojik Arastirma Kurumu - TUBITAK, OU=Kamu Sertifikasyon Merkezi - Kamu SM, CN=TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1",
        "C=TW, O=TAIWAN-CA, OU=Root CA, CN=TWCA Global Root CA",
        "C=TW, O=TAIWAN-CA, OU=Root CA, CN=TWCA Root Certification Authority",
        "O=TeliaSonera, CN=TeliaSonera Root CA v1",
        "C=FI, O=Telia Finland Oyj, CN=Telia Root CA v2",
        "C=PA, ST=Panama, L=Panama City, O=TrustCor Systems S. de R.L., OU=TrustCor Certificate Authority, CN=TrustCor ECA-1",
        "C=PA, ST=Panama, L=Panama City, O=TrustCor Systems S. de R.L., OU=TrustCor Certificate Authority, CN=TrustCor RootCert CA-1",
        "C=PA, ST=Panama, L=Panama City, O=TrustCor Systems S. de R.L., OU=TrustCor Certificate Authority, CN=TrustCor RootCert CA-2",
        "C=US, ST=Illinois, L=Chicago, O=Trustwave Holdings, Inc., CN=Trustwave Global Certification Authority",
        "C=US, ST=Illinois, L=Chicago, O=Trustwave Holdings, Inc., CN=Trustwave Global ECC P256 Certification Authority",
        "C=US, ST=Illinois, L=Chicago, O=Trustwave Holdings, Inc., CN=Trustwave Global ECC P384 Certification Authority",
        "C=TN, O=Agence Nationale de Certification Electronique, CN=TunTrust Root CA",
        "C=CN, O=UniTrust, CN=UCA Extended Validation Root",
        "C=CN, O=UniTrust, CN=UCA Global G2 Root",
        "C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority",
        "C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust RSA Certification Authority",
        "C=US, OU=www.xrampsecurity.com, O=XRamp Security Services Inc, CN=XRamp Global Certification Authority",
        "C=RO, O=certSIGN, OU=certSIGN ROOT CA",
        "C=RO, O=CERTSIGN SA, OU=certSIGN ROOT CA G2",
        "C=HU, L=Budapest, O=Microsec Ltd./organizationIdentifier=VATHU-23584497, CN=e-Szigno Root CA 2017",
        "C=TW, O=Chunghwa Telecom Co., Ltd., OU=ePKI Root Certification Authority",
        "C=US, OU=emSign PKI, O=eMudhra Inc, CN=emSign ECC Root CA - C3",
        "C=IN, OU=emSign PKI, O=eMudhra Technologies Limited, CN=emSign ECC Root CA - G3",
        "C=US, OU=emSign PKI, O=eMudhra Inc, CN=emSign Root CA - C1",
        "C=IN, OU=emSign PKI, O=eMudhra Technologies Limited, CN=emSign Root CA - G1",
        "C=CN, O=iTrusChina Co.,Ltd., CN=vTrus ECC Root CA",
        "C=CN, O=iTrusChina Co.,Ltd., CN=vTrus Root CA",
    ]
        .into_iter()
        .map(str::to_string)
        .collect();
}

fn main() {
    let root_dir = PathBuf::from(".");

    let mut graph = CryptoGraph {
        public_to_private: HashMap::new(),
        identity_to_public: HashMap::new(),
        ca_certs: HashSet::new(),
        root_certs: HashMap::new(),
        keys: HashSet::new(),
        cert_to_private_key: HashMap::new(),
    };

    for allow_incomplete in [true, false] {
        process_etcd_dump(
            &root_dir.join("gathers/first/etcd"),
            &mut graph,
            allow_incomplete,
        );
        process_k8s_dir_dump(
            &root_dir.join("gathers/first/kubernetes"),
            &mut graph,
            allow_incomplete,
        );
    }
}

fn globvec(location: &Path, globstr: &str) -> Vec<PathBuf> {
    let mut globoptions = glob::MatchOptions::new();
    globoptions.require_literal_leading_dot = true;

    glob::glob_with(location.join(globstr).to_str().unwrap(), globoptions)
        .unwrap()
        .map(|x| x.unwrap())
        .collect::<Vec<_>>()
}

fn process_etcd_dump(etcd_dump_dir: &PathBuf, graph: &mut CryptoGraph, allow_incomplete: bool) {
    process_k8s_yamls(etcd_dump_dir, graph, allow_incomplete);
}

fn process_k8s_dir_dump(k8s_dir: &PathBuf, graph: &mut CryptoGraph, allow_incomplete: bool) {
    // process_k8s_yamls(k8s_dir, graph, allow_incomplete);
    process_pems(k8s_dir, graph, allow_incomplete);
}

enum Location {
    K8s(K8sLocation),
    Filesystem(FileLocation),
}

impl Debug for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::K8s(arg0) => f.debug_tuple("K8s").field(arg0).finish(),
            Self::Filesystem(arg0) => f.debug_tuple("Filesystem").field(arg0).finish(),
        }
    }
}

impl Location {
    fn with_pem_bundle_index(&self, pem_bundle_index: u64) -> Self {
        match self {
            Self::K8s(k8s_location) => {
                let mut new_k8s_location = k8s_location.clone();
                new_k8s_location.yaml_location.pem_location.pem_bundle_index =
                    Some(pem_bundle_index);
                Self::K8s(new_k8s_location)
            }
            Self::Filesystem(file_location) => match file_location {
                FileLocation::Raw(pem_location_info) => {
                    let mut new_pem_location_info = pem_location_info.clone();
                    new_pem_location_info.pem_bundle_index = Some(pem_bundle_index);
                    Self::Filesystem(FileLocation::Raw(new_pem_location_info))
                }
                FileLocation::YAML(yaml_location) => {
                    let mut new_yaml_location = yaml_location.clone();
                    new_yaml_location.pem_location.pem_bundle_index = Some(pem_bundle_index);
                    Self::Filesystem(FileLocation::YAML(new_yaml_location))
                }
            },
        }
    }
}

#[derive(Debug, Clone)]
struct PemLocationInfo {
    pem_bundle_index: Option<u64>,
}

#[derive(Debug, Clone)]
enum FileLocation {
    Raw(PemLocationInfo),
    YAML(YamlLocation),
}

#[derive(Debug, Clone)]
struct YamlLocation {
    json_path: String,
    pem_location: PemLocationInfo,
}

#[derive(Debug, Clone)]
struct K8sResourceLocation {
    namespace: String,
    kind: String,
    name: String,
}

#[derive(Debug, Clone)]
struct K8sLocation {
    resource_location: K8sResourceLocation,
    yaml_location: YamlLocation,
}

#[derive(Clone)]
enum PrivateKey {
    Rsa(RsaPrivateKey),
}

#[derive(Hash, Eq, PartialEq)]
enum PublicKey {
    Rsa(RsaPublicKey),
}

impl PublicKey {
    fn from_rsa(rsa_public_key: &RSAPublicKey) -> PublicKey {
        let modulus = rsa::BigUint::from_bytes_be(&rsa_public_key.modulus);
        let exponent = rsa::BigUint::from_bytes_be(&rsa_public_key.exponent);

        PublicKey::Rsa(RsaPublicKey::new(modulus, exponent).unwrap())
    }
}

#[allow(clippy::large_enum_variant)]
enum Key {
    PrivateKey(Location, PrivateKey),
    PublicKey(Location, String),
}

struct CryptoGraph {
    public_to_private: HashMap<PublicKey, PrivateKey>,
    identity_to_public: HashMap<String, String>,
    ca_certs: HashSet<String>,
    keys: HashSet<Key>,
    cert_to_private_key: HashMap<String, PrivateKey>,

    // Maps root cert to a list of certificates signed by it
    root_certs: HashMap<String, Vec<String>>,
}

impl Display for CryptoGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (root_cert, signed_certs) in &self.root_certs {
            for signed_cert in signed_certs {
                writeln!(f, "  \"{}\" -> \"{}\" ", root_cert, signed_cert,)?;
            }
        }
        Ok(())
    }
}

fn process_k8s_yamls(gather_dir: &PathBuf, graph: &mut CryptoGraph, allow_incomplete: bool) {
    let all_yaml_files = globvec(&gather_dir, "**/*.yaml");

    all_yaml_files.iter().for_each(|yaml_path| {
        process_k8s_yaml(yaml_path.to_path_buf(), graph, allow_incomplete);
    });
}

fn process_pems(gather_dir: &PathBuf, graph: &mut CryptoGraph, allow_incomplete: bool) {
    globvec(gather_dir, "**/*.pem")
        .into_iter()
        .chain(globvec(gather_dir, "**/*.crt").into_iter())
        .chain(globvec(gather_dir, "**/*.key").into_iter())
        .chain(globvec(gather_dir, "**/*.pub").into_iter())
        .for_each(|pem_path| {
            process_pem(&pem_path, graph, allow_incomplete);
        });
}

fn process_pem(pem_file_path: &PathBuf, graph: &mut CryptoGraph, allow_incomplete: bool) {
    let mut file = fs::File::open(pem_file_path).expect("failed to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("failed to read file");
    unpem(
        &contents,
        graph,
        true,
        &Location::Filesystem(FileLocation::Raw(PemLocationInfo {
            pem_bundle_index: None,
        })),
    );
}

fn process_k8s_yaml(yaml_path: PathBuf, crypto_graph: &mut CryptoGraph, allow_incomplete: bool) {
    let mut file = fs::File::open(yaml_path.clone()).expect("failed to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("failed to read file");
    let value: Value = serde_yaml::from_str(&contents).expect("failed to parse yaml");

    scan_k8s_resource(&value, crypto_graph, allow_incomplete);
}

fn scan_k8s_secret(
    value: &Value,
    graph: &mut CryptoGraph,
    allow_incomplete: bool,
    k8s_resource_location: &K8sResourceLocation,
) {
    if let Some(data) = value.as_object().unwrap().get("data") {
        match data {
            Value::Object(data) => {
                for (key, value) in data.iter() {
                    if IGNORE_LIST_SECRET.contains(key) {
                        continue;
                    }

                    if let Value::String(value) = value {
                        if let Ok(value) =
                            base64::engine::general_purpose::STANDARD.decode(value.as_bytes())
                        {
                            let value = String::from_utf8(value).unwrap_or_else(|_| {
                                panic!("Failed to decode base64 {}", key);
                            });

                            unpem(
                                &value,
                                graph,
                                allow_incomplete,
                                &Location::K8s(K8sLocation {
                                    resource_location: k8s_resource_location.clone(),
                                    yaml_location: YamlLocation {
                                        json_path: format!(".data.\"{key}\""),
                                        pem_location: PemLocationInfo {
                                            pem_bundle_index: None,
                                        },
                                    },
                                }),
                            );
                        } else {
                            dbg!("Failed to decode base64 {}", value);
                        }
                    }
                }
            }
            _ => todo!(),
        }
    }
}

fn unpem(value: &str, graph: &mut CryptoGraph, allow_incomplete: bool, location: &Location) {
    let pems = pem::parse_many(value).unwrap();
    for (i, pem) in pems.iter().enumerate() {
        let location = location.with_pem_bundle_index(i.try_into().unwrap());

        dbg!(location);

        match pem.tag() {
            "CERTIFICATE" => {
                let x509_certificate = x509_parser::parse_x509_certificate(pem.contents())
                    .unwrap()
                    .1;

                if is_self_signed(&x509_certificate) {
                    graph_root_ca(graph, &x509_certificate);
                }

                match x509_certificate.public_key().parsed().unwrap() {
                    x509_parser::public_key::PublicKey::RSA(key) => {
                        handle_cert_subject_rsa_public_key(
                            key,
                            &x509_certificate,
                            graph,
                            allow_incomplete,
                        );
                    }
                    x509_parser::public_key::PublicKey::EC(_key) => {
                        handle_cert_subject_ec_public_key();
                    }
                    _ => {
                        panic!("unknown public key type");
                    }
                }
            }
            "RSA PUBLIC KEY" => {
                // panic!("found pem raw public key");
            }
            "RSA PRIVATE KEY" => {
                let x = rsa::RsaPrivateKey::from_pkcs1_pem(&pem.to_string()).unwrap();

                let public = PublicKey::Rsa(x.to_public_key());
                let private = PrivateKey::Rsa(x.clone());

                graph.public_to_private.insert(public, private);

                dbg!("Found private key");
                // panic!("done");
                // panic!("found private key");
            }
            "PRIVATE KEY" => {
                dbg!("Non-RSA private key");
            }
            "ENTITLEMENT DATA" => {
                dbg!("Entitlement");
            }
            "EC PRIVATE KEY" => {
                dbg!("EC Private key");
            }
            "RSA SIGNATURE" => {
                dbg!("RSA Sig");
            }
            _ => {
                panic!("unknown pem tag {}", pem.tag());
            }
        }
    }
}

fn handle_cert_subject_ec_public_key() {}

fn handle_cert_subject_rsa_public_key(
    public_key: x509_parser::public_key::RSAPublicKey,
    x509_certificate: &x509_parser::prelude::X509Certificate,
    graph: &mut CryptoGraph,
    allow_incomplete: bool,
) {
    let issuer = &x509_certificate.issuer();
    if let Vacant(_entry) = graph.root_certs.entry(issuer.to_string()) {
        if !allow_incomplete {
            panic!("Encountered signed cert before encountering its root");
        }
    } else {
        graph
            .root_certs
            .get_mut(&issuer.to_string())
            .unwrap()
            .push(x509_certificate.subject().to_string());
    }

    if let Occupied(entry) = graph
        .public_to_private
        .entry(PublicKey::from_rsa(&public_key))
    {
        graph
            .cert_to_private_key
            .insert(x509_certificate.subject().to_string(), entry.get().clone());
    } else if !allow_incomplete
        && !KNOWN_MISSING_PRIVATE_KEY_CERTS.contains(&x509_certificate.subject().to_string())
        && !EXTERNAL_CERTS.contains(&x509_certificate.subject().to_string())
    {
        panic!(
            "Could not find private key for certificate subject public key: {}",
            x509_certificate.subject()
        );
    }
}

fn graph_root_ca(
    graph: &mut CryptoGraph,
    x509_certificate: &x509_parser::prelude::X509Certificate,
) {
    if let Vacant(entry) = graph
        .root_certs
        .entry(x509_certificate.issuer().to_string())
    {
        entry.insert(vec![]);
    } else {
        graph
            .root_certs
            .get_mut(&x509_certificate.issuer().to_string())
            .unwrap()
            .push(x509_certificate.subject().to_string());
    }
}

fn is_self_signed(x509_certificate: &x509_parser::prelude::X509Certificate) -> bool {
    x509_certificate.verify_signature(None).is_ok()
}

fn scan_k8s_resource(value: &Value, graph: &mut CryptoGraph, allow_incomplete: bool) {
    let _path = get_resource_path(value);

    let location = K8sResourceLocation {
        namespace: value
            .as_object()
            .unwrap()
            .get("metadata")
            .unwrap()
            .get("namespace")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string(),
        kind: value
            .as_object()
            .unwrap()
            .get("kind")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string(),
        name: value
            .as_object()
            .unwrap()
            .get("metadata")
            .unwrap()
            .get("name")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string(),
    };

    match value
        .as_object()
        .unwrap()
        .get("kind")
        .unwrap()
        .as_str()
        .unwrap()
    {
        "Secret" => scan_k8s_secret(value, graph, allow_incomplete, &location),
        "ConfigMap" => scan_configmap(value, graph, allow_incomplete, &location),
        _ => (),
    }
}

fn scan_configmap(
    value: &Value,
    graph: &mut CryptoGraph,
    allow_incomplete: bool,
    k8s_resource_location: &K8sResourceLocation,
) {
    if let Some(data) = value.as_object().unwrap().get("data") {
        match data {
            Value::Object(data) => {
                for (key, value) in data.iter() {
                    if IGNORE_LIST_CONFIGMAP.contains(key) {
                        continue;
                    }
                    if let Value::String(value) = value {
                        unpem(
                            &value,
                            graph,
                            allow_incomplete,
                            &Location::K8s(K8sLocation {
                                resource_location: k8s_resource_location.clone(),
                                yaml_location: YamlLocation {
                                    json_path: format!(".data.\"{key}\""),
                                    pem_location: PemLocationInfo {
                                        pem_bundle_index: None,
                                    },
                                },
                            }),
                        );
                    }
                }
            }
            _ => todo!(),
        }
    }
}

fn get_resource_path(value: &Value) -> std::string::String {
    if let Some(metadata) = value.as_object().unwrap().get("metadata") {
        let namespace = if let Some(namespace) = metadata.as_object().unwrap().get("namespace") {
            namespace.as_str().unwrap()
        } else {
            "cluster-scoped"
        };

        let api_version = value
            .as_object()
            .unwrap()
            .get("apiVersion")
            .unwrap()
            .as_str()
            .unwrap();

        let kind = value
            .as_object()
            .unwrap()
            .get("kind")
            .unwrap()
            .as_str()
            .unwrap();

        let name = if let Some(name) = metadata.as_object().unwrap().get("name") {
            name.as_str().unwrap()
        } else {
            "<list>"
        };

        return format!("{}/{}/{}/{}", api_version, kind, namespace, name);
    }

    panic!("no metadata found");
}
