use std::collections::HashSet;

use lazy_static::lazy_static;

lazy_static! {
    pub(crate) static ref IGNORE_LIST_CONFIGMAP: HashSet<String> = vec![
        "verifier-public-key-redhat",
        "service-account-001.pub",
        "service-account-002.pub",
        // "ca-bundle.crt"
    ]
        .into_iter()
        .map(str::to_string)
        .collect();

    pub(crate) static ref IGNORE_LIST_SECRET: HashSet<String> = vec![
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
    pub(crate) static ref KNOWN_MISSING_PRIVATE_KEY_CERTS: HashSet<String> = vec![
        "OU=openshift, CN=admin-kubeconfig-signer",
        "OU=openshift, CN=kubelet-bootstrap-kubeconfig-signer", // TODO: Verify
        "OU=openshift, CN=root-ca" // TODO: Verify
    ]
        .into_iter()
        .map(str::to_string)
        .collect();

    pub(crate) static ref EXTERNAL_CERTS: HashSet<String> = vec![
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
