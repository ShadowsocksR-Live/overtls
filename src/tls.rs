use crate::{Error, error::Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::{fs::File, io::BufReader, net::SocketAddr, path::Path};
use tokio::net::TcpStream;
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{ClientConfig, RootCertStore},
};

//
// https://github.com/rustls/tokio-rustls/blob/main/examples/client.rs
//

pub(crate) fn retrieve_root_cert_store_for_client(ca_content: &Option<String>) -> Result<RootCertStore> {
    let mut root_cert_store = RootCertStore::empty();
    if let Some(ca_content) = ca_content {
        let mut pem = std::io::Cursor::new(ca_content.as_bytes());
        for cert in rustls_pemfile::certs(&mut pem) {
            match cert {
                Ok(cert) => root_cert_store.add(cert)?,
                Err(e) => log::error!("Error parsing certificate: {:?}", e),
            }
        }
    }
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(root_cert_store)
}

static CHROME_CIPHERS: &[rustls::SupportedCipherSuite] = &[
    // TLS 1.3 cipher suits
    rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
    rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    // TLS 1.2 cipher suits
    rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
];

pub(crate) async fn create_tls_client_stream(
    root_cert_store: RootCertStore,
    addr: SocketAddr,
    domain: &str,
) -> Result<TlsStream<TcpStream>> {
    // Clone default CryptoProvider
    let default_provider = rustls::crypto::ring::default_provider();

    // Create a custom CryptoProvider with Chrome-compatible cipher suites
    let crypto_provider = rustls::crypto::CryptoProvider {
        cipher_suites: CHROME_CIPHERS.to_vec(),
        ..default_provider
    };

    // Build ClientConfig with custom CryptoProvider
    let mut config = ClientConfig::builder_with_provider(crypto_provider.into())
        .with_safe_default_protocol_versions() // Use default protocol versions (TLS 1.2 and TLS 1.3)
        .map_err(|e| Error::from(format!("Failed to set protocol versions: {e}")))?
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    // Add ALPN protocols to mimic Chrome (HTTP/2 and HTTP/1.1)
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let connector = TlsConnector::from(std::sync::Arc::new(config));

    let stream = crate::tcp_stream::tokio_create(addr).await?;

    let domain = ServerName::try_from(domain)?.to_owned();

    let stream = connector.connect(domain, stream).await?;

    Ok(stream)
}

pub(crate) fn server_load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut res = vec![];
    for cert in rustls_pemfile::certs(&mut BufReader::new(File::open(path)?)) {
        res.push(cert?);
    }
    if res.is_empty() {
        return Err("No certificates found".into());
    }
    Ok(res)
}

pub(crate) fn server_load_keys(path: &Path) -> Result<Vec<PrivateKeyDer<'static>>> {
    let mut res = vec![];
    for key in rustls_pemfile::rsa_private_keys(&mut BufReader::new(File::open(path)?)) {
        res.push(PrivateKeyDer::from(key?));
    }
    for key in rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(path)?)) {
        res.push(PrivateKeyDer::from(key?));
    }
    for key in rustls_pemfile::ec_private_keys(&mut BufReader::new(File::open(path)?)) {
        res.push(PrivateKeyDer::from(key?));
    }
    if res.is_empty() {
        return Err("No keys found".into());
    }
    Ok(res)
}
