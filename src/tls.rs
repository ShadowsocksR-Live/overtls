use crate::error::Result;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::{fs::File, io::BufReader, net::SocketAddr, path::Path};
use tokio::net::TcpStream;
use tokio_rustls::{
    client::TlsStream,
    rustls::{ClientConfig, RootCertStore},
    TlsConnector,
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

pub(crate) async fn create_tls_client_stream(
    root_cert_store: RootCertStore,
    addr: SocketAddr,
    domain: &str,
) -> Result<TlsStream<TcpStream>> {
    let config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
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
