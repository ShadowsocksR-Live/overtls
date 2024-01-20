use crate::error::Result;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    RootCertStore,
};
use std::{
    fs::File,
    io::BufReader,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};

pub(crate) fn retrieve_root_cert_store_for_client(cafile: &Option<PathBuf>) -> Result<RootCertStore> {
    let mut root_cert_store = rustls::RootCertStore::empty();
    let mut done = false;
    if let Some(cafile) = cafile {
        if cafile.exists() {
            let mut pem = BufReader::new(File::open(cafile)?);
            for cert in rustls_pemfile::certs(&mut pem) {
                root_cert_store.add(cert?)?;
            }
            done = true;
        }
    }
    if !done {
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    Ok(root_cert_store)
}

pub(crate) async fn create_tls_client_stream(
    root_cert_store: RootCertStore,
    addr: SocketAddr,
    domain: &str,
) -> Result<TlsStream<TcpStream>> {
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(config));

    let stream = crate::tcp_stream::create(addr).await?;

    let domain = ServerName::try_from(domain)?.to_owned();

    let stream = connector.connect(domain, stream).await?;

    Ok(stream)
}

pub(crate) fn server_load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut res = vec![];
    for cert in rustls_pemfile::certs(&mut BufReader::new(File::open(path)?)) {
        res.push(cert?);
    }
    Ok(res)
}

pub(crate) fn server_load_keys(path: &Path) -> Result<Vec<PrivateKeyDer<'static>>> {
    let mut res = vec![];
    for key in rustls_pemfile::rsa_private_keys(&mut BufReader::new(File::open(path)?)) {
        res.push(PrivateKeyDer::from(key?));
    }
    Ok(res)
}
