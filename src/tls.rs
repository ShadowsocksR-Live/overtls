use rustls::RootCertStore;
use rustls_pemfile::{certs, rsa_private_keys};
use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};
use tokio::{
    io,
    net::{TcpStream, ToSocketAddrs},
};
use tokio_rustls::{
    client::TlsStream,
    rustls::{self, Certificate, OwnedTrustAnchor, PrivateKey},
    webpki, TlsConnector,
};

pub fn retrieve_root_cert_store_for_client(cafile: &Option<PathBuf>) -> anyhow::Result<RootCertStore> {
    let mut root_cert_store = rustls::RootCertStore::empty();
    let mut done = false;
    if let Some(cafile) = cafile {
        if cafile.exists() {
            let mut pem = BufReader::new(File::open(cafile)?);
            let certs = rustls_pemfile::certs(&mut pem)?;
            let trust_anchors = certs.iter().map(|cert| {
                if let Ok(ta) = webpki::TrustAnchor::try_from_cert_der(&cert[..]) {
                    OwnedTrustAnchor::from_subject_spki_name_constraints(ta.subject, ta.spki, ta.name_constraints)
                } else {
                    OwnedTrustAnchor::from_subject_spki_name_constraints(vec![], vec![], Some(vec![]))
                }
            });
            root_cert_store.add_server_trust_anchors(trust_anchors);
            done = true;
        }
    }
    if !done {
        root_cert_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(ta.subject, ta.spki, ta.name_constraints)
            }),
        );
    }
    Ok(root_cert_store)
}

pub async fn create_tls_client_stream<A: ToSocketAddrs>(
    root_cert_store: RootCertStore,
    addr: A,
    domain: &str,
) -> anyhow::Result<TlsStream<TcpStream>> {
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(config));

    let stream = TcpStream::connect(addr).await?;

    let domain = rustls::ServerName::try_from(domain)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;

    let stream = connector.connect(domain, stream).await?;

    Ok(stream)
}

pub fn server_load_certs(path: &Path) -> anyhow::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| anyhow::anyhow!("invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

pub fn server_load_keys(path: &Path) -> anyhow::Result<Vec<PrivateKey>> {
    rsa_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| anyhow::anyhow!("invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())
}
