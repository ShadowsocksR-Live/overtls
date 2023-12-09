use crate::error::Result;
use std::{
    fs::File,
    io::BufReader,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::net::TcpStream;
use tokio_rustls::{
    client::TlsStream,
    rustls::{self, Certificate, OwnedTrustAnchor, PrivateKey, RootCertStore},
    TlsConnector,
};

pub(crate) fn retrieve_root_cert_store_for_client(cafile: &Option<PathBuf>) -> Result<RootCertStore> {
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
            root_cert_store.add_trust_anchors(trust_anchors);
            done = true;
        }
    }
    if !done {
        root_cert_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            let name_constraints = ta.name_constraints.clone().map(|nc| nc.as_ref().to_vec());
            OwnedTrustAnchor::from_subject_spki_name_constraints(ta.subject.as_ref(), ta.subject_public_key_info.as_ref(), name_constraints)
        }));
    }
    Ok(root_cert_store)
}

#[derive(Debug)]
pub struct NoCertificateVerification {}

impl rustls::client::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

pub(crate) async fn create_tls_client_stream(
    root_cert_store: RootCertStore,
    addr: SocketAddr,
    domain: &str,
) -> Result<TlsStream<TcpStream>> {
    let mut config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    config.dangerous().set_certificate_verifier(Arc::new(NoCertificateVerification {}));
    let connector = TlsConnector::from(std::sync::Arc::new(config));

    let stream = crate::tcp_stream::create(addr).await?;

    let domain = rustls::ServerName::try_from(domain)?;

    let stream = connector.connect(domain, stream).await?;

    Ok(stream)
}

pub(crate) fn server_load_certs(path: &Path) -> Result<Vec<Certificate>> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(path)?))?;
    Ok(certs.into_iter().map(Certificate).collect())
}

pub(crate) fn server_load_keys(path: &Path) -> Result<Vec<PrivateKey>> {
    let keys = rustls_pemfile::rsa_private_keys(&mut BufReader::new(File::open(path)?))?;
    Ok(keys.into_iter().map(PrivateKey).collect())
}
