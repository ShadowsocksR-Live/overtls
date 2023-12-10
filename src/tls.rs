use crate::error::Result;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    RootCertStore,
};
use std::{
    fs::File,
    io::BufReader,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
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

#[derive(Debug)]
pub struct NoCertificateVerification {}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _ert: &webpki::types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _ert: &webpki::types::CertificateDer<'_>,
        _ss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![]
    }
}

pub(crate) async fn create_tls_client_stream(
    root_cert_store: RootCertStore,
    addr: SocketAddr,
    domain: &str,
) -> Result<TlsStream<TcpStream>> {
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    config.dangerous().set_certificate_verifier(Arc::new(NoCertificateVerification {}));
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
