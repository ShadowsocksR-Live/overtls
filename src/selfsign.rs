#![allow(dead_code)]

use rustls::{server::AllowAnyAuthenticatedClient, RootCertStore};
use std::convert::TryFrom;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{
    client::TlsStream as ClientTlsStream,
    rustls::{self},
    TlsAcceptor, TlsConnector,
};

pub fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

pub fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
            None => break,
            _ => {}
        }
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}

pub fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
    let addrs = (host, port).to_socket_addrs().unwrap();
    for addr in addrs {
        if let SocketAddr::V4(_) = addr {
            return addr;
        }
    }

    unreachable!("Cannot lookup address");
}

fn make_client_config(
    ca_file: &str,
    certs_file: &str,
    key_file: &str,
) -> Arc<rustls::ClientConfig> {
    let cert_file = File::open(&ca_file).expect("Cannot open CA file");
    let mut reader = BufReader::new(cert_file);

    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(&rustls_pemfile::certs(&mut reader).unwrap());

    let suites = rustls::DEFAULT_CIPHER_SUITES.to_vec();
    let versions = rustls::DEFAULT_VERSIONS.to_vec();

    let certs = load_certs(certs_file);
    let key = load_private_key(key_file);

    let config = rustls::ClientConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .expect("inconsistent cipher-suite/versions selected")
        .with_root_certificates(root_store)
        .with_single_cert(certs, key)
        .expect("invalid client auth certs/key");
    Arc::new(config)
}

fn make_server_config(certs: &str, key_file: &str) -> Arc<rustls::ServerConfig> {
    let roots = load_certs(certs);
    let certs = roots.clone();
    let mut client_auth_roots = RootCertStore::empty();
    for root in roots {
        client_auth_roots.add(&root).unwrap();
    }
    let client_auth = AllowAnyAuthenticatedClient::new(client_auth_roots);

    let privkey = load_private_key(key_file);
    let suites = rustls::ALL_CIPHER_SUITES.to_vec();
    let versions = rustls::ALL_VERSIONS.to_vec();

    let mut config = rustls::ServerConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .expect("inconsistent cipher-suites/versions specified")
        .with_client_cert_verifier(client_auth)
        .with_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
        .expect("bad certificates/private key");

    config.key_log = Arc::new(rustls::KeyLogFile::new());
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(256);
    Arc::new(config)
}

pub async fn new_tls_stream(
    domain: &str,
    addr: std::net::SocketAddr,
    ca_file: &str,
    cert_file: &str,
    key_file: &str,
) -> ClientTlsStream<TcpStream> {
    let config = make_client_config(&ca_file, &cert_file, &key_file);

    let connector = TlsConnector::from(config);

    let stream = TcpStream::connect(&addr).await.unwrap();
    let domain = rustls::ServerName::try_from(domain)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))
        .unwrap();
    let stream = connector.connect(domain, stream).await.unwrap();
    stream
}

pub fn new_tls_acceptor(cert_file: &str, key_file: &str) -> TlsAcceptor {
    let config = make_server_config(&cert_file, &key_file);
    let acceptor = TlsAcceptor::from(config);
    acceptor
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const CA_FILE: &str = "cert/dev/ca.cert";
    const CLIENT_CERT_FILE: &str = "cert/dev/client.cert";
    const CLIENT_KEY_FILE: &str = "cert/dev/client.key";
    const SERVER_CERT_FILE: &str = "cert/dev/server.fullchain";
    const SERVER_KEY_FILE: &str = "cert/dev/server.rsa";

    #[tokio::test]
    async fn server() {
        start_server().await;
    }

    #[tokio::test]
    async fn client() {
        let msg = b"Hello world\n";
        let mut buf = [0; 12];
        start_client(msg, &mut buf).await;
        assert_eq!(&buf, msg);
    }

    async fn start_server() {
        let tls_acceptor = new_tls_acceptor(SERVER_CERT_FILE, SERVER_KEY_FILE);
        let listener = TcpListener::bind("0.0.0.0:5002").await.unwrap();

        loop {
            let (stream, _peer_addr) = listener.accept().await.unwrap();
            let mut tls_stream = tls_acceptor.accept(stream).await.unwrap();
            println!("server: Accepted client conn with TLS");
            tokio::spawn(async move {
                let mut buf = [0; 12];
                tls_stream.read(&mut buf).await.unwrap();
                println!("server: got data: {:?}", buf);
                tls_stream.write(&buf).await.unwrap();
                println!("server: flush the data out");
            });
        }
    }

    async fn start_client(msg: &[u8], buf: &mut [u8]) {
        let addr = lookup_ipv4("192.168.28.130", 5002);
        let mut tls_stream = new_tls_stream(
            "testserver.com",
            addr,
            CA_FILE,
            CLIENT_CERT_FILE,
            CLIENT_KEY_FILE,
        )
        .await;

        tls_stream.write(msg).await.unwrap();
        println!("client: send data");

        tls_stream.read(buf).await.unwrap();
        println!("client: read echoed data");
    }
}
