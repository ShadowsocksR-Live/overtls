use argh::FromArgs;
use std::io;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use tokio::io::{copy, split, stdin as tokio_stdin, stdout as tokio_stdout, AsyncWriteExt};
use viatls::tls::{create_tls_cliet_stream, retrieve_root_cert_store_for_client};

/// Demo client for beginning to use tokio-rustls
#[derive(FromArgs)]
struct Options {
    /// host
    #[argh(positional)]
    host: String,

    /// port
    #[argh(option, short = 'p', default = "443")]
    port: u16,

    /// domain
    #[argh(option, short = 'd')]
    domain: Option<String>,

    /// cafile
    #[argh(option, short = 'c')]
    cafile: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options: Options = argh::from_env();

    let addr = (options.host.as_str(), options.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let domain = options.domain.unwrap_or(options.host);

    let cert_store = retrieve_root_cert_store_for_client(&options.cafile)?;
    let mut stream = create_tls_cliet_stream(cert_store, &addr, &domain).await?;

    let (mut stdin, mut stdout) = (tokio_stdin(), tokio_stdout());

    let content = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", domain);
    stream.write_all(content.as_bytes()).await?;

    let (mut reader, mut writer) = split(stream);

    tokio::select! {
        ret = copy(&mut reader, &mut stdout) => {
            ret?;
        },
        ret = copy(&mut stdin, &mut writer) => {
            ret?;
            writer.shutdown().await?
        }
    }

    Ok(())
}
