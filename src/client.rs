use crate::config::Config;
use bytes::BytesMut;
use socks5_proto::{Address, Reply};
use socks5_server::{auth::NoAuth, Connection, IncomingConnection, Server};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};

pub async fn run_client(config: &Config) -> anyhow::Result<()> {
    if config.verbose {
        println!("Starting viatls client with following settings:");
        serde_json::to_writer_pretty(std::io::stdout(), config)?;
        println!();
    }
    let client = config.client.as_ref();
    let client = client.ok_or_else(|| anyhow::anyhow!("client settings"))?;
    let addr = format!("{}:{}", client.listen_host, client.listen_port);
    let server = Server::bind(addr, std::sync::Arc::new(NoAuth)).await?;

    while let Ok((conn, _)) = server.accept().await {
        let config = config.clone();
        tokio::spawn(async move {
            let verbose = config.verbose;
            if let Err(e) = handle_incoming(conn, config).await {
                if verbose {
                    eprintln!("Error: {}", e);
                }
            }
        });
    }

    Ok(())
}

async fn handle_incoming(conn: IncomingConnection, config: Config) -> anyhow::Result<()> {
    let peer_addr = conn.peer_addr()?;
    match conn.handshake().await? {
        Connection::Associate(associate, _) => {
            let mut conn = associate
                .reply(Reply::CommandNotSupported, Address::unspecified())
                .await?;
            conn.shutdown().await?;
        }
        Connection::Bind(bind, _) => {
            let mut conn = bind
                .reply(Reply::CommandNotSupported, Address::unspecified())
                .await?;
            conn.shutdown().await?;
        }
        Connection::Connect(connect, addr) => {
            if config.verbose {
                println!("Tunnel establishing {} -> {}", peer_addr, addr);
            }
            let target = match addr {
                Address::DomainAddress(domain, port) => TcpStream::connect((domain, port)).await,
                Address::SocketAddress(addr) => TcpStream::connect(addr).await,
            };

            if let Ok(target) = target {
                let conn = connect
                    .reply(Reply::Succeeded, Address::unspecified())
                    .await?;
                let (incoming_r, incoming_w) = conn.stream.into_split();
                let (outgo_r, outgo_w) = target.into_split();

                tokio::try_join!(
                    read_and_write(incoming_r, outgo_w, config.clone(), true),
                    read_and_write(outgo_r, incoming_w, config.clone(), false),
                )?;
            } else {
                let mut conn = connect
                    .reply(Reply::HostUnreachable, Address::unspecified())
                    .await?;
                conn.shutdown().await?;
            }
        }
    }

    if config.verbose {
        println!("{} disconnected", peer_addr);
    }

    Ok(())
}

async fn read_and_write(
    reader: OwnedReadHalf,
    mut writer: OwnedWriteHalf,
    config: Config,
    encrypt: bool,
) -> anyhow::Result<()> {
    let mut buf_reader = tokio::io::BufReader::new(reader);
    let mut buf = BytesMut::with_capacity(2048);
    loop {
        match buf_reader.read_buf(&mut buf).await {
            Err(e) => {
                eprintln!("read from client error \"{}\"", e);
                break Err(anyhow::anyhow!(e));
            }
            Ok(0) => {
                // 遇到了 EOF, client closed
                break Ok(());
            }
            Ok(_n) => {
                println!("{} stream with {}", encrypt, config.method);
                writer.write_buf(&mut buf).await?;
                buf.clear();
            }
        }
    }
}
