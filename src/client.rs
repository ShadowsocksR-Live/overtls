use crate::config::Config;
use socks5_proto::{Address, Reply};
use socks5_server::{auth::NoAuth, Connection, IncomingConnection, Server};
use std::{io::Result, sync::Arc};
use tokio::{io, net::TcpStream};

pub async fn run_client(config: &Config) -> anyhow::Result<()> {
    serde_json::to_writer_pretty(std::io::stdout(), config)?;
    let client = config.client.as_ref();
    let client = client.ok_or_else(|| anyhow::anyhow!("client settings"))?;
    let addr = format!("{}:{}", client.listen_host, client.listen_port);
    let server = Server::bind(addr, Arc::new(NoAuth)).await?;

    while let Ok((conn, _)) = server.accept().await {
        tokio::spawn(async move {
            match handle_incoming(conn).await {
                Ok(()) => {}
                Err(err) => eprintln!("{err}"),
            }
        });
    }

    Ok(())
}

async fn handle_incoming(conn: IncomingConnection) -> Result<()> {
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
            let target = match addr {
                Address::DomainAddress(domain, port) => TcpStream::connect((domain, port)).await,
                Address::SocketAddress(addr) => TcpStream::connect(addr).await,
            };

            if let Ok(mut target) = target {
                let mut conn = connect
                    .reply(Reply::Succeeded, Address::unspecified())
                    .await?;
                io::copy_bidirectional(&mut target, &mut conn).await?;
            } else {
                let mut conn = connect
                    .reply(Reply::HostUnreachable, Address::unspecified())
                    .await?;
                conn.shutdown().await?;
            }
        }
    }

    Ok(())
}
