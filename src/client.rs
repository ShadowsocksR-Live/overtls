use crate::{config::Config, parseresponse::parse_response_data, program_name, tls::*, weirduri::WeirdUri};
use bytes::BytesMut;
use futures_util::SinkExt;
use futures_util::StreamExt;
use log::*;
use socks5_proto::{Address, Reply};
use socks5_server::{auth::NoAuth, connection::connect::NeedReply, Connect, Connection, IncomingConnection, Server};
use std::net::ToSocketAddrs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::WebSocketStream;
use tungstenite::protocol::{Message, Role};

pub async fn run_client(config: &Config) -> anyhow::Result<()> {
    info!("starting {} client...", program_name());
    trace!("with following settings:");
    trace!("{}", serde_json::to_string_pretty(config)?);

    let client = config.client.as_ref();
    let client = client.ok_or_else(|| anyhow::anyhow!("client settings"))?;
    let addr = format!("{}:{}", client.listen_host, client.listen_port);
    let server = Server::bind(addr, std::sync::Arc::new(NoAuth)).await?;

    while let Ok((conn, _)) = server.accept().await {
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_incoming(conn, config).await {
                error!("{}", e);
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
            let mut conn = bind.reply(Reply::CommandNotSupported, Address::unspecified()).await?;
            conn.shutdown().await?;
        }
        Connection::Connect(connect, addr) => {
            if let Err(e) = handle_socks5_cmd_connection(connect, addr, config).await {
                error!("{}: {}", peer_addr, e);
            }
        }
    }

    trace!("{} disconnected", peer_addr);

    Ok(())
}

async fn handle_socks5_cmd_connection(
    connect: Connect<NeedReply>,
    target_addr: Address,
    config: Config,
) -> anyhow::Result<()> {
    let incoming = connect.reply(Reply::Succeeded, Address::unspecified()).await?.stream;

    let peer_addr = incoming.peer_addr()?;
    let (mut incoming_r, mut incoming_w) = incoming.into_split();

    let client = config.client.as_ref().ok_or_else(|| anyhow::anyhow!("c"))?;
    let tunnel_path = config.tunnel_path.clone();
    let tunnel_path = tunnel_path.trim().trim_matches('/');

    trace!("{} -> {} tunnel establishing", peer_addr, target_addr);

    let mut buf = BytesMut::with_capacity(1024);
    target_addr.write_to_buf(&mut buf);
    let b64_addr = base64::encode(&buf);

    let uri = format!("ws://{}:{}/{}/", client.server_host, client.server_port, tunnel_path);

    let uri = WeirdUri::new(&uri, Some(b64_addr));

    let cert_store = retrieve_root_cert_store_for_client(&client.cafile)?;

    let mut addr = (client.server_host.as_str(), client.server_port).to_socket_addrs()?;
    let addr = addr.next().ok_or_else(|| anyhow::anyhow!("address"))?;
    let domain = client.server_domain.as_ref().unwrap_or(&client.server_host);

    let mut outgoing = create_tls_cliet_stream(cert_store, &addr, domain).await?;

    let (v, key) = uri.generate_request()?;
    outgoing.write_all(&v).await?;

    let mut buf = BytesMut::with_capacity(2048);
    outgoing.read_buf(&mut buf).await?;

    let response = parse_response_data(&buf)?;
    let remote_key = response
        .headers()
        .get("Sec-WebSocket-Accept")
        .ok_or_else(|| anyhow::anyhow!("{:?}", response))?;

    let accept_key = tungstenite::handshake::derive_accept_key(key.as_bytes());

    if accept_key.as_str() != remote_key.to_str()? {
        error!("{} -> {} accept key error", peer_addr, target_addr);
        return Ok(());
    }

    let ws_stream = WebSocketStream::from_raw_socket(outgoing, Role::Client, None).await;
    // let (mut ws_stream, _) = tokio_tungstenite::client_async(uri, outgoing).await?;

    let (mut ws_stream_w, mut ws_stream_r) = ws_stream.split();

    let incoming_to_ws = async {
        let mut buf = BytesMut::with_capacity(2048);
        loop {
            let len = incoming_r.read_buf(&mut buf).await?;
            if len == 0 {
                trace!("{} -> {} incoming closed", peer_addr, target_addr);
                break;
            }
            ws_stream_w.send(Message::Binary(buf.to_vec())).await?;
            trace!("{} -> {} sending message length {}", peer_addr, target_addr, buf.len());
            buf.clear();
        }
        Ok::<_, anyhow::Error>(())
    };

    let ws_to_incoming = async {
        loop {
            let msg = ws_stream_r.next().await.ok_or_else(|| anyhow::anyhow!(""))??;
            match msg {
                Message::Binary(v) => {
                    incoming_w.write_all(&v).await?;
                    trace!("{} <- {} message from server lenth {}", peer_addr, target_addr, v.len());
                }
                Message::Close(_) => {
                    trace!("{} <- {} tunnel closing", peer_addr, target_addr);
                    break;
                }
                _ => {}
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        result = incoming_to_ws => { result }
        result = ws_to_incoming => { result }
    }

    // tokio::try_join!(incoming_to_ws, ws_to_incoming,)?;
    // Ok(())
}
