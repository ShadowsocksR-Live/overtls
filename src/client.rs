use crate::{config::Config, convert_addess_to_string, program_name, tls::*, udprelay, weirduri::WeirdUri};
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use socks5_proto::{Address, Reply};
use socks5_server::{auth::NoAuth, connection::connect::NeedReply, Connect, Connection, IncomingConnection, Server};
use std::net::{SocketAddr, ToSocketAddrs};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tungstenite::{
    client::IntoClientRequest,
    handshake::{
        client::{self, Response},
        machine::TryParse,
    },
    protocol::{Message, Role},
};

pub async fn run_client(config: &Config) -> anyhow::Result<()> {
    log::info!("starting {} client...", program_name());
    log::trace!("with following settings:");
    log::trace!("{}", serde_json::to_string_pretty(config)?);

    let client = config.client.as_ref().ok_or_else(|| anyhow::anyhow!("client"))?;
    let addr = format!("{}:{}", client.listen_host, client.listen_port);
    let server = Server::bind(addr, std::sync::Arc::new(NoAuth)).await?;

    while let Ok((conn, _)) = server.accept().await {
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_incoming(conn, config).await {
                log::debug!("{}", e);
            }
        });
    }

    Ok(())
}

async fn handle_incoming(conn: IncomingConnection, config: Config) -> anyhow::Result<()> {
    let peer_addr = conn.peer_addr()?;
    match conn.handshake().await? {
        Connection::Associate(associate, _) => {
            if let Err(e) = udprelay::handle_s5_upd_associate(associate, config).await {
                log::debug!("{peer_addr} handle_s5_upd_associate \"{e}\"");
            }
        }
        Connection::Bind(bind, _) => {
            let mut conn = bind.reply(Reply::CommandNotSupported, Address::unspecified()).await?;
            conn.shutdown().await?;
        }
        Connection::Connect(connect, addr) => {
            if let Err(e) = handle_socks5_cmd_connection(connect, addr.clone(), config).await {
                log::debug!("{} -> {} {}", peer_addr, addr, e);
            }
        }
    }

    log::trace!("{} disconnected", peer_addr);

    Ok(())
}

async fn handle_socks5_cmd_connection(
    connect: Connect<NeedReply>,
    target_addr: Address,
    config: Config,
) -> anyhow::Result<()> {
    let mut incoming = connect.reply(Reply::Succeeded, Address::unspecified()).await?;

    let peer_addr = incoming.peer_addr()?;
    let (mut incoming_r, mut incoming_w) = incoming.split();

    let ws_stream = create_ws_tls_stream(&target_addr, peer_addr, &config, None).await?;
    let (mut ws_stream_w, mut ws_stream_r) = ws_stream.split();

    let incoming_to_ws = async {
        let mut buf = BytesMut::with_capacity(2048);
        loop {
            let len = incoming_r.read_buf(&mut buf).await?;
            if len == 0 {
                log::trace!("{} -> {} incoming closed", peer_addr, target_addr);
                break;
            }
            ws_stream_w.send(Message::Binary(buf.to_vec())).await?;
            log::trace!("{} -> {} sending data length {}", peer_addr, target_addr, buf.len());
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
                    log::trace!("{} <- {} recv data lenth {}", peer_addr, target_addr, v.len());
                }
                Message::Close(_) => {
                    log::trace!("{} <- {} tunnel closing", peer_addr, target_addr);
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
}

type WsTlsStream = WebSocketStream<TlsStream<TcpStream>>;

pub async fn create_ws_tls_stream(
    target_addr: &Address,
    incoming_addr: SocketAddr,
    config: &Config,
    upd_associate: Option<String>,
) -> anyhow::Result<WsTlsStream> {
    let client = config.client.as_ref().ok_or_else(|| anyhow::anyhow!("c"))?;
    let tunnel_path = config.tunnel_path.trim_matches('/');

    log::trace!("{} -> {} tunnel establishing", incoming_addr, target_addr);

    let b64_addr = convert_addess_to_string(target_addr, false);

    let uri = format!("ws://{}:{}/{}/", client.server_host, client.server_port, tunnel_path);

    let uri = WeirdUri::new(&uri, Some(b64_addr), upd_associate);

    let cert_store = retrieve_root_cert_store_for_client(&client.cafile)?;

    let mut addr = (client.server_host.as_str(), client.server_port).to_socket_addrs()?;
    let addr = addr.next().ok_or_else(|| anyhow::anyhow!("address"))?;
    let domain = client.server_domain.as_ref().unwrap_or(&client.server_host);

    let mut outgoing = create_tls_cliet_stream(cert_store, &addr, domain).await?;

    let (v, key) = client::generate_request(uri.into_client_request()?)?;
    outgoing.write_all(&v).await?;

    let mut buf = BytesMut::with_capacity(2048);
    outgoing.read_buf(&mut buf).await?;

    let response = Response::try_parse(&buf)?.ok_or_else(|| anyhow::anyhow!("response"))?.1;
    let remote_key = response
        .headers()
        .get("Sec-WebSocket-Accept")
        .ok_or_else(|| anyhow::anyhow!("{:?}", response))?;

    let accept_key = tungstenite::handshake::derive_accept_key(key.as_bytes());

    if accept_key.as_str() != remote_key.to_str()? {
        log::debug!("{} -> {} accept key error", incoming_addr, target_addr);
        return Err(anyhow::anyhow!("accept key error"));
    }

    let ws_stream = WebSocketStream::from_raw_socket(outgoing, Role::Client, None).await;
    // let (mut ws_stream, _) = tokio_tungstenite::client_async(uri, outgoing).await?;

    Ok(ws_stream)
}
