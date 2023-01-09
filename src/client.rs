use crate::{addess_to_b64str, config::Config, program_name, tls::*, udprelay, weirduri::WeirdUri, STREAM_BUFFER_SIZE};
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use socks5_impl::{
    protocol::{Address, Reply},
    server::{auth::NoAuth, connection::connect::NeedReply, Connect, Connection, IncomingConnection, Server},
};
use std::net::{SocketAddr, ToSocketAddrs};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
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

    let (udp_tx, _, incomings) = udprelay::create_udp_tunnel();
    let udp_waker = udprelay::udp_handler_watchdog(config, &incomings, &udp_tx).await?;

    while let Ok((conn, _)) = server.accept().await {
        let config = config.clone();
        let udp_tx = udp_tx.clone();
        let incomings = incomings.clone();
        let udp_waker = udp_waker.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_incoming(conn, config, Some(udp_tx), incomings, udp_waker).await {
                log::debug!("{}", e);
            }
        });
    }

    Ok(())
}

async fn handle_incoming(
    conn: IncomingConnection,
    config: Config,
    udp_tx: Option<udprelay::UdpRequestSender>,
    incomings: udprelay::SocketAddrSet,
    udp_waker: udprelay::UdpWaker,
) -> anyhow::Result<()> {
    let peer_addr = conn.peer_addr()?;
    match conn.handshake().await? {
        Connection::Associate(asso, _) => {
            if let Some(udp_tx) = udp_tx {
                if let Err(e) = udprelay::handle_s5_upd_associate(asso, udp_tx, incomings, udp_waker).await {
                    log::debug!("{peer_addr} handle_s5_upd_associate \"{e}\"");
                }
            } else {
                let mut conn = asso.reply(Reply::CommandNotSupported, Address::unspecified()).await?;
                conn.shutdown().await?;
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
    let incoming = connect.reply(Reply::Succeeded, Address::unspecified()).await?;

    let peer_addr = incoming.peer_addr()?;

    log::trace!("{} -> {} tunnel establishing", peer_addr, target_addr);

    let ws_stream = create_ws_tls_stream(Some(target_addr.clone()), &config, None).await?;
    client_traffic_loop(incoming, ws_stream, peer_addr, target_addr).await?;
    Ok(())
}

async fn client_traffic_loop<T: AsyncRead + AsyncWrite + Unpin, S: AsyncRead + AsyncWrite + Unpin>(
    mut incoming: T,
    mut ws_stream: WebSocketStream<S>,
    peer_addr: SocketAddr,
    target_addr: Address,
) -> anyhow::Result<()> {
    loop {
        let mut buf = BytesMut::with_capacity(STREAM_BUFFER_SIZE);
        tokio::select! {
            result = incoming.read_buf(&mut buf) => {
                let len = result?;
                if len == 0 {
                    log::trace!("{} -> {} incoming closed", peer_addr, target_addr);
                    break;
                }
                ws_stream.send(Message::Binary(buf.to_vec())).await?;
                log::trace!("{} -> {} length {}", peer_addr, target_addr, buf.len());
                buf.clear();
            }
            result = ws_stream.next() => {
                let msg = result.ok_or_else(|| anyhow::anyhow!(""))??;
                match msg {
                    Message::Binary(data) => {
                        incoming.write_all(&data).await?;
                        log::trace!("{} -> {} length {}", peer_addr, target_addr, data.len());
                    }
                    Message::Close(_) => {
                        log::trace!("{} -> {} ws closed", peer_addr, target_addr);
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

type WsTlsStream = WebSocketStream<TlsStream<TcpStream>>;

pub async fn create_ws_tls_stream(
    target_addr: Option<Address>,
    config: &Config,
    udp: Option<bool>,
) -> anyhow::Result<WsTlsStream> {
    let client = config.client.as_ref().ok_or_else(|| anyhow::anyhow!("c"))?;
    let tunnel_path = config.tunnel_path.trim_matches('/');

    let b64_dst = target_addr
        .as_ref()
        .map(|target_addr| addess_to_b64str(target_addr, false));

    let uri = format!("ws://{}:{}/{}/", client.server_host, client.server_port, tunnel_path);

    let uri = WeirdUri::new(&uri, b64_dst, udp, client.client_id.clone());

    let cert_store = retrieve_root_cert_store_for_client(&client.cafile)?;

    let mut addr = (client.server_host.as_str(), client.server_port).to_socket_addrs()?;
    let addr = addr.next().ok_or_else(|| anyhow::anyhow!("address"))?;
    let domain = client.server_domain.as_ref().unwrap_or(&client.server_host);

    let mut outgoing = create_tls_client_stream(cert_store, &addr, domain).await?;

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
        return Err(anyhow::anyhow!("accept key error"));
    }

    let ws_stream = WebSocketStream::from_raw_socket(outgoing, Role::Client, None).await;
    // let (mut ws_stream, _) = tokio_tungstenite::client_async(uri, outgoing).await?;

    Ok(ws_stream)
}
