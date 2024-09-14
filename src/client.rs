use crate::{
    addess_to_b64str,
    config::Config,
    error::{Error, Result},
    tls::*,
    udprelay,
    weirduri::WeirdUri,
};
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use socks5_impl::{
    protocol::{Address, Reply},
    server::{
        auth::{NoAuth, UserKeyAuth},
        connection::connect::NeedReply,
        AuthAdaptor, ClientConnection, Connect, IncomingConnection, Server,
    },
};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::{
    tungstenite::{
        client::IntoClientRequest,
        handshake::{
            client::{self, Response},
            machine::TryParse,
        },
        protocol::{Message, Role},
    },
    WebSocketStream,
};

pub async fn run_client<F>(config: &Config, quit: crate::CancellationToken, callback: Option<F>) -> Result<()>
where
    F: FnOnce(SocketAddr) + Send + Sync + 'static,
{
    log::info!("starting {} {} client...", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    #[cfg(not(target_os = "ios"))]
    {
        log::trace!("with following settings:");
        log::trace!("{}", serde_json::to_string_pretty(config)?);
    }

    let client = config.client.as_ref().ok_or("client")?;

    let listen_user = client.listen_user.as_deref().filter(|s| !s.is_empty());
    if let Some(user) = listen_user {
        let listen_password = client.listen_password.as_deref().unwrap_or("");
        let key = UserKeyAuth::new(user, listen_password);
        _run_client(config, Arc::new(key), quit, callback).await?;
    } else {
        _run_client(config, Arc::new(NoAuth), quit, callback).await?;
    }
    Ok(())
}

async fn _run_client<F, O>(config: &Config, auth: AuthAdaptor<O>, quit: crate::CancellationToken, callback: Option<F>) -> Result<()>
where
    F: FnOnce(SocketAddr) + Send + Sync + 'static,
    O: Send + Sync + 'static,
{
    let client = config.client.as_ref().ok_or("client")?;
    let addr = SocketAddr::new(client.listen_host.parse()?, client.listen_port);

    let server = Server::<O>::bind(addr, auth).await?;

    if let Some(callback) = callback {
        callback(server.local_addr()?);
    }

    let (udp_tx, _, incomings) = udprelay::create_udp_tunnel();
    udprelay::udp_handler_watchdog(config, &incomings, &udp_tx, quit.clone()).await?;

    let session_id = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let session_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    loop {
        tokio::select! {
            _ = quit.cancelled() => {
                log::info!("exiting...");
                break;
            }
            result = server.accept() => {
                let (conn, _) = result?;
                let config = config.clone();
                let udp_tx = udp_tx.clone();
                let incomings = incomings.clone();
                let session_id = session_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let session_count = session_count.clone();
                let peer_addr = conn.peer_addr()?;
                tokio::spawn(async move {
                    let count = session_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    log::debug!("session #{} from {} started, session count {}", session_id, peer_addr, count);
                    if let Err(e) = handle_incoming(conn, config, Some(udp_tx), incomings).await {
                        log::debug!("{}", e);
                    }
                    let count = session_count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) - 1;
                    log::debug!("session #{} from {} ended, session count {}", session_id, peer_addr, count);
                });
            }
        }
    }

    Ok(())
}

async fn handle_incoming<S: 'static>(
    conn: IncomingConnection<S>,
    config: Config,
    udp_tx: Option<udprelay::UdpRequestSender>,
    incomings: udprelay::SocketAddrHashSet,
) -> Result<()> {
    let peer_addr = conn.peer_addr()?;
    let (conn, _res) = conn.authenticate().await?;
    match conn.wait_request().await? {
        ClientConnection::UdpAssociate(asso, _) => {
            if let Some(udp_tx) = udp_tx {
                if let Err(e) = udprelay::handle_s5_upd_associate(asso, udp_tx, incomings).await {
                    log::debug!("{peer_addr} handle_s5_upd_associate \"{e}\"");
                }
            } else {
                let mut conn = asso.reply(Reply::CommandNotSupported, Address::unspecified()).await?;
                conn.shutdown().await?;
            }
        }
        ClientConnection::Bind(bind, _) => {
            let mut conn = bind.reply(Reply::CommandNotSupported, Address::unspecified()).await?;
            conn.shutdown().await?;
        }
        ClientConnection::Connect(connect, addr) => {
            if let Err(e) = handle_socks5_cmd_connection(connect, addr.clone(), config).await {
                log::debug!("{} <> {} {}", peer_addr, addr, e);
            }
        }
    }

    log::trace!("{} disconnected", peer_addr);

    Ok(())
}

async fn handle_socks5_cmd_connection(connect: Connect<NeedReply>, target_addr: Address, config: Config) -> Result<()> {
    let incoming = connect.reply(Reply::Succeeded, Address::unspecified()).await?;

    let peer_addr = incoming.peer_addr()?;

    log::trace!("{} -> {} tunnel establishing", peer_addr, target_addr);

    let client = config.client.as_ref().ok_or("client not exist")?;
    let addr = client.server_ip_addr.ok_or("server host")?;

    if !config.disable_tls() {
        let ws_stream = create_tls_ws_stream(addr, Some(target_addr.clone()), &config, None).await?;
        client_traffic_loop(incoming, ws_stream, peer_addr, target_addr).await?;
    } else {
        let ws_stream = create_plaintext_ws_stream(addr, Some(target_addr.clone()), &config, None).await?;
        client_traffic_loop(incoming, ws_stream, peer_addr, target_addr).await?;
    }
    Ok(())
}

async fn client_traffic_loop<T: AsyncRead + AsyncWrite + Unpin, S: AsyncRead + AsyncWrite + Unpin>(
    mut incoming: T,
    mut ws_stream: WebSocketStream<S>,
    peer_addr: SocketAddr,
    target_addr: Address,
) -> Result<()> {
    let mut timer = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        let mut buf = BytesMut::with_capacity(crate::STREAM_BUFFER_SIZE);
        tokio::select! {
            result = incoming.read_buf(&mut buf) => {
                let len = result?;
                if len == 0 {
                    log::trace!("{} -> {} incoming closed", peer_addr, target_addr);
                    ws_stream.send(Message::Close(None)).await?;
                    break;
                }
                ws_stream.send(Message::Binary(buf.to_vec())).await?;
                log::trace!("{} -> {} length {}", peer_addr, target_addr, buf.len());

                if let Err(e) = crate::traffic_status::traffic_status_update(len, 0) {
                    log::error!("{}", e);
                }

                buf.clear();
            }
            result = ws_stream.next() => {
                let msg = result.ok_or("message not exist")??;

                if let Err(e) = crate::traffic_status::traffic_status_update(0, msg.len()) {
                    log::error!("{}", e);
                }

                match msg {
                    Message::Binary(data) => {
                        incoming.write_all(&data).await?;
                        log::trace!("{} <- {} length {}", peer_addr, target_addr, data.len());
                    }
                    Message::Close(_) => {
                        log::trace!("{} <- {} ws closed", peer_addr, target_addr);
                        break;
                    }
                    Message::Pong(_) => {
                        log::trace!("{} <- {} Websocket pong from remote", peer_addr, target_addr);
                    },
                    _ => {}
                }
            }
            _ = timer.tick() => {
                ws_stream.send(Message::Ping(vec![])).await?;
                log::trace!("{} -> {} Websocket ping from local", peer_addr, target_addr);
            }
        }
    }
    Ok(())
}

type WsTlsStream = WebSocketStream<TlsStream<TcpStream>>;

pub(crate) async fn create_tls_ws_stream(
    svr_addr: SocketAddr,
    dst_addr: Option<Address>,
    config: &Config,
    udp_tunnel: Option<bool>,
) -> Result<WsTlsStream> {
    let client = config.client.as_ref().ok_or("client not exist")?;

    let cert_content = client.certificate_content();
    let cert_store = retrieve_root_cert_store_for_client(&cert_content)?;
    let domain = client.server_domain.as_ref().unwrap_or(&client.server_host);

    let stream = create_tls_client_stream(cert_store, svr_addr, domain).await?;

    let ws_stream = create_ws_stream(dst_addr, config, udp_tunnel, stream).await?;
    Ok(ws_stream)
}

pub(crate) async fn create_plaintext_ws_stream(
    server_addr: SocketAddr,
    dst_addr: Option<Address>,
    config: &Config,
    udp_tunnel: Option<bool>,
) -> Result<WebSocketStream<TcpStream>> {
    let stream = crate::tcp_stream::tokio_create(server_addr).await?;
    let ws_stream = create_ws_stream(dst_addr, config, udp_tunnel, stream).await?;
    Ok(ws_stream)
}

pub(crate) async fn create_ws_stream<S: AsyncRead + AsyncWrite + Unpin>(
    dst_addr: Option<Address>,
    config: &Config,
    udp_tunnel: Option<bool>,
    mut stream: S,
) -> Result<WebSocketStream<S>> {
    let client = config.client.as_ref().ok_or("client not exist")?;
    let err = "tunnel path not exist";
    let tunnel_path = config.tunnel_path.extract().first().ok_or(err)?.trim_matches('/');

    let b64_dst = dst_addr.as_ref().map(|dst_addr| addess_to_b64str(dst_addr, false));

    let uri = format!("ws://{}/{}/", client.server_host, tunnel_path);

    let uri = WeirdUri::new(&uri, b64_dst, udp_tunnel, client.client_id.clone());

    let (v, key) = client::generate_request(uri.into_client_request()?)?;
    stream.write_all(&v).await?;

    let mut buf = BytesMut::with_capacity(2048);
    stream.read_buf(&mut buf).await?;

    let response = Response::try_parse(&buf)?.ok_or("response parse failed")?.1;
    let remote_key = response.headers().get("Sec-WebSocket-Accept").ok_or(format!("{:?}", response))?;

    let accept_key = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());

    if accept_key.as_str() != remote_key.to_str().map_err(|e| e.to_string())? {
        return Err(Error::from("accept key error"));
    }

    let ws_stream = WebSocketStream::from_raw_socket(stream, Role::Client, None).await;
    // let (mut ws_stream, _) = tokio_tungstenite::client_async(uri, stream).await?;

    Ok(ws_stream)
}
