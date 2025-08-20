use crate::{
    addess_to_b64str,
    config::Config,
    error::{Error, Result},
    server::{END_SESSION, REMOTE_EOF, START_SESSION},
    tls::*,
    udprelay,
    weirduri::WeirdUri,
};
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use socks5_impl::{
    protocol::{Address, Reply},
    server::{
        AuthAdaptor, ClientConnection, Connect, IncomingConnection, Server,
        auth::{NoAuth, UserKeyAuth},
        connection::connect::NeedReply,
    },
};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        client::IntoClientRequest,
        handshake::{
            client::{self, Response},
            machine::TryParse,
        },
        protocol::{Message, Role},
    },
};

pub async fn run_client<F>(config: &Config, quit: crate::CancellationToken, callback: Option<F>) -> Result<()>
where
    F: FnOnce(SocketAddr) + Send + Sync + 'static,
{
    log::info!("starting {} {} client...", clap::crate_name!(), crate::cmdopt::version_info());
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

    let pool_max_size = client.pool_max_size.map_or(Some(crate::config::DEFAULT_POOL_MAX_SIZE), Some);

    if let Some(callback) = callback {
        callback(server.local_addr()?);
    }

    if config.disable_tls() {
        let manager = WsPlainConnectionManager { config: config.clone() };
        let connection_pool = ConnectionPool::new(pool_max_size, None, None, None, manager);
        client_event_loop::<_, TcpStream, _>(connection_pool, quit, server, config).await?;
    } else {
        let manager = WsTlsConnectionManager { config: config.clone() };
        let connection_pool = ConnectionPool::new(pool_max_size, None, None, None, manager);
        client_event_loop::<_, TlsStream<TcpStream>, _>(connection_pool, quit, server, config).await?;
    };
    Ok(())
}

async fn client_event_loop<M, S, O>(
    pool: Arc<ConnectionPool<M>>,
    quit: crate::CancellationToken,
    server: Server<O>,
    config: &Config,
) -> Result<()>
where
    M: ConnectionManager<Connection = WebSocketStream<S>> + Send + Sync + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: Send + Sync + 'static,
{
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
                let pool = pool.clone();
                tokio::spawn(async move {
                    let mut ws_stream = match pool.get_connection().await.map_err(std::io::Error::other) {
                        Ok(stream) => stream,
                        Err(e) => {
                            log::debug!("{peer_addr} failed to acquire WebSocket stream from pool: '{e}'");
                            return;
                        }
                    };
                    let count = session_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    log::debug!("session #{session_id} from {peer_addr} started, session count {count}");
                    if let Err(e) = handle_incoming::<_, S>(conn, config, Some(udp_tx), incomings, &mut *ws_stream).await {
                        log::debug!("{e}");
                    }
                    let count = session_count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) - 1;
                    log::debug!("session #{session_id} from {peer_addr} ended, session count {count}");
                });
            }
        }
    }

    Ok(())
}

async fn handle_incoming<IO, S>(
    conn: IncomingConnection<IO>,
    config: Config,
    udp_tx: Option<udprelay::UdpRequestSender>,
    incomings: udprelay::SocketAddrHashSet,
    ws_stream: &mut WebSocketStream<S>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    IO: 'static,
{
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
            if let Err(e) = handle_socks5_cmd_connection::<S>(connect, addr.clone(), config, ws_stream).await {
                log::debug!("{peer_addr} <> {addr} {e}");
            }
        }
    }

    log::trace!("{peer_addr} disconnected");

    Ok(())
}

async fn handle_socks5_cmd_connection<S>(
    connect: Connect<NeedReply>,
    target_addr: Address,
    _config: Config,
    ws_stream: &mut WebSocketStream<S>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let incoming = connect.reply(Reply::Succeeded, Address::unspecified()).await?;

    let peer_addr = incoming.peer_addr()?;

    log::trace!("{peer_addr} -> {target_addr} tunnel establishing");

    client_traffic_loop(incoming, ws_stream, peer_addr, target_addr).await?;
    Ok(())
}

async fn client_traffic_loop<T, S>(mut incoming: T, ws_stream: &mut WebSocketStream<S>, src: SocketAddr, dst: Address) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Send "Start session" command with target address
    let b64_addr = addess_to_b64str(&dst, false);
    let start_cmd = format!("{START_SESSION}:{b64_addr}");
    ws_stream.send(Message::Text(start_cmd.into())).await?;

    let mut timer = tokio::time::interval(std::time::Duration::from_secs(30));
    let mut session_confirmed = false;
    let mut shutdown_deadline: Option<tokio::time::Instant> = None;
    loop {
        let mut buf = BytesMut::with_capacity(crate::STREAM_BUFFER_SIZE);
        tokio::select! {
            // Only allow reading from local connection after session_confirmed
            result = async {
                if session_confirmed {
                    incoming.read_buf(&mut buf).await
                } else {
                    futures_util::future::pending::<std::io::Result<usize>>().await
                }
            } => {
                let len = result?;
                if len == 0 {
                    log::debug!("{src} -> {dst} incoming closed");
                    // Send "End session" text message
                    ws_stream.send(Message::Text(END_SESSION.into())).await?;
                    break;
                }
                ws_stream.send(Message::binary(buf.to_vec())).await?;
                log::trace!("{src} -> {dst} length {}", buf.len());

                if let Err(e) = crate::traffic_status::traffic_status_update(len, 0) {
                    log::error!("{e}");
                }

                buf.clear();
            }
            result = ws_stream.next() => {
                let msg = result.ok_or("message not exist")??;

                if let Err(e) = crate::traffic_status::traffic_status_update(0, msg.len()) {
                    log::error!("{e}");
                }

                match msg {
                    Message::Binary(data) => {
                        incoming.write_all(&data).await?;
                        log::trace!("{src} <- {dst} length {}", data.len());
                    }
                    Message::Close(_) => {
                        log::debug!("{src} <- {dst} ws closed, exiting...");
                        break;
                    }
                    Message::Text(data) => {
                        let msg_str = data.as_str();
                        if let Some(reason) = msg_str.strip_prefix(END_SESSION) {
                            let reason = reason.strip_prefix(':').unwrap_or(reason).trim();
                            log::debug!("{src} <- {dst} session ended by remote message '{END_SESSION}' with reason: '{reason}'");
                            break;
                        } else if msg_str.starts_with(START_SESSION) {
                            session_confirmed = true;
                            log::debug!("{src} <- {dst} received '{START_SESSION}' confirmation from server");
                        } else if msg_str == REMOTE_EOF {
                            log::debug!("{src} <- {dst} received from server the '{REMOTE_EOF}' indication");
                            // Force shutdown after 1 second
                            shutdown_deadline = Some(tokio::time::Instant::now() + std::time::Duration::from_secs(1));
                        } else {
                            log::warn!("{src} <- {dst} unexpected Websocket text from remote: {msg_str}");
                        }
                    }
                    Message::Ping(_) => {
                        log::trace!("{src} <- {dst} Websocket ping from remote");
                    }
                    Message::Pong(_) => {
                        log::trace!("{src} <- {dst} Websocket pong from remote");
                    }
                    _ => {}
                }
            }
            _ = timer.tick() => {
                ws_stream.send(Message::Ping(vec![].into())).await?;
                log::trace!("{src} -> {dst} Websocket ping from local");
            }
            _ = async {
                if let Some(deadline) = shutdown_deadline.take() {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    futures_util::future::pending::<()>().await;
                }
            } => {
                log::debug!("{src} <> {dst} forcibly closed after 1 second of '{REMOTE_EOF}' indication");
                ws_stream.send(Message::Text(END_SESSION.into())).await?;
                let _ = incoming.shutdown().await;
                break;
            }
        }
    }
    Ok(())
}

pub(crate) async fn create_tls_ws_stream(
    svr_addr: SocketAddr,
    dst_addr: Option<Address>,
    config: &Config,
    udp_tunnel: Option<bool>,
) -> Result<WsTlsStream> {
    let client = config.client.as_ref().ok_or("client not exist")?;

    if client.dangerous_mode.unwrap_or(false) {
        log::warn!("Dangerous mode enabled, this will skip certificate verification. It is not recommended for production use");
        let domain = client.server_domain.as_ref().unwrap_or(&client.server_host);
        let stream = create_dangerous_tls_client_stream(svr_addr, domain).await?;
        let ws_stream = create_ws_stream(dst_addr, config, udp_tunnel, stream).await?;
        return Ok(ws_stream);
    }

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
) -> Result<WsStream> {
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
    let host = client.server_domain.as_ref().unwrap_or(&client.server_host);

    let uri = format!("ws://{host}/{tunnel_path}/");

    let uri = WeirdUri::new(&uri, b64_dst, udp_tunnel, client.client_id.clone());

    let (v, key) = client::generate_request(uri.into_client_request()?)?;
    stream.write_all(&v).await?;

    let mut buf = BytesMut::with_capacity(2048);
    stream.read_buf(&mut buf).await?;

    let response = Response::try_parse(&buf)?.ok_or("response parse failed")?.1;
    let remote_key = response.headers().get("Sec-WebSocket-Accept").ok_or(format!("{response:?}"))?;

    let accept_key = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());

    if accept_key.as_str() != remote_key.to_str().map_err(|e| e.to_string())? {
        return Err(Error::from("accept key error"));
    }

    let ws_stream = WebSocketStream::from_raw_socket(stream, Role::Client, None).await;
    // let (mut ws_stream, _) = tokio_tungstenite::client_async(uri, stream).await?;

    Ok(ws_stream)
}

type WsStream = WebSocketStream<TcpStream>;
type WsTlsStream = WebSocketStream<TlsStream<TcpStream>>;

use connection_pool::{ConnectionManager, ConnectionPool};
use std::future::Future;
use std::pin::Pin;

const VALID_TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

#[derive(Clone)]
pub struct WsPlainConnectionManager {
    pub config: Config,
}

impl ConnectionManager for WsPlainConnectionManager {
    type Connection = WsStream;
    type Error = Error;
    type CreateFut = Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send>>;
    type ValidFut<'a>
        = Pin<Box<dyn Future<Output = bool> + Send + 'a>>
    where
        Self: 'a;

    fn create_connection(&self) -> Self::CreateFut {
        let config = self.config.clone();
        Box::pin(async move {
            let client = config.client.as_ref().ok_or("client not exist")?;
            let server_addr = client.server_ip_addr.ok_or("server host")?;
            let ws = create_plaintext_ws_stream(server_addr, None, &config, None).await?;
            Ok(ws)
        })
    }

    fn is_valid<'a>(&'a self, stream: &'a mut Self::Connection) -> Self::ValidFut<'a> {
        Box::pin(async move {
            let r = tokio::time::timeout(VALID_TEST_TIMEOUT, stream.send(Message::Ping(vec![].into()))).await;
            if !matches!(r, Ok(Ok(_))) {
                return false;
            }
            matches!(tokio::time::timeout(VALID_TEST_TIMEOUT, stream.next()).await, Ok(Some(_)))
        })
    }
}

#[derive(Clone)]
pub struct WsTlsConnectionManager {
    pub config: Config,
}

impl ConnectionManager for WsTlsConnectionManager {
    type Connection = WsTlsStream;
    type Error = Error;
    type CreateFut = Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send>>;
    type ValidFut<'a>
        = Pin<Box<dyn Future<Output = bool> + Send + 'a>>
    where
        Self: 'a;

    fn create_connection(&self) -> Self::CreateFut {
        let config = self.config.clone();
        Box::pin(async move {
            let client = config.client.as_ref().ok_or("client not exist")?;
            let server_addr = client.server_ip_addr.ok_or("server host")?;
            let ws = create_tls_ws_stream(server_addr, None, &config, None).await?;
            Ok(ws)
        })
    }

    fn is_valid<'a>(&'a self, stream: &'a mut Self::Connection) -> Self::ValidFut<'a> {
        Box::pin(async move {
            let r = tokio::time::timeout(VALID_TEST_TIMEOUT, stream.send(Message::Ping(vec![].into()))).await;
            if !matches!(r, Ok(Ok(_))) {
                return false;
            }
            matches!(tokio::time::timeout(VALID_TEST_TIMEOUT, stream.next()).await, Ok(Some(_)))
        })
    }
}
