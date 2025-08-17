use crate::{
    b64str_to_address,
    config::{Config, TEST_TIMEOUT_SECS},
    error::{Error, Result},
    tls::*,
    traffic_audit::{TrafficAudit, TrafficAuditPtr},
    weirduri::{CLIENT_ID, TARGET_ADDRESS, UDP_TUNNEL},
};
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use socks5_impl::protocol::Address;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::Mutex,
};
use tokio_rustls::{TlsAcceptor, rustls};
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async,
    tungstenite::{
        handshake::server::{ErrorResponse, Request, Response, create_response},
        handshake::{machine::TryParse, server},
        protocol::{Message, Role},
    },
};

pub(crate) const START_SESSION: &str = "Start session";
pub(crate) const END_SESSION: &str = "End session";

const WS_HANDSHAKE_LEN: usize = 1024;
const WS_MSG_HEADER_LEN: usize = 14;

pub async fn run_server(config: &Config, exiting_flag: crate::CancellationToken) -> Result<()> {
    log::info!("starting {} {} server...", clap::crate_name!(), crate::cmdopt::version_info());
    log::trace!("with following settings:");
    log::trace!("{}", serde_json::to_string_pretty(config)?);

    let server = config.server.as_ref().ok_or("No server settings")?;
    let h = server.listen_host.clone();
    let p = server.listen_port;
    let addr: SocketAddr = (h, p).to_socket_addrs()?.next().ok_or("Invalid server listen address")?;

    let certs = server.certfile.as_ref().filter(|_| !config.disable_tls()).and_then(|cert| {
        let certs = server_load_certs(cert);
        if let Err(err) = &certs {
            log::warn!("failed to load certificate file: {err}");
        }
        certs.ok()
    });

    let keys = server.keyfile.as_ref().filter(|_| !config.disable_tls()).and_then(|key| {
        let keys = server_load_keys(key);
        if let Err(err) = &keys {
            log::warn!("failed to load key file: {err}");
        }
        keys.ok().filter(|keys| !keys.is_empty())
    });

    let svr_cfg = if let (Some(certs), Some(mut keys)) = (certs, keys) {
        let _key = keys.first().ok_or("no keys")?;
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, keys.remove(0))
            .ok()
    } else {
        None
    };

    let acceptor = svr_cfg.map(|svr_cfg| TlsAcceptor::from(std::sync::Arc::new(svr_cfg)));
    if acceptor.is_none() {
        log::warn!("no certificate and key file, using plain TCP");
    } else {
        log::info!("using TLS");
    }

    let traffic_audit = Arc::new(Mutex::new(TrafficAudit::new()));

    let listener = match TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(e) => {
            log::error!("failed to bind to {} in file {} at line {}: \"{}\"", addr, file!(), line!(), e);
            return Err(e.into());
        }
    };

    let session_id = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let session_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    loop {
        tokio::select! {
            _ = exiting_flag.cancelled() => {
                log::info!("exiting...");
                break;
            }
            ret = listener.accept() => {
                let (stream, peer_addr) = ret?;
                let acceptor = acceptor.clone();
                let config = config.clone();
                let traffic_audit = traffic_audit.clone();

                let incoming_task = async move {
                    if let Some(acceptor) = acceptor {
                        let stream = acceptor.accept(stream).await?;
                        handle_incoming(stream, peer_addr, config, traffic_audit).await?;
                    } else {
                        handle_incoming(stream, peer_addr, config, traffic_audit).await?;
                    }
                    Ok::<_, Error>(())
                };

                let session_id = session_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let session_count = session_count.clone();

                tokio::spawn(async move {
                    let count = session_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    log::debug!("session #{session_id} from {peer_addr} started, session count {count}");
                    if let Err(e) = incoming_task.await {
                        log::debug!("{peer_addr}: {e}");
                    }
                    let count = session_count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) - 1;
                    log::debug!("session #{session_id} from {peer_addr} ended, session count {count}");
                });
            }
        }
    }

    Ok(())
}

async fn handle_incoming<S>(mut stream: S, peer: SocketAddr, config: Config, traffic_audit: TrafficAuditPtr) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = BytesMut::with_capacity(2048);
    let size = stream.read_buf(&mut buf).await?;
    if size == 0 {
        return Err(Error::from("empty request"));
    }

    if !check_uri_path(&buf, &config.tunnel_path.extract())? {
        return forward_traffic_wrapper(stream, &buf, &config).await;
    }

    websocket_traffic_handler(stream, config, peer, &buf, traffic_audit).await
}

async fn forward_traffic<StreamFrom, StreamTo>(from: StreamFrom, mut to: StreamTo, data: &[u8]) -> Result<()>
where
    StreamFrom: AsyncRead + AsyncWrite + Unpin,
    StreamTo: AsyncRead + AsyncWrite + Unpin,
{
    if !data.is_empty() {
        to.write_all(data).await?;
    }
    let (mut from_reader, mut from_writer) = tokio::io::split(from);
    let (mut to_reader, mut to_writer) = tokio::io::split(to);
    tokio::select! {
        ret = tokio::io::copy(&mut from_reader, &mut to_writer) => {
            ret?;
            to_writer.shutdown().await?;
        },
        ret = tokio::io::copy(&mut to_reader, &mut from_writer) => {
            ret?;
            from_writer.shutdown().await?
        }
    }
    Ok(())
}

fn check_uri_path(buf: &[u8], path: &[&str]) -> Result<bool> {
    let mut headers = [httparse::EMPTY_HEADER; 512];
    let mut req = httparse::Request::new(&mut headers);
    req.parse(buf)?;

    if let Some(p) = req.path {
        for path in path {
            if p == *path {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

async fn forward_traffic_wrapper<S>(stream: S, data: &[u8], config: &Config) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    log::debug!("not match path \"{}\", forward traffic directly...", config.tunnel_path);
    let forward_addr = config.forward_addr().ok_or("config forward addr not exist")?;

    let url = url::Url::parse(&forward_addr)?;
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err("".into());
    }
    let tls_enable = scheme == "https";
    let host = url.host_str().ok_or("url host not exist")?;
    let port = url.port_or_known_default().ok_or("port not exist")?;
    let forward_addr = SocketAddr::new(host.parse()?, port);

    if tls_enable {
        let cert_store = retrieve_root_cert_store_for_client(&None)?;
        let to_stream = create_tls_client_stream(cert_store, forward_addr, host).await?;
        forward_traffic(stream, to_stream, data).await
    } else {
        let to_stream = crate::tcp_stream::tokio_create(forward_addr).await?;
        forward_traffic(stream, to_stream, data).await
    }
}

async fn websocket_traffic_handler<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    config: Config,
    peer: SocketAddr,
    handshake: &[u8],
    traffic_audit: TrafficAuditPtr,
) -> Result<()> {
    let mut uri_path = "".to_string();
    let mut target_address = None;
    let mut udp_tunnel = false;
    let mut client_id = None;

    let mut retrieve_values = |req: &Request| {
        uri_path = req.uri().path().to_string();
        if let Some(value) = req.headers().get(TARGET_ADDRESS)
            && let Ok(value) = value.to_str()
        {
            target_address = Some(value.to_string());
        }
        if let Some(value) = req.headers().get(UDP_TUNNEL)
            && let Ok(value) = value.to_str()
        {
            udp_tunnel = value.parse::<bool>().unwrap_or(false);
        }
        if let Some(value) = req.headers().get(CLIENT_ID)
            && let Ok(value) = value.to_str()
        {
            client_id = Some(value.to_string());
        }
    };

    let ws_stream: WebSocketStream<S>;

    if !handshake.is_empty() {
        if let Some((_, req)) = Request::try_parse(handshake)? {
            retrieve_values(&req);

            let res = create_response(&req)?;
            let mut output = vec![];
            server::write_response(&mut output, &res)?;
            stream.write_buf(&mut &output[..]).await?;

            ws_stream = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
        } else {
            return Err("invalid handshake".into());
        }
    } else {
        let check_headers_callback = |req: &Request, res: Response| -> std::result::Result<Response, ErrorResponse> {
            retrieve_values(req);
            Ok(res)
        };
        ws_stream = accept_hdr_async(stream, check_headers_callback).await?;
    }

    if let Some(client_id) = &client_id {
        traffic_audit.lock().await.add_client(client_id);
    }

    let mut enable_client = true;
    if config.manage_clients() {
        enable_client = false;
        if let Some(client_id) = &client_id {
            enable_client = traffic_audit.lock().await.get_enable_of(client_id);
        }
    }
    if !enable_client {
        log::warn!("{peer} -> client id: \"{client_id:?}\" is disabled");
        return Ok(());
    }

    if let Some(client_id) = &client_id {
        let len = WS_HANDSHAKE_LEN;
        let len = if !handshake.is_empty() { handshake.len() } else { len };
        let len = (len * 2) as u64;
        traffic_audit.lock().await.add_upstream_traffic_of(client_id, len);
    }

    let result;
    if udp_tunnel {
        log::trace!("[UDP] {peer} tunneling established");
        result = svr_udp_tunnel(ws_stream, config, traffic_audit, &client_id).await;
        if let Err(ref e) = result {
            log::debug!("[UDP] {peer} closed with error \"{e}\"");
        } else {
            log::trace!("[UDP] {peer} closed.");
        }
    } else {
        let stream = if let Some(target_address) = &target_address {
            let stream = tcp_stream_from_b64_str(target_address, &config, peer)?;
            let successful_addr = stream.peer_addr()?;
            log::trace!("{peer} -> {successful_addr} {client_id:?} uri path: \"{uri_path}\"");
            let stream = tokio::net::TcpStream::from_std(stream)?;
            Some(stream)
        } else {
            None
        };
        result = svr_normal_tunnel(ws_stream, peer, config, traffic_audit, &client_id, stream).await;
        log::trace!("{peer} connection closed with {result:?}.");
    }
    result
}

async fn svr_normal_tunnel<S: AsyncRead + AsyncWrite + Unpin>(
    mut ws_stream: WebSocketStream<S>,
    peer: SocketAddr,
    config: Config,
    traffic_audit: TrafficAuditPtr,
    client_id: &Option<String>,
    outgoing_stream: Option<tokio::net::TcpStream>,
) -> Result<()> {
    let is_old_client = outgoing_stream.is_some();
    let mut dst_addr = outgoing_stream.as_ref().and_then(|s| s.peer_addr().ok());
    let mut outgoing: Option<tokio::net::TcpStream> = outgoing_stream;
    let mut buffer = [0; crate::STREAM_BUFFER_SIZE];
    // Mark if outgoing has been written to
    let mut outgoing_can_be_read = false;

    loop {
        tokio::select! {
            msg = ws_stream.next() => {
                let msg = msg.ok_or(format!("{peer} -> {dst_addr:?} no Websocket message"))??;
                let len = (msg.len() + WS_MSG_HEADER_LEN) as u64;
                if let Some(client_id) = &client_id {
                    traffic_audit.lock().await.add_upstream_traffic_of(client_id, len);
                }
                match msg {
                    Message::Close(_) => {
                        log::debug!("{peer} <> {dst_addr:?} incoming connection closed normally");
                        break;
                    }
                    Message::Binary(data) => {
                        if let Some(outgoing) = &mut outgoing {
                            log::trace!("{peer} -> {dst_addr:?} length {len}");
                            outgoing.write_all(&data).await?;
                            outgoing_can_be_read = true;
                        } else {
                            log::warn!("{peer} -> no outgoing connection available, dropping data len = {}", data.len());
                        }
                    }
                    Message::Text(ref data) => {
                        let msg_str = data.as_str();
                        if msg_str == END_SESSION {
                            log::debug!("{peer} <> {dst_addr:?} ended session");
                            if let Some(mut stream) = outgoing.take() {
                                let _ = stream.shutdown().await;
                            }
                            dst_addr = None;
                            outgoing_can_be_read = false;
                        } else if let Some(dst_addr_str) = msg_str.strip_prefix(&format!("{START_SESSION}:")) {
                            outgoing_can_be_read = false;
                            // Close existing connection
                            if let Some(mut stream) = outgoing.take() {
                                let _ = stream.shutdown().await;
                                log::info!("{peer} <> {dst_addr:?} closed previous session");
                            }

                            match tcp_stream_from_b64_str(dst_addr_str.trim(), &config, peer) {
                                Ok(stream) => {
                                    let stream = tokio::net::TcpStream::from_std(stream)?;
                                    dst_addr = Some(stream.peer_addr()?);
                                    outgoing = Some(stream);
                                    log::info!("{peer} -> {dst_addr:?} started new session");
                                    // Feedback confirmation to client
                                    let msg = Message::Text(START_SESSION.into());
                                    svr_send_ws_message(&mut ws_stream, msg, &traffic_audit, client_id).await?;
                                }
                                Err(e) => {
                                    log::error!("{peer} failed to create connection from BASE64 address '{dst_addr_str}': {e}");
                                    let msg = Message::Text(END_SESSION.into());
                                    log::trace!("{peer} <> {dst_addr:?} sending text message to end session");
                                    svr_send_ws_message(&mut ws_stream, msg, &traffic_audit, client_id).await?;
                                    dst_addr = None;
                                }
                            }
                        } else {
                            log::warn!("{peer} -> {dst_addr:?} received text message len = {} in unexpected state", data.len());
                        }
                    }
                    Message::Ping(data) => {
                        log::debug!("{peer} -> {dst_addr:?} received ping message len = {}", data.len());
                    }
                    Message::Pong(data) => {
                        log::debug!("{peer} -> {dst_addr:?} received pong message len = {}", data.len());
                    }
                    _ => {
                        log::debug!("{peer} -> {dst_addr:?} received unexpected message len {}, ignoring", msg.len());
                    }
                }
            }
            len = async {
                match &mut outgoing {
                    Some(outgoing) if outgoing_can_be_read => outgoing.read(&mut buffer).await,
                    _ => {
                        // If there is no outgoing connection, or not written yet, wait until a connection is established and a message is sent to destination
                        futures_util::future::pending::<std::io::Result<usize>>().await
                    }
                }
            } => {
                match len {
                    Ok(0) => {
                        log::debug!("{peer} <> {dst_addr:?} outgoing connection reached EOF");
                        if is_old_client {
                            ws_stream.send(Message::Close(None)).await?;
                            break;
                        }
                        // Don't close the WebSocket, even don't close the outgoing connection
                        // At current moment, we just mark the outgoing connection as can't be read,
                        // but it's not means it can't be written to.
                        outgoing_can_be_read = false;
                    }
                    Ok(n) => {
                        let msg = Message::binary(buffer[..n].to_vec());
                        let len = (msg.len() + WS_MSG_HEADER_LEN) as u64;
                        log::trace!("{peer} <- {dst_addr:?} length {len}");
                        svr_send_ws_message(&mut ws_stream, msg, &traffic_audit, client_id).await?;
                    }
                    Err(e) => {
                        if is_old_client {
                            log::debug!("{peer} <> {dst_addr:?} outgoing connection closed '{e}'");
                            ws_stream.send(Message::Close(None)).await?;
                            break;
                        }
                        // Close the outgoing connection but keep the WebSocket connection
                        if let Some(mut stream) = outgoing.take() {
                            let _ = stream.shutdown().await;
                        }
                        dst_addr = None;
                        outgoing_can_be_read = false;
                        let msg = Message::Text(END_SESSION.into());
                        log::debug!("{peer} <> {dst_addr:?} sending text message to end session");
                        svr_send_ws_message(&mut ws_stream, msg, &traffic_audit, client_id).await?;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn svr_send_ws_message<S: AsyncRead + AsyncWrite + Unpin>(
    ws_stream: &mut WebSocketStream<S>,
    msg: Message,
    traffic_audit: &TrafficAuditPtr,
    client_id: &Option<String>,
) -> Result<()> {
    if let Some(client_id) = client_id {
        let len = (msg.len() + WS_MSG_HEADER_LEN) as u64;
        traffic_audit.lock().await.add_downstream_traffic_of(client_id, len);
    }
    ws_stream.send(msg).await?;
    Ok(())
}

async fn svr_udp_tunnel<S: AsyncRead + AsyncWrite + Unpin>(
    mut ws_stream: WebSocketStream<S>,
    _config: Config,
    traffic_audit: TrafficAuditPtr,
    client_id: &Option<String>,
) -> Result<()> {
    let udp_socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    let udp_socket_v6 = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await?;

    let mut buf = vec![0u8; crate::STREAM_BUFFER_SIZE];
    let mut buf_v6 = vec![0u8; crate::STREAM_BUFFER_SIZE];

    let dst_src_pairs = Arc::new(Mutex::new(HashMap::new()));

    loop {
        tokio::select! {
            Some(msg) = ws_stream.next() => {
                let msg = msg?;
                if let Some(client_id) = client_id {
                    let len = (msg.len() + WS_MSG_HEADER_LEN) as u64;
                    traffic_audit.lock().await.add_upstream_traffic_of(client_id, len);
                }
                match msg {
                    Message::Close(_) => {
                        log::trace!("[UDP] tunnel closed by remote client {client_id:?}");
                        break;
                    }
                    Message::Ping(_) => {
                        log::trace!("[UDP] received ping message, ignoring");
                    }
                    Message::Pong(_) => {
                        log::trace!("[UDP] received pong message, ignoring");
                    }
                    Message::Binary(data) => {
                        let buf = BytesMut::from(&data[..]);
                        svr_send_udp_packet_to_dst(buf, &dst_src_pairs, &udp_socket, &udp_socket_v6).await?;
                    }
                    Message::Text(_) => {
                        log::warn!("[UDP] unexpected text message, ignoring");
                    }
                    _ => {
                        log::warn!("[UDP] unexpected message type: {msg:?}, ignoring");
                    }
                }
            }
            Ok((len, addr)) = udp_socket.recv_from(&mut buf) => {
                let pkt = buf[..len].to_vec();
                svr_udp_write_ws_stream(&pkt, &mut ws_stream, &dst_src_pairs, addr, &traffic_audit, client_id).await?;
            }
            Ok((len, addr)) = udp_socket_v6.recv_from(&mut buf_v6) => {
                let pkt = buf_v6[..len].to_vec();
                svr_udp_write_ws_stream(&pkt, &mut ws_stream, &dst_src_pairs, addr, &traffic_audit, client_id).await?;
            }
            else => {
                break;
            }
        }
    }
    Ok(())
}

async fn svr_send_udp_packet_to_dst(
    mut buf: BytesMut,
    dst_src_pairs: &Arc<Mutex<HashMap<Address, Address>>>,
    udp_socket: &UdpSocket,
    udp_socket_v6: &UdpSocket,
) -> Result<()> {
    let (dst_addr, src_addr, pkt) = crate::udprelay::decode_udp_packet(&mut buf)?;
    log::trace!("[UDP] {src_addr} -> {dst_addr} length {}", pkt.len());

    dst_src_pairs.lock().await.insert(dst_addr.clone(), src_addr.clone());

    // select the IPv4 destination address first if available, otherwise use the IPv6 address
    let mut ipv4_addr = None;
    let mut ipv6_addr = None;
    for addr in dst_addr.to_socket_addrs()? {
        match addr {
            SocketAddr::V4(_) if ipv4_addr.is_none() => {
                ipv4_addr = Some(addr);
            }
            SocketAddr::V6(_) if ipv6_addr.is_none() => {
                ipv6_addr = Some(addr);
            }
            _ => {}
        }
    }
    let info = format!("{src_addr} <> {dst_addr} All addresses failed to select");
    let mut dst_addr = ipv4_addr.or(ipv6_addr).ok_or(Error::from(info))?;

    if dst_addr.port() == 53 && addr_is_private(&dst_addr) {
        match dst_addr {
            SocketAddr::V4(_) => dst_addr = "8.8.8.8:53".parse::<SocketAddr>()?,
            SocketAddr::V6(_) => dst_addr = "[2001:4860:4860::8888]:53".parse::<SocketAddr>()?,
        }
    }

    if dst_addr.is_ipv4() {
        udp_socket.send_to(&pkt, &dst_addr).await?;
    } else {
        udp_socket_v6.send_to(&pkt, dst_addr).await?;
    }
    Ok(())
}

// TODO: use IpAddr::is_global() instead when it's stable
fn addr_is_private(addr: &SocketAddr) -> bool {
    fn is_benchmarking(addr: &Ipv4Addr) -> bool {
        addr.octets()[0] == 198 && (addr.octets()[1] & 0xfe) == 18
    }
    fn addr_v4_is_private(addr: &Ipv4Addr) -> bool {
        is_benchmarking(addr) || addr.is_private() || addr.is_loopback() || addr.is_link_local()
    }
    match addr {
        SocketAddr::V4(addr) => addr_v4_is_private(addr.ip()),
        SocketAddr::V6(_) => false,
    }
}

async fn svr_udp_write_ws_stream<S: AsyncRead + AsyncWrite + Unpin>(
    pkt: &[u8],
    ws_stream: &mut WebSocketStream<S>,
    dst_src_pairs: &Arc<Mutex<HashMap<Address, Address>>>,
    addr: SocketAddr,
    traffic_audit: &TrafficAuditPtr,
    client_id: &Option<String>,
) -> Result<()> {
    let dst_addr = Address::from(addr);
    let src_addr = dst_src_pairs.lock().await.get(&dst_addr).cloned();
    if let Some(src_addr) = src_addr {
        // Note: here dst_addr and src_addr are swapped
        let buf = crate::udprelay::build_udp_packet(&src_addr, &dst_addr, pkt);

        let msg = Message::binary(buf.to_vec());

        log::trace!("[UDP] {src_addr} <- {dst_addr} length {}", pkt.len());
        if let Some(client) = client_id {
            let len = (msg.len() + WS_MSG_HEADER_LEN) as u64;
            traffic_audit.lock().await.add_downstream_traffic_of(client, len);
        }

        ws_stream.send(msg).await?;
    }
    Ok(())
}

fn tcp_stream_from_b64_str<T: AsRef<str>>(b64_addr: T, config: &Config, peer: SocketAddr) -> Result<std::net::TcpStream> {
    let addr_str = b64str_to_address(b64_addr.as_ref(), false)?.to_string();

    let time_out = std::time::Duration::from_secs(config.test_timeout_secs.unwrap_or(TEST_TIMEOUT_SECS));
    // try to connect to the first available address
    for dst_addr in addr_str.to_socket_addrs()? {
        match crate::tcp_stream::std_create(dst_addr, Some(time_out)) {
            Ok(stream) => {
                stream.set_nonblocking(true)?;
                return Ok(stream);
            }
            Err(ref e) => {
                log::debug!("{peer} <> {dst_addr} destination address is unreachable: {e}");
            }
        }
    }
    Err(Error::from(format!("{peer} <> {addr_str} All addresses failed to connect")))
}
