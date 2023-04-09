use crate::{
    b64str_to_address,
    config::Config,
    error::{Error, Result},
    tls::*,
    traffic_audit::{TrafficAudit, TrafficAuditPtr},
    weirduri::{CLIENT_ID, TARGET_ADDRESS, UDP_TUNNEL},
    STREAM_BUFFER_SIZE,
};
use bytes::{BufMut, BytesMut};
use futures_util::{SinkExt, StreamExt};
use socks5_impl::protocol::Address;
use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::Mutex,
};
use tokio_rustls::{rustls, TlsAcceptor};
use tokio_tungstenite::{accept_hdr_async, WebSocketStream};
use tungstenite::{
    handshake::server::{create_response, ErrorResponse, Request, Response},
    handshake::{machine::TryParse, server},
    protocol::{Message, Role},
};

const WS_HANDSHAKE_LEN: usize = 1024;
const WS_MSG_HEADER_LEN: usize = 14;

pub async fn run_server(config: &Config, exiting_flag: Option<Arc<AtomicBool>>) -> Result<()> {
    log::info!("starting {} server...", env!("CARGO_PKG_NAME"));
    log::trace!("with following settings:");
    log::trace!("{}", serde_json::to_string_pretty(config)?);

    let server = config.server.as_ref().ok_or("No server settings")?;
    let h = server.listen_host.clone();
    let p = server.listen_port;
    let addr: SocketAddr = (h, p).to_socket_addrs()?.next().ok_or("Invalid server address")?;

    let certs = if let Some(ref cert) = server.certfile {
        if !config.disable_tls() {
            server_load_certs(cert).ok()
        } else {
            None
        }
    } else {
        None
    };

    let keys = if let Some(ref key) = server.keyfile {
        if !config.disable_tls() {
            server_load_keys(key).ok()
        } else {
            None
        }
    } else {
        None
    };

    let svr_cfg = if let (Some(certs), Some(mut keys)) = (certs, keys) {
        rustls::ServerConfig::builder()
            .with_safe_defaults()
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

    let listener = TcpListener::bind(&addr).await?;

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        if let Some(exiting_flag) = &exiting_flag {
            if exiting_flag.load(Ordering::Relaxed) {
                log::info!("exiting...");
                break;
            }
        }
        let acceptor = acceptor.clone();
        let config = config.clone();
        let traffic_audit = traffic_audit.clone();

        let incoming_task = async move {
            if let Some(acceptor) = acceptor {
                let stream = acceptor.accept(stream).await?;
                if let Err(e) = handle_incoming(stream, peer_addr, config, traffic_audit).await {
                    log::debug!("{}: {}", peer_addr, e);
                }
            } else if let Err(e) = handle_incoming(stream, peer_addr, config, traffic_audit).await {
                log::debug!("{}: {}", peer_addr, e);
            } else {
                log::debug!("some unknown error with {}", peer_addr);
            }
            Ok::<_, Error>(())
        };

        tokio::spawn(async move {
            if let Err(err) = incoming_task.await {
                log::debug!("{:?}", err);
            }
        });
    }
    Ok(())
}

async fn handle_incoming<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    peer: SocketAddr,
    config: Config,
    traffic_audit: TrafficAuditPtr,
) -> Result<()> {
    let mut buf = BytesMut::with_capacity(2048);
    let size = stream.read_buf(&mut buf).await?;
    if size == 0 {
        return Err(Error::from("empty request"));
    }

    if !check_uri_path(&buf, &config.tunnel_path)? {
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

fn check_uri_path(buf: &[u8], path: &str) -> Result<bool> {
    let mut headers = [httparse::EMPTY_HEADER; 512];
    let mut req = httparse::Request::new(&mut headers);
    req.parse(buf)?;

    if let Some(p) = req.path {
        if p == path {
            return Ok(true);
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
    let forward_addr = &SocketAddr::new(host.parse()?, port);

    if tls_enable {
        let cert_store = retrieve_root_cert_store_for_client(&None)?;
        let to_stream = create_tls_client_stream(cert_store, forward_addr, host).await?;
        forward_traffic(stream, to_stream, data).await
    } else {
        let to_stream = crate::tcp_stream::create(forward_addr).await?;
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
    let mut target_address = "".to_string();
    let mut uri_path = "".to_string();
    let mut udp_tunnel = false;
    let mut client_id = None;

    let mut retrieve_values = |req: &Request| {
        uri_path = req.uri().path().to_string();
        if let Some(value) = req.headers().get(TARGET_ADDRESS) {
            if let Ok(value) = value.to_str() {
                target_address = value.to_string();
            }
        }
        if let Some(value) = req.headers().get(UDP_TUNNEL) {
            if let Ok(value) = value.to_str() {
                udp_tunnel = value.parse::<bool>().unwrap_or(false);
            }
        }
        if let Some(value) = req.headers().get(CLIENT_ID) {
            if let Ok(value) = value.to_str() {
                client_id = Some(value.to_string());
            }
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
        log::warn!("{} -> client id: \"{:?}\" is disabled", peer, client_id);
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
        log::trace!("[UDP] {} tunneling established", peer);
        result = create_udp_tunnel(ws_stream, config, traffic_audit, &client_id).await;
        if let Err(ref e) = result {
            log::debug!("[UDP] {} closed error: {}", peer, e);
        } else {
            log::trace!("[UDP] {} closed.", peer);
        }
    } else {
        let addr_str = b64str_to_address(&target_address, false)?.to_string();
        let dst_addr = addr_str.to_socket_addrs()?.next().ok_or("addr string parse failed")?;
        log::trace!("{} -> {} {client_id:?} uri path: \"{}\"", peer, dst_addr, uri_path);
        result = normal_tunnel(ws_stream, config, traffic_audit, &client_id, &dst_addr).await;
        if let Err(ref e) = result {
            log::debug!("{} <> {} connection closed error: {}", peer, dst_addr, e);
        } else {
            log::trace!("{} <> {} connection closed.", peer, dst_addr);
        }
    }
    result
}

async fn normal_tunnel<S: AsyncRead + AsyncWrite + Unpin>(
    mut ws_stream: WebSocketStream<S>,
    _config: Config,
    traffic_audit: TrafficAuditPtr,
    client_id: &Option<String>,
    dst_addr: &SocketAddr,
) -> Result<()> {
    let mut outgoing = crate::tcp_stream::create(dst_addr).await?;

    let (ws_stream_tx, mut ws_stream_rx) = tokio::sync::mpsc::channel(1024);
    let (outgoing_tx, mut outgoing_rx) = tokio::sync::mpsc::channel(1024);

    let ws_stream_to_outgoing = async move {
        loop {
            tokio::select! {
                Some(msg) = ws_stream.next() => {
                    let msg = msg?;
                    if let Some(client_id) = &client_id {
                        let len = (msg.len() + WS_MSG_HEADER_LEN) as u64;
                        traffic_audit.lock().await.add_upstream_traffic_of(client_id, len);
                    }
                    if msg.is_close() {
                        break;
                    }
                    if msg.is_text() || msg.is_binary() {
                        outgoing_tx.send(msg.into_data()).await?;
                    }
                }
                Some(data) = ws_stream_rx.recv() => {
                    let msg = Message::binary(data);
                    if let Some(client_id) = &client_id {
                        let len = (msg.len() + WS_MSG_HEADER_LEN) as u64;
                        traffic_audit.lock().await.add_downstream_traffic_of(client_id, len);
                    }
                    ws_stream.send(msg).await?;
                }
                else => {
                    break;
                }
            }
        }
        Ok::<_, Error>(())
    };

    let outgoing_to_ws_stream = async move {
        loop {
            tokio::select! {
                Ok(data) = async {
                    let mut b2 = [0; STREAM_BUFFER_SIZE];
                    let n = outgoing.read(&mut b2).await?;
                    Ok::<_, Error>(Some(b2[..n].to_vec()))
                 } => {
                    if let Some(data) = data {
                        if data.is_empty() {
                            break;
                        }
                        ws_stream_tx.send(data).await?;
                    } else {
                        break;
                    }
                }
                Some(msg) = outgoing_rx.recv() => {
                    outgoing.write_all(&msg).await?;
                }
                else => {
                    break;
                }
            }
        }
        Ok::<_, Error>(())
    };

    tokio::select! {
        r = ws_stream_to_outgoing => { if let Err(e) = r { log::debug!("{} ws_stream_to_outgoing \"{}\"", dst_addr, e); } }
        r = outgoing_to_ws_stream => { if let Err(e) = r { log::debug!("{} outgoing_to_ws_stream \"{}\"", dst_addr, e); } }
    }
    Ok(())
}

async fn create_udp_tunnel<S: AsyncRead + AsyncWrite + Unpin>(
    mut ws_stream: WebSocketStream<S>,
    _config: Config,
    traffic_audit: TrafficAuditPtr,
    client_id: &Option<String>,
) -> Result<()> {
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let udp_socket_v6 = UdpSocket::bind("[::]:0").await?;

    let mut buf = vec![0u8; STREAM_BUFFER_SIZE];
    let mut buf_v6 = vec![0u8; STREAM_BUFFER_SIZE];

    let dst_src_pairs = Arc::new(Mutex::new(HashMap::new()));

    loop {
        tokio::select! {
            Some(msg) = ws_stream.next() => {
                let msg = msg?;
                if let Some(client_id) = client_id {
                    let len = (msg.len() + WS_MSG_HEADER_LEN) as u64;
                    traffic_audit.lock().await.add_upstream_traffic_of(client_id, len);
                }
                if msg.is_close() {
                    break;
                }
                if msg.is_text() || msg.is_binary() {
                    let data = msg.into_data();
                    let mut buf = BytesMut::from(&data[..]);
                    let dst_addr = Address::from_data(&buf)?;
                    let _ = buf.split_to(dst_addr.serialized_len());
                    let src_addr = Address::from_data(&buf)?;
                    let _ = buf.split_to(src_addr.serialized_len());
                    let pkt = buf.to_vec();
                    log::trace!("[UDP] {src_addr} -> {dst_addr} length {}", pkt.len());

                    dst_src_pairs.lock().await.insert(dst_addr.clone(), src_addr);

                    let dst_addr = SocketAddr::try_from(dst_addr)?;

                    if dst_addr.is_ipv4() {
                        udp_socket.send_to(&pkt, &dst_addr).await?;
                    } else {
                        udp_socket_v6.send_to(&pkt, dst_addr).await?;
                    }
                }
            }
            Ok((len, addr)) = udp_socket.recv_from(&mut buf) => {
                let pkt = buf[..len].to_vec();
                _write_ws_stream(&pkt, &mut ws_stream, &dst_src_pairs, addr, &traffic_audit, client_id).await?;
            }
            Ok((len, addr)) = udp_socket_v6.recv_from(&mut buf_v6) => {
                let pkt = buf_v6[..len].to_vec();
                _write_ws_stream(&pkt, &mut ws_stream, &dst_src_pairs, addr, &traffic_audit, client_id).await?;
            }
            else => {
                break;
            }
        }
    }
    Ok(())
}

async fn _write_ws_stream<S: AsyncRead + AsyncWrite + Unpin>(
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
        // write back to client, data format: src_addr + dst_addr + payload
        let mut buf = BytesMut::new();
        src_addr.write_to_buf(&mut buf);
        dst_addr.write_to_buf(&mut buf);
        buf.put_slice(pkt);

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
