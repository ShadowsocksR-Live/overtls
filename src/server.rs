use crate::{b64str_to_address, config::Config, tls::*, udprelay, weirduri::TARGET_ADDRESS, weirduri::UDP};
use bytes::{BufMut, BytesMut};
use futures_util::{SinkExt, StreamExt};
use socks5_proto::Address;
use std::net::{SocketAddr, ToSocketAddrs};
use std::{collections::HashMap, sync::Arc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::{net::UdpSocket, sync::Mutex};
use tokio_rustls::{rustls, server::TlsStream, TlsAcceptor};
use tokio_tungstenite::{accept_hdr_async, WebSocketStream};
use tungstenite::{
    handshake::server::{create_response, ErrorResponse, Request, Response},
    handshake::{machine::TryParse, server},
    protocol::{Message, Role},
};

pub async fn run_server(config: &Config) -> anyhow::Result<()> {
    log::info!("starting {} server...", crate::program_name());
    log::trace!("with following settings:");
    log::trace!("{}", serde_json::to_string_pretty(config)?);

    let server = config.server.as_ref();
    let server = server.ok_or_else(|| anyhow::anyhow!("server settings"))?;
    let addr = format!("{}:{}", server.listen_host, server.listen_port);

    let certs = if let Some(ref cert) = server.certfile {
        server_load_certs(cert).ok()
    } else {
        None
    };

    let keys = if let Some(ref key) = server.keyfile {
        server_load_keys(key).ok()
    } else {
        None
    };

    let svr_cfg = if let (Some(certs), Some(mut keys)) = (certs, keys) {
        rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, keys.remove(0))
            .map_err(|err| anyhow::anyhow!(err))
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

    let listener = TcpListener::bind(&addr).await?;

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let config = config.clone();

        let incoming_task = async move {
            if let Some(acceptor) = acceptor {
                let stream = acceptor.accept(stream).await?;
                if let Err(e) = handle_tls_incoming(stream, config).await {
                    log::debug!("{}: {}", peer_addr, e);
                }
            } else if let Err(e) = handle_incoming(stream, config).await {
                log::debug!("{}: {}", peer_addr, e);
            }
            Ok::<_, anyhow::Error>(())
        };

        tokio::spawn(async move {
            if let Err(err) = incoming_task.await {
                log::debug!("{:?}", err);
            }
        });
    }
}

fn extract_forward_addr(config: &Config) -> Option<String> {
    config.server.as_ref()?.forward_addr.clone()
}

async fn handle_tls_incoming(mut stream: TlsStream<TcpStream>, config: Config) -> anyhow::Result<()> {
    let peer = stream.get_ref().0.peer_addr()?;

    let mut buf = BytesMut::with_capacity(2048);
    let size = stream.read_buf(&mut buf).await?;
    if size == 0 {
        return Err(anyhow::anyhow!("empty request"));
    }

    if !check_uri_path(&buf, &config.tunnel_path).await? {
        return forward_traffic_wrapper(stream, &buf, &config).await;
    }

    websocket_traffic_handler(stream, config, peer, &buf).await
}

async fn forward_traffic<StreamFrom, StreamTo>(from: StreamFrom, mut to: StreamTo, data: &[u8]) -> anyhow::Result<()>
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

async fn check_uri_path(buf: &[u8], path: &str) -> anyhow::Result<bool> {
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

async fn forward_traffic_wrapper<S>(stream: S, data: &[u8], config: &Config) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    log::debug!("not match path \"{}\", forward traffic directly...", config.tunnel_path);
    let forword_addr = extract_forward_addr(config).ok_or_else(|| anyhow::anyhow!(""))?;
    let to_stream = TcpStream::connect(forword_addr).await?;
    forward_traffic(stream, to_stream, data).await
}

async fn handle_incoming(stream: TcpStream, config: Config) -> anyhow::Result<()> {
    let mut buf = [0; 512];
    stream.peek(&mut buf).await?;

    if !check_uri_path(&buf, &config.tunnel_path).await? {
        return forward_traffic_wrapper(stream, &[], &config).await;
    }

    let peer = stream.peer_addr()?;

    websocket_traffic_handler(stream, config, peer, &[]).await
}

async fn websocket_traffic_handler<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    config: Config,
    peer: SocketAddr,
    handshake: &[u8],
) -> anyhow::Result<()> {
    log::trace!("{} -> tunnel path \"{}\"", peer, config.tunnel_path);

    let mut target_address = "".to_string();
    let mut uri_path = "".to_string();
    let mut udp = false;

    let mut retrieve_values = |req: &Request| {
        uri_path = req.uri().path().to_string();
        if let Some(value) = req.headers().get(TARGET_ADDRESS) {
            if let Ok(value) = value.to_str() {
                target_address = value.to_string();
            }
        }
        if let Some(value) = req.headers().get(UDP) {
            if let Ok(value) = value.to_str() {
                udp = value.parse::<bool>().unwrap_or(false);
            }
        }
    };

    let mut ws_stream: WebSocketStream<S>;

    if !handshake.is_empty() {
        if let Some((_, req)) = Request::try_parse(handshake)? {
            retrieve_values(&req);

            let res = create_response(&req)?;
            let mut output = vec![];
            server::write_response(&mut output, &res)?;
            stream.write_buf(&mut &output[..]).await?;

            ws_stream = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
        } else {
            return Err(anyhow::anyhow!("invalid handshake"));
        }
    } else {
        let check_headers_callback = |req: &Request, res: Response| -> anyhow::Result<Response, ErrorResponse> {
            retrieve_values(req);
            Ok(res)
        };
        ws_stream = accept_hdr_async(stream, check_headers_callback).await?;
    }

    if udp {
        return udp_tunnel(ws_stream, peer, uri_path, config).await;
    }

    let addr_str = b64str_to_address(&target_address, false).await?.to_string();
    let target_address = addr_str.to_socket_addrs()?.next().ok_or_else(|| anyhow::anyhow!(""))?;

    log::trace!("{} -> {}  uri path: \"{}\"", peer, addr_str, uri_path);

    let mut outgoing = TcpStream::connect(target_address).await?;

    let (ws_stream_tx, mut ws_stream_rx) = tokio::sync::mpsc::channel(1024);
    let (outgoing_tx, mut outgoing_rx) = tokio::sync::mpsc::channel(1024);

    let ws_stream_to_outgoing = async move {
        loop {
            tokio::select! {
                Some(msg) = ws_stream.next() => {
                    let msg = msg?;
                    if msg.is_close() {
                        break;
                    }
                    if msg.is_text() || msg.is_binary() {
                        outgoing_tx.send(msg.into_data()).await?;
                    }
                }
                Some(data) = ws_stream_rx.recv() => {
                    ws_stream.send(Message::binary(data)).await?;
                }
                else => {
                    break;
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    let outgoing_to_ws_stream = async move {
        loop {
            tokio::select! {
                Ok(data) = async {
                    let mut b2 = [0; 2048];
                    let n = outgoing.read(&mut b2).await?;
                    Ok::<_, anyhow::Error>(Some(b2[..n].to_vec()))
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
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        r = ws_stream_to_outgoing => { if let Err(e) = r { log::debug!("{} ws_stream_to_outgoing \"{}\"", peer, e); } }
        r = outgoing_to_ws_stream => { if let Err(e) = r { log::debug!("{} outgoing_to_ws_stream \"{}\"", peer, e); } }
    }
    log::trace!("{} <> {} connection closed.", peer, addr_str);

    Ok(())
}

async fn udp_tunnel<S: AsyncRead + AsyncWrite + Unpin>(
    mut ws_stream: WebSocketStream<S>,
    peer: SocketAddr,
    uri_path: String,
    _config: Config,
) -> anyhow::Result<()> {
    log::trace!("{} -> udp target uri path: \"{}\"", peer, uri_path);

    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let udp_socket_v6 = UdpSocket::bind("[::]:0").await?;

    let mut buf = vec![0u8; 2048];
    let mut buf_v6 = vec![0u8; 2048];

    let addresses = Arc::new(Mutex::new(HashMap::new()));

    loop {
        tokio::select! {
            Some(msg) = ws_stream.next() => {
                let msg = msg?;
                if msg.is_close() {
                    break;
                }
                if msg.is_text() || msg.is_binary() {
                    let data = msg.into_data();
                    let buf = BytesMut::from(&data[..]);
                    let dst_addr = Address::read_from(&mut &buf[..]).await?;
                    let src_addr = Address::read_from(&mut &buf[..]).await?;
                    let pkt = buf.to_vec();
                    // log::debug!("[UDP] packet from {src_addr} -> {dst_addr} {} bytes", pkt.len());

                    addresses.lock().await.insert(dst_addr.clone(), src_addr);

                    let dst_addr = udprelay::to_socket_addr(&dst_addr)?;

                    if dst_addr.is_ipv4() {
                        udp_socket.send_to(&pkt, &dst_addr).await?;
                    } else {
                        udp_socket_v6.send_to(&pkt, dst_addr).await?;
                    }
                }
            }
            Ok((len, addr)) = udp_socket.recv_from(&mut buf) => {
                let pkt = buf[..len].to_vec();
                _write_ws_stream(&pkt, &mut ws_stream, &addresses, addr).await?;
            }
            Ok((len, addr)) = udp_socket_v6.recv_from(&mut buf_v6) => {
                let pkt = buf_v6[..len].to_vec();
                _write_ws_stream(&pkt, &mut ws_stream, &addresses, addr).await?;
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
    addresses: &Arc<Mutex<HashMap<Address, Address>>>,
    addr: SocketAddr,
) -> anyhow::Result<()> {
    let dst_addr = Address::SocketAddress(addr);
    let src_addr = addresses.lock().await.get(&dst_addr).cloned();
    if let Some(src_addr) = src_addr {
        // write back to client, data format: src_addr + dst_addr + payload
        let mut buf = BytesMut::new();
        src_addr.write_to_buf(&mut buf);
        dst_addr.write_to_buf(&mut buf);
        buf.put_slice(pkt);

        ws_stream.send(Message::binary(buf.to_vec())).await?;
    }
    Ok(())
}
