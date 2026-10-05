use crate::{
    b64str_to_address,
    config::{Config, TEST_TIMEOUT_SECS},
    error::{Error, Result},
    panel_sync::PanelSyncClient,
    tls::*,
    traffic_audit::{TrafficAudit, TrafficAuditPtr},
    weirduri::{CLIENT_ID, TARGET_ADDRESS, UDP_TUNNEL},
};
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use method_name::method_name_unstable;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use socks5_impl::protocol::Address;
use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::{Mutex, mpsc, watch},
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
use uuid::Uuid;

pub(crate) const START_SESSION: &str = "Start session";
pub(crate) const END_SESSION: &str = "End session";
pub(crate) const REMOTE_EOF: &str = "Remote EOF";

const WS_HANDSHAKE_LEN: usize = 1024;
const WS_MSG_HEADER_LEN: usize = 14;

pub async fn run_server(config: &Config, exiting_flag: crate::CancellationToken) -> Result<()> {
    let mn = method_name_unstable!();
    crate::ensure_rustls_crypto_provider()?;

    log::info!("starting {} {} server...", clap::crate_name!(), crate::cmdopt::version_info());
    log::trace!("with following settings:");
    log::trace!("{}", serde_json::to_string_pretty(config)?);

    let server = config.server.as_ref().ok_or("No server settings")?;
    let h = server.listen_host.clone();
    let p = server.listen_port;
    let addr: SocketAddr = (h, p).to_socket_addrs()?.next().ok_or("Invalid server listen address")?;

    let tls_paths = if config.disable_tls() {
        None
    } else {
        server.certfile.as_ref().zip(server.keyfile.as_ref())
    };
    let (tls_file_watcher, tls_events, cert_path, key_path) = match tls_paths {
        Some((cert_path, key_path)) => {
            let (watcher, events, cert_path, key_path) = watch_server_tls_files(cert_path, key_path)?;
            (Some(watcher), Some(events), Some(cert_path), Some(key_path))
        }
        None => (None, None, None, None),
    };
    let acceptor = tls_paths.and_then(|(cert_path, key_path)| match server_tls_acceptor(cert_path, key_path) {
        Ok(acceptor) => Some(acceptor),
        Err(error) => {
            log::warn!("{mn} -- failed to load server certificate or key: {error}");
            None
        }
    });
    let (tls_acceptor_tx, tls_acceptor_rx) = watch::channel(acceptor);
    if tls_acceptor_rx.borrow().is_none() {
        log::warn!("{mn} -- no certificate and key file, using plain TCP");
    } else {
        log::info!("{mn} -- using TLS");
    }

    let traffic_audit = Arc::new(Mutex::new(TrafficAudit::new()));

    let panel_sync_config = config.get_panel_sync_config();
    if let Some(panel_sync_config) = panel_sync_config
        && panel_sync_config.enabled.unwrap_or(false)
    {
        let sync_traffic_audit = traffic_audit.clone();
        let sync_quit = exiting_flag.clone();
        tokio::spawn(async move {
            let syncer = PanelSyncClient::new(&panel_sync_config);
            if let Err(e) = syncer.run(sync_traffic_audit, sync_quit).await {
                log::warn!("{} -- panel sync task stopped: {e}", method_name_unstable!());
            }
        });
    }

    let listener = match TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(e) => {
            log::error!("{mn} -- failed to bind to {addr} in file {} at line {}: \"{e}\"", file!(), line!(),);
            return Err(e.into());
        }
    };

    let session_id = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let session_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let _tls_file_watcher = tls_file_watcher;
    let mut tls_reload_task = match (tls_events, cert_path, key_path) {
        (Some(events), Some(cert_path), Some(key_path)) => Some(tokio::spawn(reload_server_tls_on_events(
            events,
            tls_acceptor_tx,
            cert_path,
            key_path,
            exiting_flag.clone(),
        ))),
        _ => None,
    };

    loop {
        tokio::select! {
            _ = exiting_flag.cancelled() => {
                log::info!("{mn} -- exiting...");
                break;
            }
            ret = listener.accept() => {
                let (stream, peer_addr) = ret?;
                let acceptor = tls_acceptor_rx.borrow().clone();
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
                    let mn = method_name_unstable!();
                    let count = session_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    log::debug!("{mn} -- session #{session_id} from {peer_addr} started, session count {count}");
                    if let Err(e) = incoming_task.await {
                        log::debug!("{mn} -- {peer_addr}: {e}");
                    }
                    let count = session_count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) - 1;
                    log::debug!("{mn} -- session #{session_id} from {peer_addr} ended, session count {count}");
                });
            }
        }
    }

    if let Some(task) = tls_reload_task.take() {
        let _ = task.await;
    }

    Ok(())
}

fn watch_server_tls_files(
    cert_path: &Path,
    key_path: &Path,
) -> std::io::Result<(RecommendedWatcher, mpsc::UnboundedReceiver<notify::Result<Event>>, PathBuf, PathBuf)> {
    let absolute_path = |path: &Path| -> std::io::Result<PathBuf> {
        if path.is_absolute() {
            Ok(path.to_path_buf())
        } else {
            Ok(std::env::current_dir()?.join(path))
        }
    };
    let cert_path = absolute_path(cert_path)?;
    let key_path = absolute_path(key_path)?;
    let (event_sender, events) = mpsc::unbounded_channel();
    let mut watcher = notify::recommended_watcher(move |event| {
        let _ = event_sender.send(event);
    })
    .map_err(std::io::Error::other)?;

    let directories: HashSet<PathBuf> = [&cert_path, &key_path]
        .into_iter()
        .filter_map(|path| path.parent().map(Path::to_path_buf))
        .collect();
    for directory in directories {
        watcher
            .watch(&directory, RecursiveMode::NonRecursive)
            .map_err(std::io::Error::other)?;
    }

    Ok((watcher, events, cert_path, key_path))
}

async fn reload_server_tls_on_events(
    mut events: mpsc::UnboundedReceiver<notify::Result<Event>>,
    tls_acceptor: watch::Sender<Option<TlsAcceptor>>,
    cert_path: PathBuf,
    key_path: PathBuf,
    exiting_flag: crate::CancellationToken,
) {
    let mn = method_name_unstable!();
    const DEBOUNCE: std::time::Duration = std::time::Duration::from_millis(250);
    loop {
        tokio::select! {
            _ = exiting_flag.cancelled() => return,
            event = events.recv() => match event {
                Some(Ok(event)) if !event_affects_tls_files(&event, &cert_path, &key_path) => continue,
                Some(Ok(_)) => {}
                Some(Err(error)) => {
                    log::warn!("{mn} -- TLS file watcher error: {error}");
                    continue;
                }
                None => return,
            },
        };
        let mut debounce = Box::pin(tokio::time::sleep(DEBOUNCE));
        loop {
            tokio::select! {
                _ = exiting_flag.cancelled() => return,
                _ = &mut debounce => break,
                event = events.recv() => match event {
                    Some(Ok(event)) if event_affects_tls_files(&event, &cert_path, &key_path) => {
                        debounce.as_mut().reset(tokio::time::Instant::now() + DEBOUNCE)
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => log::warn!("{mn} -- TLS file watcher error: {error}"),
                    None => return,
                },
            }
        }

        let cert_path_for_load = cert_path.clone();
        let key_path_for_load = key_path.clone();
        let load = tokio::task::spawn_blocking(move || server_tls_acceptor(&cert_path_for_load, &key_path_for_load));
        let result = tokio::select! {
            _ = exiting_flag.cancelled() => return,
            result = load => result,
        };
        match result {
            Ok(Ok(acceptor)) => {
                tls_acceptor.send_replace(Some(acceptor));
                log::info!("{mn} -- reloaded server TLS certificate and private key");
            }
            Ok(Err(error)) => {
                log::warn!("{mn} -- failed to reload server TLS certificate and private key; keeping the current configuration: {error}")
            }
            Err(error) => log::error!("{mn} -- TLS reload task failed: {error}"),
        }
    }
}

fn event_affects_tls_files(event: &Event, cert_path: &Path, key_path: &Path) -> bool {
    !event.kind.is_access() && event.paths.iter().any(|path| path == cert_path || path == key_path)
}

fn server_tls_acceptor(cert_path: &Path, key_path: &Path) -> std::io::Result<TlsAcceptor> {
    let certs = server_load_certs(cert_path).map_err(std::io::Error::other)?;
    let key = server_load_keys(key_path)
        .map_err(std::io::Error::other)?
        .into_iter()
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no private key found"))?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(std::io::Error::other)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
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
    let mn = method_name_unstable!();
    log::debug!("{mn} -- not match path \"{}\", forward traffic directly...", config.tunnel_path);
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
    let mut client_id: Option<Uuid> = None;

    let mut retrieve_values = |req: &Request| {
        uri_path = req.uri().path().to_string();
        if let Some(value) = req.headers().get(TARGET_ADDRESS)
            && let Ok(value) = value.to_str()
            && let Ok(address) = b64str_to_address(value, false)
        {
            target_address = Some(address);
        }
        if let Some(value) = req.headers().get(UDP_TUNNEL)
            && let Ok(value) = value.to_str()
        {
            udp_tunnel = value.parse::<bool>().unwrap_or(false);
        }
        if let Some(value) = req.headers().get(CLIENT_ID)
            && let Ok(value) = value.to_str()
            && let Ok(uuid) = Uuid::parse_str(value)
        {
            client_id = Some(uuid);
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
        #[allow(clippy::result_large_err)]
        let check_headers_callback = |req: &Request, res: Response| -> std::result::Result<Response, ErrorResponse> {
            retrieve_values(req);
            Ok(res)
        };
        ws_stream = accept_hdr_async(stream, check_headers_callback).await?;
    }

    if let Some(client_id) = &client_id {
        traffic_audit.lock().await.add_client(client_id);
    }

    let mut panel_sync_enabled = true;
    let panel_sync_config = config.get_panel_sync_config();
    if let Some(panel_sync_config) = panel_sync_config
        && panel_sync_config.enabled.unwrap_or(false)
    {
        panel_sync_enabled = false;
        if let Some(client_id) = &client_id {
            panel_sync_enabled = traffic_audit.lock().await.get_enable_of(client_id);
        }
    }
    let mn = method_name_unstable!();
    if !panel_sync_enabled {
        log::warn!("{mn} -- {peer} -> client id: \"{client_id:?}\" is disabled");
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
        log::trace!("{mn} -- [UDP] {peer} tunneling established");
        result = svr_udp_tunnel(ws_stream, config, traffic_audit, &client_id).await;
        if let Err(ref e) = result {
            log::debug!("{mn} -- [UDP] {peer} closed with error \"{e}\"");
        } else {
            log::trace!("{mn} -- [UDP] {peer} closed.");
        }
    } else {
        let stream = if let Some(target_address) = &target_address {
            let time_out = std::time::Duration::from_secs(config.test_timeout_secs.unwrap_or(TEST_TIMEOUT_SECS));
            let stream = tcp_stream_from_s5_address(target_address, time_out, peer)?;
            let successful_addr = stream.peer_addr()?;
            log::trace!("{peer} -> {successful_addr} {client_id:?} uri path: \"{uri_path}\"");
            let stream = tokio::net::TcpStream::from_std(stream)?;
            Some(stream)
        } else {
            None
        };
        result = svr_normal_tunnel(ws_stream, peer, config, traffic_audit, &client_id, stream).await;
        log::trace!("{mn} -- {peer} connection closed with {result:?}.");
    }
    result
}

async fn svr_normal_tunnel<S: AsyncRead + AsyncWrite + Unpin>(
    mut ws_stream: WebSocketStream<S>,
    peer: SocketAddr,
    config: Config,
    traffic_audit: TrafficAuditPtr,
    client_id: &Option<Uuid>,
    outgoing_stream: Option<tokio::net::TcpStream>,
) -> Result<()> {
    let is_old_client = outgoing_stream.is_some();
    let mut dst_addr = outgoing_stream.as_ref().and_then(|s| s.peer_addr().ok());
    let mut outgoing: Option<tokio::net::TcpStream> = outgoing_stream;
    let mut buffer = [0; crate::STREAM_BUFFER_SIZE];
    // Mark if outgoing has been written to
    let mut outgoing_can_be_read = false;
    let mut enable_check = tokio::time::interval(std::time::Duration::from_secs(1));
    let mn = method_name_unstable!();

    loop {
        tokio::select! {
            _ = enable_check.tick() => {
                if let Some(client_id) = client_id
                    && !traffic_audit.lock().await.get_enable_of(client_id)
                {
                    log::debug!("{mn} -- {peer} <> {dst_addr:?} client id {client_id:?} disabled by panel sync");
                    let _ = ws_stream.send(Message::Text(END_SESSION.into())).await;
                    break;
                }
            }
            msg = ws_stream.next() => {
                let msg = msg.ok_or(format!("{peer} -> {dst_addr:?} no Websocket message"))??;
                let len = (msg.len() + WS_MSG_HEADER_LEN) as u64;
                if let Some(client_id) = &client_id {
                    traffic_audit.lock().await.add_upstream_traffic_of(client_id, len);
                }
                match msg {
                    Message::Close(_) => {
                        log::debug!("{mn} -- {peer} <> {dst_addr:?} incoming connection closed normally");
                        break;
                    }
                    Message::Binary(data) => {
                        if let Some(outgoing) = &mut outgoing {
                            log::trace!("{mn} -- {peer} -> {dst_addr:?} length {len}");
                            outgoing.write_all(&data).await?;
                            outgoing_can_be_read = true;
                        } else {
                            log::warn!("{mn} -- {peer} -> no outgoing connection available, dropping data len = {}", data.len());
                        }
                    }
                    Message::Text(ref data) => {
                        let msg_str = data.as_str();
                        if let Some(reason) = msg_str.strip_prefix(END_SESSION) {
                            let reason = reason.strip_prefix(':').unwrap_or(reason).trim();
                            log::debug!("{mn} -- {peer} <> {dst_addr:?} ended session with '{END_SESSION}' message with '{reason}'");
                            if let Some(mut stream) = outgoing.take() {
                                let _ = stream.shutdown().await;
                            }
                            dst_addr = None;
                            outgoing_can_be_read = false;
                        } else if let Some(dst_addr_str) = msg_str.strip_prefix(START_SESSION) {
                            let dst_addr_str = dst_addr_str.strip_prefix(':').map(|s| s.trim()).unwrap_or("");
                            let dst_address = b64str_to_address(dst_addr_str, false).unwrap_or(Address::unspecified());
                            outgoing_can_be_read = false;
                            // Close existing connection
                            if let Some(mut stream) = outgoing.take() {
                                let _ = stream.shutdown().await;
                                log::info!("{mn} -- {peer} <> {dst_addr:?} closed previous session");
                            }

                            let time_out = std::time::Duration::from_secs(config.test_timeout_secs.unwrap_or(TEST_TIMEOUT_SECS));
                            match tcp_stream_from_s5_address(&dst_address, time_out, peer) {
                                Ok(stream) => {
                                    let stream = tokio::net::TcpStream::from_std(stream)?;
                                    dst_addr = Some(stream.peer_addr()?);
                                    outgoing = Some(stream);
                                    log::info!("{mn} -- {peer} -> {dst_addr:?} started new session");
                                    // Feedback confirmation to client
                                    let msg = Message::Text(START_SESSION.into());
                                    svr_send_ws_message(&mut ws_stream, msg, &traffic_audit, client_id).await?;
                                }
                                Err(e) => {
                                    log::error!("{mn} -- {peer} failed to create connection to address '{dst_address}': {e}");
                                    let msg = Message::Text(END_SESSION.into());
                                    log::trace!("{mn} -- {peer} <> {dst_addr:?} sending text message '{END_SESSION}' to end session");
                                    svr_send_ws_message(&mut ws_stream, msg, &traffic_audit, client_id).await?;
                                    dst_addr = None;
                                }
                            }
                        } else {
                            log::warn!("{mn} -- {peer} -> {dst_addr:?} received text message len = {} in unexpected state", data.len());
                        }
                    }
                    Message::Ping(_data) => {
                        log::debug!("{mn} -- {peer} -> {dst_addr:?} received ping message");
                    }
                    Message::Pong(_data) => {
                        log::debug!("{mn} -- {peer} -> {dst_addr:?} received pong message");
                    }
                    _ => {
                        log::debug!("{mn} -- {peer} -> {dst_addr:?} received unexpected message len {}, ignoring", msg.len());
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
                        log::debug!("{mn} -- {peer} <> {dst_addr:?} outgoing connection reached EOF");
                        if is_old_client {
                            ws_stream.send(Message::Close(None)).await?;
                            break;
                        }
                        // Don't close the WebSocket, even don't close the outgoing connection
                        // At current moment, we just mark the outgoing connection as can't be read,
                        // but it's not means it can't be written to.
                        let msg = Message::Text(REMOTE_EOF.into());
                        svr_send_ws_message(&mut ws_stream, msg, &traffic_audit, client_id).await?;
                        outgoing_can_be_read = false;
                    }
                    Ok(n) => {
                        let msg = Message::binary(buffer[..n].to_vec());
                        let len = (msg.len() + WS_MSG_HEADER_LEN) as u64;
                        log::trace!("{mn} -- {peer} <- {dst_addr:?} length {len}");
                        svr_send_ws_message(&mut ws_stream, msg, &traffic_audit, client_id).await?;
                    }
                    Err(e) => {
                        if is_old_client {
                            log::debug!("{mn} -- {peer} <> {dst_addr:?} outgoing connection closed '{e}'");
                            ws_stream.send(Message::Close(None)).await?;
                            break;
                        }
                        // Close the outgoing connection but keep the WebSocket connection
                        if let Some(mut outgoing) = outgoing.take() {
                            let _ = outgoing.shutdown().await;
                        }
                        dst_addr = None;
                        outgoing_can_be_read = false;
                        let msg = Message::Text(END_SESSION.into());
                        log::debug!("{mn} -- {peer} <> {dst_addr:?} sending text message '{END_SESSION}' to end session because '{e}'");
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
    client_id: &Option<Uuid>,
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
    client_id: &Option<Uuid>,
) -> Result<()> {
    let udp_socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    let udp_socket_v6 = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await?;

    let mut buf = vec![0u8; crate::STREAM_BUFFER_SIZE];
    let mut buf_v6 = vec![0u8; crate::STREAM_BUFFER_SIZE];

    let dst_src_pairs = Arc::new(Mutex::new(HashMap::new()));
    let mut enable_check = tokio::time::interval(std::time::Duration::from_secs(1));
    let mn = method_name_unstable!();

    loop {
        tokio::select! {
            _ = enable_check.tick() => {
                if let Some(client_id) = client_id
                    && !traffic_audit.lock().await.get_enable_of(client_id)
                {
                    log::debug!("{mn} -- [UDP] tunnel disabled by panel sync for client {client_id:?}");
                    break;
                }
            }
            Some(msg) = ws_stream.next() => {
                let msg = msg?;
                if let Some(client_id) = client_id {
                    let len = (msg.len() + WS_MSG_HEADER_LEN) as u64;
                    traffic_audit.lock().await.add_upstream_traffic_of(client_id, len);
                }
                match msg {
                    Message::Close(_) => {
                        log::trace!("{mn} -- [UDP] tunnel closed by remote client {client_id:?}");
                        break;
                    }
                    Message::Ping(_) => {
                        log::trace!("{mn} -- [UDP] received ping message, ignoring");
                    }
                    Message::Pong(_) => {
                        log::trace!("{mn} -- [UDP] received pong message, ignoring");
                    }
                    Message::Binary(data) => {
                        let buf = BytesMut::from(&data[..]);
                        svr_send_udp_packet_to_dst(buf, &dst_src_pairs, &udp_socket, &udp_socket_v6).await?;
                    }
                    Message::Text(_) => {
                        log::warn!("{mn} -- [UDP] unexpected text message, ignoring");
                    }
                    _ => {
                        log::warn!("{mn} -- [UDP] unexpected message type: {msg:?}, ignoring");
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
    let mn = method_name_unstable!();
    let (dst_addr, src_addr, pkt) = crate::udprelay::decode_udp_packet(&mut buf)?;
    log::trace!("{mn} -- [UDP] {src_addr} -> {dst_addr} length {}", pkt.len());

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
    fn addr_v6_is_private(addr: &Ipv6Addr) -> bool {
        addr.is_loopback() || (addr.segments()[0] & 0xffc0) == 0xfe80 || (addr.segments()[0] & 0xfe00) == 0xfc00
    }
    match addr {
        SocketAddr::V4(addr) => addr_v4_is_private(addr.ip()),
        SocketAddr::V6(addr) => addr_v6_is_private(addr.ip()),
    }
}

async fn svr_udp_write_ws_stream<S: AsyncRead + AsyncWrite + Unpin>(
    pkt: &[u8],
    ws_stream: &mut WebSocketStream<S>,
    dst_src_pairs: &Arc<Mutex<HashMap<Address, Address>>>,
    addr: SocketAddr,
    traffic_audit: &TrafficAuditPtr,
    client_id: &Option<Uuid>,
) -> Result<()> {
    let mn = method_name_unstable!();
    let dst_addr = Address::from(addr);
    let src_addr = dst_src_pairs.lock().await.get(&dst_addr).cloned();
    if let Some(src_addr) = src_addr {
        // Note: here dst_addr and src_addr are swapped
        let buf = crate::udprelay::build_udp_packet(&src_addr, &dst_addr, pkt);

        let msg = Message::binary(buf.to_vec());

        log::trace!("{mn} -- [UDP] {src_addr} <- {dst_addr} length {}", pkt.len());
        if let Some(client) = client_id {
            let len = (msg.len() + WS_MSG_HEADER_LEN) as u64;
            traffic_audit.lock().await.add_downstream_traffic_of(client, len);
        }

        ws_stream.send(msg).await?;
    }
    Ok(())
}

fn tcp_stream_from_s5_address(s5_addr: &Address, time_out: std::time::Duration, peer: SocketAddr) -> Result<std::net::TcpStream> {
    let mn = method_name_unstable!();
    // try to connect to the first available address
    for dst_addr in s5_addr.to_socket_addrs()? {
        if addr_is_private(&dst_addr) {
            log::warn!("{mn} -- {peer} <> {dst_addr} destination address is private, skipping");
            continue;
        }
        match crate::tcp_stream::std_create(dst_addr, Some(time_out)) {
            Ok(stream) => {
                stream.set_nonblocking(true)?;
                return Ok(stream);
            }
            Err(ref e) => {
                log::debug!("{mn} -- {peer} <> {dst_addr} destination address is unreachable: {e}");
            }
        }
    }
    Err(Error::from(format!("{mn} -- {peer} <> {s5_addr} All addresses failed to connect")))
}

#[cfg(test)]
mod tls_reload_event_tests {
    use super::event_affects_tls_files;
    use notify::{
        Event, EventKind,
        event::{AccessKind, AccessMode, DataChange, ModifyKind},
    };
    use std::path::Path;

    #[test]
    fn ignores_read_access_to_tls_files() {
        let cert_path = Path::new("/etc/overtls/fullchain.pem");
        let key_path = Path::new("/etc/overtls/privkey.pem");
        let event = Event::new(EventKind::Access(AccessKind::Open(AccessMode::Read))).add_path(cert_path.to_path_buf());

        assert!(!event_affects_tls_files(&event, cert_path, key_path));
    }

    #[test]
    fn accepts_modifications_to_tls_files() {
        let cert_path = Path::new("/etc/overtls/fullchain.pem");
        let key_path = Path::new("/etc/overtls/privkey.pem");
        let event = Event::new(EventKind::Modify(ModifyKind::Data(DataChange::Content))).add_path(cert_path.to_path_buf());

        assert!(event_affects_tls_files(&event, cert_path, key_path));
    }
}
