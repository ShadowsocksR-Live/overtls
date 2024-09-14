use crate::{
    client,
    config::Config,
    dns,
    error::{Error, Result},
};
use async_shared_timeout::{runtime, Timeout};
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use socks5_impl::{
    protocol::{Address, Reply, StreamOperation, UdpHeader},
    server::{
        connection::associate::{AssociatedUdpSocket, NeedReply as UdpNeedReply},
        UdpAssociate,
    },
};
use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::UdpSocket,
    sync::{broadcast, mpsc, Mutex},
    time,
};
use tokio_tungstenite::{tungstenite::protocol::Message, WebSocketStream};

pub(crate) type UdpRequestReceiver = broadcast::Receiver<(Bytes, Address, Address)>;
pub(crate) type UdpRequestSender = broadcast::Sender<(Bytes, Address, Address)>;
pub(crate) type SocketAddrHashSet = Arc<Mutex<HashSet<SocketAddr>>>;

pub(crate) async fn handle_s5_upd_associate(
    associate: UdpAssociate<UdpNeedReply>,
    udp_tx: UdpRequestSender,
    incomings: SocketAddrHashSet,
) -> Result<()> {
    let listen_ip = associate.local_addr()?.ip();

    // listen on a random port
    let udp_listener = UdpSocket::bind(SocketAddr::from((listen_ip, 0))).await;
    match udp_listener.and_then(|socket| socket.local_addr().map(|addr| (socket, addr))) {
        Ok((listen_udp, listen_addr)) => {
            log::trace!("[UDP] {listen_addr} listen on");

            let s5_listen_addr = listen_addr.into();
            let mut reply_listener = associate.reply(Reply::Succeeded, s5_listen_addr).await?;

            let buf_size = MAX_UDP_RELAY_PACKET_SIZE - UdpHeader::max_serialized_len();
            let listen_udp = Arc::new(AssociatedUdpSocket::from((listen_udp, buf_size)));

            let udp_rx = udp_tx.subscribe();

            let incoming_addr = Arc::new(Mutex::new(SocketAddr::from(([0, 0, 0, 0], 0))));

            let timeout_secs = Duration::from_secs(10); // TODO: configurable
            let runtime = runtime::Tokio::new();
            let timeout = Timeout::new(runtime, timeout_secs);

            let res = tokio::select! {
                _ = timeout.wait() => Ok::<_, Error>(()),
                res = reply_listener.wait_until_closed() => res.map_err(|e| e.into()),
                res = socks5_to_relay(listen_udp.clone(), incoming_addr.clone(), incomings.clone(), udp_tx, &timeout) => res,
                res = relay_to_socks5(listen_udp, incoming_addr.clone(), udp_rx, &timeout) => res,
            };

            reply_listener.shutdown().await?;

            log::trace!("[UDP] {listen_addr} listener closed with {res:?}");

            {
                let incoming = *incoming_addr.lock().await;
                incomings.lock().await.remove(&incoming);
            }

            res
        }
        Err(err) => {
            let mut conn = associate.reply(Reply::GeneralFailure, Address::unspecified()).await?;
            conn.shutdown().await?;
            Err(err.into())
        }
    }
}

pub(crate) static MAX_UDP_RELAY_PACKET_SIZE: usize = 1500;

#[allow(dead_code)]
pub(crate) const fn command_max_serialized_len() -> usize {
    2 + 6 + Address::max_serialized_len()
}

async fn socks5_to_relay(
    listen_udp: Arc<AssociatedUdpSocket>,
    incoming: Arc<Mutex<SocketAddr>>,
    incomings: SocketAddrHashSet,
    udp_tx: UdpRequestSender,
    timeout: &Timeout<runtime::Tokio>,
) -> Result<()> {
    loop {
        // log::trace!("[UDP] waiting for incoming packet");

        let buf_size = MAX_UDP_RELAY_PACKET_SIZE - UdpHeader::max_serialized_len();
        listen_udp.set_max_packet_size(buf_size);

        let (pkt, frag, dst_addr, src_addr) = listen_udp.recv_from().await?;
        if frag != 0 {
            log::warn!("[UDP] packet fragment is not supported");
            break;
        }

        incoming.lock().await.clone_from(&src_addr);
        incomings.lock().await.insert(src_addr);

        // log::trace!("[UDP] {src_addr} -> {dst_addr} incoming packet size {}", pkt.len());
        let src_addr = src_addr.into();
        let _ = udp_tx.send((pkt, dst_addr, src_addr));
        timeout.reset();
    }
    log::trace!("[UDP] socks5_to_relay exiting.");
    Ok(())
}

async fn relay_to_socks5(
    listen_udp: Arc<AssociatedUdpSocket>,
    incoming_addr: Arc<Mutex<SocketAddr>>,
    mut udp_rx: UdpRequestReceiver,
    timeout: &Timeout<runtime::Tokio>,
) -> Result<()> {
    while let Ok((pkt, addr, _from_addr)) = udp_rx.recv().await {
        let to_addr = SocketAddr::try_from(addr.clone())?;
        if *incoming_addr.lock().await == to_addr {
            // log::trace!("[UDP] {to_addr} <- {_from_addr} feedback to incoming");
            listen_udp.send_to(pkt, 0, addr, to_addr).await?;
            timeout.reset();
        }
    }
    log::trace!("[UDP] relay_to_socks5 exiting.");
    Ok(())
}

pub(crate) fn create_udp_tunnel() -> (UdpRequestSender, UdpRequestReceiver, SocketAddrHashSet) {
    let incomings: SocketAddrHashSet = Arc::new(Mutex::new(HashSet::<SocketAddr>::new()));
    let (tx, rx) = tokio::sync::broadcast::channel::<(Bytes, Address, Address)>(10);
    (tx, rx, incomings)
}

pub(crate) async fn run_udp_loop(udp_tx: UdpRequestSender, incomings: SocketAddrHashSet, config: Config) -> Result<()> {
    let client = config.client.as_ref().ok_or("config client not exist")?;
    let svr_addr = client.server_ip_addr.ok_or("server ip addr")?;

    if !config.disable_tls() {
        let ws_stream = client::create_tls_ws_stream(svr_addr, None, &config, Some(true)).await?;
        _run_udp_loop(udp_tx, incomings, ws_stream, config.cache_dns()).await?;
    } else {
        let ws_stream = client::create_plaintext_ws_stream(svr_addr, None, &config, Some(true)).await?;
        _run_udp_loop(udp_tx, incomings, ws_stream, config.cache_dns()).await?;
    }
    Ok(())
}

async fn _run_udp_loop<S: AsyncRead + AsyncWrite + Unpin>(
    udp_tx: UdpRequestSender,
    incomings: SocketAddrHashSet,
    mut ws_stream: WebSocketStream<S>,
    cache_dns: bool,
) -> Result<()> {
    let mut udp_rx = udp_tx.subscribe();

    let mut timer = tokio::time::interval(Duration::from_secs(30));

    let cache = dns::create_dns_cache();

    let mut res = Ok::<_, Error>(());
    loop {
        let _res = tokio::select! {
            Ok((pkt, dst_addr, src_addr)) = udp_rx.recv() => {
                let direction = { incomings.lock().await.contains(&SocketAddr::try_from(dst_addr.clone())?) };
                if !direction {
                    // packet send to remote server, format: dst_addr + src_addr + pkt
                    let mut buf = BytesMut::new();
                    dst_addr.write_to_buf(&mut buf);
                    src_addr.write_to_buf(&mut buf);
                    buf.put_slice(&pkt);

                    if let Err(e) = crate::traffic_status::traffic_status_update(buf.len(), 0) {
                        log::error!("{}", e);
                    }

                    if dst_addr.port() == 53 {
                        let msg = dns::parse_data_to_dns_message(&pkt, false)?;
                        let domain = dns::extract_domain_from_dns_message(&msg)?;
                        if let (true, Some(cached_message)) = (cache_dns, dns::dns_cache_get_message(&cache, &msg).await) {
                            log::debug!("[UDP] {src_addr} -> {dst_addr} DNS query hit cache \"{}\"", domain);
                            let data = cached_message.to_vec().map_err(|e| e.to_string())?;
                            udp_tx.send((Bytes::from(data), src_addr, dst_addr))?;
                            continue;
                        }
                        log::debug!("[UDP] {src_addr} -> {dst_addr} DNS query \"{}\"", domain);
                    } else {
                        log::debug!("[UDP] {src_addr} -> {dst_addr} send to remote size {}", buf.len());
                    }
                    let msg = Message::Binary(buf.freeze().to_vec());
                    ws_stream.send(msg).await?;
                } else {
                    // log::trace!("[UDP] {dst_addr} <- {src_addr} skip feedback packet");
                }
                 Ok::<_, Error>(())
            },
            msg = ws_stream.next() => {
                let len = msg.as_ref().map(|m| m.as_ref().map(|m| m.len()).unwrap_or(0)).unwrap_or(0);
                if let Err(e) = crate::traffic_status::traffic_status_update(0, len) {
                    log::error!("{}", e);
                }

                match msg {
                    Some(Ok(Message::Binary(buf))) => {
                        let mut buf = BytesMut::from(&buf[..]);
                        let incoming_addr = Address::try_from(&buf[..])?;
                        let _ = buf.split_to(incoming_addr.len());
                        let remote_addr = Address::try_from(&buf[..])?;
                        let _ = buf.split_to(remote_addr.len());
                        let pkt = buf.to_vec();

                        if remote_addr.port() == 53 {
                            let msg = dns::parse_data_to_dns_message(&pkt, false)?;
                            let domain = dns::extract_domain_from_dns_message(&msg)?;
                            let mut ipaddr = format!("{:?}", dns::extract_ipaddr_from_dns_message(&msg));
                            ipaddr.truncate(48);
                            if cache_dns {
                                dns::dns_cache_put_message(&cache, &msg).await;
                            }
                            log::debug!("[UDP] {incoming_addr} <- {remote_addr} DNS response \"{}\" <==> \"{}\"", domain, ipaddr);
                        } else {
                            log::debug!("[UDP] {incoming_addr} <- {remote_addr} recv from remote size {}", len);
                        }
                        udp_tx.send((Bytes::from(pkt), incoming_addr, remote_addr))?;
                    },
                    Some(Ok(Message::Close(_))) => {
                        log::trace!("[UDP] ws stream closed by remote");
                        break;
                    },
                    Some(Ok(Message::Pong(_))) => {
                        log::trace!("[UDP] Websocket pong from remote");
                    },
                    Some(Ok(_)) => {
                        log::trace!("[UDP] unexpected Websocket message");
                    },
                    Some(Err(err)) => {
                        log::trace!("[UDP] error \"{err}\"");
                        res = Err(err.into());
                        break;
                    },
                    None => {
                        log::trace!("[UDP] Websocket stream closed by local");
                        break;
                    }
                }
                Ok::<_, Error>(())
            },
            _ = timer.tick() => {
                ws_stream.send(Message::Ping(vec![])).await?;
                log::trace!("[UDP] Websocket ping from local");
                Ok::<_, Error>(())
            }
        };
    }

    log::trace!("[UDP] _run_udp_loop exiting...");

    res
}

pub(crate) async fn udp_handler_watchdog(
    config: &Config,
    incomings: &SocketAddrHashSet,
    udp_tx: &UdpRequestSender,
    quit: crate::CancellationToken,
) -> Result<()> {
    let config = config.clone();
    let incomings = incomings.clone();
    let udp_tx = udp_tx.clone();

    tokio::spawn(async move {
        loop {
            let udp_tx = udp_tx.clone();
            let incomings = incomings.clone();
            let config = config.clone();

            let block = async move {
                let (tx, mut rx) = mpsc::channel::<()>(10);

                log::trace!("[UDP] udp client guard thread started");
                let _ = tokio::spawn(async move {
                    if let Err(e) = run_udp_loop(udp_tx, incomings, config).await {
                        log::trace!("[UDP] {}", e);
                    }
                    let _ = tx.send(()).await;
                })
                .await;
                let _ = rx.recv().await;
                time::sleep(Duration::from_secs(1)).await;
            };

            tokio::select! {
                _ = quit.cancelled() => {
                    break;
                },
                _ = block => {
                    log::trace!("[UDP] udp client guard thread exited");
                }
            };
        }
    });
    Ok(())
}
