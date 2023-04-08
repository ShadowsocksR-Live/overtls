use crate::{
    client,
    config::Config,
    error::{Error, Result},
};
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use socks5_impl::{
    protocol::{Address, Reply, UdpHeader},
    server::{
        connection::associate::{AssociatedUdpSocket, NeedReply as UdpNeedReply},
        Associate,
    },
};
use std::{
    collections::HashSet,
    net::{SocketAddr, ToSocketAddrs},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::UdpSocket,
    sync::{broadcast, mpsc, Mutex},
    time,
};
use tokio_tungstenite::WebSocketStream;
use tungstenite::protocol::Message;

pub(crate) type UdpRequestReceiver = broadcast::Receiver<(Bytes, Address, Address)>;
pub(crate) type UdpRequestSender = broadcast::Sender<(Bytes, Address, Address)>;
pub(crate) type SocketAddrSet = Arc<Mutex<HashSet<SocketAddr>>>;
pub(crate) type UdpWaker = mpsc::Sender<()>;

pub(crate) async fn handle_s5_upd_associate(
    associate: Associate<UdpNeedReply>,
    udp_tx: UdpRequestSender,
    incomings: SocketAddrSet,
    udp_waker: UdpWaker,
) -> Result<()> {
    let listen_ip = associate.local_addr()?.ip();

    // listen on a random port
    let udp_listener = UdpSocket::bind(SocketAddr::from((listen_ip, 0))).await;
    match udp_listener.and_then(|socket| socket.local_addr().map(|addr| (socket, addr))) {
        Ok((listen_udp, listen_addr)) => {
            log::info!("[UDP] listen on {listen_addr}");

            let _ = udp_waker.send(()).await;

            let s5_listen_addr = listen_addr.into();
            let mut reply_listener = associate.reply(Reply::Succeeded, s5_listen_addr).await?;

            let buf_size = MAX_UDP_RELAY_PACKET_SIZE - UdpHeader::max_serialized_len();
            let listen_udp = Arc::new(AssociatedUdpSocket::from((listen_udp, buf_size)));

            let udp_rx = udp_tx.subscribe();

            let incoming_addr = Arc::new(Mutex::new(SocketAddr::from(([0, 0, 0, 0], 0))));

            let res = tokio::select! {
                _ = reply_listener.wait_until_closed() => Ok::<_, Error>(()),
                res = socks5_to_relay(listen_udp.clone(), incoming_addr.clone(), incomings.clone(), udp_tx) => res,
                res = relay_to_socks5(listen_udp, incoming_addr.clone(), udp_rx) => res,
            };

            reply_listener.shutdown().await?;

            log::trace!("[UDP] listener {listen_addr} closed with {res:?}");

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
    incomings: SocketAddrSet,
    udp_tx: UdpRequestSender,
) -> Result<()> {
    loop {
        log::trace!("[UDP] waiting for incoming packet");

        let buf_size = MAX_UDP_RELAY_PACKET_SIZE - UdpHeader::max_serialized_len();
        listen_udp.set_max_packet_size(buf_size);

        let (pkt, frag, dst_addr, src_addr) = listen_udp.recv_from().await?;
        if frag != 0 {
            log::warn!("[UDP] packet fragment is not supported");
            break;
        }

        incoming.lock().await.clone_from(&src_addr);
        incomings.lock().await.insert(src_addr);

        log::trace!("[UDP] incoming packet {src_addr} -> {dst_addr} {} bytes", pkt.len());
        let src_addr = src_addr.into();
        let _ = udp_tx.send((pkt, dst_addr, src_addr));
    }
    log::trace!("[UDP] socks5_to_relay exiting.");
    Ok(())
}

async fn relay_to_socks5(
    listen_udp: Arc<AssociatedUdpSocket>,
    incoming_addr: Arc<Mutex<SocketAddr>>,
    mut udp_rx: UdpRequestReceiver,
) -> Result<()> {
    while let Ok((pkt, addr, _)) = udp_rx.recv().await {
        let to_addr = SocketAddr::try_from(addr.clone())?;
        if *incoming_addr.lock().await == to_addr {
            log::trace!("[UDP] feedback to incoming {to_addr}");
            listen_udp.send_to(pkt, 0, addr, to_addr).await?;
        }
    }
    log::trace!("[UDP] relay_to_socks5 exiting.");
    Ok(())
}

pub(crate) fn create_udp_tunnel() -> (UdpRequestSender, UdpRequestReceiver, SocketAddrSet) {
    let incomings = Arc::new(Mutex::new(HashSet::<SocketAddr>::new()));
    let (tx, rx) = tokio::sync::broadcast::channel::<(Bytes, Address, Address)>(10);
    (tx, rx, incomings)
}

pub(crate) async fn run_udp_loop(udp_tx: UdpRequestSender, incomings: SocketAddrSet, config: Config) -> Result<()> {
    let client = config.client.as_ref().ok_or("config client not exist")?;
    let mut addr = (client.server_host.as_str(), client.server_port).to_socket_addrs()?;
    let svr_addr = addr.next().ok_or("client address not exist")?;

    if !config.disable_tls() {
        let ws_stream = client::create_tls_ws_stream(&svr_addr, None, &config, Some(true)).await?;
        _run_udp_loop(udp_tx, incomings, ws_stream).await?;
    } else {
        let ws_stream = client::create_plaintext_ws_stream(&svr_addr, None, &config, Some(true)).await?;
        _run_udp_loop(udp_tx, incomings, ws_stream).await?;
    }
    Ok(())
}

async fn _run_udp_loop<S: AsyncRead + AsyncWrite + Unpin>(
    udp_tx: UdpRequestSender,
    incomings: SocketAddrSet,
    mut ws_stream: WebSocketStream<S>,
) -> Result<()> {
    let mut udp_rx = udp_tx.subscribe();

    loop {
        let _res = tokio::select! {
            Ok((pkt, dst_addr, src_addr)) = udp_rx.recv() => {
                let flag = { incomings.lock().await.contains(&SocketAddr::try_from(dst_addr.clone())?) };
                if !flag {
                    // packet send to remote server, format: dst_addr + src_addr + pkt
                    let mut buf = BytesMut::new();
                    dst_addr.write_to_buf(&mut buf);
                    src_addr.write_to_buf(&mut buf);
                    buf.put_slice(&pkt);

                    #[cfg(target_os = "android")]
                    if let Err(e) = crate::android::native::traffic_status_update(buf.len(), 0) {
                        log::error!("{}", e);
                    }

                    log::trace!("[UDP] send to remote {src_addr} -> {dst_addr} {} bytes", buf.len());
                    let msg = Message::Binary(buf.freeze().to_vec());
                    ws_stream.send(msg).await?;
                } else {
                    log::trace!("[UDP] skip feedback packet {src_addr} -> {dst_addr}");
                }
                 Ok::<_, Error>(())
            },
            msg = ws_stream.next() => {
                let len = msg.as_ref().map(|m| m.as_ref().map(|m| m.len()).unwrap_or(0)).unwrap_or(0);
                #[cfg(target_os = "android")]
                if let Err(e) = crate::android::native::traffic_status_update(0, len) {
                    log::error!("{}", e);
                }

                match msg {
                    Some(Ok(Message::Binary(buf))) => {
                        let mut buf = BytesMut::from(&buf[..]);
                        let incoming_addr = Address::from_data(&buf)?;
                        let _ = buf.split_to(incoming_addr.serialized_len());
                        let remote_addr = Address::from_data(&buf)?;
                        let _ = buf.split_to(remote_addr.serialized_len());
                        let pkt = buf.to_vec();
                        log::trace!("[UDP] {} <- {} length {}", incoming_addr, remote_addr, len);
                        udp_tx.send((Bytes::from(pkt), incoming_addr, remote_addr))?;
                    },
                    Some(Ok(Message::Close(_))) => {
                        log::trace!("[UDP] ws stream closed by remote");
                        break;
                    },
                    Some(Ok(_)) => {
                        log::trace!("[UDP] unexpected ws message");
                    },
                    Some(Err(err)) => {
                        log::trace!("[UDP] ws stream error {}", err);
                        break;
                    },
                    None => {
                        log::trace!("[UDP] ws stream closed by local");
                        break;
                    }
                }
                Ok::<_, Error>(())
            },
        };
    }

    log::trace!("[UDP] run_udp_loop exiting.");

    Ok(())
}

pub(crate) async fn udp_handler_watchdog(
    config: &Config,
    incomings: &SocketAddrSet,
    udp_tx: &UdpRequestSender,
) -> Result<UdpWaker> {
    let config = config.clone();
    let incomings = incomings.clone();
    let udp_tx = udp_tx.clone();
    let (tx, mut rx) = mpsc::channel::<()>(10);

    let tx2 = tx.clone();
    tokio::spawn(async move {
        let running = Arc::new(AtomicBool::new(false));
        while rx.recv().await.is_some() {
            if running.load(Ordering::Relaxed) {
                continue;
            }
            running.store(true, Ordering::Relaxed);
            let udp_tx = udp_tx.clone();
            let incomings = incomings.clone();
            let config = config.clone();
            let running = running.clone();
            let tx2 = tx2.clone();
            tokio::spawn(async move {
                log::trace!("[UDP] udp client watchdog thread started");
                let result = run_udp_loop(udp_tx, incomings, config).await;
                log::trace!("[UDP] udp client watchdog thread stopped for {:?}", result);
                running.store(false, Ordering::Relaxed);
                time::sleep(Duration::from_secs(1)).await;
                let _ = tx2.send(()).await; // restart watchdog
            });
        }
    });
    tx.send(()).await?; // bootstrap
    Ok(tx)
}
