use crate::{client, config::Config};
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use socks5_proto::{Address, Reply, UdpHeader};
use socks5_server::{
    connection::associate::{AssociatedUdpSocket, NeedReply as UdpNeedReply},
    Associate,
};
use std::{collections::HashSet, net::SocketAddr, sync::Arc};
use tokio::{
    net::UdpSocket,
    sync::{broadcast, mpsc, Mutex},
};
use tungstenite::protocol::Message;

pub type UdpRequestReceiver = broadcast::Receiver<(Bytes, Address, Address)>;
pub type UdpRequestSender = broadcast::Sender<(Bytes, Address, Address)>;
pub type SocketAddrSet = Arc<Mutex<HashSet<SocketAddr>>>;
pub type UdpWaker = mpsc::Sender<()>;

pub async fn handle_s5_upd_associate(
    associate: Associate<UdpNeedReply>,
    udp_tx: UdpRequestSender,
    incomings: SocketAddrSet,
    udp_waker: UdpWaker,
) -> anyhow::Result<()> {
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
                _ = reply_listener.wait_until_closed() => Ok::<_, anyhow::Error>(()),
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
            Err(anyhow::anyhow!(err))
        }
    }
}

pub static MAX_UDP_RELAY_PACKET_SIZE: usize = 1500;

pub const fn command_max_serialized_len() -> usize {
    2 + 6 + Address::max_serialized_len()
}

async fn socks5_to_relay(
    listen_udp: Arc<AssociatedUdpSocket>,
    incoming: Arc<Mutex<SocketAddr>>,
    incomings: SocketAddrSet,
    udp_tx: UdpRequestSender,
) -> anyhow::Result<()> {
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
) -> anyhow::Result<()> {
    while let Ok((pkt, addr, _)) = udp_rx.recv().await {
        let to_addr = addr.to_socket_addr()?;
        if *incoming_addr.lock().await == to_addr {
            log::trace!("[UDP] feedback to incoming {to_addr}");
            listen_udp.send_to(pkt, 0, addr, to_addr).await?;
        }
    }
    log::trace!("[UDP] relay_to_socks5 exiting.");
    Ok(())
}

pub fn create_udp_tunnel() -> (UdpRequestSender, UdpRequestReceiver, SocketAddrSet) {
    let incomings = Arc::new(Mutex::new(HashSet::<SocketAddr>::new()));
    let (tx, rx) = tokio::sync::broadcast::channel::<(Bytes, Address, Address)>(10);
    (tx, rx, incomings)
}

pub async fn run_udp_loop(udp_tx: UdpRequestSender, incomings: SocketAddrSet, config: Config) -> anyhow::Result<()> {
    let ws_stream = client::create_ws_tls_stream(None, &config, Some(true)).await?;
    let (mut ws_stream_w, mut ws_stream_r) = ws_stream.split();

    let mut udp_rx = udp_tx.subscribe();

    loop {
        let _res = tokio::select! {
            Ok((pkt, dst_addr, src_addr)) = udp_rx.recv() => {
                let flag = { incomings.lock().await.contains(&dst_addr.to_socket_addr()?) };
                if !flag {
                    // packet send to remote server, format: dst_addr + src_addr + pkt
                    let mut buf = BytesMut::new();
                    dst_addr.write_to_buf(&mut buf);
                    src_addr.write_to_buf(&mut buf);
                    buf.put_slice(&pkt);

                    log::trace!("[UDP] send to remote {src_addr} -> {dst_addr} {} bytes", buf.len());
                    let msg = Message::Binary(buf.freeze().to_vec());
                    ws_stream_w.send(msg).await?;
                } else {
                    log::trace!("[UDP] skip feedback packet {src_addr} -> {dst_addr}");
                }
                 Ok::<_, anyhow::Error>(())
            },
            msg = ws_stream_r.next() => {
                match msg {
                    Some(Ok(Message::Binary(buf))) => {
                        let mut buf = BytesMut::from(&buf[..]);
                        let dst_addr = Address::read_from(&mut &buf[..]).await?;
                        let _ = buf.split_to(dst_addr.serialized_len());
                        let src_addr = Address::read_from(&mut &buf[..]).await?;
                        let _ = buf.split_to(src_addr.serialized_len());
                        let pkt = buf.to_vec();
                        log::trace!("[UDP] recv from remote {src_addr} -> {dst_addr} {} bytes", pkt.len());
                        udp_tx.send((Bytes::from(pkt), dst_addr, src_addr))?;
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
                Ok::<_, anyhow::Error>(())
            },
        };
    }

    log::trace!("[UDP] run_udp_loop exiting.");

    Ok(())
}

pub async fn udp_handler_watchdog(
    config: &Config,
    incomings: &SocketAddrSet,
    udp_tx: &UdpRequestSender,
) -> anyhow::Result<UdpWaker> {
    let config = config.clone();
    let incomings = incomings.clone();
    let udp_tx = udp_tx.clone();
    let (tx, mut rx) = mpsc::channel::<()>(10);

    let running = Arc::new(Mutex::new(false));

    let tx2 = tx.clone();
    tokio::spawn(async move {
        while rx.recv().await.is_some() {
            if *running.lock().await {
                continue;
            }
            let udp_tx = udp_tx.clone();
            let incomings = incomings.clone();
            let config = config.clone();
            let running = running.clone();
            let tx2 = tx2.clone();
            tokio::spawn(async move {
                *running.lock().await = true;
                log::trace!("[UDP] udp client watchdog thread started");
                let _ = run_udp_loop(udp_tx, incomings, config).await;
                log::trace!("[UDP] udp client watchdog thread stopped");
                *running.lock().await = false;
                let _ = tx2.send(()).await; // restart watchdog
            });
        }
    });
    tx.send(()).await?; // bootstrap
    Ok(tx)
}
