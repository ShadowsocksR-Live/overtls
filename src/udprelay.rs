use crate::{client, config::Config};
use bytes::Bytes;
use socks5_proto::UdpHeader;
use socks5_proto::{Address, Reply};
use socks5_server::{
    connection::associate::{AssociatedUdpSocket, NeedReply as UdpNeedReply},
    Associate,
};
use std::sync::atomic::AtomicUsize;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tokio::{
    net::UdpSocket,
    sync::mpsc::{self, Receiver, Sender},
};

type AssociateSendPacketReceiver = tokio::sync::mpsc::Receiver<(Bytes, Address)>;
type AssociateRecvPacketSender = tokio::sync::mpsc::Sender<(Bytes, Address)>;
type AssociateSendPacketSender = AssociateRecvPacketSender;
type AssociateRecvPacketReceiver = AssociateSendPacketReceiver;

pub type UdpPacketReceiver = AssociateSendPacketReceiver;
pub type UdpPacketSender = AssociateRecvPacketSender;

pub type UdpRequestReceiver = tokio::sync::mpsc::Receiver<UdpRequest>;
pub type UdpRequestSender = tokio::sync::mpsc::Sender<UdpRequest>;

#[derive(Debug)]
pub struct UdpRequest {
    assoc_id: u64,
    pkt_send_rx: AssociateSendPacketReceiver,
    pkt_recv_tx: AssociateRecvPacketSender,
}

impl UdpRequest {
    fn new(pkt_send_rx: AssociateSendPacketReceiver, pkt_recv_tx: AssociateRecvPacketSender) -> Self {
        Self {
            assoc_id: Self::get_random_u64(),
            pkt_send_rx,
            pkt_recv_tx,
        }
    }

    pub fn new_associate() -> (Self, AssociateSendPacketSender, AssociateRecvPacketReceiver) {
        let (pkt_send_tx, pkt_send_rx) = tokio::sync::mpsc::channel(1);
        let (pkt_recv_tx, pkt_recv_rx) = tokio::sync::mpsc::channel(1);
        (Self::new(pkt_send_rx, pkt_recv_tx), pkt_send_tx, pkt_recv_rx)
    }

    fn get_random_u64() -> u64 {
        static RNG: AtomicU64 = AtomicU64::new(0);
        RNG.fetch_add(1, Ordering::Relaxed);
        RNG.load(Ordering::Relaxed)
    }
}

impl std::fmt::Display for UdpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[associate] [{}]", self.assoc_id)
    }
}

pub async fn handle_s5_upd_associate(
    associate: Associate<UdpNeedReply>,
    config: Config,
    udp_req_tx: UdpRequestSender,
) -> anyhow::Result<()> {
    let listen_ip = associate.local_addr()?.ip();
    log::info!("[socks5] {} UDP associate", listen_ip);

    // listen on a random port
    let udp_listener = UdpSocket::bind(SocketAddr::from((listen_ip, 0))).await;
    match udp_listener.and_then(|socket| socket.local_addr().map(|addr| (socket, addr))) {
        Ok((listen_udp, listen_addr)) => {
            let (relay_req, pkt_send_tx, pkt_recv_rx) = UdpRequest::new_associate();
            let _ = udp_req_tx.send(relay_req).await;

            let listen_addr = Address::SocketAddress(listen_addr);
            let mut reply_listener = associate.reply(Reply::Succeeded, listen_addr).await?;

            let buf_size = MAX_UDP_RELAY_PACKET_SIZE.load(Ordering::Acquire) - UdpHeader::max_serialized_len();
            let listen_udp = Arc::new(AssociatedUdpSocket::from((listen_udp, buf_size)));
            let ctrl_addr = reply_listener.peer_addr()?;

            let res = tokio::select! {
                _ = reply_listener.wait_until_closed() => Ok::<_, anyhow::Error>(()),
                res = socks5_to_relay(listen_udp.clone(), config, ctrl_addr, pkt_send_tx) => res,
                res = relay_to_socks5(listen_udp,ctrl_addr, pkt_recv_rx) => res,
            };

            reply_listener.shutdown().await?;

            log::info!("[socks5] [{ctrl_addr}] [dissociate]");

            res
        }
        Err(err) => {
            let mut conn = associate.reply(Reply::GeneralFailure, Address::unspecified()).await?;
            conn.shutdown().await?;
            Err(anyhow::anyhow!(err))
        }
    }
}

pub static MAX_UDP_RELAY_PACKET_SIZE: AtomicUsize = AtomicUsize::new(1500);

pub const fn command_max_serialized_len() -> usize {
    2 + 6 + Address::max_serialized_len()
}

async fn socks5_to_relay(
    listen_udp: Arc<AssociatedUdpSocket>,
    config: Config,
    ctrl_addr: SocketAddr,
    pkt_recv_tx: UdpPacketSender,
) -> anyhow::Result<()> {
    loop {
        let buf_size = MAX_UDP_RELAY_PACKET_SIZE.load(Ordering::Acquire) - UdpHeader::max_serialized_len();
        listen_udp.set_max_packet_size(buf_size);

        let (pkt, frag, dst_addr, src_addr) = listen_udp.recv_from().await?;

        if frag == 0 {
            log::debug!("[socks5] [{ctrl_addr}] [associate] [packet-to] {dst_addr}");
            let _ = pkt_recv_tx.send((pkt, dst_addr)).await;
            listen_udp.connect(src_addr).await?;
            break;
        } else {
            log::warn!("[socks5] [{ctrl_addr}] [associate] [packet-to] socks5 UDP packet fragment is not supported");
        }
    }

    loop {
        let buf_size = MAX_UDP_RELAY_PACKET_SIZE.load(Ordering::Acquire) - UdpHeader::max_serialized_len();
        listen_udp.set_max_packet_size(buf_size);

        let (pkt, frag, dst_addr) = listen_udp.recv().await?;

        if frag == 0 {
            log::debug!("[socks5] [{ctrl_addr}] [associate] [packet-to] {dst_addr}");
            let _ = pkt_recv_tx.send((pkt, dst_addr)).await;
        } else {
            log::warn!("[socks5] [{ctrl_addr}] [associate] [packet-to] socks5 UDP packet fragment is not supported");
        }
    }
}

async fn relay_to_socks5(
    listen_udp: Arc<AssociatedUdpSocket>,
    ctrl_addr: SocketAddr,
    mut pkt_recv_rx: UdpPacketReceiver,
) -> anyhow::Result<()> {
    while let Some((pkt, src_addr)) = pkt_recv_rx.recv().await {
        log::debug!("[socks5] [{ctrl_addr}] [associate] [packet-from] {src_addr}");
        listen_udp.send(pkt, 0, src_addr).await?;
    }
    Ok(())
}

use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use tungstenite::{
    client::IntoClientRequest,
    handshake::{client::Response, machine::TryParse},
    protocol::{Message, Role},
};

pub fn create_udp_tunnel() -> (UdpRequestSender, UdpRequestReceiver) {
    tokio::sync::mpsc::channel::<UdpRequest>(1024)
}

pub async fn run_udp_loop(mut req_rx: UdpRequestReceiver, config: Config) -> anyhow::Result<()> {
    let mut ws_stream = client::create_ws_tls_stream(None, &config, Some(&vec![1])).await?;
    let (mut ws_stream_w, mut ws_stream_r) = ws_stream.split();
    let timeout_ms = 2000;

    while let Some(req) = req_rx.recv().await {
        tokio::spawn(process_request(/*conn.clone(),*/ req, timeout_ms));
    }
    Ok(())
}

async fn process_request(
    // conn: Arc<AsyncMutex<Option<Connection>>>,
    req: UdpRequest,
    timeout: u64,
) {
    log::info!("[relay] [task] {req}");

    {
        // conn.udp_sessions().insert(req.assoc_id, req.pkt_recv_tx);
        // while let Some((pkt, addr)) = req.pkt_send_rx.recv().await {
        //     tokio::spawn(
        //         conn.clone()
        //             .handle_packet_to(req.assoc_id, pkt, addr, conn.udp_relay_mode()),
        //     );
        // }

        // log::info!("[relay] [task] [dissociate] [{}]", req.assoc_id);
        // conn.clone().udp_sessions().remove(req.assoc_id);
        // conn.handle_dissociate(req.assoc_id).await;
    }
}
