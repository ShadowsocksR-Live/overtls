use crate::{config::Config, program_name, tls::*, weirduri::WeirdUri};
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
    sync::{atomic::Ordering, Arc},
};
use tokio::{
    net::UdpSocket,
    sync::mpsc::{self, Receiver, Sender},
};

pub async fn handle_s5_upd_associate(associate: Associate<UdpNeedReply>, config: Config) -> anyhow::Result<()> {
    let listen_ip = associate.local_addr()?.ip();
    log::info!("[socks5] {} UDP associate", listen_ip);

    // listen on a random port
    let udp_listener = UdpSocket::bind(SocketAddr::from((listen_ip, 0))).await;
    match udp_listener.and_then(|socket| socket.local_addr().map(|addr| (socket, addr))) {
        Ok((listen_socket, listen_addr)) => {
            let mut reply_listener = associate
                .reply(Reply::Succeeded, Address::SocketAddress(listen_addr))
                .await?;

            let buf_size = MAX_UDP_RELAY_PACKET_SIZE.load(Ordering::Acquire)
                - (command_max_serialized_len() - UdpHeader::max_serialized_len());
            let listen_socket = Arc::new(AssociatedUdpSocket::from((listen_socket, buf_size)));
            let ctrl_addr = reply_listener.peer_addr()?;

            log::info!("[socks5] {} UDP associate listen_addr {}", ctrl_addr, listen_addr);

            let (pkt_send_tx, pkt_send_rx) = mpsc::channel(1);
            let (pkt_recv_tx, pkt_recv_rx) = mpsc::channel(1);

            // let (relay_req, pkt_send_tx, pkt_recv_rx) = RelayRequest::new_associate();
            // let _ = req_tx.send(relay_req).await;

            let res = tokio::select! {
                _ = reply_listener.wait_until_closed() => Ok::<_, anyhow::Error>(()),
                res = socks5_to_relay(listen_socket.clone(),ctrl_addr, pkt_send_tx) => res,
                res = relay_to_socks5(listen_socket,ctrl_addr, pkt_recv_rx) => res,
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
    socket: Arc<AssociatedUdpSocket>,
    ctrl_addr: SocketAddr,
    pkt_send_tx: Sender<(Bytes, Address)>,
) -> anyhow::Result<()> {
    loop {
        let buf_size = MAX_UDP_RELAY_PACKET_SIZE.load(Ordering::Acquire) - UdpHeader::max_serialized_len();
        socket.set_max_packet_size(buf_size);

        let (pkt, frag, dst_addr, src_addr) = socket.recv_from().await?;

        if frag == 0 {
            log::debug!("[socks5] [{ctrl_addr}] [associate] [packet-to] {dst_addr}");
            let _ = pkt_send_tx.send((pkt, dst_addr)).await;
            socket.connect(src_addr).await?;
            break;
        } else {
            log::warn!("[socks5] [{ctrl_addr}] [associate] [packet-to] socks5 UDP packet fragment is not supported");
        }
    }

    loop {
        let buf_size = MAX_UDP_RELAY_PACKET_SIZE.load(Ordering::Acquire)
            - (command_max_serialized_len() - UdpHeader::max_serialized_len());
        socket.set_max_packet_size(buf_size);

        let (pkt, frag, dst_addr) = socket.recv().await?;

        if frag == 0 {
            log::debug!("[socks5] [{ctrl_addr}] [associate] [packet-to] {dst_addr}");

            let dst_addr = match dst_addr {
                Address::DomainAddress(domain, port) => Address::DomainAddress(domain, port),
                Address::SocketAddress(addr) => Address::SocketAddress(addr),
            };

            let _ = pkt_send_tx.send((pkt, dst_addr)).await;
        } else {
            log::warn!("[socks5] [{ctrl_addr}] [associate] [packet-to] socks5 UDP packet fragment is not supported");
        }
    }
}

async fn relay_to_socks5(
    socket: Arc<AssociatedUdpSocket>,
    ctrl_addr: SocketAddr,
    mut pkt_recv_rx: Receiver<(Bytes, Address)>,
) -> anyhow::Result<()> {
    while let Some((pkt, src_addr)) = pkt_recv_rx.recv().await {
        log::debug!("[socks5] [{ctrl_addr}] [associate] [packet-from] {src_addr}");
        socket.send(pkt, 0, src_addr).await?;
    }
    Ok(())
}
