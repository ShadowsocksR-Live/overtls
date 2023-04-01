use crate::error::Result;
use std::net::SocketAddr;
use tokio::net::TcpStream;

pub(crate) async fn create(addr: &SocketAddr) -> Result<TcpStream> {
    #[cfg(target_os = "android")]
    {
        let socket = if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };

        // for android vpn service, we need to call VPNService.protect(int) to protect the socket
        // https://developer.android.com/reference/android/net/VpnService.html#protect(int)
        use std::os::unix::io::AsRawFd;
        crate::android::tun_callbacks::on_socket_created(socket.as_raw_fd());

        Ok(socket.connect(*addr).await?)
    }

    #[cfg(not(target_os = "android"))]
    Ok(TcpStream::connect(addr).await?)
}
