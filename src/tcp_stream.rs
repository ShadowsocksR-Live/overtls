pub(crate) async fn tokio_create(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
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

        Ok(socket.connect(addr).await?)
    }

    #[cfg(not(target_os = "android"))]
    tokio::net::TcpStream::connect(addr).await
}

pub(crate) fn std_create(addr: std::net::SocketAddr, timeout: Option<std::time::Duration>) -> std::io::Result<std::net::TcpStream> {
    use socket2::{Domain, SockAddr, Socket, Type};
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::STREAM, None)?;

    #[cfg(target_os = "android")]
    {
        use std::os::unix::io::AsRawFd;
        crate::android::tun_callbacks::on_socket_created(socket.as_raw_fd());
    }

    if let Some(timeout) = timeout {
        socket.connect_timeout(&SockAddr::from(addr), timeout)?;
    } else {
        socket.connect(&SockAddr::from(addr))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        Ok(unsafe { std::net::TcpStream::from_raw_fd(socket.into_raw_fd()) })
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::{FromRawSocket, IntoRawSocket};
        Ok(unsafe { std::net::TcpStream::from_raw_socket(socket.into_raw_socket()) })
    }
}
