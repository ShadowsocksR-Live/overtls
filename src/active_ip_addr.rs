#[cfg(target_os = "windows")]
pub fn get_active_network_interface_address() -> std::io::Result<std::net::IpAddr> {
    use std::net::SocketAddr;
    use windows::Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, WIN32_ERROR},
        NetworkManagement::{
            IpHelper::{
                GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_INCLUDE_PREFIX, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211,
                IP_ADAPTER_ADDRESSES_LH,
            },
            Ndis::IfOperStatusUp,
        },
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6},
    };

    pub(crate) fn get_adapters_addresses<F>(mut callback: F) -> std::io::Result<()>
    where
        F: FnMut(IP_ADAPTER_ADDRESSES_LH) -> std::io::Result<()>,
    {
        let mut size = 0;
        let flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
        let family = AF_UNSPEC.0 as u32;

        // Make an initial call to GetAdaptersAddresses to get the size needed into the size variable
        let result = unsafe { GetAdaptersAddresses(family, flags, None, None, &mut size) };

        if WIN32_ERROR(result) != ERROR_BUFFER_OVERFLOW {
            WIN32_ERROR(result).ok()?;
        }
        // Allocate memory for the buffer
        let mut addresses: Vec<u8> = vec![0; (size + 4) as usize];

        // Make a second call to GetAdaptersAddresses to get the actual data we want
        let result = unsafe {
            let addr = Some(addresses.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH);
            GetAdaptersAddresses(family, flags, None, addr, &mut size)
        };

        WIN32_ERROR(result).ok()?;

        // If successful, output some information from the data we received
        let mut current_addresses = addresses.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !current_addresses.is_null() {
            unsafe {
                callback(*current_addresses)?;
                current_addresses = (*current_addresses).Next;
            }
        }
        Ok(())
    }

    pub(crate) unsafe fn sockaddr_to_socket_addr(sock_addr: *const SOCKADDR) -> std::io::Result<SocketAddr> {
        use std::io::{Error, ErrorKind};
        let address = match (*sock_addr).sa_family {
            AF_INET => sockaddr_in_to_socket_addr(&*(sock_addr as *const SOCKADDR_IN)),
            AF_INET6 => sockaddr_in6_to_socket_addr(&*(sock_addr as *const SOCKADDR_IN6)),
            _ => return Err(Error::new(ErrorKind::Other, "Unsupported address type")),
        };
        Ok(address)
    }

    pub(crate) unsafe fn sockaddr_in_to_socket_addr(sockaddr_in: &SOCKADDR_IN) -> SocketAddr {
        let ip_bytes = sockaddr_in.sin_addr.S_un.S_addr.to_ne_bytes();
        let ip = std::net::IpAddr::from(ip_bytes);
        let port = u16::from_be(sockaddr_in.sin_port);
        SocketAddr::new(ip, port)
    }

    pub(crate) unsafe fn sockaddr_in6_to_socket_addr(sockaddr_in6: &SOCKADDR_IN6) -> SocketAddr {
        let ip = std::net::IpAddr::from(sockaddr_in6.sin6_addr.u.Byte);
        let port = u16::from_be(sockaddr_in6.sin6_port);
        SocketAddr::new(ip, port)
    }

    let mut addrs = vec![];
    get_adapters_addresses(|adapter| {
        if adapter.OperStatus == IfOperStatusUp && (adapter.IfType == IF_TYPE_IEEE80211 || adapter.IfType == IF_TYPE_ETHERNET_CSMACD) {
            let mut iter_address = adapter.FirstUnicastAddress;
            while !iter_address.is_null() {
                let address = unsafe { &*iter_address };
                {
                    let sockaddr_ptr = address.Address.lpSockaddr;
                    let sockaddr = unsafe { &*(sockaddr_ptr as *const SOCKADDR) };
                    let a = unsafe { sockaddr_to_socket_addr(sockaddr)? };
                    addrs.push(a.ip());
                }
                iter_address = address.Next;
            }
        }
        Ok(())
    })?;

    // find out ipv4 address or find out ipv6 address or return error
    use std::io::ErrorKind::NotFound;
    let addr = addrs.clone().into_iter().find(|addr| addr.is_ipv4()).unwrap_or(
        addrs
            .into_iter()
            .find(|addr| addr.is_ipv6())
            .ok_or(std::io::Error::new(NotFound, "no active network interface address"))?,
    );

    Ok(addr)
}

#[cfg(target_family = "unix")]
pub fn get_active_network_interface_address() -> std::io::Result<std::net::IpAddr> {
    use std::io::ErrorKind::NotFound;
    pnet::datalink::interfaces()
        .into_iter()
        .find_map(|interface| {
            if interface.is_up() && interface.is_broadcast() && interface.is_running() && !interface.is_loopback() {
                let mut ips = interface.ips.clone();
                ips.sort();
                ips.iter().map(|ip_network| ip_network.ip()).next()
            } else {
                None
            }
        })
        .ok_or(std::io::Error::new(NotFound, "no active network interface address"))
}
