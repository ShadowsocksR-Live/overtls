#[cfg(target_os = "windows")]
pub fn get_active_network_interface_address() -> Option<std::net::IpAddr> {
    use std::ptr;
    use windows::Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR},
        NetworkManagement::{
            IpHelper::{GetAdaptersAddresses, GET_ADAPTERS_ADDRESSES_FLAGS, IF_TYPE_IEEE80211, IP_ADAPTER_ADDRESSES_LH},
            Ndis::IfOperStatusUp,
        },
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6},
    };

    let mut ipv6 = None;

    unsafe {
        let mut addresses: *mut IP_ADAPTER_ADDRESSES_LH = ptr::null_mut();
        let mut buffer_size: u32 = 0;
        let flags = GET_ADAPTERS_ADDRESSES_FLAGS::default();
        let result = GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, Some(ptr::null_mut()), Some(addresses), &mut buffer_size);
        if result != ERROR_BUFFER_OVERFLOW.0 {
            return None;
        }
        let mut buffer: Vec<u8> = Vec::with_capacity(buffer_size as usize);
        addresses = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        let result = GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, Some(ptr::null_mut()), Some(addresses), &mut buffer_size);
        if result != NO_ERROR.0 {
            return None;
        }
        let mut current_address = addresses;
        while !current_address.is_null() {
            let adapter_address = &*current_address;
            if adapter_address.OperStatus == IfOperStatusUp && adapter_address.IfType == IF_TYPE_IEEE80211 {
                let mut current_ip_address = adapter_address.FirstUnicastAddress;
                while !current_ip_address.is_null() {
                    let ip_address = &*current_ip_address;
                    let sockaddr_ptr = ip_address.Address.lpSockaddr;
                    let sockaddr = &*(sockaddr_ptr as *const SOCKADDR);
                    match sockaddr.sa_family {
                        AF_INET => {
                            let sockaddr_in = &*(sockaddr_ptr as *const SOCKADDR_IN);
                            let ip = sockaddr_in.sin_addr.S_un.S_addr;
                            let ip_bytes = ip.to_ne_bytes();
                            let ip_addr = std::net::Ipv4Addr::from(ip_bytes);
                            return Some(std::net::IpAddr::V4(ip_addr));
                        }
                        AF_INET6 => {
                            let sockaddr_in6 = &*(sockaddr_ptr as *const SOCKADDR_IN6);
                            let ip = sockaddr_in6.sin6_addr.u.Byte;
                            let ip_addr = std::net::Ipv6Addr::from(ip);
                            ipv6 = Some(std::net::IpAddr::V6(ip_addr));
                        }
                        _ => {}
                    }
                    current_ip_address = ip_address.Next;
                }
            }
            current_address = adapter_address.Next;
        }
    }
    ipv6
}

#[cfg(target_family = "unix")]
pub fn get_active_network_interface_address() -> Option<std::net::IpAddr> {
    pnet::datalink::interfaces().into_iter().find_map(|interface| {
        if interface.is_up() && interface.is_broadcast() && interface.is_running() && !interface.is_loopback() {
            let mut ips = interface.ips.clone();
            ips.sort();
            ips.iter().map(|ip_network| ip_network.ip()).next()
        } else {
            None
        }
    })
}
