use hickory_proto::{
    op::{Message, Query, ResponseCode::NoError},
    rr::RData,
};
use moka::future::Cache;
use std::{net::IpAddr, time::Duration};

pub(crate) fn parse_data_to_dns_message(data: &[u8], used_by_tcp: bool) -> std::io::Result<Message> {
    if used_by_tcp {
        let err = std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid DNS data");
        if data.len() < 2 {
            return Err(err);
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let data = data.get(2..len + 2).ok_or(err)?;
        return parse_data_to_dns_message(data, false);
    }
    let message = Message::from_vec(data).map_err(std::io::Error::from)?;
    Ok(message)
}

pub(crate) fn extract_ipaddr_from_dns_message(message: &Message) -> std::io::Result<IpAddr> {
    if message.response_code() != NoError {
        let msg = format!("{:?}", message.response_code());
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, msg));
    }
    let mut cname = None;
    for answer in message.answers() {
        let err = std::io::Error::new(std::io::ErrorKind::Other, "DNS response not contains answer data");
        match answer.data().ok_or(err)? {
            RData::A(addr) => {
                return Ok(IpAddr::V4((*addr).into()));
            }
            RData::AAAA(addr) => {
                return Ok(IpAddr::V6((*addr).into()));
            }
            RData::CNAME(name) => {
                cname = Some(name.to_utf8());
            }
            _ => {}
        }
    }
    if let Some(cname) = cname {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, cname));
    }
    Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", message.answers())))
}

pub(crate) fn extract_domain_from_dns_message(message: &Message) -> std::io::Result<String> {
    let err = std::io::Error::new(std::io::ErrorKind::Other, "DNS request not contains query body");
    let query = message.queries().first().ok_or(err)?;
    let name = query.name().to_string();
    Ok(name)
}

pub(crate) fn create_dns_cache() -> Cache<Vec<Query>, Message> {
    Cache::builder()
        .time_to_live(Duration::from_secs(30 * 60))
        .time_to_idle(Duration::from_secs(5 * 60))
        .build()
}

pub(crate) async fn dns_cache_get_message(cache: &Cache<Vec<Query>, Message>, message: &Message) -> Option<Message> {
    if let Some(mut cached_message) = cache.get(&message.queries().to_vec()).await {
        cached_message.set_id(message.id());
        return Some(cached_message);
    }
    None
}

pub(crate) async fn dns_cache_put_message(cache: &Cache<Vec<Query>, Message>, message: &Message) {
    cache.insert(message.queries().to_vec(), message.clone()).await;
}
