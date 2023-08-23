use moka::future::Cache;
use std::{net::IpAddr, time::Duration};
use trust_dns_proto::{
    op::{Message, Query, ResponseCode::NoError},
    rr::RData,
};

pub(crate) fn parse_data_to_dns_message(data: &[u8], used_by_tcp: bool) -> std::result::Result<Message, String> {
    if used_by_tcp {
        if data.len() < 2 {
            return Err("Invalid DNS data".into());
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let data = data.get(2..len + 2).ok_or("Invalid DNS data")?;
        return parse_data_to_dns_message(data, false);
    }
    let message = Message::from_vec(data).map_err(|e| e.to_string())?;
    Ok(message)
}

pub(crate) fn extract_ipaddr_from_dns_message(message: &Message) -> std::result::Result<IpAddr, String> {
    if message.response_code() != NoError {
        return Err(format!("{:?}", message.response_code()));
    }
    let mut cname = None;
    for answer in message.answers() {
        match answer.data().ok_or("DNS response not contains answer data")? {
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
        return Err(cname);
    }
    Err(format!("{:?}", message.answers()))
}

pub(crate) fn extract_domain_from_dns_message(message: &Message) -> std::result::Result<String, String> {
    let query = message.queries().get(0).ok_or("DNS request not contains query body")?;
    let name = query.name().to_string();
    Ok(name)
}

pub(crate) fn create_dns_cache() -> Cache<Vec<Query>, Message> {
    Cache::builder()
        .time_to_live(Duration::from_secs(30 * 60))
        .time_to_idle(Duration::from_secs(5 * 60))
        .build()
}

pub(crate) fn dns_cache_get_message(cache: &Cache<Vec<Query>, Message>, message: &Message) -> Option<Message> {
    if let Some(mut cached_message) = cache.get(&message.queries().to_vec()) {
        cached_message.set_id(message.id());
        return Some(cached_message);
    }
    None
}

pub(crate) async fn dns_cache_put_message(cache: &Cache<Vec<Query>, Message>, message: &Message) {
    cache.insert(message.queries().to_vec(), message.clone()).await;
}
