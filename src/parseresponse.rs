use http::{header::HeaderName, HeaderMap, HeaderValue, StatusCode};
use httparse::Status;
use tungstenite::{
    error::{Error, ProtocolError, Result},
    handshake::{client::Response, headers::MAX_HEADERS},
};

/// Parse the response data from the server.
/// stolen from https://github.com/snapview/tungstenite-rs/blob/80d0547fab5e4e510c73fb0c30f53d731864c37b/src/handshake/client.rs#L240
/// hopefully this will be fixed in tungstenite-rs
pub fn parse_response_data(data: &[u8]) -> Result<Response> {
    let response = try_parse(data)?
        .ok_or(Error::Protocol(ProtocolError::HandshakeIncomplete))?
        .1;
    let key = response
        .headers()
        .get("Sec-WebSocket-Accept")
        .ok_or(Error::Protocol(ProtocolError::SecWebSocketAcceptKeyMismatch))?
        .to_str()?
        .to_owned();
    let data = VerifyData { accept_key: key };
    data.verify_response(response)
}

fn try_parse(buf: &[u8]) -> Result<Option<(usize, Response)>> {
    let mut hbuffer = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Response::new(&mut hbuffer);
    Ok(match req.parse(buf)? {
        Status::Partial => None,
        Status::Complete(size) => Some((size, response_from_httparse(req)?)),
    })
}

fn response_from_httparse(raw: httparse::Response) -> Result<Response> {
    if raw.version.expect("Bug: no HTTP version") < /*1.*/1 {
        return Err(Error::Protocol(ProtocolError::WrongHttpMethod));
    }

    let headers = header_map_from_httparse(raw.headers)?;

    let mut response = Response::new(());
    *response.status_mut() = StatusCode::from_u16(raw.code.expect("Bug: no HTTP status code"))?;
    *response.headers_mut() = headers;
    // TODO: httparse only supports HTTP 0.9/1.0/1.1 but not HTTP 2.0
    // so the only valid value we could get in the response would be 1.1.
    *response.version_mut() = http::Version::HTTP_11;

    Ok(response)
}

fn header_map_from_httparse<'b: 'h, 'h>(raw: &'b [httparse::Header<'h>]) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    for h in raw {
        headers.append(
            HeaderName::from_bytes(h.name.as_bytes())?,
            HeaderValue::from_bytes(h.value)?,
        );
    }

    Ok(headers)
}

/// Information for handshake verification.
#[derive(Debug)]
struct VerifyData {
    /// Accepted server key.
    accept_key: String,
}

impl VerifyData {
    pub fn verify_response(&self, response: Response) -> Result<Response> {
        // 1. If the status code received from the server is not 101, the
        // client handles the response per HTTP [RFC2616] procedures. (RFC 6455)
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(Error::Http(response.map(|_| None)));
        }

        let headers = response.headers();

        // 2. If the response lacks an |Upgrade| header field or the |Upgrade|
        // header field contains a value that is not an ASCII case-
        // insensitive match for the value "websocket", the client MUST
        // _Fail the WebSocket Connection_. (RFC 6455)
        if !headers
            .get("Upgrade")
            .and_then(|h| h.to_str().ok())
            .map(|h| h.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
        {
            return Err(Error::Protocol(ProtocolError::MissingUpgradeWebSocketHeader));
        }
        // 3.  If the response lacks a |Connection| header field or the
        // |Connection| header field doesn't contain a token that is an
        // ASCII case-insensitive match for the value "Upgrade", the client
        // MUST _Fail the WebSocket Connection_. (RFC 6455)
        if !headers
            .get("Connection")
            .and_then(|h| h.to_str().ok())
            .map(|h| h.eq_ignore_ascii_case("Upgrade"))
            .unwrap_or(false)
        {
            return Err(Error::Protocol(ProtocolError::MissingConnectionUpgradeHeader));
        }
        // 4.  If the response lacks a |Sec-WebSocket-Accept| header field or
        // the |Sec-WebSocket-Accept| contains a value other than the
        // base64-encoded SHA-1 of ... the client MUST _Fail the WebSocket
        // Connection_. (RFC 6455)
        if !headers
            .get("Sec-WebSocket-Accept")
            .map(|h| h == &self.accept_key)
            .unwrap_or(false)
        {
            return Err(Error::Protocol(ProtocolError::SecWebSocketAcceptKeyMismatch));
        }
        // 5.  If the response includes a |Sec-WebSocket-Extensions| header
        // field and this header field indicates the use of an extension
        // that was not present in the client's handshake (the server has
        // indicated an extension not requested by the client), the client
        // MUST _Fail the WebSocket Connection_. (RFC 6455)
        // TODO

        // 6.  If the response includes a |Sec-WebSocket-Protocol| header field
        // and this header field indicates the use of a subprotocol that was
        // not present in the client's handshake (the server has indicated a
        // subprotocol not requested by the client), the client MUST _Fail
        // the WebSocket Connection_. (RFC 6455)
        // TODO

        Ok(response)
    }
}
