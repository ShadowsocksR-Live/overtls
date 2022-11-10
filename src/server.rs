use crate::{config::Config, parseresponse::parse_response_data, tls::*, weirduri::TARGET_ADDRESS};
use bytes::BytesMut;
use env_logger;
use futures_util::{SinkExt, StreamExt, Stream};
use httparse;
use log::*;
use log::*;
use socks5_proto::{Address, Reply};
use socks5_server::{auth::NoAuth, connection::connect::NeedReply, Connect, Connection, IncomingConnection, Server};
use std::net::{SocketAddr, ToSocketAddrs};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::{
    rustls::{self, Certificate, OwnedTrustAnchor, PrivateKey},
    server::TlsStream,
    webpki, TlsConnector,
};
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::WebSocketStream;
use tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tungstenite::protocol::{Message, Role};
use futures_util::future::join_all;

pub async fn run_server(config: &Config) -> anyhow::Result<()> {
    info!("starting {} server...", crate::program_name());
    trace!("with following settings:");
    trace!("{}", serde_json::to_string_pretty(config)?);

    let server = config.server.as_ref();
    let server = server.ok_or_else(|| anyhow::anyhow!("server settings"))?;
    let addr = format!("{}:{}", server.listen_host, server.listen_port);

    let certs = if let Some(ref cert) = server.certfile {
        server_load_certs(cert).ok()
    } else {
        None
    };

    let keys = if let Some(ref key) = server.keyfile {
        server_load_keys(key).ok()
    } else {
        None
    };

    let svr_cfg = if let (Some(certs), Some(mut keys)) = (certs, keys) {
        rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, keys.remove(0))
            .map_err(|err| anyhow::anyhow!(err))
            .ok()
    } else {
        None
    };

    let acceptor = if let Some(svr_cfg) = svr_cfg {
        Some(TlsAcceptor::from(std::sync::Arc::new(svr_cfg)))
    } else {
        None
    };

    let listener = TcpListener::bind(&addr).await?;

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let config = config.clone();

        let incoming_task = async move {
            if let Some(acceptor) = acceptor {
                let stream = acceptor.accept(stream).await?;
                if let Err(e) = handle_tls_incoming(stream, config).await {
                    error!("{}: {}", peer_addr, e);
                }
            } else {
                if let Err(e) = handle_incoming(stream, config).await {
                    error!("{}: {}", peer_addr, e);
                }
            }
            Ok::<_, anyhow::Error>(())
        };

        tokio::spawn(async move {
            if let Err(err) = incoming_task.await {
                eprintln!("{:?}", err);
            }
        });
    }
}

async fn handle_tls_incoming(stream: TlsStream<TcpStream>, config: Config) -> anyhow::Result<()> {
    trace!(
        "tls incoming connection {} with {:?}",
        stream.get_ref().0.peer_addr()?,
        config
    );
    Ok(())
}

async fn handle_incoming(stream: TcpStream, config: Config) -> anyhow::Result<()> {
    // let peer_addr = stream.peer_addr()?;
    // info!("Echo: {} - {:?}", peer_addr, config);
    let _ = handle_connection(stream, config).await;
    // let (mut reader, mut writer) = tokio::io::split(stream);
    // let _n = tokio::io::copy(&mut reader, &mut writer).await?;
    // writer.flush().await?;

    {
        // stream
        //     .write_all(
        //         &b"HTTP/1.0 200 ok\r\n\
        //     Connection: close\r\n\
        //     Content-length: 12\r\n\
        //     \r\n\
        //     Hello world!"[..],
        //     )
        //     .await?;
        // stream.shutdown().await?;
        // println!("Hello: {}", peer_addr);
    }

    // let server = Server::bind(addr, std::sync::Arc::new(NoAuth)).await?;

    // while let Ok((conn, _)) = server.accept().await {
    //     let config = config.clone();
    //     tokio::spawn(async move {
    //         if let Err(e) = handle_incoming(conn, config).await {
    //             error!("{}", e);
    //         }
    //     });
    // }

    Ok(())
}

async fn check_uri_path(stream: &TcpStream, path: &str) -> anyhow::Result<bool> {
    let mut buf = [0; 512];
    stream.peek(&mut buf).await?;

    let mut headers = [httparse::EMPTY_HEADER; 512];
    let mut req = httparse::Request::new(&mut headers);
    req.parse(&buf)?;

    if let Some(p) = req.path {
        if p == path {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn handle_connection(stream: TcpStream, config: Config) -> anyhow::Result<()> {
    if !check_uri_path(&stream, config.tunnel_path.as_str()).await? {
        warn!("invalid path \"{}\"", config.tunnel_path);
        // TODO: go anthor precess for nomal http request, not a ws proxy request
    }

    let peer = stream.peer_addr()?;
    let mut target_address = "".to_string();
    let mut uri_path = "".to_string();

    let check_headers_callback = |req: &Request, res: Response| -> anyhow::Result<Response, ErrorResponse> {
        uri_path = req.uri().path().to_string();
        req.headers().get(TARGET_ADDRESS).map(|value| {
            if let Ok(value) = value.to_str() {
                target_address = value.to_string();
            }
        });
        Ok(res)
    };

    use futures::channel::mpsc;
    use futures::sink::SinkExt;
    use futures::stream::{self, StreamExt};
    
    let mut ws_stream = accept_hdr_async(stream, check_headers_callback).await?;

    let target_address = base64::decode(target_address)?;
    let target_address = Address::read_from(&mut &target_address[..]).await?;
    let target_address = target_address.to_string().to_socket_addrs()?.next().unwrap();

    trace!("{} -> {}  uri path: \"{}\"", peer, target_address, uri_path);

    let mut outgoing = TcpStream::connect(target_address).await?;

    let (mut ws_r, mut ws_w) = ws_stream.split();
    let (mut outging_r, mut outgoing_w) = outgoing.split();

    let ws_to_outgoing = async {
        let mut buf = [0u8; 1024 * 8];
        while let Some(msg) = ws_r.next().await {
            let msg = msg?;
            if msg.is_close() {
                trace!("{} -> {} ws connection closed.", peer, target_address);
                break;
            }
            if msg.is_text() || msg.is_binary() {
                outgoing_w.write_all(&msg.into_data()).await?;
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    let outgoing_to_ws = async {
        let mut buf = [0u8; 1024 * 8];
        loop {
            let n = outging_r.try_read(&mut buf)?;
            if n == 0 {
                break;
            }
            ws_w.send(Message::Binary(buf.to_vec())).await?;
            // ws_w.write_all(&buf[..n]).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        result = ws_to_outgoing => { result }
        result = outgoing_to_ws => { result }
    }

    // let (_ws_to_outgoing, _outgoing_to_ws) = tokio::join!(ws_to_outgoing, outgoing_to_ws);

    // while let Some(msg) = ws_stream.next().await {
    //     let msg = msg?;
    //     if msg.is_close() {
    //         trace!("{} -> {} ws connection closed.", peer, target_address);
    //         break;
    //     }
    //     if msg.is_text() || msg.is_binary() {
    //         ws_stream.send(msg).await?;
    //     }
    // }

    // Ok(())
}
