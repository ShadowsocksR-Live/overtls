use overtls::{client, config, server, Error, Result};
use std::{
    fs::File,
    sync::{atomic::AtomicBool, Arc},
};

mod cmdopt;

#[tokio::main]
async fn main() -> Result<()> {
    let opt = cmdopt::CmdOpt::parse_cmd();

    dotenvy::dotenv().ok();

    let level = if opt.verbose { "trace" } else { "info" };
    let default = format!("{}={}", module_path!(), level);
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();

    let is_server = opt.is_server();

    let f = File::open(&opt.config)?;
    let mut config: config::Config = serde_json::from_reader(f)?;

    if opt.qrcode {
        let qrcode = config.generate_ssr_qrcode()?;
        println!("{}", qrcode);
        return Ok(());
    }

    config.is_server = is_server;
    config.check_correctness()?;

    let exiting_flag = Arc::new(AtomicBool::new(false));
    let exiting_flag_clone = exiting_flag.clone();

    let main_body = async {
        if is_server {
            if config.exist_server() {
                server::run_server(&config, Some(exiting_flag_clone)).await?;
            } else {
                return Err(Error::from("Config is not a server config"));
            }
        } else if config.exist_client() {
            client::run_client(&config, Some(exiting_flag_clone)).await?;
        } else {
            return Err("Config is not a client config".into());
        }

        Ok(())
    };

    let listen_addr = config.listen_addr()?;

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await?;
        log::info!("Recieve SIGINT");
        exiting_flag.store(true, std::sync::atomic::Ordering::Relaxed);

        let addr = if listen_addr.is_ipv6() { "::1" } else { "127.0.0.1" };
        let _ = std::net::TcpStream::connect((addr, listen_addr.port()));

        Ok::<(), Error>(())
    });

    if let Err(e) = main_body.await {
        log::error!("{}", e);
    }

    Ok(())
}
