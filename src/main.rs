use overtls::{client, config, server, Error, Result};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{atomic::AtomicBool, Arc},
};

mod cmdopt;

fn main() -> Result<()> {
    let opt = cmdopt::CmdOpt::parse_cmd();

    dotenvy::dotenv().ok();

    let level = format!("{}={:?}", module_path!(), opt.verbosity);
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    let is_server = opt.is_server();

    let mut config = config::Config::from_config_file(&opt.config)?;
    config.set_cache_dns(opt.cache_dns);

    if opt.qrcode {
        let qrcode = config.generate_ssr_qrcode()?;
        println!("{}", qrcode);
        return Ok(());
    }

    config.check_correctness(is_server)?;

    #[cfg(unix)]
    if opt.daemonize {
        let stdout = std::fs::File::create("/tmp/overtls.out")?;
        let stderr = std::fs::File::create("/tmp/overtls.err")?;
        let daemonize = daemonize::Daemonize::new()
            .working_directory("/tmp")
            .umask(0o777)
            .stdout(stdout)
            .stderr(stderr)
            .privileged_action(|| "Executed before drop privileges");
        let _ = daemonize.start()?;
    }

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async_main(config))
}

async fn async_main(config: config::Config) -> Result<()> {
    let exiting_flag = Arc::new(AtomicBool::new(false));
    let exiting_flag_clone = exiting_flag.clone();

    let main_body = async {
        if config.is_server {
            if config.exist_server() {
                server::run_server(&config, Some(exiting_flag_clone)).await?;
            } else {
                return Err(Error::from("Config is not a server config"));
            }
        } else if config.exist_client() {
            let callback = |addr| {
                log::trace!("Listening on {}", addr);
            };
            client::run_client(&config, Some(exiting_flag_clone), Some(callback)).await?;
        } else {
            return Err("Config is not a client config".into());
        }

        Ok(())
    };

    let local_addr = config.listen_addr()?;

    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut kill_signal = signal(SignalKind::terminate())?;
            tokio::select! {
                _ = tokio::signal::ctrl_c() => log::info!("Ctrl-C received, shutting down..."),
                _ = kill_signal.recv() => log::info!("Kill signal received, shutting down..."),
            }
        }

        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await?;
            log::info!("Ctrl-C received, shutting down...");
        }

        exiting_flag.store(true, std::sync::atomic::Ordering::Relaxed);

        let addr = if local_addr.is_ipv6() {
            SocketAddr::from((Ipv6Addr::LOCALHOST, local_addr.port()))
        } else {
            SocketAddr::from((Ipv4Addr::LOCALHOST, local_addr.port()))
        };
        let _ = std::net::TcpStream::connect(addr);

        Ok::<(), Error>(())
    });

    if let Err(e) = main_body.await {
        log::error!("{}", e);
    }

    Ok(())
}
