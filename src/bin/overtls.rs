use overtls::{client, config, server, CmdOpt, Error, Result};

fn main() -> Result<()> {
    let opt = CmdOpt::parse_cmd();

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
    let shutdown_token = overtls::CancellationToken::new();
    let shutdown_token_clone = shutdown_token.clone();

    let main_body = async {
        if config.is_server {
            if config.exist_server() {
                server::run_server(&config, shutdown_token_clone).await?;
            } else {
                return Err(Error::from("Config is not a server config"));
            }
        } else if config.exist_client() {
            let callback = |addr| {
                log::trace!("Listening on {}", addr);
            };
            client::run_client(&config, shutdown_token_clone, Some(callback)).await?;
        } else {
            return Err("Config is not a client config".into());
        }

        Ok(())
    };

    ctrlc2::set_async_handler(async move {
        log::info!("Ctrl-C received, exiting...");
        shutdown_token.cancel();
    })
    .await;

    if let Err(e) = main_body.await {
        log::error!("{}", e);
    }

    Ok(())
}
