use overtls::{client, config, server, Error, Result};
use std::fs::File;

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
    config.is_server = is_server;
    config.check_correctness()?;

    let main_body = async {
        if is_server {
            if config.exist_server() {
                server::run_server(&config).await?;
            } else {
                return Err(Error::from("Config is not a server config"));
            }
        } else if config.exist_client() {
            client::run_client(&config).await?;
        } else {
            return Err("Config is not a client config".into());
        }

        Ok(())
    };

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await?;
        log::trace!("Recieve SIGINT");
        tx.send("Exiting signal error")?;
        Ok::<(), Error>(())
    });
    tokio::select! {
        biased;
        _ = rx => {},
        result = main_body => {
            if let Err(e) = result {
                log::error!("{e}");
            }
        },
    }

    Ok(())
}
