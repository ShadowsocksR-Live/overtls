use log::*;
use std::fs::File;
use viatls::{client, cmdopt, config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = cmdopt::CmdOpt::parse_cmd();
    let is_server = opt.is_server();
    let (config, verbose) = match opt {
        cmdopt::CmdOpt::Server { config, verbose } => (config, verbose),
        cmdopt::CmdOpt::Client { config, verbose } => (config, verbose),
    };

    if verbose {
        std::env::set_var("RUST_LOG", "info");
    }

    env_logger::init();

    let f = File::open(config)?;
    let mut config: config::Config = serde_json::from_reader(f)?;
    config.check_correctness()?;
    if is_server {
        if config.exist_server() {
            info!("Server config: {:?}", config);
            unimplemented!();
        } else {
            anyhow::bail!("Config is not a server config");
        }
    } else if config.exist_client() {
        client::run_client(&config).await?;
    } else {
        anyhow::bail!("Config is not a client config");
    }

    Ok(())
}
