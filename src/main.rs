use overtls::{client, config, server, Error, Result};
use std::fs::File;

mod cmdopt;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let opt = cmdopt::CmdOpt::parse_cmd();
    let is_server = opt.is_server();

    let f = File::open(&opt.config)?;
    let mut config: config::Config = serde_json::from_reader(f)?;
    config.is_server = is_server;
    config.check_correctness()?;
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
}
