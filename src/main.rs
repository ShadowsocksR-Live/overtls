use std::fs::File;

use structopt::StructOpt;

mod client;
mod cmdopt;
mod config;
mod server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = cmdopt::CmdOpt::from_args();
    let (config, verbose, is_server) = match opt {
        cmdopt::CmdOpt::Server { config, verbose } => (config, verbose, true),
        cmdopt::CmdOpt::Client { config, verbose } => (config, verbose, false),
    };

    let f = File::open(config)?;
    let mut config: config::Config = serde_json::from_reader(f)?;
    config.verbose = verbose;
    config.check_correctness()?;
    if is_server {
        if config.is_server() {
            println!("Server config: {:?}, verbose: {}", config, verbose);
            unimplemented!();
        } else {
            anyhow::bail!("Config is not a server config");
        }
    } else if config.is_client() {
        client::run_client(&config).await?;
    } else {
        anyhow::bail!("Config is not a client config");
    }

    Ok(())
}
