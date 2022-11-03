use structopt::StructOpt;

mod cmdopt;
mod client;
mod config;
mod server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = cmdopt::CmdOpt::from_args();

    match opt {
        cmdopt::CmdOpt::Server { config, verbose } => {
            println!("Server config: {:?}, verbose: {}", config, verbose);
            unimplemented!();
        }
        cmdopt::CmdOpt::Client { config, verbose } => {
            println!("Client config: {:?}, verbose: {}", config, verbose);
        }
    }
    Ok(())
}
