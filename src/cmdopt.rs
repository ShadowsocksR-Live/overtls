use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, PartialEq, Eq, Debug)]
pub enum CmdOpt {
    /// Running OverTLS server
    Server {
        #[structopt(short, long)]
        /// config file path for server
        config: PathBuf,

        #[structopt(short, long)]
        /// Verbose mode.
        verbose: bool,
    },

    /// Running OverTLS client
    Client {
        #[structopt(short, long)]
        /// config file path for client
        config: PathBuf,

        #[structopt(short, long)]
        /// Verbose mode.
        verbose: bool,
    },
}

impl CmdOpt {
    pub fn is_server(&self) -> bool {
        match self {
            CmdOpt::Server { .. } => true,
            CmdOpt::Client { .. } => false,
        }
    }

    pub fn parse_cmd() -> CmdOpt {
        CmdOpt::from_args()
    }
}
