use std::path::PathBuf;

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Server,
    Client,
}

/// Proxy tunnel over tls
#[derive(clap::Parser, Debug, Clone, PartialEq, Eq)]
#[command(author, version, about = "Proxy tunnel over tls.", long_about = None)]
pub struct CmdOpt {
    /// Run as server or client
    #[arg(short, long, value_enum, value_name = "role", default_value = "client")]
    pub role: Role,

    /// Config file path
    #[structopt(short, long, value_name = "file path")]
    pub config: PathBuf,
}

impl CmdOpt {
    pub fn is_server(&self) -> bool {
        self.role == Role::Server
    }

    pub fn parse_cmd() -> CmdOpt {
        <CmdOpt as clap::Parser>::parse()
    }
}
