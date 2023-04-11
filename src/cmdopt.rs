#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Server,
    Client,
}

/// Proxy tunnel over tls
#[derive(clap::Parser, Debug, Clone, PartialEq, Eq)]
#[command(author, version, about = "Proxy tunnel over tls.", long_about = None)]
pub struct CmdOpt {
    /// Role of server or client
    #[arg(short, long, value_enum, value_name = "role", default_value = "client")]
    pub role: Role,

    /// Config file path
    #[arg(short, long, value_name = "file path")]
    pub config: std::path::PathBuf,

    /// Verbose mode.
    #[arg(short, long)]
    pub verbose: bool,

    /// Generate QR code for client.
    #[arg(short, long)]
    pub qrcode: bool,
}

impl CmdOpt {
    pub fn is_server(&self) -> bool {
        self.role == Role::Server
    }

    pub fn parse_cmd() -> CmdOpt {
        clap::Parser::parse()
    }
}
