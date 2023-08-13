#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Server,
    Client,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum ArgVerbosity {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
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

    /// Verbosity level
    #[arg(short, long, value_name = "level", value_enum, default_value = "info")]
    pub verbosity: ArgVerbosity,

    #[cfg(target_family = "unix")]
    #[arg(short, long)]
    /// Daemonize for unix family.
    pub daemonize: bool,

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
