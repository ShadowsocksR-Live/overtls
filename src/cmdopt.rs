#[repr(C)]
#[derive(clap::ValueEnum, Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Server = 0,
    #[default]
    Client,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum ArgVerbosity {
    Off = 0,
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

#[cfg(target_os = "android")]
impl TryFrom<jni::sys::jint> for ArgVerbosity {
    type Error = std::io::Error;
    fn try_from(value: jni::sys::jint) -> Result<Self, <Self as TryFrom<jni::sys::jint>>::Error> {
        match value {
            0 => Ok(ArgVerbosity::Off),
            1 => Ok(ArgVerbosity::Error),
            2 => Ok(ArgVerbosity::Warn),
            3 => Ok(ArgVerbosity::Info),
            4 => Ok(ArgVerbosity::Debug),
            5 => Ok(ArgVerbosity::Trace),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid verbosity level")),
        }
    }
}

impl From<ArgVerbosity> for log::LevelFilter {
    fn from(verbosity: ArgVerbosity) -> Self {
        match verbosity {
            ArgVerbosity::Off => log::LevelFilter::Off,
            ArgVerbosity::Error => log::LevelFilter::Error,
            ArgVerbosity::Warn => log::LevelFilter::Warn,
            ArgVerbosity::Info => log::LevelFilter::Info,
            ArgVerbosity::Debug => log::LevelFilter::Debug,
            ArgVerbosity::Trace => log::LevelFilter::Trace,
        }
    }
}

impl From<log::Level> for ArgVerbosity {
    fn from(level: log::Level) -> Self {
        match level {
            log::Level::Error => ArgVerbosity::Error,
            log::Level::Warn => ArgVerbosity::Warn,
            log::Level::Info => ArgVerbosity::Info,
            log::Level::Debug => ArgVerbosity::Debug,
            log::Level::Trace => ArgVerbosity::Trace,
        }
    }
}

impl std::fmt::Display for ArgVerbosity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArgVerbosity::Off => write!(f, "off"),
            ArgVerbosity::Error => write!(f, "error"),
            ArgVerbosity::Warn => write!(f, "warn"),
            ArgVerbosity::Info => write!(f, "info"),
            ArgVerbosity::Debug => write!(f, "debug"),
            ArgVerbosity::Trace => write!(f, "trace"),
        }
    }
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

    /// Cache DNS Query result
    #[arg(long)]
    pub cache_dns: bool,

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
