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
#[derive(clap::Parser, Debug, Clone, PartialEq, Eq, Default)]
#[command(author, version, about = "Proxy tunnel over tls.", long_about = None)]
pub struct CmdOpt {
    /// Role of server or client
    #[arg(short, long, value_enum, value_name = "role", default_value = "client")]
    pub role: Role,

    /// Config file path
    #[arg(short, long, value_name = "file path", conflicts_with = "url_of_node")]
    pub config: Option<std::path::PathBuf>,

    /// URL of the server node used by client
    #[arg(short, long, value_name = "url", conflicts_with = "config")]
    pub url_of_node: Option<String>,

    /// Local listening address associated with the URL
    #[arg(short, long, value_name = "addr:port", requires = "url_of_node", conflicts_with = "config")]
    pub listen_addr: Option<std::net::SocketAddr>,

    /// Cache DNS Query result
    #[arg(long)]
    pub cache_dns: bool,

    /// Verbosity level
    #[arg(short, long, value_name = "level", value_enum, default_value = "info")]
    pub verbosity: ArgVerbosity,

    #[arg(short, long)]
    /// Daemonize for unix family or run as service for windows
    pub daemonize: bool,

    /// Generate URL of the server node for client.
    #[arg(short, long)]
    pub generate_url: bool,

    /// Use C API for client.
    #[arg(long)]
    pub c_api: bool,
}

impl CmdOpt {
    pub fn is_server(&self) -> bool {
        self.role == Role::Server
    }

    pub fn parse_cmd() -> CmdOpt {
        fn output_error_and_exit<T: std::fmt::Display>(msg: T) -> ! {
            eprintln!("{}", msg);
            std::process::exit(1);
        }

        let args: CmdOpt = clap::Parser::parse();
        if args.role == Role::Server {
            if args.config.is_none() {
                output_error_and_exit("Config file is required for server");
            }
            if args.c_api {
                output_error_and_exit("C API is not supported for server");
            }
            if args.generate_url {
                output_error_and_exit("Generate URL is not supported for server");
            }
            if args.listen_addr.is_some() {
                output_error_and_exit("Listen address is not supported for server");
            }
            if args.url_of_node.is_some() {
                output_error_and_exit("Node URL is not supported for server");
            }
        }
        if args.role == Role::Client && args.config.is_none() && args.url_of_node.is_none() {
            output_error_and_exit("Config file or node URL is required for client");
        }
        args
    }
}
