#[repr(C)]
#[derive(clap::ValueEnum, Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Server = 0,
    #[default]
    Client,
}

/// Proxy tunnel over tls
#[derive(clap::Parser, Debug, Clone, PartialEq, Eq)]
#[command(author = clap::crate_authors!(", "), version = version_info(), about = about_info(), long_about = None)]
pub struct CmdOpt {
    /// Role of server or client
    #[arg(short, long, value_enum, value_name = "role", default_value = "client")]
    pub role: Role,

    /// Config file path
    #[arg(short, long, value_name = "file path", conflicts_with = "url_of_node")]
    pub config: Option<std::path::PathBuf>,

    /// URL of the server node used by client
    #[arg(short, long, value_name = "url", conflicts_with = "config", requires = "listen_addr")]
    pub url_of_node: Option<String>,

    /// Local listening address, it is required for url_of_node, and optional for config file.
    /// If specified with a config file, it overrides the listen address from that config.
    #[arg(short, long, value_name = "addr:port")]
    pub listen_addr: Option<std::net::SocketAddr>,

    /// Public IP address advertised in UDP ASSOCIATE replies.
    #[arg(short, long, value_name = "ip")]
    pub advertise_ip: Option<std::net::IpAddr>,

    /// Maximum lifetime in seconds for the UDP loop, default is 3600 seconds (1 hour).
    #[arg(long, value_name = "seconds")]
    pub max_lifetime: Option<u64>,

    /// Cache DNS Query result
    #[arg(long)]
    pub cache_dns: bool,

    /// Verbosity level, possible values are "error", "warn", "info", "debug", "trace"
    #[arg(short, long, value_name = "level", default_value = "info")]
    pub verbosity: log::LevelFilter,

    #[arg(short, long)]
    /// Daemonize for unix family or run as service for windows
    pub daemonize: bool,

    /// Generate URL of the server node for client.
    #[arg(short, long)]
    pub generate_url: bool,

    /// Use C API for client.
    #[arg(long)]
    pub c_api: bool,

    /// Connection pool max size
    #[arg(short, long, value_name = "size")]
    pub pool_max_size: Option<usize>,
}

impl CmdOpt {
    pub fn is_server(&self) -> bool {
        self.role == Role::Server
    }

    pub fn parse_cmd() -> CmdOpt {
        fn output_error_and_exit<T: std::fmt::Display>(msg: T) -> ! {
            eprintln!("{msg}");
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
            if args.advertise_ip.is_some() {
                output_error_and_exit("Advertise IP is not supported for server");
            }
            if args.max_lifetime.is_some() {
                output_error_and_exit("Max lifetime is not supported for server");
            }
            if args.url_of_node.is_some() {
                output_error_and_exit("Node URL is not supported for server");
            }
        }
        if args.role == Role::Client
            && let Some(size) = args.pool_max_size
            && size < 10
        {
            output_error_and_exit("Connection pool max size must be greater than 10");
        }
        if args.role == Role::Client && args.config.is_none() && args.url_of_node.is_none() {
            output_error_and_exit("Config file or node URL is required for client");
        }
        args
    }
}

pub(crate) const fn version_info() -> &'static str {
    concat!(clap::crate_version!(), " (", env!("GIT_HASH"), " ", env!("BUILD_TIME"), ")")
}

fn about_info() -> String {
    format!("Proxy tunnel over tls.\nVersion {}", version_info())
}
