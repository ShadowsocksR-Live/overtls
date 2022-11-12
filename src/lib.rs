pub mod client;
pub mod cmdopt;
pub mod config;
pub mod server;
pub mod tls;
pub mod weirduri;

pub fn program_name() -> String {
    let name = std::env::args()
        .next()
        .as_ref()
        .map(std::path::Path::new)
        .and_then(std::path::Path::file_name)
        .and_then(std::ffi::OsStr::to_str)
        .map(String::from);
    name.unwrap_or_default()
        .split('.')
        .next()
        .unwrap_or_default()
        .to_string()
}
