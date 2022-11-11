pub mod client;
pub mod cmdopt;
pub mod config;
pub mod parseresponse;
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
    name.unwrap().split('.').next().unwrap().to_string()
}
