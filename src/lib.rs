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
    format!("{}", name.unwrap().split('.').next().unwrap())
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
