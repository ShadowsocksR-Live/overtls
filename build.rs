fn main() -> std::io::Result<()> {
    // Set the environment variables GIT_HASH
    if let Ok(git_hash) = get_git_hash() {
        println!("cargo:rustc-env=GIT_HASH={}", git_hash.trim());
    }

    // Get the build time
    let build_time = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    println!("cargo:rustc-env=BUILD_TIME={build_time}");

    Ok(())
}

fn get_git_hash() -> std::io::Result<String> {
    use std::process::Command;
    let git_hash = Command::new("git").args(["rev-parse", "--short", "HEAD"]).output()?.stdout;
    let git_hash = String::from_utf8(git_hash).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(git_hash)
}
