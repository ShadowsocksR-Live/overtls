use crate::config::Config;

pub async fn run_client(config: &Config) -> anyhow::Result<()> {
    serde_json::to_writer_pretty(std::io::stdout(), config)?;

    Ok(())
}
