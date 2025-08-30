use anyhow::Result;
use clap::Parser;
use std::time::Duration;

mod app;
mod bounded_vec;
mod oui_map;
mod ptp;
mod socket;
mod themes;
mod types;
mod ui;
mod version;

use app::App;
use themes::ThemeName;

fn theme_help_text() -> String {
    let themes = ThemeName::all_themes()
        .iter()
        .map(|theme| theme.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    format!("Color theme to use (available: {})", themes)
}

fn parse_theme(s: &str) -> Result<String, String> {
    if ThemeName::all_themes()
        .iter()
        .any(|theme| theme.as_str() == s)
    {
        Ok(s.to_string())
    } else {
        let available = ThemeName::all_themes()
            .iter()
            .map(|theme| theme.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        Err(format!(
            "Invalid theme '{}'. Available themes: {}",
            s, available
        ))
    }
}

#[derive(Parser)]
#[command(name = "ptp-trace")]
#[command(about = "A terminal UI application for tracing PTP hosts in a network")]
#[command(version = version::get_version())]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Network interface(s) to monitor. Can be specified multiple times. If not specified, monitors all interfaces.
    #[arg(short, long)]
    interface: Vec<String>,

    /// Update interval in milliseconds
    #[arg(short, long, default_value = "1000")]
    update_interval: u64,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,

    #[arg(short, long, default_value = "default", value_parser = parse_theme, help = theme_help_text())]
    theme: String,
}

#[derive(Parser)]
pub enum Commands {
    /// Show detailed version information
    VersionInfo,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle subcommands
    if let Some(command) = cli.command {
        match command {
            Commands::VersionInfo => {
                version::print_header_info();
                return Ok(());
            }
        }
    }

    // Parse theme
    let theme_name = ThemeName::from_str(&cli.theme).unwrap_or_else(|| {
        eprintln!("Unknown theme '{}', using default", cli.theme);
        ThemeName::Default
    });

    // Create raw socket receiver early to fail fast if network setup is problematic
    let raw_socket_receiver = socket::create(&cli.interface).await?;

    // Initialize the application
    let update_interval = Duration::from_millis(cli.update_interval);
    let mut app = App::new(update_interval, cli.debug, theme_name, raw_socket_receiver)?;

    // Run the TUI application
    app.run().await?;

    Ok(())
}
