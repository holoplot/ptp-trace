use anyhow::Result;
use clap::Parser;
use std::time::Duration;

mod app;
mod bounded_vec;
mod grpc;
mod headless;
mod oui_map;
mod ptp;
mod service;
mod source;
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
    /// Use INTERFACE:native_vlan_id to specify native VLAN for untagged traffic.
    #[arg(short, long, conflicts_with = "pcap_file")]
    interface: Vec<String>,

    /// Read packets from a pcap file instead of network interfaces. In pcap mode, timestamps are shown relative to the last packet in the file
    #[arg(short = 'f', long, value_name = "FILE", conflicts_with = "interface")]
    pcap_file: Option<String>,

    /// Update interval in milliseconds
    #[arg(short, long, default_value = "1000")]
    update_interval: u64,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,

    #[arg(short, long, default_value = "default", value_parser = parse_theme, help = theme_help_text())]
    theme: String,

    /// Disable mouse support (mouse support is enabled by default)
    #[arg(long)]
    no_mouse: bool,

    /// Run in headless mode (no TUI, just logging)
    #[arg(long)]
    headless: bool,

    /// Log level for headless mode: error (critical events), warn (error + state changes), info (warn + discoveries, default), debug (info + all packets)
    #[arg(long, default_value = "info", requires = "headless")]
    log_level: String,

    /// Web server port for gRPC API and static files (default: 50051). Server always attempts to start but continues if port is unavailable
    #[arg(long, default_value = "50051")]
    web_port: u16,
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

    // Create packet source (either from network interfaces or pcap file)
    let raw_socket_receiver = if let Some(pcap_path) = &cli.pcap_file {
        source::create_pcap_receiver(pcap_path).await?
    } else {
        source::create_raw_socket_receiver(&cli.interface).await?
    };

    // Always create service layer and start gRPC server
    use service::PtpServiceImpl;
    let service = PtpServiceImpl::new(raw_socket_receiver).await?;

    // Start web server in background (always attempt, warn if it fails)
    let web_addr = format!("0.0.0.0:{}", cli.web_port);
    let web_service = service.clone();
    tokio::spawn(async move {
        use grpc::server::start_grpc_server;
        if let Err(e) = start_grpc_server(web_addr, web_service).await {
            eprintln!("Warning: Web server failed to start: {}", e);
            eprintln!("Continuing without web API...");
        }
    });

    // Run in headless mode or TUI mode
    if cli.headless {
        // Parse log level
        use headless::LogLevel;
        let log_level = LogLevel::from_str(&cli.log_level).unwrap_or_else(|| {
            eprintln!(
                "Invalid log level '{}', using 'info'. Valid levels: error, warn, info, debug",
                cli.log_level
            );
            LogLevel::Info
        });

        // Run headless mode - log events and anomalies
        use headless::run_headless_mode;
        run_headless_mode(service, log_level).await?;
    } else {
        let update_interval = Duration::from_millis(cli.update_interval);
        let mut app = App::new(
            update_interval,
            cli.debug,
            theme_name,
            service,
            !cli.no_mouse,
        )?;
        app.run().await?;
    }

    Ok(())
}
