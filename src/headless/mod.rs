//! Headless mode for PTP monitoring
//!
//! This module provides headless operation mode that logs events
//! without displaying a TUI.

pub mod logger;

use crate::service::PtpService;
use anyhow::Result;
use std::sync::Arc;

pub use logger::{LogLevel, LoggerConfig};

/// Run headless mode with event logging
pub async fn run_headless_mode(service: Arc<dyn PtpService>, log_level: LogLevel) -> Result<()> {
    let mut event_rx = service.subscribe_to_events().await?;
    let logger_config = LoggerConfig::detect();

    // Only show startup message if on TTY (avoids noise in systemd logs)
    if logger_config.use_timestamps {
        println!(
            "PTP monitoring started in headless mode (log level: {:?})",
            log_level
        );
        println!("Monitoring for PTP events...\n");
    }

    while let Some(event) = event_rx.recv().await {
        logger::log_event(&event, log_level, &logger_config);
    }

    Ok(())
}
