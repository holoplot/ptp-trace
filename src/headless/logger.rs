//! Logging utilities for headless mode

use crate::service::events::PtpEvent;
use chrono::Local;
use std::io::IsTerminal;

/// Log level for headless mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error, // Only critical events (timeouts, link down, grandmaster/domain changes)
    Warn,  // Error + host updates and state changes
    Info,  // Warn + host discoveries and minor events (default)
    Debug, // Info + verbose output (includes all packets)
}

impl LogLevel {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "error" => Some(LogLevel::Error),
            "warn" => Some(LogLevel::Warn),
            "info" => Some(LogLevel::Info),
            "debug" => Some(LogLevel::Debug),
            _ => None,
        }
    }
}

/// ANSI color codes
mod colors {
    pub const RED: &str = "\x1b[31m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const GREEN: &str = "\x1b[32m";
    pub const CYAN: &str = "\x1b[36m";
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
}

/// Logger configuration
pub struct LoggerConfig {
    pub use_colors: bool,
    pub use_timestamps: bool,
}

impl LoggerConfig {
    /// Detect environment and create appropriate config
    pub fn detect() -> Self {
        let is_tty = std::io::stdout().is_terminal();
        Self {
            use_colors: is_tty,
            use_timestamps: is_tty,
        }
    }
}

/// Format a timestamp for logging
fn timestamp() -> String {
    Local::now().format("[%Y-%m-%d %H:%M:%S%.3f]").to_string()
}

/// Format a log level with optional color
fn format_level(level: &str, color: &str, config: &LoggerConfig) -> String {
    if config.use_colors {
        format!("{}{}{}{}", colors::BOLD, color, level, colors::RESET)
    } else {
        level.to_string()
    }
}

/// Log an event (one line per event)
pub fn log_event(event: &PtpEvent, log_level: LogLevel, config: &LoggerConfig) {
    let ts = if config.use_timestamps {
        format!("{} ", timestamp())
    } else {
        String::new()
    };

    match event {
        // Error level events - critical network issues
        PtpEvent::GrandmasterChange {
            domain,
            old_gm,
            new_gm,
        } => {
            if log_level >= LogLevel::Error {
                let level = format_level("ERROR", colors::RED, config);
                let old_gm_str = old_gm
                    .map(|gm| gm.to_string())
                    .unwrap_or_else(|| "(none)".to_string());
                println!(
                    "{}{}: Grandmaster changed in domain {} | old={} new={}",
                    ts, level, domain, old_gm_str, new_gm
                );
            }
        }

        PtpEvent::DomainChange {
            clock_identity,
            old_domain,
            new_domain,
        } => {
            if log_level >= LogLevel::Error {
                let level = format_level("ERROR", colors::RED, config);
                println!(
                    "{}{}: Host {} changed domain | old={} new={}",
                    ts, level, clock_identity, old_domain, new_domain
                );
            }
        }

        PtpEvent::HostTimeout {
            clock_identity,
            last_seen_ago_secs,
        } => {
            if log_level >= LogLevel::Error {
                let level = format_level("ERROR", colors::RED, config);
                println!(
                    "{}{}: Host {} timeout | last_seen={}s ago",
                    ts, level, clock_identity, last_seen_ago_secs
                );
            }
        }

        PtpEvent::InterfaceLinkChange { interface, link_up } => {
            // Link down is ERROR, link up is WARN
            if !link_up && log_level >= LogLevel::Error {
                let level = format_level("ERROR", colors::RED, config);
                println!("{}{}: Interface {} link down", ts, level, interface);
            } else if *link_up && log_level >= LogLevel::Warn {
                let level = format_level("WARN", colors::YELLOW, config);
                println!("{}{}: Interface {} link up", ts, level, interface);
            }
        }

        PtpEvent::ClockQualityDegraded {
            clock_identity,
            old_class,
            new_class,
            old_accuracy,
            new_accuracy,
        } => {
            if log_level >= LogLevel::Error {
                let level = format_level("ERROR", colors::RED, config);
                println!(
                    "{}{}: Clock quality degraded for {} | class: {}->{} accuracy: {}->{}",
                    ts, level, clock_identity, old_class, new_class, old_accuracy, new_accuracy
                );
            }
        }

        // Warn level events - state changes and updates
        PtpEvent::HostUpdated { host, changes } => {
            if log_level >= LogLevel::Warn {
                let level = format_level("WARN", colors::YELLOW, config);
                for change in changes {
                    println!(
                        "{}{}: Host {} updated | {} {}",
                        ts,
                        level,
                        host.clock_identity,
                        change.as_str(),
                        change.description()
                    );
                }
            }
        }

        PtpEvent::InterfaceAddressChange {
            interface,
            added,
            removed,
        } => {
            if (!added.is_empty() || !removed.is_empty()) && log_level >= LogLevel::Warn {
                let level = format_level("WARN", colors::YELLOW, config);
                let added_str = added
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                let removed_str = removed
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                println!(
                    "{}{}: Interface {} address change | added=[{}] removed=[{}]",
                    ts, level, interface, added_str, removed_str
                );
            }
        }

        // Info level events - new discoveries
        PtpEvent::HostDiscovered(host) => {
            if log_level >= LogLevel::Info {
                let level = format_level("INFO", colors::GREEN, config);
                let domain = host
                    .domain_number
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "?".to_string());
                let ips = host
                    .ip_addresses
                    .iter()
                    .map(|(ip, ifaces)| format!("{}({})", ip, ifaces.join(",")))
                    .collect::<Vec<_>>()
                    .join(", ");
                let ifaces = host
                    .interfaces
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                println!(
                    "{}{}: New host discovered | id={} domain={} ips=[{}] interfaces=[{}]",
                    ts, level, host.clock_identity, domain, ips, ifaces
                );
            }
        }

        // Debug level events - individual packets
        PtpEvent::PacketReceived(packet) => {
            if log_level >= LogLevel::Debug {
                let level = format_level("DEBUG", colors::CYAN, config);
                let clock_id = packet.ptp.header().source_port_identity.clock_identity;
                let msg_type = match &packet.ptp {
                    crate::types::PtpMessage::Announce(_) => "Announce",
                    crate::types::PtpMessage::DelayReq(_) => "DelayReq",
                    crate::types::PtpMessage::DelayResp(_) => "DelayResp",
                    crate::types::PtpMessage::Sync(_) => "Sync",
                    crate::types::PtpMessage::PDelayReq(_) => "PDelayReq",
                    crate::types::PtpMessage::PDelayResp(_) => "PDelayResp",
                    crate::types::PtpMessage::FollowUp(_) => "FollowUp",
                    crate::types::PtpMessage::PDelayRespFollowup(_) => "PDelayRespFollowup",
                    crate::types::PtpMessage::Signaling(_) => "Signaling",
                    crate::types::PtpMessage::Management(_) => "Management",
                };
                println!(
                    "{}{}: Packet received | from={} type={} seq={}",
                    ts,
                    level,
                    clock_id,
                    msg_type,
                    packet.ptp.header().sequence_id
                );
            }
        }
    }
}
