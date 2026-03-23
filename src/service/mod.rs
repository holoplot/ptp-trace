//! Service abstraction layer for PTP monitoring
//!
//! This module provides a service-oriented interface to PTP packet capture and host tracking,
//! decoupling the domain logic from presentation layers (TUI, gRPC, headless mode).

pub mod events;
pub mod implementation;
pub mod interface_monitor;

pub use events::PtpEvent;
pub use implementation::PtpServiceImpl;

use crate::ptp::PtpHost;
use crate::types::{ClockIdentity, ParsedPacket};
use anyhow::Result;
use async_trait::async_trait;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::mpsc;

/// Statistics about the PTP monitoring service
#[derive(Debug, Clone, Default)]
pub struct PtpStatistics {
    pub total_hosts: usize,
    pub transmitter_count: usize,
    pub receiver_count: usize,
    pub listening_count: usize,
    pub last_packet_age_ms: u64,
    pub total_packets: u64,
    pub hostname: String,
    pub interfaces: Vec<String>,
    pub version: String,
    pub local_ips: Vec<IpAddr>,
    pub last_packet_timestamp: Option<SystemTime>,
}

/// Main service trait for PTP monitoring
#[async_trait]
pub trait PtpService: Send + Sync {
    /// Get all currently known hosts
    async fn get_hosts(&self) -> Result<Vec<PtpHost>>;

    /// Get a specific host by clock identity
    async fn get_host_by_id(&self, clock_identity: &ClockIdentity) -> Result<Option<PtpHost>>;

    /// Get packet history for a specific host
    async fn get_packet_history(&self, clock_identity: &ClockIdentity)
    -> Result<Vec<ParsedPacket>>;

    /// Get current statistics
    async fn get_statistics(&self) -> Result<PtpStatistics>;

    /// Subscribe to real-time events
    async fn subscribe_to_events(&self) -> Result<mpsc::Receiver<PtpEvent>>;

    /// Clear all hosts
    async fn clear_hosts(&self) -> Result<()>;

    /// Clear packet history for a specific host
    #[allow(dead_code)]
    async fn clear_host_packet_history(&self, clock_identity: &ClockIdentity) -> Result<()>;

    /// Clear all packet histories
    #[allow(dead_code)]
    async fn clear_all_packet_histories(&self) -> Result<()>;

    /// Set maximum packet history size per host
    #[allow(dead_code)]
    async fn set_max_packet_history(&self, max_history: usize) -> Result<()>;
}

/// Type alias for a service instance wrapped in Arc for shared ownership
#[allow(dead_code)]
pub type ServiceHandle = Arc<dyn PtpService>;
