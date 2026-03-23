//! Network interface monitoring for detecting link and IP address changes
//!
//! This module monitors network interfaces for changes in link state and IP addresses,
//! emitting events when changes are detected.

use crate::service::events::PtpEvent;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc;

/// Snapshot of interface state for change detection
#[derive(Debug, Clone)]
struct InterfaceState {
    pub link_up: bool,
    pub addresses: HashSet<IpAddr>,
}

/// Monitors network interfaces for changes
pub struct InterfaceMonitor {
    /// Current state of each interface
    states: HashMap<String, InterfaceState>,
    /// Channel to send events
    event_tx: mpsc::Sender<PtpEvent>,
    /// Polling interval
    poll_interval: Duration,
}

impl InterfaceMonitor {
    /// Create a new interface monitor
    pub fn new(event_tx: mpsc::Sender<PtpEvent>) -> Self {
        Self {
            states: HashMap::new(),
            event_tx,
            poll_interval: Duration::from_secs(5),
        }
    }

    /// Set the polling interval
    #[allow(dead_code)]
    pub fn set_poll_interval(&mut self, interval: Duration) {
        self.poll_interval = interval;
    }

    /// Start monitoring interfaces in the background
    pub async fn start(mut self) -> Result<()> {
        let mut interval = tokio::time::interval(self.poll_interval);

        loop {
            interval.tick().await;

            if let Err(e) = self.check_interfaces().await {
                eprintln!("Error checking interfaces: {}", e);
            }
        }
    }

    /// Check all interfaces for changes
    async fn check_interfaces(&mut self) -> Result<()> {
        // Get current interfaces and their addresses
        let interfaces = if_addrs::get_if_addrs()?;

        let mut current_interfaces: HashMap<String, HashSet<IpAddr>> = HashMap::new();

        for iface in interfaces {
            current_interfaces
                .entry(iface.name.clone())
                .or_default()
                .insert(iface.addr.ip());
        }

        // Check for changes in existing interfaces
        for (name, old_state) in &self.states {
            if let Some(current_addrs) = current_interfaces.get(name) {
                // Interface still exists, check for address changes
                let added: Vec<IpAddr> = current_addrs
                    .difference(&old_state.addresses)
                    .copied()
                    .collect();
                let removed: Vec<IpAddr> = old_state
                    .addresses
                    .difference(current_addrs)
                    .copied()
                    .collect();

                if !added.is_empty() || !removed.is_empty() {
                    let event = PtpEvent::InterfaceAddressChange {
                        interface: name.clone(),
                        added,
                        removed,
                    };
                    let _ = self.event_tx.send(event).await;
                }
            } else if old_state.link_up {
                // Interface disappeared (link down)
                let event = PtpEvent::InterfaceLinkChange {
                    interface: name.clone(),
                    link_up: false,
                };
                let _ = self.event_tx.send(event).await;
            }
        }

        // Check for new interfaces (link up)
        for (name, addrs) in &current_interfaces {
            if !self.states.contains_key(name) {
                let event = PtpEvent::InterfaceLinkChange {
                    interface: name.clone(),
                    link_up: true,
                };
                let _ = self.event_tx.send(event).await;

                // Also report the addresses
                if !addrs.is_empty() {
                    let event = PtpEvent::InterfaceAddressChange {
                        interface: name.clone(),
                        added: addrs.iter().copied().collect(),
                        removed: vec![],
                    };
                    let _ = self.event_tx.send(event).await;
                }
            }
        }

        // Update states
        self.states.clear();
        for (name, addrs) in current_interfaces {
            self.states.insert(
                name,
                InterfaceState {
                    link_up: true,
                    addresses: addrs,
                },
            );
        }

        Ok(())
    }
}
