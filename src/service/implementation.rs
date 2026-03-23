//! Service implementation for PTP monitoring
//!
//! This module provides the concrete implementation of the PtpService trait,
//! managing packet capture, host tracking, and event emission.

use crate::ptp::PtpTracker;
use crate::service::events::{ChangeType, PtpEvent};
use crate::service::interface_monitor::InterfaceMonitor;
use crate::service::{PtpService, PtpStatistics};
use crate::source::RawSocketReceiver;
use crate::types::{ClockIdentity, ParsedPacket};
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};

/// Snapshot of host state for change detection
#[derive(Debug, Clone)]
struct HostSnapshot {
    domain_number: Option<u8>,
    ip_addresses: std::collections::HashSet<std::net::IpAddr>,
    interfaces: std::collections::HashSet<String>,
    state_type: String, // "Listening", "TimeTransmitter", "TimeReceiver"
    is_bmca_winner: bool,
    clock_class: Option<u8>,
    selected_transmitter: Option<ClockIdentity>,
}

/// Implementation of PtpService
pub struct PtpServiceImpl {
    /// The PTP tracker wrapped in Arc<RwLock<>> for thread-safe access
    tracker: Arc<RwLock<PtpTracker>>,

    /// Event subscribers
    event_subscribers: Arc<RwLock<Vec<mpsc::Sender<PtpEvent>>>>,

    /// Previous state snapshots for change detection
    previous_states: Arc<RwLock<HashMap<ClockIdentity, HostSnapshot>>>,

    /// Grandmaster tracking for domain change detection
    domain_grandmasters: Arc<RwLock<HashMap<u8, ClockIdentity>>>,
}

impl PtpServiceImpl {
    /// Create a new service instance and start background processing
    pub async fn new(raw_socket_receiver: RawSocketReceiver) -> Result<Arc<Self>> {
        let tracker = Arc::new(RwLock::new(PtpTracker::new(raw_socket_receiver)?));
        let event_subscribers = Arc::new(RwLock::new(Vec::new()));
        let previous_states = Arc::new(RwLock::new(HashMap::new()));
        let domain_grandmasters = Arc::new(RwLock::new(HashMap::new()));

        let service = Arc::new(Self {
            tracker,
            event_subscribers,
            previous_states,
            domain_grandmasters,
        });

        // Start background packet processing
        Self::start_packet_processing(service.clone()).await;

        // Start interface monitoring
        Self::start_interface_monitoring(service.clone()).await;

        // Start periodic host updates
        Self::start_periodic_updates(service.clone()).await;

        Ok(service)
    }

    /// Start background task for processing packets
    async fn start_packet_processing(service: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                // Process packets and get the list of processed packets
                let packets = {
                    let mut tracker = service.tracker.write().await;
                    tracker.scan_network().await
                };

                // Emit PacketReceived events for each packet
                for packet in packets {
                    service
                        .emit_event(PtpEvent::PacketReceived((*packet).clone()))
                        .await;
                }

                // Detect and emit events for changes
                if let Err(e) = service.detect_and_emit_changes().await {
                    eprintln!("Error detecting changes: {}", e);
                }

                // Small delay to prevent busy-waiting
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
    }

    /// Start background task for monitoring interfaces
    async fn start_interface_monitoring(service: Arc<Self>) {
        // Create a channel for interface events
        let (event_tx, mut event_rx) = mpsc::channel(100);

        // Spawn interface monitor
        tokio::spawn(async move {
            let monitor = InterfaceMonitor::new(event_tx);
            if let Err(e) = monitor.start().await {
                eprintln!("Interface monitor error: {}", e);
            }
        });

        // Forward interface events to subscribers
        let service_clone = service.clone();
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                service_clone.emit_event(event).await;
            }
        });
    }

    /// Start periodic updates to emit fresh host data
    async fn start_periodic_updates(service: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                // Wait 500ms between updates
                tokio::time::sleep(Duration::from_millis(500)).await;

                // Get all hosts and emit updates (to refresh counters, timestamps, etc.)
                let tracker = service.tracker.read().await;
                let hosts = tracker.get_hosts();

                for host in hosts {
                    service.emit_event(PtpEvent::HostUpdated {
                        host: host.clone(),
                        changes: vec![], // Empty changes - just a data refresh
                    }).await;
                }
            }
        });
    }

    /// Detect changes and emit events
    async fn detect_and_emit_changes(&self) -> Result<()> {
        let tracker = self.tracker.read().await;
        let hosts = tracker.get_hosts();
        let mut previous_states = self.previous_states.write().await;
        let mut domain_gms = self.domain_grandmasters.write().await;

        for host in hosts {
            let clock_id = host.clock_identity;

            // Create current snapshot
            let current_snapshot = HostSnapshot {
                domain_number: host.domain_number,
                ip_addresses: host.ip_addresses.keys().copied().collect(),
                interfaces: host.interfaces.clone(),
                state_type: host.state.short_string().to_string(),
                is_bmca_winner: matches!(host.state, crate::ptp::PtpHostState::TimeTransmitter(ref s) if s.is_bmca_winner),
                clock_class: if let crate::ptp::PtpHostState::TimeTransmitter(ref s) = host.state {
                    s.clock_class.map(|c| c.class())
                } else {
                    None
                },
                selected_transmitter: if let crate::ptp::PtpHostState::TimeReceiver(ref s) = host.state {
                    s.selected_transmitter_identity
                } else {
                    None
                },
            };

            if let Some(prev) = previous_states.get(&clock_id) {
                // Detect changes
                let mut changes = Vec::new();

                if prev.domain_number != current_snapshot.domain_number {
                    changes.push(ChangeType::DomainNumber {
                        old: prev.domain_number,
                        new: current_snapshot.domain_number,
                    });

                    // Emit domain change event
                    if let (Some(old), Some(new)) =
                        (prev.domain_number, current_snapshot.domain_number)
                    {
                        self.emit_event(PtpEvent::DomainChange {
                            clock_identity: clock_id,
                            old_domain: old,
                            new_domain: new,
                        })
                        .await;
                    }
                }

                if prev.ip_addresses != current_snapshot.ip_addresses {
                    let added: Vec<String> = current_snapshot
                        .ip_addresses
                        .difference(&prev.ip_addresses)
                        .map(|ip| ip.to_string())
                        .collect();
                    let removed: Vec<String> = prev
                        .ip_addresses
                        .difference(&current_snapshot.ip_addresses)
                        .map(|ip| ip.to_string())
                        .collect();

                    changes.push(ChangeType::IpAddress { added, removed });
                }

                if prev.interfaces != current_snapshot.interfaces {
                    let added: Vec<String> = current_snapshot
                        .interfaces
                        .difference(&prev.interfaces)
                        .cloned()
                        .collect();
                    let removed: Vec<String> = prev
                        .interfaces
                        .difference(&current_snapshot.interfaces)
                        .cloned()
                        .collect();

                    changes.push(ChangeType::Interface { added, removed });
                }

                if prev.state_type != current_snapshot.state_type {
                    changes.push(ChangeType::State {
                        old: prev.state_type.clone(),
                        new: current_snapshot.state_type.clone(),
                    });
                }

                if prev.clock_class != current_snapshot.clock_class {
                    let old_str = prev
                        .clock_class
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "none".to_string());
                    let new_str = current_snapshot
                        .clock_class
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "none".to_string());

                    changes.push(ChangeType::ClockQuality {
                        description: format!("{} -> {}", old_str, new_str),
                    });
                }

                if prev.selected_transmitter != current_snapshot.selected_transmitter {
                    changes.push(ChangeType::SelectedTransmitter {
                        old: prev.selected_transmitter.map(|id| id.to_string()),
                        new: current_snapshot.selected_transmitter.map(|id| id.to_string()),
                    });
                }

                // Check for grandmaster changes
                if current_snapshot.is_bmca_winner
                    && let Some(domain) = current_snapshot.domain_number {
                        let old_gm = domain_gms.insert(domain, clock_id);
                        if old_gm.is_some() && old_gm != Some(clock_id) {
                            self.emit_event(PtpEvent::GrandmasterChange {
                                domain,
                                old_gm,
                                new_gm: clock_id,
                            })
                            .await;
                        }
                    }

                if !changes.is_empty() {
                    self.emit_event(PtpEvent::HostUpdated {
                        host: host.clone(),
                        changes,
                    })
                    .await;
                }
            } else {
                // New host discovered
                self.emit_event(PtpEvent::HostDiscovered(host.clone()))
                    .await;

                // Track if it's a GM
                if current_snapshot.is_bmca_winner
                    && let Some(domain) = current_snapshot.domain_number {
                        domain_gms.insert(domain, clock_id);
                    }
            }

            previous_states.insert(clock_id, current_snapshot);
        }

        Ok(())
    }

    /// Emit an event to all subscribers
    async fn emit_event(&self, event: PtpEvent) {
        let subscribers = self.event_subscribers.read().await;
        let mut dead_subscribers = Vec::new();

        for (idx, subscriber) in subscribers.iter().enumerate() {
            if subscriber.send(event.clone()).await.is_err() {
                dead_subscribers.push(idx);
            }
        }

        // Clean up dead subscribers
        if !dead_subscribers.is_empty() {
            drop(subscribers);
            let mut subscribers = self.event_subscribers.write().await;
            for idx in dead_subscribers.iter().rev() {
                subscribers.remove(*idx);
            }
        }
    }
}

#[async_trait]
impl PtpService for PtpServiceImpl {
    async fn get_hosts(&self) -> Result<Vec<crate::ptp::PtpHost>> {
        let tracker = self.tracker.read().await;
        Ok(tracker.get_hosts().into_iter().cloned().collect())
    }

    async fn get_host_by_id(
        &self,
        clock_identity: &ClockIdentity,
    ) -> Result<Option<crate::ptp::PtpHost>> {
        let tracker = self.tracker.read().await;
        Ok(tracker.get_host_by_clock_identity(clock_identity).cloned())
    }

    async fn get_packet_history(
        &self,
        clock_identity: &ClockIdentity,
    ) -> Result<Vec<ParsedPacket>> {
        let tracker = self.tracker.read().await;
        Ok(tracker
            .get_host_packet_history(*clock_identity)
            .unwrap_or_default())
    }

    async fn get_statistics(&self) -> Result<PtpStatistics> {
        let tracker = self.tracker.read().await;
        let hosts = tracker.get_hosts();

        // Get system hostname
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string());

        // Get monitored interfaces from tracker
        let interfaces: Vec<String> = tracker
            .raw_socket_receiver
            .get_interfaces()
            .iter()
            .map(|(name, _, _)| name.clone())
            .collect();

        // Get version
        let version = crate::version::get_version().to_string();

        Ok(PtpStatistics {
            total_hosts: hosts.len(),
            transmitter_count: tracker.get_transmitter_count(),
            receiver_count: tracker.get_receiver_count(),
            listening_count: hosts
                .iter()
                .filter(|h| matches!(h.state, crate::ptp::PtpHostState::Listening))
                .count(),
            last_packet_age_ms: tracker.get_last_packet_age().as_millis() as u64,
            total_packets: hosts
                .iter()
                .map(|h| h.total_messages_sent_count as u64)
                .sum(),
            hostname,
            interfaces,
            version,
            local_ips: tracker.get_local_ips(),
            last_packet_timestamp: tracker.raw_socket_receiver.get_last_timestamp(),
        })
    }

    async fn subscribe_to_events(&self) -> Result<mpsc::Receiver<PtpEvent>> {
        let (tx, rx) = mpsc::channel(1000);
        let mut subscribers = self.event_subscribers.write().await;
        subscribers.push(tx);
        Ok(rx)
    }

    async fn clear_hosts(&self) -> Result<()> {
        let mut tracker = self.tracker.write().await;
        tracker.clear_hosts();
        let mut previous_states = self.previous_states.write().await;
        previous_states.clear();
        let mut domain_gms = self.domain_grandmasters.write().await;
        domain_gms.clear();
        Ok(())
    }

    async fn clear_host_packet_history(&self, clock_identity: &ClockIdentity) -> Result<()> {
        let mut tracker = self.tracker.write().await;
        tracker.clear_host_packet_history(*clock_identity);
        Ok(())
    }

    async fn clear_all_packet_histories(&self) -> Result<()> {
        let mut tracker = self.tracker.write().await;
        tracker.clear_all_packet_histories();
        Ok(())
    }

    async fn set_max_packet_history(&self, max_history: usize) -> Result<()> {
        let mut tracker = self.tracker.write().await;
        tracker.set_max_packet_history(max_history);
        Ok(())
    }
}
