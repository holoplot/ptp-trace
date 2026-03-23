//! Anomaly detection for PTP monitoring

use crate::service::events::PtpEvent;
use crate::types::{ClockIdentity, PtpClockAccuracy, PtpClockClass};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Represents a detected anomaly
#[derive(Debug, Clone)]
pub enum Anomaly {
    GrandmasterChanged {
        domain: u8,
        old_gm: Option<ClockIdentity>,
        new_gm: ClockIdentity,
    },
    DomainChanged {
        host: ClockIdentity,
        old_domain: u8,
        new_domain: u8,
    },
    ClockQualityDegraded {
        host: ClockIdentity,
        old_class: PtpClockClass,
        new_class: PtpClockClass,
        old_accuracy: PtpClockAccuracy,
        new_accuracy: PtpClockAccuracy,
    },
    HostTimeout {
        host: ClockIdentity,
        last_seen_ago_secs: u64,
    },
    InterfaceLinkDown {
        interface: String,
    },
    InterfaceAddressLost {
        interface: String,
        removed: Vec<std::net::IpAddr>,
    },
}

/// Anomaly detector that tracks PTP events and identifies anomalies
pub struct AnomalyDetector {
    last_grandmasters: HashMap<u8, ClockIdentity>,
    last_clock_qualities: HashMap<ClockIdentity, (PtpClockClass, PtpClockAccuracy)>,
    last_host_seen: HashMap<ClockIdentity, Instant>,
    timeout_threshold: Duration,
}

impl AnomalyDetector {
    /// Create a new anomaly detector
    pub fn new() -> Self {
        Self {
            last_grandmasters: HashMap::new(),
            last_clock_qualities: HashMap::new(),
            last_host_seen: HashMap::new(),
            timeout_threshold: Duration::from_secs(60),
        }
    }

    /// Set the timeout threshold for host timeouts
    pub fn set_timeout_threshold(&mut self, threshold: Duration) {
        self.timeout_threshold = threshold;
    }

    /// Check an event for anomalies
    pub fn check_event(&mut self, event: &PtpEvent) -> Option<Anomaly> {
        match event {
            PtpEvent::GrandmasterChange {
                domain,
                old_gm,
                new_gm,
            } => {
                // Always report GM changes as anomalies
                let anomaly = Some(Anomaly::GrandmasterChanged {
                    domain: *domain,
                    old_gm: *old_gm,
                    new_gm: *new_gm,
                });
                self.last_grandmasters.insert(*domain, *new_gm);
                anomaly
            }

            PtpEvent::DomainChange {
                clock_identity,
                old_domain,
                new_domain,
            } => {
                // Domain changes are anomalies
                Some(Anomaly::DomainChanged {
                    host: *clock_identity,
                    old_domain: *old_domain,
                    new_domain: *new_domain,
                })
            }

            PtpEvent::ClockQualityDegraded {
                clock_identity,
                old_class,
                new_class,
                old_accuracy,
                new_accuracy,
            } => {
                // Clock quality degradation is an anomaly
                let anomaly = Some(Anomaly::ClockQualityDegraded {
                    host: *clock_identity,
                    old_class: *old_class,
                    new_class: *new_class,
                    old_accuracy: *old_accuracy,
                    new_accuracy: *new_accuracy,
                });
                self.last_clock_qualities
                    .insert(*clock_identity, (*new_class, *new_accuracy));
                anomaly
            }

            PtpEvent::HostTimeout {
                clock_identity,
                last_seen_ago_secs,
            } => {
                // Host timeouts are anomalies
                Some(Anomaly::HostTimeout {
                    host: *clock_identity,
                    last_seen_ago_secs: *last_seen_ago_secs,
                })
            }

            PtpEvent::InterfaceLinkChange {
                interface,
                link_up,
            } => {
                if !link_up {
                    // Link down is an anomaly
                    Some(Anomaly::InterfaceLinkDown {
                        interface: interface.clone(),
                    })
                } else {
                    // Link up is informational, not an anomaly
                    None
                }
            }

            PtpEvent::InterfaceAddressChange {
                interface,
                added: _,
                removed,
            } => {
                if !removed.is_empty() {
                    // Address removal is an anomaly
                    Some(Anomaly::InterfaceAddressLost {
                        interface: interface.clone(),
                        removed: removed.clone(),
                    })
                } else {
                    // Address addition is informational, not an anomaly
                    None
                }
            }

            PtpEvent::HostDiscovered(host) => {
                // Update last seen time
                self.last_host_seen
                    .insert(host.clock_identity, Instant::now());
                None // Not an anomaly
            }

            PtpEvent::HostUpdated { host, .. } => {
                // Update last seen time
                self.last_host_seen
                    .insert(host.clock_identity, Instant::now());
                None // Not an anomaly
            }

            PtpEvent::PacketReceived(packet) => {
                // Update last seen time
                let clock_id = packet.ptp.header().source_port_identity.clock_identity;
                self.last_host_seen.insert(clock_id, Instant::now());
                None // Not an anomaly
            }
        }
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}
