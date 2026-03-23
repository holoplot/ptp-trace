use crate::ptp::PtpHost;
use crate::types::{ClockIdentity, ParsedPacket, PtpClockAccuracy, PtpClockClass};
use std::net::IpAddr;

/// Events emitted by the PTP service for real-time monitoring
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum PtpEvent {
    /// A new PTP host was discovered on the network
    HostDiscovered(PtpHost),

    /// An existing host was updated
    HostUpdated {
        host: PtpHost,
        changes: Vec<ChangeType>,
    },

    /// A host has timed out (no packets received for timeout threshold)
    #[allow(dead_code)]
    HostTimeout {
        clock_identity: ClockIdentity,
        last_seen_ago_secs: u64,
    },

    /// A host changed PTP domain
    DomainChange {
        clock_identity: ClockIdentity,
        old_domain: u8,
        new_domain: u8,
    },

    /// The grandmaster changed in a domain (BMCA election result changed)
    GrandmasterChange {
        domain: u8,
        old_gm: Option<ClockIdentity>,
        new_gm: ClockIdentity,
    },

    /// Clock quality degraded
    #[allow(dead_code)]
    ClockQualityDegraded {
        clock_identity: ClockIdentity,
        old_class: PtpClockClass,
        new_class: PtpClockClass,
        old_accuracy: PtpClockAccuracy,
        new_accuracy: PtpClockAccuracy,
    },

    /// Network interface link state changed
    InterfaceLinkChange { interface: String, link_up: bool },

    /// Network interface IP addresses changed
    InterfaceAddressChange {
        interface: String,
        added: Vec<IpAddr>,
        removed: Vec<IpAddr>,
    },

    /// A PTP packet was received (for real-time streaming)
    PacketReceived(ParsedPacket),
}

/// Types of changes that can occur to a host
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ChangeType {
    IpAddress {
        added: Vec<String>,
        removed: Vec<String>,
    },
    Interface {
        added: Vec<String>,
        removed: Vec<String>,
    },
    #[allow(dead_code)]
    VlanId {
        old: Option<u16>,
        new: Option<u16>,
    },
    DomainNumber {
        old: Option<u8>,
        new: Option<u8>,
    },
    State {
        old: String,
        new: String,
    },
    ClockQuality {
        description: String,
    },
    #[allow(dead_code)]
    MessageCounts,
    SelectedTransmitter {
        old: Option<String>,
        new: Option<String>,
    },
}

impl ChangeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChangeType::IpAddress { .. } => "ip_address",
            ChangeType::Interface { .. } => "interface",
            ChangeType::VlanId { .. } => "vlan_id",
            ChangeType::DomainNumber { .. } => "domain_number",
            ChangeType::State { .. } => "state",
            ChangeType::ClockQuality { .. } => "clock_quality",
            ChangeType::MessageCounts => "message_counts",
            ChangeType::SelectedTransmitter { .. } => "selected_transmitter",
        }
    }

    #[allow(dead_code)]
    pub fn description(&self) -> String {
        match self {
            ChangeType::IpAddress { added, removed } => {
                let mut parts = Vec::new();
                if !added.is_empty() {
                    parts.push(format!("added=[{}]", added.join(", ")));
                }
                if !removed.is_empty() {
                    parts.push(format!("removed=[{}]", removed.join(", ")));
                }
                parts.join(" ")
            }
            ChangeType::Interface { added, removed } => {
                let mut parts = Vec::new();
                if !added.is_empty() {
                    parts.push(format!("added=[{}]", added.join(", ")));
                }
                if !removed.is_empty() {
                    parts.push(format!("removed=[{}]", removed.join(", ")));
                }
                parts.join(" ")
            }
            ChangeType::VlanId { old, new } => {
                format!(
                    "{} -> {}",
                    old.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string()),
                    new.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string())
                )
            }
            ChangeType::DomainNumber { old, new } => {
                format!(
                    "{} -> {}",
                    old.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string()),
                    new.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string())
                )
            }
            ChangeType::State { old, new } => {
                format!("{} -> {}", old, new)
            }
            ChangeType::ClockQuality { description } => description.clone(),
            ChangeType::MessageCounts => "updated".to_string(),
            ChangeType::SelectedTransmitter { old, new } => {
                format!(
                    "{} -> {}",
                    old.as_ref().map(|s| s.as_str()).unwrap_or("none"),
                    new.as_ref().map(|s| s.as_str()).unwrap_or("none")
                )
            }
        }
    }
}
