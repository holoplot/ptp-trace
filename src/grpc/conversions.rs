//! Type conversions between Rust types and protobuf types

use crate::grpc::proto;
use crate::ptp::{PtpHost, PtpHostState};
use crate::service::events::PtpEvent;
use crate::types::{ClockIdentity, ParsedPacket, PtpMessageType, PtpVersion};
use std::time::SystemTime;

/// Convert PtpVersion to protobuf enum
fn ptp_version_to_proto(version: PtpVersion) -> i32 {
    match version {
        PtpVersion::V1 => proto::PtpVersion::PtpVersion1 as i32,
        PtpVersion::V2 => proto::PtpVersion::PtpVersion2 as i32,
    }
}

/// Convert PtpMessageType to protobuf enum
fn ptp_message_type_to_proto(msg_type: PtpMessageType) -> i32 {
    match msg_type {
        PtpMessageType::Sync => proto::PtpMessageType::Sync as i32,
        PtpMessageType::DelayReq => proto::PtpMessageType::DelayReq as i32,
        PtpMessageType::PDelayReq => proto::PtpMessageType::PdelayReq as i32,
        PtpMessageType::PDelayResp => proto::PtpMessageType::PdelayResp as i32,
        PtpMessageType::FollowUp => proto::PtpMessageType::FollowUp as i32,
        PtpMessageType::DelayResp => proto::PtpMessageType::DelayResp as i32,
        PtpMessageType::PDelayRespFollowUp => proto::PtpMessageType::PdelayRespFollowUp as i32,
        PtpMessageType::Announce => proto::PtpMessageType::Announce as i32,
        PtpMessageType::Signaling => proto::PtpMessageType::Signaling as i32,
        PtpMessageType::Management => proto::PtpMessageType::Management as i32,
    }
}

impl From<&PtpHost> for proto::Host {
    fn from(host: &PtpHost) -> Self {
        let mut ip_addresses = Vec::new();
        for (ip, interfaces) in &host.ip_addresses {
            ip_addresses.push(proto::IpAddress {
                ip: ip.to_string(),
                interfaces: interfaces.clone(),
            });
        }

        let state = match &host.state {
            PtpHostState::Listening => proto::HostState {
                state_type: proto::host_state::StateType::Listening as i32,
                is_grandmaster: false,
                selected_transmitter: None,
            },
            PtpHostState::TimeTransmitter(s) => proto::HostState {
                state_type: proto::host_state::StateType::TimeTransmitter as i32,
                is_grandmaster: s.is_bmca_winner,
                selected_transmitter: None,
            },
            PtpHostState::TimeReceiver(s) => proto::HostState {
                state_type: proto::host_state::StateType::TimeReceiver as i32,
                is_grandmaster: false,
                selected_transmitter: s
                    .selected_transmitter_identity
                    .as_ref()
                    .map(|id| format!("{}", id)),
            },
        };

        let clock_quality = if let PtpHostState::TimeTransmitter(s) = &host.state {
            Some(proto::ClockQuality {
                clock_class: s.clock_class.map(|c| c.class() as u32).unwrap_or(0),
                clock_accuracy: s.clock_accuracy.map(|a| a.accuracy as u32).unwrap_or(0),
                offset_scaled_log_variance: s
                    .offset_scaled_log_variance
                    .map(|v| v as u32)
                    .unwrap_or(0),
                priority1: s.priority1.map(|p| p as u32),
                priority2: s.priority2.map(|p| p as u32),
                gm_identifier: s.gm_identifier.as_ref().map(|id| format!("{}", id)),
                steps_removed: s.steps_removed.map(|sr| sr as u32),
                last_sync_origin_timestamp: s.last_sync_origin_timestamp.map(|ts| ts.to_string()),
                last_followup_origin_timestamp: s
                    .last_followup_origin_timestamp
                    .map(|ts| ts.to_string()),
                current_utc_offset: s.current_utc_offset.map(|offset| offset.offset as i32),
            })
        } else {
            None
        };

        proto::Host {
            clock_identity: format!("{}", host.clock_identity),
            ip_addresses,
            interfaces: host.interfaces.iter().cloned().collect(),
            vlan_id: host.vlan_id.map(|v| v as u32),
            domain_number: host.domain_number.map(|d| d as u32),
            version: host.last_version.map(ptp_version_to_proto),
            vendor: host.get_vendor_name().map(|v| v.to_string()),
            announce_count: host.announce_count,
            sync_count: host.sync_count,
            follow_up_count: host.follow_up_count,
            delay_req_count: host.delay_req_count,
            delay_resp_count: host.delay_resp_count,
            pdelay_req_count: host.pdelay_req_count,
            pdelay_resp_count: host.pdelay_resp_count,
            pdelay_resp_follow_up_count: host.pdelay_resp_follow_up_count,
            total_messages_sent_count: host.total_messages_sent_count,
            total_messages_received_count: host.total_messages_received_count,
            signaling_message_count: host.signaling_message_count,
            management_message_count: host.management_message_count,
            state: Some(state),
            clock_quality,
            last_correction_field: host.last_correction_field.map(|cf| cf.to_string()),
        }
    }
}

impl From<&ParsedPacket> for proto::Packet {
    fn from(packet: &ParsedPacket) -> Self {
        let header = packet.ptp.header();

        // Convert message type from header enum
        let message_type = ptp_message_type_to_proto(header.message_type);

        // Convert version enum
        let version = ptp_version_to_proto(header.version);

        let timestamp_nanos = packet
            .raw
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        proto::Packet {
            message_type,
            source_clock_id: format!("{}", header.source_port_identity.clock_identity),
            domain_number: header.domain_number as u32,
            timestamp: timestamp_nanos.to_string(),
            source_ip: packet.raw.source_addr.map(|addr| addr.to_string()),
            interface: packet.raw.interface_name.clone(),
            vlan_id: packet.raw.vlan_id.map(|v| v as u32),
            sequence_id: header.sequence_id as u32,
            raw_payload: packet.raw.ptp_payload.clone(),
            raw_ethernet_frame: packet.raw.data.clone(),
            version,
            message_length: header.message_length as u32,
            flags: header.flags.short(),
            correction_field: header.correction_field.to_string(),
            log_message_interval: header.log_message_interval.exponent as i32,
        }
    }
}

impl From<&PtpEvent> for proto::HostEvent {
    fn from(event: &PtpEvent) -> Self {
        match event {
            PtpEvent::HostDiscovered(host) => proto::HostEvent {
                event_type: proto::host_event::EventType::Discovered as i32,
                host: Some(host.into()),
                changes: vec![],
            },
            PtpEvent::HostUpdated { host, changes } => proto::HostEvent {
                event_type: proto::host_event::EventType::Updated as i32,
                host: Some(host.into()),
                changes: changes.iter().map(|c| c.as_str().to_string()).collect(),
            },
            PtpEvent::HostTimeout {
                clock_identity,
                last_seen_ago_secs: _,
            } => {
                // Create a minimal host representation for timeout events
                let host = PtpHost::new(*clock_identity);
                proto::HostEvent {
                    event_type: proto::host_event::EventType::Timeout as i32,
                    host: Some((&host).into()),
                    changes: vec![],
                }
            }
            _ => {
                // For other events, we don't emit them as HostEvent
                // This is a fallback that shouldn't normally be used
                proto::HostEvent {
                    event_type: proto::host_event::EventType::Discovered as i32,
                    host: None,
                    changes: vec![],
                }
            }
        }
    }
}

/// Parse a clock identity from hex string format
pub fn parse_clock_identity(s: &str) -> Result<ClockIdentity, String> {
    // Expected format: "00:11:22:33:44:55:66:77" or "0011223344556677"
    let clean = s.replace(":", "").replace("-", "");

    if clean.len() != 16 {
        return Err(format!("Invalid clock identity length: {}", clean.len()));
    }

    let mut bytes = [0u8; 8];
    for i in 0..8 {
        bytes[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("Invalid hex digit: {}", e))?;
    }

    Ok(ClockIdentity { clock_id: bytes })
}
