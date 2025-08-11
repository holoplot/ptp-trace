use crate::oui_map::lookup_vendor_bytes;
use anyhow::Result;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;

const MAX_PACKET_SIZE: usize = 1024;

#[derive(Debug, Clone)]
pub struct PtpHost {
    pub clock_identity: String,
    pub ip_address: IpAddr,
    pub port: u16,
    pub domain_number: u8,
    pub priority1: u8,
    pub priority2: u8,
    pub clock_class: u8,
    pub clock_accuracy: u8,
    pub offset_scaled_log_variance: u16,
    pub steps_removed: u16,
    pub time_source: u8,
    pub grandleader_identity: String,
    pub grandleader_priority1: u8,
    pub grandleader_priority2: u8,
    pub grandleader_clock_class: u8,
    pub grandleader_clock_accuracy: u8,
    pub grandleader_offset_scaled_log_variance: u16,
    pub last_seen: Instant,
    pub announce_count: u32,
    pub sync_count: u32,
    pub delay_req_count: u32,
    pub delay_resp_count: u32,

    pub state: PtpState,
    pub mean_path_delay: Option<Duration>,
    pub offset_from_leader: Option<Duration>,
    pub selected_leader_id: Option<String>,
    pub selected_leader_confidence: f32, // 0.0 to 1.0 confidence score
    pub last_sync_timestamp: Option<Instant>,
    pub current_utc_offset: Option<i16>,
    pub last_origin_timestamp: Option<[u8; 10]>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PtpState {
    Initializing,
    Listening,
    PreLeader,
    Leader,
    Passive,
    Uncalibrated,
    Follower,
    Faulty,
    Disabled,
    Unknown,
}

impl Default for PtpState {
    fn default() -> Self {
        PtpState::Unknown
    }
}

impl std::fmt::Display for PtpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PtpState::Initializing => write!(f, "INIT"),
            PtpState::Listening => write!(f, "LSTN"),
            PtpState::PreLeader => write!(f, "PREL"),
            PtpState::Leader => write!(f, "LEAD"),
            PtpState::Passive => write!(f, "PASV"),
            PtpState::Uncalibrated => write!(f, "UNCL"),
            PtpState::Follower => write!(f, "FOLL"),
            PtpState::Faulty => write!(f, "FALT"),
            PtpState::Disabled => write!(f, "DSBL"),
            PtpState::Unknown => write!(f, "UNKN"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PtpMessageType {
    Sync = 0x0,
    DelayReq = 0x1,
    PDelayReq = 0x2,
    PDelayResp = 0x3,
    FollowUp = 0x8,
    DelayResp = 0x9,
    PDelayRespFollowUp = 0xa,
    Announce = 0xb,
    Signaling = 0xc,
    Management = 0xd,
}

impl TryFrom<u8> for PtpMessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x0 => Ok(PtpMessageType::Sync),
            0x1 => Ok(PtpMessageType::DelayReq),
            0x2 => Ok(PtpMessageType::PDelayReq),
            0x3 => Ok(PtpMessageType::PDelayResp),
            0x8 => Ok(PtpMessageType::FollowUp),
            0x9 => Ok(PtpMessageType::DelayResp),
            0xa => Ok(PtpMessageType::PDelayRespFollowUp),
            0xb => Ok(PtpMessageType::Announce),
            0xc => Ok(PtpMessageType::Signaling),
            0xd => Ok(PtpMessageType::Management),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PtpHeader {
    pub message_type: PtpMessageType,
    pub version: u8,
    pub message_length: u16,
    pub domain_number: u8,
    pub flags: [u8; 2],
    pub correction_field: i64,
    pub source_port_identity: [u8; 10],
    pub sequence_id: u16,
    pub control_field: u8,
    pub log_message_interval: i8,
}

#[derive(Debug, Clone)]
pub struct AnnounceMessage {
    pub header: PtpHeader,
    pub origin_timestamp: [u8; 10],
    pub current_utc_offset: i16,
    pub grandmaster_priority_1: u8,
    pub grandmaster_clock_quality: [u8; 4],
    pub grandmaster_priority_2: u8,
    pub grandmaster_identity: [u8; 8],
    pub steps_removed: u16,
    pub time_source: u8,
}

impl PtpHost {
    pub fn new(clock_identity: String, ip_address: IpAddr, port: u16) -> Self {
        let now = Instant::now();
        Self {
            clock_identity,
            ip_address,
            port,
            domain_number: 0,
            priority1: 128,
            priority2: 128,
            clock_class: 248,
            clock_accuracy: 0xFE,
            offset_scaled_log_variance: 0xFFFF,
            steps_removed: 0, // Initialize as potential leader
            time_source: 0xA0,
            grandleader_identity: "00:00:00:00:00:00:00:00".to_string(),
            grandleader_priority1: 128,
            grandleader_priority2: 128,
            grandleader_clock_class: 248,
            grandleader_clock_accuracy: 0xFE,
            grandleader_offset_scaled_log_variance: 0xFFFF,
            last_seen: now,
            announce_count: 0,
            sync_count: 0,
            delay_req_count: 0,
            delay_resp_count: 0,

            state: PtpState::Listening,
            mean_path_delay: None,
            offset_from_leader: None,
            selected_leader_id: None,
            selected_leader_confidence: 0.0,
            last_sync_timestamp: None,
            current_utc_offset: None,
            last_origin_timestamp: None,
        }
    }

    pub fn update_last_seen(&mut self) {
        self.last_seen = Instant::now();
    }

    pub fn is_leader(&self) -> bool {
        matches!(self.state, PtpState::Leader)
    }

    pub fn is_follower(&self) -> bool {
        matches!(self.state, PtpState::Follower)
    }

    pub fn get_vendor_name(&self) -> Option<&'static str> {
        get_vendor_by_clock_identity(&self.clock_identity)
    }

    pub fn time_since_last_seen(&self) -> Duration {
        Instant::now().duration_since(self.last_seen)
    }

    pub fn quality_indicator(&self) -> u8 {
        // Simple quality calculation based on clock class and steps removed
        let base_quality: u8 = match self.clock_class {
            0..=6 => 100,
            7..=51 => 90,
            52..=127 => 80,
            128..=187 => 70,
            188..=247 => 60,
            248 => 50,
            249..=250 => 40,
            251 => 30,
            252 => 20,
            253 => 10,
            _ => 0,
        };
        base_quality.saturating_sub((self.steps_removed as u8).saturating_mul(5))
    }

    fn update_from_announce(&mut self, announce: &AnnounceMessage) {
        self.domain_number = announce.header.domain_number;
        self.priority1 = announce.grandmaster_priority_1;
        self.priority2 = announce.grandmaster_priority_2;
        self.clock_class = announce.grandmaster_clock_quality[0];
        self.clock_accuracy = announce.grandmaster_clock_quality[1];
        self.offset_scaled_log_variance = u16::from_be_bytes([
            announce.grandmaster_clock_quality[2],
            announce.grandmaster_clock_quality[3],
        ]);
        self.steps_removed = announce.steps_removed;
        self.time_source = announce.time_source;

        self.grandleader_identity = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            announce.grandmaster_identity[0],
            announce.grandmaster_identity[1],
            announce.grandmaster_identity[2],
            announce.grandmaster_identity[3],
            announce.grandmaster_identity[4],
            announce.grandmaster_identity[5],
            announce.grandmaster_identity[6],
            announce.grandmaster_identity[7]
        );
        self.grandleader_priority1 = announce.grandmaster_priority_1;
        self.grandleader_priority2 = announce.grandmaster_priority_2;
        self.grandleader_clock_class = announce.grandmaster_clock_quality[0];
        self.grandleader_clock_accuracy = announce.grandmaster_clock_quality[1];
        self.grandleader_offset_scaled_log_variance = u16::from_be_bytes([
            announce.grandmaster_clock_quality[2],
            announce.grandmaster_clock_quality[3],
        ]);

        // Store UTC offset and origin timestamp
        self.current_utc_offset = Some(announce.current_utc_offset);
        self.last_origin_timestamp = Some(announce.origin_timestamp);

        // Determine state based on PTP hierarchy info
        // Key insight: Compare the announcing device's clock identity with the grandmaster it claims
        let _is_self_grandmaster = self.clock_identity == self.grandleader_identity;

        // Set state and selected leader based on announce content
        if self.steps_removed == 0 {
            // This device claims to be the grandmaster
            self.state = PtpState::Leader;
            self.selected_leader_id = None; // Leaders don't follow anyone
        } else {
            // This device is following the announced grandmaster
            // Only set selected leader from announce if we don't already have it from sync traffic
            if self.selected_leader_id.is_none()
                && self.grandleader_identity != "00:00:00:00:00:00:00:00"
                && !self.grandleader_identity.is_empty()
            {
                self.selected_leader_id = Some(self.grandleader_identity.clone());
                self.selected_leader_confidence = 0.7; // Good confidence from announce
            }

            if self.steps_removed == 1 {
                self.state = PtpState::Follower;
            } else {
                self.state = PtpState::Passive;
            }
        }

        self.announce_count += 1;
    }

    /// Format the PTP origin timestamp as a human-readable string
    pub fn format_origin_timestamp(&self) -> String {
        match &self.last_origin_timestamp {
            Some(timestamp) => {
                // PTP timestamp is 10 bytes: 6 bytes seconds + 4 bytes nanoseconds
                let seconds = u64::from_be_bytes([
                    0,
                    0,
                    timestamp[0],
                    timestamp[1],
                    timestamp[2],
                    timestamp[3],
                    timestamp[4],
                    timestamp[5],
                ]);
                let nanoseconds =
                    u32::from_be_bytes([timestamp[6], timestamp[7], timestamp[8], timestamp[9]]);

                // PTP epoch starts at January 1, 1900 00:00:00 UTC
                // Unix epoch starts at January 1, 1970 00:00:00 UTC
                // Difference is 70 years = 2,208,988,800 seconds
                const PTP_TO_UNIX_EPOCH_OFFSET: u64 = 2_208_988_800;

                if seconds >= PTP_TO_UNIX_EPOCH_OFFSET {
                    let unix_seconds = seconds - PTP_TO_UNIX_EPOCH_OFFSET;
                    // Format as readable datetime if it's a reasonable Unix timestamp
                    if unix_seconds < 4_000_000_000 {
                        // Reasonable timestamp range (before year 2096)
                        format!("{}.{:06}s", unix_seconds, nanoseconds / 1000)
                    } else {
                        format!("{}.{:06}s", unix_seconds, nanoseconds / 1000)
                    }
                } else {
                    format!("PTP:{}.{:06}s", seconds, nanoseconds / 1000)
                }
            }
            None => "N/A".to_string(),
        }
    }

    /// Format the current UTC offset as a human-readable string
    pub fn format_utc_offset(&self) -> String {
        match self.current_utc_offset {
            Some(offset) => {
                if offset >= 0 {
                    format!("+{}s", offset)
                } else {
                    format!("{}s", offset)
                }
            }
            None => "N/A".to_string(),
        }
    }
}

/// Extract vendor name from clock identity string using OUI lookup
pub fn get_vendor_by_clock_identity(clock_identity: &str) -> Option<&'static str> {
    // Extract first 6 bytes from clock identity
    // Clock identity format: "xx:xx:xx:xx:xx:xx:xx:xx"
    let parts: Vec<&str> = clock_identity.split(':').collect();
    if parts.len() != 8 {
        return None;
    }

    let mut bytes = [0u8; 6];
    // Extract first 3 octets (0, 1, 2)
    for (i, part) in parts.iter().take(3).enumerate() {
        if let Ok(byte) = u8::from_str_radix(part, 16) {
            bytes[i] = byte;
        } else {
            return None;
        }
    }
    // Extract last 3 octets (5, 6, 7) and place them at positions 3, 4, 5
    for (i, part) in parts.iter().skip(5).take(3).enumerate() {
        if let Ok(byte) = u8::from_str_radix(part, 16) {
            bytes[i + 3] = byte;
        } else {
            return None;
        }
    }

    lookup_vendor_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oui_vendor_lookup() {
        // Test Cisco OUI-24 (00:00:0c)
        assert_eq!(
            get_vendor_by_clock_identity("00:00:0c:11:22:33:44:55"),
            Some("Cisco Systems, Inc")
        );

        // Test a known vendor from the map
        let result = get_vendor_by_clock_identity("00:1b:c5:00:01:23:44:55");
        assert!(result.is_some(), "Should find a vendor for this OUI");

        // Test unknown OUI
        assert_eq!(
            get_vendor_by_clock_identity("ff:ff:ff:11:22:33:44:55"),
            None
        );

        // Test invalid format
        assert_eq!(get_vendor_by_clock_identity("invalid"), None);

        // Test short format
        assert_eq!(get_vendor_by_clock_identity("00:00"), None);
    }
}

pub struct PtpTracker {
    hosts: HashMap<String, PtpHost>,
    last_packet: Instant,
    event_socket: UdpSocket,
    general_socket: UdpSocket,
    // Track recent sync/follow-up senders per domain for master-slave correlation
    recent_sync_senders: HashMap<u8, Vec<(String, Instant)>>,
    // Track interfaces for determining inbound interface of packets
    interfaces: Vec<(String, std::net::Ipv4Addr)>,
}

#[derive(Debug, Clone)]
pub struct ProcessedPacket {
    pub timestamp: std::time::Instant,
    pub source_ip: std::net::IpAddr,
    pub source_port: u16,
    pub interface: String,
    pub message_type: PtpMessageType,
    pub message_length: u16,
    pub clock_identity: String,
    pub domain_number: u8,
    pub sequence_id: u16,
    pub flags: [u8; 2],
    pub log_message_interval: i8,
}

impl PtpTracker {
    pub fn new(
        event_socket: UdpSocket,
        general_socket: UdpSocket,
        interfaces: Vec<(String, std::net::Ipv4Addr)>,
    ) -> Result<Self> {
        Ok(Self {
            hosts: HashMap::new(),
            last_packet: Instant::now(),
            event_socket,
            general_socket,
            recent_sync_senders: HashMap::new(),
            interfaces,
        })
    }

    pub async fn scan_network(&mut self) -> Result<Vec<ProcessedPacket>> {
        // Process PTP messages and collect packet info
        let packets = self.process_ptp_messages().await?;
        self.cleanup_old_sync_senders();
        self.last_packet = Instant::now();
        Ok(packets)
    }

    async fn process_ptp_messages(&mut self) -> Result<Vec<ProcessedPacket>> {
        let mut buffer = [0u8; MAX_PACKET_SIZE];
        let mut packets_to_process = Vec::new();

        // Collect packets from both sockets first to avoid borrowing issues
        {
            // Check event socket (port 319)
            let event_socket = &self.event_socket;
            for _ in 0..50 {
                // Limit iterations to prevent blocking too long
                match event_socket.try_recv_from(&mut buffer) {
                    Ok((len, src_addr)) => {
                        packets_to_process.push((buffer[..len].to_vec(), src_addr, 319));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // No more messages available
                        break;
                    }
                    Err(e) => {
                        eprintln!("Error receiving PTP packet from event socket: {}", e);
                        break;
                    }
                }
            }

            // Check general socket (port 320)
            let general_socket = &self.general_socket;
            for _ in 0..50 {
                // Limit iterations to prevent blocking too long
                match general_socket.try_recv_from(&mut buffer) {
                    Ok((len, src_addr)) => {
                        packets_to_process.push((buffer[..len].to_vec(), src_addr, 320));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // No more messages available
                        break;
                    }
                    Err(e) => {
                        eprintln!("Error receiving PTP packet from general socket: {}", e);
                        break;
                    }
                }
            }
        }

        let mut processed_packets = Vec::new();

        // Now process collected packets
        for (packet_data, src_addr, port) in packets_to_process {
            match self.handle_ptp_packet(&packet_data, src_addr, port).await {
                Ok(Some(packet_info)) => {
                    processed_packets.push(packet_info);
                }
                Ok(None) => {
                    // Packet was processed but not recorded (invalid/filtered)
                }
                Err(e) => {
                    eprintln!(
                        "Error processing PTP packet from {} on port {}: {}",
                        src_addr, port, e
                    );
                }
            }
        }

        Ok(processed_packets)
    }

    async fn handle_ptp_packet(
        &mut self,
        data: &[u8],
        src_addr: SocketAddr,
        src_port: u16,
    ) -> Result<Option<ProcessedPacket>> {
        // Basic PTP packet validation
        if data.len() < 34 {
            return Ok(None); // Packet too small to be valid PTP
        }

        // Check PTP version (should be 2)
        if (data[1] & 0x0f) != 2 {
            return Ok(None); // Not PTPv2
        }

        // Parse PTP header
        let header = match self.parse_ptp_header(data) {
            Ok(h) => h,
            Err(_) => return Ok(None), // Invalid header
        };

        // Extract clock identity from source port identity (bytes 20-27)
        let clock_id = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            header.source_port_identity[0],
            header.source_port_identity[1],
            header.source_port_identity[2],
            header.source_port_identity[3],
            header.source_port_identity[4],
            header.source_port_identity[5],
            header.source_port_identity[6],
            header.source_port_identity[7]
        );

        // Determine inbound interface
        let interface = crate::socket::get_interface_for_ip(&src_addr.ip(), &self.interfaces)
            .unwrap_or_else(|| "unknown".to_string());

        // Create packet info for recording
        let packet_info = ProcessedPacket {
            timestamp: std::time::Instant::now(),
            source_ip: src_addr.ip(),
            source_port: src_port,
            interface,
            message_type: header.message_type,
            message_length: header.message_length,
            clock_identity: clock_id.clone(),
            domain_number: header.domain_number,
            sequence_id: header.sequence_id,
            flags: header.flags,
            log_message_interval: header.log_message_interval,
        };

        // Parse announce message first if needed to avoid borrowing conflicts
        let announce_msg = if header.message_type == PtpMessageType::Announce {
            self.parse_announce_message(data).ok()
        } else {
            None
        };

        // Get or create host entry
        let host = self
            .hosts
            .entry(clock_id.clone())
            .or_insert_with(|| PtpHost::new(clock_id.clone(), src_addr.ip(), src_addr.port()));

        // Update last seen
        host.update_last_seen();
        host.domain_number = header.domain_number;

        // Set initial state to listening if still unknown and no announce messages received
        if host.state == PtpState::Unknown && host.announce_count == 0 {
            host.state = PtpState::Listening;
        }

        // Process message based on type
        match header.message_type {
            PtpMessageType::Announce => {
                host.announce_count += 1;
                if let Some(announce) = announce_msg {
                    host.update_from_announce(&announce);
                }
            }
            PtpMessageType::Sync => {
                host.sync_count += 1;
                host.last_sync_timestamp = Some(std::time::Instant::now());

                // Record this as a recent sync sender for this domain
                let domain_senders = self
                    .recent_sync_senders
                    .entry(header.domain_number)
                    .or_insert_with(Vec::new);
                let now = std::time::Instant::now();

                // Add or update this sender
                if let Some(existing) = domain_senders.iter_mut().find(|(id, _)| id == &clock_id) {
                    existing.1 = now;
                } else {
                    domain_senders.push((clock_id.clone(), now));
                }

                // Keep only recent senders (last 60 seconds)
                domain_senders.retain(|(_, timestamp)| {
                    now.duration_since(*timestamp) < Duration::from_secs(60)
                });

                // If we see sync messages but no announce messages, infer state
                if host.announce_count == 0 {
                    // Sync messages usually come from masters/leaders
                    host.state = PtpState::Leader;
                    host.selected_leader_id = None; // Leaders don't follow anyone
                }
            }
            PtpMessageType::DelayReq => {
                host.delay_req_count += 1;
                // Delay requests are sent by followers
                if host.announce_count == 0 {
                    host.state = PtpState::Follower;
                }

                // Find the most recent sync sender in this domain - this is the chosen master
                // Look for sync traffic within the last 10 seconds as it should be recent
                let now = std::time::Instant::now();
                if let Some(domain_senders) = self.recent_sync_senders.get(&header.domain_number) {
                    // Find the most recent sync sender that's still active (within last 10 seconds)
                    if let Some((master_id, _sync_time)) = domain_senders
                        .iter()
                        .filter(|(_, timestamp)| {
                            now.duration_since(*timestamp) < Duration::from_secs(10)
                        })
                        .max_by_key(|(_, timestamp)| *timestamp)
                    {
                        host.selected_leader_id = Some(master_id.clone());
                        host.selected_leader_confidence = 1.0; // High confidence - recent sync traffic
                    } else if let Some((master_id, _)) = domain_senders
                        .iter()
                        .max_by_key(|(_, timestamp)| *timestamp)
                    {
                        // Fall back to any recent sync sender even if slightly older
                        host.selected_leader_id = Some(master_id.clone());
                        host.selected_leader_confidence = 0.5; // Medium confidence - older sync traffic
                    } else if host.selected_leader_id.is_none() {
                        host.selected_leader_id = Some("No recent sync traffic".to_string());
                        host.selected_leader_confidence = 0.0;
                    }
                } else if host.selected_leader_id.is_none() {
                    host.selected_leader_id = Some("No sync traffic seen".to_string());
                    host.selected_leader_confidence = 0.0;
                }
            }
            PtpMessageType::DelayResp => {
                host.delay_resp_count += 1;

                // Delay responses are sent by masters/leaders
                if host.announce_count == 0 {
                    host.state = PtpState::Leader;
                    host.selected_leader_id = None; // Leaders don't follow anyone
                }
            }
            PtpMessageType::FollowUp => {
                // Record this as a recent sync sender for this domain (follow-up correlates with sync)
                let domain_senders = self
                    .recent_sync_senders
                    .entry(header.domain_number)
                    .or_insert_with(Vec::new);
                let now = std::time::Instant::now();

                // Add or update this sender
                if let Some(existing) = domain_senders.iter_mut().find(|(id, _)| id == &clock_id) {
                    existing.1 = now;
                } else {
                    domain_senders.push((clock_id.clone(), now));
                }

                // Keep only recent senders (last 60 seconds)
                domain_senders.retain(|(_, timestamp)| {
                    now.duration_since(*timestamp) < Duration::from_secs(60)
                });

                // Follow-up messages are sent by masters for two-step timing
                if host.announce_count == 0 {
                    host.state = PtpState::Leader;
                    host.selected_leader_id = None; // Leaders don't follow anyone
                }
            }
            _ => {

                // Handle other message types as needed
            }
        }

        Ok(Some(packet_info))
    }

    fn parse_ptp_header(&self, data: &[u8]) -> Result<PtpHeader> {
        if data.len() < 34 {
            return Err(anyhow::anyhow!("Packet too short for PTP header"));
        }

        let message_type = PtpMessageType::try_from(data[0] & 0x0f)
            .map_err(|_| anyhow::anyhow!("Unknown PTP message type"))?;

        let version = data[1] & 0x0f;
        let message_length = u16::from_be_bytes([data[2], data[3]]);
        let domain_number = data[4];
        let flags = [data[6], data[7]];

        // Parse correction field (64-bit signed integer)
        let correction_field = i64::from_be_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);

        // Source port identity (10 bytes: 8 for clock identity + 2 for port number)
        let mut source_port_identity = [0u8; 10];
        source_port_identity.copy_from_slice(&data[20..30]);

        let sequence_id = u16::from_be_bytes([data[30], data[31]]);
        let control_field = data[32];
        let log_message_interval = data[33] as i8;

        Ok(PtpHeader {
            message_type,
            version,
            message_length,
            domain_number,
            flags,
            correction_field,
            source_port_identity,
            sequence_id,
            control_field,
            log_message_interval,
        })
    }

    fn parse_announce_message(&self, data: &[u8]) -> Result<AnnounceMessage> {
        if data.len() < 64 {
            // 34 (header) + 30 (announce content) = 64 minimum
            return Err(anyhow::anyhow!("Packet too short for Announce message"));
        }

        let header = self.parse_ptp_header(data)?;

        // Parse announce-specific fields starting at byte 34
        let announce_data = &data[34..];

        if announce_data.len() < 30 {
            return Err(anyhow::anyhow!("Announce data too short"));
        }

        let mut origin_timestamp = [0u8; 10];
        origin_timestamp.copy_from_slice(&announce_data[0..10]);

        let current_utc_offset = i16::from_be_bytes([announce_data[10], announce_data[11]]);

        // Skip reserved byte at index 12
        let grandmaster_priority_1 = announce_data[13];

        let mut grandmaster_clock_quality = [0u8; 4];
        grandmaster_clock_quality.copy_from_slice(&announce_data[14..18]);

        let grandmaster_priority_2 = announce_data[18];

        let mut grandmaster_identity = [0u8; 8];
        grandmaster_identity.copy_from_slice(&announce_data[19..27]);

        let steps_removed = u16::from_be_bytes([announce_data[27], announce_data[28]]);
        let time_source = announce_data[29];

        Ok(AnnounceMessage {
            header,
            origin_timestamp,
            current_utc_offset,
            grandmaster_priority_1,
            grandmaster_clock_quality,
            grandmaster_priority_2,
            grandmaster_identity,
            steps_removed,
            time_source,
        })
    }

    fn cleanup_old_sync_senders(&mut self) {
        let now = std::time::Instant::now();
        let timeout = Duration::from_secs(60); // Keep sync senders for 60 seconds

        for (_, senders) in self.recent_sync_senders.iter_mut() {
            senders.retain(|(_, timestamp)| now.duration_since(*timestamp) < timeout);
        }

        // Remove domains with no recent senders
        self.recent_sync_senders
            .retain(|_, senders| !senders.is_empty());
    }

    pub fn get_hosts(&self) -> Vec<&PtpHost> {
        let mut hosts: Vec<&PtpHost> = self.hosts.values().collect();
        hosts.sort_by(|a, b| {
            // Sort by: Leader first, then by quality, then by clock identity
            match (a.is_leader(), b.is_leader()) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => match b.quality_indicator().cmp(&a.quality_indicator()) {
                    std::cmp::Ordering::Equal => a.clock_identity.cmp(&b.clock_identity),
                    other => other,
                },
            }
        });
        hosts
    }

    pub fn clear_hosts(&mut self) {
        self.hosts.clear();
    }

    pub fn get_leader_count(&self) -> usize {
        self.hosts.values().filter(|h| h.is_leader()).count()
    }

    pub fn get_follower_count(&self) -> usize {
        self.hosts.values().filter(|h| h.is_follower()).count()
    }

    pub fn get_last_packet_age(&self) -> Duration {
        Instant::now().duration_since(self.last_packet)
    }
}
