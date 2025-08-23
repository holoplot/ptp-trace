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
    pub ip_addresses: HashMap<IpAddr, String>,
    pub port: u16,
    pub domain_number: u8,
    pub priority1: u8,
    pub priority2: u8,
    pub clock_class: u8,
    pub clock_accuracy: u8,
    pub offset_scaled_log_variance: u16,
    pub steps_removed: u16,
    pub time_source: u8,
    pub primary_transmitter_identity: String,
    pub primary_transmitter_priority1: u8,
    pub primary_transmitter_priority2: u8,
    pub primary_transmitter_clock_class: u8,
    pub primary_transmitter_clock_accuracy: u8,
    pub primary_transmitter_scaled_log_variance: u16,
    pub last_seen: Instant,
    pub announce_count: u32,
    pub sync_count: u32,
    pub delay_req_count: u32,
    pub delay_resp_count: u32,
    pub total_message_count: u32,

    pub state: PtpState,
    pub selected_transmitter_id: Option<String>,
    pub selected_transmitter_confidence: f32, // 0.0 to 1.0 confidence score
    pub last_sync_timestamp: Option<Instant>,
    pub current_utc_offset: Option<i16>,
    pub last_origin_timestamp: Option<[u8; 10]>,
    pub timestamp_source: Option<String>,
    pub announce_origin_timestamp: Option<[u8; 10]>,
    pub sync_origin_timestamp: Option<[u8; 10]>,
    pub followup_origin_timestamp: Option<[u8; 10]>,
    pub last_version: Option<u8>,
    pub last_correction_field: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PtpState {
    Initializing,
    Listening,
    PreTransmitter,
    Transmitter,
    Passive,
    Uncalibrated,
    Receiver,
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
            PtpState::Initializing => write!(f, "I"),
            PtpState::Listening => write!(f, "L"),
            PtpState::PreTransmitter => write!(f, "PL"),
            PtpState::Transmitter => write!(f, "T"),
            PtpState::Passive => write!(f, "P"),
            PtpState::Uncalibrated => write!(f, "U"),
            PtpState::Receiver => write!(f, "R"),
            PtpState::Faulty => write!(f, "F"),
            PtpState::Disabled => write!(f, "D"),
            PtpState::Unknown => write!(f, "?"),
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
    pub _control_field: u8,
    pub log_message_interval: i8,
}

#[derive(Debug, Clone)]
pub struct AnnounceMessage {
    pub header: PtpHeader,
    pub origin_timestamp: [u8; 10],
    pub current_utc_offset: i16,
    pub primary_transmitter_priority_1: u8,
    pub primary_transmitter_clock_quality: [u8; 4],
    pub primary_transmitter_priority_2: u8,
    pub primary_transmitter_identity: [u8; 8],
    pub steps_removed: u16,
    pub time_source: u8,
}

pub struct SyncMessage {
    pub _header: PtpHeader,
    pub origin_timestamp: [u8; 10],
}

pub struct FollowUpMessage {
    pub _header: PtpHeader,
    pub precise_origin_timestamp: [u8; 10],
}

impl PtpHost {
    pub fn new(clock_identity: String, ip_address: IpAddr, port: u16, interface: String) -> Self {
        let now = Instant::now();
        Self {
            clock_identity,
            ip_addresses: {
                let mut map = HashMap::new();
                map.insert(ip_address, interface);
                map
            },
            port,
            domain_number: 0,
            priority1: 128,
            priority2: 128,
            clock_class: 248,
            clock_accuracy: 0xFE,
            offset_scaled_log_variance: 0xFFFF,
            steps_removed: 0, // Initialize as potential transmitter
            time_source: 0xA0,
            primary_transmitter_identity: "00:00:00:00:00:00:00:00".to_string(),
            primary_transmitter_priority1: 128,
            primary_transmitter_priority2: 128,
            primary_transmitter_clock_class: 248,
            primary_transmitter_clock_accuracy: 0xFE,
            primary_transmitter_scaled_log_variance: 0xFFFF,
            last_seen: now,
            announce_count: 0,
            sync_count: 0,
            delay_req_count: 0,
            delay_resp_count: 0,
            total_message_count: 0,

            state: PtpState::Listening,
            selected_transmitter_id: None,
            selected_transmitter_confidence: 0.0,
            last_sync_timestamp: None,
            current_utc_offset: None,
            last_origin_timestamp: None,
            timestamp_source: None,
            announce_origin_timestamp: None,
            sync_origin_timestamp: None,
            followup_origin_timestamp: None,
            last_version: None,
            last_correction_field: None,
        }
    }

    pub fn update_last_seen(&mut self) {
        self.last_seen = Instant::now();
    }

    pub fn is_transmitter(&self) -> bool {
        matches!(self.state, PtpState::Transmitter)
    }

    pub fn is_receiver(&self) -> bool {
        matches!(self.state, PtpState::Receiver)
    }

    pub fn get_vendor_name(&self) -> Option<&'static str> {
        get_vendor_by_clock_identity(&self.clock_identity)
    }

    pub fn time_since_last_seen(&self) -> Duration {
        Instant::now().duration_since(self.last_seen)
    }

    pub fn add_ip_address(&mut self, ip: IpAddr, interface: String) {
        self.ip_addresses.insert(ip, interface);
    }

    pub fn get_primary_ip(&self) -> Option<&IpAddr> {
        self.ip_addresses.keys().next()
    }

    pub fn has_multiple_ips(&self) -> bool {
        self.ip_addresses.len() > 1
    }

    pub fn get_ip_count(&self) -> usize {
        self.ip_addresses.len()
    }

    pub fn update_version(&mut self, version: u8) {
        self.last_version = Some(version);
    }

    pub fn get_version_string(&self) -> String {
        match self.last_version {
            Some(version) => format!("v{}", version),
            None => "Unknown".to_string(),
        }
    }

    pub fn update_correction_field(&mut self, correction_field: i64) {
        if correction_field != 0 {
            self.last_correction_field = Some(correction_field);
        }
    }

    pub fn get_correction_field_string(&self) -> String {
        match self.last_correction_field {
            Some(correction) => correction.to_string(),
            None => "Unknown".to_string(),
        }
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
        self.priority1 = announce.primary_transmitter_priority_1;
        self.priority2 = announce.primary_transmitter_priority_2;
        self.clock_class = announce.primary_transmitter_clock_quality[0];
        self.clock_accuracy = announce.primary_transmitter_clock_quality[1];
        self.offset_scaled_log_variance = u16::from_be_bytes([
            announce.primary_transmitter_clock_quality[2],
            announce.primary_transmitter_clock_quality[3],
        ]);
        self.steps_removed = announce.steps_removed;
        self.time_source = announce.time_source;

        self.primary_transmitter_identity = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            announce.primary_transmitter_identity[0],
            announce.primary_transmitter_identity[1],
            announce.primary_transmitter_identity[2],
            announce.primary_transmitter_identity[3],
            announce.primary_transmitter_identity[4],
            announce.primary_transmitter_identity[5],
            announce.primary_transmitter_identity[6],
            announce.primary_transmitter_identity[7]
        );
        self.primary_transmitter_priority1 = announce.primary_transmitter_priority_1;
        self.primary_transmitter_priority2 = announce.primary_transmitter_priority_2;
        self.primary_transmitter_clock_class = announce.primary_transmitter_clock_quality[0];
        self.primary_transmitter_clock_accuracy = announce.primary_transmitter_clock_quality[1];
        self.primary_transmitter_scaled_log_variance = u16::from_be_bytes([
            announce.primary_transmitter_clock_quality[2],
            announce.primary_transmitter_clock_quality[3],
        ]);

        // Store UTC offset and origin timestamp
        self.current_utc_offset = Some(announce.current_utc_offset);
        self.last_origin_timestamp = Some(announce.origin_timestamp);

        // Determine state based on PTP hierarchy info
        // Key insight: Compare the announcing device's clock identity with the primary transmitter it claims
        let _is_self_primary_transmitter = self.clock_identity == self.primary_transmitter_identity;

        // Set state and selected transmitter based on announce content
        if self.steps_removed == 0 {
            // This device claims to be the primary transmitter
            self.state = PtpState::Transmitter;
            self.selected_transmitter_id = None; // Transmitters don't receive from anyone
        } else {
            // This device is following the announced primary transmitter
            // Only set selected transmitter from announce if we don't already have it from sync traffic
            if self.selected_transmitter_id.is_none()
                && self.primary_transmitter_identity != "00:00:00:00:00:00:00:00"
                && !self.primary_transmitter_identity.is_empty()
            {
                self.selected_transmitter_id = Some(self.primary_transmitter_identity.clone());
                self.selected_transmitter_confidence = 0.7; // Good confidence from announce
            }

            if self.steps_removed == 1 {
                self.state = PtpState::Receiver;
            } else {
                self.state = PtpState::Passive;
            }
        }

        self.announce_count += 1;
        self.total_message_count += 1;
        self.announce_origin_timestamp = Some(announce.origin_timestamp);
        self.last_origin_timestamp = Some(announce.origin_timestamp);
        self.timestamp_source = Some("Announce".to_string());
    }

    /// Format a PTP timestamp as YYYY:MM:DD:HH:MM:SS:nanos
    fn format_ptp_timestamp(timestamp: &[u8; 10]) -> String {
        use chrono::{DateTime, Datelike, Timelike};

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

        // PTP epoch: 1970-01-01 00:00:00 TAI (International Atomic Time)
        // Unix epoch: 1970-01-01 00:00:00 UTC (Coordinated Universal Time)
        //
        // TAI does not have leap seconds, UTC does
        // Relationship: UTC = TAI - (leap seconds offset)
        //
        // Current leap seconds offset (as of 2024): 37 seconds
        // This means TAI is 37 seconds ahead of UTC
        //
        // Note: This offset changes when leap seconds are added to UTC
        // Historical leap seconds:
        // - 1972-06-30: 1 second
        // - 1972-12-31: 1 second
        // - ... (many more)
        // - 2016-12-31: 1 second (total: 37 seconds as of 2024)

        const LEAP_SECONDS_OFFSET: u64 = 37; // TAI - UTC offset as of 2024

        // PTP timestamp is in TAI seconds since 1970-01-01
        // Convert to UTC seconds for display
        if seconds >= LEAP_SECONDS_OFFSET {
            let utc_seconds = seconds - LEAP_SECONDS_OFFSET;
            if utc_seconds < 4_000_000_000 {
                // Use chrono to convert UTC timestamp to datetime
                if let Some(dt) = DateTime::from_timestamp(utc_seconds as i64, nanoseconds) {
                    format!(
                        "{}-{:02}-{:02} {:02}:{:02}:{:02}.{:09}",
                        dt.year(),
                        dt.month(),
                        dt.day(),
                        dt.hour(),
                        dt.minute(),
                        dt.second(),
                        nanoseconds
                    )
                } else {
                    format!("UTC: {}.{:09}", utc_seconds, nanoseconds)
                }
            } else {
                format!("UTC: {}.{:09}", utc_seconds, nanoseconds)
            }
        } else {
            format!("TAI: {}.{:09}", seconds, nanoseconds)
        }
    }

    /// Format the announce origin timestamp
    pub fn format_announce_timestamp(&self) -> String {
        match &self.announce_origin_timestamp {
            Some(timestamp) => Self::format_ptp_timestamp(timestamp),
            None => "N/A".to_string(),
        }
    }

    /// Format the sync origin timestamp
    pub fn format_sync_timestamp(&self) -> String {
        match &self.sync_origin_timestamp {
            Some(timestamp) => Self::format_ptp_timestamp(timestamp),
            None => "N/A".to_string(),
        }
    }

    /// Format the follow-up origin timestamp
    pub fn format_followup_timestamp(&self) -> String {
        match &self.followup_origin_timestamp {
            Some(timestamp) => Self::format_ptp_timestamp(timestamp),
            None => "N/A".to_string(),
        }
    }

    /// Resolve clock class to human-readable description
    pub fn format_clock_class(&self) -> String {
        let description = match self.clock_class {
            0..=5 => "Reserved",
            6 => "Primary reference (GPS, atomic clock, etc.)",
            7 => "Primary reference (degraded)",
            8..=12 => "Reserved",
            13 => "Application specific",
            14 => "Application specific (degraded)",
            15..=51 => "Reserved",
            52 => "Class 7 (degraded A)",
            53..=57 => "Reserved",
            58 => "Class 14 (degraded A)",
            59..=67 => "Reserved",
            68..=122 => "Alternate PTP profile",
            123..=132 => "Reserved",
            133..=170 => "Alternate PTP profile",
            171..=186 => "Reserved",
            187 => "Class 7 (degraded B)",
            188..=192 => "Reserved",
            193 => "Class 14 (degraded B)",
            194..=215 => "Reserved",
            216..=232 => "Alternate PTP profile",
            233..=247 => "Reserved",
            248 => "Default, free-running",
            249..=254 => "Reserved",
            255 => "Follower-only",
        };
        format!("{} ({})", self.clock_class, description)
    }

    /// Resolve clock accuracy
    pub fn format_clock_accuracy(&self) -> String {
        let description = match self.clock_accuracy {
            0..=0x1f => "Reserved",
            0x20 => "25 ns",
            0x21 => "100 ns",
            0x22 => "250 ns",
            0x23 => "1 µs",
            0x24 => "2.5 µs",
            0x25 => "10 µs",
            0x26 => "25 µs",
            0x27 => "100 µs",
            0x28 => "250 µs",
            0x29 => "1 ms",
            0x2a => "2.5 ms",
            0x2b => "10 ms",
            0x2c => "25 ms",
            0x2d => "100 ms",
            0x2e => "250 ms",
            0x2f => "1 s",
            0x30 => "10 s",
            0x31 => "> 10 s",
            0x32..=0x7f => "Reserved",
            0x80..=0xfd => "Alternate PTP profile",
            0xfe => "Unknown",
            0xff => "Reserved",
        };
        format!("{} ({})", self.clock_accuracy, description)
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

    #[test]
    fn test_ptp_timestamp_formatting() {
        // Test a known timestamp: January 1, 2024 00:00:00 UTC
        // UTC timestamp: 1704067200 seconds since Unix epoch
        // PTP uses TAI: TAI = UTC + leap_seconds_offset
        // TAI timestamp: 1704067200 + 37 = 1704067237 seconds since PTP epoch (1970 TAI)
        let mut timestamp = [0u8; 10];

        // Set seconds (big-endian, 6 bytes) - this is TAI time
        let ptp_seconds: u64 = 1704067237;
        timestamp[0] = ((ptp_seconds >> 40) & 0xff) as u8;
        timestamp[1] = ((ptp_seconds >> 32) & 0xff) as u8;
        timestamp[2] = ((ptp_seconds >> 24) & 0xff) as u8;
        timestamp[3] = ((ptp_seconds >> 16) & 0xff) as u8;
        timestamp[4] = ((ptp_seconds >> 8) & 0xff) as u8;
        timestamp[5] = (ptp_seconds & 0xff) as u8;

        // Set nanoseconds (big-endian, 4 bytes) - 123456789 nanoseconds
        let nanos: u32 = 123456789;
        timestamp[6] = ((nanos >> 24) & 0xff) as u8;
        timestamp[7] = ((nanos >> 16) & 0xff) as u8;
        timestamp[8] = ((nanos >> 8) & 0xff) as u8;
        timestamp[9] = (nanos & 0xff) as u8;

        let formatted = PtpHost::format_ptp_timestamp(&timestamp);
        assert_eq!(formatted, "2024-01-01 00:00:00.123456789");
    }

    #[test]
    fn test_clock_class_formatting() {
        let mut host = PtpHost::new(
            "00:11:22:33:44:55:66:77".to_string(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            319,
            "eth0".to_string(),
        );

        // Test common clock class values
        host.clock_class = 6;
        assert_eq!(
            host.format_clock_class(),
            "6 (Primary reference (GPS, atomic clock, etc.))"
        );

        host.clock_class = 7;
        assert_eq!(
            host.format_clock_class(),
            "7 (Primary reference (degraded))"
        );

        host.clock_class = 248;
        assert_eq!(host.format_clock_class(), "248 (Default, free-running)");

        host.clock_class = 255;
        assert_eq!(host.format_clock_class(), "255 (Follower-only)");
    }

    #[test]
    fn test_priority_and_clock_class_fields() {
        let mut host = PtpHost::new(
            "00:11:22:33:44:55:66:77".to_string(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            319,
            "eth0".to_string(),
        );

        // Test default values
        assert_eq!(host.priority1, 128);
        assert_eq!(host.clock_class, 248);
        assert_eq!(host.total_message_count, 0);

        // Test setting custom values
        host.priority1 = 64;
        host.clock_class = 6;
        assert_eq!(host.priority1, 64);
        assert_eq!(host.clock_class, 6);

        // Test another set of values
        host.priority1 = 255;
        host.clock_class = 255;
        assert_eq!(host.priority1, 255);
        assert_eq!(host.clock_class, 255);

        // Test message count increment
        host.total_message_count += 1;
        assert_eq!(host.total_message_count, 1);
        host.total_message_count += 5;
        assert_eq!(host.total_message_count, 6);
    }

    #[test]
    fn test_multiple_ip_addresses() {
        use std::net::{IpAddr, Ipv4Addr};

        let mut host = PtpHost::new(
            "00:11:22:33:44:55:66:77".to_string(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            319,
            "eth0".to_string(),
        );

        // Initially should have one IP
        assert_eq!(host.get_ip_count(), 1);
        assert!(host.get_primary_ip().is_some());
        assert!(!host.has_multiple_ips());

        // Add a second IP with interface
        host.add_ip_address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)), "eth1".to_string());
        assert_eq!(host.get_ip_count(), 2);
        assert!(host.has_multiple_ips());

        // Adding the same IP again should update the interface
        host.add_ip_address(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            "eth0".to_string(),
        );
        assert_eq!(host.get_ip_count(), 2);

        // Add a third IP
        host.add_ip_address(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), "eth2".to_string());
        assert_eq!(host.get_ip_count(), 3);
        assert!(host.has_multiple_ips());
    }

    #[test]
    fn test_version_tracking() {
        use std::net::{IpAddr, Ipv4Addr};

        let mut host = PtpHost::new(
            "00:11:22:33:44:55:66:77".to_string(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            319,
            "eth0".to_string(),
        );

        // Initially should have no version
        assert_eq!(host.last_version, None);
        assert_eq!(host.get_version_string(), "Unknown");

        // Update with PTPv2
        host.update_version(2);
        assert_eq!(host.last_version, Some(2));
        assert_eq!(host.get_version_string(), "v2");

        // Update with different version
        host.update_version(1);
        assert_eq!(host.last_version, Some(1));
        assert_eq!(host.get_version_string(), "v1");
    }

    #[test]
    fn test_correction_field_tracking() {
        use std::net::{IpAddr, Ipv4Addr};

        let mut host = PtpHost::new(
            "00:11:22:33:44:55:66:77".to_string(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            319,
            "eth0".to_string(),
        );

        // Initially correction field should be None
        assert_eq!(host.last_correction_field, None);
        assert_eq!(host.get_correction_field_string(), "Unknown");

        // Update correction field
        host.update_correction_field(1500);
        assert_eq!(host.last_correction_field, Some(1500));
        assert_eq!(host.get_correction_field_string(), "1500");

        // Update with different correction field
        host.update_correction_field(-750);
        assert_eq!(host.last_correction_field, Some(-750));
        assert_eq!(host.get_correction_field_string(), "-750");
    }
}

pub struct PtpTracker {
    hosts: HashMap<String, PtpHost>,
    last_packet: Instant,
    event_socket: UdpSocket,
    general_socket: UdpSocket,
    // Track recent sync/follow-up senders per domain for transmitter-receiver correlation
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
    pub version: u8,
    pub message_type: PtpMessageType,
    pub message_length: u16,
    pub clock_identity: String,
    pub domain_number: u8,
    pub sequence_id: u16,
    pub flags: [u8; 2],
    pub correction_field: i64,
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
            version: header.version,
            message_type: header.message_type,
            message_length: header.message_length,
            clock_identity: clock_id.clone(),
            domain_number: header.domain_number,
            sequence_id: header.sequence_id,
            flags: header.flags,
            correction_field: header.correction_field,
            log_message_interval: header.log_message_interval,
        };

        // Parse messages first if needed to avoid borrowing conflicts
        let announce_msg = if header.message_type == PtpMessageType::Announce {
            self.parse_announce_message(data).ok()
        } else {
            None
        };

        let sync_msg = if header.message_type == PtpMessageType::Sync {
            self.parse_sync_message(data).ok()
        } else {
            None
        };

        let followup_msg = if header.message_type == PtpMessageType::FollowUp {
            self.parse_follow_up_message(data).ok()
        } else {
            None
        };

        // Get or create host entry
        let host = self.hosts.entry(clock_id.clone()).or_insert_with(|| {
            PtpHost::new(
                clock_id.clone(),
                src_addr.ip(),
                src_addr.port(),
                packet_info.interface.clone(),
            )
        });

        // Add this IP address if it's not already known for this host
        host.add_ip_address(src_addr.ip(), packet_info.interface.clone());

        // Update last seen
        host.update_last_seen();
        host.domain_number = header.domain_number;
        host.update_version(header.version);
        host.update_correction_field(header.correction_field);

        // Set initial state to listening if still unknown and no announce messages received
        if host.state == PtpState::Unknown && host.announce_count == 0 {
            host.state = PtpState::Listening;
        }

        // Process message based on type
        match header.message_type {
            PtpMessageType::Announce => {
                host.announce_count += 1;
                host.total_message_count += 1;
                if let Some(announce) = announce_msg {
                    host.update_from_announce(&announce);
                }
            }
            PtpMessageType::Sync => {
                host.sync_count += 1;
                host.total_message_count += 1;
                host.last_sync_timestamp = Some(std::time::Instant::now());

                // Extract origin timestamp from Sync message
                if let Some(sync_msg) = sync_msg {
                    host.sync_origin_timestamp = Some(sync_msg.origin_timestamp);
                    host.last_origin_timestamp = Some(sync_msg.origin_timestamp);
                    host.timestamp_source = Some("Sync".to_string());
                }

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
                    // Sync messages usually come from (primary) transmitters
                    host.state = PtpState::Transmitter;
                    host.selected_transmitter_id = None; // Transmitters don't receive from anyone
                }
            }
            PtpMessageType::DelayReq => {
                host.delay_req_count += 1;
                host.total_message_count += 1;
                // Delay requests are sent by receivers
                if host.announce_count == 0 {
                    host.state = PtpState::Receiver;
                }

                // Find the most recent sync sender in this domain - this is the chosen transmitter
                // Look for sync traffic within the last 10 seconds as it should be recent
                let now = std::time::Instant::now();
                if let Some(domain_senders) = self.recent_sync_senders.get(&header.domain_number) {
                    // Find the most recent sync sender that's still active (within last 10 seconds)
                    if let Some((transmitter_id, _sync_time)) = domain_senders
                        .iter()
                        .filter(|(_, timestamp)| {
                            now.duration_since(*timestamp) < Duration::from_secs(10)
                        })
                        .max_by_key(|(_, timestamp)| *timestamp)
                    {
                        host.selected_transmitter_id = Some(transmitter_id.clone());
                        host.selected_transmitter_confidence = 1.0; // High confidence - recent sync traffic
                    } else if let Some((transmitter_id, _)) = domain_senders
                        .iter()
                        .max_by_key(|(_, timestamp)| *timestamp)
                    {
                        // Fall back to any recent sync sender even if slightly older
                        host.selected_transmitter_id = Some(transmitter_id.clone());
                        host.selected_transmitter_confidence = 0.5; // Medium confidence - older sync traffic
                    } else if host.selected_transmitter_id.is_none() {
                        host.selected_transmitter_id = Some("No recent sync traffic".to_string());
                        host.selected_transmitter_confidence = 0.0;
                    }
                } else if host.selected_transmitter_id.is_none() {
                    host.selected_transmitter_id = Some("No sync traffic seen".to_string());
                    host.selected_transmitter_confidence = 0.0;
                }
            }
            PtpMessageType::DelayResp => {
                host.delay_resp_count += 1;
                host.total_message_count += 1;

                // Delay responses are sent by (primary) transmitters
                if host.announce_count == 0 {
                    host.state = PtpState::Transmitter;
                    host.selected_transmitter_id = None; // Transmitters don't receive from anyone
                }
            }
            PtpMessageType::FollowUp => {
                host.total_message_count += 1;
                // Extract precise origin timestamp from Follow-Up message
                if let Some(followup_msg) = followup_msg {
                    host.followup_origin_timestamp = Some(followup_msg.precise_origin_timestamp);
                    host.last_origin_timestamp = Some(followup_msg.precise_origin_timestamp);
                    host.timestamp_source = Some("Follow-Up".to_string());
                }

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

                // Follow-up messages are sent by transmitters for two-step timing
                if host.announce_count == 0 {
                    host.state = PtpState::Transmitter;
                    host.selected_transmitter_id = None; // Transmitters don't receive from anyone
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
        let _control_field = data[32];
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
            _control_field,
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
        let primary_transmitter_priority_1 = announce_data[13];

        let mut primary_transmitter_clock_quality = [0u8; 4];
        primary_transmitter_clock_quality.copy_from_slice(&announce_data[14..18]);

        let primary_transmitter_priority_2 = announce_data[18];

        let mut primary_transmitter_identity = [0u8; 8];
        primary_transmitter_identity.copy_from_slice(&announce_data[19..27]);

        let steps_removed = u16::from_be_bytes([announce_data[27], announce_data[28]]);
        let time_source = announce_data[29];

        Ok(AnnounceMessage {
            header,
            origin_timestamp,
            current_utc_offset,
            primary_transmitter_priority_1,
            primary_transmitter_clock_quality,
            primary_transmitter_priority_2,
            primary_transmitter_identity,
            steps_removed,
            time_source,
        })
    }

    fn parse_sync_message(&self, data: &[u8]) -> Result<SyncMessage> {
        if data.len() < 44 {
            // 34 (header) + 10 (origin timestamp) = 44 minimum
            return Err(anyhow::anyhow!("Packet too short for Sync message"));
        }

        let header = self.parse_ptp_header(data)?;

        // Parse sync-specific fields starting at byte 34
        let sync_data = &data[34..];

        if sync_data.len() < 10 {
            return Err(anyhow::anyhow!("Sync data too short"));
        }

        let mut origin_timestamp = [0u8; 10];
        origin_timestamp.copy_from_slice(&sync_data[0..10]);

        Ok(SyncMessage {
            _header: header,
            origin_timestamp,
        })
    }

    fn parse_follow_up_message(&self, data: &[u8]) -> Result<FollowUpMessage> {
        if data.len() < 44 {
            // 34 (header) + 10 (precise origin timestamp) = 44 minimum
            return Err(anyhow::anyhow!("Packet too short for Follow-Up message"));
        }

        let header = self.parse_ptp_header(data)?;

        // Parse follow-up specific fields starting at byte 34
        let followup_data = &data[34..];

        if followup_data.len() < 10 {
            return Err(anyhow::anyhow!("Follow-Up data too short"));
        }

        let mut precise_origin_timestamp = [0u8; 10];
        precise_origin_timestamp.copy_from_slice(&followup_data[0..10]);

        Ok(FollowUpMessage {
            _header: header,
            precise_origin_timestamp,
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
            // Sort by: transmitter first, then by quality, then by clock identity
            match (a.is_transmitter(), b.is_transmitter()) {
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

    pub fn get_transmitter_count(&self) -> usize {
        self.hosts.values().filter(|h| h.is_transmitter()).count()
    }

    pub fn get_receiver_count(&self) -> usize {
        self.hosts.values().filter(|h| h.is_receiver()).count()
    }

    pub fn get_last_packet_age(&self) -> Duration {
        Instant::now().duration_since(self.last_packet)
    }
}
