use crate::oui_map::lookup_vendor_bytes;
use std::fmt::Display;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PtpTimestamp {
    pub seconds: u64,
    pub nanoseconds: u32,
}

impl PtpTimestamp {
    pub fn total_nanoseconds(&self) -> u128 {
        (self.seconds as u128) * 1_000_000_000u128 + (self.nanoseconds as u128)
    }

    pub fn rtp_samples(&self, samplerate: u32) -> u32 {
        let samples = self.total_nanoseconds() * (samplerate as u128) / 1_000_000_000u128;
        samples as u32
    }

    pub fn common_samplerates(&self) -> Vec<u32> {
        vec![44100, 48000, 96000]
    }

    pub fn format_common_samplerates(&self, prefix: &str) -> Vec<(String, String)> {
        if self.seconds == 0 && self.nanoseconds == 0 {
            return vec![];
        }

        self.common_samplerates()
            .into_iter()
            .map(|rate| {
                (
                    format!("{} @{} Hz", prefix, rate),
                    self.rtp_samples(rate).to_string(),
                )
            })
            .collect()
    }
}

impl TryFrom<&[u8]> for PtpTimestamp {
    type Error = anyhow::Error;

    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        if b.len() != 10 {
            Err(anyhow::anyhow!("Packet too short for PTP timestamp"))
        } else {
            Ok(Self {
                seconds: u64::from_be_bytes([0, 0, b[0], b[1], b[2], b[3], b[4], b[5]]),
                nanoseconds: u32::from_be_bytes([b[6], b[7], b[8], b[9]]),
            })
        }
    }
}

impl Display for PtpTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use hifitime::{Duration, Epoch, TimeScale};

        if self.seconds == 0 && self.nanoseconds == 0 {
            write!(f, "0")
        } else {
            // PTP uses TAI time since 1 January 1970 00:00:00, in nanoseconds
            // Create TAI epoch from PTP timestamp
            let duration = Duration::from_total_nanoseconds(self.total_nanoseconds() as i128);
            let epoch = Epoch::from_unix_duration(duration);

            let (year, month, day, hour, minute, second, nanosecond) = epoch.to_gregorian_utc();

            let dur_utc = epoch.to_duration_in_time_scale(TimeScale::UTC);
            let dur_tai = epoch.to_duration_in_time_scale(TimeScale::TAI);
            let tai_offset = (dur_tai - dur_utc).to_seconds();

            write!(
                f,
                "{}-{:02}-{:02} {:02}:{:02}:{:02}.{:09} ({:+}s)",
                year, month, day, hour, minute, second, nanosecond, tai_offset,
            )
        }
    }
}

#[test]
fn test_ptp_timestamp_rtp_samples() {
    let timestamp = PtpTimestamp {
        seconds: 1,
        nanoseconds: 0,
    };
    assert_eq!(timestamp.rtp_samples(48000), 48000);

    let timestamp = PtpTimestamp {
        seconds: 2,
        nanoseconds: 500_000_000,
    };
    assert_eq!(timestamp.rtp_samples(48000), 120000);
}

pub fn format_timestamp(timestamp: Option<PtpTimestamp>) -> String {
    match timestamp {
        Some(ts) => ts.to_string(),
        None => "N/A".to_string(),
    }
}

#[test]
fn test_ptp_timestamp_formatting() {
    // Test TAI offset display functionality
    let mut timestamp = [0u8; 10];

    // Set a test timestamp with TAI seconds
    let ptp_seconds: u64 = 3914496037;
    timestamp[0] = ((ptp_seconds >> 40) & 0xff) as u8;
    timestamp[1] = ((ptp_seconds >> 32) & 0xff) as u8;
    timestamp[2] = ((ptp_seconds >> 24) & 0xff) as u8;
    timestamp[3] = ((ptp_seconds >> 16) & 0xff) as u8;
    timestamp[4] = ((ptp_seconds >> 8) & 0xff) as u8;
    timestamp[5] = (ptp_seconds & 0xff) as u8;

    // Set nanoseconds (big-endian, 4 bytes)
    let nanos: u32 = 123456789;
    timestamp[6] = ((nanos >> 24) & 0xff) as u8;
    timestamp[7] = ((nanos >> 16) & 0xff) as u8;
    timestamp[8] = ((nanos >> 8) & 0xff) as u8;
    timestamp[9] = (nanos & 0xff) as u8;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PtpMessageType {
    Sync = 0x0,
    DelayReq = 0x1,   // End-to-end delay request (transmitter-receiver mode)
    PDelayReq = 0x2,  // Peer delay request (peer-to-peer mode)
    PDelayResp = 0x3, // Peer delay response (peer-to-peer mode)
    FollowUp = 0x8,
    DelayResp = 0x9,          // End-to-end delay response (transmitter-receiver mode)
    PDelayRespFollowUp = 0xa, // Peer delay response follow-up (peer-to-peer mode)
    Announce = 0xb,
    Signaling = 0xc,
    Management = 0xd,
}

impl TryFrom<u8> for PtpMessageType {
    type Error = anyhow::Error;

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
            _ => Err(anyhow::anyhow!("Unknown PTP message type")),
        }
    }
}

impl Display for PtpMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PtpMessageType::Sync => write!(f, "SYNC"),
            PtpMessageType::DelayReq => write!(f, "DELAY_REQ"),
            PtpMessageType::PDelayReq => write!(f, "PDELAY_REQ"),
            PtpMessageType::PDelayResp => write!(f, "PDELAY_RESP"),
            PtpMessageType::FollowUp => write!(f, "FOLLOW_UP"),
            PtpMessageType::DelayResp => write!(f, "DELAY_RESP"),
            PtpMessageType::PDelayRespFollowUp => write!(f, "PDELAY_RESP_FU"),
            PtpMessageType::Announce => write!(f, "ANNOUNCE"),
            PtpMessageType::Signaling => write!(f, "SIGNALING"),
            PtpMessageType::Management => write!(f, "MANAGEMENT"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtpVersion {
    V1,
    V2,
}

impl TryFrom<u8> for PtpVersion {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x1 => Ok(PtpVersion::V1),
            0x2 => Ok(PtpVersion::V2),
            _ => Err(anyhow::anyhow!("Unknown PTP version")),
        }
    }
}

impl Display for PtpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PtpVersion::V1 => write!(f, "v1"),
            PtpVersion::V2 => write!(f, "v2"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy, Ord, PartialOrd, Default)]
pub struct ClockIdentity {
    pub clock_id: [u8; 8],
}

impl ClockIdentity {
    /// Extract vendor name from clock identity string using OUI lookup
    pub fn extract_vendor_name(&self) -> Option<&'static str> {
        let mac_bytes: [u8; 6] = [
            self.clock_id[0],
            self.clock_id[1],
            self.clock_id[2],
            self.clock_id[5],
            self.clock_id[6],
            self.clock_id[7],
        ];

        lookup_vendor_bytes(mac_bytes)
    }
}

impl TryFrom<&[u8]> for ClockIdentity {
    type Error = anyhow::Error;

    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            clock_id: b.try_into()?,
        })
    }
}

#[test]
fn test_oui_vendor_lookup() {
    // Test Cisco OUI-24 (00:00:0c)
    let b: [u8; 8] = [0x00, 0x00, 0x0c, 0x11, 0x22, 0x33, 0x44, 0x55];
    assert_eq!(
        ClockIdentity::try_from(&b[..])
            .unwrap()
            .extract_vendor_name(),
        Some("Cisco Systems, Inc")
    );

    // Test unknown OUI
    let b: [u8; 8] = [0xff, 0xff, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55];
    assert_eq!(
        ClockIdentity::try_from(&b[..])
            .unwrap()
            .extract_vendor_name(),
        None
    );
}

impl Display for ClockIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.clock_id[0],
            self.clock_id[1],
            self.clock_id[2],
            self.clock_id[3],
            self.clock_id[4],
            self.clock_id[5],
            self.clock_id[6],
            self.clock_id[7],
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtpClockClass {
    class: u8,
}

impl PtpClockClass {
    pub fn new(class: u8) -> Self {
        Self { class }
    }

    pub fn class(&self) -> u8 {
        self.class
    }
}

impl Display for PtpClockClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self.class {
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
        write!(f, "{} ({})", self.class, description)
    }
}

#[test]
fn test_clock_class_formatting() {
    assert_eq!(
        PtpClockClass::new(6).to_string(),
        "6 (Primary reference (GPS, atomic clock, etc.))"
    );

    assert_eq!(
        PtpClockClass::new(7).to_string(),
        "7 (Primary reference (degraded))"
    );
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct PtpClockAccuracy {
    pub accuracy: u8,
}

impl PtpClockAccuracy {
    pub fn new(accuracy: u8) -> Self {
        Self { accuracy }
    }
}

impl Display for PtpClockAccuracy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self.accuracy {
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
        write!(f, "{} ({})", self.accuracy, description)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct PtpUtcOffset {
    pub offset: i16,
}

impl PtpUtcOffset {
    pub fn new(offset: i16) -> Self {
        Self { offset }
    }
}

impl Display for PtpUtcOffset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:+}s", self.offset)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct PtpLogInterval {
    pub exponent: i8,
}

impl PtpLogInterval {
    pub fn new(exponent: i8) -> Self {
        Self { exponent }
    }
}

impl Display for PtpLogInterval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.exponent == 0x7f {
            return write!(f, "-");
        }

        let interval_seconds = 2.0_f64.powf(self.exponent as f64);
        write!(f, "{:.2}s ({})", interval_seconds, self.exponent)
    }
}

#[test]
fn test_format_log_interval() {
    // Test that -1 gives 0.5 seconds
    assert_eq!(PtpLogInterval::new(-1).to_string(), "0.50s (-1)");

    // Test other common values
    assert_eq!(PtpLogInterval::new(0).to_string(), "1.00s (0)");
    assert_eq!(PtpLogInterval::new(1).to_string(), "2.00s (1)");
    assert_eq!(PtpLogInterval::new(-2).to_string(), "0.25s (-2)");
    assert_eq!(PtpLogInterval::new(3).to_string(), "8.00s (3)");

    // Test reserved value
    assert_eq!(PtpLogInterval::new(0x7f).to_string(), "-");
}

#[derive(Debug, Clone, Copy)]
pub struct PtpCorrectionField {
    pub value: i64,
}

impl PtpCorrectionField {
    pub fn new(value: i64) -> Self {
        Self { value }
    }
}

impl Display for PtpCorrectionField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ns = (self.value as f64) / (1u64 << 16) as f64;

        if ns == 0.0 {
            write!(f, "0")
        } else if ns.abs() < 1000.0 {
            write!(f, "{:+.2} ns", ns)
        } else if ns.abs() < 1000000.0 {
            write!(f, "{:+.03} μs", ns / 1000.0)
        } else {
            write!(f, "{:+.03} s", ns / 1000000000.0)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy, Ord, PartialOrd)]
pub struct PortIdentity {
    pub clock_identity: ClockIdentity,
    pub port_number: u16,
}

impl TryFrom<&[u8]> for PortIdentity {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            clock_identity: ClockIdentity::try_from(&value[0..8])?,
            port_number: u16::from_be_bytes(value[8..10].try_into().unwrap()),
        })
    }
}

impl Display for PortIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{:04x}", self.clock_identity, self.port_number,)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PtpHeaderFlags {
    v: [u8; 2],
    alternate_tt_flag: bool,
    two_step_flag: bool,
    unicast_flag: bool,
    profile_specific_1: bool,
    profile_specific_2: bool,
    ptp_security_flag: bool,
    leap61: bool,
    leap59: bool,
    current_utc_offset_valid: bool,
    ptp_timescale: bool,
    time_traceable: bool,
    frequency_traceable: bool,
}

impl PtpHeaderFlags {
    pub fn short(&self) -> String {
        format!("{:02x}{:02x}", self.v[0], self.v[1])
    }

    pub fn details(&self) -> Vec<(&str, bool)> {
        vec![
            ("Alternate TT Flag", self.alternate_tt_flag),
            ("Two-Step Flag", self.two_step_flag),
            ("Unicast Flag", self.unicast_flag),
            ("Profile Specific 1", self.profile_specific_1),
            ("Profile Specific 2", self.profile_specific_2),
            ("Security Flag", self.ptp_security_flag),
            ("Leap 61", self.leap61),
            ("Leap 59", self.leap59),
            ("UTC Offset Valid", self.current_utc_offset_valid),
            ("PTP Timescale", self.ptp_timescale),
            ("Time Traceable", self.time_traceable),
            ("Frequency Traceable", self.frequency_traceable),
        ]
    }
}

impl TryFrom<&[u8]> for PtpHeaderFlags {
    type Error = anyhow::Error;

    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            v: v.try_into()?,
            alternate_tt_flag: v[0] & (1 << 0) != 0,
            two_step_flag: v[0] & (1 << 1) != 0,
            unicast_flag: v[0] & (1 << 2) != 0,
            profile_specific_1: v[0] & (1 << 5) != 0,
            profile_specific_2: v[0] & (1 << 6) != 0,
            ptp_security_flag: v[0] & (1 << 7) != 0,
            leap61: v[1] & (1 << 0) != 0,
            leap59: v[1] & (1 << 1) != 0,
            current_utc_offset_valid: v[1] & (1 << 2) != 0,
            ptp_timescale: v[1] & (1 << 3) != 0,
            time_traceable: v[1] & (1 << 4) != 0,
            frequency_traceable: v[1] & (1 << 5) != 0,
        })
    }
}

impl Display for PtpHeaderFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.details()
                .iter()
                .map(|(s, b)| format!("{s}: {b}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn format_kv(kv: Vec<(String, String)>) -> String {
    kv.iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Debug, Clone, Copy)]
pub struct PtpHeader {
    pub message_type: PtpMessageType,
    pub version: PtpVersion,
    pub message_length: u16,
    pub domain_number: u8,
    pub flags: PtpHeaderFlags,
    pub correction_field: PtpCorrectionField,
    pub source_port_identity: PortIdentity,
    pub sequence_id: u16,
    pub _control_field: u8,
    pub log_message_interval: PtpLogInterval,
}

impl TryFrom<&[u8]> for PtpHeader {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < 34 {
            Err(anyhow::anyhow!("Packet too short for PTP header"))
        } else {
            Ok(PtpHeader {
                message_type: PtpMessageType::try_from(data[0] & 0x0f)?,
                version: PtpVersion::try_from(data[1] & 0x0f)?,
                message_length: u16::from_be_bytes([data[2], data[3]]),
                domain_number: data[4],
                flags: PtpHeaderFlags::try_from(&data[5..7])?,
                correction_field: PtpCorrectionField::new(i64::from_be_bytes([
                    data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
                ])),
                source_port_identity: PortIdentity::try_from(&data[20..30])?,
                sequence_id: u16::from_be_bytes([data[30], data[31]]),
                _control_field: data[32],
                log_message_interval: PtpLogInterval::new(data[33] as i8),
            })
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AnnounceMessage {
    pub header: PtpHeader,
    pub origin_timestamp: PtpTimestamp,
    pub current_utc_offset: PtpUtcOffset,
    pub priority1: u8,
    pub priority2: u8,
    pub clock_class: PtpClockClass,
    pub clock_accuracy: PtpClockAccuracy,
    pub offset_scaled_log_variance: u16,
    pub ptt_identity: ClockIdentity,
    pub steps_removed: u16,
    pub time_source: u8,
}

impl AnnounceMessage {
    pub fn details(&self) -> Vec<(String, String)> {
        vec![
            (
                "Origin Timestamp".to_string(),
                self.origin_timestamp.to_string(),
            ),
            (
                "Current UTC Offset".to_string(),
                self.current_utc_offset.to_string(),
            ),
            ("Priority1".to_string(), self.priority1.to_string()),
            ("Priority2".to_string(), self.priority2.to_string()),
            ("Clock Class".to_string(), self.clock_class.to_string()),
            (
                "Clock Accuracy".to_string(),
                self.clock_accuracy.to_string(),
            ),
            (
                "Offset Scaled Log Variance".to_string(),
                self.offset_scaled_log_variance.to_string(),
            ),
            ("PTP Identity".to_string(), self.ptt_identity.to_string()),
            ("Steps Removed".to_string(), self.steps_removed.to_string()),
            ("Time Source".to_string(), self.time_source.to_string()),
        ]
    }
}

impl TryFrom<&[u8]> for AnnounceMessage {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        // 34 (header) + 30 (announce content) = 64 minimum
        if data.len() < 64 {
            Err(anyhow::anyhow!("Packet too short for Announce message"))
        } else {
            Ok(AnnounceMessage {
                header: PtpHeader::try_from(&data[..34])?,
                origin_timestamp: PtpTimestamp::try_from(&data[34..44])?,
                current_utc_offset: PtpUtcOffset::new(i16::from_be_bytes([data[44], data[45]])),
                priority1: data[47],
                clock_class: PtpClockClass::new(data[48]),
                clock_accuracy: PtpClockAccuracy::new(data[49]),
                offset_scaled_log_variance: u16::from_be_bytes([data[50], data[51]]),
                priority2: data[52],
                ptt_identity: ClockIdentity::try_from(&data[53..61])?,
                steps_removed: u16::from_be_bytes([data[61], data[62]]),
                time_source: data[63],
            })
        }
    }
}

impl Display for AnnounceMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format_kv(self.details()))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SyncMessage {
    pub header: PtpHeader,
    pub origin_timestamp: PtpTimestamp,
}

impl SyncMessage {
    pub fn details_compact(&self) -> Vec<(String, String)> {
        vec![("OriginTS".to_string(), self.origin_timestamp.to_string())]
    }

    pub fn details(&self) -> Vec<(String, String)> {
        let mut v = vec![("OriginTS".to_string(), self.origin_timestamp.to_string())];

        v.extend(self.origin_timestamp.format_common_samplerates("→ samples"));

        v
    }
}

impl TryFrom<&[u8]> for SyncMessage {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        // 34 (header) + 10 (sync content) = 44 minimum
        if data.len() < 44 {
            Err(anyhow::anyhow!("Packet too short for Sync message"))
        } else {
            Ok(SyncMessage {
                header: PtpHeader::try_from(&data[..34])?,
                origin_timestamp: PtpTimestamp::try_from(&data[34..44])?,
            })
        }
    }
}

impl Display for SyncMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format_kv(self.details_compact()))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FollowUpMessage {
    pub header: PtpHeader,
    pub precise_origin_timestamp: PtpTimestamp,
}

impl FollowUpMessage {
    pub fn details_compact(&self) -> Vec<(String, String)> {
        vec![(
            "PreciseOriginTS".to_string(),
            self.precise_origin_timestamp.to_string(),
        )]
    }

    pub fn details(&self) -> Vec<(String, String)> {
        let mut v = vec![(
            "PreciseOriginTS".to_string(),
            self.precise_origin_timestamp.to_string(),
        )];

        v.extend(
            self.precise_origin_timestamp
                .format_common_samplerates("→ samples"),
        );

        v
    }
}

impl TryFrom<&[u8]> for FollowUpMessage {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        // 34 (header) + 10 (precise origin timestamp) = 44 minimum
        if data.len() < 44 {
            Err(anyhow::anyhow!("Packet too short for Sync message"))
        } else {
            Ok(FollowUpMessage {
                header: PtpHeader::try_from(&data[..34])?,
                precise_origin_timestamp: PtpTimestamp::try_from(&data[34..44])?,
            })
        }
    }
}

impl Display for FollowUpMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format_kv(self.details_compact()))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PDelayReqMessage {
    pub header: PtpHeader,
    pub origin_timestamp: PtpTimestamp,
}

impl PDelayReqMessage {
    pub fn details(&self) -> Vec<(String, String)> {
        vec![("OriginTS".to_string(), self.origin_timestamp.to_string())]
    }
}

impl TryFrom<&[u8]> for PDelayReqMessage {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        // 34 (header) + 20 (delay request content) = 54 minimum
        if data.len() < 54 {
            Err(anyhow::anyhow!("Packet too short for PDelayReq message"))
        } else {
            Ok(PDelayReqMessage {
                header: PtpHeader::try_from(&data[..34])?,
                origin_timestamp: PtpTimestamp::try_from(&data[34..44])?,
            })
        }
    }
}

impl Display for PDelayReqMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format_kv(self.details()))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PDelayRespMessage {
    pub header: PtpHeader,
    pub request_receipt_timestamp: PtpTimestamp,
    pub requesting_port_identity: PortIdentity,
}

impl PDelayRespMessage {
    pub fn details(&self) -> Vec<(String, String)> {
        vec![
            (
                "RequestReceiptTS".to_string(),
                self.request_receipt_timestamp.to_string(),
            ),
            (
                "RequestingPI".to_string(),
                self.requesting_port_identity.to_string(),
            ),
        ]
    }
}

impl TryFrom<&[u8]> for PDelayRespMessage {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        // 34 (header) + 20 (pdelay resp content) = 54 minimum
        if data.len() < 54 {
            Err(anyhow::anyhow!("Packet too short for PDelayResp message"))
        } else {
            Ok(PDelayRespMessage {
                header: PtpHeader::try_from(&data[..34])?,
                request_receipt_timestamp: PtpTimestamp::try_from(&data[34..44])?,
                requesting_port_identity: PortIdentity::try_from(&data[44..54])?,
            })
        }
    }
}

impl Display for PDelayRespMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format_kv(self.details()))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PDelayRespFollowUpMessage {
    pub header: PtpHeader,
    pub response_origin_timestamp: PtpTimestamp,
    pub requesting_port_identity: PortIdentity,
}

impl PDelayRespFollowUpMessage {
    pub fn details(&self) -> Vec<(String, String)> {
        vec![
            (
                "ResponseOriginTS".to_string(),
                self.response_origin_timestamp.to_string(),
            ),
            (
                "RequestingPI".to_string(),
                self.requesting_port_identity.to_string(),
            ),
        ]
    }
}

impl TryFrom<&[u8]> for PDelayRespFollowUpMessage {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        // 34 (header) + 20 (pdelay resp follow-up content) = 54 minimum
        if data.len() < 54 {
            Err(anyhow::anyhow!("Invalid PDelayRespFollowUpMessage length"))
        } else {
            Ok(PDelayRespFollowUpMessage {
                header: PtpHeader::try_from(&data[..34])?,
                response_origin_timestamp: PtpTimestamp::try_from(&data[34..44])?,
                requesting_port_identity: PortIdentity::try_from(&data[44..54])?,
            })
        }
    }
}

impl Display for PDelayRespFollowUpMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format_kv(self.details()))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DelayReqMessage {
    pub header: PtpHeader,
    pub origin_timestamp: PtpTimestamp,
}

impl DelayReqMessage {
    pub fn details(&self) -> Vec<(String, String)> {
        vec![("Origin TS".to_string(), self.origin_timestamp.to_string())]
    }
}

impl TryFrom<&[u8]> for DelayReqMessage {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        // 34 (header) + 10 (origin timestamp) = 44 minimum
        if data.len() < 44 {
            Err(anyhow::anyhow!("Invalid PDelayRespFollowUpMessage length"))
        } else {
            Ok(DelayReqMessage {
                header: PtpHeader::try_from(&data[..34])?,
                origin_timestamp: PtpTimestamp::try_from(&data[34..44])?,
            })
        }
    }
}

impl Display for DelayReqMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format_kv(self.details()))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DelayRespMessage {
    pub header: PtpHeader,
    pub receive_timestamp: PtpTimestamp,
    pub requesting_port_identity: PortIdentity,
}

impl DelayRespMessage {
    pub fn details(&self) -> Vec<(String, String)> {
        vec![
            ("Receive TS".to_string(), self.receive_timestamp.to_string()),
            (
                "Requesting PI".to_string(),
                self.requesting_port_identity.to_string(),
            ),
        ]
    }
}

impl TryFrom<&[u8]> for DelayRespMessage {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        // 34 (header) + 20 (delay resp content) = 54 minimum
        if data.len() < 54 {
            Err(anyhow::anyhow!("Invalid DelayRespMessage length"))
        } else {
            Ok(DelayRespMessage {
                header: PtpHeader::try_from(&data[..34])?,
                receive_timestamp: PtpTimestamp::try_from(&data[34..44])?,
                requesting_port_identity: PortIdentity::try_from(&data[44..54])?,
            })
        }
    }
}

impl Display for DelayRespMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format_kv(self.details()))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SignalingMessage {
    pub header: PtpHeader,
    pub target_port_identity: PortIdentity,
    // FIXME!
}

impl SignalingMessage {
    pub fn details(&self) -> Vec<(String, String)> {
        vec![(
            "Target PI".to_string(),
            self.target_port_identity.to_string(),
        )]
    }
}

impl TryFrom<&[u8]> for SignalingMessage {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < 54 {
            Err(anyhow::anyhow!("Invalid SignalingMessage length"))
        } else {
            Ok(SignalingMessage {
                header: PtpHeader::try_from(&data[..34])?,
                target_port_identity: PortIdentity::try_from(&data[34..44])?,
            })
        }
    }
}

impl Display for SignalingMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format_kv(self.details()))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ManagementMessage {
    pub header: PtpHeader,
    pub target_port_identity: PortIdentity,
    pub starting_boundary_hops: u8,
    pub boundary_hops: u8,
    pub action_field: u8,
    // FIXME!
}

impl ManagementMessage {
    pub fn details(&self) -> Vec<(String, String)> {
        vec![
            (
                "Target PI".to_string(),
                format!("{}", self.target_port_identity),
            ),
            (
                "StartingBoundaryHops".to_string(),
                format!("{}", self.starting_boundary_hops),
            ),
            (
                "BoundaryHops".to_string(),
                format!("{}", self.boundary_hops),
            ),
            ("ActionField".to_string(), format!("{}", self.action_field)),
        ]
    }
}

impl TryFrom<&[u8]> for ManagementMessage {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < 54 {
            Err(anyhow::anyhow!("Invalid ManagementMessage length"))
        } else {
            Ok(ManagementMessage {
                header: PtpHeader::try_from(&data[..34])?,
                target_port_identity: PortIdentity::try_from(&data[34..44])?,
                starting_boundary_hops: data[44],
                boundary_hops: data[45],
                action_field: data[46] & 0x0f,
            })
        }
    }
}

impl Display for ManagementMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format_kv(self.details()))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PtpMessage {
    Announce(AnnounceMessage),
    DelayReq(DelayReqMessage),
    DelayResp(DelayRespMessage),
    Sync(SyncMessage),
    PDelayReq(PDelayReqMessage),
    PDelayResp(PDelayRespMessage),
    FollowUp(FollowUpMessage),
    PDelayRespFollowup(PDelayRespFollowUpMessage),
    Signaling(SignalingMessage),
    Management(ManagementMessage),
}

impl PtpMessage {
    pub fn header(&self) -> &PtpHeader {
        match self {
            PtpMessage::Announce(msg) => &msg.header,
            PtpMessage::DelayReq(msg) => &msg.header,
            PtpMessage::DelayResp(msg) => &msg.header,
            PtpMessage::Sync(msg) => &msg.header,
            PtpMessage::PDelayReq(msg) => &msg.header,
            PtpMessage::PDelayResp(msg) => &msg.header,
            PtpMessage::FollowUp(msg) => &msg.header,
            PtpMessage::PDelayRespFollowup(msg) => &msg.header,
            PtpMessage::Signaling(msg) => &msg.header,
            PtpMessage::Management(msg) => &msg.header,
        }
    }

    pub fn details(&self) -> Vec<(String, String)> {
        match self {
            PtpMessage::Announce(msg) => msg.details(),
            PtpMessage::DelayReq(msg) => msg.details(),
            PtpMessage::DelayResp(msg) => msg.details(),
            PtpMessage::Sync(msg) => msg.details(),
            PtpMessage::PDelayReq(msg) => msg.details(),
            PtpMessage::PDelayResp(msg) => msg.details(),
            PtpMessage::FollowUp(msg) => msg.details(),
            PtpMessage::PDelayRespFollowup(msg) => msg.details(),
            PtpMessage::Signaling(msg) => msg.details(),
            PtpMessage::Management(msg) => msg.details(),
        }
    }
}

impl TryFrom<&[u8]> for PtpMessage {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let header = PtpHeader::try_from(&data[..34])?;

        match header.message_type {
            PtpMessageType::Announce => Ok(PtpMessage::Announce(AnnounceMessage::try_from(data)?)),
            PtpMessageType::DelayReq => Ok(PtpMessage::DelayReq(DelayReqMessage::try_from(data)?)),
            PtpMessageType::DelayResp => {
                Ok(PtpMessage::DelayResp(DelayRespMessage::try_from(data)?))
            }
            PtpMessageType::Sync => Ok(PtpMessage::Sync(SyncMessage::try_from(data)?)),
            PtpMessageType::PDelayReq => {
                Ok(PtpMessage::PDelayReq(PDelayReqMessage::try_from(data)?))
            }
            PtpMessageType::PDelayResp => {
                Ok(PtpMessage::PDelayResp(PDelayRespMessage::try_from(data)?))
            }
            PtpMessageType::FollowUp => Ok(PtpMessage::FollowUp(FollowUpMessage::try_from(data)?)),
            PtpMessageType::PDelayRespFollowUp => Ok(PtpMessage::PDelayRespFollowup(
                PDelayRespFollowUpMessage::try_from(data)?,
            )),
            PtpMessageType::Signaling => {
                Ok(PtpMessage::Signaling(SignalingMessage::try_from(data)?))
            }
            PtpMessageType::Management => {
                Ok(PtpMessage::Management(ManagementMessage::try_from(data)?))
            }
        }
    }
}

impl Display for PtpMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PtpMessage::Announce(msg) => msg.fmt(f),
            PtpMessage::DelayReq(msg) => msg.fmt(f),
            PtpMessage::DelayResp(msg) => msg.fmt(f),
            PtpMessage::Sync(msg) => msg.fmt(f),
            PtpMessage::PDelayReq(msg) => msg.fmt(f),
            PtpMessage::PDelayResp(msg) => msg.fmt(f),
            PtpMessage::FollowUp(msg) => msg.fmt(f),
            PtpMessage::PDelayRespFollowup(msg) => msg.fmt(f),
            PtpMessage::Signaling(msg) => msg.fmt(f),
            PtpMessage::Management(msg) => msg.fmt(f),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub ptp: PtpMessage,
    pub raw: std::sync::Arc<crate::source::RawPacket>,
}

#[test]
fn test_ptp_header_parsing() {
    let header_data = [
        0x00, 0x02, 0x00, 0x2C, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B, 0x19, 0xFF, 0xFE, 0x12, 0x34, 0x56, 0x00, 0x01,
        0x00, 0x64, 0x00, 0x00,
    ];

    let header = PtpHeader::try_from(&header_data[..]).unwrap();

    assert_eq!(header.message_type.to_string(), "SYNC");
    assert_eq!(header.version.to_string(), "v2");
    assert_eq!(header.message_length, 44);
    assert_eq!(header.domain_number, 0);
    assert_eq!(header.sequence_id, 100);
    assert_eq!(header.log_message_interval.exponent, 0);
}

#[test]
fn test_announce_message_parsing() {
    let msg_data = [
        0x0B, 0x02, 0x00, 0x40, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B, 0x19, 0xFF, 0xFE, 0x12, 0x34, 0x56, 0x00, 0x01,
        0x00, 0x01, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x25, 0x00, 0x80, 0x06, 0x20, 0xFF, 0xFF, 0x80, 0x00, 0x1B, 0x19, 0xFF, 0xFE, 0x12, 0x34,
        0x56, 0x00, 0x00, 0x20,
    ];

    let announce = AnnounceMessage::try_from(&msg_data[..]).unwrap();

    assert_eq!(announce.header.message_type.to_string(), "ANNOUNCE");
    assert_eq!(announce.header.message_length, 64);
    assert_eq!(announce.priority1, 0x80);
    assert_eq!(announce.priority2, 0x80);
    assert_eq!(announce.clock_class.class(), 0x06);
    assert_eq!(announce.current_utc_offset.offset, 37);
    assert_eq!(announce.steps_removed, 0);
    assert_eq!(announce.time_source, 0x20);
}

#[test]
fn test_sync_message_parsing() {
    let msg_data = [
        0x00, 0x02, 0x00, 0x2C, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B, 0x19, 0xFF, 0xFE, 0x11, 0x22, 0x33, 0x00, 0x01,
        0x00, 0x7B, 0x00, 0xFF, 0x00, 0x00, 0x3B, 0x9A, 0xCA, 0x00, 0x1D, 0xCD, 0x65, 0x00,
    ];

    let sync = SyncMessage::try_from(&msg_data[..]).unwrap();

    assert_eq!(sync.header.message_type.to_string(), "SYNC");
    assert_eq!(sync.header.message_length, 44);
    assert_eq!(sync.header.sequence_id, 123);
    assert_eq!(sync.header.log_message_interval.exponent, -1);
    assert_eq!(sync.origin_timestamp.seconds, 1000000000);
    assert_eq!(sync.origin_timestamp.nanoseconds, 500000000);
}

#[test]
fn test_followup_message_parsing() {
    let msg_data = [
        0x08, 0x02, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B, 0x19, 0xFF, 0xFE, 0x44, 0x55, 0x66, 0x00, 0x01,
        0x00, 0x7B, 0x02, 0xFF, 0x00, 0x00, 0x3B, 0x9A, 0xCA, 0x00, 0x1D, 0xCD, 0x65, 0x01,
    ];

    let followup = FollowUpMessage::try_from(&msg_data[..]).unwrap();

    assert_eq!(followup.header.message_type.to_string(), "FOLLOW_UP");
    assert_eq!(followup.header.sequence_id, 123);
    assert_eq!(followup.precise_origin_timestamp.seconds, 1000000000);
    assert_eq!(followup.precise_origin_timestamp.nanoseconds, 500000001);
}

#[test]
fn test_ptp_header_parsing_errors() {
    let short_data = [0u8; 33];
    assert!(PtpHeader::try_from(&short_data[..]).is_err());

    let invalid_msg_data = [
        0x0F, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    assert!(PtpHeader::try_from(&invalid_msg_data[..]).is_err());

    let invalid_ver_data = [
        0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    assert!(PtpHeader::try_from(&invalid_ver_data[..]).is_err());
}

#[test]
fn test_message_parsing_errors() {
    let short_announce = [0u8; 63];
    assert!(AnnounceMessage::try_from(&short_announce[..]).is_err());

    let short_sync = [0u8; 43];
    assert!(SyncMessage::try_from(&short_sync[..]).is_err());
}
