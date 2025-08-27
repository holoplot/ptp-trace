use anyhow::Result;
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};

use crate::types::{
    AnnounceMessage, ClockIdentity, DelayRespMessage, FollowUpMessage, PDelayRespFollowUpMessage,
    PDelayRespMessage, ProcessedPacket, PtpClockAccuracy, PtpClockClass, PtpCorrectionField,
    PtpHeader, PtpMessage, PtpTimestamp, PtpUtcOffset, PtpVersion, SyncMessage,
};

/// A deque that maintains a maximum capacity by removing oldest elements
#[derive(Debug, Clone)]
pub struct BoundedVec<T> {
    items: VecDeque<T>,
    max_size: usize,
}

impl<T> BoundedVec<T> {
    fn new(max_size: usize) -> Self {
        Self {
            items: VecDeque::new(),
            max_size,
        }
    }

    fn push(&mut self, item: T) {
        self.items.push_back(item);
        if self.items.len() > self.max_size {
            self.items.pop_front();
        }
    }

    fn to_vec(&self) -> Vec<T>
    where
        T: Clone,
    {
        self.items.iter().cloned().collect()
    }

    fn clear(&mut self) {
        self.items.clear();
    }

    fn len(&self) -> usize {
        self.items.len()
    }
}

#[derive(Debug, Clone)]
pub struct PtpHostStateTimeTransmitter {
    pub last_sync_timestamp: Option<Instant>,
    pub priority1: Option<u8>,
    pub priority2: Option<u8>,
    pub clock_class: Option<PtpClockClass>,
    pub clock_accuracy: Option<PtpClockAccuracy>,
    pub steps_removed: Option<u16>,
    pub offset_scaled_log_variance: Option<u16>,
    pub time_source: Option<u8>,
    pub ptt_identifier: Option<ClockIdentity>,
    pub last_announce_origin_timestamp: Option<PtpTimestamp>,
    pub last_sync_origin_timestamp: Option<PtpTimestamp>,
    pub last_followup_origin_timestamp: Option<PtpTimestamp>,
    pub current_utc_offset: Option<PtpUtcOffset>,
    /// True if this transmitter has been selected as the Best Master Clock in its domain
    /// BMCA winners are displayed as "PTT" (Primary Time Transmitter) in the UI
    pub is_bmca_winner: bool,
}

impl Default for PtpHostStateTimeTransmitter {
    fn default() -> Self {
        PtpHostStateTimeTransmitter {
            last_sync_timestamp: None,
            priority1: None,
            priority2: None,
            clock_class: None,
            clock_accuracy: None,
            steps_removed: None,
            offset_scaled_log_variance: None,
            time_source: None,
            ptt_identifier: None,
            last_announce_origin_timestamp: None,
            last_sync_origin_timestamp: None,
            last_followup_origin_timestamp: None,
            current_utc_offset: None,
            is_bmca_winner: false,
        }
    }
}

impl PtpHostStateTimeTransmitter {
    fn from_announce(announce: &AnnounceMessage) -> Self {
        let mut s = PtpHostStateTimeTransmitter::default();
        s.update_from_announce(announce);
        s
    }

    fn update_from_announce(&mut self, msg: &AnnounceMessage) {
        self.priority1 = Some(msg.priority1);
        self.priority2 = Some(msg.priority2);
        self.clock_class = Some(msg.clock_class);
        self.clock_accuracy = Some(msg.clock_accuracy);
        self.offset_scaled_log_variance = Some(msg.offset_scaled_log_variance);
        self.steps_removed = Some(msg.steps_removed);
        self.time_source = Some(msg.time_source);
        self.ptt_identifier = Some(msg.ptt_identity);
        self.current_utc_offset = Some(msg.current_utc_offset);
        self.last_announce_origin_timestamp = Some(msg.origin_timestamp);
    }

    fn from_sync(msg: &SyncMessage) -> Self {
        let mut s = PtpHostStateTimeTransmitter::default();
        s.update_from_sync(msg);
        s
    }

    fn update_from_sync(&mut self, msg: &SyncMessage) {
        self.last_sync_origin_timestamp = Some(msg.origin_timestamp);
        self.last_sync_timestamp = Some(Instant::now());
    }

    fn from_follow_up(msg: &FollowUpMessage) -> Self {
        let mut s = PtpHostStateTimeTransmitter::default();
        s.update_from_follow_up(msg);
        s
    }

    fn update_from_follow_up(&mut self, msg: &FollowUpMessage) {
        self.last_followup_origin_timestamp = Some(msg.precise_origin_timestamp);
    }

    /// Compare this transmitter with another for BMCA (Best Master Clock Algorithm)
    ///
    /// Implements IEEE 1588 BMCA comparison algorithm. Returns std::cmp::Ordering where:
    /// - Less = this transmitter is better (should win)
    /// - Greater = other transmitter is better
    /// - Equal = transmitters are equivalent (shouldn't happen due to clock identity tiebreaker)
    ///
    /// Comparison order follows IEEE 1588 specification:
    /// 1. Priority1 (lower wins)
    /// 2. Clock Class (lower wins)
    /// 3. Clock Accuracy (lower wins)
    /// 4. Offset Scaled Log Variance (lower wins)
    /// 5. Priority2 (lower wins)
    /// 6. Clock Identity (lower wins, final tiebreaker)
    ///
    /// If a transmitter has data and the other doesn't, the one with data wins.
    pub fn compare_for_bmca(
        &self,
        other: &Self,
        our_clock_id: ClockIdentity,
        other_clock_id: ClockIdentity,
    ) -> std::cmp::Ordering {
        use std::cmp::Ordering;

        // 1. Priority1 comparison (lower is better)
        if let (Some(our_p1), Some(other_p1)) = (self.priority1, other.priority1) {
            match our_p1.cmp(&other_p1) {
                Ordering::Equal => {}
                other => return other,
            }
        } else if self.priority1.is_some() && other.priority1.is_none() {
            return Ordering::Less; // We have priority1, other doesn't
        } else if self.priority1.is_none() && other.priority1.is_some() {
            return Ordering::Greater; // Other has priority1, we don't
        }

        // 2. Clock Class comparison (lower is better)
        if let (Some(our_cc), Some(other_cc)) = (self.clock_class, other.clock_class) {
            match our_cc.class().cmp(&other_cc.class()) {
                Ordering::Equal => {}
                other => return other,
            }
        } else if self.clock_class.is_some() && other.clock_class.is_none() {
            return Ordering::Less; // We have clock class, other doesn't
        } else if self.clock_class.is_none() && other.clock_class.is_some() {
            return Ordering::Greater; // Other has clock class, we don't
        }

        // 3. Clock Accuracy comparison (lower is better)
        if let (Some(our_acc), Some(other_acc)) = (self.clock_accuracy, other.clock_accuracy) {
            match our_acc.accuracy.cmp(&other_acc.accuracy) {
                Ordering::Equal => {}
                other => return other,
            }
        } else if self.clock_accuracy.is_some() && other.clock_accuracy.is_none() {
            return Ordering::Less; // We have accuracy, other doesn't
        } else if self.clock_accuracy.is_none() && other.clock_accuracy.is_some() {
            return Ordering::Greater; // Other has accuracy, we don't
        }

        // 4. Offset Scaled Log Variance comparison (lower is better)
        if let (Some(our_var), Some(other_var)) = (
            self.offset_scaled_log_variance,
            other.offset_scaled_log_variance,
        ) {
            match our_var.cmp(&other_var) {
                Ordering::Equal => {}
                other => return other,
            }
        } else if self.offset_scaled_log_variance.is_some()
            && other.offset_scaled_log_variance.is_none()
        {
            return Ordering::Less; // We have variance, other doesn't
        } else if self.offset_scaled_log_variance.is_none()
            && other.offset_scaled_log_variance.is_some()
        {
            return Ordering::Greater; // Other has variance, we don't
        }

        // 5. Priority2 comparison (lower is better)
        if let (Some(our_p2), Some(other_p2)) = (self.priority2, other.priority2) {
            match our_p2.cmp(&other_p2) {
                Ordering::Equal => {}
                other => return other,
            }
        } else if self.priority2.is_some() && other.priority2.is_none() {
            return Ordering::Less; // We have priority2, other doesn't
        } else if self.priority2.is_none() && other.priority2.is_some() {
            return Ordering::Greater; // Other has priority2, we don't
        }

        // 6. Clock Identity comparison (lower is better - used as tiebreaker)
        our_clock_id.clock_id.cmp(&other_clock_id.clock_id)
    }
}

#[derive(Debug, Clone)]
pub struct PtpHostStateTimeReceiver {
    pub last_delay_response_origin_timestamp: Option<PtpTimestamp>,
    pub last_pdelay_response_origin_timestamp: Option<PtpTimestamp>,
    pub last_pdelay_follow_up_timestamp: Option<PtpTimestamp>,
    pub selected_transmitter_identity: Option<ClockIdentity>,
    pub selected_transmitter_confidence: f32, // 0.0 to 1.0 confidence score
}

impl Default for PtpHostStateTimeReceiver {
    fn default() -> Self {
        PtpHostStateTimeReceiver {
            last_delay_response_origin_timestamp: None,
            last_pdelay_response_origin_timestamp: None,
            last_pdelay_follow_up_timestamp: None,
            selected_transmitter_identity: None,
            selected_transmitter_confidence: 0.0,
        }
    }
}

impl PtpHostStateTimeReceiver {
    fn from_recent_sync_sender(recent_sync_sender: ClockIdentity, age: Duration) -> Self {
        let mut s = PtpHostStateTimeReceiver::default();
        s.update_from_recent_sync_sender(recent_sync_sender, age);
        s
    }

    fn update_from_recent_sync_sender(&mut self, recent_sync_sender: ClockIdentity, age: Duration) {
        if self.selected_transmitter_confidence < 1.0 {
            // We assume that the most recent sync sender in this domain is the chosen transmitter
            self.selected_transmitter_identity = Some(recent_sync_sender);

            // Map 0..5 seconds to confidence
            self.selected_transmitter_confidence =
                (age.as_millis() as f32 / 5000.0).clamp(0.0, 0.9);
        }
    }

    fn from_delay_resp(msg: &DelayRespMessage) -> Self {
        let mut s = PtpHostStateTimeReceiver::default();
        s.update_from_delay_resp(msg);
        s
    }

    fn update_from_delay_resp(&mut self, msg: &DelayRespMessage) {
        self.last_delay_response_origin_timestamp = Some(msg.receive_timestamp);
        self.selected_transmitter_identity = Some(msg.header.source_port_identity.clock_identity);
        self.selected_transmitter_confidence = 1.0;
    }

    fn from_pdelay_resp(msg: &PDelayRespMessage) -> Self {
        let mut s = PtpHostStateTimeReceiver::default();
        s.update_from_pdelay_resp(msg);
        s
    }

    fn update_from_pdelay_resp(&mut self, msg: &PDelayRespMessage) {
        self.last_pdelay_response_origin_timestamp = Some(msg.request_receipt_timestamp);
    }

    fn from_pdelay_resp_follow_up(msg: &PDelayRespFollowUpMessage) -> Self {
        let mut s = PtpHostStateTimeReceiver::default();
        s.update_from_pdelay_resp_follow_up(msg);
        s
    }

    fn update_from_pdelay_resp_follow_up(&mut self, msg: &PDelayRespFollowUpMessage) {
        self.last_pdelay_follow_up_timestamp = Some(msg.response_origin_timestamp);
    }
}

#[derive(Debug, Clone)]
pub enum PtpHostState {
    Listening,
    TimeTransmitter(PtpHostStateTimeTransmitter),
    TimeReceiver(PtpHostStateTimeReceiver),
}

impl Default for PtpHostState {
    fn default() -> Self {
        PtpHostState::Listening
    }
}

impl std::fmt::Display for PtpHostState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PtpHostState::Listening => write!(f, "Listening"),
            PtpHostState::TimeTransmitter(s) => {
                if s.is_bmca_winner {
                    write!(f, "Primary Time Transmitter")
                } else {
                    write!(f, "Time Transmitter")
                }
            }
            PtpHostState::TimeReceiver(_) => write!(f, "Time Receiver"),
        }
    }
}

impl PtpHostState {
    /// Transition to TimeTransmitter state
    fn update_from_announce(&mut self, announce: &AnnounceMessage) {
        match self {
            PtpHostState::TimeTransmitter(state) => {
                state.update_from_announce(announce);
            }
            _ => {
                *self = PtpHostState::TimeTransmitter(PtpHostStateTimeTransmitter::from_announce(
                    announce,
                ));
            }
        }
    }

    fn update_from_sync(&mut self, msg: &SyncMessage) {
        match self {
            PtpHostState::TimeTransmitter(state) => {
                state.update_from_sync(msg);
            }
            _ => {
                *self = PtpHostState::TimeTransmitter(PtpHostStateTimeTransmitter::from_sync(msg));
            }
        }
    }

    fn update_from_follow_up(&mut self, msg: &FollowUpMessage) {
        match self {
            PtpHostState::TimeTransmitter(state) => {
                state.update_from_follow_up(msg);
            }
            _ => {
                *self =
                    PtpHostState::TimeTransmitter(PtpHostStateTimeTransmitter::from_follow_up(msg));
            }
        }
    }

    // Transition to TimeReceiver state
    fn update_from_recent_sync_sender(&mut self, recent_sync_sender: ClockIdentity, age: Duration) {
        match self {
            PtpHostState::TimeReceiver(state) => {
                state.update_from_recent_sync_sender(recent_sync_sender, age);
            }
            _ => {
                *self = PtpHostState::TimeReceiver(
                    PtpHostStateTimeReceiver::from_recent_sync_sender(recent_sync_sender, age),
                );
            }
        }
    }

    fn update_from_delay_resp(&mut self, msg: &DelayRespMessage) {
        match self {
            PtpHostState::TimeReceiver(state) => {
                state.update_from_delay_resp(msg);
            }
            _ => {
                *self = PtpHostState::TimeReceiver(PtpHostStateTimeReceiver::from_delay_resp(msg));
            }
        }
    }

    fn update_from_pdelay_resp(&mut self, msg: &PDelayRespMessage) {
        match self {
            PtpHostState::TimeReceiver(state) => {
                state.update_from_pdelay_resp(msg);
            }
            _ => {
                *self = PtpHostState::TimeReceiver(PtpHostStateTimeReceiver::from_pdelay_resp(msg));
            }
        }
    }

    fn update_from_pdelay_resp_follow_up(&mut self, msg: &PDelayRespFollowUpMessage) {
        match self {
            PtpHostState::TimeReceiver(state) => {
                state.update_from_pdelay_resp_follow_up(msg);
            }
            _ => {
                *self = PtpHostState::TimeReceiver(
                    PtpHostStateTimeReceiver::from_pdelay_resp_follow_up(msg),
                );
            }
        }
    }

    pub fn short_string(&self) -> &str {
        match self {
            PtpHostState::Listening => "L",
            PtpHostState::TimeTransmitter(state) => {
                if state.is_bmca_winner {
                    "PTT"
                } else {
                    "TT"
                }
            }
            PtpHostState::TimeReceiver(_) => "TR",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PtpHost {
    pub clock_identity: ClockIdentity,
    pub ip_addresses: HashMap<IpAddr, Vec<String>>,
    pub domain_number: Option<u8>,
    pub last_version: Option<PtpVersion>,
    pub last_seen: Instant,

    pub announce_count: u32,
    pub sync_count: u32,
    pub follow_up_count: u32,
    pub delay_req_count: u32,
    pub delay_resp_count: u32,
    pub pdelay_req_count: u32,
    pub pdelay_resp_count: u32,
    pub pdelay_resp_follow_up_count: u32,
    pub total_messages_sent_count: u32,
    pub total_messages_received_count: u32,
    pub signaling_message_count: u32,
    pub management_message_count: u32,

    pub state: PtpHostState,
    pub last_correction_field: Option<PtpCorrectionField>,
    pub packet_history: BoundedVec<ProcessedPacket>,
}

impl PtpHost {
    pub fn new(clock_identity: ClockIdentity) -> Self {
        Self {
            clock_identity,
            ip_addresses: HashMap::new(),
            domain_number: None,
            last_seen: Instant::now(),

            announce_count: 0,
            sync_count: 0,
            follow_up_count: 0,
            delay_req_count: 0,
            delay_resp_count: 0,
            pdelay_req_count: 0,
            pdelay_resp_count: 0,
            pdelay_resp_follow_up_count: 0,
            total_messages_sent_count: 0,
            total_messages_received_count: 0,
            signaling_message_count: 0,
            management_message_count: 0,

            state: PtpHostState::Listening,
            last_version: None,
            last_correction_field: None,
            packet_history: BoundedVec::new(1000), // Default max history
        }
    }

    fn update_from_ptp_header(&mut self, header: &PtpHeader) {
        self.domain_number = Some(header.domain_number);
        self.last_version = Some(header.version);
        self.last_correction_field = Some(header.correction_field);
        self.last_seen = Instant::now();
    }

    pub fn get_vendor_name(&self) -> Option<&'static str> {
        self.clock_identity.extract_vendor_name()
    }

    pub fn is_transmitter(&self) -> bool {
        match self.state {
            PtpHostState::TimeTransmitter(_) => true,
            _ => false,
        }
    }

    pub fn is_receiver(&self) -> bool {
        match self.state {
            PtpHostState::TimeReceiver(_) => true,
            _ => false,
        }
    }

    pub fn time_since_last_seen(&self) -> Duration {
        Instant::now().duration_since(self.last_seen)
    }

    pub fn add_ip_address(&mut self, ip: IpAddr, interface: String) {
        self.ip_addresses.entry(ip).or_insert_with(|| Vec::new());

        let v = self.ip_addresses.get_mut(&ip).unwrap();

        if !v.contains(&interface) {
            v.push(interface);
        }
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

    pub fn has_local_ip(&self, local_ips: &[std::net::IpAddr]) -> bool {
        self.ip_addresses.keys().any(|ip| local_ips.contains(ip))
    }

    pub fn add_packet(&mut self, packet: ProcessedPacket) {
        self.packet_history.push(packet);
    }

    pub fn set_max_packet_history(&mut self, max_history: usize) {
        self.packet_history.max_size = max_history;
        // Truncate existing history if needed
        while self.packet_history.len() > max_history {
            self.packet_history.items.pop_front();
        }
    }

    pub fn get_packet_history(&self) -> Vec<ProcessedPacket> {
        self.packet_history.to_vec()
    }

    pub fn clear_packet_history(&mut self) {
        self.packet_history.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiple_ip_addresses() {
        use std::net::{IpAddr, Ipv4Addr};

        let mut host = PtpHost::new(ClockIdentity::default());

        host.add_ip_address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)), "eth1".to_string());

        // Initially should have one IP
        assert_eq!(host.get_ip_count(), 1);
        assert!(host.get_primary_ip().is_some());
        assert!(!host.has_multiple_ips());

        // Add a second IP with different address
        host.add_ip_address(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            "eth0".to_string(),
        );
        assert_eq!(host.get_ip_count(), 2);
        assert!(host.has_multiple_ips());

        // Adding the same IP again with different interface should not increase count
        host.add_ip_address(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)),
            "eth1-backup".to_string(),
        );
        assert_eq!(host.get_ip_count(), 2);

        // Add a third IP
        host.add_ip_address(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), "eth2".to_string());
        assert_eq!(host.get_ip_count(), 3);
        assert!(host.has_multiple_ips());
    }
}

pub struct PtpTracker {
    hosts: HashMap<ClockIdentity, PtpHost>,
    last_packet: Instant,
    raw_socket_receiver: crate::socket::RawSocketReceiver,
    // Track recent sync/follow-up senders per domain for transmitter-receiver correlation
    recent_sync_senders: HashMap<u8, Vec<(ClockIdentity, Instant)>>,
    // Track interfaces for determining inbound interface of packets
    interfaces: Vec<(String, std::net::Ipv4Addr)>,
}

impl PtpTracker {
    pub fn new(raw_socket_receiver: crate::socket::RawSocketReceiver) -> Result<Self> {
        let interfaces = raw_socket_receiver.get_interfaces().to_vec();
        Ok(Self {
            hosts: HashMap::new(),
            last_packet: Instant::now(),
            raw_socket_receiver,
            recent_sync_senders: HashMap::new(),
            interfaces,
        })
    }

    pub async fn scan_network(&mut self) {
        self.process_ptp_messages().await;
        self.cleanup_old_sync_senders();
        self.run_bmca_election();
    }

    async fn process_ptp_messages(&mut self) {
        // Process packets from raw socket capture
        for _ in 0..100 {
            // Limit iterations to prevent blocking too long
            match self.raw_socket_receiver.try_recv() {
                Some(raw_packet) => {
                    self.handle_raw_packet(&raw_packet).await;
                    self.last_packet = Instant::now();
                }
                None => {
                    // No more packets available
                    break;
                }
            }
        }
    }

    async fn handle_raw_packet(&mut self, raw_packet: &crate::socket::RawPacket) {
        let msg = match PtpMessage::try_from(raw_packet.ptp_payload.as_slice()) {
            Ok(m) => m,
            Err(_) => return, // Invalid message
        };

        // Create packet info for recording
        let packet = ProcessedPacket {
            ptp_message: msg,
            timestamp: std::time::Instant::now(),
            vlan_id: raw_packet.vlan_id,
            source_ip: raw_packet.source_addr.ip(),
            source_port: raw_packet.source_addr.port(),
            interface: raw_packet.interface_name.clone(),
            _raw_packet_data: raw_packet.data.clone(),
        };

        let sending_host = self
            .hosts
            .entry(msg.header().source_port_identity.clock_identity)
            .or_insert_with(|| PtpHost::new(msg.header().source_port_identity.clock_identity));

        // Add this IP address if it's not already known for this host
        sending_host.add_ip_address(raw_packet.source_addr.ip(), packet.interface.clone());

        sending_host.total_messages_sent_count += 1;
        sending_host.update_from_ptp_header(msg.header());
        sending_host.add_packet(packet.clone());

        match msg {
            PtpMessage::Announce(msg) => {
                sending_host.announce_count += 1;
                sending_host.state.update_from_announce(&msg);
            }
            PtpMessage::Sync(msg) => {
                sending_host.sync_count += 1;
                sending_host.state.update_from_sync(&msg);

                // Record this as a recent sync sender for this domain
                let domain_senders = self
                    .recent_sync_senders
                    .entry(msg.header.domain_number)
                    .or_insert_with(Vec::new);

                let now = std::time::Instant::now();
                if let Some(existing) = domain_senders
                    .iter_mut()
                    .find(|(id, _)| id == &msg.header.source_port_identity.clock_identity)
                {
                    existing.1 = now;
                } else {
                    domain_senders.push((msg.header.source_port_identity.clock_identity, now));
                }
            }
            PtpMessage::DelayReq(msg) => {
                sending_host.delay_req_count += 1;

                let now = std::time::Instant::now();
                if let Some(domain_senders) =
                    self.recent_sync_senders.get(&msg.header.domain_number)
                {
                    // Find the most recent sync sender and determine the age of the last sync
                    if let Some((clock_identity, sync_time)) = domain_senders
                        .iter()
                        .max_by_key(|(_, timestamp)| *timestamp)
                    {
                        let age = now.duration_since(*sync_time);

                        sending_host
                            .state
                            .update_from_recent_sync_sender(*clock_identity, age);
                    }
                }
            }
            PtpMessage::DelayResp(msg) => {
                sending_host.delay_resp_count += 1;

                let receiving_host = self
                    .hosts
                    .entry(msg.requesting_port_identity.clock_identity)
                    .or_insert_with(|| PtpHost::new(msg.requesting_port_identity.clock_identity));

                receiving_host.delay_resp_count += 1;
                receiving_host.total_messages_received_count += 1;
                receiving_host.state.update_from_delay_resp(&msg);
                receiving_host.add_packet(packet.clone());
            }
            PtpMessage::PDelayReq(_) => {
                sending_host.pdelay_req_count += 1;
                // PDelay requests are used for peer-to-peer delay measurement
                // In P2P mode, each node measures delay with its neighbors directly
                // Could extract timing information if needed for analysis
                sending_host.pdelay_req_count += 1;
            }
            PtpMessage::PDelayResp(msg) => {
                // PDelay responses are sent in response to PDelay requests
                // These contain receive and transmit timestamps for delay calculation
                // Like PDelayReq, they don't indicate transmitter-receiver relationship

                sending_host.pdelay_resp_count += 1;

                let receiving_host = self
                    .hosts
                    .entry(msg.requesting_port_identity.clock_identity)
                    .or_insert_with(|| PtpHost::new(msg.requesting_port_identity.clock_identity));

                receiving_host.pdelay_resp_count += 1;
                receiving_host.total_messages_received_count += 1;
                receiving_host.state.update_from_pdelay_resp(&msg);

                receiving_host.add_packet(packet);
            }
            PtpMessage::PDelayRespFollowup(msg) => {
                sending_host.pdelay_resp_follow_up_count += 1;
                // PDelay response follow-up messages provide precise transmit timestamps
                // for peer delay measurements in two-step mode. This completes the
                // peer delay measurement cycle: PDelayReq -> PDelayResp -> PDelayRespFollowUp
                let receiving_host = self
                    .hosts
                    .entry(msg.requesting_port_identity.clock_identity)
                    .or_insert_with(|| PtpHost::new(msg.requesting_port_identity.clock_identity));

                receiving_host.pdelay_resp_follow_up_count += 1;
                receiving_host.total_messages_received_count += 1;
                receiving_host.state.update_from_pdelay_resp_follow_up(&msg);
                receiving_host.add_packet(packet);
            }
            PtpMessage::FollowUp(msg) => {
                sending_host.follow_up_count += 1;
                sending_host.state.update_from_follow_up(&msg);
            }
            PtpMessage::Signaling(_) => {
                sending_host.signaling_message_count += 1;
            }
            PtpMessage::Management(_) => {
                sending_host.management_message_count += 1;
            }
        }

        self.last_packet = std::time::Instant::now();
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
                _ => std::cmp::Ordering::Equal,
            }
        });
        hosts
    }

    pub fn get_host_by_clock_identity(&self, clock_identity: &ClockIdentity) -> Option<&PtpHost> {
        self.hosts
            .values()
            .find(|h| h.clock_identity == *clock_identity)
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

    pub fn set_max_packet_history(&mut self, max_history: usize) {
        for host in self.hosts.values_mut() {
            host.set_max_packet_history(max_history);
        }
    }

    pub fn get_host_packet_history(
        &self,
        clock_identity: ClockIdentity,
    ) -> Option<Vec<ProcessedPacket>> {
        self.hosts
            .get(&clock_identity)
            .map(|host| host.get_packet_history())
    }

    pub fn clear_host_packet_history(&mut self, clock_identity: ClockIdentity) {
        if let Some(host) = self.hosts.get_mut(&clock_identity) {
            host.clear_packet_history();
        }
    }

    pub fn clear_all_packet_histories(&mut self) {
        for host in self.hosts.values_mut() {
            host.clear_packet_history();
        }
    }

    pub fn get_local_ips(&self) -> Vec<std::net::IpAddr> {
        self.interfaces
            .iter()
            .map(|(_, ip)| std::net::IpAddr::V4(*ip))
            .collect()
    }

    /// Run the Best Master Clock Algorithm (BMCA) election to determine the best transmitter in each domain
    ///
    /// This implements IEEE 1588 BMCA which compares transmitters using the following criteria (in order):
    /// 1. Priority1 (lower is better)
    /// 2. Clock Class (lower is better)
    /// 3. Clock Accuracy (lower is better)
    /// 4. Offset Scaled Log Variance (lower is better)
    /// 5. Priority2 (lower is better)
    /// 6. Clock Identity (lower is better, used as tiebreaker)
    ///
    /// The algorithm:
    /// - Groups all transmitters by domain number
    /// - For each domain with multiple transmitters, runs pairwise comparisons
    /// - Marks the best transmitter as the BMCA winner (shown as "PT" in UI)
    /// - Updates all receivers in the domain to select the BMCA winner
    ///
    /// Transmitters missing announce message data are considered inferior to those with complete data.
    pub fn run_bmca_election(&mut self) {
        use std::collections::HashMap;

        // Group transmitters by domain
        let mut domain_transmitters: HashMap<u8, Vec<ClockIdentity>> = HashMap::new();

        for (clock_id, host) in &self.hosts {
            if let (Some(domain), PtpHostState::TimeTransmitter(_)) =
                (host.domain_number, &host.state)
            {
                domain_transmitters
                    .entry(domain)
                    .or_insert_with(Vec::new)
                    .push(*clock_id);
            }
        }

        // For each domain, find the best transmitter using BMCA
        for (domain, transmitters) in domain_transmitters {
            if transmitters.is_empty() {
                continue;
            }

            // Only log BMCA elections when there are multiple transmitters competing
            let log_election = transmitters.len() > 1;

            // Reset all winners in this domain first
            for clock_id in &transmitters {
                if let Some(host) = self.hosts.get_mut(clock_id) {
                    if let PtpHostState::TimeTransmitter(ref mut state) = host.state {
                        state.is_bmca_winner = false;
                    }
                }
            }

            // Find the best transmitter by comparing all pairs
            let mut best_clock_id = transmitters[0];

            for &candidate_clock_id in &transmitters[1..] {
                if let (Some(best_host), Some(candidate_host)) = (
                    self.hosts.get(&best_clock_id),
                    self.hosts.get(&candidate_clock_id),
                ) {
                    if let (
                        PtpHostState::TimeTransmitter(ref best_state),
                        PtpHostState::TimeTransmitter(ref candidate_state),
                    ) = (&best_host.state, &candidate_host.state)
                    {
                        let comparison_result = candidate_state.compare_for_bmca(
                            best_state,
                            candidate_clock_id,
                            best_clock_id,
                        );

                        if comparison_result == std::cmp::Ordering::Less {
                            best_clock_id = candidate_clock_id;
                        }
                    }
                }
            }

            // Mark the winner
            if let Some(winner_host) = self.hosts.get_mut(&best_clock_id) {
                if let PtpHostState::TimeTransmitter(ref mut state) = winner_host.state {
                    state.is_bmca_winner = true;
                    if log_election {
                        eprintln!(
                            "BMCA: Domain {} winner: {} (Primary Time Transmitter)",
                            domain, best_clock_id
                        );
                    }
                }
            }

            // Update receivers in this domain to select the BMCA winner as their transmitter
            self.update_receivers_for_domain(domain, best_clock_id);
        }
    }

    /// Update all receivers in a domain to select the BMCA winner as their transmitter
    fn update_receivers_for_domain(&mut self, domain: u8, winner_clock_id: ClockIdentity) {
        for host in self.hosts.values_mut() {
            if host.domain_number == Some(domain) {
                if let PtpHostState::TimeReceiver(ref mut receiver_state) = host.state {
                    receiver_state.selected_transmitter_identity = Some(winner_clock_id);
                    receiver_state.selected_transmitter_confidence = 1.0; // High confidence from BMCA
                }
            }
        }
    }
}

#[cfg(test)]
mod bmca_tests {
    use super::*;
    use crate::types::{PtpClockAccuracy, PtpClockClass};

    fn create_test_transmitter_state() -> PtpHostStateTimeTransmitter {
        PtpHostStateTimeTransmitter {
            priority1: Some(128),
            priority2: Some(128),
            clock_class: Some(PtpClockClass::new(6)),
            clock_accuracy: Some(PtpClockAccuracy::new(0x20)),
            offset_scaled_log_variance: Some(0x4E5D),
            steps_removed: Some(0),
            time_source: Some(0x20),
            ..Default::default()
        }
    }

    fn create_test_clock_identity(id: u64) -> ClockIdentity {
        ClockIdentity {
            clock_id: [
                (id >> 56) as u8,
                (id >> 48) as u8,
                (id >> 40) as u8,
                (id >> 32) as u8,
                (id >> 24) as u8,
                (id >> 16) as u8,
                (id >> 8) as u8,
                id as u8,
            ],
        }
    }

    #[test]
    fn test_bmca_priority1_comparison() {
        let mut state1 = create_test_transmitter_state();
        let mut state2 = create_test_transmitter_state();

        state1.priority1 = Some(64);
        state2.priority1 = Some(128);

        let clock1 = create_test_clock_identity(1);
        let clock2 = create_test_clock_identity(2);

        // Lower priority1 should win
        assert_eq!(
            state1.compare_for_bmca(&state2, clock1, clock2),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            state2.compare_for_bmca(&state1, clock2, clock1),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn test_bmca_clock_class_comparison() {
        let mut state1 = create_test_transmitter_state();
        let mut state2 = create_test_transmitter_state();

        // Same priority1, different clock class
        state1.priority1 = Some(128);
        state2.priority1 = Some(128);
        state1.clock_class = Some(PtpClockClass::new(6)); // Better (lower)
        state2.clock_class = Some(PtpClockClass::new(7)); // Worse (higher)

        let clock1 = create_test_clock_identity(1);
        let clock2 = create_test_clock_identity(2);

        // Lower clock class should win
        assert_eq!(
            state1.compare_for_bmca(&state2, clock1, clock2),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn test_bmca_clock_identity_tiebreaker() {
        let state1 = create_test_transmitter_state();
        let state2 = create_test_transmitter_state();

        // Identical parameters, should use clock identity as tiebreaker
        let clock1 = create_test_clock_identity(0x0000000000000001);
        let clock2 = create_test_clock_identity(0x0000000000000002);

        // Lower clock identity should win
        assert_eq!(
            state1.compare_for_bmca(&state2, clock1, clock2),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            state2.compare_for_bmca(&state1, clock2, clock1),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn test_bmca_missing_data_handling() {
        let mut state1 = create_test_transmitter_state();
        let mut state2 = create_test_transmitter_state();

        // State1 has priority1, state2 doesn't
        state1.priority1 = Some(128);
        state2.priority1 = None;

        let clock1 = create_test_clock_identity(1);
        let clock2 = create_test_clock_identity(2);

        // Having data should be better than not having data
        assert_eq!(
            state1.compare_for_bmca(&state2, clock1, clock2),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            state2.compare_for_bmca(&state1, clock2, clock1),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn test_bmca_winner_flag() {
        let mut state = create_test_transmitter_state();
        assert!(!state.is_bmca_winner);

        state.is_bmca_winner = true;
        assert!(state.is_bmca_winner);
    }
}
