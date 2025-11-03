//! Cross-platform raw socket implementation for PTP and gPTP traffic capture
//!
//! This module implements packet capture using pnet for cross-platform
//! promiscuous mode support. Works on Linux, macOS, and Windows.
//! Supports both PTP over UDP (Layer 3) and gPTP over Ethernet (Layer 2).

use anyhow::Result;
use pnet::datalink::{self, Channel, Config};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;
use tokio::sync::mpsc;
use tokio::time::Duration;

const PTP_EVENT_PORT: u16 = 319;
const PTP_GENERAL_PORT: u16 = 320;
const PTP_MULTICAST_ADDR: &str = "224.0.1.129";
/// gPTP (generalized Precision Time Protocol) EtherType for Layer 2 transport
const GPTP_ETHERTYPE: u16 = 0x88f7;
/// gPTP multicast MAC address (IEEE 802.1AS)
const GPTP_MULTICAST_MAC: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e];

type InterfaceSourceType = (String, Option<Ipv4Addr>, Option<u16>);

#[derive(Debug, Clone)]
pub struct RawPacket {
    pub timestamp: std::time::SystemTime,
    pub data: Vec<u8>,
    pub source_addr: Option<std::net::SocketAddr>,
    pub source_mac: [u8; 6],
    pub dest_addr: Option<std::net::SocketAddr>,
    pub dest_mac: [u8; 6],
    pub vlan_id: Option<u16>,
    pub ttl: Option<u8>,
    pub interface_name: String,
    pub ptp_payload: Vec<u8>,
}

pub enum PacketSource {
    Socket {
        receiver: mpsc::UnboundedReceiver<RawPacket>,
        interfaces: Vec<InterfaceSourceType>,
        _multicast_sockets: Vec<Socket>,
    },
    Pcap {
        packets: Vec<RawPacket>,
        current_index: usize,
        last_timestamp: Option<SystemTime>,
    },
}

pub struct RawSocketReceiver {
    source: PacketSource,
}

impl RawSocketReceiver {
    pub fn try_recv(&mut self) -> Option<RawPacket> {
        match &mut self.source {
            PacketSource::Socket { receiver, .. } => receiver.try_recv().ok(),
            PacketSource::Pcap {
                packets,
                current_index,
                ..
            } => {
                if *current_index < packets.len() {
                    let packet = packets[*current_index].clone();
                    *current_index += 1;
                    Some(packet)
                } else {
                    None
                }
            }
        }
    }

    pub fn get_interfaces(&self) -> &[InterfaceSourceType] {
        match &self.source {
            PacketSource::Socket { interfaces, .. } => interfaces,
            PacketSource::Pcap { .. } => &[],
        }
    }

    pub fn get_last_timestamp(&self) -> Option<SystemTime> {
        match &self.source {
            PacketSource::Socket { .. } => None,
            PacketSource::Pcap { last_timestamp, .. } => *last_timestamp,
        }
    }
}

fn iface_addrs_by_name(ifname: &str) -> io::Result<Option<Ipv4Addr>> {
    let mut v4: Option<Ipv4Addr> = None;

    for iface in if_addrs::get_if_addrs().map_err(io::Error::other)? {
        if iface.name == ifname {
            match iface.addr {
                if_addrs::IfAddr::V4(a) if v4.is_none() => v4 = Some(a.ip),
                _ => {}
            }
        }
    }
    Ok(v4)
}

fn get_all_interface_addrs() -> io::Result<Vec<InterfaceSourceType>> {
    let mut interfaces = Vec::new();

    // Get available interfaces using pnet datalink
    let all_interfaces = datalink::interfaces();

    for iface in all_interfaces {
        // Skip loopback interfaces
        if iface.is_loopback() {
            continue;
        }

        let interface_name = iface.name.clone();
        let native_vlan_id: Option<u16> = None;

        // Get IPv4 addresses for this interface
        for ip in &iface.ips {
            if let IpAddr::V4(ipv4) = ip.ip() {
                if !ipv4.is_loopback() && is_suitable_interface_name(&interface_name) {
                    interfaces.push((interface_name.clone(), Some(ipv4), native_vlan_id));
                    break; // Only take first IPv4 address per interface
                } else {
                    println!("Excluding interface: {} (filtered)", interface_name);
                }
            }
        }
    }

    if interfaces.is_empty() {
        println!("Warning: No suitable interfaces found.");
        println!(
            "Consider specifying interfaces manually with --interface (e.g., --interface eth0)"
        );
    }

    Ok(interfaces)
}

fn is_suitable_interface_name(interface_name: &str) -> bool {
    // Skip common virtual interface patterns
    let virtual_prefixes = [
        "veth", "docker", "br-", "virbr", "vmnet", "tun", "tap", "wg", "dummy", "bond", "team",
        "macvlan", "vlan", "lo", "flannel", "cni0", "wg", "wl", "wlan", "ww", "idrac",
    ];

    for prefix in &virtual_prefixes {
        if interface_name.starts_with(prefix) {
            return false;
        }
    }

    true
}

fn join_multicast_group(interface_name: &str, interface_addr: Ipv4Addr) -> Result<Socket> {
    // Create socket to join the multicast group - keep it alive to maintain membership
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;

    let multicast_addr: Ipv4Addr = PTP_MULTICAST_ADDR.parse()?;

    // Join multicast group once per interface (same IP for both PTP ports)
    socket
        .join_multicast_v4(&multicast_addr, &interface_addr)
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to join multicast group on interface {}: {}",
                interface_name,
                e
            )
        })?;

    println!(
        "Joined PTP multicast group {} on interface {} ({})",
        PTP_MULTICAST_ADDR, interface_name, interface_addr
    );

    Ok(socket)
}

fn process_ethernet_packet(
    packet_data: &[u8],
    interface_name: &str,
    native_vlan_id: Option<u16>,
) -> Option<RawPacket> {
    let ethernet = EthernetPacket::new(packet_data)?;

    let mut vlan_id: Option<u16> = None;
    let mut payload_data = ethernet.payload();
    let mut ethertype = ethernet.get_ethertype();

    // Handle VLAN tags (802.1Q and 802.1ad QinQ)
    if ethertype == EtherTypes::Vlan {
        if payload_data.len() < 4 {
            return None;
        }
        // Extract VLAN ID from the outer VLAN tag (first 12 bits of the TCI field)
        vlan_id = Some(u16::from_be_bytes([payload_data[0], payload_data[1]]) & 0x0FFF);
        // Get the inner EtherType
        let inner_ethertype_val = u16::from_be_bytes([payload_data[2], payload_data[3]]);
        ethertype = if inner_ethertype_val == 0x0800 {
            EtherTypes::Ipv4
        } else if inner_ethertype_val == 0x8100 {
            // Double VLAN tag (QinQ) - skip inner VLAN tag
            EtherTypes::Vlan
        } else {
            return None; // Only handle IPv4 for now
        };
        // Skip the outer VLAN header (4 bytes)
        payload_data = &payload_data[4..];

        // Handle inner VLAN tag if present (QinQ)
        if ethertype == EtherTypes::Vlan {
            if payload_data.len() < 4 {
                return None;
            }
            // For QinQ, we keep the outer VLAN ID but could extract inner if needed
            // Inner VLAN ID: u16::from_be_bytes([payload_data[0], payload_data[1]]) & 0x0FFF
            let inner_inner_ethertype_val = u16::from_be_bytes([payload_data[2], payload_data[3]]);
            ethertype = if inner_inner_ethertype_val == 0x0800 {
                EtherTypes::Ipv4
            } else {
                return None; // Only handle IPv4 for now
            };
            // Skip the inner VLAN header (4 bytes)
            payload_data = &payload_data[4..];
        }
    }

    // Check if this is gPTP (Layer 2) or PTP over UDP (Layer 3)
    if ethertype.0 == GPTP_ETHERTYPE {
        // Handle gPTP (IEEE 802.1AS - Layer 2 transport)
        // gPTP uses Ethernet frames directly without IP/UDP encapsulation
        let source_mac = ethernet.get_source().octets();
        let dest_mac = ethernet.get_destination().octets();

        // Optional filtering: accept gPTP multicast or any unicast gPTP traffic
        // gPTP typically uses multicast address 01:80:c2:00:00:0e but can also be unicast
        if dest_mac != GPTP_MULTICAST_MAC && dest_mac[0] & 0x01 == 0x01 {
            // Skip non-gPTP multicast packets (but allow unicast)
            return None;
        }

        // For gPTP, we don't have IP addresses, so use None
        let source_addr = None;
        let dest_addr = None;

        // gPTP payload starts directly after ethernet header (and VLAN if present)
        let ptp_payload = payload_data.to_vec();

        Some(RawPacket {
            timestamp: SystemTime::now(),
            data: packet_data.to_vec(),
            source_addr,
            source_mac,
            dest_addr,
            dest_mac,
            vlan_id: vlan_id.or(native_vlan_id),
            ttl: None, // No TTL in Layer 2
            interface_name: interface_name.to_string(),
            ptp_payload,
        })
    } else if ethertype == EtherTypes::Ipv4 {
        // Handle PTP over UDP (existing code)
        let ipv4_packet = Ipv4Packet::new(payload_data)?;

        // Check if this is UDP
        if ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
            return None;
        }

        let udp_packet = UdpPacket::new(ipv4_packet.payload())?;

        // Filter for PTP ports
        let dest_port = udp_packet.get_destination();
        if dest_port != PTP_EVENT_PORT && dest_port != PTP_GENERAL_PORT {
            return None;
        }

        let ttl = Some(ipv4_packet.get_ttl());

        let source_mac = ethernet.get_source().octets();
        let dest_mac = ethernet.get_destination().octets();
        let source_ip = ipv4_packet.get_source();
        let dest_ip = ipv4_packet.get_destination();
        let source_port = udp_packet.get_source();

        let source_addr = Some(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            source_ip,
            source_port,
        )));
        let dest_addr = Some(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            dest_ip, dest_port,
        )));

        // Extract PTP payload
        let ptp_payload = udp_packet.payload().to_vec();

        Some(RawPacket {
            timestamp: SystemTime::now(),
            data: packet_data.to_vec(),
            source_addr,
            source_mac,
            dest_addr,
            dest_mac,
            vlan_id: vlan_id.or(native_vlan_id),
            ttl,
            interface_name: interface_name.to_string(),
            ptp_payload,
        })
    } else {
        // Not PTP or gPTP
        None
    }
}

async fn capture_on_interface(
    interface_name: String,
    native_vlan_id: Option<u16>,
    sender: mpsc::UnboundedSender<RawPacket>,
    _multicast_socket: Socket,
) -> Result<()> {
    // Find the interface
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .ok_or_else(|| anyhow::anyhow!("Interface {} not found", interface_name))?;

    // Create datalink channel
    let config = Config::default();
    let (_, mut rx) = match datalink::channel(&interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            return Err(anyhow::anyhow!(
                "Unsupported channel type for interface {}",
                interface_name
            ));
        }
        Err(e) => {
            eprintln!(
                "Failed to open datalink channel on interface {}: {}",
                interface_name, e
            );
            return Err(anyhow::anyhow!(
                "Failed to open datalink channel on {}: {}",
                interface_name,
                e
            ));
        }
    };

    loop {
        match rx.next() {
            Ok(packet_data) => {
                if let Some(raw_packet) =
                    process_ethernet_packet(packet_data, &interface_name, native_vlan_id)
                    && sender.send(raw_packet).is_err()
                {
                    // Receiver has been dropped, exit the loop
                    break;
                }
            }
            Err(e) => {
                eprintln!("Error capturing packet on {}: {}", interface_name, e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        // Yield to other tasks every packet to prevent monopolizing CPU
        tokio::task::yield_now().await;
    }

    Ok(())
}

pub async fn create_raw_socket_receiver(ifnames: &[String]) -> Result<RawSocketReceiver> {
    // Get interfaces to monitor
    let target_interfaces = if ifnames.is_empty() {
        // Default to all available interfaces
        get_all_interface_addrs()?
    } else {
        // Use specified interfaces
        let mut interfaces = Vec::new();
        for ifname in ifnames {
            let parts: Vec<&str> = ifname.split(",").collect();
            let mut native_vlan_id: Option<u16> = None;
            let mut ifname_clone = ifname.clone();

            if parts.len() > 1 {
                ifname_clone = parts[0].to_string().clone();
                native_vlan_id = parts[1].parse::<u16>().ok();
            }

            let iface_v4 = iface_addrs_by_name(&ifname_clone)?;

            interfaces.push((ifname_clone, iface_v4, native_vlan_id));
        }
        interfaces
    };

    if target_interfaces.is_empty() {
        return Err(anyhow::anyhow!(
            "No suitable interfaces available for PTP monitoring"
        ));
    }

    println!(
        "Starting live capture on: {}",
        target_interfaces
            .iter()
            .map(|(name, _, vlan_id)| format!(
                "{0}({1})",
                name.as_str(),
                vlan_id.unwrap_or_default()
            ))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let (sender, receiver) = mpsc::unbounded_channel();

    // Set up multicast group membership and start packet capture for each interface
    let mut multicast_sockets = Vec::new();
    for (interface_name, interface_addr, native_vlan_id) in &target_interfaces {
        let sender_clone = sender.clone();
        let interface_name_clone = interface_name.clone();
        let native_vlan_id_clone = *native_vlan_id;

        // Try to join multicast group if interface has an IP address
        let multicast_socket = if let Some(interface_addr) = interface_addr {
            match join_multicast_group(interface_name, *interface_addr) {
                Ok(socket) => {
                    let socket_clone = socket.try_clone().unwrap();
                    multicast_sockets.push(socket);
                    socket_clone
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Could not join multicast group on {}: {}",
                        interface_name, e
                    );
                    // Create a dummy socket for interfaces without multicast capability
                    Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::DGRAM,
                        Some(socket2::Protocol::UDP),
                    )
                    .unwrap()
                }
            }
        } else {
            println!("Registered {} for generic socket", interface_name);
            // Create a dummy socket for interfaces without IP addresses
            Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .unwrap()
        };

        tokio::spawn(async move {
            // Stagger startup to reduce resource contention
            tokio::time::sleep(Duration::from_millis(200)).await;

            if let Err(e) = capture_on_interface(
                interface_name_clone.clone(),
                native_vlan_id_clone,
                sender_clone,
                multicast_socket,
            )
            .await
            {
                eprintln!("Packet capture error on {}: {}", interface_name_clone, e);
            }
        });
    }

    Ok(RawSocketReceiver {
        source: PacketSource::Socket {
            receiver,
            interfaces: target_interfaces,
            _multicast_sockets: multicast_sockets,
        },
    })
}

pub async fn create_pcap_receiver(pcap_path: &str) -> Result<RawSocketReceiver> {
    use pcap_file::pcap::PcapReader;
    use pcap_file::pcapng::PcapNgReader;
    use std::fs::File;

    let mut packets: Vec<RawPacket> = Vec::new();
    let mut last_timestamp: Option<SystemTime> = None;

    let file = File::open(pcap_path)?;

    // Try to read as PCAPNG first, then as regular PCAP
    if let Ok(mut pcapng_reader) = PcapNgReader::new(file) {
        println!("Reading as PCAPNG format");

        while let Some(block) = pcapng_reader.next_block() {
            match block {
                Ok(pcap_file::pcapng::Block::EnhancedPacket(epb)) => {
                    let packet_data = epb.data;
                    if let Some(raw_packet) = process_ethernet_packet(&packet_data, "pcap", None) {
                        if last_timestamp.is_none()
                            || raw_packet.timestamp > last_timestamp.unwrap()
                        {
                            last_timestamp = Some(raw_packet.timestamp);
                        }
                        packets.push(raw_packet);
                    }
                }
                Ok(pcap_file::pcapng::Block::SimplePacket(spb)) => {
                    let packet_data = spb.data;
                    if let Some(raw_packet) = process_ethernet_packet(&packet_data, "pcap", None) {
                        if last_timestamp.is_none()
                            || raw_packet.timestamp > last_timestamp.unwrap()
                        {
                            last_timestamp = Some(raw_packet.timestamp);
                        }
                        packets.push(raw_packet);
                    }
                }
                Ok(_) => {
                    // Other block types (section header, interface description, etc.)
                    continue;
                }
                Err(e) => {
                    eprintln!("Error reading PCAPNG block: {}", e);
                    break;
                }
            }
        }
    } else {
        println!("Failed to read as PCAPNG, trying regular PCAP format");

        // Re-open file for PCAP reading
        let file = File::open(pcap_path)?;
        let mut pcap_reader = PcapReader::new(file)?;

        while let Some(pkt) = pcap_reader.next_packet() {
            match pkt {
                Ok(packet) => {
                    let packet_data = packet.data;
                    if let Some(raw_packet) = process_ethernet_packet(&packet_data, "pcap", None) {
                        if last_timestamp.is_none()
                            || raw_packet.timestamp > last_timestamp.unwrap()
                        {
                            last_timestamp = Some(raw_packet.timestamp);
                        }
                        packets.push(raw_packet);
                    }
                }
                Err(e) => {
                    eprintln!("Error reading PCAP packet: {}", e);
                    break;
                }
            }
        }
    }

    println!(
        "Loaded {} PTP packets from pcap file: {}",
        packets.len(),
        pcap_path
    );

    Ok(RawSocketReceiver {
        source: PacketSource::Pcap {
            packets,
            current_index: 0,
            last_timestamp,
        },
    })
}
