//! Cross-platform raw socket implementation for PTP traffic capture
//!
//! This module implements packet capture using pnet for cross-platform
//! promiscuous mode support. Works on Linux, macOS, and Windows.

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

#[derive(Debug, Clone)]
pub struct RawPacket {
    pub timestamp: std::time::SystemTime,
    pub data: Vec<u8>,
    pub source_addr: std::net::SocketAddr,
    pub source_mac: [u8; 6],
    pub dest_addr: std::net::SocketAddr,
    pub dest_mac: [u8; 6],
    pub vlan_id: Option<u16>,
    pub interface_name: String,
    pub ptp_payload: Vec<u8>,
}

pub enum PacketSource {
    Socket {
        receiver: mpsc::UnboundedReceiver<RawPacket>,
        interfaces: Vec<(String, Ipv4Addr)>,
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

    pub fn get_interfaces(&self) -> &[(String, Ipv4Addr)] {
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

fn get_all_interface_addrs() -> io::Result<Vec<(String, Ipv4Addr)>> {
    let mut interfaces = Vec::new();

    // Get available interfaces using pnet datalink
    let all_interfaces = datalink::interfaces();

    for iface in all_interfaces {
        // Skip loopback interfaces
        if iface.is_loopback() {
            continue;
        }

        let interface_name = iface.name.clone();

        // Get IPv4 addresses for this interface
        for ip in &iface.ips {
            if let IpAddr::V4(ipv4) = ip.ip() {
                if !ipv4.is_loopback() && is_suitable_interface_name(&interface_name) {
                    interfaces.push((interface_name.clone(), ipv4));
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

fn process_ethernet_packet(packet_data: &[u8], interface_name: &str) -> Option<RawPacket> {
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

    // Check if this is an IPv4 packet
    if ethertype != EtherTypes::Ipv4 {
        return None;
    }

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

    let source_mac = ethernet.get_source().octets();
    let dest_mac = ethernet.get_destination().octets();
    let source_ip = ipv4_packet.get_source();
    let dest_ip = ipv4_packet.get_destination();
    let source_port = udp_packet.get_source();

    let source_addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(source_ip, source_port));
    let dest_addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(dest_ip, dest_port));

    // Extract PTP payload
    let ptp_payload = udp_packet.payload().to_vec();

    Some(RawPacket {
        timestamp: SystemTime::now(),
        data: packet_data.to_vec(),
        source_addr,
        source_mac,
        dest_addr,
        dest_mac,
        vlan_id,
        interface_name: interface_name.to_string(),
        ptp_payload,
    })
}

async fn capture_on_interface(
    interface_name: String,
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
                if let Some(raw_packet) = process_ethernet_packet(packet_data, &interface_name) {
                    if sender.send(raw_packet).is_err() {
                        // Receiver has been dropped, exit the loop
                        break;
                    }
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

pub async fn create_receiver(ifnames: &[String]) -> Result<RawSocketReceiver> {
    // Get interfaces to monitor
    let target_interfaces = if ifnames.is_empty() {
        // Default to all available interfaces
        get_all_interface_addrs()?
    } else {
        // Use specified interfaces
        let mut interfaces = Vec::new();
        for ifname in ifnames {
            let iface_v4 = iface_addrs_by_name(ifname)?;
            let iface_v4 = iface_v4.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("iface {} has no IPv4", ifname),
                )
            })?;
            interfaces.push((ifname.clone(), iface_v4));
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
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let (sender, receiver) = mpsc::unbounded_channel();

    // Set up multicast group membership for each interface
    let mut multicast_sockets = Vec::new();
    for (interface_name, interface_addr) in &target_interfaces {
        // Join multicast groups and keep sockets alive
        match join_multicast_group(interface_name, *interface_addr) {
            Ok(socket) => multicast_sockets.push(socket),
            Err(e) => {
                eprintln!(
                    "Warning: Could not join multicast group on {}: {}",
                    interface_name, e
                );
            }
        }
    }

    // Start packet capture on each interface
    for (i, (interface_name, _)) in target_interfaces.iter().enumerate() {
        let sender_clone = sender.clone();
        let interface_name_clone = interface_name.clone();
        let multicast_socket = multicast_sockets[i].try_clone().unwrap();
        tokio::spawn(async move {
            // Stagger startup to reduce resource contention
            tokio::time::sleep(Duration::from_millis(200)).await;

            if let Err(e) =
                capture_on_interface(interface_name_clone.clone(), sender_clone, multicast_socket)
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

pub async fn create_pcap(pcap_path: &str) -> Result<RawSocketReceiver> {
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
                    if let Some(raw_packet) = process_ethernet_packet(&packet_data, "pcap") {
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
                    if let Some(raw_packet) = process_ethernet_packet(&packet_data, "pcap") {
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
                    if let Some(raw_packet) = process_ethernet_packet(&packet_data, "pcap") {
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

    if let Some(last_ts) = last_timestamp {
        println!("Last packet timestamp: {:?}", last_ts);
    }

    Ok(RawSocketReceiver {
        source: PacketSource::Pcap {
            packets,
            current_index: 0,
            last_timestamp,
        },
    })
}
