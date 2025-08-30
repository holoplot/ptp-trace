//! Cross-platform raw socket implementation for PTP traffic capture
//!
//! This module implements packet capture using libpcap/pcap for cross-platform
//! promiscuous mode support. Works on Linux, macOS, and Windows.

use anyhow::Result;
use libc::timeval;
use pcap::{Capture, Device, Linktype, Packet};
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{SystemTime, UNIX_EPOCH};
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

    // Get available devices from pcap
    let devices = match Device::list() {
        Ok(devices) => devices,
        Err(e) => {
            eprintln!("Warning: Failed to list pcap devices: {}", e);
            return Ok(interfaces);
        }
    };

    for device in devices {
        // Skip loopback devices
        if device.flags.is_loopback() {
            continue;
        }

        // Skip devices without names
        let device_name = device.name.clone();

        // Get IPv4 addresses for this device
        for addr in &device.addresses {
            if let IpAddr::V4(ipv4) = addr.addr {
                if !ipv4.is_loopback() && is_suitable_interface(&device) {
                    interfaces.push((device_name.clone(), ipv4));
                    break; // Only take first IPv4 address per interface
                } else {
                    println!("Excluding interface: {} (filtered)", device_name);
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

fn is_suitable_interface(device: &Device) -> bool {
    let device_name = &device.name;

    // Skip loopback
    if device.flags.is_loopback() {
        return false;
    }

    // Skip if marked as down
    if !device.flags.is_up() {
        return false;
    }

    // Skip common virtual interface patterns
    let virtual_prefixes = [
        "veth", "docker", "br-", "virbr", "vmnet", "tun", "tap", "wg", "dummy", "bond", "team",
        "macvlan", "vlan", "lo", "flannel", "cni0", "wg", "wl", "wlan", "ww", "idrac",
    ];

    for prefix in &virtual_prefixes {
        if device_name.starts_with(prefix) {
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

fn timeval_to_systemtime(tv: timeval) -> SystemTime {
    // tv_sec is seconds since epoch, tv_usec is microseconds
    let dur = Duration::new(tv.tv_sec as u64, (tv.tv_usec as u32) * 1000);
    UNIX_EPOCH + dur
}

fn process_ethernet_packet(packet: &Packet, interface_name: &str) -> Option<RawPacket> {
    let packet_data = packet.data;

    // Minimum Ethernet frame size check
    if packet_data.len() < 14 {
        return None;
    }

    let dest_mac = [
        packet_data[0],
        packet_data[1],
        packet_data[2],
        packet_data[3],
        packet_data[4],
        packet_data[5],
    ];

    let source_mac = [
        packet_data[6],
        packet_data[7],
        packet_data[8],
        packet_data[9],
        packet_data[10],
        packet_data[11],
    ];

    // Parse Ethernet header
    let ethertype = u16::from_be_bytes([packet_data[12], packet_data[13]]);
    let mut ip_offset = 14;

    let mut vlan_id: Option<u16> = None;

    // Handle VLAN tags (skip them for now as requested)
    if ethertype == 0x8100 {
        // VLAN tag present, skip 4 bytes
        if packet_data.len() < 18 {
            return None;
        }
        ip_offset = 18;
        vlan_id = Some(u16::from_be_bytes([packet_data[14], packet_data[15]]) & 0x0FFF);
        let inner_ethertype = u16::from_be_bytes([packet_data[16], packet_data[17]]);
        if inner_ethertype != 0x0800 {
            // Not IPv4
            return None;
        }
    } else if ethertype != 0x0800 {
        // Not IPv4
        return None;
    }

    // Parse IPv4 header
    if packet_data.len() < ip_offset + 20 {
        return None;
    }

    let ip_header = &packet_data[ip_offset..];
    let ip_version = (ip_header[0] >> 4) & 0x0F;
    let ip_protocol = ip_header[9];

    if ip_version != 4 || ip_protocol != 17 {
        // Not IPv4 or not UDP
        return None;
    }

    let source_ip = Ipv4Addr::new(ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
    let dest_ip = Ipv4Addr::new(ip_header[16], ip_header[17], ip_header[18], ip_header[19]);

    let ip_header_length = ((ip_header[0] & 0x0F) * 4) as usize;
    if packet_data.len() < ip_offset + ip_header_length + 8 {
        return None;
    }

    // Parse UDP header
    let udp_offset = ip_offset + ip_header_length;
    let udp_header = &packet_data[udp_offset..];

    let source_port = u16::from_be_bytes([udp_header[0], udp_header[1]]);
    let dest_port = u16::from_be_bytes([udp_header[2], udp_header[3]]);
    let udp_length = u16::from_be_bytes([udp_header[4], udp_header[5]]) as usize;

    // Filter for PTP ports
    if dest_port != PTP_EVENT_PORT && dest_port != PTP_GENERAL_PORT {
        return None;
    }

    // Extract PTP payload
    let ptp_offset = udp_offset + 8;
    if packet_data.len() < ptp_offset || udp_length < 8 {
        return None;
    }

    let ptp_payload_length = std::cmp::min(udp_length - 8, packet_data.len() - ptp_offset);
    let ptp_payload = packet_data[ptp_offset..ptp_offset + ptp_payload_length].to_vec();

    let source_addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(source_ip, source_port));
    let dest_addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(dest_ip, dest_port));

    Some(RawPacket {
        timestamp: timeval_to_systemtime(packet.header.ts),
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
) -> Result<()> {
    // Find the pcap device
    let device = Device::list()?
        .into_iter()
        .find(|d| d.name == interface_name)
        .ok_or_else(|| anyhow::anyhow!("Interface {} not found", interface_name))?;

    // Create capture handle with optimized settings for multiple interfaces
    let mut cap = match Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(100)
        .buffer_size(1024 * 1024) // Smaller buffer per interface
        .immediate_mode(true) // Don't buffer packets
        .open()
    {
        Ok(cap) => cap,
        Err(e) => {
            eprintln!(
                "Failed to open capture on interface {}: {}",
                interface_name, e
            );
            return Err(anyhow::anyhow!(
                "Failed to open pcap capture on {}: {}",
                interface_name,
                e
            ));
        }
    };

    // Set BPF filter for UDP traffic on PTP ports
    cap.filter(
        &format!(
            "udp and (port {} or port {})",
            PTP_EVENT_PORT, PTP_GENERAL_PORT
        ),
        true,
    )?;

    // Check if we're capturing on Ethernet
    if cap.get_datalink() != Linktype::ETHERNET {
        eprintln!(
            "Warning: Interface {} is not Ethernet, packet parsing may fail",
            interface_name
        );
    }

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(raw_packet) = process_ethernet_packet(&packet, &interface_name) {
                    if sender.send(raw_packet).is_err() {
                        // Receiver has been dropped, exit the loop
                        break;
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Timeout is expected, continue
                tokio::task::yield_now().await;
                continue;
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

pub async fn create_socket(ifnames: &[String]) -> Result<RawSocketReceiver> {
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

    let (sender, receiver) = mpsc::unbounded_channel();

    // Start packet capture on each interface
    for (interface_name, _) in &target_interfaces {
        let sender_clone = sender.clone();
        let interface_name_clone = interface_name.clone();
        tokio::spawn(async move {
            // Stagger startup to reduce resource contention
            tokio::time::sleep(Duration::from_millis(200)).await;

            if let Err(e) = capture_on_interface(interface_name_clone.clone(), sender_clone).await {
                eprintln!("Packet capture error on {}: {}", interface_name_clone, e);
            }
        });
    }

    println!(
        "pcap monitoring started on {} interface(s) for PTP events (port {}) and general messages (port {}): {}",
        target_interfaces.len(),
        PTP_EVENT_PORT,
        PTP_GENERAL_PORT,
        target_interfaces
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    Ok(RawSocketReceiver {
        source: PacketSource::Socket {
            receiver,
            interfaces: target_interfaces,
            _multicast_sockets: multicast_sockets,
        },
    })
}

pub async fn create_pcap(pcap_path: &str) -> Result<RawSocketReceiver> {
    use pcap::Capture;

    // Open pcap file
    let mut cap = Capture::from_file(pcap_path)?;

    let mut packets = Vec::new();
    let mut last_timestamp: Option<SystemTime> = None;

    // Read all packets from pcap file
    while let Ok(packet) = cap.next_packet() {
        if let Some(raw_packet) = process_ethernet_packet(&packet, "pcap") {
            // Track the latest timestamp for reference
            if last_timestamp.is_none() || raw_packet.timestamp > last_timestamp.unwrap() {
                last_timestamp = Some(raw_packet.timestamp);
            }
            packets.push(raw_packet);
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
