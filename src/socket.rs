use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};
use std::sync::mpsc;
use std::thread;

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::net::UdpSocket;

const PTP_EVENT_PORT: u16 = 319;
const PTP_GENERAL_PORT: u16 = 320;
const PTP_MULTICAST_ADDR: &str = "224.0.1.129";

fn iface_addrs_by_name(ifname: &str) -> io::Result<Option<Ipv4Addr>> {
    let mut v4: Option<Ipv4Addr> = None;

    for iface in if_addrs::get_if_addrs().map_err(|e| io::Error::new(io::ErrorKind::Other, e))? {
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

    for iface in if_addrs::get_if_addrs().map_err(|e| io::Error::new(io::ErrorKind::Other, e))? {
        if let if_addrs::IfAddr::V4(addr) = iface.addr {
            // Skip loopback interfaces
            if !addr.ip.is_loopback() {
                interfaces.push((iface.name, addr.ip));
            }
        }
    }
    Ok(interfaces)
}

pub fn get_interface_for_ip(ip: &IpAddr, interfaces: &[(String, Ipv4Addr)]) -> Option<String> {
    if let IpAddr::V4(ipv4) = ip {
        // Try to find which interface this IP might have come from based on subnet
        for (ifname, iface_addr) in interfaces {
            // For simplicity, we'll match based on the first 3 octets (Class C subnet)
            // This is a heuristic and may not be perfect for all network configurations
            let ip_octets = ipv4.octets();
            let iface_octets = iface_addr.octets();
            if ip_octets[0] == iface_octets[0]
                && ip_octets[1] == iface_octets[1]
                && ip_octets[2] == iface_octets[2]
            {
                return Some(ifname.clone());
            }
        }
    }
    None
}

pub async fn create(
    ifnames: &[String],
) -> Result<((UdpSocket, UdpSocket), Vec<(String, Ipv4Addr)>)> {
    // Get interfaces to listen on
    let interfaces = if ifnames.is_empty() {
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

    if interfaces.is_empty() {
        return Err(anyhow::anyhow!(
            "No IPv4 interfaces available for PTP monitoring"
        ));
    }

    // Create the event socket (port 319) using socket2 for multicast support
    let event_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    event_socket.set_reuse_address(true)?;
    let event_bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), PTP_EVENT_PORT);
    event_socket.bind(&event_bind_addr.into())
        .map_err(|e| anyhow::anyhow!("Failed to bind to PTP event port {}: {}. You may need to run with sudo or check if another PTP application is running.", PTP_EVENT_PORT, e))?;

    // Create the general socket (port 320) using socket2 for multicast support
    let general_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    general_socket.set_reuse_address(true)?;
    let general_bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), PTP_GENERAL_PORT);
    general_socket.bind(&general_bind_addr.into())
        .map_err(|e| anyhow::anyhow!("Failed to bind to PTP general port {}: {}. You may need to run with sudo or check if another PTP application is running.", PTP_GENERAL_PORT, e))?;

    // Join the PTP multicast group on all specified interfaces for both sockets
    let multicast_addr: Ipv4Addr = PTP_MULTICAST_ADDR.parse()?;

    for (ifname, iface_addr) in &interfaces {
        event_socket
            .join_multicast_v4(&multicast_addr, iface_addr)
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to join multicast group on interface {} for event socket: {}",
                    ifname,
                    e
                )
            })?;

        general_socket
            .join_multicast_v4(&multicast_addr, iface_addr)
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to join multicast group on interface {} for general socket: {}",
                    ifname,
                    e
                )
            })?;
    }

    // Convert to tokio UdpSockets
    event_socket.set_nonblocking(true)?;
    general_socket.set_nonblocking(true)?;
    let tokio_event_socket = UdpSocket::from_std(event_socket.into())?;
    let tokio_general_socket = UdpSocket::from_std(general_socket.into())?;

    println!(
        "Listening on {} interface(s) for PTP events (port {}) and general messages (port {}): {}",
        interfaces.len(),
        PTP_EVENT_PORT,
        PTP_GENERAL_PORT,
        interfaces
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    Ok(((tokio_event_socket, tokio_general_socket), interfaces))
}
