# PTP Trace

A powerful cross-platform application for monitoring, analyzing, and accessing PTPv2 (Precision Time Protocol) networks in real-time with multiple operation modes: **Interactive TUI** or **Headless Monitoring**.

![License](https://img.shields.io/badge/license-GPLv2-blue.svg)
![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue)

## Overview

PTP Trace offers two flexible modes of operation:

- **🖥️ Interactive TUI** - Full-featured terminal UI with mouse support for interactive monitoring
- **📊 Headless Mode** - Background monitoring with event logging

All modes share a common service layer and support both live packet capture and offline PCAP analysis.

## Features

### **Two Operation Modes**

#### 1. Interactive Terminal UI (TUI Mode)
- Real-time dashboard with multiple panels
- Multiple themes: Default, Monokai, Matrix
- Intuitive keyboard navigation
- Mouse support - Click to switch views, select rows, and navigate content
- Responsive layout that adapts to terminal size
- Live updates without screen flicker
- Pause mode to temporarily stop network parsing for UI inspection

#### 2. Headless Mode
- Background monitoring without TUI overhead
- Comprehensive event logging:
  - Grandmaster changes (BMCA election results)
  - PTP domain changes
  - Clock quality degradation
  - Host timeouts and state changes
  - Time transmitter selection changes
  - Network interface link state changes
  - IP address changes
  - Host discoveries and updates
- Human-readable logging with timestamps
- Configurable log levels (error, warn, info, debug)
- Runs as a daemon-friendly service

### **Network Monitoring** (All Modes)
- Automatic PTP and gPTP host discovery (UDP ports 319/320 and Ethernet 0x88f7)
- **Cross-platform packet capture** - Uses pnet for live capturing on Linux, macOS, and Windows
- **Dual protocol support** - Handles both PTP over UDP (Layer 3) and gPTP over Ethernet (Layer 2, IEEE 802.1AS)
- **PCAP file support** - Read and analyze PTP packets from captured pcap files (offline analysis mode)
- **Multicast group membership** - Ensures network interfaces receive multicast PTP traffic
- **Full packet analysis** - Records both raw packet data and parsed PTP content
- **Smart interface selection** - Automatically filters virtual interfaces while supporting manual override
- Host classification by PTP state
- **BMCA (Best Master Clock Algorithm)** - Automatic time transmitter detection
- Grandmaster marked with "GM" indicator
- Network statistics and quality metrics
- Timing relationship tracking
- **Time reference modes** - Live network uses current system time; pcap mode uses last packet timestamp as reference
- **Tree view mode** (TUI only) - Hierarchical display showing transmitter-receiver relationships
- Visual hierarchy mapping of transmitter-receiver relationships
- **VLAN support** - Detects and displays VLAN tags in PTP packets
- **Native VLAN** - Supports specifying native vlan id on interfaces

### **Host Management** (TUI Mode)
- Comprehensive host table with sortable columns
- Multiple sort options (State, IP, Clock Identity, Domain, etc.)
- Selection tracking across operations
- Quality indicators and confidence levels
- OUI database integration to show vendor information
- Local machine identification: Your own machine is marked with asterisks (*)
- Mouse-enabled selection - Click on any host row to select it instantly

### **Packet Analysis** (TUI Mode)
- Real-time packet history with version identification
- Color-coded message types (ANNOUNCE, SYNC, DELAY_REQ, PDELAY_REQ, etc.)
- Interface-aware capture - Tracks which interface each packet was received on
- Interactive packet selection - Click to select packets, double-click for detailed view
- Scroll wheel support - Navigate through packet history with mouse wheel

## Quick Start

### Prerequisites
- Rust 1.70.0 or later
- **Administrator privileges required** - Needed for promiscuous mode packet capture (in live capture mode)
- Network interfaces with PTP traffic (ports 319/320)
- **Platform-specific requirements**:
  - **macOS**: Xcode command line tools (`xcode-select --install`)
  - **Windows**: WinPcap or Npcap installed

### Installation

```bash
# Clone the repository
git clone https://github.com/holoplot/ptp-trace.git
cd ptp-trace

# Build from source
cargo build --release

# Run with default settings (TUI mode, requires root)
sudo ./target/release/ptp-trace
```

## Usage Examples

### Interactive TUI Mode

```bash
# Monitor with default TUI (requires root)
sudo ./target/release/ptp-trace

# Monitor specific interface
sudo ./target/release/ptp-trace --interface eth0

# Monitor multiple interfaces
sudo ./target/release/ptp-trace --interface eth0 --interface eth1

# Use Matrix theme with faster updates
sudo ./target/release/ptp-trace --theme matrix --update-interval 500

# Disable mouse support
sudo ./target/release/ptp-trace --no-mouse

# Analyze PCAP file (no admin privileges needed)
./target/release/ptp-trace --pcap-file capture.pcap
```

### Headless Mode

```bash
# Monitor in headless mode with all events logged (default: info level)
sudo ./target/release/ptp-trace --headless

# Log only critical events (error level) - GM changes, timeouts, link down, quality degradation
sudo ./target/release/ptp-trace --headless --log-level error

# Log critical and state change events (warn level) - error + host updates
sudo ./target/release/ptp-trace --headless --log-level warn

# Verbose logging including all packets (debug level)
sudo ./target/release/ptp-trace --headless --log-level debug

# Monitor specific interface with custom web port
sudo ./target/release/ptp-trace -i eth0 --headless --web-port 9090

# Example output (one line per event):
# [2026-02-09 10:23:45.123] INFO: New host discovered | id=00:11:22:33:44:55:66:77 domain=0 ips=[192.168.1.100(eth0)] interfaces=[eth0]
# [2026-02-09 10:24:12.456] ERROR: Grandmaster changed in domain 0 | old=00:11:22:33:44:55:66:77 new=aa:bb:cc:dd:ee:ff:00:11
```

## Command Line Options

```bash
Usage: ptp-trace [OPTIONS] [COMMAND]

Options:
  -i, --interface <INTERFACE>      Network interface(s) to monitor
  -f, --pcap-file <FILE>           Read from PCAP file (offline analysis)
  -u, --update-interval <MS>       Update interval in milliseconds [default: 1000]
  -d, --debug                      Enable debug logging
  -t, --theme <THEME>              Color theme (default, monokai, matrix) [default: default]
      --no-mouse                   Disable mouse support (TUI mode)
      --headless                   Run in headless mode (no TUI)
      --log-level <LEVEL>          Log level: error, warn, info, debug [default: info]
  -h, --help                       Print help
  -V, --version                    Print version
```

## TUI Controls

### **Navigation**
- `Tab` - Cycle between views: Host Table → Host Details → Packet History
- `↑` / `k` - Move selection up or scroll up
- `↓` / `j` - Move selection down or scroll down
- `PgUp` / `PgDn` - Page navigation (10 items)
- `Home` / `End` - Jump to top/bottom
- `Enter` - Show packet details modal
- `q` - Close modal/help or quit application
- `Esc` - Close help screen

### **Mouse Support** (enabled by default, disable with `--no-mouse`)
- `Click` - Switch to view and select row
- `Double-click` - Open packet details modal
- `Click outside modal` - Close modal
- `Scroll wheel` - Navigate selections/scroll content

### **Table Operations**
- `s` - Cycle sort columns
- `S` - Toggle sort direction
- `a` - Previous sort column
- `t` - Toggle tree view mode

### **Actions**
- `r` - Refresh/rescan network
- `Ctrl+L` - Refresh/redraw screen
- `c` - Clear hosts and packet history
- `x` - Clear packet history for selected host
- `p` - Toggle pause mode
- `w` - Toggle packet auto-scroll
- `e` - Toggle expanded packet history
- `d` - Toggle debug mode

### **Help & Exit**
- `h` / `F1` - Show/hide help
- `q` - Quit application

## PCAP File Analysis

PTP Trace supports offline analysis of PTP traffic from pcap files.

### Creating PCAP Files:
```bash
# Capture PTP traffic with tcpdump (Linux/macOS)
sudo tcpdump -i eth0 -w ptp_capture.pcap 'udp port 319 or udp port 320 or ether proto 0x88f7'

# Capture with Wireshark (all platforms)
# Filter: udp.port == 319 or udp.port == 320 or eth.type == 0x88f7
# Save as: ptp_capture.pcap

# Analyze in TUI mode
./target/release/ptp-trace --pcap-file ptp_capture.pcap

# Analyze in headless mode
./target/release/ptp-trace --pcap-file ptp_capture.pcap --headless
```

Note: PCAP analysis does not support native VLAN specification at this time.

## Demo

![Demo](demo.gif)

## Terminology & Inclusive Language

In accordance with [IEEE 1588g-2022](https://standards.ieee.org/ieee/1588g/10478/), this project uses **inclusive terminology** to describe the roles of network components.

### **Term Mapping**

| **Inclusive term**                 | **Industry Standard** | **Description**                              |
|------------------------------------|-----------------------|----------------------------------------------|
| **Time Transmitter**               | Master Clock          | Device that provides timing reference        |
| **Time Receiver**                  | Slave Clock           | Device that synchronizes to timing reference |

The term **Grandmaster** remains unchanged and refers to the clock at the top of the hierarchy.

A [blog post from Meinberg](https://blog.meinbergglobal.com/2023/02/13/a-step-toward-a-more-inclusive-terminology-for-ptp/) has more information about the topic.

## Themes

Choose from multiple built-in themes for TUI mode:
- **default** - Clean and professional
- **monokai** - Dark theme with vibrant colors
- **matrix** - Green-on-black terminal aesthetic

Use `--theme <name>` to select a theme.

## Current Status

### **Implemented Features**
- ✅ Complete terminal UI framework with keyboard and mouse support
- ✅ Headless monitoring mode with event logging
- ✅ Full raw packet payloads for hexdump display
- ✅ Cross-platform packet capture (Linux, macOS, Windows)
- ✅ PCAP file analysis (offline mode)
- ✅ Host table with sorting and scrolling
- ✅ Packet history with detailed view
- ✅ Multiple theme support
- ✅ Real-time event streaming
- ✅ Network interface monitoring
- ✅ Comprehensive keyboard controls
- ✅ Debug mode with scroll information

## Development

### **Building**
```bash
# Development build
cargo build

# Optimized release build
cargo build --release

# Run tests
cargo test

# Format code
cargo fmt

# Lint code
cargo clippy
```

### Update built-in OUI database

This project features an integrated OUI database for MAC address lookup.
The information is compiled into the binary at build time.

```bash
# Update OUI database
python3 -r oui/requirements.txt
python3 oui/gen_oui_rust_phf.py >src/oui_map.rs

# Lint after updating
cargo clippy
```

### **Dependencies**

**Core:**
- **ratatui** - Terminal UI framework
- **tokio** - Async runtime
- **crossterm** - Cross-platform terminal handling
- **clap** - Command line argument parsing
- **anyhow** - Error handling

**Networking:**
- **pnet** - Cross-platform packet capture
- **socket2** - Advanced socket operations and multicast
- **libc** - Low-level system calls

**Utilities:**
- **chrono** - Date and time
- **if-addrs** - Network interface enumeration
- **phf** - Compile-time hash tables
- **serde** - Serialization

## Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Update documentation
6. Submit a pull request

### **Code Standards**
- Follow Rust best practices
- Document public APIs
- Include tests for new features
- Use `cargo fmt` for formatting
- Pass `cargo clippy` lints

## License

This project is licensed under the GPLv2 License - see the [LICENSE](LICENSE) file for details.

## Related Projects

- [**statime**](https://github.com/pendulum-project/statime) - Rust PTP implementation
- [**ptp4l**](http://linuxptp.sourceforge.net/) - Linux PTP daemon
- [**ratatui**](https://github.com/ratatui-org/ratatui) - Terminal UI library
- [**tokio**](https://tokio.rs/) - Async runtime for Rust
