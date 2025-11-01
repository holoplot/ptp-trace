# 🕰️ PTP Trace

A powerful cross-platform terminal-based application for monitoring and analyzing PTPv2 (Precision Time Protocol) networks in real-time with full keyboard and mouse support.

![License](https://img.shields.io/badge/license-GPLv2-blue.svg)
![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue)

## ✨ Features

### 🖥️ **Interactive Terminal UI**
- 📊 Real-time dashboard with multiple panels
- 🎨 Multiple themes: Default, Monokai, Matrix
- ⌨️ Intuitive keyboard navigation
- 🖱️ Mouse support - Click to switch views, select rows, and navigate content
- 📱 Responsive layout that adapts to terminal size
- 🔄 Live updates without screen flicker
- ⏸️ Pause mode to temporarily stop network parsing for UI inspection

### 🌐 **Network Monitoring**
- 🔍 Automatic PTP and gPTP host discovery (UDP ports 319/320 and Ethernet 0x88f7)
- 📡 **Cross-platform packet capture** - Uses pnet for live capturing on Linux, macOS, and Windows
- 🌐 **Dual protocol support** - Handles both PTP over UDP (Layer 3) and gPTP over Ethernet (Layer 2, IEEE 802.1AS)
- 📄 **PCAP file support** - Read and analyze PTP packets from captured pcap files (offline analysis mode)
- 🌐 **Multicast group membership** - Ensures network interfaces receive multicast PTP traffic
- 🔍 **Full packet analysis** - Records both raw packet data and parsed PTP content
- 🎯 **Smart interface selection** - Automatically filters virtual interfaces while supporting manual override
- 🏷️ Host classification by PTP state
- 🏆 **BMCA (Best Master Clock Algorithm)** - Automatic primary time transmitter detection
- 📊 Primary Time Transmitter marked with "PTT" indicator
- 📈 Network statistics and quality metrics
- 🕐 Timing relationship tracking
- ⏸️ **Time reference modes** - Live network uses current system time; pcap mode uses last packet timestamp as reference
- 🌳 **Tree view mode** - Hierarchical display showing transmitter-receiver relationships with proper indentation and PTT (Primary Time Transmitter) indicators
- 🌳 Visual hierarchy mapping of transmitter-receiver relationships
- 🏷️ **VLAN support** - Detects and displays VLAN tags in PTP packets

### 📋 **Host Management**
- 📝 Comprehensive host table with sortable columns
- 🔢 Multiple sort options (State, IP, Clock Identity, Domain, etc.)
- 🎯 Selection tracking across operations
- 📊 Quality indicators and confidence levels
- 🔍 OUI database integration to show vendor information
- ⭐ Local machine identification: Your own machine is marked with asterisks (*) in the host list and details
- 🖱️ Mouse-enabled selection - Click on any host row to select it instantly

### 📦 **Packet Analysis**
- 📋 Real-time packet history with version identification
- 🎨 Color-coded message types (ANNOUNCE, SYNC, DELAY_REQ, PDELAY_REQ, etc.)
- 🌐 Interface-aware capture - Tracks which interface each packet was received on
- 🖱️ Interactive packet selection - Click to select packets, double-click for detailed view
- 📜 Scroll wheel support - Navigate through packet history with mouse wheel

## 📄 PCAP File Analysis

PTP Trace supports offline analysis of PTP traffic from pcap files in offline mode.

### Creating PCAP Files:
```bash
# Capture PTP traffic with tcpdump (Linux/macOS)
sudo tcpdump -i eth0 -w ptp_capture.pcap 'udp port 319 or udp port 320 or ether proto 0x88f7'

# Capture with Wireshark (all platforms)
# Filter: udp.port == 319 or udp.port == 320 or eth.type == 0x88f7
# Save as: ptp_capture.pcap

# Analyze the captured file
./target/release/ptp-trace --pcap-file ptp_capture.pcap
```

## Demo

![Demo](demo.gif)

## 🚀 Quick Start

### 📋 Prerequisites
- 🦀 Rust 1.70.0 or later
- 🔧 **Administrator privileges required** - Needed for promiscuous mode packet capture (in live capture mode)
- 🌐 Network interfaces with PTP traffic (ports 319/320)
- 📦 **Platform-specific requirements**:
  - **macOS**: Xcode command line tools (`xcode-select --install`)
  - **Windows**: WinPcap or Npcap installed

### 🔨 Installation

```bash
# Clone the repository
git clone https://github.com/holoplot/ptp-trace.git
cd ptp-trace

# Build from source
cargo build --release

# Run with default settings (requires root)
sudo ./target/release/ptp-trace
```

### ⚙️ Command Line Options

```bash
# 📄 Analyze packets from pcap file (offline mode, no admin privileges needed)
./target/release/ptp-trace --pcap-file capture.pcap

# 🌐 Monitor specific interface (requires root)
sudo ./target/release/ptp-trace --interface eth0

# 🌐 Monitor multiple interfaces (requires admin privileges)
sudo ./target/release/ptp-trace --interface eth0 --interface eth1        # Linux/macOS

# 🌐 Monitor all suitable interfaces (default behavior, requires admin privileges)
# Automatically excludes virtual interfaces (Docker, VPN, etc.)
sudo ./target/release/ptp-trace                                          # Linux/macOS
./target/release/ptp-trace.exe                                          # Windows (as Administrator)

# 🌐 Force monitoring of virtual interfaces (requires explicit specification)
sudo ./target/release/ptp-trace --interface docker0 --interface br-123456

# ⚡ Faster updates (500ms)
sudo ./target/release/ptp-trace --update-interval 500

# 🎨 Use Matrix theme
sudo ./target/release/ptp-trace --theme matrix

# 🖱️ Disable mouse support (enabled by default)
sudo ./target/release/ptp-trace --no-mouse

# 📄 Analyze pcap file with custom theme and faster updates
./target/release/ptp-trace --pcap-file capture.pcap --theme matrix --update-interval 250

# 🐛 Enable debug mode
sudo ./target/release/ptp-trace --debug

# 🔧 Combine options for live monitoring
sudo ./target/release/ptp-trace --interface eth0 --interface eth1 --theme matrix --update-interval 500 --no-mouse

# Note: --interface and --pcap-file options are mutually exclusive
```

## 🎮 Controls

### 🎮 **Navigation**
- `Tab` - 🔄 Cycle between views: Host Table → Host Details → Packet History
- `↑` / `k` - 📈 Move selection up (host table) or scroll up (details/packets)
- `↓` / `j` - 📉 Move selection down (host table) or scroll down (details/packets)
- `PgUp` / `PgDn` - 📄 Page navigation (10 items) or scroll by page
- `Home` / `End` - 🏠 Jump to top/bottom
- `Enter` - 📋 Show packet details modal (when packet history is active)
- `q` - 🚪 Close packet details modal (when modal is open) or quit application
- `Esc` - 🚪 Close help screen

### 🖱️ **Mouse Support** (enabled by default, disable with `--no-mouse`)
- `Click` - 🎯 Switch to view and select row (host table/packet history)
- `Double-click` - 📋 Open packet details modal (packet history rows)
- `Click outside modal` - 🚪 Close packet details modal (or use 'q' key)
- `Scroll wheel` - 🔄 Navigate selections/scroll content (3 lines per scroll)

### 📊 **Table Operations**
- `s` - 🔄 Cycle sort columns
- `S` - ↕️ Toggle sort direction
- `a` - ⬅️ Previous sort column
- `t` - 🌳 Toggle tree view mode
- Green headers indicate active sort column

### 🎬 **Actions**
- `r` - 🔄 Refresh/rescan network
- `Ctrl+L` - 🔄 Refresh/redraw screen
- `c` - 🗑️ Clear hosts and packet history
- `x` - 🗑️ Clear packet history for selected host
- `p` - ⏸️ Toggle pause mode (stops network parsing, shows "PAUSED" in header)
- `w` - 🔄 Toggle packet auto-scroll
- `e` - 📊 Toggle expanded packet history
- `d` - 🐛 Toggle debug mode

### ℹ️ **Help & Exit**
- `h` / `F1` - ❓ Show/hide help
- `Esc` / `q` - 🚪 Close help screen
- `q` - 🚫 Close modal/help or quit application

### 📋 **Interface Behavior**
- **Three-way navigation**: Use `Tab` to cycle between Host Table, Host Details, and Packet History
- **Scrollable views**: Host Details and Packet History are fully scrollable with arrow keys, Page Up/Down, Home/End
- **Preserved selections**: Packet selection is maintained when switching views until you select a different host
- **Auto-scroll control**: Packet auto-scroll is disabled when manually navigating, re-enable with `w`
- **Smart resets**: Scroll positions reset to top when selecting a different host
- **Mouse integration**: Mouse and keyboard controls work seamlessly together
- **Accessibility**: Use `--no-mouse` flag to disable mouse support if needed

## ✊ Terminology & Inclusive Language

In accordance with [IEEE 1588g-2022](https://standards.ieee.org/ieee/1588g/10478/), this project uses **inclusive terminology** to describe the roles of network components.

### 🔄 **Term Mapping**

| **Inclusive term**                 | **Industry Standard** | **Description**                              |
|------------------------------------|-----------------------|----------------------------------------------|
| **Time Transmitter**               | Master Clock          | Device that provides timing reference        |
| **Time Receiver**                  | Slave Clock           | Device that synchronizes to timing reference |
| **Primary Time Transmitter (PTT)** | Grandmaster Clock     | Best master clock selected by BMCA algorithm |

The underlying PTP protocol and packet structures remain unchanged - only the user-facing terminology has been modernized for clarity and inclusivity.

A [blog post from Meinberg](https://blog.meinbergglobal.com/2023/02/13/a-step-toward-a-more-inclusive-terminology-for-ptp/) has more information about the topic.

## 🎨 Themes

Choose from multiple built-in themes. See the output of `ptp-trace --help` to get a list of available themes.

## 🚧 Current Status

### ✅ **Implemented Features**
- 🖼️ Complete terminal UI framework
- 🎮 Application structure and navigation
- 📊 Host table with sorting and scrolling
- 📦 Packet history with detailed view
- 🎨 Multiple theme support
- ⌨️ Comprehensive keyboard controls
- 🔍 Debug mode with scroll information

### 🗺️ **Future Roadmap**
- 📤 **Data export** - JSON, PCAP output formats for raw packet data
- 🔍 **Advanced filtering** - Search and filter capabilities for both live and pcap modes
- 📊 **Enhanced analytics** - Statistical analysis of timing data
- 🔧 **Configuration management** - Save/load application settings
- ⚡ **Hardware-accelerated filtering** - Use BPF filters for efficient packet capture

## 🛠️ Development

### 🔧 **Building**
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
The information is compiled into the binary at build time so that it can be used without an internet connection from a single binary.
To update the database, follow these steps:

```bash
# Update OUI database
python3 -r oui/requirements.txt
python3 oui/gen_oui_rust_phf.py >src/oui_map.rs

# Make sure to lint the code after updating the database
cargo clippy
```

Feel free to contribute to this project by submitting pull requests with the updated OUI database.

### 📚 **Dependencies**
- 🖥️ **ratatui** - Terminal UI framework
- ⚡ **tokio** - Async runtime
- ⌨️ **crossterm** - Cross-platform terminal handling
- 📝 **clap** - Command line argument parsing
- ❗ **anyhow** - Error handling
- 🔌 **pnet** - Cross-platform packet capture
- 🔧 **socket2** - Advanced socket operations and multicast group joining
- 🧮 **libc** - Low-level system calls

## 🤝 Contributing

We welcome contributions! Please:

1. 🍴 Fork the repository
2. 🌿 Create a feature branch
3. 🔧 Make your changes
4. ✅ Add tests if applicable
5. 📝 Update documentation
6. 🚀 Submit a pull request

### 📏 **Code Standards**
- 🦀 Follow Rust best practices
- 📝 Document public APIs
- ✅ Include tests for new features
- 🎨 Use `cargo fmt` for formatting
- 🔍 Pass `cargo clippy` lints

## 📜 License

This project is licensed under the GPLv2 License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- 🕰️ [**statime**](https://github.com/pendulum-project/statime) - Rust PTP implementation
- 🐧 [**ptp4l**](http://linuxptp.sourceforge.net/) - Linux PTP daemon
- 🖼️ [**ratatui**](https://github.com/ratatui-org/ratatui) - Terminal UI library
- ⚡ [**tokio**](https://tokio.rs/) - Async runtime for Rust

## 🆘 Support

- 📖 Use `h` or `F1` in the application for interactive help
- 🐛 Enable debug mode with `d` for troubleshooting
- 📧 Report issues on the project's issue tracker
- 💬 Join discussions for feature requests and support

---

**🕰️ Built for precision timing networks • 🦀 Written in Rust • 🖥️ Runs in your terminal**
