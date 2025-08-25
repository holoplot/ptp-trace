# 🕰️ PTP Trace

A powerful cross-platform terminal-based application for monitoring and analyzing PTPv2 (Precision Time Protocol) networks in real-time.

![License](https://img.shields.io/badge/license-GPLv2-blue.svg)
![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue)

## ✨ Features

### 🖥️ **Interactive Terminal UI**
- 📊 Real-time dashboard with multiple panels
- 🎨 Multiple themes: Default, Monokai, Matrix
- ⌨️ Intuitive keyboard navigation
- 📱 Responsive layout that adapts to terminal size
- 🔄 Live updates without screen flicker
- ⏸️ Pause mode to temporarily stop network parsing for UI inspection

### 🌐 **Network Monitoring**
- 🔍 Automatic PTP host discovery on port 319 and 320
- 📡 **Cross-platform packet capture** - Uses libpcap/pcap for promiscuous mode on Linux, macOS, and Windows
- 🌐 **Multicast group membership** - Ensures network interfaces receive multicast PTP traffic
- 🔍 **Full packet analysis** - Records both raw packet data and parsed PTP content
- 🎯 **Smart interface selection** - Automatically filters virtual interfaces while supporting manual override
- ⚡ **Hardware-accelerated filtering** - Uses BPF filters for efficient packet capture
- 🏷️ Host classification by PTP state
- 🏆 **BMCA (Best Master Clock Algorithm)** - Automatic primary time transmitter detection
- 📊 Primary Time Transmitter marked with "PT" indicator
- 📈 Network statistics and quality metrics
- 🕐 Timing relationship tracking
- 🌳 Visual hierarchy mapping of transmitter-receiver relationships

### 📋 **Host Management**
- 📝 Comprehensive host table with sortable columns
- 🌳 Hierarchical tree view showing transmitter-receiver relationships
- 🔢 Multiple sort options (State, IP, Clock Identity, Domain, etc.)
- 🎯 Selection tracking across operations
- 📊 Quality indicators and confidence levels
- 🔍 OUI database integration to show vendor information
- ⭐ Local machine identification: Your own machine is marked with asterisks (*) in the host list and details

### 📦 **Packet Analysis**
- 📋 Real-time packet history with version identification
- 🎨 Color-coded message types (ANNOUNCE, SYNC, DELAY_REQ, PDELAY_REQ, etc.)
- 🌐 **Interface-aware capture** - Tracks which interface each packet was received on

## Demo

![Demo](demo.gif)

## 🚀 Quick Start

### 📋 Prerequisites
- 🦀 Rust 1.70.0 or later
- 🔧 **Administrator privileges required** - Needed for promiscuous mode packet capture
- 🌐 Network interfaces with PTP traffic (ports 319/320)
- 📦 **Platform-specific requirements**:
  - **Linux**: libpcap-dev (`sudo apt install libpcap-dev`)
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

# 🐛 Enable debug mode
sudo ./target/release/ptp-trace --debug

# 🔧 Combine options
sudo ./target/release/ptp-trace --interface eth0 --interface eth1 --theme matrix --update-interval 500
```

## 🎮 Controls

### 🎮 **Navigation**
- `↑` / `k` - 📈 Move selection up
- `↓` / `j` - 📉 Move selection down
- `PgUp` / `PgDn` - 📄 Page navigation (10 items)
- `Home` / `End` - 🏠 Jump to top/bottom

### 📊 **Table Operations**
- `s` - 🔄 Cycle sort columns
- `S` - ↕️ Toggle sort direction
- `t` - 🌳 Toggle hierarchical tree view
- Green headers indicate active sort column

### 🎬 **Actions**
- `r` - 🔄 Refresh/rescan network
- `c` - 🗑️ Clear hosts and packet history
- `p` - ⏸️ Toggle pause mode (stops network parsing, shows "PAUSED" in header)
- `e` - 📊 Toggle expanded packet history
- `d` - 🐛 Toggle debug mode

### ℹ️ **Help & Exit**
- `h` / `F1` - ❓ Show/hide help
- `Esc` - 🚪 Close help or quit
- `q` - 🚫 Quit application

## 🎨 Themes

Choose from multiple built-in themes. See the output of `ptp-trace --help` to get a list of available themes.

## 🚧 Current Status

### ✅ **Implemented Features**
- 🖼️ Complete terminal UI framework
- 🎮 Application structure and navigation
- 📊 Host table with sorting and scrolling
- 🌳 Hierarchical tree view for PTP topology visualization
- 📦 Packet history with detailed view
- 🎨 Multiple theme support
- ⌨️ Comprehensive keyboard controls
- 🔍 Debug mode with scroll information

### 🗺️ **Future Roadmap**
- 📤 **Data export** - JSON, PCAP output formats for raw packet data
- 🔍 **Advanced filtering** - Search and filter capabilities
- 📊 **Enhanced analytics** - Statistical analysis of timing data
- 🔧 **Configuration management** - Save/load application settings
- 📦 **Packet inspection tools** - Hex dump viewer for raw packet analysis

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
- 📡 **pcap** - Cross-platform packet capture (libpcap/WinPcap/Npcap)
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
