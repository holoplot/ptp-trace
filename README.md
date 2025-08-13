# 🕰️ PTP Trace

A powerful terminal-based application for monitoring and analyzing PTPv2 (Precision Time Protocol) networks in real-time.

![License](https://img.shields.io/badge/license-GPLv2-blue.svg)
![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)

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
- 📡 Real-time packet capture and analysis
- 🏷️ Host classification by PTP state
- 📈 Network statistics and quality metrics
- 🕐 Timing relationship tracking
- 🌳 Visual hierarchy mapping of leader-follower relationships

### 📋 **Host Management**
- 📝 Comprehensive host table with sortable columns
- 🌳 Hierarchical tree view showing leader-follower relationships
- 🔢 Multiple sort options (State, IP, Clock Identity, Domain, etc.)
- 🎯 Selection tracking across operations
- 📊 Quality indicators and confidence levels
- 🔍 OUI database integration to show vendor information

### 📦 **Packet Analysis**
- 📋 Real-time packet history
- 🎨 Color-coded message types (ANNOUNCE, SYNC, DELAY_REQ, etc.)

## Demo

![Demo](demo.gif)

## 🚀 Quick Start

### 📋 Prerequisites
- 🦀 Rust 1.70.0 or later
- 🔧 Privilege to bind ports < 1024 (root)

### 🔨 Installation

```bash
# Clone the repository
git clone https://github.com/holoplot/ptp-trace.git
cd ptp-trace

# Build from source
cargo build --release

# Run with default settings
./target/release/ptp-trace
```

### ⚙️ Command Line Options

```bash
# 🌐 Monitor specific interface
./target/release/ptp-trace --interface eth0

# 🌐 Monitor multiple interfaces
./target/release/ptp-trace --interface eth0 --interface eth1

# 🌐 Monitor all interfaces (default behavior)
./target/release/ptp-trace

# ⚡ Faster updates (500ms)
./target/release/ptp-trace --update-interval 500

# 🎨 Use Matrix theme
./target/release/ptp-trace --theme matrix

# 🐛 Enable debug mode
./target/release/ptp-trace --debug

# 🔧 Combine options
./target/release/ptp-trace --interface eth0 --interface eth1 --theme matrix --update-interval 500
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
- `p` - ⏸️ Toggle pause mode
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
- 📤 **Data export** - JSON, PCAP output formats
- 🔍 **Advanced filtering** - Search and filter capabilities
- 📊 **Enhanced analytics** - Statistical analysis of timing data
- 🔧 **Configuration management** - Save/load application settings

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
