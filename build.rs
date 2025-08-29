use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    // Handle libpcap linking for cross-platform support
    configure_libpcap_linking();

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("version.rs");

    // Get git describe output for version
    let git_version = get_git_version();

    // Get git commit hash
    let git_hash = get_git_hash();

    // Get build timestamp
    let build_time = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();

    // Generate version constants
    let version_code = format!(
        r#"
/// Version string generated at compile time
pub const VERSION: &str = "{}";

/// Git commit hash (short)
pub const GIT_HASH: &str = "{}";

/// Build timestamp
pub const BUILD_TIME: &str = "{}";
"#,
        git_version, git_hash, build_time
    );

    fs::write(&dest_path, version_code).unwrap();

    // Tell cargo to rerun if git HEAD changes
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
}

fn configure_libpcap_linking() {
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".to_string());
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown".to_string());

    println!("cargo:rerun-if-env-changed=LIBPCAP_LIBDIR");
    println!("cargo:rerun-if-env-changed=LIBPCAP_VER");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");

    match target_os.as_str() {
        "windows" => configure_windows_pcap(),
        "macos" => configure_macos_pcap(),
        "linux" => configure_linux_pcap(&target, &target_arch),
        _ => {
            println!("cargo:warning=Unknown target OS: {}", target_os);
        }
    }
}

fn configure_windows_pcap() {
    // Windows uses WinPcap/Npcap instead of libpcap
    println!("cargo:rustc-link-lib=wpcap");
    println!("cargo:rustc-link-lib=Packet");

    // Check for LIBPCAP_LIBDIR environment variable (for Npcap SDK)
    if let Ok(lib_dir) = env::var("LIBPCAP_LIBDIR") {
        println!("cargo:rustc-link-search=native={}", lib_dir);
    }

    // Common Npcap installation paths
    let npcap_paths = [
        "C:\\npcap-sdk\\Lib\\x64",
        "C:\\npcap-sdk\\Lib",
        "C:\\WpdPack\\Lib\\x64",
        "C:\\WpdPack\\Lib",
    ];

    for path in &npcap_paths {
        if Path::new(path).exists() {
            println!("cargo:rustc-link-search=native={}", path);
            break;
        }
    }
}

fn configure_macos_pcap() {
    // macOS has libpcap built-in
    println!("cargo:rustc-link-lib=pcap");

    // Check for custom libpcap location
    if let Ok(lib_dir) = env::var("LIBPCAP_LIBDIR") {
        println!("cargo:rustc-link-search=native={}", lib_dir);
    }

    // Common macOS libpcap paths
    let macos_paths = ["/usr/lib", "/opt/homebrew/lib", "/usr/local/lib"];

    for path in &macos_paths {
        if Path::new(&format!("{}/libpcap.dylib", path)).exists()
            || Path::new(&format!("{}/libpcap.a", path)).exists()
        {
            println!("cargo:rustc-link-search=native={}", path);
            break;
        }
    }
}

fn configure_linux_pcap(target: &str, target_arch: &str) {
    // Linux uses libpcap
    println!("cargo:rustc-link-lib=pcap");

    // Check for custom libpcap location first
    if let Ok(lib_dir) = env::var("LIBPCAP_LIBDIR") {
        println!("cargo:rustc-link-search=native={}", lib_dir);
        return;
    }

    // Try pkg-config first
    if let Ok(output) = Command::new("pkg-config")
        .args(["--libs", "libpcap"])
        .output()
    {
        if output.status.success() {
            let libs = String::from_utf8_lossy(&output.stdout);
            for lib in libs.split_whitespace() {
                if let Some(stripped) = lib.strip_prefix("-L") {
                    println!("cargo:rustc-link-search=native={}", stripped);
                } else if let Some(stripped) = lib.strip_prefix("-l") {
                    println!("cargo:rustc-link-lib={}", stripped);
                }
            }
            return;
        }
    }

    // Fallback to architecture-specific paths for cross-compilation
    let lib_paths = match (target_arch, target.contains("musl")) {
        ("x86_64", false) => vec!["/usr/lib/x86_64-linux-gnu", "/usr/lib64", "/usr/lib"],
        ("aarch64", false) => vec!["/usr/lib/aarch64-linux-gnu", "/usr/lib64", "/usr/lib"],
        ("arm", false) => vec![
            "/usr/lib/arm-linux-gnueabihf",
            "/usr/lib/arm-linux-gnueabi",
            "/usr/lib",
        ],
        (_, true) => vec!["/usr/lib", "/lib"],
        _ => vec!["/usr/lib", "/usr/lib64", "/lib", "/lib64"],
    };

    for path in &lib_paths {
        if Path::new(&format!("{}/libpcap.so", path)).exists()
            || Path::new(&format!("{}/libpcap.a", path)).exists()
        {
            println!("cargo:rustc-link-search=native={}", path);
            break;
        }
    }
}

fn get_git_version() -> String {
    // Try git describe first (preferred)
    if let Ok(output) = Command::new("git")
        .args(["describe", "--tags", "--dirty", "--always"])
        .output()
    {
        if output.status.success() {
            if let Ok(version) = String::from_utf8(output.stdout) {
                let version = version.trim();
                // If version doesn't start with 'v' and contains no '-', it's just a commit hash
                if !version.starts_with('v') && !version.contains('-') {
                    // Get Cargo version and append git hash
                    let cargo_version =
                        env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.1.0".to_string());
                    return if version.len() >= 7 {
                        format!("{}-g{}", cargo_version, &version[..7])
                    } else {
                        format!("{}-g{}", cargo_version, version)
                    };
                }
                return version.to_string();
            }
        }
    }

    // Fallback to git rev-parse for just commit hash
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
    {
        if output.status.success() {
            if let Ok(hash) = String::from_utf8(output.stdout) {
                let cargo_version =
                    env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.1.0".to_string());
                return format!("{}-g{}", cargo_version, hash.trim());
            }
        }
    }

    // Final fallback to Cargo.toml version
    env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.1.0".to_string())
}

fn get_git_hash() -> String {
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
    {
        if output.status.success() {
            if let Ok(hash) = String::from_utf8(output.stdout) {
                return hash.trim().to_string();
            }
        }
    }

    "unknown".to_string()
}
