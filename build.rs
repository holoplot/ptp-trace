use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
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

/// Full version string with git info
pub const FULL_VERSION: &str = concat!("{}", " (", "{}", ")");
"#,
        git_version, git_hash, build_time, git_version, git_hash
    );

    fs::write(&dest_path, version_code).unwrap();

    // Tell cargo to rerun if git HEAD changes
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
}

fn get_git_version() -> String {
    // Try git describe first (preferred)
    if let Ok(output) = Command::new("git")
        .args(&["describe", "--tags", "--dirty", "--always"])
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
        .args(&["rev-parse", "--short", "HEAD"])
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
        .args(&["rev-parse", "--short", "HEAD"])
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
