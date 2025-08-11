// Include the generated version information
include!(concat!(env!("OUT_DIR"), "/version.rs"));

/// Get the application version string for display
pub fn get_version() -> &'static str {
    VERSION
}

/// Get just the git hash
pub fn get_git_hash() -> &'static str {
    GIT_HASH
}

/// Get the build timestamp
pub fn get_build_time() -> &'static str {
    BUILD_TIME
}

/// Test function to demonstrate header version display
pub fn print_header_info() {
    println!("Header would display:");
    println!("  Line 1: PTP Network Tracer v{}", get_version());
    println!(
        "  Line 2: Built: {} | Git: {}",
        get_build_time(),
        get_git_hash()
    );
    println!("CLI version: {}", get_version());
}
