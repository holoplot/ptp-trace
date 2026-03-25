use mime_guess::from_path;
use rust_embed::RustEmbed;
use std::borrow::Cow;

#[derive(RustEmbed)]
#[folder = "frontend/dist/"]
#[prefix = ""]
pub struct StaticAssets;

pub fn get_asset(path: &str) -> Option<(Cow<'static, [u8]>, String)> {
    // Handle root path
    let path = if path.is_empty() || path == "/" {
        "index.html"
    } else {
        // Remove leading slash
        path.strip_prefix('/').unwrap_or(path)
    };

    // Try to get the asset
    if let Some(asset) = StaticAssets::get(path) {
        let mime_type = from_path(path).first_or_octet_stream().to_string();
        return Some((asset.data, mime_type));
    }

    // For SPA routing, fall back to index.html for non-asset paths
    if (!path.contains('.') || path.starts_with("host/"))
        && let Some(asset) = StaticAssets::get("index.html") {
            return Some((asset.data, "text/html".to_string()));
        }

    None
}
