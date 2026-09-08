use std::path::{Path, PathBuf};

use crate::error::CynError;

/// Default feed directory relative to data home.
const DEFAULT_FEED_REL: &str = "cyn/plugins";

/// Configuration for Cyn.
#[derive(Debug, Clone)]
pub struct Config {
    /// Path to the local NVT feed directory.
    pub feed_path: PathBuf,
}

impl Config {
    /// Build configuration from explicit values, falling back to defaults.
    pub fn resolve(feed_override: Option<PathBuf>) -> Result<Self, CynError> {
        let feed_path = match feed_override {
            Some(p) => p,
            None => default_feed_path(),
        };
        Ok(Self { feed_path })
    }

    /// Return the plugins folder path the scanner should use.
    #[allow(dead_code)]
    pub fn plugins_folder(&self) -> &Path {
        &self.feed_path
    }
}

/// Compute the default feed path.
///
/// Uses `$XDG_DATA_HOME/cyn/plugins` if set, otherwise `~/.local/share/cyn/plugins`.
fn default_feed_path() -> PathBuf {
    if let Ok(data_home) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(data_home).join(DEFAULT_FEED_REL);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join(DEFAULT_FEED_REL);
    }
    PathBuf::from("/var/lib/cyn/plugins")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_with_explicit_feed() {
        let cfg = Config::resolve(Some(PathBuf::from("/tmp/feed"))).unwrap();
        assert_eq!(cfg.feed_path, PathBuf::from("/tmp/feed"));
    }
}
