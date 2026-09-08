use std::fs;
use std::path::Path;

use crate::config::Config;
use crate::error::CynError;

/// Information about the local feed.
#[derive(Debug)]
pub struct FeedInfo {
    pub path: String,
    pub version: String,
    pub plugin_count: usize,
    pub exists: bool,
}

/// Check the status of the local NVT feed.
pub fn status(config: &Config) -> Result<FeedInfo, CynError> {
    let feed_path = &config.feed_path;

    if !feed_path.exists() {
        return Ok(FeedInfo {
            path: feed_path.display().to_string(),
            version: String::new(),
            plugin_count: 0,
            exists: false,
        });
    }

    let version = read_feed_version(feed_path)?;
    let plugin_count = count_nasl_scripts(feed_path)?;

    Ok(FeedInfo {
        path: feed_path.display().to_string(),
        version,
        plugin_count,
        exists: true,
    })
}

/// Perform a feed update by synchronising from upstream.
///
/// Uses rsync if available, otherwise returns an error with instructions.
pub fn update(
    config: &Config,
    upstream_url: Option<&str>,
    _signature_check: bool,
) -> Result<(), CynError> {
    let url = upstream_url.unwrap_or("rsync://feed.community.greenbone.net/community-feed/");

    // Ensure feed directory exists
    let feed_path = &config.feed_path;
    if !feed_path.exists() {
        fs::create_dir_all(feed_path).map_err(|e| CynError::FeedUpdate(format!("{e}")))?;
    }

    // Try rsync
    let status = std::process::Command::new("rsync")
        .args([
            "--delete",
            "--times",
            "--recursive",
            "--partial",
            url,
            &feed_path.display().to_string(),
        ])
        .status();

    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(CynError::FeedUpdate(format!(
            "rsync exited with status {s}"
        ))),
        Err(e) => Err(CynError::FeedUpdate(format!(
            "rsync not available: {e}. Install rsync or download the feed manually to {}",
            feed_path.display()
        ))),
    }
}

/// Read the feed version from `plugin_feed_info.inc`.
fn read_feed_version(feed_path: &Path) -> Result<String, CynError> {
    let info_file = feed_path.join("plugin_feed_info.inc");
    if !info_file.exists() {
        return Ok(String::from("unknown"));
    }
    let content = fs::read_to_string(&info_file).map_err(|e| CynError::FeedInvalid {
        reason: format!("cannot read plugin_feed_info.inc: {e}"),
    })?;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("PLUGIN_SET") {
            // PLUGIN_SET = "202401011031"
            if let Some(start) = trimmed.find('"') {
                if let Some(end) = trimmed[start + 1..].find('"') {
                    return Ok(trimmed[start + 1..start + 1 + end].to_string());
                }
            }
        }
    }
    Ok(String::from("unknown"))
}

/// Count `.nasl` scripts in the feed directory (recursive).
fn count_nasl_scripts(feed_path: &Path) -> Result<usize, CynError> {
    let mut count = 0;
    count_nasl_recursive(feed_path, &mut count)?;
    Ok(count)
}

fn count_nasl_recursive(dir: &Path, count: &mut usize) -> Result<(), CynError> {
    let entries = fs::read_dir(dir).map_err(|e| CynError::FeedInvalid {
        reason: format!("cannot read feed directory: {e}"),
    })?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            count_nasl_recursive(&path, count)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("nasl") {
            *count += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn feed_status_nonexistent() {
        let config = Config::resolve(Some(PathBuf::from("/nonexistent/feed"))).unwrap();
        let info = status(&config).unwrap();
        assert!(!info.exists);
    }

    #[test]
    fn feed_status_with_mock_feed() {
        let dir = tempfile::tempdir().unwrap();
        let feed = dir.path();

        // Create plugin_feed_info.inc
        fs::write(
            feed.join("plugin_feed_info.inc"),
            r#"PLUGIN_SET = "202501011200";
PLUGIN_FEED = "Greenbone Community Feed";
FEED_VENDOR = "Greenbone AG";
"#,
        )
        .unwrap();

        // Create some .nasl files
        fs::write(feed.join("test.nasl"), "exit(0);").unwrap();
        let sub = feed.join("subdir");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("nested.nasl"), "exit(0);").unwrap();

        let config = Config::resolve(Some(feed.to_path_buf())).unwrap();
        let info = status(&config).unwrap();

        assert!(info.exists);
        assert_eq!(info.version, "202501011200");
        assert_eq!(info.plugin_count, 2);
    }

    #[test]
    fn count_nasl_scripts_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(count_nasl_scripts(dir.path()).unwrap(), 0);
    }
}
