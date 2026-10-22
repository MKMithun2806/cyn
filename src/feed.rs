use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::error::CynError;

/// Default Greenbone community feed base URL.
const DEFAULT_FEED_URL: &str = "rsync://feed.community.greenbone.net/community";

/// Default feed release version (matches Greenbone's FEED_RELEASE).
const DEFAULT_FEED_VERSION: &str = "24.10";

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

/// Perform a feed update by synchronising NASL scripts from upstream.
///
/// Uses rsync to download the NVT feed. The user sees live rsync output.
pub fn update(
    config: &Config,
    upstream_url: Option<&str>,
    feed_version: Option<&str>,
) -> Result<(), CynError> {
    let base_url = upstream_url.unwrap_or(DEFAULT_FEED_URL);
    let version = feed_version.unwrap_or(DEFAULT_FEED_VERSION);

    // The Greenbone community feed stores NASL scripts under:
    //   vulnerability-feed/<VERSION>/vt-data/nasl/
    let rsync_url = format!("{base_url}/vulnerability-feed/{version}/vt-data/nasl/");

    let feed_path = &config.feed_path;
    let parent = feed_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|e| CynError::FeedUpdate(format!("{e}")))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| CynError::FeedUpdate(format!("clock error: {e}")))?
        .as_nanos();
    let staging = parent.join(format!(".cyn-feed-{nonce}.tmp"));
    fs::create_dir(&staging).map_err(|e| CynError::FeedUpdate(format!("{e}")))?;

    println!("Syncing feed from:");
    println!("  {rsync_url}");
    println!("  -> {}", feed_path.display());
    println!();

    let status = Command::new("rsync")
        .args([
            "--stats",
            "--progress",
            "--delete",
            "--times",
            "--recursive",
            "--partial",
            "--compress",
            &rsync_url,
            &staging.display().to_string(),
        ])
        .status()
        .map_err(|e| {
            CynError::FeedUpdate(format!(
                "rsync not found: {e}\n\
             Install rsync: sudo apk add rsync\n\
             Or download the feed manually:\n\
               greenbone-feed-sync --type nvts\n\
             Or copy to {dest}",
                dest = feed_path.display()
            ))
        })?;

    if !status.success() {
        let msg = format!("rsync exited with status {status}");

        // Provide helpful guidance for common errors
        if msg.contains("Unknown module") || msg.contains("does not exist") {
            return Err(CynError::FeedUpdate(format!(
                "{msg}\n\n\
                 The feed URL module was not found on the server.\n\
                 This can happen if:\n\
                 1. The feed version {version} is not available\n\
                 2. The Greenbone community feed server is temporarily down\n\
                 3. The rsync module structure has changed\n\n\
                 Try:\n\
                 1. Check available versions at https://community.greenbone.net\n\
                 2. Specify a different version: cyn feed update --url <URL>\n\
                 3. Use greenbone-feed-sync: greenbone-feed-sync --type nvts\n\
                 4. Download manually and place .nasl files in {}",
                feed_path.display()
            )));
        }

        let _ = fs::remove_dir_all(&staging);
        return Err(CynError::FeedUpdate(msg));
    }

    let backup = parent.join(format!(".cyn-feed-{nonce}.old"));
    if feed_path.exists() {
        fs::rename(feed_path, &backup)
            .map_err(|e| CynError::FeedUpdate(format!("cannot stage existing feed: {e}")))?;
    }
    if let Err(error) = fs::rename(&staging, feed_path) {
        if backup.exists() {
            let _ = fs::rename(&backup, feed_path);
        }
        let _ = fs::remove_dir_all(&staging);
        return Err(CynError::FeedUpdate(format!("cannot activate feed: {error}")));
    }
    let _ = fs::remove_dir_all(&backup);
    println!("Feed sync complete.");
    Ok(())
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
        let config = Config::resolve(Some(PathBuf::from("/nonexistent/feed")), None).unwrap();
        let info = status(&config).unwrap();
        assert!(!info.exists);
    }

    #[test]
    fn feed_status_with_mock_feed() {
        let dir = tempfile::tempdir().unwrap();
        let feed = dir.path();

        fs::write(
            feed.join("plugin_feed_info.inc"),
            r#"PLUGIN_SET = "202501011200";
PLUGIN_FEED = "Greenbone Community Feed";
FEED_VENDOR = "Greenbone AG";
"#,
        )
        .unwrap();

        fs::write(feed.join("test.nasl"), "exit(0);").unwrap();
        let sub = feed.join("subdir");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("nested.nasl"), "exit(0);").unwrap();

        let config = Config::resolve(Some(feed.to_path_buf()), None).unwrap();
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
