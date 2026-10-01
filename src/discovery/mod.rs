mod nmap;
mod types;

pub use nmap::NmapBackend;
pub use types::{DiscoveryResult, Protocol};

use std::fmt;

#[derive(Debug, Clone)]
pub struct DiscoveryRequest {
    pub target: String,
    pub ports: Option<String>,
}

#[derive(Debug)]
pub enum DiscoveryError {
    Io(std::io::Error),
    CommandFailed(String),
    Parse(String),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "failed to run discovery backend: {error}"),
            Self::CommandFailed(error) => write!(f, "discovery backend failed: {error}"),
            Self::Parse(error) => write!(f, "discovery result could not be parsed: {error}"),
        }
    }
}

impl std::error::Error for DiscoveryError {}

/// Backend boundary for host and service discovery.
pub trait DiscoveryBackend {
    fn discover<'a>(
        &'a self,
        request: &'a DiscoveryRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<DiscoveryResult, DiscoveryError>> + Send + 'a>,
    >;
}

pub async fn discover(request: &DiscoveryRequest) -> Result<DiscoveryResult, DiscoveryError> {
    NmapBackend.discover(request).await
}

pub fn from_nmap(scan: crate::nmap::NmapScan) -> DiscoveryResult {
    scan.into()
}
