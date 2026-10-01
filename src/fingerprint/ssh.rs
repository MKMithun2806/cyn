use super::ServiceFingerprint;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub async fn fingerprint(mut stream: TcpStream) -> Option<ServiceFingerprint> {
    let mut banner = vec![0; 512];
    let size = stream.read(&mut banner).await.ok()?;
    let banner = String::from_utf8_lossy(&banner[..size]).trim().to_string();
    if !banner.starts_with("SSH-") {
        return None;
    }

    parse_banner(&banner)
}

fn parse_banner(banner: &str) -> Option<ServiceFingerprint> {
    let mut fingerprint = ServiceFingerprint {
        protocol: Some("ssh".into()),
        banner: Some(banner.into()),
        ..Default::default()
    };
    let server = banner.split_once('-')?.1.split_once('-')?.1;
    let product_version = server.split_whitespace().next()?;
    if let Some((product, version)) = product_version.split_once('_') {
        fingerprint.product = Some(product.into());
        fingerprint.version = Some(version.into());
    } else {
        fingerprint.product = Some(product_version.into());
    }
    Some(fingerprint)
}

#[cfg(test)]
mod tests {
    use super::parse_banner;

    #[test]
    fn parses_openssh_banner() {
        let fingerprint = parse_banner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13").unwrap();
        assert_eq!(fingerprint.product.as_deref(), Some("OpenSSH"));
        assert_eq!(fingerprint.version.as_deref(), Some("9.6p1"));
    }
}
