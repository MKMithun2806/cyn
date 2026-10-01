use super::ServiceFingerprint;
use std::collections::BTreeMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn fingerprint(mut stream: TcpStream, host: &str) -> Option<ServiceFingerprint> {
    let request = format!("HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.ok()?;
    let mut response = vec![0; 8192];
    let size = stream.read(&mut response).await.ok()?;
    if size == 0 {
        return None;
    }
    parse_response(&String::from_utf8_lossy(&response[..size]))
}

fn parse_response(text: &str) -> Option<ServiceFingerprint> {
    let mut lines = text.lines();
    let status = lines.next()?.trim();
    if !status.starts_with("HTTP/") {
        return None;
    }

    let mut headers = BTreeMap::new();
    let mut product = None;
    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().to_string();
        if key == "server" {
            product = Some(value.clone());
        }
        headers.insert(key, value);
    }

    Some(ServiceFingerprint {
        protocol: Some("http".into()),
        banner: Some(status.into()),
        product,
        headers,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::parse_response;

    #[test]
    fn parses_http_server_and_headers() {
        let fingerprint =
            parse_response("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nX-Powered-By: Rust\r\n\r\n")
                .unwrap();
        assert_eq!(fingerprint.protocol.as_deref(), Some("http"));
        assert_eq!(fingerprint.product.as_deref(), Some("nginx/1.24.0"));
        assert_eq!(fingerprint.headers.get("x-powered-by").unwrap(), "Rust");
    }
}
