use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use url::Url;

#[derive(Clone, Copy)]
pub enum Family {
    V4,
    V6,
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

pub async fn fetch(raw_url: &str, family: Option<Family>, budget: Duration) -> Result<Response, String> {
    let started = std::time::Instant::now();
    let mut current = raw_url.to_string();
    for _ in 0..3 {
        let left = budget.saturating_sub(started.elapsed());
        if left.is_zero() {
            return Err("timeout".into());
        }
        let response = timeout(left, fetch_once(&current, family))
            .await
            .map_err(|_| "timeout".to_string())?
            .map_err(|err| err)?;
        if matches!(response.status, 301 | 302 | 303 | 307 | 308) {
            if let Some(location) = response.body.lines().find_map(|line| {
                let line = line.trim();
                line.strip_prefix("location:")
                    .or_else(|| line.strip_prefix("Location:"))
                    .map(|value| value.trim().to_string())
            }) {
                current = resolve_location(&current, &location)?;
                continue;
            }
        }
        return Ok(response);
    }
    Err("too many redirects".into())
}

pub async fn fetch_https(raw_url: &str, family: Option<Family>, budget: Duration) -> Result<Response, String> {
    require_https(raw_url)?;
    fetch(raw_url, family, budget).await
}

fn require_https(raw_url: &str) -> Result<(), String> {
    let url = Url::parse(raw_url).map_err(|err| err.to_string())?;
    if url.scheme() != "https" { return Err("HTTPS required".into()); }
    Ok(())
}

fn resolve_location(base: &str, location: &str) -> Result<String, String> {
    let base = Url::parse(base).map_err(|err| err.to_string())?;
    let target = base.join(location).map_err(|err| err.to_string())?;
    if !matches!(target.scheme(), "http" | "https") {
        return Err("unsupported redirect scheme".into());
    }
    if base.scheme() == "https" && target.scheme() != "https" {
        return Err("HTTPS redirect downgrade refused".into());
    }
    Ok(target.to_string())
}

async fn fetch_once(raw_url: &str, family: Option<Family>) -> Result<Response, String> {
    let url = Url::parse(raw_url).map_err(|err| err.to_string())?;
    if !matches!(url.scheme(), "http" | "https") { return Err("unsupported URL scheme".into()); }
    let https = url.scheme() == "https";
    let host = url.host_str().ok_or("missing host")?.to_string();
    let port = url.port_or_known_default().unwrap_or(if https { 443 } else { 80 });
    let path = if url.query().is_some() {
        format!("{}?{}", url.path(), url.query().unwrap_or(""))
    } else {
        let path = url.path();
        if path.is_empty() { "/".into() } else { path.to_string() }
    };
    let stream = connect(&host, port, family).await?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: AIEnv/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    if https {
        let config = tls_config();
        let connector = TlsConnector::from(config);
        let name = ServerName::try_from(host).map_err(|err| err.to_string())?;
        let mut tls = connector.connect(name, stream).await.map_err(|err| err.to_string())?;
        tls.write_all(request.as_bytes()).await.map_err(|err| err.to_string())?;
        read_http(&mut tls).await
    } else {
        let mut tcp = stream;
        tcp.write_all(request.as_bytes()).await.map_err(|err| err.to_string())?;
        read_http(&mut tcp).await
    }
}

async fn connect(host: &str, port: u16, family: Option<Family>) -> Result<TcpStream, String> {
    let addrs = tokio::net::lookup_host((host, port)).await.map_err(|err| err.to_string())?;
    let mut last = "no address".to_string();
    for addr in addrs {
        match family {
            Some(Family::V4) if !addr.is_ipv4() => continue,
            Some(Family::V6) if !addr.is_ipv6() => continue,
            _ => {}
        }
        match timeout(Duration::from_secs(6), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => last = err.to_string(),
            Err(_) => last = "connect timeout".into(),
        }
    }
    Err(last)
}

fn install_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // rustls 0.23 panics if both ring and aws-lc-rs are linked and neither
        // was chosen. This process uses ring.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    use std::sync::OnceLock;
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG.get_or_init(build_tls_config).clone()
}

pub fn build_tls_config() -> Arc<rustls::ClientConfig> {
    install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    let natives = rustls_native_certs::load_native_certs();
    for cert in natives.certs {
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

async fn read_http<S>(stream: &mut S) -> Result<Response, String>
where
    S: AsyncReadExt + Unpin,
{
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await.map_err(|err| err.to_string())?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 512 * 1024 {
            break;
        }
    }
    parse_http(&buf)
}

fn parse_http(bytes: &[u8]) -> Result<Response, String> {
    let split = bytes.windows(4).position(|window| window == b"\r\n\r\n").ok_or("no http header")?;
    let head = String::from_utf8_lossy(&bytes[..split]).to_string();
    let raw_body = &bytes[split + 4..];
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    if status == 0 {
        return Err("not an http response".into());
    }
    let chunked = head.lines().any(|line| {
        let line = line.to_lowercase();
        line.starts_with("transfer-encoding:") && line.contains("chunked")
    });
    let body_bytes = if chunked { decode_chunks(raw_body) } else { raw_body.to_vec() };
    let body = String::from_utf8_lossy(&body_bytes).to_string();
    if matches!(status, 301 | 302 | 303 | 307 | 308) {
        let location = head.lines().find_map(|line| {
            let lower = line.to_lowercase();
            lower.strip_prefix("location:").map(|_| line.split_once(':').map(|(_, value)| value.trim().to_string())).flatten()
        });
        if let Some(location) = location {
            return Ok(Response { status, body: format!("location: {location}\n{body}") });
        }
    }
    Ok(Response { status, body })
}

fn decode_chunks(mut bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let Some(line_end) = bytes.windows(2).position(|window| window == b"\r\n") else {
            break;
        };
        let line = String::from_utf8_lossy(&bytes[..line_end]);
        let size_hex = line.split(';').next().unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(size_hex, 16) else {
            break;
        };
        bytes = &bytes[line_end + 2..];
        if size == 0 || bytes.len() < size {
            break;
        }
        out.extend_from_slice(&bytes[..size]);
        if bytes.len() >= size + 2 {
            bytes = &bytes[size + 2..];
        } else {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirects_cannot_downgrade_https() {
        assert!(resolve_location("https://example.com/a", "http://example.com/b").is_err());
        assert!(resolve_location("https://example.com/a", "HTTP://example.com/b").is_err());
        assert!(resolve_location("https://example.com/a", "file:///tmp/data").is_err());
        assert_eq!(resolve_location("https://example.com/a", "/b").unwrap(), "https://example.com/b");
        assert_eq!(resolve_location("https://example.com/a", "//other.example/b").unwrap(), "https://other.example/b");
        assert_eq!(resolve_location("https://example.com/a", "https://other.example/b").unwrap(), "https://other.example/b");
        assert!(require_https("http://example.com").is_err());
        assert!(require_https("https://example.com").is_ok());
    }
}
