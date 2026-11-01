use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::{Deserialize, Serialize};

const PAGE: &str = include_str!("page.html");

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserPayload {
    pub scan_id: String,
    #[serde(default)]
    pub timezone: String,
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub user_agent: String,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub webdriver: bool,
    #[serde(default)]
    pub geolocation: String,
    #[serde(default)]
    pub webrtc: Vec<IceAddress>,
    #[serde(default)]
    pub accept_language: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IceAddress {
    pub ip: String,
    #[serde(default)]
    pub kind: String,
}

pub struct Hub {
    pub url: String,
    pub scan_id: String,
    pub slot: Arc<Mutex<Option<BrowserPayload>>>,
    stop: Arc<AtomicBool>,
    _thread: JoinHandle<()>,
}

impl Hub {
    pub fn start(scan_id: String) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|err| err.to_string())?;
        listener.set_nonblocking(true).map_err(|err| err.to_string())?;
        let port = listener.local_addr().map_err(|err| err.to_string())?.port();
        let token = generate_token()?;
        let expected = Expected { port, token: token.clone(), scan_id: scan_id.clone() };
        let slot = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_slot = slot.clone();
        let thread_stop = stop.clone();
        let thread = thread::spawn(move || serve(listener, thread_slot, thread_stop, expected));
        Ok(Self {
            url: format!("http://127.0.0.1:{port}/?scan={}#k={token}", url::form_urlencoded::byte_serialize(scan_id.as_bytes()).collect::<String>()),
            scan_id,
            slot,
            stop,
            _thread: thread,
        })
    }
}

impl Hub {
    /// URL without the secret `#k=` fragment, safe to show in the UI or put in
    /// exported reports.
    pub fn public_url(&self) -> String {
        strip_fragment(&self.url)
    }
}

fn strip_fragment(url: &str) -> String {
    url.split('#').next().unwrap_or(url).to_string()
}

impl Drop for Hub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

const MAX_BODY: usize = 256 * 1024;
const MAX_HEAD: usize = 16 * 1024;

#[derive(Clone)]
struct Expected {
    port: u16,
    token: String,
    scan_id: String,
}

fn generate_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|err| err.to_string())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Token length is public; for equal lengths inspect every byte.
    if a.len() != b.len() { return false; }
    let mut difference = 0u8;
    for (&left, &right) in a.iter().zip(b) { difference |= left ^ right; }
    difference == 0
}

struct RequestHead<'a> {
    method: &'a str,
    path: &'a str,
    headers: Vec<(&'a str, &'a str)>,
}

impl<'a> RequestHead<'a> {
    fn parse(head: &'a str) -> Result<Self, u16> {
        let mut lines = head.split("\r\n");
        let mut request = lines.next().ok_or(400u16)?.split_whitespace();
        let method = request.next().ok_or(400u16)?;
        let target = request.next().ok_or(400u16)?;
        if request.next() != Some("HTTP/1.1") || request.next().is_some() { return Err(400); }
        let mut headers = Vec::new();
        for line in lines {
            let (key, value) = line.split_once(':').ok_or(400u16)?;
            if key.is_empty() || key.bytes().any(|b| !b.is_ascii_alphanumeric() && b != b'-') {
                return Err(400);
            }
            // Reject duplicates to avoid ambiguous security/framing headers.
            if headers.iter().any(|(old, _): &(&str, &str)| old.eq_ignore_ascii_case(key)) {
                return Err(400);
            }
            headers.push((key, value.trim()));
        }
        Ok(Self { method, path: target.split('?').next().unwrap_or(target), headers })
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| *value)
    }

    fn body_length(&self) -> Result<usize, u16> {
        if self.header("transfer-encoding").is_some() { return Err(400); }
        let length = match self.header("content-length") {
            Some(value) => value.parse::<usize>().map_err(|_| 400u16)?,
            None => 0,
        };
        if length > MAX_BODY { return Err(413); }
        Ok(length)
    }
}

fn authorize(req: &RequestHead<'_>, expected: &Expected) -> Result<(), u16> {
    let local = format!("127.0.0.1:{}", expected.port);
    let localhost = format!("localhost:{}", expected.port);
    if !matches!(req.header("host"), Some(host) if host == local || host == localhost) {
        return Err(421);
    }
    if req.method == "OPTIONS" { return Err(405); }
    if req.path.starts_with("/api/") {
        let token = req.header("x-aienv-token").ok_or(401u16)?;
        if !constant_time_eq(token.as_bytes(), expected.token.as_bytes()) { return Err(401); }
    }
    if req.method == "POST" && req.path == "/api/report" {
        let origin = req.header("origin");
        if let Some(origin) = origin {
            if origin != format!("http://{local}") && origin != format!("http://{localhost}") {
                return Err(403);
            }
        }
        let site = req.header("sec-fetch-site");
        if matches!(site, Some("cross-site" | "same-site")) { return Err(403); }
        if origin.is_none() && site != Some("same-origin") { return Err(403); }
        let content_type = req.header("content-type").unwrap_or("");
        if !content_type.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/json") {
            return Err(400);
        }
    }
    req.body_length()?;
    Ok(())
}

fn parse_report(body: &[u8], scan_id: &str) -> Result<BrowserPayload, u16> {
    if body.len() > MAX_BODY { return Err(413); }
    let payload: BrowserPayload = serde_json::from_slice(body).map_err(|_| 400u16)?;
    if payload.scan_id.is_empty() || payload.scan_id != scan_id { return Err(400); }
    Ok(payload)
}

fn serve(listener: TcpListener, slot: Arc<Mutex<Option<BrowserPayload>>>, stop: Arc<AtomicBool>, expected: Expected) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let slot = slot.clone();
                let expected = expected.clone();
                thread::spawn(move || { let _ = handle(stream, slot, expected); });
            }
            Err(_) => thread::sleep(Duration::from_millis(40)),
        }
    }
}

fn handle(mut stream: TcpStream, slot: Arc<Mutex<Option<BrowserPayload>>>, expected: Expected) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    stream.set_write_timeout(Some(Duration::from_secs(4)))?;
    let response = read_response(&mut stream, &slot, &expected)
        .unwrap_or_else(|status| http(status, "text/plain", b"request rejected"));
    stream.write_all(&response)
}

fn read_response(stream: &mut TcpStream, slot: &Mutex<Option<BrowserPayload>>, expected: &Expected) -> Result<Vec<u8>, u16> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let split = loop {
        if let Some(split) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            if split > MAX_HEAD { return Err(400); }
            break split;
        }
        if buf.len() > MAX_HEAD { return Err(400); }
        let n = stream.read(&mut tmp).map_err(|_| 400u16)?;
        if n == 0 { return Err(400); }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = std::str::from_utf8(&buf[..split]).map_err(|_| 400u16)?;
    let req = RequestHead::parse(head)?;
    authorize(&req, expected)?;
    let length = req.body_length()?;
    let method = req.method.to_string();
    let path = req.path.to_string();
    let accept = req.header("accept-language").unwrap_or("").to_string();
    while buf.len() - split - 4 < length {
        let remaining = length - (buf.len() - split - 4);
        let limit = remaining.min(tmp.len());
        let n = stream.read(&mut tmp[..limit]).map_err(|_| 400u16)?;
        if n == 0 { return Err(400); }
        buf.extend_from_slice(&tmp[..n]);
    }
    match (method.as_str(), path.as_str()) {
        ("GET", "/") => Ok(http(200, "text/html; charset=utf-8", PAGE.as_bytes())),
        ("GET", "/api/headers") => {
            let body = serde_json::json!({ "acceptLanguage": accept }).to_string();
            Ok(http(200, "application/json; charset=utf-8", body.as_bytes()))
        }
        ("POST", "/api/report") => {
            let mut payload = parse_report(&buf[split + 4..split + 4 + length], &expected.scan_id)?;
            if payload.accept_language.is_empty() { payload.accept_language = accept; }
            *slot.lock().map_err(|_| 500u16)? = Some(payload);
            Ok(http(204, "text/plain", b""))
        }
        (_, "/" | "/api/headers" | "/api/report") => Err(405),
        _ => Err(404),
    }
}

fn http(status: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        421 => "Misdirected Request",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

pub fn open_url(url: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        return std::process::Command::new("open").arg(url).spawn().is_ok();
    }
    #[cfg(target_os = "windows")]
    {
        return std::process::Command::new("cmd").args(["/C", "start", "", url]).spawn().is_ok();
    }
    #[cfg(target_os = "linux")]
    {
        // A desktop portal can leave xdg-open running without opening anything.
        // Try a real browser first, then the desktop default.
        for program in ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "firefox", "xdg-open"] {
            if std::process::Command::new(program).arg(url).spawn().is_ok() {
                return true;
            }
        }
        return false;
    }
    #[allow(unreachable_code)]
    {
        let _ = url;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected() -> Expected {
        Expected { port: 12345, token: "a".repeat(64), scan_id: "scan-1".into() }
    }

    fn report_head() -> String {
        format!("POST /api/report HTTP/1.1\r\nHost: 127.0.0.1:12345\r\nX-AIEnv-Token: {}\r\nOrigin: http://127.0.0.1:12345\r\nSec-Fetch-Site: same-origin\r\nContent-Type: application/json; charset=utf-8", expected().token)
    }

    fn auth(head: &str) -> Result<(), u16> {
        authorize(&RequestHead::parse(head)?, &expected())
    }

    #[test]
    fn valid_requests() {
        assert_eq!(auth(&report_head()), Ok(()));
        assert_eq!(auth(&report_head().replace("127.0.0.1", "localhost")), Ok(()));
        assert_eq!(auth(&report_head().replace("\r\nOrigin: http://127.0.0.1:12345", "")), Ok(()));
        assert_eq!(auth(&report_head().replace("\r\nSec-Fetch-Site: same-origin", "")), Ok(()));
        assert_eq!(auth("GET / HTTP/1.1\r\nHost: 127.0.0.1:12345"), Ok(()));
    }

    #[test]
    fn token_required_on_all_api_routes() {
        let token_header = format!("\r\nX-AIEnv-Token: {}", expected().token);
        for route in ["/api/report", "/api/headers", "/api/unknown"] {
            let head = report_head().replace("/api/report", route);
            assert_eq!(auth(&head.replace(&token_header, "")), Err(401));
            assert_eq!(auth(&head.replace(&token_header, "\r\nX-AIEnv-Token: wrong")), Err(401));
        }
    }

    #[test]
    fn host_checked_on_every_route() {
        for path in ["/", "/api/report", "/api/headers", "/unknown"] {
            for host in ["evil.com:12345", "127.0.0.1:12346", "localhost:12346"] {
                let head = format!("GET {path} HTTP/1.1\r\nHost: {host}");
                assert_eq!(auth(&head), Err(421));
            }
        }
        assert_eq!(auth("GET / HTTP/1.1"), Err(421));
    }

    #[test]
    fn rejects_cross_site_and_non_json() {
        assert_eq!(auth(&report_head().replace("Origin: http://127.0.0.1:12345", "Origin: https://evil.com")), Err(403));
        for site in ["cross-site", "same-site"] {
            assert_eq!(auth(&report_head().replace("Sec-Fetch-Site: same-origin", &format!("Sec-Fetch-Site: {site}"))), Err(403));
        }
        let no_provenance = report_head().replace("\r\nOrigin: http://127.0.0.1:12345", "").replace("\r\nSec-Fetch-Site: same-origin", "");
        assert_eq!(auth(&no_provenance), Err(403));
        assert_eq!(auth(&report_head().replace("application/json; charset=utf-8", "text/plain")), Err(400));
        assert_eq!(auth("OPTIONS /api/report HTTP/1.1\r\nHost: 127.0.0.1:12345"), Err(405));
    }

    #[test]
    fn validates_payload_and_size() {
        for body in [r#"{}"#, r#"{"scanId":""}"#, r#"{"scanId":"other"}"#] {
            assert_eq!(parse_report(body.as_bytes(), "scan-1").unwrap_err(), 400);
        }
        assert!(parse_report(br#"{"scanId":"scan-1"}"#, "scan-1").is_ok());
        assert_eq!(parse_report(&vec![b' '; MAX_BODY + 1], "scan-1").unwrap_err(), 413);
        assert_eq!(auth(&format!("{}\r\nContent-Length: {}", report_head(), MAX_BODY + 1)), Err(413));
        assert_eq!(auth(&format!("{}\r\nContent-Length: {}", report_head(), usize::MAX)), Err(413));
        assert_eq!(auth(&format!("{}\r\nContent-Length: invalid", report_head())), Err(400));
        assert_eq!(auth(&format!("{}\r\nTransfer-Encoding: chunked", report_head())), Err(400));
        assert_eq!(auth(&format!("{}\r\nHost: evil.com", report_head())), Err(400));
    }

    #[test]
    fn public_url_hides_token() {
        assert_eq!(strip_fragment("http://127.0.0.1:1/?scan=s#k=abc"), "http://127.0.0.1:1/?scan=s");
        let hub = Hub::start("scan-x".into()).unwrap();
        let token = hub.url.split("#k=").nth(1).unwrap().to_string();
        assert!(!hub.public_url().contains(&token));
        assert!(hub.public_url().ends_with("?scan=scan-x"));
    }

    #[test]
    fn constant_time_comparison() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"xbc"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn tokens_are_random_and_absent_from_page() {
        let first = generate_token().unwrap();
        let second = generate_token().unwrap();
        for token in [&first, &second] {
            assert_eq!(token.len(), 64);
            assert!(token.bytes().all(|b| b.is_ascii_hexdigit()));
            let response = String::from_utf8(http(200, "text/html; charset=utf-8", PAGE.as_bytes())).unwrap();
            assert!(!response.contains(token));
            assert!(response.contains("X-Content-Type-Options: nosniff"));
            assert!(response.contains("Referrer-Policy: no-referrer"));
            assert!(response.contains("connect-src 'self'"));
            assert!(!response.to_lowercase().contains("access-control-allow-"));
        }
        assert_ne!(first, second);
    }

    fn exchange(hub: &Hub, request: &str) -> String {
        let url = url::Url::parse(&hub.url).unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", url.port().unwrap())).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn hub_tokens_and_raw_http() {
        let first = Hub::start("scan-1".into()).unwrap();
        let second = Hub::start("scan-2".into()).unwrap();
        let url = url::Url::parse(&first.url).unwrap();
        let token = url.fragment().unwrap().strip_prefix("k=").unwrap();
        let other = url::Url::parse(&second.url).unwrap();
        assert_eq!(token.len(), 64);
        assert!(token.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(url.fragment(), other.fragment());
        let host = format!("127.0.0.1:{}", url.port().unwrap());
        let response = exchange(&first, &format!("GET /?scan=scan-1 HTTP/1.1\r\nHost: {host}\r\n\r\n"));
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(!response.contains(token));
        assert!(response.contains("X-Content-Type-Options: nosniff"));
        assert!(response.contains("Referrer-Policy: no-referrer"));
        assert!(response.contains("connect-src 'self'"));
        assert!(!response.to_lowercase().contains("access-control-allow-"));
        let response = exchange(&first, "GET / HTTP/1.1\r\nHost: evil.com:12345\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 421 Misdirected Request"));
        let body = r#"{"scanId":"scan-1"}"#;
        let request = format!("POST /api/report HTTP/1.1\r\nHost: {host}\r\nX-AIEnv-Token: {token}\r\nOrigin: http://{host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        assert!(exchange(&first, &request).starts_with("HTTP/1.1 204 No Content"));
        assert_eq!(first.slot.lock().unwrap().as_ref().unwrap().scan_id, "scan-1");
        let oversized = format!("POST /api/report HTTP/1.1\r\nHost: {host}\r\nX-AIEnv-Token: {token}\r\nOrigin: http://{host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1);
        assert!(exchange(&first, &oversized).starts_with("HTTP/1.1 413 Payload Too Large"));
    }
}
