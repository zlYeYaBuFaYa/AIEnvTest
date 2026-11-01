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
    #[serde(default)]
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
        let slot = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_slot = slot.clone();
        let thread_stop = stop.clone();
        let thread_id = scan_id.clone();
        let thread = thread::spawn(move || serve(listener, thread_slot, thread_stop, thread_id));
        Ok(Self {
            url: format!("http://127.0.0.1:{port}/?scan={scan_id}"),
            scan_id,
            slot,
            stop,
            _thread: thread,
        })
    }
}

impl Drop for Hub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn serve(listener: TcpListener, slot: Arc<Mutex<Option<BrowserPayload>>>, stop: Arc<AtomicBool>, scan_id: String) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let slot = slot.clone();
                let scan_id = scan_id.clone();
                thread::spawn(move || {
                    let _ = handle(stream, slot, scan_id);
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(40)),
            Err(_) => thread::sleep(Duration::from_millis(40)),
        }
    }
}

fn handle(mut stream: TcpStream, slot: Arc<Mutex<Option<BrowserPayload>>>, scan_id: String) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    stream.set_write_timeout(Some(Duration::from_secs(4)))?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if request_complete(&buf) || buf.len() > 300_000 {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock || err.kind() == std::io::ErrorKind::TimedOut => break,
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.lines();
    let request = lines.next().unwrap_or("");
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");
    let path = target.split('?').next().unwrap_or("/");
    let accept = header_value(&text, "accept-language");
    let response = if method == "GET" && (path == "/" || path.is_empty()) {
        let page = PAGE.replace("__SCAN_ID__", &scan_id);
        http(200, "text/html; charset=utf-8", page.as_bytes())
    } else if method == "GET" && path == "/api/headers" {
        let body = serde_json::json!({ "acceptLanguage": accept }).to_string();
        http(200, "application/json; charset=utf-8", body.as_bytes())
    } else if method == "POST" && path == "/api/report" {
        let body = body_of(&text);
        match serde_json::from_str::<BrowserPayload>(body) {
            Ok(mut payload) => {
                if payload.scan_id.is_empty() {
                    payload.scan_id = scan_id;
                }
                if payload.accept_language.is_empty() {
                    payload.accept_language = accept;
                }
                if let Ok(mut guard) = slot.lock() {
                    *guard = Some(payload);
                }
                http(204, "text/plain", b"")
            }
            Err(_) => http(400, "text/plain", b"bad report"),
        }
    } else {
        http(404, "text/plain", b"not found")
    };
    stream.write_all(&response)
}

fn request_complete(buf: &[u8]) -> bool {
    let Some(split) = buf.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&buf[..split]);
    let length = header_value(&head, "content-length").parse::<usize>().unwrap_or(0);
    buf.len() >= split + 4 + length
}

fn header_value(head: &str, name: &str) -> String {
    for line in head.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case(name) {
                return value.trim().to_string();
            }
        }
    }
    String::new()
}

fn body_of(text: &str) -> &str {
    text.split_once("\r\n\r\n").map(|(_, body)| body).unwrap_or("")
}

fn http(status: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "OK",
    };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
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
