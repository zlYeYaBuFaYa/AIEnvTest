pub mod parse;
pub mod windows_parse;
pub mod windows_zones;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[derive(Debug, Clone)]
pub struct ProxySnapshot {
    pub sources: std::collections::BTreeMap<String,String>,
    pub wpad: bool,
    pub enabled: bool,
    pub pac: bool,
    pub pac_url: String,
    pub bypass: Vec<String>,
    pub http_proxy: String,
    pub https_proxy: String,
    pub socks_proxy: String,
}

#[derive(Debug, Clone)]
pub struct PlatformSnapshot {
    pub dns_blocks: Vec<parse::ResolverBlock>,
    pub errors: std::collections::BTreeMap<String, String>,
    pub os: String,
    pub timezone: String,
    pub windows_territory: Option<String>,
    pub windows_routes: Vec<windows_parse::EffectiveRoute>,
    pub locale: String,
    pub dns_servers: Vec<String>,
    pub route_v4_a: Option<String>,
    pub route_v4_b: Option<String>,
    pub route_v6: Ipv6Route,
    pub proxy: ProxySnapshot,
    pub hosts: Result<String, CollectError>,
    pub location_enabled: Option<bool>,
}

pub fn collect() -> PlatformSnapshot {
    #[cfg(target_os = "linux")]
    {
        return linux::collect();
    }
    #[cfg(target_os = "macos")]
    {
        return macos::collect();
    }
    #[cfg(target_os = "windows")]
    {
        return windows::collect();
    }
    #[allow(unreachable_code)]
    {
        PlatformSnapshot {
            dns_blocks: Vec::new(),
            errors: Default::default(),
            os: std::env::consts::OS.to_string(),
            timezone: String::new(),
            windows_territory: None, windows_routes: vec![],
            locale: String::new(),
            dns_servers: Vec::new(),
            route_v4_a: None,
            route_v4_b: None,
            route_v6: Ipv6Route::Unknown("unsupported platform".into()),
            proxy: ProxySnapshot {
            sources: Default::default(), wpad: false,
                enabled: false,
                pac: false,
                pac_url: String::new(),
                bypass: Vec::new(),
                http_proxy: String::new(),
                https_proxy: String::new(),
                socks_proxy: String::new(),
            },
            hosts: Err(CollectError::Io("unsupported platform".into())),
            location_enabled: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Ipv6Route {
    Absent,
    Present { iface: String },
    Unknown(String),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CollectError {
    #[error("command not found")]
    NotFound,
    #[error("collection timed out")]
    Timeout,
    #[error("exit {}: {stderr} (stdout: {stdout})", code.map(|value| value.to_string()).unwrap_or_else(|| "unknown".into()))]
    NonZeroExit { code: Option<i32>, stderr: String, stdout: String },
    #[error("{0}")]
    Io(String),
    #[error("invalid UTF-8 output")]
    Decode,
}

pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub fn run(program: &str, args: &[&str], timeout: std::time::Duration) -> Result<String, CollectError> {
    use std::{io::Read, process::{Command, Stdio}, time::Instant};
    let mut child = Command::new(program).args(args).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().map_err(|e| if e.kind() == std::io::ErrorKind::NotFound { CollectError::NotFound } else { CollectError::Io(e.to_string()) })?;
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || { let mut v = Vec::new(); stdout.read_to_end(&mut v).map(|_| v) });
    let err = std::thread::spawn(move || { let mut v = Vec::new(); stderr.read_to_end(&mut v).map(|_| v) });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < timeout => std::thread::sleep(std::time::Duration::from_millis(20)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                // Do not join readers here: descendants may still hold their pipes open.
                return Err(match result { Err(e) => CollectError::Io(e.to_string()), _ => CollectError::Timeout });
            }
        }
    };
    // A descendant can inherit the pipes even after the command exits. Bound reader waits too.
    while !out.is_finished() || !err.is_finished() {
        if started.elapsed() >= timeout { return Err(CollectError::Timeout); }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let stdout = out.join().map_err(|_| CollectError::Io("stdout reader panicked".into()))?.map_err(|e| CollectError::Io(e.to_string()))?;
    let stderr = err.join().map_err(|_| CollectError::Io("stderr reader panicked".into()))?.map_err(|e| CollectError::Io(e.to_string()))?;
    if !status.success() { return Err(CollectError::NonZeroExit { code: status.code(), stderr: String::from_utf8_lossy(&stderr).into(), stdout: String::from_utf8_lossy(&stdout).into() }); }
    String::from_utf8(stdout).map_err(|_| CollectError::Decode)
}

thread_local! {
    static ERRORS: std::cell::RefCell<std::collections::BTreeMap<String, String>> = Default::default();
}
fn record(key: &str, error: &CollectError) { ERRORS.with(|e| { e.borrow_mut().insert(key.into(), error.to_string()); }); }
fn clear_errors() { ERRORS.with(|e| e.borrow_mut().clear()); }
fn take_errors() -> std::collections::BTreeMap<String, String> { ERRORS.with(|e| std::mem::take(&mut *e.borrow_mut())) }

pub(crate) fn command_stdout(key: &str, program: &str, args: &[&str]) -> Option<String> {
    let mut result = run(program, args, DEFAULT_TIMEOUT);
    #[cfg(unix)]
    if matches!(result, Err(CollectError::NotFound)) {
        for dir in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
            result = run(&format!("{dir}/{program}"), args, DEFAULT_TIMEOUT);
            if !matches!(result, Err(CollectError::NotFound)) { break; }
        }
    }
    if let Err(e) = &result { record(key, e); }
    result.ok()
}

pub fn read_file(path: impl AsRef<std::path::Path>) -> Result<String, CollectError> {
    std::fs::read_to_string(path).map_err(|e| if e.kind() == std::io::ErrorKind::InvalidData { CollectError::Decode } else { CollectError::Io(e.to_string()) })
}
pub(crate) fn read_to_string(key: &str, path: &str) -> String {
    read_file(path).unwrap_or_else(|e| { record(key, &e); String::new() })
}

pub(crate) fn env_bypass() -> Vec<String> {
    let mut items = Vec::new();
    for key in ["no_proxy", "NO_PROXY"] {
        if let Ok(value) = std::env::var(key) {
            items.extend(parse::split_bypass_list(&value));
        }
    }
    items
}

pub(crate) fn env_proxy(names: &[&str]) -> String {
    for name in names {
        if let Ok(value) = std::env::var(name) {
            if !value.trim().is_empty() {
                return value;
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod collection_tests {
    use super::*;
    #[test]
    fn errors_are_keyed_and_drained_and_scans_discard_stale_errors() {
        clear_errors();
        assert!(command_stdout("dns", "aienv-nonexistent-binary-47ad", &[]).is_none());
        assert_eq!(take_errors().get("dns").map(String::as_str), Some("command not found"));
        assert!(take_errors().is_empty());
        record("stale_scan", &CollectError::Timeout);
        let snapshot = collect();
        assert!(!snapshot.errors.contains_key("stale_scan"));
        assert!(take_errors().is_empty());
    }
    #[test]
    fn missing_binary_is_typed() {
        assert!(matches!(run("aienv-nonexistent-binary-47ad", &[], DEFAULT_TIMEOUT), Err(CollectError::NotFound)));
    }
    #[cfg(unix)]
    #[test]
    fn command_timeout_is_bounded() {
        let started = std::time::Instant::now();
        assert!(matches!(run("sleep", &["5"], std::time::Duration::from_millis(200)), Err(CollectError::Timeout)));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }
    #[cfg(unix)]
    #[test]
    fn nonzero_exit_with_stdout_is_error() {
        match run("sh", &["-c", "printf partial; printf broken >&2; exit 7"], DEFAULT_TIMEOUT) {
            Err(CollectError::NonZeroExit { code, stdout, stderr }) => {
                assert_eq!(code, Some(7)); assert_eq!(stdout, "partial"); assert_eq!(stderr, "broken");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }
    #[test]
    fn unreadable_file_keeps_error() {
        assert!(read_file("/aienv-no-such-directory-47ad/hosts").is_err());
    }
}
