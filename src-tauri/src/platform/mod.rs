pub mod parse;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[derive(Debug, Clone)]
pub struct ProxySnapshot {
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
    pub os: String,
    pub timezone: String,
    pub locale: String,
    pub dns_servers: Vec<String>,
    pub route_v4_a: Option<String>,
    pub route_v4_b: Option<String>,
    pub route_v6: Option<String>,
    pub proxy: ProxySnapshot,
    pub hosts: String,
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
            os: std::env::consts::OS.to_string(),
            timezone: String::new(),
            locale: String::new(),
            dns_servers: Vec::new(),
            route_v4_a: None,
            route_v4_b: None,
            route_v6: None,
            proxy: ProxySnapshot {
                enabled: false,
                pac: false,
                pac_url: String::new(),
                bypass: Vec::new(),
                http_proxy: String::new(),
                https_proxy: String::new(),
                socks_proxy: String::new(),
            },
            hosts: String::new(),
            location_enabled: None,
        }
    }
}

pub(crate) fn command_stdout(program: &str, args: &[&str]) -> Option<String> {
    let candidates = [
        program.to_string(),
        format!("/usr/sbin/{program}"),
        format!("/usr/bin/{program}"),
        format!("/sbin/{program}"),
        format!("/bin/{program}"),
    ];
    for candidate in candidates {
        if let Ok(output) = std::process::Command::new(candidate).args(args).output() {
            if output.status.success() || !output.stdout.is_empty() {
                return Some(String::from_utf8_lossy(&output.stdout).to_string());
            }
        }
    }
    None
}

pub(crate) fn read_to_string(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
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
