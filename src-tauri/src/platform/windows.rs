use super::parse::{self, dedup_keep};
use super::{command_stdout, env_bypass, env_proxy, PlatformSnapshot, ProxySnapshot};

/// Windows collectors use PowerShell and the registry.
/// They are compiled only on Windows and were not executed in the Linux verification environment.
pub fn collect() -> PlatformSnapshot {
    let route_v4_a = route_v4("1.1.1.1");
    let route_v4_b = route_v4("8.8.8.8");
    PlatformSnapshot {
        os: "windows".into(),
        timezone: timezone(),
        locale: locale(),
        dns_servers: dns_servers(),
        route_v4_a,
        route_v4_b,
        route_v6: route_v6("2606:4700:4700::1111"),
        proxy: proxy(),
        hosts: hosts(),
        location_enabled: location_enabled(),
    }
}

pub fn route_v4(dest: &str) -> Option<String> {
    let script = format!("(Find-NetRoute -RemoteIPAddress '{dest}' | Select-Object -First 1).InterfaceAlias");
    let text = powershell(&script)?;
    let iface = text.lines().find(|line| !line.trim().is_empty())?.trim().to_string();
    if iface.is_empty() { None } else { Some(iface) }
}

pub fn route_v6(dest: &str) -> Option<String> {
    route_v4(dest)
}

fn timezone() -> String {
    let text = powershell("(Get-TimeZone).Id").unwrap_or_default();
    let id = text.lines().find(|line| !line.trim().is_empty()).unwrap_or("").trim();
    if id.is_empty() {
        String::new()
    } else {
        parse::windows_tz_to_iana(id)
    }
}

fn locale() -> String {
    powershell("(Get-Culture).Name")
        .unwrap_or_default()
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim()
        .to_string()
}

fn dns_servers() -> Vec<String> {
    let text = powershell(
        "(Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses } | ForEach-Object { $_.ServerAddresses }) -join \"`n\"",
    )
    .unwrap_or_default();
    dedup_keep(
        text.lines()
            .map(|line| line.trim().to_string())
            .filter(|ip| !ip.is_empty() && !parse::is_ignored_dns(ip))
            .collect(),
    )
}

fn proxy() -> ProxySnapshot {
    let enable = reg("ProxyEnable").unwrap_or_default();
    let server = reg("ProxyServer").unwrap_or_default();
    let bypass_raw = reg("ProxyOverride").unwrap_or_default();
    let pac_url = reg("AutoConfigURL").unwrap_or_default();
    let mut bypass = parse::split_bypass_list(&bypass_raw);
    bypass.extend(env_bypass());
    let enabled = enable.trim() == "0x1" || enable.trim() == "1" || !server.trim().is_empty();
    ProxySnapshot {
        enabled: enabled || !env_proxy(&["http_proxy", "https_proxy", "all_proxy"]).is_empty(),
        pac: !pac_url.trim().is_empty(),
        pac_url: pac_url.trim().to_string(),
        bypass: dedup_keep(bypass),
        http_proxy: if server.trim().is_empty() { env_proxy(&["http_proxy", "HTTP_PROXY"]) } else { server.trim().to_string() },
        https_proxy: env_proxy(&["https_proxy", "HTTPS_PROXY"]),
        socks_proxy: env_proxy(&["all_proxy", "ALL_PROXY"]),
    }
}

fn hosts() -> String {
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let path = std::path::Path::new(&windir).join("System32\\drivers\\etc\\hosts");
    std::fs::read_to_string(path).unwrap_or_default()
}

fn location_enabled() -> Option<bool> {
    let text = powershell(
        "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location' -Name Value).Value",
    )?;
    let text = text.trim().to_lowercase();
    if text == "allow" {
        Some(true)
    } else if text == "deny" {
        Some(false)
    } else {
        None
    }
}

fn powershell(script: &str) -> Option<String> {
    command_stdout("powershell", &["-NoProfile", "-NonInteractive", "-Command", script])
}

fn reg(name: &str) -> Option<String> {
    let text = command_stdout(
        "reg",
        &[
            "query",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            "/v",
            name,
        ],
    )?;
    for line in text.lines() {
        let line = line.trim();
        if line.to_lowercase().starts_with(&name.to_lowercase()) {
            let mut parts = line.split_whitespace();
            let _key = parts.next();
            let _typ = parts.next();
            let value = parts.collect::<Vec<_>>().join(" ");
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}
