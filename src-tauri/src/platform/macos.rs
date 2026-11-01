use super::parse::{self, dedup_keep};
use super::{command_stdout, env_bypass, env_proxy, read_to_string, PlatformSnapshot, ProxySnapshot};

/// macOS collectors shell out to `scutil`, `route`, and `defaults`.
/// They are compiled on macOS and were not executed in the Linux verification environment.
pub fn collect() -> PlatformSnapshot {
    let route_v4_a = route_v4("1.1.1.1");
    let route_v4_b = route_v4("8.8.8.8");
    PlatformSnapshot {
        os: "macos".into(),
        timezone: timezone(),
        locale: locale(),
        dns_servers: dns_servers(route_v4_a.as_deref()),
        route_v4_a,
        route_v4_b,
        route_v6: route_v6("2606:4700:4700::1111"),
        proxy: proxy(),
        hosts: read_to_string("/etc/hosts"),
        location_enabled: location_enabled(),
    }
}

pub fn route_v4(dest: &str) -> Option<String> {
    let text = command_stdout("route", &["-n", "get", dest])?;
    iface_from_route(&text)
}

pub fn route_v6(dest: &str) -> Option<String> {
    let text = command_stdout("route", &["-n", "get", "-inet6", dest])?;
    iface_from_route(&text)
}

fn iface_from_route(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("interface:") {
            let iface = rest.trim();
            if !iface.is_empty() {
                return Some(iface.to_string());
            }
        }
    }
    None
}

fn timezone() -> String {
    if let Some(text) = command_stdout("readlink", &["/etc/localtime"]) {
        if let Some(idx) = text.find("zoneinfo/") {
            return text[idx + "zoneinfo/".len()..].trim().to_string();
        }
    }
    String::new()
}

fn locale() -> String {
    if let Some(text) = command_stdout("defaults", &["read", "-g", "AppleLanguages"]) {
        if let Some(lang) = parse::parse_apple_languages(&text) {
            return lang;
        }
    }
    command_stdout("defaults", &["read", "-g", "AppleLocale"])
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn dns_servers(iface: Option<&str>) -> Vec<String> {
    let Some(text) = command_stdout("scutil", &["--dns"]) else {
        return Vec::new();
    };
    dedup_keep(parse::parse_scutil_dns(&text, iface))
}

fn proxy() -> ProxySnapshot {
    let text = command_stdout("scutil", &["--proxy"]).unwrap_or_default();
    let (enabled, pac, bypass, pac_url) = parse::parse_scutil_proxy(&text);
    let mut bypass = bypass;
    bypass.extend(env_bypass());
    ProxySnapshot {
        enabled: enabled || !env_proxy(&["http_proxy", "https_proxy", "all_proxy"]).is_empty(),
        pac,
        pac_url: pac_url.unwrap_or_default(),
        bypass: dedup_keep(bypass),
        http_proxy: env_proxy(&["http_proxy", "HTTP_PROXY"]),
        https_proxy: env_proxy(&["https_proxy", "HTTPS_PROXY"]),
        socks_proxy: env_proxy(&["all_proxy", "ALL_PROXY"]),
    }
}

fn location_enabled() -> Option<bool> {
    // Reading locationd preferences often needs a local user privilege the app may not have.
    let text = command_stdout(
        "defaults",
        &["read", "/Library/Preferences/com.apple.locationd", "LocationServicesEnabled"],
    )?;
    let text = text.trim();
    if text == "1" || text.eq_ignore_ascii_case("true") {
        Some(true)
    } else if text == "0" || text.eq_ignore_ascii_case("false") {
        Some(false)
    } else {
        None
    }
}
