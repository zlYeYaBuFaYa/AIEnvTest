use std::net::Ipv4Addr;

use super::parse::{self, dedup_keep};
use super::{command_stdout, env_bypass, env_proxy, read_to_string, PlatformSnapshot, ProxySnapshot};

pub fn collect() -> PlatformSnapshot {
    super::clear_errors();
    let route_v4_a = route_v4("1.1.1.1");
    let route_v4_b = route_v4("8.8.8.8");
    let route_v6 = route_v6("2606:4700:4700::1111");
    let dns_iface = route_v4_a.clone().or_else(|| route_v4_b.clone());
    PlatformSnapshot {
        os: "linux".into(),
        timezone: timezone(),
        locale: locale(),
        dns_servers: dns_servers(dns_iface.as_deref()),
        route_v4_a,
        route_v4_b,
        route_v6,
        proxy: proxy(),
        hosts: super::read_file("/etc/hosts"),
        location_enabled: location_enabled(),
        errors: super::take_errors(),
    }
}

pub fn route_v4(dest: &str) -> Option<String> {
    if let Some(text) = command_stdout("route_v4", "ip", &["-4", "route", "get", dest]) {
        if let Some(dev) = parse::parse_ip_route_dev(&text) {
            return Some(dev);
        }
    }
    let dest: Ipv4Addr = dest.parse().ok()?;
    parse::parse_proc_route_v4(&read_to_string("route_v4", "/proc/net/route"), dest)
}

pub fn route_v6(dest: &str) -> super::Ipv6Route {
    use super::Ipv6Route::*;
    // /proc is an authoritative route table even when iproute2 is unavailable.
    match super::read_file("/proc/net/ipv6_route") {
        Ok(text) => {
            if text.lines().any(|l| { let f: Vec<_> = l.split_whitespace().collect(); f.len() != 10 || f[..9].iter().zip([32, 2, 32, 2, 32, 8, 8, 8, 8]).any(|(v, len)| v.len() != len || !v.chars().all(|c| c.is_ascii_hexdigit())) || u8::from_str_radix(f[1], 16).map_or(true, |n| n > 128) || u8::from_str_radix(f[3], 16).map_or(true, |n| n > 128) }) {
                return Unknown("unparsable IPv6 route table".into());
            }
            let addr = dest.parse::<std::net::Ipv6Addr>().unwrap();
            match parse::parse_proc_route_v6(&text, &addr.octets()) {
                Some(iface) if iface != "lo" => Present { iface },
                _ => Absent,
            }
        }
        Err(e) => Unknown(e.to_string()),
    }
}

fn timezone() -> String {
    if let Some(text) = command_stdout("timezone", "timedatectl", &["show", "-p", "Timezone", "--value"]) {
        let tz = text.trim();
        if !tz.is_empty() {
            return tz.to_string();
        }
    }
    let file = read_to_string("timezone", "/etc/timezone");
    if !file.trim().is_empty() {
        return file.trim().to_string();
    }
    if let Some(text) = command_stdout("timezone", "readlink", &["-f", "/etc/localtime"]) {
        if let Some(idx) = text.find("zoneinfo/") {
            return text[idx + "zoneinfo/".len()..].trim().to_string();
        }
    }
    String::new()
}

fn locale() -> String {
    // The session locale is what browsers and apps actually inherit.
    // /etc/default/locale is only a fallback when the session did not choose one.
    for key in ["LC_ALL", "LANG", "LC_MESSAGES"] {
        if let Ok(value) = std::env::var(key) {
            if usable_locale(&value) {
                return value;
            }
        }
    }
    if let Some(text) = command_stdout("locale", "localectl", &["status"]) {
        if let Some(lang) = parse::parse_localectl_lang(&text) {
            if usable_locale(&lang) {
                return lang;
            }
        }
    }
    if let Some(lang) = parse::parse_localectl_lang(&read_to_string("locale", "/etc/default/locale")) {
        if usable_locale(&lang) {
            return lang;
        }
    }
    std::env::var("LANG").unwrap_or_default()
}

fn usable_locale(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && value != "C" && value != "POSIX"
}

fn dns_servers(iface: Option<&str>) -> Vec<String> {
    let mut servers = Vec::new();
    if let Some(text) = command_stdout("dns", "resolvectl", &["dns"]) {
        servers.extend(parse::parse_resolvectl(&text, iface));
    }
    servers.extend(parse::parse_resolv_conf(&read_to_string("dns", "/etc/resolv.conf")));
    if let Some(iface) = iface {
        if let Some(text) = command_stdout("dns", "nmcli", &["-t", "-f", "IP4.DNS,IP6.DNS", "device", "show", iface]) {
            for line in text.lines() {
                if let Some((_, value)) = line.split_once(':') {
                    if !value.trim().is_empty() {
                        servers.push(value.trim().to_string());
                    }
                }
            }
        }
    }
    dedup_keep(servers.into_iter().filter(|ip| !parse::is_ignored_dns(ip)).collect())
}

fn proxy() -> ProxySnapshot {
    let mut enabled = false;
    let mut pac = false;
    let mut pac_url = String::new();
    let mut bypass = env_bypass();
    if let Some(mode) = command_stdout("proxy", "gsettings", &["get", "org.gnome.system.proxy", "mode"]) {
        let mode = mode.trim().trim_matches('\'').to_string();
        if mode == "manual" {
            enabled = true;
        } else if mode == "auto" {
            enabled = true;
            pac = true;
        }
    }
    if let Some(text) = command_stdout("proxy", "gsettings", &["get", "org.gnome.system.proxy", "ignore-hosts"]) {
        bypass.extend(parse::split_bypass_list(&text));
    }
    if let Some(url) = command_stdout("proxy", "gsettings", &["get", "org.gnome.system.proxy", "autoconfig-url"]) {
        let url = url.trim().trim_matches('\'').to_string();
        if !url.is_empty() && url != "''" && url != "@as []" {
            pac_url = url;
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let path = std::path::Path::new(&home).join(".config/kioslaverc");
        if let Ok(text) = std::fs::read_to_string(path) {
            let (kde_enabled, kde_pac, kde_bypass, kde_url) = parse::parse_kioslaverc(&text);
            if kde_enabled {
                enabled = true;
            }
            if kde_pac {
                pac = true;
            }
            bypass.extend(kde_bypass);
            if pac_url.is_empty() {
                pac_url = kde_url.unwrap_or_default();
            }
        }
    }
    let env_text = read_to_string("proxy", "/etc/environment");
    for line in env_text.lines() {
        if let Some(value) = line.strip_prefix("no_proxy=").or_else(|| line.strip_prefix("NO_PROXY=")) {
            bypass.extend(parse::split_bypass_list(value.trim_matches('"')));
        }
    }
    ProxySnapshot {
        http_proxy: first_nonempty(&[
            env_proxy(&["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"]),
            gsettings_host_port("org.gnome.system.proxy.http"),
        ]),
        https_proxy: gsettings_host_port("org.gnome.system.proxy.https"),
        socks_proxy: gsettings_host_port("org.gnome.system.proxy.socks"),
        enabled: enabled || !env_proxy(&["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy"]).is_empty(),
        pac,
        pac_url,
        bypass: dedup_keep(bypass),
    }
}

fn first_nonempty(values: &[String]) -> String {
    values.iter().find(|value| !value.is_empty()).cloned().unwrap_or_default()
}

fn gsettings_host_port(schema: &str) -> String {
    let host = command_stdout("proxy", "gsettings", &["get", schema, "host"])
        .unwrap_or_default();
    let host = host.trim().trim_matches('\'').to_string();
    if host.is_empty() {
        return String::new();
    }
    let port = command_stdout("proxy", "gsettings", &["get", schema, "port"])
        .unwrap_or_default();
    let port = port.trim();
    if port.is_empty() || port == "0" {
        host
    } else {
        format!("{host}:{port}")
    }
}

fn location_enabled() -> Option<bool> {
    let text = command_stdout("location", "gsettings", &["get", "org.gnome.system.location", "enabled"])?;
    let text = text.trim().to_lowercase();
    if text.contains("true") {
        Some(true)
    } else if text.contains("false") {
        Some(false)
    } else {
        None
    }
}
