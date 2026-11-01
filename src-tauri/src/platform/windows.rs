use super::parse::{self, dedup_keep};
use super::{command_stdout, env_bypass, env_proxy, PlatformSnapshot, ProxySnapshot};

/// Windows collectors use PowerShell and the registry.
/// They are compiled only on Windows and were not executed in the Linux verification environment.
pub fn collect() -> PlatformSnapshot {
    super::clear_errors();
    let route_v4_a = route_v4("1.1.1.1");
    let route_v4_b = route_v4("8.8.8.8");
    PlatformSnapshot {
            dns_blocks: Vec::new(),
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
        errors: super::take_errors(),
    }
}

pub fn route_v4(dest: &str) -> Option<String> {
    let script = format!("(Find-NetRoute -RemoteIPAddress '{dest}' | Select-Object -First 1).InterfaceAlias");
    let text = powershell("route_v4", &script)?;
    let iface = text.lines().find(|line| !line.trim().is_empty())?.trim().to_string();
    if iface.is_empty() { None } else { Some(iface) }
}

pub fn route_v6(_dest: &str) -> super::Ipv6Route {
    let script = "$ErrorActionPreference = 'Stop'; $r = @(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0'); if ($r.Count -eq 0) { 'ABSENT' } else { 'IFACE:' + $r[0].InterfaceAlias }";
    match super::run("powershell", &["-NoProfile", "-NonInteractive", "-Command", script], super::DEFAULT_TIMEOUT) {
        Ok(text) if text.trim() == "ABSENT" => super::Ipv6Route::Absent,
        Ok(text) if text.trim().starts_with("IFACE:") && text.trim().len() > 6 => super::Ipv6Route::Present { iface: text.trim()[6..].into() },
        Ok(_) => super::Ipv6Route::Unknown("unparsable IPv6 route".into()),
        Err(e) => super::Ipv6Route::Unknown(e.to_string()),
    }
}

fn timezone() -> String {
    let text = powershell("timezone", "(Get-TimeZone).Id").unwrap_or_default();
    let id = text.lines().find(|line| !line.trim().is_empty()).unwrap_or("").trim();
    if id.is_empty() {
        String::new()
    } else {
        parse::windows_tz_to_iana(id)
    }
}

fn locale() -> String {
    powershell("locale", "(Get-Culture).Name")
        .unwrap_or_default()
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim()
        .to_string()
}

fn dns_servers() -> Vec<String> {
    let text = powershell("dns",
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
    // Read optional registry properties in one successful collection: absent values
    // are normal, while failure to read the settings remains a collection error.
    let raw = powershell("proxy", r"$ErrorActionPreference='Stop'; Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyEnable,ProxyServer,ProxyOverride,AutoConfigURL,AutoDetect | ConvertTo-Json -Compress").unwrap_or_default();
    let settings: serde_json::Value = serde_json::from_str(&raw).unwrap_or_else(|e| {
        super::record("proxy", &super::CollectError::Io(format!("invalid proxy settings: {e}")));
        serde_json::Value::Null
    });
    let value = |name: &str| settings[name].as_str().map(str::to_owned).or_else(|| settings[name].as_u64().map(|n| n.to_string())).unwrap_or_default();
    let enable=value("ProxyEnable");
    let server=value("ProxyServer");
    let bypass_raw=value("ProxyOverride");
    let pac_url=value("AutoConfigURL");
    let wpad=value("AutoDetect")=="1";
    let manual = parse::parse_windows_proxy(&enable, &server);
    let env = (env_proxy(&["http_proxy","HTTP_PROXY"]), env_proxy(&["https_proxy","HTTPS_PROXY"]), env_proxy(&["all_proxy","ALL_PROXY"]));
    let mut sources = std::collections::BTreeMap::new();
    for (key,value) in [("wininet.http",&manual.0),("wininet.https",&manual.1),("wininet.socks",&manual.2),("env.http",&env.0),("env.https",&env.1),("env.all",&env.2),("pac",&pac_url)] { if !value.is_empty() { sources.insert(key.into(),value.clone()); } }
    let enabled = [&manual.0,&manual.1,&manual.2,&env.0,&env.1,&env.2].iter().any(|v| !v.is_empty());
    let mut bypass = if manual.0.is_empty() && manual.1.is_empty() && manual.2.is_empty() { vec![] } else { parse::split_bypass_list(&bypass_raw) };
    if [&env.0,&env.1,&env.2].iter().any(|v| !v.is_empty()) { bypass.extend(env_bypass()); }
    ProxySnapshot { sources, wpad, enabled, pac: !pac_url.is_empty(), pac_url, bypass: dedup_keep(bypass),
        http_proxy: if !env.0.is_empty() {env.0} else {manual.0},
        https_proxy: if !env.1.is_empty() {env.1} else {manual.1},
        socks_proxy: if !env.2.is_empty() {env.2} else {manual.2} }
}

fn hosts() -> Result<String, super::CollectError> {
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let path = std::path::Path::new(&windir).join("System32\\drivers\\etc\\hosts");
    super::read_file(path)
}

fn location_enabled() -> Option<bool> {
    let text = powershell("location",
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

fn powershell(key: &str, script: &str) -> Option<String> {
    command_stdout(key, "powershell", &["-NoProfile", "-NonInteractive", "-Command", script])
}
