use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfaceClass {
    Tunnel,
    Physical,
    Other,
}

pub fn classify_iface(name: &str) -> IfaceClass {
    let n = name
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .to_lowercase();
    if n.is_empty() || n == "lo" || n == "loopback" {
        return IfaceClass::Other;
    }
    if n.starts_with("veth")
        || n.starts_with("docker")
        || n.starts_with("br-")
        || n.starts_with("virbr")
        || n.starts_with("cni")
    {
        return IfaceClass::Other;
    }
    if n.starts_with("utun")
        || n.starts_with("tun")
        || n.starts_with("tap")
        || n.starts_with("wg")
        || n.starts_with("zt")
        || n.starts_with("gif")
        || n.starts_with("ppp")
        || n.starts_with("ipsec")
        || n.starts_with("awg")
    {
        return IfaceClass::Tunnel;
    }
    const NEEDLES: &[&str] = &[
        "wireguard",
        "wintun",
        "tailscale",
        "nordlynx",
        "mullvad",
        "openvpn",
        "zerotier",
        "outline",
        "clash",
        "sing-box",
        "singbox",
        "proton",
        "warp",
    ];
    if NEEDLES.iter().any(|needle| n.contains(needle)) {
        return IfaceClass::Tunnel;
    }
    if n.starts_with("en")
        || n.starts_with("eth")
        || n.starts_with("wlan")
        || n.starts_with("wlp")
        || n.starts_with("wlx")
        || n.starts_with("wlo")
        || n.starts_with("wifi")
        || n.starts_with("wi-fi")
        || n.starts_with("wwan")
        || n.starts_with("em")
        || is_biosdevname(&n)
        || n.contains("ethernet")
        || n.contains("wi-fi")
        || n.contains("wifi")
        || n.contains("wireless")
        || n.contains("local area")
    {
        return IfaceClass::Physical;
    }
    IfaceClass::Other
}

fn is_biosdevname(name: &str) -> bool {
    let mut parts = name.split('p');
    let Some(head) = parts.next() else {
        return false;
    };
    if !head.is_empty() {
        return false;
    }
    let mut nums = 0;
    for part in parts {
        if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        nums += 1;
    }
    nums >= 2
}

pub fn is_private_ip(ip: &str) -> bool {
    let ip = ip.trim();
    if ip.eq_ignore_ascii_case("::1") || ip == "0.0.0.0" || ip == "255.255.255.255" {
        return true;
    }
    if let Ok(v4) = ip.parse::<Ipv4Addr>() {
        return v4.is_private()
            || v4.is_loopback()
            || v4.is_link_local()
            || v4.is_unspecified()
            || v4.is_broadcast();
    }
    let lower = ip.to_lowercase();
    lower.starts_with("fe80:") || lower.starts_with("fc") || lower.starts_with("fd") || lower == "::"
}

pub fn is_ignored_dns(ip: &str) -> bool {
    matches!(
        ip.trim().to_lowercase().as_str(),
        "224.0.0.251" | "ff02::fb" | "ff02::1:3"
    )
}

pub fn cn_dns_provider(ip: &str) -> Option<&'static str> {
    match ip.trim() {
        "223.5.5.5" | "223.6.6.6" | "2400:3200::1" | "2400:3200:baba::1" => Some("AliDNS"),
        "119.29.29.29" | "119.28.28.28" | "182.254.116.116" | "2402:4e00::" => Some("DNSPod"),
        "114.114.114.114" | "114.114.115.115" => Some("114 DNS"),
        "180.76.76.76" | "2400:da00::6666" => Some("Baidu DNS"),
        "1.2.4.8" | "210.2.4.8" => Some("CNNIC"),
        "101.226.4.6" | "218.30.118.6" | "123.125.81.6" => Some("360 DNS"),
        "117.50.10.10" | "117.50.11.11" | "52.80.52.52" | "52.80.66.66" => Some("OneDNS"),
        "101.6.6.6" => Some("TUNA DNS"),
        "202.96.128.86" | "202.96.134.133" | "202.96.209.5" | "202.96.209.133" => Some("China Telecom"),
        "202.106.0.20" | "202.106.196.115" | "221.5.88.88" | "221.6.4.66" => Some("China Unicom"),
        _ => None,
    }
}

pub fn norm_country(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() == 2 && trimmed.chars().all(|c| c.is_ascii_alphabetic()) {
        return trimmed.to_uppercase();
    }
    match trimmed.to_lowercase().as_str() {
        "united states" | "united states of america" | "usa" | "美国" => "US".into(),
        "china" | "people's republic of china" | "中国" | "中华人民共和国" => "CN".into(),
        "hong kong" | "hong kong sar" | "香港" => "HK".into(),
        "macao" | "macau" | "澳门" | "澳門" => "MO".into(),
        "japan" | "日本" => "JP".into(),
        "singapore" | "新加坡" => "SG".into(),
        "south korea" | "korea, republic of" | "republic of korea" | "韩国" | "韓国" => "KR".into(),
        "taiwan" | "台湾" | "台灣" => "TW".into(),
        "united kingdom" | "uk" | "great britain" | "英国" => "GB".into(),
        "germany" | "德国" => "DE".into(),
        "france" | "法国" => "FR".into(),
        "australia" | "澳大利亚" => "AU".into(),
        "canada" | "加拿大" => "CA".into(),
        "netherlands" | "the netherlands" => "NL".into(),
        "ireland" => "IE".into(),
        "switzerland" => "CH".into(),
        "sweden" => "SE".into(),
        "norway" => "NO".into(),
        "denmark" => "DK".into(),
        "finland" => "FI".into(),
        "spain" => "ES".into(),
        "italy" => "IT".into(),
        "portugal" => "PT".into(),
        "poland" => "PL".into(),
        "austria" => "AT".into(),
        "belgium" => "BE".into(),
        "new zealand" => "NZ".into(),
        other => other.to_uppercase(),
    }
}

pub fn is_mainland_china(country: &str) -> bool {
    norm_country(country) == "CN"
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LangTag {
    pub lang: String,
    pub script: String,
    pub region: String,
}

pub fn split_tag(raw: &str) -> LangTag {
    let trimmed = raw.trim();
    let trimmed = trimmed.split(';').next().unwrap_or("").trim();
    let trimmed = trimmed.split('.').next().unwrap_or("").trim();
    let trimmed = trimmed.split('@').next().unwrap_or("").trim();
    let normalized = trimmed.replace('_', "-");
    let mut parts = normalized.split('-').filter(|part| !part.is_empty());
    let lang = parts.next().unwrap_or("").to_lowercase();
    let mut script = String::new();
    let mut region = String::new();
    for part in parts {
        if part.len() == 4 && part.chars().all(|c| c.is_ascii_alphabetic()) {
            script = part.to_lowercase();
        } else if (part.len() == 2 && part.chars().all(|c| c.is_ascii_alphabetic()))
            || (part.len() == 3 && part.chars().all(|c| c.is_ascii_digit()))
        {
            region = part.to_uppercase();
        }
    }
    LangTag { lang, script, region }
}

fn script_region_conflict(script: &str, region: &str) -> bool {
    match (script, region) {
        ("hant", "CN" | "SG") => true,
        ("hans", "TW" | "HK" | "MO") => true,
        _ => false,
    }
}

pub fn tags_compatible(observed: &str, expected: &str) -> bool {
    let observed = split_tag(observed);
    let expected = split_tag(expected);
    if observed.lang.is_empty() || observed.lang != expected.lang {
        return false;
    }
    if !observed.region.is_empty()
        && !expected.region.is_empty()
        && observed.region != expected.region
    {
        return false;
    }
    if !observed.script.is_empty()
        && !expected.script.is_empty()
        && observed.script != expected.script
    {
        return false;
    }
    if script_region_conflict(&expected.script, &observed.region)
        || script_region_conflict(&observed.script, &expected.region)
    {
        return false;
    }
    true
}

pub fn any_language_match(observed: &[String], expected: &[String]) -> bool {
    observed
        .iter()
        .any(|item| expected.iter().any(|want| tags_compatible(item, want)))
}

pub fn canon_tz(tz: &str) -> String {
    match tz.trim() {
        "UTC" | "Etc/UTC" | "GMT" | "Etc/GMT" | "Etc/GMT+0" | "Zulu" => "UTC".into(),
        other => other.to_string(),
    }
}

pub fn tz_allowed(tz: &str, allowed: &[String]) -> bool {
    let canon = canon_tz(tz);
    allowed.iter().any(|item| canon_tz(item) == canon)
}

pub fn parse_accept_language(header: &str) -> Vec<String> {
    header
        .split(',')
        .map(|part| part.split(';').next().unwrap_or("").trim().to_string())
        .filter(|part| !part.is_empty())
        .collect()
}

pub fn bypass_entry_matches(entry: &str, target: &str) -> bool {
    let entry = entry
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '<' || c == '>')
        .trim()
        .to_lowercase();
    if entry.is_empty() || entry == "local" || entry == "loopback" {
        return false;
    }
    if entry == "*" {
        return true;
    }
    let entry = entry.trim_start_matches('*').trim_start_matches('.').to_string();
    if entry.is_empty() {
        return true;
    }
    let target = target.trim().trim_end_matches('.').to_lowercase();
    target == entry || target.ends_with(&format!(".{entry}"))
}

pub fn bypass_hits_claude(entries: &[String]) -> Option<String> {
    const TARGETS: &[&str] = &[
        "claude.ai",
        "www.claude.ai",
        "anthropic.com",
        "api.anthropic.com",
        "console.anthropic.com",
        "claude.com",
    ];
    for entry in entries {
        if entry.trim() == "*" || bypass_entry_matches(entry, "claude.ai") && entry.trim() == "*" {
            return Some(entry.trim().to_string());
        }
        for target in TARGETS {
            if bypass_entry_matches(entry, target) {
                return Some(entry.trim().to_string());
            }
        }
    }
    None
}

pub fn split_bypass_list(raw: &str) -> Vec<String> {
    raw.split(|c| c == ',' || c == ';' || c == '\n')
        .map(|part| part.trim().trim_matches(|c| c == '[' || c == ']' || c == '\'' || c == '"').to_string())
        .filter(|part| !part.is_empty())
        .collect()
}

pub fn parse_ecs_subnets(lines: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    for line in lines {
        let lower = line.to_lowercase();
        if !(lower.contains("edns0-client-subnet") || lower.contains("edns-client-subnet")) {
            continue;
        }
        let mut parts = line.split_whitespace();
        let _label = parts.next();
        if let Some(subnet) = parts.next() {
            let subnet = subnet.trim_matches('"').trim().to_string();
            if !subnet.is_empty() {
                found.push(subnet);
            }
        }
    }
    found
}

pub fn parse_hosts(text: &str) -> Vec<(String, String)> {
    const TARGETS: &[&str] = &[
        "claude.ai",
        "www.claude.ai",
        "anthropic.com",
        "www.anthropic.com",
        "api.anthropic.com",
        "console.anthropic.com",
        "claude.com",
        "www.claude.com",
    ];
    let mut hits = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(ip) = parts.next() else { continue };
        for host in parts {
            let host = host.trim().trim_end_matches('.').to_lowercase();
            if TARGETS.iter().any(|target| *target == host) {
                hits.push((ip.to_string(), host));
            }
        }
    }
    hits
}

pub fn parse_ip_route_dev(text: &str) -> Option<String> {
    let mut prev_dev = false;
    for token in text.split_whitespace() {
        if prev_dev {
            return Some(token.to_string());
        }
        if token == "dev" {
            prev_dev = true;
        }
    }
    None
}

pub fn parse_proc_route_v4(text: &str, dest: Ipv4Addr) -> Option<String> {
    let dest_u = u32::from(dest);
    let mut best: Option<(u32, String)> = None;
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 {
            continue;
        }
        let Ok(raw_dest) = u32::from_str_radix(cols[1], 16) else {
            continue;
        };
        let Ok(raw_mask) = u32::from_str_radix(cols[7], 16) else {
            continue;
        };
        let flags = u32::from_str_radix(cols[3], 16).unwrap_or(0);
        const RTF_UP: u32 = 0x1;
        if flags & RTF_UP == 0 {
            continue;
        }
        // /proc/net/route prints little-endian words. swap_bytes turns them into
        // the same numeric order as u32::from(Ipv4Addr).
        let network = raw_dest.swap_bytes();
        let mask = raw_mask.swap_bytes();
        if dest_u & mask != network & mask {
            continue;
        }
        let prefix = mask.count_ones();
        let replace = match &best {
            None => true,
            Some((best_prefix, _)) => prefix >= *best_prefix,
        };
        if replace {
            best = Some((prefix, cols[0].to_string()));
        }
    }
    best.map(|(_, iface)| iface)
}

pub fn parse_proc_route_v6(text: &str, dest: &[u8; 16]) -> Option<String> {
    const RTF_REJECT: u32 = 0x0200;
    let mut best: Option<(u32, String)> = None;
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let dest_hex = cols[0];
        let Ok(prefix) = cols[1].parse::<u32>() else {
            continue;
        };
        let flags = u32::from_str_radix(cols[8], 16).unwrap_or(0);
        let iface = cols[9];
        if flags & RTF_REJECT != 0 || iface == "lo" {
            continue;
        }
        let Some(route_dest) = parse_v6_hex(dest_hex) else {
            continue;
        };
        if !prefix_match(dest, &route_dest, prefix) {
            continue;
        }
        let replace = match &best {
            None => true,
            Some((best_prefix, _)) => prefix >= *best_prefix,
        };
        if replace {
            best = Some((prefix, iface.to_string()));
        }
    }
    best.map(|(_, iface)| iface)
}

fn parse_v6_hex(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn prefix_match(addr: &[u8; 16], network: &[u8; 16], prefix: u32) -> bool {
    let prefix = prefix.min(128) as usize;
    let full = prefix / 8;
    let rem = prefix % 8;
    if addr[..full] != network[..full] {
        return false;
    }
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    addr[full] & mask == network[full] & mask
}

pub fn parse_resolv_conf(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("").trim();
            let mut parts = line.split_whitespace();
            if parts.next() == Some("nameserver") {
                parts.next().map(|ip| ip.to_string())
            } else {
                None
            }
        })
        .filter(|ip| !is_ignored_dns(ip))
        .collect()
}

pub fn parse_resolvectl(text: &str, want_iface: Option<&str>) -> Vec<String> {
    let mut servers = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Global:") {
            push_ips(rest, &mut servers);
            continue;
        }
        if let Some(start) = line.find('(') {
            if let Some(end) = line.find(')') {
                let iface = &line[start + 1..end];
                if let Some(want) = want_iface {
                    if !want.is_empty() && iface != want {
                        continue;
                    }
                }
                if let Some(colon) = line.find(':') {
                    push_ips(&line[colon + 1..], &mut servers);
                }
            }
        }
    }
    servers
}

fn push_ips(text: &str, out: &mut Vec<String>) {
    for token in text.split_whitespace() {
        let token = token.trim_matches(|c: char| c == ',' || c == '%');
        if token.contains('.') || token.contains(':') {
            if !is_ignored_dns(token) {
                out.push(token.to_string());
            }
        }
    }
}

pub fn dedup_keep(items: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for item in items {
        if !item.is_empty() && !out.iter().any(|seen| seen == &item) {
            out.push(item);
        }
    }
    out
}

pub fn parse_scutil_proxy(text: &str) -> (bool, bool, Vec<String>, Option<String>) {
    let mut enabled = false;
    let mut pac = false;
    let mut pac_url = None;
    let mut bypass = Vec::new();
    let mut in_exceptions = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("ExceptionsList") {
            in_exceptions = true;
            continue;
        }
        if in_exceptions {
            if trimmed.starts_with('}') {
                in_exceptions = false;
                continue;
            }
            if let Some((_, value)) = trimmed.split_once(':') {
                let value = value.trim().to_string();
                if !value.is_empty() {
                    bypass.push(value);
                }
            }
            continue;
        }
        if let Some((key, value)) = trimmed.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            match key {
                "HTTPEnable" | "HTTPSEnable" | "SOCKSEnable" if value == "1" => enabled = true,
                "ProxyAutoConfigEnable" if value == "1" => {
                    enabled = true;
                    pac = true;
                }
                "ProxyAutoConfigURLString" if !value.is_empty() => pac_url = Some(value.to_string()),
                _ => {}
            }
        }
    }
    (enabled, pac, bypass, pac_url)
}

pub fn parse_scutil_dns(text: &str, want_iface: Option<&str>) -> Vec<String> {
    let mut blocks: Vec<Vec<String>> = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let flush = |block: &mut Vec<String>, blocks: &mut Vec<Vec<String>>| {
        if !block.is_empty() {
            blocks.push(std::mem::take(block));
        }
    };
    for line in text.lines() {
        if line.starts_with("resolver #") {
            flush(&mut current, &mut blocks);
            continue;
        }
        current.push(line.to_string());
    }
    flush(&mut current, &mut blocks);
    let mut servers = Vec::new();
    for block in blocks {
        let mut mdns = false;
        let mut domain = false;
        let mut iface = String::new();
        let mut nameservers = Vec::new();
        for line in &block {
            let trimmed = line.trim();
            if trimmed.starts_with("options") && trimmed.contains("mdns") {
                mdns = true;
            }
            if trimmed.starts_with("domain") {
                domain = true;
            }
            if trimmed.starts_with("if_index") {
                if let Some(start) = trimmed.find('(') {
                    if let Some(end) = trimmed.find(')') {
                        iface = trimmed[start + 1..end].to_string();
                    }
                }
            }
            if trimmed.starts_with("nameserver[") {
                if let Some((_, ip)) = trimmed.split_once(':') {
                    nameservers.push(ip.trim().to_string());
                }
            }
        }
        if mdns || domain {
            continue;
        }
        if let Some(want) = want_iface {
            if !want.is_empty() && !iface.is_empty() && iface != want {
                continue;
            }
        }
        servers.extend(nameservers);
    }
    servers.into_iter().filter(|ip| !is_ignored_dns(ip)).collect()
}

pub fn parse_apple_languages(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim().trim_matches(|c| c == '(' || c == ')' || c == ',');
        if let Some(start) = line.find('"') {
            if let Some(end) = line[start + 1..].find('"') {
                let value = &line[start + 1..start + 1 + end];
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    let trimmed = text.trim();
    if !trimmed.is_empty() && !trimmed.contains('(') {
        return Some(trimmed.trim_matches('"').to_string());
    }
    None
}

pub fn parse_localectl_lang(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(idx) = line.find("LANG=") {
            let value = line[idx + 5..].split_whitespace().next().unwrap_or("");
            let value = value.trim_matches('"');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

pub fn parse_kioslaverc(text: &str) -> (bool, bool, Vec<String>, Option<String>) {
    let mut section = false;
    let mut proxy_type = 0;
    let mut no_proxy = Vec::new();
    let mut pac_url = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            section = line.eq_ignore_ascii_case("[Proxy Settings]");
            continue;
        }
        if !section {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "ProxyType" => proxy_type = value.trim().parse().unwrap_or(0),
                "NoProxyFor" => no_proxy = split_bypass_list(value),
                "Proxy Config Script" | "autoconfigUrl" => {
                    let value = value.trim();
                    if !value.is_empty() {
                        pac_url = Some(value.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    let pac = proxy_type == 2;
    let enabled = proxy_type == 1 || pac;
    (enabled, pac, no_proxy, pac_url)
}

pub fn windows_tz_to_iana(windows_id: &str) -> String {
    let id = windows_id.trim();
    let mapped = match id {
        "Pacific Standard Time" => "America/Los_Angeles",
        "Mountain Standard Time" => "America/Denver",
        "US Mountain Standard Time" => "America/Phoenix",
        "Central Standard Time" => "America/Chicago",
        "Eastern Standard Time" => "America/New_York",
        "Alaskan Standard Time" => "America/Anchorage",
        "Hawaiian Standard Time" => "Pacific/Honolulu",
        "Aleutian Standard Time" => "America/Adak",
        "Atlantic Standard Time" => "America/Halifax",
        "Newfoundland Standard Time" => "America/St_Johns",
        "Canada Central Standard Time" => "America/Regina",
        "SA Pacific Standard Time" => "America/Bogota",
        "GMT Standard Time" => "Europe/London",
        "Greenwich Standard Time" => "Atlantic/Reykjavik",
        "W. Europe Standard Time" => "Europe/Berlin",
        "Romance Standard Time" => "Europe/Paris",
        "Central Europe Standard Time" => "Europe/Budapest",
        "Central European Standard Time" => "Europe/Warsaw",
        "E. Europe Standard Time" => "Europe/Bucharest",
        "FLE Standard Time" => "Europe/Kiev",
        "GTB Standard Time" => "Europe/Athens",
        "South Africa Standard Time" => "Africa/Johannesburg",
        "Tokyo Standard Time" => "Asia/Tokyo",
        "Korea Standard Time" => "Asia/Seoul",
        "Singapore Standard Time" => "Asia/Singapore",
        "Taipei Standard Time" => "Asia/Taipei",
        "China Standard Time" => "Asia/Shanghai",
        "AUS Eastern Standard Time" => "Australia/Sydney",
        "E. Australia Standard Time" => "Australia/Brisbane",
        "Cen. Australia Standard Time" => "Australia/Adelaide",
        "AUS Central Standard Time" => "Australia/Darwin",
        "W. Australia Standard Time" => "Australia/Perth",
        "Tasmania Standard Time" => "Australia/Hobart",
        "New Zealand Standard Time" => "Pacific/Auckland",
        "UTC" | "Coordinated Universal Time" => "UTC",
        other => other,
    };
    mapped.to_string()
}

pub fn datacenter_hint(org: &str, hosting: Option<bool>) -> bool {
    if hosting == Some(true) {
        return true;
    }
    let org = org.to_lowercase();
    const NEEDLES: &[&str] = &[
        "amazon",
        "aws",
        "google cloud",
        "google llc",
        "digitalocean",
        "linode",
        "akamai",
        "cloudflare",
        "ovh",
        "hetzner",
        "leaseweb",
        "choopa",
        "m247",
        "datacamp",
        "vultr",
        "contabo",
        "oracle cloud",
        "alibaba",
        "tencent",
        "huawei cloud",
        "hostinger",
        "scaleway",
        "psychz",
        "quadranet",
        "frantech",
        "constant company",
        "datacamp",
        "colo",
        "datacenter",
        "data center",
        "hosting",
    ];
    NEEDLES.iter().any(|needle| org.contains(needle))
}

pub fn known_public_ca(issuer: &str) -> bool {
    let issuer = issuer.to_lowercase();
    const NEEDLES: &[&str] = &[
        "let's encrypt",
        "lets encrypt",
        "isrg",
        "digicert",
        "google trust services",
        "globalsign",
        "sectigo",
        "amazon",
        "starfield",
        "go daddy",
        "godaddy",
        "entrust",
        "microsoft",
        "comodo",
        "usertrust",
        "buypass",
        "actalis",
        "certainly",
        "ssl.com",
        "identrust",
        "geotrust",
        "thawte",
        "rapidssl",
        "quovadis",
        "swisssign",
        "harica",
        "certum",
        "zerossl",
        "cloudflare",
        "network solutions",
        "cpanel",
    ];
    NEEDLES.iter().any(|needle| issuer.contains(needle))
}

pub fn suspicious_intercept_ca(issuer: &str) -> bool {
    let issuer = issuer.to_lowercase();
    const NEEDLES: &[&str] = &[
        "mitmproxy",
        "fiddler",
        "charles proxy",
        "charles",
        "do_not_trust",
        "dont_trust",
        "do not trust",
        "mkcert",
        "burp",
        "portswigger",
        "proxyman",
        "http toolkit",
        "clash",
    ];
    NEEDLES.iter().any(|needle| issuer.contains(needle))
}

pub fn corporate_intercept_ca(issuer: &str) -> bool {
    let issuer = issuer.to_lowercase();
    const NEEDLES: &[&str] = &[
        "zscaler",
        "blue coat",
        "bluecoat",
        "forcepoint",
        "netskope",
        "palo alto",
        "fortinet",
        "cisco umbrella",
    ];
    NEEDLES.iter().any(|needle| issuer.contains(needle))
}

pub fn pac_mentions_claude(body: &str) -> bool {
    let lower = body.to_lowercase();
    lower.contains("claude.ai")
        || lower.contains("anthropic.com")
        || lower.contains("claude.com")
}

pub fn os_token_from_ua(ua: &str) -> &'static str {
    let ua = ua.to_lowercase();
    if ua.contains("windows nt") || ua.contains("win64") || ua.contains("win32") {
        "windows"
    } else if ua.contains("mac os x") || ua.contains("macintosh") {
        "macos"
    } else if ua.contains("android") {
        "android"
    } else if ua.contains("linux") {
        "linux"
    } else {
        "unknown"
    }
}

pub fn platform_matches_os(os: &str, platform: &str, ua: &str) -> bool {
    let os = os.to_lowercase();
    let platform = platform.to_lowercase();
    let ua_os = os_token_from_ua(ua);
    let platform_os = if platform.contains("win") {
        "windows"
    } else if platform.contains("mac") {
        "macos"
    } else if platform.contains("linux") || platform.contains("x11") {
        "linux"
    } else if platform.is_empty() {
        "unknown"
    } else {
        "other"
    };
    let os_ok = match os.as_str() {
        "windows" => platform_os == "windows" || platform_os == "unknown",
        "macos" => platform_os == "macos" || platform_os == "unknown",
        "linux" => platform_os == "linux" || platform_os == "unknown",
        _ => true,
    };
    let ua_ok = ua_os == "unknown" || ua_os == os || (os == "linux" && ua_os == "android");
    // A desktop Linux machine should not present as Android, and vice versa is out of scope.
    let ua_ok = if os == "linux" {
        ua_os == "linux" || ua_os == "unknown"
    } else {
        ua_ok
    };
    os_ok && ua_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_tunnel_and_physical_names() {
        for name in ["utun3", "tun0", "tap0", "wg0", "tailscale0", "ppp0", "zt0", "outline-tap0"] {
            assert_eq!(classify_iface(name), IfaceClass::Tunnel, "{name}");
        }
        for name in [
            "Tailscale",
            "WireGuard Tunnel",
            "NordLynx",
            "Wintun Userspace Tunnel",
            "OpenVPN Data Channel",
        ] {
            assert_eq!(classify_iface(name), IfaceClass::Tunnel, "{name}");
        }
        for name in ["en0", "enp0s3", "eth0", "wlan0", "wlp3s0", "ens5", "Wi-Fi", "Ethernet"] {
            assert_eq!(classify_iface(name), IfaceClass::Physical, "{name}");
        }
        assert_eq!(classify_iface("docker0"), IfaceClass::Other);
        assert_eq!(classify_iface("lo"), IfaceClass::Other);
        assert_eq!(classify_iface("vEthernet (Default Switch)"), IfaceClass::Other);
    }

    #[test]
    fn private_and_china_dns_tables() {
        assert!(is_private_ip("10.0.0.2"));
        assert!(is_private_ip("127.0.0.1"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("172.30.0.1"));
        assert!(!is_private_ip("1.1.1.1"));
        assert!(!is_private_ip("8.8.8.8"));
        assert!(is_private_ip("fe80::1"));
        assert!(is_private_ip("fd00::1"));
        assert_eq!(cn_dns_provider("223.5.5.5"), Some("AliDNS"));
        assert_eq!(cn_dns_provider("114.114.114.114"), Some("114 DNS"));
        assert_eq!(cn_dns_provider("1.1.1.1"), None);
        assert!(is_mainland_china("CN"));
        assert!(is_mainland_china("China"));
        assert!(!is_mainland_china("HK"));
        assert!(!is_mainland_china("US"));
    }

    #[test]
    fn language_tags_follow_the_region() {
        assert!(tags_compatible("en_US.UTF-8", "en-US"));
        assert!(!tags_compatible("en_GB.UTF-8", "en-US"));
        assert!(tags_compatible("en", "en-US"));
        assert!(tags_compatible("ja_JP", "ja-JP"));
        assert!(!tags_compatible("zh_CN.UTF-8", "zh-TW"));
        assert!(!tags_compatible("zh-CN", "zh-Hant"));
        assert!(tags_compatible("zh-TW", "zh-Hant"));
        assert!(any_language_match(&["en-US".into(), "zh-CN".into()], &["en-US".into()]));
        assert!(!any_language_match(&["zh-CN".into()], &["en-US".into()]));
    }

    #[test]
    fn bypass_list_catches_claude_and_wildcards() {
        assert!(bypass_entry_matches("*", "claude.ai"));
        assert!(bypass_entry_matches("*.anthropic.com", "api.anthropic.com"));
        assert!(bypass_entry_matches(".claude.ai", "claude.ai"));
        assert!(bypass_entry_matches("claude.ai", "www.claude.ai"));
        assert!(!bypass_entry_matches("example.com", "claude.ai"));
        assert!(!bypass_entry_matches("<local>", "claude.ai"));
        let entries = split_bypass_list("<local>;localhost,*.claude.ai");
        assert_eq!(bypass_hits_claude(&entries).as_deref(), Some("*.claude.ai"));
        assert!(bypass_hits_claude(&["127.0.0.1".into()]).is_none());
    }

    #[test]
    fn parses_routes_hosts_dns_and_proxy_samples() {
        let proc = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
enp0s3\t00000000\t01001EAC\t0003\t0\t0\t0\t00000000\t0\t0\t0
docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
enp0s3\t00001EAC\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
";
        assert_eq!(
            parse_proc_route_v4(proc, "1.1.1.1".parse().unwrap()).as_deref(),
            Some("enp0s3")
        );
        assert_eq!(
            parse_proc_route_v4(proc, "172.17.0.5".parse().unwrap()).as_deref(),
            Some("docker0")
        );
        assert_eq!(
            parse_proc_route_v4(proc, "172.30.0.9".parse().unwrap()).as_deref(),
            Some("enp0s3")
        );

        let v6 = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo
fe800000000000000000000000000000 10 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 enp0s3
";
        let dest = [
            0x26u8, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11,
        ];
        assert!(parse_proc_route_v6(v6, &dest).is_none());

        assert_eq!(
            parse_ip_route_dev("1.1.1.1 via 172.30.0.1 dev enp0s3 src 172.30.0.20 uid 1000").as_deref(),
            Some("enp0s3")
        );
        assert_eq!(
            parse_resolv_conf("nameserver 10.0.0.2\n# nameserver 1.1.1.1\nnameserver 224.0.0.251\n"),
            vec!["10.0.0.2".to_string()]
        );
        let hosts = "127.0.0.1 localhost\n0.0.0.0 claude.ai api.anthropic.com\n1.2.3.4 example.com\n";
        let overrides = parse_hosts(hosts);
        assert_eq!(overrides.len(), 2);
        assert!(overrides.iter().any(|(_, host)| host == "claude.ai"));

        let proxy = "\
<dictionary> {
  HTTPEnable : 1
  HTTPSEnable : 1
  SOCKSEnable : 0
  ProxyAutoConfigEnable : 0
  ExceptionsList : <array> {
    0 : *.local
    1 : claude.ai
  }
}
";
        let (enabled, pac, bypass, _) = parse_scutil_proxy(proxy);
        assert!(enabled);
        assert!(!pac);
        assert_eq!(bypass_hits_claude(&bypass).as_deref(), Some("claude.ai"));

        let dns = "\
resolver #1
  nameserver[0] : 1.1.1.1
  if_index : 12 (en0)
  flags    : Request A records
resolver #2
  domain   : local
  options  : mdns
  nameserver[0] : 224.0.0.251
";
        assert_eq!(parse_scutil_dns(dns, Some("en0")), vec!["1.1.1.1".to_string()]);
        assert_eq!(
            parse_apple_languages("(\n    \"en-US\",\n    \"zh-Hans-CN\"\n)\n").as_deref(),
            Some("en-US")
        );
        assert_eq!(windows_tz_to_iana("Tokyo Standard Time"), "Asia/Tokyo");
        assert_eq!(windows_tz_to_iana("China Standard Time"), "Asia/Shanghai");
        assert!(datacenter_hint("AS14618 Amazon.com, Inc.", Some(true)));
        assert!(!datacenter_hint("Comcast Cable Communications", Some(false)));
        assert!(known_public_ca("C=US, O=Google Trust Services, CN=WE1"));
        assert!(suspicious_intercept_ca("O=mitmproxy, CN=mitmproxy"));
        assert!(pac_mentions_claude("if (host == \"claude.ai\") return \"DIRECT\";"));
    }

    #[test]
    fn ecs_and_timezone_helpers() {
        let lines = vec![
            "35.170.83.204".into(),
            "edns0-client-subnet 1.2.3.0/24".into(),
        ];
        assert_eq!(parse_ecs_subnets(&lines), vec!["1.2.3.0/24".to_string()]);
        assert!(parse_ecs_subnets(&["35.170.83.204".into()]).is_empty());
        assert_eq!(canon_tz("Etc/UTC"), "UTC");
        assert!(tz_allowed("America/Los_Angeles", &["America/Los_Angeles".into(), "America/New_York".into()]));
        assert!(!tz_allowed("Asia/Shanghai", &["America/New_York".into()]));
        assert!(platform_matches_os("linux", "Linux x86_64", "Mozilla/5.0 (X11; Linux x86_64)"));
        assert!(!platform_matches_os("linux", "Win32", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"));
    }
}
