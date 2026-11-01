//! PowerShell JSON parsing is deliberately available on every target.
use super::{CollectError, parse::{self, IfaceClass, ResolverBlock}};
use serde_json::Value;

// Missing routes, NRPT rules and location consent are normal; other calls retain Stop.
pub fn route_script() -> String {
    "Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue | Select-Object ifIndex,DestinationPrefix,NextHop,RouteMetric,InterfaceMetric".into()
}
pub fn nrpt_script() -> String {
    "Get-DnsClientNrptPolicy -Effective -ErrorAction SilentlyContinue | Select-Object *".into()
}
pub fn location_script() -> String {
    r"(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -Name Value -ErrorAction SilentlyContinue).Value".into()
}
pub fn powershell_script(script: &str) -> String {
    format!("[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); $ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; {script} | ConvertTo-Json -Depth 4 -Compress")
}

pub fn json_rows(bytes: &[u8]) -> Result<Vec<Value>, CollectError> {
    let text = std::str::from_utf8(bytes).map_err(|_| CollectError::Decode)?;
    let text = text.trim_start_matches('\u{feff}').trim();
    if text.is_empty() { return Ok(vec![]); }
    let value: Value = serde_json::from_str(text).map_err(|e| CollectError::Io(format!("invalid PowerShell JSON: {e}")))?;
    Ok(match value { Value::Array(rows) => rows, Value::Null => vec![], row => vec![row] })
}
fn string(v: &Value, key: &str) -> String { v[key].as_str().unwrap_or("").to_string() }
fn number(v: &Value, key: &str) -> u32 { v[key].as_u64().and_then(|n| n.try_into().ok()).or_else(|| v[key].as_str()?.parse().ok()).unwrap_or(0) }
fn strings(v: &Value) -> Vec<String> { match v { Value::Array(a) => a.iter().flat_map(strings).collect(), Value::String(s) => s.split([',',';']).map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect(), _ => vec![] } }
fn index(v: &Value) -> u32 { let n=number(v,"ifIndex"); if n==0 {number(v,"InterfaceIndex")} else {n} }
fn up(v: &Value) -> bool { string(v,"Status").eq_ignore_ascii_case("up") || number(v,"Status")==1 }
fn connected(v: &Value) -> bool { string(v,"ConnectionState").eq_ignore_ascii_case("connected") || v["ConnectionState"].as_u64()==Some(1) }

pub fn classify_adapter(a: &Value) -> IfaceClass {
    let kind = number(a, "InterfaceType");
    if matches!(kind, 131 | 53) {
        return IfaceClass::Tunnel;
    }
    if a["HardwareInterface"].as_bool() == Some(true) && matches!(kind, 6 | 71) {
        return IfaceClass::Physical;
    }
    let driver = ["InterfaceDescription", "DriverDescription", "ComponentID"]
        .map(|key| string(a, key)).join(" ").to_lowercase();
    let local = |text: &str| ["hyper-v", "vethernet", "virtualbox", "vmware", "host-only"]
        .iter().any(|needle| text.contains(needle));
    let vpn = |text: &str| ["wintun", "tap-windows", "tap0901", "wireguard", "openvpn",
        "clash", "mihomo", "sing-box", "v2rayn", "tailscale", "zerotier", "anyconnect",
        "globalprotect", "fortinet", "utun"].iter().any(|needle| text.contains(needle));
    let virtual_adapter = a["HardwareInterface"].as_bool() == Some(false)
        || a["Virtual"].as_bool() == Some(true);
    if local(&driver) {
        return IfaceClass::Other;
    }
    if virtual_adapter && vpn(&driver) {
        return IfaceClass::Tunnel;
    }
    // Only use the display name after type and driver evidence is exhausted.
    let name = string(a, "Name").to_lowercase();
    if virtual_adapter && !local(&name) && vpn(&name) {
        return IfaceClass::Tunnel;
    }
    IfaceClass::Other
}
#[derive(Debug, Clone)]
pub struct EffectiveRoute { pub index: u32, pub alias: String, pub class: IfaceClass, pub classification: &'static str, pub metric: u64 }
pub fn effective_route(adapters: &[Value], interfaces: &[Value], routes: &[Value], ipv6: bool) -> Option<EffectiveRoute> {
    routes.iter().filter(|r| string(r,"DestinationPrefix")==if ipv6 {"::/0"} else {"0.0.0.0/0"}).filter_map(|r| {
        let idx=index(r);
        let a=adapters.iter().find(|a| index(a)==idx && up(a))?;
        let family=if ipv6 {23} else {2};
        let metric=r.get("InterfaceMetric").filter(|v| !v.is_null()).map(|_| number(r,"InterfaceMetric")).or_else(|| interfaces.iter().find(|i| index(i)==idx && number(i,"AddressFamily")==family).map(|i| number(i,"InterfaceMetric")))?;
        Some(EffectiveRoute { index:idx, alias:string(a,"Name"), class:classify_adapter(a), classification:match classify_adapter(a) { IfaceClass::Tunnel=>"tunnel", IfaceClass::Physical=>"physical", IfaceClass::Other if a["Virtual"].as_bool()==Some(true) || a["HardwareInterface"].as_bool()==Some(false)=>"virtual-local", _=>"other" }, metric:u64::from(number(r,"RouteMetric"))+u64::from(metric) })
    }).min_by_key(|r| (r.metric,r.index))
}

/// One block per interface and address family, retaining the original NRPT fields.
pub fn dns_blocks(adapters: &[Value], interfaces: &[Value], dns: &[Value], nrpt: &[Value]) -> Vec<ResolverBlock> {
    let mut blocks=vec![];
    for d in dns {
        let idx=index(d); let family=number(d,"AddressFamily");
        let Some(a)=adapters.iter().find(|a| index(a)==idx && up(a)) else {continue};
        if number(a,"InterfaceType")==24 || (classify_adapter(a)==IfaceClass::Other && (a["Virtual"].as_bool()==Some(true) || a["HardwareInterface"].as_bool()==Some(false))) {continue;}
        let Some(i)=interfaces.iter().find(|i| index(i)==idx && number(i,"AddressFamily")==family && connected(i)) else {continue};
        let nameservers=strings(&d["ServerAddresses"]).into_iter().filter(|s| s.parse::<std::net::IpAddr>().is_ok() && !parse::is_ignored_dns(s)).collect();
        blocks.push(ResolverBlock { nameservers, iface:string(d,"InterfaceAlias"), interface_index:Some(idx), address_family:Some(family), order:Some(number(i,"InterfaceMetric")), ..Default::default() });
    }
    blocks.sort_by_key(|b| b.order);
    for rule in nrpt {
        // Preserve the root namespace so catch-all policies outrank interface DNS.
        let domains=strings(&rule["Namespace"]).into_iter().map(|d| if d == "." { d } else { d.trim_matches('.').to_lowercase() }).collect();
        let nameservers=strings(&rule["NameServers"]);
        // Keep policy-only/DoH/DirectAccess rules too: an unsupported policy must
        // never silently fall back to sending probes to ordinary adapter DNS.
        blocks.push(ResolverBlock {domains,nameservers,order:Some(0), policy:Some(rule.clone()), ..Default::default()});
    }
    blocks
}

pub fn effective_servers(blocks: &[ResolverBlock]) -> Vec<String> {
    parse::dedup_keep(["claude.ai","api.anthropic.com"].iter().flat_map(|h| parse::resolvers_for_host(blocks,h)).flat_map(|b| b.nameservers.clone()).collect())
}

pub fn proxy_snapshot(settings: &Value, env: (String,String,String), environment_bypass: Vec<String>) -> super::ProxySnapshot {
    let value = |name: &str| settings[name].as_str().map(str::to_owned).or_else(|| settings[name].as_u64().map(|n| n.to_string())).unwrap_or_default();
    let enable=value("ProxyEnable");
    let server=value("ProxyServer");
    let bypass_raw=value("ProxyOverride");
    let pac_url=value("AutoConfigURL");
    let wpad=value("AutoDetect")=="1";
    let manual = parse::parse_windows_proxy(&enable, &server);
    let mut sources = std::collections::BTreeMap::new();
    for (key,value) in [("wininet.http",&manual.0),("wininet.https",&manual.1),("wininet.socks",&manual.2),("env.http",&env.0),("env.https",&env.1),("env.all",&env.2),("pac",&pac_url)] { if !value.is_empty() { sources.insert(key.into(),value.clone()); } }
    let enabled = [&manual.0,&manual.1,&manual.2,&env.0,&env.1,&env.2].iter().any(|v| !v.is_empty());
    let mut bypass = if manual.0.is_empty() && manual.1.is_empty() && manual.2.is_empty() { vec![] } else { parse::split_bypass_list(&bypass_raw) };
    if [&env.0,&env.1,&env.2].iter().any(|v| !v.is_empty()) { bypass.extend(environment_bypass); }
    super::ProxySnapshot { sources, wpad, enabled, pac: !pac_url.is_empty(), pac_url, bypass: parse::dedup_keep(bypass),
        http_proxy: if !env.0.is_empty() {env.0} else {manual.0},
        https_proxy: if !env.1.is_empty() {env.1} else {manual.1},
        socks_proxy: if !env.2.is_empty() {env.2} else {manual.2} }
}

pub fn scalar(rows: &[Value]) -> String { rows.first().and_then(Value::as_str).unwrap_or("").to_string() }
pub fn location(value: &str) -> Option<bool> { match value.to_lowercase().as_str() { "allow"=>Some(true), "deny"=>Some(false), _=>None } }

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> Value { serde_json::from_str(include_str!("fixtures/windows_network.json")).unwrap() }
    fn array(v: &Value, key: &str) -> Vec<Value> { json_rows(&serde_json::to_vec(&v[key]).unwrap()).unwrap() }
    #[test]
    fn optional_collection_scripts_tolerate_missing_items() {
        for script in [route_script(), nrpt_script(), location_script()] {
            let script = powershell_script(&script);
            assert!(script.contains("-ErrorAction SilentlyContinue"));
            assert!(script.contains("$ErrorActionPreference='Stop'"));
        }
        assert_eq!(location(&scalar(&json_rows(b"").unwrap())), None);
    }
    #[test]
    fn catch_all_policy_yields_to_specific_namespace() {
        let b=dns_blocks(&[], &[], &[], &[
            json!({"Namespace":".","NameServers":"9.9.9.9"}),
            json!({"Namespace":".claude.ai","NameServers":"1.1.1.1"})]);
        assert_eq!(parse::resolvers_for_host(&b,"api.claude.ai")[0].nameservers, vec!["1.1.1.1"]);
        assert_eq!(parse::resolvers_for_host(&b,"example.org")[0].nameservers, vec!["9.9.9.9"]);
    }
    #[test]
    fn utf8_bom_single_empty_and_invalid_output() {
        assert_eq!(json_rows("\u{feff}{\"Name\":\"以太网\"}".as_bytes()).unwrap()[0]["Name"],"以太网");
        assert!(json_rows(b" \r\n").unwrap().is_empty());
        assert!(json_rows(b"null").unwrap().is_empty());
        assert!(matches!(json_rows(&[255]),Err(CollectError::Decode)));
        assert!(json_rows(b"broken").is_err());
    }
    #[test]
    fn classification_uses_types_and_drivers_before_aliases() {
        let f=fixture(); let a=array(&f,"adapters");
        assert_eq!(classify_adapter(&a[0]),IfaceClass::Physical);
        let mut renamed=a[0].clone(); renamed["Name"]=json!("vEthernet WireGuard");
        assert_eq!(classify_adapter(&renamed),IfaceClass::Physical);
        assert_eq!(classify_adapter(&a[1]),IfaceClass::Physical);
        assert_eq!(classify_adapter(&a[2]),IfaceClass::Tunnel);
        assert_eq!(classify_adapter(&a[3]),IfaceClass::Other);
        for kind in [53,131] { assert_eq!(classify_adapter(&json!({"Name":"以太网","InterfaceType":kind})),IfaceClass::Tunnel); }
        for driver in ["tap0901","WireGuard","OpenVPN","Mihomo","sing-box","v2rayN","Tailscale","ZeroTier","Cisco AnyConnect","GlobalProtect","Fortinet","utun9"] {
            assert_eq!(classify_adapter(&json!({"Name":"renamed","InterfaceType":6,"HardwareInterface":false,"DriverDescription":driver})),IfaceClass::Tunnel,"{driver}");
        }
        for driver in ["VMware Virtual Ethernet","VirtualBox Host-Only"] {
            assert_eq!(classify_adapter(&json!({"Name":"WireGuard","InterfaceType":6,"Virtual":true,"DriverDescription":driver})),IfaceClass::Other);
        }
    }
    #[test]
    fn effective_route_ignores_disconnected_and_adds_metrics() {
        let f=fixture(); let a=array(&f,"adapters"); let i=array(&f,"interfaces"); let mut r=array(&f,"routes");
        let best=effective_route(&a,&i,&r,false).unwrap();
        assert_eq!((best.index,best.metric,best.class),(20,6,IfaceClass::Tunnel));
        r[2]["RouteMetric"]=json!(100);
        assert_eq!(effective_route(&a,&i,&r,false).unwrap().index,4);
        assert!(effective_route(&a,&i,&r,true).is_none());
    }
    #[test]
    fn active_dns_join_policy_and_metric_selection() {
        let f=fixture(); let a=array(&f,"adapters"); let i=array(&f,"interfaces"); let d=array(&f,"dns");
        let b=dns_blocks(&a,&i,&d,&[]);
        assert_eq!(b.len(),2); assert_eq!(b[0].interface_index,Some(20)); assert_eq!(b[0].address_family,Some(2)); assert_eq!(b[0].order,Some(5));
        assert_eq!(effective_servers(&b),vec!["1.1.1.1","8.8.8.8"]);
        let mut disconnected=i.clone(); disconnected[2]["ConnectionState"]=json!(2);
        assert_eq!(effective_servers(&dns_blocks(&a,&disconnected,&d,&[])),vec!["192.168.1.1"]);
        let b=dns_blocks(&a,&i,&d,&array(&f,"nrpt"));
        assert_eq!(effective_servers(&b),vec!["9.9.9.9","149.112.112.112"]);
        assert_eq!(parse::resolvers_for_host(&b,"API.CLAUDE.AI.")[0].nameservers,vec!["9.9.9.9"]);
        assert_eq!(parse::resolvers_for_host(&b,"notclaude.ai")[0].nameservers,vec!["1.1.1.1","8.8.8.8"]);
        let b=dns_blocks(&a,&i,&d,&[json!({"Namespace":".","NameServers":"9.9.9.9"})]);
        assert_eq!(effective_servers(&b),vec!["9.9.9.9"]);
        let b=dns_blocks(&a,&i,&d,&[json!({"Namespace":".","DirectAccessEnabled":true})]);
        assert!(effective_servers(&b).is_empty());
    }
    #[test]
    fn cldr_territories_aliases_and_unknown() {
        for (zone,country,expected) in [
            ("Eastern Standard Time","CA","America/Toronto"),("Eastern Standard Time","US","America/New_York"),
            ("W. Europe Standard Time","NL","Europe/Amsterdam"),("W. Europe Standard Time","DE","Europe/Berlin"),
            ("Tokyo Standard Time","JP","Asia/Tokyo"),("Korea Standard Time","KR","Asia/Seoul"),
            ("Singapore Standard Time","SG","Asia/Singapore"),("Taipei Standard Time","TW","Asia/Taipei"),
            ("Pacific Standard Time","US","America/Los_Angeles")
        ] { assert_eq!(parse::windows_to_iana(zone,Some(country))[0],expected); }
        assert!(parse::windows_to_iana("Eastern Standard Time",Some("CA")).contains(&"America/New_York".into()));
        assert!(parse::windows_to_iana("unknown",None).is_empty());
        for (alias,canonical) in [("Asia/Calcutta","Asia/Kolkata"),("US/Pacific","America/Los_Angeles"),("Asia/Saigon","Asia/Ho_Chi_Minh"),("Europe/Kiev","Europe/Kyiv")] { assert_eq!(parse::canon_tz(alias),canonical); }
    }
}
