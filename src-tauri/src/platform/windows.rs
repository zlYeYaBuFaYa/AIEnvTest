use super::{command_stdout, env_bypass, env_proxy, PlatformSnapshot, ProxySnapshot};
use super::windows_parse as wp;
use serde_json::Value;

pub fn collect() -> PlatformSnapshot {
    super::clear_errors();
    let adapters=shared_rows("Get-NetAdapter -IncludeHidden | Select-Object ifIndex,Name,InterfaceDescription,InterfaceType,MediaType,PhysicalMediaType,Status,Virtual,HardwareInterface,DriverDescription,ComponentID");
    let interfaces=shared_rows("Get-NetIPInterface | Select-Object ifIndex,AddressFamily,ConnectionState,InterfaceMetric");
    let routes=rows("route_v4", &wp::route_script());
    let dns=rows("dns", "Get-DnsClientServerAddress | Select-Object InterfaceIndex,InterfaceAlias,AddressFamily,ServerAddresses");
    let nrpt=rows("dns", &wp::nrpt_script());
    let dns_blocks=wp::dns_blocks(&adapters,&interfaces,&dns,&nrpt);
    let dns_servers=if super::ERRORS.with(|e| e.borrow().contains_key("dns")) { vec![] } else { wp::effective_servers(&dns_blocks) };
    if dns_servers.is_empty() && !super::ERRORS.with(|e| e.borrow().contains_key("dns")) {
        super::record("dns", &super::CollectError::Io("no usable effective resolver for target hosts (inactive interfaces, unavailable policy, or unsupported policy transport)".into()));
    }
    let v4=wp::effective_route(&adapters,&interfaces,&routes,false);
    let v6=wp::effective_route(&adapters,&interfaces,&routes,true);
    let route_v4_a=v4.as_ref().map(|r| r.alias.clone());
    let route_v6=if let Some(r)=&v6 { super::Ipv6Route::Present {iface:r.alias.clone()} }
        else if super::ERRORS.with(|e| e.borrow().contains_key("route_v4")) { super::Ipv6Route::Unknown("route collection failed".into()) }
        else { super::Ipv6Route::Absent };
    PlatformSnapshot {
        os:"windows".into(), timezone:scalar("timezone","(Get-TimeZone).Id"),
        windows_territory:Some(scalar("territory","(New-Object System.Globalization.RegionInfo (Get-Culture).Name).TwoLetterISORegionName")).filter(|s| !s.is_empty()),
        windows_routes:v4.into_iter().chain(v6).collect(),
        locale:scalar("locale","(Get-Culture).Name"),
        dns_blocks,dns_servers,route_v4_b:route_v4_a.clone(),route_v4_a,route_v6,
        proxy:proxy(),hosts:hosts(),location_enabled:location_enabled(),errors:super::take_errors(),
    }
}
// Only adapter and IP-interface inventory are shared route/DNS inputs.
fn shared_rows(script: &str) -> Vec<Value> {
    let result = super::run("powershell.exe", &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &wp::powershell_script(script)], super::DEFAULT_TIMEOUT)
        .and_then(|text| wp::json_rows(text.as_bytes()));
    match result {
        Ok(rows) => rows,
        Err(error) => {
            for key in ["route_v4", "dns"] { super::record(key, &error); }
            vec![]
        }
    }
}
fn rows(key: &str, script: &str) -> Vec<Value> {
    let Some(text)=powershell(key,script) else {return vec![]};
    match wp::json_rows(text.as_bytes()) { Ok(rows)=>rows, Err(e)=>{super::record(key,&e); vec![]} }
}
fn scalar(key: &str, script: &str) -> String {
    wp::scalar(&rows(key,script))
}
fn proxy() -> ProxySnapshot {
    // Read optional registry properties in one successful collection: absent values
    // are normal, while failure to read the settings remains a collection error.
    let settings = rows("proxy", r"Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyEnable,ProxyServer,ProxyOverride,AutoConfigURL,AutoDetect").into_iter().next().unwrap_or_default();
    wp::proxy_snapshot(&settings, (env_proxy(&["http_proxy","HTTP_PROXY"]),env_proxy(&["https_proxy","HTTPS_PROXY"]),env_proxy(&["all_proxy","ALL_PROXY"])),env_bypass())
}


fn hosts() -> Result<String, super::CollectError> {
    let windir=std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    super::read_file(std::path::Path::new(&windir).join("System32").join("drivers").join("etc").join("hosts"))
}
fn location_enabled() -> Option<bool> {
    wp::location(&scalar("location", &wp::location_script()))
}
fn powershell(key: &str, script: &str) -> Option<String> {
    let script=wp::powershell_script(script);
    command_stdout(key,"powershell.exe",&["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command",&script])
}
