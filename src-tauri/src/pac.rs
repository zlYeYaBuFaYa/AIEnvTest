use std::collections::BTreeMap;
use boa_engine::{Context, Source};
pub const TARGETS: [(&str, &str); 2] = [("https://claude.ai/", "claude.ai"), ("https://api.anthropic.com/v1/messages", "api.anthropic.com")];
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route { Direct, Proxy(String) }
impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::Direct => f.write_str("DIRECT"), Self::Proxy(route) => f.write_str(route) }
    }
}
pub fn parse_routes(s: &str) -> Result<Vec<Route>, String> {
    let mut out = Vec::new();
    for item in s.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        let mut parts: Vec<_> = item.split_whitespace().map(str::to_owned).collect();
        if let Some(kind) = parts.first_mut() { *kind = kind.to_ascii_uppercase(); }
        let refs: Vec<_> = parts.iter().map(String::as_str).collect();
        match refs.as_slice() {
            ["DIRECT"] => out.push(Route::Direct),
            [kind, addr] if ["PROXY", "HTTP", "HTTPS", "SOCKS", "SOCKS4", "SOCKS5"].contains(kind) && addr.rsplit_once(':').is_some_and(|(h,p)| !h.is_empty() && p.parse::<u16>().is_ok_and(|p| p>0)) => out.push(Route::Proxy(format!("{kind} {addr}"))),
            _ => return Err("invalid PAC route".into()),
        }
    }
    if out.is_empty() { Err("empty PAC route".into()) } else { Ok(out) }
}
/// A timed-out worker is detached. Runtime limits still bound ordinary JS loops/recursion.
/// No host bindings, filesystem or network are exposed to the script.
pub fn evaluate(script: &str, url: &str, host: &str, ips: BTreeMap<String,String>) -> Result<Vec<Route>, String> {
    if script.len() > 512*1024 { return Err("PAC exceeds 512 KiB".into()); }
    let (script,url,host) = (script.to_owned(), url.to_owned(), host.to_owned());
    let (tx,rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = (|| {
            let mut ctx = Context::default();
            ctx.runtime_limits_mut().set_loop_iteration_limit(10_000_000);
            ctx.runtime_limits_mut().set_recursion_limit(128);
            let setup = format!("const __ips = {};\n{}", serde_json::to_string(&ips).unwrap(), include_str!("pac_helpers.js"));
            ctx.eval(Source::from_bytes(&setup)).map_err(|e| e.to_string())?;
            ctx.eval(Source::from_bytes(&script)).map_err(|e| e.to_string())?;
            let call = format!("FindProxyForURL({}, {})", serde_json::to_string(&url).unwrap(), serde_json::to_string(&host).unwrap());
            let v = ctx.eval(Source::from_bytes(&call)).map_err(|e| e.to_string())?;
            let s = v.as_string().ok_or("PAC must return a string")?.to_std_string_escaped();
            parse_routes(&s)
        })();
        let _ = tx.send(result);
    });
    rx.recv_timeout(std::time::Duration::from_secs(5)).map_err(|_| "PAC evaluation timed out".to_string())?
}
pub async fn read_file_url(raw: &str) -> Option<String> {
    let path = url::Url::parse(raw).ok()?.to_file_path().ok()?;
    tokio::time::timeout(std::time::Duration::from_secs(6), tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let file = std::fs::File::open(path).ok()?;
        let mut bytes = Vec::new();
        file.take(512*1024+1).read_to_end(&mut bytes).ok()?;
        if bytes.len()>512*1024 { return None; }
        String::from_utf8(bytes).ok()
    })).await.ok()?.ok()?
}

pub async fn resolve_targets() -> BTreeMap<String,String> {
    let mut map = BTreeMap::new();
    // UDP connect selects a local address without sending a packet.
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("192.0.2.1:9").is_ok() {
            if let Ok(local) = socket.local_addr() { if !local.ip().is_unspecified() { map.insert("__myIpAddress".into(),local.ip().to_string()); } }
        }
    }
    for (_,host) in TARGETS {
        if let Ok(Ok(mut ips)) = tokio::time::timeout(std::time::Duration::from_secs(2), tokio::net::lookup_host((host,443))).await {
            if let Some(ip) = ips.find(|a| a.is_ipv4()) { map.insert(host.into(), ip.ip().to_string()); }
        }
    }
    map
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn routes_allow_case_and_spacing() {
        assert_eq!(parse_routes(" direct ;  pRoXy   p:80 ; socks5  s:1080 ").unwrap(),
            vec![Route::Direct, Route::Proxy("PROXY p:80".into()), Route::Proxy("SOCKS5 s:1080".into())]);
        assert_eq!(parse_routes("PROXY p:80; DIRECT").unwrap().iter().map(ToString::to_string).collect::<Vec<_>>().join("; "), "PROXY p:80; DIRECT");
    }
    #[test] fn large_rule_loop() {
        assert_eq!(evaluate("function FindProxyForURL(){for(var i=0;i<150000;i++){} return 'PROXY p:80'}", "u", "h", BTreeMap::new()).unwrap(), vec![Route::Proxy("PROXY p:80".into())]);
    }
    #[test] fn pac_rules() {
        for script in ["function FindProxyForURL(u,h){if(h==='claude.ai') return 'PROXY p:80';return 'PROXY p:80'}", "// claude.ai\nfunction FindProxyForURL(){return 'PROXY p:80'}"] {
            assert!(matches!(evaluate(script,TARGETS[0].0,TARGETS[0].1,BTreeMap::new()).unwrap()[0], Route::Proxy(_)));
        }
        assert_eq!(evaluate("function FindProxyForURL(u,h){return shExpMatch(h,'*.anthropic.com')?'DIRECT':'PROXY p:80'}",TARGETS[1].0,TARGETS[1].1,BTreeMap::new()).unwrap()[0], Route::Direct);
        let start=std::time::Instant::now();
        assert!(evaluate("function FindProxyForURL(){while(true){}}","u","h",BTreeMap::new()).is_err());
        assert!(start.elapsed()<std::time::Duration::from_secs(6));
        assert!(evaluate("function !", "u","h",BTreeMap::new()).is_err());
        assert_eq!(evaluate("function FindProxyForURL(u,h){return isInNet(dnsResolve(h),'10.0.0.0','255.0.0.0')?'DIRECT':'PROXY p:80'}","u","h",BTreeMap::from([("h".into(),"10.1.2.3".into())])).unwrap()[0],Route::Direct);
    }

    #[test] fn large_rule_list_pac_evaluates() {
        // gfwlist-style PAC: thousands of rules scanned in a loop.
        let rules: Vec<String> = (0..6000).map(|i| format!("\"site{i}.example\"")).collect();
        let script = format!("var rules=[{}, \"claude.ai\"];\nfunction FindProxyForURL(u,h){{for(var i=0;i<rules.length;i++){{if(dnsDomainIs(h,rules[i]))return 'PROXY 127.0.0.1:7890';}}return 'DIRECT';}}", rules.join(","));
        let routes = evaluate(&script, TARGETS[0].0, TARGETS[0].1, BTreeMap::new()).unwrap();
        assert!(matches!(routes[0], Route::Proxy(_)));
    }
}
