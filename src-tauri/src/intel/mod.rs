use async_trait::async_trait;
use serde_json::Value;

use crate::net::{dns, http::{self, Family}};
use crate::platform::parse::{self, is_private_ip};

const IPINFO_EXIT: &str = "https://ipinfo.io/json";
const IPINFO_BASE: &str = "https://ipinfo.io/";
const IPWHOIS_BASE: &str = "https://ipwho.is/";
const BASH_ID: &str = "https://bash.ws/id";
const BASH_TEST_BASE: &str = "https://bash.ws/dnsleak/test/";

/// Public IP, DNS-leak, and EDNS client-subnet lookups.
///
/// [`PublicDirectory`] talks to ipinfo.io, ipwho.is, bash.ws, and Google's
/// `o-o.myaddr` TXT name. A later self-hosted directory can implement the same
/// trait and replace it without touching the checks.
#[async_trait]
pub trait NetworkDirectory: Send + Sync {
    async fn lookup_ip(&self, ip: &str) -> Result<IpFacts, String>;
    async fn current_exit(&self, family: Family) -> Result<IpFacts, String>;
    async fn effective_exit(&self, family: Family, _proxy: &crate::platform::ProxySnapshot) -> Result<IpFacts,String> { self.current_exit(family).await }
    async fn udp_probe(&self) -> (crate::net::udp::StunResult,crate::net::udp::StunResult,Result<bool,String>) { (crate::net::udp::StunResult::Unknown("probe not run".into()),crate::net::udp::StunResult::Unknown("probe not run".into()),Err("probe not run".into())) }
    async fn dns_leak(&self, resolvers: &[String]) -> LeakReport;
    async fn client_subnet(&self, resolvers: &[String]) -> EcsReport;
}

#[derive(Debug, Clone)]
pub struct IpFacts {
    pub ip: String,
    pub country: String,
    pub region: String,
    pub city: String,
    pub org: String,
    pub timezone: String,
    pub hosting: Option<bool>,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct ObservedResolver {
    pub path: String,
    pub resolver: String,
    pub ip: String,
    pub country: String,
    pub city: String,
    pub asn: String,
}

#[derive(Debug, Clone)]
pub struct LeakReport {
    pub config_details: Vec<String>,
    pub hits: Vec<ObservedResolver>,
    pub system_inconclusive: bool,
    pub config_inconclusive: bool,
}

#[derive(Debug, Clone)]
pub struct EcsReport { pub results: Vec<ResolverResult> }
#[derive(Debug, Clone)]
pub struct ResolverResult { pub resolver: String, pub values: Vec<String>, pub error: Option<String> }

impl ResolverResult {
    pub fn readable(&self) -> String {
        let mut parts = Vec::new();
        if !self.values.is_empty() { parts.push(self.values.join(", ")); }
        if let Some(error) = &self.error { parts.push(error.clone()); }
        if parts.is_empty() { parts.push("no answers".into()); }
        format!("{}: {}", self.resolver, parts.join("; "))
    }
}

pub struct PublicDirectory;

#[async_trait]
impl NetworkDirectory for PublicDirectory {
    async fn lookup_ip(&self, ip: &str) -> Result<IpFacts, String> {
        lookup_ip(ip).await
    }

    async fn current_exit(&self, family: Family) -> Result<IpFacts, String> {
        if let Ok(facts) = exit_from_ipinfo(family).await {
            return Ok(facts);
        }
        exit_from_ipwhois(family).await
    }

    async fn effective_exit(&self, family: Family, proxy: &crate::platform::ProxySnapshot) -> Result<IpFacts,String> {
        let mut last = "exit unavailable".to_string();
        for url in [IPINFO_EXIT, IPWHOIS_BASE] {
            match crate::net::proxy::fetch(proxy,url,Some(family)).await {
                Ok((r,path)) if (200..300).contains(&r.status) => {
                    let facts = if url == IPINFO_EXIT { parse_ipinfo(&r.body) } else { parse_ipwhois(&r.body) };
                    if let Ok(mut f) = facts { if validate_family(&f.ip,family).is_ok() { f.source = format!("{}; path: {}",f.source,path); return Ok(f); } }
                    last = "exit response invalid".into();
                }, Ok(_) => last = "exit HTTP request refused".into(), Err(e) => last = e,
            }
        }
        Err(last)
    }

    async fn udp_probe(&self) -> (crate::net::udp::StunResult,crate::net::udp::StunResult,Result<bool,String>) {
        tokio::join!(crate::net::udp::stun("stun.l.google.com:19302"),crate::net::udp::stun("stun.cloudflare.com:3478"),crate::net::udp::quic())
    }

    async fn dns_leak(&self, resolvers: &[String]) -> LeakReport {
        let mut report = bash_ws_leak(resolvers).await.unwrap_or(LeakReport { config_details: vec![], hits: vec![], system_inconclusive: true, config_inconclusive: false });
        let config = fallback_leak(resolvers).await;
        report.config_inconclusive = config.config_inconclusive;
        report.hits.extend(config.hits);
        report.config_details = config.config_details;
        report
    }

    async fn client_subnet(&self, resolvers: &[String]) -> EcsReport {
        EcsReport { results: google_txt(resolvers).await }
    }
}

pub struct NullDirectory;

#[async_trait]
impl NetworkDirectory for NullDirectory {
    async fn lookup_ip(&self, _ip: &str) -> Result<IpFacts, String> {
        Err("offline".into())
    }
    async fn current_exit(&self, _family: Family) -> Result<IpFacts, String> {
        Err("offline".into())
    }
    async fn dns_leak(&self, _resolvers: &[String]) -> LeakReport {
        LeakReport { config_details: vec![], hits: Vec::new(), system_inconclusive: true, config_inconclusive: false }
    }
    async fn client_subnet(&self, _resolvers: &[String]) -> EcsReport {
        EcsReport { results: vec![] }
    }
}

async fn exit_from_ipinfo(family: Family) -> Result<IpFacts, String> {
    let response = http::fetch_https(IPINFO_EXIT, Some(family), std::time::Duration::from_secs(10)).await?;
    if !(200..300).contains(&response.status) {
        return Err(format!("ipinfo status {}", response.status));
    }
    let facts = parse_ipinfo(&response.body)?;
    validate_family(&facts.ip, family)?;
    Ok(facts)
}

async fn exit_from_ipwhois(family: Family) -> Result<IpFacts, String> {
    let response = http::fetch_https(
        IPWHOIS_BASE,
        Some(family),
        std::time::Duration::from_secs(10),
    )
    .await?;
    if !(200..300).contains(&response.status) { return Err(format!("ipwho.is status {}", response.status)); }
    let facts = parse_ipwhois(&response.body)?;
    validate_family(&facts.ip, family)?;
    Ok(facts)
}

async fn lookup_ip(ip: &str) -> Result<IpFacts, String> {
    let ip: std::net::IpAddr = ip.parse().map_err(|_| "invalid IP address".to_string())?;
    let ip = ip.to_string();
    let ipinfo = format!("{IPINFO_BASE}{ip}/json");
    if let Ok(response) = http::fetch_https(&ipinfo, None, std::time::Duration::from_secs(8)).await {
        if (200..300).contains(&response.status) {
            if let Ok(mut facts) = parse_ipinfo(&response.body) {
                if facts.ip.is_empty() {
                    facts.ip = ip.to_string();
                }
                return Ok(facts);
            }
        }
    }
    let url = format!("{IPWHOIS_BASE}{ip}");
    let response = http::fetch_https(&url, None, std::time::Duration::from_secs(8)).await?;
    if !(200..300).contains(&response.status) { return Err(format!("ipwho.is status {}", response.status)); }
    let mut facts = parse_ipwhois(&response.body)?;
    if facts.ip.is_empty() {
        facts.ip = ip.to_string();
    }
    Ok(facts)
}

fn parse_ipinfo(body: &str) -> Result<IpFacts, String> {
    let value: Value = serde_json::from_str(body).map_err(|err| err.to_string())?;
    if value.get("error").is_some() || text(&value, "country").is_empty() {
        return Err("ipinfo did not return a country".into());
    }
    Ok(IpFacts {
        ip: text(&value, "ip"),
        country: parse::norm_country(&text(&value, "country")),
        region: text(&value, "region"),
        city: text(&value, "city"),
        org: text(&value, "org"),
        timezone: text(&value, "timezone"),
        hosting: None,
        source: "ipinfo.io".into(),
    })
}

fn parse_ipwhois(body: &str) -> Result<IpFacts, String> {
    let value: Value = serde_json::from_str(body).map_err(|err| err.to_string())?;
    if value.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(format!("ipwho.is lookup failed: {}", text(&value, "message")));
    }
    let country = parse::norm_country(&text(&value, "country_code"));
    if country.is_empty() { return Err("ipwho.is did not return a country".into()); }
    let connection = &value["connection"];
    let mut org = text(connection, "org");
    if org.is_empty() { org = text(connection, "isp"); }
    if org.is_empty() {
        if let Some(asn) = connection.get("asn").and_then(Value::as_u64) {
            org = format!("AS{asn}");
        }
    }
    Ok(IpFacts {
        ip: text(&value, "ip"),
        country,
        region: text(&value, "region"),
        city: text(&value, "city"),
        org,
        timezone: text(&value["timezone"], "id"),
        hosting: None,
        source: "ipwho.is".into(),
    })
}

fn text(value: &Value, key: &str) -> String {
    value.get(key).and_then(|item| item.as_str()).unwrap_or("").trim().to_string()
}

async fn bash_ws_leak(resolvers: &[String]) -> Option<LeakReport> {
    let response = http::fetch_https(BASH_ID, None, std::time::Duration::from_secs(8)).await.ok()?;
    let id: String = response.body.chars().filter(|c| c.is_ascii_digit()).collect();
    if id.is_empty() {
        return None;
    }
    let names: Vec<String> = (1..=8).map(|i| format!("{i}.{id}.bash.ws")).collect();
    let _ = resolvers; // System path must never send packets directly to configured servers.
    let completed = futures::future::join_all(names.iter().map(|name| async move {
        tokio::time::timeout(std::time::Duration::from_secs(3), tokio::net::lookup_host((name.as_str(),443))).await.is_ok()
    })).await.into_iter().all(|v| v);
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let url = format!("{BASH_TEST_BASE}{id}?json=2");
    let response = http::fetch_https(&url, None, std::time::Duration::from_secs(12)).await.ok()?;
    let value: Value = serde_json::from_str(&response.body).ok()?;
    let rows = value.as_array()?;
    let mut hits = Vec::new();
    for row in rows {
        let kind = row.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if kind != "dns" {
            continue;
        }
        let ip = row.get("ip").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
        if ip.is_empty() || is_private_ip(&ip) {
            continue;
        }
        let country = parse::norm_country(row.get("country_name").and_then(|v| v.as_str()).unwrap_or(""));
        if hits.iter().any(|hit: &ObservedResolver| hit.ip == ip) {
            continue;
        }
        hits.push(ObservedResolver {
            path: "system".into(), resolver: "system".into(),
            ip,
            country,
            city: row.get("city_name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            asn: row.get("asn").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        });
    }
    Some(LeakReport { config_details: vec![], system_inconclusive: !completed || hits.is_empty(), config_inconclusive: false, hits })
}

async fn fallback_leak(resolvers: &[String]) -> LeakReport {
    let mut hits = Vec::new();
    let rows = google_txt(resolvers).await;
    let mut incomplete = rows.is_empty();
    let mut details = Vec::new();
    for row in rows {
        details.push(row.readable());
        incomplete |= row.error.is_some();
        for ip in row.values.iter().map(|s| s.trim().trim_matches('"')).filter(|s| s.parse::<std::net::IpAddr>().is_ok() && !is_private_ip(s)) {
            let facts = lookup_ip(ip).await.ok();
            incomplete |= facts.is_none();
            hits.push(ObservedResolver { path: "configured-server".into(), resolver: row.resolver.clone(), ip: ip.into(),
                country: facts.as_ref().map(|f| f.country.clone()).unwrap_or_default(),
                city: facts.as_ref().map(|f| f.city.clone()).unwrap_or_default(),
                asn: facts.as_ref().map(|f| f.org.clone()).unwrap_or_default() });
        }
    }
    LeakReport { config_details: details, system_inconclusive: false, config_inconclusive: incomplete || hits.is_empty(), hits }
}

async fn google_txt(resolvers: &[String]) -> Vec<ResolverResult> {
    // All configured resolvers, with at most four blocking UDP queries in flight.
    use futures::{stream, StreamExt};
    stream::iter(resolvers.iter().cloned()).map(|resolver| async move {
        let server = resolver.clone();
        let result = tokio::time::timeout(std::time::Duration::from_secs(4), tokio::task::spawn_blocking(move || dns::query_txt(&server, "o-o.myaddr.l.google.com"))).await;
        match result {
            Ok(Ok(Ok(values))) => ResolverResult { resolver, values, error: None },
            Ok(Ok(Err(error))) => ResolverResult { resolver, values: vec![], error: Some(error) },
            Ok(Err(error)) => ResolverResult { resolver, values: vec![], error: Some(error.to_string()) },
            Err(_) => ResolverResult { resolver, values: vec![], error: Some("timeout".into()) },
        }
    }).buffered(4).collect().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intel_sources_are_https() {
        for url in [IPINFO_EXIT, IPINFO_BASE, IPWHOIS_BASE, BASH_ID, BASH_TEST_BASE] {
            assert!(url.starts_with("https://"), "insecure source: {url}");
        }
    }

    #[test]
    fn parses_ipwhois() {
        let sample = r#"{
            "ip":"8.8.8.8", "success":true, "type":"IPv4",
            "country":"United States", "country_code":"US",
            "region":"California", "city":"Mountain View",
            "connection":{"asn":15169,"org":"Google LLC","isp":"Google LLC"},
            "timezone":{"id":"America/Los_Angeles","utc":"-07:00"}
        }"#;
        let facts = parse_ipwhois(sample).unwrap();
        assert_eq!(facts.ip, "8.8.8.8");
        assert_eq!(facts.country, "US");
        assert_eq!(facts.region, "California");
        assert_eq!(facts.city, "Mountain View");
        assert_eq!(facts.org, "Google LLC");
        assert_eq!(facts.timezone, "America/Los_Angeles");
        assert_eq!(facts.source, "ipwho.is");
        assert_eq!(facts.hosting, None);
    }

    #[test]
    fn rejects_unsuccessful_ipwhois() {
        assert!(parse_ipwhois(r#"{"success":false,"message":"Invalid IP address"}"#).is_err());
        assert!(parse_ipwhois(r#"{"success":true,"country_code":""}"#).is_err());
        assert!(parse_ipwhois(r#"{"country_code":"US"}"#).is_err());
    }

    #[test]
    fn ipwhois_org_fallbacks() {
        let facts = parse_ipwhois(r#"{"success":true,"country_code":"US","connection":{"isp":"Example ISP","asn":123}}"#).unwrap();
        assert_eq!(facts.org, "Example ISP");
        let facts = parse_ipwhois(r#"{"success":true,"country_code":"US","connection":{"asn":123}}"#).unwrap();
        assert_eq!(facts.org, "AS123");
    }
}

fn validate_family(ip: &str, family: Family) -> Result<(), String> {
    match (ip.parse::<std::net::IpAddr>(), family) {
        (Ok(std::net::IpAddr::V4(_)), Family::V4) | (Ok(std::net::IpAddr::V6(_)), Family::V6) => Ok(()),
        _ => Err("exit service returned an invalid IP or the wrong address family".into()),
    }
}

#[cfg(test)]
mod family_tests {
    use super::*;
    #[test]
    fn validates_requested_family() {
        assert!(validate_family("1.1.1.1", Family::V4).is_ok());
        assert!(validate_family("::1", Family::V6).is_ok());
        assert!(validate_family("2a09:bac5::1", Family::V4).is_err());
        assert!(validate_family("1.1.1.1", Family::V6).is_err());
        assert!(validate_family("invalid", Family::V4).is_err());
    }
}
