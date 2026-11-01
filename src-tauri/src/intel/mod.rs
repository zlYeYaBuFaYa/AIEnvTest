use async_trait::async_trait;
use serde_json::Value;

use crate::net::{dns, http::{self, Family}};
use crate::platform::parse::{self, is_private_ip};

/// Public IP, DNS-leak, and EDNS client-subnet lookups.
///
/// [`PublicDirectory`] talks to ipinfo.io, ip-api.com, bash.ws, and Google's
/// `o-o.myaddr` TXT name. A later self-hosted directory can implement the same
/// trait and replace it without touching the checks.
#[async_trait]
pub trait NetworkDirectory: Send + Sync {
    async fn lookup_ip(&self, ip: &str) -> Result<IpFacts, String>;
    async fn current_exit(&self, family: Family) -> Result<IpFacts, String>;
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
    pub ip: String,
    pub country: String,
    pub city: String,
    pub asn: String,
}

#[derive(Debug, Clone)]
pub struct LeakReport {
    pub hits: Vec<ObservedResolver>,
    pub inconclusive: bool,
}

#[derive(Debug, Clone)]
pub struct EcsReport {
    pub subnet: Option<String>,
    pub failed: bool,
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
        exit_from_ip_api(family).await
    }

    async fn dns_leak(&self, resolvers: &[String]) -> LeakReport {
        if let Some(report) = bash_ws_leak(resolvers).await {
            if !report.hits.is_empty() {
                return report;
            }
        }
        fallback_leak(resolvers).await
    }

    async fn client_subnet(&self, resolvers: &[String]) -> EcsReport {
        let resolvers = resolvers.to_vec();
        let lines = tokio::task::spawn_blocking(move || google_txt(&resolvers))
            .await
            .unwrap_or_default();
        if lines.is_empty() {
            return EcsReport { subnet: None, failed: true };
        }
        EcsReport {
            subnet: parse::parse_ecs_subnets(&lines).into_iter().next(),
            failed: false,
        }
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
        LeakReport { hits: Vec::new(), inconclusive: true }
    }
    async fn client_subnet(&self, _resolvers: &[String]) -> EcsReport {
        EcsReport { subnet: None, failed: true }
    }
}

async fn exit_from_ipinfo(family: Family) -> Result<IpFacts, String> {
    let response = http::fetch("https://ipinfo.io/json", Some(family), std::time::Duration::from_secs(10)).await?;
    if response.status >= 400 {
        return Err(format!("ipinfo status {}", response.status));
    }
    parse_ipinfo(&response.body)
}

async fn exit_from_ip_api(family: Family) -> Result<IpFacts, String> {
    let response = http::fetch(
        "http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,timezone,isp,org,as,query,hosting,proxy",
        Some(family),
        std::time::Duration::from_secs(10),
    )
    .await?;
    parse_ip_api(&response.body)
}

async fn lookup_ip(ip: &str) -> Result<IpFacts, String> {
    let ipinfo = format!("https://ipinfo.io/{ip}/json");
    if let Ok(response) = http::fetch(&ipinfo, None, std::time::Duration::from_secs(8)).await {
        if response.status < 400 {
            if let Ok(mut facts) = parse_ipinfo(&response.body) {
                if facts.ip.is_empty() {
                    facts.ip = ip.to_string();
                }
                return Ok(facts);
            }
        }
    }
    let url = format!(
        "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,timezone,isp,org,as,query,hosting,proxy"
    );
    let response = http::fetch(&url, None, std::time::Duration::from_secs(8)).await?;
    let mut facts = parse_ip_api(&response.body)?;
    if facts.ip.is_empty() {
        facts.ip = ip.to_string();
    }
    Ok(facts)
}

fn parse_ipinfo(body: &str) -> Result<IpFacts, String> {
    let value: Value = serde_json::from_str(body).map_err(|err| err.to_string())?;
    if value.get("error").is_some() || value.get("country").is_none() {
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

fn parse_ip_api(body: &str) -> Result<IpFacts, String> {
    let value: Value = serde_json::from_str(body).map_err(|err| err.to_string())?;
    if value.get("status").and_then(|s| s.as_str()) == Some("fail") {
        return Err(text(&value, "message"));
    }
    let country = {
        let code = text(&value, "countryCode");
        if code.is_empty() { parse::norm_country(&text(&value, "country")) } else { parse::norm_country(&code) }
    };
    if country.is_empty() {
        return Err("ip-api did not return a country".into());
    }
    let org = {
        let org = text(&value, "org");
        if org.is_empty() { text(&value, "as") } else { org }
    };
    Ok(IpFacts {
        ip: text(&value, "query"),
        country,
        region: text(&value, "regionName"),
        city: text(&value, "city"),
        org: if org.is_empty() { text(&value, "isp") } else { org },
        timezone: text(&value, "timezone"),
        hosting: value.get("hosting").and_then(|v| v.as_bool()),
        source: "ip-api.com".into(),
    })
}

fn text(value: &Value, key: &str) -> String {
    value.get(key).and_then(|item| item.as_str()).unwrap_or("").trim().to_string()
}

async fn bash_ws_leak(resolvers: &[String]) -> Option<LeakReport> {
    let response = http::fetch("https://bash.ws/id", None, std::time::Duration::from_secs(8)).await.ok()?;
    let id: String = response.body.chars().filter(|c| c.is_ascii_digit()).collect();
    if id.is_empty() {
        return None;
    }
    let names: Vec<String> = (1..=8).map(|i| format!("{i}.{id}.bash.ws")).collect();
    let resolvers = resolvers.to_vec();
    let _ = tokio::task::spawn_blocking(move || {
        dns::blast(&resolvers, &names);
        std::thread::sleep(std::time::Duration::from_millis(1200));
    })
    .await;
    let url = format!("https://bash.ws/dnsleak/test/{id}?json=2");
    let response = http::fetch(&url, None, std::time::Duration::from_secs(12)).await.ok()?;
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
            ip,
            country,
            city: row.get("city_name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            asn: row.get("asn").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        });
    }
    Some(LeakReport { inconclusive: hits.is_empty(), hits })
}

async fn fallback_leak(resolvers: &[String]) -> LeakReport {
    let resolvers = resolvers.to_vec();
    let ips = tokio::task::spawn_blocking(move || {
        let mut ips = Vec::new();
        for line in google_txt(&resolvers) {
            let line = line.trim().trim_matches('"').to_string();
            if line.parse::<std::net::IpAddr>().is_ok() && !is_private_ip(&line) {
                ips.push(line);
            }
        }
        for server in &resolvers {
            if let Ok(answers) = dns::query_a(server, "whoami.akamai.net") {
                for ip in answers {
                    if !is_private_ip(&ip) {
                        ips.push(ip);
                    }
                }
            }
        }
        ips
    })
    .await
    .unwrap_or_default();
    let mut hits = Vec::new();
    for ip in ips {
        if hits.iter().any(|hit: &ObservedResolver| hit.ip == ip) {
            continue;
        }
        let facts = lookup_ip(&ip).await.ok();
        hits.push(ObservedResolver {
            country: facts.as_ref().map(|facts| facts.country.clone()).unwrap_or_default(),
            city: facts.as_ref().map(|facts| facts.city.clone()).unwrap_or_default(),
            asn: facts.as_ref().map(|facts| facts.org.clone()).unwrap_or_default(),
            ip,
        });
    }
    LeakReport { inconclusive: hits.is_empty(), hits }
}

fn google_txt(resolvers: &[String]) -> Vec<String> {
    for server in resolvers {
        if let Ok(lines) = dns::query_txt(server, "o-o.myaddr.l.google.com") {
            if !lines.is_empty() {
                return lines;
            }
        }
    }
    Vec::new()
}
