mod judge;

use async_trait::async_trait;

use crate::check::{finish, EnvironmentCheck};
use crate::context::{BrowserState, ScanContext};
use crate::model::{params, CheckMeta, CheckResult, Judgement, Status};
use crate::net::http;
use crate::platform::parse::{self, IfaceClass};
use judge::{
    judge_clock, judge_configured_dns, judge_ecs, judge_exit, judge_fingerprint, judge_ipv6,
    judge_leak, judge_locale, judge_location, judge_proxy, judge_reach, judge_timezone,
    judge_tls, judge_webrtc, DnsServerView, LeakHit, ProxyView, ReachHit, WebRtcIp,
};

// Only reject missing values for collectors that have usable fallback sources.
fn collection_failure(platform: &crate::platform::PlatformSnapshot, key: &str, missing: bool) -> Option<Judgement> {
    if !missing { return None; }
    let error = platform.errors.get(key)?;
    Some(Judgement::new(Status::Inconclusive, "collection.unavailable", params(&[]), "advice.collection.retry", params(&[]))
        .observe("collectionError", error))
}

pub fn all() -> Vec<Box<dyn EnvironmentCheck>> {
    vec![
        Box::new(ExitV4),
        Box::new(ExitV6),
        Box::new(RouteV4),
        Box::new(UdpQuic),
        Box::new(SystemProxy),
        Box::new(DnsConfigured),
        Box::new(DnsLeak),
        Box::new(DnsEcs),
        Box::new(Timezone),
        Box::new(Locale),
        Box::new(WebRtc),
        Box::new(Fingerprint),
        Box::new(Location),
        Box::new(Clock),
        Box::new(HostsFile),
        Box::new(TlsIssuer),
        Box::new(Reachability),
    ]
}

struct ExitV4;
struct ExitV6;
struct RouteV4;
struct UdpQuic;
struct SystemProxy;
struct DnsConfigured;
struct DnsLeak;
struct DnsEcs;
struct Timezone;
struct Locale;
struct WebRtc;
struct Fingerprint;
struct Location;
struct Clock;
struct HostsFile;
struct TlsIssuer;
struct Reachability;

#[async_trait]
impl EnvironmentCheck for ExitV4 {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "exit_ipv4", category: "exit" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        let mut judgement = match ctx.exit_v4().await {
            Ok(facts) => judge_exit(
                Some(&facts.ip),
                Some(&facts.country),
                &facts.city,
                &facts.region,
                &facts.org,
                facts.hosting,
                &ctx.region,
            )
            .observe("source", &facts.source)
            .observe("timezone", &facts.timezone),
            Err(err) => judge_exit(None, None, "", "", "", None, &ctx.region).observe("error", &err),
        };
        judgement = annotate_exit_paths(ctx, http::Family::V4, judgement).await;
        finish(&self.meta(), judgement)
    }
}

async fn annotate_exit_paths(ctx:&ScanContext,family:http::Family,mut judgement:Judgement)->Judgement {
    // The successful collector includes the actual selected PAC fallback in its source.
    let path=judgement.observed.get("source").and_then(|s|s.split_once("; path: ").map(|(_,p)|p.to_owned()));
    judgement=judgement.observe("path",match path {Some(p)=>p,None=>ctx.path_label("https://ipinfo.io/json").await});
    match ctx.direct_exit(family).await {
        Ok(f)=>{
            if f.country=="CN" && matches!(judgement.status,Status::Pass|Status::Warn) {
                judgement.status=Status::Warn;
                judgement.summary_key="exit.pathDifference".into();judgement.summary_params=params(&[]);
                judgement.advice_key="advice.exit.pathDifference".into();judgement.advice_params=params(&[]);
            }
            judgement=judgement.observe("direct",format!("path: direct; {}, {}",f.ip,f.country));
        },
        Err(e)=>judgement=judgement.observe("direct",format!("path: direct; unavailable: {e}")),
    }
    judgement
}

#[async_trait]
impl EnvironmentCheck for ExitV6 {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "exit_ipv6", category: "exit" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        let route = &ctx.platform.route_v6;
        let judgement = match ctx.exit_v6().await {
            Ok(facts) => judge_ipv6(route, Some(&facts.country), &format!("{}, {}, {}", facts.city, facts.region, facts.country), &ctx.region)
                .observe("ip", &facts.ip).observe("source", &facts.source),
            Err(err) => {
                let unknown = crate::platform::Ipv6Route::Unknown("effective proxy IPv6 path was not observed".into());
                judge_ipv6(if ctx.platform.proxy.enabled || ctx.platform.proxy.pac || ctx.platform.proxy.wpad { &unknown } else { route }, None, "", &ctx.region).observe("error",err)
            },
        };
        let judgement = annotate_exit_paths(ctx, http::Family::V6, judgement).await;
        finish(&self.meta(), judgement)
    }
}

#[async_trait]
impl EnvironmentCheck for RouteV4 {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "route_ipv4", category: "routing" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        if let Some(judgement) = collection_failure(&ctx.platform, "route_v4", ctx.platform.route_v4_a.is_none() || ctx.platform.route_v4_b.is_none()) {
            return finish(&self.meta(), judgement);
        }
        let country = ctx.exit_v4().await.ok().map(|facts| facts.country);
        let judgement = judge::judge_route_classified(
            ctx.platform.route_v4_a.as_deref(),
            ctx.platform.route_v4_b.as_deref(),
            country.as_deref(),
            &ctx.region,
            ctx.platform.windows_routes.iter().find(|r| Some(r.alias.as_str()) == ctx.platform.route_v4_a.as_deref()).map(|r| r.class),
        );
        let judgement = if let Some(route) = ctx.platform.windows_routes.iter().find(|r| Some(r.alias.as_str()) == ctx.platform.route_v4_a.as_deref()) {
            judgement.observe("ifIndex",route.index.to_string()).observe("interfaceClass",route.classification).observe("routeMetric",route.metric.to_string())
        } else { judgement };
        finish(&self.meta(), judgement)
    }
}

#[async_trait]
impl EnvironmentCheck for UdpQuic {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "udp_quic", category: "routing" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        use crate::net::udp::StunResult;
        let (a,b,quic)=ctx.udp_probe().await;
        let tcp=ctx.exit_v4().await.ok();
        let mut countries=Vec::new();let mut details=Vec::new();let mut unknown=false;let mut blocked=0;
        for (server,r) in [("google",a),("cloudflare",b)] {
            match r {
                StunResult::Mapped(ip)=>match ctx.lookup(&ip.to_string()).await {Ok(f) if !f.country.is_empty()=>{details.push(format!("{server}: {ip} {}",f.country));countries.push(f.country)}, _=>{unknown=true;details.push(format!("{server}: {ip}, country unavailable"));}},
                StunResult::Blocked=>{blocked+=1;details.push(format!("{server}: UDP administratively blocked"));},
                StunResult::Unknown(e)=>{unknown=true;details.push(format!("{server}: {e}"));},
            }
        }
        let (status,key)=judge::judge_udp_measurements(&countries,tcp.as_ref().map(|t|t.country.as_str()),&ctx.region.country,unknown,blocked,&quic);
        finish(&self.meta(),Judgement::new(status,key,params(&[]),"advice.quic.measured",params(&[]))
            .observe("UDP",details.join("; ")).observe("QUIC",format!("{quic:?}")).observe("TCP effective country",tcp.map(|f|f.country).unwrap_or_default()))
    }
}

fn combine_pac_judgement(base: Judgement, direct: bool, failed: bool, tunnel: bool) -> Judgement {
    // The initial PAC judgement is unknown until evaluation; retain a bypass failure.
    if base.status == Status::Fail { return base; }
    Judgement::new(
        if direct && tunnel { Status::Warn } else if direct { Status::Fail } else if failed { Status::Inconclusive } else { Status::Pass },
        if direct && tunnel { "proxy.pacDirectTunnel" } else if direct { "proxy.pacDirect" } else if failed { "proxy.pacUnknown" } else { "proxy.pacProxy" },
        params(&[]), "advice.proxy.readPac", params(&[]),
    )
}

#[async_trait]
impl EnvironmentCheck for SystemProxy {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "system_proxy", category: "proxy" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        if let Some(judgement) = collection_failure(&ctx.platform, "proxy", true) {
            return finish(&self.meta(), judgement);
        }
        let fetched = if ctx.platform.proxy.pac && ctx.platform.proxy.pac_url.starts_with("file:") {
            crate::pac::read_file_url(&ctx.platform.proxy.pac_url).await
        } else if ctx.platform.proxy.pac && ctx.platform.proxy.pac_url.starts_with("http") {
            http::fetch(&ctx.platform.proxy.pac_url, None, std::time::Duration::from_secs(6))
                .await
                .ok()
                .filter(|response| (200..300).contains(&response.status))
                .map(|response| response.body)
        } else {
            None
        };
        let iface = ctx.platform.route_v4_a.as_deref().or(ctx.platform.route_v4_b.as_deref());
        let tunnel = ctx.platform.windows_routes.iter().find(|r| Some(r.alias.as_str()) == iface).map(|r| r.class).or_else(|| iface.map(parse::classify_iface)) == Some(IfaceClass::Tunnel);
        let judgement = judge_proxy(ProxyView {
            enabled: ctx.platform.proxy.enabled,
            pac: ctx.platform.proxy.pac,
            pac_url: &ctx.platform.proxy.pac_url,
            bypass: &ctx.platform.proxy.bypass,
            route_is_tunnel: tunnel,
        });
        let mut judgement = judgement;
        if ctx.platform.proxy.pac {
            let ips = crate::pac::resolve_targets().await;
            let mut results = Vec::new();
            let mut failed = false;
            let mut direct = false;
            for (url,host) in crate::pac::TARGETS {
                let result = if let Some(body) = fetched.as_ref() {
                    let (body,url,host,ips)=(body.clone(),url.to_string(),host.to_string(),ips.clone());
                    tokio::task::spawn_blocking(move || crate::pac::evaluate(&body,&url,&host,ips)).await.unwrap_or_else(|e| Err(e.to_string()))
                } else { Err("PAC fetch failed".into()) };
                direct |= result.as_ref().is_ok_and(|r| r.first()==Some(&crate::pac::Route::Direct));
                failed |= result.is_err();
                let text = match &result { Ok(routes) => routes.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "), Err(error) => error.clone() };
                results.push(format!("{url} → {text}"));
            }
            judgement = combine_pac_judgement(judgement, direct, failed, tunnel)
                .observe("pac", &ctx.platform.proxy.pac_url).observe("pacRoutes", results.join("; "));
        } else if ctx.platform.proxy.wpad {
            judgement = Judgement::new(Status::Inconclusive,"proxy.pacUnknown",params(&[]),"advice.proxy.readPac",params(&[]));
        }
        for (source,value) in &ctx.platform.proxy.sources { judgement = judgement.observe(source,value); }
        judgement = judgement.observe("wpad", ctx.platform.proxy.wpad.to_string());
        for (key,value) in [("httpsProxy",&ctx.platform.proxy.https_proxy),("socksProxy",&ctx.platform.proxy.socks_proxy)] { judgement = judgement.observe(key,value); }

        if !ctx.platform.proxy.http_proxy.is_empty() {
            judgement = judgement.observe("httpProxy", &ctx.platform.proxy.http_proxy);
        }
        finish(&self.meta(), judgement)
    }
}

fn unsupported_nrpt(blocks: &[parse::ResolverBlock]) -> Option<Judgement> {
    let mut result = None;
    for host in ["claude.ai", "api.anthropic.com"] {
        if parse::resolvers_for_host(blocks, host).iter().any(|b| b.policy.is_some() && b.nameservers.is_empty()) {
            let judgement = result.get_or_insert_with(|| Judgement::new(Status::Inconclusive, "dns.scopedInfo", params(&[]), "advice.ecs.retry", params(&[])));
            *judgement = judgement.clone().observe(host, "NRPT policy without plain DNS servers");
        }
    }
    result
}

#[async_trait]
impl EnvironmentCheck for DnsConfigured {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "dns_configured", category: "dns" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        if let Some(judgement) = unsupported_nrpt(&ctx.platform.dns_blocks) {
            return finish(&self.meta(), judgement);
        }
        if let Some(judgement) = collection_failure(&ctx.platform, "dns", ctx.platform.dns_servers.is_empty()) {
            return finish(&self.meta(), judgement);
        }
        let mut servers = Vec::new();
        for ip in &ctx.platform.dns_servers {
            let provider = parse::cn_dns_provider(ip).map(|name| name.to_string());
            let country = if provider.is_none() && !parse::is_private_ip(ip) {
                ctx.lookup(ip).await.ok().map(|facts| facts.country).unwrap_or_default()
            } else {
                String::new()
            };
            servers.push(DnsServerView { ip: ip.clone(), country, provider });
        }
        let mut result = judge_configured_dns(&servers, &ctx.region.recommended_dns);
        // Configuration alone cannot establish an actual DNS leak.
        if result.status == Status::Fail { result.status = Status::Warn; }
        for host in ["claude.ai","api.anthropic.com"] {
            let blocks = parse::resolvers_for_host(&ctx.platform.dns_blocks, host);
            let scoped: Vec<_> = blocks.into_iter().filter(|b| !b.domains.is_empty()).collect();
            if !scoped.is_empty() {
                let known_cn = scoped.iter().flat_map(|b| &b.nameservers).any(|ip| parse::cn_dns_provider(ip).is_some());
                result = result.observe(host, scoped.iter().flat_map(|b| b.nameservers.iter().map(move |ip| {
                    let mut context = Vec::new();
                    if !b.iface.is_empty() { context.push(b.iface.clone()); }
                    if !b.domains.is_empty() { context.push(format!("domain {}", b.domains.join(", "))); }
                    format!("{host} → {ip} ({})", context.join(", "))
                })).collect::<Vec<_>>().join("; "));
                if known_cn { result.status = Status::Fail; result.summary_key="dns.scopedCn".into(); }
                else if result.status != Status::Fail { result.status=Status::Info; result.summary_key="dns.scopedInfo".into(); }
            }
        }
        finish(&self.meta(), result)
    }
}

#[async_trait]
impl EnvironmentCheck for DnsLeak {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "dns_leak", category: "dns" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        let report = ctx.leak().await;
        let hits = report
            .hits
            .iter()
            .map(|hit| LeakHit {
                path: hit.path.clone(), resolver: hit.resolver.clone(),
                provider: parse::cn_dns_provider(&hit.ip).map(|name| name.to_string()),
                ip: hit.ip.clone(),
                country: hit.country.clone(),
                city: hit.city.clone(),
                asn: hit.asn.clone(),
            })
            .collect::<Vec<_>>();
        finish(&self.meta(), judge_leak(&hits, report.system_inconclusive, &ctx.region).observe("configProbe", report.config_details.join("; ")).observe("configProbeStatus", if report.config_inconclusive { "incomplete" } else { "complete" }))
    }
}

#[async_trait]
impl EnvironmentCheck for DnsEcs {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "dns_ecs", category: "dns" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        let report = ctx.ecs().await;
        let mut judgments = Vec::new();
        let mut details = Vec::new();
        let mut missing = report.results.is_empty();
        for row in report.results {
            missing |= row.error.is_some();
            details.push(row.readable());
            let subnets = parse::parse_ecs_subnets(&row.values);
            let egress_ips: Vec<_> = row.values.iter().map(|s| s.trim().trim_matches('"')).filter(|s| s.parse::<std::net::IpAddr>().is_ok()).map(str::to_string).collect();
            for subnet in subnets.into_iter().chain(egress_ips) {
                let base = subnet.split('/').next().unwrap_or("");
                let country = ctx.lookup(base).await.ok().map(|f| f.country);
                missing |= country.as_ref().is_none_or(|c| c.is_empty());
                judgments.push(judge_ecs(Some(&subnet), country.as_deref(), &ctx.region));
            }
        }
        let result = aggregate_dns(judgments, missing);
        finish(&self.meta(), result.observe("path", "configured-server").observe("resolvers", details.join("; ")))

    }
}

fn aggregate_dns(results: Vec<Judgement>, missing: bool) -> Judgement {
    if let Some(fail) = results.iter().find(|j| j.status == Status::Fail) { return fail.clone(); }
    if missing { return Judgement::new(Status::Inconclusive, "ecs.unavailable", params(&[]), "advice.ecs.retry", params(&[])); }
    results.into_iter().max_by_key(|j| j.status.rank()).unwrap_or_else(|| Judgement::new(Status::Info, "ecs.absent", params(&[]), "advice.ecs.ok", params(&[])))
}

#[async_trait]
impl EnvironmentCheck for Timezone {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "timezone", category: "system" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        if let Some(judgement) = collection_failure(&ctx.platform, "timezone", ctx.platform.timezone.trim().is_empty()) {
            return finish(&self.meta(), judgement);
        }
        let browser = match ctx.browser().await {
            BrowserState::Ready(payload) if !payload.timezone.is_empty() => Some(payload.timezone),
            _ => None,
        };
        let ip_tz = ctx.exit_v4().await.ok().map(|facts| facts.timezone).filter(|tz| !tz.is_empty());
        finish(
            &self.meta(),
            if ctx.platform.os == "windows" {
                judge::judge_windows_timezone(&ctx.platform.timezone, ctx.platform.windows_territory.as_deref(), browser.as_deref(), ip_tz.as_deref(), &ctx.region)
            } else { judge_timezone(&ctx.platform.timezone, browser.as_deref(), ip_tz.as_deref(), &ctx.region) },
        )
    }
}

#[async_trait]
impl EnvironmentCheck for Locale {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "locale", category: "system" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        if let Some(judgement) = collection_failure(&ctx.platform, "locale", ctx.platform.locale.trim().is_empty()) {
            return finish(&self.meta(), judgement);
        }
        let (langs, accept, missing) = match ctx.browser().await {
            BrowserState::Ready(payload) => {
                let missing = payload.languages.is_empty() && payload.accept_language.is_empty();
                (payload.languages, payload.accept_language, missing)
            }
            BrowserState::Missing => (Vec::new(), String::new(), true),
        };
        finish(
            &self.meta(),
            judge_locale(&ctx.platform.locale, &langs, &accept, missing, &ctx.region),
        )
    }
}

#[async_trait]
impl EnvironmentCheck for WebRtc {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "webrtc", category: "browser" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        let BrowserState::Ready(payload) = ctx.browser().await else {
            return finish(&self.meta(), judge_webrtc(None, &[], &ctx.region));
        };
        let mut ips = Vec::new();
        for candidate in payload.webrtc.iter().take(8) {
            if candidate.ip.parse::<std::net::IpAddr>().is_err() {
                continue;
            }
            let country = if parse::is_private_ip(&candidate.ip) {
                String::new()
            } else {
                ctx.lookup(&candidate.ip).await.ok().map(|facts| facts.country).unwrap_or_default()
            };
            ips.push(WebRtcIp { ip: candidate.ip.clone(), kind: candidate.kind.clone(), country });
        }
        finish(&self.meta(), judge_webrtc(payload.webrtc_status.as_ref(), &ips, &ctx.region))
    }
}

#[async_trait]
impl EnvironmentCheck for Fingerprint {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "fingerprint", category: "browser" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        if let Some(judgement) = collection_failure(&ctx.platform, "timezone", ctx.platform.timezone.trim().is_empty()) {
            return finish(&self.meta(), judgement);
        }
        if let Some(judgement) = collection_failure(&ctx.platform, "locale", ctx.platform.locale.trim().is_empty()) {
            return finish(&self.meta(), judgement);
        }
        let BrowserState::Ready(payload) = ctx.browser().await else {
            return finish(
                &self.meta(),
                judge_fingerprint(&ctx.platform.os, "", "", false, "", &ctx.platform.timezone, &[], &ctx.platform.locale, true),
            );
        };
        let mapped = if ctx.platform.os == "windows" { parse::windows_to_iana(&ctx.platform.timezone, ctx.platform.windows_territory.as_deref().or(Some(&ctx.region.country))) } else { vec![ctx.platform.timezone.clone()] };
        let system_timezone = mapped.iter().find(|tz| parse::canon_tz(tz)==parse::canon_tz(&payload.timezone)).or_else(|| mapped.first()).map(String::as_str).unwrap_or("");
        finish(
            &self.meta(),
            judge_fingerprint(
                &ctx.platform.os,
                &payload.user_agent,
                &payload.platform,
                payload.webdriver,
                &payload.timezone,
                system_timezone,
                &payload.languages,
                &ctx.platform.locale,
                false,
            ),
        )
    }
}

#[async_trait]
impl EnvironmentCheck for Location {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "location", category: "system" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        if let Some(judgement) = collection_failure(&ctx.platform, "location", ctx.platform.location_enabled.is_none()) {
            return finish(&self.meta(), judgement);
        }
        let permission = match ctx.browser().await {
            BrowserState::Ready(payload) if !payload.geolocation.is_empty() => Some(payload.geolocation),
            _ => None,
        };
        finish(&self.meta(), judge_location(ctx.platform.location_enabled, permission.as_deref()))
    }
}

#[async_trait]
impl EnvironmentCheck for Clock {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "clock", category: "system" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        finish(&self.meta(), judge_clock(ctx.clock().await))
    }
}

#[async_trait]
impl EnvironmentCheck for HostsFile {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "hosts", category: "destination" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        finish(&self.meta(), judge::judge_hosts_file(&ctx.platform.hosts))
    }
}

#[async_trait]
impl EnvironmentCheck for TlsIssuer {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "tls", category: "destination" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        let facts = ctx.tls().await;
        let issuer = if facts.issuer.is_empty() { None } else { Some(facts.issuer.as_str()) };
        let direct = crate::net::tls::inspect("claude.ai").await;
        finish(&self.meta(), judge_tls(issuer, facts.verified, facts.error.as_deref())
            .observe("path",facts.path).observe("subject",facts.subject).observe("direct",format!("path: direct; {:?}",direct)))
    }
}

#[async_trait]
impl EnvironmentCheck for Reachability {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "reachability", category: "destination" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        let samples = ctx.reach().await;
        let hits = samples
            .iter()
            .map(|sample| ReachHit {
                host: sample.host,
                class: sample.class,
                status: sample.status,
                latency_ms: sample.latency_ms,
                error: sample.error.clone(),
            })
            .collect::<Vec<_>>();
        finish(&self.meta(), judge_reach(&hits)
            .observe("path.claude.ai",samples.first().map(|s|s.path.clone()).unwrap_or_default())
            .observe("path.api.anthropic.com",samples.get(1).map(|s|s.path.clone()).unwrap_or_default())
            .observe("direct",format!("path: direct; {}",ctx.direct_reach().await)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::BrowserPayload;
    use crate::intel::NullDirectory;
    use crate::platform;
    use crate::region;
    use std::sync::{Arc, Mutex as StdMutex};

    pub(super) fn empty_snapshot() -> platform::PlatformSnapshot {
        platform::PlatformSnapshot {
            windows_territory: None, windows_routes: vec![],
            dns_blocks: Vec::new(),
            os: "linux".into(), timezone: String::new(), locale: String::new(),
            dns_servers: Vec::new(), route_v4_a: None, route_v4_b: None,
            route_v6: platform::Ipv6Route::Absent,
            proxy: platform::ProxySnapshot {
            sources: Default::default(), wpad: false,
                enabled: false, pac: false, pac_url: String::new(), bypass: Vec::new(),
                http_proxy: String::new(), https_proxy: String::new(), socks_proxy: String::new(),
            },
            hosts: Ok(String::new()), location_enabled: None, errors: Default::default(),
        }
    }

    #[tokio::test]
    async fn collection_errors_reach_affected_checks() {
        let mut snapshot = empty_snapshot();
        for key in ["timezone", "locale", "dns", "route_v4", "proxy", "location"] {
            snapshot.errors.insert(key.into(), format!("{key} collection denied"));
        }
        let ctx = ScanContext::new(
            region::find("us").unwrap().clone(), snapshot, Arc::new(NullDirectory),
            Arc::new(StdMutex::new(None::<BrowserPayload>)),
            "test".into(), "http://127.0.0.1/".into(), false,
        );
        for (check, key) in [
            (Box::new(Timezone) as Box<dyn EnvironmentCheck>, "timezone"),
            (Box::new(Locale), "locale"), (Box::new(DnsConfigured), "dns"),
            (Box::new(RouteV4), "route_v4"),
            (Box::new(SystemProxy), "proxy"), (Box::new(Location), "location"),
        ] {
            let result = check.detect(&ctx).await;
            assert_eq!(result.status, Status::Inconclusive, "{key}");
            assert_eq!(result.observed.get("collectionError"), ctx.platform.errors.get(key));
        }
    }

    #[tokio::test]
    async fn policy_without_plain_dns_never_passes_or_selects_adapter_servers() {
        for namespace in [".", ".claude.ai"] {
            let mut snapshot = empty_snapshot();
            snapshot.dns_blocks = platform::windows_parse::dns_blocks(&[], &[], &[], &[
                serde_json::json!({"Namespace":namespace,"DirectAccessEnabled":true})]);
            snapshot.dns_blocks.push(parse::ResolverBlock { nameservers: vec!["8.8.8.8".into()], ..Default::default() });
            assert!(parse::resolvers_for_host(&snapshot.dns_blocks, "claude.ai").iter().flat_map(|b| &b.nameservers).next().is_none());
            snapshot.dns_servers = platform::windows_parse::effective_servers(&snapshot.dns_blocks);
            let ctx = ScanContext::new(region::find("us").unwrap().clone(), snapshot, Arc::new(NullDirectory),
                Arc::new(StdMutex::new(None::<BrowserPayload>)), "test".into(), "http://127.0.0.1/".into(), false);
            let result = DnsConfigured.detect(&ctx).await;
            assert_eq!(result.status, Status::Inconclusive);
            assert_eq!(result.observed.get("claude.ai").map(String::as_str), Some("NRPT policy without plain DNS servers"));
        }
    }

    #[test]
    fn successful_fallback_values_remain_usable() {
        let mut snapshot = empty_snapshot();
        snapshot.errors.insert("dns".into(), "resolvectl unavailable".into());
        assert!(collection_failure(&snapshot, "dns", true).is_some());
        snapshot.dns_servers.push("8.8.8.8".into());
        assert!(collection_failure(&snapshot, "dns", snapshot.dns_servers.is_empty()).is_none());
        assert_eq!(judge_configured_dns(&[], &[]).status, Status::Warn);
    }

    #[tokio::test]
    async fn unavailable_intel_and_independent_ipv6_probe() {
        let mut snapshot = platform::collect();
        snapshot.route_v6 = platform::Ipv6Route::Absent;
        let ctx = ScanContext::new(
            region::find("us").unwrap().clone(),
            snapshot,
            Arc::new(NullDirectory),
            Arc::new(StdMutex::new(None::<BrowserPayload>)),
            "test".into(),
            "http://127.0.0.1/".into(),
            false,
        );
        assert_eq!(ExitV4.detect(&ctx).await.status, Status::Inconclusive);
        let v6 = ExitV6.detect(&ctx).await;
        assert_eq!(v6.status, Status::Pass);
        // Even a confirmed absent route must not skip the exit probe.
        assert_eq!(v6.observed.get("error").map(String::as_str), Some("offline"));
    }

}

#[cfg(test)] mod feature4_tests {
    use super::*;
    #[test] fn aggregation_leak_wins_and_missing_never_passes() {
        let p=crate::region::find("us").unwrap();
        assert_eq!(aggregate_dns(vec![judge_ecs(Some("1.2.3.0/24"),Some("US"),p)],true).status,Status::Inconclusive);
        assert_eq!(aggregate_dns(vec![judge_ecs(Some("1.2.3.0/24"),Some("US"),p),judge_ecs(Some("2.3.4.0/24"),Some("CN"),p)],true).status,Status::Fail);
        assert_eq!(judge_leak(&[LeakHit {path:"system".into(),resolver:"system".into(),ip:"1.2.3.4".into(),country:String::new(),city:String::new(),asn:String::new(),provider:None}],false,p).status,Status::Inconclusive);
    }
    #[test]
    fn leak_paths_are_independent() {
        let preset = crate::region::find("us").unwrap();
        let hit = |path: &str, country: &str| LeakHit {
            path: path.into(), resolver: "resolver".into(), ip: "1.2.3.4".into(),
            country: country.into(), city: String::new(), asn: String::new(), provider: None,
        };
        let report = crate::intel::LeakReport {
            config_details: vec!["223.5.5.5: timeout".into()],
            hits: vec![], system_inconclusive: false, config_inconclusive: true,
        };
        assert_eq!(judge_leak(&[hit("system", "US")], report.system_inconclusive, preset).status, Status::Pass);
        assert_eq!(judge_leak(&[hit("system", "US"), hit("configured-server", "CN")], false, preset).status, Status::Warn);
        assert_eq!(judge_leak(&[hit("system", "CN")], true, preset).status, Status::Fail);
        assert_eq!(judge_leak(&[hit("configured-server", "US")], false, preset).status, Status::Inconclusive);
        assert_eq!(judge_leak(&[], false, preset).status, Status::Inconclusive);
        assert_eq!(judge_leak(&[hit("system", "US")], true, preset).status, Status::Inconclusive);
        assert_eq!(judge_leak(&[hit("system", "JP"), hit("configured-server", "")], false, preset).status, Status::Warn);
        assert_eq!(judge_leak(&[hit("system", "US"), hit("configured-server", "")], false, preset).status, Status::Pass);
        let mut mainland_provider = hit("system", "");
        mainland_provider.provider = Some("mainland provider".into());
        assert_eq!(judge_leak(&[mainland_provider], false, preset).status, Status::Fail);
    }
    #[test]
    fn pac_first_route_and_bypass_judgements() {
        let base = || judge_proxy(ProxyView { enabled: true, pac: true, pac_url: "file:///proxy.pac", bypass: &[], route_is_tunnel: false });
        for (routes, tunnel, expected) in [
            ("direct; proxy p:80", false, Status::Fail),
            ("DIRECT; PROXY p:80", true, Status::Warn),
            ("proxy p:80; direct", false, Status::Pass),
            ("socks p:1080", false, Status::Pass),
        ] {
            let routes = crate::pac::parse_routes(routes).unwrap();
            let direct = routes.first() == Some(&crate::pac::Route::Direct);
            assert_eq!(combine_pac_judgement(base(), direct, false, tunnel).status, expected);
        }
        let bypass = vec!["claude.ai".into()];
        let base = judge_proxy(ProxyView { enabled: true, pac: true, pac_url: "", bypass: &bypass, route_is_tunnel: false });
        let combined = combine_pac_judgement(base, false, false, false);
        assert_eq!(combined.status, Status::Fail);
        assert_eq!(combined.summary_key, "proxy.bypassClaude");
    }
    #[tokio::test] async fn proxy_secrets_do_not_reach_json() {
        use std::sync::{Arc,Mutex};
        let mut platform=crate::platform::collect();
        platform.errors.clear();
        platform.proxy.enabled=true; platform.proxy.pac=false; platform.proxy.bypass.clear();
        platform.proxy.http_proxy="http://alice:supersecret@proxy.example:8080/?TOKEN=privatevalue".into();
        let ctx=ScanContext::new(crate::region::find("us").unwrap().clone(),platform,Arc::new(crate::intel::NullDirectory),Arc::new(Mutex::new(None)),"test".into(),"http://127.0.0.1/".into(),false);
        let check=SystemProxy.detect(&ctx).await;
        let json=serde_json::to_string(&check).unwrap();
        for secret in ["alice","supersecret","privatevalue"] { assert!(!json.contains(secret),"{json}"); }
        let report=crate::model::ScanReport {generated_at:String::new(),os:"linux".into(),region_id:"us".into(),region_name:Default::default(),verdict:crate::model::Verdict::Review,checks:vec![check],browser_url:String::new(),browser_opened:false,phase:1};
        let json=serde_json::to_string(&report).unwrap();
        assert!(!json.contains("supersecret") && !json.contains("privatevalue"));
    }
}

#[cfg(test)]
pub(crate) fn test_snapshot()->crate::platform::PlatformSnapshot { tests::empty_snapshot() }

#[cfg(test)] mod effective_path_tests {
use super::*;
use crate::{intel::{NetworkDirectory,IpFacts,LeakReport,EcsReport},platform::ProxySnapshot};
struct Fake;
fn facts(country:&str)->IpFacts {IpFacts{ip:if country=="CN"{"203.0.113.2"}else{"198.51.100.8"}.into(),country:country.into(),city:"New York".into(),region:"New York".into(),org:"ISP".into(),timezone:"America/New_York".into(),hosting:Some(false),source:"fake; path: effective(PROXY proxy.invalid:8080)".into()} }
#[async_trait] impl NetworkDirectory for Fake {
 async fn current_exit(&self,_:http::Family)->Result<IpFacts,String>{Ok(facts("CN"))}
 async fn effective_exit(&self,_:http::Family,_:&ProxySnapshot)->Result<IpFacts,String>{Ok(facts("US"))}
 async fn lookup_ip(&self,_:&str)->Result<IpFacts,String>{Err("not run".into())}
 async fn dns_leak(&self,_:&[String])->LeakReport{unreachable!()}
 async fn client_subnet(&self,_:&[String])->EcsReport{unreachable!()}
}
#[tokio::test] async fn mainland_direct_overseas_effective_warns_in_both_families(){
 let mut platform=test_snapshot();platform.proxy.enabled=true;platform.proxy.http_proxy="http://user:secret@proxy.invalid:8080".into();
 let ctx=ScanContext::new(crate::region::find("us").unwrap().clone(),platform,std::sync::Arc::new(Fake),Default::default(),"test".into(),String::new(),false);
 for check in [Box::new(ExitV4) as Box<dyn EnvironmentCheck>,Box::new(ExitV6)] {
 let result=check.detect(&ctx).await;assert_eq!(result.status,Status::Warn);assert_eq!(result.summary_key,"exit.pathDifference");assert!(result.observed["direct"].contains("CN"));assert_eq!(result.observed["path"],"effective(PROXY proxy.invalid:8080)");assert!(!serde_json::to_string(&result).unwrap().contains("secret"));
 }
}
}
