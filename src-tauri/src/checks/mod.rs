mod judge;

use async_trait::async_trait;

use crate::check::{finish, EnvironmentCheck};
use crate::context::{BrowserState, ScanContext};
use crate::model::{params, CheckMeta, CheckResult, Judgement, Status};
use crate::net::http;
use crate::platform::parse::{self, IfaceClass};
use judge::{
    judge_clock, judge_configured_dns, judge_ecs, judge_exit, judge_fingerprint, judge_hosts, judge_ipv6,
    judge_leak, judge_locale, judge_location, judge_proxy, judge_quic, judge_reach, judge_route, judge_timezone,
    judge_tls, judge_webrtc, DnsServerView, LeakHit, ProxyView, ReachHit, WebRtcIp,
};

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
        let judgement = match ctx.exit_v4().await {
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
        finish(&self.meta(), judgement)
    }
}

#[async_trait]
impl EnvironmentCheck for ExitV6 {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "exit_ipv6", category: "exit" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        let iface = ctx.platform.route_v6.clone();
        let judgement = if iface.is_none() {
            judge_ipv6(None, None, "", &ctx.region)
        } else {
            match ctx.exit_v6().await {
                Ok(facts) => {
                    let place = format!("{}, {}, {}", facts.city, facts.region, facts.country);
                    judge_ipv6(iface.as_deref(), Some(&facts.country), &place, &ctx.region)
                        .observe("ip", &facts.ip)
                        .observe("source", &facts.source)
                }
                Err(err) => judge_ipv6(iface.as_deref(), None, "", &ctx.region).observe("error", &err),
            }
        };
        finish(&self.meta(), judgement)
    }
}

#[async_trait]
impl EnvironmentCheck for RouteV4 {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "route_ipv4", category: "routing" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        let country = ctx.exit_v4().await.ok().map(|facts| facts.country);
        let judgement = judge_route(
            ctx.platform.route_v4_a.as_deref(),
            ctx.platform.route_v4_b.as_deref(),
            country.as_deref(),
            &ctx.region,
        );
        finish(&self.meta(), judgement)
    }
}

#[async_trait]
impl EnvironmentCheck for UdpQuic {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "udp_quic", category: "routing" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        let iface = ctx.platform.route_v4_a.as_deref().or(ctx.platform.route_v4_b.as_deref());
        finish(&self.meta(), judge_quic(iface, ctx.platform.proxy.enabled))
    }
}

#[async_trait]
impl EnvironmentCheck for SystemProxy {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "system_proxy", category: "proxy" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        let fetched = if ctx.platform.proxy.pac && ctx.platform.proxy.pac_url.starts_with("http") {
            http::fetch(&ctx.platform.proxy.pac_url, None, std::time::Duration::from_secs(6))
                .await
                .ok()
                .map(|response| response.body)
        } else {
            None
        };
        let iface = ctx.platform.route_v4_a.as_deref().or(ctx.platform.route_v4_b.as_deref());
        let tunnel = iface.map(parse::classify_iface) == Some(IfaceClass::Tunnel);
        let judgement = judge_proxy(ProxyView {
            enabled: ctx.platform.proxy.enabled,
            pac: ctx.platform.proxy.pac,
            pac_url: &ctx.platform.proxy.pac_url,
            pac_body: fetched.as_deref(),
            bypass: &ctx.platform.proxy.bypass,
            route_is_tunnel: tunnel,
        });
        let mut judgement = judgement;
        if !ctx.platform.proxy.http_proxy.is_empty() {
            judgement = judgement.observe("httpProxy", &ctx.platform.proxy.http_proxy);
        }
        finish(&self.meta(), judgement)
    }
}

#[async_trait]
impl EnvironmentCheck for DnsConfigured {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "dns_configured", category: "dns" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
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
        finish(&self.meta(), judge_configured_dns(&servers, &ctx.region.recommended_dns))
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
                provider: parse::cn_dns_provider(&hit.ip).map(|name| name.to_string()),
                ip: hit.ip.clone(),
                country: hit.country.clone(),
                city: hit.city.clone(),
                asn: hit.asn.clone(),
            })
            .collect::<Vec<_>>();
        finish(&self.meta(), judge_leak(&hits, report.inconclusive, &ctx.region))
    }
}

#[async_trait]
impl EnvironmentCheck for DnsEcs {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "dns_ecs", category: "dns" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        let report = ctx.ecs().await;
        if report.failed && report.subnet.is_none() {
            return finish(
                &self.meta(),
                Judgement::new(Status::Inconclusive, "ecs.unavailable", params(&[]), "advice.ecs.retry", params(&[])),
            );
        }
        let country = if let Some(subnet) = &report.subnet {
            let base = subnet.split('/').next().unwrap_or("");
            if parse::is_private_ip(base) {
                None
            } else {
                ctx.lookup(base).await.ok().map(|facts| facts.country)
            }
        } else {
            None
        };
        finish(&self.meta(), judge_ecs(report.subnet.as_deref(), country.as_deref(), &ctx.region))
    }
}

#[async_trait]
impl EnvironmentCheck for Timezone {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "timezone", category: "system" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        let browser = match ctx.browser().await {
            BrowserState::Ready(payload) if !payload.timezone.is_empty() => Some(payload.timezone),
            _ => None,
        };
        let ip_tz = ctx.exit_v4().await.ok().map(|facts| facts.timezone).filter(|tz| !tz.is_empty());
        finish(
            &self.meta(),
            judge_timezone(&ctx.platform.timezone, browser.as_deref(), ip_tz.as_deref(), &ctx.region),
        )
    }
}

#[async_trait]
impl EnvironmentCheck for Locale {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "locale", category: "system" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
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
            return finish(&self.meta(), judge_webrtc(true, &[], &ctx.region));
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
        finish(&self.meta(), judge_webrtc(false, &ips, &ctx.region))
    }
}

#[async_trait]
impl EnvironmentCheck for Fingerprint {
    fn meta(&self) -> CheckMeta {
        CheckMeta { id: "fingerprint", category: "browser" }
    }
    async fn detect(&self, ctx: &ScanContext) -> CheckResult {
        let BrowserState::Ready(payload) = ctx.browser().await else {
            return finish(
                &self.meta(),
                judge_fingerprint(&ctx.platform.os, "", "", false, "", &ctx.platform.timezone, &[], &ctx.platform.locale, true),
            );
        };
        finish(
            &self.meta(),
            judge_fingerprint(
                &ctx.platform.os,
                &payload.user_agent,
                &payload.platform,
                payload.webdriver,
                &payload.timezone,
                &ctx.platform.timezone,
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
        finish(&self.meta(), judge_hosts(&parse::parse_hosts(&ctx.platform.hosts)))
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
        finish(&self.meta(), judge_tls(issuer, facts.verified, facts.error.as_deref()))
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
                ok: sample.ok,
                status: sample.status,
                latency_ms: sample.latency_ms,
                error: sample.error.clone(),
            })
            .collect::<Vec<_>>();
        finish(&self.meta(), judge_reach(&hits))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::BrowserPayload;
    use crate::check::{BackupBlob, FixReport, PhaseError};
    use crate::intel::NullDirectory;
    use crate::platform;
    use crate::region;
    use std::sync::{Arc, Mutex as StdMutex};

    #[tokio::test]
    async fn phase_two_methods_stay_unimplemented() {
        struct Stub;
        #[async_trait]
        impl EnvironmentCheck for Stub {
            fn meta(&self) -> CheckMeta {
                CheckMeta { id: "stub", category: "system" }
            }
            async fn detect(&self, _ctx: &ScanContext) -> CheckResult {
                unreachable!("detect is not under test")
            }
        }
        let ctx = ScanContext::new(
            region::find("us").unwrap().clone(),
            platform::collect(),
            Arc::new(NullDirectory),
            Arc::new(StdMutex::new(None::<BrowserPayload>)),
            "test".into(),
            "http://127.0.0.1/".into(),
            false,
        );
        let stub = Stub;
        assert!(matches!(stub.backup(&ctx).await, Err(PhaseError::NotImplemented)));
        assert!(matches!(
            stub.restore(&ctx, &BackupBlob { id: "x".into(), payload: String::new() }).await,
            Err(PhaseError::NotImplemented)
        ));
        assert!(matches!(stub.fix(&ctx).await, Err(PhaseError::NotImplemented)));
        let _ = FixReport { id: "x".into(), changed: false, detail: String::new() };
    }
}
