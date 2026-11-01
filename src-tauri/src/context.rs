use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use tokio::sync::OnceCell;

use crate::browser::BrowserPayload;
use crate::intel::{EcsReport, IpFacts, LeakReport, NetworkDirectory};
use crate::net::http::{self, Family};
use crate::net::{ntp, tls};
use crate::platform::PlatformSnapshot;
use crate::region::RegionPreset;

#[derive(Debug, Clone)]
pub enum BrowserState {
    Ready(BrowserPayload),
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachClass { Ok, Unreachable, RegionDenied, RateLimited, ServerError }

pub fn classify_reach(host: &str, status: Option<u16>) -> ReachClass {
    match status {
        Some(200..=399) => ReachClass::Ok,
        Some(401 | 404) if host == "api.anthropic.com" => ReachClass::Ok,
        Some(403 | 451) => ReachClass::RegionDenied,
        Some(429) => ReachClass::RateLimited,
        Some(500..=599) => ReachClass::ServerError,
        Some(_) => ReachClass::ServerError,
        None => ReachClass::Unreachable,
    }
}

#[derive(Debug, Clone)]
pub struct ReachSample {
    pub host: &'static str,
    pub class: ReachClass,
    pub status: Option<u16>,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

pub struct ScanContext {
    pub region: Arc<RegionPreset>,
    pub platform: PlatformSnapshot,
    pub browser_url: String,
    pub browser_opened: bool,
    directory: Arc<dyn NetworkDirectory>,
    exit_v4: OnceCell<Result<IpFacts, String>>,
    exit_v6: OnceCell<Result<IpFacts, String>>,
    leak: OnceCell<LeakReport>,
    ecs: OnceCell<EcsReport>,
    clock: OnceCell<Option<i64>>,
    tls: OnceCell<tls::CertFacts>,
    reach: OnceCell<Vec<ReachSample>>,
    browser: OnceCell<BrowserState>,
    slot: Arc<StdMutex<Option<BrowserPayload>>>,
    scan_id: String,
}

impl ScanContext {
    pub fn new(
        region: RegionPreset,
        platform: PlatformSnapshot,
        directory: Arc<dyn NetworkDirectory>,
        slot: Arc<StdMutex<Option<BrowserPayload>>>,
        scan_id: String,
        browser_url: String,
        browser_opened: bool,
    ) -> Self {
        Self {
            region: Arc::new(region),
            platform,
            browser_url,
            browser_opened,
            directory,
            exit_v4: OnceCell::new(),
            exit_v6: OnceCell::new(),
            leak: OnceCell::new(),
            ecs: OnceCell::new(),
            clock: OnceCell::new(),
            tls: OnceCell::new(),
            reach: OnceCell::new(),
            browser: OnceCell::new(),
            slot,
            scan_id,
        }
    }

    pub async fn exit_v4(&self) -> Result<IpFacts, String> {
        let directory = self.directory.clone();
        self.exit_v4
            .get_or_init(|| async move { directory.current_exit(Family::V4).await })
            .await
            .clone()
    }

    pub async fn exit_v6(&self) -> Result<IpFacts, String> {
        let directory = self.directory.clone();
        self.exit_v6
            .get_or_init(|| async move { directory.current_exit(Family::V6).await })
            .await
            .clone()
    }

    pub async fn lookup(&self, ip: &str) -> Result<IpFacts, String> {
        self.directory.lookup_ip(ip).await
    }

    pub async fn leak(&self) -> LeakReport {
        let directory = self.directory.clone();
        let resolvers = self.platform.dns_servers.clone();
        self.leak
            .get_or_init(|| async move { directory.dns_leak(&resolvers).await })
            .await
            .clone()
    }

    pub async fn ecs(&self) -> EcsReport {
        let directory = self.directory.clone();
        let resolvers = self.platform.dns_servers.clone();
        self.ecs
            .get_or_init(|| async move { directory.client_subnet(&resolvers).await })
            .await
            .clone()
    }

    pub async fn clock(&self) -> Option<i64> {
        *self.clock.get_or_init(|| async { tokio::task::spawn_blocking(ntp::offset_millis).await.ok().flatten() }).await
    }

    pub async fn tls(&self) -> tls::CertFacts {
        self.tls.get_or_init(|| tls::inspect("claude.ai")).await.clone()
    }

    pub async fn reach(&self) -> Vec<ReachSample> {
        self.reach
            .get_or_init(|| async {
                let (claude, api) = tokio::join!(
                    timed("https://claude.ai/", "claude.ai"),
                    timed("https://api.anthropic.com/", "api.anthropic.com"),
                );
                vec![claude, api]
            })
            .await
            .clone()
    }

    pub async fn browser(&self) -> BrowserState {
        let slot = self.slot.clone();
        let scan_id = self.scan_id.clone();
        self.browser
            .get_or_init(|| async move {
                let start = Instant::now();
                while start.elapsed() < Duration::from_secs(22) {
                    let ready = slot.lock().ok().and_then(|guard| guard.clone()).filter(|payload| payload.scan_id == scan_id);
                    if let Some(payload) = ready {
                        return BrowserState::Ready(payload);
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                BrowserState::Missing
            })
            .await
            .clone()
    }
}

async fn timed(url: &str, host: &'static str) -> ReachSample {
    let started = Instant::now();
    match http::fetch(url, None, Duration::from_secs(12)).await {
        Ok(response) if response.status > 0 => ReachSample {
            host,
            class: classify_reach(host, Some(response.status)),
            status: Some(response.status),
            latency_ms: Some(started.elapsed().as_millis() as u64),
            error: None,
        },
        Ok(_) => ReachSample {
            host,
            class: ReachClass::Unreachable,
            status: None,
            latency_ms: Some(started.elapsed().as_millis() as u64),
            error: Some("empty response".into()),
        },
        Err(err) => ReachSample {
            host,
            class: ReachClass::Unreachable,
            status: None,
            latency_ms: None,
            error: Some(err),
        },
    }
}

#[cfg(test)]
mod reach_tests {
    use super::*;
    #[test]
    fn classifies_transport_and_http_responses() {
        for code in [200, 204, 301, 399] { assert_eq!(classify_reach("claude.ai", Some(code)), ReachClass::Ok); }
        for code in [401, 404] {
            assert_eq!(classify_reach("api.anthropic.com", Some(code)), ReachClass::Ok);
            assert_ne!(classify_reach("claude.ai", Some(code)), ReachClass::Ok);
        }
        for code in [403, 451] { assert_eq!(classify_reach("claude.ai", Some(code)), ReachClass::RegionDenied); }
        assert_eq!(classify_reach("claude.ai", Some(429)), ReachClass::RateLimited);
        for code in [500, 503, 599] { assert_eq!(classify_reach("claude.ai", Some(code)), ReachClass::ServerError); }
        assert_eq!(classify_reach("claude.ai", None), ReachClass::Unreachable);
    }
}
