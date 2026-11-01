use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures::future::join_all;

use crate::browser;
use crate::context::ScanContext;
use crate::intel::PublicDirectory;
use crate::model::ScanReport;
use crate::platform;
use crate::region;
use crate::report;
use crate::browser::Hub;
use crate::checks;

pub struct PreparedScan {
    pub report: ScanReport,
}

pub async fn execute_with(region_id: &str, ready: impl FnOnce(Hub), updated: impl Fn(ScanReport) + Send + 'static) -> Result<PreparedScan, String> {
    let region = region::find(region_id).cloned().ok_or_else(|| format!("unknown region {region_id}"))?;
    let scan_id = format!("scan-{}", SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0));
    let hub = browser::Hub::start(scan_id.clone())?;
    let opened = browser::open_url(&hub.url);
    let slot = hub.slot.clone();
    let public_url = hub.public_url();
    ready(hub);
    let platform = tokio::task::spawn_blocking(platform::collect).await.map_err(|err| err.to_string())?;
    let ctx = Arc::new(ScanContext::new(
        region.clone(),
        platform,
        Arc::new(PublicDirectory),
        slot.clone(),
        scan_id,
        public_url,
        opened,
    ));
    let checks = checks::all();
    let mut results = join_all(checks.iter().map(|check| check.detect(&ctx))).await;
    results.sort_by(|a, b| category_rank(&a.category).cmp(&category_rank(&b.category)).then(a.id.cmp(&b.id)));
    let verdict = report::verdict(&results);
    let report = ScanReport {
        generated_at: chrono::Utc::now().to_rfc3339(),
        os: std::env::consts::OS.to_string(),
        region_id: region.id.clone(),
        region_name: region.name.clone(),
        verdict,
        checks: results,
        browser_url: ctx.browser_url.clone(),
        browser_opened: ctx.browser_opened,
        phase: 2,
    };
    let initial = ctx.browser_version();
    let mut current = report.clone();
    tauri::async_runtime::spawn(async move {
        let mut previous = initial;
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            if Arc::strong_count(&slot) <= 2 { break; }
            let payload = slot.lock().ok().and_then(|s| s.clone());
            let next = payload.as_ref().and_then(|p| serde_json::to_string(p).ok());
            if next.is_none() || next == previous { continue; }
            if let Some(payload) = payload { ctx.refresh_browser(payload); }
            previous = next;
            refresh_browser_checks(&ctx, &mut current).await;
            updated(current.clone());
        }
    });
    Ok(PreparedScan { report })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "talks to the network and opens a browser"]
    async fn live_scan_prints_a_report() {
        let hub = std::sync::Mutex::new(None);
        let prepared = execute_with("us", |h| *hub.lock().unwrap()=Some(h), |_| {}).await.expect("scan");
        eprintln!("verdict {:?}", prepared.report.verdict);
        for check in &prepared.report.checks {
            eprintln!("{:?} {} {}", check.status, check.id, check.summary_en);
        }
        assert_eq!(prepared.report.checks.len(), 17);
    }
}

fn category_rank(category: &str) -> u8 {
    match category {
        "exit" => 0,
        "routing" => 1,
        "proxy" => 2,
        "dns" => 3,
        "system" => 4,
        "browser" => 5,
        "destination" => 6,
        _ => 9,
    }
}

pub fn browser_dependent(id: &str) -> bool { matches!(id, "timezone" | "locale" | "webrtc" | "fingerprint" | "location") }

async fn refresh_browser_checks(ctx:&ScanContext, current:&mut ScanReport) {
    for check in checks::all().into_iter().filter(|c|browser_dependent(c.meta().id)) {
        let result=check.detect(ctx).await;
        if let Some(old)=current.checks.iter_mut().find(|c|c.id==result.id){*old=result;}
    }
    current.verdict=report::verdict(&current.checks);
    current.generated_at=chrono::Utc::now().to_rfc3339();
}

#[cfg(test)] mod refresh_tests {
    use super::*;
    use crate::{browser::BrowserPayload, intel::NullDirectory, model::Status};
    #[tokio::test] async fn late_browser_payload_refreshes_only_dependent_checks_and_verdict(){
        let mut platform=crate::checks::test_snapshot();
        platform.timezone="America/New_York".into();platform.locale="en-US".into();
        let ctx=ScanContext::new(region::find("us").unwrap().clone(),platform,Arc::new(NullDirectory),Arc::new(std::sync::Mutex::new(None)),"late".into(),"http://127.0.0.1/".into(),false);
        // Reproduce the browser timeout without sleeping or opening sockets.
        ctx.cache_missing_browser_for_test();
        let mut results=Vec::new();
        for check in checks::all().into_iter().filter(|c|browser_dependent(c.meta().id)||c.meta().id=="exit_ipv4") {results.push(check.detect(&ctx).await);}
        let exit=serde_json::to_value(results.iter().find(|c|c.id=="exit_ipv4").unwrap()).unwrap();
        let mut report=ScanReport {generated_at:String::new(),os:"linux".into(),region_id:"us".into(),region_name:Default::default(),verdict:report::verdict(&results),checks:results,browser_url:String::new(),browser_opened:false,phase:1};
        ctx.refresh_browser(BrowserPayload{scan_id:"wrong".into(),timezone:"Asia/Shanghai".into(),..Default::default()});
        assert!(matches!(ctx.browser().await,crate::context::BrowserState::Missing));
        ctx.refresh_browser(BrowserPayload{scan_id:"late".into(),timezone:"Asia/Shanghai".into(),languages:vec!["zh-CN".into()],geolocation:"granted".into(),..Default::default()});
        refresh_browser_checks(&ctx,&mut report).await;
        assert_eq!(report.checks.iter().find(|c|c.id=="timezone").unwrap().status,Status::Fail);
        assert_eq!(serde_json::to_value(report.checks.iter().find(|c|c.id=="exit_ipv4").unwrap()).unwrap(),exit);
        assert_eq!(report.verdict,report::verdict(&report.checks));
        assert!(!report.generated_at.is_empty());
        ctx.refresh_browser(BrowserPayload{scan_id:"late".into(),timezone:"America/New_York".into(),languages:vec!["en-US".into()],..Default::default()});
        refresh_browser_checks(&ctx,&mut report).await;
        assert_eq!(report.checks.iter().find(|c|c.id=="timezone").unwrap().observed.get("browser").map(String::as_str),Some("America/New_York"));
    }
}
