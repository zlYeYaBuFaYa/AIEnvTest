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
    pub hub: Hub,
}

pub async fn execute(region_id: &str) -> Result<PreparedScan, String> {
    let region = region::find(region_id).cloned().ok_or_else(|| format!("unknown region {region_id}"))?;
    let platform = tokio::task::spawn_blocking(platform::collect).await.map_err(|err| err.to_string())?;
    let scan_id = format!("scan-{}", SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0));
    let hub = browser::Hub::start(scan_id.clone())?;
    let opened = browser::open_url(&hub.url);
    let ctx = ScanContext::new(
        region.clone(),
        platform,
        Arc::new(PublicDirectory),
        hub.slot.clone(),
        scan_id,
        hub.url.clone(),
        opened,
    );
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
        phase: 1,
    };
    Ok(PreparedScan { report, hub })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "talks to the network and opens a browser"]
    async fn live_scan_prints_a_report() {
        let prepared = execute("us").await.expect("scan");
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
