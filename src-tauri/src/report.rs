use crate::i18n;
use crate::model::{CheckResult, ScanReport, Status, Verdict};

const CRITICAL: &[&str] = &["exit_ipv4", "dns_leak"];

pub fn verdict(checks: &[CheckResult]) -> Verdict {
    if checks.iter().any(|check| check.status == Status::Fail) {
        return Verdict::Exposed;
    }
    if checks.iter().any(|check| {
        CRITICAL.contains(&check.id.as_str()) && check.status == Status::Inconclusive
    }) {
        return Verdict::Inconclusive;
    }
    if checks
        .iter()
        .any(|check| matches!(check.status, Status::Warn | Status::Inconclusive))
    {
        return Verdict::Review;
    }
    Verdict::Consistent
}

pub fn markdown(report: &ScanReport, lang: &str) -> String {
    let region = report
        .region_name
        .get(lang)
        .or_else(|| report.region_name.get("en"))
        .cloned()
        .unwrap_or_else(|| report.region_id.clone());
    let verdict = i18n::tr(lang, &format!("verdict.{}", verdict_key(report.verdict)), &Default::default());
    let mut out = String::new();
    out.push_str(&format!("# {}\n\n", i18n::tr(lang, "report.title", &Default::default())));
    out.push_str(&format!("- {}: {}\n", i18n::tr(lang, "report.generated", &Default::default()), report.generated_at));
    out.push_str(&format!("- {}: {}\n", i18n::tr(lang, "report.os", &Default::default()), report.os));
    out.push_str(&format!(
        "- {}: {} ({})\n",
        i18n::tr(lang, "report.region", &Default::default()),
        region,
        report.region_id
    ));
    out.push_str(&format!("- {}: {}\n", i18n::tr(lang, "report.verdict", &Default::default()), verdict));
    out.push_str(&format!("- {}: {}\n\n", i18n::tr(lang, "report.phase", &Default::default()), report.phase));
    out.push_str(&format!("> {}\n\n", i18n::tr(lang, "notice.purpose.body", &Default::default())));
    out.push_str(&format!("> {}\n\n", i18n::tr(lang, "notice.risk.body", &Default::default())));

    let mut category = String::new();
    for check in &report.checks {
        if check.category != category {
            category = check.category.clone();
            let title = i18n::tr(lang, &format!("group.{}", check.category), &Default::default());
            out.push_str(&format!("## {title}\n\n"));
        }
        let name = i18n::tr(lang, &format!("check.{}.title", check.id), &Default::default());
        let status = i18n::tr(lang, &format!("status.{}", status_key(check.status)), &Default::default());
        let summary = i18n::tr(lang, &check.summary_key, &check.summary_params);
        let advice = i18n::tr(lang, &check.advice_key, &check.advice_params);
        out.push_str(&format!("### {name} — {status}\n\n"));
        out.push_str(&format!("{summary}\n\n"));
        if !check.observed.is_empty() {
            out.push_str(&format!("**{}**\n\n", i18n::tr(lang, "field.observed", &Default::default())));
            for (key, value) in &check.observed {
                out.push_str(&format!("- {key}: {value}\n"));
            }
            out.push('\n');
        }
        if !check.expected.is_empty() {
            out.push_str(&format!("**{}**\n\n", i18n::tr(lang, "field.expected", &Default::default())));
            for (key, value) in &check.expected {
                out.push_str(&format!("- {key}: {value}\n"));
            }
            out.push('\n');
        }
        out.push_str(&format!("**{}**\n\n{advice}\n\n", i18n::tr(lang, "field.advice", &Default::default())));
    }
    out
}

fn verdict_key(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Consistent => "consistent",
        Verdict::Review => "review",
        Verdict::Exposed => "exposed",
        Verdict::Inconclusive => "inconclusive",
    }
}

fn status_key(status: Status) -> &'static str {
    match status {
        Status::Pass => "pass",
        Status::Warn => "warn",
        Status::Fail => "fail",
        Status::Info => "info",
        Status::Inconclusive => "inconclusive",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{params, CheckResult};
    use std::collections::BTreeMap;

    fn sample(status: Status, id: &str) -> CheckResult {
        CheckResult {
            id: id.into(),
            category: "exit".into(),
            status,
            observed: BTreeMap::new(),
            expected: BTreeMap::new(),
            summary_key: "exit.missing".into(),
            summary_params: params(&[]),
            advice_key: "advice.exit.missing".into(),
            advice_params: params(&[]),
            summary_en: "missing".into(),
            advice_en: "retry".into(),
        }
    }

    #[test]
    fn verdict_ranks_fail_above_warning_and_keeps_critical_gaps() {
        assert_eq!(verdict(&[sample(Status::Pass, "exit_ipv4"), sample(Status::Info, "dns_ecs")]), Verdict::Consistent);
        assert_eq!(verdict(&[sample(Status::Warn, "route_ipv4")]), Verdict::Review);
        assert_eq!(verdict(&[sample(Status::Fail, "timezone")]), Verdict::Exposed);
        assert_eq!(
            verdict(&[sample(Status::Inconclusive, "exit_ipv4"), sample(Status::Pass, "dns_leak")]),
            Verdict::Inconclusive
        );
        assert_eq!(verdict(&[sample(Status::Inconclusive, "clock")]), Verdict::Review);
    }
}
