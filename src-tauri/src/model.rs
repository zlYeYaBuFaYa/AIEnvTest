use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Warn,
    Fail,
    Info,
    Inconclusive,
}

impl Status {
    pub fn rank(self) -> u8 {
        match self {
            Status::Pass => 0,
            Status::Info => 1,
            Status::Inconclusive => 2,
            Status::Warn => 3,
            Status::Fail => 4,
        }
    }

    pub fn worst(self, other: Status) -> Status {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Consistent,
    Review,
    Exposed,
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub id: String,
    pub category: String,
    pub status: Status,
    pub observed: BTreeMap<String, String>,
    pub expected: BTreeMap<String, String>,
    pub summary_key: String,
    pub summary_params: BTreeMap<String, String>,
    pub advice_key: String,
    pub advice_params: BTreeMap<String, String>,
    pub summary_en: String,
    pub advice_en: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport {
    pub generated_at: String,
    pub os: String,
    pub region_id: String,
    pub region_name: BTreeMap<String, String>,
    pub verdict: Verdict,
    pub checks: Vec<CheckResult>,
    pub browser_url: String,
    pub browser_opened: bool,
    pub phase: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegionSummary {
    pub id: String,
    pub country: String,
    pub group: String,
    pub name: BTreeMap<String, String>,
    pub timezones: Vec<String>,
    pub languages: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CheckMeta {
    pub id: &'static str,
    pub category: &'static str,
}

#[derive(Debug, Clone)]
pub struct Judgement {
    pub status: Status,
    pub observed: BTreeMap<String, String>,
    pub expected: BTreeMap<String, String>,
    pub summary_key: String,
    pub summary_params: BTreeMap<String, String>,
    pub advice_key: String,
    pub advice_params: BTreeMap<String, String>,
}

pub fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

impl Judgement {
    pub fn new(
        status: Status,
        summary_key: &str,
        summary_params: BTreeMap<String, String>,
        advice_key: &str,
        advice_params: BTreeMap<String, String>,
    ) -> Self {
        Self {
            status,
            observed: BTreeMap::new(),
            expected: BTreeMap::new(),
            summary_key: summary_key.to_string(),
            summary_params,
            advice_key: advice_key.to_string(),
            advice_params,
        }
    }

    pub fn observe(mut self, key: &str, value: impl AsRef<str>) -> Self {
        let value = value.as_ref().trim();
        if !value.is_empty() {
            self.observed.insert(key.to_string(), value.to_string());
        }
        self
    }

    pub fn expect(mut self, key: &str, value: impl AsRef<str>) -> Self {
        let value = value.as_ref().trim();
        if !value.is_empty() {
            self.expected.insert(key.to_string(), value.to_string());
        }
        self
    }
}
