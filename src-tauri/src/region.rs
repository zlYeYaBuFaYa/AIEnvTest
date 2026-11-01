use std::collections::BTreeMap;

use serde::Deserialize;

use crate::model::RegionSummary;

#[derive(Debug, Clone, Deserialize)]
struct Catalog {
    regions: Vec<RegionPreset>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegionPreset {
    pub id: String,
    pub country: String,
    pub group: String,
    pub name: BTreeMap<String, String>,
    pub timezones: Vec<String>,
    pub languages: Vec<String>,
    pub cities: Vec<String>,
    pub recommended_dns: Vec<String>,
}

impl RegionPreset {
    pub fn display(&self, lang: &str) -> String {
        self.name
            .get(lang)
            .or_else(|| self.name.get("en"))
            .cloned()
            .unwrap_or_else(|| self.id.clone())
    }
}

pub fn catalog() -> &'static [RegionPreset] {
    use std::sync::OnceLock;
    static CATALOG: OnceLock<Vec<RegionPreset>> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let raw = include_str!("../../regions/presets.json");
        let parsed: Catalog = serde_json::from_str(raw).expect("regions/presets.json");
        parsed.regions
    })
}

pub fn find(id: &str) -> Option<&'static RegionPreset> {
    catalog().iter().find(|region| region.id == id)
}

pub fn summaries() -> Vec<RegionSummary> {
    let mut items: Vec<RegionSummary> = catalog()
        .iter()
        .map(|region| RegionSummary {
            id: region.id.clone(),
            country: region.country.clone(),
            group: region.group.clone(),
            name: region.name.clone(),
            timezones: region.timezones.clone(),
            languages: region.languages.clone(),
        })
        .collect();
    items.sort_by(|a, b| {
        a.group
            .cmp(&b.group)
            .then_with(|| a.name.get("en").cmp(&b.name.get("en")))
    });
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_cover_the_agreed_homes_and_skip_china() {
        let regions = catalog();
        let ids: Vec<&str> = regions.iter().map(|r| r.id.as_str()).collect();
        for required in ["us", "jp", "sg", "kr", "tw", "gb", "de", "fr", "au", "ca", "ie", "nl"] {
            assert!(ids.contains(&required), "missing {required}");
        }
        for region in regions {
            let country = region.country.to_uppercase();
            assert_ne!(country, "CN", "{}", region.id);
            assert_ne!(country, "HK", "{}", region.id);
            assert_ne!(country, "MO", "{}", region.id);
            assert!(region.name.contains_key("en"), "{}", region.id);
            assert!(region.name.contains_key("zh-CN"), "{}", region.id);
            assert!(region.name.contains_key("ja"), "{}", region.id);
            assert!(region.name.contains_key("ko"), "{}", region.id);
            assert!(!region.timezones.is_empty(), "{}", region.id);
            assert!(!region.languages.is_empty(), "{}", region.id);
            assert!(!region.recommended_dns.is_empty(), "{}", region.id);
            let blob = format!(
                "{} {} {}",
                region.id,
                region.country,
                region.name.values().cloned().collect::<Vec<_>>().join(" ")
            )
            .to_lowercase();
            assert!(!blob.contains("hong kong"), "{blob}");
            assert!(!blob.contains("hongkong"), "{blob}");
            assert!(!blob.contains("中国"), "{blob}");
            assert!(!blob.contains("mainland"), "{blob}");
        }
        let us = find("us").unwrap();
        assert!(us.timezones.len() >= 4, "the US preset needs several timezones");
        assert!(us.timezones.iter().any(|tz| tz == "America/Los_Angeles"));
        assert!(us.timezones.iter().any(|tz| tz == "America/New_York"));
    }
}
