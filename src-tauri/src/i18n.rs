use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

fn load(raw: &str) -> HashMap<String, String> {
    serde_json::from_str(raw).expect("locale json")
}

fn catalogs() -> &'static HashMap<&'static str, HashMap<String, String>> {
    static CATALOGS: OnceLock<HashMap<&'static str, HashMap<String, String>>> = OnceLock::new();
    CATALOGS.get_or_init(|| {
        let mut map = HashMap::new();
        map.insert("en", load(include_str!("../../locales/en.json")));
        map.insert("zh-CN", load(include_str!("../../locales/zh-CN.json")));
        map.insert("ja", load(include_str!("../../locales/ja.json")));
        map.insert("ko", load(include_str!("../../locales/ko.json")));
        map
    })
}

pub fn tr(lang: &str, key: &str, params: &BTreeMap<String, String>) -> String {
    let catalogs = catalogs();
    let template = catalogs
        .get(lang)
        .and_then(|catalog| catalog.get(key))
        .or_else(|| catalogs.get("en").and_then(|catalog| catalog.get(key)))
        .cloned()
        .unwrap_or_else(|| key.to_string());
    let mut rendered = template;
    for (name, value) in params {
        rendered = rendered.replace(&format!("{{{name}}}"), value);
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_catalogs_share_keys_and_cover_check_copy() {
        let catalogs = catalogs();
        let en = catalogs.get("en").unwrap();
        for lang in ["zh-CN", "ja", "ko"] {
            let other = catalogs.get(lang).unwrap();
            for key in en.keys() {
                assert!(other.contains_key(key), "{lang} missing {key}");
            }
            assert_eq!(en.len(), other.len(), "{lang}");
        }
        for key in [
            "exit.missing",
            "exit.mainland",
            "exit.okDatacenter",
            "v6.none",
            "route.physicalExposed",
            "quic.proxyBypass",
            "proxy.bypassClaude",
            "dns.fail",
            "leak.inconclusive",
            "ecs.fail",
            "tz.shanghai",
            "locale.systemMismatch",
            "webrtc.fail",
            "fp.webdriver",
            "loc.warnOs",
            "clock.fail",
            "hosts.fail",
            "tls.suspicious",
            "reach.ok",
            "notice.purpose.body",
            "notice.risk.body",
            "check.exit_ipv4.title",
        ] {
            let rendered = tr("en", key, &BTreeMap::new());
            assert_ne!(rendered, key, "{key}");
            assert_ne!(tr("zh-CN", key, &BTreeMap::new()), key);
        }
    }
}
