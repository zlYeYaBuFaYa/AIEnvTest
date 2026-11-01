use crate::model::{params, Judgement, Status};
use crate::platform::parse::{
    self, any_language_match, canon_tz, corporate_intercept_ca, datacenter_hint, is_mainland_china,
    is_private_ip, known_public_ca, suspicious_intercept_ca, tz_allowed, IfaceClass,
};
use crate::region::RegionPreset;

fn place(city: &str, region: &str, country: &str) -> String {
    let mut parts = Vec::new();
    if !city.is_empty() {
        parts.push(city.to_string());
    }
    if !region.is_empty() {
        parts.push(region.to_string());
    }
    if !country.is_empty() {
        parts.push(country.to_string());
    }
    if parts.is_empty() {
        "unknown".into()
    } else {
        parts.join(", ")
    }
}

pub fn judge_exit(ip: Option<&str>, geo_country: Option<&str>, city: &str, region_name: &str, org: &str, hosting: Option<bool>, preset: &RegionPreset) -> Judgement {
    let expected = preset.country.clone();
    let expected_name = preset.display("en");
    let base = |status, key: &str, extra: &[(&str, &str)], advice: &str| {
        let mut pairs = vec![("expected", expected_name.as_str())];
        pairs.extend_from_slice(extra);
        Judgement::new(status, key, params(&pairs), advice, params(&[("expected", expected_name.as_str())]))
            .expect("country", &expected)
    };
    let Some(ip) = ip.filter(|ip| !ip.is_empty()) else {
        return base(Status::Fail, "exit.missing", &[], "advice.exit.missing");
    };
    let Some(country) = geo_country.map(parse::norm_country).filter(|c| !c.is_empty()) else {
        return base(Status::Warn, "exit.unlocated", &[("ip", ip)], "advice.exit.missing").observe("ip", ip);
    };
    let where_ = place(city, region_name, &country);
    let mut judgement = base(
        Status::Pass,
        "exit.ok",
        &[("ip", ip), ("country", country.as_str()), ("place", where_.as_str()), ("org", org)],
        "advice.exit.ok",
    )
    .observe("ip", ip)
    .observe("country", &country)
    .observe("city", city)
    .observe("region", region_name)
    .observe("org", org);
    if is_mainland_china(&country) {
        judgement.status = Status::Fail;
        judgement.summary_key = "exit.mainland".into();
        judgement.summary_params = params(&[("ip", ip), ("place", &where_), ("expected", &expected_name)]);
        judgement.advice_key = "advice.exit.tunnel".into();
        return judgement;
    }
    if country != expected {
        judgement.status = Status::Fail;
        judgement.summary_key = "exit.countryMismatch".into();
        judgement.summary_params = params(&[
            ("ip", ip),
            ("country", &country),
            ("place", &where_),
            ("expected", &expected_name),
        ]);
        judgement.advice_key = "advice.exit.tunnel".into();
        return judgement;
    }
    let dc = datacenter_hint(org, hosting);
    if dc {
        judgement.status = Status::Warn;
        judgement.summary_key = "exit.okDatacenter".into();
        judgement.summary_params = params(&[
            ("ip", ip),
            ("place", &where_),
            ("org", org),
            ("expected", &expected_name),
        ]);
        judgement.advice_key = "advice.exit.datacenter".into();
    }
    if !preset.cities.is_empty() && !city.is_empty() {
        let city_l = city.to_lowercase();
        let matched = preset.cities.iter().any(|want| {
            let want = want.to_lowercase();
            city_l.contains(&want) || want.contains(&city_l)
        });
        if !matched {
            let expected_cities = preset.cities.join(", ");
            if judgement.status != Status::Warn {
                judgement.status = Status::Warn;
                judgement.summary_key = "exit.cityMismatch".into();
                judgement.advice_key = "advice.exit.city".into();
            }
            judgement.summary_params.insert("city".into(), city.to_string());
            judgement.summary_params.insert("expectedCities".into(), expected_cities.clone());
            judgement.expected.insert("city".into(), expected_cities);
        }
    }
    if let Some(hosting) = hosting {
        judgement.observed.insert("hosting".into(), hosting.to_string());
    }
    judgement
}

pub fn judge_ipv6(iface: Option<&str>, exit_country: Option<&str>, place_text: &str, preset: &RegionPreset) -> Judgement {
    let expected = preset.display("en");
    let Some(iface) = iface.filter(|iface| !iface.is_empty()) else {
        return Judgement::new(Status::Pass, "v6.none", params(&[]), "advice.v6.keepOff", params(&[]))
            .expect("country", &preset.country);
    };
    let class = parse::classify_iface(iface);
    let country = exit_country.map(parse::norm_country).unwrap_or_default();
    let mut judgement = Judgement::new(
        Status::Warn,
        "v6.unmeasured",
        params(&[("iface", iface), ("expected", expected.as_str())]),
        "advice.v6.tunnel",
        params(&[("expected", expected.as_str())]),
    )
    .observe("iface", iface)
    .observe("country", &country)
    .observe("place", place_text)
    .expect("country", &preset.country);
    if country.is_empty() {
        judgement.summary_key = "v6.unmeasured".into();
        return judgement;
    }
    let matches = country == preset.country;
    let mainland = is_mainland_china(&country);
    match class {
        IfaceClass::Tunnel if matches => {
            judgement.status = Status::Pass;
            judgement.summary_key = "v6.tunnelOk".into();
            judgement.advice_key = "advice.v6.ok".into();
        }
        IfaceClass::Tunnel => {
            judgement.status = Status::Fail;
            judgement.summary_key = "v6.tunnelMismatch".into();
        }
        IfaceClass::Physical if mainland || !matches => {
            judgement.status = Status::Fail;
            judgement.summary_key = "v6.physicalLeak".into();
            judgement.summary_params.insert("place".into(), place_text.to_string());
        }
        IfaceClass::Physical => {
            judgement.status = Status::Warn;
            judgement.summary_key = "v6.physicalOk".into();
        }
        IfaceClass::Other => {
            judgement.status = Status::Warn;
            judgement.summary_key = "v6.unknown".into();
        }
    }
    judgement
}

pub fn judge_route(iface_a: Option<&str>, iface_b: Option<&str>, exit_country: Option<&str>, preset: &RegionPreset) -> Judgement {
    let expected = preset.display("en");
    let primary = iface_a.filter(|s| !s.is_empty()).or(iface_b.filter(|s| !s.is_empty()));
    let Some(iface) = primary else {
        return Judgement::new(Status::Warn, "route.missing", params(&[]), "advice.route.missing", params(&[]))
            .expect("country", &preset.country);
    };
    let alt = iface_b.filter(|s| !s.is_empty() && Some(*s) != Some(iface));
    if let Some(alt) = alt {
        let physical = matches!(parse::classify_iface(iface), IfaceClass::Physical)
            || matches!(parse::classify_iface(alt), IfaceClass::Physical);
        let status = if physical { Status::Fail } else { Status::Warn };
        return Judgement::new(
            status,
            "route.split",
            params(&[("ifaceA", iface), ("ifaceB", alt), ("expected", expected.as_str())]),
            "advice.route.tunnel",
            params(&[("expected", expected.as_str())]),
        )
        .observe("iface", iface)
        .observe("ifaceAlt", alt);
    }
    let class = parse::classify_iface(iface);
    let country = exit_country.map(parse::norm_country).unwrap_or_default();
    let matches = country == preset.country && !country.is_empty();
    let mut judgement = Judgement::new(
        Status::Warn,
        "route.unknown",
        params(&[("iface", iface), ("expected", expected.as_str())]),
        "advice.route.tunnel",
        params(&[("expected", expected.as_str())]),
    )
    .observe("iface", iface)
    .expect("path", "tunnel");
    match class {
        IfaceClass::Tunnel => {
            judgement.status = Status::Pass;
            judgement.summary_key = "route.tunnel".into();
            judgement.advice_key = "advice.route.ok".into();
        }
        IfaceClass::Physical if !matches => {
            judgement.status = Status::Fail;
            judgement.summary_key = "route.physicalExposed".into();
        }
        IfaceClass::Physical => {
            judgement.status = Status::Warn;
            judgement.summary_key = "route.physicalOk".into();
        }
        IfaceClass::Other => {}
    }
    judgement
}

pub fn judge_quic(iface: Option<&str>, proxy_enabled: bool) -> Judgement {
    let Some(iface) = iface.filter(|s| !s.is_empty()) else {
        return Judgement::new(Status::Inconclusive, "quic.missing", params(&[]), "advice.quic.missing", params(&[]));
    };
    match parse::classify_iface(iface) {
        IfaceClass::Tunnel => Judgement::new(
            Status::Pass,
            "quic.tunnel",
            params(&[("iface", iface)]),
            "advice.quic.ok",
            params(&[]),
        )
        .observe("iface", iface),
        IfaceClass::Physical if proxy_enabled => Judgement::new(
            Status::Fail,
            "quic.proxyBypass",
            params(&[("iface", iface)]),
            "advice.quic.block",
            params(&[]),
        )
        .observe("iface", iface),
        IfaceClass::Physical => Judgement::new(
            Status::Warn,
            "quic.direct",
            params(&[("iface", iface)]),
            "advice.quic.block",
            params(&[]),
        )
        .observe("iface", iface),
        IfaceClass::Other => Judgement::new(
            Status::Inconclusive,
            "quic.unknown",
            params(&[("iface", iface)]),
            "advice.quic.missing",
            params(&[]),
        )
        .observe("iface", iface),
    }
}

pub struct ProxyView<'a> {
    pub enabled: bool,
    pub pac: bool,
    pub pac_url: &'a str,
    pub pac_body: Option<&'a str>,
    pub bypass: &'a [String],
    pub route_is_tunnel: bool,
}

pub fn judge_proxy(view: ProxyView<'_>) -> Judgement {
    if let Some(hit) = parse::bypass_hits_claude(view.bypass) {
        let key = if hit == "*" { "proxy.bypassAll" } else { "proxy.bypassClaude" };
        return Judgement::new(Status::Fail, key, params(&[("entry", hit.as_str())]), "advice.proxy.removeBypass", params(&[]))
            .observe("bypass", &view.bypass.join(", "))
            .observe("entry", &hit);
    }
    if view.pac {
        if let Some(body) = view.pac_body {
            if parse::pac_mentions_claude(body) {
                return Judgement::new(
                    Status::Fail,
                    "proxy.pacHit",
                    params(&[("entry", "claude.ai / anthropic.com")]),
                    "advice.proxy.removeBypass",
                    params(&[]),
                )
                .observe("pac", view.pac_url);
            }
            return Judgement::new(Status::Warn, "proxy.pacClean", params(&[("url", view.pac_url)]), "advice.proxy.readPac", params(&[]))
                .observe("pac", view.pac_url);
        }
        return Judgement::new(Status::Warn, "proxy.pacUnread", params(&[("url", view.pac_url)]), "advice.proxy.readPac", params(&[]))
            .observe("pac", if view.pac_url.is_empty() { "enabled" } else { view.pac_url });
    }
    if view.enabled {
        return Judgement::new(Status::Pass, "proxy.enabledClean", params(&[]), "advice.proxy.ok", params(&[]))
            .observe("bypass", &view.bypass.join(", "));
    }
    if view.route_is_tunnel {
        return Judgement::new(Status::Pass, "proxy.disabledTunnel", params(&[]), "advice.proxy.ok", params(&[]));
    }
    Judgement::new(Status::Warn, "proxy.disabledOpen", params(&[]), "advice.proxy.enableOrTunnel", params(&[]))
}

pub struct DnsServerView {
    pub ip: String,
    pub country: String,
    pub provider: Option<String>,
}

pub fn judge_configured_dns(servers: &[DnsServerView], recommended: &[String]) -> Judgement {
    let recommended_text = recommended.join(", ");
    if servers.is_empty() {
        return Judgement::new(Status::Warn, "dns.none", params(&[]), "advice.dns.missing", params(&[]))
            .expect("dns", &recommended_text);
    }
    let mut bad = Vec::new();
    let mut local = Vec::new();
    let mut good = Vec::new();
    let mut unknown = Vec::new();
    for server in servers {
        if let Some(provider) = &server.provider {
            bad.push(format!("{} ({provider})", server.ip));
        } else if is_private_ip(&server.ip) {
            local.push(server.ip.clone());
        } else if is_mainland_china(&server.country) {
            bad.push(format!("{} ({})", server.ip, server.country));
        } else if server.country.is_empty() {
            unknown.push(server.ip.clone());
        } else {
            good.push(format!("{} ({})", server.ip, server.country));
        }
    }
    let detail_all = servers
        .iter()
        .map(|server| server.ip.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let mut judgement = Judgement::new(
        Status::Pass,
        "dns.ok",
        params(&[("detail", &good.join(", "))]),
        "advice.dns.ok",
        params(&[]),
    )
    .observe("servers", &detail_all)
    .expect("dns", &recommended_text);
    if !bad.is_empty() {
        let detail = bad.join(", ");
        judgement.status = Status::Fail;
        judgement.summary_key = "dns.fail".into();
        judgement.summary_params = params(&[("count", &bad.len().to_string()), ("detail", &detail), ("recommended", &recommended_text)]);
        judgement.advice_key = "advice.dns.replace".into();
        judgement.advice_params = params(&[("recommended", &recommended_text)]);
        return judgement;
    }
    if good.is_empty() && !local.is_empty() {
        let detail = local.join(", ");
        judgement.status = Status::Info;
        judgement.summary_key = "dns.local".into();
        judgement.summary_params = params(&[("detail", &detail)]);
        judgement.advice_key = "advice.dns.seeLeak".into();
        return judgement;
    }
    if good.is_empty() {
        let detail = unknown.join(", ");
        judgement.status = Status::Warn;
        judgement.summary_key = "dns.unknown".into();
        judgement.summary_params = params(&[("detail", &detail)]);
        judgement.advice_key = "advice.dns.seeLeak".into();
    }
    judgement
}

pub struct LeakHit {
    pub ip: String,
    pub country: String,
    pub city: String,
    pub asn: String,
    pub provider: Option<String>,
}

pub fn judge_leak(hits: &[LeakHit], inconclusive: bool, preset: &RegionPreset) -> Judgement {
    let expected = preset.display("en");
    if hits.is_empty() || inconclusive {
        return Judgement::new(
            Status::Inconclusive,
            "leak.inconclusive",
            params(&[]),
            "advice.leak.retry",
            params(&[]),
        )
        .expect("country", &preset.country);
    }
    let detail = hits
        .iter()
        .map(|hit| {
            let country = if hit.country.is_empty() { "?" } else { hit.country.as_str() };
            format!("{} {country} {}", hit.ip, hit.asn)
        })
        .collect::<Vec<_>>()
        .join("; ");
    let mut judgement = Judgement::new(
        Status::Pass,
        "leak.ok",
        params(&[("detail", &detail), ("expected", expected.as_str())]),
        "advice.leak.ok",
        params(&[]),
    )
    .observe("resolvers", &detail)
    .expect("country", &preset.country);
    let bad = hits.iter().any(|hit| hit.provider.is_some() || is_mainland_china(&hit.country));
    if bad {
        judgement.status = Status::Fail;
        judgement.summary_key = "leak.fail".into();
        judgement.advice_key = "advice.leak.fix".into();
        judgement.advice_params = params(&[("expected", expected.as_str())]);
        return judgement;
    }
    let third = hits.iter().any(|hit| {
        let country = parse::norm_country(&hit.country);
        !country.is_empty() && country != preset.country
    });
    if third {
        judgement.status = Status::Warn;
        judgement.summary_key = "leak.mismatch".into();
        judgement.advice_key = "advice.leak.fix".into();
        judgement.advice_params = params(&[("expected", expected.as_str())]);
    }
    judgement
}

pub fn judge_ecs(subnet: Option<&str>, country: Option<&str>, preset: &RegionPreset) -> Judgement {
    let expected = preset.display("en");
    let Some(subnet) = subnet.filter(|s| !s.is_empty()) else {
        return Judgement::new(Status::Info, "ecs.absent", params(&[]), "advice.ecs.ok", params(&[]))
            .expect("country", &preset.country);
    };
    let Some(country) = country.map(parse::norm_country).filter(|c| !c.is_empty()) else {
        return Judgement::new(
            Status::Inconclusive,
            "ecs.unlocated",
            params(&[("subnet", subnet)]),
            "advice.ecs.retry",
            params(&[]),
        )
        .observe("subnet", subnet);
    };
    let mut judgement = Judgement::new(
        Status::Pass,
        "ecs.ok",
        params(&[("subnet", subnet), ("expected", expected.as_str()), ("country", country.as_str())]),
        "advice.ecs.ok",
        params(&[]),
    )
    .observe("subnet", subnet)
    .observe("country", &country)
    .expect("country", &preset.country);
    if is_mainland_china(&country) {
        judgement.status = Status::Fail;
        judgement.summary_key = "ecs.fail".into();
        judgement.advice_key = "advice.ecs.fix".into();
    } else if country != preset.country {
        judgement.status = Status::Warn;
        judgement.summary_key = "ecs.mismatch".into();
        judgement.advice_key = "advice.ecs.fix".into();
    }
    judgement
}

pub fn judge_timezone(system: &str, browser: Option<&str>, ip_tz: Option<&str>, preset: &RegionPreset) -> Judgement {
    let expected = preset.display("en");
    let allowed = preset.timezones.join(", ");
    let system_canon = canon_tz(system);
    let mut judgement = Judgement::new(
        Status::Pass,
        "tz.ok",
        params(&[("system", &system_canon), ("expected", expected.as_str()), ("allowed", &allowed)]),
        "advice.tz.ok",
        params(&[]),
    )
    .observe("system", if system.is_empty() { "unknown" } else { system })
    .expect("timezone", &allowed);
    if let Some(browser) = browser {
        judgement.observed.insert("browser".into(), browser.to_string());
    }
    if let Some(ip_tz) = ip_tz {
        judgement.observed.insert("ipTimezone".into(), ip_tz.to_string());
    }
    if system.trim().is_empty() {
        judgement.status = Status::Warn;
        judgement.summary_key = "tz.unknown".into();
        judgement.advice_key = "advice.tz.set".into();
        judgement.advice_params = params(&[("expected", expected.as_str())]);
        return judgement;
    }
    if !tz_allowed(system, &preset.timezones) {
        judgement.status = Status::Fail;
        judgement.advice_key = "advice.tz.set".into();
        judgement.advice_params = params(&[("expected", expected.as_str())]);
        if canon_tz(system) == "Asia/Shanghai" {
            judgement.summary_key = "tz.shanghai".into();
            judgement.summary_params = params(&[("system", system), ("expected", expected.as_str()), ("allowed", &allowed)]);
        } else {
            judgement.summary_key = "tz.systemMismatch".into();
            judgement.summary_params = params(&[("system", system), ("expected", expected.as_str()), ("allowed", &allowed)]);
        }
        return judgement;
    }
    if let Some(browser) = browser.filter(|tz| !tz.is_empty()) {
        if !tz_allowed(browser, &preset.timezones) {
            judgement.status = Status::Fail;
            judgement.summary_key = "tz.browserMismatch".into();
            judgement.summary_params = params(&[("browser", browser), ("system", system), ("expected", expected.as_str()), ("allowed", &allowed)]);
            judgement.advice_key = "advice.tz.browser".into();
            return judgement;
        }
        if canon_tz(browser) != canon_tz(system) {
            judgement.status = Status::Warn;
            judgement.summary_key = "tz.browserDiffers".into();
            judgement.summary_params = params(&[("browser", browser), ("system", system), ("expected", expected.as_str())]);
            judgement.advice_key = "advice.tz.browser".into();
            return judgement;
        }
    }
    if let Some(ip_tz) = ip_tz.filter(|tz| !tz.is_empty()) {
        if !tz_allowed(ip_tz, &preset.timezones) {
            judgement.status = Status::Warn;
            judgement.summary_key = "tz.ipDiffers".into();
            judgement.summary_params = params(&[("ipTz", ip_tz), ("system", system), ("expected", expected.as_str()), ("allowed", &allowed)]);
            judgement.advice_key = "advice.tz.set".into();
            judgement.advice_params = params(&[("expected", expected.as_str())]);
        }
    }
    judgement
}

pub fn judge_locale(system: &str, browser_langs: &[String], accept: &str, browser_missing: bool, preset: &RegionPreset) -> Judgement {
    let expected = preset.languages.join(", ");
    let name = preset.display("en");
    let mut judgement = Judgement::new(
        Status::Pass,
        "locale.ok",
        params(&[("system", system), ("expected", &expected)]),
        "advice.locale.ok",
        params(&[]),
    )
    .observe("system", system)
    .observe("browser", &browser_langs.join(", "))
    .observe("acceptLanguage", accept)
    .expect("languages", &expected);
    if system.trim().is_empty() {
        judgement.status = Status::Warn;
        judgement.summary_key = "locale.unknown".into();
        judgement.advice_key = "advice.locale.set".into();
        judgement.advice_params = params(&[("expected", &expected)]);
        return judgement;
    }
    if !any_language_match(&[system.to_string()], &preset.languages) {
        judgement.status = Status::Fail;
        judgement.summary_key = "locale.systemMismatch".into();
        judgement.summary_params = params(&[("system", system), ("expected", &expected), ("region", name.as_str())]);
        judgement.advice_key = "advice.locale.set".into();
        judgement.advice_params = params(&[("expected", &expected)]);
        return judgement;
    }
    if browser_missing {
        judgement.status = Status::Warn;
        judgement.summary_key = "locale.browserMissing".into();
        judgement.summary_params = params(&[("expected", &expected), ("system", system)]);
        judgement.advice_key = "advice.locale.retryBrowser".into();
        return judgement;
    }
    if !browser_langs.is_empty() && !any_language_match(browser_langs, &preset.languages) {
        judgement.status = Status::Fail;
        judgement.summary_key = "locale.browserMismatch".into();
        judgement.summary_params = params(&[("browser", &browser_langs.join(", ")), ("expected", &expected)]);
        judgement.advice_key = "advice.locale.browser".into();
        judgement.advice_params = params(&[("expected", &expected)]);
        return judgement;
    }
    let accept_tags = parse::parse_accept_language(accept);
    if !accept_tags.is_empty() && !any_language_match(&accept_tags, &preset.languages) {
        judgement.status = Status::Fail;
        judgement.summary_key = "locale.acceptMismatch".into();
        judgement.summary_params = params(&[("accept", accept), ("expected", &expected)]);
        judgement.advice_key = "advice.locale.browser".into();
        judgement.advice_params = params(&[("expected", &expected)]);
    }
    judgement
}

pub struct WebRtcIp {
    pub ip: String,
    pub kind: String,
    pub country: String,
}

pub fn judge_webrtc(missing: bool, ips: &[WebRtcIp], preset: &RegionPreset) -> Judgement {
    let expected = preset.display("en");
    if missing {
        return Judgement::new(Status::Inconclusive, "webrtc.missing", params(&[]), "advice.webrtc.retry", params(&[]));
    }
    let public: Vec<&WebRtcIp> = ips.iter().filter(|ip| !is_private_ip(&ip.ip)).collect();
    let described = ips
        .iter()
        .map(|ip| format!("{} ({})", ip.ip, ip.kind))
        .collect::<Vec<_>>()
        .join(", ");
    if public.is_empty() {
        let key = if ips.is_empty() { "webrtc.none" } else { "webrtc.localOnly" };
        return Judgement::new(Status::Pass, key, params(&[("ips", if described.is_empty() { "none" } else { described.as_str() })]), "advice.webrtc.ok", params(&[]))
            .observe("candidates", if described.is_empty() { "none" } else { described.as_str() })
            .expect("country", &preset.country);
    }
    let bad = public.iter().find(|ip| {
        let country = parse::norm_country(&ip.country);
        is_mainland_china(&country) || (!country.is_empty() && country != preset.country)
    });
    if let Some(bad) = bad {
        return Judgement::new(
            Status::Fail,
            "webrtc.fail",
            params(&[("ip", bad.ip.as_str()), ("country", bad.country.as_str()), ("expected", expected.as_str())]),
            "advice.webrtc.disable",
            params(&[]),
        )
        .observe("candidates", &described)
        .expect("country", &preset.country);
    }
    let unknown = public.iter().any(|ip| parse::norm_country(&ip.country).is_empty());
    if unknown {
        return Judgement::new(Status::Warn, "webrtc.fail", params(&[("ip", public[0].ip.as_str()), ("country", "unknown"), ("expected", expected.as_str())]), "advice.webrtc.disable", params(&[]))
            .observe("candidates", &described);
    }
    Judgement::new(Status::Pass, "webrtc.ok", params(&[("expected", expected.as_str())]), "advice.webrtc.ok", params(&[]))
        .observe("candidates", &described)
        .expect("country", &preset.country)
}

pub fn judge_fingerprint(os: &str, ua: &str, platform: &str, webdriver: bool, browser_tz: &str, system_tz: &str, langs: &[String], system_locale: &str, missing: bool) -> Judgement {
    if missing {
        return Judgement::new(Status::Inconclusive, "fp.missing", params(&[]), "advice.fp.retry", params(&[]));
    }
    let mut judgement = Judgement::new(Status::Pass, "fp.ok", params(&[("os", os)]), "advice.fp.ok", params(&[]))
        .observe("userAgent", ua)
        .observe("platform", platform)
        .observe("webdriver", if webdriver { "true" } else { "false" });
    if webdriver {
        judgement.status = Status::Fail;
        judgement.summary_key = "fp.webdriver".into();
        judgement.advice_key = "advice.fp.webdriver".into();
        return judgement;
    }
    if !parse::platform_matches_os(os, platform, ua) {
        judgement.status = Status::Fail;
        judgement.summary_key = "fp.platform".into();
        judgement.summary_params = params(&[("platform", platform), ("uaOs", parse::os_token_from_ua(ua)), ("os", os)]);
        judgement.advice_key = "advice.fp.platform".into();
        return judgement;
    }
    if !browser_tz.is_empty() && !system_tz.is_empty() && canon_tz(browser_tz) != canon_tz(system_tz) {
        judgement.status = Status::Warn;
        judgement.summary_key = "fp.tz".into();
        judgement.summary_params = params(&[("browserTz", browser_tz), ("systemTz", system_tz)]);
        judgement.advice_key = "advice.fp.align".into();
        return judgement;
    }
    if !langs.is_empty() && !system_locale.is_empty() && !any_language_match(langs, &[system_locale.to_string()]) {
        judgement.status = Status::Warn;
        judgement.summary_key = "fp.lang".into();
        judgement.advice_key = "advice.fp.align".into();
    }
    judgement
}

pub fn judge_location(os_enabled: Option<bool>, browser_perm: Option<&str>) -> Judgement {
    let perm = browser_perm.unwrap_or("");
    let mut judgement = Judgement::new(Status::Inconclusive, "loc.unknown", params(&[]), "advice.loc.off", params(&[]))
        .observe("system", match os_enabled {
            Some(true) => "enabled",
            Some(false) => "disabled",
            None => "unknown",
        })
        .observe("permission", if perm.is_empty() { "unknown" } else { perm });
    if os_enabled == Some(true) {
        judgement.status = Status::Warn;
        judgement.summary_key = "loc.warnOs".into();
        judgement.advice_key = "advice.loc.off".into();
        return judgement;
    }
    if perm == "granted" {
        judgement.status = Status::Warn;
        judgement.summary_key = "loc.warnBrowser".into();
        judgement.advice_key = "advice.loc.off".into();
        return judgement;
    }
    if os_enabled == Some(false) && (perm == "denied" || perm == "prompt" || perm.is_empty()) {
        if perm == "prompt" {
            judgement.status = Status::Info;
            judgement.summary_key = "loc.prompt".into();
            judgement.advice_key = "advice.loc.prompt".into();
        } else {
            judgement.status = Status::Pass;
            judgement.summary_key = "loc.ok".into();
            judgement.advice_key = "advice.loc.ok".into();
        }
        return judgement;
    }
    if perm == "prompt" {
        judgement.status = Status::Info;
        judgement.summary_key = "loc.prompt".into();
        judgement.advice_key = "advice.loc.prompt".into();
    }
    judgement
}

pub fn judge_clock(offset_ms: Option<i64>) -> Judgement {
    let Some(offset) = offset_ms else {
        return Judgement::new(Status::Inconclusive, "clock.unavailable", params(&[]), "advice.clock.retry", params(&[]));
    };
    let label = format_offset(offset);
    let abs = offset.abs();
    let (status, key, advice) = if abs < 5_000 {
        (Status::Pass, "clock.ok", "advice.clock.ok")
    } else if abs < 120_000 {
        (Status::Warn, "clock.warn", "advice.clock.sync")
    } else {
        (Status::Fail, "clock.fail", "advice.clock.sync")
    };
    Judgement::new(status, key, params(&[("offset", &label)]), advice, params(&[]))
        .observe("offset", &label)
        .expect("offset", "within 5 seconds of NTP")
}

fn format_offset(ms: i64) -> String {
    let sign = if ms < 0 { "-" } else { "+" };
    let abs = ms.abs();
    if abs < 1000 {
        format!("{sign}{abs} ms")
    } else {
        format!("{sign}{:.1} s", abs as f64 / 1000.0)
    }
}

pub fn judge_hosts(overrides: &[(String, String)]) -> Judgement {
    if overrides.is_empty() {
        return Judgement::new(Status::Pass, "hosts.ok", params(&[]), "advice.hosts.ok", params(&[]))
            .expect("entries", "none");
    }
    let entries = overrides
        .iter()
        .map(|(ip, host)| format!("{ip} {host}"))
        .collect::<Vec<_>>()
        .join(", ");
    Judgement::new(Status::Fail, "hosts.fail", params(&[("entries", &entries)]), "advice.hosts.remove", params(&[]))
        .observe("entries", &entries)
}

pub fn judge_tls(issuer: Option<&str>, verified: bool, error: Option<&str>) -> Judgement {
    let Some(issuer) = issuer.filter(|s| !s.is_empty()) else {
        return Judgement::new(
            Status::Inconclusive,
            "tls.unavailable",
            params(&[("error", error.unwrap_or("no certificate"))]),
            "advice.tls.retry",
            params(&[]),
        );
    };
    let mut judgement = Judgement::new(Status::Pass, "tls.ok", params(&[("issuer", issuer)]), "advice.tls.ok", params(&[]))
        .observe("issuer", issuer)
        .observe("verified", if verified { "yes" } else { "no" });
    if suspicious_intercept_ca(issuer) {
        judgement.status = Status::Fail;
        judgement.summary_key = "tls.suspicious".into();
        judgement.advice_key = "advice.tls.disableIntercept".into();
        return judgement;
    }
    if corporate_intercept_ca(issuer) || !verified || !known_public_ca(issuer) {
        judgement.status = Status::Warn;
        judgement.summary_key = "tls.unknown".into();
        judgement.advice_key = "advice.tls.disableIntercept".into();
    }
    judgement
}

pub struct ReachHit {
    pub host: &'static str,
    pub ok: bool,
    pub status: Option<u16>,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

pub fn judge_reach(hits: &[ReachHit]) -> Judgement {
    let detail = hits
        .iter()
        .map(|hit| match (hit.ok, hit.status, hit.latency_ms, &hit.error) {
            (true, Some(status), Some(ms), _) => format!("{} HTTP {status} in {ms} ms", hit.host),
            (true, _, Some(ms), _) => format!("{} in {ms} ms", hit.host),
            (_, _, _, Some(err)) => format!("{} failed ({err})", hit.host),
            _ => format!("{} failed", hit.host),
        })
        .collect::<Vec<_>>()
        .join("; ");
    let ok_count = hits.iter().filter(|hit| hit.ok).count();
    let (status, key, advice) = if hits.is_empty() || ok_count == 0 {
        (Status::Fail, "reach.fail", "advice.reach.fix")
    } else if ok_count == hits.len() {
        (Status::Pass, "reach.ok", "advice.reach.ok")
    } else {
        (Status::Warn, "reach.partial", "advice.reach.fix")
    };
    let claude_ms = hits.iter().find(|hit| hit.host.contains("claude.ai")).and_then(|hit| hit.latency_ms).unwrap_or(0);
    let api_ms = hits.iter().find(|hit| hit.host.contains("api.")).and_then(|hit| hit.latency_ms).unwrap_or(0);
    Judgement::new(
        status,
        key,
        params(&[
            ("detail", &detail),
            ("claudeMs", &claude_ms.to_string()),
            ("apiMs", &api_ms.to_string()),
        ]),
        advice,
        params(&[]),
    )
    .observe("detail", &detail)
}
