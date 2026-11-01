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
        return base(Status::Inconclusive, "exit.missing", &[], "advice.exit.missing");
    };
    let Some(country) = geo_country.map(parse::norm_country).filter(|c| !c.is_empty()) else {
        return base(Status::Inconclusive, "exit.unlocated", &[("ip", ip)], "advice.exit.missing").observe("ip", ip);
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

pub fn judge_ipv6(route: &crate::platform::Ipv6Route, exit_country: Option<&str>, place_text: &str, preset: &RegionPreset) -> Judgement {
    use crate::platform::Ipv6Route;
    let iface = match route { Ipv6Route::Present { iface } => iface.as_str(), _ => "unknown" };
    if exit_country.is_none() && matches!(route, Ipv6Route::Absent) {
        return Judgement::new(Status::Pass, "v6.none", params(&[]), "advice.v6.keepOff", params(&[]));
    }
    let country = exit_country.map(parse::norm_country).unwrap_or_default();
    let (status, key) = if country.is_empty() {
        (Status::Inconclusive, "v6.unavailable")
    } else if country != preset.country {
        (Status::Fail, "v6.exitMismatch")
    } else {
        (Status::Pass, "v6.exitOk")
    };
    let mut j = Judgement::new(status, key, params(&[("iface", iface), ("country", &country), ("expected", &preset.display("en")), ("place", place_text)]), if status == Status::Pass { "advice.v6.ok" } else { "advice.v6.tunnel" }, params(&[("expected", &preset.display("en"))]))
        .observe("iface", iface).observe("country", &country).expect("country", &preset.country);
    if let Ipv6Route::Unknown(error) = route { j = j.observe("routeError", error); }
    j
}

pub fn judge_route(iface_a: Option<&str>, iface_b: Option<&str>, exit_country: Option<&str>, preset: &RegionPreset) -> Judgement {
    judge_route_classified(iface_a,iface_b,exit_country,preset,None)
}

pub fn judge_route_classified(iface_a: Option<&str>, iface_b: Option<&str>, exit_country: Option<&str>, preset: &RegionPreset, class: Option<IfaceClass>) -> Judgement {
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
    let class = class.unwrap_or_else(|| parse::classify_iface(iface));
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
        // Without a located exit we cannot tell a direct mainland path from a
        // home-region one, so this is a gap in observation, not an exposure.
        IfaceClass::Physical if country.is_empty() => {
            judgement.status = Status::Inconclusive;
            judgement.summary_key = "route.physicalUnmeasured".into();
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

pub struct ProxyView<'a> {
    pub enabled: bool,
    pub pac: bool,
    pub pac_url: &'a str,
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
        return Judgement::new(Status::Inconclusive, "proxy.pacUnknown", params(&[]), "advice.proxy.readPac", params(&[])).observe("pac", view.pac_url);
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
    pub path: String,
    pub resolver: String,
    pub ip: String,
    pub country: String,
    pub city: String,
    pub asn: String,
    pub provider: Option<String>,
}

pub fn judge_leak(hits: &[LeakHit], system_inconclusive: bool, preset: &RegionPreset) -> Judgement {
    let expected = preset.display("en");
    if hits.is_empty() {
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
            format!("{} via {}: {} {country} {}", hit.path, hit.resolver, hit.ip, hit.asn)
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
    let bad = hits.iter().any(|hit| hit.path == "system" && (hit.provider.is_some() || is_mainland_china(&hit.country)));
    if bad {
        judgement.status = Status::Fail;
        judgement.summary_key = "leak.fail".into();
        judgement.advice_key = "advice.leak.fix".into();
        judgement.advice_params = params(&[("expected", expected.as_str())]);
        return judgement;
    }
    if hits.iter().any(|h| h.path == "configured-server" && (h.provider.is_some() || is_mainland_china(&h.country))) {
        judgement.status = Status::Warn;
        judgement.summary_key = "leak.configWarning".into();
        return judgement;
    }
    if system_inconclusive || hits.iter().any(|h| h.path == "system" && h.country.is_empty()) || !hits.iter().any(|h| h.path == "system") {
        judgement.status = Status::Inconclusive;
        judgement.summary_key = "leak.inconclusive".into();
        judgement.advice_key = "advice.leak.retry".into();
        return judgement;
    }
    let third = hits.iter().filter(|h| h.path == "system").any(|hit| {
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

pub fn judge_windows_timezone(raw: &str, territory: Option<&str>, browser: Option<&str>, ip_tz: Option<&str>, preset: &RegionPreset) -> Judgement {
    let mapped=parse::windows_to_iana(raw,territory.or(Some(&preset.country)));
    let chosen=mapped.iter().find(|id| browser.is_some_and(|b| canon_tz(b)==canon_tz(id)) && tz_allowed(id,&preset.timezones))
        .or_else(|| mapped.iter().find(|id| tz_allowed(id,&preset.timezones))).or_else(|| mapped.first());
    judge_timezone(chosen.map(String::as_str).unwrap_or(""),browser,ip_tz,preset)
        .observe("system",raw).observe("windowsTerritory",territory.unwrap_or(&preset.country)).observe("mappedTimezones",mapped.join(", "))
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
        judgement.status = Status::Inconclusive;
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
        judgement.status = Status::Inconclusive;
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

pub fn judge_webrtc(collection: Option<&crate::browser::WebRtcStatus>, ips: &[WebRtcIp], preset: &RegionPreset) -> Judgement {
    let expected = preset.display("en");
    if collection.is_none() {
        return Judgement::new(Status::Inconclusive, "webrtc.missing", params(&[]), "advice.webrtc.retry", params(&[]));
    }
    let collection = collection.unwrap();
    if !collection.supported {
        return Judgement::new(Status::Info, "webrtc.disabled", params(&[]), "advice.webrtc.ok", params(&[]));
    }
    // Retain observed mismatches even if gathering later failed.
    let incomplete = !collection.error.is_empty() || collection.ice_state != "complete";
    let public: Vec<&WebRtcIp> = ips.iter().filter(|ip| !is_private_ip(&ip.ip)).collect();
    let described = ips
        .iter()
        .map(|ip| format!("{} ({})", ip.ip, ip.kind))
        .collect::<Vec<_>>()
        .join(", ");
    if public.is_empty() && incomplete {
        return Judgement::new(Status::Inconclusive, "webrtc.missing", params(&[]), "advice.webrtc.retry", params(&[])).observe("iceState", &collection.ice_state).observe("error", &collection.error);
    }
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
    let unknown = collection.ice_state != "complete" || public.iter().any(|ip| parse::norm_country(&ip.country).is_empty());
    if unknown {
        return Judgement::new(Status::Inconclusive, "webrtc.unmeasured", params(&[("ip", public[0].ip.as_str()), ("country", "unknown"), ("expected", expected.as_str())]), "advice.webrtc.disable", params(&[]))
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
    if os_enabled.is_none() {
        return judgement;
    }
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

pub fn judge_hosts_file(hosts: &Result<String, crate::platform::CollectError>) -> Judgement {
    match hosts {
        Ok(text) => judge_hosts(&parse::parse_hosts(text)),
        Err(e) => Judgement::new(Status::Inconclusive, "hosts.unavailable", params(&[]), "advice.hosts.retry", params(&[])).observe("error", e.to_string()),
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
    pub class: crate::context::ReachClass,
    pub status: Option<u16>,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

pub fn judge_reach(hits: &[ReachHit]) -> Judgement {
    let detail = hits
        .iter()
        .map(|hit| match (hit.class == crate::context::ReachClass::Ok, hit.status, hit.latency_ms, &hit.error) {
            (_, Some(status), Some(ms), _) => format!("{} HTTP {status} in {ms} ms", hit.host),
            (_, Some(status), _, _) => format!("{} HTTP {status}", hit.host),
            (true, _, Some(ms), _) => format!("{} in {ms} ms", hit.host),
            (_, _, _, Some(err)) => format!("{} failed ({err})", hit.host),
            _ => format!("{} failed", hit.host),
        })
        .collect::<Vec<_>>()
        .join("; ");
    let ok_count = hits.iter().filter(|hit| hit.class == crate::context::ReachClass::Ok).count();
    use crate::context::ReachClass;
    let has = |class| hits.iter().any(|h| h.class == class);
    let (status, key, advice) = if has(ReachClass::RegionDenied) {
        (Status::Fail, "reach.regionDenied", "advice.reach.fix")
    } else if hits.is_empty() || has(ReachClass::ServerError) {
        (Status::Inconclusive, "reach.serverError", "advice.reach.fix")
    } else if has(ReachClass::RateLimited) {
        (Status::Warn, "reach.rateLimited", "advice.reach.fix")
    } else if ok_count == 0 {
        (Status::Inconclusive, "reach.fail", "advice.reach.fix")
    } else if ok_count == hits.len() {
        (Status::Pass, "reach.ok", "advice.reach.ok")
    } else {
        (Status::Inconclusive, "reach.partial", "advice.reach.fix")
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
    .observe("classes", hits.iter().map(|h| format!("{}: {}", h.host, match h.class { ReachClass::Ok => "reachable", ReachClass::Unreachable => "unreachable", ReachClass::RegionDenied => "region denied", ReachClass::RateLimited => "rate limited", ReachClass::ServerError => "server error" })).collect::<Vec<_>>().join("; "))
}

#[cfg(test)]
mod observation_tests {
    use super::*;
    use crate::{browser::WebRtcStatus, platform::{CollectError, Ipv6Route}, context::ReachClass};
    #[test]
    fn windows_timezone_territories_and_raw_observation() {
        for (id,territory,region) in [("Eastern Standard Time","CA","ca"),("Eastern Standard Time","US","us"),("W. Europe Standard Time","NL","nl"),("W. Europe Standard Time","DE","de")] {
            let p=crate::region::find(region).unwrap();
            let j=judge_windows_timezone(id,Some(territory),None,None,p);
            assert_eq!(j.status,Status::Pass,"{region}");
            assert_eq!(j.observed["system"],id);
            assert_eq!(judge_windows_timezone(id,None,None,None,p).status,Status::Pass);
        }
        assert_eq!(judge_windows_timezone("unknown",None,None,None,preset()).status,Status::Inconclusive);
    }
    fn preset() -> &'static RegionPreset { crate::region::find("us").unwrap() }
    #[test]
    fn empty_system_values_are_inconclusive_without_collection_errors() {
        for empty in ["", "  "] {
            assert_eq!(judge_timezone(empty, Some("America/New_York"), None, preset()).status, Status::Inconclusive);
            assert_eq!(judge_locale(empty, &["en-US".into()], "en-US", false, preset()).status, Status::Inconclusive);
        }
        for permission in [None, Some("granted"), Some("denied"), Some("prompt")] {
            assert_eq!(judge_location(None, permission).status, Status::Inconclusive);
        }
    }
    #[test]
    fn ipv6_absence_unknown_and_observed_countries() {
        assert_eq!(judge_ipv6(&Ipv6Route::Absent, None, "", preset()).status, Status::Pass);
        assert_eq!(judge_ipv6(&Ipv6Route::Unknown("missing command".into()), None, "", preset()).status, Status::Inconclusive);
        let present = Ipv6Route::Present { iface: "utun0".into() };
        assert_eq!(judge_ipv6(&present, None, "", preset()).status, Status::Inconclusive);
        for route in [Ipv6Route::Absent, present, Ipv6Route::Unknown("error".into())] {
            assert_eq!(judge_ipv6(&route, Some("US"), "", preset()).status, Status::Pass);
            assert_eq!(judge_ipv6(&route, Some("CN"), "", preset()).status, Status::Fail);
            assert_eq!(judge_ipv6(&route, Some("JP"), "", preset()).status, Status::Fail);
            assert_eq!(judge_ipv6(&route, Some(""), "", preset()).status, Status::Inconclusive);
        }
    }
    #[test]
    fn physical_route_with_unknown_exit_is_inconclusive() {
        assert_eq!(judge_route(Some("eth0"), Some("eth0"), None, preset()).status, Status::Inconclusive);
        assert_eq!(judge_route(Some("eth0"), Some("eth0"), Some("CN"), preset()).status, Status::Fail);
        assert_eq!(judge_route(Some("eth0"), Some("eth0"), Some("US"), preset()).status, Status::Warn);
    }
    #[test]
    fn missing_intel_is_not_exposure() {
        assert_eq!(judge_exit(None, None, "", "", "", None, preset()).status, Status::Inconclusive);
        assert_eq!(judge_exit(Some("1.1.1.1"), None, "", "", "", None, preset()).status, Status::Inconclusive);
    }
    #[test]
    fn unreadable_hosts_are_not_clean() {
        assert_eq!(judge_hosts_file(&Err(CollectError::Io("denied".into()))).status, Status::Inconclusive);
        assert_eq!(judge_hosts_file(&Ok(String::new())).status, Status::Pass);
        assert_eq!(judge_hosts_file(&Ok("1.2.3.4 claude.ai".into())).status, Status::Fail);
    }
    #[test]
    fn webrtc_collection_states_are_distinct() {
        let mut status = WebRtcStatus { supported: true, ice_state: "complete".into(), error: String::new(), candidates: 0 };
        assert_eq!(judge_webrtc(None, &[], preset()).status, Status::Inconclusive);
        assert_eq!(judge_webrtc(Some(&status), &[], preset()).status, Status::Pass);
        status.supported = false;
        assert_eq!(judge_webrtc(Some(&status), &[], preset()).status, Status::Info);
        status.supported = true;
        for state in ["timeout", "failed", ""] {
            status.ice_state = state.into();
            assert_eq!(judge_webrtc(Some(&status), &[], preset()).status, Status::Inconclusive);
        }
        status.ice_state = "complete".into(); status.error = "offer failed".into();
        assert_eq!(judge_webrtc(Some(&status), &[], preset()).status, Status::Inconclusive);
        let leak = [WebRtcIp { ip: "8.8.8.8".into(), kind: "srflx".into(), country: "CN".into() }];
        assert_eq!(judge_webrtc(Some(&status), &leak, preset()).status, Status::Fail);
        let located = [WebRtcIp { ip: "8.8.8.8".into(), kind: "srflx".into(), country: "US".into() }];
        assert_eq!(judge_webrtc(Some(&status), &located, preset()).status, Status::Pass);
        for state in ["timeout", "failed", "gathering"] {
            status.ice_state = state.into();
            assert_eq!(judge_webrtc(Some(&status), &located, preset()).status, Status::Inconclusive);
            assert_eq!(judge_webrtc(Some(&status), &leak, preset()).status, Status::Fail);
        }
        status.ice_state = "complete".into();
        let unknown = [WebRtcIp { ip: "8.8.8.8".into(), kind: "srflx".into(), country: String::new() }];
        assert_eq!(judge_webrtc(Some(&status), &unknown, preset()).status, Status::Inconclusive);
    }
    #[test]
    fn reachability_uses_response_classes() {
        let hit = |class| ReachHit { host: "claude.ai", class, status: None, latency_ms: None, error: None };
        for (class, expected) in [(ReachClass::Ok, Status::Pass), (ReachClass::RegionDenied, Status::Fail), (ReachClass::RateLimited, Status::Warn), (ReachClass::ServerError, Status::Inconclusive), (ReachClass::Unreachable, Status::Inconclusive)] {
            let j = judge_reach(&[hit(class), hit(class)]);
            assert_eq!(j.status, expected); assert!(j.observed.contains_key("classes"));
        }
        assert_eq!(judge_reach(&[hit(ReachClass::Ok), hit(ReachClass::Unreachable)]).status, Status::Inconclusive);
        assert_eq!(judge_reach(&[]).status, Status::Inconclusive);
    }
}

/// Only measured discrepancies establish exposure; missing measurements remain gaps.
pub fn judge_udp_measurements(countries:&[String],tcp:Option<&str>,target:&str,unknown:bool,blocked:usize,quic:&Result<bool,String>)->(Status,&'static str){
    if countries.iter().any(|c|c=="CN"||tcp.filter(|t|!t.is_empty()).is_some_and(|t|c!=t)) {(Status::Fail,"quic.measuredLeak")}
    else if blocked==2 && quic.is_err(){(Status::Pass,"quic.blocked")}
    else if unknown || countries.is_empty() || tcp.is_none_or(str::is_empty) || !matches!(quic,Ok(true)){(Status::Inconclusive,"quic.measureUnknown")}
    else if countries.iter().all(|c|c==target){(Status::Pass,"quic.measuredOk")}
    else{(Status::Inconclusive,"quic.measureUnknown")}
}
#[cfg(test)] mod udp_tests {
use super::*;
#[test] fn measured_paths_leaks_and_gaps(){
 let ok=Ok(true);let err=Err("not run".into());
 for (countries,tcp,unknown,blocked,q,status) in [
 (vec!["US".into(),"US".into()],Some("US"),false,0,&ok,Status::Pass),
 (vec!["CN".into()],Some("US"),true,0,&err,Status::Fail),
 (vec!["JP".into()],Some("US"),false,0,&ok,Status::Fail),
 (vec![],None,false,2,&err,Status::Pass),
 (vec![],None,true,0,&err,Status::Inconclusive),
 (vec!["US".into()],Some("US"),true,0,&ok,Status::Inconclusive),
 (vec!["US".into()],None,false,0,&ok,Status::Inconclusive),
 (vec!["US".into()],Some("US"),false,0,&err,Status::Inconclusive),
 ] {assert_eq!(judge_udp_measurements(&countries,tcp,"US",unknown,blocked,q).0,status);}
}
}
