/// Shared redaction for display and both export formats. Preserve URL spelling.
pub fn redact_url(input: &str) -> String {
    let mut s = input.to_string();
    if let Some(start) = s.find("://") {
        let a = start + 3;
        let end = s[a..].find(['/', '?', '#']).map(|i| a+i).unwrap_or(s.len());
        if let Some(at) = s[a..end].rfind('@') { s.replace_range(a..a+at, "***"); }
    }
    if let Some(q) = s.find('?') {
        let end = s[q..].find('#').map(|i| q+i).unwrap_or(s.len());
        let query = s[q+1..end].split('&').map(|part| {
            let (k, _) = part.split_once('=').unwrap_or((part, ""));
            let decoded = url::form_urlencoded::parse(format!("{k}=").as_bytes()).next().map(|(k,_)| k.into_owned()).unwrap_or_default();
            if ["token","key","auth","password","passwd","pwd","secret","sig","signature","access_token","apikey","api_key","session"].contains(&decoded.to_lowercase().as_str()) { format!("{k}=***") } else { part.into() }
        }).collect::<Vec<String>>().join("&");
        s.replace_range(q+1..end, &query);
    }
    s
}
pub fn redact_text(text: &str) -> String {
    text.split_inclusive(char::is_whitespace).map(|part| {
        let end = part.trim_end().len();
        format!("{}{}", redact_url(&part[..end]), &part[end..])
    }).collect()
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn credentials_and_queries() {
        assert_eq!(redact_url("socks5://user:password@host:8/p?ToKen=secret&ok=1"), "socks5://***@host:8/p?ToKen=***&ok=1");
        assert!(!redact_text("proxy http://user:password@host/?api_key=secret").contains("secret"));
    }
}
