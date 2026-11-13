use crate::models::unix_now;
use anyhow::{Context, Result, bail};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NormalizedCookieBundle {
    pub format_label: String,
    pub cookies: Vec<serde_json::Value>,
    pub origins: Vec<serde_json::Value>,
    pub domains: Vec<String>,
}

impl NormalizedCookieBundle {
    pub fn to_state_json_pretty(&self) -> String {
        serde_json::to_string_pretty(&serde_json::json!({
            "cookies": self.cookies,
            "origins": self.origins,
        }))
        .unwrap_or_else(|_| "{\"cookies\":[],\"origins\":[]}".to_string())
    }

    pub fn summary_badge(&self) -> String {
        let dom_str = if self.domains.is_empty() {
            "no domain".to_string()
        } else if self.domains.len() <= 3 {
            self.domains.join(", ")
        } else {
            format!(
                "{}, +{} more",
                self.domains[..2].join(", "),
                self.domains.len() - 2
            )
        };
        if self.origins.is_empty() {
            format!(
                "{} cookies ({}) • {}",
                self.cookies.len(),
                dom_str,
                self.format_label
            )
        } else {
            format!(
                "{} cookies + {} origins ({}) • {}",
                self.cookies.len(),
                self.origins.len(),
                dom_str,
                self.format_label
            )
        }
    }
}

fn extract_host_from_url_or_domain(raw: &str) -> Option<String> {
    let trimmed = raw
        .trim()
        .trim_matches(['"', '\'', ' ', '\t', '\r', '\n', ';']);
    if trimmed.is_empty() {
        return None;
    }
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .or_else(|| trimmed.strip_prefix("wss://"))
        .or_else(|| trimmed.strip_prefix("ws://"))
        .unwrap_or(trimmed);
    let had_scheme = without_scheme.len() != trimmed.len();
    let host_port = without_scheme
        .split(['/', '?', '#', ',', ' ', '\t', '\r', '\n'])
        .next()
        .unwrap_or("")
        .trim();
    let host = host_port.split(':').next().unwrap_or("").trim();
    if host.is_empty() || (!host.contains('.') && !host.eq_ignore_ascii_case("localhost")) {
        return None;
    }
    if had_scheme {
        Some(host.trim_start_matches('.').to_ascii_lowercase())
    } else if host.starts_with('.') {
        Some(format!(".{}", host.trim_start_matches('.').to_ascii_lowercase()))
    } else {
        Some(host.to_ascii_lowercase())
    }
}

fn extract_origin_from_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_matches(['"', '\'']);
    let (scheme, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        ("https://", r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        ("http://", r)
    } else {
        return None;
    };
    let authority = rest.split(['/', '?', '#', ',', ' ', '\t', '\r', '\n']).next()?.trim();
    if authority.is_empty() {
        return None;
    }
    Some(format!("{scheme}{authority}"))
}

fn infer_domain_from_cookie_name(name: &str) -> Option<&'static str> {
    match name.trim() {
        "c_user" | "xs" | "datr" | "sb" | "fr" | "wd" | "presence" => Some(".facebook.com"),
        "SID" | "HSID" | "SSID" | "APISID" | "SAPISID" | "__Secure-1PSID" | "__Secure-3PSID"
        | "__Secure-1PAPISID" | "__Secure-3PAPISID" | "NID" => Some(".google.com"),
        "auth_token" | "ct0" | "twid" | "kdt" => Some(".x.com"),
        "sessionid" | "sessionid_ss" | "sid_tt" | "uid_tt" | "tt_webid" | "odin_tt" => {
            Some(".tiktok.com")
        }
        "SPC_EC" | "SPC_F" | "SPC_U" | "SPC_ST" | "SPC_R_T_ID" | "SPC_T_ID" => {
            Some(".shopee.vn")
        }
        "ds_user_id" | "csrftoken" | "ig_did" | "mid" | "rur" => Some(".instagram.com"),
        "li_at" | "liap" | "li_rm" => Some(".linkedin.com"),
        "user_session" | "_gh_sess" | "dotcom_user" | "__Host-user_session_same_site" => {
            Some(".github.com")
        }
        "ubid-main" | "x-main" | "at-main" | "sess-at-main" | "session-id" => {
            Some(".amazon.com")
        }
        "SUB" | "SUBP" | "SSOLoginState" => Some(".weibo.com"),
        _ => None,
    }
}

pub(crate) fn normalize_same_site_str(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "strict" => Some("Strict"),
        "lax" => Some("Lax"),
        "none" | "no_restriction" | "norestriction" => Some("None"),
        _ => None,
    }
}

fn normalize_single_cookie_json(
    item: &serde_json::Value,
    default_domain: Option<&str>,
) -> Option<serde_json::Value> {
    let obj = item.as_object()?;
    let name = obj.get("name")?.as_str()?.trim();
    if name.is_empty() {
        return None;
    }
    let value = match obj.get("value") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        Some(serde_json::Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    };

    let raw_domain = obj
        .get("domain")
        .or_else(|| obj.get("host"))
        .and_then(|v| v.as_str())
        .and_then(extract_host_from_url_or_domain)
        .or_else(|| {
            obj.get("url")
                .and_then(|v| v.as_str())
                .and_then(extract_host_from_url_or_domain)
        })
        .or_else(|| default_domain.and_then(extract_host_from_url_or_domain))
        .or_else(|| infer_domain_from_cookie_name(name).map(ToString::to_string))?;

    let host_only = obj
        .get("hostOnly")
        .or_else(|| obj.get("host_only"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let is_host_prefix = name.starts_with("__Host-");
    let is_secure_prefix = name.starts_with("__Secure-");

    let clean_domain = if host_only || is_host_prefix {
        raw_domain.trim_start_matches('.').to_string()
    } else {
        raw_domain
    };
    if clean_domain.is_empty() {
        return None;
    }

    let raw_path = obj
        .get("path")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("/");
    let path = if is_host_prefix || raw_path.is_empty() || !raw_path.starts_with('/') {
        "/".to_string()
    } else {
        raw_path.to_string()
    };

    let http_only = obj
        .get("httpOnly")
        .or_else(|| obj.get("http_only"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let same_site = obj
        .get("sameSite")
        .or_else(|| obj.get("same_site"))
        .and_then(|v| v.as_str())
        .and_then(normalize_same_site_str);

    let secure = obj
        .get("secure")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || same_site == Some("None")
        || is_host_prefix
        || is_secure_prefix;

    let explicit_session = obj
        .get("session")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let raw_exp = obj
        .get("expires")
        .or_else(|| obj.get("expirationDate"))
        .or_else(|| obj.get("expiry"))
        .and_then(|v| {
            v.as_f64()
                .or_else(|| v.as_i64().map(|n| n as f64))
                .or_else(|| v.as_str().and_then(|s| s.trim().parse::<f64>().ok()))
        });
    let (expires, session) = match raw_exp {
        Some(ts) if !explicit_session && ts > 0.0 => {
            let secs = if ts > 100_000_000_000.0 {
                ts / 1000.0
            } else {
                ts
            };
            (secs, false)
        }
        _ => (-1.0, true),
    };

    let mut out = serde_json::Map::new();
    out.insert("name".into(), serde_json::Value::String(name.to_string()));
    out.insert("value".into(), serde_json::Value::String(value.clone()));
    out.insert("domain".into(), serde_json::Value::String(clean_domain));
    out.insert("path".into(), serde_json::Value::String(path));
    out.insert("expires".into(), serde_json::json!(expires));
    out.insert(
        "size".into(),
        serde_json::json!(name.len().saturating_add(value.len())),
    );
    out.insert("httpOnly".into(), serde_json::Value::Bool(http_only));
    out.insert("secure".into(), serde_json::Value::Bool(secure));
    out.insert("session".into(), serde_json::Value::Bool(session));
    if let Some(ss) = same_site {
        out.insert("sameSite".into(), serde_json::Value::String(ss.to_string()));
    }
    Some(serde_json::Value::Object(out))
}

fn parse_semicolon_cookie_pairs(
    raw_pairs: &str,
    fallback_domain: Option<&str>,
) -> Result<Vec<serde_json::Value>> {
    let mut explicit_domain: Option<String> = None;
    let mut explicit_path = "/".to_string();
    let mut explicit_secure = false;
    let mut explicit_http_only = false;
    let mut explicit_same_site: Option<&'static str> = None;
    let mut explicit_expires: Option<f64> = None;
    let mut kv_pairs: Vec<(String, String)> = Vec::new();

    let cleaned = raw_pairs
        .trim()
        .strip_prefix("Cookie:")
        .or_else(|| raw_pairs.trim().strip_prefix("cookie:"))
        .unwrap_or(raw_pairs.trim());

    for token in cleaned.split(';') {
        let part = token.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('=') {
            let key = k.trim();
            let val = v.trim().trim_matches('"');
            if key.is_empty() {
                continue;
            }
            match key.to_ascii_lowercase().as_str() {
                "domain" => {
                    explicit_domain = extract_host_from_url_or_domain(val);
                }
                "path" => {
                    if val.starts_with('/') {
                        explicit_path = val.to_string();
                    }
                }
                "samesite" => {
                    explicit_same_site = normalize_same_site_str(val);
                }
                "max-age" => {
                    if let Ok(secs) = val.parse::<i64>() {
                        explicit_expires = Some((unix_now().saturating_add(secs)) as f64);
                    }
                }
                "expires" => {
                    if let Ok(ts) = val.parse::<f64>() {
                        explicit_expires = Some(ts);
                    }
                }
                _ => {
                    kv_pairs.push((key.to_string(), val.to_string()));
                }
            }
        } else {
            match part.to_ascii_lowercase().as_str() {
                "secure" => explicit_secure = true,
                "httponly" => explicit_http_only = true,
                _ => {}
            }
        }
    }

    if kv_pairs.is_empty() {
        bail!("No valid name=value pairs found in cookie string");
    }

    let inferred_batch_domain = explicit_domain
        .or_else(|| {
            kv_pairs
                .iter()
                .find_map(|(k, _)| infer_domain_from_cookie_name(k).map(ToString::to_string))
        })
        .or_else(|| {
            fallback_domain
                .filter(|u| !u.trim().eq_ignore_ascii_case("https://browserscan.net"))
                .and_then(extract_host_from_url_or_domain)
        });

    let Some(domain) = inferred_batch_domain else {
        bail!(
            "Raw key=value cookies require a target domain. Include 'domain=.example.com;' or set the profile's Startup URL first."
        );
    };

    let default_exp = explicit_expires.unwrap_or_else(|| (unix_now() + 86_400 * 180) as f64);
    let mut out = Vec::with_capacity(kv_pairs.len());
    for (name, value) in kv_pairs {
        let cookie_domain = infer_domain_from_cookie_name(&name)
            .filter(|d| domain == *d || domain.ends_with(d.trim_start_matches('.')))
            .unwrap_or(domain.as_str());
        let mut map = serde_json::Map::new();
        map.insert("name".into(), serde_json::Value::String(name));
        map.insert("value".into(), serde_json::Value::String(value));
        map.insert(
            "domain".into(),
            serde_json::Value::String(cookie_domain.to_string()),
        );
        map.insert(
            "path".into(),
            serde_json::Value::String(explicit_path.clone()),
        );
        map.insert("expires".into(), serde_json::json!(default_exp));
        map.insert(
            "secure".into(),
            serde_json::Value::Bool(explicit_secure || cookie_domain.starts_with('.')),
        );
        map.insert(
            "httpOnly".into(),
            serde_json::Value::Bool(explicit_http_only),
        );
        if let Some(ss) = explicit_same_site {
            map.insert("sameSite".into(), serde_json::Value::String(ss.to_string()));
        }
        if let Some(norm) =
            normalize_single_cookie_json(&serde_json::Value::Object(map), Some(cookie_domain))
        {
            out.push(norm);
        }
    }
    Ok(out)
}

fn collect_unique_domains(cookies: &[serde_json::Value]) -> Vec<String> {
    let mut domains = Vec::new();
    for c in cookies {
        if let Some(d) = c
            .get("domain")
            .and_then(|v| v.as_str())
            .map(|s| s.trim_start_matches('.').to_ascii_lowercase())
            && !d.is_empty()
            && !domains.contains(&d)
        {
            domains.push(d);
        }
    }
    domains
}

/// Parses and normalizes any supported cookie/state payload into BonLogin's canonical CDP State JSON:
/// 1. Playwright / BonLogin State JSON (`{"cookies": [...], "origins": [...]}`)
/// 2. Cookie-Editor / EditThisCookie JSON Array (`[{"name": ..., "value": ..., "domain": ...}]`)
/// 3. J2Team / Cookie & Token Grabber JSON (`{"url": "...", "cookies": [...]}` or `{"url": "...", "cookie": "...", "localStorage": {...}}`)
/// 4. Netscape HTTP Cookie File format (`# Netscape HTTP Cookie File` / 7 columns including `#HttpOnly_`)
/// 5. cURL command (`curl 'https://...' -H 'Cookie: ...'` or `-b '...'`)
/// 6. Raw `Cookie: k=v; k2=v2` or MMO pipe account line `UID|Pass|2FA|c_user=...; xs=...`
pub fn parse_and_normalize_cookies(
    raw_payload: &str,
    fallback_url: Option<&str>,
) -> Result<NormalizedCookieBundle> {
    let trimmed = raw_payload.trim().trim_start_matches('\u{feff}').trim();
    if trimmed.is_empty() {
        bail!("Cookie payload is empty");
    }

    // 1. JSON formats (Array or Object)
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        let parsed: serde_json::Value =
            serde_json::from_str(trimmed).context("Invalid JSON syntax in cookie payload")?;
        match parsed {
            serde_json::Value::Array(arr) => {
                if arr.is_empty() {
                    return Ok(NormalizedCookieBundle {
                        format_label: "Empty JSON Array".to_string(),
                        cookies: Vec::new(),
                        origins: Vec::new(),
                        domains: Vec::new(),
                    });
                }
                let mut cookies = Vec::with_capacity(arr.len());
                for item in &arr {
                    if let Some(c) = normalize_single_cookie_json(item, fallback_url) {
                        cookies.push(c);
                    }
                }
                if cookies.is_empty() {
                    bail!(
                        "JSON array contains no valid cookies (each item needs 'name', 'value', and 'domain')"
                    );
                }
                let domains = collect_unique_domains(&cookies);
                return Ok(NormalizedCookieBundle {
                    format_label: "Cookie-Editor JSON".to_string(),
                    cookies,
                    origins: Vec::new(),
                    domains,
                });
            }
            serde_json::Value::Object(obj) => {
                let top_url_or_domain = obj
                    .get("domain")
                    .or_else(|| obj.get("url"))
                    .or_else(|| obj.get("origin"))
                    .and_then(|v| v.as_str())
                    .or(fallback_url);

                let mut origins = obj
                    .get("origins")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                if let Some(ls_obj) = obj.get("localStorage").and_then(|v| v.as_object())
                    && !ls_obj.is_empty()
                    && let Some(origin_url) = obj
                        .get("url")
                        .or_else(|| obj.get("origin"))
                        .and_then(|v| v.as_str())
                        .or(fallback_url)
                        .and_then(extract_origin_from_url)
                {
                    let ls_items: Vec<serde_json::Value> = ls_obj
                        .iter()
                        .map(|(k, v)| {
                            let val_str = v
                                .as_str()
                                .map(ToString::to_string)
                                .unwrap_or_else(|| v.to_string());
                            serde_json::json!({ "name": k, "value": val_str })
                        })
                        .collect();
                    origins.push(serde_json::json!({
                        "origin": origin_url,
                        "localStorage": ls_items,
                    }));
                }

                let mut cookies = Vec::new();
                if let Some(arr) = obj.get("cookies").and_then(|v| v.as_array()) {
                    for item in arr {
                        if let Some(c) = normalize_single_cookie_json(item, top_url_or_domain) {
                            cookies.push(c);
                        }
                    }
                } else if let Some(raw_cookie_str) = obj
                    .get("cookie")
                    .or_else(|| obj.get("cookies"))
                    .and_then(|v| v.as_str())
                    && !raw_cookie_str.trim().is_empty()
                {
                    cookies.extend(parse_semicolon_cookie_pairs(
                        raw_cookie_str,
                        top_url_or_domain,
                    )?);
                } else if obj.contains_key("name") && obj.contains_key("value") {
                    let val = serde_json::Value::Object(obj.clone());
                    if let Some(c) = normalize_single_cookie_json(&val, top_url_or_domain) {
                        cookies.push(c);
                    }
                }

                let has_cookies_key = obj.contains_key("cookies") || obj.contains_key("origins");
                if cookies.is_empty() && origins.is_empty() && !has_cookies_key {
                    bail!(
                        "JSON object does not contain 'cookies', 'origins', or a valid cookie {{'name','value','domain'}}"
                    );
                }

                let format_label = if obj.contains_key("origins") {
                    "State JSON"
                } else if obj.contains_key("url") && obj.contains_key("cookies") {
                    "J2Team Cookie JSON"
                } else if obj.contains_key("localStorage") {
                    "Token Grabber JSON"
                } else {
                    "Cookie JSON"
                }
                .to_string();
                let domains = collect_unique_domains(&cookies);
                return Ok(NormalizedCookieBundle {
                    format_label,
                    cookies,
                    origins,
                    domains,
                });
            }
            _ => bail!("Cookie JSON must be an Array [...] or Object {{...}}"),
        }
    }

    // 2. Netscape HTTP Cookie File format (7 tab/whitespace columns)
    let mut netscape_cookies = Vec::new();
    for raw_line in trimmed.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let (http_only, effective_line) = if let Some(rest) = line
            .strip_prefix("#HttpOnly_")
            .or_else(|| line.strip_prefix("#httponly_"))
        {
            (true, rest.trim())
        } else if line.starts_with('#') {
            continue;
        } else {
            (false, line)
        };

        let cols: Vec<&str> = if effective_line.contains('\t') {
            effective_line.splitn(7, '\t').collect()
        } else {
            effective_line.split_whitespace().collect()
        };
        if cols.len() >= 6
            && matches!(
                cols[1].to_ascii_uppercase().as_str(),
                "TRUE" | "FALSE" | "1" | "0"
            )
            && matches!(
                cols[3].to_ascii_uppercase().as_str(),
                "TRUE" | "FALSE" | "1" | "0"
            )
        {
            let domain = cols[0].trim();
            let path = cols[2].trim();
            let secure = matches!(cols[3].to_ascii_uppercase().as_str(), "TRUE" | "1");
            let expires = cols[4].trim().parse::<f64>().unwrap_or(-1.0);
            let name = cols[5].trim();
            let value = cols.get(6).copied().unwrap_or("").trim();
            let candidate = serde_json::json!({
                "name": name,
                "value": value,
                "domain": domain,
                "path": path,
                "secure": secure,
                "httpOnly": http_only,
                "expires": expires,
            });
            if let Some(norm) = normalize_single_cookie_json(&candidate, fallback_url) {
                netscape_cookies.push(norm);
            }
        }
    }
    if !netscape_cookies.is_empty() {
        let domains = collect_unique_domains(&netscape_cookies);
        return Ok(NormalizedCookieBundle {
            format_label: "Netscape Cookie File".to_string(),
            cookies: netscape_cookies,
            origins: Vec::new(),
            domains,
        });
    }

    // 3. cURL command (`curl 'https://...' -H 'Cookie: ...'` or `-b '...'`)
    if trimmed.starts_with("curl ") || trimmed.contains(" -H ") || trimmed.contains(" --cookie ") {
        let mut curl_url: Option<String> = None;
        for token in trimmed.split_whitespace() {
            let clean = token.trim_matches(['\'', '"', '\\']);
            if clean.starts_with("https://") || clean.starts_with("http://") {
                curl_url = Some(clean.to_string());
                break;
            }
        }
        let mut cookie_headers = Vec::new();
        let lower = trimmed.to_ascii_lowercase();
        let mut search_idx = 0;
        while let Some(pos) = lower[search_idx..].find("cookie:") {
            let start = search_idx + pos + "cookie:".len();
            let rest = &trimmed[start..];
            let end = rest.find(['\'', '"', '\n', '\r']).unwrap_or(rest.len());
            let extracted = rest[..end].trim();
            if !extracted.is_empty() {
                cookie_headers.push(extracted.to_string());
            }
            search_idx = start + end;
        }
        for flag in ["-b ", "--cookie "] {
            if let Some(pos) = trimmed.find(flag) {
                let after = trimmed[pos + flag.len()..].trim_start();
                if let Some(quote) = after.chars().next().filter(|c| *c == '\'' || *c == '"') {
                    let inner = &after[1..];
                    if let Some(end) = inner.find(quote) {
                        cookie_headers.push(inner[..end].to_string());
                    }
                }
            }
        }
        if !cookie_headers.is_empty() {
            let joined = cookie_headers.join("; ");
            let domain_hint = curl_url.as_deref().or(fallback_url);
            let cookies = parse_semicolon_cookie_pairs(&joined, domain_hint)?;
            let domains = collect_unique_domains(&cookies);
            return Ok(NormalizedCookieBundle {
                format_label: "cURL Command".to_string(),
                cookies,
                origins: Vec::new(),
                domains,
            });
        }
    }

    // 4. Raw `Cookie: a=1; b=2` or MMO pipe format `UID|Pass|2FA|c_user=1; xs=2`
    let candidate_raw = if trimmed.contains('|') {
        trimmed
            .split('|')
            .map(str::trim)
            .find(|seg| seg.contains('=') && (seg.contains(';') || infer_domain_from_cookie_name(seg.split('=').next().unwrap_or("")).is_some()))
            .unwrap_or(trimmed)
    } else {
        trimmed
    };
    let cookies = parse_semicolon_cookie_pairs(candidate_raw, fallback_url)?;
    let domains = collect_unique_domains(&cookies);
    Ok(NormalizedCookieBundle {
        format_label: "Raw Cookie String".to_string(),
        cookies,
        origins: Vec::new(),
        domains,
    })
}

pub fn read_prelaunch_cookies_in(root_dir: &Path, short_id: &str) -> String {
    let states_dir = root_dir.join("states");
    let pre_path = states_dir.join(format!("bon_{short_id}_prelaunch.json"));
    if let Ok(s) = std::fs::read_to_string(&pre_path)
        && !s.trim().is_empty()
    {
        return s;
    }
    String::new()
}


pub fn save_prelaunch_cookies_in(root_dir: &Path, short_id: &str, raw: &str) -> Result<()> {
    let dir = root_dir.join("states");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("bon_{short_id}_prelaunch.json"));
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        let _ = std::fs::remove_file(path);
    } else if let Ok(bundle) = parse_and_normalize_cookies(trimmed, None) {
        std::fs::write(path, bundle.to_state_json_pretty())?;
    } else {
        std::fs::write(path, trimmed)?;
    }
    Ok(())
}

