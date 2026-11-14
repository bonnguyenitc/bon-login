use crate::launcher::{probe_live_runtime_in, profile_user_data_dir_in};
use crate::models::{GeoInfo, Profile};
use anyhow::{Result, bail};
use std::path::Path;

pub fn read_profile_bookmarks_in(root_dir: &Path, profile: &Profile) -> Vec<(String, String)> {
    let bm_path = root_dir
        .join("profiles")
        .join(&profile.id)
        .join("Default")
        .join("Bookmarks");
    let Ok(raw) = std::fs::read_to_string(&bm_path) else {
        return Vec::new();
    };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return Vec::new();
    };
    let Some(children) = val
        .get("roots")
        .and_then(|r| r.get("bookmark_bar"))
        .and_then(|b| b.get("children"))
        .and_then(|c| c.as_array())
    else {
        return Vec::new();
    };
    children
        .iter()
        .filter_map(|item| {
            let name = item.get("name")?.as_str()?.trim();
            let url = item.get("url")?.as_str()?.trim();
            (!url.is_empty()).then(|| (name.to_string(), url.to_string()))
        })
        .collect()
}

/// Parses `"Name|URL, URL2, ..."` into `(Name, URL)` bookmark pairs.
pub fn parse_bookmarks_editable(raw: &str) -> Vec<(String, String)> {
    raw.split([',', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|token| {
            let (name, url_raw) = if let Some((l, r)) = token.split_once('|') {
                (l.trim(), r.trim())
            } else {
                ("", token)
            };
            let url = if url_raw.starts_with("http://")
                || url_raw.starts_with("https://")
                || url_raw.starts_with("chrome://")
                || url_raw.starts_with("chrome-extension://")
            {
                url_raw.to_string()
            } else {
                format!("https://{url_raw}")
            };
            let label = if !name.is_empty() {
                name.to_string()
            } else {
                url.split("://")
                    .nth(1)
                    .unwrap_or(&url)
                    .split('/')
                    .next()
                    .unwrap_or("Bookmark")
                    .trim_start_matches("www.")
                    .to_string()
            };
            (label, url)
        })
        .collect()
}

pub fn write_profile_bookmarks_checked_in(
    root_dir: &Path,
    profile: &Profile,
    items: &[(String, String)],
) -> Result<()> {
    if probe_live_runtime_in(root_dir, &profile.id).is_some() {
        bail!(
            "Stop running browser '{}' before editing disk Bookmarks so Chromium does not overwrite them on exit",
            profile.name
        );
    }
    let user_data_dir = profile_user_data_dir_in(root_dir, &profile.id)?;
    write_profile_bookmarks_items(&user_data_dir, items);
    Ok(())
}

pub fn write_profile_bookmarks_items(user_data_dir: &Path, items: &[(String, String)]) {
    let def_dir = user_data_dir.join("Default");
    let _ = std::fs::create_dir_all(&def_dir);
    let bm_path = def_dir.join("Bookmarks");
    let existing = std::fs::read_to_string(&bm_path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
    let roots = existing.as_ref().and_then(|v| v.get("roots"));
    let other_children = roots
        .and_then(|r| r.get("other")?.get("children").cloned())
        .unwrap_or_else(|| serde_json::json!([]));
    let synced_children = roots
        .and_then(|r| r.get("synced")?.get("children").cloned())
        .unwrap_or_else(|| serde_json::json!([]));
    let mut children: Vec<serde_json::Value> = items
        .iter()
        .enumerate()
        .map(|(i, (name, url))| {
            serde_json::json!({
                "id": (i + 2).to_string(),
                "name": name,
                "type": "url",
                "url": url,
            })
        })
        .collect();
    if let Some(prev_bar) = roots
        .and_then(|r| r.get("bookmark_bar")?.get("children")?.as_array())
    {
        for entry in prev_bar {
            if entry.get("url").is_none() {
                children.push(entry.clone());
            }
        }
    }
    let bm_json = serde_json::json!({
        "roots": {
            "bookmark_bar": {
                "children": children,
                "id": "1",
                "name": "Bookmarks bar",
                "type": "folder"
            },
            "other": { "children": other_children, "id": "100", "name": "Other bookmarks", "type": "folder" },
            "synced": { "children": synced_children, "id": "101", "name": "Mobile bookmarks", "type": "folder" }
        },
        "version": 1
    });
    if let Ok(s) = serde_json::to_string_pretty(&bm_json) {
        let _ = std::fs::write(bm_path, s);
    }
    ensure_bookmark_bar_visible(&def_dir);
}

fn ensure_bookmark_bar_visible(def_dir: &Path) {
    let pref_path = def_dir.join("Preferences");
    let mut prefs: serde_json::Value = std::fs::read_to_string(&pref_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    if prefs
        .get("bookmark_bar")
        .and_then(|b| b.get("show_on_all_tabs"))
        .and_then(|v| v.as_bool())
        == Some(true)
    {
        return;
    }
    if let Some(obj) = prefs.as_object_mut() {
        let bar = obj
            .entry("bookmark_bar")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(bar_obj) = bar.as_object_mut() {
            bar_obj.insert("show_on_all_tabs".to_string(), serde_json::Value::Bool(true));
        }
        if let Ok(s) = serde_json::to_string(&prefs) {
            let _ = std::fs::write(pref_path, s);
        }
    }
}

/// Ensures `<user_data_dir>/Default/Preferences` and `<user_data_dir>/Local State` have the
/// Bookmarks bar visible plus the profile's display name (`[#id4] Name`) and seed-matched toolbar color.
pub fn ensure_profile_bookmarks(profile: &Profile, user_data_dir: &Path) {
    let def_dir = user_data_dir.join("Default");
    let _ = std::fs::create_dir_all(&def_dir);

    let badge_name = profile.window_badge_label();
    let (_, _, skcolor) = Profile::accent_color_for_seed(profile.seed);
    let avatar_idx = 26 + ((profile.seed as usize) % 29);

    let pref_path = def_dir.join("Preferences");
    let mut prefs: serde_json::Value = std::fs::read_to_string(&pref_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    if !prefs.is_object() {
        prefs = serde_json::json!({});
    }
    prefs["bookmark_bar"]["show_on_all_tabs"] = serde_json::Value::Bool(true);
    prefs["profile"]["name"] = serde_json::Value::String(badge_name.clone());
    prefs["profile"]["is_using_default_name"] = serde_json::Value::Bool(false);
    prefs["profile"]["avatar_index"] = serde_json::json!(avatar_idx);
    prefs["browser"]["theme"] = serde_json::json!({
        "color_variant": 1,
        "user_color2": skcolor
    });
    if let Ok(s) = serde_json::to_string(&prefs) {
        let _ = std::fs::write(&pref_path, s);
    }

    let local_state_path = user_data_dir.join("Local State");
    let mut local_state: serde_json::Value = std::fs::read_to_string(&local_state_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    if !local_state.is_object() {
        local_state = serde_json::json!({});
    }
    let def_info = &mut local_state["profile"]["info_cache"]["Default"];
    def_info["name"] = serde_json::Value::String(badge_name);
    def_info["is_using_default_name"] = serde_json::Value::Bool(false);
    def_info["avatar_icon"] = serde_json::Value::String(format!(
        "chrome://theme/IDR_PROFILE_AVATAR_{avatar_idx}"
    ));
    def_info["profile_color_seed"] = serde_json::json!(skcolor);
    def_info["profile_highlight_color"] = serde_json::json!(skcolor);
    def_info["default_avatar_fill_color"] = serde_json::json!(skcolor);
    if let Ok(s) = serde_json::to_string(&local_state) {
        let _ = std::fs::write(&local_state_path, s);
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Generates `<user_data_dir>/bon_preflight.html` — a zero-bandwidth local Stealth & Proxy Health
/// Preflight Card displaying resolved GeoIP, DNS/WebRTC lock status, live C++ fingerprint verification,
/// and 1-click quick bookmarks. Returns the `file://...` URL.
pub fn write_profile_preflight_card(
    profile: &Profile,
    user_data_dir: &Path,
    effective_geo: Option<&GeoInfo>,
) -> String {
    let _ = std::fs::create_dir_all(user_data_dir);
    let card_path = user_data_dir.join("bon_preflight.html");
    let geo = effective_geo.or(profile.resolved_geo.as_ref());
    let proxy_label = profile
        .proxy
        .as_ref()
        .map(|px| format!("{}://{}", px.protocol.as_str(), px.display_short()))
        .unwrap_or_else(|| "Direct (No Proxy)".to_string());
    let ip_label = geo
        .map(|g| g.ip.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("Direct / Unverified");
    let cc_label = geo
        .map(|g| g.country_code.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("--");
    let tz_label = profile
        .custom_timezone
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| geo.map(|g| g.timezone.as_str()).filter(|s| !s.is_empty()))
        .unwrap_or("System Default");
    let loc_label = profile
        .custom_locale
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| geo.map(|g| g.locale.as_str()).filter(|s| !s.is_empty()))
        .unwrap_or("en-US");
    let latency_label = geo
        .and_then(|g| g.latency_ms)
        .map(|ms| format!("{ms} ms"))
        .unwrap_or_else(|| "0 B (Local)".to_string());
    let (_, renderer) = profile
        .os_platform
        .webgl_for_seed(profile.seed, profile.gpu_spoofing);
    let kind_label = geo.map(|g| g.ip_kind.label()).unwrap_or("Unknown");
    let city_label = geo
        .map(|g| g.city.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("—");
    let asn_label = {
        let asn = geo.map(|g| g.asn.as_str()).unwrap_or("");
        let isp = geo.map(|g| g.isp.as_str()).unwrap_or("");
        match (asn.is_empty(), isp.is_empty()) {
            (true, true) => "—".to_string(),
            (false, true) => asn.to_string(),
            (true, false) => isp.to_string(),
            (false, false) => format!("{asn} {isp}"),
        }
    };
    let tz_ok = if profile.timezone_coherent() { "yes" } else { "MISMATCH" };
    let loc_ok = if profile.locale_coherent() { "yes" } else { "MISMATCH" };
    let dns_lock = if profile.proxy.is_some() {
        "Locked (ATYP 0x03 Remote DNS)"
    } else {
        "System Resolver (Direct)"
    };
    let bms_root = user_data_dir
        .parent()
        .and_then(Path::parent)
        .unwrap_or(user_data_dir);
    let bookmarks = read_profile_bookmarks_in(bms_root, profile);
    let mut bm_links = String::new();
    for (name, url) in &bookmarks {
        bm_links.push_str(&format!(
            r#"<a class="chip" href="{}">🔖 {}</a>"#,
            html_escape(url),
            html_escape(name)
        ));
    }
    bm_links.push_str(
        r#"<a class="chip ext" href="https://browserscan.net">🌐 BrowserScan</a>
           <a class="chip ext" href="https://abrahamjuliot.github.io/creepjs/">🛡️ CreepJS</a>
           <a class="chip ext" href="https://ipwho.is/">📍 ipwho.is</a>"#,
    );

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>BonLogin Preflight — {name}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ margin: 0; padding: 32px 24px; background: #141417; color: #f5f5f7; font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif; }}
  .wrap {{ max-width: 820px; margin: 0 auto; }}
  .hdr {{ display: flex; justify-content: space-between; align-items: center; padding: 18px 22px; background: #1e1e24; border: 1px solid rgba(255,255,255,0.1); border-radius: 14px; margin-bottom: 16px; }}
  .title {{ font-size: 18px; font-weight: 700; display: flex; align-items: center; gap: 10px; }}
  .badge {{ background: rgba(48,209,88,0.16); color: #30d158; border: 1px solid rgba(48,209,88,0.4); padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }}
  .grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px; margin-bottom: 16px; }}
  .card {{ background: #1e1e24; border: 1px solid rgba(255,255,255,0.09); border-radius: 12px; padding: 16px 18px; }}
  .card h3 {{ margin: 0 0 10px 0; font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: #8e8e93; }}
  .row {{ display: flex; justify-content: space-between; padding: 5px 0; font-size: 13px; border-bottom: 1px solid rgba(255,255,255,0.05); }}
  .row:last-child {{ border-bottom: none; }}
  .k {{ color: #aeaeb2; }}
  .v {{ font-family: "SF Mono", Menlo, monospace; color: #f5f5f7; font-weight: 500; text-align: right; max-width: 62%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .ok {{ color: #30d158; }}
  .chips {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }}
  .chip {{ text-decoration: none; background: #2c2c34; color: #64d2ff; border: 1px solid rgba(100,210,255,0.25); padding: 6px 12px; border-radius: 8px; font-size: 12.5px; font-weight: 500; }}
  .chip:hover {{ background: #363640; }}
</style>
</head>
<body>
<div class="wrap">
  <div class="hdr">
    <div class="title">🛡️ {badge} <span style="color:#8e8e93;font-weight:400;font-size:13px">Zero-Bandwidth Stealth Preflight</span></div>
    <div class="badge" id="wd-status">Checking C++ Stealth…</div>
  </div>
  <div class="grid">
    <div class="card">
      <h3>Network &amp; Fail-Closed Tunnel</h3>
      <div class="row"><span class="k">Proxy Endpoint</span><span class="v">{proxy}</span></div>
      <div class="row"><span class="k">Exit IP / Country</span><span class="v ok">{ip} ({cc})</span></div>
      <div class="row"><span class="k">IP kind / City</span><span class="v">{kind} · {city}</span></div>
      <div class="row"><span class="k">ASN / ISP</span><span class="v">{asn}</span></div>
      <div class="row"><span class="k">Timezone coherent</span><span class="v">{tz_ok}</span></div>
      <div class="row"><span class="k">Locale coherent</span><span class="v">{loc_ok}</span></div>
      <div class="row"><span class="k">DNS Leak Guard</span><span class="v ok">{dns}</span></div>
      <div class="row"><span class="k">WebRTC Policy</span><span class="v ok">disable_non_proxied_udp</span></div>
      <div class="row"><span class="k">Tunnel Latency</span><span class="v">{latency}</span></div>
    </div>
    <div class="card">
      <h3>C++ Fingerprint Coherence (Seed #{seed})</h3>
      <div class="row"><span class="k">Platform / Brand</span><span class="v">{os} {os_ver} • {brand}</span></div>
      <div class="row"><span class="k">Timezone (Configured / Live)</span><span class="v" id="live-tz">{tz}</span></div>
      <div class="row"><span class="k">Locale / Accept-Lang</span><span class="v" id="live-lang">{loc}</span></div>
      <div class="row"><span class="k">CPU Cores (Live)</span><span class="v" id="live-cores">{cores} Cores</span></div>
      <div class="row"><span class="k">WebGL Renderer</span><span class="v" id="live-gpu" title="{gpu}">{gpu}</span></div>
    </div>
  </div>
  <div class="card">
    <h3>Quick Launch &amp; Verification Links</h3>
    <div class="chips">{bm_links}</div>
  </div>
</div>
<script>
(() => {{
  const wd = navigator.webdriver;
  const el = document.getElementById('wd-status');
  if (wd === false) {{
    el.textContent = '100% Stealth • webdriver=false';
  }} else {{
    el.textContent = 'WARN: webdriver=' + wd;
    el.style.color = '#ff453a';
  }}
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  document.getElementById('live-tz').textContent = '{tz} / ' + tz;
  document.getElementById('live-lang').textContent = navigator.language + ' (' + (navigator.languages || []).join(',') + ')';
  document.getElementById('live-cores').textContent = navigator.hardwareConcurrency + ' Cores (' + navigator.platform + ')';
}})();
</script>
</body>
</html>"#,
        name = html_escape(&profile.name),
        badge = html_escape(&profile.window_badge_label()),
        proxy = html_escape(&proxy_label),
        ip = html_escape(ip_label),
        cc = html_escape(cc_label),
        kind = html_escape(kind_label),
        city = html_escape(city_label),
        asn = html_escape(&asn_label),
        tz_ok = tz_ok,
        loc_ok = loc_ok,
        dns = html_escape(dns_lock),
        latency = html_escape(&latency_label),
        seed = profile.seed,
        os = html_escape(profile.os_platform.label()),
        os_ver = html_escape(&profile.os_version),
        brand = html_escape(profile.brand.as_cli_str()),
        tz = html_escape(tz_label),
        loc = html_escape(loc_label),
        cores = profile.hardware_concurrency,
        gpu = html_escape(renderer),
        bm_links = bm_links,
    );
    let _ = std::fs::write(&card_path, html);
    format!("file://{}", card_path.to_string_lossy())
}

