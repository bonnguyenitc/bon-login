use crate::extensions::*;
use crate::flows::*;
use crate::launcher::*;
use crate::models::{
    BrowserBrand, BrowserExtension, GeoInfo, GpuSpoofMode, PlatformType, Profile, ProxyConfig,
    ProxyProtocol, RuntimeInfo, SavedProxy, unix_now,
};
use anyhow::{Context, Result, anyhow, bail};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Full Headless CLI Control Plane (`bon-login <command> ...`)
// ---------------------------------------------------------------------------

fn find_profile_by_query<'a>(profiles: &'a [Profile], query: &str) -> Result<&'a Profile> {
    let q = query.trim();
    if q.is_empty() {
        bail!("Profile identifier or name is required");
    }
    let stripped = q.strip_prefix("bon_").unwrap_or(q);
    if let Some(p) = profiles.iter().find(|p| {
        p.id.eq_ignore_ascii_case(q)
            || p.short_id().eq_ignore_ascii_case(stripped)
            || p.name.eq_ignore_ascii_case(q)
    }) {
        return Ok(p);
    }
    let q_lower = q.to_ascii_lowercase();
    profiles
        .iter()
        .find(|p| p.name.to_ascii_lowercase().contains(&q_lower))
        .ok_or_else(|| anyhow!("No profile found matching '{query}'"))
}

fn find_saved_proxy_by_query<'a>(proxies: &'a [SavedProxy], query: &str) -> Result<&'a SavedProxy> {
    let q = query.trim();
    if q.is_empty() {
        bail!("Proxy identifier or name is required");
    }
    if let Some(p) = proxies.iter().find(|p| {
        let sid: String = p
            .id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(8)
            .collect();
        p.id.eq_ignore_ascii_case(q)
            || sid.eq_ignore_ascii_case(q)
            || p.name.eq_ignore_ascii_case(q)
            || p.config.display_short().eq_ignore_ascii_case(q)
    }) {
        return Ok(p);
    }
    let q_lower = q.to_ascii_lowercase();
    proxies
        .iter()
        .find(|p| {
            p.name.to_ascii_lowercase().contains(&q_lower)
                || p.config.host.to_ascii_lowercase().contains(&q_lower)
        })
        .ok_or_else(|| anyhow!("No saved proxy found matching '{query}' in Proxy Manager"))
}

fn find_extension_by_query<'a>(
    exts: &'a [BrowserExtension],
    query: &str,
) -> Result<&'a BrowserExtension> {
    let q = query.trim();
    if q.is_empty() {
        bail!("Extension ID or name is required");
    }
    if let Some(e) = exts.iter().find(|e| {
        e.id.eq_ignore_ascii_case(q)
            || e.name.eq_ignore_ascii_case(q)
            || (!e.source_url.is_empty() && e.source_url.eq_ignore_ascii_case(q))
    }) {
        return Ok(e);
    }
    let q_lower = q.to_ascii_lowercase();
    exts.iter()
        .find(|e| {
            e.id.to_ascii_lowercase().contains(&q_lower)
                || e.name.to_ascii_lowercase().contains(&q_lower)
        })
        .ok_or_else(|| anyhow!("No extension found matching '{query}'"))
}

fn parse_bool_flag(val: &str) -> Result<bool> {
    match val.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" | "enable" | "enabled" => Ok(true),
        "0" | "false" | "off" | "no" | "disable" | "disabled" => Ok(false),
        other => bail!("Invalid boolean value '{other}' (expected on/off or true/false)"),
    }
}

#[derive(Debug, Default)]
pub struct ParsedProfileCliFlags {
    pub cookies_raw: Option<String>,
    pub bookmarks: Option<Vec<(String, String)>>,
}

pub fn parse_profile_cli_flags(
    profile: &mut Profile,
    saved_proxies: &[SavedProxy],
    flags: &[String],
) -> Result<ParsedProfileCliFlags> {
    let mut parsed = ParsedProfileCliFlags::default();
    let mut idx = 0;
    while idx < flags.len() {
        let key = flags[idx].as_str();
        let next_val = || -> Result<&str> {
            flags
                .get(idx + 1)
                .map(String::as_str)
                .ok_or_else(|| anyhow!("Missing value for flag '{key}'"))
        };
        match key {
            "--name" => {
                profile.name = next_val()?.trim().to_string();
                idx += 2;
            }
            "--group" => {
                let g = next_val()?.trim();
                profile.group_tag = if g.eq_ignore_ascii_case("none") {
                    String::new()
                } else {
                    g.to_string()
                };
                idx += 2;
            }
            "--os" => {
                profile.set_platform(PlatformType::from_str_lossy(next_val()?));
                idx += 2;
            }
            "--brand" => {
                profile.set_brand(BrowserBrand::from_str_lossy(next_val()?));
                idx += 2;
            }
            "--seed" => {
                let raw = next_val()?.trim();
                if raw.eq_ignore_ascii_case("random") {
                    profile.reseed();
                } else {
                    profile.set_seed(raw.parse().context("Invalid --seed integer")?);
                }
                idx += 2;
            }
            "--cores" => {
                profile.hardware_concurrency =
                    next_val()?.trim().parse().context("Invalid --cores")?;
                idx += 2;
            }
            "--gpu" => {
                let v = next_val()?.trim().to_ascii_lowercase();
                profile.gpu_spoofing = if v == "native" || v == "passthrough" {
                    GpuSpoofMode::NativePassthrough
                } else {
                    GpuSpoofMode::SeedGenerated
                };
                idx += 2;
            }
            "--canvas" => {
                profile.spoof_canvas = parse_bool_flag(next_val()?)?;
                idx += 2;
            }
            "--audio" => {
                profile.spoof_audio = parse_bool_flag(next_val()?)?;
                idx += 2;
            }
            "--font" => {
                profile.spoof_font = parse_bool_flag(next_val()?)?;
                idx += 2;
            }
            "--rects" => {
                profile.spoof_client_rects = parse_bool_flag(next_val()?)?;
                idx += 2;
            }
            "--window-size" => {
                profile.window_size = next_val()?.trim().to_string();
                idx += 2;
            }
            "--timezone" => {
                let tz = next_val()?.trim();
                profile.custom_timezone =
                    (!tz.is_empty() && !tz.eq_ignore_ascii_case("auto")).then(|| tz.to_string());
                idx += 2;
            }
            "--locale" => {
                let loc = next_val()?.trim();
                profile.custom_locale =
                    (!loc.is_empty() && !loc.eq_ignore_ascii_case("auto")).then(|| loc.to_string());
                idx += 2;
            }
            "--startup-url" | "--url" => {
                profile.startup_url = next_val()?.trim().to_string();
                idx += 2;
            }
            "--notes" => {
                profile.notes = next_val()?.to_string();
                idx += 2;
            }
            "--tags" => {
                profile.tags = Profile::parse_tags_csv(next_val()?);
                idx += 2;
            }
            "--totp" | "--2fa" => {
                profile.totp_secret = next_val()?.trim().to_string();
                idx += 2;
            }
            "--bookmarks" => {
                let raw = next_val()?.trim();
                let items = if raw.is_empty()
                    || raw.eq_ignore_ascii_case("none")
                    || raw.eq_ignore_ascii_case("clear")
                {
                    Vec::new()
                } else {
                    parse_bookmarks_editable(raw)
                };
                parsed.bookmarks = Some(items);
                idx += 2;
            }
            "--cookies" => {
                let raw = next_val()?;
                let payload = if Path::new(raw).is_file() {
                    std::fs::read_to_string(raw)?
                } else {
                    raw.to_string()
                };
                parsed.cookies_raw = Some(payload);
                idx += 2;
            }
            "--proxy" => {
                let p_q = next_val()?.trim();
                if p_q.is_empty()
                    || p_q.eq_ignore_ascii_case("none")
                    || p_q.eq_ignore_ascii_case("direct")
                {
                    profile.clear_proxy();
                } else {
                    let sp = find_saved_proxy_by_query(saved_proxies, p_q)?;
                    profile.assign_saved_proxy(sp);
                }
                idx += 2;
            }
            "--proxy-tag" => {
                let tag = next_val()?.trim().trim_start_matches('#');
                let pool: Vec<&SavedProxy> = saved_proxies
                    .iter()
                    .filter(|sp| sp.group_tag.eq_ignore_ascii_case(tag))
                    .collect();
                if pool.is_empty() {
                    bail!("No saved proxies found in Proxy Manager with tag '{tag}'");
                }
                let chosen = pool[(profile.seed as usize) % pool.len()];
                profile.assign_saved_proxy(chosen);
                idx += 2;
            }
            other => bail!("Unknown profile flag '{other}'"),
        }
    }
    if let Some(raw) = &parsed.cookies_raw
        && !raw.trim().is_empty()
    {
        parse_and_normalize_cookies(raw, Some(&profile.startup_url))?;
    }
    Ok(parsed)
}

fn profile_summary_json_in(root_dir: &Path, p: &Profile) -> serde_json::Value {
    let sid = p.short_id();
    let session = format!("bon_{sid}");
    let live = probe_live_runtime_in(root_dir, &p.id);
    serde_json::json!({
        "id": p.id,
        "short_id": sid,
        "session": session,
        "name": p.name,
        "group": p.group_tag,
        "seed": p.seed,
        "os": p.os_platform.as_cli_str(),
        "os_version": p.os_version,
        "brand": p.brand.as_cli_str(),
        "brand_version": p.brand_version,
        "cores": p.hardware_concurrency,
        "gpu": p.gpu_spoofing.as_str(),
        "window_size": p.window_size,
        "proxy": p.proxy.as_ref().map(|px| px.display_short()).unwrap_or_else(|| "Direct".to_string()),
        "geo": p.resolved_geo.as_ref().map(|g| serde_json::json!({
            "ip": g.ip,
            "country": g.country_code,
            "timezone": g.timezone,
            "locale": g.locale,
            "latency_ms": g.latency_ms,
        })),
        "startup_url": p.startup_url,
        "notes": p.notes,
        "running": live.is_some(),
        "pid": live.as_ref().map(|r| r.pid),
        "cdp_port": live.as_ref().map(|r| r.cdp_port),
        "ws_url": live.as_ref().map(|r| r.ws_url.clone()),
        "download_dir": root_dir.join("downloads").join(format!("bon_{sid}")),
        "cli": format!("agent-browser --session {session} snapshot -i -c"),
    })
}

fn saved_proxy_summary_json(p: &SavedProxy) -> serde_json::Value {
    let sid: String = p
        .id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(8)
        .collect();
    serde_json::json!({
        "id": p.id,
        "short_id": sid,
        "name": p.name,
        "tag": p.group_tag,
        "protocol": p.config.protocol.as_str(),
        "host": p.config.host,
        "port": p.config.port,
        "display": p.config.display_short(),
        "editable": p.config.to_editable_string(),
        "has_auth": p.config.username.is_some(),
        "geo": p.resolved_geo,
        "last_error": p.last_error,
        "started_at": p.format_started_at(),
        "expired_at": p.expired_at,
        "expired_label": p.format_expired_at(),
    })
}

pub fn ensure_profile_launched_via_supervisor(
    db: &crate::db::Database,
    profile: &Profile,
) -> Result<RuntimeInfo> {
    if let Some(info) = db.probe_live_runtime(&profile.id) {
        return Ok(info);
    }

    let err_file = launch_error_file_path_in(db.root_dir(), &profile.id);
    let _ = std::fs::remove_file(&err_file);

    let exe = std::env::current_exe().context("Failed to resolve current executable path")?;
    let mut child = Command::new(exe)
        .env("BONLOGIN_DATA_DIR", db.root_dir())
        .args(["--hold-profile", &profile.id])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("Failed to spawn background profile supervisor")?;

    for _ in 0..80 {
        if let Ok(err_txt) = std::fs::read_to_string(&err_file)
            && !err_txt.trim().is_empty()
        {
            let _ = std::fs::remove_file(&err_file);
            bail!("{}", err_txt.trim());
        }
        if let Some(info) = db.probe_live_runtime(&profile.id)
            && info.pid > 0
        {
            let sid = profile.short_id();
            let _ = ensure_agent_browser_connected_in(db.root_dir(), &sid, &info.ws_url);
            return Ok(info);
        }
        if let Ok(Some(status)) = child.try_wait() {
            if let Ok(err_txt) = std::fs::read_to_string(&err_file)
                && !err_txt.trim().is_empty()
            {
                let _ = std::fs::remove_file(&err_file);
                bail!("{}", err_txt.trim());
            }
            bail!("Supervisor exited early with status {status}");
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    bail!("Timed out (12s) waiting for profile '{}' to launch", profile.name)
}

pub async fn check_proxy_config_live(cfg: &ProxyConfig) -> Result<GeoInfo> {
    let mut tun = crate::proxy_tunnel::LocalProxyTunnel::start(cfg.clone()).await?;
    let port = tun.local_port();
    let res = crate::geoip::resolve_geo_via_port(Some(port)).await;
    tun.stop();
    res
}

pub async fn check_free_proxy_config_fast(cfg: &ProxyConfig) -> Result<GeoInfo> {
    let mut tun = crate::proxy_tunnel::LocalProxyTunnel::start(cfg.clone()).await?;
    let port = tun.local_port();
    let res = crate::geoip::resolve_geo_via_port_fast(port).await;
    tun.stop();
    res
}

pub async fn discover_free_proxies(
    protocol: Option<ProxyProtocol>,
    country: Option<&str>,
    search_query: &str,
    limit: usize,
    verify: bool,
) -> Result<Vec<crate::models::FreeProxyCandidate>> {
    let all = crate::geoip::fetch_free_proxy_candidates().await?;
    let cc_filter = country.unwrap_or("All");
    let mut matched: Vec<crate::models::FreeProxyCandidate> = all
        .into_iter()
        .filter(|fp| fp.matches_filter(search_query, protocol, cc_filter, false))
        .collect();
    if !verify {
        matched.truncate(limit);
        return Ok(matched);
    }
    let scan_cap = (limit * 4).clamp(16, 48);
    matched.truncate(scan_cap);
    let mut set = tokio::task::JoinSet::new();
    for mut fp in matched {
        set.spawn(async move {
            if let Ok(geo) = check_free_proxy_config_fast(&fp.config).await {
                fp.country_code = geo.country_code.clone();
                fp.timezone = geo.timezone.clone();
                fp.verified_geo = Some(geo);
                Some(fp)
            } else {
                None
            }
        });
    }
    let mut live = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(Some(fp)) = res {
            live.push(fp);
            if live.len() >= limit {
                set.abort_all();
                break;
            }
        }
    }
    live.sort_by(|a, b| {
        a.effective_latency_ms()
            .unwrap_or(9999)
            .cmp(&b.effective_latency_ms().unwrap_or(9999))
    });
    Ok(live)
}

pub async fn rotate_and_check_proxy_live(cfg: &ProxyConfig) -> Result<(String, GeoInfo)> {
    let url = cfg
        .change_ip_url
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| anyhow!("Proxy has no rotation URL (append |http://... to proxy string)"))?;
    let rotate_msg = crate::geoip::trigger_proxy_rotation(url).await?;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let geo = check_proxy_config_live(cfg).await?;
    Ok((rotate_msg, geo))
}
pub async fn check_or_rotate_profile_proxy(
    db: &std::sync::Mutex<crate::db::Database>,
    profile: &Profile,
    rotate: bool,
) -> Result<(Option<String>, GeoInfo)> {
    let res = if let Some(cfg) = &profile.proxy {
        if rotate {
            rotate_and_check_proxy_live(cfg)
                .await
                .map(|(m, g)| (Some(m), g))
        } else {
            check_proxy_config_live(cfg).await.map(|g| (None, g))
        }
    } else if rotate {
        bail!("Profile has no proxy configured");
    } else {
        crate::geoip::resolve_geo_via_port(None)
            .await
            .map(|g| (None, g))
    };
    if let Ok((_, ref geo)) = res
        && let Ok(db_guard) = db.lock()
    {
        if let Some(cfg) = &profile.proxy {
            let _ = db_guard.sync_geo_for_proxy_endpoint(cfg, geo);
        }
        let _ = db_guard.update_resolved_geo(&profile.id, Some(geo));
    }
    res
}

pub async fn check_or_rotate_saved_proxy(
    db: &std::sync::Mutex<crate::db::Database>,
    sp: &SavedProxy,
    rotate: bool,
) -> Result<(Option<String>, GeoInfo)> {
    let res = if rotate {
        rotate_and_check_proxy_live(&sp.config)
            .await
            .map(|(m, g)| (Some(m), g))
    } else {
        check_proxy_config_live(&sp.config).await.map(|g| (None, g))
    };
    match &res {
        Ok((_, geo)) => {
            if let Ok(db_guard) = db.lock() {
                let _ = db_guard.sync_geo_for_proxy_endpoint(&sp.config, geo);
            }
        }
        Err(e) => {
            if let Ok(db_guard) = db.lock() {
                let _ = db_guard.update_saved_proxy_check(&sp.id, None, Some(&e.to_string()));
            }
        }
    }
    res
}

pub fn tile_window_targets(
    targets: &[(u16, String)],
    mon_rect: (i32, i32, i32, i32),
    win_w: i32,
    win_h: i32,
) -> (usize, usize, i32, i32) {
    let total = targets.len();
    if total == 0 {
        return (0, 0, win_w, win_h);
    }
    let (mon_x, mon_y, mon_w, mon_h) = mon_rect;
    let placements = compute_tile_work_area_bounds(mon_x, mon_y, mon_w, mon_h, win_w, win_h, total);
    let (applied_w, applied_h) = placements
        .first()
        .map(|&(_, _, w, h)| (w, h))
        .unwrap_or((win_w, win_h));
    let pairs: Vec<_> = targets.iter().zip(placements.iter()).collect();
    let arranged = parallel_map(&pairs, |((port, ws_url), (l, t, w, h))| {
        cdp_set_window_bounds(*port, ws_url, *l, *t, *w, *h).is_ok()
    })
    .into_iter()
    .filter(|&ok| ok)
    .count();
    (arranged, total, applied_w, applied_h)
}

pub fn arrange_running_windows_on_display_in(
    root_dir: &Path,
    profiles: &[Profile],
    display_idx: usize,
    win_w: i32,
    win_h: i32,
) -> (usize, usize, i32, i32) {
    let targets: Vec<(u16, String)> =
        parallel_map(profiles, |p| probe_live_runtime_in(root_dir, &p.id))
            .into_iter()
            .flatten()
            .map(|rt| (rt.cdp_port, rt.ws_url))
            .collect();
    let mon_rect = macos_display_rect(display_idx);
    tile_window_targets(&targets, mon_rect, win_w, win_h)
}


fn attach_launched_session_in(
    root_dir: &Path,
    short_id: &str,
    ws_url: &str,
    pin_tab: Option<&str>,
    open_url: Option<&str>,
) -> Result<String> {
    if let Some(tag) = pin_tab {
        ensure_agent_browser_pinned_tab_in(root_dir, short_id, tag, ws_url, open_url)
    } else {
        let s = ensure_agent_browser_connected_in(root_dir, short_id, ws_url)?;
        if let Some(u) = open_url.filter(|u| !u.trim().is_empty()) {
            let _ = agent_browser_cmd_for_short_id_in(root_dir, short_id)
                .args(["--session", &s, "open", u.trim()])
                .output();
        }
        Ok(s)
    }
}

fn print_cli_help() {
    println!(
        "BonLogin — Full CLI & Agent-Browser Control Plane\n\n\
         BROWSER & AGENT CONTROL:\n  \
           bon-login                                                     Open GPUI Desktop App\n  \
           bon-login list [--group <g>] [--search <q>]                   List profiles & live CDP/Agent status (JSON)\n  \
           bon-login launch <id|name|--group <g>|--all> [--pin-tab <t>] [--url <u>] Launch profile(s) & connect agent-browser\n  \
           bon-login stop <id|name|--group <g>|--all>                    Stop running profile(s) & flush cookies\n  \
           bon-login sync <id|name>                                      Sync OAuth popups & extension windows into tabs\n  \
           bon-login arrange [--size <W,H>] [--display <1..N>]           Tile all running browser windows into a screen grid\n  \
           bon-login focus <id|name>                                     Bring running browser window to the front on macOS\n  \
           bon-login type <id|name> <text...>                            Human-type text into focused input via CDP (bypass paste block)\n  \
           bon-login totp <id|name> [--type]                             Generate 6-digit 2FA code (and optionally type into browser)\n  \
           bon-login screenshot <id|name> [--out <file>]                 Capture PNG screenshot of running profile via CDP\n  \
           bon-login broadcast <open|type|totp> [val] [--group <g>]      Sync navigation/typing/2FA across running profiles\n  \
           bon-login serve [--port <19820>]                              Start local HTTP JSON control plane for n8n/Python/agents\n  \
           bon-login agent <id|name> [--record <flow>] <ab args...>      Run agent-browser (auto-records DOM steps)\n\n\
         AGENT FLOW PLAYBOOKS (`bon-login flow ...`):\n  \
           bon-login flow list                                           List saved DOM flows & required {{vars}}\n  \
           bon-login flow show <flow_name>                               Show steps & locators of a saved flow\n  \
           bon-login flow save <flow_name> <id|name> [--var k=literal]   Save profile's recent agent steps as reusable flow\n  \
           bon-login flow run <flow_name> <id|name|--group <g>|--all> [--var k=v] [--from-step <n>]\n  \
           bon-login flow heal <flow_name> <step_idx> <id|name> <ab args...>  Self-heal broken step & update flow\n  \
           bon-login flow step <flow_name> <step_idx> <optional|required|delete>\n  \
           bon-login flow history <id|name> [--clear]                    Inspect or clear auto-recorded profile steps\n  \
           bon-login flow delete <flow_name>                             Delete a saved flow\n\n\
         PROFILE MANAGEMENT (`bon-login profile ...`):\n  \
           bon-login profile list [--group <g>] [--search <q>]\n  \
           bon-login profile show <id|name>\n  \
           bon-login profile create <name> [--os macos|windows|linux] [--brand chrome|edge]\n                            [--group <g>] [--tags <t1,t2>] [--totp <secret>] [--proxy <saved_proxy|none>]\n                            [--proxy-tag <tag>] [--seed <u32|random>] [--cores <n>] [--gpu native|seed]\n                            [--canvas on|off] [--audio on|off] [--font on|off] [--rects on|off]\n                            [--window-size <W,H>] [--timezone <tz|auto>] [--locale <loc|auto>]\n                            [--startup-url <url>] [--notes <txt>] [--bookmarks <Name|URL,...>] [--cookies <file_or_json>]\n  \
           bon-login profile update <id|name|--group <g>|--all> [same flags as create]\n  \
           bon-login profile bookmarks <id|name> [list|add <Name|URL>|clear]\n  \
           bon-login profile reseed <id|name|--group <g>|--all>\n  \
           bon-login profile clone <id|name> [--count <n>] [--name <prefix>]\n  \
           bon-login profile batch-create --count <n> [--prefix <p>] [--group <g>] [--os <os>] [--brand <b>] [--proxy-tag <tag>]\n  \
           bon-login profile check-proxy <id|name|--group <g>|--all>\n  \
           bon-login profile rotate-proxy <id|name|--group <g>|--all>\n  \
           bon-login profile clean-cache <id|name|--group <g>|--all>\n  \
           bon-login profile warmup <id|name|--group <g>|--all> [url1,url2...] [--dwell <secs>]\n  \
           bon-login profile export-cookies <id|name> [--out <file>]\n  \
           bon-login profile import-cookies <id|name> <file_or_json>\n  \
           bon-login profile export-zip <id|name|--group <g>|--all>      Export full profile archive (.zip with cookies & user-data)\n  \
           bon-login profile import-zip <zip_file>                       Restore profile from .zip archive\n  \
           bon-login profile export-csv [--out <file>]                   Export profiles to CSV\n  \
           bon-login profile import-csv <csv_or_tsv_file>                Bulk import profiles from CSV/TSV\n  \
           bon-login profile trash [list|restore <id|--all>|empty]       Manage soft-deleted profiles in Trash\n  \
           bon-login profile wipe <id|name|--group <g>|--all>\n  \
           bon-login profile delete <id|name|--group <g>|--all> [--permanent]\n  \
           bon-login profile backup [--out <file>]\n  \
           bon-login profile restore <file>\n\n\
         PROXY MANAGER (`bon-login proxy ...`):\n  \
           bon-login proxy list [--tag <t>]\n  \
           bon-login proxy free [--protocol socks5|http] [--country <CC>] [--search <q>] [--limit <n>] [--verify] [--save] [--tag <t>]\n  \
           bon-login proxy add <raw_proxy_or_file> [--protocol http|socks5] [--tag <t>] [--name <n>] [--expire <days_or_date>]\n  \
           bon-login proxy update <id|name|--tag <t>|--all> [--name <n>] [--tag <t>] [--expire <days_or_date|none>] [--rotate-url <url|none>]\n  \
           bon-login proxy check <id|name|--tag <t>|--all>\n  \
           bon-login proxy rotate <id|name|--tag <t>|--all>\n  \
           bon-login proxy extend <id|name|--tag <t>|--all> <days|0|clear>\n  \
           bon-login proxy assign <proxy_id_or_name|--tag <t>|--all|none> --to <profile_id|name|--group <g>|--all>\n  \
           bon-login proxy export [--tag <t>] [--out <file>]\n  \
           bon-login proxy delete <id|name|--tag <t>|--all>\n\n\
         GROUPS & TAGS (`bon-login group ...` / `bon-login tag ...`):\n  \
           bon-login group list | add <name> | delete <name> | move <id|name|--group <g>|--all> <group|none>\n  \
           bon-login tag list   | add <name> | delete <name>\n\n\
         EXTENSIONS (`bon-login ext ...`):\n  \
           bon-login ext list\n  \
           bon-login ext enable <id|name|--all> | disable <id|name|--all>\n  \
           bon-login ext add <file_or_folder_or_store_url_or_id>\n  \
           bon-login ext remove <id|name>\n  \
           bon-login ext open <ext_id|name> [--profile <profile_id|name>]\n\n\
         KERNEL (`bon-login kernel ...`):\n  \
           bon-login kernel status | check | install [--force]"
    );
}

pub fn build_tokio_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .on_thread_start(|| {
            unsafe extern "C" {
                fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
            }
            // QOS_CLASS_USER_INITIATED (0x19) schedules interactive workers on Apple Silicon P-cores
            unsafe {
                let _ = pthread_set_qos_class_self_np(0x19, 0);
            }
        })
        .build()
        .expect("Failed to start Tokio runtime")
}

fn cli_tokio_handle() -> &'static tokio::runtime::Handle {
    static CLI_RT: std::sync::LazyLock<tokio::runtime::Runtime> =
        std::sync::LazyLock::new(build_tokio_runtime);
    CLI_RT.handle()
}

pub fn try_run_cli() -> Option<Result<()>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first()?.as_str();

    Some((|| -> Result<()> {
        match cmd {
            "--hold-profile" => {
                let profile_id = args
                    .get(1)
                    .ok_or_else(|| anyhow!("Missing profile_id for --hold-profile"))?;
                let db = crate::db::Database::open_default()?;
                let profiles = db.list_profiles()?;
                let profile = find_profile_by_query(&profiles, profile_id)?.clone();
                let err_file = launch_error_file_path_in(db.root_dir(), &profile.id);
                let _ = std::fs::remove_file(&err_file);
                match cli_tokio_handle().block_on(launch_profile_in(db.root_dir(), &profile)) {
                    Ok((mut running, maybe_geo)) => {
                        RuntimeSupervisor::record_post_launch_db(
                            &db,
                            &profile,
                            maybe_geo.as_ref(),
                        );
                        let mut tick = 0u8;
                        loop {
                            if !running.is_process_running() {
                                break;
                            }
                            if tick.is_multiple_of(16) && !running.is_alive() {
                                break;
                            }
                            tick = tick.wrapping_add(1);
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        running.stop_gracefully();
                        Ok(())
                    }
                    Err(e) => {
                        let _ = db.profile_user_data_dir(&profile.id);
                        let _ = std::fs::write(&err_file, e.to_string());
                        Err(e)
                    }
                }
            }
            "list" | "ls" => run_profile_list_cli(&args[1..]),
            "launch" | "start" => run_launch_cli(&args[1..]),
            "stop" | "close" => run_stop_cli(&args[1..]),
            "sync" => {
                let target = args
                    .get(1)
                    .ok_or_else(|| anyhow!("Usage: bon-login sync <short_id|name>"))?;
                let db = crate::db::Database::open_default()?;
                let profiles = db.list_profiles()?;
                let p = find_profile_by_query(&profiles, target)?;
                let info = db.probe_live_runtime(&p.id).ok_or_else(|| {
                    anyhow!("Profile '{}' (bon_{}) is not running", p.name, p.short_id())
                })?;
                let res = agent_sync_targets_in(db.root_dir(), &p.short_id(), &info.ws_url)?;
                println!("{}", serde_json::to_string_pretty(&res)?);
                Ok(())
            }
            "focus" => {
                let target = args
                    .get(1)
                    .ok_or_else(|| anyhow!("Usage: bon-login focus <short_id|name>"))?;
                let db = crate::db::Database::open_default()?;
                let profiles = db.list_profiles()?;
                let p = find_profile_by_query(&profiles, target)?;
                let rt = db.probe_live_runtime(&p.id).ok_or_else(|| {
                    anyhow!("Profile '{}' (bon_{}) is not running", p.name, p.short_id())
                })?;
                cdp_focus_window_in(db.root_dir(), &p.id, rt.pid, rt.cdp_port, &rt.ws_url)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "short_id": p.short_id(),
                        "pid": rt.pid,
                        "focused": true,
                    }))?
                );
                Ok(())
            }
            "arrange" | "tile" => run_arrange_cli(&args[1..]),
            "type" | "human-type" => run_type_cli(&args[1..]),
            "totp" | "2fa" => run_totp_cli(&args[1..]),
            "screenshot" | "shot" => run_screenshot_cli(&args[1..]),
            "broadcast" | "multi" => run_broadcast_cli(&args[1..]),
            "serve" | "server" => cli_tokio_handle().block_on(run_serve_cli(&args[1..])),
            "agent" | "ab" => run_agent_cli(&args[1..]),
            "flow" | "flows" => run_flow_subcommand(&args[1..]),
            "profile" | "profiles" => run_profile_subcommand(&args[1..]),
            "proxy" | "proxies" => run_proxy_subcommand(&args[1..]),
            "group" | "groups" => run_group_subcommand(&args[1..]),
            "tag" | "tags" => run_tag_subcommand(&args[1..]),
            "ext" | "extension" | "extensions" => run_ext_subcommand(&args[1..]),
            "kernel" => run_kernel_subcommand(&args[1..]),
            "--help" | "-h" | "help" => {
                print_cli_help();
                Ok(())
            }
            other => bail!("Unknown command '{other}'. Run `bon-login --help` for usage."),
        }
    })())
}

fn run_profile_list_cli(args: &[String]) -> Result<()> {
    let mut group_filter: Option<String> = None;
    let mut search_query = String::new();
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "--group" => {
                group_filter = args.get(idx + 1).cloned();
                idx += 2;
            }
            "--search" | "-q" => {
                search_query = args.get(idx + 1).cloned().unwrap_or_default();
                idx += 2;
            }
            _ => idx += 1,
        }
    }
    let db = crate::db::Database::open_default()?;
    let profiles = db.list_profiles()?;
    let matched: Vec<&Profile> = profiles
        .iter()
        .filter(|p| p.matches_filter(&search_query, group_filter.as_deref()))
        .collect();
    let root = db.root_dir();
    let items: Vec<serde_json::Value> = parallel_map(&matched, |p| profile_summary_json_in(root, p));
    println!("{}", serde_json::to_string_pretty(&items)?);
    Ok(())
}

fn run_launch_cli(args: &[String]) -> Result<()> {
    let db = crate::db::Database::open_default()?;
    let profiles = db.list_profiles()?;
    let (targets, consumed) = select_profiles_by_target(&profiles, args).map_err(|_| {
        anyhow!("Usage: bon-login launch <short_id|name|--group <g>|--all> [--pin-tab <tag>] [--url <url>]")
    })?;
    let mut pin_tab: Option<String> = None;
    let mut open_url: Option<String> = None;
    let mut idx = consumed;
    while idx < args.len() {
        match args[idx].as_str() {
            "--pin-tab" => {
                pin_tab = args.get(idx + 1).cloned();
                idx += 2;
            }
            "--url" => {
                open_url = args.get(idx + 1).cloned();
                idx += 2;
            }
            _ => idx += 1,
        }
    }
    let mut results = Vec::new();
    for profile in targets {
        let short_id = profile.short_id();
        let info = ensure_profile_launched_via_supervisor(&db, &profile)?;
        let session = attach_launched_session_in(
            db.root_dir(),
            &short_id,
            &info.ws_url,
            pin_tab.as_deref(),
            open_url.as_deref(),
        )?;
        results.push(serde_json::json!({
            "ok": true,
            "id": profile.id,
            "short_id": short_id,
            "session": session,
            "name": profile.name,
            "pid": info.pid,
            "cdp_port": info.cdp_port,
            "ws_url": info.ws_url,
            "local_proxy_port": info.local_proxy_port,
            "download_dir": db.profile_download_dir(&short_id),
            "cli": format!("agent-browser --session {session} snapshot -i -c"),
        }));
    }
    if results.len() == 1 {
        println!("{}", serde_json::to_string_pretty(&results[0])?);
    } else {
        println!("{}", serde_json::to_string_pretty(&results)?);
    }
    Ok(())
}

fn run_stop_cli(args: &[String]) -> Result<()> {
    let db = crate::db::Database::open_default()?;
    let profiles = db.list_profiles()?;
    let is_all = args
        .first()
        .is_some_and(|f| f == "--all" || f == "all");
    let (targets, _) = select_profiles_by_target(&profiles, args).map_err(|_| {
        anyhow!("Usage: bon-login stop <short_id|name|--group <g>|--all>")
    })?;
    let root = db.root_dir();
    let stopped: Vec<String> = parallel_map(&targets, |p| {
        let sid = p.short_id();
        let did_stop = stop_external_runtime_in(root, &p.id, &sid);
        (did_stop || !is_all).then_some(sid)
    })
    .into_iter()
    .flatten()
    .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "ok": true,
            "stopped": stopped,
        }))?
    );
    Ok(())
}

fn select_profiles_by_target(
    profiles: &[Profile],
    args: &[String],
) -> Result<(Vec<Profile>, usize)> {
    let first = args
        .first()
        .ok_or_else(|| anyhow!("Missing profile target (<id|name|--group <g>|--all>)"))?;
    if first == "--all" || first == "all" {
        return Ok((profiles.to_vec(), 1));
    }
    if first == "--group" {
        let g = args
            .get(1)
            .ok_or_else(|| anyhow!("Missing group name after --group"))?;
        let matched: Vec<Profile> = profiles
            .iter()
            .filter(|p| p.group_tag.eq_ignore_ascii_case(g))
            .cloned()
            .collect();
        if matched.is_empty() {
            bail!("No profiles found in group '{g}'");
        }
        return Ok((matched, 2));
    }
    let mut out = Vec::new();
    for token in first.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        out.push(find_profile_by_query(profiles, token)?.clone());
    }
    Ok((out, 1))
}

fn run_profile_subcommand(args: &[String]) -> Result<()> {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    let rest = if args.is_empty() { &[] } else { &args[1..] };
    let db = crate::db::Database::open_default()?;

    match sub {
        "list" | "ls" => run_profile_list_cli(rest),
        "show" | "info" | "get" => {
            let target = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login profile show <id|name>"))?;
            let profiles = db.list_profiles()?;
            let p = find_profile_by_query(&profiles, target)?;
            let mut val = serde_json::to_value(p)?;
            if let Some(obj) = val.as_object_mut() {
                if let Some(proxy_obj) = obj.get_mut("proxy").and_then(|v| v.as_object_mut())
                    && proxy_obj.get("password").is_some_and(|pw| !pw.is_null())
                {
                    proxy_obj.insert("password".into(), serde_json::json!("***"));
                }
                let sid = p.short_id();
                let live = db.probe_live_runtime(&p.id);
                obj.insert("short_id".into(), serde_json::json!(sid));
                obj.insert("session".into(), serde_json::json!(format!("bon_{sid}")));
                obj.insert("running".into(), serde_json::json!(live.is_some()));
                obj.insert("live_runtime".into(), serde_json::json!(live));
                obj.insert(
                    "has_prelaunch_cookies".into(),
                    serde_json::json!(!db.read_prelaunch_cookies(&sid).trim().is_empty()),
                );
                let disk_bytes = db
                    .profile_user_data_dir(&p.id)
                    .ok()
                    .map(|d| dir_size_bytes(&d))
                    .unwrap_or(0);
                let bms: Vec<serde_json::Value> = db
                    .read_bookmarks(p)
                    .into_iter()
                    .map(|(n, u)| serde_json::json!({"name": n, "url": u}))
                    .collect();
                obj.insert("disk_bytes".into(), serde_json::json!(disk_bytes));
                obj.insert("disk_usage".into(), serde_json::json!(format_bytes(disk_bytes)));
                obj.insert("bookmarks".into(), serde_json::json!(bms));
                obj.insert(
                    "download_dir".into(),
                    serde_json::json!(db.profile_download_dir(&sid)),
                );
            }
            println!("{}", serde_json::to_string_pretty(&val)?);
            Ok(())
        }
        "create" | "add" | "new" => {
            let (name, flag_slice) = if let Some(first) = rest.first()
                && !first.starts_with('-')
            {
                (first.clone(), &rest[1..])
            } else {
                let existing = db.list_profiles()?.len();
                (format!("Profile-{:02}", existing + 1), rest)
            };
            let saved_proxies = db.list_proxies()?;
            let mut prof = Profile::new_default(name, PlatformType::MacOS);
            let parsed = parse_profile_cli_flags(&mut prof, &saved_proxies, flag_slice)?;
            db.save_profile_bundle(
                &prof,
                parsed.cookies_raw.as_deref(),
                parsed.bookmarks.as_deref(),
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&profile_summary_json_in(db.root_dir(), &prof))?
            );
            Ok(())
        }
        "update" | "edit" | "set" => {
            let profiles = db.list_profiles()?;
            let saved_proxies = db.list_proxies()?;
            let (mut targets, consumed) = select_profiles_by_target(&profiles, rest)?;
            let flags = &rest[consumed..];
            if flags.is_empty() {
                bail!("Usage: bon-login profile update <id|name|--group <g>|--all> [--os ... --proxy ...]");
            }
            let mut updated = Vec::new();
            for mut p in targets.drain(..) {
                let parsed = parse_profile_cli_flags(&mut p, &saved_proxies, flags)?;
                let norm = db.save_profile_bundle(
                    &p,
                    parsed.cookies_raw.as_deref(),
                    parsed.bookmarks.as_deref(),
                )?;
                if let (Some(live), Some(bundle)) = (db.probe_live_runtime(&p.id), norm) {
                    let _ = agent_import_state_or_cookies_in(
                        db.root_dir(),
                        &p.short_id(),
                        &live.ws_url,
                        &bundle.to_state_json_pretty(),
                    );
                }
                updated.push(profile_summary_json_in(db.root_dir(), &p));
            }
            if updated.len() == 1 {
                println!("{}", serde_json::to_string_pretty(&updated[0])?);
            } else {
                println!("{}", serde_json::to_string_pretty(&updated)?);
            }
            Ok(())
        }
        "clone" => {
            let target = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login profile clone <id|name> [--count <n>] [--name <prefix>]"))?;
            let mut count: usize = 1;
            let mut custom_name: Option<String> = None;
            let mut idx = 1;
            while idx < rest.len() {
                match rest[idx].as_str() {
                    "--count" | "-n" => {
                        count = rest
                            .get(idx + 1)
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(1)
                            .clamp(1, 500);
                        idx += 2;
                    }
                    "--name" => {
                        custom_name = rest.get(idx + 1).cloned();
                        idx += 2;
                    }
                    _ => idx += 1,
                }
            }
            let profiles = db.list_profiles()?;
            let src = find_profile_by_query(&profiles, target)?;
            let cloned = db.clone_profiles(src, count, custom_name.as_deref())?;
            let created: Vec<serde_json::Value> = cloned
                .iter()
                .map(|p| profile_summary_json_in(db.root_dir(), p))
                .collect();
            println!("{}", serde_json::to_string_pretty(&created)?);
            Ok(())
        }
        "batch-create" | "batch" => {
            let mut count: usize = 5;
            let mut prefix = "Account".to_string();
            let mut proxy_tag: Option<String> = None;
            let mut forwarded_flags = Vec::new();
            let mut idx = 0;
            while idx < rest.len() {
                match rest[idx].as_str() {
                    "--count" | "-n" => {
                        count = rest
                            .get(idx + 1)
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(5)
                            .clamp(1, 500);
                        idx += 2;
                    }
                    "--prefix" => {
                        prefix = rest.get(idx + 1).cloned().unwrap_or(prefix);
                        idx += 2;
                    }
                    "--proxy-tag" => {
                        proxy_tag = rest
                            .get(idx + 1)
                            .map(|s| s.trim().trim_start_matches('#').to_string());
                        idx += 2;
                    }
                    other => {
                        forwarded_flags.push(other.to_string());
                        if let Some(val) = rest.get(idx + 1)
                            && !matches!(val.as_str(), "--count" | "-n" | "--prefix" | "--proxy-tag")
                        {
                            forwarded_flags.push(val.clone());
                            idx += 2;
                        } else {
                            idx += 1;
                        }
                    }
                }
            }
            let saved_proxies = db.list_proxies()?;
            let proxy_pool: Vec<&SavedProxy> = if let Some(tag) = &proxy_tag {
                let pool: Vec<&SavedProxy> = saved_proxies
                    .iter()
                    .filter(|sp| sp.group_tag.eq_ignore_ascii_case(tag))
                    .collect();
                if pool.is_empty() {
                    bail!("No saved proxies found in Proxy Manager with tag '{tag}'");
                }
                pool
            } else {
                Vec::new()
            };
            let mut created = Vec::new();
            for i in 1..=count {
                let mut p = Profile::new_default(format!("{prefix}-{i:02}"), PlatformType::MacOS);
                let parsed = parse_profile_cli_flags(&mut p, &saved_proxies, &forwarded_flags)?;
                if !proxy_pool.is_empty() {
                    let sp = proxy_pool[(i - 1) % proxy_pool.len()];
                    p.assign_saved_proxy(sp);
                }
                db.save_profile_bundle(
                    &p,
                    parsed.cookies_raw.as_deref(),
                    parsed.bookmarks.as_deref(),
                )?;
                created.push(profile_summary_json_in(db.root_dir(), &p));
            }
            println!("{}", serde_json::to_string_pretty(&created)?);
            Ok(())
        }
        "reseed" | "new-fingerprint" => {
            let profiles = db.list_profiles()?;
            let (mut targets, _) = select_profiles_by_target(&profiles, rest)?;
            let mut reseeded = Vec::new();
            for mut p in targets.drain(..) {
                p.reseed();
                db.upsert_profile(&p)?;
                reseeded.push(profile_summary_json_in(db.root_dir(), &p));
            }
            if reseeded.len() == 1 {
                println!("{}", serde_json::to_string_pretty(&reseeded[0])?);
            } else {
                println!("{}", serde_json::to_string_pretty(&reseeded)?);
            }
            Ok(())
        }
        "check-proxy" | "rotate-proxy" | "rotate" => {
            let rotate = sub != "check-proxy";
            let profiles = db.list_profiles()?;
            let (targets, _) = select_profiles_by_target(&profiles, rest)?;
            let db_mtx = std::sync::Mutex::new(db);
            let mut out = Vec::new();
            let mut any_failed = false;
            for p in targets {
                match cli_tokio_handle()
                    .block_on(check_or_rotate_profile_proxy(&db_mtx, &p, rotate))
                {
                    Ok((rot_opt, geo)) => {
                        if let Some(rot_msg) = rot_opt {
                            out.push(serde_json::json!({
                                "id": p.id,
                                "short_id": p.short_id(),
                                "name": p.name,
                                "ok": true,
                                "rotation": rot_msg,
                                "geo": geo,
                            }));
                        } else {
                            out.push(serde_json::json!({
                                "id": p.id,
                                "short_id": p.short_id(),
                                "name": p.name,
                                "ok": true,
                                "mode": if p.proxy.is_some() { "Proxy" } else { "Direct" },
                                "geo": geo,
                            }));
                        }
                    }
                    Err(e) => {
                        any_failed = true;
                        let mut item = serde_json::json!({
                            "id": p.id,
                            "short_id": p.short_id(),
                            "name": p.name,
                            "ok": false,
                            "error": e.to_string(),
                        });
                        if !rotate && let Some(obj) = item.as_object_mut() {
                            obj.insert(
                                "mode".into(),
                                serde_json::json!(if p.proxy.is_some() { "Proxy" } else { "Direct" }),
                            );
                        }
                        out.push(item);
                    }
                }
            }
            println!("{}", serde_json::to_string_pretty(&out)?);
            if rotate && any_failed {
                std::process::exit(1);
            }
            Ok(())
        }
        "clean-cache" | "clean" => {
            let profiles = db.list_profiles()?;
            let (targets, _) = select_profiles_by_target(&profiles, rest).map_err(|_| {
                anyhow!("Usage: bon-login profile clean-cache <id|name|--group <g>|--all>")
            })?;
            let mut results = Vec::new();
            let mut total_freed = 0u64;
            for p in targets {
                let (freed, remaining) = db.clean_profile_cache(&p.id)?;
                total_freed = total_freed.saturating_add(freed);
                results.push(serde_json::json!({
                    "short_id": p.short_id(),
                    "name": p.name,
                    "freed_bytes": freed,
                    "freed_label": format_bytes(freed),
                    "remaining_bytes": remaining,
                    "remaining_label": format_bytes(remaining),
                }));
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "total_freed_bytes": total_freed,
                    "total_freed_label": format_bytes(total_freed),
                    "profiles": results,
                }))?
            );
            Ok(())
        }
        "export-cookies" | "export-state" => {
            let target = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login profile export-cookies <id|name> [--out <file>]"))?;
            let out_file = rest
                .windows(2)
                .find_map(|w| (w[0] == "--out" || w[0] == "-o").then(|| PathBuf::from(&w[1])));
            let profiles = db.list_profiles()?;
            let p = find_profile_by_query(&profiles, target)?;
            let sid = p.short_id();
            let json = if let Some(live) = db.probe_live_runtime(&p.id) {
                agent_export_state_in(db.root_dir(), &sid, &live.ws_url)?.1
            } else {
                db.read_saved_cookies(&sid).ok_or_else(|| {
                    anyhow!(
                        "Profile '{}' is not running and has no saved state file yet",
                        p.name
                    )
                })?
            };
            let final_path = out_file.unwrap_or_else(|| {
                db.backups_dir().join(format!("bon_{sid}_cookies.json"))
            });
            std::fs::write(&final_path, &json)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "short_id": sid,
                    "path": final_path,
                    "bytes": json.len(),
                }))?
            );
            Ok(())
        }
        "import-cookies" | "import-state" => {
            let target = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login profile import-cookies <id|name> <file_or_json>"))?;
            let input = rest
                .get(1)
                .ok_or_else(|| anyhow!("Missing cookie/state file path or raw JSON payload"))?;
            let payload = if Path::new(input).is_file() {
                std::fs::read_to_string(input)?
            } else {
                input.clone()
            };
            let profiles = db.list_profiles()?;
            let p = find_profile_by_query(&profiles, target)?;
            let sid = p.short_id();
            let bundle = parse_and_normalize_cookies(&payload, Some(&p.startup_url))?;
            let normalized_json = bundle.to_state_json_pretty();
            db.save_prelaunch_cookies(&sid, &normalized_json)?;
            let live_msg = if let Some(live) = db.probe_live_runtime(&p.id) {
                Some(agent_import_state_or_cookies_in(
                    db.root_dir(),
                    &sid,
                    &live.ws_url,
                    &normalized_json,
                )?)
            } else {
                None
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "short_id": sid,
                    "format": bundle.format_label,
                    "cookie_count": bundle.cookies.len(),
                    "origin_count": bundle.origins.len(),
                    "domains": bundle.domains,
                    "saved_prelaunch": true,
                    "live_imported": live_msg,
                }))?
            );
            Ok(())
        }
        "wipe" => {
            let profiles = db.list_profiles()?;
            let (targets, _) = select_profiles_by_target(&profiles, rest).map_err(|_| {
                anyhow!("Usage: bon-login profile wipe <id|name|--group <g>|--all>")
            })?;
            let mut wiped = Vec::new();
            for p in targets {
                db.stop_external_runtime(&p.id, &p.short_id());
                db.wipe_profile_data(&p.id)?;
                wiped.push(p.short_id());
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "wiped": wiped,
                }))?
            );
            Ok(())
        }
        "delete" | "rm" => {
            let permanent = rest.iter().any(|a| a == "--permanent" || a == "--hard" || a == "--force");
            let clean_args: Vec<String> = rest
                .iter()
                .filter(|a| !matches!(a.as_str(), "--permanent" | "--hard" | "--force"))
                .cloned()
                .collect();
            let profiles = db.list_profiles()?;
            let (targets, _) = select_profiles_by_target(&profiles, &clean_args)?;
            let mut deleted = Vec::new();
            for p in targets {
                db.stop_external_runtime(&p.id, &p.short_id());
                if permanent {
                    let _ = db.wipe_profile_data(&p.id);
                    db.delete_profile(&p.id)?;
                } else {
                    db.soft_delete_profile(&p.id)?;
                }
                deleted.push(p.short_id());
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "mode": if permanent { "permanent" } else { "trash" },
                    "deleted": deleted,
                }))?
            );
            Ok(())
        }
        "backup" => {
            let out_file = rest
                .windows(2)
                .find_map(|w| (w[0] == "--out" || w[0] == "-o").then(|| PathBuf::from(&w[1])));
            let (final_path, _) = db.export_profiles_json_to(out_file.as_deref())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "path": final_path,
                    "count": db.list_profiles()?.len(),
                }))?
            );
            Ok(())
        }
        "restore" => {
            let file = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login profile restore <backup_json_file>"))?;
            let raw = std::fs::read_to_string(file)
                .with_context(|| format!("Failed to read backup file '{file}'"))?;
            let imported = db.import_profiles_json(&raw)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "imported": imported,
                }))?
            );
            Ok(())
        }
        "export-csv" => {
            let out_file = rest
                .windows(2)
                .find_map(|w| (w[0] == "--out" || w[0] == "-o").then(|| PathBuf::from(&w[1])));
            let (final_path, _) = db.export_profiles_csv_to(out_file.as_deref())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "path": final_path,
                    "count": db.list_profiles()?.len(),
                }))?
            );
            Ok(())
        }
        "import-csv" => {
            let file = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login profile import-csv <csv_or_tsv_file>"))?;
            let raw = std::fs::read_to_string(file)
                .with_context(|| format!("Failed to read CSV file '{file}'"))?;
            let imported = db.import_profiles_csv(&raw)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "imported": imported,
                }))?
            );
            Ok(())
        }
        "export-zip" => {
            let profiles = db.list_profiles()?;
            let (targets, _) = select_profiles_by_target(&profiles, rest).map_err(|_| {
                anyhow!("Usage: bon-login profile export-zip <id|name|--group <g>|--all>")
            })?;
            let mut exported = Vec::new();
            for p in &targets {
                if db.probe_live_runtime(&p.id).is_some() {
                    bail!("Stop profile '{}' before exporting .zip archive", p.name);
                }
                let path = db.export_profile_archive_zip(p)?;
                exported.push(serde_json::json!({
                    "ok": true,
                    "short_id": p.short_id(),
                    "name": p.name,
                    "path": path,
                }));
            }
            if exported.len() == 1 {
                println!("{}", serde_json::to_string_pretty(&exported[0])?);
            } else {
                println!("{}", serde_json::to_string_pretty(&exported)?);
            }
            Ok(())
        }
        "import-zip" => {
            let file = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login profile import-zip <zip_file>"))?;
            let restored = db.import_profile_archive_zip(Path::new(file))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "id": restored.id,
                    "short_id": restored.short_id(),
                    "name": restored.name,
                }))?
            );
            Ok(())
        }
        "warmup" | "cookie-robot" => {
            let profiles = db.list_profiles()?;
            let (targets, consumed) = select_profiles_by_target(&profiles, rest).map_err(|_| {
                anyhow!("Usage: bon-login profile warmup <id|name|--group <g>|--all> [url1,url2...] [--dwell <secs>]")
            })?;
            let tail = &rest[consumed..];
            let dwell: u64 = tail
                .windows(2)
                .find_map(|w| (w[0] == "--dwell" || w[0] == "-d").then(|| w[1].parse().ok()).flatten())
                .unwrap_or(4)
                .clamp(1, 60);
            let urls: Vec<String> = if let Some(raw_urls) = tail.first().filter(|s| !s.starts_with('-')) {
                raw_urls
                    .split([',', ' ', '\n'])
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string)
                    .collect()
            } else {
                vec![
                    "https://www.wikipedia.org".to_string(),
                    "https://www.reddit.com".to_string(),
                    "https://www.youtube.com".to_string(),
                    "https://www.amazon.com".to_string(),
                ]
            };
            let mut results = Vec::new();
            for p in &targets {
                let info = ensure_profile_launched_via_supervisor(&db, p)?;
                let visited = run_cookie_robot_warmup_in(db.root_dir(), &p.short_id(), &info.ws_url, &urls, dwell)?;
                results.push(serde_json::json!({
                    "ok": true,
                    "short_id": p.short_id(),
                    "name": p.name,
                    "visited": visited,
                    "dwell_secs": dwell,
                    "urls": urls,
                }));
            }
            if results.len() == 1 {
                println!("{}", serde_json::to_string_pretty(&results[0])?);
            } else {
                println!("{}", serde_json::to_string_pretty(&results)?);
            }
            Ok(())
        }
        "bookmarks" | "bookmark" => {
            let target = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login profile bookmarks <id|name> [list|add <Name|URL,...>|clear]"))?;
            let profiles = db.list_profiles()?;
            let p = find_profile_by_query(&profiles, target)?;
            let action = rest.get(1).map(String::as_str).unwrap_or("list");
            match action {
                "list" | "ls" => {}
                "clear" | "reset" => {
                    db.write_bookmarks_checked(p, &[])?;
                }
                "add" | "set" => {
                    let raw = rest.get(2..).unwrap_or(&[]).join(",");
                    let mut items = if action == "set" {
                        Vec::new()
                    } else {
                        db.read_bookmarks(p)
                    };
                    for (n, u) in parse_bookmarks_editable(&raw) {
                        if !items.iter().any(|(_, eu)| eu.eq_ignore_ascii_case(&u)) {
                            items.push((n, u));
                        }
                    }
                    db.write_bookmarks_checked(p, &items)?;
                }
                other => bail!("Unknown bookmarks action '{other}' (expected list, add, set, or clear)"),
            }
            let bms: Vec<serde_json::Value> = db
                .read_bookmarks(p)
                .into_iter()
                .map(|(n, u)| serde_json::json!({"name": n, "url": u}))
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "short_id": p.short_id(),
                    "bookmarks": bms,
                }))?
            );
            Ok(())
        }
        "trash" => {
            let action = rest.first().map(String::as_str).unwrap_or("list");
            match action {
                "list" | "ls" => {
                    let trashed = db.list_trashed_profiles()?;
                    let items: Vec<serde_json::Value> = trashed
                        .iter()
                        .map(|p| profile_summary_json_in(db.root_dir(), p))
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&items)?);
                    Ok(())
                }
                "restore" => {
                    let q = rest
                        .get(1)
                        .ok_or_else(|| anyhow!("Usage: bon-login profile trash restore <id|name|--all>"))?;
                    let trashed = db.list_trashed_profiles()?;
                    let targets: Vec<Profile> = if q == "--all" || q == "all" {
                        trashed
                    } else {
                        vec![find_profile_by_query(&trashed, q)?.clone()]
                    };
                    for t in &targets {
                        db.restore_profile(&t.id)?;
                    }
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": true,
                            "restored": targets.len(),
                        }))?
                    );
                    Ok(())
                }
                "empty" => {
                    let trashed = db.list_trashed_profiles()?;
                    for t in &trashed {
                        let _ = db.wipe_profile_data(&t.id);
                        let _ = db.delete_profile(&t.id);
                    }
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": true,
                            "emptied": trashed.len(),
                        }))?
                    );
                    Ok(())
                }
                other => bail!("Unknown trash action '{other}' (expected list, restore, or empty)"),
            }
        }
        other => bail!("Unknown profile subcommand '{other}'"),
    }
}

fn select_proxies_by_target(
    proxies: &[SavedProxy],
    args: &[String],
) -> Result<(Vec<SavedProxy>, usize)> {
    let first = args
        .first()
        .ok_or_else(|| anyhow!("Missing proxy target (<id|name|--tag <t>|--all>)"))?;
    if first == "--all" || first == "all" {
        return Ok((proxies.to_vec(), 1));
    }
    if first == "--tag" {
        let tag = args
            .get(1)
            .ok_or_else(|| anyhow!("Missing tag name after --tag"))?
            .trim_start_matches('#');
        let matched: Vec<SavedProxy> = proxies
            .iter()
            .filter(|p| p.group_tag.eq_ignore_ascii_case(tag))
            .cloned()
            .collect();
        if matched.is_empty() {
            bail!("No saved proxies found with tag '{tag}'");
        }
        return Ok((matched, 2));
    }
    let mut out = Vec::new();
    for token in first.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        out.push(find_saved_proxy_by_query(proxies, token)?.clone());
    }
    Ok((out, 1))
}

fn run_proxy_subcommand(args: &[String]) -> Result<()> {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    let rest = if args.is_empty() { &[] } else { &args[1..] };
    let db = crate::db::Database::open_default()?;

    match sub {
        "list" | "ls" => {
            let tag_filter = rest
                .windows(2)
                .find_map(|w| (w[0] == "--tag").then(|| w[1].trim_start_matches('#').to_string()));
            let proxies = db.list_proxies()?;
            let items: Vec<serde_json::Value> = proxies
                .iter()
                .filter(|p| {
                    tag_filter
                        .as_deref()
                        .is_none_or(|t| p.group_tag.eq_ignore_ascii_case(t))
                })
                .map(saved_proxy_summary_json)
                .collect();
            println!("{}", serde_json::to_string_pretty(&items)?);
            Ok(())
        }
        "free" | "find-free" | "search-free" => {
            let mut protocol: Option<ProxyProtocol> = None;
            let mut country: Option<String> = None;
            let mut search_query = String::new();
            let mut limit: usize = 20;
            let mut verify = false;
            let mut save = false;
            let mut tag = "free".to_string();
            let mut idx = 0;
            while idx < rest.len() {
                match rest[idx].as_str() {
                    "--protocol" | "--type" | "-p" => {
                        if let Some(v) = rest.get(idx + 1) {
                            protocol = Some(ProxyProtocol::from_str_lossy(v));
                        }
                        idx += 2;
                    }
                    "--country" | "-c" => {
                        country = rest.get(idx + 1).cloned();
                        idx += 2;
                    }
                    "--search" | "-q" => {
                        search_query = rest.get(idx + 1).cloned().unwrap_or_default();
                        idx += 2;
                    }
                    "--limit" | "-n" => {
                        if let Some(v) = rest.get(idx + 1).and_then(|s| s.parse::<usize>().ok()) {
                            limit = v.clamp(1, 200);
                        }
                        idx += 2;
                    }
                    "--tag" => {
                        if let Some(v) = rest.get(idx + 1) {
                            tag = v.trim().trim_start_matches('#').to_string();
                        }
                        idx += 2;
                    }
                    "--verify" | "--live" => {
                        verify = true;
                        idx += 1;
                    }
                    "--save" | "--import" => {
                        save = true;
                        idx += 1;
                    }
                    _ => idx += 1,
                }
            }
            let found = cli_tokio_handle().block_on(discover_free_proxies(
                protocol,
                country.as_deref(),
                &search_query,
                limit,
                verify,
            ))?;
            let mut saved_ids = Vec::new();
            if save && !found.is_empty() {
                let existing = db.list_proxies()?;
                let _ = db.insert_tag(&tag);
                db.with_transaction(|db| {
                    for fp in &found {
                        let dup = existing.iter().any(|sp| {
                            sp.config.protocol == fp.config.protocol
                                && sp.config.host.eq_ignore_ascii_case(&fp.config.host)
                                && sp.config.port == fp.config.port
                        });
                        if !dup {
                            let sp = fp.to_saved_proxy(&tag);
                            saved_ids.push(sp.id.clone());
                            db.upsert_proxy(&sp)?;
                        }
                    }
                    Ok(())
                })?;
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "verified": verify,
                    "saved_count": saved_ids.len(),
                    "count": found.len(),
                    "proxies": found,
                }))?
            );
            Ok(())
        }
        "add" | "import" => {
            let raw_arg = rest
                .first()
                .filter(|s| !s.starts_with('-'))
                .ok_or_else(|| {
                    anyhow!("Usage: bon-login proxy add <raw_proxy_or_file> [--protocol http|socks5] [--tag <t>] [--name <n>] [--expire <days_or_date>]")
                })?;
            let mut default_proto = ProxyProtocol::Http;
            let mut tag = String::new();
            let mut explicit_name: Option<String> = None;
            let mut expire_ts: Option<i64> = None;
            let mut idx = 1;
            while idx < rest.len() {
                match rest[idx].as_str() {
                    "--protocol" | "--type" => {
                        if let Some(v) = rest.get(idx + 1) {
                            default_proto = ProxyProtocol::from_str_lossy(v);
                        }
                        idx += 2;
                    }
                    "--tag" | "--group" => {
                        tag = rest
                            .get(idx + 1)
                            .map(|s| s.trim().trim_start_matches('#').to_string())
                            .unwrap_or_default();
                        idx += 2;
                    }
                    "--name" => {
                        explicit_name = rest.get(idx + 1).cloned();
                        idx += 2;
                    }
                    "--expire" => {
                        let v = rest
                            .get(idx + 1)
                            .ok_or_else(|| anyhow!("Missing value for --expire"))?;
                        expire_ts = SavedProxy::parse_expiration_strict(v)
                            .map_err(|e| anyhow!("{e}: '{v}'"))?;
                        idx += 2;
                    }
                    _ => idx += 1,
                }
            }
            let content = if Path::new(raw_arg).is_file() {
                std::fs::read_to_string(raw_arg)?
            } else {
                raw_arg.clone()
            };
            let mut existing_count = db.list_proxies()?.len();
            let mut added = Vec::new();
            db.with_transaction(|db| {
                for line in content.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    if let Some((cfg, inline_name)) =
                        ProxyConfig::parse_with_optional_name(line, default_proto)?
                    {
                        existing_count += 1;
                        let name = explicit_name
                            .clone()
                            .or(inline_name)
                            .unwrap_or_else(|| format!("Proxy #{existing_count:02}"));
                        let mut sp = SavedProxy::new(name, tag.clone(), cfg);
                        sp.expired_at = expire_ts;
                        db.upsert_proxy(&sp)?;
                        added.push(saved_proxy_summary_json(&sp));
                    }
                }
                Ok(())
            })?;
            println!("{}", serde_json::to_string_pretty(&added)?);
            Ok(())
        }
        "update" | "edit" | "set" => {
            let proxies = db.list_proxies()?;
            let (mut targets, consumed) = select_proxies_by_target(&proxies, rest)?;
            let flags = &rest[consumed..];
            if flags.is_empty() {
                bail!("Usage: bon-login proxy update <id|name|--tag <t>|--all> [--name <n>] [--tag <t>] [--expire <days_or_date|none>] [--rotate-url <url|none>]");
            }
            let mut idx = 0;
            let mut new_name: Option<String> = None;
            let mut new_tag: Option<String> = None;
            let mut new_expire: Option<Option<i64>> = None;
            let mut new_rotate_url: Option<Option<String>> = None;
            while idx < flags.len() {
                match flags[idx].as_str() {
                    "--name" => {
                        new_name = flags.get(idx + 1).map(|s| s.trim().to_string());
                        idx += 2;
                    }
                    "--tag" | "--group" => {
                        let t = flags.get(idx + 1).map(|s| s.trim().trim_start_matches('#')).unwrap_or("");
                        new_tag = Some(if t.eq_ignore_ascii_case("none") {
                            String::new()
                        } else {
                            t.to_string()
                        });
                        idx += 2;
                    }
                    "--expire" => {
                        let v = flags
                            .get(idx + 1)
                            .ok_or_else(|| anyhow!("Missing value for --expire"))?;
                        new_expire = Some(
                            SavedProxy::parse_expiration_strict(v)
                                .map_err(|e| anyhow!("{e}: '{v}'"))?,
                        );
                        idx += 2;
                    }
                    "--rotate-url" | "--change-ip-url" => {
                        let v = flags.get(idx + 1).map(|s| s.trim()).unwrap_or("");
                        if v.is_empty() || v.eq_ignore_ascii_case("none") || v.eq_ignore_ascii_case("clear") {
                            new_rotate_url = Some(None);
                        } else if v.starts_with("http://") || v.starts_with("https://") {
                            new_rotate_url = Some(Some(v.to_string()));
                        } else {
                            bail!("--rotate-url must start with http:// or https:// (or 'none')");
                        }
                        idx += 2;
                    }
                    other => bail!("Unknown proxy update flag '{other}'"),
                }
            }
            let count = targets.len();
            let mut updated = Vec::new();
            db.with_transaction(|db| {
                for (i, mut sp) in targets.drain(..).enumerate() {
                    if let Some(n) = &new_name {
                        sp.name = if count == 1 {
                            n.clone()
                        } else {
                            format!("{n}-{:02}", i + 1)
                        };
                    }
                    if let Some(t) = &new_tag {
                        sp.group_tag = t.clone();
                    }
                    if let Some(exp) = new_expire {
                        sp.expired_at = exp;
                    }
                    if let Some(rot) = &new_rotate_url {
                        sp.config.change_ip_url = rot.clone();
                    }
                    db.upsert_proxy(&sp)?;
                    updated.push(saved_proxy_summary_json(&sp));
                }
                Ok(())
            })?;
            println!("{}", serde_json::to_string_pretty(&updated)?);
            Ok(())
        }
        "export" | "copy" => {
            let tag_filter = rest
                .windows(2)
                .find_map(|w| (w[0] == "--tag").then(|| w[1].trim_start_matches('#').to_string()));
            let out_file = rest
                .windows(2)
                .find_map(|w| (w[0] == "--out" || w[0] == "-o").then(|| PathBuf::from(&w[1])));
            let proxies = db.list_proxies()?;
            let lines: Vec<String> = proxies
                .iter()
                .filter(|p| {
                    tag_filter
                        .as_deref()
                        .is_none_or(|t| p.group_tag.eq_ignore_ascii_case(t))
                })
                .map(|p| p.config.to_editable_string())
                .collect();
            if let Some(path) = out_file {
                std::fs::write(&path, lines.join("\n"))?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "path": path,
                        "count": lines.len(),
                    }))?
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&lines)?);
            }
            Ok(())
        }
        "check" | "rotate" => {
            let rotate = sub == "rotate";
            let proxies = db.list_proxies()?;
            let (targets, _) = select_proxies_by_target(&proxies, rest)?;
            let db_mtx = std::sync::Mutex::new(db);
            let mut results = Vec::new();
            let mut any_failed = false;
            for sp in targets {
                match cli_tokio_handle().block_on(check_or_rotate_saved_proxy(&db_mtx, &sp, rotate))
                {
                    Ok((rot_opt, geo)) => {
                        let mut item = serde_json::json!({
                            "id": sp.id,
                            "name": sp.name,
                            "host": sp.config.display_short(),
                            "ok": true,
                            "geo": geo,
                        });
                        if let (Some(rot_msg), Some(obj)) = (rot_opt, item.as_object_mut()) {
                            obj.insert("rotation".into(), serde_json::json!(rot_msg));
                        }
                        results.push(item);
                    }
                    Err(e) => {
                        any_failed = true;
                        results.push(serde_json::json!({
                            "id": sp.id,
                            "name": sp.name,
                            "host": sp.config.display_short(),
                            "ok": false,
                            "error": e.to_string(),
                        }));
                    }
                }
            }
            println!("{}", serde_json::to_string_pretty(&results)?);
            if rotate && any_failed {
                std::process::exit(1);
            }
            Ok(())
        }
        "extend" => {
            let proxies = db.list_proxies()?;
            let (targets, consumed) = select_proxies_by_target(&proxies, rest)?;
            let days_raw = rest
                .get(consumed)
                .ok_or_else(|| anyhow!("Usage: bon-login proxy extend <id|name|--tag <t>|--all> <days|0|clear>"))?
                .trim();
            let days: i64 = if days_raw.eq_ignore_ascii_case("clear") || days_raw.eq_ignore_ascii_case("none") {
                0
            } else {
                days_raw
                    .trim_start_matches('+')
                    .trim_end_matches(['d', 'D'])
                    .parse()
                    .context("Invalid days integer")?
            };
            let now = unix_now();
            let mut updated = Vec::new();
            for mut sp in targets {
                sp.expired_at = if days <= 0 {
                    None
                } else {
                    let base = sp.expired_at.unwrap_or(now).max(now);
                    Some(base + days * 86_400)
                };
                db.upsert_proxy(&sp)?;
                updated.push(serde_json::json!({
                    "id": sp.id,
                    "name": sp.name,
                    "expired_at": sp.expired_at,
                    "expired_label": sp.format_expired_at(),
                }));
            }
            println!("{}", serde_json::to_string_pretty(&updated)?);
            Ok(())
        }
        "assign" => {
            let first = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login proxy assign <proxy|--tag <t>|--all|none> --to <profile|--group <g>|--all>"))?;
            let clear_proxy = first.eq_ignore_ascii_case("none") || first.eq_ignore_ascii_case("direct");
            let (proxy_pool, consumed) = if clear_proxy {
                (Vec::new(), 1)
            } else {
                let proxies = db.list_proxies()?;
                select_proxies_by_target(&proxies, rest)?
            };
            let after = &rest[consumed..];
            let to_idx = after
                .iter()
                .position(|a| a == "--to")
                .ok_or_else(|| anyhow!("Usage: bon-login proxy assign <proxy|--tag <t>|--all|none> --to <profile|--group <g>|--all>"))?;
            let prof_args = &after[to_idx + 1..];
            let profiles = db.list_profiles()?;
            let (mut target_profiles, _) = select_profiles_by_target(&profiles, prof_args)?;
            let mut assigned = Vec::new();
            for (idx, mut p) in target_profiles.drain(..).enumerate() {
                if clear_proxy {
                    p.clear_proxy();
                    db.upsert_profile(&p)?;
                    assigned.push(serde_json::json!({
                        "profile_short_id": p.short_id(),
                        "profile_name": p.name,
                        "proxy": "Direct",
                    }));
                } else {
                    let chosen = &proxy_pool[idx % proxy_pool.len()];
                    p.assign_saved_proxy(chosen);
                    db.upsert_profile(&p)?;
                    assigned.push(serde_json::json!({
                        "profile_short_id": p.short_id(),
                        "profile_name": p.name,
                        "proxy": chosen.config.display_short(),
                        "proxy_name": chosen.name,
                    }));
                }
            }
            println!("{}", serde_json::to_string_pretty(&assigned)?);
            Ok(())
        }
        "delete" | "rm" => {
            let proxies = db.list_proxies()?;
            let (targets, _) = select_proxies_by_target(&proxies, rest)?;
            let mut deleted = Vec::new();
            for sp in targets {
                db.delete_proxy(&sp.id)?;
                deleted.push(sp.id);
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "deleted": deleted,
                }))?
            );
            Ok(())
        }
        other => bail!("Unknown proxy subcommand '{other}'"),
    }
}

fn run_group_subcommand(args: &[String]) -> Result<()> {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    let rest = if args.is_empty() { &[] } else { &args[1..] };
    let db = crate::db::Database::open_default()?;
    match sub {
        "list" | "ls" => {
            let profiles = db.list_profiles()?;
            let groups = db.list_groups()?;
            let items: Vec<serde_json::Value> = groups
                .into_iter()
                .map(|g| {
                    let count = profiles
                        .iter()
                        .filter(|p| p.group_tag.eq_ignore_ascii_case(&g))
                        .count();
                    serde_json::json!({ "name": g, "profiles_count": count })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&items)?);
            Ok(())
        }
        "add" | "create" => {
            let name = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login group add <name>"))?;
            db.insert_group(name)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "ok": true, "group": name.trim() }))?
            );
            Ok(())
        }
        "delete" | "rm" => {
            let name = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login group delete <name>"))?;
            db.delete_group(name)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "ok": true, "deleted": name.trim() }))?
            );
            Ok(())
        }
        "move" | "assign" => {
            let profiles = db.list_profiles()?;
            let (mut targets, consumed) = select_profiles_by_target(&profiles, rest).map_err(|_| {
                anyhow!("Usage: bon-login group move <id|name|--group <g>|--all> <group_name|none>")
            })?;
            let group_name = rest
                .get(consumed)
                .ok_or_else(|| anyhow!("Usage: bon-login group move <id|name|--group <g>|--all> <group_name|none>"))?
                .trim();
            let next_group = if group_name.eq_ignore_ascii_case("none") {
                String::new()
            } else {
                group_name.to_string()
            };
            let mut moved = Vec::new();
            for mut p in targets.drain(..) {
                p.group_tag = next_group.clone();
                db.upsert_profile(&p)?;
                moved.push(serde_json::json!({
                    "ok": true,
                    "short_id": p.short_id(),
                    "name": p.name,
                    "group": p.group_tag,
                }));
            }
            if moved.len() == 1 {
                println!("{}", serde_json::to_string_pretty(&moved[0])?);
            } else {
                println!("{}", serde_json::to_string_pretty(&moved)?);
            }
            Ok(())
        }
        other => bail!("Unknown group subcommand '{other}'"),
    }
}

fn run_tag_subcommand(args: &[String]) -> Result<()> {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    let rest = if args.is_empty() { &[] } else { &args[1..] };
    let db = crate::db::Database::open_default()?;
    match sub {
        "list" | "ls" => {
            let proxies = db.list_proxies()?;
            let tags = db.list_tags()?;
            let items: Vec<serde_json::Value> = tags
                .into_iter()
                .map(|t| {
                    let count = proxies
                        .iter()
                        .filter(|p| p.group_tag.eq_ignore_ascii_case(&t))
                        .count();
                    serde_json::json!({ "name": t, "proxies_count": count })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&items)?);
            Ok(())
        }
        "add" | "create" => {
            let name = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login tag add <name>"))?
                .trim()
                .trim_start_matches('#');
            db.insert_tag(name)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "ok": true, "tag": name }))?
            );
            Ok(())
        }
        "delete" | "rm" => {
            let name = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login tag delete <name>"))?
                .trim()
                .trim_start_matches('#');
            db.delete_tag(name)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "ok": true, "deleted": name }))?
            );
            Ok(())
        }
        other => bail!("Unknown tag subcommand '{other}'"),
    }
}

fn run_ext_subcommand(args: &[String]) -> Result<()> {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    let rest = if args.is_empty() { &[] } else { &args[1..] };
    let db = crate::db::Database::open_default()?;
    match sub {
        "list" | "ls" => {
            let exts = db.list_extensions()?;
            let items: Vec<serde_json::Value> = exts
                .iter()
                .map(|e| {
                    let rt = resolve_extension_runtime_info_in(db.root_dir(), e);
                    serde_json::json!({
                        "id": e.id,
                        "name": e.name,
                        "enabled": e.enabled,
                        "is_default": e.is_default,
                        "runtime_id": rt.as_ref().map(|(id, _)| id),
                        "entry_url": rt.as_ref().map(|(_, url)| url),
                        "source_url": e.source_url,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&items)?);
            Ok(())
        }
        "enable" | "disable" => {
            let enable = sub == "enable";
            let target = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login ext {sub} <id|name|--all>"))?;
            let exts = db.list_extensions()?;
            let targets: Vec<BrowserExtension> = if target == "--all" || target == "all" {
                exts
            } else {
                let mut list = Vec::new();
                for tok in target.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    list.push(find_extension_by_query(&exts, tok)?.clone());
                }
                list
            };
            let mut results = Vec::new();
            for mut ext in targets {
                if enable {
                    let flag = std::sync::atomic::AtomicBool::new(false);
                    ext = cli_tokio_handle().block_on(
                        crate::extensions::activate_extension_cancellable_in(
                            db.root_dir(),
                            ext,
                            &flag,
                        ),
                    )?;
                } else {
                    ext.enabled = false;
                }
                db.upsert_extension(&ext)?;
                db.set_extension_enabled(&ext.id, enable)?;
                let rt = resolve_extension_runtime_info_in(db.root_dir(), &ext);
                results.push(serde_json::json!({
                    "ok": true,
                    "id": ext.id,
                    "name": ext.name,
                    "enabled": enable,
                    "runtime_id": rt.as_ref().map(|(id, _)| id),
                    "entry_url": rt.as_ref().map(|(_, url)| url),
                }));
            }
            if results.len() == 1 {
                println!("{}", serde_json::to_string_pretty(&results[0])?);
            } else {
                println!("{}", serde_json::to_string_pretty(&results)?);
            }
            Ok(())
        }
        "add" | "install" => {
            let src = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login ext add <file_or_folder_or_store_url_or_id>"))?;
            let ext = if Path::new(src).exists() {
                install_extension_from_file_in(db.root_dir(), Path::new(src))?
            } else {
                cli_tokio_handle().block_on(download_extension_from_url_in(db.root_dir(), src))?
            };
            db.upsert_extension(&ext)?;
            let rt = resolve_extension_runtime_info_in(db.root_dir(), &ext);
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "id": ext.id,
                    "name": ext.name,
                    "enabled": ext.enabled,
                    "runtime_id": rt.as_ref().map(|(id, _)| id),
                    "entry_url": rt.as_ref().map(|(_, url)| url),
                }))?
            );
            Ok(())
        }
        "remove" | "delete" | "rm" => {
            let target = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login ext remove <id|name>"))?;
            let exts = db.list_extensions()?;
            let ext = find_extension_by_query(&exts, target)?;
            if ext.is_default {
                db.set_extension_enabled(&ext.id, false)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "id": ext.id,
                        "disabled_default": true,
                    }))?
                );
            } else {
                db.delete_extension(&ext.id)?;
                remove_extension_files_in(db.root_dir(), &ext.id);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "deleted": ext.id,
                    }))?
                );
            }
            Ok(())
        }
        "open" => {
            let ext_target = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login ext open <ext_id|name> [--profile <profile_id|name>]"))?;
            let prof_target = rest
                .windows(2)
                .find_map(|w| (w[0] == "--profile" || w[0] == "-p").then(|| w[1].as_str()))
                .or_else(|| {
                    rest.get(1)
                        .filter(|s| !s.starts_with('-'))
                        .map(String::as_str)
                });
            let exts = db.list_extensions()?;
            let ext = find_extension_by_query(&exts, ext_target)?;
            let (runtime_id, entry_url) = resolve_extension_runtime_info_in(db.root_dir(), ext)
                .ok_or_else(|| anyhow!("Could not resolve extension entry URL for '{}'", ext.name))?;
            let profiles = db.list_profiles()?;
            let profile = if let Some(q) = prof_target {
                find_profile_by_query(&profiles, q)?
            } else {
                profiles
                    .iter()
                    .find(|p| db.probe_live_runtime(&p.id).is_some())
                    .ok_or_else(|| {
                        anyhow!(
                            "No running profile found. Specify `--profile <id|name>` or launch a profile first."
                        )
                    })?
            };
            let info = ensure_profile_launched_via_supervisor(&db, profile)?;
            let cli =
                agent_open_extension_tab_in(db.root_dir(), &profile.short_id(), &info.ws_url, &entry_url)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "profile_short_id": profile.short_id(),
                    "session": format!("bon_{}", profile.short_id()),
                    "extension_id": ext.id,
                    "runtime_id": runtime_id,
                    "entry_url": entry_url,
                    "cli": cli,
                }))?
            );
            Ok(())
        }
        other => bail!("Unknown extension subcommand '{other}'"),
    }
}

fn run_kernel_subcommand(args: &[String]) -> Result<()> {
    let sub = args.first().map(String::as_str).unwrap_or("status");
    let force = args.iter().any(|a| a == "--force" || a == "-f");
    match sub {
        "status" | "info" | "check" => {
            let k = locate_chromium_kernel();
            let version_out = k.as_ref().and_then(|info| {
                unquarantine_macos_app(&info.path);
                Command::new(&info.path)
                    .arg("--version")
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "installed": k.is_some(),
                    "healthy": version_out.is_some(),
                    "version": k.as_ref().map(|i| &i.version_label),
                    "binary_version": version_out,
                    "path": k.as_ref().map(|i| &i.path),
                }))?
            );
            Ok(())
        }
        "install" | "download" | "update" => {
            let k = install_adryfish_kernel_blocking_opts(force)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "version": k.version_label,
                    "path": k.path,
                }))?
            );
            Ok(())
        }
        other => bail!("Unknown kernel subcommand '{other}' (expected status, check, or install [--force])"),
    }
}

fn run_arrange_cli(args: &[String]) -> Result<()> {
    let raw_size = args
        .windows(2)
        .find_map(|w| (w[0] == "--size" || w[0] == "-s").then_some(w[1].as_str()))
        .unwrap_or("960,600");
    let display_num: usize = args
        .windows(2)
        .find_map(|w| {
            (w[0] == "--display" || w[0] == "--monitor" || w[0] == "-d")
                .then(|| w[1].parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(1)
        .max(1);
    let (win_w, win_h) =
        parse_window_size(raw_size).ok_or_else(|| anyhow!("Invalid --size '{raw_size}' (use W,H)"))?;
    let db = crate::db::Database::open_default()?;
    let profiles = db.list_profiles()?;
    let (arranged, total_running, applied_w, applied_h) =
        arrange_running_windows_on_display_in(db.root_dir(), &profiles, display_num - 1, win_w, win_h);
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "ok": true,
            "arranged": arranged,
            "total_running": total_running,
            "display": display_num,
            "window_size": [applied_w, applied_h],
        }))?
    );
    Ok(())
}

fn run_type_cli(args: &[String]) -> Result<()> {
    let target = args
        .first()
        .ok_or_else(|| anyhow!("Usage: bon-login type <short_id|name> <text...>"))?;
    let text = args.get(1..).unwrap_or(&[]).join(" ");
    if text.is_empty() {
        bail!("Usage: bon-login type <short_id|name> <text...>");
    }
    let db = crate::db::Database::open_default()?;
    let profiles = db.list_profiles()?;
    let p = find_profile_by_query(&profiles, target)?;
    let rt = db.probe_live_runtime(&p.id)
        .ok_or_else(|| anyhow!("Profile '{}' (bon_{}) is not running", p.name, p.short_id()))?;
    let typed = cdp_type_as_human(rt.cdp_port, &text)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "ok": true,
            "short_id": p.short_id(),
            "typed_chars": typed,
        }))?
    );
    Ok(())
}

fn run_totp_cli(args: &[String]) -> Result<()> {
    let target = args
        .first()
        .ok_or_else(|| anyhow!("Usage: bon-login totp <short_id|name> [--type]"))?;
    let do_type = args.iter().any(|a| a == "--type" || a == "-t");
    let db = crate::db::Database::open_default()?;
    let profiles = db.list_profiles()?;
    let p = find_profile_by_query(&profiles, target)?;
    let (code, remaining_secs) = p
        .current_totp()
        .ok_or_else(|| anyhow!("Profile '{}' has no valid 2FA TOTP secret", p.name))?;
    let mut typed = false;
    if do_type {
        let rt = db.probe_live_runtime(&p.id)
            .ok_or_else(|| anyhow!("Profile '{}' (bon_{}) is not running", p.name, p.short_id()))?;
        cdp_type_as_human(rt.cdp_port, &format!("{code}\n"))?;
        typed = true;
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "ok": true,
            "short_id": p.short_id(),
            "code": code,
            "remaining_secs": remaining_secs,
            "typed": typed,
        }))?
    );
    Ok(())
}

fn run_screenshot_cli(args: &[String]) -> Result<()> {
    let target = args
        .first()
        .ok_or_else(|| anyhow!("Usage: bon-login screenshot <short_id|name> [--out <file>]"))?;
    let out_file = args
        .windows(2)
        .find_map(|w| (w[0] == "--out" || w[0] == "-o").then(|| PathBuf::from(&w[1])));
    let db = crate::db::Database::open_default()?;
    let profiles = db.list_profiles()?;
    let p = find_profile_by_query(&profiles, target)?;
    let rt = db.probe_live_runtime(&p.id)
        .ok_or_else(|| anyhow!("Profile '{}' (bon_{}) is not running", p.name, p.short_id()))?;
    let path = cdp_capture_screenshot_in(db.root_dir(), &p.short_id(), rt.cdp_port, out_file.as_deref())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "ok": true,
            "short_id": p.short_id(),
            "path": path,
        }))?
    );
    Ok(())
}

fn run_broadcast_cli(args: &[String]) -> Result<()> {
    let op = args
        .first()
        .ok_or_else(|| anyhow!("Usage: bon-login broadcast <open|type|totp> [value] [--group <g>]"))?
        .as_str();
    if !matches!(op, "open" | "goto" | "navigate" | "type" | "totp" | "2fa") {
        bail!("Unknown broadcast op '{op}' (expected open, type, or totp)");
    }
    let group_filter = args
        .windows(2)
        .find_map(|w| (w[0] == "--group" || w[0] == "-g").then_some(w[1].as_str()));
    let val = if matches!(op, "totp" | "2fa") {
        String::new()
    } else {
        args.get(1)
            .filter(|s| !s.starts_with('-'))
            .cloned()
            .ok_or_else(|| anyhow!("Missing value/URL for `bon-login broadcast {op} <value>`"))?
    };
    let db = crate::db::Database::open_default()?;
    let profiles = db.list_profiles()?;
    let running: Vec<(Profile, RuntimeInfo)> = profiles
        .into_iter()
        .filter(|p| {
            group_filter.is_none_or(|g| p.group_tag.eq_ignore_ascii_case(g))
        })
        .filter_map(|p| db.probe_live_runtime(&p.id).map(|rt| (p, rt)))
        .collect();
    let ok_count = std::thread::scope(|s| {
        let handles: Vec<_> = running
            .iter()
            .map(|(p, rt)| {
                let v = val.clone();
                s.spawn(move || match op {
                    "open" | "goto" | "navigate" => cdp_navigate_page(rt.cdp_port, &v).is_ok(),
                    "type" => cdp_type_as_human(rt.cdp_port, &v).is_ok(),
                    "totp" | "2fa" => cdp_type_totp(p, rt.cdp_port).is_ok(),
                    _ => false,
                })
            })
            .collect();
        handles
            .into_iter()
            .filter_map(|h| h.join().ok().filter(|&ok| ok))
            .count()
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "ok": true,
            "op": op,
            "succeeded": ok_count,
            "total_running": running.len(),
        }))?
    );
    Ok(())
}

#[derive(Clone)]
pub struct ControlEngine {
    pub db: std::sync::Arc<std::sync::Mutex<crate::db::Database>>,
    pub supervisor: RuntimeSupervisor,
    pub in_process_launch: bool,
    on_mutation: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

impl ControlEngine {
    pub fn open_at(root_dir: &Path) -> Result<Self> {
        let db = crate::db::Database::open_at(root_dir)?;
        let supervisor = RuntimeSupervisor::new_in(root_dir);
        Ok(Self {
            db: std::sync::Arc::new(std::sync::Mutex::new(db)),
            supervisor,
            in_process_launch: false,
            on_mutation: None,
        })
    }

    pub fn attached(
        db: std::sync::Arc<std::sync::Mutex<crate::db::Database>>,
        supervisor: RuntimeSupervisor,
        on_mutation: std::sync::Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self {
            db,
            supervisor,
            in_process_launch: true,
            on_mutation: Some(on_mutation),
        }
    }

    fn notify_mutation(&self) {
        if let Some(cb) = &self.on_mutation {
            cb();
        }
    }

    fn lookup_profile(&self, target_decoded: &str) -> std::result::Result<Profile, (u16, String)> {
        let guard = self.db.lock().map_err(|_| {
            (
                500,
                serde_json::json!({"ok": false, "error": "Database lock poisoned"}).to_string(),
            )
        })?;
        let profiles = guard.list_profiles().map_err(|e| {
            (
                500,
                serde_json::json!({"ok": false, "error": e.to_string()}).to_string(),
            )
        })?;
        find_profile_by_query(&profiles, target_decoded)
            .cloned()
            .map_err(|e| {
                (
                    404,
                    serde_json::json!({"ok": false, "error": e.to_string()}).to_string(),
                )
            })
    }

    async fn ensure_profile_running(&self, profile: &Profile) -> Result<RuntimeInfo> {
        if let Some(info) = self.supervisor.live_info(&profile.id) {
            return Ok(info);
        }
        if self.in_process_launch {
            let info = self.supervisor.ensure_launched(&self.db, profile).await?;
            self.notify_mutation();
            return Ok(info);
        }
        let root_dir = self.supervisor.root_dir().to_path_buf();
        let prof_cl = profile.clone();
        tokio::task::spawn_blocking(move || {
            let db = crate::db::Database::open_at(&root_dir)?;
            ensure_profile_launched_via_supervisor(&db, &prof_cl)
        })
        .await?
    }

    async fn run_blocking_json<T, F, M>(err_code: u16, work: F, map_ok: M) -> (u16, String)
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
        M: FnOnce(T) -> serde_json::Value,
    {
        match tokio::task::spawn_blocking(work).await {
            Ok(Ok(val)) => (200, map_ok(val).to_string()),
            Ok(Err(e)) => (
                err_code,
                serde_json::json!({"ok": false, "error": e.to_string()}).to_string(),
            ),
            Err(e) => (
                500,
                serde_json::json!({"ok": false, "error": e.to_string()}).to_string(),
            ),
        }
    }

    pub async fn handle_http(&self, method: &str, path: &str, body: &str) -> (u16, String) {
        let clean_path = path.split('?').next().unwrap_or(path).trim_end_matches('/');
        match (method, clean_path) {
            ("GET", "" | "/health" | "/status") => (
                200,
                serde_json::json!({"ok": true, "service": "bon-login"}).to_string(),
            ),
            ("GET", "/profiles") => {
                let engine = self.clone();
                tokio::task::spawn_blocking(move || {
                    let Ok(db) = engine.db.lock() else {
                        return (
                            500,
                            serde_json::json!({"ok": false, "error": "DB lock error"}).to_string(),
                        );
                    };
                    match db.list_profiles() {
                        Ok(list) => {
                            let items: Vec<serde_json::Value> = list
                                .iter()
                                .map(|p| {
                                    let mut val = profile_summary_json_in(db.root_dir(), p);
                                    if let Some(live) = engine.supervisor.live_info(&p.id)
                                        && let Some(obj) = val.as_object_mut()
                                    {
                                        obj.insert("running".into(), serde_json::json!(true));
                                        obj.insert("pid".into(), serde_json::json!(live.pid));
                                        obj.insert(
                                            "cdp_port".into(),
                                            serde_json::json!(live.cdp_port),
                                        );
                                        obj.insert("ws_url".into(), serde_json::json!(live.ws_url));
                                    }
                                    val
                                })
                                .collect();
                            (
                                200,
                                serde_json::json!({"ok": true, "profiles": items}).to_string(),
                            )
                        }
                        Err(e) => (
                            500,
                            serde_json::json!({"ok": false, "error": e.to_string()}).to_string(),
                        ),
                    }
                })
                .await
                .unwrap_or_else(|e| {
                    (
                        500,
                        serde_json::json!({"ok": false, "error": e.to_string()}).to_string(),
                    )
                })
            }
            ("GET", "/proxies/free") => {
                match discover_free_proxies(None, None, "", 30, false).await {
                    Ok(list) => (
                        200,
                        serde_json::json!({"ok": true, "count": list.len(), "proxies": list})
                            .to_string(),
                    ),
                    Err(e) => (
                        500,
                        serde_json::json!({"ok": false, "error": e.to_string()}).to_string(),
                    ),
                }
            }
            ("GET", "/flows") => {
                let root_dir = self.supervisor.root_dir().to_path_buf();
                tokio::task::spawn_blocking(move || {
                    let items: Vec<serde_json::Value> = list_saved_flows_in(&root_dir)
                        .into_iter()
                        .map(|flow| {
                            let vars = extract_flow_vars(&flow);
                            serde_json::json!({
                                "name": flow.name,
                                "domain": flow.domain,
                                "steps_count": flow.steps.len(),
                                "vars": vars,
                                "updated_at": flow.updated_at,
                                "steps": flow.steps,
                            })
                        })
                        .collect();
                    (
                        200,
                        serde_json::json!({"ok": true, "flows": items}).to_string(),
                    )
                })
                .await
                .unwrap_or_else(|e| {
                    (
                        500,
                        serde_json::json!({"ok": false, "error": e.to_string()}).to_string(),
                    )
                })
            }
            ("POST", "/arrange") => {
                let (w, h) = parse_window_size(body).unwrap_or((960, 600));
                let engine = self.clone();
                tokio::task::spawn_blocking(move || {
                    let profiles = engine
                        .db
                        .lock()
                        .ok()
                        .and_then(|db| db.list_profiles().ok())
                        .unwrap_or_default();
                    let targets: Vec<(u16, String)> = parallel_map(&profiles, |p| {
                        engine
                            .supervisor
                            .live_info(&p.id)
                            .map(|rt| (rt.cdp_port, rt.ws_url))
                    })
                    .into_iter()
                    .flatten()
                    .collect();
                    let mon_rect = macos_display_rect(0);
                    let (arranged, total, _, _) =
                        tile_window_targets(&targets, mon_rect, w, h);
                    (
                        200,
                        serde_json::json!({"ok": true, "arranged": arranged, "total": total})
                            .to_string(),
                    )
                })
                .await
                .unwrap_or_else(|e| {
                    (
                        500,
                        serde_json::json!({"ok": false, "error": e.to_string()}).to_string(),
                    )
                })
            }
            ("POST", p_path) if p_path.starts_with("/profiles/") => {
                let rest = &p_path["/profiles/".len()..];
                if let Some((target, flow_raw)) = rest
                    .split_once("/flow/")
                    .or_else(|| rest.split_once("/flows/"))
                {
                    let profile = match self.lookup_profile(&percent_decode(target)) {
                        Ok(p) => p,
                        Err(resp) => return resp,
                    };
                    let clean_flow = match sanitize_flow_name(&percent_decode(flow_raw)) {
                        Ok(n) => n,
                        Err(e) => {
                            return (
                                400,
                                serde_json::json!({"ok": false, "error": e.to_string()})
                                    .to_string(),
                            );
                        }
                    };
                    let root_dir = self.supervisor.root_dir().to_path_buf();
                    let Ok(fl_path) = flow_file_path_in(&root_dir, &clean_flow) else {
                        return (
                            400,
                            serde_json::json!({"ok": false, "error": "Invalid flow name"})
                                .to_string(),
                        );
                    };
                    if !fl_path.is_file() {
                        return (
                            404,
                            serde_json::json!({
                                "ok": false,
                                "error": format!("Flow '{clean_flow}' not found"),
                            })
                            .to_string(),
                        );
                    }
                    let info = match self.ensure_profile_running(&profile).await {
                        Ok(i) => i,
                        Err(e) => {
                            return (
                                500,
                                serde_json::json!({"ok": false, "error": e.to_string()})
                                    .to_string(),
                            );
                        }
                    };
                    let vars = parse_flow_vars_body(body);
                    let short_id = profile.short_id();
                    let flow_out = clean_flow.clone();
                    let out = Self::run_blocking_json(
                        500,
                        move || {
                            run_flow_on_live_session_in(
                                &root_dir,
                                &clean_flow,
                                &profile,
                                &info.ws_url,
                                &vars,
                            )
                        },
                        move |steps| {
                            serde_json::json!({
                                "ok": true,
                                "flow": flow_out,
                                "short_id": short_id,
                                "executed_steps": steps,
                            })
                        },
                    )
                    .await;
                    self.notify_mutation();
                    return out;
                }

                let Some((target, action)) = rest.rsplit_once('/') else {
                    return (
                        404,
                        serde_json::json!({"ok": false, "error": "Expected /profiles/<id>/<action>"})
                            .to_string(),
                    );
                };
                let profile = match self.lookup_profile(&percent_decode(target)) {
                    Ok(p) => p,
                    Err(resp) => return resp,
                };

                match action {
                    "rotate-proxy" => {
                        if profile.proxy.is_none() {
                            return (
                                400,
                                serde_json::json!({"ok": false, "error": "No proxy configured"})
                                    .to_string(),
                            );
                        }
                        match check_or_rotate_profile_proxy(&self.db, &profile, true).await {
                            Ok((rot, geo)) => {
                                self.notify_mutation();
                                (
                                    200,
                                    serde_json::json!({"ok": true, "rotation": rot, "geo": geo})
                                        .to_string(),
                                )
                            }
                            Err(e) => (
                                502,
                                serde_json::json!({"ok": false, "error": e.to_string()})
                                    .to_string(),
                            ),
                        }
                    }
                    "launch" | "start" => match self.ensure_profile_running(&profile).await {
                        Ok(info) => {
                            let short_id = profile.short_id();
                            let body_owned = body.to_string();
                            let ws_url = info.ws_url.clone();
                            let sid_cl = short_id.clone();
                            let root_dir = self.supervisor.root_dir().to_path_buf();
                            let session = tokio::task::spawn_blocking(move || {
                                let opts: serde_json::Value = serde_json::from_str(&body_owned)
                                    .unwrap_or(serde_json::Value::Null);
                                let open_url = opts.get("url").and_then(|v| v.as_str());
                                let pin_tab = opts.get("pin_tab").and_then(|v| v.as_str());
                                attach_launched_session_in(
                                    &root_dir,
                                    &sid_cl,
                                    &ws_url,
                                    pin_tab,
                                    open_url,
                                )
                                .unwrap_or_else(|_| format!("bon_{sid_cl}"))
                            })
                            .await
                            .unwrap_or_else(|_| format!("bon_{short_id}"));
                            (
                                200,
                                serde_json::json!({
                                    "ok": true,
                                    "id": profile.id,
                                    "short_id": short_id,
                                    "session": session,
                                    "pid": info.pid,
                                    "cdp_port": info.cdp_port,
                                    "ws_url": info.ws_url,
                                })
                                .to_string(),
                            )
                        }
                        Err(e) => (
                            500,
                            serde_json::json!({"ok": false, "error": e.to_string()}).to_string(),
                        ),
                    },
                    "stop" | "close" => {
                        let sup = self.supervisor.clone();
                        let pid = profile.id.clone();
                        let sid = profile.short_id();
                        let stopped =
                            tokio::task::spawn_blocking(move || sup.stop(&pid, &sid))
                                .await
                                .unwrap_or(false);
                        self.notify_mutation();
                        (
                            200,
                            serde_json::json!({"ok": true, "short_id": profile.short_id(), "stopped": stopped})
                                .to_string(),
                        )
                    }
                    "clean-cache" => {
                        let sup = self.supervisor.clone();
                        if sup.live_info(&profile.id).is_some() {
                            return (
                                409,
                                serde_json::json!({"ok": false, "error": "Cannot clean cache while profile is running"})
                                    .to_string(),
                            );
                        }
                        let root_dir = sup.root_dir().to_path_buf();
                        let pid = profile.id.clone();
                        let sid = profile.short_id();
                        let out = Self::run_blocking_json(
                            500,
                            move || clean_profile_cache_in(&root_dir, &pid),
                            move |(freed, rem)| {
                                serde_json::json!({
                                    "ok": true,
                                    "short_id": sid,
                                    "freed_bytes": freed,
                                    "remaining_bytes": rem,
                                })
                            },
                        )
                        .await;
                        if out.0 == 200 {
                            self.notify_mutation();
                        }
                        out
                    }
                    "type" => {
                        let Some(rt) = self.supervisor.live_info(&profile.id) else {
                            return (
                                409,
                                serde_json::json!({"ok": false, "error": "Profile is not running"})
                                    .to_string(),
                            );
                        };
                        let body_owned = body.to_string();
                        Self::run_blocking_json(
                            500,
                            move || cdp_type_as_human(rt.cdp_port, &body_owned),
                            |n| serde_json::json!({"ok": true, "typed_chars": n}),
                        )
                        .await
                    }
                    "totp" | "2fa" => {
                        let Some(rt) = self.supervisor.live_info(&profile.id) else {
                            return (
                                409,
                                serde_json::json!({"ok": false, "error": "Profile is not running"})
                                    .to_string(),
                            );
                        };
                        Self::run_blocking_json(
                            400,
                            move || cdp_type_totp(&profile, rt.cdp_port),
                            |code| serde_json::json!({"ok": true, "code": code, "typed": true}),
                        )
                        .await
                    }
                    "screenshot" => {
                        let Some(rt) = self.supervisor.live_info(&profile.id) else {
                            return (
                                409,
                                serde_json::json!({"ok": false, "error": "Profile is not running"})
                                    .to_string(),
                            );
                        };
                        let sid = profile.short_id();
                        let root_dir = self.supervisor.root_dir().to_path_buf();
                        Self::run_blocking_json(
                            500,
                            move || cdp_capture_screenshot_in(&root_dir, &sid, rt.cdp_port, None),
                            |path| serde_json::json!({"ok": true, "path": path}),
                        )
                        .await
                    }
                    _ => (
                        404,
                        serde_json::json!({"ok": false, "error": "Unknown profile action"})
                            .to_string(),
                    ),
                }
            }
            _ => (
                404,
                serde_json::json!({"ok": false, "error": "Not found"}).to_string(),
            ),
        }
    }
}

#[cfg(test)]
pub async fn handle_control_http_request_in(
    root_dir: &Path,
    method: &str,
    path: &str,
    body: &str,
) -> (u16, String) {
    match ControlEngine::open_at(root_dir) {
        Ok(engine) => engine.handle_http(method, path, body).await,
        Err(e) => (
            500,
            serde_json::json!({"ok": false, "error": e.to_string()}).to_string(),
        ),
    }
}

pub async fn serve_control_http_on_listener(
    listener: tokio::net::TcpListener,
) -> Result<()> {
    let engine = ControlEngine::open_at(&crate::db::default_workspace_root())?;
    serve_control_http_with_engine(listener, engine).await
}

pub async fn serve_control_http_with_engine(
    listener: tokio::net::TcpListener,
    engine: ControlEngine,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let (mut sock, _) = listener.accept().await?;
        let req_engine = engine.clone();
        tokio::spawn(async move {
            const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
            const MAX_HTTP_BODY_BYTES: usize = 64 * 1024;
            let mut raw_buf = Vec::with_capacity(4096);
            let mut chunk = [0u8; 4096];
            let mut header_end = None;
            let mut content_len = 0usize;
            let mut payload_too_large = false;
            while raw_buf.len() < MAX_HTTP_HEADER_BYTES + MAX_HTTP_BODY_BYTES + 4096 {
                let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_secs(5), sock.read(&mut chunk)).await
                else {
                    break;
                };
                if n == 0 {
                    break;
                }
                raw_buf.extend_from_slice(&chunk[..n]);
                if header_end.is_none() {
                    if let Some(pos) = raw_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let end = pos + 4;
                        header_end = Some(end);
                        let hdr_s = String::from_utf8_lossy(&raw_buf[..end]);
                        for line in hdr_s.lines() {
                            if let Some((k, v)) = line.split_once(':')
                                && k.trim().eq_ignore_ascii_case("content-length")
                            {
                                content_len = v.trim().parse().unwrap_or(0);
                            }
                        }
                        if content_len > MAX_HTTP_BODY_BYTES {
                            payload_too_large = true;
                            break;
                        }
                    } else if raw_buf.len() > MAX_HTTP_HEADER_BYTES {
                        payload_too_large = true;
                        break;
                    }
                }
                if let Some(end) = header_end
                    && raw_buf.len() >= end.saturating_add(content_len)
                {
                    break;
                }
            }
            let Some(end) = header_end else {
                if payload_too_large {
                    let msg = "{\"ok\":false,\"error\":\"HTTP headers too large\"}";
                    let resp = format!(
                        "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}",
                        msg.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                }
                return;
            };
            let hdr_part = String::from_utf8_lossy(&raw_buf[..end]).to_string();
            // Reject browser-initiated cross-origin requests & DNS-rebinding Host headers
            let mut has_valid_host = false;
            let mut has_forbidden_hdr = false;
            for l in hdr_part.lines().skip(1) {
                if let Some((k, v)) = l.split_once(':') {
                    let k = k.trim();
                    let v = v.trim().to_ascii_lowercase();
                    if k.eq_ignore_ascii_case("origin")
                        || k.eq_ignore_ascii_case("sec-fetch-site")
                    {
                        has_forbidden_hdr = true;
                    } else if k.eq_ignore_ascii_case("host") {
                        let host_only = v.split(':').next().unwrap_or("");
                        if host_only == "127.0.0.1" || host_only == "localhost" {
                            has_valid_host = true;
                        } else {
                            has_forbidden_hdr = true;
                        }
                    }
                }
            }
            if has_forbidden_hdr || !has_valid_host {
                let forbidden =
                    "{\"ok\":false,\"error\":\"Browser cross-origin requests forbidden\"}";
                let resp = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{forbidden}",
                    forbidden.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                return;
            }
            if payload_too_large {
                let too_big = "{\"ok\":false,\"error\":\"Request body exceeds 64 KiB maximum\"}";
                let resp = format!(
                    "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{too_big}",
                    too_big.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                return;
            }
            if raw_buf.len() < end.saturating_add(content_len) {
                let incomplete = "{\"ok\":false,\"error\":\"Incomplete HTTP request body\"}";
                let resp = format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{incomplete}",
                    incomplete.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                return;
            }
            let body = String::from_utf8_lossy(&raw_buf[end..end + content_len]).to_string();
            let mut first_line = hdr_part.lines().next().unwrap_or("").split_whitespace();
            let method = first_line.next().unwrap_or("GET").to_string();
            let path = first_line.next().unwrap_or("/").to_string();
            let (status, resp_body) = req_engine.handle_http(&method, &path, &body).await;
            let status_text = match status {
                200 => "OK",
                400 => "Bad Request",
                404 => "Not Found",
                409 => "Conflict",
                413 => "Payload Too Large",
                502 => "Bad Gateway",
                _ => "Internal Server Error",
            };
            let http_resp = format!(
                "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                resp_body.len()
            );
            let _ = sock.write_all(http_resp.as_bytes()).await;
        });
    }
}

pub const CONTROL_HTTP_ENDPOINTS: &[&str] = &[
    "GET /health",
    "GET /profiles",
    "GET /flows",
    "POST /profiles/:id/launch",
    "POST /profiles/:id/stop",
    "POST /profiles/:id/rotate-proxy",
    "POST /profiles/:id/clean-cache",
    "POST /profiles/:id/type",
    "POST /profiles/:id/totp",
    "POST /profiles/:id/screenshot",
    "POST /profiles/:id/flow/:flow_name",
    "POST /arrange",
];

async fn run_serve_cli(args: &[String]) -> Result<()> {
    let port: u16 = args
        .windows(2)
        .find_map(|w| (w[0] == "--port" || w[0] == "-p").then(|| w[1].parse().ok()).flatten())
        .unwrap_or(19820);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("Failed to bind 127.0.0.1:{port}"))?;
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "listening": format!("http://127.0.0.1:{port}"),
            "endpoints": CONTROL_HTTP_ENDPOINTS
        })
    );
    serve_control_http_on_listener(listener).await
}

fn run_agent_cli(args: &[String]) -> Result<()> {
    let mut inline_record_flow: Option<String> = None;
    let mut filtered = Vec::with_capacity(args.len());
    let mut idx = 0;
    while idx < args.len() {
        if args[idx] == "--record" {
            let flow_name = args
                .get(idx + 1)
                .ok_or_else(|| anyhow!("Missing flow name after --record"))?;
            inline_record_flow = Some(sanitize_flow_name(flow_name)?);
            idx += 2;
        } else if let Some(flow_name) = args[idx].strip_prefix("--record=") {
            inline_record_flow = Some(sanitize_flow_name(flow_name)?);
            idx += 1;
        } else {
            filtered.push(args[idx].clone());
            idx += 1;
        }
    }

    let target = filtered.first().ok_or_else(|| {
        anyhow!("Usage: bon-login agent <short_id|name> [--record <flow>] <agent-browser args...>")
    })?;
    let rest = &filtered[1..];
    if rest.is_empty() {
        bail!("Usage: bon-login agent <short_id|name> [--record <flow>] <agent-browser args...>");
    }
    validate_stealth_agent_args(rest)?;
    let db = crate::db::Database::open_default()?;
    let profiles = db.list_profiles()?;
    let profile = find_profile_by_query(&profiles, target)?.clone();
    let short_id = profile.short_id();
    let info = ensure_profile_launched_via_supervisor(&db, &profile)?;
    let session = format!("bon_{short_id}");

    let prepared_steps =
        prepare_recorded_steps_in(db.root_dir(), &short_id, &session, &info.ws_url, rest);
    let out = run_agent_browser_with_reconnect_in(db.root_dir(), &short_id, &session, &info.ws_url, rest)?;

    if out.status.success() {
        let has_snapshot = unpack_agent_commands(rest)
            .iter()
            .any(|c| c.first().is_some_and(|op| op == "snapshot"));
        if has_snapshot {
            let stdout_str = String::from_utf8_lossy(&out.stdout);
            let parsed = parse_snapshot_refs(&stdout_str);
            if !parsed.is_empty() {
                save_snap_cache_in(db.root_dir(), &short_id, &parsed);
            }
        }
        if !prepared_steps.is_empty() {
            append_steps_to_flow_path(
                &db.history_flow_path(&short_id),
                &format!("history_{short_id}"),
                &prepared_steps,
            );
            if let Some(flow_name) = inline_record_flow
                && let Ok(fp) = db.flow_file_path(&flow_name)
            {
                append_steps_to_flow_path(&fp, &flow_name, &prepared_steps);
            }
        }
    }

    use std::io::Write;
    let _ = std::io::stdout().write_all(&out.stdout);
    let _ = std::io::stderr().write_all(&out.stderr);
    if !out.status.success() {
        std::process::exit(out.status.code().unwrap_or(1));
    }
    Ok(())
}
fn run_flow_subcommand(args: &[String]) -> Result<()> {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    let rest = if args.is_empty() { &[] } else { &args[1..] };
    let db = crate::db::Database::open_default()?;

    match sub {
        "list" | "ls" => {
            let items: Vec<serde_json::Value> = db
                .list_flows()
                .into_iter()
                .map(|flow| {
                    let vars = extract_flow_vars(&flow);
                    let path = db.flow_file_path(&flow.name).unwrap_or_default();
                    serde_json::json!({
                        "name": flow.name,
                        "domain": flow.domain,
                        "steps_count": flow.steps.len(),
                        "vars": vars,
                        "updated_at": flow.updated_at,
                        "path": path,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&items)?);
            Ok(())
        }
        "show" | "get" | "info" => {
            let name = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login flow show <flow_name>"))?;
            let path = db.flow_file_path(name)?;
            if !path.is_file() {
                bail!("Flow '{}' not found at {}", name, path.display());
            }
            let flow = load_flow_from_path(&path, name)?;
            let vars = extract_flow_vars(&flow);
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "name": flow.name,
                    "domain": flow.domain,
                    "updated_at": flow.updated_at,
                    "vars": vars,
                    "steps_count": flow.steps.len(),
                    "steps": flow.steps,
                    "path": path,
                }))?
            );
            Ok(())
        }
        "save" => {
            let flow_raw = rest.first().ok_or_else(|| {
                anyhow!(
                    "Usage: bon-login flow save <flow_name> <profile_id|name> [--var key=literal ...]"
                )
            })?;
            let prof_target = rest.get(1).ok_or_else(|| {
                anyhow!(
                    "Usage: bon-login flow save <flow_name> <profile_id|name> [--var key=literal ...]"
                )
            })?;
            let profiles = db.list_profiles()?;
            let profile = find_profile_by_query(&profiles, prof_target)?;
            let mut var_pairs = Vec::new();
            let mut idx = 2;
            while idx < rest.len() {
                if let Some((kv, step)) = parse_var_flag(rest, idx) {
                    var_pairs.push(kv);
                    idx += step;
                } else {
                    idx += 1;
                }
            }
            let hist = db.save_history_as_flow(flow_raw, profile, &var_pairs)?;
            let out_path = db.flow_file_path(&hist.name)?;
            let vars = extract_flow_vars(&hist);
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "name": hist.name,
                    "domain": hist.domain,
                    "steps_count": hist.steps.len(),
                    "vars": vars,
                    "steps": hist.steps,
                    "path": out_path,
                }))?
            );
            Ok(())
        }
        "history" => {
            let prof_target = rest.first().ok_or_else(|| {
                anyhow!("Usage: bon-login flow history <profile_id|name> [--clear]")
            })?;
            let clear = rest.iter().any(|a| a == "--clear");
            let profiles = db.list_profiles()?;
            let profile = find_profile_by_query(&profiles, prof_target)?;
            let short_id = profile.short_id();
            if clear {
                db.clear_flow_session_cache(&short_id);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "profile_short_id": short_id,
                        "cleared": true,
                    }))?
                );
                return Ok(());
            }
            let hist = load_flow_from_path(&db.history_flow_path(&short_id), &format!("history_{short_id}"))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "profile_short_id": short_id,
                    "steps_count": hist.steps.len(),
                    "steps": hist.steps,
                }))?
            );
            Ok(())
        }
        "run" | "replay" => {
            let flow_raw = rest.first().ok_or_else(|| {
                anyhow!(
                    "Usage: bon-login flow run <flow_name> <id|name|--group <g>|--all> [--var k=v ...] [--from-step <n>]"
                )
            })?;
            let flow_name = sanitize_flow_name(flow_raw)?;
            let path = db.flow_file_path(&flow_name)?;
            if !path.is_file() {
                bail!("Flow '{}' not found at {}", flow_name, path.display());
            }
            let profiles = db.list_profiles()?;
            let (targets, consumed) =
                select_profiles_by_target(&profiles, &rest[1..]).map_err(|_| {
                    anyhow!(
                        "Usage: bon-login flow run <flow_name> <id|name|--group <g>|--all> [--var k=v ...] [--from-step <n>]"
                    )
                })?;

            let mut cli_vars: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();
            let mut from_step: usize = 0;
            let mut idx = 1 + consumed;
            while idx < rest.len() {
                if let Some(((k, v), step)) = parse_var_flag(rest, idx) {
                    cli_vars.insert(k, v);
                    idx += step;
                } else if matches!(rest[idx].as_str(), "--from-step" | "--from") {
                    let raw_n = rest
                        .get(idx + 1)
                        .ok_or_else(|| anyhow!("Missing step index after {}", rest[idx]))?;
                    from_step = raw_n
                        .parse::<usize>()
                        .with_context(|| format!("Invalid --from-step integer '{raw_n}'"))?;
                    idx += 2;
                } else {
                    idx += 1;
                }
            }

            let mut profile_results = Vec::new();
            let mut any_failed = false;

            for profile in &targets {
                let short_id = profile.short_id();
                let info = ensure_profile_launched_via_supervisor(&db, profile)?;
                let report = replay_flow_steps_in(
                    db.root_dir(),
                    &flow_name,
                    profile,
                    &info.ws_url,
                    &cli_vars,
                    from_step,
                )?;
                if let Some(fail) = report.failure {
                    any_failed = true;
                    profile_results.push(serde_json::json!({
                        "ok": false,
                        "profile_short_id": short_id,
                        "profile_name": profile.name,
                        "executed_steps": report.executed_steps,
                        "failure": fail,
                    }));
                } else {
                    profile_results.push(serde_json::json!({
                        "ok": true,
                        "profile_short_id": short_id,
                        "profile_name": profile.name,
                        "executed_steps": report.executed_steps,
                    }));
                }
            }

            let out_json = if profile_results.len() == 1 {
                profile_results.remove(0)
            } else {
                serde_json::json!({
                    "ok": !any_failed,
                    "flow": flow_name,
                    "results": profile_results,
                })
            };
            println!("{}", serde_json::to_string_pretty(&out_json)?);
            if any_failed {
                std::process::exit(1);
            }
            Ok(())
        }
        "heal" => {
            if rest.len() < 4 {
                bail!(
                    "Usage: bon-login flow heal <flow_name> <step_index> <profile_id|name> <agent-browser args...>"
                );
            }
            let flow_name = sanitize_flow_name(&rest[0])?;
            let step_idx: usize = rest[1]
                .parse()
                .context("step_index must be a non-negative integer")?;
            let prof_target = &rest[2];
            let ab_args = normalize_heal_agent_args(&rest[3..]);
            validate_stealth_agent_args(&ab_args)?;

            let path = db.flow_file_path(&flow_name)?;
            if !path.is_file() {
                bail!("Flow '{}' not found at {}", flow_name, path.display());
            }
            let init_flow = load_flow_from_path(&path, &flow_name)?;
            if step_idx >= init_flow.steps.len() {
                bail!(
                    "step_index {step_idx} out of range (flow '{}' has {} steps)",
                    flow_name,
                    init_flow.steps.len()
                );
            }

            let profiles = db.list_profiles()?;
            let profile = find_profile_by_query(&profiles, prof_target)?;
            let short_id = profile.short_id();
            let info = ensure_profile_launched_via_supervisor(&db, profile)?;
            let session = format!("bon_{short_id}");

            let mut healed_steps =
                prepare_recorded_steps_in(db.root_dir(), &short_id, &session, &info.ws_url, &ab_args);
            let healed_step = healed_steps.pop().ok_or_else(|| {
                anyhow!("Command did not produce a recordable DOM step for healing")
            })?;

            let out =
                run_agent_browser_with_reconnect_in(db.root_dir(), &short_id, &session, &info.ws_url, &ab_args)?;
            if !out.status.success() {
                bail!(
                    "Heal command failed on live browser: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }

            let updated_step = {
                let _guard = FLOW_FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                let mut flow = load_flow_from_path(&path, &flow_name)?;
                if step_idx >= flow.steps.len() {
                    bail!(
                        "step_index {step_idx} out of range (flow '{}' now has {} steps)",
                        flow_name,
                        flow.steps.len()
                    );
                }
                let mut next_step = healed_step;
                if let Some(orig_val) = &flow.steps[step_idx].value
                    && orig_val.contains("{{")
                    && next_step.value.is_some()
                {
                    next_step.value = Some(orig_val.clone());
                }
                flow.steps[step_idx] = next_step.clone();
                save_flow_to_path(&path, &mut flow)?;
                next_step
            };

            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "flow": flow_name,
                    "healed_step_index": step_idx,
                    "updated_step": updated_step,
                    "resume_cli": format!(
                        "bon-login flow run {flow_name} {short_id} --from-step {}",
                        step_idx + 1
                    ),
                }))?
            );
            Ok(())
        }
        "step" => {
            if rest.len() < 3 {
                bail!(
                    "Usage: bon-login flow step <flow_name> <step_index> <optional|required|toggle|delete>"
                );
            }
            let step_idx: usize = rest[1]
                .parse()
                .context("step_index must be a non-negative integer")?;
            let updated = db.mutate_flow_step(&rest[0], step_idx, &rest[2])?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "flow": updated.name,
                    "steps_count": updated.steps.len(),
                    "steps": updated.steps,
                }))?
            );
            Ok(())
        }
        "delete" | "rm" | "remove" => {
            let name = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login flow delete <flow_name>"))?;
            let existed = db.delete_flow(name)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "deleted": sanitize_flow_name(name)?,
                    "existed": existed,
                }))?
            );
            Ok(())
        }
        other => bail!(
            "Unknown flow subcommand '{other}' (expected list, show, save, run, heal, step, history, delete)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_target_selectors_and_cli_lookup_helpers() {
        let mut p1 = Profile::new_default("FB Ads Alpha", PlatformType::MacOS);
        p1.group_tag = "Facebook".to_string();
        let mut p2 = Profile::new_default("TikTok Shop Beta", PlatformType::Windows);
        p2.group_tag = "TikTok".to_string();
        let list = vec![p1.clone(), p2.clone()];

        // 1. find_profile_by_query supports `bon_<short_id>`, exact name, and substring match
        let bon_q = format!("bon_{}", p1.short_id());
        assert_eq!(find_profile_by_query(&list, &bon_q).unwrap().id, p1.id);
        assert_eq!(find_profile_by_query(&list, "shop beta").unwrap().id, p2.id);
        assert!(find_profile_by_query(&list, "").is_err());

        // 2. select_profiles_by_target supports `--all`, `--group`, and comma-separated targets
        let (all_p, used_all) = select_profiles_by_target(&list, &["--all".to_string()]).unwrap();
        assert_eq!(all_p.len(), 2);
        assert_eq!(used_all, 1);

        let (grp_p, used_grp) = select_profiles_by_target(
            &list,
            &["--group".to_string(), "tiktok".to_string(), "--extra".to_string()],
        )
        .unwrap();
        assert_eq!(grp_p.len(), 1);
        assert_eq!(grp_p[0].id, p2.id);
        assert_eq!(used_grp, 2);

        let csv_q = format!("{},{}", p1.short_id(), p2.short_id());
        let (csv_p, _) = select_profiles_by_target(&list, &[csv_q]).unwrap();
        assert_eq!(csv_p.len(), 2);

        // 3. select_proxies_by_target supports `--all`, `--tag #Tag`, and host:port lookup
        let sp1 = SavedProxy::new(
            "US Proxy 1",
            "US-Resi",
            ProxyConfig {
                protocol: ProxyProtocol::Socks5,
                host: "198.51.100.10".to_string(),
                port: 1080,
                username: None,
                password: None,
                change_ip_url: None,
            },
        );
        let proxies = vec![sp1.clone()];
        let (tag_px, used_t) =
            select_proxies_by_target(&proxies, &["--tag".to_string(), "#us-resi".to_string()])
                .unwrap();
        assert_eq!(tag_px.len(), 1);
        assert_eq!(used_t, 2);
        assert_eq!(
            find_saved_proxy_by_query(&proxies, "198.51.100.10:1080")
                .unwrap()
                .id,
            sp1.id
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_control_live_totp_screenshot_conflict_and_csrf_guards() {
        let tmp = std::env::temp_dir().join(format!(
            "bonlogin-ctrl-live-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let ws = crate::db::Database::open_at(&tmp).unwrap();
        let mut p = Profile::new_default("LiveCtrlProf", PlatformType::MacOS);
        p.totp_secret = "JBSWY3DPEHPK3PXP".to_string();
        ws.upsert_profile(&p).unwrap();

        let sup = RuntimeSupervisor::new_in(&tmp);
        let db_arc = Arc::new(Mutex::new(ws));
        let engine = ControlEngine::attached(db_arc.clone(), sup.clone(), Arc::new(|| {}));

        // 1. Calling `/type`, `/totp`, `/screenshot` on a STOPPED profile returns 409 Conflict
        for action in ["type", "totp", "screenshot"] {
            let (code, _) = engine
                .handle_http("POST", &format!("/profiles/{}/{action}", p.short_id()), "hi")
                .await;
            assert_eq!(code, 409, "expected 409 when profile stopped for {action}");
        }

        // 2. Mock a live CDP server handling `/json/list`, `Input.dispatchKeyEvent` (for `/totp`), and `Page.captureScreenshot`
        let cdp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let cdp_port = cdp_listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in cdp_listener.incoming().flatten() {
                let mut s = s;
                let mut req_buf = [0u8; 1024];
                let n = s.read(&mut req_buf).unwrap_or(0);
                let req_str = String::from_utf8_lossy(&req_buf[..n]);
                if req_str.starts_with("GET /json/list") {
                    let body = format!(
                        r#"[{{"id":"t1","type":"page","url":"https://example.com","webSocketDebuggerUrl":"ws://127.0.0.1:{cdp_port}/devtools/page/t1"}}]"#
                    );
                    let _ = s.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    );
                } else if req_str.contains("Upgrade: websocket") {
                    let _ = s.write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                    );
                    while let Ok(h) = {
                        let mut b = [0u8; 2];
                        s.read_exact(&mut b).map(|_| b)
                    } {
                        let len0 = (h[1] & 0x7f) as usize;
                        let len = if len0 == 126 {
                            let mut ext = [0u8; 2];
                            if s.read_exact(&mut ext).is_err() {
                                break;
                            }
                            u16::from_be_bytes(ext) as usize
                        } else {
                            len0
                        };
                        let mut mask = [0u8; 4];
                        if s.read_exact(&mut mask).is_err() {
                            break;
                        }
                        let mut payload = vec![0u8; len];
                        if s.read_exact(&mut payload).is_err() {
                            break;
                        }
                        for (i, b) in payload.iter_mut().enumerate() {
                            *b ^= mask[i & 3];
                        }
                        let msg: serde_json::Value =
                            serde_json::from_slice(&payload).unwrap_or_default();
                        let id = msg["id"].as_u64().unwrap_or(1);
                        let method = msg["method"].as_str().unwrap_or("");
                        let reply = if method == "Page.captureScreenshot" {
                            // Valid 1x1 PNG in base64 ("iVBORw0KGgo=")
                            serde_json::json!({"id": id, "result": {"data": "iVBORw0KGgo="}})
                        } else {
                            serde_json::json!({"id": id, "result": {}})
                        };
                        let r_bytes = reply.to_string().into_bytes();
                        let mut frame = vec![0x81, r_bytes.len() as u8];
                        frame.extend_from_slice(&r_bytes);
                        if s.write_all(&frame).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let child = Command::new("sleep").arg("30").spawn().unwrap();
        let info = RuntimeInfo {
            pid: child.id(),
            cdp_port,
            ws_url: format!("ws://127.0.0.1:{cdp_port}/devtools/browser/live"),
            local_proxy_port: None,
        };
        let pdir = db_arc.lock().unwrap().profile_user_data_dir(&p.id).unwrap();
        std::fs::write(
            pdir.join("bon_runtime.json"),
            serde_json::to_string(&info).unwrap(),
        )
        .unwrap();
        sup.insert_test_process(&p.id, &p.short_id(), child, info);

        // 3. `/clean-cache` on a RUNNING profile must return 409 Conflict
        let (code_cc, _) = engine
            .handle_http("POST", &format!("/profiles/{}/clean-cache", p.short_id()), "")
            .await;
        assert_eq!(code_cc, 409);

        // 4. `/totp` generates 6-digit code and types it via CDP (7 chars including '\n')
        let (code_totp, body_totp) = engine
            .handle_http("POST", &format!("/profiles/{}/totp", p.short_id()), "")
            .await;
        assert_eq!(code_totp, 200, "totp failed: {body_totp}");
        let totp_val: serde_json::Value = serde_json::from_str(&body_totp).unwrap();
        assert_eq!(totp_val["code"].as_str().unwrap().len(), 6);

        // 5. `/screenshot` captures PNG into workspace downloads directory
        let (code_shot, body_shot) = engine
            .handle_http("POST", &format!("/profiles/{}/screenshot", p.short_id()), "")
            .await;
        assert_eq!(code_shot, 200, "screenshot failed: {body_shot}");
        let shot_val: serde_json::Value = serde_json::from_str(&body_shot).unwrap();
        let shot_path = PathBuf::from(shot_val["path"].as_str().unwrap());
        assert!(shot_path.is_file());
        assert_eq!(std::fs::read(&shot_path).unwrap(), b"\x89PNG\r\n\x1a\n");

        // 6. Browser cross-origin headers (`Origin` and `Sec-Fetch-Site`) are rejected with 403
        let std_l = TcpListener::bind("127.0.0.1:0").unwrap();
        std_l.set_nonblocking(true).unwrap();
        let http_p = std_l.local_addr().unwrap().port();
        let tk_l = tokio::net::TcpListener::from_std(std_l).unwrap();
        let eng_cl = engine.clone();
        let srv = tokio::spawn(async move {
            let _ = serve_control_http_with_engine(tk_l, eng_cl).await;
        });
        for evil_hdr in ["Origin: https://evil.example", "Sec-Fetch-Site: cross-site"] {
            let mut s = std::net::TcpStream::connect(("127.0.0.1", http_p)).unwrap();
            s.write_all(
                format!("GET /profiles HTTP/1.1\r\nHost: 127.0.0.1:{http_p}\r\n{evil_hdr}\r\n\r\n")
                    .as_bytes(),
            )
            .unwrap();
            let mut resp = String::new();
            let _ = s.read_to_string(&mut resp);
            assert!(
                resp.starts_with("HTTP/1.1 403"),
                "expected 403 for {evil_hdr}, got: {resp}"
            );
        }
        srv.abort();
        sup.stop_all();
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
