use crate::extensions::{
    discover_unpacked_extensions_in, sync_enabled_remote_extensions_in,
};
use crate::flows::clear_flow_session_cache_in;
use crate::models::{
    GeoInfo, Profile, RuntimeInfo, unix_now,
};
use anyhow::{Context, Result, anyhow, bail};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

// Re-exports from extracted modules (callers still use crate::launcher::...)
pub use crate::cookies::{NormalizedCookieBundle, parse_and_normalize_cookies, read_prelaunch_cookies_in, save_prelaunch_cookies_in};
pub use crate::bookmarks::{read_profile_bookmarks_in, parse_bookmarks_editable, write_profile_bookmarks_checked_in, write_profile_bookmarks_items, ensure_profile_bookmarks, write_profile_preflight_card};
pub use crate::archive::{export_profile_archive_zip_in, import_profile_archive_zip_in};


#[derive(Debug, Clone)]
pub struct KernelInfo {
    pub path: PathBuf,
    pub version_label: String,
}

pub fn app_support_dir() -> PathBuf {
    crate::db::app_data_dir().unwrap_or_else(|_| std::env::temp_dir().join("com.bonlogin.app"))
}

/// Locates the `adryfish/fingerprint-chromium` binary on macOS.
pub fn locate_chromium_kernel() -> Option<KernelInfo> {
    if let Ok(env_path) = std::env::var("BONLOGIN_CHROMIUM_PATH") {
        let trimmed = env_path.trim();
        if !trimmed.is_empty() {
            let p = PathBuf::from(trimmed);
            if p.is_file() {
                return Some(KernelInfo {
                    path: p,
                    version_label: "Custom Kernel (BONLOGIN_CHROMIUM_PATH)".to_string(),
                });
            }
        }
    }

    let mut candidate_roots = vec![app_support_dir().join("kernels")];
    let sys_kernels = crate::db::system_app_data_dir().join("kernels");
    if !candidate_roots.contains(&sys_kernels) {
        candidate_roots.push(sys_kernels);
    }
    for kernels_dir in candidate_roots {
        if !kernels_dir.is_dir() {
            continue;
        }
        let direct_app = kernels_dir.join("Chromium.app/Contents/MacOS/Chromium");
        if direct_app.is_file() {
            return Some(KernelInfo {
                path: direct_app,
                version_label: "adryfish Chromium (Bundled)".to_string(),
            });
        }

        if let Ok(entries) = std::fs::read_dir(&kernels_dir) {
            let mut subdirs: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect();
            subdirs.sort_by(|a, b| b.cmp(a));

            for dir in subdirs {
                let candidate = dir.join("Chromium.app/Contents/MacOS/Chromium");
                if candidate.is_file() {
                    let folder_name = dir
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("adryfish-chromium");
                    return Some(KernelInfo {
                        path: candidate,
                        version_label: folder_name.to_string(),
                    });
                }
            }
        }
    }

    let system_app = PathBuf::from("/Applications/Chromium.app/Contents/MacOS/Chromium");
    if system_app.is_file() {
        return Some(KernelInfo {
            path: system_app,
            version_label: "Applications/Chromium.app".to_string(),
        });
    }
    None
}


/// Removes macOS Gatekeeper quarantine attributes (`com.apple.quarantine`) when present on the `.app` bundle.
pub fn unquarantine_macos_app(binary_path: &Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    fn has_quarantine_xattr(p: &Path) -> bool {
        unsafe extern "C" {
            fn getxattr(
                path: *const std::ffi::c_char,
                name: *const std::ffi::c_char,
                value: *mut std::ffi::c_void,
                size: usize,
                position: u32,
                options: std::ffi::c_int,
            ) -> isize;
        }
        let Ok(c_path) = CString::new(p.as_os_str().as_bytes()) else {
            return true;
        };
        unsafe {
            getxattr(
                c_path.as_ptr(),
                c"com.apple.quarantine".as_ptr(),
                std::ptr::null_mut(),
                0,
                0,
                0,
            ) >= 0
        }
    }

    let target = binary_path
        .ancestors()
        .find(|p| p.extension().and_then(|e| e.to_str()) == Some("app"))
        .unwrap_or(binary_path);

    if !has_quarantine_xattr(target) && !has_quarantine_xattr(binary_path) {
        return;
    }
    let _ = Command::new("xattr")
        .args(["-cr", &target.to_string_lossy()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}
pub const ADRYFISH_MACOS_DMG_URL: &str = "https://github.com/adryfish/fingerprint-chromium/releases/download/148.0.7778.215/ungoogled-chromium_148.0.7778.215-1.1_macos.dmg";
pub const ADRYFISH_MACOS_VERSION_DIR: &str = "chromium-148.0.7778.215";

pub fn install_adryfish_kernel_blocking_opts(force: bool) -> Result<KernelInfo> {
    if !force && let Some(existing) = locate_chromium_kernel() {
        unquarantine_macos_app(&existing.path);
        return Ok(existing);
    }

    let dest_dir = app_support_dir()
        .join("kernels")
        .join(ADRYFISH_MACOS_VERSION_DIR);
    std::fs::create_dir_all(&dest_dir)?;

    let dmg_path = dest_dir.join("adryfish-chromium.dmg");
    let mount_point = dest_dir.join("mnt");
    let _ = std::fs::remove_dir_all(&mount_point);
    std::fs::create_dir_all(&mount_point)?;

    let curl_status = Command::new("curl")
        .args([
            "-fL",
            "--retry",
            "2",
            "-o",
            &dmg_path.to_string_lossy(),
            ADRYFISH_MACOS_DMG_URL,
        ])
        .status()
        .context("Failed to execute curl to download adryfish DMG")?;
    if !curl_status.success() {
        bail!("Failed to download adryfish DMG from GitHub releases");
    }

    let attach_status = Command::new("hdiutil")
        .args([
            "attach",
            &dmg_path.to_string_lossy(),
            "-mountpoint",
            &mount_point.to_string_lossy(),
            "-nobrowse",
            "-readonly",
            "-quiet",
        ])
        .status()
        .context("Failed to mount adryfish DMG via hdiutil")?;
    if !attach_status.success() {
        bail!("hdiutil attach failed on downloaded DMG");
    }

    let mounted_app = mount_point.join("Chromium.app");
    let target_app = dest_dir.join("Chromium.app");
    let _ = std::fs::remove_dir_all(&target_app);

    let cp_res = Command::new("cp")
        .args([
            "-R",
            &mounted_app.to_string_lossy(),
            &target_app.to_string_lossy(),
        ])
        .status();

    let _ = Command::new("hdiutil")
        .args(["detach", &mount_point.to_string_lossy(), "-force", "-quiet"])
        .status();
    let _ = std::fs::remove_dir_all(&mount_point);
    let _ = std::fs::remove_file(&dmg_path);

    let cp_status = cp_res.context("Failed to copy Chromium.app from mounted DMG")?;
    if !cp_status.success() {
        bail!("cp -R Chromium.app failed");
    }

    let binary_path = target_app.join("Contents/MacOS/Chromium");
    unquarantine_macos_app(&binary_path);

    locate_chromium_kernel().ok_or_else(|| anyhow!("Kernel installed but binary not found"))
}

pub fn profile_user_data_dir_in(root_dir: &Path, profile_id: &str) -> Result<PathBuf> {
    let dir = root_dir.join("profiles").join(profile_id);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create user-data-dir at {}", dir.display()))?;
    Ok(dir)
}

pub fn profile_download_dir_in(root_dir: &Path, short_id: &str) -> PathBuf {
    let dir = root_dir.join("downloads").join(format!("bon_{short_id}"));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub(crate) fn runtime_file_path_in(root_dir: &Path, profile_id: &str) -> PathBuf {
    root_dir
        .join("profiles")
        .join(profile_id)
        .join("bon_runtime.json")
}

pub(crate) fn launch_error_file_path_in(root_dir: &Path, profile_id: &str) -> PathBuf {
    root_dir
        .join("profiles")
        .join(profile_id)
        .join("bon_launch_error.txt")
}

fn unix_pid_alive(pid: u32) -> bool {
    if pid == 0 || pid > i32::MAX as u32 {
        return false;
    }
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    let rc = unsafe { kill(pid as i32, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(1)
}
fn unix_send_signal(pid: u32, sig: i32) {
    if pid > 0 && pid <= i32::MAX as u32 {
        unsafe extern "C" {
            fn kill(pid: i32, sig: i32) -> i32;
        }
        unsafe {
            let _ = kill(pid as i32, sig);
        }
    }
}

/// Checks whether a profile currently has a live Chromium instance with an open window.
pub fn probe_live_runtime_in(root_dir: &Path, profile_id: &str) -> Option<RuntimeInfo> {
    let mut rt_path = root_dir.join("profiles");
    rt_path.push(profile_id);
    rt_path.push("bon_runtime.json");

    let Ok(raw) = std::fs::read_to_string(&rt_path) else {
        return None;
    };
    let Ok(info) = serde_json::from_str::<RuntimeInfo>(&raw) else {
        return None;
    };

    let pid_alive = info.pid > 0 && unix_pid_alive(info.pid);
    if info.pid > 0 && !pid_alive {
        let _ = std::fs::remove_file(&rt_path);
        rt_path.set_file_name("DevToolsActivePort");
        let _ = std::fs::remove_file(&rt_path);
        return None;
    }

    match cdp_has_open_window(info.cdp_port) {
        Some(true) => Some(info),
        Some(false) => None,
        None if pid_alive => Some(info),
        None => {
            let _ = std::fs::remove_file(&rt_path);
            rt_path.set_file_name("DevToolsActivePort");
            let _ = std::fs::remove_file(&rt_path);
            None
        }
    }
}

fn flush_prelaunch_state_if_needed_in(
    root_dir: &Path,
    short_id: &str,
    cdp_port: u16,
    ws_url: &str,
) {
    if short_id.is_empty() || cdp_has_open_window(cdp_port) != Some(true) {
        return;
    }
    let states_dir = root_dir.join("states");
    let pre_path = states_dir.join(format!("bon_{short_id}_prelaunch.json"));
    if let Ok((_, live_json)) = agent_export_state_in(root_dir, short_id, ws_url)
        && pre_path.is_file()
    {
        let _ = std::fs::write(pre_path, live_json);
    }
}

fn singleton_lock_pid(user_data_dir: &Path) -> Option<u32> {
    let target = std::fs::read_link(user_data_dir.join("SingletonLock")).ok()?;
    let pid: u32 = target.to_string_lossy().rsplit('-').next()?.parse().ok()?;
    unix_pid_alive(pid).then_some(pid)
}

fn cleanup_stale_singleton_locks(user_data_dir: &Path) {
    if singleton_lock_pid(user_data_dir).is_some() {
        return;
    }
    for name in ["SingletonLock", "SingletonSocket", "SingletonCookie", "RunningChromeVersion"] {
        let _ = std::fs::remove_file(user_data_dir.join(name));
    }
}

/// Gracefully stops a profile launched by another process (CLI daemon or previous session).
fn close_agent_browser_session_async_in(root_dir: &Path, short_id: &str) {
    if short_id.is_empty() {
        return;
    }
    let session = format!("bon_{short_id}");
    if let Ok(mut child) = agent_browser_cmd_for_short_id_in(root_dir, short_id)
        .args(["--session", &session, "close"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
}

fn terminate_pid_gracefully(pid: u32, mut has_exited: impl FnMut() -> bool) {
    #[cfg(unix)]
    if pid > 0 {
        unix_send_signal(pid, 15);
        for i in 0..45 {
            if has_exited() {
                return;
            }
            let wait_ms = if i < 10 { 15 } else { 50 };
            std::thread::sleep(Duration::from_millis(wait_ms));
        }
        if !has_exited() {
            unix_send_signal(pid, 9);
        }
    }
}

pub fn stop_external_runtime_in(root_dir: &Path, profile_id: &str, short_id: &str) -> bool {
    let prof_dir = root_dir.join("profiles").join(profile_id);
    let rt_path = prof_dir.join("bon_runtime.json");
    let active_port_path = prof_dir.join("DevToolsActivePort");
    let maybe_info = std::fs::read_to_string(&rt_path)
        .ok()
        .and_then(|s| serde_json::from_str::<RuntimeInfo>(&s).ok())
        .or_else(|| {
            std::fs::read_to_string(&active_port_path)
                .ok()
                .and_then(|c| parse_devtools_active_port(&c).ok())
                .map(|(cdp_port, ws_url)| RuntimeInfo {
                    pid: 0,
                    cdp_port,
                    ws_url,
                    local_proxy_port: None,
                })
        });
    let had_files = rt_path.is_file() || active_port_path.is_file();

    let mut stopped_any = false;
    if let Some(info) = maybe_info {
        flush_prelaunch_state_if_needed_in(root_dir, short_id, info.cdp_port, &info.ws_url);
        if info.pid > 0 {
            terminate_pid_gracefully(info.pid, || !unix_pid_alive(info.pid));
            stopped_any = true;
        } else if let Some(list_body) = cdp_http_get_body(info.cdp_port, "/json/list")
            && let Ok(serde_json::Value::Array(arr)) = serde_json::from_str(&list_body)
        {
            for item in arr {
                if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                    let _ = cdp_http_get_body(info.cdp_port, &format!("/json/close/{id}"));
                    stopped_any = true;
                }
            }
        }
    }

    let removed_files =
        std::fs::remove_file(&rt_path).is_ok() || std::fs::remove_file(&active_port_path).is_ok();
    if stopped_any || had_files || removed_files {
        close_agent_browser_session_async_in(root_dir, short_id);
    }
    stopped_any || had_files || removed_files
}

pub fn wipe_profile_data_in(root_dir: &Path, profile_id: &str) -> Result<()> {
    let clean_id = profile_id.trim();
    if clean_id.is_empty()
        || clean_id.contains("..")
        || clean_id.contains('/')
        || clean_id.contains('\\')
    {
        bail!("Invalid profile_id for wipe: '{profile_id}'");
    }
    let profiles_root = root_dir.join("profiles");
    let dir = profiles_root.join(clean_id);
    if dir.exists() {
        let trash_dir = profiles_root.join(format!(
            ".trash_{}_{}",
            profile_id,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        if std::fs::rename(&dir, &trash_dir).is_ok() {
            std::thread::spawn(move || {
                let _ = std::fs::remove_dir_all(trash_dir);
            });
        } else {
            std::fs::remove_dir_all(&dir)
                .with_context(|| format!("Failed to wipe profile dir {}", dir.display()))?;
        }
    }
    let short_id: String = profile_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(8)
        .collect();
    let states_dir = root_dir.join("states");
    let _ = std::fs::remove_file(states_dir.join(format!("bon_{short_id}_prelaunch.json")));
    let _ = std::fs::remove_file(states_dir.join(format!("bon_{short_id}_state.json")));
    Ok(())
}

fn dir_size_bytes_seq(path: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    let mut total = 0u64;
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            total = total.saturating_add(dir_size_bytes_seq(&entry.path()));
        } else if ft.is_file()
            && let Ok(meta) = entry.metadata()
        {
            total = total.saturating_add(meta.len());
        }
    }
    total
}

pub fn parallel_map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    if items.len() <= 1 {
        return items.iter().map(f).collect();
    }
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(items.len());
    let next_idx = std::sync::atomic::AtomicUsize::new(0);
    let slots: Vec<std::sync::Mutex<Option<R>>> =
        (0..items.len()).map(|_| std::sync::Mutex::new(None)).collect();
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    let i = next_idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= items.len() {
                        break;
                    }
                    let val = f(&items[i]);
                    if let Ok(mut guard) = slots[i].lock() {
                        *guard = Some(val);
                    }
                }
            });
        }
    });
    slots
        .into_iter()
        .filter_map(|m| m.into_inner().ok().flatten())
        .collect()
}

pub fn dir_size_bytes(path: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    let mut total = 0u64;
    let mut subdirs = Vec::new();
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            subdirs.push(entry.path());
        } else if ft.is_file()
            && let Ok(meta) = entry.metadata()
        {
            total = total.saturating_add(meta.len());
        }
    }
    let sub_sum = parallel_map(&subdirs, |d| dir_size_bytes_seq(d))
        .into_iter()
        .fold(0u64, u64::saturating_add);
    total.saturating_add(sub_sum)
}

pub fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{bytes} B")
    }
}

fn is_safe_cache_cleanup_entry(name: &str) -> bool {
    matches!(
        name,
        "Cache"
            | "Code Cache"
            | "GPUCache"
            | "ShaderCache"
            | "DawnCache"
            | "DawnWebGPUCache"
            | "DawnGraphiteCache"
            | "GrShaderCache"
            | "GraphiteDawnCache"
            | "Crashpad"
            | "BrowserMetrics"
            | "Safe Browsing"
            | "ComponentMetrics"
            | "CacheStorage"
            | "ScriptCache"
    ) || name.ends_with(".tmp")
}

fn clean_dir_ephemeral_recursive(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut freed = 0u64;
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        let p = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if is_safe_cache_cleanup_entry(&name_str) {
            let sz = if ft.is_dir() {
                dir_size_bytes(&p)
            } else {
                entry.metadata().map(|m| m.len()).unwrap_or(0)
            };
            let removed = if ft.is_dir() {
                std::fs::remove_dir_all(&p).is_ok()
            } else {
                std::fs::remove_file(&p).is_ok()
            };
            if removed {
                freed = freed.saturating_add(sz);
            }
        } else if ft.is_dir() {
            freed = freed.saturating_add(clean_dir_ephemeral_recursive(&p));
        }
    }
    freed
}

/// Removes Chromium cache/shader/crashpad bloat from a stopped profile's user-data-dir while preserving Cookies & LocalStorage.
/// Returns `(freed_bytes, remaining_bytes)`.
pub fn clean_profile_cache_in(root_dir: &Path, profile_id: &str) -> Result<(u64, u64)> {
    if probe_live_runtime_in(root_dir, profile_id).is_some() {
        bail!("Cannot clean disk cache while profile '{profile_id}' is running");
    }
    let dir = root_dir.join("profiles").join(profile_id);
    if !dir.is_dir() {
        return Ok((0, 0));
    }
    let freed = clean_dir_ephemeral_recursive(&dir);
    let remaining = dir_size_bytes(&dir);
    Ok((freed, remaining))
}

/// Builds the exact `adryfish/fingerprint-chromium` + Patchright Stealth + WebRTC + DNS leak prevention flags.
/// Maps a BCP-47 locale to the exact `.lproj` ICU locale bundled inside macOS `Chromium.app/Contents/Resources/`
/// so `navigator.language`, `Intl.DateTimeFormat().resolvedOptions().locale`, and `(1).toLocaleString(undefined)`
/// match on CreepJS (`localeEntropyIsTrusty == true` and `localeIntlEntropyIsTrusty == true`).
pub fn chromium_icu_locale(locale: &str) -> String {
    let trimmed = locale.trim().replace('_', "-");
    let lower = trimmed.to_ascii_lowercase();
    match lower.as_str() {
        "" | "en" | "en-us" => "en-US".to_string(),
        "en-gb" | "en-uk" => "en-GB".to_string(),
        "zh-cn" | "zh-hans" | "zh" => "zh-CN".to_string(),
        "zh-tw" | "zh-hant" => "zh-TW".to_string(),
        "zh-hk" => "zh-HK".to_string(),
        "pt-br" => "pt-BR".to_string(),
        "pt-pt" | "pt" => "pt-PT".to_string(),
        "es-419" => "es-419".to_string(),
        "fr-ca" => "fr-CA".to_string(),
        "sr-latn" => "sr-Latn".to_string(),
        _ => trimmed
            .split('-')
            .next()
            .unwrap_or("en-US")
            .to_ascii_lowercase(),
    }
}

pub fn build_chromium_args_with_extensions(
    profile: &Profile,
    local_proxy_port: Option<u16>,
    user_data_dir: &Path,
    effective_geo: Option<&GeoInfo>,
    extension_dirs: &[PathBuf],
) -> Vec<String> {
    let geo = effective_geo.or(profile.resolved_geo.as_ref());

    let timezone_opt = profile
        .custom_timezone
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| geo.map(|g| g.timezone.as_str()).filter(|s| !s.is_empty()));
    let locale = profile
        .custom_locale
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| geo.map(|g| g.locale.as_str()).filter(|s| !s.is_empty()))
        .unwrap_or("en-US");
    let icu_locale = chromium_icu_locale(locale);

    let raw_accept_lang = if let Some(custom_loc) = profile
        .custom_locale
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        format!("{custom_loc},en-US;q=0.9,en;q=0.8")
    } else {
        geo.map(|g| g.accept_lang.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("en-US,en;q=0.9")
            .to_string()
    };
    let first_accept = raw_accept_lang
        .split([',', ';'])
        .next()
        .unwrap_or("")
        .trim();
    let accept_lang = if first_accept.eq_ignore_ascii_case(&icu_locale) {
        raw_accept_lang
    } else {
        format!("{icu_locale},{raw_accept_lang}")
    };

    // Note: Do not pass `--fingerprint-brand-version` or `--fingerprint-platform-version` so
    // `adryfish/fingerprint-chromium` 148 selects its authentic seed-matched Client Hints versions
    // (`kChromiumVersions[seed % 4]` / `kEdgeVersions[seed % 4]` + `Edg/148.0.0.0` in UA).
    let mut args = vec![
        format!("--user-data-dir={}", user_data_dir.display()),
        format!("--fingerprint={}", profile.seed),
        format!(
            "--fingerprint-platform={}",
            profile.os_platform.as_cli_str()
        ),
        format!("--fingerprint-brand={}", profile.brand.as_cli_str()),
        format!(
            "--fingerprint-hardware-concurrency={}",
            profile.hardware_concurrency
        ),
        format!("--lang={icu_locale}"),
        format!("--accept-lang={accept_lang}"),
        "-AppleLanguages".to_string(),
        // XML plist array sets macOS NSUserDefaults AppleLanguages without parsing as a valid GURL in StartupBrowserCreator
        format!("<array><string>{locale}</string></array>"),
    ];
    if let Some(tz) = timezone_opt {
        args.push(format!("--timezone={tz}"));
    }

    if let Some(disabled_csv) = profile.disabled_spoofing_csv() {
        args.push(format!("--disable-spoofing={disabled_csv}"));
    }

    let win_size = profile.window_size.trim();
    if !win_size.is_empty() {
        args.push(format!("--window-size={win_size}"));
    }
    args.push(format!("--window-name={}", profile.window_badge_label()));

    if let Some(port) = local_proxy_port {
        args.push(format!("--proxy-server=http://127.0.0.1:{port}"));
        args.push("--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1".to_string());
    }

    if !extension_dirs.is_empty() {
        let joined = extension_dirs
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(",");
        args.push(format!("--disable-extensions-except={joined}"));
        args.push(format!("--load-extension={joined}"));
        args.push("--disable-features=DisableLoadExtensionCommandLineSwitch".to_string());
    }
    args.push("--allow-file-access-from-files".to_string());

    // WebRTC lock flags
    args.extend([
        "--disable-non-proxied-udp".to_string(),
        "--webrtc-ip-handling-policy=disable_non_proxied_udp".to_string(),
        "--force-webrtc-ip-handling-policy".to_string(),
        "--enforce-webrtc-ip-permission-check".to_string(),
    ]);

    // Patchright Stealth flags
    args.extend([
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--no-service-autorun".to_string(),
        "--password-store=basic".to_string(),
        "--use-mock-keychain".to_string(),
    ]);

    // CDP dynamic port allocation
    args.extend([
        "--remote-debugging-port=0".to_string(),
        "--remote-debugging-address=127.0.0.1".to_string(),
    ]);

    for url in profile.startup_urls() {
        let resolved_url = if matches!(
            url.to_ascii_lowercase().as_str(),
            "bon://preflight" | "bon://start" | "preflight"
        ) {
            format!(
                "file://{}",
                user_data_dir.join("bon_preflight.html").to_string_lossy()
            )
        } else {
            url
        };
        args.push(resolved_url);
    }

    args
}

pub fn parse_devtools_active_port(contents: &str) -> Result<(u16, String)> {
    let mut lines = contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty());

    let port_str = lines
        .next()
        .ok_or_else(|| anyhow!("DevToolsActivePort is empty"))?;
    let cdp_port: u16 = port_str
        .parse()
        .with_context(|| format!("Invalid CDP port in DevToolsActivePort: '{port_str}'"))?;
    if cdp_port == 0 {
        bail!("DevToolsActivePort reported port 0");
    }

    let raw_ws_path = lines.next().unwrap_or("/devtools/browser");
    let ws_path = if raw_ws_path.starts_with('/') {
        raw_ws_path.to_string()
    } else {
        format!("/{raw_ws_path}")
    };

    let ws_url = format!("ws://127.0.0.1:{cdp_port}{ws_path}");
    Ok((cdp_port, ws_url))
}

/// Queries CDP `/json/list` over loopback to check whether any browser tab/window (`page` or `app`) is still open.
/// On macOS, clicking the red close button closes the window while leaving the Chromium process idle in the Dock.
pub fn cdp_has_open_window(cdp_port: u16) -> Option<bool> {
    #[derive(serde::Deserialize)]
    struct CdpTargetType<'a> {
        #[serde(borrow, rename = "type", default)]
        kind: std::borrow::Cow<'a, str>,
    }
    let body = cdp_http_get_body(cdp_port, "/json/list")?;
    let items: Vec<CdpTargetType<'_>> = serde_json::from_str(body.trim()).ok()?;
    Some(
        items
            .iter()
            .any(|item| matches!(item.kind.as_ref(), "page" | "app" | "webview")),
    )
}

pub struct RunningProcess {
    profile_id: String,
    root_dir: PathBuf,
    child: Child,
    info: RuntimeInfo,
    short_id: String,
    tunnel: Option<crate::proxy_tunnel::LocalProxyTunnel>,
    saw_window: bool,
    empty_window_polls: u8,
    launched_at: std::time::Instant,
}

impl RunningProcess {
    pub fn is_process_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    pub fn is_alive(&mut self) -> bool {
        if !self.is_process_running() {
            return false;
        }
        match cdp_has_open_window(self.info.cdp_port) {
            Some(true) => {
                self.saw_window = true;
                self.empty_window_polls = 0;
                true
            }
            Some(false) => {
                if self.saw_window {
                    self.empty_window_polls = self.empty_window_polls.saturating_add(1);
                    // Require 2 consecutive empty polls (~1.6s) so transient tab reloads never kill the browser
                    self.empty_window_polls < 2
                } else {
                    self.launched_at.elapsed() <= Duration::from_secs(15)
                }
            }
            None => true,
        }
    }

    pub fn stop_gracefully(&mut self) {
        let was_running = self.is_process_running();
        if was_running {
            flush_prelaunch_state_if_needed_in(
                &self.root_dir,
                &self.short_id,
                self.info.cdp_port,
                &self.info.ws_url,
            );
            let pid = self.child.id();
            terminate_pid_gracefully(pid, || !matches!(self.child.try_wait(), Ok(None)));
        }

        let _ = self.child.kill();
        let _ = self.child.wait();

        if let Some(mut tunnel) = self.tunnel.take() {
            tunnel.stop();
        }

        let mut removed_files = false;
        if !self.profile_id.is_empty() {
            let r1 =
                std::fs::remove_file(runtime_file_path_in(&self.root_dir, &self.profile_id)).is_ok();
            let r2 = std::fs::remove_file(
                self.root_dir
                    .join("profiles")
                    .join(&self.profile_id)
                    .join("DevToolsActivePort"),
            )
            .is_ok();
            removed_files = r1 || r2;
        }

        if was_running || removed_files {
            close_agent_browser_session_async_in(&self.root_dir, &self.short_id);
        }
    }
}

type InFlightEntry = (
    tokio::sync::broadcast::Sender<std::result::Result<RuntimeInfo, String>>,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
);
type InFlightLaunchMap = std::collections::HashMap<String, InFlightEntry>;

#[derive(Clone)]
pub struct RuntimeSupervisor {
    root_dir: PathBuf,
    kernel_override: Option<PathBuf>,
    processes: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, RunningProcess>>>,
    in_flight: std::sync::Arc<std::sync::Mutex<InFlightLaunchMap>>,
}

impl Default for RuntimeSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeSupervisor {
    pub fn new() -> Self {
        Self::new_in(app_support_dir())
    }

    pub fn new_in(root_dir: impl Into<PathBuf>) -> Self {
        Self {
            root_dir: root_dir.into(),
            kernel_override: None,
            processes: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            in_flight: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_kernel_in(
        root_dir: impl Into<PathBuf>,
        kernel_path: impl Into<PathBuf>,
    ) -> Self {
        let mut sup = Self::new_in(root_dir);
        sup.kernel_override = Some(kernel_path.into());
        sup
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn record_post_launch_db(
        db: &crate::db::Database,
        profile: &Profile,
        maybe_geo: Option<&GeoInfo>,
    ) {
        if let Some(geo) = maybe_geo {
            if let Some(cfg) = &profile.proxy {
                let _ = db.sync_geo_for_proxy_endpoint(cfg, geo);
            }
            let _ = db.update_resolved_geo(&profile.id, Some(geo));
        }
        let _ = db.touch_last_launched(&profile.id);
    }

    pub fn insert_owned(&self, proc: RunningProcess) {
        if let Ok(mut map) = self.processes.lock() {
            map.insert(proc.profile_id.clone(), proc);
        }
    }

    #[cfg(test)]
    pub(crate) fn insert_test_process(
        &self,
        profile_id: &str,
        short_id: &str,
        child: Child,
        info: RuntimeInfo,
    ) {
        self.insert_owned(RunningProcess {
            profile_id: profile_id.to_string(),
            root_dir: self.root_dir.clone(),
            child,
            info,
            short_id: short_id.to_string(),
            tunnel: None,
            saw_window: true,
            empty_window_polls: 0,
            launched_at: std::time::Instant::now(),
        });
    }

    pub fn contains_owned(&self, profile_id: &str) -> bool {
        self.processes
            .lock()
            .ok()
            .is_some_and(|m| m.contains_key(profile_id))
    }

    pub fn live_info(&self, profile_id: &str) -> Option<RuntimeInfo> {
        if let Ok(map) = self.processes.lock()
            && let Some(p) = map.get(profile_id)
        {
            return Some(p.info.clone());
        }
        probe_live_runtime_in(&self.root_dir, profile_id)
    }

    pub async fn ensure_launched(
        &self,
        db: &std::sync::Mutex<crate::db::Database>,
        profile: &Profile,
    ) -> Result<RuntimeInfo> {
        if let Some(existing) = self.live_info(&profile.id) {
            return Ok(existing);
        }

        enum FlightRole {
            Leader(
                tokio::sync::broadcast::Sender<std::result::Result<RuntimeInfo, String>>,
                std::sync::Arc<std::sync::atomic::AtomicBool>,
            ),
            Follower(tokio::sync::broadcast::Receiver<std::result::Result<RuntimeInfo, String>>),
            WaitCancelled(
                tokio::sync::broadcast::Receiver<std::result::Result<RuntimeInfo, String>>,
            ),
        }
        let (tx, cancelled) = loop {
            let role = {
                let mut guard = self
                    .in_flight
                    .lock()
                    .map_err(|_| anyhow!("Supervisor lock poisoned"))?;
                if let Some((existing_tx, existing_cancelled)) = guard.get(&profile.id) {
                    if existing_cancelled.load(std::sync::atomic::Ordering::SeqCst) {
                        FlightRole::WaitCancelled(existing_tx.subscribe())
                    } else {
                        FlightRole::Follower(existing_tx.subscribe())
                    }
                } else {
                    let (tx, _) = tokio::sync::broadcast::channel(8);
                    let cancelled =
                        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    guard.insert(profile.id.clone(), (tx.clone(), cancelled.clone()));
                    FlightRole::Leader(tx, cancelled)
                }
            };
            match role {
                FlightRole::Leader(tx, cancelled) => break (tx, cancelled),
                FlightRole::Follower(mut rx) => {
                    return match rx.recv().await {
                        Ok(Ok(info)) => Ok(info),
                        Ok(Err(msg)) => bail!("{msg}"),
                        Err(_) => self
                            .live_info(&profile.id)
                            .ok_or_else(|| anyhow!("In-flight launch cancelled")),
                    };
                }
                FlightRole::WaitCancelled(mut rx) => {
                    while rx.recv().await.is_ok() {}
                    if let Some(existing) = self.live_info(&profile.id) {
                        return Ok(existing);
                    }
                }
            }
        };
        struct InFlightGuard {
            map: std::sync::Arc<std::sync::Mutex<InFlightLaunchMap>>,
            id: String,
            cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
        }
        impl Drop for InFlightGuard {
            fn drop(&mut self) {
                if let Ok(mut m) = self.map.lock()
                    && m.get(&self.id)
                        .is_some_and(|(_, c)| std::sync::Arc::ptr_eq(c, &self.cancelled))
                {
                    m.remove(&self.id);
                }
            }
        }
        let _flight_guard = InFlightGuard {
            map: self.in_flight.clone(),
            id: profile.id.clone(),
            cancelled: cancelled.clone(),
        };

        match launch_profile_with_kernel_in(
            &self.root_dir,
            profile,
            self.kernel_override.as_deref(),
        )
        .await
        {
            Ok((mut proc, maybe_geo)) => {
                if cancelled.load(std::sync::atomic::Ordering::SeqCst) {
                    let _ = tokio::task::spawn_blocking(move || proc.stop_gracefully()).await;
                    let _ = tx.send(Err("Launch stopped".to_string()));
                    bail!("Launch stopped");
                }
                let info = proc.info.clone();
                if let Ok(db_guard) = db.lock() {
                    Self::record_post_launch_db(&db_guard, profile, maybe_geo.as_ref());
                }
                self.insert_owned(proc);
                let _ = tx.send(Ok(info.clone()));
                Ok(info)
            }
            Err(e) => {
                let _ = tx.send(Err(e.to_string()));
                Err(e)
            }
        }
    }

    pub fn stop(&self, profile_id: &str, short_id: &str) -> bool {
        let mut stopped_in_flight = false;
        if let Ok(flight) = self.in_flight.lock()
            && let Some((tx, cancelled)) = flight.get(profile_id)
        {
            cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = tx.send(Err("Launch stopped".to_string()));
            stopped_in_flight = true;
        }
        let mut stopped_owned = false;
        let maybe_proc = self
            .processes
            .lock()
            .ok()
            .and_then(|mut m| m.remove(profile_id));
        if let Some(mut proc) = maybe_proc {
            proc.stop_gracefully();
            stopped_owned = true;
        }
        let stopped_ext = if stopped_owned {
            false
        } else {
            stop_external_runtime_in(&self.root_dir, profile_id, short_id)
        };
        stopped_in_flight || stopped_owned || stopped_ext
    }

    pub fn stop_and_wipe(&self, profile_id: &str, short_id: &str) -> Result<()> {
        self.stop(profile_id, short_id);
        wipe_profile_data_in(&self.root_dir, profile_id)
    }

    pub fn stop_all(&self) {
        if let Ok(flight) = self.in_flight.lock() {
            for (tx, cancelled) in flight.values() {
                cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
                let _ = tx.send(Err("Launch stopped".to_string()));
            }
        }
        let drained: Vec<std::sync::Mutex<RunningProcess>> = self
            .processes
            .lock()
            .map(|mut map| map.drain().map(|(_, p)| std::sync::Mutex::new(p)).collect())
            .unwrap_or_default();
        parallel_map(&drained, |slot| {
            if let Ok(mut proc) = slot.lock() {
                proc.stop_gracefully();
            }
        });
    }

    pub fn reconcile_live(
        &self,
        candidate_ids: &[String],
    ) -> (Vec<String>, std::collections::HashMap<String, RuntimeInfo>) {
        let mut exited_procs = Vec::new();
        let mut in_proc_ids = std::collections::HashSet::new();
        if let Ok(mut map) = self.processes.lock() {
            let dead_ids: Vec<String> = map
                .iter_mut()
                .filter_map(|(id, proc)| {
                    if proc.is_alive() {
                        in_proc_ids.insert(id.clone());
                        None
                    } else {
                        Some(id.clone())
                    }
                })
                .collect();
            for id in dead_ids {
                if let Some(proc) = map.remove(&id) {
                    exited_procs.push((id, proc));
                }
            }
        }
        let mut exited = Vec::with_capacity(exited_procs.len());
        for (id, mut proc) in exited_procs {
            proc.stop_gracefully();
            exited.push(id);
        }
        let mut external_live = std::collections::HashMap::new();
        for pid in candidate_ids {
            if !in_proc_ids.contains(pid)
                && let Some(info) = probe_live_runtime_in(&self.root_dir, pid)
            {
                external_live.insert(pid.clone(), info);
            }
        }
        (exited, external_live)
    }
}

pub async fn launch_profile_in(
    root_dir: &Path,
    profile: &Profile,
) -> Result<(RunningProcess, Option<GeoInfo>)> {
    launch_profile_with_kernel_in(root_dir, profile, None).await
}

pub(crate) async fn launch_profile_with_kernel_in(
    root_dir: &Path,
    profile: &Profile,
    kernel_override: Option<&Path>,
) -> Result<(RunningProcess, Option<GeoInfo>)> {
    let kernel_path = match kernel_override {
        Some(p) => p.to_path_buf(),
        None => locate_chromium_kernel()
            .ok_or_else(|| {
                anyhow!(
                    "adryfish/fingerprint-chromium binary not found. Click 'Download Kernel 148' \
                     in the top bar or place Chromium.app in ~/Library/Application Support/com.bonlogin.app/kernels/."
                )
            })?
            .path,
    };

    let kernel_path_for_prep = kernel_path.clone();
    let skip_unquarantine = kernel_override.is_some();
    let root_for_prep = root_dir.to_path_buf();
    let prep_fut = async move {
        if !skip_unquarantine {
            tokio::task::spawn_blocking(move || unquarantine_macos_app(&kernel_path_for_prep))
                .await
                .ok();
        }
        sync_enabled_remote_extensions_in(&root_for_prep).await;
    };
    let geo_fut = async {
        if let Some(proxy_cfg) = &profile.proxy {
            let mut tun = crate::proxy_tunnel::LocalProxyTunnel::start(proxy_cfg.clone()).await?;
            let port = tun.local_port();
            match crate::geoip::resolve_geo_via_port(Some(port)).await {
                Ok(geo) => Ok::<_, anyhow::Error>((Some(tun), Some(geo))),
                Err(e) => {
                    tun.stop();
                    Err(anyhow!("Proxy check failed (Fail-Closed): {e}"))
                }
            }
        } else if profile.custom_timezone.is_none() && profile.resolved_geo.is_none() {
            Ok((None, crate::geoip::resolve_geo_via_port(None).await.ok()))
        } else {
            Ok((None, None))
        }
    };
    let (geo_res, ()) = tokio::join!(geo_fut, prep_fut);
    let (mut tunnel, newly_resolved_geo) = geo_res?;

    let local_proxy_port = tunnel.as_ref().map(|t| t.local_port());
    let user_data_dir = match profile_user_data_dir_in(root_dir, &profile.id) {
        Ok(dir) => dir,
        Err(e) => {
            if let Some(mut tun) = tunnel.take() {
                tun.stop();
            }
            return Err(e);
        }
    };

    #[cfg(target_os = "macos")]
    let winbounds_dylib = ensure_macos_winbounds_dylib_in(root_dir);

    let active_port_file = user_data_dir.join("DevToolsActivePort");
    let _ = std::fs::remove_file(&active_port_file);
    let _ = std::fs::remove_file(runtime_file_path_in(root_dir, &profile.id));
    let _ = std::fs::remove_file(launch_error_file_path_in(root_dir, &profile.id));
    cleanup_stale_singleton_locks(&user_data_dir);
    let _ = profile_download_dir_in(root_dir, &profile.short_id());
    ensure_profile_bookmarks(profile, &user_data_dir);
    let _ = write_profile_preflight_card(profile, &user_data_dir, newly_resolved_geo.as_ref());
    let ext_dirs = discover_unpacked_extensions_in(root_dir);
    let args = build_chromium_args_with_extensions(
        profile,
        local_proxy_port,
        &user_data_dir,
        newly_resolved_geo.as_ref(),
        &ext_dirs,
    );

    struct SpawnedChildGuard {
        child: Option<Child>,
        root_dir: PathBuf,
        profile_id: String,
    }
    impl Drop for SpawnedChildGuard {
        fn drop(&mut self) {
            if let Some(mut c) = self.child.take() {
                let _ = c.kill();
                let _ = c.wait();
                let _ = std::fs::remove_file(runtime_file_path_in(&self.root_dir, &self.profile_id));
                let _ = std::fs::remove_file(
                    self.root_dir
                        .join("profiles")
                        .join(&self.profile_id)
                        .join("DevToolsActivePort"),
                );
            }
        }
    }

    let mut cmd = Command::new(&kernel_path);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(target_os = "macos")]
    if let Some(ref dylib) = winbounds_dylib {
        cmd.env("DYLD_INSERT_LIBRARIES", dylib);
    }
    let mut child_guard = match cmd.spawn()
    {
        Ok(c) => SpawnedChildGuard {
            child: Some(c),
            root_dir: root_dir.to_path_buf(),
            profile_id: profile.id.clone(),
        },
        Err(e) => {
            if let Some(mut tun) = tunnel.take() {
                tun.stop();
            }
            return Err(anyhow!(
                "Failed to spawn Chromium at {}: {e}",
                kernel_path.display()
            ));
        }
    };

    let pid = child_guard.child.as_ref().map(Child::id).unwrap_or(0);
    let mut cdp_endpoint: Option<(u16, String)> = None;

    for i in 0..218 {
        if let Ok(contents) = std::fs::read_to_string(&active_port_file)
            && let Ok(parsed) = parse_devtools_active_port(&contents)
        {
            cdp_endpoint = Some(parsed);
            break;
        }

        if let Some(c) = child_guard.child.as_mut()
            && let Ok(Some(status)) = c.try_wait()
        {
            if let Some(mut tun) = tunnel.take() {
                tun.stop();
            }
            bail!("Chromium exited early with status {status} before opening DevToolsActivePort");
        }

        let poll_ms = if i < 30 { 10 } else { 25 };
        tokio::time::sleep(Duration::from_millis(poll_ms)).await;
    }

    let (cdp_port, ws_url) = match cdp_endpoint {
        Some(v) => v,
        None => {
            if let Some(mut tun) = tunnel.take() {
                tun.stop();
            }
            bail!(
                "Timed out (5s) waiting for DevToolsActivePort at {}",
                active_port_file.display()
            );
        }
    };
    let info = RuntimeInfo {
        pid,
        cdp_port,
        ws_url: ws_url.clone(),
        local_proxy_port,
    };
    let mut saw_window = false;
    for i in 0..135 {
        if cdp_has_open_window(cdp_port) == Some(true) {
            saw_window = true;
            break;
        }
        let poll_ms = if i < 25 { 10 } else { 25 };
        tokio::time::sleep(Duration::from_millis(poll_ms)).await;
    }
    let short_id = profile.short_id();
    clear_flow_session_cache_in(root_dir, &short_id);
    let prelaunch_cookies = read_prelaunch_cookies_in(root_dir, &short_id);
    if !prelaunch_cookies.trim().is_empty() {
        let sid = short_id.clone();
        let ws_clone = ws_url.clone();
        let startup_url_hint = profile.startup_url.clone();
        let root_for_ck = root_dir.to_path_buf();
        let _ = tokio::task::spawn_blocking(move || {
            let payload = parse_and_normalize_cookies(&prelaunch_cookies, Some(&startup_url_hint))
                .map(|b| b.to_state_json_pretty())
                .unwrap_or(prelaunch_cookies);
            let _ = agent_import_state_or_cookies_in(&root_for_ck, &sid, &ws_clone, &payload);
        })
        .await;
    }
    if let Ok(json) = serde_json::to_string(&info) {
        let _ = std::fs::write(runtime_file_path_in(root_dir, &profile.id), json);
    }
    let child = child_guard
        .child
        .take()
        .ok_or_else(|| anyhow!("Browser child process missing"))?;
    Ok((
        RunningProcess {
            profile_id: profile.id.clone(),
            root_dir: root_dir.to_path_buf(),
            child,
            info,
            short_id,
            tunnel,
            saw_window,
            empty_window_polls: 0,
            launched_at: std::time::Instant::now(),
        },
        newly_resolved_geo,
    ))
}

// ---------------------------------------------------------------------------
// Built-in `vercel-labs/agent-browser` Runner, Cookie Robot & State Manager
// ---------------------------------------------------------------------------

fn agent_browser_cmd() -> Command {
    static BIN: std::sync::LazyLock<PathBuf> = std::sync::LazyLock::new(|| {
        if let Some(home) = dirs::home_dir() {
            let local_bin = home.join(".local/bin/agent-browser");
            if local_bin.is_file() {
                return local_bin;
            }
        }
        let brew_bin = Path::new("/opt/homebrew/bin/agent-browser");
        if brew_bin.is_file() {
            return brew_bin.to_path_buf();
        }
        PathBuf::from("agent-browser")
    });
    let mut cmd = Command::new(BIN.as_os_str());
    cmd.env("AGENT_BROWSER_NO_VERSION_CHECK", "1")
        .env("AGENT_BROWSER_IDLE_TIMEOUT_MS", "0");
    cmd
}

pub(crate) fn agent_browser_cmd_for_short_id_in(root_dir: &Path, short_id: &str) -> Command {
    let mut cmd = agent_browser_cmd();
    if !short_id.is_empty() {
        cmd.env(
            "AGENT_BROWSER_DOWNLOAD_PATH",
            profile_download_dir_in(root_dir, short_id),
        );
    }
    cmd
}

fn cdp_http_get_body(cdp_port: u16, path: &str) -> Option<String> {
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};

    // shortcut: 1 MiB cap covers 1500+ open CDP targets without unbounded allocation
    const MAX_CDP_HTTP_BYTES: usize = 1_048_576;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), cdp_port);
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(250)).ok()?;
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(250)));
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{cdp_port}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).ok()?;

    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        let scan_from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(rel) = crate::proxy_tunnel::find_double_crlf(&buf[scan_from..]) {
            break scan_from + rel + 4;
        }
        if buf.len() > 65536 {
            return None;
        }
    };
    let headers = std::str::from_utf8(&buf[..header_end]).ok()?;
    let content_len = headers.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| v.trim().parse::<usize>().ok())
            .flatten()
    });
    let target_end = content_len
        .map(|len| header_end.saturating_add(len).min(MAX_CDP_HTTP_BYTES))
        .unwrap_or(MAX_CDP_HTTP_BYTES);
    while buf.len() < target_end {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let body_slice = if let Some(len) = content_len {
        buf.get(header_end..header_end.saturating_add(len))?
    } else {
        buf.get(header_end..)?
    };
    std::str::from_utf8(body_slice).ok().map(ToString::to_string)
}

fn extract_port_from_ws_url(ws_url: &str) -> Option<u16> {
    let after_host = ws_url.strip_prefix("ws://127.0.0.1:")?;
    let port_str = after_host.split('/').next()?;
    port_str.parse().ok()
}

/// Parses `"W,H"`, `"WxH"`, or `"W×H"` into `(width, height)` clamped to sensible bounds.
pub fn parse_window_size(raw: &str) -> Option<(i32, i32)> {
    let cleaned = raw.trim().replace(['×', 'x', 'X', ' '], ",");
    let mut parts = cleaned.split(',').filter(|s| !s.is_empty());
    let w: i32 = parts.next()?.parse().ok()?;
    let h: i32 = parts.next()?.parse().ok()?;
    (w >= 200 && h >= 180).then_some((w.min(7680), h.min(4320)))
}

/// Queries macOS `NSScreen.screens` (`visibleFrame`, which excludes the macOS Menu Bar, Notch, and Dock)
/// and converts from AppKit bottom-left coordinates into Quartz/CDP global top-left coordinates
/// `(work_x, work_y, work_w, work_h)`. Falls back to `CGDisplayBounds` if AppKit screens are unavailable.
/// Note: GPUI's `PlatformDisplay::bounds()` on macOS discards `origin` and always returns `(0, 0)`,
/// which would place Display 2+ browser windows onto Display 1 if used directly.
pub fn macos_active_display_rects() -> Vec<(i32, i32, i32, i32)> {
    #[cfg(target_os = "macos")]
    {
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct CGPoint {
            x: f64,
            y: f64,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct CGSize {
            width: f64,
            height: f64,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct CGRect {
            origin: CGPoint,
            size: CGSize,
        }
        #[link(name = "AppKit", kind = "framework")]
        unsafe extern "C" {}
        #[link(name = "objc", kind = "dylib")]
        unsafe extern "C" {
            fn objc_getClass(name: *const std::ffi::c_char) -> *mut std::ffi::c_void;
            fn sel_registerName(name: *const std::ffi::c_char) -> *mut std::ffi::c_void;
            fn objc_msgSend();
        }
        #[link(name = "ApplicationServices", kind = "framework")]
        unsafe extern "C" {
            fn CGGetActiveDisplayList(
                max_displays: u32,
                active_displays: *mut u32,
                display_count: *mut u32,
            ) -> i32;
            fn CGDisplayBounds(display: u32) -> CGRect;
        }

        unsafe {
            let msg_ptr: unsafe extern "C" fn(
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
            ) -> *mut std::ffi::c_void = std::mem::transmute(objc_msgSend as *const ());
            let app_cls = objc_getClass(c"NSApplication".as_ptr());
            if !app_cls.is_null() {
                let _ = msg_ptr(app_cls, sel_registerName(c"sharedApplication".as_ptr()));
            }
            let cls = objc_getClass(c"NSScreen".as_ptr());
            if !cls.is_null() {
                let msg_usize: unsafe extern "C" fn(
                    *mut std::ffi::c_void,
                    *mut std::ffi::c_void,
                ) -> usize = std::mem::transmute(objc_msgSend as *const ());
                let msg_idx: unsafe extern "C" fn(
                    *mut std::ffi::c_void,
                    *mut std::ffi::c_void,
                    usize,
                ) -> *mut std::ffi::c_void = std::mem::transmute(objc_msgSend as *const ());
                let msg_rect: unsafe extern "C" fn(
                    *mut std::ffi::c_void,
                    *mut std::ffi::c_void,
                ) -> CGRect = std::mem::transmute(objc_msgSend as *const ());

                let screens = msg_ptr(cls, sel_registerName(c"screens".as_ptr()));
                if !screens.is_null() {
                    let n = msg_usize(screens, sel_registerName(c"count".as_ptr()));
                    if n > 0 {
                        let sel_obj = sel_registerName(c"objectAtIndex:".as_ptr());
                        let sel_frame = sel_registerName(c"frame".as_ptr());
                        let sel_vis = sel_registerName(c"visibleFrame".as_ptr());
                        let s0 = msg_idx(screens, sel_obj, 0);
                        let primary_h = msg_rect(s0, sel_frame).size.height;
                        let mut rects = Vec::with_capacity(n.min(32));
                        for i in 0..n.min(32) {
                            let scr = msg_idx(screens, sel_obj, i);
                            if scr.is_null() {
                                continue;
                            }
                            let v = msg_rect(scr, sel_vis);
                            let top_x = v.origin.x.round() as i32;
                            let top_y = (primary_h - (v.origin.y + v.size.height)).round() as i32;
                            let w = (v.size.width.round() as i32).max(500);
                            let h = (v.size.height.round() as i32).max(360);
                            rects.push((top_x, top_y, w, h));
                        }
                        if !rects.is_empty() {
                            return rects;
                        }
                    }
                }
            }

            let mut ids = [0u32; 32];
            let mut count = 0u32;
            let rc = CGGetActiveDisplayList(32, ids.as_mut_ptr(), &mut count);
            if rc == 0 && count > 0 {
                let rects: Vec<(i32, i32, i32, i32)> = ids[..(count as usize).min(32)]
                    .iter()
                    .map(|&id| {
                        let b = CGDisplayBounds(id);
                        (
                            b.origin.x.round() as i32,
                            b.origin.y.round() as i32 + 25,
                            (b.size.width.round() as i32).max(500),
                            (b.size.height.round() as i32 - 25).max(360),
                        )
                    })
                    .collect();
                if !rects.is_empty() {
                    return rects;
                }
            }
        }
    }
    vec![(0, 25, 1920, 1055)]
}

pub fn macos_display_rect(display_idx: usize) -> (i32, i32, i32, i32) {
    let rects = macos_active_display_rects();
    let idx = display_idx.min(rects.len().saturating_sub(1));
    rects.get(idx).copied().unwrap_or((0, 25, 1920, 1055))
}

#[cfg(target_os = "macos")]
fn ensure_macos_winbounds_dylib_in(root_dir: &Path) -> Option<PathBuf> {
    const DYLIB_BYTES: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/libbon_winbounds.dylib"));
    let kernels_dir = root_dir.join("kernels");
    let _ = std::fs::create_dir_all(&kernels_dir);
    let target = kernels_dir.join("libbon_winbounds_v2.dylib");
    if let Ok(existing) = std::fs::read(&target)
        && existing == DYLIB_BYTES
    {
        return Some(target);
    }
    let tmp = kernels_dir.join(format!(
        ".libbon_winbounds.{}.{}.tmp",
        std::process::id(),
        rand::random::<u32>()
    ));
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp).ok()?;
        if f.write_all(DYLIB_BYTES).is_err() || f.sync_all().is_err() {
            let _ = std::fs::remove_file(&tmp);
            return None;
        }
    }
    if std::fs::rename(&tmp, &target).is_err() {
        let _ = std::fs::remove_file(&tmp);
        if !target.is_file() {
            return None;
        }
    }
    Some(target)
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_post_winbounds_notification(
    cdp_port: u16,
    left: i32,
    top: i32,
    width: i32,
    height: i32,
    raise: bool,
) {
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFNotificationCenterGetDistributedCenter() -> *mut std::ffi::c_void;
        fn CFStringCreateWithBytes(
            alloc: *const std::ffi::c_void,
            bytes: *const u8,
            num_bytes: isize,
            encoding: u32,
            is_external: u8,
        ) -> *const std::ffi::c_void;
        fn CFNotificationCenterPostNotificationWithOptions(
            center: *mut std::ffi::c_void,
            name: *const std::ffi::c_void,
            object: *const std::ffi::c_void,
            user_info: *const std::ffi::c_void,
            options: usize,
        );
        fn CFRelease(cf: *const std::ffi::c_void);
    }
    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    const K_CF_NOTIFICATION_DELIVER_IMMEDIATELY: usize = 1;

    let name_bytes = b"com.bonlogin.winbounds";
    let spec = format!(
        "{cdp_port},{left},{top},{width},{height},{}",
        if raise { 1 } else { 0 }
    );
    unsafe {
        let center = CFNotificationCenterGetDistributedCenter();
        if center.is_null() {
            return;
        }
        let cf_name = CFStringCreateWithBytes(
            std::ptr::null(),
            name_bytes.as_ptr(),
            name_bytes.len() as isize,
            K_CF_STRING_ENCODING_UTF8,
            0,
        );
        let cf_obj = CFStringCreateWithBytes(
            std::ptr::null(),
            spec.as_ptr(),
            spec.len() as isize,
            K_CF_STRING_ENCODING_UTF8,
            0,
        );
        if !cf_name.is_null() && !cf_obj.is_null() {
            CFNotificationCenterPostNotificationWithOptions(
                center,
                cf_name,
                cf_obj,
                std::ptr::null(),
                K_CF_NOTIFICATION_DELIVER_IMMEDIATELY,
            );
        }
        if !cf_name.is_null() {
            CFRelease(cf_name);
        }
        if !cf_obj.is_null() {
            CFRelease(cf_obj);
        }
    }
}

/// Computes `(cols, rows, applied_w, applied_h)` for `count` windows inside `(work_w, work_h)`.
pub fn compute_tile_grid_dims(
    work_w: i32,
    work_h: i32,
    win_w: i32,
    win_h: i32,
    _count: usize,
) -> (usize, usize, i32, i32) {
    let usable_w = work_w.max(500);
    let usable_h = work_h.max(360);
    let w = win_w.clamp(200, usable_w);
    let h = win_h.clamp(180, usable_h);
    let cols = (usable_w / w).max(1) as usize;
    let rows = (usable_h / h).max(1) as usize;
    (cols, rows, w, h)
}

pub fn auto_fit_window_size(mon_w: i32, mon_h: i32, count: usize) -> (i32, i32) {
    let usable_w = mon_w.max(500);
    let usable_h = mon_h.max(360);
    let n = count.max(1);
    let max_cols = (usable_w / 200).max(1) as usize;
    let max_rows = (usable_h / 180).max(1) as usize;
    let landscape = usable_w >= usable_h;
    let (cols, rows) = match n {
        1 => (1, 1),
        2 => if landscape { (2, 1) } else { (1, 2) },
        3 | 4 => (2, 2),
        5 | 6 => if landscape { (3, 2) } else { (2, 3) },
        7 | 8 if landscape && usable_w / 4 >= 240 => (4, 2),
        7..=9 => (3, 3),
        _ => {
            let aspect = (usable_w as f32 / usable_h as f32).clamp(0.75, 2.0);
            let c = ((n as f32 * aspect).sqrt().ceil() as usize).clamp(1, max_cols);
            let r = n.div_ceil(c).clamp(1, max_rows);
            (c, r)
        }
    };
    let cols = cols.min(max_cols) as i32;
    let rows = rows.min(max_rows) as i32;
    ((usable_w / cols).max(200), (usable_h / rows).max(180))
}

/// Computes `(left, top, width, height)` for `count` windows tiled inside a usable work-area
/// `(work_x, work_y, work_w, work_h)` (already excluding the macOS menu bar and Dock).
pub fn compute_tile_work_area_bounds(
    work_x: i32,
    work_y: i32,
    work_w: i32,
    work_h: i32,
    win_w: i32,
    win_h: i32,
    count: usize,
) -> Vec<(i32, i32, i32, i32)> {
    if count == 0 {
        return Vec::new();
    }
    let usable_w = work_w.max(500);
    let usable_h = work_h.max(360);
    let (cols, rows, w, h) = compute_tile_grid_dims(usable_w, usable_h, win_w, win_h, count);
    let per_layer = (cols * rows).max(1);

    (0..count)
        .map(|i| {
            let cell = i % per_layer;
            let col = (cell % cols) as i32;
            let row = (cell / cols) as i32;
            let base_left = if cols > 1 && (cols as i32) * w > usable_w {
                work_x + (col * (usable_w - w)) / (cols as i32 - 1)
            } else {
                work_x + col * w
            };
            let base_top = if rows > 1 && (rows as i32) * h > usable_h {
                work_y + (row * (usable_h - h)) / (rows as i32 - 1)
            } else {
                work_y + row * h
            };
            let left = base_left.min(work_x + usable_w - w);
            let top = base_top.min(work_y + usable_h - h);
            (left, top, w, h)
        })
        .collect()
}

/// Computes `(left, top, width, height)` for `count` windows tiled across a full monitor `(mon_x, mon_y, mon_w, mon_h)`.
/// Reserves `25px` at the top of the monitor for the macOS menu bar and cascades overflow layers by `24px`.
#[cfg(test)]
pub fn compute_tile_bounds(
    mon_x: i32,
    mon_y: i32,
    mon_w: i32,
    mon_h: i32,
    win_w: i32,
    win_h: i32,
    count: usize,
) -> Vec<(i32, i32, i32, i32)> {
    compute_tile_work_area_bounds(mon_x, mon_y + 25, mon_w, mon_h - 25, win_w, win_h, count)
}

pub(crate) fn encode_ws_client_text_frame(msg: &str) -> Vec<u8> {
    let payload = msg.as_bytes();
    let mask = [0x12u8, 0x34, 0x56, 0x78];
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.push(0x81);
    if payload.len() < 126 {
        frame.push(0x80 | (payload.len() as u8));
    } else if payload.len() <= u16::MAX as usize {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        frame.push(b ^ mask[i & 3]);
    }
    frame
}

/// Minimal stealth CDP WebSocket client (zero `Runtime.enable` or `Emulation.*` domains).
struct CdpClient {
    stream: std::net::TcpStream,
    buf: Vec<u8>,
    next_id: u64,
}

impl CdpClient {
    fn connect(cdp_port: u16, ws_url: &str) -> Result<Self> {
        use std::io::{Read, Write};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};

        let ws_path = ws_url
            .strip_prefix("ws://127.0.0.1:")
            .and_then(|s| s.split_once('/'))
            .map(|(_, path)| format!("/{path}"))
            .context("Invalid CDP WebSocket URL")?;

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), cdp_port);
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(350))?;
        let _ = stream.set_nodelay(true);
        let _ = stream.set_read_timeout(Some(Duration::from_millis(600)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(600)));

        let handshake = format!(
            "GET {ws_path} HTTP/1.1\r\n\
             Host: 127.0.0.1:{cdp_port}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        stream.write_all(handshake.as_bytes())?;

        let mut buf = Vec::with_capacity(2048);
        let mut chunk = [0u8; 1024];
        let header_end = loop {
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                bail!("Unexpected EOF during CDP WebSocket handshake");
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            if buf.len() > 16384 {
                bail!("CDP WebSocket handshake header too large");
            }
        };
        if !buf[..header_end].starts_with(b"HTTP/1.1 101") {
            bail!("CDP WebSocket upgrade rejected");
        }
        buf.drain(..header_end);
        Ok(Self {
            stream,
            buf,
            next_id: 1,
        })
    }

    fn connect_first_page(cdp_port: u16) -> Result<(String, Self)> {
        let (target_id, page_ws_url) = cdp_first_page_target(cdp_port)?;
        let client = Self::connect(cdp_port, &page_ws_url)?;
        Ok((target_id, client))
    }

    fn set_read_timeout(&mut self, timeout: Duration) {
        let _ = self.stream.set_read_timeout(Some(timeout));
    }

    fn call(&mut self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        use std::io::{Read, Write};
        let expected_id = self.next_id;
        self.next_id += 1;
        let req = serde_json::json!({
            "id": expected_id,
            "method": method,
            "params": params,
        });
        let frame = encode_ws_client_text_frame(&req.to_string());
        self.stream.write_all(&frame)?;

        let mut chunk = [0u8; 2048];
        for _ in 0..16 {
            while self.buf.len() < 2 {
                let n = self.stream.read(&mut chunk)?;
                if n == 0 {
                    bail!("EOF reading CDP WebSocket frame");
                }
                self.buf.extend_from_slice(&chunk[..n]);
            }
            let opcode = self.buf[0] & 0x0f;
            let len0 = (self.buf[1] & 0x7f) as usize;
            let (hdr_len, payload_len) = if len0 < 126 {
                (2usize, len0)
            } else if len0 == 126 {
                while self.buf.len() < 4 {
                    let n = self.stream.read(&mut chunk)?;
                    if n == 0 {
                        bail!("EOF reading CDP frame length");
                    }
                    self.buf.extend_from_slice(&chunk[..n]);
                }
                (4, u16::from_be_bytes([self.buf[2], self.buf[3]]) as usize)
            } else {
                while self.buf.len() < 10 {
                    let n = self.stream.read(&mut chunk)?;
                    if n == 0 {
                        bail!("EOF reading CDP 64-bit frame length");
                    }
                    self.buf.extend_from_slice(&chunk[..n]);
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&self.buf[2..10]);
                (10, u64::from_be_bytes(arr) as usize)
            };
            const MAX_CDP_WS_FRAME_BYTES: usize = 32 * 1024 * 1024;
            if payload_len > MAX_CDP_WS_FRAME_BYTES {
                bail!(
                    "CDP frame length ({payload_len} bytes) exceeds maximum ({MAX_CDP_WS_FRAME_BYTES})"
                );
            }
            while self.buf.len() < hdr_len + payload_len {
                let n = self.stream.read(&mut chunk)?;
                if n == 0 {
                    bail!("EOF reading CDP frame payload");
                }
                self.buf.extend_from_slice(&chunk[..n]);
            }
            let data: Vec<u8> = self.buf.drain(..hdr_len + payload_len).skip(hdr_len).collect();
            if opcode == 0x8 {
                bail!("CDP WebSocket closed by browser");
            }
            if opcode == 0x9 {
                let pong = [0x8Au8, 0x80, 0x12, 0x34, 0x56, 0x78];
                let _ = self.stream.write_all(&pong);
                continue;
            }
            if opcode == 0x1
                && let Ok(val) = serde_json::from_slice::<serde_json::Value>(&data)
                && val.get("id").and_then(|v| v.as_u64()) == Some(expected_id)
            {
                if let Some(err) = val.get("error") {
                    bail!("CDP error: {err}");
                }
                return Ok(val);
            }
        }
        bail!("Timed out waiting for CDP response id={expected_id}")
    }
}

fn cdp_first_page_target(cdp_port: u16) -> Result<(String, String)> {
    let list_body =
        cdp_http_get_body(cdp_port, "/json/list").context("Failed to query CDP /json/list")?;
    let targets: serde_json::Value = serde_json::from_str(list_body.trim())?;
    targets
        .as_array()
        .and_then(|arr| {
            let find_page = |skip_internal: bool| {
                arr.iter().find_map(|t| {
                    let ty = t.get("type")?.as_str()?;
                    let url = t.get("url").and_then(|u| u.as_str()).unwrap_or("");
                    let ok_url = !skip_internal
                        || (!url.starts_with("chrome-extension://")
                            && !url.starts_with("devtools://"));
                    if !matches!(ty, "page" | "app") || !ok_url {
                        return None;
                    }
                    let id = t.get("id")?.as_str()?.to_string();
                    let ws = t
                        .get("webSocketDebuggerUrl")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string)
                        .unwrap_or_else(|| format!("ws://127.0.0.1:{cdp_port}/devtools/page/{id}"));
                    Some((id, ws))
                })
            };
            find_page(true).or_else(|| find_page(false))
        })
        .context("No open browser page target found")
}

/// Resizes, restores, or activates a running Chromium window via Browser-domain CDP (`Browser.setWindowBounds`),
/// preserving 100% stealth (no `Emulation.*` or `Runtime.enable`).
fn cdp_update_and_activate_window(
    cdp_port: u16,
    ws_url: &str,
    rect: Option<(i32, i32, i32, i32)>,
    raise_macos: bool,
) -> Result<()> {
    let (target_id, _) = cdp_first_page_target(cdp_port)?;
    let mut cdp = CdpClient::connect(cdp_port, ws_url)?;

    let win_resp = cdp.call(
        "Browser.getWindowForTarget",
        serde_json::json!({ "targetId": target_id }),
    )?;
    let window_id = win_resp
        .get("result")
        .and_then(|r| r.get("windowId"))
        .and_then(|w| w.as_i64())
        .context("Missing windowId in Browser.getWindowForTarget")?;
    let win_state = win_resp
        .get("result")
        .and_then(|r| r.get("bounds"))
        .and_then(|b| b.get("windowState"))
        .and_then(|s| s.as_str())
        .unwrap_or("normal");

    if if rect.is_some() {
        win_state != "normal"
    } else {
        win_state == "minimized"
    } {
        cdp.call(
            "Browser.setWindowBounds",
            serde_json::json!({
                "windowId": window_id,
                "bounds": { "windowState": "normal" }
            }),
        )?;
    }

    if let Some((left, top, width, height)) = rect {
        cdp.call(
            "Browser.setWindowBounds",
            serde_json::json!({
                "windowId": window_id,
                "bounds": { "left": left, "top": top, "width": width, "height": height }
            }),
        )?;
    }

    let _ = cdp.call(
        "Target.activateTarget",
        serde_json::json!({ "targetId": target_id }),
    );

    #[cfg(target_os = "macos")]
    if let Some((left, top, width, height)) = rect {
        macos_post_winbounds_notification(cdp_port, left, top, width, height, raise_macos);
    } else if raise_macos {
        macos_post_winbounds_notification(cdp_port, 0, 0, 0, 0, true);
    }
    Ok(())
}

#[cfg(test)]
pub fn cdp_set_window_bounds(
    cdp_port: u16,
    ws_url: &str,
    left: i32,
    top: i32,
    width: i32,
    height: i32,
) -> Result<()> {
    cdp_update_and_activate_window(cdp_port, ws_url, Some((left, top, width, height)), true)
}

pub fn cdp_set_window_bounds_quiet(
    cdp_port: u16,
    ws_url: &str,
    left: i32,
    top: i32,
    width: i32,
    height: i32,
) -> Result<()> {
    cdp_update_and_activate_window(cdp_port, ws_url, Some((left, top, width, height)), false)
}

/// Brings a running Chromium window to the front on macOS (restores if minimized, activates CDP target, and raises PID).
pub fn cdp_focus_window_in(
    root_dir: &Path,
    profile_id: &str,
    pid: u32,
    cdp_port: u16,
    ws_url: &str,
) -> Result<()> {
    let cdp_res = cdp_update_and_activate_window(cdp_port, ws_url, None, true);
    #[cfg(target_os = "macos")]
    {
        let effective_pid = if pid > 0 {
            Some(pid)
        } else {
            singleton_lock_pid(&root_dir.join("profiles").join(profile_id))
        };
        if let Some(p) = effective_pid {
            let script = format!(
                "tell application \"System Events\" to set frontmost of first process whose unix id is {p} to true"
            );
            let _ = Command::new("osascript")
                .args(["-e", &script])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
    cdp_res
}

/// Types `text` character-by-character into the focused element of a running Chromium window via
/// page-target CDP `Input.dispatchKeyEvent` (no `Runtime.enable` or clipboard paste event).
pub fn cdp_type_as_human(cdp_port: u16, text: &str) -> Result<usize> {
    if text.is_empty() {
        return Ok(0);
    }
    let (_, mut cdp) = CdpClient::connect_first_page(cdp_port)?;
    let mut typed = 0usize;
    for ch in text.chars() {
        if ch == '\r' {
            continue;
        }
        let (down_params, up_params) = if ch == '\n' {
            (
                serde_json::json!({
                    "type": "rawKeyDown",
                    "key": "Enter",
                    "code": "Enter",
                    "windowsVirtualKeyCode": 13,
                    "nativeVirtualKeyCode": 13,
                    "text": "\r",
                    "unmodifiedText": "\r"
                }),
                serde_json::json!({
                    "type": "keyUp",
                    "key": "Enter",
                    "code": "Enter",
                    "windowsVirtualKeyCode": 13,
                    "nativeVirtualKeyCode": 13
                }),
            )
        } else {
            let s = ch.to_string();
            (
                serde_json::json!({
                    "type": "keyDown",
                    "key": s,
                    "text": s,
                    "unmodifiedText": s
                }),
                serde_json::json!({
                    "type": "keyUp",
                    "key": s
                }),
            )
        };
        cdp.call("Input.dispatchKeyEvent", down_params)?;
        cdp.call("Input.dispatchKeyEvent", up_params)?;
        typed += 1;
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(typed)
}

/// Reads `<user_data_dir>/Default/Bookmarks` into `(Name, URL)` pairs (empty if no bookmarks yet).
/// Generates the current 6-digit TOTP code for `profile` and types `{code}\n` into the active browser input.
pub fn cdp_type_totp(profile: &Profile, cdp_port: u16) -> Result<String> {
    let (code, _) = profile
        .current_totp()
        .ok_or_else(|| anyhow!("Profile '{}' has no valid 2FA TOTP secret", profile.name))?;
    cdp_type_as_human(cdp_port, &format!("{code}\n"))?;
    Ok(code)
}

/// Navigates the active page tab of a running Chromium instance via CDP `Page.navigate`.
pub fn cdp_navigate_page(cdp_port: u16, url: &str) -> Result<()> {
    let (_, mut cdp) = CdpClient::connect_first_page(cdp_port)?;
    cdp.call("Page.navigate", serde_json::json!({ "url": url.trim() }))?;
    Ok(())
}

/// Captures a PNG screenshot of the active tab via CDP `Page.captureScreenshot` (no `Runtime.enable`).
pub fn cdp_capture_screenshot_in(
    root_dir: &Path,
    short_id: &str,
    cdp_port: u16,
    custom_out: Option<&Path>,
) -> Result<PathBuf> {
    use base64::Engine;
    let (_, mut cdp) = CdpClient::connect_first_page(cdp_port)?;
    cdp.set_read_timeout(Duration::from_secs(4));
    let resp = cdp.call("Page.captureScreenshot", serde_json::json!({ "format": "png" }))?;
    let b64 = resp
        .get("result")
        .and_then(|r| r.get("data"))
        .and_then(|d| d.as_str())
        .context("Missing base64 data in Page.captureScreenshot response")?;
    let png_bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("Failed to decode screenshot PNG base64")?;
    let out_path = match custom_out {
        Some(p) => p.to_path_buf(),
        None => {
            let dir = crate::db::export_dir_for_root(root_dir);
            dir.join(format!("bon_{short_id}_{}.png", unix_now()))
        }
    };
    std::fs::write(&out_path, png_bytes)?;
    Ok(out_path)
}

// ---------------------------------------------------------------------------
// Multi-Profile Synchronizer (1-to-N Live Input & Navigation Mirror via CDP)
// ---------------------------------------------------------------------------

const MASTER_SYNC_RECORDER_JS: &str = r#"(() => {
  const st = window.__bonSyncState || (window.__bonSyncState = { q: [], hooked: false, lastUrl: location.href });
  if (!st.hooked) {
    st.hooked = true;
    const push = (ev) => {
      ev.vw = window.innerWidth || 1280;
      ev.vh = window.innerHeight || 800;
      if (st.q.length < 256) st.q.push(ev);
    };
    window.addEventListener('mousedown', (e) => {
      if (!e.isTrusted) return;
      push({ k: 'mouse', sub: 'down', x: Math.round(e.clientX), y: Math.round(e.clientY), b: e.button || 0, c: e.detail || 1, m: (e.altKey?1:0)|(e.ctrlKey?2:0)|(e.metaKey?4:0)|(e.shiftKey?8:0) });
    }, true);
    window.addEventListener('mouseup', (e) => {
      if (!e.isTrusted) return;
      push({ k: 'mouse', sub: 'up', x: Math.round(e.clientX), y: Math.round(e.clientY), b: e.button || 0, c: e.detail || 1, m: (e.altKey?1:0)|(e.ctrlKey?2:0)|(e.metaKey?4:0)|(e.shiftKey?8:0) });
    }, true);
    let wt = null, wx = 0, wy = 0, lx = 0, ly = 0;
    window.addEventListener('wheel', (e) => {
      if (!e.isTrusted) return;
      wx += e.deltaX; wy += e.deltaY; lx = Math.round(e.clientX); ly = Math.round(e.clientY);
      if (!wt) {
        wt = setTimeout(() => {
          push({ k: 'wheel', x: lx, y: ly, dx: Math.round(wx), dy: Math.round(wy) });
          wx = 0; wy = 0; wt = null;
        }, 45);
      }
    }, { capture: true, passive: true });
    window.addEventListener('keydown', (e) => {
      if (!e.isTrusted) return;
      if (e.key === 'Shift' || e.key === 'Control' || e.key === 'Alt' || e.key === 'Meta') return;
      push({ k: 'key', sub: 'down', key: e.key || '', code: e.code || '', vk: e.keyCode || 0, m: (e.altKey?1:0)|(e.ctrlKey?2:0)|(e.metaKey?4:0)|(e.shiftKey?8:0) });
    }, true);
    window.addEventListener('keyup', (e) => {
      if (!e.isTrusted) return;
      if (e.key === 'Shift' || e.key === 'Control' || e.key === 'Alt' || e.key === 'Meta') return;
      push({ k: 'key', sub: 'up', key: e.key || '', code: e.code || '', vk: e.keyCode || 0, m: (e.altKey?1:0)|(e.ctrlKey?2:0)|(e.metaKey?4:0)|(e.shiftKey?8:0) });
    }, true);
  }
  if (location.href !== st.lastUrl) {
    st.lastUrl = location.href;
  }
  const out = st.q.splice(0, 64);
  return JSON.stringify({ url: location.href, vw: window.innerWidth || 1280, vh: window.innerHeight || 800, events: out });
})()"#;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SyncCapturedEvent {
    #[serde(rename = "k", default)]
    pub kind: String,
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub x: i32,
    #[serde(default)]
    pub y: i32,
    #[serde(default)]
    pub vw: i32,
    #[serde(default)]
    pub vh: i32,
    #[serde(rename = "b", default)]
    pub button: u8,
    #[serde(rename = "c", default)]
    pub click_count: i32,
    #[serde(rename = "m", default)]
    pub modifiers: i32,
    #[serde(default)]
    pub dx: i32,
    #[serde(default)]
    pub dy: i32,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub vk: i32,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SyncMasterPollBatch {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub vw: i32,
    #[serde(default)]
    pub vh: i32,
    #[serde(default)]
    pub events: Vec<SyncCapturedEvent>,
}

impl CdpClient {
    /// Evaluates `expression` inside an isolated utility world (`Page.createIsolatedWorld`) on the page
    /// without calling `Runtime.enable`, preserving 100% C++ stealth on BrowserScan & CreepJS.
    fn eval_in_isolated_world(
        &mut self,
        target_id: &str,
        cached_ctx_id: &mut Option<i64>,
        expression: &str,
    ) -> Result<String> {
        for attempt in 0..2 {
            let ctx_id = match *cached_ctx_id {
                Some(id) => id,
                None => {
                    let world = self.call(
                        "Page.createIsolatedWorld",
                        serde_json::json!({
                            "frameId": target_id,
                            "worldName": "__bon_sync",
                            "grantUniveralAccess": true
                        }),
                    )?;
                    let id = world
                        .get("result")
                        .and_then(|r| r.get("executionContextId"))
                        .and_then(|v| v.as_i64())
                        .context("Missing executionContextId from Page.createIsolatedWorld")?;
                    *cached_ctx_id = Some(id);
                    id
                }
            };
            match self.call(
                "Runtime.evaluate",
                serde_json::json!({
                    "expression": expression,
                    "contextId": ctx_id,
                    "returnByValue": true
                }),
            ) {
                Ok(resp) => {
                    if resp
                        .get("result")
                        .and_then(|r| r.get("exceptionDetails"))
                        .is_some()
                        && attempt == 0
                    {
                        *cached_ctx_id = None;
                        continue;
                    }
                    let s = resp
                        .get("result")
                        .and_then(|r| r.get("result"))
                        .and_then(|r| r.get("value"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("{}")
                        .to_string();
                    return Ok(s);
                }
                Err(_) if attempt == 0 => {
                    *cached_ctx_id = None;
                }
                Err(e) => return Err(e),
            }
        }
        bail!("Failed to evaluate in isolated world")
    }
}

/// Scales `(x, y)` from Master viewport `(src_vw, src_vh)` to Follower viewport `(dst_vw, dst_vh)`.
pub fn scale_sync_point(
    x: i32,
    y: i32,
    src_vw: i32,
    src_vh: i32,
    dst_vw: i32,
    dst_vh: i32,
) -> (i32, i32) {
    let sw = src_vw.max(1) as f64;
    let sh = src_vh.max(1) as f64;
    let dw = dst_vw.max(1) as f64;
    let dh = dst_vh.max(1) as f64;
    let sx = ((x as f64 / sw) * dw).round() as i32;
    let sy = ((y as f64 / sh) * dh).round() as i32;
    (sx.clamp(0, dst_vw.max(1)), sy.clamp(0, dst_vh.max(1)))
}

/// Dispatches a batch of `SyncCapturedEvent`s (and optional URL navigation) onto a Follower CDP client.
fn dispatch_sync_batch_to_follower(
    cdp: &mut CdpClient,
    follower_target_id: &str,
    follower_ctx_id: &mut Option<i64>,
    follower_vw_vh: &mut (i32, i32),
    nav_url: Option<&str>,
    events: &[SyncCapturedEvent],
) -> Result<usize> {
    let mut applied = 0usize;
    if let Some(u) = nav_url.filter(|u| {
        !u.is_empty() && !u.starts_with("devtools://") && !u.starts_with("chrome-extension://")
    }) {
        cdp.call("Page.navigate", serde_json::json!({ "url": u }))?;
        *follower_ctx_id = None;
        applied += 1;
    }
    if events.is_empty() {
        return Ok(applied);
    }
    if follower_vw_vh.0 <= 0
        && let Ok(raw_vp) = cdp.eval_in_isolated_world(
            follower_target_id,
            follower_ctx_id,
            "JSON.stringify([window.innerWidth||1280, window.innerHeight||800])",
        )
        && let Ok(pair) = serde_json::from_str::<[i32; 2]>(&raw_vp)
    {
        *follower_vw_vh = (pair[0].max(200), pair[1].max(200));
    }
    let (dst_vw, dst_vh) = if follower_vw_vh.0 > 0 {
        *follower_vw_vh
    } else {
        (1280, 800)
    };

    for ev in events {
        match ev.kind.as_str() {
            "mouse" => {
                let (tx, ty) = scale_sync_point(ev.x, ev.y, ev.vw, ev.vh, dst_vw, dst_vh);
                let (btn_name, buttons_mask) = match ev.button {
                    2 => ("right", 2),
                    1 => ("middle", 4),
                    _ => ("left", 1),
                };
                if ev.sub == "down" {
                    let _ = cdp.call(
                        "Input.dispatchMouseEvent",
                        serde_json::json!({
                            "type": "mouseMoved",
                            "x": tx,
                            "y": ty,
                            "modifiers": ev.modifiers,
                        }),
                    );
                    cdp.call(
                        "Input.dispatchMouseEvent",
                        serde_json::json!({
                            "type": "mousePressed",
                            "x": tx,
                            "y": ty,
                            "button": btn_name,
                            "buttons": buttons_mask,
                            "clickCount": ev.click_count.max(1),
                            "modifiers": ev.modifiers,
                        }),
                    )?;
                } else {
                    cdp.call(
                        "Input.dispatchMouseEvent",
                        serde_json::json!({
                            "type": "mouseReleased",
                            "x": tx,
                            "y": ty,
                            "button": btn_name,
                            "buttons": 0,
                            "clickCount": ev.click_count.max(1),
                            "modifiers": ev.modifiers,
                        }),
                    )?;
                }
                applied += 1;
            }
            "wheel" => {
                let (tx, ty) = scale_sync_point(ev.x, ev.y, ev.vw, ev.vh, dst_vw, dst_vh);
                cdp.call(
                    "Input.dispatchMouseEvent",
                    serde_json::json!({
                        "type": "mouseWheel",
                        "x": tx,
                        "y": ty,
                        "deltaX": ev.dx,
                        "deltaY": ev.dy,
                    }),
                )?;
                applied += 1;
            }
            "key" => {
                let is_down = ev.sub == "down";
                let is_printable = ev.key.chars().count() == 1 && (ev.modifiers & !8) == 0;
                let params = if is_down {
                    if ev.key == "Enter" {
                        serde_json::json!({
                            "type": "rawKeyDown",
                            "key": "Enter",
                            "code": "Enter",
                            "windowsVirtualKeyCode": 13,
                            "nativeVirtualKeyCode": 13,
                            "text": "\r",
                            "unmodifiedText": "\r",
                            "modifiers": ev.modifiers,
                        })
                    } else if is_printable {
                        serde_json::json!({
                            "type": "keyDown",
                            "key": ev.key,
                            "code": ev.code,
                            "windowsVirtualKeyCode": ev.vk,
                            "nativeVirtualKeyCode": ev.vk,
                            "text": ev.key,
                            "unmodifiedText": ev.key,
                            "modifiers": ev.modifiers,
                        })
                    } else {
                        serde_json::json!({
                            "type": "rawKeyDown",
                            "key": ev.key,
                            "code": ev.code,
                            "windowsVirtualKeyCode": ev.vk,
                            "nativeVirtualKeyCode": ev.vk,
                            "modifiers": ev.modifiers,
                        })
                    }
                } else {
                    serde_json::json!({
                        "type": "keyUp",
                        "key": ev.key,
                        "code": ev.code,
                        "windowsVirtualKeyCode": ev.vk,
                        "nativeVirtualKeyCode": ev.vk,
                        "modifiers": ev.modifiers,
                    })
                };
                cdp.call("Input.dispatchKeyEvent", params)?;
                applied += 1;
            }
            _ => {}
        }
    }
    Ok(applied)
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SynchronizerStatus {
    pub active: bool,
    pub master_short_id: String,
    pub master_port: u16,
    pub follower_short_ids: Vec<String>,
    pub follower_ports: Vec<u16>,
    pub mirrored_events: u64,
}

struct FollowerConnState {
    port: u16,
    target_id: String,
    ctx_id: Option<i64>,
    vw_vh: (i32, i32),
    client: Option<CdpClient>,
}

/// Runs the blocking Master -> Followers CDP input & navigation synchronizer loop until `stop_flag` is set
/// or the Master browser window closes. Returns the total count of mirrored events.
pub fn run_multi_profile_synchronizer_loop(
    master_port: u16,
    follower_ports: &[u16],
    stop_flag: &std::sync::atomic::AtomicBool,
    event_counter: Option<&std::sync::atomic::AtomicU64>,
) -> Result<u64> {
    use std::sync::atomic::Ordering;
    if follower_ports.is_empty() {
        bail!("At least 1 follower profile is required for Synchronizer");
    }
    let (mut master_target_id, mut master_cdp) = CdpClient::connect_first_page(master_port)
        .with_context(|| format!("Failed to connect to Master profile CDP port {master_port}"))?;
    let mut master_ctx_id: Option<i64> = None;
    let mut last_master_url = String::new();

    let mut followers: Vec<FollowerConnState> = follower_ports
        .iter()
        .copied()
        .filter(|&p| p != master_port)
        .map(|port| {
            let (tid, client) = match CdpClient::connect_first_page(port) {
                Ok((t, c)) => (t, Some(c)),
                Err(_) => (String::new(), None),
            };
            FollowerConnState {
                port,
                target_id: tid,
                ctx_id: None,
                vw_vh: (0, 0),
                client,
            }
        })
        .collect();
    if followers.is_empty() {
        bail!("Follower ports cannot be identical to Master port {master_port}");
    }

    let mut total_mirrored = 0u64;
    let mut consecutive_master_errs = 0u8;

    while !stop_flag.load(Ordering::Relaxed) {
        let poll_res = master_cdp.eval_in_isolated_world(
            &master_target_id,
            &mut master_ctx_id,
            MASTER_SYNC_RECORDER_JS,
        );
        let raw_json = match poll_res {
            Ok(s) => {
                consecutive_master_errs = 0;
                s
            }
            Err(_) => {
                consecutive_master_errs = consecutive_master_errs.saturating_add(1);
                if consecutive_master_errs > 12 {
                    break;
                }
                if let Ok((new_tid, new_c)) = CdpClient::connect_first_page(master_port) {
                    master_target_id = new_tid;
                    master_cdp = new_c;
                    master_ctx_id = None;
                }
                std::thread::sleep(Duration::from_millis(80));
                continue;
            }
        };

        let batch: SyncMasterPollBatch = serde_json::from_str(&raw_json).unwrap_or_default();
        let nav_url = if !batch.url.is_empty() && batch.url != last_master_url {
            let changed = !last_master_url.is_empty();
            last_master_url = batch.url.clone();
            changed.then_some(last_master_url.as_str())
        } else {
            None
        };

        if nav_url.is_some() || !batch.events.is_empty() {
            for fl in &mut followers {
                if fl.client.is_none()
                    && let Ok((tid, c)) = CdpClient::connect_first_page(fl.port)
                {
                    fl.target_id = tid;
                    fl.client = Some(c);
                    fl.ctx_id = None;
                    fl.vw_vh = (0, 0);
                }
                if let Some(cdp) = &mut fl.client {
                    match dispatch_sync_batch_to_follower(
                        cdp,
                        &fl.target_id,
                        &mut fl.ctx_id,
                        &mut fl.vw_vh,
                        nav_url,
                        &batch.events,
                    ) {
                        Ok(n) => {
                            total_mirrored = total_mirrored.saturating_add(n as u64);
                            if let Some(cnt) = event_counter {
                                cnt.fetch_add(n as u64, Ordering::Relaxed);
                            }
                        }
                        Err(_) => {
                            fl.client = None;
                            fl.ctx_id = None;
                        }
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(35));
    }
    Ok(total_mirrored)
}

struct ActiveSyncGuard {
    status: SynchronizerStatus,
    stop_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    event_counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

static ACTIVE_SYNCHRONIZER: std::sync::LazyLock<std::sync::Mutex<Option<ActiveSyncGuard>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

/// Starts or replaces the background Multi-Profile Synchronizer session in-process.
pub fn start_background_synchronizer(
    master_short_id: String,
    master_port: u16,
    followers: Vec<(String, u16)>,
) -> Result<SynchronizerStatus> {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    let dedup_followers: Vec<(String, u16)> = followers
        .into_iter()
        .filter(|(_, port)| *port != master_port)
        .collect();
    if dedup_followers.is_empty() {
        bail!("Select at least 1 running Follower profile different from Master");
    }
    stop_background_synchronizer();

    let stop_flag = std::sync::Arc::new(AtomicBool::new(false));
    let event_counter = std::sync::Arc::new(AtomicU64::new(0));
    let follower_short_ids: Vec<String> = dedup_followers.iter().map(|(id, _)| id.clone()).collect();
    let follower_ports: Vec<u16> = dedup_followers.iter().map(|(_, p)| *p).collect();

    let status = SynchronizerStatus {
        active: true,
        master_short_id,
        master_port,
        follower_short_ids,
        follower_ports: follower_ports.clone(),
        mirrored_events: 0,
    };
    let flag_thread = stop_flag.clone();
    let cnt_thread = event_counter.clone();
    std::thread::spawn(move || {
        let _ = run_multi_profile_synchronizer_loop(
            master_port,
            &follower_ports,
            &flag_thread,
            Some(&cnt_thread),
        );
        flag_thread.store(true, Ordering::Relaxed);
    });

    if let Ok(mut guard) = ACTIVE_SYNCHRONIZER.lock() {
        *guard = Some(ActiveSyncGuard {
            status: status.clone(),
            stop_flag,
            event_counter,
        });
    }
    Ok(status)
}

/// Stops the active background Multi-Profile Synchronizer session, if any.
pub fn stop_background_synchronizer() -> SynchronizerStatus {
    use std::sync::atomic::Ordering;
    if let Ok(mut guard) = ACTIVE_SYNCHRONIZER.lock()
        && let Some(active) = guard.take()
    {
        active.stop_flag.store(true, Ordering::Relaxed);
        let mut st = active.status;
        st.active = false;
        st.mirrored_events = active.event_counter.load(Ordering::Relaxed);
        return st;
    }
    SynchronizerStatus::default()
}

/// Queries the current state of the in-process Multi-Profile Synchronizer.
pub fn current_synchronizer_status() -> SynchronizerStatus {
    use std::sync::atomic::Ordering;
    if let Ok(mut guard) = ACTIVE_SYNCHRONIZER.lock() {
        if let Some(active) = guard.as_ref() {
            if active.stop_flag.load(Ordering::Relaxed) {
                let mut st = active.status.clone();
                st.active = false;
                st.mirrored_events = active.event_counter.load(Ordering::Relaxed);
                *guard = None;
                return st;
            }
            let mut st = active.status.clone();
            st.mirrored_events = active.event_counter.load(Ordering::Relaxed);
            return st;
        }
    }
    SynchronizerStatus::default()
}

/// Returns true when an `agent-browser` command failed due to an unattached/stale CDP session
/// rather than a page-level selector or script error.
pub fn should_reconnect_agent_session(stderr: &[u8], stdout: &[u8]) -> bool {
    let combined = format!(
        "{} {}",
        String::from_utf8_lossy(stderr).to_ascii_lowercase(),
        String::from_utf8_lossy(stdout).to_ascii_lowercase()
    );
    [
        "not connected",
        "no browser",
        "browser closed",
        "target closed",
        "connection closed",
        "websocket",
        "econnrefused",
        "connect first",
        "no active",
    ]
    .iter()
    .any(|needle| combined.contains(needle))
}

pub fn ensure_agent_browser_connected_in(
    root_dir: &Path,
    short_id: &str,
    ws_url: &str,
) -> Result<String> {
    let session = format!("bon_{short_id}");
    let run_connect = || {
        agent_browser_cmd_for_short_id_in(root_dir, short_id)
            .args([
                "--session",
                &session,
                "--input-mode",
                "human",
                "connect",
                ws_url,
            ])
            .output()
            .context("Failed to execute `agent-browser`. Is `agent-browser` installed in PATH?")
    };
    let mut out = run_connect()?;
    if !out.status.success() {
        std::thread::sleep(Duration::from_millis(150));
        out = run_connect()?;
    }
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("agent-browser connect failed: {}", stderr.trim());
    }
    Ok(session)
}

/// Creates a pinned-tab sub-session (`bon_<id8>_<tag>`) so multiple agents can operate concurrently on separate tabs.
pub fn ensure_agent_browser_pinned_tab_in(
    root_dir: &Path,
    short_id: &str,
    tab_tag: &str,
    ws_url: &str,
    initial_url: Option<&str>,
) -> Result<String> {
    let clean_tag: String = tab_tag
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    let suffix = if clean_tag.is_empty() { "tab1" } else { &clean_tag };
    let session = format!("bon_{short_id}_{suffix}");

    let out = agent_browser_cmd_for_short_id_in(root_dir, short_id)
        .args([
            "--session",
            &session,
            "--input-mode",
            "human",
            "--pin-tab",
            "connect",
            ws_url,
        ])
        .output()
        .context("Failed to execute `agent-browser` for pinned tab")?;
    if !out.status.success() {
        bail!(
            "agent-browser --pin-tab connect failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    if let Some(url) = initial_url.filter(|u| !u.trim().is_empty()) {
        let _ = agent_browser_cmd_for_short_id_in(root_dir, short_id)
            .args(["--session", &session, "tab", "new", url.trim()])
            .output();
    }
    Ok(session)
}

/// Re-scans CDP targets (OAuth popups, Web3 wallet windows, extensions) and returns the active tab list.
pub fn agent_sync_targets_in(
    root_dir: &Path,
    short_id: &str,
    ws_url: &str,
) -> Result<serde_json::Value> {
    let session = ensure_agent_browser_connected_in(root_dir, short_id, ws_url)?;
    let tabs_out = agent_browser_cmd_for_short_id_in(root_dir, short_id)
        .args(["--session", &session, "tab", "--json"])
        .output()?;
    let tabs_json = serde_json::from_slice::<serde_json::Value>(&tabs_out.stdout)
        .unwrap_or_else(|_| serde_json::json!({}));
    Ok(serde_json::json!({
        "ok": true,
        "session": session,
        "tabs": tabs_json.get("data").and_then(|d| d.get("tabs")).cloned().unwrap_or(tabs_json),
    }))
}

/// Blocks `agent-browser` commands/flags that invoke CDP `Emulation.*` or override BonLogin's C++ stealth fingerprint.
pub fn validate_stealth_agent_args(args: &[String]) -> Result<()> {
    for raw in args {
        let lower_raw = raw.to_ascii_lowercase();
        if lower_raw.contains("object.defineproperty(navigator")
            || lower_raw.contains("navigator.__definegetter__")
            || lower_raw.contains("object.setprototypeof(navigator")
        {
            bail!(
                "Blocked by BonLogin Stealth Guardrail: JS prototype mutation on `navigator` triggers anti-bot detection on BrowserScan/CreepJS. BonLogin already spoofs `navigator` at the C++ Blink layer."
            );
        }
    }

    let flat_tokens: Vec<String> = args
        .iter()
        .flat_map(|a| a.split_whitespace())
        .map(|s| {
            s.trim_matches(['"', '\'', ';', ','])
                .to_ascii_lowercase()
        })
        .filter(|s| !s.is_empty())
        .collect();

    for (idx, lower) in flat_tokens.iter().enumerate() {
        for forbidden_flag in [
            "--user-agent",
            "--proxy",
            "--proxy-bypass",
            "--args",
            "--executable-path",
            "--profile",
            "--engine",
            "--headers",
            "--device",
            "--viewport",
        ] {
            if lower == forbidden_flag || lower.starts_with(&format!("{forbidden_flag}=")) {
                bail!(
                    "Blocked by BonLogin Stealth Guardrail: flag '{lower}' overrides C++ fingerprint/proxy tunnel. Configure this in BonLogin Profile Settings instead."
                );
            }
        }
        if lower == "set"
            && let Some(sub) = flat_tokens.get(idx + 1)
            && matches!(
                sub.as_str(),
                "viewport" | "device" | "geo" | "media" | "headers"
            )
        {
            bail!(
                "Blocked by BonLogin Stealth Guardrail: 'agent-browser set {sub}' invokes CDP Emulation/Network overrides that expose automation on BrowserScan/CreepJS."
            );
        }
    }
    Ok(())
}

/// Opens an extension popup/options page inside a running profile via `agent-browser --session bon_<id> tab new <url>`.
pub fn agent_open_extension_tab_in(
    root_dir: &Path,
    short_id: &str,
    ws_url: &str,
    ext_url: &str,
) -> Result<String> {
    let session = ensure_agent_browser_connected_in(root_dir, short_id, ws_url)?;
    let out = agent_browser_cmd_for_short_id_in(root_dir, short_id)
        .args(["--session", &session, "tab", "new", ext_url])
        .output()?;
    if !out.status.success() {
        bail!(
            "agent-browser tab new failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(format!(
        "agent-browser --session {session} snapshot -i"
    ))
}
#[cfg(test)]
pub fn agent_audit_fingerprint_in(
    root_dir: &Path,
    short_id: &str,
    ws_url: &str,
) -> Result<String> {
    let session = ensure_agent_browser_connected_in(root_dir, short_id, ws_url)?;
    let js = r#"JSON.stringify({
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        webdriver: navigator.webdriver,
        hardwareConcurrency: navigator.hardwareConcurrency,
        deviceMemory: navigator.deviceMemory || null,
        language: navigator.language,
        languages: navigator.languages,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        screen: screen.width + 'x' + screen.height + ' (avail ' + screen.availWidth + 'x' + screen.availHeight + ')',
        brands: navigator.userAgentData ? navigator.userAgentData.brands : [],
        webgl: (() => {
            try {
                const c = document.createElement('canvas');
                const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
                if (!gl) return 'unavailable';
                const ext = gl.getExtension('WEBGL_debug_renderer_info');
                return ext
                    ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) + ' / ' + gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)
                    : gl.getParameter(gl.VENDOR) + ' / ' + gl.getParameter(gl.RENDERER);
            } catch (e) { return String(e); }
        })()
    }, null, 2)"#;

    let out = agent_browser_cmd()
        .args(["--session", &session, "eval", js])
        .output()?;
    if !out.status.success() {
        bail!(
            "Fingerprint audit failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if let Ok(unquoted) = serde_json::from_str::<String>(&raw) {
        return Ok(unquoted);
    }
    Ok(raw)
}

pub fn agent_export_state_in(
    root_dir: &Path,
    short_id: &str,
    ws_url: &str,
) -> Result<(PathBuf, String)> {
    let session = ensure_agent_browser_connected_in(root_dir, short_id, ws_url)?;
    let dir = root_dir.join("states");
    std::fs::create_dir_all(&dir)?;
    let state_path = dir.join(format!("bon_{short_id}_state.json"));

    let out = agent_browser_cmd_for_short_id_in(root_dir, short_id)
        .args([
            "--session",
            &session,
            "state",
            "save",
            &state_path.to_string_lossy(),
        ])
        .output()?;
    if !out.status.success() {
        bail!(
            "state save failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    let json = std::fs::read_to_string(&state_path).unwrap_or_else(|_| "{}".to_string());
    Ok((state_path, json))
}

fn apply_cookies_via_cli_set_in(
    root_dir: &Path,
    session: &str,
    short_id: &str,
    cookies: &[serde_json::Value],
    only_host_prefix: bool,
) -> usize {
    let mut applied = 0;
    for c in cookies {
        let Some(name) = c.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        if only_host_prefix && !name.starts_with("__Host-") {
            continue;
        }
        let value = c.get("value").and_then(|v| v.as_str()).unwrap_or("");
        let domain = c.get("domain").and_then(|v| v.as_str()).unwrap_or("");
        let path = c.get("path").and_then(|v| v.as_str()).unwrap_or("/");
        let secure = c.get("secure").and_then(|v| v.as_bool()).unwrap_or(false);
        let http_only = c.get("httpOnly").and_then(|v| v.as_bool()).unwrap_or(false);
        let same_site = c.get("sameSite").and_then(|v| v.as_str());
        let session_flag = c.get("session").and_then(|v| v.as_bool()).unwrap_or(false);
        let expires = c.get("expires").and_then(|v| v.as_f64()).unwrap_or(-1.0);

        let mut args = vec![
            "--session".to_string(),
            session.to_string(),
            "cookies".to_string(),
            "set".to_string(),
            name.to_string(),
            value.to_string(),
        ];
        if name.starts_with("__Host-") {
            let host = domain.trim_start_matches('.');
            args.push("--url".to_string());
            args.push(format!("https://{host}/"));
            args.push("--path".to_string());
            args.push("/".to_string());
            args.push("--secure".to_string());
        } else {
            if !domain.is_empty() {
                args.push("--domain".to_string());
                args.push(domain.to_string());
            }
            args.push("--path".to_string());
            args.push(path.to_string());
            if secure {
                args.push("--secure".to_string());
            }
        }
        if http_only {
            args.push("--http-only".to_string());
        }
        if let Some(ss) = same_site.and_then(crate::cookies::normalize_same_site_str) {
            args.push("--same-site".to_string());
            args.push(ss.to_string());
        }
        if !session_flag && expires > 0.0 {
            args.push("--expires".to_string());
            args.push(format!("{}", expires as i64));
        }
        if agent_browser_cmd_for_short_id_in(root_dir, short_id)
            .args(&args)
            .output()
            .is_ok_and(|o| o.status.success())
        {
            applied += 1;
        }
    }
    applied
}

pub fn agent_import_state_or_cookies_in(
    root_dir: &Path,
    short_id: &str,
    ws_url: &str,
    raw_payload: &str,
) -> Result<String> {
    let session = ensure_agent_browser_connected_in(root_dir, short_id, ws_url)?;
    let dir = root_dir.join("states");
    std::fs::create_dir_all(&dir)?;
    let trimmed = raw_payload.trim();
    let source_text = if !trimmed.is_empty() {
        trimmed.to_string()
    } else {
        let prelaunch = dir.join(format!("bon_{short_id}_prelaunch.json"));
        let default_state = dir.join(format!("bon_{short_id}_state.json"));
        if prelaunch.is_file() {
            std::fs::read_to_string(&prelaunch)?
        } else if default_state.is_file() {
            std::fs::read_to_string(&default_state)?
        } else {
            bail!(
                "Paste Cookies (JSON, Netscape, cURL, or key=value) first, or export a state file for bon_{short_id}"
            );
        }
    };

    let bundle = parse_and_normalize_cookies(&source_text, None)?;
    if bundle.cookies.is_empty() && bundle.origins.is_empty() {
        return Ok("No cookies or origins to import".to_string());
    }

    let state_json = bundle.to_state_json_pretty();
    let tmp_file = dir.join(format!("bon_{short_id}_import.json"));
    let state_file = dir.join(format!("bon_{short_id}_state.json"));
    let _ = std::fs::write(&state_file, &state_json);

    let non_host_cookies: Vec<&serde_json::Value> = bundle
        .cookies
        .iter()
        .filter(|c| {
            !c.get("name")
                .and_then(|v| v.as_str())
                .is_some_and(|n| n.starts_with("__Host-"))
        })
        .collect();

    if !non_host_cookies.is_empty() || !bundle.origins.is_empty() {
        let load_payload = serde_json::to_string_pretty(&serde_json::json!({
            "cookies": non_host_cookies,
            "origins": bundle.origins,
        }))?;
        std::fs::write(&tmp_file, &load_payload)?;
        let out = agent_browser_cmd_for_short_id_in(root_dir, short_id)
            .args([
                "--session",
                &session,
                "state",
                "load",
                &tmp_file.to_string_lossy(),
            ])
            .output()?;
        if !out.status.success() {
            // shortcut: cap per-cookie CLI fallback at 25 so malformed bundles never stall for 20s
            let cap = bundle.cookies.len().min(25);
            let fallback_set = apply_cookies_via_cli_set_in(
                root_dir,
                &session,
                short_id,
                &bundle.cookies[..cap],
                false,
            );
            if fallback_set == 0 {
                let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                bail!("Import failed: {stderr} {stdout}");
            }
        }
    }
    let _ = apply_cookies_via_cli_set_in(root_dir, &session, short_id, &bundle.cookies, true);

    // Refresh active tab so newly injected session cookies take effect immediately
    let _ = agent_browser_cmd_for_short_id_in(root_dir, short_id)
        .args(["--session", &session, "reload"])
        .output();

    Ok(format!("Imported {}", bundle.summary_badge()))
}

/// Runs a Cookie Robot warm-up sequence on a running profile (`ws_url`), visiting each URL,
/// scrolling naturally, waiting `dwell_secs`, and exporting the accumulated cookies to prelaunch storage.
pub fn run_cookie_robot_warmup_in(
    root_dir: &Path,
    short_id: &str,
    ws_url: &str,
    urls: &[String],
    dwell_secs: u64,
) -> Result<usize> {
    let clean_urls: Vec<String> = urls
        .iter()
        .map(|u| u.trim())
        .filter(|u| !u.is_empty())
        .map(|u| {
            if u.starts_with("http://") || u.starts_with("https://") {
                u.to_string()
            } else {
                format!("https://{u}")
            }
        })
        .collect();
    if clean_urls.is_empty() {
        bail!("At least 1 warm-up URL is required");
    }
    let session = ensure_agent_browser_connected_in(root_dir, short_id, ws_url)?;
    let cdp_port = extract_port_from_ws_url(ws_url);
    let wait_s = dwell_secs.clamp(1, 30);
    let mut visited = 0usize;
    for url in &clean_urls {
        if let Some(port) = cdp_port
            && cdp_has_open_window(port) == Some(false)
        {
            break;
        }
        let opened = agent_browser_cmd_for_short_id_in(root_dir, short_id)
            .args(["--session", &session, "open", url])
            .output()
            .is_ok_and(|o| o.status.success());
        if !opened {
            break;
        }
        visited += 1;
        std::thread::sleep(Duration::from_millis(800));
        let _ = agent_browser_cmd_for_short_id_in(root_dir, short_id)
            .args(["--session", &session, "scroll", "down", "420"])
            .output();
        std::thread::sleep(Duration::from_secs(wait_s));
        if let Some(port) = cdp_port
            && cdp_has_open_window(port) == Some(false)
        {
            break;
        }
        let _ = agent_browser_cmd_for_short_id_in(root_dir, short_id)
            .args(["--session", &session, "scroll", "up", "160"])
            .output();
    }
    if visited > 0
        && let Ok((_, live_json)) = agent_export_state_in(root_dir, short_id, ws_url)
    {
        let _ = save_prelaunch_cookies_in(root_dir, short_id, &live_json);
    }
    Ok(visited)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::*;
    use crate::extensions::*;
    use crate::flows::*;
    use crate::models::{
        BrowserBrand, BrowserExtension, GpuSpoofMode, PlatformType, ProxyConfig, ProxyProtocol,
        SavedProxy,
    };

    #[test]
    fn test_build_chromium_args_macos_native_direct() {
        let mut profile = Profile::new_default("Mac Direct", PlatformType::MacOS);
        profile.seed = 987654;
        profile.os_version = "15.2.0".to_string();
        profile.brand = BrowserBrand::Chrome;
        profile.brand_version = "148.0.7778.215".to_string();
        profile.hardware_concurrency = 10;
        profile.gpu_spoofing = GpuSpoofMode::NativePassthrough;
        profile.spoof_font = false;
        profile.window_size = "1600,1000".to_string();
        profile.startup_url = "https://browserscan.net".to_string();

        let data_dir = PathBuf::from("/tmp/bonlogin-test/profile-mac");
        let args = build_chromium_args_with_extensions(&profile, None, &data_dir, None, &[]);

        assert!(args.contains(&"--user-data-dir=/tmp/bonlogin-test/profile-mac".to_string()));
        assert!(args.contains(&"--fingerprint=987654".to_string()));
        assert!(args.contains(&"--fingerprint-platform=macos".to_string()));
        assert!(args.contains(&"--fingerprint-brand=Chrome".to_string()));
        assert!(args.contains(&"--disable-spoofing=font,gpu".to_string()));
        assert!(args.contains(&"--window-size=1600,1000".to_string()));
        assert_eq!(
            args.last().map(String::as_str),
            Some("https://browserscan.net")
        );
    }

    #[test]
    fn test_build_chromium_args_windows_seed_with_proxy() {
        let mut profile = Profile::new_default("Win Proxy", PlatformType::Windows);
        profile.seed = 123456;
        profile.os_version = "15.0.0".to_string();
        profile.brand = BrowserBrand::Edge;
        profile.brand_version = "148.0.7778.215".to_string();
        profile.hardware_concurrency = 8;
        profile.gpu_spoofing = GpuSpoofMode::SeedGenerated;
        profile.startup_url = String::new();

        let geo = GeoInfo {
            ip: "203.0.113.9".to_string(),
            country_code: "VN".to_string(),
            timezone: "Asia/Ho_Chi_Minh".to_string(),
            locale: "vi-VN".to_string(),
            accept_lang: "vi-VN,vi,en-US;q=0.9,en;q=0.8".to_string(),
            latency_ms: Some(95),
        };

        let data_dir = PathBuf::from("/tmp/bonlogin-test/profile-win");
        let args = build_chromium_args_with_extensions(&profile, Some(58123), &data_dir, Some(&geo), &[]);

        assert!(args.contains(&"--fingerprint=123456".to_string()));
        assert!(args.contains(&"--fingerprint-platform=windows".to_string()));
        assert!(args.contains(&"--fingerprint-brand=Edge".to_string()));
        assert!(args.contains(&"--timezone=Asia/Ho_Chi_Minh".to_string()));
        assert!(!args.iter().any(|a| a.starts_with("--disable-spoofing=")));
        assert!(args.contains(&"--proxy-server=http://127.0.0.1:58123".to_string()));
        assert!(
            args.contains(&"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1".to_string())
        );
        assert!(args.contains(&"--lang=vi".to_string()));
        assert!(args.contains(&"--accept-lang=vi,vi-VN,vi,en-US;q=0.9,en;q=0.8".to_string()));
        assert!(args.contains(&"-AppleLanguages".to_string()));
        assert!(args.contains(&"<array><string>vi-VN</string></array>".to_string()));
        assert_eq!(chromium_icu_locale("zh-CN"), "zh-CN");
        assert_eq!(chromium_icu_locale("pt-BR"), "pt-BR");
        assert_eq!(chromium_icu_locale("ja-JP"), "ja");
        for _ in 0..20 {
            let s = Profile::random_seed();
            assert!(matches!(s % 13, 2 | 5));
        }
    }

    #[test]
    fn test_parse_devtools_active_port() {
        let raw = "61234\n/devtools/browser/9a8b7c6d-1234-5678-90ab-cdef12345678\n";
        let (port, ws_url) = parse_devtools_active_port(raw).unwrap();
        assert_eq!(port, 61234);
        assert_eq!(
            ws_url,
            "ws://127.0.0.1:61234/devtools/browser/9a8b7c6d-1234-5678-90ab-cdef12345678"
        );
    }

    #[test]
    fn test_cdp_has_open_window_parses_page_targets() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut keep_alive = Vec::new();
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = s.read(&mut buf);
                let body = r#"[{"type":"service_worker"},{"type":"page","url":"https://browserscan.net"}]"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
                keep_alive.push(s);
            }
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = s.read(&mut buf);
                // Response without Content-Length (closed at EOF) and >64KB payload
                let pad = "x".repeat(70_000);
                let body = format!(r#"[{{"type":"service_worker","pad":"{pad}"}}]"#);
                let resp = format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{body}");
                let _ = s.write_all(resp.as_bytes());
            }
            std::thread::sleep(Duration::from_secs(1));
        });

        assert_eq!(cdp_has_open_window(port), Some(true));
        assert_eq!(cdp_has_open_window(port), Some(false));
    }

    #[test]
    fn test_sha256_and_deterministic_extension_runtime_id() {
        use base64::Engine;
        // Known SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let digest = sha256_bytes(b"abc");
        assert_eq!(digest[0], 0xba);
        assert_eq!(digest[1], 0x78);
        assert_eq!(digest[31], 0xad);

        let key_b64 = deterministic_spki_key_b64("cookie-token-grabber");
        let der = base64::engine::general_purpose::STANDARD
            .decode(&key_b64)
            .unwrap();
        let ext_id = pubkey_to_chrome_ext_id(&der);
        assert_eq!(ext_id.len(), 32);
        assert!(ext_id.bytes().all(|b| (b'a'..=b'p').contains(&b)));
        // Deterministic across calls
        let key_b64_2 = deterministic_spki_key_b64("cookie-token-grabber");
        assert_eq!(key_b64, key_b64_2);
    }

    #[test]
    fn test_patch_unpacked_extension_and_resolve_runtime_info() {
        let tmp = std::env::temp_dir().join(format!("bon_ext_test_{}", unix_now()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(
            tmp.join("manifest.json"),
            r#"{
              "manifest_version": 3,
              "name": "TestExt",
              "version": "1.0.0",
              "optional_host_permissions": ["*://*/*"],
              "background": { "service_worker": "bg.js" },
              "action": { "default_popup": "popup.html" }
            }"#,
        )
        .unwrap();
        std::fs::write(tmp.join("bg.js"), "console.log('bg');").unwrap();
        std::fs::write(tmp.join("popup.html"), "<html><head></head><body>Hi</body></html>").unwrap();

        patch_unpacked_extension_for_agent(&tmp, "test-ext-id", None);
        let ext = BrowserExtension {
            id: "test-ext-id".to_string(),
            name: "TestExt".to_string(),
            icon_label: "TE".to_string(),
            icon_bg: 0x3B82F6,
            is_default: false,
            enabled: true,
            source_url: String::new(),
            folder_path: tmp.to_string_lossy().into_owned(),
            created_at: 0,
        };
        let (runtime_id, entry_url) = resolve_extension_runtime_info_in(&tmp, &ext).unwrap();
        assert_eq!(runtime_id.len(), 32);
        assert_eq!(
            entry_url,
            format!("chrome-extension://{runtime_id}/popup.html")
        );
        let bg_patched = std::fs::read_to_string(tmp.join("bg.js")).unwrap();
        assert!(bg_patched.contains("__BON_EXT_SHIM__"));
        let html_patched = std::fs::read_to_string(tmp.join("popup.html")).unwrap();
        assert!(html_patched.contains("__bon_ext_shim.js"));
        let manifest_patched = std::fs::read_to_string(tmp.join("manifest.json")).unwrap();
        assert!(manifest_patched.contains("\"<all_urls>\""));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn test_e2e_launch_adryfish_and_agent_browser_connect() {
        let Some(_kernel) = locate_chromium_kernel() else {
            return;
        };

        let prev_enabled = crate::db::Database::open_default()
            .ok()
            .and_then(|db| db.list_extensions().ok())
            .and_then(|exts| {
                exts.into_iter()
                    .find(|e| e.id == "cookie-token-grabber")
                    .map(|e| e.enabled)
            })
            .unwrap_or(false);
        if let Ok(db) = crate::db::Database::open_default() {
            let _ = db.set_extension_enabled("cookie-token-grabber", true);
        }

        let mut profile = Profile::new_default("E2E Smoke Profile", PlatformType::MacOS);
        profile.seed = 777888;
        profile.hardware_concurrency = 12;
        profile.startup_url = "about:blank".to_string();
        let short_id = profile.short_id();

        let e2e_root = app_support_dir();
        let (mut running, _) = launch_profile_in(&e2e_root, &profile)
            .await
            .expect("launch_profile should spawn adryfish Chromium and read DevToolsActivePort");

        assert!(running.info.cdp_port > 0);
        assert!(running.info.ws_url.starts_with("ws://127.0.0.1:"));
        assert!(running.is_alive());
        assert_eq!(cdp_has_open_window(running.info.cdp_port), Some(true));
        assert!(running.saw_window);

        let audit = agent_audit_fingerprint_in(&e2e_root, &short_id, &running.info.ws_url)
            .expect("agent_audit_fingerprint should succeed");
        assert!(
            audit.contains("\"webdriver\": false") || audit.contains("\"webdriver\":false"),
            "Expected webdriver=false in audit: {audit}"
        );
        assert!(
            audit.contains("\"hardwareConcurrency\": 12")
                || audit.contains("\"hardwareConcurrency\":12"),
            "Expected hardwareConcurrency=12 in audit: {audit}"
        );

        // Verify agent-browser can open and interact with the loaded extension's popup page
        let grabber_ext = BrowserExtension {
            id: "cookie-token-grabber".to_string(),
            name: "Cookie & Token Grabber".to_string(),
            icon_label: "📋".to_string(),
            icon_bg: 0x0D9488,
            is_default: true,
            enabled: true,
            source_url: String::new(),
            folder_path: String::new(),
            created_at: 0,
        };
        let (_rt_id, entry_url) =
            resolve_extension_runtime_info_in(&e2e_root, &grabber_ext).expect("should resolve extension URL");
        agent_open_extension_tab_in(&e2e_root, &short_id, &running.info.ws_url, &entry_url)
            .expect("agent_open_extension_tab should open extension popup in new tab");
        let snap_out = agent_browser_cmd()
            .args(["--session", &format!("bon_{short_id}"), "snapshot", "-i"])
            .output()
            .expect("snapshot on extension popup should succeed");
        let snap_txt = String::from_utf8_lossy(&snap_out.stdout);
        assert!(
            snap_txt.contains("Grab Active Tab Cookies"),
            "Expected extension popup controls in snapshot: {snap_txt}"
        );

        let parsed_ext_snap = parse_snapshot_refs(&snap_txt);
        save_snap_cache_in(&app_support_dir(), &short_id, &parsed_ext_snap);
        let grab_ref = parsed_ext_snap
            .iter()
            .find(|(_, m)| m.name.contains("Grab Active Tab Cookies"))
            .map(|(k, _)| format!("@{k}"))
            .expect("should find Grab Active Tab Cookies ref in parsed snapshot");
        let recorded = prepare_recorded_steps_in(
            &app_support_dir(),
            &short_id,
            &format!("bon_{short_id}"),
            &running.info.ws_url,
            &["click".to_string(), grab_ref],
        );
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].op, "click");

        let fallback_step = FlowStep {
            op: "click".to_string(),
            locators: vec![
                "#nonexistent_missing_id".to_string(),
                "role:button:Grab Active Tab Cookies".to_string(),
            ],
            value: None,
            extra_args: Vec::new(),
            optional: false,
        };
        let sess_name = format!("bon_{short_id}");
        let mut e2e_adapter = SubprocessAgentSession {
            root_dir: &e2e_root,
            short_id: &short_id,
            session: &sess_name,
            ws_url: &running.info.ws_url,
        };
        let (win_idx, matched_loc) = execute_single_flow_step_with(
            &mut e2e_adapter,
            &fallback_step,
            &std::collections::HashMap::new(),
        )
        .expect("fallback locator should succeed when primary selector is missing");
        assert_eq!(win_idx, 1);
        assert_eq!(matched_loc, "role:button:Grab Active Tab Cookies");

        let (state_path, state_json) =
            agent_export_state_in(&e2e_root, &short_id, &running.info.ws_url).expect("export state should work");
        assert!(state_path.is_file());
        assert!(state_json.contains("cookies"));

        running.stop_gracefully();
        assert!(!running.is_alive());

        if let Ok(db) = crate::db::Database::open_default() {
            let _ = db.set_extension_enabled("cookie-token-grabber", prev_enabled);
        }
        let _ = wipe_profile_data_in(&e2e_root, &profile.id);
        clear_flow_session_cache_in(&e2e_root, &short_id);
    }


    #[test]
    fn test_validate_stealth_agent_args_and_pinned_tab_cli() {
        assert!(
            validate_stealth_agent_args(&[
                "snapshot".to_string(),
                "-i".to_string(),
                "-c".to_string()
            ])
            .is_ok()
        );
        assert!(
            validate_stealth_agent_args(&[
                "set".to_string(),
                "viewport".to_string(),
                "1920".to_string(),
                "1080".to_string()
            ])
            .is_err()
        );
        assert!(
            validate_stealth_agent_args(&[
                "set".to_string(),
                "device".to_string(),
                "iPhone 15".to_string()
            ])
            .is_err()
        );
        assert!(
            validate_stealth_agent_args(&[
                "--user-agent=CustomUA".to_string(),
                "open".to_string(),
                "https://example.com".to_string()
            ])
            .is_err()
        );
        assert!(
            validate_stealth_agent_args(&[
                "batch".to_string(),
                "set viewport 1920 1080".to_string(),
                "click @e1".to_string()
            ])
            .is_err()
        );
        assert!(
            validate_stealth_agent_args(&[
                "eval".to_string(),
                "Object.defineProperty(navigator, 'webdriver', {get: () => false})".to_string()
            ])
            .is_err()
        );
        assert!(
            validate_stealth_agent_args(&[
                "--headers={\"X-Test\":\"1\"}".to_string(),
                "open".to_string(),
                "https://example.com".to_string()
            ])
            .is_err()
        );
        assert!(should_reconnect_agent_session(
            b"Error: Browser not connected. Run connect first.",
            b""
        ));
        assert!(!should_reconnect_agent_session(
            b"Error: Element @e99 not found on page",
            b""
        ));
        let info = RuntimeInfo {
            pid: 1234,
            cdp_port: 55111,
            ws_url: "ws://127.0.0.1:55111/devtools/browser/abc".to_string(),
            local_proxy_port: None,
        };
        assert_eq!(
            info.pinned_tab_cli("76a2aa96", "worker 1"),
            "agent-browser --session bon_76a2aa96_worker1 --input-mode human --pin-tab connect \"ws://127.0.0.1:55111/devtools/browser/abc\""
        );
    }

    #[test]
    fn test_apply_profile_cli_flags() {
        let mut p = Profile::new_default("Init", PlatformType::MacOS);
        let sp = SavedProxy::new(
            "US Resi 01",
            "US-Tag",
            ProxyConfig {
                protocol: ProxyProtocol::Socks5,
                host: "198.51.100.7".to_string(),
                port: 1080,
                username: Some("u".to_string()),
                password: Some("pw".to_string()),
                change_ip_url: None,
            },
        );
        let flags: Vec<String> = [
            "--name",
            "TikTok Shop US",
            "--group",
            "TikTok",
            "--os",
            "windows",
            "--brand",
            "edge",
            "--seed",
            "555666",
            "--cores",
            "12",
            "--gpu",
            "native",
            "--canvas",
            "off",
            "--window-size",
            "1920,1080",
            "--timezone",
            "America/New_York",
            "--locale",
            "en-US",
            "--proxy-tag",
            "#US-Tag",
            "--notes",
            "Seller account",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        parse_profile_cli_flags(&mut p, &[sp], &flags).unwrap();
        assert_eq!(p.name, "TikTok Shop US");
        assert_eq!(p.group_tag, "TikTok");
        assert_eq!(p.os_platform, PlatformType::Windows);
        assert_eq!(p.brand, BrowserBrand::Edge);
        assert_eq!(p.seed, 555666);
        assert_eq!(p.hardware_concurrency, 12);
        assert_eq!(p.gpu_spoofing, GpuSpoofMode::NativePassthrough);
        assert!(!p.spoof_canvas);
        assert_eq!(p.window_size, "1920,1080");
        assert_eq!(p.custom_timezone.as_deref(), Some("America/New_York"));
        assert_eq!(
            p.proxy.as_ref().map(|x| x.display_short()).as_deref(),
            Some("198.51.100.7:1080")
        );
    }

    #[tokio::test]
    async fn test_cancellable_extension_download_and_unpack() {
        use std::sync::atomic::AtomicBool;
        let cancelled = AtomicBool::new(true);
        let tmp = std::env::temp_dir().join(format!(
            "bon_cancel_ext_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let test_id = "bon_test_cancelled_ext";
        remove_extension_files_in(&tmp, test_id);

        let err = download_extension_from_url_cancellable_in(
            &tmp,
            "https://example.com/ext.zip",
            Some(test_id),
            &cancelled,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("cancelled"));
        assert!(!tmp.join("extensions").join(test_id).exists());

        let err2 = install_extension_from_bytes_cancellable_in(
            &tmp,
            b"PK\x03\x04dummy",
            Some(test_id),
            "https://example.com/ext.zip",
            &cancelled,
        )
        .unwrap_err();
        assert!(err2.to_string().contains("cancelled"));
        assert!(!tmp.join("extensions").join(test_id).exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }
    #[test]
    fn test_flow_snapshot_parsing_locators_and_parameterization() {
        let snap_txt = "\
- heading \"Sign In\" [level=1, ref=e1]\n\
- textbox \"Email\" [ref=e2]\n\
- textbox [ref=e3]\n\
- button \"Continue\" [ref=e4]\n\
- button \"Continue\" [ref=e5]\n";
        let snap_map = parse_snapshot_refs(snap_txt);
        assert_eq!(
            snap_map.get("e2"),
            Some(&SnapshotRefMeta {
                role: "textbox".to_string(),
                name: "Email".to_string(),
                unique: true,
                role_index: 0,
            })
        );
        assert_eq!(
            snap_map.get("e3"),
            Some(&SnapshotRefMeta {
                role: "textbox".to_string(),
                name: String::new(),
                unique: false,
                role_index: 1,
            })
        );
        assert_eq!(snap_map.get("e4").map(|m| m.unique), Some(false));

        let dom_nodes = vec![
            serde_json::json!({"role": "textbox", "accName": "Email", "id": "email_input", "name": "user_email"}),
            serde_json::json!({"role": "textbox", "accName": "", "id": "secret_code", "name": "otp"}),
        ];
        let matched_unnamed = match_ref_dom_attrs_from_nodes(
            &["@e3".to_string()],
            &snap_map,
            &dom_nodes,
        );
        assert_eq!(
            matched_unnamed.get("@e3").map(|a| (a.id.as_str(), a.name.as_str())),
            Some(("secret_code", "otp"))
        );
        let mut dom_attrs = std::collections::HashMap::new();
        dom_attrs.insert(
            "@e2".to_string(),
            RefDomAttrs {
                data_testid: "login-email".to_string(),
                id: "email_input".to_string(),
                name: "user_email".to_string(),
                placeholder: "Enter email".to_string(),
                input_type: "email".to_string(),
                ..Default::default()
            },
        );
        let step = build_flow_step_from_cmd(
            &[
                "fill".to_string(),
                "@e2".to_string(),
                "alice@example.com".to_string(),
            ],
            &snap_map,
            &dom_attrs,
        )
        .expect("should build fill step");
        assert_eq!(step.op, "fill");
        assert_eq!(
            step.locators,
            vec![
                "[data-testid=\"login-email\"]",
                "[id=\"email_input\"]",
                "[name=\"user_email\"]",
                "role:textbox:Email",
                "[placeholder=\"Enter email\"]",
                "input[type=\"email\"]",
            ]
        );

        let open_step = FlowStep {
            op: "open".to_string(),
            locators: Vec::new(),
            value: Some("https://x.com/login".to_string()),
            extra_args: Vec::new(),
            optional: false,
        };
        let mut steps = vec![open_step, step];
        parameterize_flow_steps(
            &mut steps,
            &[
                ("short".to_string(), "alice".to_string()),
                ("username".to_string(), "alice@example.com".to_string()),
            ],
        );
        assert_eq!(steps[0].value.as_deref(), Some("https://x.com/login"));
        assert_eq!(steps[1].value.as_deref(), Some("{{username}}"));

        let bad_stealth_step = FlowStep {
            op: "set".to_string(),
            locators: Vec::new(),
            value: Some("viewport".to_string()),
            extra_args: vec!["1920".to_string(), "1080".to_string()],
            optional: false,
        };
        let dummy_root = std::env::temp_dir();
        let mut guard_adapter = SubprocessAgentSession {
            root_dir: &dummy_root,
            short_id: "12345678",
            session: "bon_12345678",
            ws_url: "ws://127.0.0.1:9222/devtools/browser/test",
        };
        let err = execute_single_flow_step_with(
            &mut guard_adapter,
            &bad_stealth_step,
            &std::collections::HashMap::new(),
        )
        .unwrap_err();
        let jev_payload = build_jev_find_payload(&steps[1], &snap_map);
        assert_eq!(
            jev_payload["candidates"][0]["id"].as_str(),
            Some("@e2")
        );
        assert_eq!(
            jev_payload["candidates"][0]["text"].as_str(),
            Some("[@e2] textbox · Email")
        );
        assert_eq!(
            normalize_heal_agent_args(&[
                "fill".to_string(),
                "e3".to_string(),
                "e100".to_string()
            ]),
            vec!["fill", "@e3", "e100"]
        );
        assert_eq!(
            normalize_heal_agent_args(&[
                "click".to_string(),
                "--new-tab".to_string(),
                "e4".to_string()
            ]),
            vec!["click", "--new-tab", "@e4"]
        );
        assert_eq!(
            normalize_heal_agent_args(&[
                "batch".to_string(),
                "--bail".to_string(),
                "fill e2 \"e100\"".to_string(),
                "click e5".to_string()
            ]),
            vec!["batch", "--bail", "fill @e2 e100", "click @e5"]
        );
        let mut long_snap = std::collections::HashMap::new();
        long_snap.insert(
            "e9".to_string(),
            SnapshotRefMeta {
                role: "link".to_string(),
                name: "x".repeat(500),
                unique: true,
                role_index: 0,
            },
        );
        let long_payload = build_jev_find_payload(&steps[1], &long_snap);
        assert!(
            long_payload["candidates"][0]["text"]
                .as_str()
                .unwrap()
                .len()
                < 320
        );
        assert!(err.contains("Stealth Guardrail"));
        let flow = AgentFlow {
            name: "test_login".to_string(),
            domain: "example.com".to_string(),
            updated_at: 0,
            steps,
        };
        assert_eq!(extract_flow_vars(&flow), vec!["username".to_string()]);

        let cmds = build_locator_candidate_commands(
            "fill",
            "role:textbox:Email",
            Some("bob@example.com"),
            &[],
        );
        assert_eq!(
            cmds[0],
            vec![
                "find",
                "role",
                "textbox",
                "fill",
                "--name",
                "Email",
                "--exact",
                "bob@example.com"
            ]
        );
        // `type` must NOT be silently coerced to `fill`; falls back to snapshot ref resolution
        assert!(
            build_locator_candidate_commands("type", "role:textbox:Email", Some("abc"), &[])
                .is_empty()
        );
        assert!(
            build_locator_candidate_commands("wait", "text:Continue", None, &[]).is_empty()
        );
        assert!(
            build_locator_candidate_commands(
                "click",
                "role:button:Continue",
                None,
                &["--new-tab".to_string()]
            )
            .is_empty()
        );
        assert_eq!(
            match_semantic_locator_in_snapshot("role:textbox:Email", &snap_map).as_deref(),
            Some("e2")
        );
        assert_eq!(
            match_semantic_locator_in_snapshot("text:Continue", &snap_map).as_deref(),
            Some("e4")
        );
        // `open` parameterizes non-secret URL/tenant vars while ignoring password collisions
        let mut open_steps = vec![FlowStep {
            op: "open".to_string(),
            locators: Vec::new(),
            value: Some("https://acme-shop.example.com/login".to_string()),
            extra_args: Vec::new(),
            optional: false,
        }];
        parameterize_flow_steps(
            &mut open_steps,
            &[
                ("password".to_string(), "login".to_string()),
                ("tenant".to_string(), "acme-shop".to_string()),
            ],
        );
        assert_eq!(
            open_steps[0].value.as_deref(),
            Some("https://{{tenant}}.example.com/login")
        );
    }

    #[test]
    fn test_parse_window_size_and_compute_tile_bounds() {
        assert_eq!(parse_window_size("960,600"), Some((960, 600)));
        assert_eq!(parse_window_size(" 800 x 700 "), Some((800, 700)));
        assert_eq!(parse_window_size("720×540"), Some((720, 540)));
        assert_eq!(parse_window_size("100,100"), None);

        let bounds = compute_tile_bounds(0, 0, 1920, 1080, 960, 500, 5);
        assert_eq!(bounds.len(), 5);
        assert_eq!(bounds[0], (0, 25, 960, 500));
        assert_eq!(bounds[1], (960, 25, 960, 500));
        assert_eq!(bounds[2], (0, 525, 960, 500));
        assert_eq!(bounds[3], (960, 525, 960, 500));
        // 5th window snaps cleanly to exact grid slot (0, 0) without crooked diagonal offset
        assert_eq!(bounds[4], (0, 25, 960, 500));

        // Work-area tiling (already accounts for macOS menu bar y=30 and left Dock x=57)
        // must start directly at `(work_x, work_y)` without adding a fake +25px menu bar offset!
        let work_2x2 = compute_tile_work_area_bounds(57, 30, 2503, 1050, 2503 / 2, 1050 / 2, 4);
        assert_eq!(work_2x2[0], (57, 30, 1251, 525));
        assert_eq!(work_2x2[1], (1308, 30, 1251, 525));
        assert_eq!(work_2x2[2], (57, 555, 1251, 525));
        assert_eq!(work_2x2[3], (1308, 555, 1251, 525));

        // Laptop work-area (`1463×949`) with 6 windows (`Auto Fit (6)` = `487×474`) and 8 windows (`4×2` = `365×474`)
        // must tile side-by-side with zero overlap (`49`, `536`, `1023`).
        let laptop_3x2 = compute_tile_work_area_bounds(49, 33, 1463, 949, 487, 474, 6);
        assert_eq!(laptop_3x2.len(), 6);
        assert_eq!(laptop_3x2[0], (49, 33, 487, 474));
        assert_eq!(laptop_3x2[1], (536, 33, 487, 474));
        assert_eq!(laptop_3x2[2], (1023, 33, 487, 474));
        assert_eq!(laptop_3x2[3], (49, 507, 487, 474));
        assert_eq!(laptop_3x2[4], (536, 507, 487, 474));
        assert_eq!(laptop_3x2[5], (1023, 507, 487, 474));

        let laptop_4x2 = compute_tile_work_area_bounds(49, 33, 1463, 949, 365, 474, 8);
        assert_eq!(laptop_4x2[0], (49, 33, 365, 474));
        assert_eq!(laptop_4x2[1], (414, 33, 365, 474));
        assert_eq!(laptop_4x2[2], (779, 33, 365, 474));
        assert_eq!(laptop_4x2[3], (1144, 33, 365, 474));

        // Exhaustive invariant check across counts 1..=25 and all presets / custom sizes:
        // 1) All windows stay strictly inside `(work_x..work_x+work_w, work_y..work_y+work_h)`
        // 2) Within each layer (`per_layer` cells), NO two windows ever overlap (`0px` overlap)
        // 3) Overflow windows (`i >= per_layer`) snap to exact `(left, top, w, h)` of `i % per_layer`
        for &(wx, wy, ww, wh) in &[(56, 33, 1456, 949), (0, 25, 1920, 1055), (57, 30, 2503, 1050)] {
            for count in 1..=25 {
                let (aw, ah) = auto_fit_window_size(ww, wh, count);
                let placements = compute_tile_work_area_bounds(wx, wy, ww, wh, aw, ah, count);
                let (cols, rows, _, _) = compute_tile_grid_dims(ww, wh, aw, ah, count);
                let per_layer = cols * rows;
                assert!(per_layer >= count.min(((ww / 200) * (wh / 180)) as usize));
                for (i, &(l, t, w, h)) in placements.iter().enumerate() {
                    assert!(l >= wx && l + w <= wx + ww);
                    assert!(t >= wy && t + h <= wy + wh);
                    if i >= per_layer {
                        assert_eq!(placements[i], placements[i % per_layer]);
                    }
                }
                let layer0 = &placements[..count.min(per_layer)];
                for a in 0..layer0.len() {
                    for b in (a + 1)..layer0.len() {
                        let (al, at, aw, ah) = layer0[a];
                        let (bl, bt, bw, bh) = layer0[b];
                        let sep = al + aw <= bl || bl + bw <= al || at + ah <= bt || bt + bh <= at;
                        assert!(sep, "overlap for count={count}: {:?} vs {:?}", layer0[a], layer0[b]);
                    }
                }
            }
            // Custom size slightly over half-screen (`735×480` on `1456×949`) must NOT overlap!
            let custom = compute_tile_work_area_bounds(wx, wy, ww, wh, 735, 480, 6);
            let (cc, cr, _, _) = compute_tile_grid_dims(ww, wh, 735, 480, 6);
            let c_layer = &custom[..6.min(cc * cr)];
            for a in 0..c_layer.len() {
                for b in (a + 1)..c_layer.len() {
                    let (al, at, aw, ah) = c_layer[a];
                    let (bl, bt, bw, bh) = c_layer[b];
                    assert!(al + aw <= bl || bl + bw <= al || at + ah <= bt || bt + bh <= at);
                }
            }
        }

        let tmp_prefs_dir = std::env::temp_dir().join(format!(
            "bonlogin-arr-prefs-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = std::fs::create_dir_all(&tmp_prefs_dir);
        let saved = crate::ui::ArrangePrefs {
            display_idx: 0,
            preset_idx: Some(4),
            custom_size: "365,474".to_string(),
        };
        saved.save_in(&tmp_prefs_dir);
        let loaded = crate::ui::ArrangePrefs::load_in(&tmp_prefs_dir);
        assert_eq!(loaded.preset_idx, Some(4));
        assert_eq!(loaded.custom_size, "365,474");
        let _ = std::fs::remove_dir_all(&tmp_prefs_dir);

        // macOS active display enumeration must return non-empty global work-area rects
        let displays = macos_active_display_rects();
        assert!(!displays.is_empty());
        assert!(displays[0].2 >= 500 && displays[0].3 >= 360);
        // Primary display work area top Y must account for the macOS menu bar (>= 24px)
        assert!(displays[0].1 >= 20, "expected visibleFrame top Y >= 20, got {:?}", displays[0]);

        // Loopback test for `cdp_set_window_bounds` (HTTP /json/list + WebSocket Browser.setWindowBounds)
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            // 1. Serve /json/list
            let (mut s1, _) = listener.accept().unwrap();
            let mut b1 = [0u8; 512];
            let _ = s1.read(&mut b1);
            let body = r#"[{"id":"target-1","type":"page","url":"https://example.com"}]"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            s1.write_all(resp.as_bytes()).unwrap();

            // 2. Serve WebSocket upgrade + 3 CDP requests (getWindowForTarget, setWindowBounds normal, setWindowBounds rect)
            let (mut s2, _) = listener.accept().unwrap();
            let mut b2 = [0u8; 1024];
            let _ = s2.read(&mut b2);
            s2.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                .unwrap();

            fn read_masked_text(s: &mut std::net::TcpStream) -> String {
                let mut h = [0u8; 2];
                s.read_exact(&mut h).unwrap();
                let len = (h[1] & 0x7f) as usize;
                let len = if len == 126 {
                    let mut ext = [0u8; 2];
                    s.read_exact(&mut ext).unwrap();
                    u16::from_be_bytes(ext) as usize
                } else {
                    len
                };
                let mut mask = [0u8; 4];
                s.read_exact(&mut mask).unwrap();
                let mut payload = vec![0u8; len];
                s.read_exact(&mut payload).unwrap();
                for (i, b) in payload.iter_mut().enumerate() {
                    *b ^= mask[i & 3];
                }
                String::from_utf8(payload).unwrap()
            }
            fn write_unmasked_text(s: &mut std::net::TcpStream, msg: &str) {
                let bytes = msg.as_bytes();
                let mut f = vec![0x81, bytes.len() as u8];
                f.extend_from_slice(bytes);
                s.write_all(&f).unwrap();
            }

            let req1 = read_masked_text(&mut s2);
            assert!(req1.contains("Browser.getWindowForTarget"));
            write_unmasked_text(
                &mut s2,
                r#"{"id":1,"result":{"windowId":7,"bounds":{"windowState":"maximized"}}}"#,
            );

            let req2 = read_masked_text(&mut s2);
            assert!(req2.contains(r#""windowState":"normal""#));
            write_unmasked_text(&mut s2, r#"{"id":2,"result":{}}"#);

            let req3 = read_masked_text(&mut s2);
            assert!(req3.contains(r#""width":960"#) && req3.contains(r#""height":600"#));
            write_unmasked_text(&mut s2, r#"{"id":3,"result":{}}"#);

            let req4 = read_masked_text(&mut s2);
            assert!(req4.contains("Target.activateTarget"));
            write_unmasked_text(&mut s2, r#"{"id":4,"result":{}}"#);
        });

        let ws_url = format!("ws://127.0.0.1:{port}/devtools/browser/mock");
        cdp_set_window_bounds(port, &ws_url, 10, 25, 960, 600).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn test_export_and_import_profile_archive_zip_and_trash() {
        let db = crate::db::Database::open_in_memory().unwrap();
        let mut p = Profile::new_default("ZipTestProfile", PlatformType::MacOS);
        p.tags = vec!["Live".to_string(), "VIP".to_string()];
        p.totp_secret = "JBSWY3DPEHPK3PXP".to_string();
        p.notes = "Backup test note".to_string();
        db.upsert_profile(&p).unwrap();

        // Verify soft-delete -> Trash -> Restore
        assert_eq!(db.list_profiles().unwrap().len(), 1);
        assert_eq!(db.list_trashed_profiles().unwrap().len(), 0);
        db.soft_delete_profile(&p.id).unwrap();
        assert_eq!(db.list_profiles().unwrap().len(), 0);
        assert_eq!(db.list_trashed_profiles().unwrap().len(), 1);
        db.restore_profile(&p.id).unwrap();
        let active = db.list_profiles().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].tags, vec!["Live", "VIP"]);
        assert_eq!(active[0].totp_secret, "JBSWY3DPEHPK3PXP");

        // Verify .zip export and import round-trip
        let zip_root = app_support_dir();
        let zip_out = crate::db::export_dir_for_root(&zip_root);
        let zip_path = export_profile_archive_zip_in(&zip_root, &zip_out, &p).unwrap();
        assert!(zip_path.is_file());
        let mut existing = std::collections::HashSet::new();
        existing.insert(p.id.clone());
        let restored = import_profile_archive_zip_in(&zip_root, &zip_path, &existing).unwrap();
        assert_ne!(restored.id, p.id);
        assert_eq!(restored.tags, vec!["Live", "VIP"]);
        assert_eq!(restored.totp_secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(restored.notes, "Backup test note");
        let _ = std::fs::remove_file(&zip_path);
        let _ = wipe_profile_data_in(&zip_root, &restored.id);

        // Verify path-traversal ID in .zip metadata is replaced with a safe UUID
        let mut malicious = p.clone();
        malicious.id = "../../outside_dir".to_string();
        let mal_zip = export_profile_archive_zip_in(&zip_root, &zip_out, &malicious).unwrap();
        let sanitized =
            import_profile_archive_zip_in(&zip_root, &mal_zip, &std::collections::HashSet::new()).unwrap();
        assert!(uuid::Uuid::parse_str(&sanitized.id).is_ok());
        let _ = std::fs::remove_file(&mal_zip);
        let _ = wipe_profile_data_in(&zip_root, &sanitized.id);

        // Verify multi-URL startup_url works as cookie domain fallback
        let bundle = parse_and_normalize_cookies(
            "sid=abc123; theme=dark",
            Some("https://shop.example.com, https://google.com"),
        )
        .unwrap();
        assert_eq!(bundle.cookies[0]["domain"], "shop.example.com");
        // Verify clean_profile_cache removes Cache/GPUCache while keeping Cookies intact
        let cache_test_id = format!("bon_cache_test_{}", rand::random::<u32>());
        let p_dir = app_support_dir().join("profiles").join(&cache_test_id);
        let def_dir = p_dir.join("Default");
        std::fs::create_dir_all(def_dir.join("Cache")).unwrap();
        std::fs::create_dir_all(p_dir.join("GPUCache")).unwrap();
        std::fs::write(def_dir.join("Cache/data_0"), vec![0u8; 4096]).unwrap();
        std::fs::write(p_dir.join("GPUCache/shader_0"), vec![0u8; 2048]).unwrap();
        std::fs::write(def_dir.join("Cookies"), b"SQLite format 3\0keep").unwrap();
        let (freed, rem) = clean_profile_cache_in(&zip_root, &cache_test_id).unwrap();
        assert_eq!(freed, 6144);
        assert_eq!(rem, 20);
        assert!(def_dir.join("Cookies").is_file());
        assert!(!def_dir.join("Cache").exists());
        let _ = wipe_profile_data_in(&zip_root, &cache_test_id);
        // Verify cleanup_stale_singleton_locks keeps live PID lock and removes dead PID lock
        #[cfg(unix)]
        {
            let lock_test_dir = std::env::temp_dir().join(format!("bon_lock_test_{}", rand::random::<u32>()));
            std::fs::create_dir_all(&lock_test_dir).unwrap();
            let my_pid = std::process::id();
            std::os::unix::fs::symlink(format!("host-{my_pid}"), lock_test_dir.join("SingletonLock")).unwrap();
            cleanup_stale_singleton_locks(&lock_test_dir);
            assert!(lock_test_dir.join("SingletonLock").symlink_metadata().is_ok());
            let _ = std::fs::remove_file(lock_test_dir.join("SingletonLock"));
            std::os::unix::fs::symlink("host-99999999", lock_test_dir.join("SingletonLock")).unwrap();
            cleanup_stale_singleton_locks(&lock_test_dir);
            assert!(lock_test_dir.join("SingletonLock").symlink_metadata().is_err());
            let _ = std::fs::remove_dir_all(&lock_test_dir);
        }

        // Verify cdp_type_as_human sends Input.dispatchKeyEvent frames without Runtime.enable
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut s1, _) = listener.accept().unwrap();
            let mut b1 = [0u8; 512];
            let _ = s1.read(&mut b1);
            let body = format!(
                r#"[{{"id":"t1","type":"page","url":"https://x.com","webSocketDebuggerUrl":"ws://127.0.0.1:{port}/devtools/page/t1"}}]"#
            );
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            s1.write_all(resp.as_bytes()).unwrap();

            let (mut s2, _) = listener.accept().unwrap();
            let mut b2 = [0u8; 1024];
            let _ = s2.read(&mut b2);
            s2.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                .unwrap();
            for req_id in 1..=4 {
                let mut h = [0u8; 2];
                s2.read_exact(&mut h).unwrap();
                let len = (h[1] & 0x7f) as usize;
                let len = if len == 126 {
                    let mut ext = [0u8; 2];
                    s2.read_exact(&mut ext).unwrap();
                    u16::from_be_bytes(ext) as usize
                } else {
                    len
                };
                let mut discard = vec![0u8; 4 + len];
                s2.read_exact(&mut discard).unwrap();
                let reply = format!(r#"{{"id":{req_id},"result":{{}}}}"#);
                let mut frame = vec![0x81, reply.len() as u8];
                frame.extend_from_slice(reply.as_bytes());
                s2.write_all(&frame).unwrap();
            }
        });
        let typed = cdp_type_as_human(port, "A\n").unwrap();
        assert_eq!(typed, 2);
        server.join().unwrap();

        // Verify local HTTP control handler inside spawn_blocking (including %20 decoding)
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let def_root = app_support_dir();
        let (code, body_s) =
            rt.block_on(handle_control_http_request_in(&def_root, "GET", "/health", ""));
        assert_eq!(code, 200);
        assert!(body_s.contains("\"bon-login\""));
        let (code404, _) = rt.block_on(handle_control_http_request_in(
            &def_root,
            "POST",
            "/profiles/NonExistent%20Profile/rotate-proxy",
            "",
        ));
        assert_eq!(code404, 404);

        // Verify ensure_profile_bookmarks enables bookmark_bar without auto-populating default bookmarks
        let bm_prof = Profile::new_default("TikTok Shop 01", PlatformType::MacOS);
        let bm_dir = app_support_dir().join("profiles").join(&bm_prof.id);
        ensure_profile_bookmarks(&bm_prof, &bm_dir);
        let pref_file = bm_dir.join("Default/Preferences");
        let pref_txt = std::fs::read_to_string(&pref_file).unwrap();
        assert!(pref_txt.contains("\"show_on_all_tabs\":true"));
        assert!(pref_txt.contains(&bm_prof.window_badge_label()));
        let local_state_txt = std::fs::read_to_string(bm_dir.join("Local State")).unwrap();
        assert!(local_state_txt.contains(&bm_prof.window_badge_label()));
        assert!(read_profile_bookmarks_in(&def_root, &bm_prof).is_empty());
        let custom_items = parse_bookmarks_editable("My Dashboard|https://dash.example.com, shop.example.com");
        assert_eq!(custom_items.len(), 2);
        assert_eq!(custom_items[0], ("My Dashboard".to_string(), "https://dash.example.com".to_string()));
        assert_eq!(custom_items[1], ("shop.example.com".to_string(), "https://shop.example.com".to_string()));
        write_profile_bookmarks_items(&bm_dir, &custom_items);
        assert_eq!(read_profile_bookmarks_in(&def_root, &bm_prof), custom_items);
        write_profile_bookmarks_items(&bm_dir, &[]);
        assert!(read_profile_bookmarks_in(&def_root, &bm_prof).is_empty());
        let _ = wipe_profile_data_in(&def_root, &bm_prof.id);
        // Verify parse_flow_vars_text and save_profile_history_as_flow
        let parsed_vars = parse_flow_vars_text("email=user@test.com, pass=secret123\notp=999999");
        assert_eq!(parsed_vars.get("email").map(String::as_str), Some("user@test.com"));
        assert_eq!(parsed_vars.get("pass").map(String::as_str), Some("secret123"));
        assert_eq!(parsed_vars.get("otp").map(String::as_str), Some("999999"));
        let hist_prof = Profile::new_default("FlowUIProf", PlatformType::Linux);
        let hist_path = history_flow_path_in(&def_root, &hist_prof.short_id());
        let mut dummy_hist = AgentFlow {
            name: "hist".to_string(),
            domain: "example.com".to_string(),
            updated_at: 1,
            steps: vec![FlowStep {
                op: "fill".to_string(),
                locators: vec!["#email".to_string()],
                value: Some("user@test.com".to_string()),
                extra_args: vec![],
                optional: false,
            }],
        };
        save_flow_to_path(&hist_path, &mut dummy_hist).unwrap();
        let saved_fl = save_profile_history_as_flow_in(
            &def_root,
            "ui_test_flow_tmp",
            &hist_prof,
            &[("email".to_string(), "user@test.com".to_string())],
        )
        .unwrap();
        assert_eq!(saved_fl.steps[0].value.as_deref(), Some("{{email}}"));
        assert!(list_saved_flows_in(&def_root).iter().any(|f| f.name == "ui_test_flow_tmp"));
        let mutated = mutate_flow_step_in(&def_root, "ui_test_flow_tmp", 0, "optional").unwrap();
        assert!(mutated.steps[0].optional);
        let parsed_json_vars =
            parse_flow_vars_body(r#"{"vars":{"email":"json@test.com","count":3}}"#);
        assert_eq!(
            parsed_json_vars.get("email").map(String::as_str),
            Some("json@test.com")
        );
        assert_eq!(parsed_json_vars.get("count").map(String::as_str), Some("3"));
        let (code_fl, body_fl) =
            rt.block_on(handle_control_http_request_in(&def_root, "GET", "/flows", ""));
        assert_eq!(code_fl, 200);
        assert!(body_fl.contains("\"ui_test_flow_tmp\""));
        assert_eq!(percent_decode("US%20Resi%20%2301"), "US Resi #01");
        let (code_fl404, body_fl404) = rt.block_on(handle_control_http_request_in(
            &def_root,
            "POST",
            "/profiles/Missing%20%2399/flow/ui_test_flow_tmp",
            "{}",
        ));
        assert_eq!(code_fl404, 404);
        assert!(body_fl404.contains("Missing #99"));
        if let Some(first_prof) = crate::db::Database::open_default()
            .ok()
            .and_then(|d| d.list_profiles().ok())
            .and_then(|v| v.into_iter().next())
        {
            let p_id = first_prof.short_id();
            let (c_mfl, b_mfl) = rt.block_on(handle_control_http_request_in(
                &def_root,
                "POST",
                &format!("/profiles/{p_id}/flow/nonexistent_flow_404_check"),
                "{}",
            ));
            assert_eq!(c_mfl, 404);
            assert!(b_mfl.contains("Flow 'nonexistent_flow_404_check' not found"));
        }
        let _ = std::fs::remove_file(flow_file_path_in(&def_root, "ui_test_flow_tmp").unwrap());
        clear_flow_session_cache_in(&def_root, &hist_prof.short_id());
        assert!(unix_pid_alive(std::process::id()));
        assert!(!unix_pid_alive(0));
        assert!(!unix_pid_alive(u32::MAX));
        let hw_tmp = app_support_dir().join("backups").join(".hw_test_tmp");
        let _ = std::fs::remove_dir_all(&hw_tmp);
        std::fs::create_dir_all(hw_tmp.join("sub_a")).unwrap();
        std::fs::create_dir_all(hw_tmp.join("sub_b")).unwrap();
        std::fs::create_dir_all(hw_tmp.join("sub_c")).unwrap();
        std::fs::write(hw_tmp.join("sub_a/f1.bin"), vec![7u8; 1024]).unwrap();
        std::fs::write(hw_tmp.join("sub_b/f2.bin"), vec![9u8; 2048]).unwrap();
        clonefile_or_copy(&hw_tmp.join("sub_a/f1.bin"), &hw_tmp.join("sub_c/f3.bin")).unwrap();
        assert_eq!(dir_size_bytes(&hw_tmp), 4096);
        let _ = std::fs::remove_dir_all(&hw_tmp);
    }

    #[test]
    fn test_runtime_supervisor_stops_owned_and_external_processes_and_reconciles() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let sup = RuntimeSupervisor::new();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for _ in 0..6 {
                if let Ok((mut s, _)) = listener.accept() {
                    let mut buf = [0u8; 256];
                    let _ = s.read(&mut buf);
                    let body = r#"[{"type":"page","url":"https://example.com"}]"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes());
                }
            }
        });

        let prof = Profile::new_default("SupOwned", PlatformType::MacOS);
        let sid = prof.short_id();
        let p_dir = profile_user_data_dir_in(sup.root_dir(), &prof.id).unwrap();
        let child = Command::new("sleep").arg("30").spawn().unwrap();
        let child_pid = child.id();
        let info = RuntimeInfo {
            pid: child_pid,
            cdp_port: port,
            ws_url: format!("ws://127.0.0.1:{port}/devtools/browser/sup"),
            local_proxy_port: None,
        };
        std::fs::write(
            runtime_file_path_in(sup.root_dir(), &prof.id),
            serde_json::to_string(&info).unwrap(),
        )
        .unwrap();
        sup.insert_test_process(&prof.id, &sid, child, info.clone());
        assert!(sup.contains_owned(&prof.id));
        assert_eq!(sup.live_info(&prof.id).as_ref(), Some(&info));

        let (exited, ext_live) = sup.reconcile_live(std::slice::from_ref(&prof.id));
        assert!(exited.is_empty());
        assert!(ext_live.is_empty());

        assert!(sup.stop_and_wipe(&prof.id, &sid).is_ok());
        assert!(!sup.contains_owned(&prof.id));
        assert!(!unix_pid_alive(child_pid));
        assert!(!p_dir.exists());
    }

    #[test]
    fn test_control_http_adapter_with_isolated_workspace_and_live_bookmark_guard() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let tmp = std::env::temp_dir().join(format!(
            "bonlogin-ctrl-test-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let ws = crate::db::Workspace::open_at(&tmp).unwrap();
        let mut p = Profile::new_default("CtrlTest #01", crate::models::PlatformType::MacOS);
        p.group_tag = "Ads".to_string();
        ws.upsert_profile(&p).unwrap();

        // Seed a flow & a profile Cache file inside the isolated `tmp` workspace
        let mut scoped_flow = AgentFlow {
            name: "scoped_only_flow".to_string(),
            domain: "example.com".to_string(),
            updated_at: 1,
            steps: vec![],
        };
        save_flow_to_path(&tmp.join("flows/scoped_only_flow.json"), &mut scoped_flow).unwrap();
        let scoped_cache = tmp.join("profiles").join(&p.id).join("Default/Cache");
        std::fs::create_dir_all(&scoped_cache).unwrap();
        std::fs::write(scoped_cache.join("data_0"), vec![1u8; 2048]).unwrap();

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();

        // 1. Scoped GET /profiles, GET /flows, and POST /clean-cache operate strictly inside `tmp`
        let (code, body) =
            rt.block_on(handle_control_http_request_in(&tmp, "GET", "/profiles", ""));
        assert_eq!(code, 200);
        assert!(body.contains("CtrlTest #01"));

        let (code_fl, body_fl) =
            rt.block_on(handle_control_http_request_in(&tmp, "GET", "/flows", ""));
        assert_eq!(code_fl, 200);
        assert!(body_fl.contains("scoped_only_flow"));

        let (code_cc, body_cc) = rt.block_on(handle_control_http_request_in(
            &tmp,
            "POST",
            "/profiles/CtrlTest%20%2301/clean-cache",
            "",
        ));
        assert_eq!(code_cc, 200);
        assert!(body_cc.contains("2048"));
        assert!(!scoped_cache.exists());

        // 2. Async rotate-proxy hits local rotation webhook and fails closed on dead proxy port (502)
        let (code_no_px, _) = rt.block_on(handle_control_http_request_in(
            &tmp,
            "POST",
            "/profiles/CtrlTest%20%2301/rotate-proxy",
            "",
        ));
        assert_eq!(code_no_px, 400);

        let rot_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let rot_port = rot_listener.local_addr().unwrap().port();
        let dead_proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_proxy_port = dead_proxy_listener.local_addr().unwrap().port();
        drop(dead_proxy_listener);
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = rot_listener.accept() {
                let mut buf = [0u8; 256];
                let _ = s.read(&mut buf);
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}",
                );
            }
        });
        p.proxy = Some(ProxyConfig {
            protocol: ProxyProtocol::Http,
            host: "127.0.0.1".to_string(),
            port: dead_proxy_port,
            username: None,
            password: None,
            change_ip_url: Some(format!("http://127.0.0.1:{rot_port}/rotate")),
        });
        ws.upsert_profile(&p).unwrap();
        let (code_rot_502, _) = rt.block_on(handle_control_http_request_in(
            &tmp,
            "POST",
            "/profiles/CtrlTest%20%2301/rotate-proxy",
            "",
        ));
        assert_eq!(code_rot_502, 502);
        assert_eq!(crate::control::CONTROL_HTTP_ENDPOINTS.len(), 16);
        assert!(crate::control::CONTROL_HTTP_ENDPOINTS.contains(&"GET /flows"));
        assert!(crate::control::CONTROL_HTTP_ENDPOINTS.contains(&"POST /profiles/:id/totp"));
        assert!(crate::control::CONTROL_HTTP_ENDPOINTS.contains(&"POST /profiles/:id/screenshot"));
        assert!(crate::control::CONTROL_HTTP_ENDPOINTS.contains(&"POST /profiles/:id/preflight"));
        assert!(crate::control::CONTROL_HTTP_ENDPOINTS.contains(&"POST /profiles/:id/flow/:flow_name"));
        assert!(crate::control::CONTROL_HTTP_ENDPOINTS.contains(&"GET /synchronizer"));
        assert!(crate::control::CONTROL_HTTP_ENDPOINTS.contains(&"POST /synchronizer/start"));
        assert!(crate::control::CONTROL_HTTP_ENDPOINTS.contains(&"POST /synchronizer/stop"));
        let (code_sync, body_sync) =
            rt.block_on(handle_control_http_request_in(&tmp, "GET", "/synchronizer", ""));
        assert_eq!(code_sync, 200);
        assert!(body_sync.contains("\"synchronizer\""));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_workspace_multithread_sidecar_isolation_and_pure_chromium_args() {
        let dir_a = std::env::temp_dir().join(format!(
            "bonlogin-ws-mt-a-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let dir_b = std::env::temp_dir().join(format!(
            "bonlogin-ws-mt-b-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let ws_a = crate::db::Workspace::open_at(&dir_a).unwrap();
        let ws_b = crate::db::Workspace::open_at(&dir_b).unwrap();

        let p1 = Profile::new_default("Alpha-01", PlatformType::MacOS);
        let p2 = Profile::new_default("Alpha-02", PlatformType::MacOS);
        ws_a.upsert_profile(&p1).unwrap();
        ws_a.upsert_profile(&p2).unwrap();

        // Seed two live runtime files inside `dir_a` (PID = current process so unix_pid_alive == true,
        // closed ephemeral CDP port so cdp_has_open_window == None -> treated as live process).
        let closed_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = closed_listener.local_addr().unwrap().port();
        drop(closed_listener);
        let rt_json = serde_json::to_string(&RuntimeInfo {
            pid: std::process::id(),
            cdp_port: closed_port,
            ws_url: format!("ws://127.0.0.1:{closed_port}/devtools/browser/test"),
            local_proxy_port: None,
        })
        .unwrap();
        for p in [&p1, &p2] {
            let pdir = ws_a.profile_user_data_dir(&p.id).unwrap();
            std::fs::write(pdir.join("bon_runtime.json"), &rt_json).unwrap();
        }

        // 1. Multi-thread `/arrange` (>=2 profiles triggers `parallel_map` worker threads)
        // MUST see both live runtimes in `ws_a` instead of dropping thread-local root!
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let (code_arr, body_arr) = rt.block_on(handle_control_http_request_in(
            &dir_a,
            "POST",
            "/arrange",
            "960,600",
        ));
        assert_eq!(code_arr, 200);
        let arr_val: serde_json::Value = serde_json::from_str(&body_arr).unwrap();
        assert_eq!(arr_val["total"], 2, "worker threads escaped Workspace root: {body_arr}");

        // 2. Stop live files so offline Workspace sidecars (cookies, bookmarks, flows, archive zip) can run concurrently across ws_a & ws_b
        for p in [&p1, &p2] {
            let _ = std::fs::remove_file(ws_a.profile_user_data_dir(&p.id).unwrap().join("bon_runtime.json"));
        }
        let pb = Profile::new_default("Beta-01", PlatformType::Windows);
        ws_b.upsert_profile(&pb).unwrap();

        std::thread::scope(|s| {
            let dir_a_t1 = dir_a.clone();
            let dir_b_t1 = dir_b.clone();
            let p1_t1 = p1.clone();
            s.spawn(move || {
                let w_a = crate::db::Workspace::open_at(&dir_a_t1).unwrap();
                let w_b = crate::db::Workspace::open_at(&dir_b_t1).unwrap();
                w_a.save_prelaunch_cookies(&p1_t1.short_id(), "c_user=alpha; xs=111")
                    .unwrap();
                w_a.write_bookmarks_checked(
                    &p1_t1,
                    &[("AlphaShop".to_string(), "https://alpha.example".to_string())],
                )
                .unwrap();
                let zip_a = w_a.export_profile_archive_zip(&p1_t1).unwrap();
                assert!(zip_a.starts_with(w_a.backups_dir()));
                let restored_in_b = w_b.import_profile_archive_zip(&zip_a).unwrap();
                assert_eq!(restored_in_b.name, "Alpha-01");
                assert!(
                    w_b.read_prelaunch_cookies(&restored_in_b.short_id())
                        .contains("alpha")
                );
            });
            let dir_a_t2 = dir_a.clone();
            let dir_b_t2 = dir_b.clone();
            let pb_t2 = pb.clone();
            s.spawn(move || {
                let w_a = crate::db::Workspace::open_at(&dir_a_t2).unwrap();
                let w_b = crate::db::Workspace::open_at(&dir_b_t2).unwrap();
                let hist_path = w_b.history_flow_path(&pb_t2.short_id());
                let mut h = AgentFlow {
                    name: "hist".to_string(),
                    domain: "beta.example".to_string(),
                    updated_at: 1,
                    steps: vec![FlowStep {
                        op: "click".to_string(),
                        locators: vec!["role=button[name=\"Go\"]".to_string()],
                        value: None,
                        extra_args: vec![],
                        optional: false,
                    }],
                };
                save_flow_to_path(&hist_path, &mut h).unwrap();
                w_b.save_history_as_flow("beta_flow", &pb_t2, &[]).unwrap();
                assert_eq!(w_b.list_flows().len(), 1);
                assert!(w_a.list_flows().is_empty());
            });
        });

        assert_eq!(ws_a.read_bookmarks(&p1).len(), 1);
        assert!(ws_b.read_bookmarks(&pb).is_empty());

        // 3. `build_chromium_args_with_extensions` is 100% pure: takes explicit extension dirs without touching global DB/disk
        let custom_ext_dir = dir_a.join("extensions/custom-test-ext");
        let args = build_chromium_args_with_extensions(
            &p1,
            None,
            Path::new("/tmp/pure-profile-dir"),
            None,
            std::slice::from_ref(&custom_ext_dir),
        );
        assert!(
            args.iter()
                .any(|a| a == &format!("--load-extension={}", custom_ext_dir.display()))
        );

        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    #[test]
    fn test_unified_domain_workflows_live_bookmark_guard_and_attached_control_engine() {
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        };

        let tmp = std::env::temp_dir().join(format!(
            "bonlogin-cand2-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let ws = crate::db::Workspace::open_at(&tmp).unwrap();
        let mut p = Profile::new_default("EngineProf", PlatformType::MacOS);
        p.startup_url = "https://shop.example.com".to_string();
        ws.upsert_profile(&p).unwrap();
        let orig_bms = vec![("Shop".to_string(), "https://shop.example.com".to_string())];
        ws.write_bookmarks_checked(&p, &orig_bms).unwrap();

        // Simulate live running browser owned by an attached RuntimeSupervisor
        let sup = RuntimeSupervisor::new_in(&tmp);
        let closed_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = closed_l.local_addr().unwrap().port();
        drop(closed_l);
        let child = Command::new("sleep").arg("30").spawn().unwrap();
        let child_pid = child.id();
        let info = RuntimeInfo {
            pid: child_pid,
            cdp_port: closed_port,
            ws_url: format!("ws://127.0.0.1:{closed_port}/devtools/browser/c2"),
            local_proxy_port: None,
        };
        let pdir = ws.profile_user_data_dir(&p.id).unwrap();
        std::fs::write(
            pdir.join("bon_runtime.json"),
            serde_json::to_string(&info).unwrap(),
        )
        .unwrap();
        sup.insert_test_process(&p.id, &p.short_id(), child, info);

        // 1. Modifying bookmarks while browser is running MUST return an explicit error (not silently drop)
        let changed_bms = vec![("NewBM".to_string(), "https://new.example.com".to_string())];
        assert!(
            ws.save_profile_bundle(&p, Some(""), Some(&changed_bms)).is_err(),
            "must reject bookmark modification while browser is open"
        );
        assert_eq!(ws.read_bookmarks(&p), orig_bms);

        // 2. Saving notes + cookies with UNCHANGED bookmarks while browser is running MUST succeed
        p.notes = "Updated while live".to_string();
        let saved_bundle = ws
            .save_profile_bundle(&p, Some("sid_tok=xyz987"), Some(&orig_bms))
            .unwrap();
        assert!(saved_bundle.is_some());
        assert!(ws.read_prelaunch_cookies(&p.short_id()).contains("sid_tok"));
        assert_eq!(ws.list_profiles().unwrap()[0].notes, "Updated while live");

        // 3. Attached ControlEngine stops owned RuntimeSupervisor session & fires UI mutation callback
        let db_arc = Arc::new(Mutex::new(ws));
        let notify_hits = Arc::new(AtomicUsize::new(0));
        let hits_cl = notify_hits.clone();
        let engine = ControlEngine::attached(
            db_arc.clone(),
            sup.clone(),
            Arc::new(move || {
                hits_cl.fetch_add(1, Ordering::SeqCst);
            }),
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (code_stop, body_stop) =
            rt.block_on(engine.handle_http("POST", "/profiles/EngineProf/stop", ""));
        assert_eq!(code_stop, 200, "stop failed: {body_stop}");
        assert!(!sup.contains_owned(&p.id), "attached stop must drain owned supervisor process");
        assert!(!unix_pid_alive(child_pid));
        assert!(notify_hits.load(Ordering::SeqCst) >= 1, "UI notify callback must fire on HTTP stop");

        // 4. Failed SavedProxy rotation also records last_error in DB
        let sp = SavedProxy::new(
            "DeadRotateProxy",
            "Test",
            ProxyConfig {
                protocol: ProxyProtocol::Http,
                host: "127.0.0.1".to_string(),
                port: closed_port,
                username: None,
                password: None,
                change_ip_url: None,
            },
        );
        db_arc.lock().unwrap().upsert_proxy(&sp).unwrap();
        let rot_err = rt.block_on(check_or_rotate_saved_proxy(&db_arc, &sp, true));
        assert!(rot_err.is_err());
        let stored_sp = db_arc.lock().unwrap().list_proxies().unwrap().remove(0);
        assert!(stored_sp.last_error.is_some(), "failed rotation must record last_error");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_runtime_supervisor_single_flight_fail_closed_and_encapsulated_shutdown() {
        use std::io::{Read, Write};
        use std::os::unix::fs::PermissionsExt;
        use std::sync::{Arc, Mutex};

        let tmp = std::env::temp_dir().join(format!(
            "bonlogin-cand3-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let ws = crate::db::Workspace::open_at(&tmp).unwrap();

        // Local stub for CDP `/json/list`
        let cdp_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let cdp_port = cdp_listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for _ in 0..16 {
                if let Ok((mut s, _)) = cdp_listener.accept() {
                    let mut buf = [0u8; 256];
                    let _ = s.read(&mut buf);
                    let body = r#"[{"type":"page","url":"https://example.com"}]"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes());
                }
            }
        });

        let spawn_log = tmp.join("kernel_spawns.log");
        let fake_kernel = tmp.join("fake_chromium.sh");
        let script = format!(
            "#!/bin/sh\n\
             echo spawned >> \"{}\"\n\
             udd=\"\"\n\
             for arg in \"$@\"; do\n\
               case \"$arg\" in\n\
                 --user-data-dir=*) udd=\"${{arg#--user-data-dir=}}\" ;;\n\
               esac\n\
             done\n\
             sleep 0.08\n\
             printf \"{}\\n/devtools/browser/fake-sf\\n\" > \"$udd/DevToolsActivePort\"\n\
             exec sleep 30\n",
            spawn_log.display(),
            cdp_port
        );
        std::fs::write(&fake_kernel, script).unwrap();
        std::fs::set_permissions(&fake_kernel, std::fs::Permissions::from_mode(0o755)).unwrap();

        let sup = RuntimeSupervisor::new_with_kernel_in(&tmp, &fake_kernel);

        // 1. Fail-closed gate: dead proxy port MUST abort before spawning kernel
        let dead_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_port = dead_l.local_addr().unwrap().port();
        drop(dead_l);
        let mut dead_prof = Profile::new_default("FailClosedProf", PlatformType::MacOS);
        dead_prof.proxy = Some(ProxyConfig {
            protocol: ProxyProtocol::Http,
            host: "127.0.0.1".to_string(),
            port: dead_port,
            username: None,
            password: None,
            change_ip_url: None,
        });
        ws.upsert_profile(&dead_prof).unwrap();
        let db_arc = Arc::new(Mutex::new(ws));

        let fail_res = sup.ensure_launched(&db_arc, &dead_prof).await;
        assert!(
            fail_res.as_ref().is_err_and(|e| e.to_string().contains("Fail-Closed")),
            "expected Fail-Closed error, got: {fail_res:?}"
        );
        assert!(
            !spawn_log.exists(),
            "kernel MUST NOT be spawned when fail-closed proxy check fails"
        );

        // 2. Single-flight concurrent launch: 2 simultaneous callers spawn kernel ONCE and share RuntimeInfo
        let mut ok_prof = Profile::new_default("SingleFlightProf", PlatformType::MacOS);
        ok_prof.custom_timezone = Some("UTC".to_string());
        db_arc.lock().unwrap().upsert_profile(&ok_prof).unwrap();

        let sup1 = sup.clone();
        let db1 = db_arc.clone();
        let p1 = ok_prof.clone();
        let t1 = tokio::spawn(async move { sup1.ensure_launched(&db1, &p1).await });

        let sup2 = sup.clone();
        let db2 = db_arc.clone();
        let p2 = ok_prof.clone();
        let t2 = tokio::spawn(async move { sup2.ensure_launched(&db2, &p2).await });

        let (r1, r2) = tokio::join!(t1, t2);
        let info1 = r1.unwrap().unwrap();
        let info2 = r2.unwrap().unwrap();
        assert_eq!(info1.pid, info2.pid, "single-flight callers must share the same child PID");
        assert_eq!(info1.cdp_port, cdp_port);

        let spawns = std::fs::read_to_string(&spawn_log).unwrap_or_default();
        assert_eq!(
            spawns.lines().count(),
            1,
            "concurrent ensure_launched must spawn kernel exactly once, got: {spawns:?}"
        );
        let persisted = db_arc
            .lock()
            .unwrap()
            .list_profiles()
            .unwrap()
            .into_iter()
            .find(|p| p.id == ok_prof.id)
            .unwrap();
        assert!(persisted.last_launched_at.is_some());

        // 3. Unified graceful stop reaps child and removes bon_runtime.json
        assert!(sup.stop(&ok_prof.id, &ok_prof.short_id()));
        assert!(!sup.contains_owned(&ok_prof.id));
        assert!(!unix_pid_alive(info1.pid));
        assert!(!runtime_file_path_in(&tmp, &ok_prof.id).exists());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_cdp_client_rfc6455_64bit_frame_and_minimized_window_restore() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        // 1. Verify RFC 6455 7-bit, 16-bit, and 64-bit (>= 65536 bytes) masked client frame encoding
        let big_payload = "x".repeat(70_000);
        let big_frame = encode_ws_client_text_frame(&big_payload);
        assert_eq!(big_frame[0], 0x81);
        assert_eq!(
            big_frame[1],
            0x80 | 127,
            "payloads >= 65536 bytes must use RFC 6455 64-bit length indicator 127, not u16 truncation"
        );
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&big_frame[2..10]);
        assert_eq!(u64::from_be_bytes(len_bytes), 70_000);
        assert_eq!(big_frame.len(), 14 + 70_000);

        // 2. Loopback HTTP + WebSocket CDP server verifying minimized window restore + setWindowBounds + activateTarget
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (methods_tx, methods_rx) = std::sync::mpsc::channel::<Vec<(String, serde_json::Value)>>();
        std::thread::spawn(move || {
            // Connection 1: GET /json/list
            let (mut s1, _) = listener.accept().unwrap();
            let mut b1 = [0u8; 512];
            let _ = s1.read(&mut b1);
            let list_json = format!(
                r#"[{{"id":"tab-42","type":"page","url":"https://browserscan.net","webSocketDebuggerUrl":"ws://127.0.0.1:{port}/devtools/page/tab-42"}}]"#
            );
            let http_resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{list_json}",
                list_json.len()
            );
            s1.write_all(http_resp.as_bytes()).unwrap();
            drop(s1);

            // Connection 2: Browser WebSocket upgrade + 4 JSON-RPC calls
            let (mut ws, _) = listener.accept().unwrap();
            let mut hs = [0u8; 1024];
            let _ = ws.read(&mut hs);
            ws.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            )
            .unwrap();

            let read_masked_frame = |sock: &mut std::net::TcpStream| -> serde_json::Value {
                let mut h2 = [0u8; 2];
                sock.read_exact(&mut h2).unwrap();
                let len0 = (h2[1] & 0x7f) as usize;
                let plen = if len0 < 126 {
                    len0
                } else if len0 == 126 {
                    let mut b2 = [0u8; 2];
                    sock.read_exact(&mut b2).unwrap();
                    u16::from_be_bytes(b2) as usize
                } else {
                    let mut b8 = [0u8; 8];
                    sock.read_exact(&mut b8).unwrap();
                    u64::from_be_bytes(b8) as usize
                };
                let mut mask = [0u8; 4];
                sock.read_exact(&mut mask).unwrap();
                let mut data = vec![0u8; plen];
                sock.read_exact(&mut data).unwrap();
                for (i, b) in data.iter_mut().enumerate() {
                    *b ^= mask[i & 3];
                }
                serde_json::from_slice(&data).unwrap()
            };
            let write_unmasked_frame = |sock: &mut std::net::TcpStream, txt: &str| {
                let bytes = txt.as_bytes();
                let mut f = vec![0x81, bytes.len() as u8];
                f.extend_from_slice(bytes);
                sock.write_all(&f).unwrap();
            };

            let mut seen = Vec::new();
            for step in 0..4 {
                let req = read_masked_frame(&mut ws);
                let id = req["id"].as_u64().unwrap();
                let method = req["method"].as_str().unwrap().to_string();
                seen.push((method.clone(), req["params"].clone()));
                let reply = if step == 0 {
                    serde_json::json!({
                        "id": id,
                        "result": { "windowId": 7, "bounds": { "windowState": "minimized" } }
                    })
                } else {
                    serde_json::json!({ "id": id, "result": {} })
                };
                write_unmasked_frame(&mut ws, &reply.to_string());
            }
            let _ = methods_tx.send(seen);
        });

        cdp_set_window_bounds(
            port,
            &format!("ws://127.0.0.1:{port}/devtools/browser/root"),
            10,
            25,
            960,
            600,
        )
        .unwrap();
        let calls = methods_rx.recv().unwrap();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0].0, "Browser.getWindowForTarget");
        assert_eq!(calls[1].0, "Browser.setWindowBounds");
        assert_eq!(calls[1].1["bounds"]["windowState"], "normal");
        assert_eq!(calls[2].0, "Browser.setWindowBounds");
        assert_eq!(calls[2].1["bounds"]["width"], 960);
        assert_eq!(calls[3].0, "Target.activateTarget");
    }

    #[test]
    fn test_agent_flow_replay_self_healing_promotion_and_snapshot_recovery() {
        struct ScriptedAgent {
            calls: Vec<Vec<String>>,
        }
        impl AgentSession for ScriptedAgent {
            fn exec(&mut self, args: &[String]) -> std::result::Result<String, String> {
                self.calls.push(args.to_vec());
                match args {
                    // Step 0: primary CSS selector `#broken-submit` fails, fallback `role:button:Sign In` succeeds!
                    [op, sel] if op == "click" && sel == "#broken-submit" => {
                        Err("Timeout waiting for #broken-submit".to_string())
                    }
                    [f, r, role, op, ..]
                        if f == "find" && r == "role" && role == "button" && op == "click" =>
                    {
                        Ok("Clicked Sign In".to_string())
                    }
                    // Step 1: `select` with `role:combobox:Country` has empty `find` candidates -> triggers live snapshot recovery!
                    [s, ..] if s == "snapshot" => Ok(
                        "- combobox \"Country\" [ref=e7]\n- button \"Continue\" [ref=e8]\n"
                            .to_string(),
                    ),
                    [op, target, val]
                        if op == "select" && target == "@e7" && val == "VN" =>
                    {
                        Ok("Selected VN".to_string())
                    }
                    // Step 2 (optional): fails and gets skipped
                    [op, sel] if op == "click" && sel == "#cookie-banner-dismiss" => {
                        Err("Banner absent".to_string())
                    }
                    // Step 3 (required): fails and triggers diagnostic snapshot + jev_find_payload
                    _ => Err("Selector #otp-submit not found".to_string()),
                }
            }
        }

        let tmp = std::env::temp_dir().join(format!(
            "bonlogin-cand4-flow-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let ws = crate::db::Workspace::open_at(&tmp).unwrap();
        let prof = Profile::new_default("FlowRunnerProf", PlatformType::MacOS);
        let flow_path = ws.flow_file_path("checkout_flow").unwrap();
        let mut flow = AgentFlow {
            name: "checkout_flow".to_string(),
            domain: "shop.example".to_string(),
            updated_at: 1,
            steps: vec![
                FlowStep {
                    op: "click".to_string(),
                    locators: vec![
                        "#broken-submit".to_string(),
                        "role:button:Sign In".to_string(),
                    ],
                    value: None,
                    extra_args: vec![],
                    optional: false,
                },
                FlowStep {
                    op: "select".to_string(),
                    locators: vec!["role:combobox:Country".to_string()],
                    value: Some("{{country}}".to_string()),
                    extra_args: vec![],
                    optional: false,
                },
                FlowStep {
                    op: "click".to_string(),
                    locators: vec!["#cookie-banner-dismiss".to_string()],
                    value: None,
                    extra_args: vec![],
                    optional: true,
                },
                FlowStep {
                    op: "click".to_string(),
                    locators: vec!["#otp-submit".to_string()],
                    value: None,
                    extra_args: vec![],
                    optional: false,
                },
            ],
        };
        save_flow_to_path(&flow_path, &mut flow).unwrap();

        let mut vars = std::collections::HashMap::new();
        vars.insert("country".to_string(), "VN".to_string());
        let mut agent = ScriptedAgent { calls: Vec::new() };
        let report = replay_flow_steps_with_in(
            ws.root_dir(),
            "checkout_flow",
            &prof,
            &vars,
            0,
            &mut agent,
        )
        .unwrap();

        assert_eq!(report.executed_steps.len(), 3);
        assert_eq!(report.executed_steps[0]["status"], "ok");
        assert_eq!(report.executed_steps[1]["status"], "ok");
        assert_eq!(report.executed_steps[2]["status"], "skipped_optional");

        // Winning fallback locator (`role:button:Sign In`) was promoted to index 0 on disk!
        let reloaded = load_flow_from_path(&flow_path, "checkout_flow").unwrap();
        assert_eq!(reloaded.steps[0].locators[0], "role:button:Sign In");

        // Step 3 failure includes diagnostic snapshot & resume_cli `--from-step 4`
        let fail = report.failure.expect("step 3 should report structured failure");
        assert_eq!(fail["failed_step"], 3);
        assert!(
            fail["resume_cli"]
                .as_str()
                .unwrap()
                .ends_with("--from-step 4")
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_ponytail_review_security_race_and_bounds_fixes() {
        use std::io::{Read, Write};
        use std::os::unix::fs::PermissionsExt;
        use std::sync::{Arc, Mutex};

        let tmp = std::env::temp_dir().join(format!(
            "bonlogin-review-fixes-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let ws = crate::db::Workspace::open_at(&tmp).unwrap();

        // --- Finding 1: DNS-rebinding Host header bypass & missing Host header ---
        let std_http = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        std_http.set_nonblocking(true).unwrap();
        let http_port = std_http.local_addr().unwrap().port();
        let tokio_http = tokio::net::TcpListener::from_std(std_http).unwrap();
        let engine = ControlEngine::open_at(&tmp).unwrap();
        let srv_task = tokio::spawn(async move {
            let _ = serve_control_http_with_engine(tokio_http, engine).await;
        });

        let send_raw_http = |raw_req: &str| -> String {
            let mut s = std::net::TcpStream::connect(("127.0.0.1", http_port)).unwrap();
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            s.write_all(raw_req.as_bytes()).unwrap();
            let mut resp = String::new();
            let _ = s.read_to_string(&mut resp);
            resp
        };

        let rebind_resp = send_raw_http(&format!(
            "GET /health HTTP/1.1\r\nHost: localhost.attacker.com:{http_port}\r\n\r\n"
        ));
        assert!(
            rebind_resp.starts_with("HTTP/1.1 403"),
            "DNS-rebinding Host localhost.attacker.com MUST be rejected with 403, got: {rebind_resp}"
        );
        let no_host_resp = send_raw_http("GET /health HTTP/1.1\r\nConnection: close\r\n\r\n");
        assert!(
            no_host_resp.starts_with("HTTP/1.1 403"),
            "missing Host header MUST be rejected with 403, got: {no_host_resp}"
        );
        let ok_resp = send_raw_http(&format!(
            "GET /health HTTP/1.1\r\nHost: 127.0.0.1:{http_port}\r\n\r\n"
        ));
        assert!(ok_resp.starts_with("HTTP/1.1 200"), "valid loopback Host failed: {ok_resp}");
        srv_task.abort();

        // --- Finding 2: Extension symlink overwrite, manifest `../` traversal, and unsafe `preferred_id` ---
        let outside_dir = tmp.join("outside_sensitive");
        std::fs::create_dir_all(&outside_dir).unwrap();
        let outside_html = outside_dir.join("victim.html");
        let outside_js = outside_dir.join("victim.js");
        std::fs::write(&outside_html, "<html><head></head><body>clean</body></html>").unwrap();
        std::fs::write(&outside_js, "console.log('clean');").unwrap();

        let ext_dir = tmp.join("extensions/evil-ext");
        std::fs::create_dir_all(&ext_dir).unwrap();
        std::fs::write(
            ext_dir.join("manifest.json"),
            r#"{"manifest_version":3,"name":"Evil","version":"1.0","background":{"service_worker":"../../outside_sensitive/victim.js"}}"#,
        )
        .unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside_html, ext_dir.join("popup.html")).unwrap();

        patch_unpacked_extension_for_agent(&ext_dir, "evil-ext", None);
        assert_eq!(
            std::fs::read_to_string(&outside_html).unwrap(),
            "<html><head></head><body>clean</body></html>",
            "symlinked HTML outside ext_dir MUST NOT be modified"
        );
        assert_eq!(
            std::fs::read_to_string(&outside_js).unwrap(),
            "console.log('clean');",
            "service_worker traversal outside ext_dir MUST NOT be modified"
        );

        // Build a minimal valid extension zip and pass traversal preferred_id `../../outside_sensitive`
        let stage_zip_src = tmp.join("zip_src");
        std::fs::create_dir_all(&stage_zip_src).unwrap();
        std::fs::write(
            stage_zip_src.join("manifest.json"),
            r#"{"manifest_version":3,"name":"SafeZip","version":"1.0"}"#,
        )
        .unwrap();
        let zip_file = tmp.join("safe.zip");
        Command::new("/usr/bin/zip")
            .current_dir(&stage_zip_src)
            .args(["-q", "-r", &zip_file.to_string_lossy(), "."])
            .status()
            .unwrap();
        let zip_bytes = std::fs::read(&zip_file).unwrap();
        let installed = install_extension_from_bytes_cancellable_in(
            &tmp,
            &zip_bytes,
            Some("../../outside_sensitive"),
            "local",
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
        assert!(
            outside_html.is_file(),
            "unsafe preferred_id MUST NOT delete directories outside extensions/"
        );
        assert!(Path::new(&installed.folder_path).starts_with(tmp.join("extensions")));

        // --- Finding 3: Stopping a profile while `ensure_launched` is mid-flight MUST cancel it ---
        let cdp_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let cdp_p = cdp_l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for _ in 0..8 {
                if let Ok((mut s, _)) = cdp_l.accept() {
                    let mut b = [0u8; 256];
                    let _ = s.read(&mut b);
                    let body = r#"[{"type":"page","url":"https://example.com"}]"#;
                    let _ = s.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    );
                }
            }
        });
        let slow_kernel = tmp.join("slow_chromium.sh");
        std::fs::write(
            &slow_kernel,
            format!(
                "#!/bin/sh\n\
                 udd=\"\"\n\
                 for arg in \"$@\"; do\n\
                   case \"$arg\" in --user-data-dir=*) udd=\"${{arg#--user-data-dir=}}\" ;; esac\n\
                 done\n\
                 sleep 0.18\n\
                 printf \"{cdp_p}\\n/devtools/browser/slow\\n\" > \"$udd/DevToolsActivePort\"\n\
                 exec sleep 30\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&slow_kernel, std::fs::Permissions::from_mode(0o755)).unwrap();

        let sup = RuntimeSupervisor::new_with_kernel_in(&tmp, &slow_kernel);
        let mut cancel_prof = Profile::new_default("CancelMidFlight", PlatformType::MacOS);
        cancel_prof.custom_timezone = Some("UTC".to_string());
        ws.upsert_profile(&cancel_prof).unwrap();
        let db_arc = Arc::new(Mutex::new(ws));

        let sup_launch = sup.clone();
        let db_launch = db_arc.clone();
        let prof_launch = cancel_prof.clone();
        let launch_jh = tokio::spawn(async move {
            sup_launch.ensure_launched(&db_launch, &prof_launch).await
        });
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            sup.stop(&cancel_prof.id, &cancel_prof.short_id()),
            "stop() during in-flight launch should report cancellation"
        );
        let launch_out = launch_jh.await.unwrap();
        assert!(
            launch_out.is_err(),
            "in-flight launch stopped mid-way must return Err, got: {launch_out:?}"
        );
        assert!(!sup.contains_owned(&cancel_prof.id));

        // --- Finding 4: `stop_external_runtime_in` keeps `bon_runtime.json` until SIGTERM finishes ---
        let ext_prof = Profile::new_default("SlowExitExt", PlatformType::MacOS);
        let ext_pdir = profile_user_data_dir_in(&tmp, &ext_prof.id).unwrap();
        let mut slow_exit_child = Command::new("/bin/sh")
            .args(["-c", "trap 'sleep 0.16; exit 0' TERM; while :; do sleep 0.05; done"])
            .spawn()
            .unwrap();
        let closed_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_p = closed_l.local_addr().unwrap().port();
        drop(closed_l);
        let rt_path = runtime_file_path_in(&tmp, &ext_prof.id);
        std::fs::write(
            &rt_path,
            serde_json::to_string(&RuntimeInfo {
                pid: slow_exit_child.id(),
                cdp_port: closed_p,
                ws_url: format!("ws://127.0.0.1:{closed_p}/devtools/browser/ext"),
                local_proxy_port: None,
            })
            .unwrap(),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(30));
        let tmp_stop = tmp.clone();
        let ext_id = ext_prof.id.clone();
        let ext_sid = ext_prof.short_id();
        let stop_thread =
            std::thread::spawn(move || stop_external_runtime_in(&tmp_stop, &ext_id, &ext_sid));
        std::thread::sleep(Duration::from_millis(40));
        assert!(
            rt_path.is_file(),
            "bon_runtime.json must stay present while external Chromium PID is still shutting down"
        );
        assert!(stop_thread.join().unwrap());
        let _ = slow_exit_child.wait();
        assert!(!rt_path.exists());
        let _ = ext_pdir;

        // --- Finding 6 & 7: CdpClient 32 MiB frame cap + Workspace-scoped screenshot ---
        let ws_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ws_p = ws_l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            // 1. /json/list
            let (mut s1, _) = ws_l.accept().unwrap();
            let mut b1 = [0u8; 512];
            let _ = s1.read(&mut b1);
            let list = format!(
                r#"[{{"id":"t1","type":"page","url":"https://example.com","webSocketDebuggerUrl":"ws://127.0.0.1:{ws_p}/devtools/page/t1"}}]"#
            );
            s1.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{list}", list.len())
                    .as_bytes(),
            )
            .unwrap();
            drop(s1);

            // 2. WebSocket sends oversized 64 MiB frame header
            let (mut s2, _) = ws_l.accept().unwrap();
            let mut hs = [0u8; 1024];
            let _ = s2.read(&mut hs);
            s2.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            )
            .unwrap();
            let mut req_buf = [0u8; 512];
            let _ = s2.read(&mut req_buf);
            let mut hdr = vec![0x81u8, 127];
            hdr.extend_from_slice(&(64u64 * 1024 * 1024).to_be_bytes());
            let _ = s2.write_all(&hdr);
        });
        let big_err = cdp_navigate_page(ws_p, "https://example.com")
            .unwrap_err()
            .to_string();
        assert!(
            big_err.contains("exceeds maximum"),
            "expected frame size cap error, got: {big_err}"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_ponytail_round2_stop_restart_icon_symlink_cli_atomic_and_http_framing() {
        use std::io::{Read, Write};
        use std::os::unix::fs::PermissionsExt;
        use std::sync::{Arc, Mutex};

        let tmp = std::env::temp_dir().join(format!(
            "bonlogin-ponytail-r2-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let db = Arc::new(Mutex::new(crate::db::Workspace::open_at(&tmp).unwrap()));

        // --- Finding 4: Zip symlink strip + load_extension_icon_bytes path-traversal guard ---
        let outside_secret = tmp.join("outside_secret.png");
        std::fs::write(&outside_secret, b"SECRET_ICON_BYTES").unwrap();
        let zip_src = tmp.join("evil_ext_src");
        std::fs::create_dir_all(&zip_src).unwrap();
        std::fs::write(
            zip_src.join("manifest.json"),
            r#"{"manifest_version":3,"name":"EvilIconExt","version":"1.0.0","icons":{"128":"../../outside_secret.png"}}"#,
        )
        .unwrap();
        let evil_zip = tmp.join("evil_ext.zip");
        let z_ok = Command::new("/usr/bin/zip")
            .current_dir(&zip_src)
            .args(["-q", "-r", &evil_zip.to_string_lossy(), "."])
            .status()
            .unwrap();
        assert!(z_ok.success());
        let zip_bytes = std::fs::read(&evil_zip).unwrap();
        let installed = install_extension_from_bytes_cancellable_in(
            &tmp,
            &zip_bytes,
            Some("evil_icon_ext"),
            "local://evil.zip",
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
        assert!(
            crate::extensions::load_extension_icon_bytes(&installed).is_none(),
            "load_extension_icon_bytes must reject ../../ traversal outside extension folder"
        );
        let unpacked_dir = PathBuf::from(&installed.folder_path);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside_secret, unpacked_dir.join("sym_icon.png")).unwrap();
            std::fs::write(
                unpacked_dir.join("manifest.json"),
                r#"{"manifest_version":3,"name":"EvilIconExt","version":"1.0.0","icons":{"128":"sym_icon.png"}}"#,
            )
            .unwrap();
            assert!(
                crate::extensions::load_extension_icon_bytes(&installed).is_none(),
                "load_extension_icon_bytes must reject symlink icons pointing outside extension folder"
            );
        }

        // --- Finding 3: CLI flag parsing must not write cookies/bookmarks if a later flag fails ---
        let mut cli_prof = Profile::new_default("AtomicCliProf", PlatformType::MacOS);
        let bad_flags = vec![
            "--cookies".to_string(),
            "sid_atomic=should_not_persist".to_string(),
            "--url".to_string(),
            "https://leak.example".to_string(),
            "--bookmarks".to_string(),
            "Leak|https://leak.example".to_string(),
            "--proxy".to_string(),
            "NonExistentProxyName".to_string(),
        ];
        assert!(parse_profile_cli_flags(&mut cli_prof, &[], &bad_flags).is_err());
        assert!(
            read_prelaunch_cookies_in(&tmp, &cli_prof.short_id()).is_empty(),
            "failed CLI flag batch must not leave partial prelaunch cookies on disk"
        );
        assert!(
            read_profile_bookmarks_in(&tmp, &cli_prof).is_empty(),
            "failed CLI flag batch must not leave partial bookmarks on disk"
        );
        // Valid flag batch saved via save_profile_bundle preserves cookies when --cookies is omitted later
        let ok_flags = vec![
            "--cookies".to_string(),
            "sid_atomic=persisted_ok".to_string(),
            "--url".to_string(),
            "https://shop.example".to_string(),
            "--bookmarks".to_string(),
            "Shop|https://shop.example".to_string(),
        ];
        let parsed_ok = parse_profile_cli_flags(&mut cli_prof, &[], &ok_flags).unwrap();
        db.lock()
            .unwrap()
            .save_profile_bundle(
                &cli_prof,
                parsed_ok.cookies_raw.as_deref(),
                parsed_ok.bookmarks.as_deref(),
            )
            .unwrap();
        let note_only_flags = vec!["--notes".to_string(), "KeepCookies".to_string()];
        let parsed_note = parse_profile_cli_flags(&mut cli_prof, &[], &note_only_flags).unwrap();
        assert!(parsed_note.cookies_raw.is_none());
        db.lock()
            .unwrap()
            .save_profile_bundle(
                &cli_prof,
                parsed_note.cookies_raw.as_deref(),
                parsed_note.bookmarks.as_deref(),
            )
            .unwrap();
        assert!(
            read_prelaunch_cookies_in(&tmp, &cli_prof.short_id()).contains("persisted_ok"),
            "updating --notes without --cookies must preserve existing prelaunch cookies"
        );

        // --- Finding 6: HTTP Content-Length > 65536 -> 413, truncated body -> 400 ---
        let sup = RuntimeSupervisor::new_in(&tmp);
        let engine = crate::control::ControlEngine::attached(db.clone(), sup, Arc::new(|| {}));
        let std_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        std_l.set_nonblocking(true).unwrap();
        let http_port = std_l.local_addr().unwrap().port();
        let tk_l = tokio::net::TcpListener::from_std(std_l).unwrap();
        let srv = tokio::spawn(async move {
            let _ = crate::control::serve_control_http_with_engine(tk_l, engine).await;
        });
        let send_raw = |raw: &str| -> String {
            let mut s = std::net::TcpStream::connect(("127.0.0.1", http_port)).unwrap();
            s.write_all(raw.as_bytes()).unwrap();
            let _ = s.shutdown(std::net::Shutdown::Write);
            let mut out = String::new();
            let _ = s.read_to_string(&mut out);
            out
        };
        let resp_413 = send_raw(
            "POST /profiles/any/type HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100000\r\n\r\nhi",
        );
        assert!(
            resp_413.starts_with("HTTP/1.1 413"),
            "oversized Content-Length must return 413, got: {resp_413}"
        );
        let resp_400 = send_raw(
            "POST /profiles/any/type HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 500\r\n\r\nshort",
        );
        assert!(
            resp_400.starts_with("HTTP/1.1 400"),
            "truncated HTTP body must return 400, got: {resp_400}"
        );
        srv.abort();

        // --- Finding 1: Stop-then-Start serializes cleanly + stop_all() cancels in-flight ---
        let cdp_mock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let cdp_port = cdp_mock.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in cdp_mock.incoming().flatten() {
                let mut s = s;
                let mut b = [0u8; 512];
                let _ = s.read(&mut b);
                let body = r#"[{"id":"p1","type":"page","url":"https://example.com"}]"#;
                let _ = s.write_all(
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len())
                        .as_bytes(),
                );
            }
        });
        let fake_kernel = tmp.join("fake_chromium_r2.sh");
        let script = format!(
            "#!/bin/sh\nfor arg in \"$@\"; do\n  case \"$arg\" in\n    --user-data-dir=*) dir=\"${{arg#--user-data-dir=}}\" ;;\n  esac\ndone\nsleep 0.25\nprintf '%s\\n/devtools/browser/r2\\n' '{cdp_port}' > \"$dir/DevToolsActivePort\"\nexec sleep 30\n"
        );
        std::fs::write(&fake_kernel, script).unwrap();
        std::fs::set_permissions(&fake_kernel, std::fs::Permissions::from_mode(0o755)).unwrap();

        let sup_race = RuntimeSupervisor::new_with_kernel_in(&tmp, &fake_kernel);
        let race_prof = Profile::new_default("StopThenStart", PlatformType::MacOS);
        db.lock().unwrap().upsert_profile(&race_prof).unwrap();

        let sup1 = sup_race.clone();
        let db1 = db.clone();
        let p1 = race_prof.clone();
        let h1 = tokio::spawn(async move { sup1.ensure_launched(&db1, &p1).await });
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(sup_race.stop(&race_prof.id, &race_prof.short_id()));

        // Immediately re-launch while h1 is still finishing its 250ms startup + teardown!
        let sup2 = sup_race.clone();
        let db2 = db.clone();
        let p2 = race_prof.clone();
        let h2 = tokio::spawn(async move { sup2.ensure_launched(&db2, &p2).await });

        let r1 = h1.await.unwrap();
        assert!(r1.is_err(), "first cancelled launch must fail");
        let r2 = h2
            .await
            .unwrap()
            .expect("immediate restart after stop must wait for teardown and succeed");
        assert!(unix_pid_alive(r2.pid));
        assert!(sup_race.contains_owned(&race_prof.id));
        assert!(sup_race.stop(&race_prof.id, &race_prof.short_id()));

        // Also verify stop_all() cancels an in-flight launch before it finishes
        let sup3 = sup_race.clone();
        let db3 = db.clone();
        let p3 = race_prof.clone();
        let h3 = tokio::spawn(async move { sup3.ensure_launched(&db3, &p3).await });
        tokio::time::sleep(Duration::from_millis(60)).await;
        sup_race.stop_all();
        assert!(
            h3.await.unwrap().is_err(),
            "stop_all() must cancel in-flight launches"
        );
        assert!(!sup_race.contains_owned(&race_prof.id));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_ponytail_round3_json_import_proxy_expire_corrupt_flow_and_from_step() {
        let tmp = std::env::temp_dir().join(format!(
            "bonlogin-ponytail-r3-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let db = crate::db::Workspace::open_at(&tmp).unwrap();

        // --- Finding 1: import_profiles_json must sanitize path-traversal IDs and dedup duplicate IDs ---
        let mut p_trav = Profile::new_default("TraversalJson", PlatformType::MacOS);
        p_trav.id = "../../outside_victim".to_string();
        let mut p_dup1 = Profile::new_default("DupOne", PlatformType::MacOS);
        p_dup1.id = "11111111-1111-4111-8111-111111111111".to_string();
        let mut p_dup2 = Profile::new_default("DupTwo", PlatformType::Windows);
        p_dup2.id = "11111111-1111-4111-8111-111111111111".to_string();
        let raw_json = serde_json::to_string(&vec![p_trav, p_dup1, p_dup2]).unwrap();
        let imported_n = db.import_profiles_json(&raw_json).unwrap();
        assert_eq!(imported_n, 3);
        let all = db.list_profiles().unwrap();
        assert_eq!(
            all.len(),
            3,
            "duplicate IDs inside imported JSON array must get fresh UUIDs instead of overwriting"
        );
        for prof in &all {
            assert!(
                uuid::Uuid::parse_str(&prof.id).is_ok(),
                "imported profile ID '{}' must be a valid UUID",
                prof.id
            );
        }
        assert!(
            wipe_profile_data_in(&tmp, "../../outside_victim").is_err(),
            "wipe_profile_data_in must reject traversal profile_id"
        );

        // --- Finding 2: SavedProxy::parse_expiration_strict rejects typos instead of clearing ---
        assert!(SavedProxy::parse_expiration_strict("2027/05/01").is_err());
        assert!(SavedProxy::parse_expiration_strict("31/02/2027").is_err());
        assert_eq!(SavedProxy::parse_expiration_strict("clear"), Ok(None));
        assert_eq!(SavedProxy::parse_expiration_strict(""), Ok(None));
        assert!(SavedProxy::parse_expiration_strict("30d").unwrap().is_some());

        // --- Finding 3: Corrupt flow JSON must not be overwritten by append_steps_to_flow_path ---
        let corrupt_path = db.flow_file_path("corrupt_flow").unwrap();
        let corrupt_raw = "{\"name\":\"corrupt_flow\",\"steps\":[TRAILING_BROKEN_JSON";
        std::fs::write(&corrupt_path, corrupt_raw).unwrap();
        append_steps_to_flow_path(
            &corrupt_path,
            "corrupt_flow",
            &[FlowStep {
                op: "open".to_string(),
                locators: vec![],
                value: Some("https://example.com".to_string()),
                extra_args: vec![],
                optional: false,
            }],
        );
        assert_eq!(
            std::fs::read_to_string(&corrupt_path).unwrap(),
            corrupt_raw,
            "recording must not overwrite a hand-edited flow file that has a JSON syntax error"
        );

        // --- Finding 4: replay_flow_steps_with_in must reject out-of-range --from-step ---
        let ok_flow_path = db.flow_file_path("two_steps").unwrap();
        let mut two_flow = AgentFlow {
            name: "two_steps".to_string(),
            domain: "example.com".to_string(),
            updated_at: 1,
            steps: vec![
                FlowStep {
                    op: "open".to_string(),
                    locators: vec![],
                    value: Some("https://example.com".to_string()),
                    extra_args: vec![],
                    optional: false,
                },
                FlowStep {
                    op: "click".to_string(),
                    locators: vec!["#go".to_string()],
                    value: None,
                    extra_args: vec![],
                    optional: false,
                },
            ],
        };
        save_flow_to_path(&ok_flow_path, &mut two_flow).unwrap();
        struct NoopSession;
        impl AgentSession for NoopSession {
            fn exec(&mut self, _args: &[String]) -> std::result::Result<String, String> {
                Ok("ok".to_string())
            }
        }
        let mut noop = NoopSession;
        assert!(
            replay_flow_steps_with_in(
                &tmp,
                "two_steps",
                &all[0],
                &std::collections::HashMap::new(),
                99,
                &mut noop,
            )
            .is_err(),
            "from_step > flow.steps.len() must return Err instead of succeeding with 0 steps"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_multi_profile_synchronizer_scales_and_mirrors_events() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        assert_eq!(scale_sync_point(500, 400, 1000, 800, 1920, 1080), (960, 540));
        assert_eq!(scale_sync_point(-10, 9999, 1000, 800, 1280, 720), (0, 720));

        fn spawn_mock_cdp(is_master: bool) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let log_cl = log.clone();
            std::thread::spawn(move || {
                let mut poll_count = 0usize;
                for stream in listener.incoming().flatten() {
                    let mut s = stream;
                    let mut buf = [0u8; 1024];
                    let n = s.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    if req.starts_with("GET /json/list") {
                        let body = format!(
                            r#"[{{"id":"f1","type":"page","url":"https://example.com","webSocketDebuggerUrl":"ws://127.0.0.1:{port}/devtools/page/f1"}}]"#
                        );
                        let _ = s.write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                                body.len()
                            )
                            .as_bytes(),
                        );
                    } else if req.contains("Upgrade: websocket") {
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
                            let method = msg["method"].as_str().unwrap_or("").to_string();
                            log_cl.lock().unwrap().push(method.clone());
                            let reply = if method == "Page.createIsolatedWorld" {
                                serde_json::json!({"id": id, "result": {"executionContextId": 77}})
                            } else if method == "Runtime.evaluate" {
                                let val_str = if is_master {
                                    poll_count += 1;
                                    if poll_count == 1 {
                                        r#"{"url":"https://example.com/a","vw":1000,"vh":800,"events":[{"k":"mouse","sub":"down","x":500,"y":400,"vw":1000,"vh":800,"b":0,"c":1,"m":0},{"k":"key","sub":"down","key":"a","code":"KeyA","vk":65,"m":0}]}"#
                                    } else {
                                        r#"{"url":"https://example.com/b","vw":1000,"vh":800,"events":[]}"#
                                    }
                                } else {
                                    "[2000,1600]"
                                };
                                serde_json::json!({"id": id, "result": {"result": {"type": "string", "value": val_str}}})
                            } else {
                                serde_json::json!({"id": id, "result": {}})
                            };
                            let r_bytes = reply.to_string().into_bytes();
                            let mut frame = if r_bytes.len() < 126 {
                                vec![0x81, r_bytes.len() as u8]
                            } else {
                                let l = (r_bytes.len() as u16).to_be_bytes();
                                vec![0x81, 126, l[0], l[1]]
                            };
                            frame.extend_from_slice(&r_bytes);
                            if s.write_all(&frame).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
            (port, log)
        }

        let (m_port, m_log) = spawn_mock_cdp(true);
        let (f_port, f_log) = spawn_mock_cdp(false);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_bg = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(120));
            stop_bg.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let mirrored =
            run_multi_profile_synchronizer_loop(m_port, &[f_port], &stop, None).unwrap();
        assert!(mirrored >= 3, "expected mouse + key + url navigation mirrored, got {mirrored}");
        let master_methods = m_log.lock().unwrap().clone();
        let follower_methods = f_log.lock().unwrap().clone();
        assert!(!master_methods.iter().any(|m| m == "Runtime.enable"));
        assert!(!follower_methods.iter().any(|m| m == "Runtime.enable"));
        assert!(follower_methods.iter().any(|m| m == "Input.dispatchMouseEvent"));
        assert!(follower_methods.iter().any(|m| m == "Input.dispatchKeyEvent"));
        assert!(follower_methods.iter().any(|m| m == "Page.navigate"));
    }

    #[test]
    fn test_flow_csv_variables_and_preflight_card_generation() {
        let csv_raw = "profile,email,pass\nShop Beta,beta@example.com,\"p@ss,2\"\nShop Alpha,alpha@example.com,pass1\n";
        let rows = crate::flows::parse_flow_csv_rows(csv_raw).unwrap();
        assert_eq!(rows.len(), 2);

        let p_alpha = Profile::new_default("Shop Alpha", PlatformType::MacOS);
        let p_gamma = Profile::new_default("Shop Gamma", PlatformType::Windows);
        let mut base = std::collections::HashMap::new();
        base.insert("site".to_string(), "tiktok.com".to_string());

        // Matches by profile name ("Shop Alpha" is row index 1)
        let v_alpha = crate::flows::resolve_profile_csv_vars(&p_alpha, 0, &rows, &base);
        assert_eq!(v_alpha.get("email").map(String::as_str), Some("alpha@example.com"));
        assert_eq!(v_alpha.get("pass").map(String::as_str), Some("pass1"));
        assert_eq!(v_alpha.get("site").map(String::as_str), Some("tiktok.com"));

        // Falls back to index modulo row count when profile name isn't in CSV
        let v_gamma = crate::flows::resolve_profile_csv_vars(&p_gamma, 0, &rows, &base);
        assert_eq!(v_gamma.get("email").map(String::as_str), Some("beta@example.com"));
        assert_eq!(v_gamma.get("pass").map(String::as_str), Some("p@ss,2"));

        // Preflight card generation & bon://preflight startup URL resolution
        let tmp = std::env::temp_dir().join(format!(
            "bonlogin-preflight-test-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let mut pre_prof = Profile::new_default("Preflight <Test>", PlatformType::MacOS);
        pre_prof.startup_url = "bon://preflight".to_string();
        let udir = profile_user_data_dir_in(&tmp, &pre_prof.id).unwrap();
        let file_url = write_profile_preflight_card(&pre_prof, &udir, None);
        assert!(file_url.starts_with("file://") && file_url.ends_with("/bon_preflight.html"));
        let html = std::fs::read_to_string(udir.join("bon_preflight.html")).unwrap();
        assert!(html.contains("Preflight &lt;Test&gt;"));
        assert!(html.contains("disable_non_proxied_udp"));

        let args = build_chromium_args_with_extensions(&pre_prof, None, &udir, None, &[]);
        assert_eq!(args.last().map(String::as_str), Some(file_url.as_str()));

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
