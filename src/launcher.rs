use crate::models::{BrowserExtension, GeoInfo, Profile, RuntimeInfo, unix_now};
use anyhow::{Context, Result, anyhow, bail};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct KernelInfo {
    pub path: PathBuf,
    pub version_label: String,
    pub is_adryfish_bundle: bool,
}

pub fn app_support_dir() -> PathBuf {
    dirs::data_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join("Library/Application Support")))
        .unwrap_or_else(std::env::temp_dir)
        .join("com.bonlogin.app")
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
                    is_adryfish_bundle: true,
                });
            }
        }
    }

    let kernels_dir = app_support_dir().join("kernels");
    if kernels_dir.is_dir() {
        let direct_app = kernels_dir.join("Chromium.app/Contents/MacOS/Chromium");
        if direct_app.is_file() {
            return Some(KernelInfo {
                path: direct_app,
                version_label: "adryfish Chromium (Bundled)".to_string(),
                is_adryfish_bundle: true,
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
                        is_adryfish_bundle: true,
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
            is_adryfish_bundle: true,
        });
    }

    None
}

/// Discovers enabled unpacked Chrome extensions inside `~/Library/Application Support/com.bonlogin.app/extensions/*`.
pub fn discover_unpacked_extensions() -> Vec<PathBuf> {
    if let Ok(db) = crate::db::Database::open_fast()
        && let Ok(exts) = db.list_extensions()
    {
        let mut enabled_paths = Vec::new();
        for ext in exts.into_iter().filter(|e| e.enabled) {
            if let Ok(p) = ensure_extension_unpacked(&ext)
                && p.join("manifest.json").is_file()
            {
                enabled_paths.push(p);
            }
        }
        return enabled_paths;
    }

    let ext_dir = app_support_dir().join("extensions");
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir(ext_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() && p.join("manifest.json").is_file() {
                found.push(p);
            }
        }
    }
    found.sort();
    found
}

/// Strips the `Cr24` binary header from a Chrome `.crx` (CRX2 or CRX3) archive to expose its inner `.zip` payload.
pub fn strip_crx_header(bytes: &[u8]) -> Result<&[u8]> {
    if bytes.starts_with(b"PK\x03\x04") {
        return Ok(bytes);
    }
    if bytes.starts_with(b"Cr24") && bytes.len() >= 12 {
        let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if version == 2 && bytes.len() >= 16 {
            let pub_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
            let sig_len = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
            let offset = 16usize.saturating_add(pub_len).saturating_add(sig_len);
            if offset < bytes.len() && bytes[offset..].starts_with(b"PK\x03\x04") {
                return Ok(&bytes[offset..]);
            }
        } else if version == 3 {
            let header_len =
                u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
            let offset = 12usize.saturating_add(header_len);
            if offset < bytes.len() && bytes[offset..].starts_with(b"PK\x03\x04") {
                return Ok(&bytes[offset..]);
            }
        }
    }
    if let Some(pos) = bytes.windows(4).position(|w| w == b"PK\x03\x04") {
        return Ok(&bytes[pos..]);
    }
    bail!("File is neither a valid .CRX nor a .ZIP archive")
}

fn read_extension_name_from_dir(dir: &Path, fallback: &str) -> String {
    let manifest_path = dir.join("manifest.json");
    let Ok(raw) = std::fs::read_to_string(&manifest_path) else {
        return fallback.to_string();
    };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return fallback.to_string();
    };
    let Some(name_str) = val.get("name").and_then(|v| v.as_str()) else {
        return fallback.to_string();
    };
    if let Some(msg_key) = name_str
        .strip_prefix("__MSG_")
        .and_then(|s| s.strip_suffix("__"))
    {
        let default_locale = val
            .get("default_locale")
            .and_then(|v| v.as_str())
            .unwrap_or("en");
        for loc in [default_locale, "en", "en_US", "en_GB"] {
            let msg_path = dir
                .join("_locales")
                .join(loc)
                .join("messages.json");
            if let Ok(msg_raw) = std::fs::read_to_string(&msg_path)
                && let Ok(msg_json) = serde_json::from_str::<serde_json::Value>(&msg_raw)
                && let Some( obj) = msg_json.as_object()
            {
                for (k, v) in obj {
                    if k.eq_ignore_ascii_case(msg_key)
                        && let Some(resolved) = v.get("message").and_then(|m| m.as_str())
                        && !resolved.trim().is_empty()
                    {
                        return resolved.trim().to_string();
                    }
                }
            }
        }
    }
    name_str.trim().to_string()
}

/// Loads raw icon bytes `(is_svg, bytes)` for an extension from bundled assets or unpacked `manifest.json`.
pub fn load_extension_icon_bytes(ext: &BrowserExtension) -> Option<(bool, Vec<u8>)> {
    match ext.id.as_str() {
        "ublock-origin-lite" => {
            return Some((
                false,
                include_bytes!("../assets/extensions/ublock-origin-lite.png").to_vec(),
            ));
        }
        "authenticator-2fa" => {
            return Some((
                false,
                include_bytes!("../assets/extensions/authenticator-2fa.png").to_vec(),
            ));
        }
        "cookie-editor" => {
            return Some((
                false,
                include_bytes!("../assets/extensions/cookie-editor.png").to_vec(),
            ));
        }
        "bitwarden" => {
            return Some((
                false,
                include_bytes!("../assets/extensions/bitwarden.png").to_vec(),
            ));
        }
        "violentmonkey" => {
            return Some((
                false,
                include_bytes!("../assets/extensions/violentmonkey.png").to_vec(),
            ));
        }
        "capsolver" => {
            return Some((
                false,
                include_bytes!("../assets/extensions/capsolver.png").to_vec(),
            ));
        }
        "simple-translate" => {
            return Some((
                false,
                include_bytes!("../assets/extensions/simple-translate.png").to_vec(),
            ));
        }
        "metamask" => {
            return Some((
                false,
                include_bytes!("../assets/extensions/metamask.png").to_vec(),
            ));
        }
        "rabby-wallet" => {
            return Some((
                false,
                include_bytes!("../assets/extensions/rabby-wallet.png").to_vec(),
            ));
        }
        "phantom" => {
            return Some((
                false,
                include_bytes!("../assets/extensions/phantom.png").to_vec(),
            ));
        }
        "okx-wallet" => {
            return Some((
                false,
                include_bytes!("../assets/extensions/okx-wallet.png").to_vec(),
            ));
        }
        "cookie-token-grabber" => {
            return Some((
                true,
                include_bytes!("../assets/extensions/cookie-token-grabber.svg").to_vec(),
            ));
        }
        "ip-status-badge" => {
            return Some((
                true,
                include_bytes!("../assets/extensions/ip-status-badge.svg").to_vec(),
            ));
        }
        "coordinates" => {
            return Some((
                true,
                include_bytes!("../assets/extensions/coordinates.svg").to_vec(),
            ));
        }
        _ => {}
    }

    let ext_dir = if !ext.folder_path.trim().is_empty() {
        PathBuf::from(ext.folder_path.trim())
    } else {
        app_support_dir().join("extensions").join(&ext.id)
    };
    let manifest_path = ext_dir.join("manifest.json");
    let raw = std::fs::read_to_string(&manifest_path).ok()?;
    let val: serde_json::Value = serde_json::from_str(&raw).ok()?;

    let icon_node = val
        .get("icons")
        .or_else(|| val.get("action").and_then(|a| a.get("default_icon")))
        .or_else(|| val.get("browser_action").and_then(|a| a.get("default_icon")))?;

    let rel_path = if let Some(s) = icon_node.as_str() {
        Some(s.to_string())
    } else if let Some(obj) = icon_node.as_object() {
        obj.iter()
            .max_by_key(|(k, _)| k.parse::<u32>().unwrap_or(0))
            .and_then(|(_, v)| v.as_str().map(ToString::to_string))
    } else {
        None
    }?;

    let icon_file = ext_dir.join(rel_path.trim_start_matches('/'));
    let bytes = std::fs::read(&icon_file).ok()?;
    let is_svg = icon_file
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("svg"));
    Some((is_svg, bytes))
}

fn flatten_single_nested_manifest_dir(target_dir: &Path) {
    if target_dir.join("manifest.json").is_file() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(target_dir) else {
        return;
    };
    let subdirs: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| !n.starts_with("__MACOSX") && !n.starts_with('.'))
        })
        .collect();
    if subdirs.len() == 1 && subdirs[0].join("manifest.json").is_file() {
        let sub = &subdirs[0];
        if let Ok(inner) = std::fs::read_dir(sub) {
            for item in inner.flatten() {
                let dest = target_dir.join(item.file_name());
                let _ = std::fs::rename(item.path(), dest);
            }
        }
        let _ = std::fs::remove_dir_all(sub);
    }
}

fn pick_icon_badge(name: &str) -> (String, u32) {
    let ch: String = name
        .chars()
        .filter(|c| c.is_alphanumeric())
        .take(2)
        .collect();
    let label = if ch.is_empty() {
        "🧩".to_string()
    } else {
        ch.to_uppercase()
    };
    let palette = [0x3B82F6, 0x10B981, 0xEA580C, 0x7E22CE, 0x0284C7, 0xD97706];
    let hash = name.bytes().fold(0usize, |acc, b| acc.wrapping_add(b as usize));
    (label, palette[hash % palette.len()])
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else {
            std::fs::copy(entry.path(), dest_path)?;
        }
    }
    Ok(())
}

/// Installs a `.zip`, `.crx`, or unpacked folder into `~/Library/Application Support/com.bonlogin.app/extensions/`.
pub fn install_extension_from_file(src_path: &Path) -> Result<BrowserExtension> {
    if !src_path.exists() {
        bail!("File not found: {}", src_path.display());
    }
    let stem = src_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("custom-ext")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c.to_ascii_lowercase() } else { '-' })
        .collect::<String>();
    let ext_id = if stem.trim_matches('-').is_empty() {
        format!("ext-{}", unix_now())
    } else {
        stem.trim_matches('-').to_string()
    };

    if src_path.is_dir() {
        if !src_path.join("manifest.json").is_file() {
            bail!("Directory does not contain a manifest.json file");
        }
        let dest_dir = app_support_dir().join("extensions").join(&ext_id);
        if dest_dir.exists() {
            let _ = std::fs::remove_dir_all(&dest_dir);
        }
        copy_dir_recursive(src_path, &dest_dir)?;
        let name = read_extension_name_from_dir(&dest_dir, &ext_id);
        let (icon_label, icon_bg) = pick_icon_badge(&name);
        return Ok(BrowserExtension {
            id: ext_id,
            name,
            icon_label,
            icon_bg,
            is_default: false,
            enabled: true,
            source_url: src_path.to_string_lossy().into_owned(),
            folder_path: dest_dir.to_string_lossy().into_owned(),
            created_at: unix_now(),
        });
    }

    let raw_bytes = std::fs::read(src_path)
        .with_context(|| format!("Failed to read {}", src_path.display()))?;
    install_extension_from_bytes(&raw_bytes, Some(&ext_id), &src_path.to_string_lossy())
}

/// Extracts `.crx` or `.zip` bytes into `~/Library/Application Support/com.bonlogin.app/extensions/<id>`.
pub fn install_extension_from_bytes(
    raw_bytes: &[u8],
    preferred_id: Option<&str>,
    source_url: &str,
) -> Result<BrowserExtension> {
    let zip_bytes = strip_crx_header(raw_bytes)?;
    let ext_id = preferred_id
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("ext-{}", unix_now()));

    let ext_root = app_support_dir().join("extensions");
    std::fs::create_dir_all(&ext_root)?;
    let dest_dir = ext_root.join(&ext_id);
    if dest_dir.exists() {
        let _ = std::fs::remove_dir_all(&dest_dir);
    }
    std::fs::create_dir_all(&dest_dir)?;

    let tmp_zip = std::env::temp_dir().join(format!("bonlogin_{ext_id}.zip"));
    std::fs::write(&tmp_zip, zip_bytes)?;

    let status = Command::new("/usr/bin/unzip")
        .args([
            "-q",
            "-o",
            &tmp_zip.to_string_lossy(),
            "-d",
            &dest_dir.to_string_lossy(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = std::fs::remove_file(&tmp_zip);

    if !status.is_ok_and(|s| s.success()) {
        let _ = std::fs::remove_dir_all(&dest_dir);
        bail!("Failed to extract archive (must be a valid .CRX or .ZIP extension)");
    }

    flatten_single_nested_manifest_dir(&dest_dir);
    if !dest_dir.join("manifest.json").is_file() {
        let _ = std::fs::remove_dir_all(&dest_dir);
        bail!("Archive does not contain a Chrome extension manifest.json");
    }

    let name = read_extension_name_from_dir(&dest_dir, &ext_id);
    let (icon_label, icon_bg) = pick_icon_badge(&name);
    Ok(BrowserExtension {
        id: ext_id,
        name,
        icon_label,
        icon_bg,
        is_default: false,
        enabled: true,
        source_url: source_url.to_string(),
        folder_path: dest_dir.to_string_lossy().into_owned(),
        created_at: unix_now(),
    })
}

/// Downloads an extension from a Chrome Web Store URL, 32-char ID, or direct `.crx`/`.zip` URL.
pub async fn download_extension_from_url(url_or_id: &str) -> Result<BrowserExtension> {
    let trimmed = url_or_id.trim();
    if trimmed.is_empty() {
        bail!("Please enter a Chrome Web Store URL or Extension link");
    }

    let (download_url, preferred_id) =
        if let Some(store_id) = BrowserExtension::extract_chrome_store_id(trimmed) {
            let crx_url = format!(
                "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=134.0.0.0&acceptformat=crx2,crx3&x=id%3D{store_id}%26uc"
            );
            (crx_url, Some(store_id))
        } else if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            (trimmed.to_string(), None)
        } else {
            bail!("Invalid URL or Chrome Web Store ID: {trimmed}");
        };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
        .build()?;
    let resp = client
        .get(&download_url)
        .send()
        .await
        .with_context(|| format!("Failed to download from {download_url}"))?;
    if !resp.status().is_success() {
        bail!("Download returned HTTP {}", resp.status());
    }
    let bytes = resp.bytes().await?;
    if bytes.is_empty() {
        bail!("Downloaded empty response from store");
    }
    install_extension_from_bytes(&bytes, preferred_id.as_deref(), trimmed)
}

/// Ensures an enabled extension has a valid unpacked MV3 directory on disk in `extensions/<id>`.
pub fn ensure_extension_unpacked(ext: &BrowserExtension) -> Result<PathBuf> {
    let ext_dir = app_support_dir().join("extensions").join(&ext.id);
    if ext_dir.join("manifest.json").is_file() {
        return Ok(ext_dir);
    }
    std::fs::create_dir_all(&ext_dir)?;
    let clean_name = ext.name.replace('"', "'");
    let content_js = match ext.id.as_str() {
        "coordinates" => {
            r#"(() => {
  const b = document.createElement('div');
  b.style.cssText = 'position:fixed;bottom:8px;right:8px;z-index:2147483647;background:rgba(15,17,23,0.88);color:#60a5fa;padding:3px 8px;border-radius:4px;font:11px monospace;pointer-events:none;border:1px solid #3b82f6;';
  b.textContent = 'x: 0, y: 0';
  document.documentElement.appendChild(b);
  window.addEventListener('mousemove', e => { b.textContent = `x: ${e.clientX}, y: ${e.clientY}`; }, { passive: true });
})();"#
        }
        "cookie-token-grabber" => {
            r#"(() => {
  window.addEventListener('keydown', e => {
    if (e.altKey && e.shiftKey && e.code === 'KeyC') {
      const payload = JSON.stringify({ url: location.href, cookie: document.cookie, localStorage: { ...localStorage } }, null, 2);
      navigator.clipboard.writeText(payload);
    }
  });
})();"#
        }
        "ip-status-badge" => {
            r#"(() => {
  const b = document.createElement('div');
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  b.style.cssText = 'position:fixed;bottom:8px;left:8px;z-index:2147483647;background:rgba(15,17,23,0.88);color:#34d399;padding:3px 8px;border-radius:4px;font:11px monospace;cursor:pointer;border:1px solid #10b981;';
  b.textContent = `🌐 ${navigator.language} | ${tz}`;
  b.title = 'Click to hide';
  b.onclick = () => b.remove();
  document.documentElement.appendChild(b);
})();"#
        }
        "element-helper" => {
            r#"(() => {
  window.__bonElementHelper = true;
})();"#
        }
        _ => "// BonLogin Managed Extension\n",
    };
    let manifest = format!(
        r#"{{
  "manifest_version": 3,
  "name": "{clean_name}",
  "version": "1.0.0",
  "description": "{clean_name} managed by BonLogin",
  "content_scripts": [
    {{
      "matches": ["<all_urls>"],
      "js": ["content.js"],
      "run_at": "document_idle"
    }}
  ]
}}"#
    );
    std::fs::write(ext_dir.join("manifest.json"), manifest)?;
    std::fs::write(ext_dir.join("content.js"), content_js)?;
    Ok(ext_dir)
}

/// Removes an unpacked extension directory from disk.
pub fn remove_extension_files(ext_id: &str) {
    if ext_id.trim().is_empty() || ext_id.contains("..") || ext_id.contains('/') {
        return;
    }
    let dir = app_support_dir().join("extensions").join(ext_id);
    if dir.exists() {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Removes macOS Gatekeeper quarantine attributes (`com.apple.quarantine`) from the `.app` bundle once per session.
pub fn unquarantine_macos_app(binary_path: &Path) {
    #[cfg(target_os = "macos")]
    {
        use std::collections::HashSet;
        use std::sync::{LazyLock, Mutex};

        static UNQUARANTINED: LazyLock<Mutex<HashSet<PathBuf>>> =
            LazyLock::new(|| Mutex::new(HashSet::new()));
        let target = binary_path
            .ancestors()
            .find(|p| p.extension().and_then(|e| e.to_str()) == Some("app"))
            .unwrap_or(binary_path)
            .to_path_buf();

        if let Ok(mut set) = UNQUARANTINED.lock()
            && !set.insert(target.clone())
        {
            return;
        }
        let _ = Command::new("xattr")
            .args(["-cr", &target.to_string_lossy()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = binary_path;
    }
}
pub const ADRYFISH_MACOS_DMG_URL: &str = "https://github.com/adryfish/fingerprint-chromium/releases/download/148.0.7778.215/ungoogled-chromium_148.0.7778.215-1.1_macos.dmg";
pub const ADRYFISH_MACOS_VERSION_DIR: &str = "chromium-148.0.7778.215";

pub fn install_adryfish_kernel_blocking() -> Result<KernelInfo> {
    if let Some(existing) = locate_chromium_kernel() {
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

pub fn profile_user_data_dir(profile_id: &str) -> Result<PathBuf> {
    let dir = app_support_dir().join("profiles").join(profile_id);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create user-data-dir at {}", dir.display()))?;
    Ok(dir)
}

pub fn wipe_profile_data(profile_id: &str) -> Result<()> {
    let dir = app_support_dir().join("profiles").join(profile_id);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)
            .with_context(|| format!("Failed to wipe profile dir {}", dir.display()))?;
    }
    std::fs::create_dir_all(&dir)?;
    let short_id: String = profile_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(8)
        .collect();
    let states_dir = app_support_dir().join("states");
    let _ = std::fs::remove_file(states_dir.join(format!("bon_{short_id}_prelaunch.json")));
    let _ = std::fs::remove_file(states_dir.join(format!("bon_{short_id}_state.json")));
    Ok(())
}

pub fn read_prelaunch_cookies(short_id: &str) -> String {
    let path = app_support_dir()
        .join("states")
        .join(format!("bon_{short_id}_prelaunch.json"));
    std::fs::read_to_string(path).unwrap_or_default()
}

pub fn save_prelaunch_cookies(short_id: &str, raw: &str) -> Result<()> {
    let dir = app_support_dir().join("states");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("bon_{short_id}_prelaunch.json"));
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        let _ = std::fs::remove_file(path);
    } else {
        std::fs::write(path, trimmed)?;
    }
    Ok(())
}

/// Builds the exact `adryfish/fingerprint-chromium` + Patchright Stealth + WebRTC + DNS leak prevention flags.
pub fn build_chromium_args(
    profile: &Profile,
    local_proxy_port: Option<u16>,
    user_data_dir: &Path,
    effective_geo: Option<&GeoInfo>,
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

    let accept_lang = if let Some(custom_loc) = profile
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
        format!("--lang={locale}"),
        format!("--accept-lang={accept_lang}"),
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

    if let Some(port) = local_proxy_port {
        args.push(format!("--proxy-server=http://127.0.0.1:{port}"));
        args.push("--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1".to_string());
    }

    let exts = discover_unpacked_extensions();
    if !exts.is_empty() {
        let joined = exts
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(",");
        args.push(format!("--load-extension={joined}"));
    }

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

    let startup = profile.startup_url.trim();
    if !startup.is_empty() {
        args.push(startup.to_string());
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
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), cdp_port);
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(200)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
    let req = format!("GET /json/list HTTP/1.1\r\nHost: 127.0.0.1:{cdp_port}\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;

    // Chromium's net::HttpServer keeps sockets open; frame by Content-Length instead of waiting for EOF.
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 65536 {
            return None;
        }
    };

    let headers = std::str::from_utf8(&buf[..header_end]).ok()?;
    let content_len = headers
        .lines()
        .find_map(|line| {
            let (k, v) = line.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())
                .flatten()
        })?;

    while buf.len() < header_end + content_len {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    let body = std::str::from_utf8(buf.get(header_end..header_end + content_len)?).ok()?;
    let items: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    let arr = items.as_array()?;
    Some(arr.iter().any(|item| {
        item.get("type")
            .and_then(|t| t.as_str())
            .is_some_and(|t| matches!(t, "page" | "app" | "webview"))
    }))
}

pub struct RunningProcess {
    pub child: Child,
    pub info: RuntimeInfo,
    pub short_id: String,
    pub tunnel: Option<crate::proxy_tunnel::LocalProxyTunnel>,
    pub saw_window: bool,
    pub launched_at: std::time::Instant,
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
                true
            }
            Some(false) => !(self.saw_window || self.launched_at.elapsed() > Duration::from_secs(8)),
            None => true,
        }
    }

    pub fn stop_gracefully(&mut self) {
        if self.is_process_running() {
            #[cfg(unix)]
            {
                let pid = self.child.id().to_string();
                let _ = Command::new("kill")
                    .args(["-TERM", &pid])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }

            for _ in 0..40 {
                if let Ok(Some(_)) = self.child.try_wait() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        let _ = self.child.kill();
        let _ = self.child.wait();

        if let Some(mut tunnel) = self.tunnel.take() {
            tunnel.stop();
        }

        if !self.short_id.is_empty() {
            let session = format!("bon_{}", self.short_id);
            let _ = agent_browser_cmd()
                .args(["--session", &session, "close"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

pub async fn launch_profile(profile: &Profile) -> Result<(RunningProcess, Option<GeoInfo>)> {
    let kernel = locate_chromium_kernel().ok_or_else(|| {
        anyhow!(
            "adryfish/fingerprint-chromium binary not found. Click 'Download Kernel 148' \
             in the top bar or place Chromium.app in ~/Library/Application Support/com.bonlogin.app/kernels/."
        )
    })?;

    let (mut tunnel, newly_resolved_geo) = if let Some(proxy_cfg) = &profile.proxy {
        let mut tun = crate::proxy_tunnel::LocalProxyTunnel::start(proxy_cfg.clone()).await?;
        let port = tun.local_port();
        match crate::geoip::resolve_geo_via_port(Some(port)).await {
            Ok(geo) => (Some(tun), Some(geo)),
            Err(e) => {
                tun.stop();
                return Err(anyhow!("Proxy check failed (Fail-Closed): {e}"));
            }
        }
    } else if profile.custom_timezone.is_none() && profile.resolved_geo.is_none() {
        (None, crate::geoip::resolve_geo_via_port(None).await.ok())
    } else {
        (None, None)
    };

    let local_proxy_port = tunnel.as_ref().map(|t| t.local_port());
    let user_data_dir = match profile_user_data_dir(&profile.id) {
        Ok(dir) => dir,
        Err(e) => {
            if let Some(mut tun) = tunnel.take() {
                tun.stop();
            }
            return Err(e);
        }
    };

    let active_port_file = user_data_dir.join("DevToolsActivePort");
    let _ = std::fs::remove_file(&active_port_file);

    unquarantine_macos_app(&kernel.path);

    let args = build_chromium_args(
        profile,
        local_proxy_port,
        &user_data_dir,
        newly_resolved_geo.as_ref(),
    );

    let mut child = match Command::new(&kernel.path)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            if let Some(mut tun) = tunnel.take() {
                tun.stop();
            }
            return Err(anyhow!(
                "Failed to spawn Chromium at {}: {e}",
                kernel.path.display()
            ));
        }
    };

    let pid = child.id();
    let mut cdp_endpoint: Option<(u16, String)> = None;

    for _ in 0..50 {
        if let Ok(contents) = std::fs::read_to_string(&active_port_file)
            && let Ok(parsed) = parse_devtools_active_port(&contents)
        {
            cdp_endpoint = Some(parsed);
            break;
        }

        if let Ok(Some(status)) = child.try_wait() {
            if let Some(mut tun) = tunnel.take() {
                tun.stop();
            }
            bail!("Chromium exited early with status {status} before opening DevToolsActivePort");
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let (cdp_port, ws_url) = match cdp_endpoint {
        Some(v) => v,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            if let Some(mut tun) = tunnel.take() {
                tun.stop();
            }
            bail!(
                "Timed out (5s) waiting for DevToolsActivePort at {}",
                active_port_file.display()
            );
        }
    };


    let mut saw_window = false;
    for _ in 0..30 {
        if cdp_has_open_window(cdp_port) == Some(true) {
            saw_window = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let short_id = profile.short_id();
    let prelaunch_cookies = read_prelaunch_cookies(&short_id);
    let sid = short_id.clone();
    let ws_clone = ws_url.clone();
    if !prelaunch_cookies.trim().is_empty() {
        let _ = tokio::task::spawn_blocking(move || {
            let _ = agent_import_state_or_cookies(&sid, &ws_clone, &prelaunch_cookies);
        })
        .await;
    } else {
        tokio::task::spawn_blocking(move || {
            let _ = ensure_agent_browser_connected(&sid, &ws_clone);
        });
    }
    let info = RuntimeInfo {
        pid,
        cdp_port,
        ws_url,
        local_proxy_port,
    };

    Ok((
        RunningProcess {
            child,
            info,
            short_id,
            tunnel,
            saw_window,
            launched_at: std::time::Instant::now(),
        },
        newly_resolved_geo,
    ))
}

// ---------------------------------------------------------------------------
// Built-in `vercel-labs/agent-browser` Runner, Cookie Robot & State Manager
// ---------------------------------------------------------------------------

fn agent_browser_cmd() -> Command {
    if let Some(home) = dirs::home_dir() {
        let local_bin = home.join(".local/bin/agent-browser");
        if local_bin.is_file() {
            return Command::new(local_bin);
        }
    }
    let brew_bin = Path::new("/opt/homebrew/bin/agent-browser");
    if brew_bin.is_file() {
        return Command::new(brew_bin);
    }
    Command::new("agent-browser")
}

fn ensure_agent_browser_connected(short_id: &str, ws_url: &str) -> Result<String> {
    let session = format!("bon_{short_id}");
    let out = agent_browser_cmd()
        .args([
            "--session",
            &session,
            "--input-mode",
            "human",
            "connect",
            ws_url,
        ])
        .output()
        .context("Failed to execute `agent-browser`. Is `agent-browser` installed in PATH?")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("agent-browser connect failed: {}", stderr.trim());
    }
    Ok(session)
}
#[cfg(test)]
pub fn agent_audit_fingerprint(short_id: &str, ws_url: &str) -> Result<String> {
    let session = ensure_agent_browser_connected(short_id, ws_url)?;
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

pub fn agent_export_state(short_id: &str, ws_url: &str) -> Result<(PathBuf, String)> {
    let session = ensure_agent_browser_connected(short_id, ws_url)?;
    let dir = app_support_dir().join("states");
    std::fs::create_dir_all(&dir)?;
    let state_path = dir.join(format!("bon_{short_id}_state.json"));

    let out = agent_browser_cmd()
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

pub fn agent_import_state_or_cookies(
    short_id: &str,
    ws_url: &str,
    raw_payload: &str,
) -> Result<String> {
    let session = ensure_agent_browser_connected(short_id, ws_url)?;
    let dir = app_support_dir().join("states");
    std::fs::create_dir_all(&dir)?;

    let trimmed = raw_payload.trim();
    let file_path = if trimmed.is_empty() {
        let default_state = dir.join(format!("bon_{short_id}_state.json"));
        if !default_state.is_file() {
            bail!(
                "Paste JSON/cURL cookies into the input box first, or export a state file for bon_{short_id}"
            );
        }
        default_state
    } else {
        let tmp_file = dir.join(format!("bon_{short_id}_import.json"));
        std::fs::write(&tmp_file, trimmed)?;
        tmp_file
    };

    let content = std::fs::read_to_string(&file_path).unwrap_or_default();
    let is_full_state = content.contains("\"cookies\"") && content.contains("\"origins\"");

    let out = if is_full_state {
        agent_browser_cmd()
            .args([
                "--session",
                &session,
                "state",
                "load",
                &file_path.to_string_lossy(),
            ])
            .output()?
    } else {
        agent_browser_cmd()
            .args([
                "--session",
                &session,
                "cookies",
                "set",
                "--curl",
                &file_path.to_string_lossy(),
            ])
            .output()?
    };

    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if !out.status.success() {
        bail!("Import failed: {stderr} {stdout}");
    }
    Ok(if stdout.is_empty() {
        format!("Imported state/cookies from {}", file_path.display())
    } else {
        stdout
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{BrowserBrand, GpuSpoofMode, PlatformType};

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
        let args = build_chromium_args(&profile, None, &data_dir, None);

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
        let args = build_chromium_args(&profile, Some(58123), &data_dir, Some(&geo));

        assert!(args.contains(&"--fingerprint=123456".to_string()));
        assert!(args.contains(&"--fingerprint-platform=windows".to_string()));
        assert!(args.contains(&"--fingerprint-brand=Edge".to_string()));
        assert!(args.contains(&"--timezone=Asia/Ho_Chi_Minh".to_string()));
        assert!(!args.iter().any(|a| a.starts_with("--disable-spoofing=")));
        assert!(args.contains(&"--proxy-server=http://127.0.0.1:58123".to_string()));
        assert!(
            args.contains(&"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1".to_string())
        );
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
                let body = r#"[{"type":"service_worker"}]"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
                keep_alive.push(s);
            }
            std::thread::sleep(Duration::from_secs(1));
        });

        assert_eq!(cdp_has_open_window(port), Some(true));
        assert_eq!(cdp_has_open_window(port), Some(false));
    }

    #[tokio::test]
    async fn test_e2e_launch_adryfish_and_agent_browser_connect() {
        let Some(_kernel) = locate_chromium_kernel() else {
            return;
        };

        let mut profile = Profile::new_default("E2E Smoke Profile", PlatformType::MacOS);
        profile.seed = 777888;
        profile.hardware_concurrency = 12;
        profile.startup_url = "about:blank".to_string();
        let short_id = profile.short_id();

        let (mut running, _) = launch_profile(&profile)
            .await
            .expect("launch_profile should spawn adryfish Chromium and read DevToolsActivePort");

        assert!(running.info.cdp_port > 0);
        assert!(running.info.ws_url.starts_with("ws://127.0.0.1:"));
        assert!(running.is_alive());
        assert_eq!(cdp_has_open_window(running.info.cdp_port), Some(true));
        assert!(running.saw_window);

        let audit = agent_audit_fingerprint(&short_id, &running.info.ws_url)
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

        let (state_path, state_json) =
            agent_export_state(&short_id, &running.info.ws_url).expect("export state should work");
        assert!(state_path.is_file());
        assert!(state_json.contains("cookies"));

        running.stop_gracefully();
        assert!(!running.is_alive());

        let _ = wipe_profile_data(&profile.id);
        if let Ok(dir) = profile_user_data_dir(&profile.id) {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

}
