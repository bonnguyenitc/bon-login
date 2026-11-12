use crate::launcher::app_support_dir;
use crate::models::{BrowserExtension, unix_now};
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// Computes SHA-256 via macOS CommonCrypto for Chrome 32-char extension IDs (`a-p`).
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    unsafe extern "C" {
        fn CC_SHA256(data: *const core::ffi::c_void, len: u32, md: *mut u8) -> *mut u8;
    }
    let len_u32 = u32::try_from(data.len()).expect("sha256 input exceeds 4 GiB");
    let mut out = [0u8; 32];
    unsafe {
        let _ = CC_SHA256(data.as_ptr().cast(), len_u32, out.as_mut_ptr());
    }
    out
}

/// Converts a SubjectPublicKeyInfo DER byte slice into Chrome's 32-char extension ID (`a-p`).
pub fn pubkey_to_chrome_ext_id(spki_der: &[u8]) -> String {
    let digest = sha256_bytes(spki_der);
    let mut id = String::with_capacity(32);
    for &b in &digest[..16] {
        id.push((b'a' + (b >> 4)) as char);
        id.push((b'a' + (b & 0x0f)) as char);
    }
    id
}

/// Synthesizes a valid deterministic ASN.1 DER RSA-1024 SubjectPublicKeyInfo (`"key"`) for non-CRX extensions.
pub fn deterministic_spki_key_b64(seed_id: &str) -> String {
    use base64::Engine;
    const SPKI_PREFIX: [u8; 29] = [
        0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00,
    ];
    const SPKI_SUFFIX: [u8; 5] = [0x02, 0x03, 0x01, 0x00, 0x01];
    let mut der = Vec::with_capacity(162);
    der.extend_from_slice(&SPKI_PREFIX);
    for block in 0..4u8 {
        let mut input = seed_id.as_bytes().to_vec();
        input.push(b':');
        input.push(b'0' + block);
        let mut h = sha256_bytes(&input);
        if block == 0 {
            h[0] |= 0x80;
        }
        if block == 3 {
            h[31] |= 0x01;
        }
        der.extend_from_slice(&h);
    }
    der.extend_from_slice(&SPKI_SUFFIX);
    base64::engine::general_purpose::STANDARD.encode(&der)
}

fn read_proto_varint(buf: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut val = 0u64;
    let mut shift = 0u32;
    while pos < buf.len() {
        let b = buf[pos];
        pos += 1;
        val |= u64::from(b & 0x7f).checked_shl(shift)?;
        if (b & 0x80) == 0 {
            return Some((val, pos));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

/// Extracts the developer's RSA public key (base64) from a CRX2 or CRX3 header so unpacked extensions
/// retain their exact Chrome Web Store 32-char `chrome-extension://<id>` identity.
pub fn extract_crx_public_key_b64(bytes: &[u8], preferred_id: Option<&str>) -> Option<String> {
    use base64::Engine;
    if !bytes.starts_with(b"Cr24") || bytes.len() < 12 {
        return None;
    }
    let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version == 2 && bytes.len() >= 16 {
        let pub_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        let end = 16usize.saturating_add(pub_len);
        if pub_len > 0 && end <= bytes.len() {
            return Some(base64::engine::general_purpose::STANDARD.encode(&bytes[16..end]));
        }
        return None;
    }
    if version != 3 {
        return None;
    }
    let header_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    let header_end = 12usize.saturating_add(header_len);
    if header_end > bytes.len() {
        return None;
    }
    let header = &bytes[12..header_end];
    // Google Web Store's own CRX3 signing key ID (not the extension's developer key)
    const WEBSTORE_SIGNING_ID: &str = "lfoeajgcchlidpicbabpmckkejpckcfb";
    let mut pos = 0;
    let mut fallback_key: Option<String> = None;
    while pos < header.len() {
        let (tag, next_pos) = read_proto_varint(header, pos)?;
        pos = next_pos;
        let field_num = tag >> 3;
        let wire_type = tag & 7;
        match wire_type {
            0 => {
                let (_, next_p) = read_proto_varint(header, pos)?;
                pos = next_p;
            }
            2 => {
                let (len, next_p) = read_proto_varint(header, pos)?;
                let end_p = next_p.saturating_add(len as usize);
                if end_p > header.len() {
                    break;
                }
                let payload = &header[next_p..end_p];
                pos = end_p;
                if field_num == 2 || field_num == 3 {
                    let mut sub_pos = 0;
                    while sub_pos < payload.len() {
                        let Some((stag, snext)) = read_proto_varint(payload, sub_pos) else {
                            break;
                        };
                        sub_pos = snext;
                        let sfield = stag >> 3;
                        let swire = stag & 7;
                        if swire == 2 {
                            let Some((slen, sp)) = read_proto_varint(payload, sub_pos) else {
                                break;
                            };
                            let send = sp.saturating_add(slen as usize);
                            if send > payload.len() {
                                break;
                            }
                            if sfield == 1 {
                                let pub_bytes = &payload[sp..send];
                                let cid = pubkey_to_chrome_ext_id(pub_bytes);
                                let b64 =
                                    base64::engine::general_purpose::STANDARD.encode(pub_bytes);
                                if preferred_id.is_some_and(|want| want.eq_ignore_ascii_case(&cid))
                                {
                                    return Some(b64);
                                }
                                if field_num == 2 && cid != WEBSTORE_SIGNING_ID {
                                    fallback_key = Some(b64);
                                }
                            }
                            sub_pos = send;
                        } else if swire == 0 {
                            let Some((_, sp)) = read_proto_varint(payload, sub_pos) else {
                                break;
                            };
                            sub_pos = sp;
                        } else {
                            break;
                        }
                    }
                }
            }
            _ => break,
        }
    }
    fallback_key
}

const BON_EXT_SHIM_JS: &str = r#"/* __BON_EXT_SHIM__ */
;(() => {
  if (typeof globalThis.__bonExtShimInstalled !== 'undefined') return;
  globalThis.__bonExtShimInstalled = true;
  const ch = typeof chrome !== 'undefined' ? chrome : (typeof browser !== 'undefined' ? browser : null);
  if (!ch) return;

  if (ch.tabs && ch.tabs.query) {
    const origQuery = ch.tabs.query.bind(ch.tabs);
    const isSelfExtOnly = (tabs) =>
      Array.isArray(tabs) &&
      tabs.length === 1 &&
      tabs[0] &&
      typeof tabs[0].url === 'string' &&
      tabs[0].url.startsWith('chrome-extension://');

    ch.tabs.query = function(queryInfo, callback) {
      if (!queryInfo || !queryInfo.active) {
        return callback ? origQuery(queryInfo, callback) : origQuery(queryInfo);
      }
      if (callback) {
        return origQuery(queryInfo, (tabs) => {
          if (!isSelfExtOnly(tabs)) return callback(tabs);
          const allInfo = Object.assign({}, queryInfo);
          delete allInfo.active;
          origQuery(allInfo, (allTabs) => {
            const webTabs = (allTabs || []).filter(t => t && t.url && !t.url.startsWith('chrome-extension://') && !t.url.startsWith('devtools://'));
            if (webTabs.length > 0) {
              return callback([Object.assign({}, webTabs[webTabs.length - 1], { active: true })]);
            }
            callback(tabs);
          });
        });
      }
      return origQuery(queryInfo).then(async (tabs) => {
        if (!isSelfExtOnly(tabs)) return tabs;
        const allInfo = Object.assign({}, queryInfo);
        delete allInfo.active;
        const allTabs = await origQuery(allInfo);
        const webTabs = (allTabs || []).filter(t => t && t.url && !t.url.startsWith('chrome-extension://') && !t.url.startsWith('devtools://'));
        if (webTabs.length > 0) {
          return [Object.assign({}, webTabs[webTabs.length - 1], { active: true })];
        }
        return tabs;
      });
    };
  }

  const normalizeExtUrl = (u) => {
    if (!u || typeof u !== 'string') return null;
    if (u.startsWith('chrome-extension://')) return u;
    if (!u.includes('://') && u !== 'about:blank' && ch.runtime && ch.runtime.getURL) {
      return ch.runtime.getURL(u.replace(/^\//, ''));
    }
    return null;
  };

  if (ch.windows && ch.windows.create && ch.tabs && ch.tabs.update) {
    const origWinCreate = ch.windows.create.bind(ch.windows);
    const origTabUpdate = ch.tabs.update.bind(ch.tabs);
    ch.windows.create = function(createData, callback) {
      const rawUrl = createData && (Array.isArray(createData.url) ? createData.url[0] : createData.url);
      const extUrl = normalizeExtUrl(rawUrl);
      if (!extUrl) {
        return callback ? origWinCreate(createData, callback) : origWinCreate(createData);
      }
      const patched = Object.assign({}, createData, { url: 'about:blank' });
      if (callback) {
        return origWinCreate(patched, (win) => {
          const tabId = win && win.tabs && win.tabs[0] && win.tabs[0].id;
          if (tabId !== undefined) {
            setTimeout(() => origTabUpdate(tabId, { url: extUrl }, () => callback(win)), 40);
          } else {
            callback(win);
          }
        });
      }
      return origWinCreate(patched).then(async (win) => {
        const tabId = win && win.tabs && win.tabs[0] && win.tabs[0].id;
        if (tabId !== undefined) {
          await new Promise(r => setTimeout(r, 40));
          await origTabUpdate(tabId, { url: extUrl });
        }
        return win;
      });
    };
  }

  if (ch.tabs && ch.tabs.create && ch.tabs.update) {
    const origTabCreate = ch.tabs.create.bind(ch.tabs);
    const origTabUpdate = ch.tabs.update.bind(ch.tabs);
    ch.tabs.create = function(createProperties, callback) {
      const extUrl = normalizeExtUrl(createProperties && createProperties.url);
      if (!extUrl) {
        return callback ? origTabCreate(createProperties, callback) : origTabCreate(createProperties);
      }
      const patched = Object.assign({}, createProperties, { url: 'about:blank' });
      if (callback) {
        return origTabCreate(patched, (tab) => {
          if (tab && tab.id !== undefined) {
            setTimeout(() => origTabUpdate(tab.id, { url: extUrl }, (updated) => callback(updated || tab)), 40);
          } else {
            callback(tab);
          }
        });
      }
      return origTabCreate(patched).then(async (tab) => {
        if (tab && tab.id !== undefined) {
          await new Promise(r => setTimeout(r, 40));
          return await origTabUpdate(tab.id, { url: extUrl });
        }
        return tab;
      });
    };
  }
})();
"#;

fn inject_html_shim_recursive(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        let p = entry.path();
        if ft.is_dir() {
            inject_html_shim_recursive(&p);
        } else if ft.is_file()
            && p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("html"))
            && let Ok(html) = std::fs::read_to_string(&p)
            && !html.contains("__bon_ext_shim.js")
        {
            let tag = r#"<script src="/__bon_ext_shim.js"></script>"#;
            let patched = if let Some(idx) = html.to_ascii_lowercase().find("<head>") {
                let split_at = idx + "<head>".len();
                format!("{}{}{}", &html[..split_at], tag, &html[split_at..])
            } else {
                format!("{tag}{html}")
            };
            let _ = std::fs::write(&p, patched);
        }
    }
}

fn prepend_js_shim_if_needed(ext_dir: &Path, rel_js: &str) {
    let rel = rel_js.trim().trim_start_matches('/');
    if rel.is_empty() || rel.contains("..") {
        return;
    }
    let cand = ext_dir.join(rel);
    let Ok(meta) = std::fs::symlink_metadata(&cand) else {
        return;
    };
    if !meta.file_type().is_file() {
        return;
    }
    let (Ok(canon_root), Ok(canon_cand)) = (ext_dir.canonicalize(), cand.canonicalize()) else {
        return;
    };
    if !canon_cand.starts_with(&canon_root) {
        return;
    }
    if let Ok(raw) = std::fs::read_to_string(&canon_cand)
        && !raw.contains("__BON_EXT_SHIM__")
    {
        let _ = std::fs::write(&canon_cand, format!("{BON_EXT_SHIM_JS}\n{raw}"));
    }
}

fn sanitize_extension_id(raw: &str) -> Option<String> {
    let clean: String = raw
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    let trimmed = clean.trim_matches(['-', '_']);
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Patches an unpacked extension directory so `agent-browser` can deterministically address its
/// `chrome-extension://<id>` pages, query active web tabs from popup tabs, and intercept popup windows.
pub fn patch_unpacked_extension_for_agent(
    ext_dir: &Path,
    ext_id_hint: &str,
    crx_key_b64: Option<&str>,
) {
    let manifest_path = ext_dir.join("manifest.json");
    let Ok(raw) = std::fs::read_to_string(&manifest_path) else {
        return;
    };
    let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return;
    };
    let Some(obj) = val.as_object_mut() else {
        return;
    };

    let has_valid_key = obj
        .get("key")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.trim().is_empty());
    if let Some(k) = crx_key_b64 {
        obj.insert("key".to_string(), serde_json::Value::String(k.to_string()));
    } else if !has_valid_key {
        let seed = if let Some(store_id) = BrowserExtension::extract_chrome_store_id(ext_id_hint) {
            store_id
        } else {
            ext_id_hint.to_string()
        };
        obj.insert(
            "key".to_string(),
            serde_json::Value::String(deterministic_spki_key_b64(&seed)),
        );
    }

    let mv = obj
        .get("manifest_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(3);
    if mv >= 3 {
        let mut hosts: Vec<String> = obj
            .get("host_permissions")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(ToString::to_string))
                    .collect()
            })
            .unwrap_or_default();
        if let Some(opt_arr) = obj
            .get("optional_host_permissions")
            .and_then(|v| v.as_array())
        {
            for item in opt_arr.iter().filter_map(|x| x.as_str()) {
                if !hosts.iter().any(|h| h == item) {
                    hosts.push(item.to_string());
                }
            }
        }
        if !hosts.is_empty() && !hosts.iter().any(|h| h == "<all_urls>") {
            hosts.push("<all_urls>".to_string());
        }
        if !hosts.is_empty() {
            obj.insert(
                "host_permissions".to_string(),
                serde_json::Value::Array(
                    hosts.into_iter().map(serde_json::Value::String).collect(),
                ),
            );
        }
    }

    if let Some(bg) = obj.get("background") {
        if let Some(sw) = bg.get("service_worker").and_then(|v| v.as_str()) {
            prepend_js_shim_if_needed(ext_dir, sw);
        }
        if let Some(scripts) = bg.get("scripts").and_then(|v| v.as_array()) {
            for s in scripts.iter().filter_map(|v| v.as_str()) {
                prepend_js_shim_if_needed(ext_dir, s);
            }
        }
    }

    let _ = std::fs::write(ext_dir.join("__bon_ext_shim.js"), BON_EXT_SHIM_JS);
    inject_html_shim_recursive(ext_dir);
    if let Ok(pretty) = serde_json::to_string_pretty(&val) {
        let _ = std::fs::write(&manifest_path, pretty);
    }
}

/// Computes the runtime 32-char `chrome-extension://<id>` and primary entry HTML URL (`popup`/`options`/`sidepanel`) for an extension.
pub fn resolve_extension_runtime_info_in(
    root_dir: &Path,
    ext: &BrowserExtension,
) -> Option<(String, String)> {
    use base64::Engine;
    let ext_dir = ensure_extension_unpacked_in(root_dir, ext).ok()?;
    let raw = std::fs::read_to_string(ext_dir.join("manifest.json")).ok()?;
    let val: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let key_b64 = val.get("key").and_then(|v| v.as_str())?;
    let key_der = base64::engine::general_purpose::STANDARD
        .decode(key_b64.trim())
        .ok()?;
    let runtime_id = pubkey_to_chrome_ext_id(&key_der);

    let popup_candidates = [
        val.get("action")
            .and_then(|a| a.get("default_popup"))
            .and_then(|v| v.as_str()),
        val.get("browser_action")
            .and_then(|a| a.get("default_popup"))
            .and_then(|v| v.as_str()),
        val.get("page_action")
            .and_then(|a| a.get("default_popup"))
            .and_then(|v| v.as_str()),
        val.get("side_panel")
            .and_then(|a| a.get("default_path"))
            .and_then(|v| v.as_str()),
        val.get("options_ui")
            .and_then(|a| a.get("page"))
            .and_then(|v| v.as_str()),
        val.get("options_page").and_then(|v| v.as_str()),
    ];
    for cand in popup_candidates.into_iter().flatten() {
        let clean = cand.trim().trim_start_matches('/');
        if !clean.is_empty() {
            return Some((
                runtime_id.clone(),
                format!("chrome-extension://{runtime_id}/{clean}"),
            ));
        }
    }
    for fallback in [
        "home.html",
        "popup.html",
        "index.html",
        "notification.html",
        "options.html",
    ] {
        if ext_dir.join(fallback).is_file() {
            return Some((
                runtime_id.clone(),
                format!("chrome-extension://{runtime_id}/{fallback}"),
            ));
        }
    }
    Some((
        runtime_id.clone(),
        format!("chrome-extension://{runtime_id}/manifest.json"),
    ))
}

pub fn is_placeholder_extension_dir(dir: &Path) -> bool {
    !dir.join("manifest.json").is_file()
        || std::fs::read_to_string(dir.join("content.js"))
            .is_ok_and(|c| c.contains("BonLogin Managed Extension"))
}

/// Discovers enabled unpacked Chrome extensions inside `~/Library/Application Support/com.bonlogin.app/extensions/*`.
pub fn discover_unpacked_extensions_in(root_dir: &Path) -> Vec<PathBuf> {
    if let Ok(db) = crate::db::Database::open_at(root_dir)
        && let Ok(exts) = db.list_extensions()
    {
        let mut enabled_paths = Vec::new();
        for ext in exts.into_iter().filter(|e| e.enabled) {
            if let Ok(p) = ensure_extension_unpacked_in(root_dir, &ext)
                && p.join("manifest.json").is_file()
            {
                enabled_paths.push(p);
            }
        }
        return enabled_paths;
    }

    let ext_dir = root_dir.join("extensions");
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

    let clean_rel = rel_path.trim().trim_start_matches('/');
    if clean_rel.is_empty() || clean_rel.contains("..") {
        return None;
    }
    let icon_file = ext_dir.join(clean_rel);
    let meta = std::fs::symlink_metadata(&icon_file).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    let (Ok(canon_root), Ok(canon_icon)) = (ext_dir.canonicalize(), icon_file.canonicalize())
    else {
        return None;
    };
    if !canon_icon.starts_with(&canon_root) {
        return None;
    }
    let bytes = std::fs::read(&canon_icon).ok()?;
    let is_svg = canon_icon
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("svg"));
    Some((is_svg, bytes))
}

fn strip_symlinks_recursive(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            let _ = std::fs::remove_file(&p);
        } else if ft.is_dir() {
            strip_symlinks_recursive(&p);
        }
    }
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

pub(crate) fn macos_clonefile(src: &Path, dst: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    unsafe extern "C" {
        fn clonefile(
            src: *const std::ffi::c_char,
            dst: *const std::ffi::c_char,
            flags: u32,
        ) -> std::ffi::c_int;
    }
    let (Ok(c_src), Ok(c_dst)) = (
        CString::new(src.as_os_str().as_bytes()),
        CString::new(dst.as_os_str().as_bytes()),
    ) else {
        return false;
    };
    unsafe { clonefile(c_src.as_ptr(), c_dst.as_ptr(), 0) == 0 }
}

pub(crate) fn clonefile_or_copy(src: &Path, dst: &Path) -> std::io::Result<()> {
    if dst.exists() {
        let _ = std::fs::remove_file(dst);
    }
    if macos_clonefile(src, dst) {
        return Ok(());
    }
    std::fs::copy(src, dst).map(|_| ())
}

pub(crate) fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    if !dst.exists() {
        if let Some(parent) = dst.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if macos_clonefile(src, dst) {
            return Ok(());
        }
    }
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_symlink() {
            continue;
        }
        let dest_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else if ty.is_file() {
            let _ = clonefile_or_copy(&entry.path(), &dest_path);
        }
    }
    Ok(())
}

/// Installs a `.zip`, `.crx`, or unpacked folder into `~/Library/Application Support/com.bonlogin.app/extensions/`.
pub fn install_extension_from_file_in(
    root_dir: &Path,
    src_path: &Path,
) -> Result<BrowserExtension> {
    if !src_path.exists() {
        bail!("File not found: {}", src_path.display());
    }
    let stem = src_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("custom-ext")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
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
        let dest_dir = root_dir.join("extensions").join(&ext_id);
        if dest_dir.exists() {
            let _ = std::fs::remove_dir_all(&dest_dir);
        }
        copy_dir_recursive(src_path, &dest_dir)?;
        patch_unpacked_extension_for_agent(&dest_dir, &ext_id, None);
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
    install_extension_from_bytes_cancellable_in(
        root_dir,
        &raw_bytes,
        Some(&ext_id),
        &src_path.to_string_lossy(),
        &std::sync::atomic::AtomicBool::new(false),
    )
}


/// Extracts `.crx` or `.zip` bytes into a staging directory first, aborting cleanly if `cancelled` is set.
pub fn install_extension_from_bytes_cancellable_in(
    root_dir: &Path,
    raw_bytes: &[u8],
    preferred_id: Option<&str>,
    source_url: &str,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<BrowserExtension> {
    use std::sync::atomic::Ordering;
    if cancelled.load(Ordering::SeqCst) {
        bail!("Extension download cancelled");
    }
    let crx_key_b64 = extract_crx_public_key_b64(raw_bytes, preferred_id);
    let zip_bytes = strip_crx_header(raw_bytes)?;
    let ext_id = preferred_id
        .and_then(sanitize_extension_id)
        .or_else(|| {
            use base64::Engine;
            let k = crx_key_b64.as_deref()?;
            let der = base64::engine::general_purpose::STANDARD.decode(k).ok()?;
            Some(pubkey_to_chrome_ext_id(&der))
        })
        .unwrap_or_else(|| format!("ext-{}", unix_now()));

    let nonce = rand::random::<u32>();
    let stage_dir = std::env::temp_dir().join(format!("bonlogin_stage_{ext_id}_{nonce}"));
    let _ = std::fs::remove_dir_all(&stage_dir);
    std::fs::create_dir_all(&stage_dir)?;

    let tmp_zip = std::env::temp_dir().join(format!("bonlogin_{ext_id}_{nonce}.zip"));
    std::fs::write(&tmp_zip, zip_bytes)?;

    let status = Command::new("/usr/bin/unzip")
        .args([
            "-q",
            "-o",
            &tmp_zip.to_string_lossy(),
            "-d",
            &stage_dir.to_string_lossy(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = std::fs::remove_file(&tmp_zip);

    if cancelled.load(Ordering::SeqCst) {
        let _ = std::fs::remove_dir_all(&stage_dir);
        bail!("Extension download cancelled");
    }

    if !status.is_ok_and(|s| s.success()) {
        let _ = std::fs::remove_dir_all(&stage_dir);
        bail!("Failed to extract archive (must be a valid .CRX or .ZIP extension)");
    }

    strip_symlinks_recursive(&stage_dir);
    flatten_single_nested_manifest_dir(&stage_dir);
    if !stage_dir.join("manifest.json").is_file() {
        let _ = std::fs::remove_dir_all(&stage_dir);
        bail!("Archive does not contain a Chrome extension manifest.json");
    }

    patch_unpacked_extension_for_agent(&stage_dir, &ext_id, crx_key_b64.as_deref());
    if cancelled.load(Ordering::SeqCst) {
        let _ = std::fs::remove_dir_all(&stage_dir);
        bail!("Extension download cancelled");
    }

    let ext_root = root_dir.join("extensions");
    std::fs::create_dir_all(&ext_root)?;
    let dest_dir = ext_root.join(&ext_id);
    if dest_dir.exists() {
        let _ = std::fs::remove_dir_all(&dest_dir);
    }
    if std::fs::rename(&stage_dir, &dest_dir).is_err() {
        copy_dir_recursive(&stage_dir, &dest_dir)?;
        let _ = std::fs::remove_dir_all(&stage_dir);
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
pub async fn download_extension_from_url_in(
    root_dir: &Path,
    url_or_id: &str,
) -> Result<BrowserExtension> {
    download_extension_from_url_cancellable_in(
        root_dir,
        url_or_id,
        None,
        &std::sync::atomic::AtomicBool::new(false),
    )
    .await
}


/// Cancellable extension download that aborts before or during unpacking if `cancelled` becomes true.
pub async fn download_extension_from_url_cancellable_in(
    root_dir: &Path,
    url_or_id: &str,
    target_id_override: Option<&str>,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<BrowserExtension> {
    use std::sync::atomic::Ordering;
    let trimmed = url_or_id.trim();
    if trimmed.is_empty() {
        bail!("Please enter a Chrome Web Store URL or Extension link");
    }
    if cancelled.load(Ordering::SeqCst) {
        bail!("Extension download cancelled");
    }

    let (download_url, store_id_opt) =
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
    if cancelled.load(Ordering::SeqCst) {
        bail!("Extension download cancelled");
    }
    if !resp.status().is_success() {
        bail!("Download returned HTTP {}", resp.status());
    }
    let bytes = resp.bytes().await?;
    if cancelled.load(Ordering::SeqCst) {
        bail!("Extension download cancelled");
    }
    if bytes.is_empty() {
        bail!("Downloaded empty response from store");
    }
    let preferred_id = target_id_override.or(store_id_opt.as_deref());
    install_extension_from_bytes_cancellable_in(root_dir, &bytes, preferred_id, trimmed, cancelled)
}

/// Ensures an enabled extension has a valid unpacked MV3 directory on disk in `extensions/<id>`.
pub fn ensure_extension_unpacked_in(root_dir: &Path, ext: &BrowserExtension) -> Result<PathBuf> {
    let ext_dir = if !ext.folder_path.trim().is_empty() {
        PathBuf::from(ext.folder_path.trim())
    } else {
        root_dir.join("extensions").join(&ext.id)
    };
    if ext_dir.join("manifest.json").is_file() {
        if !ext_dir.join("__bon_ext_shim.js").is_file() {
            patch_unpacked_extension_for_agent(&ext_dir, &ext.id, None);
        }
        return Ok(ext_dir);
    }
    std::fs::create_dir_all(&ext_dir)?;
    let clean_name = ext.name.replace('"', "'");
    let (content_js, popup_html, popup_js) = match ext.id.as_str() {
        "coordinates" => (
            r#"(() => {
  const b = document.createElement('div');
  b.id = '__bon_coords_badge';
  b.style.cssText = 'position:fixed;bottom:8px;right:8px;z-index:2147483647;background:rgba(15,17,23,0.88);color:#60a5fa;padding:3px 8px;border-radius:4px;font:11px monospace;pointer-events:none;border:1px solid #3b82f6;';
  b.textContent = 'x: 0, y: 0';
  document.documentElement.appendChild(b);
  window.addEventListener('mousemove', e => { b.textContent = `x: ${e.clientX}, y: ${e.clientY}`; }, { passive: true });
})();"#,
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Coordinates Helper</title></head><body style="width:240px;padding:12px;font-family:sans-serif;background:#0f1117;color:#f8fafc"><h3>Coordinates Helper</h3><p id="status">Overlay active on all pages</p><button id="toggle-btn">Toggle Overlay</button><script src="popup.js"></script></body></html>"#,
            r#"document.getElementById('toggle-btn').onclick = async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  document.getElementById('status').textContent = tab ? ('Target: ' + tab.url) : 'Toggled';
};"#,
        ),
        "cookie-token-grabber" => (
            r#"(() => {
  window.addEventListener('keydown', e => {
    if (e.altKey && e.shiftKey && e.code === 'KeyC') {
      const payload = JSON.stringify({ url: location.href, cookie: document.cookie, localStorage: { ...localStorage } }, null, 2);
      navigator.clipboard.writeText(payload);
    }
  });
})();"#,
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Cookie & Token Grabber</title></head><body style="width:280px;padding:12px;font-family:sans-serif;background:#0f1117;color:#f8fafc"><h3>Cookie & Token Grabber</h3><pre id="out" style="max-height:140px;overflow:auto;font-size:11px;background:#1e293b;padding:6px"></pre><button id="grab-btn">Grab Active Tab Cookies</button><script src="popup.js"></script></body></html>"#,
            r#"async function loadCookies() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return;
  const cookies = await chrome.cookies.getAll({ url: tab.url });
  const text = JSON.stringify({ url: tab.url, count: cookies.length, cookies }, null, 2);
  document.getElementById('out').textContent = text;
  return text;
}
loadCookies();
document.getElementById('grab-btn').onclick = async () => {
  const text = await loadCookies();
  if (text && navigator.clipboard) await navigator.clipboard.writeText(text);
  document.getElementById('grab-btn').textContent = 'Copied!';
};"#,
        ),
        "ip-status-badge" => (
            r#"(() => {
  const b = document.createElement('div');
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  b.style.cssText = 'position:fixed;bottom:8px;left:8px;z-index:2147483647;background:rgba(15,17,23,0.88);color:#34d399;padding:3px 8px;border-radius:4px;font:11px monospace;cursor:pointer;border:1px solid #10b981;';
  b.textContent = `🌐 ${navigator.language} | ${tz}`;
  b.title = 'Click to hide';
  b.onclick = () => b.remove();
  document.documentElement.appendChild(b);
})();"#,
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Proxy / IP Status Badge</title></head><body style="width:240px;padding:12px;font-family:sans-serif;background:#0f1117;color:#f8fafc"><h3>Proxy / IP Status Badge</h3><div id="info"></div><script src="popup.js"></script></body></html>"#,
            r#"document.getElementById('info').textContent = navigator.language + ' | ' + (Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC');"#,
        ),
        _ => (
            "// BonLogin Managed Extension\n",
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Extension Popup</title></head><body><h1>Extension Ready</h1></body></html>"#,
            "",
        ),
    };
    let manifest = format!(
        r#"{{
  "manifest_version": 3,
  "name": "{clean_name}",
  "version": "1.0.0",
  "description": "{clean_name} managed by BonLogin",
  "permissions": ["tabs", "storage", "cookies", "clipboardWrite"],
  "host_permissions": ["<all_urls>"],
  "action": {{
    "default_title": "{clean_name}",
    "default_popup": "popup.html"
  }},
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
    std::fs::write(ext_dir.join("popup.html"), popup_html)?;
    std::fs::write(ext_dir.join("popup.js"), popup_js)?;
    patch_unpacked_extension_for_agent(&ext_dir, &ext.id, None);
    Ok(ext_dir)
}

/// Downloads any enabled remote extensions (Chrome Web Store ID or URL) that are still placeholders on disk.
pub async fn sync_enabled_remote_extensions_in(root_dir: &Path) {
    let enabled_remote: Vec<BrowserExtension> = crate::db::Database::open_at(root_dir)
        .ok()
        .and_then(|db| db.list_extensions().ok())
        .unwrap_or_default()
        .into_iter()
        .filter(|e| {
            if !e.enabled {
                return false;
            }
            let src = e.source_url.trim();
            let is_remote = BrowserExtension::extract_chrome_store_id(src).is_some()
                || src.starts_with("http://")
                || src.starts_with("https://");
            let dir = root_dir.join("extensions").join(&e.id);
            is_remote && is_placeholder_extension_dir(&dir)
        })
        .collect();
    if enabled_remote.is_empty() {
        return;
    }

    let mut set = tokio::task::JoinSet::new();
    for ext in enabled_remote {
        let root_owned = root_dir.to_path_buf();
        set.spawn(async move {
            let store_url = ext.source_url.trim().to_string();
            let eid = ext.id;
            let still_enabled = || {
                crate::db::Database::open_at(&root_owned)
                    .ok()
                    .and_then(|db| db.list_extensions().ok())
                    .is_some_and(|list| list.iter().any(|e| e.id == eid && e.enabled))
            };
            if !still_enabled() {
                return;
            }
            let cancelled = std::sync::atomic::AtomicBool::new(false);
            if let Ok(downloaded) = download_extension_from_url_cancellable_in(
                &root_owned,
                &store_url,
                Some(&eid),
                &cancelled,
            )
            .await
            {
                if let Ok(db) = crate::db::Database::open_at(&root_owned) {
                    if db
                        .list_extensions()
                        .ok()
                        .is_some_and(|list| list.iter().any(|e| e.id == eid && e.enabled))
                    {
                        let _ = db.upsert_extension(&downloaded);
                    } else {
                        remove_extension_files_in(&root_owned, &eid);
                    }
                }
            }
        });
    }
    let _ = tokio::time::timeout(Duration::from_secs(8), async {
        while set.join_next().await.is_some() {}
    })
    .await;
}


/// Removes an unpacked extension directory from disk.
pub fn remove_extension_files_in(root_dir: &Path, ext_id: &str) {
    if ext_id.trim().is_empty() || ext_id.contains("..") || ext_id.contains('/') {
        return;
    }
    let dir = root_dir.join("extensions").join(ext_id);
    if dir.exists() {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Returns true when an extension points to a remote Chrome Web Store ID / URL and only has a placeholder on disk.
pub fn needs_remote_extension_download_in(root_dir: &Path, ext: &BrowserExtension) -> bool {
    let src_trimmed = ext.source_url.trim();
    let is_remote = BrowserExtension::extract_chrome_store_id(src_trimmed).is_some()
        || src_trimmed.starts_with("http://")
        || src_trimmed.starts_with("https://");
    if !is_remote {
        return false;
    }
    let dir = if !ext.folder_path.trim().is_empty() {
        PathBuf::from(ext.folder_path.trim())
    } else {
        root_dir.join("extensions").join(&ext.id)
    };
    is_placeholder_extension_dir(&dir)
}


/// Ensures an extension is unpacked, downloading & patching from Chrome Web Store if needed.
pub async fn activate_extension_cancellable_in(
    root_dir: &Path,
    mut ext: BrowserExtension,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<BrowserExtension> {
    ext.enabled = true;
    if needs_remote_extension_download_in(root_dir, &ext) {
        let downloaded = download_extension_from_url_cancellable_in(
            root_dir,
            ext.source_url.trim(),
            Some(&ext.id),
            cancelled,
        )
        .await?;
        ext.folder_path = downloaded.folder_path;
    } else {
        ensure_extension_unpacked_in(root_dir, &ext)?;
    }
    Ok(ext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn push_proto_varint(out: &mut Vec<u8>, mut val: u64) {
        loop {
            let mut byte = (val & 0x7f) as u8;
            val >>= 7;
            if val != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if val == 0 {
                break;
            }
        }
    }

    fn build_crx3_key_proof(field_num: u64, spki_bytes: &[u8]) -> Vec<u8> {
        let mut inner = Vec::new();
        push_proto_varint(&mut inner, (1 << 3) | 2); // field 1 (public_key), wire type 2
        push_proto_varint(&mut inner, spki_bytes.len() as u64);
        inner.extend_from_slice(spki_bytes);

        let mut outer = Vec::new();
        push_proto_varint(&mut outer, (field_num << 3) | 2);
        push_proto_varint(&mut outer, inner.len() as u64);
        outer.extend_from_slice(&inner);
        outer
    }

    #[test]
    fn test_crx2_and_crx3_public_key_extraction_and_header_stripping() {
        let dev_b64 = deterministic_spki_key_b64("my-dev-extension");
        let dev_der = base64::engine::general_purpose::STANDARD
            .decode(&dev_b64)
            .unwrap();
        let dev_ext_id = pubkey_to_chrome_ext_id(&dev_der);

        // 1. CRX2 archive: Cr24 + version(2) + pub_len + sig_len + pub_key + sig + PK\x03\x04
        let sig = b"FAKE_SIGNATURE";
        let mut crx2 = Vec::new();
        crx2.extend_from_slice(b"Cr24");
        crx2.extend_from_slice(&2u32.to_le_bytes());
        crx2.extend_from_slice(&(dev_der.len() as u32).to_le_bytes());
        crx2.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        crx2.extend_from_slice(&dev_der);
        crx2.extend_from_slice(sig);
        crx2.extend_from_slice(b"PK\x03\x04CRX2_ZIP_BODY");

        assert_eq!(
            extract_crx_public_key_b64(&crx2, None).as_deref(),
            Some(dev_b64.as_str())
        );
        assert_eq!(strip_crx_header(&crx2).unwrap(), b"PK\x03\x04CRX2_ZIP_BODY");

        // 2. CRX3 archive with two proofs: developer key + preferred key
        let pref_b64 = deterministic_spki_key_b64("preferred-store-ext");
        let pref_der = base64::engine::general_purpose::STANDARD
            .decode(&pref_b64)
            .unwrap();
        let pref_ext_id = pubkey_to_chrome_ext_id(&pref_der);

        let mut crx3_hdr = Vec::new();
        crx3_hdr.extend_from_slice(&build_crx3_key_proof(2, &dev_der));
        crx3_hdr.extend_from_slice(&build_crx3_key_proof(2, &pref_der));

        let mut crx3 = Vec::new();
        crx3.extend_from_slice(b"Cr24");
        crx3.extend_from_slice(&3u32.to_le_bytes());
        crx3.extend_from_slice(&(crx3_hdr.len() as u32).to_le_bytes());
        crx3.extend_from_slice(&crx3_hdr);
        crx3.extend_from_slice(b"PK\x03\x04CRX3_ZIP_BODY");

        // Matching preferred_id picks the exact matching proof key
        assert_eq!(
            extract_crx_public_key_b64(&crx3, Some(&dev_ext_id)).as_deref(),
            Some(dev_b64.as_str())
        );
        assert_eq!(
            extract_crx_public_key_b64(&crx3, Some(&pref_ext_id)).as_deref(),
            Some(pref_b64.as_str())
        );
        // Fallback without preferred_id returns non-webstore developer key
        assert!(extract_crx_public_key_b64(&crx3, None).is_some());
        assert!(strip_crx_header(b"NOT_AN_ARCHIVE").is_err());
    }

    #[test]
    fn test_ensure_extension_unpacked_locales_nested_flatten_and_folder_install() {
        let tmp = std::env::temp_dir().join(format!(
            "bonlogin-ext-unit-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // 1. Built-in tools (`coordinates`, `ip-status-badge`) unpack full MV3 bundles and are NOT placeholders
        for (id, name) in [
            ("coordinates", "Coordinates Helper"),
            ("ip-status-badge", "Proxy / IP Status Badge"),
        ] {
            let ext = BrowserExtension {
                id: id.to_string(),
                name: name.to_string(),
                icon_label: "🎯".to_string(),
                icon_bg: 0x3B82F6,
                is_default: true,
                enabled: true,
                source_url: String::new(),
                folder_path: String::new(),
                created_at: 1,
            };
            let dir = ensure_extension_unpacked_in(&tmp, &ext).unwrap();
            assert!(dir.join("manifest.json").is_file());
            assert!(dir.join("__bon_ext_shim.js").is_file());
            assert!(!is_placeholder_extension_dir(&dir));
            assert!(!needs_remote_extension_download_in(&tmp, &ext));
            let ( is_svg, bytes) = load_extension_icon_bytes(&ext).unwrap();
            assert!(is_svg && !bytes.is_empty());
        }

        // 2. Remote CWS extension unpacks a placeholder initially and flags `needs_remote_extension_download_in == true`
        let remote_ext = BrowserExtension {
            id: "metamask".to_string(),
            name: "MetaMask".to_string(),
            icon_label: "🦊".to_string(),
            icon_bg: 0xEA580C,
            is_default: true,
            enabled: true,
            source_url: "nkbihfbeogaeaoehlefnkodbefgpgknn".to_string(),
            folder_path: String::new(),
            created_at: 2,
        };
        let mm_dir = ensure_extension_unpacked_in(&tmp, &remote_ext).unwrap();
        assert!(is_placeholder_extension_dir(&mm_dir));
        assert!(needs_remote_extension_download_in(&tmp, &remote_ext));

        // 3. Nested wrapper dir flattening + `__MSG_appName__` localization lookup + install_extension_from_file_in
        let nested_root = tmp.join("nested_stage");
        let inner_dir = nested_root.join("extension-v1.0");
        let locale_dir = inner_dir.join("_locales/en");
        std::fs::create_dir_all(&locale_dir).unwrap();
        std::fs::create_dir_all(nested_root.join("__MACOSX")).unwrap();
        std::fs::write(
            inner_dir.join("manifest.json"),
            r#"{"manifest_version":3,"name":"__MSG_extTitle__","default_locale":"en","version":"1.0"}"#,
        )
        .unwrap();
        std::fs::write(
            locale_dir.join("messages.json"),
            r#"{"EXTTITLE":{"message":"Localized Wallet Pro"}}"#,
        )
        .unwrap();

        flatten_single_nested_manifest_dir(&nested_root);
        assert!(nested_root.join("manifest.json").is_file());
        assert_eq!(
            read_extension_name_from_dir(&nested_root, "fallback"),
            "Localized Wallet Pro"
        );

        let installed = install_extension_from_file_in(&tmp, &nested_root).unwrap();
        assert_eq!(installed.name, "Localized Wallet Pro");
        assert_eq!(installed.icon_label, "LO");
        assert!(Path::new(&installed.folder_path).join("manifest.json").is_file());

        let _ = std::fs::remove_dir_all(&tmp);
    }
}

