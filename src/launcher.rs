use crate::models::{
    BrowserBrand, BrowserExtension, GeoInfo, GpuSpoofMode, PlatformType, Profile, ProxyConfig,
    ProxyProtocol, RuntimeInfo, SavedProxy, unix_now,
};
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

/// Pure-Rust SHA-256 implementation (FIPS 180-4) for computing Chrome 32-char extension IDs (`a-p`) from SPKI DER keys.
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
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
        let p = entry.path();
        if p.is_dir() {
            inject_html_shim_recursive(&p);
        } else if p
            .extension()
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

fn prepend_js_shim_if_needed(js_path: &Path) {
    if let Ok(raw) = std::fs::read_to_string(js_path)
        && !raw.contains("__BON_EXT_SHIM__")
    {
        let _ = std::fs::write(js_path, format!("{BON_EXT_SHIM_JS}\n{raw}"));
    }
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
            prepend_js_shim_if_needed(&ext_dir.join(sw.trim_start_matches('/')));
        }
        if let Some(scripts) = bg.get("scripts").and_then(|v| v.as_array()) {
            for s in scripts.iter().filter_map(|v| v.as_str()) {
                prepend_js_shim_if_needed(&ext_dir.join(s.trim_start_matches('/')));
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
pub fn resolve_extension_runtime_info(ext: &BrowserExtension) -> Option<(String, String)> {
    use base64::Engine;
    let ext_dir = ensure_extension_unpacked(ext).ok()?;
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
    install_extension_from_bytes(&raw_bytes, Some(&ext_id), &src_path.to_string_lossy())
}

/// Extracts `.crx` or `.zip` bytes into `~/Library/Application Support/com.bonlogin.app/extensions/<id>`.
pub fn install_extension_from_bytes(
    raw_bytes: &[u8],
    preferred_id: Option<&str>,
    source_url: &str,
) -> Result<BrowserExtension> {
    install_extension_from_bytes_cancellable(
        raw_bytes,
        preferred_id,
        source_url,
        &std::sync::atomic::AtomicBool::new(false),
    )
}

/// Extracts `.crx` or `.zip` bytes into a staging directory first, aborting cleanly if `cancelled` is set.
pub fn install_extension_from_bytes_cancellable(
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
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_string())
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

    let ext_root = app_support_dir().join("extensions");
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
pub async fn download_extension_from_url(url_or_id: &str) -> Result<BrowserExtension> {
    download_extension_from_url_cancellable(
        url_or_id,
        None,
        &std::sync::atomic::AtomicBool::new(false),
    )
    .await
}

/// Cancellable extension download that aborts before or during unpacking if `cancelled` becomes true.
pub async fn download_extension_from_url_cancellable(
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
    install_extension_from_bytes_cancellable(&bytes, preferred_id, trimmed, cancelled)
}

/// Ensures an enabled extension has a valid unpacked MV3 directory on disk in `extensions/<id>`.
pub fn ensure_extension_unpacked(ext: &BrowserExtension) -> Result<PathBuf> {
    let ext_dir = if !ext.folder_path.trim().is_empty() {
        PathBuf::from(ext.folder_path.trim())
    } else {
        app_support_dir().join("extensions").join(&ext.id)
    };
    if ext_dir.join("manifest.json").is_file() {
        patch_unpacked_extension_for_agent(&ext_dir, &ext.id, None);
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
pub async fn sync_enabled_remote_extensions() {
    let enabled_remote: Vec<BrowserExtension> = crate::db::Database::open_fast()
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
            let dir = app_support_dir().join("extensions").join(&e.id);
            is_remote && is_placeholder_extension_dir(&dir)
        })
        .collect();

    for ext in enabled_remote {
        let store_url = ext.source_url.trim().to_string();
        let eid = ext.id.clone();
        let still_enabled = || {
            crate::db::Database::open_fast()
                .ok()
                .and_then(|db| db.list_extensions().ok())
                .is_some_and(|list| list.iter().any(|e| e.id == eid && e.enabled))
        };
        if !still_enabled() {
            continue;
        }
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        if download_extension_from_url_cancellable(&store_url, Some(&eid), &cancelled)
            .await
            .is_ok()
            && !still_enabled()
        {
            remove_extension_files(&eid);
        }
    }
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

pub fn profile_download_dir(short_id: &str) -> PathBuf {
    let dir = app_support_dir()
        .join("downloads")
        .join(format!("bon_{short_id}"));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn runtime_file_path(profile_id: &str) -> PathBuf {
    app_support_dir()
        .join("profiles")
        .join(profile_id)
        .join("bon_runtime.json")
}

fn launch_error_file_path(profile_id: &str) -> PathBuf {
    app_support_dir()
        .join("profiles")
        .join(profile_id)
        .join("bon_launch_error.txt")
}

/// Checks whether a profile currently has a live Chromium instance with an open window.
pub fn probe_live_runtime(profile_id: &str) -> Option<RuntimeInfo> {
    let prof_dir = app_support_dir().join("profiles").join(profile_id);
    let rt_path = prof_dir.join("bon_runtime.json");
    let active_port_path = prof_dir.join("DevToolsActivePort");

    let info = if let Ok(raw) = std::fs::read_to_string(&rt_path)
        && let Ok(parsed) = serde_json::from_str::<RuntimeInfo>(&raw)
    {
        parsed
    } else if let Ok(contents) = std::fs::read_to_string(&active_port_path)
        && let Ok((cdp_port, ws_url)) = parse_devtools_active_port(&contents)
    {
        RuntimeInfo {
            pid: 0,
            cdp_port,
            ws_url,
            local_proxy_port: None,
        }
    } else {
        return None;
    };

    if cdp_has_open_window(info.cdp_port) == Some(true) {
        Some(info)
    } else {
        None
    }
}

/// Gracefully stops a profile launched by another process (CLI daemon or previous session).
pub fn stop_external_runtime(profile_id: &str, short_id: &str) -> bool {
    let prof_dir = app_support_dir().join("profiles").join(profile_id);
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

    let mut stopped_any = false;
    if let Some(info) = maybe_info {
        if info.pid > 0 {
            #[cfg(unix)]
            {
                let pid_s = info.pid.to_string();
                let _ = Command::new("kill")
                    .args(["-TERM", &pid_s])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                for _ in 0..30 {
                    if cdp_has_open_window(info.cdp_port).is_none() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                let _ = Command::new("kill")
                    .args(["-KILL", &pid_s])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            stopped_any = true;
        } else if let Some(list_body) = cdp_http_get_body(info.cdp_port, "/json/list")
            && let Ok( serde_json::Value::Array(arr) ) = serde_json::from_str(&list_body)
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
    if (stopped_any || removed_files) && !short_id.is_empty() {
        let session = format!("bon_{short_id}");
        let _ = agent_browser_cmd_for_short_id(short_id)
            .args(["--session", &session, "close"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    stopped_any || removed_files
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
        format!("({locale})"),
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
    let body = cdp_http_get_body(cdp_port, "/json/list")?;
    let items: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    let arr = items.as_array()?;
    Some(arr.iter().any(|item| {
        item.get("type")
            .and_then(|t| t.as_str())
            .is_some_and(|t| matches!(t, "page" | "app" | "webview"))
    }))
}

pub struct RunningProcess {
    pub profile_id: String,
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

        if !self.profile_id.is_empty() {
            let _ = std::fs::remove_file(runtime_file_path(&self.profile_id));
            let _ = std::fs::remove_file(
                app_support_dir()
                    .join("profiles")
                    .join(&self.profile_id)
                    .join("DevToolsActivePort"),
            );
        }

        if !self.short_id.is_empty() {
            let session = format!("bon_{}", self.short_id);
            let _ = agent_browser_cmd_for_short_id(&self.short_id)
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
    let _ = std::fs::remove_file(runtime_file_path(&profile.id));
    let _ = std::fs::remove_file(launch_error_file_path(&profile.id));
    let _ = profile_download_dir(&profile.short_id());
    unquarantine_macos_app(&kernel.path);
    sync_enabled_remote_extensions().await;
    let args = build_chromium_args(
        profile,
        local_proxy_port,
        &user_data_dir,
        newly_resolved_geo.as_ref(),
    );

    struct SpawnedChildGuard {
        child: Option<Child>,
        profile_id: String,
    }
    impl Drop for SpawnedChildGuard {
        fn drop(&mut self) {
            if let Some(mut c) = self.child.take() {
                let _ = c.kill();
                let _ = c.wait();
                let _ = std::fs::remove_file(runtime_file_path(&self.profile_id));
                let _ = std::fs::remove_file(
                    app_support_dir()
                        .join("profiles")
                        .join(&self.profile_id)
                        .join("DevToolsActivePort"),
                );
            }
        }
    }

    let mut child_guard = match Command::new(&kernel.path)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => SpawnedChildGuard {
            child: Some(c),
            profile_id: profile.id.clone(),
        },
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

    let pid = child_guard.child.as_ref().map(Child::id).unwrap_or(0);
    let mut cdp_endpoint: Option<(u16, String)> = None;

    for _ in 0..50 {
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

        tokio::time::sleep(Duration::from_millis(100)).await;
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
    if let Ok(json) = serde_json::to_string(&info) {
        let _ = std::fs::write(runtime_file_path(&profile.id), json);
    }

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
        let _ = tokio::task::spawn_blocking(move || {
            let _ = ensure_agent_browser_connected(&sid, &ws_clone);
        })
        .await;
    }
    let child = child_guard
        .child
        .take()
        .ok_or_else(|| anyhow!("Browser child process missing"))?;
    Ok((
        RunningProcess {
            profile_id: profile.id.clone(),
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
    let mut cmd = if let Some(home) = dirs::home_dir()
        && home.join(".local/bin/agent-browser").is_file()
    {
        Command::new(home.join(".local/bin/agent-browser"))
    } else if Path::new("/opt/homebrew/bin/agent-browser").is_file() {
        Command::new("/opt/homebrew/bin/agent-browser")
    } else {
        Command::new("agent-browser")
    };
    cmd.env("AGENT_BROWSER_NO_VERSION_CHECK", "1")
        .env("AGENT_BROWSER_IDLE_TIMEOUT_MS", "0");
    cmd
}

fn agent_browser_cmd_for_short_id(short_id: &str) -> Command {
    let mut cmd = agent_browser_cmd();
    if !short_id.is_empty() {
        cmd.env("AGENT_BROWSER_DOWNLOAD_PATH", profile_download_dir(short_id));
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
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
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

/// Attaches any `chrome-extension://` page tabs that opened at browser startup (before `agent-browser connect`)
/// so they appear in `agent-browser --session bon_<id> tab`.
fn sync_extension_targets_to_agent_browser(session: &str, cdp_port: u16) -> usize {
    let Some(list_body) = cdp_http_get_body(cdp_port, "/json/list") else {
        return 0;
    };
    let Ok(targets) = serde_json::from_str::<serde_json::Value>(&list_body) else {
        return 0;
    };
    let Some(target_arr) = targets.as_array() else {
        return 0;
    };
    let ext_pages: Vec<(String, String)> = target_arr
        .iter()
        .filter_map(|t| {
            let ty = t.get("type")?.as_str()?;
            let id = t.get("id")?.as_str()?;
            let url = t.get("url")?.as_str()?;
            (matches!(ty, "page" | "app") && url.starts_with("chrome-extension://"))
                .then(|| (id.to_string(), url.to_string()))
        })
        .collect();
    if ext_pages.is_empty() {
        return 0;
    }

    let known_urls: std::collections::HashSet<String> = agent_browser_cmd()
        .args(["--session", session, "tab", "--json"])
        .output()
        .ok()
        .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok())
        .and_then(|v| {
            v.get("data")?
                .get("tabs")?
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|t| t.get("url")?.as_str().map(ToString::to_string))
                        .collect()
                })
        })
        .unwrap_or_default();

    let mut attached = 0;
    for (old_id, ext_url) in ext_pages {
        if !known_urls.contains(&ext_url) {
            let opened = agent_browser_cmd()
                .args(["--session", session, "tab", "new", &ext_url])
                .output()
                .is_ok_and(|o| o.status.success());
            if opened {
                let _ = cdp_http_get_body(cdp_port, &format!("/json/close/{old_id}"));
                attached += 1;
            }
        }
    }
    attached
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

pub fn ensure_agent_browser_connected(short_id: &str, ws_url: &str) -> Result<String> {
    let session = format!("bon_{short_id}");
    let out = agent_browser_cmd_for_short_id(short_id)
        .args([
            "--session",
            &session,
            "--input-mode",
            "instant",
            "connect",
            ws_url,
        ])
        .output()
        .context("Failed to execute `agent-browser`. Is `agent-browser` installed in PATH?")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("agent-browser connect failed: {}", stderr.trim());
    }
    if let Some(port) = extract_port_from_ws_url(ws_url) {
        sync_extension_targets_to_agent_browser(&session, port);
    }
    Ok(session)
}

/// Creates a pinned-tab sub-session (`bon_<id8>_<tag>`) so multiple agents can operate concurrently on separate tabs.
pub fn ensure_agent_browser_pinned_tab(
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

    let out = agent_browser_cmd_for_short_id(short_id)
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
        let _ = agent_browser_cmd_for_short_id(short_id)
            .args(["--session", &session, "tab", "new", url.trim()])
            .output();
    }
    Ok(session)
}

/// Re-scans CDP targets (OAuth popups, Web3 wallet windows, extensions) and returns the active tab list.
pub fn agent_sync_targets(short_id: &str, ws_url: &str) -> Result<serde_json::Value> {
    let session = ensure_agent_browser_connected(short_id, ws_url)?;
    let cdp_port = extract_port_from_ws_url(ws_url).unwrap_or(0);
    let newly_attached = if cdp_port > 0 {
        sync_extension_targets_to_agent_browser(&session, cdp_port)
    } else {
        0
    };
    let tabs_out = agent_browser_cmd_for_short_id(short_id)
        .args(["--session", &session, "tab", "--json"])
        .output()?;
    let tabs_json = serde_json::from_slice::<serde_json::Value>(&tabs_out.stdout)
        .unwrap_or_else(|_| serde_json::json!({}));
    Ok(serde_json::json!({
        "ok": true,
        "session": session,
        "newly_attached_extension_tabs": newly_attached,
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
pub fn agent_open_extension_tab(short_id: &str, ws_url: &str, ext_url: &str) -> Result<String> {
    let session = ensure_agent_browser_connected(short_id, ws_url)?;
    let out = agent_browser_cmd_for_short_id(short_id)
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

    let out = agent_browser_cmd_for_short_id(short_id)
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
        agent_browser_cmd_for_short_id(short_id)
            .args([
                "--session",
                &session,
                "state",
                "load",
                &file_path.to_string_lossy(),
            ])
            .output()?
    } else {
        agent_browser_cmd_for_short_id(short_id)
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

pub fn apply_profile_cli_flags(
    profile: &mut Profile,
    saved_proxies: &[SavedProxy],
    flags: &[String],
) -> Result<()> {
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
                let os = PlatformType::from_str_lossy(next_val()?);
                profile.os_platform = os;
                profile.os_version = os.os_version_for_seed(profile.seed).to_string();
                profile.hardware_concurrency = os.optimal_cores_for_seed(profile.seed);
                profile.window_size = os.default_window_size().to_string();
                idx += 2;
            }
            "--brand" => {
                let b = BrowserBrand::from_str_lossy(next_val()?);
                profile.brand = b;
                profile.brand_version = b.version_for_seed(profile.seed).to_string();
                idx += 2;
            }
            "--seed" => {
                let raw = next_val()?.trim();
                let new_seed: u32 = if raw.eq_ignore_ascii_case("random") {
                    Profile::random_seed()
                } else {
                    raw.parse().context("Invalid --seed integer")?
                };
                profile.seed = new_seed;
                profile.os_version = profile
                    .os_platform
                    .os_version_for_seed(new_seed)
                    .to_string();
                profile.brand_version = profile.brand.version_for_seed(new_seed).to_string();
                profile.hardware_concurrency = profile.os_platform.optimal_cores_for_seed(new_seed);
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
            "--cookies" => {
                let raw = next_val()?;
                let payload = if Path::new(raw).is_file() {
                    std::fs::read_to_string(raw)?
                } else {
                    raw.to_string()
                };
                save_prelaunch_cookies(&profile.short_id(), &payload)?;
                idx += 2;
            }
            "--proxy" => {
                let p_q = next_val()?.trim();
                if p_q.is_empty()
                    || p_q.eq_ignore_ascii_case("none")
                    || p_q.eq_ignore_ascii_case("direct")
                {
                    profile.proxy = None;
                    profile.resolved_geo = None;
                } else {
                    let sp = find_saved_proxy_by_query(saved_proxies, p_q)?;
                    profile.proxy = Some(sp.config.clone());
                    profile.resolved_geo = sp.resolved_geo.clone();
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
                profile.proxy = Some(chosen.config.clone());
                profile.resolved_geo = chosen.resolved_geo.clone();
                idx += 2;
            }
            other => bail!("Unknown profile flag '{other}'"),
        }
    }
    Ok(())
}

fn profile_summary_json(p: &Profile) -> serde_json::Value {
    let sid = p.short_id();
    let session = format!("bon_{sid}");
    let live = probe_live_runtime(&p.id);
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
        "download_dir": profile_download_dir(&sid),
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
    if let Some(info) = probe_live_runtime(&profile.id) {
        return Ok(info);
    }

    let err_file = launch_error_file_path(&profile.id);
    let _ = std::fs::remove_file(&err_file);

    let exe = std::env::current_exe().context("Failed to resolve current executable path")?;
    let mut child = Command::new(exe)
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
        if let Some(info) = probe_live_runtime(&profile.id)
            && info.pid > 0
        {
            let sid = profile.short_id();
            clear_flow_session_cache(&sid);
            let _ = db.touch_last_launched(&profile.id);
            let _ = ensure_agent_browser_connected(&sid, &info.ws_url);
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

async fn check_proxy_config_live(cfg: &ProxyConfig) -> Result<GeoInfo> {
    let mut tun = crate::proxy_tunnel::LocalProxyTunnel::start(cfg.clone()).await?;
    let port = tun.local_port();
    let res = crate::geoip::resolve_geo_via_port(Some(port)).await;
    tun.stop();
    res
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
           bon-login agent <id|name> [--record <flow>] <ab args...>      Run agent-browser (auto-records DOM steps)\n\n\
         AGENT FLOW PLAYBOOKS (`bon-login flow ...`):\n  \
           bon-login flow list                                           List saved DOM flows & required {{vars}}\n  \
           bon-login flow show <flow_name>                               Show steps & locators of a saved flow\n  \
           bon-login flow save <flow_name> <id|name> [--var k=literal]   Save profile's recent agent steps as reusable flow\n  \
           bon-login flow run <flow_name> <id|name|--group <g>|--all> [--var k=v] [--from-step <n>]\n  \
           bon-login flow heal <flow_name> <step_idx> <id|name> <ab args...>  Self-heal broken step & update flow\n  \
           bon-login flow history <id|name> [--clear]                    Inspect or clear auto-recorded profile steps\n  \
           bon-login flow delete <flow_name>                             Delete a saved flow\n\n\
         PROFILE MANAGEMENT (`bon-login profile ...`):\n  \
           bon-login profile list [--group <g>] [--search <q>]\n  \
           bon-login profile show <id|name>\n  \
           bon-login profile create <name> [--os macos|windows|linux] [--brand chrome|edge|brave|opera]\n                            [--group <g>] [--proxy <saved_proxy|none>] [--proxy-tag <tag>]\n                            [--seed <u32|random>] [--cores <n>] [--gpu native|seed]\n                            [--canvas on|off] [--audio on|off] [--font on|off] [--rects on|off]\n                            [--window-size <W,H>] [--timezone <tz|auto>] [--locale <loc|auto>]\n                            [--startup-url <url>] [--notes <txt>] [--cookies <file_or_json>]\n  \
           bon-login profile update <id|name|--group <g>|--all> [same flags as create]\n  \
           bon-login profile reseed <id|name|--group <g>|--all>\n  \
           bon-login profile clone <id|name> [--count <n>] [--name <prefix>]\n  \
           bon-login profile batch-create --count <n> [--prefix <p>] [--group <g>] [--os <os>] [--brand <b>] [--proxy-tag <tag>]\n  \
           bon-login profile check-proxy <id|name|--group <g>|--all>\n  \
           bon-login profile export-cookies <id|name> [--out <file>]\n  \
           bon-login profile import-cookies <id|name> <file_or_json>\n  \
           bon-login profile wipe <id|name|--group <g>|--all>\n  \
           bon-login profile delete <id|name|--group <g>|--all>\n  \
           bon-login profile backup [--out <file>]\n  \
           bon-login profile restore <file>\n\n\
         PROXY MANAGER (`bon-login proxy ...`):\n  \
           bon-login proxy list [--tag <t>]\n  \
           bon-login proxy add <raw_proxy_or_file> [--protocol http|socks5] [--tag <t>] [--name <n>] [--expire <days_or_date>]\n  \
           bon-login proxy update <id|name|--tag <t>|--all> [--name <n>] [--tag <t>] [--expire <days_or_date|none>]\n  \
           bon-login proxy check <id|name|--tag <t>|--all>\n  \
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
           bon-login kernel status | install"
    );
}

pub fn try_run_cli(tokio_handle: &tokio::runtime::Handle) -> Option<Result<()>> {
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
                let err_file = launch_error_file_path(&profile.id);
                let _ = std::fs::remove_file(&err_file);
                match tokio_handle.block_on(launch_profile(&profile)) {
                    Ok((mut running, maybe_geo)) => {
                        if let Some(geo) = &maybe_geo {
                            let _ = db.update_resolved_geo(&profile.id, Some(geo));
                        }
                        let _ = db.touch_last_launched(&profile.id);
                        while running.is_alive() {
                            std::thread::sleep(Duration::from_millis(800));
                        }
                        running.stop_gracefully();
                        Ok(())
                    }
                    Err(e) => {
                        let _ = profile_user_data_dir(&profile.id);
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
                let info = probe_live_runtime(&p.id).ok_or_else(|| {
                    anyhow!("Profile '{}' (bon_{}) is not running", p.name, p.short_id())
                })?;
                let res = agent_sync_targets(&p.short_id(), &info.ws_url)?;
                println!("{}", serde_json::to_string_pretty(&res)?);
                Ok(())
            }
            "agent" | "ab" => run_agent_cli(&args[1..]),
            "flow" | "flows" => run_flow_subcommand(&args[1..]),
            "profile" | "profiles" => run_profile_subcommand(tokio_handle, &args[1..]),
            "proxy" | "proxies" => run_proxy_subcommand(tokio_handle, &args[1..]),
            "group" | "groups" => run_group_subcommand(&args[1..]),
            "tag" | "tags" => run_tag_subcommand(&args[1..]),
            "ext" | "extension" | "extensions" => run_ext_subcommand(tokio_handle, &args[1..]),
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
    let items: Vec<serde_json::Value> = profiles
        .iter()
        .filter(|p| p.matches_filter(&search_query, group_filter.as_deref()))
        .map(profile_summary_json)
        .collect();
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
        let session = if let Some(tag) = &pin_tab {
            ensure_agent_browser_pinned_tab(&short_id, tag, &info.ws_url, open_url.as_deref())?
        } else {
            let s = ensure_agent_browser_connected(&short_id, &info.ws_url)?;
            if let Some(u) = open_url.as_deref().filter(|u| !u.trim().is_empty()) {
                let _ = agent_browser_cmd_for_short_id(&short_id)
                    .args(["--session", &s, "open", u.trim()])
                    .output();
            }
            s
        };
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
            "download_dir": profile_download_dir(&short_id),
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
    let mut stopped = Vec::new();
    for p in &targets {
        let did_stop = stop_external_runtime(&p.id, &p.short_id());
        if did_stop || !is_all {
            stopped.push(p.short_id());
        }
    }
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

fn run_profile_subcommand(
    tokio_handle: &tokio::runtime::Handle,
    args: &[String],
) -> Result<()> {
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
                let live = probe_live_runtime(&p.id);
                obj.insert("short_id".into(), serde_json::json!(sid));
                obj.insert("session".into(), serde_json::json!(format!("bon_{sid}")));
                obj.insert("running".into(), serde_json::json!(live.is_some()));
                obj.insert("live_runtime".into(), serde_json::json!(live));
                obj.insert(
                    "has_prelaunch_cookies".into(),
                    serde_json::json!(!read_prelaunch_cookies(&sid).trim().is_empty()),
                );
                obj.insert(
                    "download_dir".into(),
                    serde_json::json!(profile_download_dir(&sid)),
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
            apply_profile_cli_flags(&mut prof, &saved_proxies, flag_slice)?;
            db.upsert_profile(&prof)?;
            println!("{}", serde_json::to_string_pretty(&profile_summary_json(&prof))?);
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
                apply_profile_cli_flags(&mut p, &saved_proxies, flags)?;
                db.upsert_profile(&p)?;
                updated.push(profile_summary_json(&p));
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
            let mut created = Vec::new();
            for i in 1..=count {
                let mut c = src.cloned_with_new_seed();
                if let Some(prefix) = &custom_name {
                    c.name = if count == 1 {
                        prefix.clone()
                    } else {
                        format!("{prefix}-{i:02}")
                    };
                } else if count > 1 {
                    c.name = format!("{} (Copy {i})", src.name);
                }
                db.upsert_profile(&c)?;
                created.push(profile_summary_json(&c));
            }
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
                        if let Some(val) = rest.get(idx + 1) {
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
                apply_profile_cli_flags(&mut p, &saved_proxies, &forwarded_flags)?;
                if !proxy_pool.is_empty() {
                    let sp = proxy_pool[(i - 1) % proxy_pool.len()];
                    p.proxy = Some(sp.config.clone());
                    p.resolved_geo = sp.resolved_geo.clone();
                }
                db.upsert_profile(&p)?;
                created.push(profile_summary_json(&p));
            }
            println!("{}", serde_json::to_string_pretty(&created)?);
            Ok(())
        }
        "reseed" | "new-fingerprint" => {
            let profiles = db.list_profiles()?;
            let (mut targets, _) = select_profiles_by_target(&profiles, rest)?;
            let mut reseeded = Vec::new();
            for mut p in targets.drain(..) {
                p.seed = Profile::random_seed();
                p.os_version = p.os_platform.os_version_for_seed(p.seed).to_string();
                p.brand_version = p.brand.version_for_seed(p.seed).to_string();
                p.hardware_concurrency = p.os_platform.optimal_cores_for_seed(p.seed);
                p.gpu_spoofing = GpuSpoofMode::SeedGenerated;
                db.upsert_profile(&p)?;
                reseeded.push(profile_summary_json(&p));
            }
            if reseeded.len() == 1 {
                println!("{}", serde_json::to_string_pretty(&reseeded[0])?);
            } else {
                println!("{}", serde_json::to_string_pretty(&reseeded)?);
            }
            Ok(())
        }
        "check-proxy" => {
            let profiles = db.list_profiles()?;
            let saved_proxies = db.list_proxies()?;
            let (targets, _) = select_profiles_by_target(&profiles, rest)?;
            let mut out = Vec::new();
            for p in targets {
                let res = if let Some(cfg) = &p.proxy {
                    tokio_handle.block_on(check_proxy_config_live(cfg))
                } else {
                    tokio_handle.block_on(crate::geoip::resolve_geo_via_port(None))
                };
                match res {
                    Ok(geo) => {
                        let _ = db.update_resolved_geo(&p.id, Some(&geo));
                        if let Some(cfg) = &p.proxy {
                            for sp in &saved_proxies {
                                if sp.config.protocol == cfg.protocol
                                    && sp.config.host == cfg.host
                                    && sp.config.port == cfg.port
                                {
                                    let _ = db.update_saved_proxy_check(&sp.id, Some(&geo), None);
                                }
                            }
                        }
                        out.push(serde_json::json!({
                            "id": p.id,
                            "short_id": p.short_id(),
                            "name": p.name,
                            "ok": true,
                            "mode": if p.proxy.is_some() { "Proxy" } else { "Direct" },
                            "geo": geo,
                        }));
                    }
                    Err(e) => {
                        out.push(serde_json::json!({
                            "id": p.id,
                            "short_id": p.short_id(),
                            "name": p.name,
                            "ok": false,
                            "mode": if p.proxy.is_some() { "Proxy" } else { "Direct" },
                            "error": e.to_string(),
                        }));
                    }
                }
            }
            println!("{}", serde_json::to_string_pretty(&out)?);
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
            let (state_path, json) = if let Some(live) = probe_live_runtime(&p.id) {
                agent_export_state(&sid, &live.ws_url)?
            } else {
                let saved = app_support_dir()
                    .join("states")
                    .join(format!("bon_{sid}_state.json"));
                let pre = app_support_dir()
                    .join("states")
                    .join(format!("bon_{sid}_prelaunch.json"));
                let chosen = if saved.is_file() {
                    saved
                } else if pre.is_file() {
                    pre
                } else {
                    bail!(
                        "Profile '{}' is not running and has no saved state file yet",
                        p.name
                    );
                };
                let content = std::fs::read_to_string(&chosen)?;
                (chosen, content)
            };
            let final_path = if let Some(custom) = out_file {
                std::fs::write(&custom, &json)?;
                custom
            } else {
                state_path
            };
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
            save_prelaunch_cookies(&sid, &payload)?;
            let live_msg = if let Some(live) = probe_live_runtime(&p.id) {
                Some(agent_import_state_or_cookies(&sid, &live.ws_url, &payload)?)
            } else {
                None
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "short_id": sid,
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
                stop_external_runtime(&p.id, &p.short_id());
                wipe_profile_data(&p.id)?;
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
            let profiles = db.list_profiles()?;
            let (targets, _) = select_profiles_by_target(&profiles, rest)?;
            let mut deleted = Vec::new();
            for p in targets {
                stop_external_runtime(&p.id, &p.short_id());
                let _ = wipe_profile_data(&p.id);
                if let Ok(dir) = profile_user_data_dir(&p.id) {
                    let _ = std::fs::remove_dir_all(dir);
                }
                db.delete_profile(&p.id)?;
                deleted.push(p.short_id());
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
        "backup" => {
            let out_file = rest
                .windows(2)
                .find_map(|w| (w[0] == "--out" || w[0] == "-o").then(|| PathBuf::from(&w[1])));
            let (default_path, json) = db.export_profiles_json()?;
            let final_path = if let Some(custom) = out_file {
                std::fs::write(&custom, &json)?;
                custom
            } else {
                default_path
            };
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

fn run_proxy_subcommand(
    tokio_handle: &tokio::runtime::Handle,
    args: &[String],
) -> Result<()> {
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
                        if let Some(v) = rest.get(idx + 1) {
                            expire_ts = SavedProxy::parse_expiration_input(v);
                        }
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
            println!("{}", serde_json::to_string_pretty(&added)?);
            Ok(())
        }
        "update" | "edit" | "set" => {
            let proxies = db.list_proxies()?;
            let (mut targets, consumed) = select_proxies_by_target(&proxies, rest)?;
            let flags = &rest[consumed..];
            if flags.is_empty() {
                bail!("Usage: bon-login proxy update <id|name|--tag <t>|--all> [--name <n>] [--tag <t>] [--expire <days_or_date|none>]");
            }
            let mut idx = 0;
            let mut new_name: Option<String> = None;
            let mut new_tag: Option<String> = None;
            let mut new_expire: Option<Option<i64>> = None;
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
                        let v = flags.get(idx + 1).map(|s| s.trim()).unwrap_or("");
                        if v.is_empty() || v.eq_ignore_ascii_case("none") || v.eq_ignore_ascii_case("clear") || v == "0" {
                            new_expire = Some(None);
                        } else {
                            new_expire = Some(SavedProxy::parse_expiration_input(v));
                        }
                        idx += 2;
                    }
                    other => bail!("Unknown proxy update flag '{other}'"),
                }
            }
            let count = targets.len();
            let mut updated = Vec::new();
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
                db.upsert_proxy(&sp)?;
                updated.push(saved_proxy_summary_json(&sp));
            }
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
        "check" => {
            let proxies = db.list_proxies()?;
            let profiles = db.list_profiles()?;
            let (targets, _) = select_proxies_by_target(&proxies, rest)?;
            let mut results = Vec::new();
            for sp in targets {
                match tokio_handle.block_on(check_proxy_config_live(&sp.config)) {
                    Ok(geo) => {
                        let _ = db.update_saved_proxy_check(&sp.id, Some(&geo), None);
                        for prof in &profiles {
                            if prof.proxy.as_ref().is_some_and(|p| {
                                p.protocol == sp.config.protocol
                                    && p.host == sp.config.host
                                    && p.port == sp.config.port
                            }) {
                                let _ = db.update_resolved_geo(&prof.id, Some(&geo));
                            }
                        }
                        results.push(serde_json::json!({
                            "id": sp.id,
                            "name": sp.name,
                            "host": sp.config.display_short(),
                            "ok": true,
                            "geo": geo,
                        }));
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        let _ = db.update_saved_proxy_check(&sp.id, None, Some(&msg));
                        results.push(serde_json::json!({
                            "id": sp.id,
                            "name": sp.name,
                            "host": sp.config.display_short(),
                            "ok": false,
                            "error": msg,
                        }));
                    }
                }
            }
            println!("{}", serde_json::to_string_pretty(&results)?);
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
                    p.proxy = None;
                    p.resolved_geo = None;
                    db.upsert_profile(&p)?;
                    assigned.push(serde_json::json!({
                        "profile_short_id": p.short_id(),
                        "profile_name": p.name,
                        "proxy": "Direct",
                    }));
                } else {
                    let chosen = &proxy_pool[idx % proxy_pool.len()];
                    p.proxy = Some(chosen.config.clone());
                    p.resolved_geo = chosen.resolved_geo.clone();
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

fn run_ext_subcommand(
    tokio_handle: &tokio::runtime::Handle,
    args: &[String],
) -> Result<()> {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    let rest = if args.is_empty() { &[] } else { &args[1..] };
    let db = crate::db::Database::open_default()?;
    match sub {
        "list" | "ls" => {
            let exts = db.list_extensions()?;
            let items: Vec<serde_json::Value> = exts
                .iter()
                .map(|e| {
                    let rt = resolve_extension_runtime_info(e);
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
                ext.enabled = enable;
                if enable {
                    let dir = ensure_extension_unpacked(&ext)?;
                    if is_placeholder_extension_dir(&dir) && !ext.source_url.trim().is_empty() {
                        let downloaded =
                            tokio_handle.block_on(download_extension_from_url(&ext.source_url))?;
                        ext.folder_path = downloaded.folder_path;
                    }
                }
                db.upsert_extension(&ext)?;
                db.set_extension_enabled(&ext.id, enable)?;
                let rt = resolve_extension_runtime_info(&ext);
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
                install_extension_from_file(Path::new(src))?
            } else {
                tokio_handle.block_on(download_extension_from_url(src))?
            };
            db.upsert_extension(&ext)?;
            let rt = resolve_extension_runtime_info(&ext);
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
                remove_extension_files(&ext.id);
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
            let (runtime_id, entry_url) = resolve_extension_runtime_info(ext)
                .ok_or_else(|| anyhow!("Could not resolve extension entry URL for '{}'", ext.name))?;
            let profiles = db.list_profiles()?;
            let profile = if let Some(q) = prof_target {
                find_profile_by_query(&profiles, q)?
            } else {
                profiles
                    .iter()
                    .find(|p| probe_live_runtime(&p.id).is_some())
                    .ok_or_else(|| {
                        anyhow!(
                            "No running profile found. Specify `--profile <id|name>` or launch a profile first."
                        )
                    })?
            };
            let info = ensure_profile_launched_via_supervisor(&db, profile)?;
            let cli = agent_open_extension_tab(&profile.short_id(), &info.ws_url, &entry_url)?;
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
    match sub {
        "status" | "info" => {
            let k = locate_chromium_kernel();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "installed": k.is_some(),
                    "version": k.as_ref().map(|i| &i.version_label),
                    "path": k.as_ref().map(|i| &i.path),
                    "is_adryfish_bundle": k.as_ref().map(|i| i.is_adryfish_bundle),
                }))?
            );
            Ok(())
        }
        "install" | "download" => {
            let k = install_adryfish_kernel_blocking()?;
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
        other => bail!("Unknown kernel subcommand '{other}' (expected status or install)"),
    }
}

// ---------------------------------------------------------------------------
// Agent Flow Playbooks (Record @eN -> Stable Locators, Replay & Self-Heal)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Default)]
pub struct SnapshotRefMeta {
    pub role: String,
    pub name: String,
    pub unique: bool,
    #[serde(default)]
    pub role_index: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefDomAttrs {
    pub data_testid: String,
    pub id: String,
    pub name: String,
    pub placeholder: String,
    pub aria_label: String,
    pub href: String,
    pub input_type: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct FlowStep {
    pub op: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locators: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_args: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub optional: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct AgentFlow {
    pub name: String,
    #[serde(default)]
    pub domain: String,
    pub updated_at: i64,
    pub steps: Vec<FlowStep>,
}

pub fn flows_dir() -> PathBuf {
    let dir = app_support_dir().join("flows");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn sanitize_flow_name(raw: &str) -> Result<String> {
    let clean: String = raw
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let clean = clean.trim_matches('_').to_string();
    if clean.is_empty() {
        bail!("Invalid flow name '{raw}'");
    }
    Ok(clean)
}

fn flow_file_path(name: &str) -> Result<PathBuf> {
    let clean = sanitize_flow_name(name)?;
    Ok(flows_dir().join(format!("{clean}.json")))
}

fn snap_cache_path(short_id: &str) -> PathBuf {
    flows_dir().join(format!("_snap_{short_id}.json"))
}

fn history_flow_path(short_id: &str) -> PathBuf {
    flows_dir().join(format!("_history_{short_id}.json"))
}

fn clear_flow_session_cache(short_id: &str) {
    let _ = std::fs::remove_file(snap_cache_path(short_id));
    let _ = std::fs::remove_file(history_flow_path(short_id));
}

fn load_snap_cache(short_id: &str) -> std::collections::HashMap<String, SnapshotRefMeta> {
    std::fs::read_to_string(snap_cache_path(short_id))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_snap_cache(
    short_id: &str,
    map: &std::collections::HashMap<String, SnapshotRefMeta>,
) {
    if let Ok(json) = serde_json::to_string(map) {
        let _ = std::fs::write(snap_cache_path(short_id), json);
    }
}

pub fn parse_snapshot_refs(
    stdout: &str,
) -> std::collections::HashMap<String, SnapshotRefMeta> {
    let mut raw_entries: Vec<(String, String, String)> = Vec::new();

    if let Ok(val) = serde_json::from_str::<serde_json::Value>(stdout)
        && let Some(refs_obj) = val
            .get("data")
            .and_then(|d| d.get("refs"))
            .and_then(|r| r.as_object())
    {
        for (k, v) in refs_obj {
            let key = k.trim_start_matches('@').to_string();
            let role = v
                .get("role")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .trim()
                .to_string();
            let name = v
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .trim()
                .to_string();
            raw_entries.push((key, role, name));
        }
        raw_entries.sort_by_key(|(k, _, _)| k.trim_start_matches('e').parse::<u32>().unwrap_or(0));
    }
    if raw_entries.is_empty() {
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("- ") {
                if let Some(ref_pos) = rest.find("ref=e") {
                    let after_ref = &rest[ref_pos + 4..];
                    let ref_key: String = after_ref
                        .chars()
                        .take_while(|c| *c == 'e' || c.is_ascii_digit())
                        .collect();
                    if ref_key.len() > 1 {
                        let before_bracket = rest[..ref_pos]
                            .rfind('[')
                            .map(|idx| rest[..idx].trim())
                            .unwrap_or(rest);
                        let role = before_bracket
                            .split_whitespace()
                            .next()
                            .unwrap_or_default()
                            .to_string();
                        let name = if let Some(q1) = before_bracket.find('"')
                            && let Some(q2) = before_bracket.rfind('"')
                            && q2 > q1
                        {
                            before_bracket[q1 + 1..q2].replace("\\\"", "\"")
                        } else {
                            String::new()
                        };
                        raw_entries.push((ref_key, role, name));
                    }
                }
            } else if let Some(after_at) = trimmed.strip_prefix('@') {
                let ref_key: String = after_at
                    .chars()
                    .take_while(|c| *c == 'e' || c.is_ascii_digit())
                    .collect();
                if ref_key.starts_with('e')
                    && ref_key.len() > 1
                    && let Some(b1) = trimmed.find('[')
                    && let Some(b2) = trimmed[b1 + 1..].find(']')
                {
                    let bracket_inner = &trimmed[b1 + 1..b1 + 1 + b2];
                    let role = bracket_inner
                        .split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .to_string();
                    let after_bracket = &trimmed[b1 + 1 + b2 + 1..];
                    let name = if let Some(q1) = after_bracket.find('"')
                        && let Some(q2) = after_bracket[q1 + 1..].find('"')
                    {
                        after_bracket[q1 + 1..q1 + 1 + q2].to_string()
                    } else {
                        String::new()
                    };
                    raw_entries.push((ref_key, role, name));
                }
            }
        }
    }

    let mut counts: std::collections::HashMap<(String, String), usize> =
        std::collections::HashMap::new();
    for (_, role, name) in &raw_entries {
        if !role.is_empty() && !name.is_empty() {
            *counts.entry((role.clone(), name.clone())).or_insert(0) += 1;
        }
    }

    let mut role_indices: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut map = std::collections::HashMap::new();
    for (key, role, name) in raw_entries {
        let unique = !role.is_empty()
            && !name.is_empty()
            && counts
                .get(&(role.clone(), name.clone()))
                .copied()
                .unwrap_or(0)
                == 1;
        let role_counter = role_indices.entry(role.to_ascii_lowercase()).or_insert(0);
        let role_index = *role_counter;
        *role_counter += 1;
        map.insert(
            key,
            SnapshotRefMeta {
                role,
                name,
                unique,
                role_index,
            },
        );
    }
    map
}

pub fn build_jev_find_payload(
    step: &FlowStep,
    snap_map: &std::collections::HashMap<String, SnapshotRefMeta>,
) -> serde_json::Value {
    let mut sorted: Vec<(&String, &SnapshotRefMeta)> = snap_map.iter().collect();
    sorted.sort_by_key(|(k, _)| k.trim_start_matches('e').parse::<u32>().unwrap_or(0));
    let candidates: Vec<serde_json::Value> = sorted
        .into_iter()
        .filter(|(_, m)| !matches!(m.role.as_str(), "heading" | "paragraph"))
        .take(250)
        .map(|(k, m)| {
            let label = if m.name.is_empty() {
                format!("[@{k}] {}", m.role)
            } else {
                let short_name: String = m.name.chars().take(300).collect();
                format!("[@{k}] {} · {short_name}", m.role)
            };
            serde_json::json!({
                "id": format!("@{k}"),
                "text": label,
            })
        })
        .collect();
    serde_json::json!({
        "query": format!(
            "Interactive control for '{}' operation matching prior locators: {}",
            step.op,
            step.locators.join(", ")
        ),
        "candidates": candidates,
        "top_k": 3,
    })
}

pub fn split_shell_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_quote: Option<char> = None;
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match in_quote {
            Some(q) if c == q => in_quote = None,
            Some('"') if c == '\\' => {
                if let Some(next) = chars.next() {
                    cur.push(next);
                }
            }
            Some(_) => cur.push(c),
            None if c == '\'' || c == '"' => in_quote = Some(c),
            None if c.is_whitespace() => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
            }
            None => cur.push(c),
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

fn is_ref_token(s: &str) -> bool {
    let rest = s.strip_prefix("@e").unwrap_or("");
    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
}

fn css_attr_escape(val: &str) -> String {
    val.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn build_stable_locators(
    ref_token: &str,
    snap: Option<&SnapshotRefMeta>,
    attrs: &RefDomAttrs,
) -> Vec<String> {
    let mut out = Vec::new();
    fn push_unique(out: &mut Vec<String>, loc: String) {
        if !loc.is_empty() && !out.contains(&loc) {
            out.push(loc);
        }
    }

    if !attrs.data_testid.is_empty() {
        push_unique(
            &mut out,
            format!("[data-testid=\"{}\"]", css_attr_escape(&attrs.data_testid)),
        );
    }
    if !attrs.id.is_empty()
        && !attrs.id.contains(':')
        && !attrs.id.contains(' ')
        && !attrs.id.chars().all(|c| c.is_ascii_digit())
    {
        push_unique(
            &mut out,
            format!("[id=\"{}\"]", css_attr_escape(&attrs.id)),
        );
    }
    if !attrs.name.is_empty() {
        push_unique(
            &mut out,
            format!("[name=\"{}\"]", css_attr_escape(&attrs.name)),
        );
    }
    if let Some(s) = snap
        && !s.role.is_empty()
        && !s.name.is_empty()
        && s.unique
    {
        push_unique(&mut out, format!("role:{}:{}", s.role, s.name));
    }
    if !attrs.placeholder.is_empty() {
        push_unique(
            &mut out,
            format!("[placeholder=\"{}\"]", css_attr_escape(&attrs.placeholder)),
        );
    }
    if !attrs.aria_label.is_empty() {
        push_unique(
            &mut out,
            format!("[aria-label=\"{}\"]", css_attr_escape(&attrs.aria_label)),
        );
    }
    if let Some(s) = snap
        && !s.role.is_empty()
        && !s.name.is_empty()
    {
        push_unique(&mut out, format!("role:{}:{}", s.role, s.name));
    }
    if !attrs.href.is_empty()
        && !attrs.href.starts_with('#')
        && !attrs.href.starts_with("javascript:")
    {
        push_unique(
            &mut out,
            format!("a[href=\"{}\"]", css_attr_escape(&attrs.href)),
        );
    }
    if matches!(
        attrs.input_type.as_str(),
        "email" | "password" | "search" | "tel" | "url" | "submit" | "checkbox" | "radio" | "file"
    ) {
        push_unique(
            &mut out,
            format!("input[type=\"{}\"]", css_attr_escape(&attrs.input_type)),
        );
    }
    if out.is_empty()
        && let Some(s) = snap
        && !s.role.is_empty()
    {
        push_unique(&mut out, format!("role:{}:", s.role));
    }
    if out.is_empty() {
        push_unique(&mut out, ref_token.to_string());
    }
    out
}

pub fn match_ref_dom_attrs_from_nodes(
    refs: &[String],
    snap_map: &std::collections::HashMap<String, SnapshotRefMeta>,
    nodes: &[serde_json::Value],
) -> std::collections::HashMap<String, RefDomAttrs> {
    let mut map = std::collections::HashMap::new();
    for r in refs {
        let key = r.trim_start_matches('@');
        let Some(snap) = snap_map.get(key) else {
            continue;
        };
        let matched = if !snap.name.is_empty() {
            nodes
                .iter()
                .find(|n| {
                    let nr = n.get("role").and_then(|v| v.as_str()).unwrap_or_default();
                    let na = n
                        .get("accName")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    nr.eq_ignore_ascii_case(&snap.role) && na.eq_ignore_ascii_case(&snap.name)
                })
                .or_else(|| {
                    nodes.iter().find(|n| {
                        n.get("accName")
                            .and_then(|v| v.as_str())
                            .is_some_and(|na| na.eq_ignore_ascii_case(&snap.name))
                    })
                })
        } else {
            None
        }
        .or_else(|| {
            nodes
                .iter()
                .filter(|n| {
                    n.get("role")
                        .and_then(|v| v.as_str())
                        .is_some_and(|nr| nr.eq_ignore_ascii_case(&snap.role))
                })
                .nth(snap.role_index)
        });
        if let Some(node) = matched {
            let get_s = |field: &str| -> String {
                node.get(field)
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            };
            map.insert(
                r.clone(),
                RefDomAttrs {
                    data_testid: get_s("testid"),
                    id: get_s("id"),
                    name: get_s("name"),
                    placeholder: get_s("placeholder"),
                    aria_label: get_s("ariaLabel"),
                    href: get_s("href"),
                    input_type: get_s("type"),
                },
            );
        }
    }
    map
}

fn fetch_refs_dom_attrs(
    short_id: &str,
    session: &str,
    refs: &[String],
    snap_map: &std::collections::HashMap<String, SnapshotRefMeta>,
) -> std::collections::HashMap<String, RefDomAttrs> {
    if refs.is_empty() {
        return std::collections::HashMap::new();
    }
    let js = r#"JSON.stringify(Array.from(document.querySelectorAll('input,button,a,select,textarea,[role],[data-testid]')).slice(0, 300).map(el => ({
        role: (el.getAttribute('role') || (el.tagName==='BUTTON'||(el.tagName==='INPUT'&&/^(submit|button|reset)$/i.test(el.type))?'button':el.tagName==='A'?'link':el.tagName==='SELECT'?'combobox':el.tagName==='INPUT'&&el.type==='checkbox'?'checkbox':el.tagName==='INPUT'&&el.type==='radio'?'radio':(el.tagName==='INPUT'||el.tagName==='TEXTAREA')?'textbox':'')).toLowerCase(),
        accName: (el.getAttribute('aria-label') || (el.labels && el.labels[0] ? el.labels[0].innerText : '') || el.getAttribute('placeholder') || el.getAttribute('title') || el.innerText || el.value || '').trim(),
        testid: el.getAttribute('data-testid') || '',
        id: el.id || '',
        name: el.getAttribute('name') || '',
        placeholder: el.getAttribute('placeholder') || '',
        ariaLabel: el.getAttribute('aria-label') || '',
        href: el.getAttribute('href') || '',
        type: el.getAttribute('type') || ''
    })))"#;
    let Ok(out) = agent_browser_cmd_for_short_id(short_id)
        .args(["--session", session, "eval", js])
        .output()
    else {
        return std::collections::HashMap::new();
    };
    if !out.status.success() {
        return std::collections::HashMap::new();
    }
    let raw_out = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let json_str = serde_json::from_str::<String>(&raw_out).unwrap_or(raw_out);
    let Ok(nodes) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str) else {
        return std::collections::HashMap::new();
    };
    match_ref_dom_attrs_from_nodes(refs, snap_map, &nodes)
}

fn strip_leading_agent_flags(tokens: &[String]) -> &[String] {
    let mut idx = 0;
    while idx < tokens.len() {
        match tokens[idx].as_str() {
            "--json" | "--bail" | "--omit-command" | "--headed" | "--full" | "-i" | "-c"
            | "--interactive" | "--compact" => idx += 1,
            _ => break,
        }
    }
    &tokens[idx..]
}

fn unpack_agent_commands(ab_args: &[String]) -> Vec<Vec<String>> {
    let trimmed = strip_leading_agent_flags(ab_args);
    if trimmed.first().is_some_and(|c| c == "batch") {
        let mut sub_cmds = Vec::new();
        for arg in &trimmed[1..] {
            if arg.starts_with('-') {
                continue;
            }
            let words = split_shell_words(arg);
            if !words.is_empty() {
                sub_cmds.push(words);
            }
        }
        sub_cmds
    } else if !trimmed.is_empty() {
        vec![trimmed.to_vec()]
    } else {
        Vec::new()
    }
}

pub fn build_flow_step_from_cmd(
    raw_tokens: &[String],
    snap_map: &std::collections::HashMap<String, SnapshotRefMeta>,
    dom_attrs: &std::collections::HashMap<String, RefDomAttrs>,
) -> Option<FlowStep> {
    let tokens = strip_leading_agent_flags(raw_tokens);
    let cmd = tokens.first()?.as_str();
    let resolve_target = |target: &str| -> Vec<String> {
        if is_ref_token(target) {
            let key = target.trim_start_matches('@');
            let snap = snap_map.get(key);
            let attrs = dom_attrs.get(target).cloned().unwrap_or_default();
            build_stable_locators(target, snap, &attrs)
        } else {
            vec![target.to_string()]
        }
    };

    match cmd {
        "open" | "goto" | "navigate" => {
            let url = tokens.iter().skip(1).find(|s| !s.starts_with('-'))?.clone();
            Some(FlowStep {
                op: "open".to_string(),
                locators: Vec::new(),
                value: Some(url),
                extra_args: Vec::new(),
                optional: false,
            })
        }
        "click" | "dblclick" | "hover" | "focus" | "check" | "uncheck" | "scrollintoview"
        | "scrollinto" => {
            let target = tokens.get(1)?;
            let op = if cmd == "scrollinto" {
                "scrollintoview"
            } else {
                cmd
            };
            Some(FlowStep {
                op: op.to_string(),
                locators: resolve_target(target),
                value: None,
                extra_args: tokens[2..].to_vec(),
                optional: false,
            })
        }
        "fill" | "type" | "select" | "upload" => {
            let target = tokens.get(1)?;
            let val = tokens.get(2)?.clone();
            Some(FlowStep {
                op: cmd.to_string(),
                locators: resolve_target(target),
                value: Some(val),
                extra_args: tokens[3..].to_vec(),
                optional: false,
            })
        }
        "press" | "key" => {
            let key = tokens.get(1)?.clone();
            Some(FlowStep {
                op: "press".to_string(),
                locators: Vec::new(),
                value: Some(key),
                extra_args: Vec::new(),
                optional: false,
            })
        }
        "scroll" => {
            let dir = tokens.get(1)?.clone();
            Some(FlowStep {
                op: "scroll".to_string(),
                locators: Vec::new(),
                value: Some(dir),
                extra_args: tokens[2..].to_vec(),
                optional: false,
            })
        }
        "wait" => {
            let first_arg = tokens.get(1)?;
            if is_ref_token(first_arg) {
                Some(FlowStep {
                    op: "wait".to_string(),
                    locators: resolve_target(first_arg),
                    value: None,
                    extra_args: tokens[2..].to_vec(),
                    optional: false,
                })
            } else {
                Some(FlowStep {
                    op: "wait".to_string(),
                    locators: Vec::new(),
                    value: None,
                    extra_args: tokens[1..].to_vec(),
                    optional: false,
                })
            }
        }
        "find" => {
            let kind = tokens.get(1)?.as_str();
            match kind {
                "role" => {
                    let role = tokens.get(2)?;
                    let action = tokens.get(3).map(String::as_str).unwrap_or("click");
                    let mut name = String::new();
                    let mut value: Option<String> = None;
                    let mut idx = 4;
                    while idx < tokens.len() {
                        match tokens[idx].as_str() {
                            "--name" => {
                                name = tokens.get(idx + 1).cloned().unwrap_or_default();
                                idx += 2;
                            }
                            "--exact" => idx += 1,
                            other if !other.starts_with('-') => {
                                value = Some(other.to_string());
                                idx += 1;
                            }
                            _ => idx += 1,
                        }
                    }
                    Some(FlowStep {
                        op: action.to_string(),
                        locators: vec![format!("role:{role}:{name}")],
                        value,
                        extra_args: Vec::new(),
                        optional: false,
                    })
                }
                "text" | "label" | "placeholder" | "testid" => {
                    let target_val = tokens.get(2)?;
                    let action = tokens.get(3).map(String::as_str).unwrap_or("click");
                    let value = tokens
                        .iter()
                        .skip(4)
                        .find(|s| !s.starts_with('-'))
                        .cloned();
                    let loc = match kind {
                        "text" => format!("text:{target_val}"),
                        "label" => format!("label:{target_val}"),
                        "placeholder" => {
                            format!("[placeholder=\"{}\"]", css_attr_escape(target_val))
                        }
                        "testid" => format!("[data-testid=\"{}\"]", css_attr_escape(target_val)),
                        _ => unreachable!(),
                    };
                    Some(FlowStep {
                        op: action.to_string(),
                        locators: vec![loc],
                        value,
                        extra_args: Vec::new(),
                        optional: false,
                    })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn prepare_recorded_steps(
    short_id: &str,
    session: &str,
    ab_args: &[String],
) -> Vec<FlowStep> {
    let cmds = unpack_agent_commands(ab_args);
    if cmds.is_empty() {
        return Vec::new();
    }
    let mut refs_to_query = Vec::new();
    for c in &cmds {
        for tok in c {
            if is_ref_token(tok) && !refs_to_query.contains(tok) {
                refs_to_query.push(tok.clone());
            }
        }
    }
    let snap_map = load_snap_cache(short_id);
    let dom_attrs = if refs_to_query.is_empty() {
        std::collections::HashMap::new()
    } else {
        fetch_refs_dom_attrs(short_id, session, &refs_to_query, &snap_map)
    };
    cmds.iter()
        .filter_map(|c| build_flow_step_from_cmd(c, &snap_map, &dom_attrs))
        .collect()
}

fn extract_domain_from_url(url: &str) -> String {
    let without_proto = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    without_proto
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .to_string()
}

fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn load_flow_from_path(path: &Path, default_name: &str) -> AgentFlow {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<AgentFlow>(&s).ok())
        .unwrap_or_else(|| AgentFlow {
            name: default_name.to_string(),
            domain: String::new(),
            updated_at: unix_now_secs(),
            steps: Vec::new(),
        })
}

fn save_flow_to_path(path: &Path, flow: &mut AgentFlow) -> Result<()> {
    flow.updated_at = unix_now_secs();
    if flow.domain.is_empty() {
        if let Some(first_url) = flow
            .steps
            .iter()
            .find(|s| s.op == "open")
            .and_then(|s| s.value.as_deref())
        {
            flow.domain = extract_domain_from_url(first_url);
        }
    }
    let json = serde_json::to_string_pretty(flow)?;
    std::fs::write(path, json)?;
    Ok(())
}

fn append_steps_to_flow_path(path: &Path, name: &str, new_steps: &[FlowStep]) {
    if new_steps.is_empty() {
        return;
    }
    let mut flow = load_flow_from_path(path, name);
    for step in new_steps {
        if flow.steps.last() != Some(step) {
            flow.steps.push(step.clone());
        }
    }
    let _ = save_flow_to_path(path, &mut flow);
}

pub fn extract_flow_vars(flow: &AgentFlow) -> Vec<String> {
    let mut vars = Vec::new();
    let mut scan_str = |s: &str| {
        let mut rest = s;
        while let Some(start) = rest.find("{{") {
            let after = &rest[start + 2..];
            if let Some(end) = after.find("}}") {
                let v = after[..end].trim();
                if !v.is_empty() && !vars.iter().any(|x| x == v) {
                    vars.push(v.to_string());
                }
                rest = &after[end + 2..];
            } else {
                break;
            }
        }
    };
    for step in &flow.steps {
        if let Some(v) = &step.value {
            scan_str(v);
        }
        for l in &step.locators {
            scan_str(l);
        }
        for a in &step.extra_args {
            scan_str(a);
        }
    }
    vars
}

pub fn parameterize_flow_steps(
    steps: &mut [FlowStep],
    literal_to_var: &[(String, String)],
) {
    for (var_name, literal) in literal_to_var {
        if literal.is_empty() {
            continue;
        }
        let placeholder = format!("{{{{{var_name}}}}}");
        for step in steps.iter_mut() {
            if step.op == "open" {
                continue;
            }
            if let Some(val) = &mut step.value {
                *val = val.replace(literal, &placeholder);
            }
            for extra in &mut step.extra_args {
                *extra = extra.replace(literal, &placeholder);
            }
        }
    }
}

pub fn substitute_flow_vars(
    input: &str,
    vars: &std::collections::HashMap<String, String>,
) -> String {
    let mut out = input.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("{{{{{k}}}}}"), v);
    }
    out
}
fn parse_var_flag(args: &[String], idx: usize) -> Option<((String, String), usize)> {
    if args.get(idx)? == "--var" {
        let (k, v) = args.get(idx + 1)?.split_once('=')?;
        Some(((k.trim().to_string(), v.to_string()), 2))
    } else if let Some(kv) = args.get(idx)?.strip_prefix("--var=") {
        let (k, v) = kv.split_once('=')?;
        Some(((k.trim().to_string(), v.to_string()), 1))
    } else {
        None
    }
}

fn run_agent_browser_with_reconnect(
    short_id: &str,
    session: &str,
    ws_url: &str,
    args: &[String],
) -> Result<std::process::Output> {
    validate_stealth_agent_args(args)?;
    let run_once = || {
        agent_browser_cmd_for_short_id(short_id)
            .args(["--session", session, "--input-mode", "instant"])
            .args(args)
            .output()
            .context("Failed to execute agent-browser")
    };
    let mut out = run_once()?;
    if !out.status.success() && should_reconnect_agent_session(&out.stderr, &out.stdout) {
        let _ = ensure_agent_browser_connected(short_id, ws_url);
        out = run_once()?;
    }
    Ok(out)
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

    let prepared_steps = prepare_recorded_steps(&short_id, &session, rest);
    let out = run_agent_browser_with_reconnect(&short_id, &session, &info.ws_url, rest)?;

    if out.status.success() {
        let has_snapshot = unpack_agent_commands(rest)
            .iter()
            .any(|c| c.first().is_some_and(|op| op == "snapshot"));
        if has_snapshot {
            let stdout_str = String::from_utf8_lossy(&out.stdout);
            let parsed = parse_snapshot_refs(&stdout_str);
            if !parsed.is_empty() {
                save_snap_cache(&short_id, &parsed);
            }
        }
        if !prepared_steps.is_empty() {
            append_steps_to_flow_path(
                &history_flow_path(&short_id),
                &format!("history_{short_id}"),
                &prepared_steps,
            );
            if let Some(flow_name) = inline_record_flow
                && let Ok(fp) = flow_file_path(&flow_name)
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

pub fn build_locator_candidate_commands(
    op: &str,
    locator: &str,
    value: Option<&str>,
    extra_args: &[String],
) -> Vec<Vec<String>> {
    if let Some(rest) = locator.strip_prefix("role:") {
        let (role, name) = rest.split_once(':').unwrap_or((rest, ""));
        let find_action = match op {
            "click" | "fill" | "check" | "hover" => Some(op),
            "type" => Some("fill"),
            _ => None,
        };
        if let Some(act) = find_action {
            let mut candidates = Vec::new();
            if !name.is_empty() {
                let mut exact_cmd = vec![
                    "find".to_string(),
                    "role".to_string(),
                    role.to_string(),
                    act.to_string(),
                    "--name".to_string(),
                    name.to_string(),
                    "--exact".to_string(),
                ];
                if let Some(v) = value {
                    exact_cmd.push(v.to_string());
                }
                candidates.push(exact_cmd);

                let mut sub_cmd = vec![
                    "find".to_string(),
                    "role".to_string(),
                    role.to_string(),
                    act.to_string(),
                    "--name".to_string(),
                    name.to_string(),
                ];
                if let Some(v) = value {
                    sub_cmd.push(v.to_string());
                }
                candidates.push(sub_cmd);
            } else {
                let mut role_only = vec![
                    "find".to_string(),
                    "role".to_string(),
                    role.to_string(),
                    act.to_string(),
                ];
                if let Some(v) = value {
                    role_only.push(v.to_string());
                }
                candidates.push(role_only);
            }
            return candidates;
        }
        return Vec::new();
    }

    if let Some(text) = locator.strip_prefix("text:") {
        let mut cmd = vec![
            "find".to_string(),
            "text".to_string(),
            text.to_string(),
            op.to_string(),
        ];
        if let Some(v) = value {
            cmd.push(v.to_string());
        }
        return vec![cmd];
    }

    if let Some(label) = locator.strip_prefix("label:") {
        let mut cmd = vec![
            "find".to_string(),
            "label".to_string(),
            label.to_string(),
            op.to_string(),
        ];
        if let Some(v) = value {
            cmd.push(v.to_string());
        }
        return vec![cmd];
    }

    let mut cmd = vec![op.to_string(), locator.to_string()];
    if let Some(v) = value {
        cmd.push(v.to_string());
    }
    cmd.extend_from_slice(extra_args);
    vec![cmd]
}

fn execute_single_flow_step(
    short_id: &str,
    session: &str,
    ws_url: &str,
    step: &FlowStep,
    vars: &std::collections::HashMap<String, String>,
) -> std::result::Result<(usize, String), String> {
    let run_ab = |args: &[String]| -> std::result::Result<std::process::Output, String> {
        let out = run_agent_browser_with_reconnect(short_id, session, ws_url, args)
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(out)
        } else {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let out_s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            Err(if !err.is_empty() { err } else { out_s })
        }
    };

    let sub_value = step.value.as_ref().map(|v| substitute_flow_vars(v, vars));
    let sub_extra: Vec<String> = step
        .extra_args
        .iter()
        .map(|a| substitute_flow_vars(a, vars))
        .collect();

    if step.locators.is_empty() {
        let mut cmd = vec![step.op.clone()];
        if let Some(v) = &sub_value {
            cmd.push(v.clone());
        }
        cmd.extend_from_slice(&sub_extra);
        return run_ab(&cmd).map(|_| (0, step.op.clone()));
    }

    let mut last_err = String::new();
    for (loc_idx, raw_loc) in step.locators.iter().enumerate() {
        let loc = substitute_flow_vars(raw_loc, vars);
        let candidates =
            build_locator_candidate_commands(&step.op, &loc, sub_value.as_deref(), &sub_extra);

        if candidates.is_empty()
            && let Some(rest) = loc.strip_prefix("role:")
        {
            let (role, name) = rest.split_once(':').unwrap_or((rest, ""));
            match run_ab(&[
                "snapshot".to_string(),
                "-i".to_string(),
                "-c".to_string(),
                "--json".to_string(),
            ]) {
                Ok(snap_out) => {
                    let snap_map = parse_snapshot_refs(&String::from_utf8_lossy(&snap_out.stdout));
                    if let Some((ref_key, _)) = snap_map.iter().find(|(_, m)| {
                        m.role.eq_ignore_ascii_case(role)
                            && (name.is_empty() || m.name.eq_ignore_ascii_case(name))
                    }) {
                        let mut cmd = vec![step.op.clone(), format!("@{ref_key}")];
                        if let Some(v) = &sub_value {
                            cmd.push(v.clone());
                        }
                        cmd.extend_from_slice(&sub_extra);
                        match run_ab(&cmd) {
                            Ok(_) => return Ok((loc_idx, loc)),
                            Err(e) => last_err = e,
                        }
                    } else {
                        last_err = format!("Element not found for {loc}");
                    }
                }
                Err(e) => last_err = e,
            }
        }

        for cmd in candidates {
            match run_ab(&cmd) {
                Ok(_) => return Ok((loc_idx, loc)),
                Err(e) => last_err = e,
            }
        }
    }
    Err(last_err)
}

fn normalize_single_cmd_tokens(raw: &[String]) -> Vec<String> {
    let mut seen_cmd = false;
    let mut normalized_target = false;
    raw.iter()
        .map(|s| {
            if !seen_cmd {
                if !s.starts_with('-') {
                    seen_cmd = true;
                }
                return s.clone();
            }
            if !normalized_target && !s.starts_with('-') {
                normalized_target = true;
                if s.strip_prefix('e')
                    .is_some_and(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()))
                {
                    return format!("@{s}");
                }
            }
            s.clone()
        })
        .collect()
}

pub fn normalize_heal_agent_args(raw: &[String]) -> Vec<String> {
    if strip_leading_agent_flags(raw)
        .first()
        .is_some_and(|c| c == "batch")
    {
        let mut seen_batch = false;
        raw.iter()
            .map(|s| {
                if !seen_batch {
                    if s == "batch" {
                        seen_batch = true;
                    }
                    return s.clone();
                }
                if s.starts_with('-') {
                    return s.clone();
                }
                let words = normalize_single_cmd_tokens(&split_shell_words(s));
                words
                    .into_iter()
                    .map(|w| {
                        if w.chars().any(char::is_whitespace) {
                            format!("\"{}\"", w.replace('"', "\\\""))
                        } else {
                            w
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect()
    } else {
        normalize_single_cmd_tokens(raw)
    }
}

fn run_flow_subcommand(args: &[String]) -> Result<()> {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    let rest = if args.is_empty() { &[] } else { &args[1..] };

    match sub {
        "list" | "ls" => {
            let mut items = Vec::new();
            if let Ok(entries) = std::fs::read_dir(flows_dir()) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
                        continue;
                    };
                    if fname.starts_with('_') || !fname.ends_with(".json") {
                        continue;
                    }
                    let stem = fname.trim_end_matches(".json");
                    let flow = load_flow_from_path(&path, stem);
                    let vars = extract_flow_vars(&flow);
                    items.push(serde_json::json!({
                        "name": flow.name,
                        "domain": flow.domain,
                        "steps_count": flow.steps.len(),
                        "vars": vars,
                        "updated_at": flow.updated_at,
                        "path": path,
                    }));
                }
            }
            println!("{}", serde_json::to_string_pretty(&items)?);
            Ok(())
        }
        "show" | "get" | "info" => {
            let name = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login flow show <flow_name>"))?;
            let path = flow_file_path(name)?;
            if !path.is_file() {
                bail!("Flow '{}' not found at {}", name, path.display());
            }
            let flow = load_flow_from_path(&path, name);
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
            let flow_name = sanitize_flow_name(flow_raw)?;
            let db = crate::db::Database::open_default()?;
            let profiles = db.list_profiles()?;
            let profile = find_profile_by_query(&profiles, prof_target)?;
            let short_id = profile.short_id();
            let hist_path = history_flow_path(&short_id);
            let mut hist = load_flow_from_path(&hist_path, &flow_name);
            if hist.steps.is_empty() {
                bail!(
                    "No recorded steps found in session history for profile '{}' (bon_{short_id})",
                    profile.name
                );
            }
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
            parameterize_flow_steps(&mut hist.steps, &var_pairs);
            hist.name = flow_name.clone();
            let out_path = flow_file_path(&flow_name)?;
            save_flow_to_path(&out_path, &mut hist)?;
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
            let db = crate::db::Database::open_default()?;
            let profiles = db.list_profiles()?;
            let profile = find_profile_by_query(&profiles, prof_target)?;
            let short_id = profile.short_id();
            if clear {
                clear_flow_session_cache(&short_id);
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
            let hist = load_flow_from_path(&history_flow_path(&short_id), &format!("history_{short_id}"));
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
            let path = flow_file_path(&flow_name)?;
            if !path.is_file() {
                bail!("Flow '{}' not found at {}", flow_name, path.display());
            }
            let mut flow = load_flow_from_path(&path, &flow_name);
            if flow.steps.is_empty() {
                bail!("Flow '{}' has 0 steps", flow_name);
            }
            let db = crate::db::Database::open_default()?;
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
                    if let Some(n) = rest.get(idx + 1).and_then(|s| s.parse::<usize>().ok()) {
                        from_step = n;
                    }
                    idx += 2;
                } else {
                    idx += 1;
                }
            }

            let mut profile_results = Vec::new();
            let mut flow_dirty = false;
            let mut any_failed = false;

            for profile in &targets {
                let short_id = profile.short_id();
                let info = ensure_profile_launched_via_supervisor(&db, profile)?;
                let session = format!("bon_{short_id}");

                let mut vars = cli_vars.clone();
                vars.entry("profile.name".to_string())
                    .or_insert_with(|| profile.name.clone());
                vars.entry("profile.short_id".to_string())
                    .or_insert_with(|| short_id.clone());
                vars.entry("profile.notes".to_string())
                    .or_insert_with(|| profile.notes.clone());

                let mut executed = Vec::new();
                let mut failed_info: Option<serde_json::Value> = None;

                for step_idx in from_step..flow.steps.len() {
                    let step = flow.steps[step_idx].clone();
                    match execute_single_flow_step(&short_id, &session, &info.ws_url, &step, &vars)
                    {
                        Ok((winning_loc_idx, matched_locator)) => {
                            if winning_loc_idx > 0
                                && winning_loc_idx < flow.steps[step_idx].locators.len()
                            {
                                let winner =
                                    flow.steps[step_idx].locators.remove(winning_loc_idx);
                                flow.steps[step_idx].locators.insert(0, winner);
                                flow_dirty = true;
                            }
                            executed.push(serde_json::json!({
                                "step": step_idx,
                                "op": step.op,
                                "matched_locator": matched_locator,
                                "status": "ok",
                            }));
                        }
                        Err(err_msg) => {
                            if step.optional {
                                executed.push(serde_json::json!({
                                    "step": step_idx,
                                    "op": step.op,
                                    "status": "skipped_optional",
                                }));
                                continue;
                            }
                            any_failed = true;
                            let snap_out = agent_browser_cmd_for_short_id(&short_id)
                                .args(["--session", &session, "snapshot", "-i", "-c"])
                                .output()
                                .ok();
                            let snap_txt = snap_out
                                .as_ref()
                                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                                .unwrap_or_default();
                            let parsed = if !snap_txt.is_empty() {
                                let p = parse_snapshot_refs(&snap_txt);
                                if !p.is_empty() {
                                    save_snap_cache(&short_id, &p);
                                }
                                p
                            } else {
                                std::collections::HashMap::new()
                            };
                            let jev_find_payload = build_jev_find_payload(&step, &parsed);
                            failed_info = Some(serde_json::json!({
                                "failed_step": step_idx,
                                "step": step,
                                "error": err_msg,
                                "snapshot": snap_txt,
                                "jev_find_payload": jev_find_payload,
                                "heal_cli": format!(
                                    "bon-login flow heal {flow_name} {step_idx} {short_id} <agent-browser cmd...>"
                                ),
                                "resume_cli": format!(
                                    "bon-login flow run {flow_name} {short_id} --from-step {}",
                                    step_idx + 1
                                ),
                            }));
                            break;
                        }
                    }
                }

                if let Some(fail) = failed_info {
                    profile_results.push(serde_json::json!({
                        "ok": false,
                        "profile_short_id": short_id,
                        "profile_name": profile.name,
                        "executed_steps": executed,
                        "failure": fail,
                    }));
                } else {
                    profile_results.push(serde_json::json!({
                        "ok": true,
                        "profile_short_id": short_id,
                        "profile_name": profile.name,
                        "executed_steps": executed,
                    }));
                }
            }

            if flow_dirty {
                let _ = save_flow_to_path(&path, &mut flow);
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

            let path = flow_file_path(&flow_name)?;
            if !path.is_file() {
                bail!("Flow '{}' not found at {}", flow_name, path.display());
            }
            let mut flow = load_flow_from_path(&path, &flow_name);
            if step_idx >= flow.steps.len() {
                bail!(
                    "step_index {step_idx} out of range (flow '{}' has {} steps)",
                    flow_name,
                    flow.steps.len()
                );
            }

            let db = crate::db::Database::open_default()?;
            let profiles = db.list_profiles()?;
            let profile = find_profile_by_query(&profiles, prof_target)?;
            let short_id = profile.short_id();
            let info = ensure_profile_launched_via_supervisor(&db, profile)?;
            let session = format!("bon_{short_id}");

            let mut healed_steps = prepare_recorded_steps(&short_id, &session, &ab_args);
            let healed_step = healed_steps.pop().ok_or_else(|| {
                anyhow!("Command did not produce a recordable DOM step for healing")
            })?;

            let out =
                run_agent_browser_with_reconnect(&short_id, &session, &info.ws_url, &ab_args)?;
            if !out.status.success() {
                bail!(
                    "Heal command failed on live browser: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }

            let mut updated_step = healed_step;
            // Preserve parameterized {{var}} value from original step if the op still takes a value
            if let Some(orig_val) = &flow.steps[step_idx].value
                && orig_val.contains("{{")
                && updated_step.value.is_some()
            {
                updated_step.value = Some(orig_val.clone());
            }
            flow.steps[step_idx] = updated_step.clone();
            save_flow_to_path(&path, &mut flow)?;

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
        "delete" | "rm" | "remove" => {
            let name = rest
                .first()
                .ok_or_else(|| anyhow!("Usage: bon-login flow delete <flow_name>"))?;
            let path = flow_file_path(name)?;
            let existed = path.is_file();
            if existed {
                std::fs::remove_file(&path)?;
            }
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
            "Unknown flow subcommand '{other}' (expected list, show, save, run, heal, history, delete)"
        ),
    }
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
        assert!(args.contains(&"--lang=vi".to_string()));
        assert!(args.contains(&"--accept-lang=vi,vi-VN,vi,en-US;q=0.9,en;q=0.8".to_string()));
        assert!(args.contains(&"-AppleLanguages".to_string()));
        assert!(args.contains(&"(vi-VN)".to_string()));
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
        let (runtime_id, entry_url) = resolve_extension_runtime_info(&ext).unwrap();
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

        let prev_enabled = crate::db::Database::open_fast()
            .ok()
            .and_then(|db| db.list_extensions().ok())
            .and_then(|exts| {
                exts.into_iter()
                    .find(|e| e.id == "cookie-token-grabber")
                    .map(|e| e.enabled)
            })
            .unwrap_or(false);
        if let Ok(db) = crate::db::Database::open_fast() {
            let _ = db.set_extension_enabled("cookie-token-grabber", true);
        }

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
            resolve_extension_runtime_info(&grabber_ext).expect("should resolve extension URL");
        agent_open_extension_tab(&short_id, &running.info.ws_url, &entry_url)
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
        save_snap_cache(&short_id, &parsed_ext_snap);
        let grab_ref = parsed_ext_snap
            .iter()
            .find(|(_, m)| m.name.contains("Grab Active Tab Cookies"))
            .map(|(k, _)| format!("@{k}"))
            .expect("should find Grab Active Tab Cookies ref in parsed snapshot");
        let recorded = prepare_recorded_steps(
            &short_id,
            &format!("bon_{short_id}"),
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
        let (win_idx, matched_loc) = execute_single_flow_step(
            &short_id,
            &format!("bon_{short_id}"),
            &running.info.ws_url,
            &fallback_step,
            &std::collections::HashMap::new(),
        )
        .expect("fallback locator should succeed when primary selector is missing");
        assert_eq!(win_idx, 1);
        assert_eq!(matched_loc, "role:button:Grab Active Tab Cookies");

        let (state_path, state_json) =
            agent_export_state(&short_id, &running.info.ws_url).expect("export state should work");
        assert!(state_path.is_file());
        assert!(state_json.contains("cookies"));

        running.stop_gracefully();
        assert!(!running.is_alive());

        if let Ok(db) = crate::db::Database::open_fast() {
            let _ = db.set_extension_enabled("cookie-token-grabber", prev_enabled);
        }
        let _ = wipe_profile_data(&profile.id);
        clear_flow_session_cache(&short_id);
        if let Ok(dir) = profile_user_data_dir(&profile.id) {
            let _ = std::fs::remove_dir_all(dir);
        }
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

        apply_profile_cli_flags(&mut p, &[sp], &flags).unwrap();
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
        let test_id = "bon_test_cancelled_ext";
        remove_extension_files(test_id);

        let err = download_extension_from_url_cancellable(
            "https://example.com/ext.zip",
            Some(test_id),
            &cancelled,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("cancelled"));
        assert!(!app_support_dir().join("extensions").join(test_id).exists());

        let err2 = install_extension_from_bytes_cancellable(
            b"PK\x03\x04dummy",
            Some(test_id),
            "https://example.com/ext.zip",
            &cancelled,
        )
        .unwrap_err();
        assert!(err2.to_string().contains("cancelled"));
        assert!(!app_support_dir().join("extensions").join(test_id).exists());
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
                ("username".to_string(), "alice@example.com".to_string()),
                ("short".to_string(), "login".to_string()),
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
        let err = execute_single_flow_step(
            "12345678",
            "bon_12345678",
            "ws://127.0.0.1:9222/devtools/browser/test",
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
    }
}
