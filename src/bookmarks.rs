use crate::launcher::{probe_live_runtime_in, profile_user_data_dir_in};
use crate::models::Profile;
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

