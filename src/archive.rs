use crate::cookies::{read_prelaunch_cookies_in, save_prelaunch_cookies_in};
use crate::extensions::clonefile_or_copy;
use crate::models::Profile;
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

fn is_chromium_ephemeral_entry(name: &str) -> bool {
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
            | "SingletonLock"
            | "SingletonSocket"
            | "SingletonCookie"
            | "DevToolsActivePort"
            | "RunningChromeVersion"
    ) || name.ends_with(".tmp")
}

fn copy_dir_filtered(src: &Path, dst: &Path) -> Result<()> {
    if !src.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if is_chromium_ephemeral_entry(&name_str) {
            continue;
        }
        let src_path = entry.path();
        let dst_path = dst.join(&file_name);
        let ft = entry.file_type()?;
        if ft.is_dir() {
            copy_dir_filtered(&src_path, &dst_path)?;
        } else if ft.is_file() {
            let _ = clonefile_or_copy(&src_path, &dst_path);
        }
    }
    Ok(())
}

/// Exports a full profile archive (`.zip`) containing `profile_metadata.json`, `prelaunch_cookies.json`,
/// and its essential `user_data` directory (Cookies, LocalStorage, IndexedDB, Extension storage) into `~/Downloads/`.
struct StageDirGuard(PathBuf);
impl Drop for StageDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn export_profile_archive_zip_in(
    root_dir: &Path,
    backups_out_dir: &Path,
    profile: &Profile,
) -> Result<PathBuf> {
    std::fs::create_dir_all(backups_out_dir)?;
    let clean_name: String = profile
        .name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(28)
        .collect();
    let short_id = profile.short_id();
    let zip_path = backups_out_dir.join(format!("bonlogin_{clean_name}_{short_id}.zip"));
    let _ = std::fs::remove_file(&zip_path);

    let nonce = rand::random::<u32>();
    let stage_dir = root_dir
        .join("backups")
        .join(format!(".stage_pack_{short_id}_{nonce}"));
    let _ = std::fs::remove_dir_all(&stage_dir);
    std::fs::create_dir_all(&stage_dir)?;
    let _stage_guard = StageDirGuard(stage_dir.clone());

    let meta_json = serde_json::to_string_pretty(profile)?;
    std::fs::write(stage_dir.join("profile_metadata.json"), meta_json)?;

    let pre_cookies = read_prelaunch_cookies_in(root_dir, &short_id);
    if !pre_cookies.trim().is_empty() {
        std::fs::write(stage_dir.join("prelaunch_cookies.json"), pre_cookies)?;
    }

    let user_data_src = root_dir.join("profiles").join(&profile.id);
    if user_data_src.is_dir() {
        let _ = copy_dir_filtered(&user_data_src, &stage_dir.join("user_data"));
    }

    let status = Command::new("/usr/bin/zip")
        .current_dir(&stage_dir)
        .args(["-r", "-q", &zip_path.to_string_lossy(), "."])
        .status()
        .context("Failed to execute /usr/bin/zip")?;

    if !status.success() {
        bail!("Failed to create profile backup archive (.zip)");
    }
    Ok(zip_path)
}

/// Restores a profile from a `.zip` archive exported by `export_profile_archive_zip`.
/// If `existing_ids` already contains the profile's UUID, assigns a fresh UUID so nothing is overwritten.
pub fn import_profile_archive_zip_in(
    root_dir: &Path,
    zip_path: &Path,
    existing_ids: &std::collections::HashSet<String>,
) -> Result<Profile> {
    if !zip_path.is_file() {
        bail!("Backup archive not found: {}", zip_path.display());
    }
    let nonce = rand::random::<u32>();
    let stage_dir = root_dir
        .join("backups")
        .join(format!(".stage_unpack_{nonce}"));
    let _ = std::fs::remove_dir_all(&stage_dir);
    std::fs::create_dir_all(&stage_dir)?;
    let _stage_guard = StageDirGuard(stage_dir.clone());

    let status = Command::new("/usr/bin/unzip")
        .args([
            "-q",
            "-o",
            &zip_path.to_string_lossy(),
            "-d",
            &stage_dir.to_string_lossy(),
        ])
        .status()
        .context("Failed to execute /usr/bin/unzip")?;
    if !status.success() {
        bail!("Invalid or corrupted .zip archive");
    }

    let meta_path = stage_dir.join("profile_metadata.json");
    if !meta_path.is_file() {
        bail!("Archive does not contain profile_metadata.json");
    }
    let meta_raw = std::fs::read_to_string(&meta_path)?;
    let mut profile: Profile =
        serde_json::from_str(&meta_raw).context("Failed to parse profile_metadata.json")?;
    profile.deleted_at = None;
    let invalid_uuid = uuid::Uuid::parse_str(&profile.id).is_err();
    if invalid_uuid || existing_ids.contains(&profile.id) {
        profile.id = uuid::Uuid::new_v4().to_string();
        if !invalid_uuid {
            profile.name = format!("{} (Restored)", profile.name);
        }
    }

    let short_id = profile.short_id();
    let pre_path = stage_dir.join("prelaunch_cookies.json");
    if let Ok(pre_raw) = std::fs::read_to_string(&pre_path)
        && !pre_raw.trim().is_empty()
    {
        let _ = save_prelaunch_cookies_in(root_dir, &short_id, &pre_raw);
    }

    let user_data_stage = stage_dir.join("user_data");
    if user_data_stage.is_dir() {
        let dst_dir = root_dir.join("profiles").join(&profile.id);
        let _ = copy_dir_filtered(&user_data_stage, &dst_dir);
    }

    Ok(profile)
}
