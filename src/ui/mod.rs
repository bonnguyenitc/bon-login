pub mod profile_list;
pub mod profile_modal;
pub mod theme;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use gpui_kit::component::{
    button::{Button, ButtonVariants as _},
    input::{Input, InputEvent, InputState, TextareaState},
    menu::{DropdownMenu as _, PopupMenuItem},
    *,
};
use gpui_kit::*;

use crate::db::Database;
use crate::launcher::{KernelInfo, RunningProcess, locate_chromium_kernel};
use crate::models::{
    BrowserBrand, BrowserExtension, PlatformType, Profile, ProfileStatus, ProxyConfig,
    ProxyProtocol, SavedProxy,
};
use crate::ui::profile_list::{ColumnVisibility, render_profile_table, render_trash_table};
use crate::ui::profile_modal::{
    ProfileModalState, ProxyEditMode, render_edit_profile_view, render_extensions_view,
    render_groups_subtab_view, render_popup_modal, render_proxies_view,
};
use crate::ui::theme::{BonTheme, SfSymbol};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceView {
    Profiles,
    Proxies,
    EditProfile,
    Extensions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileSubTab {
    Local,
    Group,
    Trash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivePopupModal {
    QuickAdd,
    ColumnSettings,
    AssignGroup,
    AddGroup,
    AddTag,
    UpdateProxy,
    UpdateProfiles,
    AddProxy,
    UploadExtension,
    InputUrlExtension,
    RemoveExtension,
    ArrangeWindows,
    QuickMeta,
    CookieRobot,
    ImportBackupZip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingDeleteAction {
    Profile(String),
    CheckedProfiles,
    PermanentProfile(String),
    EmptyTrash,
    Group(String),
    Proxy(String),
    CheckedProxies,
    Tag(String),
    Extension(String),
}
pub struct BonLoginApp {
    pub db: Arc<Mutex<Database>>,
    pub profiles: Vec<Profile>,
    pub trashed_profiles: Vec<Profile>,
    pub saved_proxies: Vec<SavedProxy>,
    pub saved_groups: Vec<String>,
    pub saved_tags: Vec<String>,
    pub extensions: Vec<BrowserExtension>,
    pub ext_url_input: Entity<InputState>,
    pub ext_file_input: Entity<InputState>,
    pub pending_delete: Option<PendingDeleteAction>,
    pub downloading_ext: bool,
    pub ext_tasks: HashMap<String, (tokio::task::AbortHandle, Arc<std::sync::atomic::AtomicBool>)>,
    pub ext_url_task: Option<(tokio::task::AbortHandle, Arc<std::sync::atomic::AtomicBool>)>,
    pub checked_proxy_ids: HashSet<String>,
    pub checking_proxy_ids: HashSet<String>,
    pub proxy_check_tasks: HashMap<String, tokio::task::AbortHandle>,
    pub modal_proxy_task: Option<tokio::task::AbortHandle>,
    pub profile_tasks: HashMap<String, tokio::task::AbortHandle>,
    pub selected_proxy_group: String,
    pub proxy_add_protocol: ProxyProtocol,
    pub proxy_selected_tag: String,
    pub proxy_raw_input: Entity<TextareaState>,
    pub proxy_expire_input: Entity<InputState>,
    pub statuses: HashMap<String, ProfileStatus>,
    pub running_processes: Arc<Mutex<HashMap<String, RunningProcess>>>,
    pub tokio_handle: tokio::runtime::Handle,
    pub kernel_info: Option<KernelInfo>,
    pub installing_kernel: bool,
    pub search_input: Entity<InputState>,
    pub search_query: String,
    pub selected_group: String,
    pub selected_profile_id: Option<String>,
    pub checked_profile_ids: HashSet<String>,
    pub col_vis: ColumnVisibility,
    pub profile_sub_tab: ProfileSubTab,
    pub popup_modal: Option<ActivePopupModal>,
    pub show_detail_drawer: bool,
    pub batch_move_group_input: Entity<InputState>,
    pub active_view: WorkspaceView,
    pub modal: Option<ProfileModalState>,
    pub batch_prefix_input: Entity<InputState>,
    pub batch_selected_group: String,
    pub batch_proxy_group: String,
    pub batch_count_input: Entity<InputState>,
    pub batch_os: PlatformType,
    pub batch_brand: BrowserBrand,
    pub arrange_display_idx: usize,
    pub arrange_size_input: Entity<InputState>,
    pub quick_meta_profile_id: Option<String>,
    pub quick_meta_tags: Vec<String>,
    pub quick_meta_tag_input: Entity<InputState>,
    pub quick_meta_note_input: Entity<TextareaState>,
    pub quick_meta_totp_input: Entity<InputState>,
    pub cookie_robot_target_id: Option<String>,
    pub cookie_robot_urls_input: Entity<TextareaState>,
    pub cookie_robot_dwell_secs: u64,
    pub backup_zip_input: Entity<InputState>,
    pub banner_message: Option<String>,
    banner_timer_for: Option<String>,
    _subscriptions: Vec<Subscription>,
}

impl BonLoginApp {
    pub fn new(
        db: Database,
        tokio_handle: tokio::runtime::Handle,
        running_processes: Arc<Mutex<HashMap<String, RunningProcess>>>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let profiles = db.list_profiles().unwrap_or_default();
        let trashed_profiles = db.list_trashed_profiles().unwrap_or_default();
        let saved_proxies = db.list_proxies().unwrap_or_default();
        let saved_groups = db.list_groups().unwrap_or_default();
        let saved_tags = db.list_tags().unwrap_or_default();
        let extensions = db.list_extensions().unwrap_or_default();
        let enabled_exts: Vec<BrowserExtension> = extensions
            .iter()
            .filter(|e| e.enabled)
            .cloned()
            .collect();
        if !enabled_exts.is_empty() {
            tokio_handle.spawn_blocking(move || {
                for ext in &enabled_exts {
                    let _ = crate::launcher::ensure_extension_unpacked(ext);
                }
            });
        }
        let selected_profile_id = profiles.first().map(|p| p.id.clone());
        let kernel_info = locate_chromium_kernel();

        let search_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("\u{1002ab}  Search..."));

        let batch_prefix_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("e.g. Profile")
                .default_value("Profile")
        });

        let batch_count_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("1–50")
                .default_value("5")
        });

        let batch_move_group_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Enter new name...")
        });

        let proxy_raw_input = cx.new(|cx| {
            TextareaState::new(window, cx)
                .rows(6)
                .placeholder("One proxy per line (type:host:port:login:password:name)")
        });

        let proxy_expire_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("DD/MM/YYYY, YYYY-MM-DD, or days (e.g. 30)")
                .default_value("30")
        });

        let ext_url_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Input URL")
        });

        let ext_file_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Path to .CRX or .ZIP file (or click Upload file to browse)")
        });

        let arrange_size_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Width,Height (e.g. 960,600)")
                .default_value("960,600")
        });
        let quick_meta_tag_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Custom tag (e.g. Shop-01, Tier1)...")
        });
        let quick_meta_note_input = cx.new(|cx| {
            TextareaState::new(window, cx)
                .rows(4)
                .placeholder("Account note, recovery email, status...")
        });
        let quick_meta_totp_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Base32 2FA Secret or otpauth:// URI...")
        });
        let cookie_robot_urls_input = cx.new(|cx| {
            TextareaState::new(window, cx)
                .rows(6)
                .default_value("https://www.google.com\nhttps://www.youtube.com\nhttps://www.wikipedia.org")
        });
        let backup_zip_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Path to backup .zip file...")
        });
        let search_sub = cx.subscribe_in(&search_input, window, {
            let search_input = search_input.clone();
            move |this, _, ev: &InputEvent, _window, cx| {
                if matches!(ev, InputEvent::Change) {
                    this.search_query = search_input.read(cx).value().to_string();
                    cx.notify();
                }
            }
        });

        let monitor_procs = running_processes.clone();
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(800))
                    .await;
                let Ok(profile_ids) = this.read_with(cx, |app, _| {
                    app.profiles.iter().map(|p| p.id.clone()).collect::<Vec<_>>()
                }) else {
                    break;
                };
                let procs = monitor_procs.clone();
                let (exited, external_live) = cx
                    .background_executor()
                    .spawn(async move {
                        let mut exited = Vec::new();
                        let mut in_proc_ids = HashSet::new();
                        if let Ok(mut map) = procs.lock() {
                            map.retain(|id, proc| {
                                if proc.is_alive() {
                                    in_proc_ids.insert(id.clone());
                                    true
                                } else {
                                    proc.stop_gracefully();
                                    exited.push(id.clone());
                                    false
                                }
                            });
                        }
                        let mut external_live = HashMap::new();
                        for pid in profile_ids {
                            if !in_proc_ids.contains(&pid)
                                && let Some(info) = crate::launcher::probe_live_runtime(&pid)
                            {
                                external_live.insert(pid, info);
                            }
                        }
                        (exited, external_live)
                    })
                    .await;
                let alive = this
                    .update(cx, |app, cx| {
                        let mut changed = false;
                        for id in &exited {
                            app.statuses.insert(id.clone(), ProfileStatus::Stopped);
                            changed = true;
                        }
                        let in_proc_keys: HashSet<String> = app
                            .running_processes
                            .lock()
                            .map(|m| m.keys().cloned().collect())
                            .unwrap_or_default();
                        for (pid, info) in &external_live {
                            if !matches!(app.statuses.get(pid), Some(ProfileStatus::Running(cur)) if cur == info) {
                                app.statuses.insert(pid.clone(), ProfileStatus::Running(info.clone()));
                                changed = true;
                            }
                        }
                        let stale_ext: Vec<String> = app
                            .statuses
                            .iter()
                            .filter(|(pid, st)| {
                                matches!(st, ProfileStatus::Running(_))
                                    && !in_proc_keys.contains(*pid)
                                    && !external_live.contains_key(*pid)
                            })
                            .map(|(pid, _)| pid.clone())
                            .collect();
                        for pid in stale_ext {
                            app.statuses.insert(pid, ProfileStatus::Stopped);
                            changed = true;
                        }
                        if changed {
                            cx.notify();
                        }
                    })
                    .is_ok();
                if !alive {
                    break;
                }
            }
        })
        .detach();

        let initial_group = saved_groups.first().cloned().unwrap_or_default();
        let initial_tag = saved_tags.first().cloned().unwrap_or_default();

        Self {
            db: Arc::new(Mutex::new(db)),
            profiles,
            trashed_profiles,
            saved_proxies,
            saved_groups,
            saved_tags,
            extensions,
            ext_url_input,
            ext_file_input,
            pending_delete: None,
            downloading_ext: false,
            ext_tasks: HashMap::new(),
            ext_url_task: None,
            checked_proxy_ids: HashSet::new(),
            checking_proxy_ids: HashSet::new(),
            proxy_check_tasks: HashMap::new(),
            modal_proxy_task: None,
            profile_tasks: HashMap::new(),
            selected_proxy_group: "All".to_string(),
            proxy_add_protocol: ProxyProtocol::Http,
            proxy_selected_tag: initial_tag,
            proxy_raw_input,
            proxy_expire_input,
            statuses: HashMap::new(),
            running_processes,
            tokio_handle,
            kernel_info,
            installing_kernel: false,
            search_input,
            search_query: String::new(),
            selected_group: "All".to_string(),
            selected_profile_id,
            checked_profile_ids: HashSet::new(),
            col_vis: ColumnVisibility::default(),
            profile_sub_tab: ProfileSubTab::Local,
            popup_modal: None,
            show_detail_drawer: true,
            batch_move_group_input,
            active_view: WorkspaceView::Profiles,
            modal: None,
            batch_prefix_input,
            batch_selected_group: initial_group,
            batch_proxy_group: "None".to_string(),
            batch_count_input,
            batch_os: PlatformType::MacOS,
            batch_brand: BrowserBrand::Chrome,
            arrange_display_idx: 0,
            arrange_size_input,
            quick_meta_profile_id: None,
            quick_meta_tags: Vec::new(),
            quick_meta_tag_input,
            quick_meta_note_input,
            quick_meta_totp_input,
            cookie_robot_target_id: None,
            cookie_robot_urls_input,
            cookie_robot_dwell_secs: 5,
            backup_zip_input,
            banner_message: None,
            banner_timer_for: None,
            _subscriptions: vec![search_sub],
        }
    }

    pub fn reload_profiles(&mut self) {
        if let Ok(db) = self.db.lock() {
            if let Ok(list) = db.list_profiles() {
                self.profiles = list;
            }
            if let Ok(tlist) = db.list_trashed_profiles() {
                self.trashed_profiles = tlist;
            }
            if let Ok(plist) = db.list_proxies() {
                let valid_ids: HashSet<String> = plist.iter().map(|p| p.id.clone()).collect();
                self.checked_proxy_ids.retain(|id| valid_ids.contains(id));
                self.saved_proxies = plist;
            }
            if let Ok(glist) = db.list_groups() {
                self.saved_groups = glist;
                if !self.batch_selected_group.is_empty()
                    && !self
                        .saved_groups
                        .iter()
                        .any(|g| g.eq_ignore_ascii_case(&self.batch_selected_group))
                {
                    self.batch_selected_group =
                        self.saved_groups.first().cloned().unwrap_or_default();
                }
            }
            if let Ok(tlist) = db.list_tags() {
                self.saved_tags = tlist;
                if !self.proxy_selected_tag.is_empty()
                    && !self
                        .saved_tags
                        .iter()
                        .any(|t| t.eq_ignore_ascii_case(&self.proxy_selected_tag))
                {
                    self.proxy_selected_tag = self.saved_tags.first().cloned().unwrap_or_default();
                }
            }
            if let Ok(elist) = db.list_extensions() {
                self.extensions = elist;
            }
        }
    }

    pub fn reload_extensions_only(&mut self) {
        if let Ok(db) = self.db.lock()
            && let Ok(elist) = db.list_extensions()
        {
            self.extensions = elist;
        }
    }

    pub fn distinct_proxy_groups_with_counts(&self) -> Vec<(String, usize)> {
        let mut out: Vec<(String, usize)> = self
            .saved_tags
            .iter()
            .map(|t| (t.clone(), 0))
            .collect();
        for sp in &self.saved_proxies {
            let tag = sp.group_tag.trim();
            if tag.is_empty() {
                continue;
            }
            if let Some(entry) = out.iter_mut().find(|(g, _)| g.eq_ignore_ascii_case(tag)) {
                entry.1 += 1;
            } else {
                out.push((tag.to_string(), 1));
            }
        }
        out
    }

    pub fn filtered_saved_proxies(&self) -> Vec<SavedProxy> {
        self.saved_proxies
            .iter()
            .filter(|sp| {
                self.selected_proxy_group == "All"
                    || sp.group_tag.eq_ignore_ascii_case(&self.selected_proxy_group)
            })
            .cloned()
            .collect()
    }

    pub fn toggle_proxy_checked(&mut self, proxy_id: &str, cx: &mut Context<Self>) {
        if !self.checked_proxy_ids.remove(proxy_id) {
            self.checked_proxy_ids.insert(proxy_id.to_string());
        }
        cx.notify();
    }

    pub fn toggle_all_filtered_proxies_checked(&mut self, cx: &mut Context<Self>) {
        let ids: Vec<String> = self
            .filtered_saved_proxies()
            .into_iter()
            .map(|p| p.id)
            .collect();
        let all_checked = !ids.is_empty() && ids.iter().all(|id| self.checked_proxy_ids.contains(id));
        if all_checked {
            for id in ids {
                self.checked_proxy_ids.remove(&id);
            }
        } else {
            for id in ids {
                self.checked_proxy_ids.insert(id);
            }
        }
        cx.notify();
    }

    pub fn clear_checked_proxies(&mut self, cx: &mut Context<Self>) {
        self.checked_proxy_ids.clear();
        cx.notify();
    }

    pub fn copy_checked_saved_proxies(&mut self, cx: &mut Context<Self>) {
        let lines: Vec<String> = self
            .saved_proxies
            .iter()
            .filter(|sp| self.checked_proxy_ids.contains(&sp.id))
            .map(|sp| sp.config.to_editable_string())
            .collect();
        if lines.is_empty() {
            return;
        }
        let count = lines.len();
        cx.write_to_clipboard(ClipboardItem::new_string(lines.join("\n")));
        self.banner_message = Some(format!("Copied {count} proxy(s) to clipboard"));
        cx.notify();
    }

    pub fn delete_checked_saved_proxies(&mut self, cx: &mut Context<Self>) {
        let ids: Vec<String> = self.checked_proxy_ids.drain().collect();
        if ids.is_empty() {
            return;
        }
        let count = ids.len();
        for id in &ids {
            self.checking_proxy_ids.remove(id);
            if let Some(handle) = self.proxy_check_tasks.remove(id) {
                handle.abort();
            }
        }
        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for id in &ids {
                    let _ = db.delete_proxy(id);
                }
                Ok(())
            });
        }
        self.reload_profiles();
        self.banner_message = Some(format!("Deleted {count} proxy(s)"));
        cx.notify();
    }

    pub fn extend_saved_proxy_days(&mut self, proxy_id: &str, days: i64, cx: &mut Context<Self>) {
        let Some(mut sp) = self.saved_proxies.iter().find(|p| p.id == proxy_id).cloned() else {
            return;
        };
        let now = crate::models::unix_now();
        sp.expired_at = if days <= 0 {
            None
        } else {
            let base = sp.expired_at.unwrap_or(now).max(now);
            Some(base + days * 86_400)
        };
        if let Ok(db) = self.db.lock() {
            let _ = db.upsert_proxy(&sp);
        }
        self.reload_profiles();
        self.banner_message = Some(if days <= 0 {
            format!("Cleared expiration for '{}'", sp.name)
        } else {
            format!("Extended '{}' by +{days} days ({})", sp.name, sp.format_expired_at())
        });
        cx.notify();
    }

    pub fn extend_checked_saved_proxies_days(&mut self, days: i64, cx: &mut Context<Self>) {
        let checked = self.checked_proxy_ids.clone();
        if checked.is_empty() {
            return;
        }
        let now = crate::models::unix_now();
        let mut count = 0;
        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for sp in &self.saved_proxies {
                    if checked.contains(&sp.id) {
                        let mut updated = sp.clone();
                        let base = updated.expired_at.unwrap_or(now).max(now);
                        updated.expired_at = Some(base + days * 86_400);
                        let _ = db.upsert_proxy(&updated);
                        count += 1;
                    }
                }
                Ok(())
            });
        }
        self.reload_profiles();
        self.banner_message = Some(format!("Extended {count} proxy(s) by +{days} days"));
        cx.notify();
    }

    pub fn add_saved_proxies_from_input(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let group_tag = self.proxy_selected_tag.trim().to_string();
        let raw = self.proxy_raw_input.read(cx).value().to_string();
        let tokens: Vec<&str> = raw
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();

        if tokens.is_empty() {
            self.banner_message =
                Some("Enter at least one proxy (e.g. http://192.168.1.1:3000:user:pass)".to_string());
            cx.notify();
            return;
        }

        let base_idx = self.saved_proxies.len() + 1;
        let default_proto = self.proxy_add_protocol;
        let expire_raw = self.proxy_expire_input.read(cx).value().to_string();
        let parsed_expired_at = SavedProxy::parse_expiration_input(&expire_raw);
        let mut added = Vec::new();
        for (i, token) in tokens.into_iter().enumerate() {
            match ProxyConfig::parse_with_optional_name(token, default_proto) {
                Ok(Some((cfg, explicit_name))) => {
                    let name = explicit_name
                        .unwrap_or_else(|| format!("Proxy #{:02}", base_idx + i));
                    let mut sp = SavedProxy::new(name, group_tag.clone(), cfg);
                    sp.expired_at = parsed_expired_at;
                    added.push(sp);
                }
                Ok(None) => {}
                Err(e) => {
                    self.banner_message = Some(format!("Invalid proxy '{token}': {e}"));
                    cx.notify();
                    return;
                }
            }
        }

        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for sp in &added {
                    let _ = db.upsert_proxy(sp);
                }
                Ok(())
            });
        }
        let count = added.len();
        self.proxy_raw_input = cx.new(|cx| {
            TextareaState::new(window, cx)
                .rows(6)
                .placeholder("One proxy per line (type:host:port:login:password:name)")
        });
        self.popup_modal = None;
        self.reload_profiles();
        self.selected_proxy_group = "All".to_string();
        self.banner_message = Some(format!("Added {count} proxy(s) (Tag: #{group_tag})"));
        cx.notify();
    }

    pub fn delete_saved_proxy(&mut self, proxy_id: &str, cx: &mut Context<Self>) {
        self.checked_proxy_ids.remove(proxy_id);
        self.checking_proxy_ids.remove(proxy_id);
        if let Some(handle) = self.proxy_check_tasks.remove(proxy_id) {
            handle.abort();
        }
        if let Ok(db) = self.db.lock() {
            let _ = db.delete_proxy(proxy_id);
        }
        self.reload_profiles();
        self.banner_message = Some("Deleted proxy".to_string());
        cx.notify();
    }

    pub fn check_saved_proxy(&mut self, proxy_id: &str, cx: &mut Context<Self>) {
        let Some(sp) = self.saved_proxies.iter().find(|p| p.id == proxy_id).cloned() else {
            return;
        };
        let pid = sp.id.clone();
        let proxy_name = sp.name.clone();
        let cfg = sp.config.clone();
        let cfg_for_profiles = cfg.clone();
        if let Some(prev) = self.proxy_check_tasks.remove(&pid) {
            prev.abort();
        }
        self.checking_proxy_ids.insert(pid.clone());
        self.banner_message = Some(format!("Checking proxy '{proxy_name}' ({})...", cfg.display_short()));
        cx.notify();

        let tokio_handle = self.tokio_handle.clone();
        let db = self.db.clone();

        let join_handle = tokio_handle.spawn(async move {
            crate::launcher::check_proxy_config_live(&cfg).await
        });
        let abort_handle = join_handle.abort_handle();
        let task_id = abort_handle.id();
        self.proxy_check_tasks.insert(pid.clone(), abort_handle);

        cx.spawn(async move |this, cx| {
            let join_res = join_handle.await;
            let _ = this.update(cx, |app, cx| {
                if app
                    .proxy_check_tasks
                    .get(&pid)
                    .is_some_and(|h| h.id() == task_id)
                {
                    app.proxy_check_tasks.remove(&pid);
                    app.checking_proxy_ids.remove(&pid);
                }
                let res = match join_res {
                    Ok(r) => r,
                    Err(e) if e.is_cancelled() => return,
                    Err(e) => Err(anyhow::anyhow!("Join error: {e}")),
                };
                if !app.saved_proxies.iter().any(|p| p.id == pid) {
                    return;
                }
                match res {
                    Ok(geo) => {
                        if let Ok(db_guard) = db.lock() {
                            let _ = db_guard.sync_geo_for_proxy_endpoint(&cfg_for_profiles, &geo);
                        }
                        app.reload_profiles();
                        app.banner_message =
                            Some(format!("Proxy '{proxy_name}' OK: {}", geo.summary_badge()));
                    }
                    Err(e) => {
                        let err_s = e.to_string();
                        if let Ok(db_guard) = db.lock() {
                            let _ = db_guard.update_saved_proxy_check(&pid, None, Some(&err_s));
                        }
                        app.reload_profiles();
                        app.banner_message =
                            Some(format!("Proxy '{proxy_name}' failed: {err_s}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn check_filtered_saved_proxies(&mut self, cx: &mut Context<Self>) {
        let ids: Vec<String> = if !self.checked_proxy_ids.is_empty() {
            self.filtered_saved_proxies()
                .into_iter()
                .filter(|p| self.checked_proxy_ids.contains(&p.id))
                .map(|p| p.id)
                .collect()
        } else {
            self.filtered_saved_proxies()
                .into_iter()
                .map(|p| p.id)
                .collect()
        };
        for id in ids {
            self.check_saved_proxy(&id, cx);
        }
    }

    pub fn apply_saved_proxy_to_selected_profile(
        &mut self,
        proxy_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(sp) = self.saved_proxies.iter().find(|p| p.id == proxy_id).cloned() else {
            return;
        };
        let Some(sel_id) = self.selected_profile_id.clone() else {
            self.banner_message = Some("Select a profile first".to_string());
            cx.notify();
            return;
        };
        let Some(mut prof) = self.profiles.iter().find(|p| p.id == sel_id).cloned() else {
            return;
        };
        prof.proxy = Some(sp.config.clone());
        prof.resolved_geo = sp.resolved_geo.clone();
        if let Ok(db) = self.db.lock() {
            let _ = db.upsert_profile(&prof);
        }
        self.reload_profiles();
        self.select_profile(&sel_id, window, cx);
        self.banner_message = Some(format!(
            "Assigned proxy '{}' (#{}) to profile '{}'",
            sp.name, sp.group_tag, prof.name
        ));
        cx.notify();
    }

    pub fn assign_filtered_proxies_to_profiles(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let pool = self.filtered_saved_proxies();
        if pool.is_empty() {
            return;
        }
        let target_profiles = self.filtered_profiles();
        if target_profiles.is_empty() {
            return;
        }
        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for (idx, mut prof) in target_profiles.into_iter().enumerate() {
                    let chosen = &pool[idx % pool.len()];
                    prof.proxy = Some(chosen.config.clone());
                    prof.resolved_geo = chosen.resolved_geo.clone();
                    let _ = db.upsert_profile(&prof);
                }
                Ok(())
            });
        }
        self.reload_profiles();
        if let Some(sel) = self.selected_profile_id.clone() {
            self.select_profile(&sel, window, cx);
        }
        self.active_view = WorkspaceView::Profiles;
        self.banner_message = Some(format!(
            "Assigned '{}' proxy group round-robin across profiles",
            self.selected_proxy_group
        ));
        cx.notify();
    }

    pub fn proxies_for_batch_group(&self) -> Vec<SavedProxy> {
        if self.batch_proxy_group == "None" {
            return Vec::new();
        }
        self.saved_proxies
            .iter()
            .filter(|sp| {
                self.batch_proxy_group == "All"
                    || sp.group_tag.eq_ignore_ascii_case(&self.batch_proxy_group)
            })
            .cloned()
            .collect()
    }

    fn cancel_modal_proxy_check(&mut self) {
        if let Some(handle) = self.modal_proxy_task.take() {
            handle.abort();
        }
        if let Some(m) = self.modal.as_mut() {
            m.checking_proxy = false;
        }
    }

    pub fn fill_modal_proxy_from_group(
        &mut self,
        group_name: Option<&str>,
        cx: &mut Context<Self>,
    ) {
        self.cancel_modal_proxy_check();
        let chosen_sp = group_name.and_then(|grp| {
            let candidates: Vec<&SavedProxy> = self
                .saved_proxies
                .iter()
                .filter(|sp| sp.group_tag.eq_ignore_ascii_case(grp))
                .collect();
            if candidates.is_empty() {
                None
            } else {
                let idx = (rand::random::<u32>() as usize) % candidates.len();
                Some(candidates[idx].clone())
            }
        });
        if let Some(m) = self.modal.as_mut() {
            match chosen_sp {
                Some(sp) => {
                    m.proxy_mode = ProxyEditMode::SavedPool;
                    m.selected_proxy = Some(sp.config.clone());
                    m.resolved_geo = sp.resolved_geo;
                    m.proxy_check_error = None;
                    self.banner_message = Some(format!(
                        "Picked proxy '{}' from group '#{}'",
                        sp.name, sp.group_tag
                    ));
                }
                None => {
                    m.selected_proxy = None;
                    m.resolved_geo = None;
                    m.proxy_check_error = None;
                }
            }
            cx.notify();
        }
    }

    pub fn set_modal_proxy_mode(
        &mut self,
        mode: ProxyEditMode,
        cx: &mut Context<Self>,
    ) {
        self.cancel_modal_proxy_check();
        if let Some(m) = self.modal.as_mut() {
            m.proxy_mode = mode;
            m.proxy_check_error = None;
            if mode == ProxyEditMode::Direct {
                m.selected_proxy = None;
                m.resolved_geo = None;
            }
            cx.notify();
        }
    }

    pub fn select_saved_proxy_for_modal(
        &mut self,
        proxy_id: &str,
        cx: &mut Context<Self>,
    ) {
        self.cancel_modal_proxy_check();
        let Some(sp) = self.saved_proxies.iter().find(|p| p.id == proxy_id).cloned() else {
            return;
        };
        if let Some(m) = self.modal.as_mut() {
            m.proxy_mode = ProxyEditMode::SavedPool;
            m.selected_proxy = Some(sp.config);
            m.resolved_geo = sp.resolved_geo;
            m.proxy_check_error = None;
            self.banner_message = Some(format!("Selected proxy '{}' (#{})", sp.name, sp.group_tag));
            cx.notify();
        }
    }

    pub fn set_modal_region_preset(
        &mut self,
        tz: &str,
        loc: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(m) = self.modal.as_mut() {
            let tz_s = tz.to_string();
            let loc_s = loc.to_string();
            m.custom_tz_input = cx.new(|cx| InputState::new(window, cx).default_value(tz_s));
            m.custom_locale_input = cx.new(|cx| InputState::new(window, cx).default_value(loc_s));
            cx.notify();
        }
    }

    pub fn check_modal_proxy(&mut self, cx: &mut Context<Self>) {
        self.cancel_modal_proxy_check();
        let Some(m) = self.modal.as_mut() else {
            return;
        };
        let Some(cfg) = m.selected_proxy.clone() else {
            m.proxy_check_error =
                Some("Select a proxy from Proxy manager before checking".to_string());
            cx.notify();
            return;
        };
        m.checking_proxy = true;
        m.proxy_check_error = None;
        cx.notify();

        let tokio_handle = self.tokio_handle.clone();
        let db = self.db.clone();
        let cfg_for_db = cfg.clone();

        let join_handle = tokio_handle.spawn(async move {
            crate::launcher::check_proxy_config_live(&cfg).await
        });
        let abort_handle = join_handle.abort_handle();
        let task_id = abort_handle.id();
        self.modal_proxy_task = Some(abort_handle);

        cx.spawn(async move |this, cx| {
            let join_res = join_handle.await;
            let _ = this.update(cx, |app, cx| {
                if app
                    .modal_proxy_task
                    .as_ref()
                    .is_some_and(|h| h.id() == task_id)
                {
                    app.modal_proxy_task = None;
                }
                let res = match join_res {
                    Ok(r) => r,
                    Err(e) if e.is_cancelled() => return,
                    Err(e) => Err(anyhow::anyhow!("Join error: {e}")),
                };
                if let Some(m) = app.modal.as_mut() {
                    m.checking_proxy = false;
                    match res {
                        Ok(geo) => {
                            m.resolved_geo = Some(geo.clone());
                            m.proxy_check_error = None;
                            if let Ok(db_guard) = db.lock() {
                                let _ = db_guard.sync_geo_for_proxy_endpoint(&cfg_for_db, &geo);
                            }
                            app.reload_profiles();
                            app.banner_message =
                                Some(format!("Proxy OK: {}", geo.summary_badge()));
                        }
                        Err(e) => {
                            m.resolved_geo = None;
                            m.proxy_check_error = Some(e.to_string());
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn select_profile(
        &mut self,
        profile_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.selected_profile_id = Some(profile_id.to_string());
        if self.active_view == WorkspaceView::EditProfile
            && let Some(p) = self.profiles.iter().find(|p| p.id == profile_id).cloned()
        {
            self.modal = Some(ProfileModalState::from_profile(&p, true, window, cx));
        }
        cx.notify();
    }

    pub fn open_edit_view(
        &mut self,
        profile_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.active_view = WorkspaceView::EditProfile;
        self.select_profile(profile_id, window, cx);
    }

    pub fn open_edit_cookies_view(
        &mut self,
        profile_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.active_view = WorkspaceView::EditProfile;
        self.select_profile(profile_id, window, cx);
        if let Some(m) = self.modal.as_mut() {
            m.active_tab = profile_modal::ProfileEditorTab::Cookies;
        }
        cx.notify();
    }

    pub fn randomize_profile_seed(
        &mut self,
        profile_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(mut p) = self.profiles.iter().find(|p| p.id == profile_id).cloned() else {
            return;
        };
        p.seed = crate::models::Profile::random_seed();
        p.os_version = p.os_platform.os_version_for_seed(p.seed).to_string();
        p.brand_version = p.brand.version_for_seed(p.seed).to_string();
        p.hardware_concurrency = p.os_platform.optimal_cores_for_seed(p.seed);
        p.gpu_spoofing = crate::models::GpuSpoofMode::SeedGenerated;
        if let Ok(db) = self.db.lock() {
            let _ = db.upsert_profile(&p);
        }
        self.reload_profiles();
        self.select_profile(profile_id, window, cx);
        self.banner_message = Some(format!("Reseeded '{}' -> #{}", p.name, p.seed));
        cx.notify();
    }

    pub fn generate_batch_profiles(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let prefix = {
            let s = self.batch_prefix_input.read(cx).value().trim().to_string();
            if s.is_empty() {
                "Account".to_string()
            } else {
                s
            }
        };
        let group = self.batch_selected_group.trim().to_string();
        let pool = self.proxies_for_batch_group();
        let requested_count = self
            .batch_count_input
            .read(cx)
            .value()
            .trim()
            .parse::<usize>()
            .unwrap_or(5)
            .clamp(1, 50);

        let mut created = Vec::new();
        let base_idx = self.profiles.len() + 1;

        for i in 0..requested_count {
            let mut p =
                Profile::new_default(format!("{prefix}-{:02}", base_idx + i), self.batch_os);
            p.brand = self.batch_brand;
            p.brand_version = self.batch_brand.version_for_seed(p.seed).to_string();
            p.os_version = self.batch_os.os_version_for_seed(p.seed).to_string();
            p.group_tag = group.clone();
            if !pool.is_empty() {
                let chosen = &pool[i % pool.len()];
                p.proxy = Some(chosen.config.clone());
                p.resolved_geo = chosen.resolved_geo.clone();
            }
            created.push(p);
        }

        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for p in &created {
                    let _ = db.upsert_profile(p);
                }
                Ok(())
            });
        }
        let count = created.len();
        let last_id = created.last().map(|p| p.id.clone());
        self.reload_profiles();
        if let Some(id) = last_id {
            self.select_profile(&id, window, cx);
        }
        self.active_view = WorkspaceView::Profiles;
        self.banner_message = Some(if group.is_empty() {
            format!("Created {count} profiles")
        } else {
            format!("Created {count} profiles in folder '{group}'")
        });
        cx.notify();
    }

    pub fn export_all_profiles_backup(&mut self, cx: &mut Context<Self>) {
        if let Ok(db) = self.db.lock() {
            match db.export_profiles_json() {
                Ok((path, json)) => {
                    cx.write_to_clipboard(ClipboardItem::new_string(json));
                    self.banner_message = Some(format!(
                        "Exported all profiles JSON to clipboard & {}",
                        path.display()
                    ));
                }
                Err(e) => {
                    self.banner_message = Some(format!("Export failed: {e}"));
                }
            }
            cx.notify();
        }
    }

    pub fn cancel_extension_task(&mut self, ext_id: &str) -> bool {
        if let Some((handle, flag)) = self.ext_tasks.remove(ext_id) {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            handle.abort();
            true
        } else {
            false
        }
    }

    pub fn close_popup_modal(&mut self, cx: &mut Context<Self>) {
        if let Some((handle, flag)) = self.ext_url_task.take() {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            handle.abort();
        }
        if self.downloading_ext {
            self.downloading_ext = false;
            self.banner_message = Some("Canceled extension download".to_string());
        }
        self.popup_modal = None;
        cx.notify();
    }

    pub fn toggle_extension(&mut self, ext_id: &str, cx: &mut Context<Self>) {
        let Some(ext) = self.extensions.iter().find(|e| e.id == ext_id).cloned() else {
            return;
        };
        let was_downloading = self.cancel_extension_task(ext_id);
        let next_enabled = !ext.enabled;
        if let Ok(db) = self.db.lock() {
            let _ = db.set_extension_enabled(ext_id, next_enabled);
        }
        self.reload_extensions_only();

        let target_dir = crate::launcher::app_support_dir()
            .join("extensions")
            .join(&ext.id);

        if next_enabled {
            let src_trimmed = ext.source_url.trim();
            let is_remote = BrowserExtension::extract_chrome_store_id(src_trimmed).is_some()
                || src_trimmed.starts_with("http://")
                || src_trimmed.starts_with("https://");
            if is_remote && crate::launcher::is_placeholder_extension_dir(&target_dir) {
                let store_url = src_trimmed.to_string();
                let eid = ext.id.clone();
                let eid_task = ext.id.clone();
                let ename = ext.name.clone();
                let tokio_handle = self.tokio_handle.clone();
                let cancel_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let flag_for_task = cancel_flag.clone();
                let flag_for_ui = cancel_flag.clone();

                let join_handle = tokio_handle.spawn(async move {
                    crate::launcher::download_extension_from_url_cancellable(
                        &store_url,
                        Some(&eid_task),
                        &flag_for_task,
                    )
                    .await
                });
                self.ext_tasks
                    .insert(eid.clone(), (join_handle.abort_handle(), cancel_flag));
                self.banner_message = Some(format!("Downloading & activating {}...", ext.name));

                cx.spawn(async move |this, cx| {
                    let res = join_handle.await;
                    let _ = this.update(cx, |app, cx| {
                        if app
                            .ext_tasks
                            .get(&eid)
                            .is_some_and(|(_, f)| Arc::ptr_eq(f, &flag_for_ui))
                        {
                            app.ext_tasks.remove(&eid);
                        }
                        let still_enabled = app
                            .extensions
                            .iter()
                            .any(|e| e.id == eid && e.enabled);
                        if flag_for_ui.load(std::sync::atomic::Ordering::SeqCst) || !still_enabled {
                            cx.notify();
                            return;
                        }
                        match res {
                            Ok(Ok(_)) => {
                                app.banner_message =
                                    Some(format!("Activated & synced extension: {ename}"));
                            }
                            Ok(Err(e)) => {
                                if let Ok(db) = app.db.lock() {
                                    let _ = db.set_extension_enabled(&eid, false);
                                }
                                app.reload_extensions_only();
                                app.banner_message =
                                    Some(format!("Extension sync failed ({ename}): {e}"));
                            }
                            Err(e) if e.is_cancelled() => {}
                            Err(e) => {
                                if let Ok(db) = app.db.lock() {
                                    let _ = db.set_extension_enabled(&eid, false);
                                }
                                app.reload_extensions_only();
                                app.banner_message =
                                    Some(format!("Extension task error ({ename}): {e}"));
                            }
                        }
                        cx.notify();
                    });
                })
                .detach();
            } else {
                let _ = crate::launcher::ensure_extension_unpacked(&ext);
                self.banner_message = Some(format!("Enabled extension: {}", ext.name));
            }
        } else {
            if was_downloading && crate::launcher::is_placeholder_extension_dir(&target_dir) {
                crate::launcher::remove_extension_files(ext_id);
            }
            self.banner_message = Some(if was_downloading {
                format!("Stopped download & disabled extension: {}", ext.name)
            } else {
                format!("Disabled extension: {}", ext.name)
            });
        }
        cx.notify();
    }

    pub fn open_or_copy_extension_agent_cli(&mut self, ext_id: &str, cx: &mut Context<Self>) {
        let Some(ext) = self.extensions.iter().find(|e| e.id == ext_id).cloned() else {
            return;
        };
        let Some((_runtime_id, entry_url)) = crate::launcher::resolve_extension_runtime_info(&ext)
        else {
            self.banner_message = Some(format!("Enable '{}' first to unpack its manifest", ext.name));
            cx.notify();
            return;
        };

        let running_target = self
            .selected_profile_id
            .as_ref()
            .and_then(|pid| {
                let prof = self.profiles.iter().find(|p| &p.id == pid)?;
                match self.statuses.get(pid) {
                    Some(ProfileStatus::Running(info)) => {
                        Some((prof.short_id(), info.ws_url.clone()))
                    }
                    _ => None,
                }
            })
            .or_else(|| {
                self.profiles.iter().find_map(|p| match self.statuses.get(&p.id) {
                    Some(ProfileStatus::Running(info)) => {
                        Some((p.short_id(), info.ws_url.clone()))
                    }
                    _ => None,
                })
            });

        if let Some((short_id, ws_url)) = running_target {
            let cli = format!(
                "agent-browser --session bon_{short_id} tab new \"{entry_url}\" && agent-browser --session bon_{short_id} snapshot -i"
            );
            cx.write_to_clipboard(ClipboardItem::new_string(cli));
            let ename = ext.name.clone();
            let tokio_handle = self.tokio_handle.clone();
            self.banner_message = Some(format!(
                "Opening {} in bon_{short_id} & copied Agent CLI...",
                ext.name
            ));
            cx.notify();
            cx.spawn(async move |this, cx| {
                let res = tokio_handle
                    .spawn_blocking(move || {
                        crate::launcher::agent_open_extension_tab(&short_id, &ws_url, &entry_url)
                    })
                    .await;
                let _ = this.update(cx, |app, cx| {
                    if let Ok(Ok(next_cmd)) = res {
                        app.banner_message =
                            Some(format!("Opened {ename} tab! Next: {next_cmd}"));
                    }
                    cx.notify();
                });
            })
            .detach();
        } else {
            let cli = format!("agent-browser tab new \"{entry_url}\" && agent-browser snapshot -i");
            cx.write_to_clipboard(ClipboardItem::new_string(cli));
            self.banner_message = Some(format!(
                "Copied {} Agent CLI ({entry_url})",
                ext.name
            ));
            cx.notify();
        }
    }

    pub fn pick_extension_file_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let tokio_handle = self.tokio_handle.clone();
        let input_entity = self.ext_file_input.clone();
        cx.spawn_in(window, async move |this, cx| {
            let chosen = tokio_handle
                .spawn_blocking(|| {
                    let out = std::process::Command::new("osascript")
                        .args([
                            "-e",
                            "POSIX path of (choose file with prompt \"Choose Extension File (.CRX or .ZIP)\")",
                        ])
                        .output()
                        .ok()?;
                    if !out.status.success() {
                        return None;
                    }
                    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    (!s.is_empty()).then_some(s)
                })
                .await
                .ok()
                .flatten();

            if let Some(path_str) = chosen {
                let _ = this.update_in(cx, |app, window, cx| {
                    let _ = input_entity;
                    app.ext_file_input = cx.new(|cx| {
                        InputState::new(window, cx)
                            .placeholder("Path to .CRX or .ZIP file")
                            .default_value(path_str)
                    });
                    cx.notify();
                });
            }
        })
        .detach();
    }

    pub fn upload_extension_from_input(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let raw_path = self.ext_file_input.read(cx).value().trim().to_string();
        let tokio_handle = self.tokio_handle.clone();
        let db_arc = self.db.clone();
        self.banner_message = Some("Installing extension...".to_string());
        cx.notify();

        cx.spawn_in(window, async move |this, cx| {
            let res = tokio_handle
                .spawn_blocking(move || {
                    let path_str = if raw_path.is_empty() {
                        let out = std::process::Command::new("osascript")
                            .args([
                                "-e",
                                "POSIX path of (choose file with prompt \"Choose Extension File (.CRX or .ZIP)\")",
                            ])
                            .output()?;
                        if !out.status.success() {
                            anyhow::bail!("Canceled file selection");
                        }
                        String::from_utf8_lossy(&out.stdout).trim().to_string()
                    } else {
                        raw_path
                    };
                    if path_str.is_empty() {
                        anyhow::bail!("No extension file selected");
                    }
                    crate::launcher::install_extension_from_file(std::path::Path::new(&path_str))
                })
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Upload task error: {e}")));

            let _ = this.update_in(cx, |app, window, cx| {
                match res {
                    Ok(ext) => {
                        let ext_name = ext.name.clone();
                        if let Ok(db) = db_arc.lock() {
                            let _ = db.upsert_extension(&ext);
                        }
                        app.reload_profiles();
                        app.ext_file_input = cx.new(|cx| {
                            InputState::new(window, cx).placeholder("Path to .CRX or .ZIP file")
                        });
                        app.popup_modal = None;
                        app.banner_message = Some(format!("Uploaded extension: {ext_name}"));
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.contains("Canceled") {
                            app.banner_message = None;
                        } else {
                            app.banner_message = Some(format!("Upload Extension failed: {msg}"));
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn download_extension_from_url_input(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let url = self.ext_url_input.read(cx).value().trim().to_string();
        if url.is_empty() {
            self.banner_message = Some("Please paste a Chrome Web Store or .CRX/.ZIP URL".to_string());
            cx.notify();
            return;
        }
        if self.downloading_ext {
            return;
        }
        if let Some((handle, flag)) = self.ext_url_task.take() {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            handle.abort();
        }
        self.downloading_ext = true;
        self.banner_message = Some("Downloading extension...".to_string());
        cx.notify();

        let db_arc = self.db.clone();
        let tokio_handle = self.tokio_handle.clone();
        let cancel_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag_for_task = cancel_flag.clone();
        let flag_for_ui = cancel_flag.clone();
        self.ext_url_input = cx.new(|cx| InputState::new(window, cx).placeholder("Input URL"));

        let join_handle = tokio_handle.spawn(async move {
            crate::launcher::download_extension_from_url_cancellable(&url, None, &flag_for_task)
                .await
        });
        self.ext_url_task = Some((join_handle.abort_handle(), cancel_flag));

        cx.spawn(async move |this, cx| {
            let res = join_handle.await;
            let _ = this.update(cx, |app, cx| {
                if app
                    .ext_url_task
                    .as_ref()
                    .is_some_and(|(_, f)| Arc::ptr_eq(f, &flag_for_ui))
                {
                    app.ext_url_task = None;
                    app.downloading_ext = false;
                }
                if flag_for_ui.load(std::sync::atomic::Ordering::SeqCst) {
                    cx.notify();
                    return;
                }
                match res {
                    Ok(Ok(ext)) => {
                        let ext_name = ext.name.clone();
                        if let Ok(db) = db_arc.lock() {
                            let _ = db.upsert_extension(&ext);
                        }
                        app.reload_profiles();
                        app.popup_modal = None;
                        app.banner_message = Some(format!("Downloaded extension: {ext_name}"));
                    }
                    Ok(Err(e)) => {
                        app.banner_message = Some(format!("Download Extension error: {e}"));
                    }
                    Err(e) if e.is_cancelled() => {}
                    Err(e) => {
                        app.banner_message = Some(format!("Download task error: {e}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn request_delete(&mut self, action: PendingDeleteAction, cx: &mut Context<Self>) {
        self.pending_delete = Some(action);
        self.popup_modal = Some(ActivePopupModal::RemoveExtension);
        cx.notify();
    }

    pub fn confirm_pending_delete(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(action) = self.pending_delete.take() else {
            self.popup_modal = None;
            cx.notify();
            return;
        };
        self.popup_modal = None;
        match action {
            PendingDeleteAction::Profile(id) => {
                self.delete_profile(&id, window, cx);
            }
            PendingDeleteAction::CheckedProfiles => {
                self.delete_checked_profiles(window, cx);
            }
            PendingDeleteAction::PermanentProfile(id) => {
                self.permanently_delete_profile(&id, window, cx);
            }
            PendingDeleteAction::EmptyTrash => {
                self.empty_trash(window, cx);
            }
            PendingDeleteAction::Group(grp) => {
                self.delete_group_and_reset(&grp, window, cx);
            }
            PendingDeleteAction::Proxy(pid) => {
                self.delete_saved_proxy(&pid, cx);
            }
            PendingDeleteAction::CheckedProxies => {
                self.delete_checked_saved_proxies(cx);
            }
            PendingDeleteAction::Tag(tag) => {
                self.delete_tag_and_reset(&tag, cx);
            }
            PendingDeleteAction::Extension(ext_id) => {
                self.cancel_extension_task(&ext_id);
                let ext_name = self
                    .extensions
                    .iter()
                    .find(|e| e.id == ext_id)
                    .map(|e| e.name.clone())
                    .unwrap_or_else(|| ext_id.clone());
                let removed = self
                    .db
                    .lock()
                    .ok()
                    .and_then(|db| db.delete_extension(&ext_id).ok())
                    .unwrap_or(false);
                if removed {
                    crate::launcher::remove_extension_files(&ext_id);
                    self.reload_profiles();
                    self.banner_message = Some(format!("Removed extension: {ext_name}"));
                } else {
                    self.banner_message = Some("Default extensions cannot be deleted".to_string());
                }
                cx.notify();
            }
        }
    }

    pub fn filtered_profiles(&self) -> Vec<Profile> {
        let group_opt = (self.selected_group != "All").then_some(self.selected_group.as_str());
        self.profiles
            .iter()
            .filter(|p| p.matches_filter(&self.search_query, group_opt))
            .cloned()
            .collect()
    }

    pub fn distinct_groups_with_counts(&self) -> Vec<(String, usize)> {
        let mut out: Vec<(String, usize)> = self
            .saved_groups
            .iter()
            .map(|g| (g.clone(), 0))
            .collect();
        for p in &self.profiles {
            let tag = p.group_tag.trim();
            if tag.is_empty() {
                continue;
            }
            if let Some(entry) = out.iter_mut().find(|(g, _)| g.eq_ignore_ascii_case(tag)) {
                entry.1 += 1;
            } else {
                out.push((tag.to_string(), 1));
            }
        }
        out
    }

    pub fn open_create_modal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let default_name = format!("Profile-{:02}", self.profiles.len() + 1);
        let template = Profile::new_default(default_name, PlatformType::MacOS);
        self.modal = Some(ProfileModalState::from_profile(&template, false, window, cx));
        self.active_view = WorkspaceView::EditProfile;
        cx.notify();
    }

    pub fn save_modal_profile(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(modal) = self.modal.as_ref() else {
            return;
        };
        let cookies_raw = modal.cookies_input.read(cx).value().to_string();
        match modal.build_profile(cx) {
            Ok(profile) => {
                let normalized_cookies = if cookies_raw.trim().is_empty() {
                    None
                } else {
                    match crate::launcher::parse_and_normalize_cookies(
                        &cookies_raw,
                        Some(&profile.startup_url),
                    ) {
                        Ok(bundle) => Some(bundle),
                        Err(e) => {
                            if let Some(m) = self.modal.as_mut() {
                                m.active_tab = profile_modal::ProfileEditorTab::Cookies;
                                m.validation_error = Some(format!("Cookies error: {e}"));
                            }
                            cx.notify();
                            return;
                        }
                    }
                };

                if let Ok(db) = self.db.lock()
                    && let Err(e) = db.upsert_profile(&profile)
                {
                    if let Some(m) = self.modal.as_mut() {
                        m.validation_error = Some(format!("DB error: {e}"));
                    }
                    cx.notify();
                    return;
                }

                let short_id = profile.short_id();
                let payload_to_save = normalized_cookies
                    .as_ref()
                    .map(|b| b.to_state_json_pretty())
                    .unwrap_or_default();
                let _ = crate::launcher::save_prelaunch_cookies(&short_id, &payload_to_save);

                let saved_id = profile.id.clone();
                let saved_name = profile.name.clone();
                let live_pair = self.running_session_pair(&saved_id);
                self.reload_profiles();
                self.select_profile(&saved_id, window, cx);
                self.active_view = WorkspaceView::Profiles;

                if let (Some((sid, ws_url)), Some(bundle)) = (live_pair, normalized_cookies) {
                    let badge = bundle.summary_badge();
                    let state_str = bundle.to_state_json_pretty();
                    let tokio_handle = self.tokio_handle.clone();
                    let prof_name = saved_name.clone();
                    self.banner_message = Some(format!(
                        "Saved '{saved_name}' & injecting {badge} into live browser..."
                    ));
                    cx.notify();
                    cx.spawn(async move |this, cx| {
                        let res = tokio_handle
                            .spawn_blocking(move || {
                                crate::launcher::agent_import_state_or_cookies(
                                    &sid, &ws_url, &state_str,
                                )
                            })
                            .await
                            .unwrap_or_else(|e| Err(anyhow::anyhow!("Join error: {e}")));
                        let _ = this.update(cx, |app, cx| {
                            app.banner_message = Some(match res {
                                Ok(msg) => format!("Saved '{prof_name}' • {msg}"),
                                Err(e) => format!("Saved '{prof_name}', live cookie inject failed: {e}"),
                            });
                            cx.notify();
                        });
                    })
                    .detach();
                } else {
                    self.banner_message = Some(format!("Saved profile '{saved_name}'"));
                    cx.notify();
                }
            }
            Err(e) => {
                if let Some(m) = self.modal.as_mut() {
                    m.validation_error = Some(e.to_string());
                }
                cx.notify();
            }
        }
    }

    pub fn set_modal_cookies_text(
        &mut self,
        text: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(m) = self.modal.as_mut() else {
            return;
        };
        m.validation_error = None;
        m.cookies_input = cx.new(|cx| {
            crate::ui::input::TextareaState::new(window, cx)
                .rows(14)
                .placeholder("Paste Cookie-Editor JSON [...], State JSON, J2Team JSON, Netscape .txt, cURL, or key=value...")
                .default_value(text)
        });
        cx.notify();
    }

    pub fn pick_modal_cookie_file(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let tokio_handle = self.tokio_handle.clone();
        let startup_url = self
            .modal
            .as_ref()
            .map(|m| m.startup_url_input.read(cx).value().to_string())
            .unwrap_or_default();
        cx.spawn_in(window, async move |this, cx| {
            let loaded = tokio_handle
                .spawn_blocking(move || -> anyhow::Result<Option<(String, String)>> {
                    let out = std::process::Command::new("osascript")
                        .args([
                            "-e",
                            "POSIX path of (choose file with prompt \"Choose Cookie File (.json or .txt)\")",
                        ])
                        .output()?;
                    if !out.status.success() {
                        return Ok(None);
                    }
                    let path_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if path_str.is_empty() {
                        return Ok(None);
                    }
                    let raw = std::fs::read_to_string(&path_str)?;
                    Ok(Some((path_str, raw)))
                })
                .await
                .unwrap_or(Ok(None));

            let _ = this.update_in(cx, |app, window, cx| match loaded {
                Ok(Some((path_str, raw))) => {
                    match crate::launcher::parse_and_normalize_cookies(&raw, Some(&startup_url)) {
                        Ok(bundle) => {
                            let badge = bundle.summary_badge();
                            app.set_modal_cookies_text(bundle.to_state_json_pretty(), window, cx);
                            app.banner_message =
                                Some(format!("Imported {badge} from {path_str}"));
                        }
                        Err(e) => {
                            app.set_modal_cookies_text(raw, window, cx);
                            if let Some(m) = app.modal.as_mut() {
                                m.validation_error = Some(format!("Cookie file error: {e}"));
                            }
                        }
                    }
                    cx.notify();
                }
                Ok(None) => {}
                Err(e) => {
                    app.banner_message = Some(format!("Failed to read cookie file: {e}"));
                    cx.notify();
                }
            });
        })
        .detach();
    }

    pub fn paste_modal_cookies_from_clipboard(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(clip) = cx.read_from_clipboard().and_then(|item| item.text()) else {
            self.banner_message = Some("Clipboard is empty".to_string());
            cx.notify();
            return;
        };
        if clip.trim().is_empty() {
            self.banner_message = Some("Clipboard text is empty".to_string());
            cx.notify();
            return;
        }
        let startup_url = self
            .modal
            .as_ref()
            .map(|m| m.startup_url_input.read(cx).value().to_string())
            .unwrap_or_default();
        match crate::launcher::parse_and_normalize_cookies(&clip, Some(&startup_url)) {
            Ok(bundle) => {
                let badge = bundle.summary_badge();
                self.set_modal_cookies_text(bundle.to_state_json_pretty(), window, cx);
                self.banner_message = Some(format!("Pasted & normalized {badge}"));
            }
            Err(_) => {
                self.set_modal_cookies_text(clip, window, cx);
                self.banner_message = Some("Pasted raw text from clipboard".to_string());
            }
        }
        cx.notify();
    }

    pub fn format_modal_cookies(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(m) = self.modal.as_ref() else {
            return;
        };
        let raw = m.cookies_input.read(cx).value().to_string();
        let startup_url = m.startup_url_input.read(cx).value().to_string();
        if raw.trim().is_empty() {
            return;
        }
        match crate::launcher::parse_and_normalize_cookies(&raw, Some(&startup_url)) {
            Ok(bundle) => {
                let badge = bundle.summary_badge();
                self.set_modal_cookies_text(bundle.to_state_json_pretty(), window, cx);
                self.banner_message = Some(format!("Normalized {badge}"));
            }
            Err(e) => {
                if let Some(m) = self.modal.as_mut() {
                    m.validation_error = Some(format!("Cookie format error: {e}"));
                }
            }
        }
        cx.notify();
    }

    pub fn clone_profile(
        &mut self,
        profile_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(orig) = self.profiles.iter().find(|p| p.id == profile_id) else {
            return;
        };
        let src_sid = orig.short_id();
        let cloned = orig.cloned_with_new_seed();
        let new_id = cloned.id.clone();
        crate::launcher::copy_prelaunch_cookies(&src_sid, &cloned.short_id());
        if let Ok(db) = self.db.lock() {
            let _ = db.upsert_profile(&cloned);
        }
        self.reload_profiles();
        self.select_profile(&new_id, window, cx);
        self.banner_message = Some(format!(
            "Cloned '{}' -> seed #{}",
            cloned.name, cloned.seed
        ));
        cx.notify();
    }

    pub fn set_arrange_size_text(
        &mut self,
        text: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.arrange_size_input
            .update(cx, |input, cx| input.set_value(text, window, cx));
        cx.notify();
    }

    pub fn running_targets_for_arrange(&self) -> Vec<(u16, String)> {
        let use_checked = self.profiles.iter().any(|p| {
            self.checked_profile_ids.contains(&p.id)
                && matches!(self.statuses.get(&p.id), Some(ProfileStatus::Running(_)))
        });
        self.profiles
            .iter()
            .filter(|p| !use_checked || self.checked_profile_ids.contains(&p.id))
            .filter_map(|p| match self.statuses.get(&p.id) {
                Some(ProfileStatus::Running(info)) => Some((info.cdp_port, info.ws_url.clone())),
                _ => None,
            })
            .collect()
    }

    pub fn arrange_open_browsers(&mut self, cx: &mut Context<Self>) {
        let targets = self.running_targets_for_arrange();
        if targets.is_empty() {
            self.banner_message = Some("No open browsers to arrange".to_string());
            cx.notify();
            return;
        }
        let raw_size = self.arrange_size_input.read(cx).value().to_string();
        let Some((win_w, win_h)) = crate::launcher::parse_window_size(&raw_size) else {
            self.banner_message =
                Some("Invalid window size (use Width,Height e.g. 960,600)".to_string());
            cx.notify();
            return;
        };

        let displays = cx.displays();
        let disp_idx = self.arrange_display_idx.min(displays.len().saturating_sub(1));
        self.arrange_display_idx = disp_idx;
        let (mon_x, mon_y, mon_w, mon_h) = displays
            .get(disp_idx)
            .map(|d| {
                let b = d.bounds();
                (
                    f32::from(b.origin.x) as i32,
                    f32::from(b.origin.y) as i32,
                    f32::from(b.size.width) as i32,
                    f32::from(b.size.height) as i32,
                )
            })
            .unwrap_or((0, 0, 1440, 900));

        let placements = crate::launcher::compute_tile_bounds(
            mon_x,
            mon_y,
            mon_w,
            mon_h,
            win_w,
            win_h,
            targets.len(),
        );
        let tokio_handle = self.tokio_handle.clone();
        let disp_num = disp_idx + 1;
        cx.spawn(async move |this, cx| {
            let (ok_count, total, applied_w, applied_h) = tokio_handle
                .spawn_blocking(move || {
                    let total = targets.len();
                    let (applied_w, applied_h) = placements
                        .first()
                        .map(|&(_, _, w, h)| (w, h))
                        .unwrap_or((win_w, win_h));
                    let ok_count = std::thread::scope(|s| {
                        let handles: Vec<_> = targets
                            .into_iter()
                            .zip(placements)
                            .map(|((cdp_port, ws_url), (left, top, w, h))| {
                                s.spawn(move || {
                                    crate::launcher::cdp_set_window_bounds(
                                        cdp_port, &ws_url, left, top, w, h,
                                    )
                                    .is_ok()
                                })
                            })
                            .collect();
                        handles
                            .into_iter()
                            .filter_map(|h| h.join().ok().filter(|&ok| ok))
                            .count()
                    });
                    (ok_count, total, applied_w, applied_h)
                })
                .await
                .unwrap_or((0, 0, win_w, win_h));
            let _ = this.update(cx, |app, cx| {
                app.banner_message = Some(format!(
                    "Arranged {ok_count}/{total} open browser(s) to {applied_w}×{applied_h} on Display {disp_num}"
                ));
                cx.notify();
            });
        })
        .detach();
    }


    pub fn delete_profile(
        &mut self,
        profile_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(handle) = self.profile_tasks.remove(profile_id) {
            handle.abort();
        }
        if let Ok(mut map) = self.running_processes.lock()
            && let Some(mut proc) = map.remove(profile_id)
        {
            self.tokio_handle.spawn_blocking(move || {
                proc.stop_gracefully();
            });
        }
        if let Ok(db) = self.db.lock() {
            let _ = db.soft_delete_profile(profile_id);
        }
        self.statuses.remove(profile_id);
        self.checked_profile_ids.remove(profile_id);
        self.reload_profiles();
        if let Some(first) = self.profiles.first().map(|p| p.id.clone()) {
            self.select_profile(&first, window, cx);
        } else {
            self.selected_profile_id = None;
            self.modal = None;
        }
        self.banner_message =
            Some("Moved profile to Trash (restore anytime from Trash tab)".to_string());
        cx.notify();
    }

    pub fn permanently_delete_profile(
        &mut self,
        profile_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(handle) = self.profile_tasks.remove(profile_id) {
            handle.abort();
        }
        if let Ok(db) = self.db.lock() {
            let _ = db.delete_profile(profile_id);
        }
        let _ = crate::launcher::wipe_profile_data(profile_id);
        self.statuses.remove(profile_id);
        self.checked_profile_ids.remove(profile_id);
        self.reload_profiles();
        if let Some(first) = self.profiles.first().map(|p| p.id.clone()) {
            self.select_profile(&first, window, cx);
        }
        self.banner_message = Some("Permanently deleted profile and wiped browser data".to_string());
        cx.notify();
    }

    pub fn restore_trashed_profile(
        &mut self,
        profile_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Ok(db) = self.db.lock() {
            let _ = db.restore_profile(profile_id);
        }
        self.reload_profiles();
        self.select_profile(profile_id, window, cx);
        self.banner_message = Some("Restored profile from Trash".to_string());
        cx.notify();
    }

    pub fn restore_all_trashed_profiles(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let ids: Vec<String> = self.trashed_profiles.iter().map(|p| p.id.clone()).collect();
        let count = ids.len();
        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for id in &ids {
                    let _ = db.restore_profile(id);
                }
                Ok(())
            });
        }
        self.reload_profiles();
        if let Some(first) = self.profiles.first().map(|p| p.id.clone()) {
            self.select_profile(&first, window, cx);
        }
        self.profile_sub_tab = ProfileSubTab::Local;
        self.banner_message = Some(format!("Restored {count} profile(s) from Trash"));
        cx.notify();
    }

    pub fn empty_trash(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        let ids: Vec<String> = self.trashed_profiles.iter().map(|p| p.id.clone()).collect();
        let count = ids.len();
        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for id in &ids {
                    let _ = db.delete_profile(id);
                }
                Ok(())
            });
        }
        for id in &ids {
            let _ = crate::launcher::wipe_profile_data(id);
        }
        self.reload_profiles();
        self.banner_message = Some(format!("Emptied Trash ({count} profile(s) permanently deleted)"));
        cx.notify();
    }

    pub fn copy_profile_totp(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let Some(prof) = self.profiles.iter().find(|p| p.id == profile_id) else {
            return;
        };
        if let Some((code, rem)) = prof.current_totp() {
            cx.write_to_clipboard(ClipboardItem::new_string(code.clone()));
            self.banner_message = Some(format!(
                "Copied 2FA code for '{}': {code} (valid {rem}s)",
                prof.name
            ));
        } else {
            self.banner_message = Some("Invalid or empty 2FA secret on this profile".to_string());
        }
        cx.notify();
    }

    pub fn open_quick_meta_modal(
        &mut self,
        profile_id: Option<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.quick_meta_profile_id = profile_id.clone();
        let (tags, note, totp) = if let Some(pid) = &profile_id
            && let Some(p) = self.profiles.iter().find(|x| &x.id == pid)
        {
            (p.tags.clone(), p.notes.clone(), p.totp_secret.clone())
        } else {
            (Vec::new(), String::new(), String::new())
        };
        self.quick_meta_tags = tags;
        self.quick_meta_tag_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Custom tag (e.g. Shop-01, Tier1)...")
        });
        self.quick_meta_note_input = cx.new(|cx| {
            TextareaState::new(window, cx)
                .rows(4)
                .placeholder("Account note, recovery email, status...")
                .default_value(note)
        });
        self.quick_meta_totp_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Base32 2FA Secret or otpauth:// URI...")
                .default_value(totp)
        });
        self.popup_modal = Some(ActivePopupModal::QuickMeta);
        cx.notify();
    }

    pub fn save_quick_meta_modal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let tags = self.quick_meta_tags.clone();
        let note = self.quick_meta_note_input.read(cx).value().trim().to_string();
        let totp = self.quick_meta_totp_input.read(cx).value().trim().to_string();
        if let Some(pid) = self.quick_meta_profile_id.clone() {
            if let Ok(db) = self.db.lock() {
                let _ = db.update_profile_quick_meta(&pid, &note, &tags, &totp);
            }
            self.banner_message = Some("Updated tags, note & 2FA".to_string());
        } else {
            let targets: Vec<Profile> = self
                .profiles
                .iter()
                .filter(|p| self.checked_profile_ids.contains(&p.id))
                .cloned()
                .collect();
            let count = targets.len();
            if let Ok(db) = self.db.lock() {
                let _ = db.with_transaction(|db| {
                    for p in &targets {
                        let new_note = if note.is_empty() { &p.notes } else { &note };
                        let new_tags = if tags.is_empty() { &p.tags } else { &tags };
                        let _ = db.update_profile_quick_meta(&p.id, new_note, new_tags, &p.totp_secret);
                    }
                    Ok(())
                });
            }
            self.banner_message = Some(format!("Updated tags & note on {count} profile(s)"));
        }
        self.popup_modal = None;
        self.reload_profiles();
        if let Some(sel) = self.selected_profile_id.clone() {
            self.select_profile(&sel, window, cx);
        }
        cx.notify();
    }

    pub fn export_single_profile_zip(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let Some(prof) = self.profiles.iter().find(|p| p.id == profile_id).cloned() else {
            return;
        };
        let name = prof.name.clone();
        let tokio_handle = self.tokio_handle.clone();
        self.banner_message = Some(format!("Packing full .zip backup for '{name}'..."));
        cx.notify();
        cx.spawn(async move |this, cx| {
            let res = tokio_handle
                .spawn_blocking(move || crate::launcher::export_profile_archive_zip(&prof))
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Join error: {e}")));
            let _ = this.update(cx, |app, cx| {
                match res {
                    Ok(path) => {
                        let path_s = path.display().to_string();
                        cx.write_to_clipboard(ClipboardItem::new_string(path_s.clone()));
                        app.banner_message =
                            Some(format!("Exported backup (.zip): {path_s} (copied path)"));
                    }
                    Err(e) => {
                        app.banner_message = Some(format!("Backup export failed: {e}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn export_checked_profiles_zip(&mut self, cx: &mut Context<Self>) {
        let targets: Vec<Profile> = self
            .profiles
            .iter()
            .filter(|p| self.checked_profile_ids.contains(&p.id))
            .filter(|p| !matches!(self.statuses.get(&p.id), Some(ProfileStatus::Running(_))))
            .cloned()
            .collect();
        if targets.is_empty() {
            self.banner_message =
                Some("Stop running profiles before exporting full .zip archives".to_string());
            cx.notify();
            return;
        }
        let count = targets.len();
        let tokio_handle = self.tokio_handle.clone();
        self.banner_message = Some(format!("Packing {count} profile archive(s) (.zip)..."));
        cx.notify();
        cx.spawn(async move |this, cx| {
            let res = tokio_handle
                .spawn_blocking(move || {
                    let mut ok = 0usize;
                    let mut last_dir = String::new();
                    for prof in &targets {
                        if let Ok(path) = crate::launcher::export_profile_archive_zip(prof) {
                            ok += 1;
                            if let Some(parent) = path.parent() {
                                last_dir = parent.display().to_string();
                            }
                        }
                    }
                    (ok, last_dir)
                })
                .await
                .unwrap_or((0, String::new()));
            let _ = this.update(cx, |app, cx| {
                let (ok, dir) = res;
                app.banner_message =
                    Some(format!("Exported {ok}/{count} .zip archive(s) to {dir}"));
                cx.notify();
            });
        })
        .detach();
    }

    pub fn browse_and_import_backup_zip(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        let tokio_handle = self.tokio_handle.clone();
        cx.spawn(async move |this, cx| {
            let chosen = tokio_handle
                .spawn_blocking(|| {
                    let script = r#"POSIX path of (choose file with prompt "Select BonLogin Profile Backup (.zip)" of type {"zip"})"#;
                    std::process::Command::new("/usr/bin/osascript")
                        .args(["-e", script])
                        .output()
                        .ok()
                        .filter(|o| o.status.success())
                        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                        .filter(|s| !s.is_empty())
                })
                .await
                .ok()
                .flatten();
            if let Some(path) = chosen {
                let _ = this.update(cx, |app, cx| {
                    app.import_backup_zip_path(path, cx);
                });
            }
        })
        .detach();
    }

    pub fn import_backup_zip_from_input(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        let raw = self.backup_zip_input.read(cx).value().trim().to_string();
        if raw.is_empty() {
            self.banner_message = Some("Select or paste a .zip backup file path first".to_string());
            cx.notify();
            return;
        }
        self.import_backup_zip_path(raw, cx);
    }

    fn import_backup_zip_path(&mut self, raw: String, cx: &mut Context<Self>) {
        let existing_ids: HashSet<String> = self
            .profiles
            .iter()
            .chain(self.trashed_profiles.iter())
            .map(|p| p.id.clone())
            .collect();
        let tokio_handle = self.tokio_handle.clone();
        self.popup_modal = None;
        self.banner_message = Some("Restoring profile backup (.zip)...".to_string());
        cx.notify();
        cx.spawn(async move |this, cx| {
            let res = tokio_handle
                .spawn_blocking(move || {
                    crate::launcher::import_profile_archive_zip(
                        std::path::Path::new(&raw),
                        &existing_ids,
                    )
                })
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Join error: {e}")));
            let _ = this.update(cx, |app, cx| {
                match res {
                    Ok(restored) => {
                        let rid = restored.id.clone();
                        let rname = restored.name.clone();
                        if let Ok(db) = app.db.lock() {
                            let _ = db.upsert_profile(&restored);
                        }
                        app.reload_profiles();
                        app.selected_profile_id = Some(rid);
                        app.banner_message =
                            Some(format!("Restored profile '{rname}' from .zip backup"));
                    }
                    Err(e) => {
                        app.banner_message = Some(format!("Failed to import .zip backup: {e}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn open_cookie_robot_modal(
        &mut self,
        profile_id: Option<String>,
        cx: &mut Context<Self>,
    ) {
        self.cookie_robot_target_id = profile_id;
        self.popup_modal = Some(ActivePopupModal::CookieRobot);
        cx.notify();
    }

    pub fn start_cookie_robot(&mut self, cx: &mut Context<Self>) {
        let raw_urls = self.cookie_robot_urls_input.read(cx).value().to_string();
        let urls: Vec<String> = raw_urls
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
        if urls.is_empty() {
            self.banner_message = Some("Enter at least 1 warm-up URL".to_string());
            cx.notify();
            return;
        }
        let dwell = self.cookie_robot_dwell_secs;
        let target_ids: Vec<String> = if let Some(pid) = &self.cookie_robot_target_id {
            vec![pid.clone()]
        } else {
            self.checked_profile_ids.iter().cloned().collect()
        };
        if target_ids.is_empty() {
            return;
        }
        let targets: Vec<Profile> = self
            .profiles
            .iter()
            .filter(|p| target_ids.contains(&p.id))
            .cloned()
            .collect();
        let total_urls = urls.len();
        self.banner_message = Some(format!(
            "Cookie Robot started for {} profile(s) ({total_urls} sites, {dwell}s each)...",
            targets.len()
        ));
        cx.notify();

        for prof in targets {
            let pid = prof.id.clone();
            let pid_task = pid.clone();
            let short_id = prof.short_id();
            let prof_name = prof.name.clone();
            let urls_clone = urls.clone();
            let existing_ws = match self.statuses.get(&pid) {
                Some(ProfileStatus::Starting(_)) => continue,
                Some(ProfileStatus::Running(info)) => Some(info.ws_url.clone()),
                _ => None,
            };
            if let Some(prev) = self.profile_tasks.remove(&pid) {
                prev.abort();
            }
            if existing_ws.is_none() {
                self.statuses.insert(
                    pid.clone(),
                    ProfileStatus::Starting("Warming up...".to_string()),
                );
            }
            let tokio_handle = self.tokio_handle.clone();
            let db = self.db.clone();
            let running_procs = self.running_processes.clone();
            let join_handle = tokio_handle.spawn(async move {
                let ws_url = if let Some(ws) = existing_ws {
                    ws
                } else {
                    let (proc, geo) = crate::launcher::launch_profile(&prof).await?;
                    let ws = proc.info.ws_url.clone();
                    if let Ok(db_guard) = db.lock() {
                        if let Some(g) = &geo {
                            let _ = db_guard.update_resolved_geo(&pid, Some(g));
                        }
                        let _ = db_guard.touch_last_launched(&pid);
                    }
                    if let Ok(mut map) = running_procs.lock() {
                        map.insert(pid.clone(), proc);
                    }
                    ws
                };
                tokio::task::spawn_blocking(move || {
                    crate::launcher::run_cookie_robot_warmup(&short_id, &ws_url, &urls_clone, dwell)
                })
                .await?
            });
            self.profile_tasks
                .insert(pid_task.clone(), join_handle.abort_handle());
            cx.spawn(async move |this, cx| {
                let join_res = join_handle.await;
                let _ = this.update(cx, |app, cx| {
                    app.profile_tasks.remove(&pid_task);
                    let res = match join_res {
                        Ok(r) => r,
                        Err(e) if e.is_cancelled() => return,
                        Err(e) => Err(anyhow::anyhow!("Warm-up task error: {e}")),
                    };
                    let live_info = app
                        .running_processes
                        .lock()
                        .ok()
                        .and_then(|m| m.get(&pid_task).map(|p| p.info.clone()));
                    match res {
                        Ok(visited) => {
                            if let Some(info) = live_info {
                                app.statuses.insert(pid_task.clone(), ProfileStatus::Running(info));
                            }
                            app.reload_profiles();
                            app.banner_message = Some(format!(
                                "Cookie Robot finished '{prof_name}': visited {visited}/{total_urls} sites & saved cookies"
                            ));
                        }
                        Err(e) => {
                            if let Some(info) = live_info {
                                app.statuses.insert(pid_task.clone(), ProfileStatus::Running(info));
                            } else {
                                app.statuses
                                    .insert(pid_task.clone(), ProfileStatus::Error(e.to_string()));
                            }
                            app.banner_message =
                                Some(format!("Cookie Robot failed on '{prof_name}': {e}"));
                        }
                    }
                    cx.notify();
                });
            })
            .detach();
        }
    }


    pub fn toggle_check_profile(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        if !self.checked_profile_ids.remove(profile_id) {
            self.checked_profile_ids.insert(profile_id.to_string());
        }
        cx.notify();
    }

    pub fn toggle_check_all_filtered(&mut self, cx: &mut Context<Self>) {
        let filtered_ids: Vec<String> = self
            .filtered_profiles()
            .into_iter()
            .map(|p| p.id)
            .collect();
        if filtered_ids.is_empty() {
            return;
        }
        let all_checked = filtered_ids
            .iter()
            .all(|id| self.checked_profile_ids.contains(id));
        if all_checked {
            for id in filtered_ids {
                self.checked_profile_ids.remove(&id);
            }
        } else {
            for id in filtered_ids {
                self.checked_profile_ids.insert(id);
            }
        }
        cx.notify();
    }

    pub fn clear_checked_profiles(&mut self, cx: &mut Context<Self>) {
        self.checked_profile_ids.clear();
        cx.notify();
    }

    pub fn launch_checked_profiles(&mut self, cx: &mut Context<Self>) {
        let ids: Vec<String> = self
            .profiles
            .iter()
            .filter(|p| self.checked_profile_ids.contains(&p.id))
            .filter(|p| !matches!(self.statuses.get(&p.id), Some(ProfileStatus::Running(_))))
            .map(|p| p.id.clone())
            .collect();
        for id in ids {
            self.launch_profile(&id, cx);
        }
    }

    pub fn stop_checked_profiles(&mut self, cx: &mut Context<Self>) {
        let ids: Vec<String> = self
            .checked_profile_ids
            .iter()
            .filter(|id| {
                matches!(
                    self.statuses.get(*id),
                    Some(ProfileStatus::Running(_) | ProfileStatus::Starting(_))
                )
            })
            .cloned()
            .collect();
        for id in ids {
            self.stop_profile(&id, cx);
        }
    }

    pub fn check_proxies_for_checked(&mut self, cx: &mut Context<Self>) {
        let ids: Vec<String> = self.checked_profile_ids.iter().cloned().collect();
        for id in ids {
            self.check_profile_proxy(&id, cx);
        }
    }

    pub fn move_checked_profiles_from_input(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let target_group = self.batch_selected_group.trim().to_string();
        let mut moved = 0usize;
        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for mut prof in self
                    .profiles
                    .iter()
                    .filter(|p| self.checked_profile_ids.contains(&p.id))
                    .cloned()
                {
                    prof.group_tag = target_group.clone();
                    if db.upsert_profile(&prof).is_ok() {
                        moved += 1;
                    }
                }
                Ok(())
            });
        }
        self.reload_profiles();
        if let Some(sel) = self.selected_profile_id.clone() {
            self.select_profile(&sel, window, cx);
        }
        self.banner_message = Some(if target_group.is_empty() {
            format!("Removed group from {moved} profile(s)")
        } else {
            format!("Moved {moved} profile(s) to folder '{target_group}'")
        });
        cx.notify();
    }

    pub fn copy_checked_ids_to_clipboard(&mut self, cx: &mut Context<Self>) {
        let rows: Vec<String> = self
            .profiles
            .iter()
            .filter(|p| self.checked_profile_ids.contains(&p.id))
            .map(|p| {
                let proxy_str = p
                    .proxy
                    .as_ref()
                    .map(|px| px.display_short())
                    .unwrap_or_else(|| "direct".to_string());
                format!("{}\t{}\t{}\t{}", p.id, p.name, p.group_tag, proxy_str)
            })
            .collect();
        let count = rows.len();
        cx.write_to_clipboard(ClipboardItem::new_string(rows.join("\n")));
        self.banner_message = Some(format!(
            "Copied {count} profile row(s) (ID, Name, Folder, Proxy) to clipboard"
        ));
        cx.notify();
    }

    pub fn copy_checked_names_to_clipboard(&mut self, cx: &mut Context<Self>) {
        let names: Vec<String> = self
            .profiles
            .iter()
            .filter(|p| self.checked_profile_ids.contains(&p.id))
            .map(|p| p.name.clone())
            .collect();
        let count = names.len();
        cx.write_to_clipboard(ClipboardItem::new_string(names.join("\n")));
        self.banner_message = Some(format!("Copied {count} profile name(s) to clipboard"));
        cx.notify();
    }

    pub fn batch_update_checked_profiles(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let targets: Vec<Profile> = self
            .profiles
            .iter()
            .filter(|p| self.checked_profile_ids.contains(&p.id))
            .cloned()
            .collect();
        if targets.is_empty() {
            self.banner_message = Some("Check at least 1 profile first".to_string());
            cx.notify();
            return;
        }
        let prefix = self.batch_prefix_input.read(cx).value().trim().to_string();
        let group = self.batch_selected_group.trim().to_string();
        let pool = self.proxies_for_batch_group();
        let target_os = self.batch_os;
        let target_brand = self.batch_brand;
        let mut updated = 0usize;

        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for (idx, mut prof) in targets.into_iter().enumerate() {
                    prof.seed = crate::models::Profile::random_seed();
                    prof.os_platform = target_os;
                    prof.os_version = target_os.os_version_for_seed(prof.seed).to_string();
                    prof.brand = target_brand;
                    prof.brand_version = target_brand.version_for_seed(prof.seed).to_string();
                    prof.gpu_spoofing = crate::models::GpuSpoofMode::SeedGenerated;
                    prof.hardware_concurrency = target_os.optimal_cores_for_seed(prof.seed);
                    prof.window_size = target_os.default_window_size().to_string();
                    if !prefix.is_empty() && prefix != "Profile" {
                        prof.name = format!("{prefix}-{:02}", idx + 1);
                    }
                    if !group.is_empty() {
                        prof.group_tag = group.clone();
                    }
                    if !pool.is_empty() {
                        let chosen = &pool[idx % pool.len()];
                        prof.proxy = Some(chosen.config.clone());
                        prof.resolved_geo = chosen.resolved_geo.clone();
                    }
                    if db.upsert_profile(&prof).is_ok() {
                        updated += 1;
                    }
                }
                Ok(())
            });
        }
        self.reload_profiles();
        if let Some(sel) = self.selected_profile_id.clone() {
            self.select_profile(&sel, window, cx);
        }
        self.active_view = WorkspaceView::Profiles;
        self.banner_message = Some(format!(
            "Batch updated {updated} checked profile(s) ({})",
            target_os.label()
        ));
        cx.notify();
    }

    pub fn export_profile_cookies_json(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let Some(prof) = self.profiles.iter().find(|p| p.id == profile_id).cloned() else {
            return;
        };
        if let Some((short_id, ws_url)) = self.running_session_pair(profile_id) {
            let prof_name = prof.name.clone();
            let tokio_handle = self.tokio_handle.clone();
            self.banner_message = Some(format!("Exporting live cookies for '{prof_name}'..."));
            cx.notify();
            cx.spawn(async move |this, cx| {
                let sid = short_id.clone();
                let res = tokio_handle
                    .spawn_blocking(move || crate::launcher::agent_export_state(&sid, &ws_url))
                    .await
                    .unwrap_or_else(|e| Err(anyhow::anyhow!("Join error: {e}")));
                let _ = this.update(cx, |app, cx| {
                    match res {
                        Ok((path, json)) => {
                            let _ = crate::launcher::save_prelaunch_cookies(&short_id, &json);
                            cx.write_to_clipboard(ClipboardItem::new_string(json));
                            app.banner_message = Some(format!(
                                "Exported live cookies for '{prof_name}' to clipboard & {}",
                                path.display()
                            ));
                        }
                        Err(e) => {
                            app.banner_message = Some(format!("Export cookies failed: {e}"));
                        }
                    }
                    cx.notify();
                });
            })
            .detach();
        } else {
            let sid = prof.short_id();
            let saved = crate::launcher::read_prelaunch_cookies(&sid);
            let payload = if !saved.trim().is_empty() {
                saved
            } else {
                let state_path = crate::launcher::app_support_dir()
                    .join("states")
                    .join(format!("bon_{sid}_state.json"));
                std::fs::read_to_string(state_path)
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| "[]".to_string())
            };
            cx.write_to_clipboard(ClipboardItem::new_string(payload));
            self.banner_message = Some(format!(
                "Exported cookies JSON for '{}' to clipboard",
                prof.name
            ));
            cx.notify();
        }
    }

    pub fn copy_single_profile_proxy(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let Some(prof) = self.profiles.iter().find(|p| p.id == profile_id) else {
            return;
        };
        let text = prof
            .proxy
            .as_ref()
            .map(|p| p.to_editable_string())
            .unwrap_or_else(|| "Local IP".to_string());
        cx.write_to_clipboard(ClipboardItem::new_string(text.clone()));
        self.banner_message = Some(format!("Copied proxy: {text}"));
        cx.notify();
    }

    pub fn copy_agent_browser_cli(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let Some(prof) = self.profiles.iter().find(|p| p.id == profile_id) else {
            return;
        };
        let short_id = prof.short_id();
        let cmd = if let Some(ProfileStatus::Running(info)) = self.statuses.get(profile_id) {
            let sid = short_id.clone();
            let ws = info.ws_url.clone();
            self.tokio_handle.spawn_blocking(move || {
                let _ = crate::launcher::agent_sync_targets(&sid, &ws);
            });
            format!(
                "{} && agent-browser --session bon_{short_id} snapshot -i -c",
                info.agent_browser_cli(&short_id)
            )
        } else {
            format!("bon-login agent {short_id} snapshot -i -c")
        };
        cx.write_to_clipboard(ClipboardItem::new_string(cmd.clone()));
        self.banner_message = Some(format!(
            "Copied Agent CLI & synced popups (session bon_{short_id})"
        ));
        cx.notify();
    }

    pub fn delete_group_and_reset(
        &mut self,
        group_name: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Ok(db) = self.db.lock() {
            let _ = db.delete_group(group_name);
        }
        self.reload_profiles();
        if self.selected_group.eq_ignore_ascii_case(group_name) {
            self.selected_group = "All".to_string();
        }
        if self.batch_selected_group.eq_ignore_ascii_case(group_name) {
            self.batch_selected_group = self.saved_groups.first().cloned().unwrap_or_default();
        }
        if let Some(sel) = self.selected_profile_id.clone() {
            self.select_profile(&sel, window, cx);
        }
        self.banner_message = Some(format!("Removed group '{group_name}'"));
        cx.notify();
    }

    pub fn create_group_from_modal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let g = self.batch_move_group_input.read(cx).value().trim().to_string();
        if g.is_empty() {
            return;
        }
        if let Ok(db) = self.db.lock() {
            let _ = db.insert_group(&g);
        }
        self.batch_move_group_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("Enter new name..."));
        self.reload_profiles();
        self.batch_selected_group = g.clone();
        if let Some(m) = self.modal.as_mut() {
            m.selected_group = g.clone();
        }
        self.banner_message = Some(format!("Created group '{g}'"));
        cx.notify();
    }

    pub fn create_tag_from_modal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let t = self.batch_move_group_input.read(cx).value().trim().to_string();
        if t.is_empty() {
            return;
        }
        if let Ok(db) = self.db.lock() {
            let _ = db.insert_tag(&t);
        }
        self.batch_move_group_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("Enter new name..."));
        self.reload_profiles();
        self.proxy_selected_tag = t.clone();
        self.banner_message = Some(format!("Created proxy tag '#{t}'"));
        cx.notify();
    }

    pub fn delete_tag_and_reset(&mut self, tag_name: &str, cx: &mut Context<Self>) {
        if let Ok(db) = self.db.lock() {
            let _ = db.delete_tag(tag_name);
        }
        self.reload_profiles();
        if self.selected_proxy_group.eq_ignore_ascii_case(tag_name) {
            self.selected_proxy_group = "All".to_string();
        }
        if self.proxy_selected_tag.eq_ignore_ascii_case(tag_name) {
            self.proxy_selected_tag = self.saved_tags.first().cloned().unwrap_or_default();
        }
        self.banner_message = Some(format!("Removed proxy tag '#{tag_name}'"));
        cx.notify();
    }

    pub fn assign_single_saved_proxy_to_checked(
        &mut self,
        proxy_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(sp) = self.saved_proxies.iter().find(|p| p.id == proxy_id).cloned() else {
            return;
        };
        let targets: Vec<Profile> = self
            .profiles
            .iter()
            .filter(|p| self.checked_profile_ids.contains(&p.id))
            .cloned()
            .collect();
        let mut updated = 0usize;
        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for mut prof in targets {
                    prof.proxy = Some(sp.config.clone());
                    prof.resolved_geo = sp.resolved_geo.clone();
                    if db.upsert_profile(&prof).is_ok() {
                        updated += 1;
                    }
                }
                Ok(())
            });
        }
        self.reload_profiles();
        if let Some(sel) = self.selected_profile_id.clone() {
            self.select_profile(&sel, window, cx);
        }
        self.banner_message = Some(format!(
            "Assigned proxy '{}' (#{}) to {updated} profile(s)",
            sp.name, sp.group_tag
        ));
        cx.notify();
    }

    pub fn batch_update_proxies_for_checked(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let targets: Vec<Profile> = self
            .profiles
            .iter()
            .filter(|p| self.checked_profile_ids.contains(&p.id))
            .cloned()
            .collect();
        if targets.is_empty() {
            return;
        }
        let pool = self.proxies_for_batch_group();
        if self.batch_proxy_group != "None" && pool.is_empty() {
            self.banner_message =
                Some("No proxies in Proxy manager yet. Open Proxy manager to add proxies first.".to_string());
            cx.notify();
            return;
        }
        let mut updated = 0usize;
        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for (idx, mut prof) in targets.into_iter().enumerate() {
                    if self.batch_proxy_group == "None" {
                        prof.proxy = None;
                        prof.resolved_geo = None;
                    } else {
                        let chosen = &pool[idx % pool.len()];
                        prof.proxy = Some(chosen.config.clone());
                        prof.resolved_geo = chosen.resolved_geo.clone();
                    }
                    if db.upsert_profile(&prof).is_ok() {
                        updated += 1;
                    }
                }
                Ok(())
            });
        }
        self.reload_profiles();
        if let Some(sel) = self.selected_profile_id.clone() {
            self.select_profile(&sel, window, cx);
        }
        self.banner_message = Some(if self.batch_proxy_group == "None" {
            format!("Cleared proxy (Without proxy) on {updated} profile(s)")
        } else {
            format!("Updated proxies from Proxy manager on {updated} profile(s)")
        });
        cx.notify();
    }

    pub fn delete_checked_profiles(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let deletable_ids: Vec<String> = self
            .checked_profile_ids
            .iter()
            .filter(|id| !matches!(self.statuses.get(*id), Some(ProfileStatus::Running(_))))
            .cloned()
            .collect();
        if deletable_ids.is_empty() {
            self.banner_message =
                Some("Stop running profiles before moving them to Trash".to_string());
            cx.notify();
            return;
        }
        let count = deletable_ids.len();
        for id in &deletable_ids {
            if let Some(handle) = self.profile_tasks.remove(id) {
                handle.abort();
            }
        }
        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for id in &deletable_ids {
                    let _ = db.soft_delete_profile(id);
                }
                Ok(())
            });
        }
        for id in &deletable_ids {
            self.statuses.remove(id);
            self.checked_profile_ids.remove(id);
        }
        self.reload_profiles();
        if let Some(first) = self.profiles.first().map(|p| p.id.clone()) {
            self.select_profile(&first, window, cx);
        } else {
            self.selected_profile_id = None;
            self.modal = None;
        }
        self.banner_message = Some(format!(
            "Moved {count} profile(s) to Trash (restore anytime from Trash tab)"
        ));
        cx.notify();
    }

    pub fn check_profile_proxy(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let Some(profile) = self.profiles.iter().find(|p| p.id == profile_id).cloned() else {
            return;
        };
        let pid = profile.id.clone();
        let was_running = matches!(self.statuses.get(&pid), Some(ProfileStatus::Running(_)));
        if !was_running {
            if let Some(prev) = self.profile_tasks.remove(&pid) {
                prev.abort();
            }
            self.statuses.insert(
                pid.clone(),
                ProfileStatus::Starting("Checking proxy...".to_string()),
            );
        }
        self.banner_message = Some(format!("Checking proxy for '{}'...", profile.name));
        cx.notify();

        let tokio_handle = self.tokio_handle.clone();
        let db = self.db.clone();
        let proxy_for_sync = profile.proxy.clone();

        let join_handle = tokio_handle.spawn(async move {
            if let Some(proxy_cfg) = profile.proxy {
                crate::launcher::check_proxy_config_live(&proxy_cfg).await
            } else {
                crate::geoip::resolve_geo_via_port(None).await
            }
        });
        let abort_handle = join_handle.abort_handle();
        let task_id = abort_handle.id();
        if !was_running {
            self.profile_tasks.insert(pid.clone(), abort_handle);
        }

        cx.spawn(async move |this, cx| {
            let join_res = join_handle.await;
            let _ = this.update(cx, |app, cx| {
                if app
                    .profile_tasks
                    .get(&pid)
                    .is_some_and(|h| h.id() == task_id)
                {
                    app.profile_tasks.remove(&pid);
                }
                let res = match join_res {
                    Ok(r) => r,
                    Err(e) if e.is_cancelled() => return,
                    Err(e) => Err(anyhow::anyhow!("Task join error: {e}")),
                };
                if !app.profiles.iter().any(|p| p.id == pid) {
                    return;
                }
                let still_running =
                    matches!(app.statuses.get(&pid), Some(ProfileStatus::Running(_)));
                match res {
                    Ok(geo) => {
                        if let Ok(db_guard) = db.lock() {
                            if let Some(cfg) = &proxy_for_sync {
                                let _ = db_guard.sync_geo_for_proxy_endpoint(cfg, &geo);
                            } else {
                                let _ = db_guard.update_resolved_geo(&pid, Some(&geo));
                            }
                        }
                        app.reload_profiles();
                        if !still_running {
                            app.statuses.insert(pid.clone(), ProfileStatus::Stopped);
                        }
                        app.banner_message = Some(format!("Proxy OK: {}", geo.summary_badge()));
                    }
                    Err(e) => {
                        let err_s = e.to_string();
                        if !still_running {
                            app.statuses
                                .insert(pid.clone(), ProfileStatus::Error(err_s.clone()));
                        }
                        app.banner_message = Some(format!("Proxy check failed: {err_s}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn launch_profile(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        if matches!(
            self.statuses.get(profile_id),
            Some(ProfileStatus::Running(_) | ProfileStatus::Starting(_))
        ) {
            return;
        }
        let Some(profile) = self.profiles.iter().find(|p| p.id == profile_id).cloned() else {
            return;
        };
        let pid = profile.id.clone();
        let short_id = profile.short_id();
        if let Some(prev) = self.profile_tasks.remove(&pid) {
            prev.abort();
        }
        self.statuses.insert(
            pid.clone(),
            ProfileStatus::Starting("Starting...".to_string()),
        );
        cx.notify();

        let tokio_handle = self.tokio_handle.clone();
        let db = self.db.clone();

        let join_handle =
            tokio_handle.spawn(async move { crate::launcher::launch_profile(&profile).await });
        let abort_handle = join_handle.abort_handle();
        let task_id = abort_handle.id();
        self.profile_tasks.insert(pid.clone(), abort_handle);

        cx.spawn(async move |this, cx| {
            let join_res = join_handle.await;
            let _ = this.update(cx, |app, cx| {
                if app
                    .profile_tasks
                    .get(&pid)
                    .is_some_and(|h| h.id() == task_id)
                {
                    app.profile_tasks.remove(&pid);
                }
                let still_starting =
                    matches!(app.statuses.get(&pid), Some(ProfileStatus::Starting(_)));
                let res = match join_res {
                    Ok(r) => r,
                    Err(e) if e.is_cancelled() => return,
                    Err(e) => Err(anyhow::anyhow!("Launch task error: {e}")),
                };
                if !still_starting || !app.profiles.iter().any(|p| p.id == pid) {
                    if let Ok((mut running_proc, _)) = res {
                        app.tokio_handle.spawn_blocking(move || {
                            running_proc.stop_gracefully();
                        });
                    }
                    return;
                }
                match res {
                    Ok((running_proc, maybe_geo)) => {
                        let info = running_proc.info.clone();
                        if let Ok(db_guard) = db.lock() {
                            if let Some(geo) = &maybe_geo {
                                let _ = db_guard.update_resolved_geo(&pid, Some(geo));
                            }
                            let _ = db_guard.touch_last_launched(&pid);
                        }
                        if let Ok(mut map) = app.running_processes.lock() {
                            map.insert(pid.clone(), running_proc);
                        }
                        app.reload_profiles();
                        app.statuses
                            .insert(pid.clone(), ProfileStatus::Running(info.clone()));
                        app.banner_message = Some(format!(
                            "Launched PID {} • Agent session: bon_{short_id} (port {})",
                            info.pid, info.cdp_port
                        ));
                    }
                    Err(e) => {
                        app.statuses
                            .insert(pid.clone(), ProfileStatus::Error(e.to_string()));
                        app.banner_message = Some(format!("Launch blocked: {e}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn stop_profile(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let cancelled_starting = if let Some(handle) = self.profile_tasks.remove(profile_id) {
            handle.abort();
            true
        } else {
            false
        };
        let short_id = self
            .profiles
            .iter()
            .find(|p| p.id == profile_id)
            .map(|p| p.short_id())
            .unwrap_or_default();
        if let Ok(mut map) = self.running_processes.lock()
            && let Some(mut proc) = map.remove(profile_id)
        {
            self.tokio_handle.spawn_blocking(move || {
                proc.stop_gracefully();
            });
        } else if !cancelled_starting {
            let pid_s = profile_id.to_string();
            self.tokio_handle.spawn_blocking(move || {
                crate::launcher::stop_external_runtime(&pid_s, &short_id);
            });
        }
        self.statuses
            .insert(profile_id.to_string(), ProfileStatus::Stopped);
        self.banner_message = Some(if cancelled_starting {
            "Stopped starting profile".to_string()
        } else {
            "Stopped browser session (cookies flushed)".to_string()
        });
        cx.notify();
    }

    fn running_session_pair(&self, profile_id: &str) -> Option<(String, String)> {
        let profile = self.profiles.iter().find(|p| p.id == profile_id)?;
        let ProfileStatus::Running(info) = self.statuses.get(profile_id)? else {
            return None;
        };
        Some((profile.short_id(), info.ws_url.clone()))
    }


    pub fn install_kernel(&mut self, cx: &mut Context<Self>) {
        if self.installing_kernel {
            return;
        }
        self.installing_kernel = true;
        self.banner_message = Some(
            "Downloading & installing adryfish/fingerprint-chromium 148.0.7778.215 (~140MB)..."
                .to_string(),
        );
        cx.notify();

        let tokio_handle = self.tokio_handle.clone();
        cx.spawn(async move |this, cx| {
            let res = tokio_handle
                .spawn_blocking(crate::launcher::install_adryfish_kernel_blocking)
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Kernel install join error: {e}")));

            let _ = this.update(cx, |app, cx| {
                app.installing_kernel = false;
                match res {
                    Ok(info) => {
                        app.banner_message = Some(format!(
                            "Kernel installed & unquarantined: {}",
                            info.path.display()
                        ));
                        app.kernel_info = Some(info);
                    }
                    Err(e) => {
                        app.banner_message = Some(format!("Kernel install failed: {e}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }
}

impl Render for BonLoginApp {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if self.banner_message != self.banner_timer_for {
            self.banner_timer_for = self.banner_message.clone();
            if let Some(msg) = self.banner_message.clone()
                && !msg.ends_with("...")
            {
                cx.spawn(async move |this, cx| {
                    cx.background_executor()
                        .timer(Duration::from_millis(3200))
                        .await;
                    let _ = this.update(cx, |app, cx| {
                        if app.banner_message.as_deref() == Some(msg.as_str()) {
                            app.banner_message = None;
                            app.banner_timer_for = None;
                            cx.notify();
                        }
                    });
                })
                .detach();
            }
        }
        let total_count = self.profiles.len();
        let filtered = self.filtered_profiles();
        let folder_counts = self.distinct_groups_with_counts();
        let group_count = folder_counts.len();
        let proxy_group_counts = self.distinct_proxy_groups_with_counts();
        let selected_group = self.selected_group.clone();
        let selected_id = self.selected_profile_id.clone();
        let active_view = self.active_view;
        let sub_tab = self.profile_sub_tab;
        let popup_modal = self.popup_modal;
        let show_drawer = self.show_detail_drawer;
        let (kernel_dot, kernel_label) = match &self.kernel_info {
            Some(_) => (BonTheme::success(), "Chromium 148 Online".to_string()),
            None => (BonTheme::warning(), "Engine Missing".to_string()),
        };

        let is_editing_existing = active_view == WorkspaceView::EditProfile
            && self
                .modal
                .as_ref()
                .and_then(|m| m.editing_id.as_ref())
                .is_some();
        let is_creating_profile =
            active_view == WorkspaceView::EditProfile && !is_editing_existing;
        let is_profiles_nav_active =
            active_view == WorkspaceView::Profiles || is_editing_existing;

        let page_title = match active_view {
            WorkspaceView::Profiles => "Profiles",
            WorkspaceView::Proxies => "Proxy management",
            WorkspaceView::EditProfile => {
                if is_editing_existing {
                    "Setting Profile"
                } else {
                    "Create Profile"
                }
            }
            WorkspaceView::Extensions => "Extensions",
        };
        let app_entity = cx.entity().clone();

        div()
            .relative()
            .size_full()
            .font_family("SF Pro")
            .bg(BonTheme::bg_canvas())
            .text_color(BonTheme::text_primary())
            .child(
                h_flex()
                    .size_full()
            // 1. GenLogin 3.0 Left Sidebar (`docs/genlogin-3.0/assets/menu-bar_profile_cloud-vs-local_01.png`)
            // ================================================================
            .child(
                v_flex()
                    .w(px(218.))
                    .h_full()
                    .flex_shrink_0()
                    .pt(px(44.))
                    .pb_3p5()
                    .px_3()
                    .justify_between()
                    .bg(BonTheme::bg_sidebar())
                    .border_r_1()
                    .border_color(BonTheme::border())
                    .child(
                        v_flex()
                            .w_full()
                            .gap_3p5()
                            // BonLogin Brand Header under macOS Traffic Lights
                            .child(
                                h_flex()
                                    .px_1p5()
                                    .gap_2p5()
                                    .items_center()
                                    .child({
                                        static LOGO_IMG: LazyLock<Arc<Image>> = LazyLock::new(|| {
                                            Arc::new(Image::from_bytes(
                                                ImageFormat::Svg,
                                                include_bytes!("../../assets/bonlogin-logo.svg")
                                                    .to_vec(),
                                            ))
                                        });
                                        img(LOGO_IMG.clone())
                                            .w(px(32.))
                                            .h(px(32.))
                                            .flex_shrink_0()
                                    })
                                    .child(
                                        v_flex()
                                            .gap_0()
                                            .child(
                                                h_flex()
                                                    .items_center()
                                                    .child(
                                                        div()
                                                            .text_sm()
                                                            .font_bold()
                                                            .text_color(BonTheme::text_primary())
                                                            .child("Bon"),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_sm()
                                                            .font_bold()
                                                            .text_color(BonTheme::info())
                                                            .child("Login"),
                                                    ),
                                            )
                                            .child(
                                                div()
                                                    .text_color(BonTheme::text_muted())
                                                    .text_size(px(9.5))
                                                    .font_semibold()
                                                    .child("STEALTH • CHROMIUM 148"),
                                            ),
                                    ),
                            )
                            // macOS Prominent [+ New Profile] Action Pill
                            .child(
                                h_flex()
                                    .w_full()
                                    .px_3()
                                    .py_1p5()
                                    .rounded_lg()
                                    .cursor_pointer()
                                    .justify_between()
                                    .items_center()
                                    .bg(if is_creating_profile {
                                        BonTheme::accent()
                                    } else {
                                        BonTheme::bg_elevated()
                                    })
                                    .border_1()
                                    .border_color(if is_creating_profile {
                                        BonTheme::accent()
                                    } else {
                                        BonTheme::border()
                                    })
                                    .hover(|s| {
                                        if is_creating_profile {
                                            s.bg(rgb(0x2997ff))
                                        } else {
                                            s.bg(rgb(0x36363b)).border_color(BonTheme::border_active())
                                        }
                                    })
                                    .text_xs()
                                    .font_semibold()
                                    .text_color(BonTheme::text_primary())
                                    .on_mouse_down(
                                        MouseButton::Left,
                                        cx.listener(|app, _, window, cx| {
                                            app.popup_modal = None;
                                            app.open_create_modal(window, cx);
                                        }),
                                    )
                                    .child(format!("{}  New Profile", SfSymbol::PLUS))
                                    .child(
                                        div()
                                            .text_size(px(10.))
                                            .text_color(if is_creating_profile {
                                                rgba(0xffffffcc).into()
                                            } else {
                                                BonTheme::text_muted()
                                            })
                                            .child("⌘N"),
                                    )
                                    .with_spring(
                                        "sidebar-create-prof-spring",
                                        SpringAnimation::new(BonTheme::snappy_spring())
                                            .to(is_creating_profile),
                                        |this, phase| {
                                            this.bg(phase.interpolate_clamped(
                                                BonTheme::bg_elevated(),
                                                BonTheme::accent(),
                                            ))
                                        },
                                    ),
                            )
                            // macOS Sidebar Navigation Section
                            .child(
                                v_flex()
                                    .w_full()
                                    .gap_0p5()
                                    .child(
                                        div()
                                            .px_2p5()
                                            .pb_1()
                                            .text_size(px(10.5))
                                            .font_semibold()
                                            .text_color(BonTheme::text_muted())
                                            .child("WORKSPACE"),
                                    )
                                    .child(sidebar_nav_item(
                                        "\u{100688}   Profiles",
                                        is_profiles_nav_active,
                                        WorkspaceView::Profiles,
                                        cx,
                                    ))
                                    .child(sidebar_nav_item(
                                        "\u{100906}   Proxies",
                                        active_view == WorkspaceView::Proxies,
                                        WorkspaceView::Proxies,
                                        cx,
                                    ))
                                    .child(sidebar_nav_item(
                                        "\u{10096e}   Extensions",
                                        active_view == WorkspaceView::Extensions,
                                        WorkspaceView::Extensions,
                                        cx,
                                    )),
                            ),
                    )
                    // Sidebar Footer: Engine Status Pill
                    .child(
                        v_flex()
                            .w_full()
                            .pt_2p5()
                            .border_t_1()
                            .border_color(BonTheme::border())
                            .gap_2()
                            .children(self.kernel_info.is_none().then(|| {
                                let installing = self.installing_kernel;
                                Button::new("btn-install-kernel")
                                    .warning()
                                    .small()
                                    .disabled(installing)
                                    .label(if installing {
                                        "Installing..."
                                    } else {
                                        "Download Kernel"
                                    })
                                    .on_click(cx.listener(|app, _, _, cx| {
                                        app.install_kernel(cx);
                                    }))
                            }))
                            .child(
                                h_flex()
                                    .px_2()
                                    .py_1()
                                    .rounded_md()
                                    .bg(rgba(0xffffff08))
                                    .gap_2()
                                    .items_center()
                                    .child(
                                        div()
                                            .w(px(7.))
                                            .h(px(7.))
                                            .rounded_full()
                                            .bg(kernel_dot),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(BonTheme::text_secondary())
                                            .child(kernel_label),
                                    ),
                            ),
                    ),
            )
            // ================================================================
            // 2. Main Workspace (GenLogin Flat Top Header + Active Screen)
            // ================================================================
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .px_6()
                    .py_4()
                    .gap_3p5()
                    .overflow_hidden()
                    // GenLogin Top Header Bar (`Profiles` title on left, `[⚡ Quick add]` on right)
                    .child(
                        h_flex()
                            .w_full()
                            .min_w_0()
                            .flex_shrink_0()
                            .pb_2p5()
                            .border_b_1()
                            .border_color(BonTheme::border())
                            .justify_between()
                            .items_center()
                            .gap_3()
                            .overflow_hidden()
                            .child(
                                h_flex()
                                    .flex_1()
                                    .min_w_0()
                                    .overflow_hidden()
                                    .gap_4()
                                    .items_center()
                                    .child(
                                        div()
                                            .flex_shrink_0()
                                            .text_lg()
                                            .font_bold()
                                            .text_color(BonTheme::text_primary())
                                            .child(page_title),
                                    )
                            )
                            .child(
                                h_flex()
                                    .flex_shrink_0()
                                    .gap_2p5()
                                    .items_center()
                                    .child({
                                        let running_total = self
                                            .statuses
                                            .values()
                                            .filter(|st| matches!(st, ProfileStatus::Running(_)))
                                            .count();
                                        let label = if running_total > 0 {
                                            format!("{}  Arrange ({running_total})", SfSymbol::PC)
                                        } else {
                                            format!("{}  Arrange", SfSymbol::PC)
                                        };
                                        Button::new("top-arrange-windows")
                                            .with_variant(BonTheme::row_action(cx))
                                            .small()
                                            .label(label)
                                            .on_click(cx.listener(|app, _, _, cx| {
                                                app.popup_modal =
                                                    Some(ActivePopupModal::ArrangeWindows);
                                                cx.notify();
                                            }))
                                    })
                                    .child(
                                        Button::new("top-quick-add")
                                            .with_variant(BonTheme::outline_blue(cx))
                                            .small()
                                            .label(format!("{}  Quick add", SfSymbol::BOLT_FILL))
                                            .on_click(cx.listener(|app, _, _, cx| {
                                                app.popup_modal = Some(ActivePopupModal::QuickAdd);
                                                cx.notify();
                                            })),
                                    ),
                            ),
                    )
                    // (Popup modals render as a full-window backdrop overlay at the root level)
                    // Main Screen Content
                    .child(match active_view {
                        WorkspaceView::Profiles => v_flex()
                            .w_full()
                            .flex_1()
                            .min_h_0()
                            .gap_3()
                            // 1. macOS Segmented Control Bar (`Local (N)` | `Groups (N)`)
                            .child(
                                h_flex()
                                    .w_full()
                                    .flex_shrink_0()
                                    .gap_3()
                                    .items_center()
                                    .child(
                                        h_flex()
                                            .p(px(3.))
                                            .gap(px(2.))
                                            .rounded_lg()
                                            .bg(BonTheme::bg_well())
                                            .border_1()
                                            .border_color(BonTheme::border())
                                            .child(genlogin_subtab_item(
                                                "Local",
                                                total_count,
                                                sub_tab == ProfileSubTab::Local,
                                                ProfileSubTab::Local,
                                                cx,
                                            ))
                                            .child(genlogin_subtab_item(
                                                "Groups",
                                                group_count,
                                                sub_tab == ProfileSubTab::Group,
                                                ProfileSubTab::Group,
                                                cx,
                                            ))
                                            .child(genlogin_subtab_item(
                                                "Trash",
                                                self.trashed_profiles.len(),
                                                sub_tab == ProfileSubTab::Trash,
                                                ProfileSubTab::Trash,
                                                cx,
                                            )),
                                    )
                                    .children((selected_group != "All").then(|| {
                                        Button::new("clear-grp-filter")
                                            .with_variant(BonTheme::outline_blue(cx))
                                            .small()
                                            .label(format!(
                                                "{}  {selected_group}  {}",
                                                SfSymbol::FOLDER_FILL,
                                                SfSymbol::XMARK
                                            ))
                                            .on_click(cx.listener(|app, _, _, cx| {
                                                app.selected_group = "All".to_string();
                                                cx.notify();
                                            }))
                                    })),
                            )
                            .child(if sub_tab == ProfileSubTab::Group {
                                render_groups_subtab_view(self, cx)
                                    .with_animation(
                                        "subtab-groups-enter",
                                        Animation::new(Duration::from_millis(140))
                                            .with_easing(ease_out_quint()),
                                        |this, delta| this.opacity(delta),
                                    )
                                    .into_any_element()
                            } else if sub_tab == ProfileSubTab::Trash {
                                render_trash_table(&self.trashed_profiles, cx)
                                    .with_animation(
                                        "subtab-trash-enter",
                                        Animation::new(Duration::from_millis(140))
                                            .with_easing(ease_out_quint()),
                                        |this, delta| this.opacity(delta),
                                    )
                                    .into_any_element()
                            } else {
                                let checked_count = self.checked_profile_ids.len();
                                let checked_running_count = self
                                    .checked_profile_ids
                                    .iter()
                                    .filter(|id| {
                                        matches!(
                                            self.statuses.get(*id),
                                            Some(
                                                ProfileStatus::Running(_)
                                                    | ProfileStatus::Starting(_)
                                            )
                                        )
                                    })
                                    .count();
                                let checked_stopped_count =
                                    checked_count.saturating_sub(checked_running_count);
                                v_flex()
                                    .w_full()
                                    .flex_1()
                                    .gap_2p5()
                                    .overflow_hidden()
                                    // Search Input Row (`🔍 Search...`)
                                    .child(
                                        h_flex()
                                            .w_full()
                                            .justify_between()
                                            .items_center()
                                            .child(
                                                div()
                                                    .w(px(270.))
                                                    .child(Input::new(&self.search_input)),
                                            )
                                            .child(
                                                h_flex()
                                                    .gap_2()
                                                    .items_center()
                                                    .child(
                                                        Button::new("top-import-zip-btn")
                                                            .with_variant(BonTheme::outline_blue(
                                                                cx,
                                                            ))
                                                            .small()
                                                            .label("📥  Import .zip")
                                                            .on_click(cx.listener(
                                                                |app, _, _, cx| {
                                                                    app.popup_modal = Some(
                                                                        ActivePopupModal::ImportBackupZip,
                                                                    );
                                                                    cx.notify();
                                                                },
                                                            )),
                                                    )
                                                    .children((!self.show_detail_drawer).then(
                                                        || {
                                                            Button::new("reopen-detail-drawer")
                                                                .with_variant(BonTheme::row_action(
                                                                    cx,
                                                                ))
                                                                .small()
                                                                .label(format!(
                                                                    "{}  Show Detail Panel",
                                                                    SfSymbol::SIDEBAR_RIGHT
                                                                ))
                                                                .on_click(cx.listener(
                                                                    |app, _, _, cx| {
                                                                        app.show_detail_drawer =
                                                                            true;
                                                                        cx.notify();
                                                                    },
                                                                ))
                                                        },
                                                    )),
                                            ),
                                    )
                                    // GenLogin Top Menu Bar (Batch Action Row below Search when profiles are checked, `docs/genlogin-3.0/assets/menu-bar_profile_top-menu-bar_01.png`)
                                    .children((checked_count > 0).then(|| {
                                        v_flex()
                                            .w_full()
                                            .gap_1p5()
                                            .child(
                                                h_flex()
                                                    .w_full()
                                                    .gap_2()
                                                    .flex_wrap()
                                                    .items_center()
                                                    .children((checked_stopped_count > 0).then(
                                                        || {
                                                            Button::new("batch-launch-sel")
                                                                .with_variant(
                                                                    BonTheme::primary_cta(cx),
                                                                )
                                                                .small()
                                                                .label(format!(
                                                                    "{}  Start {checked_stopped_count} profile{}",
                                                                    SfSymbol::PLAY_FILL,
                                                                    if checked_stopped_count == 1 {
                                                                        ""
                                                                    } else {
                                                                        "s"
                                                                    }
                                                                ))
                                                                .on_click(cx.listener(
                                                                    |app, _, _, cx| {
                                                                        app.launch_checked_profiles(
                                                                            cx,
                                                                        );
                                                                    },
                                                                ))
                                                        },
                                                    ))
                                                    .children((checked_running_count > 0).then(
                                                        || {
                                                            Button::new("batch-stop-sel")
                                                                .with_variant(
                                                                    BonTheme::outline_danger(cx),
                                                                )
                                                                .small()
                                                                .label(format!(
                                                                    "{}  Stop {checked_running_count} profile{}",
                                                                    SfSymbol::STOP_FILL,
                                                                    if checked_running_count == 1 {
                                                                        ""
                                                                    } else {
                                                                        "s"
                                                                    }
                                                                ))
                                                                .on_click(cx.listener(
                                                                    |app, _, _, cx| {
                                                                        app.stop_checked_profiles(
                                                                            cx,
                                                                        );
                                                                    },
                                                                ))
                                                        },
                                                    ))
                                                    .children((checked_running_count > 0).then(
                                                        || {
                                                            Button::new("batch-arrange-sel")
                                                                .with_variant(
                                                                    BonTheme::outline_blue(cx),
                                                                )
                                                                .small()
                                                                .label(format!(
                                                                    "{}  Arrange {checked_running_count}",
                                                                    SfSymbol::PC
                                                                ))
                                                                .on_click(cx.listener(
                                                                    |app, _, _, cx| {
                                                                        app.popup_modal = Some(
                                                                            ActivePopupModal::ArrangeWindows,
                                                                        );
                                                                        cx.notify();
                                                                    },
                                                                ))
                                                        },
                                                    ))
                                                    .child(
                                                        Button::new("batch-assign-grp-btn")
                                                            .with_variant(BonTheme::outline_blue(
                                                                cx,
                                                            ))
                                                            .small()
                                                            .label(format!(
                                                                "{}  Assign to group",
                                                                SfSymbol::FOLDER_FILL
                                                            ))
                                                            .on_click(cx.listener(
                                                                |app, _, _, cx| {
                                                                    app.popup_modal = Some(
                                                                        ActivePopupModal::AssignGroup,
                                                                    );
                                                                    cx.notify();
                                                                },
                                                            )),
                                                    )
                                                    // (Only real batch actions shown)
                                                    .child(
                                                        Button::new("batch-check-proxy-sel")
                                                            .with_variant(BonTheme::outline_blue(
                                                                cx,
                                                            ))
                                                            .small()
                                                            .label(format!(
                                                                "{}  Check proxy",
                                                                SfSymbol::CHECKMARK_SHIELD
                                                            ))
                                                            .on_click(cx.listener(
                                                                |app, _, _, cx| {
                                                                    app.check_proxies_for_checked(
                                                                        cx,
                                                                    );
                                                                },
                                                            )),
                                                    )
                                                    .child(
                                                        Button::new("batch-update-proxy-btn")
                                                            .with_variant(BonTheme::outline_blue(
                                                                cx,
                                                            ))
                                                            .small()
                                                            .label(format!(
                                                                "{}  Update proxy",
                                                                SfSymbol::ARROW_TRIANGLE_2_CIRCLEPATH
                                                            ))
                                                            .on_click(cx.listener(
                                                                |app, _, _, cx| {
                                                                    app.popup_modal = Some(
                                                                        ActivePopupModal::UpdateProxy,
                                                                    );
                                                                    cx.notify();
                                                                },
                                                            )),
                                                    )
                                                    .child(
                                                        Button::new("batch-update-profiles-btn")
                                                            .with_variant(BonTheme::outline_blue(
                                                                cx,
                                                            ))
                                                            .small()
                                                            .label(format!(
                                                                "{}  Update profiles",
                                                                SfSymbol::SLIDER_HORIZONTAL_3
                                                            ))
                                                            .on_click(cx.listener(
                                                                |app, _, _, cx| {
                                                                    app.popup_modal = Some(
                                                                        ActivePopupModal::UpdateProfiles,
                                                                    );
                                                                    cx.notify();
                                                                },
                                                            )),
                                                    )
                                                    .child(
                                                        Button::new("batch-tags-note-btn")
                                                            .with_variant(BonTheme::outline_blue(
                                                                cx,
                                                            ))
                                                            .small()
                                                            .label("🏷  Tags & Note")
                                                            .on_click(cx.listener(
                                                                |app, _, window, cx| {
                                                                    app.open_quick_meta_modal(
                                                                        None, window, cx,
                                                                    );
                                                                },
                                                            )),
                                                    )
                                                    .child(
                                                        Button::new("batch-cookie-robot-btn")
                                                            .with_variant(BonTheme::outline_blue(
                                                                cx,
                                                            ))
                                                            .small()
                                                            .label("🤖  Cookie Robot")
                                                            .on_click(cx.listener(
                                                                |app, _, _, cx| {
                                                                    app.open_cookie_robot_modal(
                                                                        None, cx,
                                                                    );
                                                                },
                                                            )),
                                                    )
                                                    .child({
                                                        let app_ids = app_entity.clone();
                                                        let app_names = app_entity.clone();
                                                        let app_zip = app_entity.clone();
                                                        let app_exp = app_entity.clone();
                                                        let app_del = app_entity.clone();
                                                        Button::new("batch-more-dots")
                                                            .ghost()
                                                            .small()
                                                            .label(SfSymbol::ELLIPSIS)
                                                            .dropdown_menu_with_anchor(
                                                                Anchor::TopRight,
                                                                move |menu, _window, _cx| {
                                                                    let a1 = app_ids.clone();
                                                                    let a2 = app_names.clone();
                                                                    let az = app_zip.clone();
                                                                    let a3 = app_exp.clone();
                                                                    let a4 = app_del.clone();
                                                                    menu.min_w(px(190.))
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                "\u{100241}   Copy IDs",
                                                                            )
                                                                            .on_click(
                                                                                move |_, _, cx| {
                                                                                    a1.update(
                                                                                        cx,
                                                                                        |app, cx| {
                                                                                            app.copy_checked_ids_to_clipboard(cx);
                                                                                        },
                                                                                    );
                                                                                },
                                                                            ),
                                                                        )
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                "\u{100241}   Copy names",
                                                                            )
                                                                            .on_click(
                                                                                move |_, _, cx| {
                                                                                    a2.update(
                                                                                        cx,
                                                                                        |app, cx| {
                                                                                            app.copy_checked_names_to_clipboard(cx);
                                                                                        },
                                                                                    );
                                                                                },
                                                                            ),
                                                                        )
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                "📦   Export Backup (.zip)",
                                                                            )
                                                                            .on_click(
                                                                                move |_, _, cx| {
                                                                                    az.update(
                                                                                        cx,
                                                                                        |app, cx| {
                                                                                            app.export_checked_profiles_zip(cx);
                                                                                        },
                                                                                    );
                                                                                },
                                                                            ),
                                                                        )
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                "\u{10023d}   Export JSON",
                                                                            )
                                                                            .on_click(
                                                                                move |_, _, cx| {
                                                                                    a3.update(
                                                                                        cx,
                                                                                        |app, cx| {
                                                                                            app.export_all_profiles_backup(cx);
                                                                                        },
                                                                                    );
                                                                                },
                                                                            ),
                                                                        )
                                                                        .separator()
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                format!(
                                                                                    "{}   Move to Trash ({checked_count})",
                                                                                    SfSymbol::TRASH
                                                                                ),
                                                                            )
                                                                            .on_click(
                                                                                move |_, _, cx| {
                                                                                    a4.update(
                                                                                        cx,
                                                                                        |app, cx| {
                                                                                            app.request_delete(
                                                                                                PendingDeleteAction::CheckedProfiles,
                                                                                                cx,
                                                                                            );
                                                                                        },
                                                                                    );
                                                                                },
                                                                            ),
                                                                        )
                                                                },
                                                            )
                                                    }),
                                            )
                                            .with_animation(
                                                "batch-action-bar-enter",
                                                Animation::new(Duration::from_millis(140))
                                                    .with_easing(ease_out_quint()),
                                                |this, delta| this.opacity(delta),
                                            )
                                    }))
                                    // GenLogin Table + Right-Hand `Detail` Drawer
                                    .child(render_profile_table(
                                        &filtered,
                                        &self.statuses,
                                        selected_id.as_deref(),
                                        &self.checked_profile_ids,
                                        self.col_vis,
                                        show_drawer,
                                        cx,
                                    ))
                                    .with_animation(
                                        "subtab-local-enter",
                                        Animation::new(Duration::from_millis(160))
                                            .with_easing(ease_out_quint()),
                                        |this, delta| this.opacity(delta),
                                    )
                                    .into_any_element()
                            })
                            .with_animation(
                                "view-profiles-enter",
                                Animation::new(Duration::from_millis(140))
                                    .with_easing(ease_out_quint()),
                                |this, delta| this.opacity(delta),
                            )
                            .into_any_element(),
                        WorkspaceView::Proxies => render_proxies_view(self, cx)
                            .with_animation(
                                "view-proxies-enter",
                                Animation::new(Duration::from_millis(140))
                                    .with_easing(ease_out_quint()),
                                |this, delta| this.opacity(delta),
                            )
                            .into_any_element(),
                        WorkspaceView::EditProfile => {
                            if let Some(modal) = self.modal.as_ref() {
                                render_edit_profile_view(
                                    modal,
                                    &self.saved_groups,
                                    &proxy_group_counts,
                                    &self.saved_proxies,
                                    cx,
                                )
                                .with_animation(
                                    "view-edit-profile-enter",
                                    Animation::new(Duration::from_millis(140))
                                        .with_easing(ease_out_quint()),
                                    |this, delta| this.opacity(delta),
                                )
                                .into_any_element()
                            } else {
                                div().child("No profile loaded").into_any_element()
                            }
                        }
                        WorkspaceView::Extensions => render_extensions_view(self, cx)
                            .with_animation(
                                "view-extensions-enter",
                                Animation::new(Duration::from_millis(140))
                                    .with_easing(ease_out_quint()),
                                |this, delta| this.opacity(delta),
                            )
                            .into_any_element(),
                    }),
            )
            )
            // Full-Window Centered Modal Overlay (with dark backdrop)
            .children(popup_modal.map(|kind| render_popup_modal(kind, self, cx)))
            // Floating Bottom-Right Toast Notification (auto-dismisses after 3.2s)
            .children(self.banner_message.as_ref().map(|msg| {
                let lower = msg.to_ascii_lowercase();
                let is_err = lower.contains("failed")
                    || lower.contains("error")
                    || lower.contains("blocked")
                    || lower.contains("invalid")
                    || lower.contains("cannot");
                let is_loading = msg.ends_with("...");
                let (accent_color, icon_bg, icon_str) = if is_err {
                    (BonTheme::danger(), BonTheme::danger_bg(), SfSymbol::XMARK_CIRCLE_FILL)
                } else if is_loading {
                    (BonTheme::info(), BonTheme::info_bg(), SfSymbol::ARROW_TRIANGLE_2_CIRCLEPATH)
                } else {
                    (BonTheme::success(), BonTheme::success_bg(), SfSymbol::CHECKMARK_CIRCLE_FILL)
                };
                let banner_id = SharedString::from(format!("toast-banner-{msg}"));
                h_flex()
                    .id(banner_id.clone())
                    .absolute()
                    .bottom_5()
                    .right_6()
                    .max_w(px(440.))
                    .px_3p5()
                    .py_2p5()
                    .gap_2p5()
                    .items_center()
                    .rounded_lg()
                    .bg(BonTheme::bg_elevated())
                    .border_1()
                    .border_color(accent_color)
                    .cursor_pointer()
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(|app, _, _, cx| {
                            app.banner_message = None;
                            app.banner_timer_for = None;
                            cx.notify();
                        }),
                    )
                    .child(
                        div()
                            .w(px(22.))
                            .h(px(22.))
                            .flex_shrink_0()
                            .rounded_full()
                            .bg(icon_bg)
                            .flex()
                            .items_center()
                            .justify_center()
                            .text_xs()
                            .font_bold()
                            .text_color(accent_color)
                            .child(icon_str),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .truncate()
                            .text_xs()
                            .font_semibold()
                            .text_color(BonTheme::text_primary())
                            .child(msg.clone()),
                    )
                    .child(
                        div()
                            .flex_shrink_0()
                            .text_xs()
                            .text_color(BonTheme::text_muted())
                            .child(SfSymbol::XMARK),
                    )
                    .with_animation(
                        banner_id,
                        Animation::new(Duration::from_millis(160))
                            .with_easing(ease_out_quint()),
                        |this, delta| {
                            this.opacity(delta).bottom(px(12.0 + delta * 8.0))
                        },
                    )
            }))
    }
}

fn genlogin_subtab_item(
    label: &'static str,
    count: usize,
    active: bool,
    target_tab: ProfileSubTab,
    cx: &mut Context<BonLoginApp>,
) -> impl IntoElement {
    h_flex()
        .px_3()
        .py_1()
        .gap_1p5()
        .items_center()
        .cursor_pointer()
        .rounded_md()
        .bg(if active {
            BonTheme::accent()
        } else {
            rgba(0x00000000).into()
        })
        .hover(|s| {
            if active {
                s.bg(rgb(0x2997ff))
            } else {
                s.bg(BonTheme::bg_hover())
            }
        })
        .on_mouse_down(
            MouseButton::Left,
            cx.listener(move |app, _, _, cx| {
                app.profile_sub_tab = target_tab;
                cx.notify();
            }),
        )
        .child(
            div()
                .text_xs()
                .font_semibold()
                .text_color(if active {
                    rgb(0xffffff).into()
                } else {
                    BonTheme::text_secondary()
                })
                .child(label),
        )
        .child(
            div()
                .px_1p5()
                .py(px(1.))
                .rounded_full()
                .bg(if active {
                    rgba(0xffffff2e)
                } else {
                    rgba(0xffffff0d)
                })
                .text_size(px(10.5))
                .font_semibold()
                .text_color(if active {
                    rgb(0xffffff).into()
                } else {
                    BonTheme::text_muted()
                })
                .child(count.to_string()),
        )
        .with_spring(
            SharedString::from(format!("subtab-spring-{label}")),
            SpringAnimation::new(BonTheme::snappy_spring()).to(active),
            |this, phase| {
                this.bg(phase.interpolate_clamped(
                    rgba(0x00000000).into(),
                    BonTheme::accent(),
                ))
            },
        )
}

fn sidebar_nav_item(
    label: &'static str,
    active: bool,
    target_view: WorkspaceView,
    cx: &mut Context<BonLoginApp>,
) -> impl IntoElement {
    h_flex()
        .w_full()
        .px_2p5()
        .py_1p5()
        .rounded_lg()
        .cursor_pointer()
        .bg(if active {
            BonTheme::accent()
        } else {
            Hsla::from(rgba(0x00000000))
        })
        .hover(|s| {
            if active {
                s.bg(rgb(0x2997ff))
            } else {
                s.bg(BonTheme::bg_hover())
            }
        })
        .items_center()
        .on_mouse_down(
            MouseButton::Left,
            cx.listener(move |app, _, _, cx| {
                app.popup_modal = None;
                app.active_view = target_view;
                cx.notify();
            }),
        )
        .child(
            div()
                .text_xs()
                .font_semibold()
                .text_color(if active {
                    rgb(0xffffff).into()
                } else {
                    BonTheme::text_primary()
                })
                .child(label),
        )
        .with_spring(
            SharedString::from(format!("nav-spring-{label}")),
            SpringAnimation::new(BonTheme::snappy_spring()).to(active),
            |this, phase| {
                this.bg(phase.interpolate_clamped(
                    Hsla::from(rgba(0x00000000)),
                    BonTheme::accent(),
                ))
            },
        )
}
