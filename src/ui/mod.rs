pub mod popup_modals;
pub mod profile_list;
pub mod profile_modal;
pub mod theme;
pub mod workspace_views;
mod actions;
mod render_layout;

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
use crate::launcher::{KernelInfo, RuntimeSupervisor, locate_chromium_kernel};
use crate::models::{
    BrowserBrand, BrowserExtension, PlatformType, Profile, ProfileStatus, ProxyConfig,
    ProxyProtocol, SavedProxy,
};
use crate::ui::profile_list::{
    ColumnVisibility, ProfileSortColumn, render_profile_table, render_trash_table,
};
use crate::ui::popup_modals::{
    AgentFlowsModalState, CloneProfileModalState, CookieRobotModalState, EditProxyModalState,
    ImportBackupZipModalState, QuickMetaModalState, render_popup_modal,
};
use crate::ui::profile_modal::{ProfileModalState, ProxyEditMode, render_edit_profile_view};
use crate::ui::workspace_views::{
    render_extensions_view, render_groups_subtab_view, render_proxies_view,
};
use crate::ui::theme::{BonTheme, SfSymbol};


gpui_kit::actions!(
    bonlogin,
    [
        QuitApp,
        CloseWindowOrModal,
        MinimizeWindow,
        ZoomWindow,
        NewProfileAction,
        QuickAddAction,
        FocusSearchAction,
        RefreshWorkspaceAction,
        ArrangeWindowsAction,
        OpenFlowsAction,
        ToggleDetailDrawerAction,
        SwitchToProfilesAction,
        SwitchToProxiesAction,
        SwitchToExtensionsAction,
        StopAllProfilesAction,
        LaunchOrStopSelectedAction,
        CopyAgentCliSelectedAction,
        DeleteSelectedAction,
    ]
);

pub fn window_bounds_to_saved(wb: WindowBounds) -> crate::db::SavedWindowBounds {
    let (b, maximized) = match wb {
        WindowBounds::Windowed(b) => (b, false),
        WindowBounds::Maximized(b) | WindowBounds::Fullscreen(b) => (b, true),
    };
    crate::db::SavedWindowBounds {
        x: f32::from(b.origin.x),
        y: f32::from(b.origin.y),
        width: f32::from(b.size.width),
        height: f32::from(b.size.height),
        maximized,
    }
}

pub fn saved_to_window_bounds(saved: crate::db::SavedWindowBounds) -> WindowBounds {
    let b = Bounds::new(
        point(px(saved.x), px(saved.y)),
        size(px(saved.width), px(saved.height)),
    );
    if saved.maximized {
        WindowBounds::Maximized(b)
    } else {
        WindowBounds::Windowed(b)
    }
}
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
pub enum ProxySubTab {
    MyProxies,
    FreeProxies,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaginatedTable {
    Profiles,
    Trash,
    MyProxies,
    FreeProxies,
}

#[derive(Clone)]
pub enum ActivePopupModal {
    QuickAdd,
    ColumnSettings,
    AssignGroup,
    AddGroup,
    AddTag { return_to_add_proxy: bool },
    UpdateProxy,
    UpdateProfiles,
    AddProxy,
    UploadExtension,
    InputUrlExtension,
    ConfirmDelete(PendingDeleteAction),
    ArrangeWindows,
    QuickMeta(QuickMetaModalState),
    CookieRobot(CookieRobotModalState),
    ImportBackupZip(ImportBackupZipModalState),
    AgentFlows(AgentFlowsModalState),
    CloneProfile(CloneProfileModalState),
    EditProxy(EditProxyModalState),
}

impl ActivePopupModal {
    pub fn anim_key(&self) -> &'static str {
        match self {
            Self::QuickAdd => "QuickAdd",
            Self::ColumnSettings => "ColumnSettings",
            Self::AssignGroup => "AssignGroup",
            Self::AddGroup => "AddGroup",
            Self::AddTag { .. } => "AddTag",
            Self::UpdateProxy => "UpdateProxy",
            Self::UpdateProfiles => "UpdateProfiles",
            Self::AddProxy => "AddProxy",
            Self::UploadExtension => "UploadExtension",
            Self::InputUrlExtension => "InputUrlExtension",
            Self::ConfirmDelete(_) => "ConfirmDelete",
            Self::ArrangeWindows => "ArrangeWindows",
            Self::QuickMeta(_) => "QuickMeta",
            Self::CookieRobot(_) => "CookieRobot",
            Self::ImportBackupZip(_) => "ImportBackupZip",
            Self::AgentFlows(_) => "AgentFlows",
            Self::CloneProfile(_) => "CloneProfile",
            Self::EditProxy(_) => "EditProxy",
        }
    }
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
    WipeProfile(String),
    CleanProfileCache(String),
    CleanCheckedCache,
}
pub struct BonLoginApp {
    pub db: Arc<Mutex<Database>>,
    pub workspace_root: std::path::PathBuf,
    pub profiles: Vec<Profile>,
    pub trashed_profiles: Vec<Profile>,
    pub saved_proxies: Vec<SavedProxy>,
    pub saved_groups: Vec<String>,
    pub saved_tags: Vec<String>,
    pub extensions: Vec<BrowserExtension>,
    pub ext_url_input: Entity<InputState>,
    pub ext_file_input: Entity<InputState>,
    pub downloading_ext: bool,
    pub ext_tasks: HashMap<String, (tokio::task::AbortHandle, Arc<std::sync::atomic::AtomicBool>)>,
    pub ext_url_task: Option<(tokio::task::AbortHandle, Arc<std::sync::atomic::AtomicBool>)>,
    pub checked_proxy_ids: HashSet<String>,
    pub checking_proxy_ids: HashSet<String>,
    pub proxy_check_tasks: HashMap<String, tokio::task::AbortHandle>,
    pub modal_proxy_task: Option<tokio::task::AbortHandle>,
    pub profile_tasks: HashMap<String, tokio::task::AbortHandle>,
    pub profile_aux_tasks: HashMap<String, tokio::task::AbortHandle>,
    pub selected_proxy_group: String,
    pub proxy_add_protocol: ProxyProtocol,
    pub proxy_selected_tag: String,
    pub proxy_raw_input: Entity<TextareaState>,
    pub proxy_expire_input: Entity<InputState>,
    pub proxy_sub_tab: ProxySubTab,
    pub free_proxies: Vec<crate::models::FreeProxyCandidate>,
    pub free_proxy_search_input: Entity<InputState>,
    pub free_proxy_search_query: String,
    pub free_proxy_protocol_filter: Option<ProxyProtocol>,
    pub free_proxy_country_filter: String,
    pub free_proxy_only_live: bool,
    pub fetching_free_proxies: bool,
    pub verifying_free_proxies: bool,
    pub checked_free_keys: HashSet<String>,
    pub checking_free_keys: HashSet<String>,
    pub free_proxy_tasks: HashMap<String, tokio::task::AbortHandle>,
    pub free_proxy_batch_task: Option<tokio::task::AbortHandle>,
    pub page_size: usize,
    pub profiles_page: usize,
    pub trash_page: usize,
    pub my_proxies_page: usize,
    pub free_proxies_page: usize,
    pub statuses: HashMap<String, ProfileStatus>,
    pub supervisor: RuntimeSupervisor,
    pub tokio_handle: tokio::runtime::Handle,
    pub kernel_info: Option<KernelInfo>,
    pub installing_kernel: bool,
    pub search_input: Entity<InputState>,
    pub search_query: String,
    pub selected_group: String,
    pub selected_profile_id: Option<String>,
    pub checked_profile_ids: HashSet<String>,
    pub col_vis: ColumnVisibility,
    pub sort_col: Option<ProfileSortColumn>,
    pub sort_asc: bool,
    pub profile_sub_tab: ProfileSubTab,
    pub popup_modal: Option<ActivePopupModal>,
    pub show_detail_drawer: bool,
    pub batch_move_group_input: Entity<InputState>,
    pub new_tag_input: Entity<InputState>,
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
    pub saved_flows: Vec<crate::flows::AgentFlow>,
    pub http_api_task: Option<tokio::task::AbortHandle>,
    pub http_api_port: Option<u16>,
    pub selected_disk_usage: String,
    pub selected_bookmarks: Vec<(String, String)>,
    pub used_proxy_counts: std::rc::Rc<HashMap<(ProxyProtocol, String, u16), usize>>,
    pub cached_group_counts: Vec<(String, usize)>,
    pub cached_proxy_group_counts: Vec<(String, usize)>,
    pub profile_data_rev: u64,
    profile_indices_cache: std::cell::RefCell<
        Option<(
            u64,
            String,
            String,
            Option<ProfileSortColumn>,
            bool,
            usize,
            std::rc::Rc<[usize]>,
        )>,
    >,
    proxy_indices_cache: std::cell::RefCell<Option<(u64, String, std::rc::Rc<[usize]>)>>,
    pub banner_message: Option<String>,
    banner_timer_for: Option<String>,
    pub recently_copied_key: Option<String>,
    pub reseed_flash_seed: Option<u32>,
    _subscriptions: Vec<Subscription>,
}

impl BonLoginApp {
    pub fn new(
        db: Database,
        tokio_handle: tokio::runtime::Handle,
        supervisor: RuntimeSupervisor,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let workspace_root = db.root_dir().to_path_buf();
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
            let root_for_exts = workspace_root.clone();
            tokio_handle.spawn_blocking(move || {
                for ext in &enabled_exts {
                    let _ = crate::extensions::ensure_extension_unpacked_in(&root_for_exts, ext);
                }
            });
        }
        let selected_profile_id = profiles.first().map(|p| p.id.clone());
        let kernel_info = locate_chromium_kernel();

        let search_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("\u{1002ab}  Search... (⌘F)"));

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
            InputState::new(window, cx).placeholder("Enter new group name...")
        });
        let new_tag_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Enter new tag name...")
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
        let free_proxy_search_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("\u{1002ab}  Search IP, country, city, ISP, source...")
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
        let saved_flows = db.list_flows();
        let selected_disk_usage = "0 B".to_string();
        let selected_bookmarks = selected_profile_id
            .as_ref()
            .and_then(|sid| profiles.iter().find(|p| &p.id == sid))
            .map(|p| db.read_bookmarks(p))
            .unwrap_or_default();
        if let Some(init_sel_id) = selected_profile_id.clone() {
            let target_id = init_sel_id.clone();
            let init_root = workspace_root.clone();
            let init_handle = tokio_handle.clone();
            cx.spawn(async move |this, cx| {
                let size_str = init_handle
                    .spawn_blocking(move || {
                        crate::launcher::profile_user_data_dir_in(&init_root, &target_id)
                            .ok()
                            .map(|d| {
                                crate::launcher::format_bytes(crate::launcher::dir_size_bytes(&d))
                            })
                            .unwrap_or_else(|| "0 B".to_string())
                    })
                    .await
                    .unwrap_or_else(|_| "0 B".to_string());
                let _ = this.update(cx, |app, cx| {
                    if app.selected_profile_id.as_deref() == Some(init_sel_id.as_str())
                        && app.selected_disk_usage != size_str
                    {
                        app.selected_disk_usage = size_str;
                        cx.notify();
                    }
                });
            })
            .detach();
        }
        let search_sub = cx.subscribe_in(&search_input, window, {
            let search_input = search_input.clone();
            move |this, _, ev: &InputEvent, _window, cx| {
                if matches!(ev, InputEvent::Change) {
                    this.search_query = search_input.read(cx).value().to_string();
                    this.profiles_page = 0;
                    cx.notify();
                }
            }
        });
        let free_search_sub = cx.subscribe_in(&free_proxy_search_input, window, {
            let free_proxy_search_input = free_proxy_search_input.clone();
            move |this, _, ev: &InputEvent, _window, cx| {
                if matches!(ev, InputEvent::Change) {
                    this.free_proxy_search_query =
                        free_proxy_search_input.read(cx).value().to_string();
                    this.free_proxies_page = 0;
                    cx.notify();
                }
            }
        });
        let mut last_saved_bounds: Option<crate::db::SavedWindowBounds> = None;
        let bounds_sub = cx.observe_window_bounds(window, move |this, window, _cx| {
            let Some(cur) = window_bounds_to_saved(window.window_bounds()).validated() else {
                return;
            };
            if last_saved_bounds == Some(cur) {
                return;
            }
            last_saved_bounds = Some(cur);
            let root = this.workspace_root.clone();
            this.tokio_handle.spawn_blocking(move || {
                let _ = crate::db::save_window_bounds_in(&root, cur);
            });
        });

        let monitor_sup = supervisor.clone();
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(800))
                    .await;
                let Ok(profile_ids) = this.read_with(cx, |app, _| {
                    app.profiles
                        .iter()
                        .filter(|p| {
                            !matches!(app.statuses.get(&p.id), Some(ProfileStatus::Starting))
                                && !app.profile_tasks.contains_key(&p.id)
                        })
                        .map(|p| p.id.clone())
                        .collect::<Vec<_>>()
                }) else {
                    break;
                };
                let sup = monitor_sup.clone();
                let (exited, external_live) = cx
                    .background_executor()
                    .spawn(async move { sup.reconcile_live(&profile_ids) })
                    .await;
                let alive = this
                    .update(cx, |app, cx| {
                        let has_running_status = app
                            .statuses
                            .values()
                            .any(|st| matches!(st, ProfileStatus::Running(_)));
                        if exited.is_empty() && external_live.is_empty() && !has_running_status {
                            return;
                        }
                        let mut changed = false;
                        for id in &exited {
                            app.statuses.insert(id.clone(), ProfileStatus::Stopped);
                            changed = true;
                        }
                        for (pid, info) in &external_live {
                            if !matches!(
                                app.statuses.get(pid),
                                Some(ProfileStatus::Starting)
                            ) && !matches!(
                                app.statuses.get(pid),
                                Some(ProfileStatus::Running(cur)) if cur == info
                            ) {
                                app.statuses
                                    .insert(pid.clone(), ProfileStatus::Running(info.clone()));
                                changed = true;
                            }
                        }
                        if has_running_status {
                            let stale_ext: Vec<String> = app
                                .statuses
                                .iter()
                                .filter(|(pid, st)| {
                                    matches!(st, ProfileStatus::Running(_))
                                        && !app.supervisor.contains_owned(pid)
                                        && !external_live.contains_key(*pid)
                                })
                                .map(|(pid, _)| pid.clone())
                                .collect();
                            for pid in stale_ext {
                                app.statuses.insert(pid, ProfileStatus::Stopped);
                                changed = true;
                            }
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
        let used_proxy_counts = std::rc::Rc::new(Self::compute_used_proxy_counts(&profiles));
        let cached_group_counts = Self::compute_group_counts(&saved_groups, &profiles);
        let cached_proxy_group_counts =
            Self::compute_proxy_group_counts(&saved_tags, &saved_proxies);
        Self {
            db: Arc::new(Mutex::new(db)),
            workspace_root,
            profiles,
            trashed_profiles,
            saved_proxies,
            saved_groups,
            saved_tags,
            extensions,
            ext_url_input,
            ext_file_input,
            downloading_ext: false,
            ext_tasks: HashMap::new(),
            ext_url_task: None,
            checked_proxy_ids: HashSet::new(),
            checking_proxy_ids: HashSet::new(),
            proxy_check_tasks: HashMap::new(),
            modal_proxy_task: None,
            profile_tasks: HashMap::new(),
            profile_aux_tasks: HashMap::new(),
            selected_proxy_group: "All".to_string(),
            proxy_add_protocol: ProxyProtocol::Http,
            proxy_selected_tag: initial_tag,
            proxy_raw_input,
            proxy_expire_input,
            proxy_sub_tab: ProxySubTab::MyProxies,
            free_proxies: Vec::new(),
            free_proxy_search_input,
            free_proxy_search_query: String::new(),
            free_proxy_protocol_filter: None,
            free_proxy_country_filter: "All".to_string(),
            free_proxy_only_live: false,
            fetching_free_proxies: false,
            verifying_free_proxies: false,
            checked_free_keys: HashSet::new(),
            checking_free_keys: HashSet::new(),
            free_proxy_tasks: HashMap::new(),
            free_proxy_batch_task: None,
            page_size: 25,
            profiles_page: 0,
            trash_page: 0,
            my_proxies_page: 0,
            free_proxies_page: 0,
            statuses: HashMap::new(),
            supervisor,
            tokio_handle,
            kernel_info,
            installing_kernel: false,
            search_input,
            search_query: String::new(),
            selected_group: "All".to_string(),
            selected_profile_id,
            checked_profile_ids: HashSet::new(),
            col_vis: ColumnVisibility::default(),
            sort_col: None,
            sort_asc: true,
            profile_sub_tab: ProfileSubTab::Local,
            popup_modal: None,
            show_detail_drawer: true,
            batch_move_group_input,
            new_tag_input,
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
            saved_flows,
            http_api_task: None,
            http_api_port: None,
            selected_disk_usage,
            selected_bookmarks,
            used_proxy_counts,
            cached_group_counts,
            cached_proxy_group_counts,
            profile_data_rev: 1,
            profile_indices_cache: std::cell::RefCell::new(None),
            proxy_indices_cache: std::cell::RefCell::new(None),
            banner_message: None,
            banner_timer_for: None,
            recently_copied_key: None,
            reseed_flash_seed: None,
            _subscriptions: vec![search_sub, free_search_sub, bounds_sub],
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
        self.saved_flows = crate::flows::list_saved_flows_in(&self.workspace_root);
        self.refresh_selected_bookmarks();
        self.used_proxy_counts = std::rc::Rc::new(Self::compute_used_proxy_counts(&self.profiles));
        self.cached_group_counts =
            Self::compute_group_counts(&self.saved_groups, &self.profiles);
        self.cached_proxy_group_counts =
            Self::compute_proxy_group_counts(&self.saved_tags, &self.saved_proxies);
        self.profile_data_rev = self.profile_data_rev.wrapping_add(1);
    }

    fn compute_group_counts(saved_groups: &[String], profiles: &[Profile]) -> Vec<(String, usize)> {
        let mut out: Vec<(String, usize)> = saved_groups.iter().map(|g| (g.clone(), 0)).collect();
        for p in profiles {
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

    fn compute_proxy_group_counts(
        saved_tags: &[String],
        saved_proxies: &[SavedProxy],
    ) -> Vec<(String, usize)> {
        let mut out: Vec<(String, usize)> = saved_tags.iter().map(|t| (t.clone(), 0)).collect();
        for sp in saved_proxies {
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

    fn compute_used_proxy_counts(
        profiles: &[Profile],
    ) -> HashMap<(ProxyProtocol, String, u16), usize> {
        let mut used_map = HashMap::new();
        for p in profiles {
            if let Some(cfg) = &p.proxy {
                *used_map
                    .entry((cfg.protocol, cfg.host.clone(), cfg.port))
                    .or_insert(0) += 1;
            }
        }
        used_map
    }
    pub fn refresh_selected_bookmarks(&mut self) {
        self.selected_bookmarks = self
            .selected_profile_id
            .as_ref()
            .and_then(|sid| self.profiles.iter().find(|p| &p.id == sid))
            .map(|p| crate::launcher::read_profile_bookmarks_in(&self.workspace_root, p))
            .unwrap_or_default();
    }

    pub fn refresh_selected_disk_usage(&mut self, cx: &mut Context<Self>) {
        let Some(sel_id) = self.selected_profile_id.clone() else {
            self.selected_disk_usage = "0 B".to_string();
            return;
        };
        let target_id = sel_id.clone();
        let root_dir = self.workspace_root.clone();
        let tokio_handle = self.tokio_handle.clone();
        cx.spawn(async move |this, cx| {
            let size_str = tokio_handle
                .spawn_blocking(move || {
                    crate::launcher::profile_user_data_dir_in(&root_dir, &target_id)
                        .ok()
                        .map(|d| crate::launcher::format_bytes(crate::launcher::dir_size_bytes(&d)))
                        .unwrap_or_else(|| "0 B".to_string())
                })
                .await
                .unwrap_or_else(|_| "0 B".to_string());
            let _ = this.update(cx, |app, cx| {
                if app.selected_profile_id.as_deref() == Some(sel_id.as_str())
                    && app.selected_disk_usage != size_str
                {
                    app.selected_disk_usage = size_str;
                    cx.notify();
                }
            });
        })
        .detach();
    }

    pub fn reload_extensions_only(&mut self) {
        if let Ok(db) = self.db.lock()
            && let Ok(elist) = db.list_extensions()
        {
            self.extensions = elist;
        }
    }

    pub fn distinct_proxy_groups_with_counts(&self) -> Vec<(String, usize)> {
        self.cached_proxy_group_counts.clone()
    }

    pub fn filtered_proxy_indices_rc(&self) -> std::rc::Rc<[usize]> {
        let rev = self.profile_data_rev;
        if let Some((c_rev, c_grp, cached)) = self.proxy_indices_cache.borrow().as_ref()
            && *c_rev == rev
            && c_grp == &self.selected_proxy_group
        {
            return cached.clone();
        }
        let indices: std::rc::Rc<[usize]> = self
            .saved_proxies
            .iter()
            .enumerate()
            .filter_map(|(i, sp)| {
                (self.selected_proxy_group == "All"
                    || sp.group_tag.eq_ignore_ascii_case(&self.selected_proxy_group))
                .then_some(i)
            })
            .collect::<Vec<_>>()
            .into();
        *self.proxy_indices_cache.borrow_mut() =
            Some((rev, self.selected_proxy_group.clone(), indices.clone()));
        indices
    }

    pub fn filtered_proxy_indices(&self) -> Vec<usize> {
        self.filtered_proxy_indices_rc().to_vec()
    }

    pub fn filtered_free_proxy_indices_rc(&self) -> std::rc::Rc<[usize]> {
        let q = self.free_proxy_search_query.trim();
        let proto = self.free_proxy_protocol_filter;
        let country = self.free_proxy_country_filter.as_str();
        let only_live = self.free_proxy_only_live;
        self.free_proxies
            .iter()
            .enumerate()
            .filter_map(|(i, fp)| fp.matches_filter(q, proto, country, only_live).then_some(i))
            .collect::<Vec<_>>()
            .into()
    }

    pub fn filtered_free_proxy_indices(&self) -> Vec<usize> {
        self.filtered_free_proxy_indices_rc().to_vec()
    }

    pub fn distinct_free_proxy_countries_with_counts(&self) -> Vec<(String, usize)> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for fp in &self.free_proxies {
            let cc = fp.effective_country().trim();
            if !cc.is_empty() {
                *counts.entry(cc.to_ascii_uppercase()).or_insert(0) += 1;
            }
        }
        let mut out: Vec<(String, usize)> = counts.into_iter().collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        out
    }

    pub fn live_free_proxies_count(&self) -> usize {
        self.free_proxies
            .iter()
            .filter(|fp| fp.verified_geo.is_some())
            .count()
    }

    /// Returns `(current_page, total_pages, start_ix, end_ix)` clamped to `total_items`.
    pub fn current_page_bounds(
        &self,
        table: PaginatedTable,
        total_items: usize,
    ) -> (usize, usize, usize, usize) {
        let page_size = self.page_size.max(1);
        let total_pages = total_items.div_ceil(page_size).max(1);
        let raw_page = match table {
            PaginatedTable::Profiles => self.profiles_page,
            PaginatedTable::Trash => self.trash_page,
            PaginatedTable::MyProxies => self.my_proxies_page,
            PaginatedTable::FreeProxies => self.free_proxies_page,
        };
        let cur_page = raw_page.min(total_pages - 1);
        let start_ix = cur_page * page_size;
        let end_ix = (start_ix + page_size).min(total_items);
        (cur_page, total_pages, start_ix, end_ix)
    }

    pub fn set_table_page(
        &mut self,
        table: PaginatedTable,
        page: usize,
        cx: &mut Context<Self>,
    ) {
        match table {
            PaginatedTable::Profiles => self.profiles_page = page,
            PaginatedTable::Trash => self.trash_page = page,
            PaginatedTable::MyProxies => self.my_proxies_page = page,
            PaginatedTable::FreeProxies => self.free_proxies_page = page,
        }
        cx.notify();
    }

    pub fn set_table_page_size(&mut self, size: usize, cx: &mut Context<Self>) {
        self.page_size = size.clamp(5, 500);
        self.profiles_page = 0;
        self.trash_page = 0;
        self.my_proxies_page = 0;
        self.free_proxies_page = 0;
        cx.notify();
    }

}

