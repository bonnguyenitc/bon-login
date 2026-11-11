use gpui_kit::component::{
    button::{Button, ButtonVariants as _},
    input::{Input, InputState, Textarea, TextareaState},
    menu::{DropdownMenu as _, PopupMenuItem},
    *,
};
use gpui_kit::*;
use std::time::Duration;
use crate::models::{
    BrowserBrand, GpuSpoofMode, PlatformType, Profile, ProxyConfig, ProxyProtocol, SavedProxy,
};
use crate::ui::theme::{BonTheme, SfSymbol};
use crate::ui::{ActivePopupModal, BonLoginApp, PendingDeleteAction, ProfileSubTab, WorkspaceView};


fn get_extension_icon(ext: &crate::models::BrowserExtension) -> Option<std::sync::Arc<Image>> {
    static CACHE: std::sync::LazyLock<
        std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<Image>>>,
    > = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

    if let Ok(guard) = CACHE.lock()
        && let Some(cached) = guard.get(&ext.id)
    {
        return Some(cached.clone());
    }
    let (is_svg, bytes) = crate::launcher::load_extension_icon_bytes(ext)?;
    let fmt = if is_svg {
        ImageFormat::Svg
    } else {
        ImageFormat::Png
    };
    let image = std::sync::Arc::new(Image::from_bytes(fmt, bytes));
    if let Ok(mut guard) = CACHE.lock() {
        guard.insert(ext.id.clone(), image.clone());
    }
    Some(image)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyEditMode {
    Direct,
    SavedPool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileEditorTab {
    Overview,
    Network,
    Location,
    Hardware,
    Cookies,
    Bookmarks,
}

pub struct ProfileModalState {
    pub editing_id: Option<String>,
    pub active_tab: ProfileEditorTab,
    pub created_at: i64,
    pub last_launched_at: Option<i64>,
    pub resolved_geo: Option<crate::models::GeoInfo>,
    pub proxy_mode: ProxyEditMode,
    pub selected_proxy: Option<ProxyConfig>,
    pub checking_proxy: bool,
    pub proxy_check_error: Option<String>,
    pub auto_geo: bool,
    pub os_platform: PlatformType,
    pub brand: BrowserBrand,
    pub gpu_spoofing: GpuSpoofMode,
    pub spoof_canvas: bool,
    pub spoof_audio: bool,
    pub spoof_font: bool,
    pub spoof_client_rects: bool,
    pub window_size: String,
    pub hardware_concurrency: u8,
    pub name_input: Entity<InputState>,
    pub selected_group: String,
    pub tags: Vec<String>,
    pub seed_input: Entity<InputState>,
    pub custom_tz_input: Entity<InputState>,
    pub custom_locale_input: Entity<InputState>,
    pub startup_url_input: Entity<InputState>,
    pub notes_input: Entity<InputState>,
    pub totp_input: Entity<InputState>,
    pub bookmarks: Vec<(String, String)>,
    pub bookmark_name_input: Entity<InputState>,
    pub bookmark_url_input: Entity<InputState>,
    pub cookies_input: Entity<TextareaState>,
    pub cookies_cache_key: std::cell::RefCell<String>,
    pub cookies_cache_status: std::cell::RefCell<Option<Result<String, String>>>,
    pub validation_error: Option<String>,
    pub deleted_at: Option<i64>,
}

impl ProfileModalState {
    pub fn from_profile(
        profile: &Profile,
        is_edit: bool,
        window: &mut Window,
        cx: &mut Context<BonLoginApp>,
    ) -> Self {
        let name_val = profile.name.clone();
        let group_val = profile.group_tag.trim().to_string();
        let seed_val = profile.seed.to_string();
        let tz_val = profile.custom_timezone.clone().unwrap_or_default();
        let loc_val = profile.custom_locale.clone().unwrap_or_default();
        let url_val = profile.startup_url.clone();
        let notes_val = profile.notes.clone();
        let totp_val = profile.totp_secret.clone();
        let tags_val = profile.tags.clone();
        let bookmarks_val = crate::launcher::read_profile_bookmarks(profile);
        let cookies_val = if is_edit {
            let sid = profile.short_id();
            let pre = crate::launcher::read_prelaunch_cookies(&sid);
            if !pre.trim().is_empty() {
                pre
            } else {
                let state_path = crate::launcher::app_support_dir()
                    .join("states")
                    .join(format!("bon_{sid}_state.json"));
                std::fs::read_to_string(state_path)
                    .ok()
                    .filter(|s| {
                        crate::launcher::parse_and_normalize_cookies(s, None)
                            .is_ok_and(|b| !b.cookies.is_empty() || !b.origins.is_empty())
                    })
                    .unwrap_or_default()
            }
        } else {
            String::new()
        };
        let proxy_mode = if profile.proxy.is_some() {
            ProxyEditMode::SavedPool
        } else {
            ProxyEditMode::Direct
        };
        let selected_proxy = profile.proxy.clone();
        let auto_geo = profile.custom_timezone.is_none() && profile.custom_locale.is_none();

        Self {
            editing_id: is_edit.then(|| profile.id.clone()),
            active_tab: ProfileEditorTab::Overview,
            created_at: profile.created_at,
            last_launched_at: profile.last_launched_at,
            resolved_geo: profile.resolved_geo.clone(),
            proxy_mode,
            selected_proxy,
            checking_proxy: false,
            proxy_check_error: None,
            auto_geo,
            os_platform: profile.os_platform,
            brand: profile.brand,
            gpu_spoofing: profile.gpu_spoofing,
            spoof_canvas: profile.spoof_canvas,
            spoof_audio: profile.spoof_audio,
            spoof_font: profile.spoof_font,
            spoof_client_rects: profile.spoof_client_rects,
            window_size: profile.window_size.clone(),
            hardware_concurrency: profile.hardware_concurrency,
            name_input: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("e.g. Client A · Facebook Ads")
                    .default_value(name_val)
            }),
            selected_group: group_val,
            tags: tags_val,
            seed_input: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("32-bit fingerprint seed")
                    .default_value(seed_val)
            }),
            custom_tz_input: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("Follows Proxy IP (or e.g. America/New_York)")
                    .default_value(tz_val)
            }),
            custom_locale_input: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("Follows IP (or en-US, vi-VN)")
                    .default_value(loc_val)
            }),
            startup_url_input: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("https://browserscan.net (comma or space for multiple tabs)")
                    .default_value(url_val)
            }),
            notes_input: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("Anything to remember about this profile...")
                    .default_value(notes_val)
            }),
            totp_input: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("Base32 2FA Secret or otpauth:// URI...")
                    .default_value(totp_val)
            }),
            bookmarks: bookmarks_val,
            bookmark_name_input: cx.new(|cx| {
                InputState::new(window, cx).placeholder("Title (optional, e.g. My Shop)")
            }),
            bookmark_url_input: cx.new(|cx| {
                InputState::new(window, cx).placeholder("URL (e.g. seller.tiktok.com)")
            }),
            cookies_input: cx.new(|cx| {
                TextareaState::new(window, cx)
                    .rows(14)
                    .placeholder("Optional: Paste Cookie JSON or State JSON to auto-inject on Launch...")
                    .default_value(cookies_val)
            }),
            cookies_cache_key: std::cell::RefCell::new(String::new()),
            cookies_cache_status: std::cell::RefCell::new(None),
            validation_error: None,
            deleted_at: profile.deleted_at,
        }
    }

    pub fn build_profile(&self, cx: &App) -> anyhow::Result<Profile> {
        let name = self.name_input.read(cx).value().trim().to_string();
        if name.is_empty() {
            anyhow::bail!("Profile name cannot be empty");
        }
        let group_tag = self.selected_group.trim().to_string();
        let seed_str = self.seed_input.read(cx).value().trim().to_string();
        let seed: u32 = seed_str
            .parse()
            .map_err(|_| anyhow::anyhow!("Seed must be a valid 32-bit unsigned integer"))?;

        let (proxy, resolved_geo) = if self.proxy_mode == ProxyEditMode::Direct {
            (None, None)
        } else {
            match &self.selected_proxy {
                Some(cfg) => (Some(cfg.clone()), self.resolved_geo.clone()),
                None => anyhow::bail!(
                    "Select a proxy from Proxy manager or switch to 'Without proxy'"
                ),
            }
        };

        let (custom_timezone, custom_locale) = if self.auto_geo {
            (None, None)
        } else {
            let tz = {
                let t = self.custom_tz_input.read(cx).value().trim().to_string();
                (!t.is_empty()).then_some(t)
            };
            let loc = {
                let l = self.custom_locale_input.read(cx).value().trim().to_string();
                (!l.is_empty()).then_some(l)
            };
            (tz, loc)
        };
        let startup_url = {
            let u = self.startup_url_input.read(cx).value().trim().to_string();
            if u.is_empty() {
                "https://browserscan.net".to_string()
            } else {
                u
            }
        };
        let notes = self.notes_input.read(cx).value().trim().to_string();
        let totp_secret = self.totp_input.read(cx).value().trim().to_string();

        Ok(Profile {
            id: self
                .editing_id
                .clone()
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            name,
            group_tag,
            tags: self.tags.clone(),
            seed,
            os_platform: self.os_platform,
            os_version: self.os_platform.os_version_for_seed(seed).to_string(),
            brand: self.brand,
            brand_version: self.brand.version_for_seed(seed).to_string(),
            hardware_concurrency: self.hardware_concurrency,
            gpu_spoofing: self.gpu_spoofing,
            spoof_canvas: self.spoof_canvas,
            spoof_audio: self.spoof_audio,
            spoof_font: self.spoof_font,
            spoof_client_rects: self.spoof_client_rects,
            window_size: self.window_size.clone(),
            custom_timezone,
            custom_locale,
            proxy,
            resolved_geo,
            startup_url,
            notes,
            totp_secret,
            created_at: self.created_at,
            last_launched_at: self.last_launched_at,
            deleted_at: self.deleted_at,
        })
    }
}

/// GenLogin 3.0 Create / Edit Profile View (`Left: Name + Group + 5 Tabs`, `Right: Live Detail Summary Table`)
pub fn render_edit_profile_view(
    modal: &ProfileModalState,
    saved_groups: &[String],
    proxy_groups: &[(String, usize)],
    saved_proxies: &[SavedProxy],
    cx: &mut Context<BonLoginApp>,
) -> Div {
    let is_edit = modal.editing_id.is_some();
    let title = if is_edit {
        "Update Profile"
    } else {
        "Create Profile"
    };
    let cta_label = if is_edit {
        "Update"
    } else {
        "+ Create profile"
    };
    let active_tab = modal.active_tab;
    let os_platform = modal.os_platform;
    let brand = modal.brand;
    let gpu_spoofing = modal.gpu_spoofing;
    let spoof_canvas = modal.spoof_canvas;
    let spoof_audio = modal.spoof_audio;
    let spoof_font = modal.spoof_font;
    let spoof_client_rects = modal.spoof_client_rects;
    let win_size = modal.window_size.clone();
    let cores = modal.hardware_concurrency;
    let err_msg = modal.validation_error.clone();
    let name_preview = {
        let v = modal.name_input.read(cx).value().trim().to_string();
        if v.is_empty() { "-".to_string() } else { v }
    };
    let group_preview = modal.selected_group.trim().to_string();
    let seed_preview = modal.seed_input.read(cx).value().to_string();
    let seed_num: u32 = seed_preview.trim().parse().unwrap_or(1000);
    let ua_preview = brand.user_agent_for(os_platform);
    let browser_ver_preview = brand.version_for_seed(seed_num);
    let os_ver_preview = os_platform.os_version_for_seed(seed_num);
    let ram_preview = Profile::device_memory_for_seed(seed_num);
    let (webgl_vendor_preview, webgl_renderer_preview) =
        os_platform.webgl_for_seed(seed_num, gpu_spoofing);
    let url_preview = {
        let v = modal.startup_url_input.read(cx).value().trim().to_string();
        if v.is_empty() { "-".to_string() } else { v }
    };
    let bookmarks_parsed = modal.bookmarks.clone();
    let bookmarks_detail_str = if bookmarks_parsed.is_empty() {
        "None".to_string()
    } else {
        bookmarks_parsed
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let cookies_raw_ref = modal.cookies_input.read(cx).value();
    if modal.cookies_cache_key.borrow().as_str() != cookies_raw_ref.as_ref() {
        let trimmed = cookies_raw_ref.trim();
        let status = if trimmed.is_empty() {
            None
        } else {
            Some(
                crate::launcher::parse_and_normalize_cookies(trimmed, Some(&url_preview))
                    .map(|b| {
                        if b.cookies.is_empty() && b.origins.is_empty() {
                            String::new()
                        } else {
                            b.summary_badge()
                        }
                    })
                    .map_err(|e| e.to_string()),
            )
        };
        *modal.cookies_cache_key.borrow_mut() = cookies_raw_ref.to_string();
        *modal.cookies_cache_status.borrow_mut() = status;
    }
    let cookies_parse_status = modal.cookies_cache_status.borrow().clone();
    let cookies_detail_str = match &cookies_parse_status {
        None => "None".to_string(),
        Some(Ok(badge)) if badge.is_empty() => "Empty".to_string(),
        Some(Ok(badge)) => badge.clone(),
        Some(Err(_)) => "Invalid format".to_string(),
    };
    let proxy_mode = modal.proxy_mode;
    let selected_proxy = modal.selected_proxy.clone();
    let checking = modal.checking_proxy;
    let check_err = modal.proxy_check_error.clone();
    let resolved_geo = modal.resolved_geo.clone();
    let auto_geo = modal.auto_geo;
    let pool_count = saved_proxies.len();

    let proxy_detail_str = if proxy_mode == ProxyEditMode::Direct {
        "withoutProxy (Direct)".to_string()
    } else if let Some(g) = &resolved_geo {
        format!("{} ({})", g.compact_ip(), g.country_code)
    } else if let Some(cfg) = &selected_proxy {
        format!(
            "{}: {}",
            cfg.protocol.as_str().to_uppercase(),
            cfg.display_short()
        )
    } else {
        "Proxy manager (not selected)".to_string()
    };

    let tz_detail_str = if auto_geo {
        resolved_geo
            .as_ref()
            .map(|g| format!("{} (Auto IP)", g.timezone))
            .unwrap_or_else(|| "Fill based on IP".to_string())
    } else {
        let v = modal.custom_tz_input.read(cx).value().trim().to_string();
        if v.is_empty() { "Fill based on IP".to_string() } else { v }
    };

    let loc_detail_str = if auto_geo {
        resolved_geo
            .as_ref()
            .map(|g| format!("{} (Prompt)", g.locale))
            .unwrap_or_else(|| "Prompt (Auto IP)".to_string())
    } else {
        let v = modal.custom_locale_input.read(cx).value().trim().to_string();
        if v.is_empty() { "Prompt (Auto IP)".to_string() } else { v }
    };

    v_flex()
        .w_full()
        .flex_1()
        .min_h_0()
        .p_5()
        .gap_4()
        .rounded_lg()
        .bg(BonTheme::bg_panel())
        .border_1()
        .border_color(BonTheme::border())
        .overflow_hidden()
        // Header Row
        .child(
            h_flex()
                .w_full()
                .flex_shrink_0()
                .pb_3()
                .border_b_1()
                .border_color(BonTheme::border())
                .justify_between()
                .items_center()
                .child(
                    div()
                        .text_base()
                        .font_bold()
                        .text_color(BonTheme::text_primary())
                        .child(title),
                )
                .child(
                    h_flex()
                        .gap_2()
                        .child(
                            Button::new("edit-cancel-top")
                                .with_variant(BonTheme::row_action(cx))
                                .small()
                                .label("Back to Profiles")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.active_view = WorkspaceView::Profiles;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("edit-save-top")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .label(cta_label)
                                .on_click(cx.listener(|app, _, window, cx| {
                                    app.save_modal_profile(window, cx);
                                })),
                        ),
                ),
        )
        .children(err_msg.map(|msg| {
            div()
                .w_full()
                .px_3()
                .py_2()
                .rounded_md()
                .bg(BonTheme::danger_bg())
                .text_color(BonTheme::danger())
                .text_xs()
                .child(msg)
        }))
        // GenLogin 3.0 2-Column Body: Left (Name + Group + 5 Tabs) | Right (Detail Table)
        .child(
            h_flex()
                .w_full()
                .min_w_0()
                .min_h_0()
                .flex_1()
                .gap_4()
                .items_start()
                .overflow_hidden()
                // Left Column: Top Identity + 5 GenLogin Tabs (`Overview | Network | Location | Hardware | Cookies`)
                .child(
                    v_flex()
                        .id("edit-profile-left-col")
                        .w_0()
                        .flex_1()
                        .min_w_0()
                        .h_full()
                        .min_h_0()
                        .gap_4()
                        .overflow_y_scroll()
                        .child(
                            v_flex()
                                .w_full()
                                .p_4()
                                .gap_3()
                                .rounded_lg()
                                .bg(BonTheme::bg_elevated())
                                .border_1()
                                .border_color(BonTheme::border())
                                .child(
                                    h_flex()
                                        .w_full()
                                        .gap_3()
                                        .items_end()
                                        .child(
                                            v_flex()
                                                .flex_1()
                                                .min_w_0()
                                                .gap_1()
                                                .child(field_label("Name"))
                                                .child(Input::new(&modal.name_input)),
                                        )
                                        .child({
                                            let app_for_grp = cx.entity();
                                            let groups_list: Vec<String> =
                                                saved_groups.to_vec();
                                            let cur_grp = group_preview.clone();
                                            v_flex()
                                                .w(px(210.))
                                                .gap_1()
                                                .child(
                                                    h_flex()
                                                        .w_full()
                                                        .justify_between()
                                                        .items_center()
                                                        .child(field_label("Group"))
                                                        .child(
                                                            div()
                                                                .id("edit-open-groups-tab")
                                                                .cursor_pointer()
                                                                .text_xs()
                                                                .font_medium()
                                                                .text_color(BonTheme::accent())
                                                                .hover(|s| {
                                                                    s.text_color(
                                                                        BonTheme::text_primary(),
                                                                    )
                                                                })
                                                                .on_click(cx.listener(
                                                                    |app, _, _, cx| {
                                                                        app.profile_sub_tab =
                                                                            ProfileSubTab::Group;
                                                                        app.active_view =
                                                                            WorkspaceView::Profiles;
                                                                        cx.notify();
                                                                    },
                                                                ))
                                                                .child("Manage Groups"),
                                                        ),
                                                )
                                                .child({
                                                    let cur_for_menu = cur_grp.clone();
                                                    let display_grp = if cur_grp.trim().is_empty() {
                                                        "No group"
                                                    } else {
                                                        cur_grp.as_str()
                                                    };
                                                    Button::new("edit-prof-group-dropdown")
                                                        .w_full()
                                                        .outline()
                                                        .dropdown_caret(true)
                                                        .label(format!(
                                                            "{}  {display_grp}",
                                                            SfSymbol::FOLDER_FILL
                                                        ))
                                                        .dropdown_menu(move |mut menu, _, _| {
                                                            let app_none = app_for_grp.clone();
                                                            menu = menu.item(
                                                                PopupMenuItem::new("No group")
                                                                    .checked(
                                                                        cur_for_menu
                                                                            .trim()
                                                                            .is_empty(),
                                                                    )
                                                                    .on_click(move |_, _, cx| {
                                                                        app_none.update(
                                                                            cx,
                                                                            |app, cx| {
                                                                                if let Some(m) =
                                                                                    app.modal
                                                                                        .as_mut()
                                                                                {
                                                                                    m.selected_group =
                                                                                        String::new();
                                                                                }
                                                                                cx.notify();
                                                                            },
                                                                        );
                                                                    }),
                                                            );
                                                            for grp in &groups_list {
                                                                let g_val = grp.clone();
                                                                let is_sel = g_val
                                                                    .eq_ignore_ascii_case(
                                                                        &cur_for_menu,
                                                                    );
                                                                let app_pick = app_for_grp.clone();
                                                                menu = menu.item(
                                                                    PopupMenuItem::new(format!(
                                                                        "{}   {g_val}",
                                                                        SfSymbol::FOLDER_FILL
                                                                    ))
                                                                    .checked(is_sel)
                                                                    .on_click(
                                                                        move |_, _, cx| {
                                                                            let g = g_val.clone();
                                                                            app_pick.update(
                                                                                cx,
                                                                                |app, cx| {
                                                                                    if let Some(m) =
                                                                                        app.modal
                                                                                            .as_mut()
                                                                                    {
                                                                                        m.selected_group =
                                                                                            g;
                                                                                    }
                                                                                    cx.notify();
                                                                                },
                                                                            );
                                                                        },
                                                                    ),
                                                                );
                                                            }
                                                            menu
                                                        })
                                                })
                                        })
                                        .child(
                                            Button::new("edit-save-inline")
                                                .with_variant(BonTheme::primary_cta(cx))
                                                .label(cta_label)
                                                .on_click(cx.listener(|app, _, window, cx| {
                                                    app.save_modal_profile(window, cx);
                                                })),
                                        ),
                                )
                                // GenLogin 5-Tab Bar: Overview | Network | Location | Hardware | Cookies
                                .child(
                                    h_flex()
                                        .w_full()
                                        .pt_2()
                                        .border_t_1()
                                        .border_color(BonTheme::border())
                                        .gap_2()
                                        .children(
                                            [
                                                (ProfileEditorTab::Overview, "Overview"),
                                                (ProfileEditorTab::Network, "Network"),
                                                (ProfileEditorTab::Location, "Location"),
                                                (ProfileEditorTab::Hardware, "Hardware"),
                                                (ProfileEditorTab::Bookmarks, "Bookmarks"),
                                                (ProfileEditorTab::Cookies, "Cookies"),
                                            ]
                                            .into_iter()
                                            .map(|(tab, lbl)| {
                                                Button::new(SharedString::from(format!(
                                                    "prof-tab-{lbl}"
                                                )))
                                                .small()
                                                .with_variant(BonTheme::toggle_pill(
                                                    cx,
                                                    active_tab == tab,
                                                ))
                                                .label(lbl)
                                                .on_click(cx.listener(move |app, _, _, cx| {
                                                    if let Some(m) = app.modal.as_mut() {
                                                        m.active_tab = tab;
                                                        cx.notify();
                                                    }
                                                }))
                                            }),
                                        ),
                                ),
                        )
                        // Active Tab Content Card
                        .child(match active_tab {
                            ProfileEditorTab::Overview => v_flex()
                                .w_full()
                                .p_4()
                                .gap_3()
                                .rounded_lg()
                                .bg(BonTheme::bg_elevated())
                                .border_1()
                                .border_color(BonTheme::border())
                                // Browser & Operating System (GenLogin Overview Row 1)
                                .child(
                                    h_flex()
                                        .w_full()
                                        .justify_between()
                                        .items_center()
                                        .child(field_label("Browser (fingerprint-chromium 148)"))
                                        .child(
                                            h_flex().gap_1p5().children(
                                                BrowserBrand::ALL.into_iter().map(|b| {
                                                    let lbl = format!(
                                                        "{} ({})",
                                                        b.as_cli_str(),
                                                        b.version_for_seed(seed_num)
                                                    );
                                                    Button::new(SharedString::from(format!(
                                                        "brand-{}",
                                                        b.as_cli_str()
                                                    )))
                                                    .small()
                                                    .with_variant(BonTheme::toggle_pill(
                                                        cx,
                                                        brand == b,
                                                    ))
                                                    .label(lbl)
                                                    .on_click(cx.listener(move |app, _, _, cx| {
                                                        if let Some(m) = app.modal.as_mut() {
                                                            m.brand = b;
                                                            cx.notify();
                                                        }
                                                    }))
                                                }),
                                            ),
                                        ),
                                )
                                .child(
                                    h_flex()
                                        .w_full()
                                        .justify_between()
                                        .items_center()
                                        .child(field_label("Operating System"))
                                        .child(
                                            h_flex().gap_1p5().children(
                                                [
                                                    ("os-windows", PlatformType::Windows, SfSymbol::PC, "Windows 11"),
                                                    ("os-macos", PlatformType::MacOS, SfSymbol::APPLE_LOGO, "Mac OS"),
                                                    ("os-linux", PlatformType::Linux, SfSymbol::TERMINAL, "Linux"),
                                                ]
                                                .into_iter()
                                                .map(|(btn_id, target_os, icon, lbl)| {
                                                    Button::new(btn_id)
                                                        .small()
                                                        .with_variant(BonTheme::toggle_pill(
                                                            cx,
                                                            os_platform == target_os,
                                                        ))
                                                        .label(format!("{icon}  {lbl}"))
                                                        .on_click(cx.listener(move |app, _, _, cx| {
                                                            if let Some(m) = app.modal.as_mut() {
                                                                let s: u32 = m
                                                                    .seed_input
                                                                    .read(cx)
                                                                    .value()
                                                                    .trim()
                                                                    .parse()
                                                                    .unwrap_or(1000);
                                                                m.os_platform = target_os;
                                                                m.gpu_spoofing =
                                                                    GpuSpoofMode::SeedGenerated;
                                                                m.hardware_concurrency =
                                                                    target_os.optimal_cores_for_seed(s);
                                                                m.window_size = target_os
                                                                    .default_window_size()
                                                                    .to_string();
                                                                cx.notify();
                                                            }
                                                        }))
                                                }),
                                            ),
                                        ),
                                )
                                // User Agent / Fingerprint Seed + Random button
                                .child(
                                    v_flex()
                                        .w_full()
                                        .gap_1p5()
                                        .child(
                                            h_flex()
                                                .w_full()
                                                .justify_between()
                                                .items_center()
                                                .child(field_label("User Agent & Fingerprint Seed"))
                                                .child(
                                                    Button::new("btn-random-seed")
                                                        .with_variant(BonTheme::row_action(cx))
                                                        .xsmall()
                                                        .label(format!(
                                                            "{}  Random Fingerprint",
                                                            SfSymbol::ARROW_CLOCKWISE
                                                        ))
                                                        .on_click(cx.listener(
                                                            |app, _, window, cx| {
                                                                if let Some(m) = app.modal.as_mut()
                                                                {
                                                                    let new_seed: u32 =
                                                                        crate::models::Profile::random_seed();
                                                                    m.hardware_concurrency = m
                                                                        .os_platform
                                                                        .optimal_cores_for_seed(
                                                                            new_seed,
                                                                        );
                                                                    m.seed_input = cx.new(|cx| {
                                                                        InputState::new(window, cx)
                                                                            .default_value(
                                                                                new_seed
                                                                                    .to_string(),
                                                                            )
                                                                    });
                                                                    cx.notify();
                                                                }
                                                            },
                                                        )),
                                                ),
                                        )
                                        .child(
                                            div()
                                                .w_full()
                                                .min_w_0()
                                                .truncate()
                                                .px_3()
                                                .py_2()
                                                .rounded_md()
                                                .bg(BonTheme::bg_panel())
                                                .border_1()
                                                .border_color(BonTheme::border())
                                                .text_xs()
                                                .text_color(BonTheme::text_primary())
                                                .child(ua_preview.clone()),
                                        )
                                        .child(
                                            h_flex()
                                                .w_full()
                                                .gap_2()
                                                .items_center()
                                                .child(field_label("Seed (32-bit):"))
                                                .child(
                                                    div()
                                                        .w(px(160.))
                                                        .child(Input::new(&modal.seed_input)),
                                                )
                                                .child(
                                                    div()
                                                        .flex_1()
                                                        .min_w_0()
                                                        .truncate()
                                                        .text_xs()
                                                        .text_color(BonTheme::text_secondary())
                                                        .child(format!(
                                                            "Client Hints: {} {browser_ver_preview} • OS {os_ver_preview} • RAM {ram_preview} GB",
                                                            brand.as_cli_str()
                                                        )),
                                                ),
                                        ),
                                )
                                // Screen Resolution
                                .child(
                                    h_flex()
                                        .w_full()
                                        .justify_between()
                                        .items_center()
                                        .child(field_label("Screen Resolution"))
                                        .child(
                                            h_flex()
                                                .gap_1p5()
                                                .children(
                                                    [
                                                        "1024,768",
                                                        "1280,800",
                                                        "1440,900",
                                                        "1920,1080",
                                                    ]
                                                    .into_iter()
                                                    .map(|sz| {
                                                        let active = win_size == sz;
                                                        Button::new(SharedString::from(format!(
                                                            "win-{sz}"
                                                        )))
                                                        .small()
                                                        .with_variant(BonTheme::toggle_pill(
                                                            cx, active,
                                                        ))
                                                        .label(sz.replace(',', "×"))
                                                        .on_click(cx.listener(
                                                            move |app, _, _, cx| {
                                                                if let Some(m) = app.modal.as_mut()
                                                                {
                                                                    m.window_size = sz.to_string();
                                                                    cx.notify();
                                                                }
                                                            },
                                                        ))
                                                    }),
                                                ),
                                        ),
                                )
                                // CPU Cores
                                .child(
                                    h_flex()
                                        .w_full()
                                        .justify_between()
                                        .items_center()
                                        .child(field_label("CPU Cores"))
                                        .child(
                                            h_flex()
                                                .gap_1p5()
                                                .children([4u8, 8, 10, 12, 16].into_iter().map(|c| {
                                                    Button::new(("cores", c as usize))
                                                        .small()
                                                        .with_variant(BonTheme::toggle_pill(
                                                            cx,
                                                            cores == c,
                                                        ))
                                                        .label(format!("{c}C"))
                                                        .on_click(cx.listener(
                                                            move |app, _, _, cx| {
                                                                if let Some(m) = app.modal.as_mut()
                                                                {
                                                                    m.hardware_concurrency = c;
                                                                    cx.notify();
                                                                }
                                                            },
                                                        ))
                                                })),
                                        ),
                                )
                                // Start URL & Notes
                                // Start URL(s) & Notes
                                .child(
                                    h_flex()
                                        .w_full()
                                        .gap_3()
                                        .child(
                                            v_flex()
                                                .flex_1()
                                                .min_w_0()
                                                .gap_1()
                                                .child(field_label("Start URL(s) (comma/space for multi-tab)"))
                                                .child(Input::new(&modal.startup_url_input)),
                                        )
                                        .child(
                                            v_flex()
                                                .flex_1()
                                                .min_w_0()
                                                .gap_1()
                                                .child(field_label("Notes"))
                                                .child(Input::new(&modal.notes_input)),
                                        ),
                                )
                                // Bookmarks Bar (Clean Title + URL Adder & Pill Chips)
                                .child(render_modal_bookmarks_section(modal, &bookmarks_parsed, false, cx))
                                // 2FA Authenticator (TOTP) & Profile Status Tags
                                .child({
                                    let cur_totp_raw = modal.totp_input.read(cx).value().to_string();
                                    let live_totp = crate::models::generate_totp_code(
                                        &cur_totp_raw,
                                        crate::models::unix_now().max(0) as u64,
                                    );
                                    let cur_tags = modal.tags.clone();
                                    h_flex()
                                        .w_full()
                                        .gap_3()
                                        .items_start()
                                        .child(
                                            v_flex()
                                                .flex_1()
                                                .min_w_0()
                                                .gap_1()
                                                .child(
                                                    h_flex()
                                                        .w_full()
                                                        .justify_between()
                                                        .items_center()
                                                        .child(field_label("2FA Secret (TOTP Base32 / otpauth://)"))
                                                        .children(live_totp.map(|(code, rem)| {
                                                            let copy_code = code.clone();
                                                            Button::new("modal-copy-live-totp")
                                                                .with_variant(BonTheme::outline_blue(cx))
                                                                .xsmall()
                                                                .label(format!(
                                                                    "{} {} {} ({rem}s)", SfSymbol::LOCK_FILL,
                                                                    &code[..3],
                                                                    &code[3..]
                                                                ))
                                                                .on_click(cx.listener(move |app, _, _, cx| {
                                                                    cx.write_to_clipboard(
                                                                        ClipboardItem::new_string(copy_code.clone()),
                                                                    );
                                                                    app.banner_message = Some(format!(
                                                                        "Copied 2FA code: {copy_code}"
                                                                    ));
                                                                    cx.notify();
                                                                }))
                                                        })),
                                                )
                                                .child(Input::new(&modal.totp_input)),
                                        )
                                        .child(
                                            v_flex()
                                                .flex_1()
                                                .min_w_0()
                                                .gap_1()
                                                .child(field_label("Status Tags"))
                                                .child(
                                                    h_flex()
                                                        .w_full()
                                                        .gap_1()
                                                        .flex_wrap()
                                                        .children(
                                                            Profile::PRESET_TAGS.into_iter().map(|tag| {
                                                                let active = cur_tags
                                                                    .iter()
                                                                    .any(|t| t.eq_ignore_ascii_case(tag));
                                                                let tag_s = tag.to_string();
                                                                Button::new(SharedString::from(format!(
                                                                    "modal-tag-{tag}"
                                                                )))
                                                                .xsmall()
                                                                .with_variant(BonTheme::toggle_pill(
                                                                    cx, active,
                                                                ))
                                                                .label(tag)
                                                                .on_click(cx.listener(
                                                                    move |app, _, _, cx| {
                                                                        if let Some(m) =
                                                                            app.modal.as_mut()
                                                                        {
                                                                            if let Some(pos) = m
                                                                                .tags
                                                                                .iter()
                                                                                .position(|t| {
                                                                                    t.eq_ignore_ascii_case(
                                                                                        &tag_s,
                                                                                    )
                                                                                })
                                                                            {
                                                                                m.tags.remove(pos);
                                                                            } else {
                                                                                m.tags.push(
                                                                                    tag_s.clone(),
                                                                                );
                                                                            }
                                                                            cx.notify();
                                                                        }
                                                                    },
                                                                ))
                                                            }),
                                                        ),
                                                ),
                                        )
                                })
                                .with_animation(
                                    "prof-tab-overview-enter",
                                    BonTheme::ui_enter_anim(),
                                    |this, delta| this.opacity(delta),
                                )
                                .into_any_element(),

                            ProfileEditorTab::Network => v_flex()
                                .w_full()
                                .p_4()
                                .gap_3()
                                .rounded_lg()
                                .bg(BonTheme::bg_elevated())
                                .border_1()
                                .border_color(BonTheme::border())
                                .child(
                                    h_flex()
                                        .w_full()
                                        .justify_between()
                                        .items_center()
                                        .child(field_label("Proxy type"))
                                        .child(
                                            div()
                                                .px_2()
                                                .py_0p5()
                                                .rounded_sm()
                                                .bg(if proxy_mode == ProxyEditMode::Direct {
                                                    BonTheme::bg_panel()
                                                } else if resolved_geo.is_some() {
                                                    BonTheme::success_bg()
                                                } else if check_err.is_some() {
                                                    BonTheme::danger_bg()
                                                } else {
                                                    BonTheme::warning_bg()
                                                })
                                                .text_xs()
                                                .font_semibold()
                                                .text_color(
                                                    if proxy_mode == ProxyEditMode::Direct {
                                                        BonTheme::text_secondary()
                                                    } else if resolved_geo.is_some() {
                                                        BonTheme::success()
                                                    } else if check_err.is_some() {
                                                        BonTheme::danger()
                                                    } else {
                                                        BonTheme::warning()
                                                    },
                                                )
                                                .child(if proxy_mode == ProxyEditMode::Direct {
                                                    "Without proxy (Local IP)".to_string()
                                                } else if let Some(g) = &resolved_geo {
                                                    format!("Verified: {}", g.summary_badge())
                                                } else if check_err.is_some() {
                                                    "Connection Failed".to_string()
                                                } else {
                                                    "Not checked yet".to_string()
                                                }),
                                        ),
                                )
                                // 2-Way Switcher: Proxy manager | Without proxy (no raw proxy input allowed outside Proxy manager)
                                .child(
                                    h_flex()
                                        .w_full()
                                        .gap_1p5()
                                        .child(
                                            Button::new("pmode-pool")
                                                .small()
                                                .with_variant(BonTheme::toggle_pill(
                                                    cx,
                                                    proxy_mode == ProxyEditMode::SavedPool,
                                                ))
                                                .label(format!("Proxy manager ({pool_count})"))
                                                .on_click(cx.listener(|app, _, _, cx| {
                                                    app.set_modal_proxy_mode(
                                                        ProxyEditMode::SavedPool,
                                                        cx,
                                                    );
                                                })),
                                        )
                                        .child(
                                            Button::new("pmode-direct")
                                                .small()
                                                .with_variant(BonTheme::toggle_pill(
                                                    cx,
                                                    proxy_mode == ProxyEditMode::Direct,
                                                ))
                                                .label("Without proxy")
                                                .on_click(cx.listener(|app, _, _, cx| {
                                                    app.set_modal_proxy_mode(
                                                        ProxyEditMode::Direct,
                                                        cx,
                                                    );
                                                })),
                                        ),
                                )
                                .children((proxy_mode == ProxyEditMode::Direct).then(|| {
                                    div()
                                        .w_full()
                                        .px_3()
                                        .py_2p5()
                                        .rounded_md()
                                        .bg(BonTheme::bg_panel())
                                        .border_1()
                                        .border_color(BonTheme::border())
                                        .text_xs()
                                        .text_color(BonTheme::text_secondary())
                                        .child("Do not use a Proxy. The profile will use your network's original IP address.")
                                }))
                                .children((proxy_mode == ProxyEditMode::SavedPool).then(|| {
                                    let app_for_menu = cx.entity();
                                    let proxies_for_menu: Vec<SavedProxy> =
                                        saved_proxies.to_vec();
                                    let selected_sp_label = selected_proxy
                                        .as_ref()
                                        .map(|cfg| {
                                            if let Some(sp) = saved_proxies
                                                .iter()
                                                .find(|sp| &sp.config == cfg)
                                            {
                                                let flag = sp
                                                    .resolved_geo
                                                    .as_ref()
                                                    .map(|g| {
                                                        crate::models::GeoInfo::country_flag(
                                                            &g.country_code,
                                                        )
                                                    })
                                                    .unwrap_or(SfSymbol::GLOBE);
                                                format!(
                                                    "{flag}  {}:{} ({}) - {} (#{})",
                                                    sp.config.host,
                                                    sp.config.port,
                                                    sp.config.protocol.as_str().to_uppercase(),
                                                    sp.name,
                                                    sp.group_tag,
                                                )
                                            } else {
                                                format!(
                                                    "{}  {} ({})",
                                                    SfSymbol::GLOBE,
                                                    cfg.display_short(),
                                                    cfg.protocol.as_str().to_uppercase(),
                                                )
                                            }
                                        })
                                        .unwrap_or_else(|| {
                                            "Select proxy from Proxy manager".to_string()
                                        });

                                    v_flex()
                                        .w_full()
                                        .gap_2p5()
                                        .p_3()
                                        .rounded_md()
                                        .bg(BonTheme::bg_panel())
                                        .border_1()
                                        .border_color(BonTheme::border())
                                        .child(
                                            h_flex()
                                                .w_full()
                                                .justify_between()
                                                .items_center()
                                                .child(field_label(
                                                    "Choose proxy created in Proxy manager",
                                                ))
                                                .child(
                                                    h_flex()
                                                        .gap_1p5()
                                                        .items_center()
                                                        .children(selected_proxy.is_some().then(
                                                            || {
                                                                Button::new("modal-check-proxy")
                                                                    .with_variant(
                                                                        BonTheme::primary_cta(cx),
                                                                    )
                                                                    .small()
                                                                    .disabled(checking)
                                                                    .label(if checking {
                                                                        "Checking..."
                                                                    } else {
                                                                        "Check proxy"
                                                                    })
                                                                    .on_click(cx.listener(
                                                                        |app, _, _, cx| {
                                                                            app.check_modal_proxy(
                                                                                cx,
                                                                            );
                                                                        },
                                                                    ))
                                                            },
                                                        ))
                                                        .child(
                                                            Button::new("pmode-goto-proxy-mgr")
                                                                .with_variant(
                                                                    BonTheme::outline_blue(cx),
                                                                )
                                                                .small()
                                                                .label("Open Proxy manager")
                                                                .on_click(cx.listener(
                                                                    |app, _, _, cx| {
                                                                        app.active_view =
                                                                            WorkspaceView::Proxies;
                                                                        cx.notify();
                                                                    },
                                                                )),
                                                        ),
                                                ),
                                        )
                                        .child(
                                            h_flex()
                                                .w_full()
                                                .gap_2()
                                                .flex_wrap()
                                                .items_center()
                                                .child(
                                                    Button::new("select-saved-proxy-dropdown")
                                                        .min_w(px(280.))
                                                        .outline()
                                                        .dropdown_caret(true)
                                                        .small()
                                                        .disabled(saved_proxies.is_empty())
                                                        .label(selected_sp_label)
                                                        .dropdown_menu(move |mut menu, _, _| {
                                                            for sp in &proxies_for_menu {
                                                                let sp_id = sp.id.clone();
                                                                let app_pick = app_for_menu.clone();
                                                                let flag = sp
                                                                    .resolved_geo
                                                                    .as_ref()
                                                                    .map(|g| {
                                                                        crate::models::GeoInfo::country_flag(
                                                                            &g.country_code,
                                                                        )
                                                                    })
                                                                    .unwrap_or(SfSymbol::GLOBE);
                                                                let item_label = format!(
                                                                    "{flag}  {}:{} ({}) - {} (#{})",
                                                                    sp.config.host,
                                                                    sp.config.port,
                                                                    sp.config
                                                                        .protocol
                                                                        .as_str()
                                                                        .to_uppercase(),
                                                                    sp.name,
                                                                    sp.group_tag
                                                                );
                                                                menu = menu.item(
                                                                    PopupMenuItem::new(item_label)
                                                                        .on_click(
                                                                            move |_, _, cx| {
                                                                                app_pick.update(
                                                                                    cx,
                                                                                    |app, cx| {
                                                                                        app.select_saved_proxy_for_modal(
                                                                                            &sp_id,
                                                                                            cx,
                                                                                        );
                                                                                    },
                                                                                );
                                                                            },
                                                                        ),
                                                                );
                                                            }
                                                            menu
                                                        }),
                                                )
                                                .children((!proxy_groups.is_empty()).then(|| {
                                                    h_flex()
                                                        .gap_1p5()
                                                        .flex_wrap()
                                                        .items_center()
                                                        .child(field_label("Random by Tag:"))
                                                        .children(
                                                            proxy_groups.iter().map(
                                                                |(grp, cnt)| {
                                                                    let grp_click = grp.clone();
                                                                    Button::new(SharedString::from(
                                                                        format!("pick-pgrp-{grp}"),
                                                                    ))
                                                                    .with_variant(
                                                                        BonTheme::row_action(cx),
                                                                    )
                                                                    .small()
                                                                    .label(format!(
                                                                        "#{grp} ({cnt})"
                                                                    ))
                                                                    .on_click(cx.listener(
                                                                        move |app, _, _, cx| {
                                                                            app.fill_modal_proxy_from_group(
                                                                                Some(&grp_click),
                                                                                cx,
                                                                            );
                                                                        },
                                                                    ))
                                                                },
                                                            ),
                                                        )
                                                })),
                                        )
                                        .children(saved_proxies.is_empty().then(|| {
                                            div()
                                                .text_xs()
                                                .text_color(BonTheme::text_muted())
                                                .child("No proxies in Proxy manager yet. Click 'Open Proxy manager' to create proxies first.")
                                        }))
                                        .children(resolved_geo.map(|g| {
                                            div()
                                                .w_full()
                                                .px_3()
                                                .py_2()
                                                .rounded_md()
                                                .bg(BonTheme::success_bg())
                                                .border_1()
                                                .border_color(BonTheme::success())
                                                .text_xs()
                                                .font_semibold()
                                                .text_color(BonTheme::success())
                                                .child(format!(
                                                    "Proxy Online: {} • Country: {} • Timezone: {} • Language: {}",
                                                    g.compact_ip(),
                                                    g.country_code,
                                                    g.timezone,
                                                    g.locale
                                                ))
                                        }))
                                        .children(check_err.map(|err| {
                                            div()
                                                .w_full()
                                                .px_3()
                                                .py_2()
                                                .rounded_md()
                                                .bg(BonTheme::danger_bg())
                                                .border_1()
                                                .border_color(BonTheme::danger())
                                                .text_xs()
                                                .text_color(BonTheme::danger())
                                                .child(format!("Proxy Check Failed: {err}"))
                                        }))
                                }))
                                .child(
                                    h_flex()
                                        .w_full()
                                        .pt_2()
                                        .border_t_1()
                                        .border_color(BonTheme::border())
                                        .justify_between()
                                        .items_center()
                                        .child(field_label("WebRTC Mode"))
                                        .child(
                                            div()
                                                .px_2()
                                                .py_0p5()
                                                .rounded_sm()
                                                .bg(BonTheme::accent_subtle())
                                                .text_xs()
                                                .font_semibold()
                                                .text_color(BonTheme::accent())
                                                .child("Forward / Non-Proxied UDP Locked"),
                                        ),
                                )
                                .with_animation(
                                    "prof-tab-network-enter",
                                    BonTheme::ui_enter_anim(),
                                    |this, delta| this.opacity(delta),
                                )
                                .into_any_element(),

                            ProfileEditorTab::Location => v_flex()
                                .w_full()
                                .p_4()
                                .gap_3()
                                .rounded_lg()
                                .bg(BonTheme::bg_elevated())
                                .border_1()
                                .border_color(BonTheme::border())
                                .child(
                                    h_flex()
                                        .w_full()
                                        .justify_between()
                                        .items_center()
                                        .child(field_label(
                                            "Fill timezone & geolocation based on external IP",
                                        ))
                                        .child(
                                            h_flex()
                                                .gap_1p5()
                                                .child(
                                                    Button::new("geo-auto-on")
                                                        .small()
                                                        .with_variant(BonTheme::toggle_pill(
                                                            cx, auto_geo,
                                                        ))
                                                        .label("Auto-match IP (Recommended)")
                                                        .on_click(cx.listener(|app, _, _, cx| {
                                                            if let Some(m) = app.modal.as_mut() {
                                                                m.auto_geo = true;
                                                                cx.notify();
                                                            }
                                                        })),
                                                )
                                                .child(
                                                    Button::new("geo-auto-off")
                                                        .small()
                                                        .with_variant(BonTheme::toggle_pill(
                                                            cx, !auto_geo,
                                                        ))
                                                        .label("Manual Override")
                                                        .on_click(cx.listener(|app, _, _, cx| {
                                                            if let Some(m) = app.modal.as_mut() {
                                                                m.auto_geo = false;
                                                                cx.notify();
                                                            }
                                                        })),
                                                ),
                                        ),
                                )
                                .children(auto_geo.then(|| {
                                    div()
                                        .w_full()
                                        .px_3()
                                        .py_2p5()
                                        .rounded_md()
                                        .bg(BonTheme::bg_panel())
                                        .border_1()
                                        .border_color(BonTheme::border())
                                        .text_xs()
                                        .text_color(BonTheme::text_secondary())
                                        .child("Timezone and language automatically follow the external IP address of your proxy or local network on every launch.")
                                }))
                                .children((!auto_geo).then(|| {
                                    v_flex()
                                        .w_full()
                                        .gap_2p5()
                                        .child(
                                            h_flex()
                                                .w_full()
                                                .gap_1p5()
                                                .flex_wrap()
                                                .items_center()
                                                .child(field_label("Quick Region:"))
                                                .children(
                                                    [
                                                        ("VN", "Asia/Ho_Chi_Minh", "vi-VN"),
                                                        ("US-NY", "America/New_York", "en-US"),
                                                        ("US-LA", "America/Los_Angeles", "en-US"),
                                                        ("UK", "Europe/London", "en-GB"),
                                                        ("SG", "Asia/Singapore", "en-US"),
                                                        ("JP", "Asia/Tokyo", "ja-JP"),
                                                    ]
                                                    .into_iter()
                                                    .map(|(lbl, tz, loc)| {
                                                        Button::new(SharedString::from(format!(
                                                            "q-reg-{lbl}"
                                                        )))
                                                        .with_variant(BonTheme::row_action(cx))
                                                        .small()
                                                        .label(lbl)
                                                        .on_click(cx.listener(
                                                            move |app, _, window, cx| {
                                                                app.set_modal_region_preset(
                                                                    tz, loc, window, cx,
                                                                );
                                                            },
                                                        ))
                                                    }),
                                                ),
                                        )
                                        .child(
                                            h_flex()
                                                .w_full()
                                                .gap_3()
                                                .child(
                                                    v_flex()
                                                        .flex_1()
                                                        .gap_1()
                                                        .child(field_label("Timezone (IANA)"))
                                                        .child(Input::new(&modal.custom_tz_input)),
                                                )
                                                .child(
                                                    v_flex()
                                                        .w(px(160.))
                                                        .gap_1()
                                                        .child(field_label("Language / Locale"))
                                                        .child(Input::new(
                                                            &modal.custom_locale_input,
                                                        )),
                                                ),
                                        )
                                }))
                                .with_animation(
                                    "prof-tab-location-enter",
                                    BonTheme::ui_enter_anim(),
                                    |this, delta| this.opacity(delta),
                                )
                                .into_any_element(),

                            ProfileEditorTab::Hardware => v_flex()
                                .w_full()
                                .p_4()
                                .gap_3()
                                .rounded_lg()
                                .bg(BonTheme::bg_elevated())
                                .border_1()
                                .border_color(BonTheme::border())
                                .child(field_label(
                                    "Hardware Parameters (WebGL, Canvas, Client Rects, Audio Context, Fonts)",
                                ))
                                .child(
                                    h_flex()
                                        .w_full()
                                        .gap_2()
                                        .flex_wrap()
                                        .child(
                                            Button::new("toggle-canvas")
                                                .small()
                                                .with_variant(BonTheme::toggle_pill(
                                                    cx,
                                                    spoof_canvas,
                                                ))
                                                .label(if spoof_canvas {
                                                    "Canvas: Noise"
                                                } else {
                                                    "Canvas: Off"
                                                })
                                                .on_click(cx.listener(|app, _, _, cx| {
                                                    if let Some(m) = app.modal.as_mut() {
                                                        m.spoof_canvas = !m.spoof_canvas;
                                                        cx.notify();
                                                    }
                                                })),
                                        )
                                        .child(
                                            Button::new("toggle-rects")
                                                .small()
                                                .with_variant(BonTheme::toggle_pill(
                                                    cx,
                                                    spoof_client_rects,
                                                ))
                                                .label(if spoof_client_rects {
                                                    "Client Rects: Noise"
                                                } else {
                                                    "Client Rects: Off"
                                                })
                                                .on_click(cx.listener(|app, _, _, cx| {
                                                    if let Some(m) = app.modal.as_mut() {
                                                        m.spoof_client_rects =
                                                            !m.spoof_client_rects;
                                                        cx.notify();
                                                    }
                                                })),
                                        )
                                        .child(
                                            Button::new("toggle-audio")
                                                .small()
                                                .with_variant(BonTheme::toggle_pill(
                                                    cx,
                                                    spoof_audio,
                                                ))
                                                .label(if spoof_audio {
                                                    "Audio Context: Noise"
                                                } else {
                                                    "Audio Context: Off"
                                                })
                                                .on_click(cx.listener(|app, _, _, cx| {
                                                    if let Some(m) = app.modal.as_mut() {
                                                        m.spoof_audio = !m.spoof_audio;
                                                        cx.notify();
                                                    }
                                                })),
                                        )
                                        .child(
                                            Button::new("toggle-font")
                                                .small()
                                                .with_variant(BonTheme::toggle_pill(cx, spoof_font))
                                                .label(if spoof_font {
                                                    "Fonts: Noise"
                                                } else {
                                                    "Fonts: Off"
                                                })
                                                .on_click(cx.listener(|app, _, _, cx| {
                                                    if let Some(m) = app.modal.as_mut() {
                                                        m.spoof_font = !m.spoof_font;
                                                        cx.notify();
                                                    }
                                                })),
                                        ),
                                )
                                .child(
                                    h_flex()
                                        .w_full()
                                        .pt_2()
                                        .border_t_1()
                                        .border_color(BonTheme::border())
                                        .justify_between()
                                        .items_center()
                                        .child(field_label("WebGL Vendor & Renderer"))
                                        .child(
                                            h_flex()
                                                .gap_1p5()
                                                .child(
                                                    Button::new("gpu-native")
                                                        .small()
                                                        .with_variant(BonTheme::toggle_pill(
                                                            cx,
                                                            gpu_spoofing
                                                                == GpuSpoofMode::NativePassthrough,
                                                        ))
                                                        .label("Apple Metal Native (Off)")
                                                        .on_click(cx.listener(|app, _, _, cx| {
                                                            if let Some(m) = app.modal.as_mut() {
                                                                m.gpu_spoofing =
                                                                    GpuSpoofMode::NativePassthrough;
                                                                cx.notify();
                                                            }
                                                        })),
                                                )
                                                .child(
                                                    Button::new("gpu-seed")
                                                        .small()
                                                        .with_variant(BonTheme::toggle_pill(
                                                            cx,
                                                            gpu_spoofing
                                                                == GpuSpoofMode::SeedGenerated,
                                                        ))
                                                        .label("WebGL: Noise (Seed GPU)")
                                                        .on_click(cx.listener(|app, _, _, cx| {
                                                            if let Some(m) = app.modal.as_mut() {
                                                                m.gpu_spoofing =
                                                                    GpuSpoofMode::SeedGenerated;
                                                                cx.notify();
                                                            }
                                                        })),
                                                ),
                                        ),
                                )
                                .with_animation(
                                    "prof-tab-hardware-enter",
                                    BonTheme::ui_enter_anim(),
                                    |this, delta| this.opacity(delta),
                                )
                                .into_any_element(),

                            ProfileEditorTab::Cookies => v_flex()
                                .w_full()
                                .flex_1()
                                .p_4()
                                .gap_3()
                                .rounded_lg()
                                .bg(BonTheme::bg_elevated())
                                .border_1()
                                .border_color(BonTheme::border())
                                .child(
                                    h_flex()
                                        .w_full()
                                        .justify_between()
                                        .items_center()
                                        .gap_2()
                                        .child(field_label(
                                            "Import or Export Cookies",
                                        ))
                                        .child(
                                            h_flex()
                                                .gap_1p5()
                                                .items_center()
                                                .child(
                                                    Button::new("modal-import-cookie-file")
                                                        .with_variant(BonTheme::outline_blue(cx))
                                                        .small()
                                                        .label(format!(
                                                            "{} Import File",
                                                            SfSymbol::ARROW_UP_DOC
                                                        ))
                                                        .on_click(cx.listener(
                                                            |app, _, window, cx| {
                                                                app.pick_modal_cookie_file(
                                                                    window, cx,
                                                                );
                                                            },
                                                        )),
                                                )
                                                .child(
                                                    Button::new("modal-paste-cookies")
                                                        .with_variant(BonTheme::row_action(cx))
                                                        .small()
                                                        .label(format!(
                                                            "{} Paste",
                                                            SfSymbol::DOC_ON_DOC
                                                        ))
                                                        .on_click(cx.listener(
                                                            |app, _, window, cx| {
                                                                app.paste_modal_cookies_from_clipboard(
                                                                    window, cx,
                                                                );
                                                            },
                                                        )),
                                                )
                                                .child(
                                                    Button::new("modal-format-cookies")
                                                        .with_variant(BonTheme::row_action(cx))
                                                        .small()
                                                        .label(format!(
                                                            "{} Format JSON",
                                                            SfSymbol::CHECKMARK
                                                        ))
                                                        .on_click(cx.listener(
                                                            |app, _, window, cx| {
                                                                app.format_modal_cookies(
                                                                    window, cx,
                                                                );
                                                            },
                                                        )),
                                                )
                                                .child(
                                                    Button::new("modal-copy-cookies")
                                                        .with_variant(BonTheme::row_action(cx))
                                                        .small()
                                                        .label(format!(
                                                            "{} Copy JSON",
                                                            SfSymbol::ARROW_DOWN_DOC
                                                        ))
                                                        .on_click(cx.listener(
                                                            |app, _, _, cx| {
                                                                if let Some(m) = app.modal.as_ref()
                                                                {
                                                                    let c = m
                                                                        .cookies_input
                                                                        .read(cx)
                                                                        .value()
                                                                        .to_string();
                                                                    cx.write_to_clipboard(
                                                                        ClipboardItem::new_string(c),
                                                                    );
                                                                    app.banner_message = Some(
                                                                        "Copied profile cookies JSON to clipboard"
                                                                            .to_string(),
                                                                    );
                                                                    cx.notify();
                                                                }
                                                            },
                                                        )),
                                                )
                                                .child(
                                                    Button::new("modal-clear-cookies")
                                                        .with_variant(BonTheme::row_action(cx))
                                                        .small()
                                                        .label(format!(
                                                            "{} Clear",
                                                            SfSymbol::TRASH
                                                        ))
                                                        .on_click(cx.listener(
                                                            |app, _, window, cx| {
                                                                app.set_modal_cookies_text(
                                                                    String::new(),
                                                                    window,
                                                                    cx,
                                                                );
                                                                app.banner_message = Some(
                                                                    "Cleared cookies input"
                                                                        .to_string(),
                                                                );
                                                                cx.notify();
                                                            },
                                                        )),
                                                ),
                                        ),
                                )
                                .child(match &cookies_parse_status {
                                    None => div()
                                        .w_full()
                                        .px_2p5()
                                        .py_1p5()
                                        .rounded_md()
                                        .bg(BonTheme::bg_well())
                                        .text_xs()
                                        .text_color(BonTheme::text_secondary())
                                        .child(
                                            "Supports: Cookie-Editor JSON [...], Playwright State JSON, J2Team JSON, Netscape .txt, cURL, or raw key=value (auto-detects FB/Google/TikTok/X/Shopee).",
                                        ),
                                    Some(Ok(badge)) => div()
                                        .w_full()
                                        .px_2p5()
                                        .py_1p5()
                                        .rounded_md()
                                        .bg(BonTheme::bg_well())
                                        .border_1()
                                        .border_color(BonTheme::success())
                                        .text_xs()
                                        .font_semibold()
                                        .text_color(BonTheme::success())
                                        .child(format!(
                                            "{}  Ready to inject: {}",
                                            SfSymbol::CHECKMARK_CIRCLE_FILL,
                                            if badge.is_empty() { "Empty" } else { badge }
                                        )),
                                    Some(Err(err)) => div()
                                        .w_full()
                                        .px_2p5()
                                        .py_1p5()
                                        .rounded_md()
                                        .bg(BonTheme::danger_bg())
                                        .border_1()
                                        .border_color(BonTheme::danger())
                                        .text_xs()
                                        .font_semibold()
                                        .text_color(BonTheme::danger())
                                        .child(format!(
                                            "{}  Invalid cookie format: {err}",
                                            SfSymbol::EXCLAMATIONMARK_TRIANGLE_FILL
                                        )),
                                })
                                .child(
                                    v_flex()
                                        .w_full()
                                        .flex_1()
                                        .gap_1p5()
                                        .child(field_label(
                                            "Paste Cookies (auto-normalized & injected when launching or updating profile):",
                                        ))
                                        .child(Textarea::new(&modal.cookies_input).w_full()),
                                )
                                .with_animation(
                                    "prof-tab-cookies-enter",
                                    BonTheme::ui_enter_anim(),
                                    |this, delta| this.opacity(delta),
                                )
                                .into_any_element(),
                            ProfileEditorTab::Bookmarks => v_flex()
                                .w_full()
                                .p_4()
                                .gap_3p5()
                                .rounded_lg()
                                .bg(BonTheme::bg_elevated())
                                .border_1()
                                .border_color(BonTheme::border())
                                .child(render_modal_bookmarks_section(modal, &bookmarks_parsed, true, cx))
                                .with_animation(
                                    "prof-tab-bookmarks-enter",
                                    BonTheme::ui_enter_anim(),
                                    |this, delta| this.opacity(delta),
                                )
                                .into_any_element(),
                        }),
                )
                // Right Column: GenLogin 3.0 `Detail` Live Summary Table (`menu-bar_profile_create-profile_01.png`)
                .child(
                    v_flex()
                        .id("edit-profile-detail-col")
                        .w(px(290.))
                        .max_h_full()
                        .min_h_0()
                        .flex_shrink_0()
                        .p_4()
                        .gap_1p5()
                        .rounded_lg()
                        .bg(BonTheme::bg_elevated())
                        .border_1()
                        .border_color(BonTheme::border())
                        .overflow_y_scroll()
                        .child(
                            div()
                                .pb_2()
                                .border_b_1()
                                .border_color(BonTheme::border())
                                .text_sm()
                                .font_bold()
                                .text_color(BonTheme::text_primary())
                                .child("Detail"),
                        )
                        .child(detail_summary_row("Profile Name", name_preview))
                        .child(detail_summary_row("Group", group_preview))
                        .child(detail_summary_row(
                            "Browser",
                            format!("{} ({browser_ver_preview})", brand.as_cli_str()),
                        ))
                        .child(detail_summary_row(
                            "OS",
                            format!("{} ({os_ver_preview})", os_platform.label()),
                        ))
                        .child(detail_summary_row("User Agent", ua_preview))
                        .child(detail_summary_row(
                            "Screen Resolution",
                            win_size.replace(',', "×"),
                        ))
                        .child(detail_summary_row(
                            "CPU / RAM",
                            format!("{cores} Cores / {ram_preview} GB"),
                        ))
                        .child(detail_summary_row("Start URL", url_preview))
                        .child(detail_summary_row("Bookmarks", bookmarks_detail_str))
                        .child(detail_summary_row("Cookies", cookies_detail_str))
                        .child(detail_summary_row("Proxy", proxy_detail_str))
                        .child(detail_summary_row(
                            "WebRTC",
                            if proxy_mode == ProxyEditMode::Direct {
                                "Real".to_string()
                            } else {
                                "Forward".to_string()
                            },
                        ))
                        .child(detail_summary_row("Timezone", tz_detail_str))
                        .child(detail_summary_row("Geolocation", loc_detail_str))
                        .child(detail_summary_row(
                            "Canvas",
                            if spoof_canvas { "Noise" } else { "Off" }.to_string(),
                        ))
                        .child(detail_summary_row(
                            "Client Rects",
                            if spoof_client_rects { "Noise" } else { "Off" }.to_string(),
                        ))
                        .child(detail_summary_row(
                            "Audio Context",
                            if spoof_audio { "Noise" } else { "Off" }.to_string(),
                        ))
                        .child(detail_summary_row(
                            "Font",
                            if spoof_font { "Noise" } else { "Off" }.to_string(),
                        ))
                        .child(detail_summary_row(
                            "WebGL",
                            if gpu_spoofing == GpuSpoofMode::SeedGenerated {
                                "Noise"
                            } else {
                                "Off (Native)"
                            }
                            .to_string(),
                        ))
                        .child(detail_summary_row(
                            "WebGL Vendor",
                            webgl_vendor_preview.to_string(),
                        ))
                        .child(detail_summary_row(
                            "WebGL Renderer",
                            webgl_renderer_preview.to_string(),
                        )),
                ),
        )
}

pub fn detail_summary_row(label: &'static str, value: String) -> Div {
    h_flex()
        .w_full()
        .min_w_0()
        .px_1()
        .py_1()
        .rounded_sm()
        .border_b_1()
        .border_color(BonTheme::border())
        .justify_between()
        .items_center()
        .gap_2()
        .overflow_hidden()
        .hover(|s| s.bg(BonTheme::bg_hover()))
        .child(
            div()
                .flex_shrink_0()
                .text_xs()
                .text_color(BonTheme::text_secondary())
                .child(label),
        )
        .child(
            div()
                .min_w_0()
                .truncate()
                .text_xs()
                .font_semibold()
                .text_color(BonTheme::text_primary())
                .child(value),
        )
}

/// GenLogin 3.0 `Extensions` View (`docs/genlogin-3.0/assets/menu-bar_extensions_01.png`)
pub fn render_extensions_view(
    app: &BonLoginApp,
    cx: &mut Context<BonLoginApp>,
) -> Div {
    let rows: Vec<Vec<crate::models::BrowserExtension>> =
        app.extensions.chunks(4).map(|c| c.to_vec()).collect();

    v_flex()
        .w_full()
        .flex_1()
        .min_h_0()
        .gap_4()
        .overflow_hidden()
        // Top Toolbar: [☁ Upload Extension] [🔗 Input URL Extension]
        .child(
            h_flex()
                .w_full()
                .gap_3()
                .items_center()
                .child(
                    Button::new("ext-btn-upload")
                        .with_variant(BonTheme::outline_blue(cx))
                        .small()
                        .label(format!("{}  Upload Extension", SfSymbol::ICLOUD_AND_ARROW_UP))
                        .on_click(cx.listener(|app, _, _, cx| {
                            app.popup_modal = Some(ActivePopupModal::UploadExtension);
                            cx.notify();
                        })),
                )
                .child(
                    Button::new("ext-btn-input-url")
                        .with_variant(BonTheme::primary_cta(cx))
                        .small()
                        .label(format!("{}  Input URL Extension", SfSymbol::LINK))
                        .on_click(cx.listener(|app, _, _, cx| {
                            app.popup_modal = Some(ActivePopupModal::InputUrlExtension);
                            cx.notify();
                        })),
                ),
        )
        // 4-Column Extension Card Grid
        .child(
            v_flex()
                .id("extensions-card-grid")
                .w_full()
                .flex_1()
                .gap_3p5()
                .overflow_y_scroll()
                .children(rows.into_iter().enumerate().map(|(row_idx, row_exts)| {
                    let missing = 4usize.saturating_sub(row_exts.len());
                    h_flex()
                        .w_full()
                        .gap_3p5()
                        .items_stretch()
                        .children(row_exts.into_iter().map(|ext| {
                            let ext_id_toggle = ext.id.clone();
                            let ext_id_remove = ext.id.clone();
                            let ext_id_agent = ext.id.clone();
                            let is_enabled = ext.enabled;
                            let is_default = ext.is_default;
                            let is_downloading = app.ext_tasks.contains_key(&ext.id);
                            v_flex()
                                .w_0()
                                .flex_1()
                                .min_w_0()
                                .rounded_lg()
                                .bg(BonTheme::bg_panel())
                                .border_1()
                                .border_color(if is_enabled {
                                    BonTheme::border_active()
                                } else {
                                    BonTheme::border()
                                })
                                .hover(|s| {
                                    s.bg(BonTheme::bg_hover())
                                        .border_color(BonTheme::border_active())
                                })
                                .overflow_hidden()
                                // Card Top: Extension Title (left) + Icon Badge (right)
                                .child(
                                    h_flex()
                                        .w_full()
                                        .min_w_0()
                                        .px_4()
                                        .py_3p5()
                                        .justify_between()
                                        .items_center()
                                        .gap_3()
                                        .overflow_hidden()
                                        .child(
                                            v_flex()
                                                .w_0()
                                                .flex_1()
                                                .min_w_0()
                                                .gap_0p5()
                                                .child(
                                                    div()
                                                        .w_full()
                                                        .truncate()
                                                        .text_xs()
                                                        .font_semibold()
                                                        .text_color(BonTheme::text_primary())
                                                        .child(ext.name.clone()),
                                                )
                                                .children(is_downloading.then(|| {
                                                    div()
                                                        .text_xs()
                                                        .text_color(BonTheme::warning())
                                                        .child("Downloading...")
                                                })),
                                        )
                                        .child(
                                            if let Some(icon_img) = get_extension_icon(&ext) {
                                                div()
                                                    .w(px(38.))
                                                    .h(px(38.))
                                                    .flex_shrink_0()
                                                    .rounded_md()
                                                    .overflow_hidden()
                                                    .flex()
                                                    .items_center()
                                                    .justify_center()
                                                    .child(
                                                        img(icon_img)
                                                            .w(px(36.))
                                                            .h(px(36.))
                                                            .rounded_md(),
                                                    )
                                                    .into_any_element()
                                            } else {
                                                div()
                                                    .w(px(38.))
                                                    .h(px(38.))
                                                    .flex_shrink_0()
                                                    .rounded_md()
                                                    .bg(rgb(ext.icon_bg))
                                                    .flex()
                                                    .items_center()
                                                    .justify_center()
                                                    .text_xs()
                                                    .font_bold()
                                                    .text_color(rgb(0xffffff))
                                                    .child(ext.icon_label)
                                                    .into_any_element()
                                            },
                                        ),
                                )
                                // Horizontal Divider
                                .child(div().w_full().h(px(1.)).bg(BonTheme::border()))
                                // Card Bottom: [⊗ Remove] (left, non-default only) + On/Off Switch (right)
                                .child(
                                    h_flex()
                                        .w_full()
                                        .px_4()
                                        .py_2p5()
                                        .justify_between()
                                        .items_center()
                                        .child(
                                            h_flex()
                                                .gap_3()
                                                .items_center()
                                                .child(
                                                    h_flex()
                                                        .gap_1()
                                                        .items_center()
                                                        .cursor_pointer()
                                                        .text_xs()
                                                        .text_color(BonTheme::text_secondary())
                                                        .hover(|s| s.text_color(BonTheme::accent()))
                                                        .on_mouse_down(
                                                            MouseButton::Left,
                                                            cx.listener(move |app, _, _, cx| {
                                                                app.open_or_copy_extension_agent_cli(
                                                                    &ext_id_agent,
                                                                    cx,
                                                                );
                                                            }),
                                                        )
                                                        .child(SfSymbol::TERMINAL)
                                                        .child("Agent"),
                                                )
                                                .children((!is_default).then(|| {
                                                    h_flex()
                                                        .gap_1()
                                                        .items_center()
                                                        .cursor_pointer()
                                                        .text_xs()
                                                        .text_color(BonTheme::text_secondary())
                                                        .hover(|s| s.text_color(BonTheme::danger()))
                                                        .on_mouse_down(
                                                            MouseButton::Left,
                                                            cx.listener(move |app, _, _, cx| {
                                                                app.request_delete(
                                                                    PendingDeleteAction::Extension(
                                                                        ext_id_remove.clone(),
                                                                    ),
                                                                    cx,
                                                                );
                                                            }),
                                                        )
                                                        .child(SfSymbol::TRASH)
                                                        .child("Remove")
                                                })),
                                        )
                                        .child(
                                            {
                                                let switch_anim_id = SharedString::from(format!(
                                                    "ext-switch-spring-{}",
                                                    ext.id
                                                ));
                                                div()
                                                    .w(px(34.))
                                                    .h(px(18.))
                                                    .rounded_full()
                                                    .py(px(2.))
                                                    .pl(if is_enabled { px(18.) } else { px(2.) })
                                                    .cursor_pointer()
                                                    .bg(if is_enabled {
                                                        BonTheme::accent()
                                                    } else {
                                                        rgb(0x3B4052).into()
                                                    })
                                                    .flex()
                                                    .items_center()
                                                    .on_mouse_down(
                                                        MouseButton::Left,
                                                        cx.listener(move |app, _, _, cx| {
                                                            app.toggle_extension(
                                                                &ext_id_toggle,
                                                                cx,
                                                            );
                                                        }),
                                                    )
                                                    .child(
                                                        div()
                                                            .w(px(14.))
                                                            .h(px(14.))
                                                            .rounded_full()
                                                            .bg(rgb(0xffffff)),
                                                    )
                                                    .with_spring(
                                                        switch_anim_id,
                                                        SpringAnimation::new(
                                                            BonTheme::snappy_spring(),
                                                        )
                                                        .to(is_enabled),
                                                        |this, phase| {
                                                            let off_bg: Hsla =
                                                                rgb(0x3B4052).into();
                                                            this.pl(phase.interpolate_clamped(
                                                                px(2.),
                                                                px(18.),
                                                            ))
                                                            .bg(phase.interpolate_clamped(
                                                                off_bg,
                                                                BonTheme::accent(),
                                                            ))
                                                        },
                                                    )
                                            },
                                        ),
                                )
                        }))
                        .children((0..missing).map(|pad_i| {
                            div()
                                .id(SharedString::from(format!("ext-pad-{row_idx}-{pad_i}")))
                                .w_0()
                                .flex_1()
                                .min_w_0()
                        }))
                })),
        )
}

/// GenLogin 3.0 `Proxy management` View (`docs/genlogin-3.0/assets/menu-bar_proxy-manager-and-genproxy_proxy-management_01.png`, without GenProxy)
pub fn render_proxies_view(
    app: &BonLoginApp,
    cx: &mut Context<BonLoginApp>,
) -> Div {
    let total_proxies = app.saved_proxies.len();
    let proxy_groups = app.distinct_proxy_groups_with_counts();
    let selected_pgrp = app.selected_proxy_group.clone();
    let filtered_indices: std::rc::Rc<[usize]> = app.filtered_proxy_indices().into();
    let filtered_len = filtered_indices.len();
    let checked_count = app.checked_proxy_ids.len();
    let all_filtered_checked = !filtered_indices.is_empty()
        && filtered_indices
            .iter()
            .all(|&i| app.checked_proxy_ids.contains(&app.saved_proxies[i].id));
    let any_filtered_checked = filtered_indices
        .iter()
        .any(|&i| app.checked_proxy_ids.contains(&app.saved_proxies[i].id));
    let proxy_hdr_mark = if all_filtered_checked {
        SfSymbol::CHECKMARK
    } else if any_filtered_checked {
        SfSymbol::MINUS
    } else {
        ""
    };
    let tag_dropdown_label = if selected_pgrp == "All" {
        format!("All Tag ({total_proxies})")
    } else {
        format!("#{selected_pgrp} ({filtered_len})")
    };
    let mut used_map: std::collections::HashMap<(ProxyProtocol, String, u16), usize> =
        std::collections::HashMap::new();
    for p in &app.profiles {
        if let Some(cfg) = &p.proxy {
            *used_map
                .entry((cfg.protocol, cfg.host.clone(), cfg.port))
                .or_insert(0) += 1;
        }
    }
    let used_counts = std::rc::Rc::new(used_map);

    let app_for_tag_menu = cx.entity();
    let groups_for_menu = proxy_groups.clone();

    v_flex()
        .w_full()
        .flex_1()
        .min_h_0()
        .gap_3()
        .overflow_hidden()
        // 1. GenLogin Top Toolbar: `[+ Add proxy]` + `[All Tag ▾]` + `[↻]` ... `[Check proxy]`
        .child(
            h_flex()
                .w_full()
                .justify_between()
                .items_center()
                .gap_2()
                .child(
                    h_flex()
                        .gap_2()
                        .items_center()
                        .child(
                            Button::new("pmgr-open-add-modal")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .label(format!("{}  Add proxy", SfSymbol::PLUS))
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = Some(ActivePopupModal::AddProxy);
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("pmgr-open-add-tag-modal")
                                .with_variant(BonTheme::outline_blue(cx))
                                .small()
                                .label(format!("{}  Add tag", SfSymbol::TAG_FILL))
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = Some(ActivePopupModal::AddTag);
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("pmgr-tag-dropdown")
                                .min_w(px(140.))
                                .outline()
                                .dropdown_caret(true)
                                .small()
                                .label(tag_dropdown_label)
                                .dropdown_menu(move |mut menu, _, _| {
                                    let app_all = app_for_tag_menu.clone();
                                    menu = menu.item(
                                        PopupMenuItem::new(format!("All Tag ({total_proxies})"))
                                            .on_click(move |_, _, cx| {
                                                app_all.update(cx, |app, cx| {
                                                    app.selected_proxy_group = "All".to_string();
                                                    cx.notify();
                                                });
                                            }),
                                    );
                                    for (grp, cnt) in &groups_for_menu {
                                        let grp_val = grp.clone();
                                        let app_grp = app_for_tag_menu.clone();
                                        menu = menu.item(
                                            PopupMenuItem::new(format!("#{grp} ({cnt})")).on_click(
                                                move |_, _, cx| {
                                                    let g = grp_val.clone();
                                                    app_grp.update(cx, |app, cx| {
                                                        app.selected_proxy_group = g;
                                                        cx.notify();
                                                    });
                                                },
                                            ),
                                        );
                                    }
                                    menu
                                }),
                        )
                        .children(
                            (selected_pgrp != "All").then(|| {
                                let t_del = selected_pgrp.clone();
                                Button::new("pmgr-del-cur-tag")
                                    .with_variant(BonTheme::outline_danger(cx))
                                    .small()
                                    .label(format!("{}  #{selected_pgrp}", SfSymbol::TRASH))
                                    .on_click(cx.listener(move |app, _, _, cx| {
                                        app.request_delete(
                                            PendingDeleteAction::Tag(t_del.clone()),
                                            cx,
                                        );
                                    }))
                            }),
                        )
                        .child(
                            Button::new("pmgr-refresh")
                                .with_variant(BonTheme::row_action(cx))
                                .small()
                                .label(SfSymbol::ARROW_CLOCKWISE)
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.reload_profiles();
                                    app.banner_message =
                                        Some("Refreshed proxy list".to_string());
                                    cx.notify();
                                })),
                        ),
                )
                .child(
                    h_flex()
                        .gap_2()
                        .items_center()
                        .child(
                            Button::new("pmgr-distribute-profiles")
                                .with_variant(BonTheme::row_action(cx))
                                .small()
                                .disabled(filtered_indices.is_empty())
                                .label("Assign to profiles")
                                .on_click(cx.listener(|app, _, window, cx| {
                                    app.assign_filtered_proxies_to_profiles(window, cx);
                                })),
                        )
                        .child(
                            Button::new("pmgr-check-all-top")
                                .with_variant(BonTheme::outline_blue(cx))
                                .small()
                                .disabled(filtered_indices.is_empty())
                                .label(if checked_count > 0 {
                                    format!("Check proxy ({checked_count})")
                                } else {
                                    "Check proxy".to_string()
                                })
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.check_filtered_saved_proxies(cx);
                                })),
                        ),
                ),
        )
        // 2. GenLogin Selection Action Bar (`[✕] [Check] [Copy] [Delete]` — shown when 1+ proxies checked)
        .children((checked_count > 0).then(|| {
            h_flex()
                .w_full()
                .gap_2()
                .items_center()
                .child(
                    Button::new("pmgr-clear-sel")
                        .with_variant(BonTheme::outline_blue(cx))
                        .small()
                        .label(SfSymbol::XMARK)
                        .on_click(cx.listener(|app, _, _, cx| {
                            app.clear_checked_proxies(cx);
                        })),
                )
                .child(
                    Button::new("pmgr-batch-extend")
                        .with_variant(BonTheme::success_cta(cx))
                        .small()
                        .label("Extend")
                        .on_click(cx.listener(|app, _, _, cx| {
                            app.extend_checked_saved_proxies_days(30, cx);
                        })),
                )
                .child(
                    Button::new("pmgr-batch-check")
                        .with_variant(BonTheme::primary_cta(cx))
                        .small()
                        .label("Check")
                        .on_click(cx.listener(|app, _, _, cx| {
                            app.check_filtered_saved_proxies(cx);
                        })),
                )
                .child(
                    Button::new("pmgr-batch-rotate")
                        .with_variant(BonTheme::outline_blue(cx))
                        .small()
                        .label("\u{1002af} Rotate IP")
                        .on_click(cx.listener(|app, _, _, cx| {
                            app.rotate_checked_saved_proxies(cx);
                        })),
                )
                .child(
                    Button::new("pmgr-batch-copy")
                        .with_variant(BonTheme::primary_cta(cx))
                        .small()
                        .label("Copy")
                        .on_click(cx.listener(|app, _, _, cx| {
                            app.copy_checked_saved_proxies(cx);
                        })),
                )
                .child(
                    Button::new("pmgr-batch-delete")
                        .with_variant(BonTheme::outline_danger(cx))
                        .small()
                        .label("Delete")
                        .on_click(cx.listener(|app, _, _, cx| {
                            app.request_delete(PendingDeleteAction::CheckedProxies, cx);
                        })),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(BonTheme::text_secondary())
                        .child(format!("{checked_count} selected")),
                )
                .with_animation(
                    "pmgr-batch-bar-enter",
                    BonTheme::ui_enter_anim(),
                    |this, delta| this.opacity(delta),
                )
        }))
        // 3. GenLogin Proxy Management Table (`[☐] | # | Name | Tag | Protocol support | Location / IP | Status | Profiles | Actions`)
        .child(
            v_flex()
                .w_full()
                .flex_1()
                .rounded_lg()
                .bg(BonTheme::bg_panel())
                .border_1()
                .border_color(BonTheme::border())
                .overflow_hidden()
                // Table Header
                .child(
                    h_flex()
                        .w_full()
                        .flex_shrink_0()
                        .px_3()
                        .py_2p5()
                        .gap_2()
                        .items_center()
                        .bg(BonTheme::bg_elevated())
                        .border_b_1()
                        .border_color(BonTheme::border())
                        .text_xs()
                        .font_semibold()
                        .text_color(BonTheme::text_muted())
                        .child(
                            BonTheme::checkbox(
                                "pmgr-hdr-chk-spring",
                                all_filtered_checked || any_filtered_checked,
                                proxy_hdr_mark,
                                BonTheme::bg_panel(),
                                cx.listener(|app, _, _, cx| {
                                    app.toggle_all_filtered_proxies_checked(cx);
                                }),
                            ),
                        )
                        .child(div().w(px(28.)).flex_shrink_0().truncate().child("#"))
                        .child(div().flex_1().min_w(px(140.)).truncate().child("Name"))
                        .child(div().w(px(80.)).flex_shrink_0().truncate().child("Tag"))
                        .child(div().w(px(108.)).flex_shrink_0().truncate().child("Protocol support"))
                        .child(div().w(px(84.)).flex_shrink_0().truncate().child("Started at"))
                        .child(div().w(px(116.)).flex_shrink_0().truncate().child("Expired at"))
                        .child(div().w(px(96.)).flex_shrink_0().truncate().child("Status"))
                        .child(div().w(px(72.)).flex_shrink_0().truncate().child("Profiles"))
                        .child(
                            div()
                                .w(px(92.))
                                .flex_shrink_0()
                                .flex()
                                .justify_end()
                                .child(SfSymbol::GEARSHAPE_FILL),
                        ),
                )
                // Rows Body
                .child(if filtered_indices.is_empty() {
                    v_flex()
                        .id("proxies-table-rows")
                        .w_full()
                        .flex_1()
                        .min_h_0()
                        .py_16()
                        .items_center()
                        .justify_center()
                        .gap_2()
                        .child(
                            div()
                                .text_sm()
                                .font_semibold()
                                .text_color(BonTheme::text_primary())
                                .child("No proxies found"),
                        )
                        .child(
                            div()
                                .text_xs()
                                .text_color(BonTheme::text_secondary())
                                .child(
                                    "Click '+ Add proxy' at the top-left to import your HTTP or SOCKS5 proxies.",
                                ),
                        )
                        .into_any_element()
                } else {
                    let indices_for_list = filtered_indices.clone();
                    let counts_for_list = used_counts.clone();
                    uniform_list(
                        "proxies-table-rows",
                        indices_for_list.len(),
                        cx.processor(move |app, range: std::ops::Range<usize>, _window, cx| {
                            let app_entity = cx.entity();
                            let mut items = Vec::with_capacity(range.len());
                            for row_ix in range {
                                let Some(&sp_ix) = indices_for_list.get(row_ix) else {
                                    continue;
                                };
                                let Some(sp) = app.saved_proxies.get(sp_ix) else {
                                    continue;
                                };
                                let row_num = row_ix + 1;
                                let pid = sp.id.clone();
                                let pid_chk_toggle = sp.id.clone();
                                let pid_check = sp.id.clone();
                                let is_checked = app.checked_proxy_ids.contains(&sp.id);
                                let is_checking = app.checking_proxy_ids.contains(&sp.id);
                                let used_count = counts_for_list
                                    .get(&(
                                        sp.config.protocol,
                                        sp.config.host.clone(),
                                        sp.config.port,
                                    ))
                                    .copied()
                                    .unwrap_or(0);

                                let flag = sp
                                    .resolved_geo
                                    .as_ref()
                                    .map(|g| crate::models::GeoInfo::country_flag(&g.country_code))
                                    .unwrap_or(SfSymbol::GLOBE);

                                let geo_str = if let Some(g) = &sp.resolved_geo {
                                    let short_tz =
                                        g.timezone.rsplit('/').next().unwrap_or(&g.timezone);
                                    format!("{} ({}) • {short_tz}", g.compact_ip(), g.country_code)
                                } else if let Some(err) = &sp.last_error {
                                    err.clone()
                                } else {
                                    "-".to_string()
                                };

                                let (badge_bg, badge_fg, status_text) = if is_checking {
                                    (
                                        BonTheme::info_bg(),
                                        BonTheme::info(),
                                        "CHECKING...".to_string(),
                                    )
                                } else if let Some(g) = &sp.resolved_geo {
                                    let ms = g.latency_ms.unwrap_or(0);
                                    (
                                        BonTheme::success_bg(),
                                        BonTheme::success(),
                                        if ms > 0 {
                                            format!("LIVE • {ms}ms")
                                        } else {
                                            "LIVE".to_string()
                                        },
                                    )
                                } else if sp.last_error.is_some() {
                                    (
                                        BonTheme::danger_bg(),
                                        BonTheme::danger(),
                                        "DEAD".to_string(),
                                    )
                                } else {
                                    (
                                        BonTheme::bg_elevated(),
                                        BonTheme::text_muted(),
                                        "-".to_string(),
                                    )
                                };

                                let app_row_menu = app_entity.clone();
                                let pid_menu_copy = sp.config.to_editable_string();
                                let pid_menu_assign = sp.id.clone();
                                let pid_menu_del = sp.id.clone();
                                let has_rot_url = sp.config.change_ip_url.is_some();
                                let name_str = sp.name.clone();
                                let sub_str = if geo_str != "-" && sp.resolved_geo.is_some() {
                                    format!("{} • {}", sp.config.display_short(), geo_str)
                                } else {
                                    sp.config.display_short()
                                };
                                let tag_opt = (!sp.group_tag.trim().is_empty())
                                    .then(|| format!("#{}", sp.group_tag));
                                let proto_str = sp.config.protocol.as_str().to_uppercase();
                                let started_str = sp.format_started_at();
                                let exp_color = if sp.is_expired() {
                                    BonTheme::danger()
                                } else if sp.is_expiring_soon() {
                                    BonTheme::warning()
                                } else if sp.expired_at.is_some() {
                                    BonTheme::text_primary()
                                } else {
                                    BonTheme::text_muted()
                                };
                                let exp_str = sp.format_expired_at();
                                items.push(
                                    h_flex()
                                        .w_full()
                                        .px_3()
                                        .py_2p5()
                                        .gap_2()
                                        .items_center()
                                        .border_b_1()
                                        .border_color(BonTheme::border())
                                        .bg(if is_checked {
                                            BonTheme::bg_selected()
                                        } else {
                                            BonTheme::bg_panel()
                                        })
                                        .hover(|s| {
                                            if is_checked {
                                                s.bg(rgba(0x0a84ff3d))
                                            } else {
                                                s.bg(BonTheme::bg_hover())
                                            }
                                        })
                                        .child(BonTheme::checkbox(
                                            format!("pmgr-row-chk-spring-{pid}"),
                                            is_checked,
                                            if is_checked { SfSymbol::CHECKMARK } else { "" },
                                            BonTheme::bg_elevated(),
                                            cx.listener(move |app, _, _, cx| {
                                                app.toggle_proxy_checked(&pid_chk_toggle, cx);
                                            }),
                                        ))
                                        .child(
                                            div()
                                                .w(px(28.))
                                                .flex_shrink_0()
                                                .truncate()
                                                .text_xs()
                                                .text_color(BonTheme::text_secondary())
                                                .child(format!("{row_num}")),
                                        )
                                        .child(
                                            v_flex()
                                                .w_0()
                                                .flex_1()
                                                .min_w(px(140.))
                                                .overflow_hidden()
                                                .gap_0p5()
                                                .child(
                                                    div()
                                                        .w_full()
                                                        .min_w_0()
                                                        .truncate()
                                                        .text_sm()
                                                        .font_semibold()
                                                        .text_color(BonTheme::text_primary())
                                                        .child(name_str),
                                                )
                                                .child(
                                                    h_flex()
                                                        .w_full()
                                                        .min_w_0()
                                                        .overflow_hidden()
                                                        .gap_1p5()
                                                        .items_center()
                                                        .child(
                                                            div()
                                                                .flex_shrink_0()
                                                                .text_xs()
                                                                .child(flag),
                                                        )
                                                        .child(
                                                            div()
                                                                .w_0()
                                                                .flex_1()
                                                                .min_w_0()
                                                                .truncate()
                                                                .text_xs()
                                                                .text_color(
                                                                    BonTheme::text_secondary(),
                                                                )
                                                                .child(sub_str),
                                                        ),
                                                ),
                                        )
                                        .child(
                                            div()
                                                .w(px(80.))
                                                .flex_shrink_0()
                                                .overflow_hidden()
                                                .children(tag_opt.map(|tag_lbl| {
                                                    h_flex()
                                                        .w_full()
                                                        .min_w_0()
                                                        .overflow_hidden()
                                                        .child(
                                                            div()
                                                                .max_w_full()
                                                                .truncate()
                                                                .px_1p5()
                                                                .py_0p5()
                                                                .rounded_sm()
                                                                .bg(BonTheme::accent_subtle())
                                                                .text_xs()
                                                                .text_color(BonTheme::accent())
                                                                .child(tag_lbl),
                                                        )
                                                })),
                                        )
                                        .child(
                                            div()
                                                .w(px(108.))
                                                .flex_shrink_0()
                                                .truncate()
                                                .text_xs()
                                                .font_semibold()
                                                .text_color(BonTheme::text_primary())
                                                .child(proto_str),
                                        )
                                        .child(
                                            div()
                                                .w(px(84.))
                                                .flex_shrink_0()
                                                .truncate()
                                                .text_xs()
                                                .text_color(BonTheme::text_secondary())
                                                .child(started_str),
                                        )
                                        .child(
                                            div()
                                                .w(px(116.))
                                                .flex_shrink_0()
                                                .truncate()
                                                .text_xs()
                                                .font_semibold()
                                                .text_color(exp_color)
                                                .child(exp_str),
                                        )
                                        .child(
                                            div()
                                                .w(px(96.))
                                                .flex_shrink_0()
                                                .overflow_hidden()
                                                .child({
                                                    let badge = div()
                                                        .truncate()
                                                        .px_2()
                                                        .py_0p5()
                                                        .rounded_sm()
                                                        .bg(badge_bg)
                                                        .text_xs()
                                                        .font_semibold()
                                                        .text_color(badge_fg)
                                                        .child(status_text);
                                                    h_flex().child(if is_checking {
                                                        badge
                                                            .with_animation(
                                                                SharedString::from(format!(
                                                                    "proxy-chk-pulse-{pid}"
                                                                )),
                                                                Animation::new(
                                                                    Duration::from_millis(1100),
                                                                )
                                                                .repeat()
                                                                .with_easing(pulsating_between(
                                                                    0.4, 1.0,
                                                                )),
                                                                |this, alpha| this.opacity(alpha),
                                                            )
                                                            .into_any_element()
                                                    } else {
                                                        badge.into_any_element()
                                                    })
                                                }),
                                        )
                                        .child(
                                            div()
                                                .w(px(72.))
                                                .flex_shrink_0()
                                                .truncate()
                                                .text_xs()
                                                .text_color(if used_count > 0 {
                                                    BonTheme::accent()
                                                } else {
                                                    BonTheme::text_muted()
                                                })
                                                .child(format!("{used_count} profile(s)")),
                                        )
                                        .child(
                                            h_flex()
                                                .w(px(92.))
                                                .flex_shrink_0()
                                                .justify_end()
                                                .items_center()
                                                .gap_1p5()
                                                .child(
                                                    Button::new(SharedString::from(format!(
                                                        "p-chk-{pid}"
                                                    )))
                                                    .with_variant(BonTheme::outline_blue(cx))
                                                    .small()
                                                    .disabled(is_checking)
                                                    .label(if is_checking { "..." } else { "Check" })
                                                    .on_click(cx.listener(move |app, _, _, cx| {
                                                        app.check_saved_proxy(&pid_check, cx);
                                                    })),
                                                )
                                                .child(
                                                    Button::new(SharedString::from(format!(
                                                        "p-more-{pid}"
                                                    )))
                                                    .ghost()
                                                    .small()
                                                    .label(SfSymbol::ELLIPSIS)
                                                    .dropdown_menu(move |menu, _, _| {
                                                        let copy_val = pid_menu_copy.clone();
                                                        let app_c = app_row_menu.clone();
                                                        let edit_id = pid_menu_del.clone();
                                                        let app_ed = app_row_menu.clone();
                                                        let assign_id = pid_menu_assign.clone();
                                                        let app_a = app_row_menu.clone();
                                                        let ext_id = pid_menu_del.clone();
                                                        let app_ext = app_row_menu.clone();
                                                        let clr_id = pid_menu_del.clone();
                                                        let app_clr = app_row_menu.clone();
                                                        let del_id = pid_menu_del.clone();
                                                        let rot_id = pid_menu_del.clone();
                                                        let app_r = app_row_menu.clone();
                                                        let app_d = app_row_menu.clone();
                                                        let mut m = menu
                                                            .item(
                                                                PopupMenuItem::new(format!(
                                                                    "{}   Edit proxy / Rotate URL",
                                                                    SfSymbol::PENCIL
                                                                ))
                                                                .on_click(move |_, window, cx| {
                                                                    let eid = edit_id.clone();
                                                                    app_ed.update(cx, |app, cx| {
                                                                        app.open_edit_proxy_modal(
                                                                            &eid, window, cx,
                                                                        );
                                                                    });
                                                                }),
                                                            )
                                                            .item(
                                                                PopupMenuItem::new(format!(
                                                                    "{}   Copy proxy",
                                                                    SfSymbol::DOC_ON_DOC
                                                                ))
                                                                .on_click(move |_, _, cx| {
                                                                    let v = copy_val.clone();
                                                                    app_c.update(cx, |app, cx| {
                                                                        cx.write_to_clipboard(
                                                                            ClipboardItem::new_string(
                                                                                v,
                                                                            ),
                                                                        );
                                                                        app.banner_message = Some(
                                                                            "Copied proxy to clipboard"
                                                                                .to_string(),
                                                                        );
                                                                        cx.notify();
                                                                    });
                                                                }),
                                                            )
                                                            .item(
                                                                PopupMenuItem::new(format!(
                                                                    "{}   Assign to selected profile",
                                                                    SfSymbol::LINK
                                                                ))
                                                                .on_click(move |_, window, cx| {
                                                                    let aid = assign_id.clone();
                                                                    app_a.update(cx, |app, cx| {
                                                                        app.apply_saved_proxy_to_selected_profile(
                                                                            &aid, window, cx,
                                                                        );
                                                                    });
                                                                }),
                                                            )
                                                            .item(
                                                                PopupMenuItem::new(format!(
                                                                    "{}   Extend +30 days",
                                                                    SfSymbol::CALENDAR
                                                                ))
                                                                .on_click(move |_, _, cx| {
                                                                    let eid = ext_id.clone();
                                                                    app_ext.update(
                                                                        cx,
                                                                        |app, cx| {
                                                                            app.extend_saved_proxy_days(
                                                                                &eid, 30, cx,
                                                                            );
                                                                        },
                                                                    );
                                                                }),
                                                            )
                                                            .item(
                                                                PopupMenuItem::new(format!(
                                                                    "{}   Clear expiration",
                                                                    SfSymbol::CLOCK_ARROW_CIRCLEPATH
                                                                ))
                                                                .on_click(move |_, _, cx| {
                                                                    let cid = clr_id.clone();
                                                                    app_clr.update(
                                                                        cx,
                                                                        |app, cx| {
                                                                            app.extend_saved_proxy_days(
                                                                                &cid, 0, cx,
                                                                            );
                                                                        },
                                                                    );
                                                                }),
                                                            );
                                                        if has_rot_url {
                                                            m = m.item(
                                                                PopupMenuItem::new(
                                                                    "\u{1002af}   Rotate Proxy IP",
                                                                )
                                                                .on_click(move |_, _, cx| {
                                                                    let rid = rot_id.clone();
                                                                    app_r.update(cx, |app, cx| {
                                                                        app.rotate_saved_proxy_ip(
                                                                            &rid, cx,
                                                                        );
                                                                    });
                                                                }),
                                                            );
                                                        }
                                                        m.separator().item(
                                                            PopupMenuItem::new(format!(
                                                                "{}   Delete proxy",
                                                                SfSymbol::TRASH
                                                            ))
                                                            .on_click(move |_, _, cx| {
                                                                let did = del_id.clone();
                                                                app_d.update(cx, |app, cx| {
                                                                    app.request_delete(
                                                                        PendingDeleteAction::Proxy(
                                                                            did,
                                                                        ),
                                                                        cx,
                                                                    );
                                                                });
                                                            }),
                                                        )
                                                    }),
                                                ),
                                        ),
                                );
                            }
                            items
                        }),
                    )
                    .with_sizing_behavior(ListSizingBehavior::Auto)
                    .w_full()
                    .flex_1()
                    .min_h_0()
                    .into_any_element()
                })
                // Table Footer (`Proxies: N   < [ 1 ] / 1 >`)
                .child(
                    h_flex()
                        .w_full()
                        .px_4()
                        .py_2()
                        .justify_end()
                        .items_center()
                        .gap_3()
                        .bg(BonTheme::bg_elevated())
                        .border_t_1()
                        .border_color(BonTheme::border())
                        .text_xs()
                        .text_color(BonTheme::text_secondary())
                        .child(format!("Proxies: {filtered_len}"))
                        .child(
                            h_flex()
                                .gap_1()
                                .items_center()
                                .child(
                                    div()
                                        .px_2()
                                        .py_0p5()
                                        .rounded_sm()
                                        .border_1()
                                        .border_color(BonTheme::border())
                                        .child("1"),
                                )
                                .child("/ 1"),
                        ),
                ),
        )
}

fn field_label(text: &'static str) -> Div {
    div()
        .text_xs()
        .text_color(BonTheme::text_secondary())
        .child(text)
}

fn render_batch_group_dropdown(
    id: &'static str,
    app: &BonLoginApp,
    cx: &mut Context<BonLoginApp>,
) -> impl IntoElement {
    let app_for_grp = cx.entity();
    let groups_list = app.saved_groups.clone();
    let cur = app.batch_selected_group.trim().to_string();
    let display_cur = if cur.is_empty() {
        "No group"
    } else {
        cur.as_str()
    };
    let cur_for_menu = cur.clone();
    Button::new(id)
        .min_w(px(160.))
        .outline()
        .dropdown_caret(true)
        .small()
        .label(format!("{}  {display_cur}", SfSymbol::FOLDER_FILL))
        .dropdown_menu(move |mut menu, _, _| {
            let app_none = app_for_grp.clone();
            menu = menu.item(
                PopupMenuItem::new("No group")
                    .checked(cur_for_menu.is_empty())
                    .on_click(move |_, _, cx| {
                        app_none.update(cx, |app, cx| {
                            app.batch_selected_group = String::new();
                            cx.notify();
                        });
                    }),
            );
            for grp in &groups_list {
                let g_val = grp.clone();
                let is_sel = g_val.eq_ignore_ascii_case(&cur_for_menu);
                let app_pick = app_for_grp.clone();
                menu = menu.item(
                    PopupMenuItem::new(format!("{}   {g_val}", SfSymbol::FOLDER_FILL))
                        .checked(is_sel)
                        .on_click(move |_, _, cx| {
                            let g = g_val.clone();
                            app_pick.update(cx, |app, cx| {
                                app.batch_selected_group = g;
                                cx.notify();
                            });
                        }),
                );
            }
            menu
        })
        .into_any_element()
}

fn render_batch_browser_os_selector(
    prefix: &'static str,
    app: &BonLoginApp,
    cx: &mut Context<BonLoginApp>,
) -> Div {
    let batch_os = app.batch_os;
    let batch_brand = app.batch_brand;
    h_flex()
        .gap_1p5()
        .flex_wrap()
        .items_center()
        .children(BrowserBrand::ALL.into_iter().map(|b| {
            Button::new(SharedString::from(format!("{prefix}-brand-{}", b.as_cli_str())))
                .small()
                .with_variant(BonTheme::toggle_pill(cx, batch_brand == b))
                .label(format!("{}  {} 148", SfSymbol::GLOBE, b.as_cli_str()))
                .on_click(cx.listener(move |app, _, _, cx| {
                    app.batch_brand = b;
                    cx.notify();
                }))
        }))
        .children(
            [
                ("win", PlatformType::Windows, SfSymbol::PC, "Windows 11"),
                ("mac", PlatformType::MacOS, SfSymbol::APPLE_LOGO, "Mac OS"),
                ("linux", PlatformType::Linux, SfSymbol::TERMINAL, "Linux"),
            ]
            .into_iter()
            .map(|(sfx, os_val, icon, lbl)| {
                Button::new(SharedString::from(format!("{prefix}-os-{sfx}")))
                    .small()
                    .with_variant(BonTheme::toggle_pill(cx, batch_os == os_val))
                    .label(format!("{icon}  {lbl}"))
                    .on_click(cx.listener(move |app, _, _, cx| {
                        app.batch_os = os_val;
                        cx.notify();
                    }))
            }),
        )
}

fn render_proxy_pool_selector(app: &BonLoginApp, cx: &mut Context<BonLoginApp>) -> Div {
    let total_proxies = app.saved_proxies.len();
    let proxy_groups = app.distinct_proxy_groups_with_counts();
    let selected = app.batch_proxy_group.clone();

    v_flex()
        .w_full()
        .p_2p5()
        .gap_2()
        .rounded_md()
        .bg(BonTheme::bg_panel())
        .border_1()
        .border_color(BonTheme::border())
        .child(
            h_flex()
                .w_full()
                .justify_between()
                .items_center()
                .child(field_label("Proxy from Proxy manager:"))
                .child(
                    Button::new("batch-goto-proxy-mgr")
                        .with_variant(BonTheme::outline_blue(cx))
                        .xsmall()
                        .label("Open Proxy manager")
                        .on_click(cx.listener(|app, _, _, cx| {
                            app.popup_modal = None;
                            app.active_view = WorkspaceView::Proxies;
                            cx.notify();
                        })),
                ),
        )
        .child(
            h_flex()
                .w_full()
                .gap_1p5()
                .flex_wrap()
                .items_center()
                .child(
                    Button::new("bpx-none")
                        .xsmall()
                        .with_variant(BonTheme::toggle_pill(cx, selected == "None"))
                        .label("Without proxy")
                        .on_click(cx.listener(|app, _, _, cx| {
                            app.batch_proxy_group = "None".to_string();
                            cx.notify();
                        })),
                )
                .child(
                    Button::new("bpx-all")
                        .xsmall()
                        .disabled(total_proxies == 0)
                        .with_variant(BonTheme::toggle_pill(cx, selected == "All"))
                        .label(format!("All Saved ({total_proxies})"))
                        .on_click(cx.listener(|app, _, _, cx| {
                            app.batch_proxy_group = "All".to_string();
                            cx.notify();
                        })),
                )
                .children(proxy_groups.into_iter().map(|(grp, cnt)| {
                    let is_sel = selected.eq_ignore_ascii_case(&grp);
                    let grp_click = grp.clone();
                    Button::new(SharedString::from(format!("bpx-tag-{grp}")))
                        .xsmall()
                        .with_variant(BonTheme::toggle_pill(cx, is_sel))
                        .label(format!("#{grp} ({cnt})"))
                        .on_click(cx.listener(move |app, _, _, cx| {
                            app.batch_proxy_group = grp_click.clone();
                            cx.notify();
                        }))
                })),
        )
}

/// GenLogin 3.0 `Profiles -> Group` Sub-Tab View (`docs/genlogin-3.0/assets/menu-bar_profile_group_01.png`)
pub fn render_groups_subtab_view(
    app: &BonLoginApp,
    cx: &mut Context<BonLoginApp>,
) -> Div {
    let q = app.search_query.trim().to_ascii_lowercase();
    let groups: Vec<(String, usize)> = app
        .distinct_groups_with_counts()
        .into_iter()
        .filter(|(grp, _)| q.is_empty() || grp.to_ascii_lowercase().contains(&q))
        .collect();
    v_flex()
        .w_full()
        .flex_1()
        .min_h_0()
        .gap_3()
        .overflow_hidden()
        // Top Bar: Search Sub-account / Group + [New group] button
        .child(
            h_flex()
                .w_full()
                .justify_between()
                .items_center()
                .child(div().w(px(280.)).child(Input::new(&app.search_input)))
                .child(
                    Button::new("btn-new-group-modal")
                        .with_variant(BonTheme::primary_cta(cx))
                        .small()
                        .label("New group")
                        .on_click(cx.listener(|app, _, _, cx| {
                            app.popup_modal = Some(ActivePopupModal::AddGroup);
                            cx.notify();
                        })),
                ),
        )
        // Group Cards List (`📁 test   🗑  ✎  >`)
        .child(
            v_flex()
                .id("groups-subtab-list")
                .w_full()
                .flex_1()
                .min_h_0()
                .gap_2p5()
                .overflow_y_scroll()
                .children(groups.is_empty().then(|| {
                    div()
                        .w_full()
                        .py_8()
                        .flex()
                        .justify_center()
                        .text_xs()
                        .text_color(BonTheme::text_secondary())
                        .child("No groups yet. Click 'New group' to create one.")
                }))
                .children(groups.into_iter().map(|(grp, cnt)| {
                    let g_open = grp.clone();
                    let g_del = grp.clone();
                    h_flex()
                        .w_full()
                        .px_4()
                        .py_3p5()
                        .rounded_md()
                        .bg(BonTheme::bg_panel())
                        .border_1()
                        .border_color(BonTheme::border())
                        .hover(|s| {
                            s.bg(BonTheme::bg_hover())
                                .border_color(BonTheme::border_active())
                        })
                        .justify_between()
                        .items_center()
                        .cursor_pointer()
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |app, _, _, cx| {
                                app.selected_group = g_open.clone();
                                app.profile_sub_tab = ProfileSubTab::Local;
                                cx.notify();
                            }),
                        )
                        .child(
                            h_flex()
                                .flex_1()
                                .min_w_0()
                                .overflow_hidden()
                                .gap_3()
                                .items_center()
                                .child(
                                    div()
                                        .w(px(36.))
                                        .h(px(36.))
                                        .flex_shrink_0()
                                        .rounded_md()
                                        .bg(BonTheme::accent_subtle())
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .text_sm()
                                        .text_color(BonTheme::accent())
                                        .child(SfSymbol::FOLDER_FILL),
                                )
                                .child(
                                    div()
                                        .min_w_0()
                                        .truncate()
                                        .text_sm()
                                        .font_bold()
                                        .text_color(BonTheme::text_primary())
                                        .child(grp.clone()),
                                )
                                .child(
                                    div()
                                        .flex_shrink_0()
                                        .px_2()
                                        .py_0p5()
                                        .rounded_sm()
                                        .bg(BonTheme::bg_elevated())
                                        .text_xs()
                                        .text_color(BonTheme::text_secondary())
                                        .child(format!("{cnt} profile(s)")),
                                ),
                        )
                        .child(
                            h_flex()
                                .flex_shrink_0()
                                .gap_2()
                                .items_center()
                                .on_mouse_down(MouseButton::Left, |_, _, cx| {
                                    cx.stop_propagation();
                                })
                                .child(
                                    Button::new(SharedString::from(format!("grp-del-{grp}")))
                                        .ghost()
                                        .small()
                                        .label(SfSymbol::TRASH)
                                        .on_click(cx.listener(move |app, _, _, cx| {
                                            app.request_delete(
                                                PendingDeleteAction::Group(g_del.clone()),
                                                cx,
                                            );
                                        })),
                                )
                                .child(
                                    div()
                                        .px_2()
                                        .text_sm()
                                        .text_color(BonTheme::text_secondary())
                                        .child(SfSymbol::CHEVRON_RIGHT),
                                ),
                        )
                })),
        )
}

/// Renders the active GenLogin 3.0 Popup Modal overlay (`Quickly add profiles`, `Column Settings`, `Assign to group`, `Add group`, `Update proxy`, `Update profiles`)
pub fn render_popup_modal(
    modal_kind: ActivePopupModal,
    app: &BonLoginApp,
    cx: &mut Context<BonLoginApp>,
) -> AnyElement {
    let card = match modal_kind {
        // 1. GenLogin `Quickly add profiles` (`docs/genlogin-3.0/assets/menu-bar_profile_create-profile_02.png`)
        ActivePopupModal::QuickAdd => {
            v_flex()
                .w(px(520.))
                .p_5()
                .gap_3p5()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border_active())
                .child(
                    h_flex()
                        .w_full()
                        .justify_between()
                        .items_center()
                        .child(
                            div()
                                .text_base()
                                .font_bold()
                                .text_color(BonTheme::text_primary())
                                .child("Quickly add profiles"),
                        )
                        .child(
                            Button::new("qa-close")
                                .ghost()
                                .small()
                                .label(SfSymbol::XMARK)
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        ),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_1()
                        .child(field_label("Browser & Operating System (fingerprint-chromium 148)"))
                        .child(render_batch_browser_os_selector("qa", app, cx)),
                )
                .child(
                    h_flex()
                        .w_full()
                        .gap_3()
                        .child(
                            v_flex()
                                .flex_1()
                                .gap_1()
                                .child(field_label("Profile number (max - 50)"))
                                .child(Input::new(&app.batch_count_input)),
                        )
                        .child(
                            v_flex()
                                .flex_1()
                                .gap_1()
                                .child(field_label("Group"))
                                .child(render_batch_group_dropdown("qa-group-dropdown", app, cx)),
                        ),
                )
                // (Only real interactive inputs shown in Quick Add)
                .child(
                    v_flex()
                        .w_full()
                        .gap_1()
                        .child(field_label("Name Prefix"))
                        .child(Input::new(&app.batch_prefix_input)),
                )
                .child(render_proxy_pool_selector(app, cx))
                .child(
                    h_flex()
                        .w_full()
                        .pt_2()
                        .border_t_1()
                        .border_color(BonTheme::border())
                        .justify_end()
                        .gap_2()
                        .child(
                            Button::new("qa-cancel")
                                .with_variant(BonTheme::row_action(cx))
                                .small()
                                .label("Cancel")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("qa-add-submit")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .label("Add")
                                .on_click(cx.listener(|app, _, window, cx| {
                                    app.popup_modal = None;
                                    app.generate_batch_profiles(window, cx);
                                })),
                        ),
                )
        }

        // 2. GenLogin `Column Settings` (`docs/genlogin-3.0/assets/menu-bar_profile_profile-column-settings_01.png`)
        ActivePopupModal::ColumnSettings => {
            let cols = app.col_vis;
            v_flex()
                .w(px(400.))
                .p_5()
                .gap_4()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border_active())
                .child(
                    h_flex()
                        .gap_2p5()
                        .items_center()
                        .child(
                            div()
                                .w(px(30.))
                                .h(px(30.))
                                .rounded_md()
                                .bg(BonTheme::accent_subtle())
                                .flex()
                                .items_center()
                                .justify_center()
                                .text_sm()
                                .text_color(BonTheme::accent())
                                .child(SfSymbol::GEARSHAPE_FILL),
                        )
                        .child(
                            div()
                                .text_base()
                                .font_bold()
                                .text_color(BonTheme::text_primary())
                                .child("Column Settings"),
                        ),
                )
                .child(
                    h_flex()
                        .w_full()
                        .gap_6()
                        .items_start()
                        // Left Column: ID, Tags, Status, Updated
                        .child(
                            v_flex()
                                .flex_1()
                                .gap_2()
                                .child(
                                    Button::new("cs-id")
                                        .small()
                                        .with_variant(BonTheme::toggle_pill(cx, cols.show_id))
                                        .label(if cols.show_id {
                                            format!("{}  ID", SfSymbol::CHECKMARK)
                                        } else {
                                            "ID".to_string()
                                        })
                                        .on_click(cx.listener(|app, _, _, cx| {
                                            app.col_vis.show_id = !app.col_vis.show_id;
                                            cx.notify();
                                        })),
                                )
                                .child(
                                    Button::new("cs-tags")
                                        .small()
                                        .with_variant(BonTheme::toggle_pill(cx, cols.show_tags))
                                        .label(if cols.show_tags {
                                            format!("{}  Tags", SfSymbol::CHECKMARK)
                                        } else {
                                            "Tags".to_string()
                                        })
                                        .on_click(cx.listener(|app, _, _, cx| {
                                            app.col_vis.show_tags = !app.col_vis.show_tags;
                                            cx.notify();
                                        })),
                                )
                                .child(
                                    Button::new("cs-status")
                                        .small()
                                        .with_variant(BonTheme::toggle_pill(cx, cols.show_status))
                                        .label(if cols.show_status {
                                            format!("{}  Status", SfSymbol::CHECKMARK)
                                        } else {
                                            "Status".to_string()
                                        })
                                        .on_click(cx.listener(|app, _, _, cx| {
                                            app.col_vis.show_status = !app.col_vis.show_status;
                                            cx.notify();
                                        })),
                                )
                                .child(
                                    Button::new("cs-updated")
                                        .small()
                                        .with_variant(BonTheme::toggle_pill(cx, cols.show_updated))
                                        .label(if cols.show_updated {
                                            format!("{}  Updated", SfSymbol::CHECKMARK)
                                        } else {
                                            "Updated".to_string()
                                        })
                                        .on_click(cx.listener(|app, _, _, cx| {
                                            app.col_vis.show_updated = !app.col_vis.show_updated;
                                            cx.notify();
                                        })),
                                ),
                        )
                        // Right Column: Name, Notes, Proxy
                        .child(
                            v_flex()
                                .flex_1()
                                .gap_2()
                                .child(
                                    Button::new("cs-name")
                                        .small()
                                        .with_variant(BonTheme::toggle_pill(cx, cols.show_name))
                                        .label(if cols.show_name {
                                            format!("{}  Name", SfSymbol::CHECKMARK)
                                        } else {
                                            "Name".to_string()
                                        })
                                        .on_click(cx.listener(|app, _, _, cx| {
                                            app.col_vis.show_name = !app.col_vis.show_name;
                                            cx.notify();
                                        })),
                                )
                                .child(
                                    Button::new("cs-notes")
                                        .small()
                                        .with_variant(BonTheme::toggle_pill(cx, cols.show_notes))
                                        .label(if cols.show_notes {
                                            format!("{}  Notes", SfSymbol::CHECKMARK)
                                        } else {
                                            "Notes".to_string()
                                        })
                                        .on_click(cx.listener(|app, _, _, cx| {
                                            app.col_vis.show_notes = !app.col_vis.show_notes;
                                            cx.notify();
                                        })),
                                )
                                .child(
                                    Button::new("cs-proxy")
                                        .small()
                                        .with_variant(BonTheme::toggle_pill(cx, cols.show_proxy))
                                        .label(if cols.show_proxy {
                                            format!("{}  Proxy", SfSymbol::CHECKMARK)
                                        } else {
                                            "Proxy".to_string()
                                        })
                                        .on_click(cx.listener(|app, _, _, cx| {
                                            app.col_vis.show_proxy = !app.col_vis.show_proxy;
                                            cx.notify();
                                        })),
                                ),
                        ),
                )
                .child(
                    h_flex()
                        .w_full()
                        .pt_3()
                        .border_t_1()
                        .border_color(BonTheme::border())
                        .justify_end()
                        .gap_2()
                        .child(
                            Button::new("cs-cancel")
                                .ghost()
                                .small()
                                .label("Cancel")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("cs-apply")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .label("Apply")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        ),
                )
        }

        // 3. GenLogin `Assign to group` (`docs/genlogin-3.0/assets/menu-bar_profile_group_04.png`)
        ActivePopupModal::AssignGroup => {
            let groups = app.distinct_groups_with_counts();
            v_flex()
                .w(px(380.))
                .p_5()
                .gap_3p5()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border_active())
                .child(
                    h_flex()
                        .w_full()
                        .justify_between()
                        .items_center()
                        .child(
                            div()
                                .text_base()
                                .font_bold()
                                .text_color(BonTheme::text_primary())
                                .child(format!("{}  Assign to group", SfSymbol::INFO_CIRCLE_FILL)),
                        )
                        .child(
                            Button::new("ag-close")
                                .ghost()
                                .small()
                                .label(SfSymbol::XMARK)
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        ),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_1p5()
                        .child(field_label("Select Group (created in Profiles -> Group):"))
                        .child(render_batch_group_dropdown("ag-group-dropdown", app, cx))
                        .child(
                            h_flex()
                                .w_full()
                                .gap_1p5()
                                .flex_wrap()
                                .children(groups.into_iter().map(|(g, cnt)| {
                                    let g_pick = g.clone();
                                    let active =
                                        app.batch_selected_group.eq_ignore_ascii_case(&g);
                                    Button::new(SharedString::from(format!("ag-pick-{g}")))
                                        .with_variant(BonTheme::toggle_pill(cx, active))
                                        .xsmall()
                                        .label(format!("{g} ({cnt})"))
                                        .on_click(cx.listener(move |app, _, _, cx| {
                                            app.batch_selected_group = g_pick.clone();
                                            cx.notify();
                                        }))
                                })),
                        ),
                )
                .child(
                    h_flex()
                        .w_full()
                        .justify_end()
                        .gap_2()
                        .child(
                            Button::new("ag-cancel")
                                .with_variant(BonTheme::row_action(cx))
                                .small()
                                .label("Cancel")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("ag-submit")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .label("Assign")
                                .on_click(cx.listener(|app, _, window, cx| {
                                    app.popup_modal = None;
                                    app.move_checked_profiles_from_input(window, cx);
                                })),
                        ),
                )
        }

        // 4. GenLogin `Add group` (`docs/genlogin-3.0/assets/menu-bar_profile_group_02.png`)
        ActivePopupModal::AddGroup => v_flex()
            .w(px(380.))
            .p_5()
            .gap_3p5()
            .rounded_lg()
            .bg(BonTheme::bg_elevated())
            .border_1()
            .border_color(BonTheme::border_active())
            .child(
                h_flex()
                    .w_full()
                    .justify_between()
                    .items_center()
                    .child(
                        div()
                            .text_base()
                            .font_bold()
                            .text_color(BonTheme::text_primary())
                            .child(format!("{}  Add group", SfSymbol::INFO_CIRCLE_FILL)),
                    )
                    .child(
                        Button::new("addg-close")
                            .ghost()
                            .small()
                            .label(SfSymbol::XMARK)
                            .on_click(cx.listener(|app, _, _, cx| {
                                app.popup_modal = None;
                                cx.notify();
                            })),
                    ),
            )
            .child(
                v_flex()
                    .w_full()
                    .gap_1()
                    .child(field_label("Group name"))
                    .child(Input::new(&app.batch_move_group_input)),
            )
            .child(
                h_flex().child(
                    Button::new("addg-submit")
                        .with_variant(BonTheme::primary_cta(cx))
                        .small()
                        .label("Add")
                        .on_click(cx.listener(|app, _, window, cx| {
                            app.popup_modal = None;
                            app.create_group_from_modal(window, cx);
                        })),
                ),
            ),


        // 4b. `Add tag` (ONLY place to create Proxy Tags in Proxy manager)
        ActivePopupModal::AddTag => v_flex()
            .w(px(380.))
            .p_5()
            .gap_3p5()
            .rounded_lg()
            .bg(BonTheme::bg_elevated())
            .border_1()
            .border_color(BonTheme::border_active())
            .child(
                h_flex()
                    .w_full()
                    .justify_between()
                    .items_center()
                    .child(
                        div()
                            .text_base()
                            .font_bold()
                            .text_color(BonTheme::text_primary())
                            .child(format!(
                                "{}  Add tag (Proxy manager)",
                                SfSymbol::INFO_CIRCLE_FILL
                            )),
                    )
                    .child(
                        Button::new("addt-close")
                            .ghost()
                            .small()
                            .label(SfSymbol::XMARK)
                            .on_click(cx.listener(|app, _, _, cx| {
                                app.popup_modal = None;
                                cx.notify();
                            })),
                    ),
            )
            .child(
                v_flex()
                    .w_full()
                    .gap_1()
                    .child(field_label("Tag name"))
                    .child(Input::new(&app.batch_move_group_input)),
            )
            .child(
                h_flex().child(
                    Button::new("addt-submit")
                        .with_variant(BonTheme::primary_cta(cx))
                        .small()
                        .label("Add")
                        .on_click(cx.listener(|app, _, window, cx| {
                            app.popup_modal = Some(ActivePopupModal::AddProxy);
                            app.create_tag_from_modal(window, cx);
                        })),
                ),
            ),
        // 5. GenLogin `Update proxy` (`docs/genlogin-3.0/assets/menu-bar_profile_create-profile_setting-profile_network_update-proxy_02.png`)
        ActivePopupModal::UpdateProxy => {
            let checked_names: Vec<String> = app
                .profiles
                .iter()
                .filter(|p| app.checked_profile_ids.contains(&p.id))
                .map(|p| p.name.clone())
                .collect();
            let total_checked = checked_names.len();

            v_flex()
                .w(px(560.))
                .p_5()
                .gap_3()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border_active())
                .child(
                    h_flex()
                        .w_full()
                        .justify_between()
                        .items_center()
                        .child(
                            div()
                                .text_base()
                                .font_bold()
                                .text_color(BonTheme::text_primary())
                                .child(format!("{}  Update proxy", SfSymbol::INFO_CIRCLE_FILL)),
                        )
                        .child(
                            Button::new("upx-close")
                                .ghost()
                                .small()
                                .label(SfSymbol::XMARK)
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        ),
                )
                // Selected profiles list preview + Total: N
                .child(
                    v_flex()
                        .w_full()
                        .p_2p5()
                        .gap_1()
                        .rounded_md()
                        .bg(BonTheme::bg_panel())
                        .border_1()
                        .border_color(BonTheme::border())
                        .children(checked_names.iter().take(3).map(|n| {
                            div()
                                .text_xs()
                                .font_semibold()
                                .text_color(BonTheme::text_primary())
                                .child(n.clone())
                        }))
                        .child(
                            div()
                                .text_xs()
                                .text_color(BonTheme::text_secondary())
                                .child(format!("Total: {total_checked}")),
                        ),
                )
                // Select proxy or tag from Proxy manager (no raw proxy input allowed outside Proxy manager)
                .child(render_proxy_pool_selector(app, cx))
                .children((!app.saved_proxies.is_empty()).then(|| {
                    let app_for_menu = cx.entity();
                    let proxies_for_menu = app.saved_proxies.clone();
                    h_flex()
                        .w_full()
                        .justify_between()
                        .items_center()
                        .child(field_label("Or assign a specific proxy from Proxy manager:"))
                        .child(
                            Button::new("upx-pick-single-saved")
                                .min_w(px(210.))
                                .outline()
                                .dropdown_caret(true)
                                .small()
                                .label("Pick single proxy")
                                .dropdown_menu(move |mut menu, _, _| {
                                    for sp in &proxies_for_menu {
                                        let sp_id = sp.id.clone();
                                        let app_pick = app_for_menu.clone();
                                        let item_label = format!(
                                            "{}  {}:{} ({}) - {} (#{})",
                                            SfSymbol::GLOBE,
                                            sp.config.host,
                                            sp.config.port,
                                            sp.config.protocol.as_str().to_uppercase(),
                                            sp.name,
                                            sp.group_tag
                                        );
                                        menu = menu.item(PopupMenuItem::new(item_label).on_click(
                                            move |_, window, cx| {
                                                app_pick.update(cx, |app, cx| {
                                                    app.popup_modal = None;
                                                    app.assign_single_saved_proxy_to_checked(
                                                        &sp_id, window, cx,
                                                    );
                                                });
                                            },
                                        ));
                                    }
                                    menu
                                }),
                        )
                }))
                .child(
                    h_flex()
                        .w_full()
                        .pt_2()
                        .border_t_1()
                        .border_color(BonTheme::border())
                        .justify_end()
                        .gap_2()
                        .child(
                            Button::new("upx-cancel")
                                .with_variant(BonTheme::row_action(cx))
                                .small()
                                .label("Cancel")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("upx-submit")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .label("Update")
                                .on_click(cx.listener(|app, _, window, cx| {
                                    app.popup_modal = None;
                                    app.batch_update_proxies_for_checked(window, cx);
                                })),
                        ),
                )
        }

        // 6. GenLogin `Update profiles` (`docs/genlogin-3.0/assets/menu-bar_profile_update-profiles_02.png`)
        ActivePopupModal::UpdateProfiles => {
            v_flex()
                .w(px(560.))
                .p_5()
                .gap_3()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border_active())
                .child(
                    h_flex()
                        .w_full()
                        .justify_between()
                        .items_center()
                        .child(
                            div()
                                .text_base()
                                .font_bold()
                                .text_color(BonTheme::text_primary())
                                .child(format!("{}  Update profiles", SfSymbol::INFO_CIRCLE_FILL)),
                        )
                        .child(
                            Button::new("uprof-close")
                                .ghost()
                                .small()
                                .label(SfSymbol::XMARK)
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        ),
                )
                .child(render_batch_browser_os_selector("uprof", app, cx))
                .child(
                    v_flex()
                        .w_full()
                        .gap_1()
                        .child(field_label("Name (Input name pattern)"))
                        .child(Input::new(&app.batch_prefix_input))
                        .child(
                            div()
                                .text_xs()
                                .text_color(BonTheme::text_muted())
                                .child("Leave 'Profile' to keep existing names, or enter a prefix (e.g. 'Shop' => Shop-01, Shop-02)"),
                        ),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_1()
                        .child(field_label("Group"))
                        .child(render_batch_group_dropdown(
                            "uprof-group-dropdown",
                            app,
                            cx,
                        )),
                )
                // (Only real implemented fields shown in Update Profiles)
                .child(
                    h_flex()
                        .w_full()
                        .pt_2()
                        .border_t_1()
                        .border_color(BonTheme::border())
                        .justify_end()
                        .gap_2()
                        .child(
                            Button::new("uprof-cancel")
                                .with_variant(BonTheme::row_action(cx))
                                .small()
                                .label("Cancel")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("uprof-submit")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .label("Update")
                                .on_click(cx.listener(|app, _, window, cx| {
                                    app.popup_modal = None;
                                    app.batch_update_checked_profiles(window, cx);
                                })),
                        ),
                )
        }

        // 7. GenLogin `Add Proxy` (`docs/genlogin-3.0/assets/menu-bar_proxy-manager-and-genproxy_proxy-management_02.png`)
        ActivePopupModal::AddProxy => {
            let proxy_groups = app.distinct_proxy_groups_with_counts();
            let add_proto = app.proxy_add_protocol;
            v_flex()
                .w(px(560.))
                .p_5()
                .gap_3()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border_active())
                .child(
                    h_flex()
                        .w_full()
                        .justify_between()
                        .items_center()
                        .child(
                            div()
                                .text_base()
                                .font_bold()
                                .text_color(BonTheme::text_primary())
                                .child("Add Proxy"),
                        )
                        .child(
                            Button::new("addpx-close")
                                .ghost()
                                .small()
                                .label(SfSymbol::XMARK)
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        ),
                )
                // Instruction Box matching `proxy-management_02.png`
                .child(
                    v_flex()
                        .w_full()
                        .p_3()
                        .gap_1()
                        .rounded_md()
                        .bg(BonTheme::bg_panel())
                        .border_1()
                        .border_color(BonTheme::border())
                        .text_xs()
                        .text_color(BonTheme::text_secondary())
                        .child("1. If you do not fill in proxy type, it will default to HTTP")
                        .child("2. Only support HTTP, HTTPS, Socks4, Socks5")
                        .child("3. Name & IP Rotation URL (|http://...) are optional")
                        .child("Example:")
                        .child("http://192.168.1.1:3000:admin:admin")
                        .child("socks://192.168.1.1:3000:user:user")
                        .child("http:192.168.1.1:3000:admin:admin:Vina Proxy|https://api.proxy.local/rotate?key=1"),
                )
                // Default protocol selector + Proxy input
                .child(
                    v_flex()
                        .w_full()
                        .gap_1p5()
                        .child(
                            h_flex()
                                .w_full()
                                .justify_between()
                                .items_center()
                                .child(field_label("Proxies (1 per line — type:host:port:login:password:name)"))
                                .child(
                                    h_flex()
                                        .gap_1()
                                        .items_center()
                                        .child(
                                            Button::new("addpx-proto-http")
                                                .xsmall()
                                                .with_variant(BonTheme::toggle_pill(
                                                    cx,
                                                    add_proto == ProxyProtocol::Http,
                                                ))
                                                .label("Default: HTTP")
                                                .on_click(cx.listener(|app, _, _, cx| {
                                                    app.proxy_add_protocol = ProxyProtocol::Http;
                                                    cx.notify();
                                                })),
                                        )
                                        .child(
                                            Button::new("addpx-proto-socks5")
                                                .xsmall()
                                                .with_variant(BonTheme::toggle_pill(
                                                    cx,
                                                    add_proto == ProxyProtocol::Socks5,
                                                ))
                                                .label("Default: SOCKS5")
                                                .on_click(cx.listener(|app, _, _, cx| {
                                                    app.proxy_add_protocol = ProxyProtocol::Socks5;
                                                    cx.notify();
                                                })),
                                        ),
                                ),
                        )
                        .child(Textarea::new(&app.proxy_raw_input)),
                )
                // Tag selector (strictly from tags created in Proxy manager)
                .child({
                    let app_for_tag = cx.entity();
                    let tags_list: Vec<String> = app.saved_tags.clone();
                    let cur_tag = app.proxy_selected_tag.clone();
                    v_flex()
                        .w_full()
                        .gap_1p5()
                        .child(
                            h_flex()
                                .w_full()
                                .justify_between()
                                .items_center()
                                .child(field_label("Tag (select from Proxy manager tags)"))
                                .child(
                                    Button::new("addpx-open-add-tag")
                                        .with_variant(BonTheme::outline_blue(cx))
                                        .xsmall()
                                        .label("+ New tag")
                                        .on_click(cx.listener(|app, _, _, cx| {
                                            app.popup_modal = Some(ActivePopupModal::AddTag);
                                            cx.notify();
                                        })),
                                ),
                        )
                        .child(
                            h_flex()
                                .w_full()
                                .gap_2()
                                .flex_wrap()
                                .items_center()
                                .child(
                                    Button::new("addpx-tag-dropdown")
                                        .min_w(px(130.))
                                        .outline()
                                        .dropdown_caret(true)
                                        .small()
                                        .label(if cur_tag.trim().is_empty() {
                                            "No tag".to_string()
                                        } else {
                                            format!("#{cur_tag}")
                                        })
                                        .dropdown_menu(move |mut menu, _, _| {
                                            let app_none = app_for_tag.clone();
                                            menu = menu.item(
                                                PopupMenuItem::new("No tag")
                                                    .checked(cur_tag.trim().is_empty())
                                                    .on_click(move |_, _, cx| {
                                                        app_none.update(cx, |app, cx| {
                                                            app.proxy_selected_tag = String::new();
                                                            cx.notify();
                                                        });
                                                    }),
                                            );
                                            for t in &tags_list {
                                                let t_val = t.clone();
                                                let is_sel = t_val.eq_ignore_ascii_case(&cur_tag);
                                                let app_pick = app_for_tag.clone();
                                                menu = menu.item(
                                                    PopupMenuItem::new(format!("#{t_val}"))
                                                        .checked(is_sel)
                                                        .on_click(move |_, _, cx| {
                                                            let chosen = t_val.clone();
                                                            app_pick.update(cx, |app, cx| {
                                                                app.proxy_selected_tag = chosen;
                                                                cx.notify();
                                                            });
                                                        }),
                                                );
                                            }
                                            menu
                                        }),
                                )
                                .children(proxy_groups.into_iter().map(|(grp, cnt)| {
                                    let grp_click = grp.clone();
                                    let active =
                                        app.proxy_selected_tag.eq_ignore_ascii_case(&grp);
                                    Button::new(SharedString::from(format!("addpx-tag-{grp}")))
                                        .xsmall()
                                        .with_variant(BonTheme::toggle_pill(cx, active))
                                        .label(format!("#{grp} ({cnt})"))
                                        .on_click(cx.listener(move |app, _, _, cx| {
                                            app.proxy_selected_tag = grp_click.clone();
                                            cx.notify();
                                        }))
                                })),
                        )
                })
                // Expiration Date / Duration section
                .child(
                    v_flex()
                        .w_full()
                        .gap_1p5()
                        .child(
                            h_flex()
                                .w_full()
                                .justify_between()
                                .items_center()
                                .child(field_label("Expired at (DD/MM/YYYY or days)"))
                                .child(
                                    h_flex()
                                        .gap_1()
                                        .items_center()
                                        .children(
                                            [
                                                ("No expiry", ""),
                                                ("+7d", "7"),
                                                ("+30d", "30"),
                                                ("+90d", "90"),
                                            ]
                                            .into_iter()
                                            .map(|(lbl, val)| {
                                                let v_str = val.to_string();
                                                Button::new(SharedString::from(format!(
                                                    "addpx-exp-{lbl}"
                                                )))
                                                .xsmall()
                                                .with_variant(BonTheme::row_action(cx))
                                                .label(lbl)
                                                .on_click(cx.listener(
                                                    move |app, _, window, cx| {
                                                        let v = v_str.clone();
                                                        app.proxy_expire_input = cx.new(|cx| {
                                                            InputState::new(window, cx)
                                                                .placeholder("DD/MM/YYYY or days")
                                                                .default_value(v)
                                                        });
                                                        cx.notify();
                                                    },
                                                ))
                                            }),
                                        ),
                                ),
                        )
                        .child(Input::new(&app.proxy_expire_input)),
                )
                // Footer: Cancel + Add
                .child(
                    h_flex()
                        .w_full()
                        .pt_2()
                        .border_t_1()
                        .border_color(BonTheme::border())
                        .justify_end()
                        .gap_2()
                        .child(
                            Button::new("addpx-cancel")
                                .with_variant(BonTheme::row_action(cx))
                                .small()
                                .label("Cancel")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("addpx-submit")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .label("Add")
                                .on_click(cx.listener(|app, _, window, cx| {
                                    app.add_saved_proxies_from_input(window, cx);
                                })),
                        ),
                )
        }
        // 9. GenLogin `Upload Extension` Modal (`docs/genlogin-3.0/assets/menu-bar_extensions_04.png`)
        ActivePopupModal::UploadExtension => v_flex()
            .w(px(480.))
            .p_5()
            .gap_4()
            .rounded_lg()
            .bg(BonTheme::bg_elevated())
            .border_1()
            .border_color(BonTheme::border_active())
            .child(
                h_flex()
                    .w_full()
                    .gap_2p5()
                    .items_center()
                    .child(
                        div()
                            .w(px(32.))
                            .h(px(32.))
                            .rounded_md()
                            .bg(BonTheme::accent_subtle())
                            .flex()
                            .items_center()
                            .justify_center()
                            .text_sm()
                            .text_color(BonTheme::accent())
                            .child(SfSymbol::ICLOUD_AND_ARROW_UP),
                    )
                    .child(
                        div()
                            .text_base()
                            .font_bold()
                            .text_color(BonTheme::text_primary())
                            .child("Upload Extension"),
                    ),
            )
            // Dashed Dropzone / Browse Box
            .child(
                v_flex()
                    .w_full()
                    .py_7()
                    .px_4()
                    .gap_1p5()
                    .rounded_md()
                    .bg(BonTheme::bg_canvas())
                    .border_1()
                    .border_color(BonTheme::border_active())
                    .items_center()
                    .justify_center()
                    .cursor_pointer()
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(|app, _, window, cx| {
                            app.pick_extension_file_dialog(window, cx);
                        }),
                    )
                    .child(
                        div()
                            .text_xl()
                            .text_color(BonTheme::accent())
                            .child(SfSymbol::ICLOUD_AND_ARROW_UP),
                    )
                    .child(
                        div()
                            .text_sm()
                            .font_semibold()
                            .text_color(BonTheme::text_primary())
                            .child("Drag & drop an extension"),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(BonTheme::text_secondary())
                            .child("Supported formats: CRX, ZIP"),
                    ),
            )
            .child(Input::new(&app.ext_file_input))
            .child(
                h_flex()
                    .w_full()
                    .pt_2()
                    .border_t_1()
                    .border_color(BonTheme::border())
                    .justify_end()
                    .gap_2()
                    .child(
                        Button::new("upext-cancel")
                            .with_variant(BonTheme::row_action(cx))
                            .small()
                            .label("Cancel")
                            .on_click(cx.listener(|app, _, _, cx| {
                                app.close_popup_modal(cx);
                            })),
                    )
                    .child(
                        Button::new("upext-submit")
                            .with_variant(BonTheme::primary_cta(cx))
                            .small()
                            .label("Upload file")
                            .on_click(cx.listener(|app, _, window, cx| {
                                app.upload_extension_from_input(window, cx);
                            })),
                    ),
            ),
        // 10. GenLogin `Input URL Extension` Modal (`docs/genlogin-3.0/assets/menu-bar_extensions_06.png`)
        ActivePopupModal::InputUrlExtension => {
            let busy = app.downloading_ext;
            v_flex()
                .w(px(480.))
                .p_5()
                .gap_4()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border_active())
                .child(
                    h_flex()
                        .w_full()
                        .gap_2p5()
                        .items_center()
                        .child(
                            div()
                                .w(px(32.))
                                .h(px(32.))
                                .rounded_md()
                                .bg(BonTheme::accent_subtle())
                                .flex()
                                .items_center()
                                .justify_center()
                                .text_sm()
                                .text_color(BonTheme::accent())
                                .child(SfSymbol::PUZZLEPIECE_EXTENSION_FILL),
                        )
                        .child(
                            div()
                                .text_base()
                                .font_bold()
                                .text_color(BonTheme::text_primary())
                                .child("Input URL Extension"),
                        ),
                )
                .child(Input::new(&app.ext_url_input))
                .child(
                    h_flex()
                        .w_full()
                        .pt_2()
                        .border_t_1()
                        .border_color(BonTheme::border())
                        .justify_end()
                        .gap_2()
                        .child(
                            Button::new("urlext-cancel")
                                .with_variant(BonTheme::row_action(cx))
                                .small()
                                .label("Cancel")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.close_popup_modal(cx);
                                })),
                        )
                        .child(
                            Button::new("urlext-submit")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .disabled(busy)
                                .label(if busy { "Downloading..." } else { "Download" })
                                .on_click(cx.listener(|app, _, window, cx| {
                                    app.download_extension_from_url_input(window, cx);
                                })),
                        ),
                )
        }
        // 11. GenLogin `Remove the extension?` Confirmation Modal (`docs/genlogin-3.0/assets/menu-bar_extensions_10.png`)
        ActivePopupModal::RemoveExtension => {
            let (title, desc, confirm_label) = match &app.pending_delete {
                Some(PendingDeleteAction::Profile(id)) => {
                    let name = app
                        .profiles
                        .iter()
                        .find(|p| &p.id == id)
                        .map(|p| p.name.clone())
                        .unwrap_or_else(|| "this profile".to_string());
                    (
                        "Move profile to Trash?",
                        format!(
                            "Move '{name}' to Trash? Its browser data and cookies are kept safe and can be restored anytime."
                        ),
                        "Move to Trash",
                    )
                }
                Some(PendingDeleteAction::CheckedProfiles) => (
                    "Move selected profiles to Trash?",
                    format!(
                        "Move {} selected profile(s) to Trash? You can restore them anytime from the Trash tab.",
                        app.checked_profile_ids.len()
                    ),
                    "Move to Trash",
                ),
                Some(PendingDeleteAction::PermanentProfile(id)) => {
                    let name = app
                        .trashed_profiles
                        .iter()
                        .find(|p| &p.id == id)
                        .map(|p| p.name.clone())
                        .unwrap_or_else(|| "this profile".to_string());
                    (
                        "Permanently delete profile?",
                        format!(
                            "Are you sure you want to permanently delete '{name}' and wipe its browser user-data-dir?"
                        ),
                        "Delete Forever",
                    )
                }
                Some(PendingDeleteAction::EmptyTrash) => (
                    "Empty Trash?",
                    format!(
                        "Permanently delete all {} profile(s) in Trash and erase their browser data?",
                        app.trashed_profiles.len()
                    ),
                    "Empty Trash",
                ),
                Some(PendingDeleteAction::Group(g)) => (
                    "Delete group?",
                    format!("Are you sure you want to delete group '{g}'?"),
                    "Yes, delete",
                ),
                Some(PendingDeleteAction::Proxy(id)) => {
                    let label = app
                        .saved_proxies
                        .iter()
                        .find(|p| &p.id == id)
                        .map(|p| format!("{}:{}", p.config.host, p.config.port))
                        .unwrap_or_else(|| "this proxy".to_string());
                    (
                        "Delete proxy?",
                        format!("Are you sure you want to delete proxy '{label}'?"),
                        "Yes, delete",
                    )
                }
                Some(PendingDeleteAction::CheckedProxies) => (
                    "Delete selected proxies?",
                    format!(
                        "Are you sure you want to delete {} selected proxy(s)?",
                        app.checked_proxy_ids.len()
                    ),
                    "Yes, delete",
                ),
                Some(PendingDeleteAction::Tag(t)) => (
                    "Delete proxy tag?",
                    format!("Are you sure you want to delete tag '#{t}'?"),
                    "Yes, delete",
                ),
                Some(PendingDeleteAction::Extension(id)) => {
                    let name = app
                        .extensions
                        .iter()
                        .find(|e| &e.id == id)
                        .map(|e| e.name.clone())
                        .unwrap_or_else(|| "this extension".to_string());
                    (
                        "Remove the extension?",
                        format!("Are you sure to remove {name}?"),
                        "Yes, remove",
                    )
                }
                Some(PendingDeleteAction::WipeProfile(id)) => {
                    let name = app
                        .profiles
                        .iter()
                        .find(|p| &p.id == id)
                        .map(|p| p.name.clone())
                        .unwrap_or_else(|| "this profile".to_string());
                    (
                        "Wipe profile browser data?",
                        format!(
                            "Reset cookies, LocalStorage & browser state for '{name}' while keeping its fingerprint & proxy settings?"
                        ),
                        "Yes, wipe data",
                    )
                }
                None => (
                    "Confirm delete?",
                    "Are you sure you want to delete this item?".to_string(),
                    "Yes, delete",
                ),
            };
            v_flex()
                .w(px(420.))
                .p_5()
                .gap_4()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border_active())
                .child(
                    h_flex()
                        .w_full()
                        .gap_3()
                        .items_start()
                        .child(
                            div()
                                .w(px(36.))
                                .h(px(36.))
                                .flex_shrink_0()
                                .rounded_full()
                                .bg(BonTheme::danger_bg())
                                .flex()
                                .items_center()
                                .justify_center()
                                .text_sm()
                                .text_color(BonTheme::danger())
                                .child(SfSymbol::TRASH),
                        )
                        .child(
                            v_flex()
                                .flex_1()
                                .min_w_0()
                                .overflow_hidden()
                                .gap_1()
                                .child(
                                    div()
                                        .text_base()
                                        .font_bold()
                                        .text_color(BonTheme::text_primary())
                                        .child(title),
                                )
                                .child(
                                    div()
                                        .w_full()
                                        .min_w_0()
                                        .truncate()
                                        .text_xs()
                                        .text_color(BonTheme::text_secondary())
                                        .child(desc),
                                ),
                        ),
                )
                .child(
                    h_flex()
                        .w_full()
                        .pt_2()
                        .justify_end()
                        .gap_2p5()
                        .child(
                            Button::new("remext-cancel")
                                .with_variant(BonTheme::row_action(cx))
                                .small()
                                .label("No, keep it")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.pending_delete = None;
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("remext-confirm")
                                .danger()
                                .small()
                                .label(confirm_label)
                                .on_click(cx.listener(|app, _, window, cx| {
                                    app.confirm_pending_delete(window, cx);
                                })),
                        ),
                )
        }

        ActivePopupModal::ArrangeWindows => {
            let displays = cx.displays();
            let disp_list: Vec<(usize, i32, i32)> = if displays.is_empty() {
                vec![(0, 1440, 900)]
            } else {
                displays
                    .iter()
                    .enumerate()
                    .map(|(i, d)| {
                        let b = d.bounds();
                        (i, f32::from(b.size.width) as i32, f32::from(b.size.height) as i32)
                    })
                    .collect()
            };
            let sel_idx = app.arrange_display_idx.min(disp_list.len().saturating_sub(1));
            let (_, mon_w, mon_h) = disp_list[sel_idx];
            let usable_w = mon_w.max(500);
            let usable_h = (mon_h - 25).max(360);
            let target_count = app.running_targets_for_arrange().len();
            let auto_n = target_count.max(1);
            let auto_cols = (auto_n as f32).sqrt().ceil().max(1.0) as i32;
            let auto_rows = ((auto_n as i32 + auto_cols - 1) / auto_cols).max(1);
            let presets: Vec<(String, i32, i32)> = vec![
                (
                    format!("Auto Fit ({auto_n})"),
                    (usable_w / auto_cols).max(500),
                    (usable_h / auto_rows).max(360),
                ),
                ("2×1 Split".to_string(), (usable_w / 2).max(500), usable_h),
                ("2×2 Grid".to_string(), (usable_w / 2).max(500), (usable_h / 2).max(360)),
                ("3×2 Grid".to_string(), (usable_w / 3).max(500), (usable_h / 2).max(360)),
                ("4×2 Grid".to_string(), (usable_w / 4).max(500), (usable_h / 2).max(360)),
            ];
            let cur_size_raw = app.arrange_size_input.read(cx).value().to_string();
            let fit_hint = if let Some((w, h)) = crate::launcher::parse_window_size(&cur_size_raw) {
                let cw = w.clamp(500, usable_w);
                let ch = h.clamp(360, usable_h);
                let cols = (usable_w / cw).max(1);
                let rows = (usable_h / ch).max(1);
                format!(
                    "Fits {cols} col(s) × {rows} row(s) ({cw}×{ch}px each) on Display {} ({mon_w}×{mon_h})",
                    sel_idx + 1
                )
            } else {
                "Enter Width,Height (min 500×360 on macOS Chromium)".to_string()
            };

            v_flex()
                .w(px(500.))
                .p_5()
                .gap_3p5()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border_active())
                .child(
                    h_flex()
                        .w_full()
                        .justify_between()
                        .items_center()
                        .child(
                            div()
                                .text_base()
                                .font_bold()
                                .text_color(BonTheme::text_primary())
                                .child(format!(
                                    "{}  Auto-Fix & Tile Open Browsers",
                                    SfSymbol::PC
                                )),
                        )
                        .child(
                            Button::new("arr-close")
                                .ghost()
                                .small()
                                .label(SfSymbol::XMARK)
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        ),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_1p5()
                        .child(field_label("1. Monitor"))
                        .child(
                            h_flex().w_full().gap_2().flex_wrap().children(
                                disp_list.into_iter().map(|(idx, dw, dh)| {
                                    let active = idx == sel_idx;
                                    Button::new(SharedString::from(format!("arr-disp-{idx}")))
                                        .with_variant(BonTheme::toggle_pill(cx, active))
                                        .small()
                                        .label(format!(
                                            "{}  Display {} ({dw}×{dh})",
                                            SfSymbol::PC,
                                            idx + 1
                                        ))
                                        .on_click(cx.listener(move |app, _, _, cx| {
                                            app.arrange_display_idx = idx;
                                            cx.notify();
                                        }))
                                }),
                            ),
                        ),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_1p5()
                        .child(field_label("2. Monitor Size Presets"))
                        .child(
                            h_flex().w_full().gap_1p5().flex_wrap().children(
                                presets.into_iter().enumerate().map(|(i, (lbl, pw, ph))| {
                                    let val_str = format!("{pw},{ph}");
                                    let active = cur_size_raw.trim() == val_str;
                                    Button::new(SharedString::from(format!("arr-preset-{i}")))
                                        .with_variant(BonTheme::toggle_pill(cx, active))
                                        .small()
                                        .label(format!("{lbl} ({pw}×{ph})"))
                                        .on_click(cx.listener(move |app, _, window, cx| {
                                            app.set_arrange_size_text(val_str.clone(), window, cx);
                                            if !app.running_targets_for_arrange().is_empty() {
                                                app.arrange_open_browsers(cx);
                                            }
                                        }))
                                }),
                            ),
                        ),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_1()
                        .child(field_label("3. Custom Browser Size (Width,Height)"))
                        .child(Input::new(&app.arrange_size_input))
                        .child(
                            div()
                                .text_xs()
                                .text_color(BonTheme::text_secondary())
                                .child(fit_hint),
                        ),
                )
                .child(
                    h_flex()
                        .w_full()
                        .pt_2()
                        .border_t_1()
                        .border_color(BonTheme::border())
                        .justify_end()
                        .gap_2()
                        .child(
                            Button::new("arr-cancel")
                                .with_variant(BonTheme::row_action(cx))
                                .small()
                                .label("Cancel")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("arr-apply")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .disabled(target_count == 0)
                                .label(if target_count > 0 {
                                    format!("Apply to {target_count} open browser(s)")
                                } else {
                                    "No open browsers".to_string()
                                })
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    app.arrange_open_browsers(cx);
                                })),
                        ),
                )
        }

        ActivePopupModal::QuickMeta => {
            let target_title = if let Some(pid) = &app.quick_meta_profile_id {
                let name = app
                    .profiles
                    .iter()
                    .find(|p| &p.id == pid)
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| "Profile".to_string());
                format!("{}  Bookmarks, Tags, Note & 2FA — {name}", SfSymbol::TAG_FILL)
            } else {
                format!(
                    "{}  Batch Bookmarks, Tags & Note ({} selected)",
                    SfSymbol::TAG_FILL,
                    app.checked_profile_ids.len()
                )
            };
            let is_single = app.quick_meta_profile_id.is_some();
            let cur_tags = app.quick_meta_tags.clone();
            let raw_totp = app.quick_meta_totp_input.read(cx).value().to_string();
            let live_totp = crate::models::generate_totp_code(
                &raw_totp,
                crate::models::unix_now().max(0) as u64,
            );

            v_flex()
                .w(px(480.))
                .p_5()
                .gap_3p5()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border_active())
                .child(
                    h_flex()
                        .w_full()
                        .justify_between()
                        .items_center()
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .truncate()
                                .text_base()
                                .font_bold()
                                .text_color(BonTheme::text_primary())
                                .child(target_title),
                        )
                        .child(
                            Button::new("qm-close")
                                .ghost()
                                .small()
                                .label(SfSymbol::XMARK)
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        ),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_1p5()
                        .child(field_label("Status Tags (click to toggle or add custom tag)"))
                        .child(
                            h_flex().w_full().gap_1p5().flex_wrap().children(
                                Profile::PRESET_TAGS.into_iter().map(|tag| {
                                    let active = cur_tags
                                        .iter()
                                        .any(|t| t.eq_ignore_ascii_case(tag));
                                    let tag_s = tag.to_string();
                                    Button::new(SharedString::from(format!("qm-preset-{tag}")))
                                        .with_variant(BonTheme::toggle_pill(cx, active))
                                        .small()
                                        .label(tag)
                                        .on_click(cx.listener(move |app, _, _, cx| {
                                            if let Some(pos) = app
                                                .quick_meta_tags
                                                .iter()
                                                .position(|t| t.eq_ignore_ascii_case(&tag_s))
                                            {
                                                app.quick_meta_tags.remove(pos);
                                            } else {
                                                app.quick_meta_tags.push(tag_s.clone());
                                            }
                                            cx.notify();
                                        }))
                                }),
                            ),
                        )
                        .children((!cur_tags.is_empty()).then(|| {
                            h_flex().w_full().gap_1().flex_wrap().children(
                                cur_tags.iter().map(|t| {
                                    let t_rem = t.clone();
                                    let (fg, bg) = Profile::tag_badge_colors(t);
                                    div()
                                        .px_2()
                                        .py_0p5()
                                        .rounded_sm()
                                        .bg(rgba(bg))
                                        .border_1()
                                        .border_color(rgb(fg))
                                        .text_xs()
                                        .font_semibold()
                                        .text_color(rgb(fg))
                                        .cursor_pointer()
                                        .on_mouse_down(
                                            MouseButton::Left,
                                            cx.listener(move |app, _, _, cx| {
                                                app.quick_meta_tags
                                                    .retain(|x| !x.eq_ignore_ascii_case(&t_rem));
                                                cx.notify();
                                            }),
                                        )
                                        .child(format!("{t} ×"))
                                }),
                            )
                        }))
                        .child(
                            h_flex()
                                .w_full()
                                .gap_2()
                                .child(
                                    div()
                                        .flex_1()
                                        .child(Input::new(&app.quick_meta_tag_input)),
                                )
                                .child(
                                    Button::new("qm-add-custom-tag")
                                        .with_variant(BonTheme::outline_blue(cx))
                                        .small()
                                        .label("+ Add Tag")
                                        .on_click(cx.listener(|app, _, window, cx| {
                                            let raw = app
                                                .quick_meta_tag_input
                                                .read(cx)
                                                .value()
                                                .trim()
                                                .to_string();
                                            for part in Profile::parse_tags_csv(&raw) {
                                                if !app
                                                    .quick_meta_tags
                                                    .iter()
                                                    .any(|t| t.eq_ignore_ascii_case(&part))
                                                {
                                                    app.quick_meta_tags.push(part);
                                                }
                                            }
                                            app.quick_meta_tag_input = cx.new(|cx| {
                                                InputState::new(window, cx)
                                                    .placeholder("Custom tag (e.g. Shop-01, Tier1)...")
                                            });
                                            cx.notify();
                                        })),
                                ),
                        ),
                )
                .children(is_single.then(|| {
                    v_flex()
                        .w_full()
                        .gap_1()
                        .child(
                            h_flex()
                                .w_full()
                                .justify_between()
                                .items_center()
                                .child(field_label("2FA Secret (TOTP Base32 / otpauth://)"))
                                .children(live_totp.map(|(code, rem)| {
                                    let copy_code = code.clone();
                                    Button::new("qm-copy-live-totp")
                                        .with_variant(BonTheme::outline_blue(cx))
                                        .xsmall()
                                        .label(format!(
                                            "{} {} {} ({rem}s) • Copy", SfSymbol::LOCK_FILL,
                                            &code[..3],
                                            &code[3..]
                                        ))
                                        .on_click(cx.listener(move |app, _, _, cx| {
                                            cx.write_to_clipboard(ClipboardItem::new_string(
                                                copy_code.clone(),
                                            ));
                                            app.banner_message =
                                                Some(format!("Copied 2FA code: {copy_code}"));
                                            cx.notify();
                                        }))
                                })),
                        )
                        .child(Input::new(&app.quick_meta_totp_input))
                }))
                .child({
                    let qm_bms = app.quick_meta_bookmarks.clone();
                    v_flex()
                        .w_full()
                        .gap_1p5()
                        .child(field_label(if is_single {
                            "Bookmarks Bar"
                        } else {
                            "Bookmarks Bar (leave empty to keep existing)"
                        }))
                        .children((!qm_bms.is_empty()).then(|| {
                            h_flex()
                                .w_full()
                                .gap_1()
                                .flex_wrap()
                                .children(qm_bms.into_iter().map(|(n, u)| {
                                    let rm_u = u.clone();
                                    div()
                                        .px_2()
                                        .py_0p5()
                                        .rounded_sm()
                                        .bg(BonTheme::bg_well())
                                        .border_1()
                                        .border_color(BonTheme::border_active())
                                        .text_xs()
                                        .font_semibold()
                                        .text_color(BonTheme::text_primary())
                                        .cursor_pointer()
                                        .hover(|s| s.bg(BonTheme::danger_bg()).border_color(BonTheme::danger()))
                                        .on_mouse_down(
                                            MouseButton::Left,
                                            cx.listener(move |app, _, _, cx| {
                                                app.quick_meta_bookmarks.retain(|(_, eu)| eu != &rm_u);
                                                cx.notify();
                                            }),
                                        )
                                        .child(format!("{} {n} ×", SfSymbol::BOOKMARK_FILL))
                                }))
                        }))
                        .child(
                            h_flex()
                                .w_full()
                                .gap_1p5()
                                .child(
                                    div()
                                        .w(px(135.))
                                        .flex_shrink_0()
                                        .child(Input::new(&app.quick_meta_bm_name_input)),
                                )
                                .child(
                                    div()
                                        .flex_1()
                                        .child(Input::new(&app.quick_meta_bm_url_input)),
                                )
                                .child(
                                    Button::new("qm-bm-add-btn")
                                        .with_variant(BonTheme::outline_blue(cx))
                                        .small()
                                        .label("+ Add")
                                        .on_click(cx.listener(|app, _, window, cx| {
                                            app.add_quick_meta_bookmark_from_inputs(window, cx);
                                        })),
                                ),
                        )
                })
                .child(
                    v_flex()
                        .w_full()
                        .gap_1()
                        .child(field_label(if is_single {
                            "Note"
                        } else {
                            "Note (leave blank to keep existing notes)"
                        }))
                        .child(Textarea::new(&app.quick_meta_note_input).w_full()),
                )
                .child(
                    h_flex()
                        .w_full()
                        .pt_2()
                        .border_t_1()
                        .border_color(BonTheme::border())
                        .justify_end()
                        .gap_2()
                        .child(
                            Button::new("qm-cancel")
                                .with_variant(BonTheme::row_action(cx))
                                .small()
                                .label("Cancel")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("qm-save")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .label("Save")
                                .on_click(cx.listener(|app, _, window, cx| {
                                    app.save_quick_meta_modal(window, cx);
                                })),
                        ),
                )
        }

        ActivePopupModal::CookieRobot => {
            let target_desc = if let Some(pid) = &app.cookie_robot_target_id {
                let name = app
                    .profiles
                    .iter()
                    .find(|p| &p.id == pid)
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| "Profile".to_string());
                format!("{}  Cookie Robot (Auto Warm-up) — {name}", SfSymbol::BOLT_FILL)
            } else {
                format!(
                    "{}  Cookie Robot (Auto Warm-up) — {} profile(s)",
                    SfSymbol::BOLT_FILL,
                    app.checked_profile_ids.len()
                )
            };
            let cur_dwell = app.cookie_robot_dwell_secs;
            let presets: [(&str, &str); 3] = [
                (
                    "Google & YouTube",
                    "https://www.google.com\nhttps://www.youtube.com\nhttps://news.google.com\nhttps://maps.google.com",
                ),
                (
                    "Social & Tech News",
                    "https://www.reddit.com\nhttps://news.ycombinator.com\nhttps://www.wikipedia.org\nhttps://github.com",
                ),
                (
                    "E-commerce & Shopping",
                    "https://www.amazon.com\nhttps://www.ebay.com\nhttps://www.walmart.com\nhttps://www.etsy.com",
                ),
            ];
            v_flex()
                .w(px(500.))
                .p_5()
                .gap_3p5()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border_active())
                .child(
                    h_flex()
                        .w_full()
                        .justify_between()
                        .items_center()
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .truncate()
                                .text_base()
                                .font_bold()
                                .text_color(BonTheme::text_primary())
                                .child(target_desc),
                        )
                        .child(
                            Button::new("cr-close")
                                .ghost()
                                .small()
                                .label(SfSymbol::XMARK)
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        ),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_1p5()
                        .child(field_label("1. Site Presets"))
                        .child(
                            h_flex().w_full().gap_1p5().flex_wrap().children(
                                presets.into_iter().enumerate().map(|(i, (lbl, urls))| {
                                    let urls_s = urls.to_string();
                                    Button::new(SharedString::from(format!("cr-preset-{i}")))
                                        .with_variant(BonTheme::outline_blue(cx))
                                        .xsmall()
                                        .label(lbl)
                                        .on_click(cx.listener(move |app, _, window, cx| {
                                            let text = urls_s.clone();
                                            app.cookie_robot_urls_input = cx.new(|cx| {
                                                TextareaState::new(window, cx)
                                                    .rows(6)
                                                    .default_value(text)
                                            });
                                            cx.notify();
                                        }))
                                }),
                            ),
                        ),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_1p5()
                        .child(field_label("2. Dwell Time per Website (Scroll & Collect Cookies)"))
                        .child(
                            h_flex().w_full().gap_1p5().children(
                                [3u64, 5, 8, 12].into_iter().map(|secs| {
                                    let active = cur_dwell == secs;
                                    Button::new(SharedString::from(format!("cr-dwell-{secs}")))
                                        .with_variant(BonTheme::toggle_pill(cx, active))
                                        .small()
                                        .label(format!("{secs}s / site"))
                                        .on_click(cx.listener(move |app, _, _, cx| {
                                            app.cookie_robot_dwell_secs = secs;
                                            cx.notify();
                                        }))
                                }),
                            ),
                        ),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_1()
                        .child(field_label("3. Target URLs (one URL per line)"))
                        .child(Textarea::new(&app.cookie_robot_urls_input).w_full()),
                )
                .child(
                    h_flex()
                        .w_full()
                        .pt_2()
                        .border_t_1()
                        .border_color(BonTheme::border())
                        .justify_end()
                        .gap_2()
                        .child(
                            Button::new("cr-cancel")
                                .with_variant(BonTheme::row_action(cx))
                                .small()
                                .label("Cancel")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("cr-run")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .label("▶ Start Warm-up")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    app.start_cookie_robot(cx);
                                })),
                        ),
                )
        }

        ActivePopupModal::ImportBackupZip => {
            v_flex()
                .w(px(460.))
                .p_5()
                .gap_3p5()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border_active())
                .child(
                    h_flex()
                        .w_full()
                        .justify_between()
                        .items_center()
                        .child(
                            div()
                                .text_base()
                                .font_bold()
                                .text_color(BonTheme::text_primary())
                                .child("\u{10023b}  Import Profile Backup (.zip)"),
                        )
                        .child(
                            Button::new("ibz-close")
                                .ghost()
                                .small()
                                .label(SfSymbol::XMARK)
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        ),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(BonTheme::text_secondary())
                        .child(
                            "Restore a full BonLogin profile archive (.zip) including fingerprint settings, cookies, LocalStorage, and user-data-dir.",
                        ),
                )
                .child(
                    h_flex()
                        .w_full()
                        .gap_2()
                        .child(
                            div()
                                .flex_1()
                                .child(Input::new(&app.backup_zip_input)),
                        )
                        .child(
                            Button::new("ibz-browse")
                                .with_variant(BonTheme::outline_blue(cx))
                                .small()
                                .label("\u{100216} Browse .zip")
                                .on_click(cx.listener(|app, _, window, cx| {
                                    app.browse_and_import_backup_zip(window, cx);
                                })),
                        ),
                )
                .child(
                    h_flex()
                        .w_full()
                        .pt_2()
                        .border_t_1()
                        .border_color(BonTheme::border())
                        .justify_end()
                        .gap_2()
                        .child(
                            Button::new("ibz-cancel")
                                .with_variant(BonTheme::row_action(cx))
                                .small()
                                .label("Cancel")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("ibz-submit")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .label("Restore Profile")
                                .on_click(cx.listener(|app, _, window, cx| {
                                    app.import_backup_zip_from_input(window, cx);
                                })),
                        ),
                )
        }

        ActivePopupModal::CloneProfile => {
            let src_name = app
                .clone_target_id
                .as_ref()
                .and_then(|id| app.profiles.iter().find(|p| &p.id == id))
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "Profile".to_string());
            v_flex()
                .w(px(420.))
                .p_5()
                .gap_3p5()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border_active())
                .child(
                    h_flex()
                        .w_full()
                        .justify_between()
                        .items_center()
                        .child(
                            div()
                                .text_base()
                                .font_bold()
                                .text_color(BonTheme::text_primary())
                                .child(format!("{}  Clone Profile — {src_name}", SfSymbol::PLUS_SQUARE_ON_SQUARE)),
                        )
                        .child(
                            Button::new("cln-close")
                                .ghost()
                                .small()
                                .label(SfSymbol::XMARK)
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        ),
                )
                .child(
                    h_flex()
                        .w_full()
                        .gap_3()
                        .child(
                            v_flex()
                                .w(px(110.))
                                .gap_1()
                                .child(field_label("Copies (1–50)"))
                                .child(Input::new(&app.clone_count_input)),
                        )
                        .child(
                            v_flex()
                                .flex_1()
                                .gap_1()
                                .child(field_label("Name Prefix"))
                                .child(Input::new(&app.clone_prefix_input)),
                        ),
                )
                .child(
                    h_flex()
                        .w_full()
                        .pt_2()
                        .border_t_1()
                        .border_color(BonTheme::border())
                        .justify_end()
                        .gap_2()
                        .child(
                            Button::new("cln-cancel")
                                .with_variant(BonTheme::row_action(cx))
                                .small()
                                .label("Cancel")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("cln-submit")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .label("Clone")
                                .on_click(cx.listener(|app, _, window, cx| {
                                    app.submit_clone_modal(window, cx);
                                })),
                        ),
                )
        }

        ActivePopupModal::EditProxy => {
            let proxy_groups = app.distinct_proxy_groups_with_counts();
            let cur_tag = app.proxy_selected_tag.clone();
            v_flex()
                .w(px(480.))
                .p_5()
                .gap_3p5()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border_active())
                .child(
                    h_flex()
                        .w_full()
                        .justify_between()
                        .items_center()
                        .child(
                            div()
                                .text_base()
                                .font_bold()
                                .text_color(BonTheme::text_primary())
                                .child(format!("{}  Edit Proxy & Rotation URL", SfSymbol::PENCIL)),
                        )
                        .child(
                            Button::new("edpx-close")
                                .ghost()
                                .small()
                                .label(SfSymbol::XMARK)
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        ),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_1()
                        .child(field_label("Proxy Name"))
                        .child(Input::new(&app.proxy_edit_name_input)),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_1p5()
                        .child(field_label("Tag"))
                        .child(
                            h_flex()
                                .w_full()
                                .gap_1p5()
                                .flex_wrap()
                                .child(
                                    Button::new("edpx-tag-none")
                                        .xsmall()
                                        .with_variant(BonTheme::toggle_pill(
                                            cx,
                                            cur_tag.trim().is_empty(),
                                        ))
                                        .label("No tag")
                                        .on_click(cx.listener(|app, _, _, cx| {
                                            app.proxy_selected_tag = String::new();
                                            cx.notify();
                                        })),
                                )
                                .children(proxy_groups.into_iter().map(|(grp, _)| {
                                    let g_c = grp.clone();
                                    let active = cur_tag.eq_ignore_ascii_case(&grp);
                                    Button::new(SharedString::from(format!("edpx-tag-{grp}")))
                                        .xsmall()
                                        .with_variant(BonTheme::toggle_pill(cx, active))
                                        .label(format!("#{grp}"))
                                        .on_click(cx.listener(move |app, _, _, cx| {
                                            app.proxy_selected_tag = g_c.clone();
                                            cx.notify();
                                        }))
                                })),
                        ),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_1()
                        .child(field_label("IP Rotation Webhook URL (http://... or https://...)"))
                        .child(Input::new(&app.proxy_edit_rotate_input)),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_1()
                        .child(field_label("Expiration Date (DD/MM/YYYY or days)"))
                        .child(Input::new(&app.proxy_expire_input)),
                )
                .child(
                    h_flex()
                        .w_full()
                        .pt_2()
                        .border_t_1()
                        .border_color(BonTheme::border())
                        .justify_end()
                        .gap_2()
                        .child(
                            Button::new("edpx-cancel")
                                .with_variant(BonTheme::row_action(cx))
                                .small()
                                .label("Cancel")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("edpx-save")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .label("Save")
                                .on_click(cx.listener(|app, _, window, cx| {
                                    app.save_edit_proxy_modal(window, cx);
                                })),
                        ),
                )
        }

        ActivePopupModal::AgentFlows => {
            let target_prof = app
                .flow_target_id
                .as_ref()
                .or(app.selected_profile_id.as_ref())
                .and_then(|id| app.profiles.iter().find(|p| &p.id == id));
            let (target_label, hist_count) = if let Some(p) = target_prof {
                let sid = p.short_id();
                let h = crate::launcher::load_flow_from_path(
                    &crate::launcher::history_flow_path(&sid),
                    "hist",
                );
                (
                    if app.flow_target_id.is_none() && app.checked_profile_ids.len() > 1 {
                        format!("{} checked profiles", app.checked_profile_ids.len())
                    } else {
                        format!("{} (bon_{sid})", p.name)
                    },
                    h.steps.len(),
                )
            } else {
                ("Selected profile(s)".to_string(), 0)
            };
            let flows = app.saved_flows.clone();
            v_flex()
                .w(px(540.))
                .p_5()
                .gap_3p5()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border_active())
                .child(
                    h_flex()
                        .w_full()
                        .justify_between()
                        .items_center()
                        .child(
                            div()
                                .text_base()
                                .font_bold()
                                .text_color(BonTheme::text_primary())
                                .child(format!("{}  Agent Flow Playbooks — {target_label}", SfSymbol::PLAY_FILL)),
                        )
                        .child(
                            Button::new("flw-close")
                                .ghost()
                                .small()
                                .label(SfSymbol::XMARK)
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        ),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_1()
                        .child(field_label(
                            "Variables {{var}} Override (key=value, comma-separated)",
                        ))
                        .child(Input::new(&app.flow_vars_input)),
                )
                .child(
                    v_flex()
                        .w_full()
                        .p_3()
                        .gap_2()
                        .rounded_md()
                        .bg(BonTheme::bg_panel())
                        .border_1()
                        .border_color(BonTheme::border())
                        .child(
                            h_flex()
                                .w_full()
                                .justify_between()
                                .items_center()
                                .child(field_label("Save Recorded Profile History as Flow"))
                                .child(
                                    h_flex()
                                        .gap_1p5()
                                        .items_center()
                                        .child(
                                            div()
                                                .text_xs()
                                                .text_color(BonTheme::text_secondary())
                                                .child(format!("{hist_count} recorded step(s)")),
                                        )
                                        .children((hist_count > 0).then(|| {
                                            Button::new("flw-clr-hist")
                                                .ghost()
                                                .xsmall()
                                                .label("Clear")
                                                .on_click(cx.listener(|app, _, _, cx| {
                                                    app.clear_profile_flow_history_ui(cx);
                                                }))
                                        })),
                                ),
                        )
                        .child(
                            h_flex()
                                .w_full()
                                .gap_2()
                                .child(
                                    div()
                                        .flex_1()
                                        .child(Input::new(&app.flow_save_name_input)),
                                )
                                .child(
                                    Button::new("flw-save-hist-btn")
                                        .with_variant(BonTheme::outline_blue(cx))
                                        .small()
                                        .label("+ Save Flow")
                                        .on_click(cx.listener(|app, _, window, cx| {
                                            app.save_history_as_flow_ui(window, cx);
                                        })),
                                ),
                        ),
                )
                .child(
                    v_flex()
                        .id("saved-flows-list")
                        .w_full()
                        .max_h(px(300.))
                        .gap_2()
                        .overflow_y_scroll()
                        .children(flows.is_empty().then(|| {
                            div()
                                .w_full()
                                .py_6()
                                .flex()
                                .justify_center()
                                .text_xs()
                                .text_color(BonTheme::text_secondary())
                                .child("No saved flows yet. Run `bon-login agent <id> ...` and click '+ Save Flow' above.")
                        }))
                        .children(flows.into_iter().map(|fl| {
                            let is_expanded =
                                app.expanded_flow_name.as_deref() == Some(fl.name.as_str());
                            let fn_exp = fl.name.clone();
                            let fn_run = fl.name.clone();
                            let fn_del = fl.name.clone();
                            let fn_for_steps = fl.name.clone();
                            let vars = crate::launcher::extract_flow_vars(&fl);
                            let meta = if vars.is_empty() {
                                format!(
                                    "{} steps • {}",
                                    fl.steps.len(),
                                    if fl.domain.is_empty() {
                                        "any domain"
                                    } else {
                                        &fl.domain
                                    }
                                )
                            } else {
                                format!(
                                    "{} steps • vars: {{{{{}}}}}",
                                    fl.steps.len(),
                                    vars.join("}}, {{")
                                )
                            };
                            let steps_list = fl.steps.clone();
                            v_flex()
                                .w_full()
                                .px_3()
                                .py_2()
                                .gap_2()
                                .rounded_md()
                                .bg(BonTheme::bg_panel())
                                .border_1()
                                .border_color(if is_expanded {
                                    BonTheme::border_active()
                                } else {
                                    BonTheme::border()
                                })
                                .child(
                                    h_flex()
                                        .w_full()
                                        .justify_between()
                                        .items_center()
                                        .gap_2()
                                        .child(
                                            v_flex()
                                                .flex_1()
                                                .min_w_0()
                                                .cursor_pointer()
                                                .on_mouse_down(
                                                    MouseButton::Left,
                                                    cx.listener(move |app, _, _, cx| {
                                                        app.toggle_expanded_flow_ui(&fn_exp, cx);
                                                    }),
                                                )
                                                .child(
                                                    div()
                                                        .truncate()
                                                        .text_xs()
                                                        .font_bold()
                                                        .text_color(BonTheme::text_primary())
                                                        .child(format!(
                                                            "{} {}",
                                                            if is_expanded { "▾" } else { "▸" },
                                                            fl.name
                                                        )),
                                                )
                                                .child(
                                                    div()
                                                        .truncate()
                                                        .text_xs()
                                                        .text_color(BonTheme::text_secondary())
                                                        .child(meta),
                                                ),
                                        )
                                        .child(
                                            h_flex()
                                                .gap_1p5()
                                                .items_center()
                                                .child(
                                                    Button::new(SharedString::from(format!(
                                                        "flw-run-{fn_run}"
                                                    )))
                                                    .with_variant(BonTheme::launch_cta(cx))
                                                    .small()
                                                    .label("▶ Run")
                                                    .on_click(cx.listener(move |app, _, _, cx| {
                                                        app.run_saved_flow_ui(&fn_run, cx);
                                                    })),
                                                )
                                                .child(
                                                    Button::new(SharedString::from(format!(
                                                        "flw-del-{fn_del}"
                                                    )))
                                                    .ghost()
                                                    .small()
                                                    .label(SfSymbol::TRASH)
                                                    .on_click(cx.listener(move |app, _, _, cx| {
                                                        app.delete_saved_flow_ui(&fn_del, cx);
                                                    })),
                                                ),
                                        ),
                                )
                                .children(is_expanded.then(|| {
                                    v_flex()
                                        .w_full()
                                        .pt_1p5()
                                        .gap_1()
                                        .border_t_1()
                                        .border_color(BonTheme::border())
                                        .children(steps_list.into_iter().enumerate().map(
                                            |(s_idx, st)| {
                                                let fn_opt = fn_for_steps.clone();
                                                let fn_rm = fn_for_steps.clone();
                                                let loc_preview =
                                                    st.locators.first().cloned().unwrap_or_default();
                                                let val_preview = st
                                                    .value
                                                    .as_deref()
                                                    .map(|v| format!(" \"{v}\""))
                                                    .unwrap_or_default();
                                                let summary = format!(
                                                    "#{s_idx}  {}  {loc_preview}{val_preview}",
                                                    st.op
                                                );
                                                let is_opt = st.optional;
                                                h_flex()
                                                    .w_full()
                                                    .px_2()
                                                    .py_1()
                                                    .gap_1p5()
                                                    .rounded_sm()
                                                    .bg(BonTheme::bg_elevated())
                                                    .justify_between()
                                                    .items_center()
                                                    .child(
                                                        div()
                                                            .flex_1()
                                                            .min_w_0()
                                                            .truncate()
                                                            .text_size(px(11.))
                                                            .text_color(if is_opt {
                                                                BonTheme::text_secondary()
                                                            } else {
                                                                BonTheme::text_primary()
                                                            })
                                                            .child(summary),
                                                    )
                                                    .child(
                                                        h_flex()
                                                            .gap_1()
                                                            .items_center()
                                                            .child(
                                                                Button::new(SharedString::from(
                                                                    format!(
                                                                        "flw-opt-{fn_opt}-{s_idx}"
                                                                    ),
                                                                ))
                                                                .ghost()
                                                                .xsmall()
                                                                .label(if is_opt {
                                                                    "Optional"
                                                                } else {
                                                                    "Required"
                                                                })
                                                                .on_click(cx.listener(
                                                                    move |app, _, _, cx| {
                                                                        app.mutate_flow_step_ui(
                                                                            &fn_opt,
                                                                            s_idx,
                                                                            "toggle",
                                                                            cx,
                                                                        );
                                                                    },
                                                                )),
                                                            )
                                                            .child(
                                                                Button::new(SharedString::from(
                                                                    format!(
                                                                        "flw-sdel-{fn_rm}-{s_idx}"
                                                                    ),
                                                                ))
                                                                .ghost()
                                                                .xsmall()
                                                                .label(SfSymbol::XMARK)
                                                                .on_click(cx.listener(
                                                                    move |app, _, _, cx| {
                                                                        app.mutate_flow_step_ui(
                                                                            &fn_rm,
                                                                            s_idx,
                                                                            "delete",
                                                                            cx,
                                                                        );
                                                                    },
                                                                )),
                                                            ),
                                                    )
                                            },
                                        ))
                                }))
                        })),
                )
        }
    };

    let modal_anim_id = SharedString::from(format!("popup-modal-{modal_kind:?}"));
    let backdrop_anim_id = SharedString::from(format!("popup-backdrop-{modal_kind:?}"));

    div()
        .absolute()
        .top_0()
        .left_0()
        .size_full()
        .bg(rgba(0x00000080))
        .flex()
        .items_center()
        .justify_center()
        .on_mouse_down(
            MouseButton::Left,
            cx.listener(|app, _, _, cx| {
                app.close_popup_modal(cx);
            }),
        )
        .child(
            card.on_mouse_down(MouseButton::Left, |_, _, cx| {
                cx.stop_propagation();
            })
            .with_animation(
                modal_anim_id,
                BonTheme::ui_enter_anim(),
                |this, delta| this.opacity(delta),
            ),
        )
        .with_animation(
            backdrop_anim_id,
            BonTheme::ui_enter_anim(),
            |this, delta| this.opacity(delta),
        )
        .into_any_element()
}

pub fn push_bookmark_from_inputs(
    list: &mut Vec<(String, String)>,
    name_input: &Entity<InputState>,
    url_input: &Entity<InputState>,
    window: &mut Window,
    cx: &mut App,
) {
    let name_raw = name_input.read(cx).value().trim().to_string();
    let url_raw = url_input.read(cx).value().trim().to_string();
    if url_raw.is_empty() {
        return;
    }
    let combined = if name_raw.is_empty() {
        url_raw
    } else {
        format!("{name_raw}|{url_raw}")
    };
    for (n, u) in crate::launcher::parse_bookmarks_editable(&combined) {
        if !list.iter().any(|(_, eu)| eu.eq_ignore_ascii_case(&u)) {
            list.push((n, u));
        }
    }
    name_input.update(cx, |s, cx| s.set_value(String::new(), window, cx));
    url_input.update(cx, |s, cx| s.set_value(String::new(), window, cx));
}

fn render_modal_bookmarks_section(
    modal: &ProfileModalState,
    bookmarks: &[(String, String)],
    show_full_rows: bool,
    cx: &mut Context<BonLoginApp>,
) -> Div {
    let pfx = if show_full_rows { "tab-bm" } else { "ov-bm" };
    v_flex()
        .w_full()
        .gap_2()
        .child(
            h_flex()
                .w_full()
                .justify_between()
                .items_center()
                .gap_2()
                .child(field_label(
                    "Bookmarks Bar (shown on all tabs)",
                ))
                .children((!bookmarks.is_empty()).then(|| {
                    Button::new(SharedString::from(format!("{pfx}-clear-all")))
                        .with_variant(BonTheme::row_action(cx))
                        .xsmall()
                        .label("Clear")
                        .on_click(cx.listener(|app, _, _, cx| {
                            if let Some(m) = app.modal.as_mut() {
                                m.bookmarks.clear();
                                cx.notify();
                            }
                        }))
                })),
        )
        .child(
            h_flex()
                .w_full()
                .gap_2()
                .child(
                    div()
                        .w(px(170.))
                        .flex_shrink_0()
                        .child(Input::new(&modal.bookmark_name_input)),
                )
                .child(
                    div()
                        .flex_1()
                        .child(Input::new(&modal.bookmark_url_input)),
                )
                .child(
                    Button::new(SharedString::from(format!("{pfx}-add-btn")))
                        .with_variant(BonTheme::outline_blue(cx))
                        .small()
                        .label("+ Add Bookmark")
                        .on_click(cx.listener(|app, _, window, cx| {
                            if let Some(m) = app.modal.as_mut() {
                                let n = m.bookmark_name_input.clone();
                                let u = m.bookmark_url_input.clone();
                                push_bookmark_from_inputs(&mut m.bookmarks, &n, &u, window, cx);
                                cx.notify();
                            }
                        })),
                ),
        )
        .child(if bookmarks.is_empty() {
            div()
                .w_full()
                .px_3()
                .py_2()
                .rounded_md()
                .bg(BonTheme::bg_well())
                .text_xs()
                .text_color(BonTheme::text_muted())
                .child("No bookmarks on bar — enter a URL above and click '+ Add Bookmark'.")
                .into_any_element()
        } else if show_full_rows {
            v_flex()
                .w_full()
                .gap_1p5()
                .children(bookmarks.iter().enumerate().map(|(i, (name, url))| {
                    let rm_url = url.clone();
                    let cp_url = url.clone();
                    h_flex()
                        .w_full()
                        .px_3()
                        .py_1p5()
                        .rounded_md()
                        .bg(BonTheme::bg_well())
                        .border_1()
                        .border_color(BonTheme::border())
                        .justify_between()
                        .items_center()
                        .gap_2()
                        .child(
                            h_flex()
                                .flex_1()
                                .min_w_0()
                                .gap_2p5()
                                .items_center()
                                .child(
                                    div()
                                        .px_2()
                                        .py_0p5()
                                        .rounded_sm()
                                        .bg(BonTheme::bg_elevated())
                                        .border_1()
                                        .border_color(BonTheme::border_active())
                                        .text_xs()
                                        .font_semibold()
                                        .text_color(BonTheme::text_primary())
                                        .child(format!("{}  {name}", SfSymbol::BOOKMARK_FILL)),
                                )
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .truncate()
                                        .text_xs()
                                        .text_color(BonTheme::text_secondary())
                                        .child(url.clone()),
                                ),
                        )
                        .child(
                            h_flex()
                                .gap_1()
                                .child(
                                    Button::new(SharedString::from(format!("cp-bm-{i}")))
                                        .ghost()
                                        .xsmall()
                                        .label(SfSymbol::DOC_ON_DOC)
                                        .on_click(cx.listener(move |app, _, _, cx| {
                                            cx.write_to_clipboard(ClipboardItem::new_string(cp_url.clone()));
                                            app.banner_message = Some(format!("Copied URL: {cp_url}"));
                                            cx.notify();
                                        })),
                                )
                                .child(
                                    Button::new(SharedString::from(format!("rm-bm-{i}")))
                                        .ghost()
                                        .xsmall()
                                        .label(SfSymbol::XMARK)
                                        .on_click(cx.listener(move |app, _, _, cx| {
                                            if let Some(m) = app.modal.as_mut() {
                                                m.bookmarks.retain(|(_, eu)| eu != &rm_url);
                                                cx.notify();
                                            }
                                        })),
                                ),
                        )
                }))
                .into_any_element()
        } else {
            h_flex()
                .w_full()
                .gap_1p5()
                .flex_wrap()
                .children(bookmarks.iter().map(|(name, url)| {
                    let rm_url = url.clone();
                    div()
                        .px_2p5()
                        .py_1()
                        .rounded_md()
                        .bg(BonTheme::bg_well())
                        .border_1()
                        .border_color(BonTheme::border_active())
                        .text_xs()
                        .font_semibold()
                        .text_color(BonTheme::text_primary())
                        .cursor_pointer()
                        .hover(|s| s.bg(BonTheme::danger_bg()).border_color(BonTheme::danger()))
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |app, _, _, cx| {
                                if let Some(m) = app.modal.as_mut() {
                                    m.bookmarks.retain(|(_, eu)| eu != &rm_url);
                                    cx.notify();
                                }
                            }),
                        )
                        .child(format!("{} {name}  ×", SfSymbol::BOOKMARK_FILL))
                }))
                .into_any_element()
        })
}
