use gpui_kit::component::{
    button::{Button, ButtonVariants as _},
    input::{Input, InputState, Textarea, TextareaState},
    menu::{DropdownMenu as _, PopupMenuItem},
    *,
};
use gpui_kit::*;
use crate::models::{
    BrowserBrand, GpuSpoofMode, PlatformType, Profile, ProfileEditorDraft, SavedProxy,
};
use crate::ui::theme::{BonTheme, SfSymbol};
use crate::ui::workspace_views::field_label;
use crate::ui::{BonLoginApp, ProfileSubTab, WorkspaceView};

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
    pub draft: ProfileEditorDraft,
    pub active_tab: ProfileEditorTab,
    pub proxy_mode: ProxyEditMode,
    pub checking_proxy: bool,
    pub proxy_check_error: Option<String>,
    pub auto_geo: bool,
    pub name_input: Entity<InputState>,
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
}

impl ProfileModalState {
    pub fn from_profile(
        root_dir: &std::path::Path,
        profile: &Profile,
        is_edit: bool,
        window: &mut Window,
        cx: &mut Context<BonLoginApp>,
    ) -> Self {
        let draft = ProfileEditorDraft::from_profile(profile, is_edit);
        let name_val = profile.name.clone();
        let seed_val = profile.seed.to_string();
        let tz_val = profile.custom_timezone.clone().unwrap_or_default();
        let loc_val = profile.custom_locale.clone().unwrap_or_default();
        let url_val = profile.startup_url.clone();
        let notes_val = profile.notes.clone();
        let totp_val = profile.totp_secret.clone();
        let bookmarks_val = crate::launcher::read_profile_bookmarks_in(root_dir, profile);
        let cookies_val = if is_edit {
            crate::db::read_saved_cookies_in(root_dir, &profile.short_id())
                .filter(|s| {
                    crate::launcher::parse_and_normalize_cookies(s, None)
                        .is_ok_and(|b| !b.cookies.is_empty() || !b.origins.is_empty())
                })
                .unwrap_or_default()
        } else {
            String::new()
        };
        let proxy_mode = if profile.proxy.is_some() {
            ProxyEditMode::SavedPool
        } else {
            ProxyEditMode::Direct
        };
        let auto_geo = profile.custom_timezone.is_none() && profile.custom_locale.is_none();

        Self {
            draft,
            active_tab: ProfileEditorTab::Overview,
            proxy_mode,
            checking_proxy: false,
            proxy_check_error: None,
            auto_geo,
            name_input: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("e.g. Client A · Facebook Ads")
                    .default_value(name_val)
            }),
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
        }
    }

    pub fn build_profile(&self, cx: &App) -> anyhow::Result<Profile> {
        let name = self.name_input.read(cx).value().to_string();
        let seed_str = self.seed_input.read(cx).value().to_string();
        let custom_tz = self.custom_tz_input.read(cx).value().to_string();
        let custom_locale = self.custom_locale_input.read(cx).value().to_string();
        let startup_url = self.startup_url_input.read(cx).value().to_string();
        let notes = self.notes_input.read(cx).value().to_string();
        let totp_secret = self.totp_input.read(cx).value().to_string();
        self.draft
            .finalize(
                &name,
                &seed_str,
                self.proxy_mode == ProxyEditMode::SavedPool,
                self.auto_geo,
                &custom_tz,
                &custom_locale,
                &startup_url,
                &notes,
                &totp_secret,
            )
            .map_err(|e| anyhow::anyhow!(e))
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
    let is_edit = modal.draft.is_edit;
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
    let p_ref = &modal.draft.profile;
    let os_platform = p_ref.os_platform;
    let brand = p_ref.brand;
    let gpu_spoofing = p_ref.gpu_spoofing;
    let spoof_canvas = p_ref.spoof_canvas;
    let spoof_audio = p_ref.spoof_audio;
    let spoof_font = p_ref.spoof_font;
    let spoof_client_rects = p_ref.spoof_client_rects;
    let win_size = p_ref.window_size.clone();
    let err_msg = modal.validation_error.clone();
    let name_preview = {
        let v = modal.name_input.read(cx).value().trim().to_string();
        if v.is_empty() { "-".to_string() } else { v }
    };
    let group_preview = p_ref.group_tag.trim().to_string();
    let seed_preview = modal.seed_input.read(cx).value().to_string();
    let seed_num: u32 = seed_preview.trim().parse().unwrap_or(p_ref.seed);
    let cores = if modal.draft.cores_pinned || seed_num == p_ref.seed {
        p_ref.hardware_concurrency
    } else {
        os_platform.optimal_cores_for_seed(seed_num)
    };
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
    let selected_proxy = modal.draft.profile.proxy.clone();
    let checking = modal.checking_proxy;
    let check_err = modal.proxy_check_error.clone();
    let resolved_geo = modal.draft.profile.resolved_geo.clone();
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
                                                                                    m.draft.profile.group_tag =
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
                                                                                        m.draft.profile.group_tag =
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
                                )
                                // 6-Tab Segmented Bar: Overview | Network | Location | Hardware | Bookmarks | Cookies
                                .child(
                                    h_flex()
                                        .w_full()
                                        .pt_2()
                                        .border_t_1()
                                        .border_color(BonTheme::border())
                                        .child(
                                            h_flex()
                                                .p(px(3.))
                                                .gap(px(2.))
                                                .rounded_lg()
                                                .bg(BonTheme::bg_well())
                                                .border_1()
                                                .border_color(BonTheme::border())
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
                                                        editor_tab_item(
                                                            tab,
                                                            lbl,
                                                            active_tab == tab,
                                                            cx,
                                                        )
                                                    }),
                                                ),
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
                                                            m.draft.select_brand(b);
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
                                                                    .unwrap_or(m.draft.profile.seed);
                                                                if s != m.draft.profile.seed {
                                                                    m.draft.randomize_to_seed(s);
                                                                }
                                                                m.draft.select_platform(target_os);
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
                                                                    m.draft
                                                                        .randomize_to_seed(new_seed);
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
                                                                    m.draft.profile.window_size =
                                                                        sz.to_string();
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
                                                                    m.draft.select_cores(c);
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
                                    let cur_tags = modal.draft.profile.tags.clone();
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
                                                                                .draft
                                                                                .profile
                                                                                .tags
                                                                                .iter()
                                                                                .position(|t| {
                                                                                    t.eq_ignore_ascii_case(
                                                                                        &tag_s,
                                                                                    )
                                                                                })
                                                                            {
                                                                                m.draft
                                                                                    .profile
                                                                                    .tags
                                                                                    .remove(pos);
                                                                            } else {
                                                                                m.draft
                                                                                    .profile
                                                                                    .tags
                                                                                    .push(
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
                                                        .dropdown_menu(move |mut menu, _, cx| {
                                                            let items: Vec<(String, String)> = app_for_menu
                                                                .read(cx)
                                                                .saved_proxies
                                                                .iter()
                                                                .map(|sp| {
                                                                    let flag = sp
                                                                        .resolved_geo
                                                                        .as_ref()
                                                                        .map(|g| {
                                                                            crate::models::GeoInfo::country_flag(
                                                                                &g.country_code,
                                                                            )
                                                                        })
                                                                        .unwrap_or(SfSymbol::GLOBE);
                                                                    let label = format!(
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
                                                                    (sp.id.clone(), label)
                                                                })
                                                                .collect();
                                                            for (sp_id, item_label) in items {
                                                                let app_pick = app_for_menu.clone();
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
                                                        m.draft.profile.spoof_canvas =
                                                            !m.draft.profile.spoof_canvas;
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
                                                        m.draft.profile.spoof_client_rects =
                                                            !m.draft.profile.spoof_client_rects;
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
                                                        m.draft.profile.spoof_audio =
                                                            !m.draft.profile.spoof_audio;
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
                                                        m.draft.profile.spoof_font =
                                                            !m.draft.profile.spoof_font;
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
                                                        .disabled(
                                                            os_platform != PlatformType::MacOS,
                                                        )
                                                        .with_variant(BonTheme::toggle_pill(
                                                            cx,
                                                            gpu_spoofing
                                                                == GpuSpoofMode::NativePassthrough,
                                                        ))
                                                        .label("Apple Metal Native (Off)")
                                                        .on_click(cx.listener(|app, _, _, cx| {
                                                            if let Some(m) = app.modal.as_mut() {
                                                                m.draft.select_gpu_spoofing(
                                                                    GpuSpoofMode::NativePassthrough,
                                                                );
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
                                                                m.draft.select_gpu_spoofing(
                                                                    GpuSpoofMode::SeedGenerated,
                                                                );
                                                                cx.notify();
                                                            }
                                                        })),
                                                ),
                                        ),
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
                                .into_any_element(),
                        }),
                )
                // Right Column: Live Fingerprint Summary Table
                .child(
                    v_flex()
                        .id("edit-profile-detail-col")
                        .w(px(296.))
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
                                .child("Live Fingerprint Summary"),
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
                        .child(detail_summary_row_mono(
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
                        .child(detail_summary_row_mono("Proxy", proxy_detail_str))
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

fn editor_tab_item(
    tab: ProfileEditorTab,
    label: &'static str,
    active: bool,
    cx: &mut Context<BonLoginApp>,
) -> impl IntoElement + use<> {
    h_flex()
        .id(SharedString::from(format!("prof-tab-{label}")))
        .px_3()
        .py_1()
        .items_center()
        .cursor_pointer()
        .rounded_md()
        .on_mouse_down(
            MouseButton::Left,
            cx.listener(move |app, _, _, cx| {
                if let Some(m) = app.modal.as_mut() {
                    m.active_tab = tab;
                    cx.notify();
                }
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
        .with_spring(
            SharedString::from(format!("prof-tab-spring-{label}")),
            SpringAnimation::new(BonTheme::snappy_spring()).to(active),
            move |this, phase| {
                this.bg(phase.interpolate_clamped(
                    Hsla::from(rgba(0x00000000)),
                    BonTheme::accent(),
                ))
                .hover(move |s| {
                    if active {
                        s.bg(rgb(0x2997ff))
                    } else {
                        s.bg(BonTheme::bg_hover())
                    }
                })
            },
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

pub fn detail_summary_row_mono(label: &'static str, value: String) -> Div {
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
                .font_family(BonTheme::font_mono())
                .text_xs()
                .font_semibold()
                .text_color(BonTheme::text_primary())
                .child(value),
        )
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
