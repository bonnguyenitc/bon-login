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
use crate::ui::{ActivePopupModal, BonLoginApp, ProfileSubTab, WorkspaceView};


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
    pub seed_input: Entity<InputState>,
    pub custom_tz_input: Entity<InputState>,
    pub custom_locale_input: Entity<InputState>,
    pub startup_url_input: Entity<InputState>,
    pub notes_input: Entity<InputState>,
    pub cookies_input: Entity<TextareaState>,
    pub validation_error: Option<String>,
}

impl ProfileModalState {
    pub fn from_profile(
        profile: &Profile,
        is_edit: bool,
        window: &mut Window,
        cx: &mut Context<BonLoginApp>,
    ) -> Self {
        let name_val = profile.name.clone();
        let group_val = if profile.group_tag.trim().is_empty() {
            "General".to_string()
        } else {
            profile.group_tag.clone()
        };
        let seed_val = profile.seed.to_string();
        let tz_val = profile.custom_timezone.clone().unwrap_or_default();
        let loc_val = profile.custom_locale.clone().unwrap_or_default();
        let url_val = profile.startup_url.clone();
        let notes_val = profile.notes.clone();
        let cookies_val = if is_edit {
            crate::launcher::read_prelaunch_cookies(&profile.short_id())
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
                    .placeholder("https://browserscan.net")
                    .default_value(url_val)
            }),
            notes_input: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("Anything to remember about this profile...")
                    .default_value(notes_val)
            }),
            cookies_input: cx.new(|cx| {
                TextareaState::new(window, cx)
                    .rows(14)
                    .placeholder("Optional: Paste Cookie JSON or State JSON to auto-inject on Launch...")
                    .default_value(cookies_val)
            }),
            validation_error: None,
        }
    }

    pub fn build_profile(&self, cx: &App) -> anyhow::Result<Profile> {
        let name = self.name_input.read(cx).value().trim().to_string();
        if name.is_empty() {
            anyhow::bail!("Profile name cannot be empty");
        }
        let group_tag = if self.selected_group.trim().is_empty() {
            "General".to_string()
        } else {
            self.selected_group.trim().to_string()
        };
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

        Ok(Profile {
            id: self
                .editing_id
                .clone()
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            name,
            group_tag,
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
            created_at: self.created_at,
            last_launched_at: self.last_launched_at,
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
    let group_preview = if modal.selected_group.trim().is_empty() {
        "General".to_string()
    } else {
        modal.selected_group.clone()
    };
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
                                                            Button::new("edit-open-groups-tab")
                                                                .ghost()
                                                                .xsmall()
                                                                .label("Manage Groups")
                                                                .on_click(cx.listener(
                                                                    |app, _, _, cx| {
                                                                        app.profile_sub_tab =
                                                                            ProfileSubTab::Group;
                                                                        app.active_view =
                                                                            WorkspaceView::Profiles;
                                                                        cx.notify();
                                                                    },
                                                                )),
                                                        ),
                                                )
                                                .child(
                                                    Button::new("edit-prof-group-dropdown")
                                                        .with_variant(BonTheme::row_action(cx))
                                                        .label(format!(
                                                            "{}  {cur_grp}  {}",
                                                            SfSymbol::FOLDER_FILL,
                                                            SfSymbol::CHEVRON_DOWN
                                                        ))
                                                        .dropdown_menu(move |mut menu, _, _| {
                                                            for grp in &groups_list {
                                                                let g_val = grp.clone();
                                                                let app_pick = app_for_grp.clone();
                                                                menu = menu.item(
                                                                    PopupMenuItem::new(format!(
                                                                        "{}   {g_val}",
                                                                        SfSymbol::FOLDER_FILL
                                                                    ))
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
                                                        }),
                                                )
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
                                            h_flex()
                                                .gap_1p5()
                                                .child(
                                                    Button::new("os-windows")
                                                        .small()
                                                        .with_variant(BonTheme::toggle_pill(
                                                            cx,
                                                            os_platform == PlatformType::Windows,
                                                        ))
                                                        .label(format!("{}  Windows 11", SfSymbol::PC))
                                                        .on_click(cx.listener(|app, _, _, cx| {
                                                            if let Some(m) = app.modal.as_mut() {
                                                                let s: u32 = m
                                                                    .seed_input
                                                                    .read(cx)
                                                                    .value()
                                                                    .trim()
                                                                    .parse()
                                                                    .unwrap_or(1000);
                                                                m.os_platform =
                                                                    PlatformType::Windows;
                                                                m.gpu_spoofing =
                                                                    GpuSpoofMode::SeedGenerated;
                                                                m.hardware_concurrency =
                                                                    PlatformType::Windows
                                                                        .optimal_cores_for_seed(s);
                                                                m.window_size =
                                                                    PlatformType::Windows
                                                                        .default_window_size()
                                                                        .to_string();
                                                                cx.notify();
                                                            }
                                                        })),
                                                )
                                                .child(
                                                    Button::new("os-macos")
                                                        .small()
                                                        .with_variant(BonTheme::toggle_pill(
                                                            cx,
                                                            os_platform == PlatformType::MacOS,
                                                        ))
                                                        .label(format!("{}  Mac OS", SfSymbol::APPLE_LOGO))
                                                        .on_click(cx.listener(|app, _, _, cx| {
                                                            if let Some(m) = app.modal.as_mut() {
                                                                let s: u32 = m
                                                                    .seed_input
                                                                    .read(cx)
                                                                    .value()
                                                                    .trim()
                                                                    .parse()
                                                                    .unwrap_or(1000);
                                                                m.os_platform = PlatformType::MacOS;
                                                                m.gpu_spoofing =
                                                                    GpuSpoofMode::SeedGenerated;
                                                                m.hardware_concurrency =
                                                                    PlatformType::MacOS
                                                                        .optimal_cores_for_seed(s);
                                                                m.window_size =
                                                                    PlatformType::MacOS
                                                                        .default_window_size()
                                                                        .to_string();
                                                                cx.notify();
                                                            }
                                                        })),
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
                                                                        rand::random::<u32>()
                                                                            .max(1000);
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
                                .child(
                                    h_flex()
                                        .w_full()
                                        .gap_3()
                                        .child(
                                            v_flex()
                                                .flex_1()
                                                .min_w_0()
                                                .gap_1()
                                                .child(field_label("Start URL"))
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
                                .with_animation(
                                    "prof-tab-overview-enter",
                                    Animation::new(Duration::from_millis(160))
                                        .with_easing(ease_out_quint()),
                                    |this, delta| this.opacity(delta).mt(px((1.0 - delta) * 6.0)),
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
                                                    "{flag}  {}:{} ({}) - {} (#{})  {}",
                                                    sp.config.host,
                                                    sp.config.port,
                                                    sp.config.protocol.as_str().to_uppercase(),
                                                    sp.name,
                                                    sp.group_tag,
                                                    SfSymbol::CHEVRON_DOWN
                                                )
                                            } else {
                                                format!(
                                                    "{}  {} ({})  {}",
                                                    SfSymbol::GLOBE,
                                                    cfg.display_short(),
                                                    cfg.protocol.as_str().to_uppercase(),
                                                    SfSymbol::CHEVRON_DOWN
                                                )
                                            }
                                        })
                                        .unwrap_or_else(|| {
                                            format!(
                                                "Select proxy from Proxy manager  {}",
                                                SfSymbol::CHEVRON_DOWN
                                            )
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
                                                        .with_variant(BonTheme::row_action(cx))
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
                                    Animation::new(Duration::from_millis(160))
                                        .with_easing(ease_out_quint()),
                                    |this, delta| this.opacity(delta).mt(px((1.0 - delta) * 6.0)),
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
                                    Animation::new(Duration::from_millis(160))
                                        .with_easing(ease_out_quint()),
                                    |this, delta| this.opacity(delta).mt(px((1.0 - delta) * 6.0)),
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
                                    Animation::new(Duration::from_millis(160))
                                        .with_easing(ease_out_quint()),
                                    |this, delta| this.opacity(delta).mt(px((1.0 - delta) * 6.0)),
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
                                        .child(field_label(
                                            "Import or Export Cookies as JSON file",
                                        ))
                                        .child(
                                            Button::new("modal-copy-cookies")
                                                .with_variant(BonTheme::row_action(cx))
                                                .small()
                                                .label("Copy Cookies JSON")
                                                .on_click(cx.listener(|app, _, _, cx| {
                                                    if let Some(m) = app.modal.as_ref() {
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
                                                })),
                                        ),
                                )
                                .child(
                                    v_flex()
                                        .w_full()
                                        .flex_1()
                                        .gap_1p5()
                                        .child(field_label(
                                            "Paste Cookie JSON / Auth State JSON (auto-injected when launching profile):",
                                        ))
                                        .child(Textarea::new(&modal.cookies_input).w_full()),
                                )
                                .with_animation(
                                    "prof-tab-cookies-enter",
                                    Animation::new(Duration::from_millis(160))
                                        .with_easing(ease_out_quint()),
                                    |this, delta| this.opacity(delta).mt(px((1.0 - delta) * 6.0)),
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

fn detail_summary_row(label: &'static str, value: String) -> Div {
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
pub fn render_bulk_backup_view(
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
                            let is_enabled = ext.enabled;
                            let is_default = ext.is_default;

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
                                            div()
                                                .w_0()
                                                .flex_1()
                                                .min_w_0()
                                                .truncate()
                                                .text_xs()
                                                .font_semibold()
                                                .text_color(BonTheme::text_primary())
                                                .child(ext.name.clone()),
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
                                        .child(if is_default {
                                            div().into_any_element()
                                        } else {
                                            h_flex()
                                                .gap_1p5()
                                                .items_center()
                                                .cursor_pointer()
                                                .text_xs()
                                                .text_color(BonTheme::text_secondary())
                                                .hover(|s| s.text_color(BonTheme::danger()))
                                                .on_mouse_down(
                                                    MouseButton::Left,
                                                    cx.listener(move |app, _, _, cx| {
                                                        app.pending_remove_ext_id =
                                                            Some(ext_id_remove.clone());
                                                        app.popup_modal =
                                                            Some(ActivePopupModal::RemoveExtension);
                                                        cx.notify();
                                                    }),
                                                )
                                                .child(SfSymbol::TRASH)
                                                .child("Remove")
                                                .into_any_element()
                                        })
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
    let filtered_proxies = app.filtered_saved_proxies();
    let checked_count = app.checked_proxy_ids.len();
    let all_filtered_checked = !filtered_proxies.is_empty()
        && filtered_proxies
            .iter()
            .all(|sp| app.checked_proxy_ids.contains(&sp.id));
    let any_filtered_checked = filtered_proxies
        .iter()
        .any(|sp| app.checked_proxy_ids.contains(&sp.id));
    let proxy_hdr_mark = if all_filtered_checked {
        SfSymbol::CHECKMARK
    } else if any_filtered_checked {
        SfSymbol::MINUS
    } else {
        ""
    };
    let tag_dropdown_label = if selected_pgrp == "All" {
        format!("All Tag ({total_proxies})  {}", SfSymbol::CHEVRON_DOWN)
    } else {
        format!(
            "#{selected_pgrp} ({})  {}",
            filtered_proxies.len(),
            SfSymbol::CHEVRON_DOWN
        )
    };

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
                                .with_variant(BonTheme::row_action(cx))
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
                            (selected_pgrp != "All" && !selected_pgrp.eq_ignore_ascii_case("General"))
                                .then(|| {
                                    let t_del = selected_pgrp.clone();
                                    Button::new("pmgr-del-cur-tag")
                                        .with_variant(BonTheme::outline_danger(cx))
                                        .small()
                                        .label(format!("{}  #{selected_pgrp}", SfSymbol::TRASH))
                                        .on_click(cx.listener(move |app, _, _, cx| {
                                            app.delete_tag_and_reset(&t_del, cx);
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
                                .disabled(filtered_proxies.is_empty())
                                .label("Assign to profiles")
                                .on_click(cx.listener(|app, _, window, cx| {
                                    app.assign_filtered_proxies_to_profiles(window, cx);
                                })),
                        )
                        .child(
                            Button::new("pmgr-check-all-top")
                                .with_variant(BonTheme::outline_blue(cx))
                                .small()
                                .disabled(filtered_proxies.is_empty())
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
                            app.delete_checked_saved_proxies(cx);
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
                    Animation::new(Duration::from_millis(160)).with_easing(ease_out_quint()),
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
                            div()
                                .w(px(18.))
                                .h(px(18.))
                                .flex_shrink_0()
                                .rounded_sm()
                                .cursor_pointer()
                                .flex()
                                .items_center()
                                .justify_center()
                                .bg(if all_filtered_checked || any_filtered_checked {
                                    BonTheme::accent()
                                } else {
                                    BonTheme::bg_panel()
                                })
                                .border_1()
                                .border_color(if all_filtered_checked || any_filtered_checked {
                                    BonTheme::accent()
                                } else {
                                    BonTheme::border()
                                })
                                .hover(|s| s.border_color(BonTheme::accent()))
                                .text_xs()
                                .font_bold()
                                .text_color(rgb(0xffffff))
                                .on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener(|app, _, _, cx| {
                                        app.toggle_all_filtered_proxies_checked(cx);
                                    }),
                                )
                                .child(proxy_hdr_mark)
                                .with_spring(
                                    "pmgr-hdr-chk-spring",
                                    SpringAnimation::new(BonTheme::snappy_spring())
                                        .to(all_filtered_checked || any_filtered_checked),
                                    |this, phase| {
                                        this.bg(phase.interpolate_clamped(
                                            BonTheme::bg_panel(),
                                            BonTheme::accent(),
                                        ))
                                        .border_color(
                                            phase.interpolate_clamped(
                                                BonTheme::border(),
                                                BonTheme::accent(),
                                            ),
                                        )
                                    },
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
                .child(
                    v_flex()
                        .id("proxies-table-rows")
                        .w_full()
                        .flex_1()
                        .min_h_0()
                        .overflow_y_scroll()
                        .children(filtered_proxies.is_empty().then(|| {
                            v_flex()
                                .w_full()
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
                        }))
                        .children(filtered_proxies.iter().enumerate().map(|(idx, sp)| {
                            let row_num = idx + 1;
                            let pid = sp.id.clone();
                            let pid_chk_toggle = sp.id.clone();
                            let pid_check = sp.id.clone();
                            let is_checked = app.checked_proxy_ids.contains(&sp.id);
                            let is_checking = app.checking_proxy_ids.contains(&sp.id);

                            let used_count = app
                                .profiles
                                .iter()
                                .filter(|p| {
                                    p.proxy.as_ref().is_some_and(|cfg| {
                                        cfg.protocol == sp.config.protocol
                                            && cfg.host == sp.config.host
                                            && cfg.port == sp.config.port
                                    })
                                })
                                .count();

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

                            let app_row_menu = cx.entity();
                            let pid_menu_copy = sp.config.to_editable_string();
                            let pid_menu_assign = sp.id.clone();
                            let pid_menu_del = sp.id.clone();

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
                                // Col 1: Checkbox
                                .child(
                                    div()
                                        .w(px(16.))
                                        .h(px(16.))
                                        .flex_shrink_0()
                                        .rounded(px(4.5))
                                        .cursor_pointer()
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .bg(if is_checked {
                                            BonTheme::accent()
                                        } else {
                                            BonTheme::bg_elevated()
                                        })
                                        .border_1()
                                        .border_color(if is_checked {
                                            BonTheme::accent()
                                        } else {
                                            BonTheme::border()
                                        })
                                        .hover(|s| s.border_color(BonTheme::accent()))
                                        .text_xs()
                                        .font_bold()
                                        .text_color(rgb(0xffffff))
                                        .on_mouse_down(
                                            MouseButton::Left,
                                            cx.listener(move |app, _, _, cx| {
                                                cx.stop_propagation();
                                                app.toggle_proxy_checked(&pid_chk_toggle, cx);
                                            }),
                                        )
                                        .child(if is_checked { SfSymbol::CHECKMARK } else { "" })
                                        .with_spring(
                                            SharedString::from(format!("pmgr-row-chk-spring-{pid}")),
                                            SpringAnimation::new(BonTheme::snappy_spring())
                                                .to(is_checked),
                                            |this, phase| {
                                                this.bg(phase.interpolate_clamped(
                                                    BonTheme::bg_elevated(),
                                                    BonTheme::accent(),
                                                ))
                                                .border_color(phase.interpolate_clamped(
                                                    BonTheme::border(),
                                                    BonTheme::accent(),
                                                ))
                                            },
                                        ),
                                )
                                // Col 2: #
                                .child(
                                    div()
                                        .w(px(28.))
                                        .flex_shrink_0()
                                        .truncate()
                                        .text_xs()
                                        .text_color(BonTheme::text_secondary())
                                        .child(format!("{row_num}")),
                                )
                                // Col 3: Name (Top: Proxy Name, Bottom: Flag + IP:Port + Country)
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
                                                .child(sp.name.clone()),
                                        )
                                        .child(
                                            h_flex()
                                                .w_full()
                                                .min_w_0()
                                                .overflow_hidden()
                                                .gap_1p5()
                                                .items_center()
                                                .child(div().flex_shrink_0().text_xs().child(flag))
                                                .child(
                                                    div()
                                                        .w_0()
                                                        .flex_1()
                                                        .min_w_0()
                                                        .truncate()
                                                        .text_xs()
                                                        .text_color(BonTheme::text_secondary())
                                                        .child(if geo_str != "-" && sp.resolved_geo.is_some() {
                                                            format!("{} • {}", sp.config.display_short(), geo_str)
                                                        } else {
                                                            sp.config.display_short()
                                                        }),
                                                ),
                                        ),
                                )
                                // Col 4: Tag
                                .child(
                                    div().w(px(80.)).flex_shrink_0().overflow_hidden().child(
                                        h_flex().w_full().min_w_0().overflow_hidden().child(
                                            div()
                                                .max_w_full()
                                                .truncate()
                                                .px_1p5()
                                                .py_0p5()
                                                .rounded_sm()
                                                .bg(BonTheme::accent_subtle())
                                                .text_xs()
                                                .text_color(BonTheme::accent())
                                                .child(format!("#{}", sp.group_tag)),
                                        ),
                                    ),
                                )
                                // Col 5: Protocol support (`HTTP` / `SOCKS5`)
                                .child(
                                    div()
                                        .w(px(108.))
                                        .flex_shrink_0()
                                        .truncate()
                                        .text_xs()
                                        .font_semibold()
                                        .text_color(BonTheme::text_primary())
                                        .child(sp.config.protocol.as_str().to_uppercase()),
                                )
                                // Col 6: Started at (`DD/MM/YYYY`)
                                .child(
                                    div()
                                        .w(px(84.))
                                        .flex_shrink_0()
                                        .truncate()
                                        .text_xs()
                                        .text_color(BonTheme::text_secondary())
                                        .child(sp.format_started_at()),
                                )
                                // Col 7: Expired at (`DD/MM/YYYY (Nd)` or `Expired`)
                                .child(
                                    div()
                                        .w(px(116.))
                                        .flex_shrink_0()
                                        .truncate()
                                        .text_xs()
                                        .font_semibold()
                                        .text_color(if sp.is_expired() {
                                            BonTheme::danger()
                                        } else if sp.is_expiring_soon() {
                                            BonTheme::warning()
                                        } else if sp.expired_at.is_some() {
                                            BonTheme::text_primary()
                                        } else {
                                            BonTheme::text_muted()
                                        })
                                        .child(sp.format_expired_at()),
                                )
                                // Col 8: Status Badge
                                .child(
                                    div().w(px(96.)).flex_shrink_0().overflow_hidden().child({
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
                                                    Animation::new(Duration::from_millis(1100))
                                                        .repeat()
                                                        .with_easing(pulsating_between(0.4, 1.0)),
                                                    |this, alpha| this.opacity(alpha),
                                                )
                                                .into_any_element()
                                        } else {
                                            badge.into_any_element()
                                        })
                                    }),
                                )
                                // Col 9: Profiles count
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
                                // Col 10: Row Actions (`[Check]` + `[⋯]`)
                                .child(
                                    h_flex()
                                        .w(px(92.))
                                        .flex_shrink_0()
                                        .justify_end()
                                        .items_center()
                                        .gap_1p5()
                                        .child(
                                            Button::new(SharedString::from(format!("p-chk-{pid}")))
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
                                                let assign_id = pid_menu_assign.clone();
                                                let app_a = app_row_menu.clone();
                                                let ext_id = pid_menu_del.clone();
                                                let app_ext = app_row_menu.clone();
                                                let clr_id = pid_menu_del.clone();
                                                let app_clr = app_row_menu.clone();
                                                let del_id = pid_menu_del.clone();
                                                let app_d = app_row_menu.clone();
                                                menu.item(
                                                    PopupMenuItem::new(format!(
                                                        "{}   Copy proxy",
                                                        SfSymbol::DOC_ON_DOC
                                                    ))
                                                    .on_click(
                                                        move |_, _, cx| {
                                                            let v = copy_val.clone();
                                                            app_c.update(cx, |app, cx| {
                                                                cx.write_to_clipboard(
                                                                    ClipboardItem::new_string(v),
                                                                );
                                                                app.banner_message = Some(
                                                                    "Copied proxy to clipboard"
                                                                        .to_string(),
                                                                );
                                                                cx.notify();
                                                            });
                                                        },
                                                    ),
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
                                                            app_ext.update(cx, |app, cx| {
                                                                app.extend_saved_proxy_days(
                                                                    &eid, 30, cx,
                                                                );
                                                            });
                                                        }),
                                                )
                                                .item(
                                                    PopupMenuItem::new(format!(
                                                        "{}   Clear expiration",
                                                        SfSymbol::CLOCK_ARROW_CIRCLEPATH
                                                    ))
                                                        .on_click(move |_, _, cx| {
                                                            let cid = clr_id.clone();
                                                            app_clr.update(cx, |app, cx| {
                                                                app.extend_saved_proxy_days(
                                                                    &cid, 0, cx,
                                                                );
                                                            });
                                                        }),
                                                )
                                                .separator()
                                                .item(
                                                    PopupMenuItem::new(format!(
                                                        "{}   Delete proxy",
                                                        SfSymbol::TRASH
                                                    ))
                                                        .on_click(move |_, _, cx| {
                                                            let did = del_id.clone();
                                                            app_d.update(cx, |app, cx| {
                                                                app.delete_saved_proxy(&did, cx);
                                                            });
                                                        }),
                                                )
                                            }),
                                        ),
                                )
                        })),
                )
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
                        .child(format!("Proxies: {}", filtered_proxies.len()))
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
    let cur = if app.batch_selected_group.trim().is_empty() {
        "General".to_string()
    } else {
        app.batch_selected_group.clone()
    };
    Button::new(id)
        .with_variant(BonTheme::row_action(cx))
        .small()
        .label(format!(
            "{}  {cur}  {}",
            SfSymbol::FOLDER_FILL,
            SfSymbol::CHEVRON_DOWN
        ))
        .dropdown_menu(move |mut menu, _, _| {
            for grp in &groups_list {
                let g_val = grp.clone();
                let app_pick = app_for_grp.clone();
                menu = menu.item(
                    PopupMenuItem::new(format!("{}   {g_val}", SfSymbol::FOLDER_FILL)).on_click(
                    move |_, _, cx| {
                        let g = g_val.clone();
                        app_pick.update(cx, |app, cx| {
                            app.batch_selected_group = g;
                            cx.notify();
                        });
                    },
                ));
            }
            menu
        })
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
        .child(
            Button::new(SharedString::from(format!("{prefix}-os-win")))
                .small()
                .with_variant(BonTheme::toggle_pill(cx, batch_os == PlatformType::Windows))
                .label(format!("{}  Windows 11", SfSymbol::PC))
                .on_click(cx.listener(|app, _, _, cx| {
                    app.batch_os = PlatformType::Windows;
                    cx.notify();
                })),
        )
        .child(
            Button::new(SharedString::from(format!("{prefix}-os-mac")))
                .small()
                .with_variant(BonTheme::toggle_pill(cx, batch_os == PlatformType::MacOS))
                .label(format!("{}  Mac OS", SfSymbol::APPLE_LOGO))
                .on_click(cx.listener(|app, _, _, cx| {
                    app.batch_os = PlatformType::MacOS;
                    cx.notify();
                })),
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
                                        .on_click(cx.listener(move |app, _, window, cx| {
                                            app.delete_group_and_reset(&g_del, window, cx);
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
                                .with_variant(BonTheme::row_action(cx))
                                .small()
                                .label(format!("Pick single proxy  {}", SfSymbol::CHEVRON_DOWN))
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
                        .child("3. Name is optional")
                        .child("Example:")
                        .child("http://192.168.1.1:3000:admin:admin")
                        .child("socks://192.168.1.1:3000")
                        .child("socks://192.168.1.1:3000:user:user")
                        .child("192.168.1.1:3000")
                        .child("http:192.168.1.1:3000:admin:admin:Vina Proxy"),
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
                                        .with_variant(BonTheme::row_action(cx))
                                        .small()
                                        .label(format!("#{cur_tag}  {}", SfSymbol::CHEVRON_DOWN))
                                        .dropdown_menu(move |mut menu, _, _| {
                                            for t in &tags_list {
                                                let t_val = t.clone();
                                                let app_pick = app_for_tag.clone();
                                                menu = menu.item(
                                                    PopupMenuItem::new(format!("#{t_val}"))
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
                                app.popup_modal = None;
                                cx.notify();
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
                                    app.popup_modal = None;
                                    cx.notify();
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
            let target_name = app
                .pending_remove_ext_id
                .as_ref()
                .and_then(|id| app.extensions.iter().find(|e| &e.id == id))
                .map(|e| e.name.clone())
                .unwrap_or_else(|| "this extension".to_string());
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
                                .bg(rgb(0xFEE2E2))
                                .flex()
                                .items_center()
                                .justify_center()
                                .text_sm()
                                .text_color(rgb(0xEF4444))
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
                                        .child("Remove the extension?"),
                                )
                                .child(
                                    div()
                                        .w_full()
                                        .min_w_0()
                                        .truncate()
                                        .text_xs()
                                        .text_color(BonTheme::text_secondary())
                                        .child(format!("Are you sure to remove {target_name}?")),
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
                                    app.pending_remove_ext_id = None;
                                    app.popup_modal = None;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("remext-confirm")
                                .danger()
                                .small()
                                .label("Yes, remove")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.confirm_remove_extension(cx);
                                })),
                        ),
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
                app.popup_modal = None;
                cx.notify();
            }),
        )
        .child(
            card.on_mouse_down(MouseButton::Left, |_, _, cx| {
                cx.stop_propagation();
            })
            .with_animation(
                modal_anim_id,
                Animation::new(Duration::from_millis(160)).with_easing(ease_out_quint()),
                |this, delta| this.opacity(delta).mt(px((1.0 - delta) * -10.0)),
            ),
        )
        .with_animation(
            backdrop_anim_id,
            Animation::new(Duration::from_millis(150)).with_easing(ease_out_quint()),
            |this, delta| this.opacity(delta),
        )
        .into_any_element()
}
