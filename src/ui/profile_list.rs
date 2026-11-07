use gpui_kit::component::{
    button::{Button, ButtonVariants as _},
    menu::{ContextMenuExt as _, DropdownMenu as _, PopupMenu, PopupMenuItem},
    *,
};
use gpui_kit::*;
use std::time::Duration;
use crate::models::{Profile, ProfileStatus};
use crate::ui::theme::{BonTheme, SfSymbol};
use crate::ui::{ActivePopupModal, BonLoginApp};

#[derive(Debug, Clone, Copy)]
pub struct ColumnVisibility {
    pub show_id: bool,
    pub show_name: bool,
    pub show_tags: bool,
    pub show_notes: bool,
    pub show_proxy: bool,
    pub show_updated: bool,
    pub show_status: bool,
}

impl Default for ColumnVisibility {
    fn default() -> Self {
        Self {
            show_id: true,
            show_name: true,
            show_tags: true,
            show_notes: true,
            show_proxy: true,
            show_updated: true,
            show_status: true,
        }
    }
}

pub fn render_profile_table(
    profiles: &[Profile],
    statuses: &std::collections::HashMap<String, ProfileStatus>,
    selected_profile_id: Option<&str>,
    checked_profile_ids: &std::collections::HashSet<String>,
    cols: ColumnVisibility,
    show_detail_drawer: bool,
    cx: &mut Context<BonLoginApp>,
) -> impl IntoElement {
    let all_checked =
        !profiles.is_empty() && profiles.iter().all(|p| checked_profile_ids.contains(&p.id));
    let any_checked = profiles.iter().any(|p| checked_profile_ids.contains(&p.id));
    let header_check_mark = if all_checked {
        SfSymbol::CHECKMARK
    } else if any_checked {
        SfSymbol::MINUS
    } else {
        ""
    };

    let selected_profile = selected_profile_id
        .and_then(|id| profiles.iter().find(|p| p.id == id))
        .cloned();

    h_flex()
        .w_full()
        .flex_1()
        .gap_4()
        .overflow_hidden()
        // Left: GenLogin 3.0 Profiles Table + Pagination Footer
        .child(
            v_flex()
                .flex_1()
                .min_w_0()
                .h_full()
                .rounded_xl()
                .bg(BonTheme::bg_panel())
                .border_1()
                .border_color(BonTheme::border())
                .overflow_hidden()
                // GenLogin Table Header (`[☐] | ID ↓ | Name ↓ | Tags | Note | Proxy | Updated at ↓ | Status | [⚙]`)
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
                        .text_color(BonTheme::text_secondary())
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
                                        .bg(if all_checked || any_checked {
                                            BonTheme::accent()
                                        } else {
                                            BonTheme::bg_panel()
                                        })
                                        .border_1()
                                        .border_color(if all_checked || any_checked {
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
                                                app.toggle_check_all_filtered(cx);
                                            }),
                                        )
                                        .child(header_check_mark)
                                        .with_spring(
                                            "prof-hdr-chk-spring",
                                            SpringAnimation::new(BonTheme::snappy_spring())
                                                .to(all_checked || any_checked),
                                            |this, phase| {
                                                this.bg(phase.interpolate_clamped(
                                                    BonTheme::bg_panel(),
                                                    BonTheme::accent(),
                                                ))
                                                .border_color(phase.interpolate_clamped(
                                                    BonTheme::border(),
                                                    BonTheme::accent(),
                                                ))
                                            },
                                        ),
                                )
                                .children(cols.show_id.then(|| {
                                    h_flex()
                                        .w(px(68.))
                                        .flex_shrink_0()
                                        .justify_between()
                                        .items_center()
                                        .pr_1()
                                        .child("ID")
                                        .child(
                                            div()
                                                .text_color(BonTheme::accent())
                                                .child(SfSymbol::ARROW_DOWN),
                                        )
                                }))
                                .children(cols.show_name.then(|| {
                                    h_flex()
                                        .w(px(128.))
                                        .flex_shrink_0()
                                        .justify_between()
                                        .items_center()
                                        .pr_1()
                                        .child("Name")
                                        .child(
                                            div()
                                                .text_color(BonTheme::accent())
                                                .child(SfSymbol::ARROW_DOWN),
                                        )
                                }))
                                .children(cols.show_tags.then(|| {
                                    div().w(px(76.)).flex_shrink_0().child("Tags")
                                }))
                                .children(cols.show_notes.then(|| {
                                    div().w(px(78.)).flex_shrink_0().child("Note")
                                }))
                                .children(cols.show_proxy.then(|| {
                                    div().w(px(96.)).flex_shrink_0().child("Proxy")
                                }))
                                .children(cols.show_updated.then(|| {
                                    h_flex()
                                        .w(px(84.))
                                        .flex_shrink_0()
                                        .justify_between()
                                        .items_center()
                                        .pr_1()
                                        .child("Updated")
                                        .child(
                                            div()
                                                .text_color(BonTheme::accent())
                                                .child(SfSymbol::ARROW_DOWN),
                                        )
                                }))
                                .children(cols.show_status.then(|| {
                                    div().w(px(64.)).flex_shrink_0().child("Status")
                                }))
                                .child(
                                    h_flex()
                                        .flex_1()
                                        .flex_shrink_0()
                                        .justify_end()
                                        .items_center()
                                        .child(
                                            Button::new("btn-col-settings-gear")
                                                .ghost()
                                                .small()
                                                .label(SfSymbol::GEARSHAPE_FILL)
                                                .on_click(cx.listener(|app, _, _, cx| {
                                                    app.popup_modal =
                                                        Some(ActivePopupModal::ColumnSettings);
                                                    cx.notify();
                                                })),
                                        ),
                                ),
                )
                // Scrollable Profile Rows Body
                .child(
                    v_flex()
                        .id("profiles-table-rows")
                        .w_full()
                        .flex_1()
                        .min_h_0()
                        .overflow_y_scroll()
                        // Empty State
                        .children(profiles.is_empty().then(|| {
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
                                        .child("No profiles found"),
                                )
                                .child(
                                    div()
                                        .text_xs()
                                        .text_color(BonTheme::text_secondary())
                                        .child(
                                            "Click '+ Create Profile' on the left menu or '⚡ Quick add' in the top right.",
                                        ),
                                )
                        }))
                        // Profile Rows
                        .children(profiles.iter().map(|profile| {
                            let status = statuses
                                .get(&profile.id)
                                .cloned()
                                .unwrap_or(ProfileStatus::Stopped);
                            let is_selected = selected_profile_id == Some(profile.id.as_str());
                            let is_checked = checked_profile_ids.contains(&profile.id);
                            render_profile_row(
                                profile,
                                status,
                                is_selected,
                                is_checked,
                                cols,
                                cx,
                            )
                        })),
                )
                // GenLogin Table Footer (`Profiles: N   < [1] >   25 / page`)
                .child(
                    h_flex()
                        .w_full()
                        .px_4()
                        .py_2p5()
                        .border_t_1()
                        .border_color(BonTheme::border())
                        .justify_end()
                        .items_center()
                        .gap_3()
                        .text_xs()
                        .text_color(BonTheme::text_secondary())
                        .child(format!("Profiles: {}", profiles.len())),
                ),
        )
        // Right: GenLogin Collapsible `Detail` Drawer (`docs/genlogin-3.0/assets/menu-bar_profile_cloud-vs-local_01.png`)
        .children(
            (show_detail_drawer && selected_profile.is_some()).then(|| {
                let prof = selected_profile.unwrap();
                let pid_refresh = prof.id.clone();
                let pid_edit = prof.id.clone();
                let proxy_str = match &prof.proxy {
                    Some(p) => format!("{} ({})", p.display_short(), p.protocol.as_str().to_uppercase()),
                    None => "Without Proxy".to_string(),
                };
                let tz_str = prof
                    .custom_timezone
                    .clone()
                    .or_else(|| prof.resolved_geo.as_ref().map(|g| g.timezone.clone()))
                    .unwrap_or_else(|| "Auto (Based on IP)".to_string());
                let content_anim_id =
                    SharedString::from(format!("detail-content-{}-{}", prof.id, prof.seed));
                v_flex()
                    .w(px(285.))
                    .h_full()
                    .flex_shrink_0()
                    .p_4()
                    .gap_2()
                    .rounded_xl()
                    .bg(BonTheme::bg_panel())
                    .border_1()
                    .border_color(BonTheme::border())
                    .overflow_hidden()
                    .child(
                        h_flex()
                            .w_full()
                            .pb_2p5()
                            .border_b_1()
                            .border_color(BonTheme::border())
                            .justify_between()
                            .items_center()
                            .child(
                                div()
                                    .text_base()
                                    .font_bold()
                                    .text_color(BonTheme::text_primary())
                                    .child("Detail"),
                            )
                            .child(
                                Button::new("close-detail-drawer")
                                    .ghost()
                                    .small()
                                    .label(SfSymbol::XMARK)
                                    .on_click(cx.listener(|app, _, _, cx| {
                                        app.show_detail_drawer = false;
                                        cx.notify();
                                    })),
                            ),
                    )
                    // Row 1: New fingerprint | ↻ Refresh
                    .child(
                        h_flex()
                            .w_full()
                            .py_1p5()
                            .border_b_1()
                            .border_color(BonTheme::border())
                            .justify_between()
                            .items_center()
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(BonTheme::text_secondary())
                                    .child("New fingerprint"),
                            )
                            .child(
                                Button::new("drawer-refresh-fp")
                                    .ghost()
                                    .small()
                                    .label(format!("{}  Refresh", SfSymbol::ARROW_CLOCKWISE))
                                    .on_click(cx.listener(move |app, _, window, cx| {
                                        app.randomize_profile_seed(&pid_refresh, window, cx);
                                    })),
                            ),
                    )
                    .child(
                        v_flex()
                            .id("detail-drawer-body")
                            .w_full()
                            .flex_1()
                            .min_h_0()
                            .gap_2()
                            .overflow_y_scroll()
                            .child(drawer_row("Profile name", prof.name.clone()))
                            .child(drawer_row(
                                "Agent session",
                                match statuses.get(&prof.id) {
                                    Some(ProfileStatus::Running(info)) => {
                                        format!("bon_{} (:{} LIVE)", prof.short_id(), info.cdp_port)
                                    }
                                    _ => format!("bon_{}", prof.short_id()),
                                },
                            ))
                            .child(drawer_row("Browser", prof.brand.as_cli_str().to_string()))
                            .child(drawer_row(
                                "Browser version",
                                prof.brand.version_for_seed(prof.seed).to_string(),
                            ))
                            .child(drawer_row(
                                "OS",
                                format!(
                                    "{} ({})",
                                    prof.os_platform.label(),
                                    prof.os_platform.os_version_for_seed(prof.seed)
                                ),
                            ))
                            .child(drawer_row("Proxy", proxy_str))
                            .child(drawer_row("Timezone", tz_str))
                            .child(drawer_row(
                                "Web RTC",
                                if prof.proxy.is_some() {
                                    "Forward".to_string()
                                } else {
                                    "Real".to_string()
                                },
                            ))
                            .child(drawer_row(
                                "Screen Resolution",
                                prof.window_size.replace(',', "×"),
                            ))
                            .child(drawer_row(
                                "CPU / RAM",
                                format!(
                                    "{} Cores / {} GB",
                                    prof.hardware_concurrency,
                                    Profile::device_memory_for_seed(prof.seed)
                                ),
                            ))
                            .child(drawer_row(
                                "Canvas",
                                if prof.spoof_canvas { "Noise" } else { "Off" }.to_string(),
                            ))
                            .child(drawer_row(
                                "WebGL",
                                prof.os_platform
                                    .webgl_for_seed(prof.seed, prof.gpu_spoofing)
                                    .1
                                    .to_string(),
                            ))
                            .child(
                                div().pt_2().child(
                                    Button::new("drawer-open-edit")
                                        .with_variant(BonTheme::outline_blue(cx))
                                        .small()
                                        .label(format!("{}  Edit Full Settings", SfSymbol::SLIDER_HORIZONTAL_3))
                                        .on_click(cx.listener(move |app, _, window, cx| {
                                            app.open_edit_view(&pid_edit, window, cx);
                                        })),
                                ),
                            )
                            .with_animation(
                                content_anim_id,
                                Animation::new(Duration::from_millis(120))
                                    .with_easing(ease_out_quint()),
                                |this, delta| this.opacity(delta),
                            ),
                    )
                    .with_animation(
                        "detail-drawer-panel",
                        Animation::new(Duration::from_millis(150)).with_easing(ease_out_quint()),
                        |this, delta| this.opacity(delta),
                    )
            }),
        )
}

fn drawer_row(label: &'static str, value: String) -> Div {
    h_flex()
        .w_full()
        .min_w_0()
        .px_1()
        .py_1p5()
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

fn build_profile_popup_menu(
    menu: PopupMenu,
    app_entity: Entity<BonLoginApp>,
    profile_id: String,
    is_busy: bool,
) -> PopupMenu {
    let app_edit = app_entity.clone();
    let pid_edit = profile_id.clone();
    // Only real implemented actions in row popup/context menu
    let app_cookies = app_entity.clone();
    let pid_cookies = profile_id.clone();
    let app_clone = app_entity.clone();
    let pid_clone = profile_id.clone();
    let app_proxy = app_entity.clone();
    let pid_proxy = profile_id.clone();
    let app_agent = app_entity.clone();
    let pid_agent = profile_id.clone();
    let app_del = app_entity;
    let pid_del = profile_id;

    menu.min_w(px(175.))
        .item(
            PopupMenuItem::new(format!("{}   Edit", SfSymbol::PENCIL))
                .disabled(is_busy)
                .on_click(move |_, window, cx| {
                    app_edit.update(cx, |app, cx| {
                        app.open_edit_view(&pid_edit, window, cx);
                    });
                }),
        )
        // (Only real actions shown)
        .item(
            PopupMenuItem::new(format!("{}   Copy Agent CLI", SfSymbol::TERMINAL)).on_click(
                move |_, _, cx| {
                    app_agent.update(cx, |app, cx| {
                        app.copy_agent_browser_cli(&pid_agent, cx);
                    });
                },
            ),
        )
        .item(
            PopupMenuItem::new(format!("{}   Export cookies", SfSymbol::ARROW_DOWN_DOC)).on_click(
                move |_, _, cx| {
                    app_cookies.update(cx, |app, cx| {
                        app.export_profile_cookies_json(&pid_cookies, cx);
                    });
                },
            ),
        )
        .item(
            PopupMenuItem::new(format!("{}   Clone", SfSymbol::PLUS_SQUARE_ON_SQUARE)).on_click(
                move |_, window, cx| {
                    app_clone.update(cx, |app, cx| {
                        app.clone_profile(&pid_clone, window, cx);
                    });
                },
            ),
        )
        .item(
            PopupMenuItem::new(format!("{}   Copy proxy", SfSymbol::DOC_ON_DOC)).on_click(
                move |_, _, cx| {
                    app_proxy.update(cx, |app, cx| {
                        app.copy_single_profile_proxy(&pid_proxy, cx);
                    });
                },
            ),
        )
        .separator()
        .item(
            PopupMenuItem::new(format!("{}   Delete", SfSymbol::TRASH))
                .disabled(is_busy)
                .on_click(move |_, window, cx| {
                    app_del.update(cx, |app, cx| {
                        app.delete_profile(&pid_del, window, cx);
                    });
                }),
        )
}

fn render_profile_row(
    profile: &Profile,
    status: ProfileStatus,
    is_selected: bool,
    is_checked: bool,
    cols: ColumnVisibility,
    cx: &mut Context<BonLoginApp>,
) -> AnyElement {
    let app_entity = cx.entity().clone();
    let profile_id = profile.id.clone();
    let select_id = profile.id.clone();
    let check_id = profile.id.clone();
    let proxy_label = match (&profile.proxy, &profile.resolved_geo) {
        (Some(_), Some(g)) => format!("{} {} ({})", SfSymbol::GLOBE, g.compact_ip(), g.country_code),
        (Some(p), None) => format!("{} {}", SfSymbol::GLOBE, p.display_short()),
        (None, _) => "Local IP".to_string(),
    };

    let is_running = matches!(status, ProfileStatus::Running(_));
    let is_starting = matches!(status, ProfileStatus::Starting(_));

    let (badge_bg, badge_fg, state_title) = match &status {
        ProfileStatus::Stopped => (
            BonTheme::success_bg(),
            BonTheme::success(),
            "Ready".to_string(),
        ),
        ProfileStatus::Starting(_) => (
            BonTheme::warning_bg(),
            BonTheme::warning(),
            "Starting".to_string(),
        ),
        ProfileStatus::Running(_) => (
            BonTheme::info_bg(),
            BonTheme::info(),
            "Running".to_string(),
        ),
        ProfileStatus::Error(_) => (
            BonTheme::danger_bg(),
            BonTheme::danger(),
            "Error".to_string(),
        ),
    };

    let note_text = profile
        .short_note(18)
        .unwrap_or_else(|| "Enter note".to_string());
    let has_note = profile.short_note(18).is_some();
    let updated_label = profile.format_last_launched();
    let numeric_id = profile.short_id();

    let is_busy = is_running || is_starting;
    let app_for_dots = app_entity.clone();
    let pid_for_dots = profile_id.clone();
    let app_for_ctx = app_entity;
    let pid_for_ctx = profile_id.clone();

    div()
        .id(SharedString::from(format!("prof-row-{profile_id}")))
        .w_full()
        .border_l_2()
        .border_b_1()
        .border_color(if is_selected || is_checked {
            BonTheme::accent()
        } else {
            BonTheme::border()
        })
        .bg(if is_selected || is_checked {
            BonTheme::bg_selected()
        } else {
            BonTheme::bg_panel()
        })
        .hover(|s| {
            if is_selected || is_checked {
                s.bg(rgba(0x0a84ff5c)).border_color(BonTheme::accent())
            } else {
                s.bg(BonTheme::bg_hover())
            }
        })
        .child(
            h_flex()
                .w_full()
                .px_3()
                .py_2p5()
                .gap_2()
                .items_center()
                .cursor_pointer()
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |app, _, window, cx| {
                        app.show_detail_drawer = true;
                        app.select_profile(&select_id, window, cx);
                    }),
                )
                // Col 0: Checkbox
                .child(
                    div()
                        .w(px(16.))
                        .h(px(16.))
                        .flex_shrink_0()
                        .rounded(px(4.5))
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
                                app.toggle_check_profile(&check_id, cx);
                            }),
                        )
                        .child(if is_checked { SfSymbol::CHECKMARK } else { "" })
                        .with_spring(
                            SharedString::from(format!("prof-chk-spring-{profile_id}")),
                            SpringAnimation::new(BonTheme::snappy_spring()).to(is_checked),
                            |this, phase| {
                                this.bg(phase.interpolate_clamped(
                                    BonTheme::bg_elevated(),
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
                // Col 1: ID (`3866478`)
                .children(cols.show_id.then(|| {
                    div()
                        .w(px(68.))
                        .flex_shrink_0()
                        .truncate()
                        .text_xs()
                        .text_color(BonTheme::text_primary())
                        .child(numeric_id)
                }))
                // Col 2: Name (`🔵 wheel-die`)
                .children(cols.show_name.then(|| {
                    h_flex()
                        .w(px(128.))
                        .flex_shrink_0()
                        .gap_1p5()
                        .items_center()
                        .overflow_hidden()
                        .child(
                            div()
                                .w(px(16.))
                                .h(px(16.))
                                .flex_shrink_0()
                                .rounded_full()
                                .border_2()
                                .border_color(rgb(0x38bdf8))
                                .bg(rgba(0x0284c733)),
                        )
                        .child(
                            div()
                                .w_0()
                                .flex_1()
                                .min_w_0()
                                .truncate()
                                .text_xs()
                                .font_semibold()
                                .text_color(BonTheme::text_primary())
                                .child(profile.name.clone()),
                        )
                }))
                // Col 3: Tags (`group_tag` + `+`)
                .children(cols.show_tags.then(|| {
                    h_flex()
                        .w(px(76.))
                        .flex_shrink_0()
                        .gap_1()
                        .items_center()
                        .overflow_hidden()
                        .child(
                            div()
                                .max_w_full()
                                .truncate()
                                .px_1p5()
                                .py_0p5()
                                .rounded_sm()
                                .bg(BonTheme::bg_elevated())
                                .border_1()
                                .border_color(BonTheme::border())
                                .text_xs()
                                .text_color(BonTheme::text_secondary())
                                .child(profile.group_tag.clone()),
                        )
                }))
                // Col 4: Note (`Enter note`)
                .children(cols.show_notes.then(|| {
                    let pid_note = profile_id.clone();
                    div()
                        .w(px(78.))
                        .flex_shrink_0()
                        .truncate()
                        .text_xs()
                        .text_color(if has_note {
                            BonTheme::text_primary()
                        } else {
                            BonTheme::text_muted()
                        })
                        .hover(|s| s.text_color(BonTheme::accent()))
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |app, _, window, cx| {
                                cx.stop_propagation();
                                app.open_edit_view(&pid_note, window, cx);
                            }),
                        )
                        .child(note_text)
                }))
                // Col 5: Proxy (`Local IP` or `🌐 ip:port`)
                .children(cols.show_proxy.then(|| {
                    let pid_proxy = profile_id.clone();
                    let has_proxy = profile.proxy.is_some();
                    div()
                        .w(px(96.))
                        .flex_shrink_0()
                        .truncate()
                        .text_xs()
                        .text_color(if profile.resolved_geo.is_some() {
                            BonTheme::success()
                        } else if has_proxy {
                            BonTheme::text_primary()
                        } else {
                            BonTheme::text_secondary()
                        })
                        .hover(|s| s.text_color(BonTheme::accent()))
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |app, _, window, cx| {
                                cx.stop_propagation();
                                if has_proxy {
                                    app.check_profile_proxy(&pid_proxy, cx);
                                } else {
                                    app.open_edit_view(&pid_proxy, window, cx);
                                }
                            }),
                        )
                        .child(proxy_label)
                }))
                // Col 6: Updated (`17 hours ago`)
                .children(cols.show_updated.then(|| {
                    div()
                        .w(px(84.))
                        .flex_shrink_0()
                        .truncate()
                        .text_xs()
                        .text_color(BonTheme::text_secondary())
                        .child(updated_label)
                }))
                // Col 7: Status (`Ready` green pill)
                .children(cols.show_status.then(|| {
                    let badge = h_flex()
                        .px_2()
                        .py_0p5()
                        .gap_1()
                        .items_center()
                        .rounded_full()
                        .bg(badge_bg)
                        .text_xs()
                        .font_semibold()
                        .text_color(badge_fg)
                        .child(
                            div()
                                .w(px(5.5))
                                .h(px(5.5))
                                .rounded_full()
                                .bg(badge_fg),
                        )
                        .child(state_title);
                    div().w(px(64.)).flex_shrink_0().child(
                        h_flex().child(if is_starting || is_running {
                            badge
                                .with_animation(
                                    SharedString::from(format!("prof-status-pulse-{profile_id}")),
                                    Animation::new(Duration::from_millis(1400))
                                        .repeat()
                                        .with_easing(pulsating_between(0.48, 1.0)),
                                    |this, alpha| this.opacity(alpha),
                                )
                                .into_any_element()
                        } else {
                            badge.into_any_element()
                        }),
                    )
                }))
                // Rightmost Action Column: ONLY `[Start]` + `[⋯]` (100% GenLogin 3.0 layout!)
                .child(
                    h_flex()
                        .flex_1()
                        .flex_shrink_0()
                        .justify_end()
                        .items_center()
                        .gap_1p5()
                        .child(if is_running {
                            let pid_stop = profile_id.clone();
                            Button::new(SharedString::from(format!("row-stop-{profile_id}")))
                                .danger()
                                .small()
                                .label("Stop")
                                .on_click(cx.listener(move |app, _, _, cx| {
                                    app.stop_profile(&pid_stop, cx);
                                }))
                        } else {
                            let pid_launch = profile_id.clone();
                            Button::new(SharedString::from(format!("row-launch-{profile_id}")))
                                .with_variant(BonTheme::launch_cta(cx))
                                .small()
                                .disabled(is_starting)
                                .label(if is_starting { "Wait..." } else { "Start" })
                                .on_click(cx.listener(move |app, _, window, cx| {
                                    app.select_profile(&pid_launch, window, cx);
                                    app.launch_profile(&pid_launch, cx);
                                }))
                        })
                        .child(
                            Button::new(SharedString::from(format!("row-dots-{profile_id}")))
                                .ghost()
                                .small()
                                .label(SfSymbol::ELLIPSIS)
                                .dropdown_menu_with_anchor(
                                    Anchor::TopRight,
                                    move |menu, _window, _cx| {
                                        build_profile_popup_menu(
                                            menu,
                                            app_for_dots.clone(),
                                            pid_for_dots.clone(),
                                            is_busy,
                                        )
                                    },
                                ),
                        ),
                ),
        )
        .context_menu(move |menu, _window, _cx| {
            build_profile_popup_menu(
                menu,
                app_for_ctx.clone(),
                pid_for_ctx.clone(),
                is_busy,
            )
        })
        .into_any_element()
}
