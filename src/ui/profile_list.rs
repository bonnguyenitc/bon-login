use gpui_kit::component::{
    button::{Button, ButtonVariants as _},
    menu::{ContextMenuExt as _, DropdownMenu as _, PopupMenu, PopupMenuItem},
    *,
};
use gpui_kit::*;
use std::time::Duration;
use crate::models::{Profile, ProfileStatus};
use crate::ui::profile_modal::detail_summary_row as drawer_row;
use crate::ui::theme::{BonTheme, SfSymbol};
use crate::ui::{ActivePopupModal, BonLoginApp, PendingDeleteAction};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileSortColumn {
    Id,
    Name,
    Tags,
    Notes,
    Proxy,
    Updated,
    Status,
}
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
    sort_col: Option<ProfileSortColumn>,
    sort_asc: bool,
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
                                    sortable_col_header(
                                        "ID",
                                        68.,
                                        ProfileSortColumn::Id,
                                        sort_col,
                                        sort_asc,
                                        cx,
                                    )
                                }))
                                .children(cols.show_name.then(|| {
                                    sortable_col_header(
                                        "Name",
                                        128.,
                                        ProfileSortColumn::Name,
                                        sort_col,
                                        sort_asc,
                                        cx,
                                    )
                                }))
                                .children(cols.show_tags.then(|| {
                                    sortable_col_header(
                                        "Tags",
                                        76.,
                                        ProfileSortColumn::Tags,
                                        sort_col,
                                        sort_asc,
                                        cx,
                                    )
                                }))
                                .children(cols.show_notes.then(|| {
                                    sortable_col_header(
                                        "Note",
                                        78.,
                                        ProfileSortColumn::Notes,
                                        sort_col,
                                        sort_asc,
                                        cx,
                                    )
                                }))
                                .children(cols.show_proxy.then(|| {
                                    sortable_col_header(
                                        "Proxy",
                                        96.,
                                        ProfileSortColumn::Proxy,
                                        sort_col,
                                        sort_asc,
                                        cx,
                                    )
                                }))
                                .children(cols.show_updated.then(|| {
                                    sortable_col_header(
                                        "Updated",
                                        84.,
                                        ProfileSortColumn::Updated,
                                        sort_col,
                                        sort_asc,
                                        cx,
                                    )
                                }))
                                .children(cols.show_status.then(|| {
                                    sortable_col_header(
                                        "Status",
                                        64.,
                                        ProfileSortColumn::Status,
                                        sort_col,
                                        sort_asc,
                                        cx,
                                    )
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
                let content_anim_id = SharedString::from(format!("detail-seed-{}", prof.seed));
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
                    .child({
                        let pid_totp = prof.id.clone();
                        let pid_meta = prof.id.clone();
                        let totp_opt = prof.current_totp();
                        let tags_str = if prof.tags.is_empty() {
                            "None".to_string()
                        } else {
                            prof.tags.join(", ")
                        };
                        v_flex()
                            .id("detail-drawer-body")
                            .w_full()
                            .flex_1()
                            .min_h_0()
                            .gap_2()
                            .overflow_y_scroll()
                            .child(drawer_row("Profile name", prof.name.clone()))
                            .child(drawer_row("Tags", tags_str))
                            .child({
                                let pid_bm_edit = prof.id.clone();
                                let pid_bm_click = prof.id.clone();
                                let bms = crate::launcher::read_profile_bookmarks(&prof);
                                v_flex()
                                    .w_full()
                                    .py_1()
                                    .gap_1p5()
                                    .border_b_1()
                                    .border_color(BonTheme::border())
                                    .child(
                                        h_flex()
                                            .w_full()
                                            .justify_between()
                                            .items_center()
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .text_color(BonTheme::text_secondary())
                                                    .child(format!("Bookmarks ({})", bms.len())),
                                            )
                                            .child(
                                                Button::new("drawer-quick-add-bm")
                                                    .with_variant(BonTheme::outline_blue(cx))
                                                    .xsmall()
                                                    .label("+ Add / Edit")
                                                    .on_click(cx.listener(move |app, _, window, cx| {
                                                        app.open_quick_meta_modal(
                                                            Some(pid_bm_edit.clone()),
                                                            window,
                                                            cx,
                                                        );
                                                    })),
                                            ),
                                    )
                                    .child(if bms.is_empty() {
                                        div()
                                            .text_xs()
                                            .text_color(BonTheme::text_muted())
                                            .child("No bookmarks — click '+ Add / Edit'")
                                            .into_any_element()
                                    } else {
                                        h_flex()
                                            .w_full()
                                            .gap_1()
                                            .flex_wrap()
                                            .children(bms.into_iter().enumerate().map(|(i, (bm_name, bm_url))| {
                                                let pid_c = pid_bm_click.clone();
                                                let n_c = bm_name.clone();
                                                let u_c = bm_url.clone();
                                                Button::new(SharedString::from(format!("drawer-bm-chip-{i}")))
                                                    .with_variant(BonTheme::row_action(cx))
                                                    .xsmall()
                                                    .label(format!("🔖 {bm_name}"))
                                                    .on_click(cx.listener(move |app, _, _, cx| {
                                                        app.open_or_copy_bookmark(&pid_c, &n_c, &u_c, cx);
                                                    }))
                                            }))
                                            .into_any_element()
                                    })
                            })
                            .children(totp_opt.map(|(code, rem)| {
                                h_flex()
                                    .w_full()
                                    .py_1()
                                    .border_b_1()
                                    .border_color(BonTheme::border())
                                    .justify_between()
                                    .items_center()
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(BonTheme::text_secondary())
                                            .child("2FA TOTP"),
                                    )
                                    .child(
                                        Button::new("drawer-copy-totp")
                                            .with_variant(BonTheme::outline_blue(cx))
                                            .xsmall()
                                            .label(format!(
                                                "🔐 {} {} ({rem}s)",
                                                &code[..3],
                                                &code[3..]
                                            ))
                                            .on_click(cx.listener(move |app, _, _, cx| {
                                                app.copy_profile_totp(&pid_totp, cx);
                                            })),
                                    )
                            }))
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
                            .child({
                                let pid_clean = prof.id.clone();
                                let pid_rot = prof.id.clone();
                                let pid_type = prof.id.clone();
                                let pid_shot = prof.id.clone();
                                let is_prof_running =
                                    matches!(statuses.get(&prof.id), Some(ProfileStatus::Running(_)));
                                let has_proxy_rot = prof
                                    .proxy
                                    .as_ref()
                                    .and_then(|p| p.change_ip_url.as_ref())
                                    .is_some();
                                h_flex()
                                    .pt_2()
                                    .gap_1p5()
                                    .flex_wrap()
                                    .child(
                                        Button::new("drawer-open-meta")
                                            .with_variant(BonTheme::row_action(cx))
                                            .small()
                                            .label("🔖 Bookmarks / Tags / 2FA")
                                            .on_click(cx.listener(move |app, _, window, cx| {
                                                app.open_quick_meta_modal(
                                                    Some(pid_meta.clone()),
                                                    window,
                                                    cx,
                                                );
                                            })),
                                    )
                                    .child(
                                        Button::new("drawer-clean-cache")
                                            .with_variant(BonTheme::row_action(cx))
                                            .small()
                                            .disabled(is_prof_running)
                                            .label("🧹 Clean Cache")
                                            .on_click(cx.listener(move |app, _, _, cx| {
                                                app.clean_single_profile_cache(&pid_clean, cx);
                                            })),
                                    )
                                    .children(has_proxy_rot.then(|| {
                                        Button::new("drawer-rotate-proxy")
                                            .with_variant(BonTheme::row_action(cx))
                                            .small()
                                            .label("🔄 Rotate IP")
                                            .on_click(cx.listener(move |app, _, _, cx| {
                                                app.rotate_profile_proxy_ip(&pid_rot, cx);
                                            }))
                                    }))
                                    .children(is_prof_running.then(|| {
                                        Button::new("drawer-human-type")
                                            .with_variant(BonTheme::outline_blue(cx))
                                            .small()
                                            .label("⌨️ Human Type")
                                            .on_click(cx.listener(move |app, _, _, cx| {
                                                app.type_clipboard_as_human(&pid_type, cx);
                                            }))
                                    }))
                                    .children(is_prof_running.then(|| {
                                        Button::new("drawer-screenshot")
                                            .with_variant(BonTheme::outline_blue(cx))
                                            .small()
                                            .label("📸 Screenshot")
                                            .on_click(cx.listener(move |app, _, _, cx| {
                                                app.capture_profile_screenshot(&pid_shot, cx);
                                            }))
                                    }))
                                    .child(
                                        Button::new("drawer-open-edit")
                                            .with_variant(BonTheme::outline_blue(cx))
                                            .small()
                                            .label(format!(
                                                "{}  Edit Full Settings",
                                                SfSymbol::SLIDER_HORIZONTAL_3
                                            ))
                                            .on_click(cx.listener(move |app, _, window, cx| {
                                                app.open_edit_view(&pid_edit, window, cx);
                                            })),
                                    )
                            })
                            .with_animation(
                                content_anim_id,
                                BonTheme::ui_enter_anim(),
                                |this, delta| this.opacity(delta),
                            )
                    })
                    .with_animation(
                        "detail-drawer-panel",
                        BonTheme::ui_enter_anim(),
                        |this, delta| this.opacity(delta),
                    )
            }),
        )
}

fn sortable_col_header(
    label: &'static str,
    width: f32,
    col: ProfileSortColumn,
    active_col: Option<ProfileSortColumn>,
    sort_asc: bool,
    cx: &mut Context<BonLoginApp>,
) -> Div {
    let is_active = active_col == Some(col);
    let arrow = if is_active {
        if sort_asc {
            SfSymbol::ARROW_UP
        } else {
            SfSymbol::ARROW_DOWN
        }
    } else {
        SfSymbol::ARROW_DOWN
    };
    h_flex()
        .w(px(width))
        .flex_shrink_0()
        .justify_between()
        .items_center()
        .pr_1()
        .cursor_pointer()
        .text_color(if is_active {
            BonTheme::text_primary()
        } else {
            BonTheme::text_secondary()
        })
        .hover(|s| s.text_color(BonTheme::text_primary()))
        .on_mouse_down(
            MouseButton::Left,
            cx.listener(move |app, _, _, cx| {
                app.toggle_profile_sort(col, cx);
            }),
        )
        .child(label)
        .child(
            div()
                .text_color(if is_active {
                    BonTheme::accent()
                } else {
                    BonTheme::text_muted()
                })
                .child(arrow),
        )
}

fn build_profile_popup_menu(
    menu: PopupMenu,
    app_entity: Entity<BonLoginApp>,
    profile_id: String,
    has_totp: bool,
    has_rotate_url: bool,
    is_running: bool,
    is_busy: bool,
) -> PopupMenu {
    let app_edit = app_entity.clone();
    let pid_edit = profile_id.clone();
    let app_meta = app_entity.clone();
    let pid_meta = profile_id.clone();
    let app_totp = app_entity.clone();
    let pid_totp = profile_id.clone();
    let app_type = app_entity.clone();
    let pid_type = profile_id.clone();
    let app_shot = app_entity.clone();
    let pid_shot = profile_id.clone();
    let app_rot = app_entity.clone();
    let pid_rot = profile_id.clone();
    let app_robot = app_entity.clone();
    let pid_robot = profile_id.clone();
    let app_import_cookies = app_entity.clone();
    let pid_import_cookies = profile_id.clone();
    let app_cookies = app_entity.clone();
    let pid_cookies = profile_id.clone();
    let app_zip = app_entity.clone();
    let pid_zip = profile_id.clone();
    let app_clean = app_entity.clone();
    let pid_clean = profile_id.clone();
    let app_clone = app_entity.clone();
    let pid_clone = profile_id.clone();
    let app_proxy = app_entity.clone();
    let pid_proxy = profile_id.clone();
    let app_agent = app_entity.clone();
    let pid_agent = profile_id.clone();
    let app_del = app_entity;
    let pid_del = profile_id;
    let mut menu = menu
        .min_w(px(195.))
        .item(
            PopupMenuItem::new(format!("{}   Edit", SfSymbol::PENCIL))
                .disabled(is_busy)
                .on_click(move |_, window, cx| {
                    app_edit.update(cx, |app, cx| {
                        app.open_edit_view(&pid_edit, window, cx);
                    });
                }),
        )
        .item(
            PopupMenuItem::new("🔖   Bookmarks, Tags & 2FA").on_click(move |_, window, cx| {
                let pid = pid_meta.clone();
                app_meta.update(cx, |app, cx| {
                    app.open_quick_meta_modal(Some(pid), window, cx);
                });
            }),
        );
    if has_totp {
        menu = menu.item(
            PopupMenuItem::new("🔐   Copy 2FA Code").on_click(move |_, _, cx| {
                app_totp.update(cx, |app, cx| {
                    app.copy_profile_totp(&pid_totp, cx);
                });
            }),
        );
    }
    menu = menu
        .item(
            PopupMenuItem::new("⌨️   Human-Type Clipboard")
                .disabled(!is_running)
                .on_click(move |_, _, cx| {
                    app_type.update(cx, |app, cx| {
                        app.type_clipboard_as_human(&pid_type, cx);
                    });
                }),
        )
        .item(
            PopupMenuItem::new("📸   Capture Screenshot")
                .disabled(!is_running)
                .on_click(move |_, _, cx| {
                    app_shot.update(cx, |app, cx| {
                        app.capture_profile_screenshot(&pid_shot, cx);
                    });
                }),
        )
        .item(
            PopupMenuItem::new("🔄   Rotate Proxy IP")
                .disabled(!has_rotate_url)
                .on_click(move |_, _, cx| {
                    app_rot.update(cx, |app, cx| {
                        app.rotate_profile_proxy_ip(&pid_rot, cx);
                    });
                }),
        );
    menu.item(
        PopupMenuItem::new("🤖   Cookie Robot (Warm-up)").on_click(move |_, _, cx| {
            let pid = pid_robot.clone();
            app_robot.update(cx, |app, cx| {
                app.open_cookie_robot_modal(Some(pid), cx);
            });
        }),
    )
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
        PopupMenuItem::new(format!("{}   Import cookies", SfSymbol::ARROW_UP_DOC)).on_click(
            move |_, window, cx| {
                app_import_cookies.update(cx, |app, cx| {
                    app.open_edit_cookies_view(&pid_import_cookies, window, cx);
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
        PopupMenuItem::new("📦   Export Backup (.zip)")
            .disabled(is_busy)
            .on_click(move |_, _, cx| {
                app_zip.update(cx, |app, cx| {
                    app.export_single_profile_zip(&pid_zip, cx);
                });
            }),
    )
    .item(
        PopupMenuItem::new("🧹   Clean Disk Cache")
            .disabled(is_busy)
            .on_click(move |_, _, cx| {
                app_clean.update(cx, |app, cx| {
                    app.clean_single_profile_cache(&pid_clean, cx);
                });
            }),
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
        PopupMenuItem::new(format!("{}   Move to Trash", SfSymbol::TRASH))
            .disabled(is_busy)
            .on_click(move |_, _, cx| {
                let pid = pid_del.clone();
                app_del.update(cx, |app, cx| {
                    app.request_delete(PendingDeleteAction::Profile(pid), cx);
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
                // Col 3: Tags (`profile.tags` colored badges + `group_tag`, click to edit tags/note)
                .children(cols.show_tags.then(|| {
                    let pid_tag = profile_id.clone();
                    let first_tag = profile.tags.first().cloned();
                    let extra_count = profile.tags.len().saturating_sub(1);
                    h_flex()
                        .w(px(76.))
                        .flex_shrink_0()
                        .gap_1()
                        .items_center()
                        .overflow_hidden()
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |app, _, window, cx| {
                                cx.stop_propagation();
                                app.open_quick_meta_modal(Some(pid_tag.clone()), window, cx);
                            }),
                        )
                        .child(if let Some(tag) = first_tag {
                            let (fg_hex, bg_hex) = Profile::tag_badge_colors(&tag);
                            let label = if extra_count > 0 {
                                format!("{tag} +{extra_count}")
                            } else {
                                tag
                            };
                            div()
                                .max_w_full()
                                .truncate()
                                .px_1p5()
                                .py_0p5()
                                .rounded_sm()
                                .bg(rgba(bg_hex))
                                .border_1()
                                .border_color(rgb(fg_hex))
                                .text_xs()
                                .font_semibold()
                                .text_color(rgb(fg_hex))
                                .child(label)
                                .into_any_element()
                        } else if !profile.group_tag.trim().is_empty() {
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
                                .child(profile.group_tag.clone())
                                .into_any_element()
                        } else {
                            div()
                                .text_xs()
                                .text_color(BonTheme::text_muted())
                                .hover(|s| s.text_color(BonTheme::accent()))
                                .child("+ Tag")
                                .into_any_element()
                        })
                }))
                // Col 4: Note + 2FA TOTP 1-click badge
                .children(cols.show_notes.then(|| {
                    let pid_note = profile_id.clone();
                    let pid_totp = profile_id.clone();
                    let totp_opt = profile.current_totp();
                    h_flex()
                        .w(px(78.))
                        .flex_shrink_0()
                        .gap_1()
                        .items_center()
                        .overflow_hidden()
                        .children(totp_opt.map(|(code, _)| {
                            div()
                                .px_1()
                                .py(px(1.))
                                .rounded_sm()
                                .bg(rgba(0xa855f726))
                                .border_1()
                                .border_color(rgb(0xc084fc))
                                .text_size(px(10.5))
                                .font_semibold()
                                .text_color(rgb(0xc084fc))
                                .hover(|s| s.bg(rgba(0xa855f744)))
                                .on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener(move |app, _, _, cx| {
                                        cx.stop_propagation();
                                        app.copy_profile_totp(&pid_totp, cx);
                                    }),
                                )
                                .child(if has_note {
                                    "2FA".to_string()
                                } else {
                                    format!("🔐{code}")
                                })
                        }))
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
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
                                        app.open_quick_meta_modal(
                                            Some(pid_note.clone()),
                                            window,
                                            cx,
                                        );
                                    }),
                                )
                                .child(note_text),
                        )
                }))
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
                        h_flex().child(if is_starting {
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
                        .child(if is_running || is_starting {
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
                                .label("Start")
                                .on_click(cx.listener(move |app, _, window, cx| {
                                    app.select_profile(&pid_launch, window, cx);
                                    app.launch_profile(&pid_launch, cx);
                                }))
                        })
                        .child({
                            let has_totp = !profile.totp_secret.trim().is_empty();
                            let has_rotate_url = profile
                                .proxy
                                .as_ref()
                                .and_then(|p| p.change_ip_url.as_ref())
                                .is_some();
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
                                            has_totp,
                                            has_rotate_url,
                                            is_running,
                                            is_busy,
                                        )
                                    },
                                )
                        }),
                ),
        )
        .context_menu({
            let has_totp = !profile.totp_secret.trim().is_empty();
            let has_rotate_url = profile
                .proxy
                .as_ref()
                .and_then(|p| p.change_ip_url.as_ref())
                .is_some();
            move |menu, _window, _cx| {
                build_profile_popup_menu(
                    menu,
                    app_for_ctx.clone(),
                    pid_for_ctx.clone(),
                    has_totp,
                    has_rotate_url,
                    is_running,
                    is_busy,
                )
            }
        })
        .into_any_element()
}

pub fn render_trash_table(
    trashed: &[Profile],
    cx: &mut Context<BonLoginApp>,
) -> Div {
    v_flex()
        .w_full()
        .flex_1()
        .min_h_0()
        .gap_3()
        .overflow_hidden()
        .child(
            h_flex()
                .w_full()
                .justify_between()
                .items_center()
                .child(
                    div()
                        .text_xs()
                        .text_color(BonTheme::text_secondary())
                        .child(
                            "Deleted profiles keep their isolated browser data & cookies on disk until permanently removed.",
                        ),
                )
                .child(
                    h_flex()
                        .gap_2()
                        .items_center()
                        .children((!trashed.is_empty()).then(|| {
                            Button::new("trash-restore-all")
                                .with_variant(BonTheme::outline_blue(cx))
                                .small()
                                .label(format!(
                                    "{}  Restore All ({})",
                                    SfSymbol::ARROW_CLOCKWISE,
                                    trashed.len()
                                ))
                                .on_click(cx.listener(|app, _, window, cx| {
                                    app.restore_all_trashed_profiles(window, cx);
                                }))
                        }))
                        .children((!trashed.is_empty()).then(|| {
                            Button::new("trash-empty-all")
                                .danger()
                                .small()
                                .label(format!("{}  Empty Trash", SfSymbol::TRASH))
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.request_delete(PendingDeleteAction::EmptyTrash, cx);
                                }))
                        })),
                ),
        )
        .child(
            v_flex()
                .w_full()
                .flex_1()
                .min_h_0()
                .rounded_xl()
                .bg(BonTheme::bg_panel())
                .border_1()
                .border_color(BonTheme::border())
                .overflow_hidden()
                .child(
                    h_flex()
                        .w_full()
                        .px_4()
                        .py_2p5()
                        .gap_3()
                        .items_center()
                        .bg(BonTheme::bg_elevated())
                        .border_b_1()
                        .border_color(BonTheme::border())
                        .text_xs()
                        .font_semibold()
                        .text_color(BonTheme::text_secondary())
                        .child(div().w(px(80.)).child("ID"))
                        .child(div().w(px(180.)).child("Name"))
                        .child(div().w(px(130.)).child("Group / Tags"))
                        .child(div().w(px(150.)).child("Proxy"))
                        .child(div().w(px(140.)).child("Deleted"))
                        .child(div().flex_1().flex().justify_end().child("Actions")),
                )
                .child(
                    v_flex()
                        .id("trash-table-rows")
                        .w_full()
                        .flex_1()
                        .min_h_0()
                        .overflow_y_scroll()
                        .children(trashed.is_empty().then(|| {
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
                                        .child("Trash is empty"),
                                )
                                .child(
                                    div()
                                        .text_xs()
                                        .text_color(BonTheme::text_secondary())
                                        .child("Profiles you delete will appear here so you can restore them anytime."),
                                )
                        }))
                        .children(trashed.iter().map(|p| {
                            let pid_restore = p.id.clone();
                            let pid_perm = p.id.clone();
                            let proxy_str = p
                                .proxy
                                .as_ref()
                                .map(|px| px.display_short())
                                .unwrap_or_else(|| "Local IP".to_string());
                            let grp_tags = if !p.tags.is_empty() {
                                p.tags.join(", ")
                            } else if !p.group_tag.is_empty() {
                                p.group_tag.clone()
                            } else {
                                "—".to_string()
                            };
                            h_flex()
                                .w_full()
                                .px_4()
                                .py_2p5()
                                .gap_3()
                                .items_center()
                                .border_b_1()
                                .border_color(BonTheme::border())
                                .hover(|s| s.bg(BonTheme::bg_hover()))
                                .child(
                                    div()
                                        .w(px(80.))
                                        .truncate()
                                        .text_xs()
                                        .text_color(BonTheme::text_secondary())
                                        .child(p.short_id()),
                                )
                                .child(
                                    div()
                                        .w(px(180.))
                                        .truncate()
                                        .text_xs()
                                        .font_semibold()
                                        .text_color(BonTheme::text_primary())
                                        .child(p.name.clone()),
                                )
                                .child(
                                    div()
                                        .w(px(130.))
                                        .truncate()
                                        .text_xs()
                                        .text_color(BonTheme::text_secondary())
                                        .child(grp_tags),
                                )
                                .child(
                                    div()
                                        .w(px(150.))
                                        .truncate()
                                        .text_xs()
                                        .text_color(BonTheme::text_secondary())
                                        .child(proxy_str),
                                )
                                .child(
                                    div()
                                        .w(px(140.))
                                        .truncate()
                                        .text_xs()
                                        .text_color(BonTheme::warning())
                                        .child(p.format_deleted_at()),
                                )
                                .child(
                                    h_flex()
                                        .flex_1()
                                        .justify_end()
                                        .items_center()
                                        .gap_2()
                                        .child(
                                            Button::new(SharedString::from(format!(
                                                "trash-res-{}",
                                                p.id
                                            )))
                                            .with_variant(BonTheme::launch_cta(cx))
                                            .small()
                                            .label("↩ Restore")
                                            .on_click(cx.listener(move |app, _, window, cx| {
                                                app.restore_trashed_profile(
                                                    &pid_restore,
                                                    window,
                                                    cx,
                                                );
                                            })),
                                        )
                                        .child(
                                            Button::new(SharedString::from(format!(
                                                "trash-perm-{}",
                                                p.id
                                            )))
                                            .danger()
                                            .small()
                                            .label("Delete Forever")
                                            .on_click(cx.listener(move |app, _, _, cx| {
                                                app.request_delete(
                                                    PendingDeleteAction::PermanentProfile(
                                                        pid_perm.clone(),
                                                    ),
                                                    cx,
                                                );
                                            })),
                                        ),
                                )
                        })),
                ),
        )
}
