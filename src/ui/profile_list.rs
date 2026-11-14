use gpui_kit::component::{
    button::{Button, ButtonVariants as _},
    menu::{ContextMenuExt as _, DropdownMenu as _, PopupMenu, PopupMenuItem},
    *,
};
use gpui_kit::*;
use std::time::Duration;
use crate::models::{IpKind, Profile, ProfileStatus};
use crate::ui::profile_modal::{
    detail_summary_row as drawer_row, detail_summary_row_mono as drawer_row_mono,
};
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
    app: &BonLoginApp,
    filtered_indices: std::rc::Rc<[usize]>,
    cx: &mut Context<BonLoginApp>,
) -> impl IntoElement {
    let profiles = &app.profiles;
    let statuses = &app.statuses;
    let checked_profile_ids = &app.checked_profile_ids;
    let cols = app.col_vis;
    let sort_col = app.sort_col;
    let sort_asc = app.sort_asc;
    let show_detail_drawer = app.show_detail_drawer;
    let selected_profile_id = app.selected_profile_id.as_deref();
    let selected_disk_usage = app.selected_disk_usage.as_str();
    let recently_copied_key = app.recently_copied_key.clone();
    let reseed_flash_seed = app.reseed_flash_seed;
    let all_checked = !filtered_indices.is_empty()
        && filtered_indices
            .iter()
            .all(|&i| checked_profile_ids.contains(&profiles[i].id));
    let any_checked = filtered_indices
        .iter()
        .any(|&i| checked_profile_ids.contains(&profiles[i].id));
    let header_check_mark = if all_checked {
        SfSymbol::CHECKMARK
    } else if any_checked {
        SfSymbol::MINUS
    } else {
        ""
    };

    let selected_profile = selected_profile_id.and_then(|id| {
        filtered_indices
            .iter()
            .find_map(|&i| (profiles[i].id == id).then_some(&profiles[i]))
    });
    h_flex()
        .w_full()
        .flex_1()
        .gap_0()
        .overflow_hidden()
        // Left: Master Profile Roster + Pagination Footer
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
                // Table Header (`[☐] | ID ↓ | Name ↓ | Tags | Note | Proxy | Updated ↓ | Status | … | [⚙]`)
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
                        .child(BonTheme::checkbox(
                            "prof-hdr-chk-spring",
                            all_checked || any_checked,
                            header_check_mark,
                            BonTheme::bg_panel(),
                            cx.listener(|app, _, _, cx| {
                                app.toggle_check_all_filtered(cx);
                            }),
                        ))
                        .children(cols.show_id.then(|| {
                            sortable_col_header(
                                "ID",
                                Some(70.),
                                ProfileSortColumn::Id,
                                sort_col,
                                sort_asc,
                                cx,
                            )
                        }))
                        .children(cols.show_name.then(|| {
                            sortable_col_header(
                                "Name",
                                Some(180.),
                                ProfileSortColumn::Name,
                                sort_col,
                                sort_asc,
                                cx,
                            )
                            .min_w(px(96.))
                            .flex_shrink_1()
                        }))
                        .children(cols.show_tags.then(|| {
                            sortable_col_header(
                                "Tags",
                                Some(88.),
                                ProfileSortColumn::Tags,
                                sort_col,
                                sort_asc,
                                cx,
                            )
                            .min_w(px(48.))
                            .flex_shrink_1()
                        }))
                        .children(cols.show_notes.then(|| {
                            sortable_col_header(
                                "Note",
                                Some(96.),
                                ProfileSortColumn::Notes,
                                sort_col,
                                sort_asc,
                                cx,
                            )
                            .min_w(px(40.))
                            .flex_shrink_1()
                        }))
                        .children(cols.show_proxy.then(|| {
                            sortable_col_header(
                                "Proxy",
                                Some(136.),
                                ProfileSortColumn::Proxy,
                                sort_col,
                                sort_asc,
                                cx,
                            )
                            .min_w(px(72.))
                            .flex_shrink_1()
                        }))
                        .children(cols.show_updated.then(|| {
                            sortable_col_header(
                                "Updated",
                                Some(86.),
                                ProfileSortColumn::Updated,
                                sort_col,
                                sort_asc,
                                cx,
                            )
                        }))
                        .children(cols.show_status.then(|| {
                            sortable_col_header(
                                "Status",
                                Some(132.),
                                ProfileSortColumn::Status,
                                sort_col,
                                sort_asc,
                                cx,
                            )
                        }))
                        .child(div().flex_1().min_w_0())
                        .child(
                            h_flex()
                                .w(px(108.))
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
                // Scrollable Virtualized Profile Rows Body
                .child(if filtered_indices.is_empty() {
                    v_flex()
                        .id("profiles-table-rows")
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
                        .into_any_element()
                } else {
                    let filtered_len = filtered_indices.len();
                    let (_, _, page_start, page_end) = app.current_page_bounds(
                        crate::ui::PaginatedTable::Profiles,
                        filtered_len,
                    );
                    let indices_for_list: std::rc::Rc<[usize]> =
                        filtered_indices[page_start..page_end].into();
                    uniform_list(
                        "profiles-table-rows",
                        indices_for_list.len(),
                        cx.processor(move |app, range: std::ops::Range<usize>, _window, cx| {
                            let selected_id = app.selected_profile_id.as_deref();
                            let copied_key = app.recently_copied_key.as_deref();
                            let cols = app.col_vis;
                            let mut ip_counts: std::collections::HashMap<String, usize> =
                                std::collections::HashMap::new();
                            let mut proxy_counts: std::collections::HashMap<
                                (String, u16, Option<String>),
                                usize,
                            > = std::collections::HashMap::new();
                            for p in &app.profiles {
                                if p.deleted_at.is_some() {
                                    continue;
                                }
                                if let Some(ip) = p.resolved_geo.as_ref().map(|g| g.ip.as_str()) {
                                    *ip_counts.entry(ip.to_string()).or_default() += 1;
                                }
                                if let Some(px) = &p.proxy {
                                    *proxy_counts
                                        .entry((px.host.clone(), px.port, px.username.clone()))
                                        .or_default() += 1;
                                }
                            }
                            let mut items = Vec::with_capacity(range.len());
                            for row_ix in range {
                                let Some(&prof_ix) = indices_for_list.get(row_ix) else {
                                    continue;
                                };
                                let Some(profile) = app.profiles.get(prof_ix) else {
                                    continue;
                                };
                                let status = app
                                    .statuses
                                    .get(&profile.id)
                                    .cloned()
                                    .unwrap_or(ProfileStatus::Stopped);
                                let is_selected = selected_id == Some(profile.id.as_str());
                                let is_checked = app.checked_profile_ids.contains(&profile.id);
                                let is_checking_proxy =
                                    app.profile_aux_tasks.contains_key(&profile.id);
                                let copied_id = copied_key
                                    .and_then(|k| k.strip_prefix("id:"))
                                    == Some(profile.id.as_str());
                                let copied_totp = copied_key
                                    .and_then(|k| k.strip_prefix("totp:"))
                                    == Some(profile.id.as_str());
                                let shared_note = profile.resolved_geo.as_ref().and_then(|g| {
                                    let n = ip_counts.get(&g.ip).copied().unwrap_or(0);
                                    (n > 1).then(|| format!("exit IP shared with {} profiles", n - 1))
                                }).or_else(|| {
                                    profile.proxy.as_ref().and_then(|px| {
                                        let n = proxy_counts
                                            .get(&(px.host.clone(), px.port, px.username.clone()))
                                            .copied()
                                            .unwrap_or(0);
                                        (n > 1).then(|| format!("proxy shared with {} profiles", n - 1))
                                    })
                                });
                                items.push(render_profile_row(
                                    profile,
                                    status,
                                    is_selected,
                                    is_checked,
                                    is_checking_proxy,
                                    copied_id,
                                    copied_totp,
                                    shared_note,
                                    cols,
                                    cx,
                                ));
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
                // Table Pagination Footer (`Profiles: N   < [1] >   25 / page`)
                .child(
                    crate::ui::workspace_views::render_table_pagination_footer(
                        "profiles",
                        crate::ui::PaginatedTable::Profiles,
                        "Profiles",
                        filtered_indices.len(),
                        None,
                        app,
                        cx,
                    ),
                ),
        )
        // Right: Collapsible Profile Inspector Drawer
        .children(
            selected_profile.map(|prof| {
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
                let flash_seed = reseed_flash_seed.filter(|&s| s == prof.seed);
                let drawer_copied_totp = recently_copied_key
                    .as_deref()
                    .and_then(|k| k.strip_prefix("totp:"))
                    == Some(prof.id.as_str());
                div()
                    .h_full()
                    .flex_shrink_0()
                    .overflow_hidden()
                    .child(
                        v_flex()
                            .w(px(304.))
                            .h_full()
                            .flex_shrink_0()
                            .p_4()
                            .gap_2p5()
                            .rounded_xl()
                            .bg(BonTheme::bg_panel())
                            .border_1()
                            .border_color(BonTheme::border())
                            .overflow_hidden()
                            // Inspector Header: Profile Name + Monospace Session ID + Close Button
                            .child(
                                h_flex()
                                    .w_full()
                                    .pb_2()
                                    .border_b_1()
                                    .border_color(BonTheme::border())
                                    .justify_between()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        v_flex()
                                            .flex_1()
                                            .min_w_0()
                                            .gap_0p5()
                                            .child(
                                                div()
                                                    .w_full()
                                                    .truncate()
                                                    .text_sm()
                                                    .font_bold()
                                                    .text_color(BonTheme::text_primary())
                                                    .child(prof.name.clone()),
                                            )
                                            .child(
                                                div()
                                                    .font_family(BonTheme::font_mono())
                                                    .text_size(px(11.))
                                                    .text_color(BonTheme::text_muted())
                                                    .child(match statuses.get(&prof.id) {
                                                        Some(ProfileStatus::Running(info)) => {
                                                            format!(
                                                                "bon_{} • :{} LIVE",
                                                                prof.short_id(),
                                                                info.cdp_port
                                                            )
                                                        }
                                                        _ => format!(
                                                            "bon_{} • seed {}",
                                                            prof.short_id(),
                                                            prof.seed
                                                        ),
                                                    }),
                                            ),
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
                            // Primary Inspector Actions: [Edit Settings] + [↻ Reseed]
                            .child(
                                h_flex()
                                    .w_full()
                                    .gap_1p5()
                                    .items_center()
                                    .child(
                                        div().flex_1().child(
                                            Button::new("drawer-open-edit")
                                                .w_full()
                                                .with_variant(BonTheme::outline_blue(cx))
                                                .small()
                                                .label(format!(
                                                    "{}  Edit Settings",
                                                    SfSymbol::SLIDER_HORIZONTAL_3
                                                ))
                                                .on_click(cx.listener(
                                                    move |app, _, window, cx| {
                                                        app.open_edit_view(&pid_edit, window, cx);
                                                    },
                                                )),
                                        ),
                                    )
                                    .child(
                                        Button::new("drawer-refresh-fp")
                                            .with_variant(BonTheme::row_action(cx))
                                            .small()
                                            .label(format!("{}  Reseed", SfSymbol::ARROW_CLOCKWISE))
                                            .on_click(cx.listener(move |app, _, window, cx| {
                                                app.randomize_profile_seed(
                                                    &pid_refresh,
                                                    window,
                                                    cx,
                                                );
                                            })),
                                    ),
                            )
                            .child({
                                let pid_totp = prof.id.clone();
                                let pid_meta = prof.id.clone();
                                let totp_opt = prof.current_totp();
                                let tags_str = if prof.tags.is_empty() {
                                    if prof.group_tag.trim().is_empty() {
                                        "None".to_string()
                                    } else {
                                        prof.group_tag.clone()
                                    }
                                } else {
                                    prof.tags.join(", ")
                                };
                                v_flex()
                                    .id("detail-drawer-body")
                                    .w_full()
                                    .flex_1()
                                    .min_h_0()
                                    .gap_1p5()
                                    .overflow_y_scroll()
                                    .child(drawer_row("Group / Tags", tags_str))
                            .child({
                                let pid_bm_edit = prof.id.clone();
                                let pid_bm_click = prof.id.clone();
                                let bms = app.selected_bookmarks.clone();
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
                                                    .label(format!("{} {bm_name}", SfSymbol::BOOKMARK_FILL))
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
                                            .with_variant(if drawer_copied_totp {
                                                BonTheme::success_cta(cx)
                                            } else {
                                                BonTheme::outline_blue(cx)
                                            })
                                            .xsmall()
                                            .label(if drawer_copied_totp {
                                                format!(
                                                    "{} Copied {} {}",
                                                    SfSymbol::CHECKMARK,
                                                    &code[..3],
                                                    &code[3..]
                                                )
                                            } else {
                                                format!(
                                                    "{} {} {} ({rem}s)",
                                                    SfSymbol::LOCK_FILL,
                                                    &code[..3],
                                                    &code[3..]
                                                )
                                            })
                                            .on_click(cx.listener(move |app, _, _, cx| {
                                                app.copy_profile_totp(&pid_totp, cx);
                                            })),
                                    )
                            }))
                            .child(drawer_row("Browser", prof.brand.as_cli_str().to_string()))
                            .child(reseed_drawer_row(
                                "Version",
                                prof.brand.version_for_seed(prof.seed).to_string(),
                                flash_seed,
                            ))
                            .child(reseed_drawer_row(
                                "OS Platform",
                                format!(
                                    "{} ({})",
                                    prof.os_platform.label(),
                                    prof.os_platform.os_version_for_seed(prof.seed)
                                ),
                                flash_seed,
                            ))
                            .child(drawer_row_mono("Proxy", proxy_str))
                            .child(drawer_row(
                                "IP quality",
                                prof.resolved_geo
                                    .as_ref()
                                    .and_then(|g| g.quality_label())
                                    .unwrap_or_else(|| "Unknown".to_string()),
                            ))
                            .children(Profile::shared_exit_label(profiles, prof).map(|note| {
                                drawer_row("Shared", note)
                            }))
                            .child(drawer_row("Timezone", tz_str))
                            .child(drawer_row(
                                "WebRTC Policy",
                                if prof.proxy.is_some() {
                                    "Proxy Tunnel (No UDP)".to_string()
                                } else {
                                    "Direct".to_string()
                                },
                            ))
                            .child(drawer_row_mono(
                                "Viewport",
                                prof.window_size.replace(',', "×"),
                            ))
                            .child(reseed_drawer_row(
                                "Hardware",
                                format!(
                                    "{} Cores • {} GB",
                                    prof.hardware_concurrency,
                                    Profile::device_memory_for_seed(prof.seed)
                                ),
                                flash_seed,
                            ))
                            .child(drawer_row(
                                "Canvas Spoof",
                                if prof.spoof_canvas { "C++ Noise" } else { "Native" }.to_string(),
                            ))
                            .child(reseed_drawer_row(
                                "WebGL Renderer",
                                prof.os_platform
                                    .webgl_for_seed(prof.seed, prof.gpu_spoofing)
                                    .1
                                    .to_string(),
                                flash_seed,
                            ))
                            .child(drawer_row_mono("Disk Usage", selected_disk_usage.to_string()))
                            .child({
                                let pid_clean = prof.id.clone();
                                let pid_wipe = prof.id.clone();
                                let pid_flow = prof.id.clone();
                                let pid_rot = prof.id.clone();
                                let pid_type = prof.id.clone();
                                let pid_shot = prof.id.clone();
                                let pid_focus = prof.id.clone();
                                let pid_pre = prof.id.clone();
                                let is_prof_running =
                                    matches!(statuses.get(&prof.id), Some(ProfileStatus::Running(_)));
                                let has_proxy_rot = prof
                                    .proxy
                                    .as_ref()
                                    .and_then(|p| p.change_ip_url.as_ref())
                                    .is_some();
                                v_flex()
                                    .pt_2p5()
                                    .mt_1()
                                    .border_t_1()
                                    .border_color(BonTheme::border())
                                    .gap_1p5()
                                    // Live Running Controls (only shown when active or proxy rotatable)
                                    .children((is_prof_running || has_proxy_rot).then(|| {
                                        h_flex()
                                            .w_full()
                                            .gap_1p5()
                                            .flex_wrap()
                                            .children(is_prof_running.then(|| {
                                                Button::new("drawer-focus-win")
                                                    .with_variant(BonTheme::outline_blue(cx))
                                                    .xsmall()
                                                    .label("\u{1002ab} Focus")
                                                    .on_click(cx.listener(move |app, _, _, cx| {
                                                        app.focus_profile_browser(&pid_focus, cx);
                                                    }))
                                            }))
                                            .children(is_prof_running.then(|| {
                                                Button::new("drawer-human-type")
                                                    .with_variant(BonTheme::outline_blue(cx))
                                                    .xsmall()
                                                    .label("\u{100a7c} Human Type")
                                                    .on_click(cx.listener(move |app, _, _, cx| {
                                                        app.type_clipboard_as_human(&pid_type, cx);
                                                    }))
                                            }))
                                            .children(is_prof_running.then(|| {
                                                Button::new("drawer-screenshot")
                                                    .with_variant(BonTheme::outline_blue(cx))
                                                    .xsmall()
                                                    .label("\u{100241} Screenshot")
                                                    .on_click(cx.listener(move |app, _, _, cx| {
                                                        app.capture_profile_screenshot(
                                                            &pid_shot, cx,
                                                        );
                                                    }))
                                            }))
                                            .children(is_prof_running.then(|| {
                                                Button::new("drawer-preflight")
                                                    .with_variant(BonTheme::outline_blue(cx))
                                                    .xsmall()
                                                    .label(format!(
                                                        "{} Preflight",
                                                        SfSymbol::CHECKMARK_SHIELD
                                                    ))
                                                    .on_click(cx.listener(move |app, _, _, cx| {
                                                        app.open_profile_preflight(&pid_pre, cx);
                                                    }))
                                            }))
                                            .children(has_proxy_rot.then(|| {
                                                Button::new("drawer-rotate-proxy")
                                                    .with_variant(BonTheme::outline_blue(cx))
                                                    .xsmall()
                                                    .label("\u{1002af} Rotate IP")
                                                    .on_click(cx.listener(move |app, _, _, cx| {
                                                        app.rotate_profile_proxy_ip(&pid_rot, cx);
                                                    }))
                                            }))
                                    }))
                                    // Row 1: Quick Tools (Meta/2FA + Agent Flows)
                                    .child(
                                        h_flex()
                                            .w_full()
                                            .gap_1p5()
                                            .child(
                                                div().flex_1().child(
                                                    Button::new("drawer-open-meta")
                                                        .w_full()
                                                        .with_variant(BonTheme::row_action(cx))
                                                        .xsmall()
                                                        .label("\u{1002e2} Tags & 2FA")
                                                        .on_click(cx.listener(
                                                            move |app, _, window, cx| {
                                                                app.open_quick_meta_modal(
                                                                    Some(pid_meta.clone()),
                                                                    window,
                                                                    cx,
                                                                );
                                                            },
                                                        )),
                                                ),
                                            )
                                            .child(
                                                div().flex_1().child(
                                                    Button::new("drawer-open-flows")
                                                        .w_full()
                                                        .with_variant(BonTheme::row_action(cx))
                                                        .xsmall()
                                                        .label("\u{100284} Agent Flows")
                                                        .on_click(cx.listener(
                                                            move |app, _, window, cx| {
                                                                app.open_agent_flows_modal(
                                                                    Some(pid_flow.clone()),
                                                                    window,
                                                                    cx,
                                                                );
                                                            },
                                                        )),
                                                ),
                                            ),
                                    )
                                    // Row 2: Storage Maintenance (Clean Cache + Destructive Wipe Data)
                                    .child(
                                        h_flex()
                                            .w_full()
                                            .gap_1p5()
                                            .child(
                                                div().flex_1().child(
                                                    Button::new("drawer-clean-cache")
                                                        .w_full()
                                                        .with_variant(BonTheme::row_action(cx))
                                                        .xsmall()
                                                        .disabled(is_prof_running)
                                                        .label("\u{1002af} Clean Cache")
                                                        .on_click(cx.listener(
                                                            move |app, _, _, cx| {
                                                                app.request_delete(
                                                                    PendingDeleteAction::CleanProfileCache(
                                                                        pid_clean.clone(),
                                                                    ),
                                                                    cx,
                                                                );
                                                            },
                                                        )),
                                                ),
                                            )
                                            .child(
                                                div().flex_1().child(
                                                    Button::new("drawer-wipe-data")
                                                        .w_full()
                                                        .with_variant(BonTheme::outline_danger(cx))
                                                        .xsmall()
                                                        .disabled(is_prof_running)
                                                        .label("\u{100211} Wipe Data")
                                                        .on_click(cx.listener(
                                                            move |app, _, _, cx| {
                                                                app.request_delete(
                                                                    PendingDeleteAction::WipeProfile(
                                                                        pid_wipe.clone(),
                                                                    ),
                                                                    cx,
                                                                );
                                                            },
                                                        )),
                                                ),
                                            ),
                                    )
                            })
                    }),
                    )
                    .with_spring(
                        "detail-drawer-spring",
                        SpringAnimation::new(BonTheme::snappy_spring()).to(show_detail_drawer),
                        |this, phase| {
                            this.w(phase.interpolate_clamped(px(0.), px(304.)))
                                .ml(phase.interpolate_clamped(px(0.), px(16.)))
                                .opacity(phase.0.clamp(0.0, 1.0))
                        },
                    )
            }),
        )
}

fn reseed_drawer_row(
    label: &'static str,
    value: String,
    flash_seed: Option<u32>,
) -> AnyElement {
    let row = drawer_row(label, value);
    if let Some(seed) = flash_seed {
        row.with_animation(
            SharedString::from(format!("reseed-row-{label}-{seed}")),
            Animation::new(Duration::from_millis(280)).with_easing(ease_out_quint()),
            |this, delta| {
                this.bg(AnimationPhase(delta).interpolate_clamped(
                    BonTheme::accent_subtle(),
                    Hsla::from(rgba(0x00000000)),
                ))
            },
        )
        .into_any_element()
    } else {
        row.into_any_element()
    }
}

fn sortable_col_header(
    label: &'static str,
    width: Option<f32>,
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
    let base = h_flex();
    let sized = if let Some(w) = width {
        base.w(px(w)).flex_shrink_0()
    } else {
        base.flex_1().min_w(px(140.))
    };
    sized
        .gap_1()
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
        .children(is_active.then(|| {
            div()
                .text_color(BonTheme::accent())
                .child(arrow)
        }))
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
    let app_focus = app_entity.clone();
    let pid_focus = profile_id.clone();
    let app_type = app_entity.clone();
    let pid_type = profile_id.clone();
    let app_shot = app_entity.clone();
    let pid_shot = profile_id.clone();
    let app_rot = app_entity.clone();
    let pid_rot = profile_id.clone();
    let app_robot = app_entity.clone();
    let pid_robot = profile_id.clone();
    let app_seed = app_entity.clone();
    let pid_seed = profile_id.clone();
    let app_audit = app_entity.clone();
    let pid_audit = profile_id.clone();
    let app_flow = app_entity.clone();
    let pid_flow = profile_id.clone();
    let app_import_cookies = app_entity.clone();
    let pid_import_cookies = profile_id.clone();
    let app_cookies = app_entity.clone();
    let pid_cookies = profile_id.clone();
    let app_zip = app_entity.clone();
    let pid_zip = profile_id.clone();
    let app_clean = app_entity.clone();
    let pid_clean = profile_id.clone();
    let app_wipe = app_entity.clone();
    let pid_wipe = profile_id.clone();
    let app_clone = app_entity.clone();
    let pid_clone = profile_id.clone();
    let app_bclone = app_entity.clone();
    let pid_bclone = profile_id.clone();
    let app_proxy = app_entity.clone();
    let pid_proxy = profile_id.clone();
    let app_copy_id = app_entity.clone();
    let pid_copy_id = profile_id.clone();
    let app_agent = app_entity.clone();
    let pid_agent = profile_id.clone();
    let app_pin = app_entity.clone();
    let pid_pin = profile_id.clone();
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
            PopupMenuItem::new("\u{1002e2}   Bookmarks, Tags & 2FA").on_click(move |_, window, cx| {
                let pid = pid_meta.clone();
                app_meta.update(cx, |app, cx| {
                    app.open_quick_meta_modal(Some(pid), window, cx);
                });
            }),
        );
    if has_totp {
        menu = menu.item(
            PopupMenuItem::new("\u{1003a0}   Copy 2FA Code").on_click(move |_, _, cx| {
                app_totp.update(cx, |app, cx| {
                    app.copy_profile_totp(&pid_totp, cx);
                });
            }),
        );
    }
    menu = menu
        .separator()
        .item(
            PopupMenuItem::new("\u{1002ab}   Focus Browser Window")
                .disabled(!is_running)
                .on_click(move |_, _, cx| {
                    app_focus.update(cx, |app, cx| {
                        app.focus_profile_browser(&pid_focus, cx);
                    });
                }),
        )
        .item(
            PopupMenuItem::new("\u{100a7c}   Human-Type Clipboard")
                .disabled(!is_running)
                .on_click(move |_, _, cx| {
                    app_type.update(cx, |app, cx| {
                        app.type_clipboard_as_human(&pid_type, cx);
                    });
                }),
        )
        .item(
            PopupMenuItem::new("\u{100241}   Capture Screenshot")
                .disabled(!is_running)
                .on_click(move |_, _, cx| {
                    app_shot.update(cx, |app, cx| {
                        app.capture_profile_screenshot(&pid_shot, cx);
                    });
                }),
        )
        .item(
            PopupMenuItem::new("\u{1002af}   Rotate Proxy IP")
                .disabled(!has_rotate_url)
                .on_click(move |_, _, cx| {
                    app_rot.update(cx, |app, cx| {
                        app.rotate_profile_proxy_ip(&pid_rot, cx);
                    });
                }),
        );
    menu.separator()
        .item(
            PopupMenuItem::new("\u{1002e6}   Cookie Robot (Warm-up)").on_click(move |_, window, cx| {
            let pid = pid_robot.clone();
            app_robot.update(cx, |app, cx| {
                app.open_cookie_robot_modal(Some(pid), window, cx);
            });
        }),
    )
    .item(
        PopupMenuItem::new("Seed profile").on_click(move |_, _, cx| {
            app_seed.update(cx, |app, cx| {
                app.seed_profile(&pid_seed, cx);
            });
        }),
    )
    .item(
        PopupMenuItem::new("Audit profile").on_click(move |_, _, cx| {
            app_audit.update(cx, |app, cx| {
                app.audit_profile(&pid_audit, cx);
            });
        }),
    )
    .item(
        PopupMenuItem::new("\u{100284}   Agent Flows (Playbooks)").on_click(move |_, window, cx| {
            let pid = pid_flow.clone();
            app_flow.update(cx, |app, cx| {
                app.open_agent_flows_modal(Some(pid), window, cx);
            });
        }),
    )
    .item(
        PopupMenuItem::new("\u{100a7c}   Copy Agent CLI").on_click(
            move |_, _, cx| {
                app_agent.update(cx, |app, cx| {
                    app.copy_agent_browser_cli(&pid_agent, cx);
                });
            },
        ),
    )
    .item(
        PopupMenuItem::new("\u{100263}   Copy Pinned-Tab CLI").on_click(move |_, _, cx| {
            app_pin.update(cx, |app, cx| {
                app.copy_pinned_tab_cli(&pid_pin, cx);
            });
        }),
    )
    .separator()
    .item(
        PopupMenuItem::new("\u{10023b}   Import cookies").on_click(
            move |_, window, cx| {
                app_import_cookies.update(cx, |app, cx| {
                    app.open_edit_cookies_view(&pid_import_cookies, window, cx);
                });
            },
        ),
    )
    .item(
        PopupMenuItem::new("\u{10023d}   Export cookies").on_click(
            move |_, _, cx| {
                app_cookies.update(cx, |app, cx| {
                    app.export_profile_cookies_json(&pid_cookies, cx);
                });
            },
        ),
    )
    .item(
        PopupMenuItem::new("\u{10023d}   Export Backup (.zip)")
            .disabled(is_busy)
            .on_click(move |_, _, cx| {
                app_zip.update(cx, |app, cx| {
                    app.export_single_profile_zip(&pid_zip, cx);
                });
            }),
    )
    .separator()
    .item(
        PopupMenuItem::new("\u{100add}   Clone (1-click)")
            .on_click(move |_, window, cx| {
                app_clone.update(cx, |app, cx| {
                    app.clone_profile(&pid_clone, window, cx);
                });
            }),
    )
    .item(
        PopupMenuItem::new("\u{100add}   Clone Multiple...").on_click(move |_, window, cx| {
            app_bclone.update(cx, |app, cx| {
                app.open_clone_modal(&pid_bclone, window, cx);
            });
        }),
    )
    .item(
        PopupMenuItem::new("\u{100241}   Copy ID").on_click(
            move |_, _, cx| {
                app_copy_id.update(cx, |app, cx| {
                    app.copy_profile_id(&pid_copy_id, cx);
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
        PopupMenuItem::new("\u{1002af}   Clean Disk Cache")
            .disabled(is_busy)
            .on_click(move |_, _, cx| {
                let pid = pid_clean.clone();
                app_clean.update(cx, |app, cx| {
                    app.request_delete(PendingDeleteAction::CleanProfileCache(pid), cx);
                });
            }),
    )
    .item(
        PopupMenuItem::new("\u{100211}   Wipe Browser Data")
            .disabled(is_busy)
            .on_click(move |_, _, cx| {
                let pid = pid_wipe.clone();
                app_wipe.update(cx, |app, cx| {
                    app.request_delete(PendingDeleteAction::WipeProfile(pid), cx);
                });
            }),
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
    is_checking_proxy: bool,
    copied_id: bool,
    copied_totp: bool,
    shared_note: Option<String>,
    cols: ColumnVisibility,
    cx: &mut Context<BonLoginApp>,
) -> AnyElement {
    let app_entity = cx.entity().clone();
    let profile_id = profile.id.clone();
    let select_id = profile.id.clone();
    let check_id = profile.id.clone();
    let proxy_label = if is_checking_proxy {
        format!("{} Checking...", SfSymbol::GLOBE)
    } else {
        match (&profile.proxy, &profile.resolved_geo) {
            (Some(_), Some(g)) => {
                let base = format!("{} {} ({})", SfSymbol::GLOBE, g.compact_ip(), g.country_code);
                let labeled = match g.quality_label() {
                    Some(q) => format!("{base} · {q}"),
                    None => base,
                };
                match &shared_note {
                    Some(note) => format!("{labeled} · {note}"),
                    None => labeled,
                }
            }
            (Some(p), None) => {
                let base = format!("{} {}", SfSymbol::GLOBE, p.display_short());
                match &shared_note {
                    Some(note) => format!("{base} · {note}"),
                    None => base,
                }
            }
            (None, _) => "Local IP".to_string(),
        }
    };
    let is_running = matches!(status, ProfileStatus::Running(_));
    let is_starting = matches!(status, ProfileStatus::Starting);

    let (badge_bg, badge_fg, state_title) = match &status {
        ProfileStatus::Stopped => (
            BonTheme::bg_elevated(),
            BonTheme::text_secondary(),
            "Ready".to_string(),
        ),
        ProfileStatus::Starting => (
            BonTheme::warning_bg(),
            BonTheme::warning(),
            "Starting".to_string(),
        ),
        ProfileStatus::Running(_) => (
            BonTheme::success_bg(),
            BonTheme::success(),
            "Running".to_string(),
        ),
        ProfileStatus::Error => (
            BonTheme::danger_bg(),
            BonTheme::danger(),
            "Error".to_string(),
        ),
    };
    let state_title = format!("{state_title} · {}", profile.trust_stage.label());

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
        .border_b_1()
        .border_color(BonTheme::border())
        .bg(if is_selected || is_checked {
            BonTheme::bg_selected()
        } else {
            BonTheme::bg_panel()
        })
        .hover(|s| {
            if is_selected || is_checked {
                s.bg(rgba(0x0a84ff5c))
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
                // Col 0: Checkbox (sibling outside row-select listener so clicking checkbox never selects row)
                .child(BonTheme::checkbox(
                    format!("prof-chk-spring-{profile_id}"),
                    is_checked,
                    if is_checked { SfSymbol::CHECKMARK } else { "" },
                    BonTheme::bg_elevated(),
                    cx.listener(move |app, _, _, cx| {
                        app.toggle_check_profile(&check_id, cx);
                    }),
                ))
                .child(
                    h_flex()
                        .flex_1()
                        .min_w_0()
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
                // Col 1: ID (`3866478`)
                .children(cols.show_id.then(|| {
                    let pid_id_col = profile_id.clone();
                    div()
                        .w(px(70.))
                        .flex_shrink_0()
                        .truncate()
                        .font_family(BonTheme::font_mono())
                        .text_xs()
                        .cursor_pointer()
                        .text_color(if copied_id {
                            BonTheme::success()
                        } else {
                            BonTheme::text_primary()
                        })
                        .hover(|s| s.text_color(BonTheme::accent()))
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |app, _, _, cx| {
                                cx.stop_propagation();
                                app.copy_profile_id(&pid_id_col, cx);
                            }),
                        )
                        .child(if copied_id {
                            format!("{} {numeric_id}", SfSymbol::CHECKMARK)
                        } else {
                            numeric_id
                        })
                }))
                // Col 2: Name (`🔵 wheel-die`)
                .children(cols.show_name.then(|| {
                    let (dot_border, dot_bg, _) = Profile::accent_color_for_seed(profile.seed);
                    h_flex()
                        .w(px(180.))
                        .min_w(px(96.))
                        .flex_shrink_1()
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
                                .border_color(rgb(dot_border))
                                .bg(rgba(dot_bg)),
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
                        .w(px(88.))
                        .min_w(px(48.))
                        .flex_shrink_1()
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
                        .w(px(96.))
                        .min_w(px(40.))
                        .flex_shrink_1()
                        .gap_1()
                        .items_center()
                        .overflow_hidden()
                        .children(totp_opt.map(|(code, _)| {
                            div()
                                .px_1()
                                .py(px(1.))
                                .rounded_sm()
                                .bg(if copied_totp {
                                    BonTheme::success_bg()
                                } else {
                                    rgba(0xa855f726).into()
                                })
                                .border_1()
                                .border_color(if copied_totp {
                                    BonTheme::success()
                                } else {
                                    rgb(0xc084fc).into()
                                })
                                .text_size(px(10.5))
                                .font_semibold()
                                .text_color(if copied_totp {
                                    BonTheme::success()
                                } else {
                                    rgb(0xc084fc).into()
                                })
                                .hover(|s| s.bg(rgba(0xa855f744)))
                                .on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener(move |app, _, _, cx| {
                                        cx.stop_propagation();
                                        app.copy_profile_totp(&pid_totp, cx);
                                    }),
                                )
                                .child(if copied_totp {
                                    format!("{} {code}", SfSymbol::CHECKMARK)
                                } else if has_note {
                                    "2FA".to_string()
                                } else {
                                    format!("{} {code}", SfSymbol::LOCK_FILL)
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
                        .w(px(136.))
                        .min_w(px(72.))
                        .flex_shrink_1()
                        .truncate()
                        .text_xs()
                        .text_color(
                            match profile.resolved_geo.as_ref().map(|g| g.ip_kind) {
                                Some(IpKind::Hosting) => BonTheme::danger(),
                                Some(IpKind::Residential | IpKind::Mobile) => BonTheme::success(),
                                _ if has_proxy && profile.resolved_geo.is_some() => {
                                    BonTheme::success()
                                }
                                _ if has_proxy => BonTheme::text_primary(),
                                _ => BonTheme::text_muted(),
                            },
                        )
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
                        .w(px(86.))
                        .flex_shrink_0()
                        .truncate()
                        .text_xs()
                        .text_color(BonTheme::text_secondary())
                        .child(updated_label)
                }))
                // Col 7: Status (`Ready` green pill)
                .children(cols.show_status.then(|| {
                    let pid_status_focus = profile_id.clone();
                    let mut badge = h_flex()
                        .max_w_full()
                        .px_2()
                        .py_0p5()
                        .gap_1()
                        .items_center()
                        .overflow_hidden()
                        .rounded_full()
                        .bg(badge_bg)
                        .text_xs()
                        .font_semibold()
                        .text_color(badge_fg)
                        .child(
                            div()
                                .w(px(5.5))
                                .h(px(5.5))
                                .flex_shrink_0()
                                .rounded_full()
                                .bg(badge_fg),
                        )
                        .child(div().min_w_0().truncate().child(state_title));
                    if is_running {
                        badge = badge
                            .cursor_pointer()
                            .hover(|s| s.opacity(0.85))
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(move |app, _, _, cx| {
                                    cx.stop_propagation();
                                    app.focus_profile_browser(&pid_status_focus, cx);
                                }),
                            );
                    }
                    div().w(px(132.)).flex_shrink_0().overflow_hidden().child(
                        h_flex().child(if is_starting {
                            badge
                                .with_animation(
                                    SharedString::from(format!("prof-status-pulse-{profile_id}")),
                                    BonTheme::status_pulse_anim(),
                                    |this, alpha| this.opacity(alpha),
                                )
                                .into_any_element()
                        } else {
                            badge.into_any_element()
                        }),
                    )
                }))
                .child(div().flex_1().min_w_0())
                // Rightmost Action Column: `[Launch/Stop]` + `[⋯]`
                .child(
                    h_flex()
                        .w(px(108.))
                        .flex_shrink_0()
                        .justify_end()
                        .items_center()
                        .gap_1p5()
                        .child(if is_running || is_starting {
                            let pid_stop = profile_id.clone();
                            Button::new(SharedString::from(format!("row-stop-{profile_id}")))
                                .danger()
                                .small()
                                .flex_shrink_0()
                                .label("Stop")
                                .on_click(cx.listener(move |app, _, _, cx| {
                                    app.stop_profile(&pid_stop, cx);
                                }))
                        } else {
                            let pid_launch = profile_id.clone();
                            Button::new(SharedString::from(format!("row-launch-{profile_id}")))
                                .with_variant(BonTheme::launch_cta(cx))
                                .small()
                                .flex_shrink_0()
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
                                .flex_shrink_0()
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
    app: &BonLoginApp,
    cx: &mut Context<BonLoginApp>,
) -> Div {
    let trashed = &app.trashed_profiles;
    let total_trash = trashed.len();
    let (_, _, page_start, page_end) =
        app.current_page_bounds(crate::ui::PaginatedTable::Trash, total_trash);
    let page_count = page_end.saturating_sub(page_start);
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
                        .child(div().w(px(80.)).flex_shrink_0().child("ID"))
                        .child(div().w(px(180.)).flex_shrink_0().truncate().child("Name"))
                        .child(div().w(px(130.)).child("Group / Tags"))
                        .child(div().w(px(150.)).child("Proxy"))
                        .child(div().w(px(140.)).child("Deleted"))
                        .child(div().flex_1().min_w_0())
                        .child(div().w(px(190.)).flex_shrink_0().flex().justify_end().child("Actions")),
                )
                .child(if trashed.is_empty() {
                    v_flex()
                        .id("trash-table-rows")
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
                                .child("Trash is empty"),
                        )
                        .child(
                            div()
                                .text_xs()
                                .text_color(BonTheme::text_secondary())
                                .child("Profiles you delete will appear here so you can restore them anytime."),
                        )
                        .into_any_element()
                } else {
                    uniform_list(
                        "trash-table-rows",
                        page_count,
                        cx.processor(move |app, range: std::ops::Range<usize>, _window, cx| {
                            let mut items = Vec::with_capacity(range.len());
                            for ix in range {
                                let Some(p) = app.trashed_profiles.get(page_start + ix) else {
                                    continue;
                                };
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
                                let short_id = p.short_id();
                                let name = p.name.clone();
                                let deleted_label = p.format_deleted_at();
                                let btn_res_id = SharedString::from(format!("trash-res-{}", p.id));
                                let btn_perm_id = SharedString::from(format!("trash-perm-{}", p.id));
                                items.push(
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
                                                .font_family(BonTheme::font_mono())
                                                .text_xs()
                                                .text_color(BonTheme::text_secondary())
                                                .child(short_id),
                                        )
                                        .child(
                                            div()
                                                .w(px(180.))
                                                .flex_shrink_0()
                                                .truncate()
                                                .text_xs()
                                                .font_semibold()
                                                .text_color(BonTheme::text_primary())
                                                .child(name),
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
                                                .child(deleted_label),
                                        )
                                        .child(div().flex_1().min_w_0())
                                        .child(
                                            h_flex()
                                                .w(px(190.))
                                                .flex_shrink_0()
                                                .justify_end()
                                                .items_center()
                                                .gap_2()
                                                .child(
                                                    Button::new(btn_res_id)
                                                        .with_variant(BonTheme::launch_cta(cx))
                                                        .small()
                                                        .label("↩ Restore")
                                                        .on_click(cx.listener(
                                                            move |app, _, window, cx| {
                                                                app.restore_trashed_profile(
                                                                    &pid_restore,
                                                                    window,
                                                                    cx,
                                                                );
                                                            },
                                                        )),
                                                )
                                                .child(
                                                    Button::new(btn_perm_id)
                                                        .danger()
                                                        .small()
                                                        .label("Delete Forever")
                                                        .on_click(cx.listener(
                                                            move |app, _, _, cx| {
                                                                app.request_delete(
                                                                    PendingDeleteAction::PermanentProfile(
                                                                        pid_perm.clone(),
                                                                    ),
                                                                    cx,
                                                                );
                                                            },
                                                        )),
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
                .child(
                    crate::ui::workspace_views::render_table_pagination_footer(
                        "trash",
                        crate::ui::PaginatedTable::Trash,
                        "Trashed",
                        total_trash,
                        None,
                        app,
                        cx,
                    ),
                ),
        )
}
