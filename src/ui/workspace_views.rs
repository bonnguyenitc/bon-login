use gpui_kit::component::{
    button::{Button, ButtonVariants as _},
    input::Input,
    menu::{DropdownMenu as _, PopupMenuItem},
    *,
};
use gpui_kit::*;
use crate::models::{BrowserBrand, PlatformType, ProxyProtocol};
use crate::ui::theme::{BonTheme, SfSymbol};
use crate::ui::{
    ActivePopupModal, BonLoginApp, PaginatedTable, PendingDeleteAction, ProfileSubTab, ProxySubTab,
    WorkspaceView,
};

static ICON_CACHE: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<Image>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

pub fn invalidate_extension_icon_cache(ext_id: &str) {
    if let Ok(mut guard) = ICON_CACHE.lock() {
        guard.remove(ext_id);
    }
}

fn get_extension_icon(ext: &crate::models::BrowserExtension) -> Option<std::sync::Arc<Image>> {
    if let Ok(guard) = ICON_CACHE.lock()
        && let Some(cached) = guard.get(&ext.id)
    {
        return Some(cached.clone());
    }
    let (is_svg, bytes) = crate::extensions::load_extension_icon_bytes(ext)?;
    let fmt = if is_svg {
        ImageFormat::Svg
    } else {
        ImageFormat::Png
    };
    let image = std::sync::Arc::new(Image::from_bytes(fmt, bytes));
    if let Ok(mut guard) = ICON_CACHE.lock() {
        guard.insert(ext.id.clone(), image.clone());
    }
    Some(image)
}

/// GenLogin 3.0 `Extensions` View (`docs/genlogin-3.0/assets/menu-bar_extensions_01.png`)
pub fn render_extensions_view(
    app: &BonLoginApp,
    cx: &mut Context<BonLoginApp>,
) -> Div {
    let rows = app.extensions.chunks(4);

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
                .children(rows.enumerate().map(|(row_idx, row_exts)| {
                    let missing = 4usize.saturating_sub(row_exts.len());
                    h_flex()
                        .w_full()
                        .gap_3p5()
                        .items_stretch()
                        .children(row_exts.iter().map(|ext| {
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
                                            if let Some(icon_img) = get_extension_icon(ext) {
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
                                                    .child(ext.icon_label.clone())
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
    let proxy_sub_tab = app.proxy_sub_tab;
    let total_proxies = app.saved_proxies.len();
    let free_total = app.free_proxies.len();
    let free_live = app.live_free_proxies_count();

    let subtab_bar = h_flex()
        .w_full()
        .flex_shrink_0()
        .justify_between()
        .items_center()
        .gap_3()
        .child(
            h_flex()
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
                        .child(proxy_subtab_item(
                            "My Proxies",
                            total_proxies,
                            proxy_sub_tab == ProxySubTab::MyProxies,
                            ProxySubTab::MyProxies,
                            cx,
                        ))
                        .child(proxy_subtab_item(
                            "Free Proxies",
                            free_total,
                            proxy_sub_tab == ProxySubTab::FreeProxies,
                            ProxySubTab::FreeProxies,
                            cx,
                        )),
                )
                .children((free_live > 0).then(|| {
                    div()
                        .px_2()
                        .py_0p5()
                        .rounded_sm()
                        .bg(BonTheme::success_bg())
                        .text_xs()
                        .font_semibold()
                        .text_color(BonTheme::success())
                        .child(format!("● {free_live} Live Free Ready"))
                })),
        );

    if proxy_sub_tab == ProxySubTab::FreeProxies {
        return v_flex()
            .w_full()
            .flex_1()
            .min_h_0()
            .gap_3()
            .overflow_hidden()
            .child(subtab_bar)
            .child(render_free_proxies_subtab_view(app, cx));
    }
    let _ = total_proxies;
    let proxy_groups = app.distinct_proxy_groups_with_counts();
    let selected_pgrp = app.selected_proxy_group.clone();
    let filtered_indices = app.filtered_proxy_indices_rc();
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
    let used_counts = app.used_proxy_counts.clone();

    let app_for_tag_menu = cx.entity();
    let groups_for_menu = proxy_groups.clone();

    v_flex()
        .w_full()
        .flex_1()
        .min_h_0()
        .gap_3()
        .overflow_hidden()
        .child(subtab_bar)
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
                                    app.popup_modal = Some(ActivePopupModal::AddTag {
                                        return_to_add_proxy: false,
                                    });
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
                    |this, delta| this.opacity(delta).mt(px((1.0 - delta) * -4.0)),
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
                    let (_, _, page_start, page_end) =
                        app.current_page_bounds(PaginatedTable::MyProxies, filtered_len);
                    let indices_for_list: std::rc::Rc<[usize]> =
                        filtered_indices[page_start..page_end].into();
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
                                let row_num = page_start + row_ix + 1;
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
                                                                BonTheme::status_pulse_anim(),
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
                .child(render_table_pagination_footer(
                    "my-proxies",
                    PaginatedTable::MyProxies,
                    "Proxies",
                    filtered_len,
                    None,
                    app,
                    cx,
                )),
        )
}

fn proxy_subtab_item(
    label: &'static str,
    count: usize,
    active: bool,
    target_tab: ProxySubTab,
    cx: &mut Context<BonLoginApp>,
) -> impl IntoElement {
    h_flex()
        .px_3()
        .py_1()
        .gap_1p5()
        .items_center()
        .cursor_pointer()
        .rounded_md()
        .on_mouse_down(
            MouseButton::Left,
            cx.listener(move |app, _, _, cx| {
                app.switch_proxy_sub_tab(target_tab, cx);
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
            SharedString::from(format!("proxy-subtab-spring-{label}")),
            SpringAnimation::new(BonTheme::snappy_spring()).to(active),
            move |this, phase| {
                this.bg(phase.interpolate_clamped(
                    rgba(0x00000000).into(),
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

fn render_free_proxies_subtab_view(
    app: &BonLoginApp,
    cx: &mut Context<BonLoginApp>,
) -> Div {
    let total_free = app.free_proxies.len();
    let live_count = app.live_free_proxies_count();
    let filtered_indices = app.filtered_free_proxy_indices_rc();
    let filtered_len = filtered_indices.len();
    let checked_count = app.checked_free_keys.len();
    let proto_filter = app.free_proxy_protocol_filter;
    let selected_country = app.free_proxy_country_filter.clone();
    let only_live = app.free_proxy_only_live;
    let is_fetching = app.fetching_free_proxies;
    let is_verifying = app.verifying_free_proxies;
    let countries_with_counts = app.distinct_free_proxy_countries_with_counts();

    let all_filtered_checked = !filtered_indices.is_empty()
        && filtered_indices.iter().all(|&i| {
            app.checked_free_keys
                .contains(&app.free_proxies[i].endpoint_key())
        });
    let any_filtered_checked = filtered_indices.iter().any(|&i| {
        app.checked_free_keys
            .contains(&app.free_proxies[i].endpoint_key())
    });
    let hdr_mark = if all_filtered_checked {
        SfSymbol::CHECKMARK
    } else if any_filtered_checked {
        SfSymbol::MINUS
    } else {
        ""
    };

    let country_dropdown_label = if selected_country == "All" || selected_country.is_empty() {
        format!("All Countries ({total_free})")
    } else {
        let flag = crate::models::GeoInfo::country_flag(&selected_country);
        format!("{flag}  {selected_country} ({filtered_len})")
    };
    let app_for_cc_menu = cx.entity();
    let cc_list_for_menu = countries_with_counts.clone();

    let saved_set: std::rc::Rc<std::collections::HashSet<(ProxyProtocol, String, u16)>> =
        std::rc::Rc::new(
            app.saved_proxies
                .iter()
                .map(|sp| {
                    (
                        sp.config.protocol,
                        sp.config.host.to_ascii_lowercase(),
                        sp.config.port,
                    )
                })
                .collect(),
        );

    v_flex()
        .w_full()
        .flex_1()
        .min_h_0()
        .gap_3()
        .overflow_hidden()
        // 1. Free Proxies Search & Discovery Toolbar
        .child(
            h_flex()
                .w_full()
                .justify_between()
                .items_center()
                .gap_2()
                .flex_wrap()
                .child(
                    h_flex()
                        .gap_2()
                        .items_center()
                        .flex_wrap()
                        .child(
                            div()
                                .w(px(260.))
                                .child(Input::new(&app.free_proxy_search_input)),
                        )
                        .child(
                            h_flex()
                                .gap_1()
                                .items_center()
                                .child(
                                    Button::new("fp-proto-all")
                                        .small()
                                        .with_variant(BonTheme::toggle_pill(
                                            cx,
                                            proto_filter.is_none(),
                                        ))
                                        .label("All")
                                        .on_click(cx.listener(|app, _, _, cx| {
                                            app.free_proxy_protocol_filter = None;
                                            cx.notify();
                                        })),
                                )
                                .child(
                                    Button::new("fp-proto-socks5")
                                        .small()
                                        .with_variant(BonTheme::toggle_pill(
                                            cx,
                                            proto_filter == Some(ProxyProtocol::Socks5),
                                        ))
                                        .label("SOCKS5")
                                        .on_click(cx.listener(|app, _, _, cx| {
                                            app.free_proxy_protocol_filter =
                                                Some(ProxyProtocol::Socks5);
                                            cx.notify();
                                        })),
                                )
                                .child(
                                    Button::new("fp-proto-http")
                                        .small()
                                        .with_variant(BonTheme::toggle_pill(
                                            cx,
                                            proto_filter == Some(ProxyProtocol::Http),
                                        ))
                                        .label("HTTP/SSL")
                                        .on_click(cx.listener(|app, _, _, cx| {
                                            app.free_proxy_protocol_filter =
                                                Some(ProxyProtocol::Http);
                                            cx.notify();
                                        })),
                                ),
                        )
                        .child(
                            Button::new("fp-country-dropdown")
                                .min_w(px(148.))
                                .outline()
                                .dropdown_caret(true)
                                .small()
                                .label(country_dropdown_label)
                                .dropdown_menu(move |mut menu, _, _| {
                                    let app_all = app_for_cc_menu.clone();
                                    menu = menu.item(
                                        PopupMenuItem::new(format!(
                                            "{}   All Countries ({total_free})",
                                            SfSymbol::GLOBE
                                        ))
                                        .on_click(move |_, _, cx| {
                                            app_all.update(cx, |app, cx| {
                                                app.free_proxy_country_filter = "All".to_string();
                                                cx.notify();
                                            });
                                        }),
                                    );
                                    for (cc, cnt) in cc_list_for_menu.iter().take(28) {
                                        let cc_val = cc.clone();
                                        let app_cc = app_for_cc_menu.clone();
                                        let flag = crate::models::GeoInfo::country_flag(&cc_val);
                                        menu = menu.item(
                                            PopupMenuItem::new(format!("{flag}   {cc_val} ({cnt})"))
                                                .on_click(move |_, _, cx| {
                                                    let c = cc_val.clone();
                                                    app_cc.update(cx, |app, cx| {
                                                        app.free_proxy_country_filter = c;
                                                        cx.notify();
                                                    });
                                                }),
                                        );
                                    }
                                    menu
                                }),
                        )
                        .child(
                            Button::new("fp-only-live-toggle")
                                .small()
                                .with_variant(BonTheme::toggle_pill(cx, only_live))
                                .label(format!(
                                    "{}  Live Only ({live_count})",
                                    SfSymbol::CHECKMARK
                                ))
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.free_proxy_only_live = !app.free_proxy_only_live;
                                    cx.notify();
                                })),
                        ),
                )
                .child(
                    h_flex()
                        .gap_2()
                        .items_center()
                        .child(
                            Button::new("fp-fetch-feeds")
                                .with_variant(BonTheme::row_action(cx))
                                .small()
                                .disabled(is_fetching)
                                .label(if is_fetching {
                                    "Fetching...".to_string()
                                } else {
                                    format!("{}  Refresh Sources", SfSymbol::ARROW_CLOCKWISE)
                                })
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.fetch_free_proxies(cx);
                                })),
                        )
                        .child(if is_verifying {
                            Button::new("fp-stop-scan")
                                .with_variant(BonTheme::outline_danger(cx))
                                .small()
                                .label(format!("{}  Stop Scan", SfSymbol::STOP_FILL))
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.stop_verifying_free_proxies(cx);
                                }))
                        } else {
                            Button::new("fp-scan-live")
                                .with_variant(BonTheme::outline_blue(cx))
                                .small()
                                .disabled(filtered_indices.is_empty() || is_fetching)
                                .label(if checked_count > 0 {
                                    format!("{}  Scan Selected ({checked_count})", SfSymbol::BOLT_FILL)
                                } else {
                                    format!("{}  Scan Live (24)", SfSymbol::BOLT_FILL)
                                })
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.verify_filtered_free_proxies(24, cx);
                                }))
                        })
                        .child(
                            Button::new("fp-save-live-or-sel")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .disabled(checked_count == 0 && live_count == 0)
                                .label(if checked_count > 0 {
                                    format!("{}  Save Selected ({checked_count})", SfSymbol::PLUS)
                                } else {
                                    format!("{}  Save Live ({live_count})", SfSymbol::PLUS)
                                })
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.save_selected_or_live_free_proxies(cx);
                                })),
                        ),
                ),
        )
        // 2. Selection Action Bar when 1+ free proxies checked
        .children((checked_count > 0).then(|| {
            h_flex()
                .w_full()
                .gap_2()
                .items_center()
                .child(
                    Button::new("fp-clear-sel")
                        .with_variant(BonTheme::outline_blue(cx))
                        .small()
                        .label(SfSymbol::XMARK)
                        .on_click(cx.listener(|app, _, _, cx| {
                            app.clear_checked_free_proxies(cx);
                        })),
                )
                .child(
                    Button::new("fp-batch-check")
                        .with_variant(BonTheme::outline_blue(cx))
                        .small()
                        .label("Check Selected")
                        .on_click(cx.listener(|app, _, _, cx| {
                            app.verify_filtered_free_proxies(40, cx);
                        })),
                )
                .child(
                    Button::new("fp-batch-save")
                        .with_variant(BonTheme::success_cta(cx))
                        .small()
                        .label("Save to My Proxies (#free)")
                        .on_click(cx.listener(|app, _, _, cx| {
                            app.save_selected_or_live_free_proxies(cx);
                        })),
                )
                .child(
                    Button::new("fp-batch-copy")
                        .with_variant(BonTheme::primary_cta(cx))
                        .small()
                        .label("Copy")
                        .on_click(cx.listener(|app, _, _, cx| {
                            app.copy_checked_free_proxies(cx);
                        })),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(BonTheme::text_secondary())
                        .child(format!("{checked_count} selected")),
                )
                .with_animation(
                    "fp-batch-bar-enter",
                    BonTheme::ui_enter_anim(),
                    |this, delta| this.opacity(delta).mt(px((1.0 - delta) * -4.0)),
                )
        }))
        // 3. Free Proxies Table (`[☐] | # | Proxy (IP:Port) | Protocol | Country / ISP | Source | Status | Actions`)
        .child(
            v_flex()
                .w_full()
                .flex_1()
                .rounded_lg()
                .bg(BonTheme::bg_panel())
                .border_1()
                .border_color(BonTheme::border())
                .overflow_hidden()
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
                        .child(BonTheme::checkbox(
                            "fp-hdr-chk-spring",
                            all_filtered_checked || any_filtered_checked,
                            hdr_mark,
                            BonTheme::bg_panel(),
                            cx.listener(|app, _, _, cx| {
                                app.toggle_all_filtered_free_proxies_checked(cx);
                            }),
                        ))
                        .child(div().w(px(28.)).flex_shrink_0().truncate().child("#"))
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(150.))
                                .truncate()
                                .child("Proxy Endpoint"),
                        )
                        .child(div().w(px(90.)).flex_shrink_0().truncate().child("Protocol"))
                        .child(
                            div()
                                .w(px(190.))
                                .flex_shrink_0()
                                .truncate()
                                .child("Country / Location"),
                        )
                        .child(div().w(px(96.)).flex_shrink_0().truncate().child("Source"))
                        .child(div().w(px(108.)).flex_shrink_0().truncate().child("Status"))
                        .child(
                            div()
                                .w(px(148.))
                                .flex_shrink_0()
                                .flex()
                                .justify_end()
                                .child(SfSymbol::GEARSHAPE_FILL),
                        ),
                )
                .child(if filtered_indices.is_empty() {
                    v_flex()
                        .id("free-proxies-empty")
                        .w_full()
                        .flex_1()
                        .min_h_0()
                        .py_16()
                        .items_center()
                        .justify_center()
                        .gap_2p5()
                        .child(
                            div()
                                .text_sm()
                                .font_semibold()
                                .text_color(BonTheme::text_primary())
                                .child(if is_fetching {
                                    "Fetching public free proxy feeds (ProxyScrape, Proxifly, Fyvri)..."
                                } else if only_live {
                                    "No verified live free proxies match your filter yet"
                                } else {
                                    "No free proxies match your filter"
                                }),
                        )
                        .child(
                            div()
                                .text_xs()
                                .text_color(BonTheme::text_secondary())
                                .child(if only_live {
                                    "Click 'Scan Live (24)' to test candidates through BonLogin's Fail-Closed GeoIP tunnel."
                                } else {
                                    "Click 'Refresh Sources' to pull the latest SOCKS5 & HTTPS public proxies."
                                }),
                        )
                        .children((!is_fetching).then(|| {
                            Button::new("fp-empty-action")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .label(if only_live && total_free > 0 {
                                    format!("{}  Disable 'Live Only' & Scan", SfSymbol::BOLT_FILL)
                                } else {
                                    format!("{}  Fetch Free Proxies", SfSymbol::ARROW_CLOCKWISE)
                                })
                                .on_click(cx.listener(move |app, _, _, cx| {
                                    if only_live && total_free > 0 {
                                        app.free_proxy_only_live = false;
                                        app.verify_filtered_free_proxies(24, cx);
                                    } else {
                                        app.fetch_free_proxies(cx);
                                    }
                                }))
                        }))
                        .into_any_element()
                } else {
                    let (_, _, page_start, page_end) =
                        app.current_page_bounds(PaginatedTable::FreeProxies, filtered_len);
                    let indices_for_list: std::rc::Rc<[usize]> =
                        filtered_indices[page_start..page_end].into();
                    let saved_set_for_list = saved_set.clone();
                    uniform_list(
                        "free-proxies-table-rows",
                        indices_for_list.len(),
                        cx.processor(move |app, range: std::ops::Range<usize>, _window, cx| {
                            let app_entity = cx.entity();
                            let mut items = Vec::with_capacity(range.len());
                            for row_ix in range {
                                let Some(&fp_ix) = indices_for_list.get(row_ix) else {
                                    continue;
                                };
                                let Some(fp) = app.free_proxies.get(fp_ix) else {
                                    continue;
                                };
                                let row_num = page_start + row_ix + 1;
                                let key = fp.endpoint_key();
                                let key_chk = key.clone();
                                let key_chk_id = key.clone();
                                let key_pulse_id = key.clone();
                                let key_check_btn = key.clone();
                                let key_save_btn = key.clone();
                                let key_menu_save = key.clone();
                                let key_menu_assign = key.clone();
                                let copy_val = fp.config.to_editable_string();
                                let is_checked = app.checked_free_keys.contains(&key);
                                let is_checking = app.checking_free_keys.contains(&key);
                                let is_already_saved = saved_set_for_list.contains(&(
                                    fp.config.protocol,
                                    fp.config.host.to_ascii_lowercase(),
                                    fp.config.port,
                                ));

                                let cc = fp.effective_country().to_string();
                                let flag = if cc.is_empty() {
                                    SfSymbol::GLOBE
                                } else {
                                    crate::models::GeoInfo::country_flag(&cc)
                                };
                                let endpoint_str = fp.config.display_short();
                                let sub_meta = match (fp.anonymity.as_str(), fp.uptime_pct) {
                                    (anon, Some(up)) if !anon.is_empty() => {
                                        format!("{anon} • {up}% uptime")
                                    }
                                    (anon, None) if !anon.is_empty() => anon.to_string(),
                                    _ => "public proxy".to_string(),
                                };
                                let proto_label = match fp.config.protocol {
                                    ProxyProtocol::Socks5 => "SOCKS5".to_string(),
                                    ProxyProtocol::Http => "HTTP • SSL".to_string(),
                                };
                                let loc_primary = if cc.is_empty() {
                                    "Unknown".to_string()
                                } else if !fp.city.is_empty() {
                                    format!("{cc} • {}", fp.city)
                                } else if let Some(g) = &fp.verified_geo {
                                    let short_tz =
                                        g.timezone.rsplit('/').next().unwrap_or(&g.timezone);
                                    format!("{cc} • {short_tz}")
                                } else {
                                    cc.clone()
                                };
                                let loc_sub = if !fp.isp.is_empty() {
                                    fp.isp.clone()
                                } else if !fp.timezone.is_empty() {
                                    fp.timezone.clone()
                                } else {
                                    "-".to_string()
                                };

                                let (badge_bg, badge_fg, status_text) = if is_checking {
                                    (
                                        BonTheme::info_bg(),
                                        BonTheme::info(),
                                        "CHECKING...".to_string(),
                                    )
                                } else if let Some(g) = &fp.verified_geo {
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
                                } else if fp.last_error.is_some() {
                                    (
                                        BonTheme::danger_bg(),
                                        BonTheme::danger(),
                                        "DEAD".to_string(),
                                    )
                                } else if let Some(ms) = fp.reported_latency_ms {
                                    (
                                        BonTheme::bg_elevated(),
                                        BonTheme::text_secondary(),
                                        format!("~{ms}ms"),
                                    )
                                } else {
                                    (
                                        BonTheme::bg_elevated(),
                                        BonTheme::text_muted(),
                                        "UNCHECKED".to_string(),
                                    )
                                };

                                let src_str = fp.source.clone();
                                let app_row_menu = app_entity.clone();
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
                                            format!("fp-row-chk-spring-{key_chk_id}"),
                                            is_checked,
                                            if is_checked { SfSymbol::CHECKMARK } else { "" },
                                            BonTheme::bg_elevated(),
                                            cx.listener(move |app, _, _, cx| {
                                                app.toggle_free_proxy_checked(&key_chk, cx);
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
                                                .min_w(px(150.))
                                                .overflow_hidden()
                                                .gap_0p5()
                                                .child(
                                                    div()
                                                        .w_full()
                                                        .truncate()
                                                        .text_sm()
                                                        .font_semibold()
                                                        .text_color(BonTheme::text_primary())
                                                        .child(endpoint_str),
                                                )
                                                .child(
                                                    div()
                                                        .w_full()
                                                        .truncate()
                                                        .text_xs()
                                                        .text_color(BonTheme::text_secondary())
                                                        .child(sub_meta),
                                                ),
                                        )
                                        .child(
                                            div()
                                                .w(px(90.))
                                                .flex_shrink_0()
                                                .truncate()
                                                .text_xs()
                                                .font_semibold()
                                                .text_color(if fp.config.protocol == ProxyProtocol::Socks5 {
                                                    BonTheme::info()
                                                } else {
                                                    BonTheme::text_primary()
                                                })
                                                .child(proto_label),
                                        )
                                        .child(
                                            v_flex()
                                                .w(px(190.))
                                                .flex_shrink_0()
                                                .overflow_hidden()
                                                .gap_0p5()
                                                .child(
                                                    h_flex()
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
                                                                .truncate()
                                                                .text_xs()
                                                                .font_semibold()
                                                                .text_color(BonTheme::text_primary())
                                                                .child(loc_primary),
                                                        ),
                                                )
                                                .child(
                                                    div()
                                                        .truncate()
                                                        .text_xs()
                                                        .text_color(BonTheme::text_muted())
                                                        .child(loc_sub),
                                                ),
                                        )
                                        .child(
                                            div()
                                                .w(px(96.))
                                                .flex_shrink_0()
                                                .overflow_hidden()
                                                .child(
                                                    h_flex().child(
                                                        div()
                                                            .truncate()
                                                            .px_1p5()
                                                            .py_0p5()
                                                            .rounded_sm()
                                                            .bg(BonTheme::accent_subtle())
                                                            .text_xs()
                                                            .text_color(BonTheme::accent())
                                                            .child(src_str),
                                                    ),
                                                ),
                                        )
                                        .child(
                                            div()
                                                .w(px(108.))
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
                                                                    "fp-chk-pulse-{key_pulse_id}"
                                                                )),
                                                                BonTheme::status_pulse_anim(),
                                                                |this, alpha| this.opacity(alpha),
                                                            )
                                                            .into_any_element()
                                                    } else {
                                                        badge.into_any_element()
                                                    })
                                                }),
                                        )
                                        .child(
                                            h_flex()
                                                .w(px(148.))
                                                .flex_shrink_0()
                                                .justify_end()
                                                .items_center()
                                                .gap_1p5()
                                                .child(
                                                    Button::new(SharedString::from(format!(
                                                        "fp-chk-{row_num}"
                                                    )))
                                                    .with_variant(BonTheme::outline_blue(cx))
                                                    .small()
                                                    .disabled(is_checking)
                                                    .label(if is_checking { "..." } else { "Check" })
                                                    .on_click(cx.listener(move |app, _, _, cx| {
                                                        app.check_single_free_proxy(
                                                            &key_check_btn,
                                                            cx,
                                                        );
                                                    })),
                                                )
                                                .child(
                                                    Button::new(SharedString::from(format!(
                                                        "fp-save-{row_num}"
                                                    )))
                                                    .with_variant(if is_already_saved {
                                                        BonTheme::row_action(cx)
                                                    } else {
                                                        BonTheme::success_cta(cx)
                                                    })
                                                    .small()
                                                    .disabled(is_already_saved)
                                                    .label(if is_already_saved {
                                                        "Saved"
                                                    } else {
                                                        "+ Save"
                                                    })
                                                    .on_click(cx.listener(move |app, _, _, cx| {
                                                        app.save_free_proxy_to_my_proxies(
                                                            &key_save_btn,
                                                            cx,
                                                        );
                                                    })),
                                                )
                                                .child(
                                                    Button::new(SharedString::from(format!(
                                                        "fp-more-{row_num}"
                                                    )))
                                                    .ghost()
                                                    .small()
                                                    .label(SfSymbol::ELLIPSIS)
                                                    .dropdown_menu(move |menu, _, _| {
                                                        let c_val = copy_val.clone();
                                                        let app_c = app_row_menu.clone();
                                                        let s_key = key_menu_save.clone();
                                                        let app_s = app_row_menu.clone();
                                                        let a_key = key_menu_assign.clone();
                                                        let app_a = app_row_menu.clone();
                                                        menu.item(
                                                            PopupMenuItem::new(format!(
                                                                "{}   Save to My Proxies (#free)",
                                                                SfSymbol::PLUS
                                                            ))
                                                            .on_click(move |_, _, cx| {
                                                                let k = s_key.clone();
                                                                app_s.update(cx, |app, cx| {
                                                                    app.save_free_proxy_to_my_proxies(
                                                                        &k, cx,
                                                                    );
                                                                });
                                                            }),
                                                        )
                                                        .item(
                                                            PopupMenuItem::new(format!(
                                                                "{}   Assign to selected profile",
                                                                SfSymbol::LINK
                                                            ))
                                                            .on_click(move |_, window, cx| {
                                                                let k = a_key.clone();
                                                                app_a.update(cx, |app, cx| {
                                                                    app.apply_free_proxy_to_selected_profile(
                                                                        &k, window, cx,
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
                                                                let v = c_val.clone();
                                                                app_c.update(cx, |app, cx| {
                                                                    cx.write_to_clipboard(
                                                                        ClipboardItem::new_string(
                                                                            v,
                                                                        ),
                                                                    );
                                                                    app.banner_message = Some(
                                                                        "Copied free proxy to clipboard"
                                                                            .to_string(),
                                                                    );
                                                                    cx.notify();
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
                .child(render_table_pagination_footer(
                    "free-proxies",
                    PaginatedTable::FreeProxies,
                    "Free Proxies",
                    filtered_len,
                    Some(format!(
                        "Live: {live_count}  •  Sources: ProxyScrape v4, Fyvri SOCKS5, Proxifly"
                    )),
                    app,
                    cx,
                )),
        )
}

pub(crate) fn field_label(text: &'static str) -> Div {
    div()
        .text_xs()
        .text_color(BonTheme::text_secondary())
        .child(text)
}

pub fn render_table_pagination_footer(
    id_prefix: &'static str,
    table: PaginatedTable,
    item_label: &str,
    total_items: usize,
    extra_left_info: Option<String>,
    app: &BonLoginApp,
    cx: &mut Context<BonLoginApp>,
) -> Div {
    let (cur_page, total_pages, start_ix, end_ix) = app.current_page_bounds(table, total_items);
    let page_size = app.page_size;
    let summary_str = if total_items == 0 {
        format!("{item_label}: 0")
    } else {
        format!(
            "{item_label}: {total_items}  (Showing {}–{end_ix})",
            start_ix + 1
        )
    };
    let win_start = cur_page
        .saturating_sub(2)
        .min(total_pages.saturating_sub(5));
    let win_end = (win_start + 5).min(total_pages);
    let app_for_size = cx.entity();

    h_flex()
        .w_full()
        .px_4()
        .py_2()
        .justify_between()
        .items_center()
        .gap_3()
        .bg(BonTheme::bg_elevated())
        .border_t_1()
        .border_color(BonTheme::border())
        .text_xs()
        .text_color(BonTheme::text_secondary())
        .child(
            h_flex()
                .gap_2p5()
                .items_center()
                .overflow_hidden()
                .child(
                    div()
                        .font_semibold()
                        .text_color(BonTheme::text_primary())
                        .child(summary_str),
                )
                .children(extra_left_info.map(|info| {
                    div()
                        .truncate()
                        .text_color(BonTheme::text_secondary())
                        .child(format!("•  {info}"))
                })),
        )
        .child(
            h_flex()
                .flex_shrink_0()
                .gap_2()
                .items_center()
                .child(
                    Button::new(SharedString::from(format!("{id_prefix}-pg-size")))
                        .outline()
                        .dropdown_caret(true)
                        .xsmall()
                        .label(format!("{page_size} / page"))
                        .dropdown_menu(move |mut menu, _, _| {
                            for sz in [10usize, 25, 50, 100] {
                                let app_sz = app_for_size.clone();
                                menu = menu.item(
                                    PopupMenuItem::new(format!("{sz} / page"))
                                        .checked(page_size == sz)
                                        .on_click(move |_, _, cx| {
                                            app_sz.update(cx, |app, cx| {
                                                app.set_table_page_size(sz, cx);
                                            });
                                        }),
                                );
                            }
                            menu
                        }),
                )
                .child(
                    h_flex()
                        .gap_1()
                        .items_center()
                        .child(
                            Button::new(SharedString::from(format!("{id_prefix}-pg-first")))
                                .with_variant(BonTheme::row_action(cx))
                                .xsmall()
                                .disabled(cur_page == 0)
                                .label("«")
                                .on_click(cx.listener(move |app, _, _, cx| {
                                    app.set_table_page(table, 0, cx);
                                })),
                        )
                        .child(
                            Button::new(SharedString::from(format!("{id_prefix}-pg-prev")))
                                .with_variant(BonTheme::row_action(cx))
                                .xsmall()
                                .disabled(cur_page == 0)
                                .label("‹ Prev")
                                .on_click(cx.listener(move |app, _, _, cx| {
                                    app.set_table_page(table, cur_page.saturating_sub(1), cx);
                                })),
                        )
                        .children((win_start..win_end).map(|p| {
                            let is_cur = p == cur_page;
                            Button::new(SharedString::from(format!("{id_prefix}-pg-num-{p}")))
                                .with_variant(if is_cur {
                                    BonTheme::primary_cta(cx)
                                } else {
                                    BonTheme::row_action(cx)
                                })
                                .xsmall()
                                .label(format!("{}", p + 1))
                                .on_click(cx.listener(move |app, _, _, cx| {
                                    app.set_table_page(table, p, cx);
                                }))
                        }))
                        .child(
                            div()
                                .px_1()
                                .text_color(BonTheme::text_muted())
                                .child(format!("/ {total_pages}")),
                        )
                        .child(
                            Button::new(SharedString::from(format!("{id_prefix}-pg-next")))
                                .with_variant(BonTheme::row_action(cx))
                                .xsmall()
                                .disabled(cur_page + 1 >= total_pages)
                                .label("Next ›")
                                .on_click(cx.listener(move |app, _, _, cx| {
                                    app.set_table_page(
                                        table,
                                        (cur_page + 1).min(total_pages - 1),
                                        cx,
                                    );
                                })),
                        )
                        .child(
                            Button::new(SharedString::from(format!("{id_prefix}-pg-last")))
                                .with_variant(BonTheme::row_action(cx))
                                .xsmall()
                                .disabled(cur_page + 1 >= total_pages)
                                .label("»")
                                .on_click(cx.listener(move |app, _, _, cx| {
                                    app.set_table_page(table, total_pages - 1, cx);
                                })),
                        ),
                ),
        )
}

pub(crate) fn render_batch_group_dropdown(
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

pub(crate) fn render_batch_browser_os_selector(
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

pub(crate) fn render_proxy_pool_selector(app: &BonLoginApp, cx: &mut Context<BonLoginApp>) -> Div {
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
    let q = app.search_query.trim();
    let groups: Vec<(String, usize)> = app
        .distinct_groups_with_counts()
        .into_iter()
        .filter(|(grp, _)| q.is_empty() || crate::models::contains_ignore_ascii_case(grp, q))
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
