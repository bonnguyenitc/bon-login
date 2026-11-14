use gpui_kit::component::{
    button::{Button, ButtonVariants as _},
    input::{Input, InputState, Textarea, TextareaState},
    menu::{DropdownMenu as _, PopupMenuItem},
    *,
};
use gpui_kit::*;
use crate::models::{Profile, ProxyProtocol};
use crate::ui::theme::{BonTheme, SfSymbol};
use crate::ui::workspace_views::{
    field_label, render_batch_browser_os_selector, render_batch_group_dropdown,
    render_proxy_pool_selector,
};
use crate::ui::{ActivePopupModal, BonLoginApp, PendingDeleteAction};

#[derive(Clone)]
pub struct CloneProfileModalState {
    pub target_id: String,
    pub count_input: Entity<InputState>,
    pub prefix_input: Entity<InputState>,
}

#[derive(Clone)]
pub struct EditProxyModalState {
    pub proxy_id: String,
    pub selected_tag: String,
    pub name_input: Entity<InputState>,
    pub rotate_input: Entity<InputState>,
    pub expire_input: Entity<InputState>,
}

#[derive(Clone)]
pub struct QuickMetaModalState {
    pub profile_id: Option<String>,
    pub tags: Vec<String>,
    pub tag_input: Entity<InputState>,
    pub note_input: Entity<TextareaState>,
    pub totp_input: Entity<InputState>,
    pub bookmarks: Vec<(String, String)>,
    pub bm_name_input: Entity<InputState>,
    pub bm_url_input: Entity<InputState>,
}

#[derive(Clone)]
pub struct CookieRobotModalState {
    pub target_id: Option<String>,
    pub urls_input: Entity<TextareaState>,
    pub dwell_secs: u64,
}

#[derive(Clone)]
pub struct ImportBackupZipModalState {
    pub zip_input: Entity<InputState>,
}

#[derive(Clone)]
pub struct AgentFlowsModalState {
    pub target_id: Option<String>,
    pub expanded_flow_name: Option<String>,
    pub save_name_input: Entity<InputState>,
    pub vars_input: Entity<InputState>,
    pub csv_input: Entity<InputState>,
    pub concurrency: usize,
}

#[derive(Clone)]
pub struct SynchronizerModalState {
    pub master_id: Option<String>,
    pub follower_ids: std::collections::HashSet<String>,
    pub auto_tile: bool,
}

/// Renders the active Popup Modal overlay
pub fn render_popup_modal(
    modal_kind: ActivePopupModal,
    app: &BonLoginApp,
    cx: &mut Context<BonLoginApp>,
) -> AnyElement {
    let anim_key = modal_kind.anim_key();
    let card = match modal_kind {
        // 1. `Quickly add profiles`
        ActivePopupModal::QuickAdd => {
            v_flex()
                .w(px(520.))
                .p_5()
                .gap_3p5()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border())
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
                                    app.close_popup_modal(cx);
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
                                    app.close_popup_modal(cx);
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

        // 2. `Column Settings`
        ActivePopupModal::ColumnSettings => {
            let cols = app.col_vis;
            v_flex()
                .w(px(400.))
                .p_5()
                .gap_4()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border())
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
                        .justify_between()
                        .items_center()
                        .gap_2()
                        .child(
                            Button::new("cs-reset-default")
                                .with_variant(BonTheme::row_action(cx))
                                .small()
                                .label("Reset Default")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.col_vis =
                                        crate::ui::profile_list::ColumnVisibility::default();
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("cs-apply")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .label("Done")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.close_popup_modal(cx);
                                })),
                        ),
                )
        }

        // 3. `Assign to group`
        ActivePopupModal::AssignGroup => {
            let groups = app.distinct_groups_with_counts();
            v_flex()
                .w(px(380.))
                .p_5()
                .gap_3p5()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border())
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
                                    app.close_popup_modal(cx);
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
                                    app.close_popup_modal(cx);
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

        // 4. `Add group`
        ActivePopupModal::AddGroup => v_flex()
            .w(px(380.))
            .p_5()
            .gap_3p5()
            .rounded_lg()
            .bg(BonTheme::bg_elevated())
            .border_1()
            .border_color(BonTheme::border())
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
                h_flex()
                    .w_full()
                    .pt_2()
                    .border_t_1()
                    .border_color(BonTheme::border())
                    .justify_end()
                    .gap_2()
                    .child(
                        Button::new("addg-cancel")
                            .with_variant(BonTheme::row_action(cx))
                            .small()
                            .label("Cancel")
                            .on_click(cx.listener(|app, _, _, cx| {
                                app.close_popup_modal(cx);
                            })),
                    )
                    .child(
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
        ActivePopupModal::AddTag { return_to_add_proxy } => v_flex()
            .w(px(380.))
            .p_5()
            .gap_3p5()
            .rounded_lg()
            .bg(BonTheme::bg_elevated())
            .border_1()
            .border_color(BonTheme::border())
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
                    .child(Input::new(&app.new_tag_input)),
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
                        Button::new("addt-cancel")
                            .with_variant(BonTheme::row_action(cx))
                            .small()
                            .label("Cancel")
                            .on_click(cx.listener(|app, _, _, cx| {
                                app.close_popup_modal(cx);
                            })),
                    )
                    .child(
                        Button::new("addt-submit")
                            .with_variant(BonTheme::primary_cta(cx))
                            .small()
                            .label("Add")
                            .on_click(cx.listener(move |app, _, window, cx| {
                                if app.create_tag_from_modal(window, cx) {
                                    app.popup_modal =
                                        return_to_add_proxy.then_some(ActivePopupModal::AddProxy);
                                    cx.notify();
                                }
                            })),
                    ),
            ),
        // 5. `Update proxy`
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
                .border_color(BonTheme::border())
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
                                    app.close_popup_modal(cx);
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
                                    app.close_popup_modal(cx);
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

        // 6. `Update profiles`
        ActivePopupModal::UpdateProfiles => {
            v_flex()
                .w(px(560.))
                .p_5()
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
                                    app.close_popup_modal(cx);
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
                                    app.close_popup_modal(cx);
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

        // 7. `Add Proxy`
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
                .border_color(BonTheme::border())
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
                                    app.close_popup_modal(cx);
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
                                            app.popup_modal = Some(ActivePopupModal::AddTag {
                                                return_to_add_proxy: true,
                                            });
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
                                    app.close_popup_modal(cx);
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
            .border_color(BonTheme::border())
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
        // 10. `Input URL Extension` Modal
        ActivePopupModal::InputUrlExtension => {
            let busy = app.downloading_ext;
            v_flex()
                .w(px(480.))
                .p_5()
                .gap_4()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border())
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
        ActivePopupModal::ConfirmDelete(action) => {
            let (title, desc, confirm_label) = match &action {
                PendingDeleteAction::Profile(id) => {
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
                PendingDeleteAction::CheckedProfiles => (
                    "Move selected profiles to Trash?",
                    format!(
                        "Move {} selected profile(s) to Trash? You can restore them anytime from the Trash tab.",
                        app.checked_profile_ids.len()
                    ),
                    "Move to Trash",
                ),
                PendingDeleteAction::PermanentProfile(id) => {
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
                PendingDeleteAction::EmptyTrash => (
                    "Empty Trash?",
                    format!(
                        "Permanently delete all {} profile(s) in Trash and erase their browser data?",
                        app.trashed_profiles.len()
                    ),
                    "Empty Trash",
                ),
                PendingDeleteAction::Group(g) => (
                    "Delete group?",
                    format!("Are you sure you want to delete group '{g}'?"),
                    "Yes, delete",
                ),
                PendingDeleteAction::Proxy(id) => {
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
                PendingDeleteAction::CheckedProxies => (
                    "Delete selected proxies?",
                    format!(
                        "Are you sure you want to delete {} selected proxy(s)?",
                        app.checked_proxy_ids.len()
                    ),
                    "Yes, delete",
                ),
                PendingDeleteAction::Tag(t) => (
                    "Delete proxy tag?",
                    format!("Are you sure you want to delete tag '#{t}'?"),
                    "Yes, delete",
                ),
                PendingDeleteAction::Extension(id) => {
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
                PendingDeleteAction::WipeProfile(id) => {
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
                PendingDeleteAction::CleanProfileCache(id) => {
                    let name = app
                        .profiles
                        .iter()
                        .find(|p| &p.id == id)
                        .map(|p| p.name.clone())
                        .unwrap_or_else(|| "this profile".to_string());
                    (
                        "Clean profile cache?",
                        format!(
                            "Clean disk & shader cache for '{name}'? Cookies & login sessions are kept."
                        ),
                        "Yes, clean cache",
                    )
                }
                PendingDeleteAction::CleanCheckedCache => {
                    let stopped_count = app
                        .checked_profile_ids
                        .iter()
                        .filter(|id| {
                            !matches!(
                                app.statuses.get(*id),
                                Some(super::ProfileStatus::Running(_) | super::ProfileStatus::Starting)
                            )
                        })
                        .count();
                    (
                        "Clean cache for selected profiles?",
                        format!(
                            "Clean disk & shader cache for {stopped_count} selected profile(s)? Cookies & sessions are kept."
                        ),
                        "Yes, clean cache",
                    )
                }
            };
            v_flex()
                .w(px(420.))
                .p_5()
                .gap_4()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border())
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
                                    app.close_popup_modal(cx);
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
            let disp_rects = crate::launcher::macos_active_display_rects();
            let disp_list: Vec<(usize, i32, i32)> = disp_rects
                .into_iter()
                .enumerate()
                .map(|(i, (_, _, w, h))| (i, w, h))
                .collect();
            let sel_idx = app.arrange_display_idx.min(disp_list.len().saturating_sub(1));
            let (_, mon_w, mon_h) = disp_list.get(sel_idx).copied().unwrap_or((0, 1440, 900));
            let usable_w = mon_w.max(500);
            let usable_h = mon_h.max(360);
            let target_count = app.running_targets_for_arrange().len();
            let presets =
                BonLoginApp::arrange_presets_for_monitor(mon_w, mon_h, target_count);
            let cur_size_raw = app.arrange_size_input.read(cx).value().to_string();
            let active_preset_idx = app
                .arrange_preset_idx
                .filter(|&idx| {
                    presets
                        .get(idx)
                        .is_some_and(|(_, pw, ph)| format!("{pw},{ph}") == cur_size_raw.trim())
                })
                .or_else(|| {
                    presets
                        .iter()
                        .position(|(_, pw, ph)| format!("{pw},{ph}") == cur_size_raw.trim())
                });
            let fit_hint = if let Some((w, h)) = crate::launcher::parse_window_size(&cur_size_raw) {
                let (cols, rows, cw, ch) = crate::launcher::compute_tile_grid_dims(
                    usable_w,
                    usable_h,
                    w,
                    h,
                    target_count.max(1),
                );
                format!(
                    "Fits {cols} col(s) × {rows} row(s) ({cw}×{ch}px each) on Display {} ({mon_w}×{mon_h})",
                    sel_idx + 1
                )
            } else {
                "Enter Width,Height (min 200×200, e.g. 486,474)".to_string()
            };

            v_flex()
                .w(px(500.))
                .p_5()
                .gap_3p5()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border())
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
                                    app.close_popup_modal(cx);
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
                                        .on_click(cx.listener(move |app, _, window, cx| {
                                            app.arrange_display_idx = idx;
                                            let count = app.running_targets_for_arrange().len();
                                            let disp_presets =
                                                BonLoginApp::arrange_presets_for_monitor(
                                                    dw, dh, count,
                                                );
                                            if let Some(p_idx) = app.arrange_preset_idx
                                                && let Some((_, pw, ph)) = disp_presets.get(p_idx)
                                            {
                                                app.set_arrange_size_text(
                                                    format!("{pw},{ph}"),
                                                    window,
                                                    cx,
                                                );
                                            }
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
                                    let active = active_preset_idx == Some(i);
                                    Button::new(SharedString::from(format!("arr-preset-{i}")))
                                        .with_variant(BonTheme::toggle_pill(cx, active))
                                        .small()
                                        .label(format!("{lbl} ({pw}×{ph})"))
                                        .on_click(cx.listener(move |app, _, window, cx| {
                                            app.arrange_preset_idx = Some(i);
                                            app.set_arrange_size_text(val_str.clone(), window, cx);
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
                                    app.close_popup_modal(cx);
                                })),
                        )
                        .child(
                            Button::new("arr-apply")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .label(if target_count > 0 {
                                    format!("Apply to {target_count} open browser(s)")
                                } else {
                                    "Save preset".to_string()
                                })
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.arrange_open_browsers(cx);
                                })),
                        ),
                )
        }

        ActivePopupModal::QuickMeta(qm) => {
            let target_title = if let Some(pid) = &qm.profile_id {
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
            let is_single = qm.profile_id.is_some();
            let cur_tags = qm.tags.clone();
            let raw_totp = qm.totp_input.read(cx).value().to_string();
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
                .border_color(BonTheme::border())
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
                                    app.close_popup_modal(cx);
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
                                            if let Some(ActivePopupModal::QuickMeta(m)) =
                                                app.popup_modal.as_mut()
                                            {
                                                if let Some(pos) = m
                                                    .tags
                                                    .iter()
                                                    .position(|t| t.eq_ignore_ascii_case(&tag_s))
                                                {
                                                    m.tags.remove(pos);
                                                } else {
                                                    m.tags.push(tag_s.clone());
                                                }
                                                cx.notify();
                                            }
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
                                                if let Some(ActivePopupModal::QuickMeta(m)) =
                                                    app.popup_modal.as_mut()
                                                {
                                                    m.tags
                                                        .retain(|x| !x.eq_ignore_ascii_case(&t_rem));
                                                    cx.notify();
                                                }
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
                                        .child(Input::new(&qm.tag_input)),
                                )
                                .child(
                                    Button::new("qm-add-custom-tag")
                                        .with_variant(BonTheme::outline_blue(cx))
                                        .small()
                                        .label("+ Add Tag")
                                        .on_click(cx.listener(|app, _, window, cx| {
                                            if let Some(ActivePopupModal::QuickMeta(m)) =
                                                app.popup_modal.as_mut()
                                            {
                                                let raw = m
                                                    .tag_input
                                                    .read(cx)
                                                    .value()
                                                    .trim()
                                                    .to_string();
                                                for part in Profile::parse_tags_csv(&raw) {
                                                    if !m
                                                        .tags
                                                        .iter()
                                                        .any(|t| t.eq_ignore_ascii_case(&part))
                                                    {
                                                        m.tags.push(part);
                                                    }
                                                }
                                                m.tag_input = cx.new(|cx| {
                                                    InputState::new(window, cx).placeholder(
                                                        "Custom tag (e.g. Shop-01, Tier1)...",
                                                    )
                                                });
                                                cx.notify();
                                            }
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
                        .child(Input::new(&qm.totp_input))
                }))
                .child({
                    let qm_bms = qm.bookmarks.clone();
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
                                                if let Some(ActivePopupModal::QuickMeta(m)) =
                                                    app.popup_modal.as_mut()
                                                {
                                                    m.bookmarks.retain(|(_, eu)| eu != &rm_u);
                                                    cx.notify();
                                                }
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
                                        .child(Input::new(&qm.bm_name_input)),
                                )
                                .child(
                                    div()
                                        .flex_1()
                                        .child(Input::new(&qm.bm_url_input)),
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
                        .child(Textarea::new(&qm.note_input).w_full()),
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
                                    app.close_popup_modal(cx);
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

        ActivePopupModal::CookieRobot(cr) => {
            let target_desc = if let Some(pid) = &cr.target_id {
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
            let cur_dwell = cr.dwell_secs;
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
                .border_color(BonTheme::border())
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
                                    app.close_popup_modal(cx);
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
                                            if let Some(ActivePopupModal::CookieRobot(m)) =
                                                app.popup_modal.as_mut()
                                            {
                                                let text = urls_s.clone();
                                                m.urls_input = cx.new(|cx| {
                                                    TextareaState::new(window, cx)
                                                        .rows(6)
                                                        .default_value(text)
                                                });
                                                cx.notify();
                                            }
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
                                            if let Some(ActivePopupModal::CookieRobot(m)) =
                                                app.popup_modal.as_mut()
                                            {
                                                m.dwell_secs = secs;
                                                cx.notify();
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
                        .child(field_label("3. Target URLs (one URL per line)"))
                        .child(Textarea::new(&cr.urls_input).w_full()),
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
                                    app.close_popup_modal(cx);
                                })),
                        )
                        .child(
                            Button::new("cr-run")
                                .with_variant(BonTheme::primary_cta(cx))
                                .small()
                                .label("▶ Start Warm-up")
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.start_cookie_robot(cx);
                                })),
                        ),
                )
        }

        ActivePopupModal::ImportBackupZip(ibz) => {
            v_flex()
                .w(px(460.))
                .p_5()
                .gap_3p5()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border())
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
                                    app.close_popup_modal(cx);
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
                                .child(Input::new(&ibz.zip_input)),
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
                                    app.close_popup_modal(cx);
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

        ActivePopupModal::CloneProfile(cm) => {
            let src_name = app
                .profiles
                .iter()
                .find(|p| p.id == cm.target_id)
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "Profile".to_string());
            v_flex()
                .w(px(420.))
                .p_5()
                .gap_3p5()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border())
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
                                    app.close_popup_modal(cx);
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
                                .child(Input::new(&cm.count_input)),
                        )
                        .child(
                            v_flex()
                                .flex_1()
                                .gap_1()
                                .child(field_label("Name Prefix"))
                                .child(Input::new(&cm.prefix_input)),
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
                                    app.close_popup_modal(cx);
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

        ActivePopupModal::EditProxy(em) => {
            let proxy_groups = app.distinct_proxy_groups_with_counts();
            let cur_tag = em.selected_tag.clone();
            v_flex()
                .w(px(480.))
                .p_5()
                .gap_3p5()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border())
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
                                    app.close_popup_modal(cx);
                                })),
                        ),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_1()
                        .child(field_label("Proxy Name"))
                        .child(Input::new(&em.name_input)),
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
                                            if let Some(ActivePopupModal::EditProxy(m)) =
                                                app.popup_modal.as_mut()
                                            {
                                                m.selected_tag = String::new();
                                                cx.notify();
                                            }
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
                                            if let Some(ActivePopupModal::EditProxy(m)) =
                                                app.popup_modal.as_mut()
                                            {
                                                m.selected_tag = g_c.clone();
                                                cx.notify();
                                            }
                                        }))
                                })),
                        ),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_1()
                        .child(field_label("IP Rotation Webhook URL (http://... or https://...)"))
                        .child(Input::new(&em.rotate_input)),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_1()
                        .child(field_label("Expiration Date (DD/MM/YYYY or days)"))
                        .child(Input::new(&em.expire_input)),
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
                                    app.close_popup_modal(cx);
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

        ActivePopupModal::AgentFlows(af) => {
            let target_prof = af
                .target_id
                .as_ref()
                .or(app.selected_profile_id.as_ref())
                .and_then(|id| app.profiles.iter().find(|p| &p.id == id));
            let (target_label, hist_count) = if let Some(p) = target_prof {
                let sid = p.short_id();
                let hist_len = crate::flows::load_flow_from_path(
                    &crate::flows::history_flow_path_in(&app.workspace_root, &sid),
                    "hist",
                )
                .map(|h| h.steps.len())
                .unwrap_or(0);
                (
                    if af.target_id.is_none() && app.checked_profile_ids.len() > 1 {
                        format!("{} checked profiles", app.checked_profile_ids.len())
                    } else {
                        format!("{} (bon_{sid})", p.name)
                    },
                    hist_len,
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
                .border_color(BonTheme::border())
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
                                    app.close_popup_modal(cx);
                                })),
                        ),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_2()
                        .child(
                            v_flex()
                                .w_full()
                                .gap_1()
                                .child(field_label(
                                    "Variables {{var}} Override (key=value, comma-separated)",
                                ))
                                .child(Input::new(&af.vars_input)),
                        )
                        .child(
                            h_flex()
                                .w_full()
                                .gap_2()
                                .items_end()
                                .child(
                                    v_flex()
                                        .flex_1()
                                        .gap_1()
                                        .child(field_label(
                                            "Batch CSV Data File (optional: email,pass,profile...)",
                                        ))
                                        .child(Input::new(&af.csv_input)),
                                )
                                .child(
                                    v_flex()
                                        .gap_1()
                                        .child(field_label("Concurrency"))
                                        .child(
                                            h_flex().gap_1().children(
                                                [1usize, 3, 5, 10].into_iter().map(|c| {
                                                    let active = af.concurrency == c;
                                                    Button::new(SharedString::from(format!(
                                                        "flw-conc-{c}"
                                                    )))
                                                    .with_variant(BonTheme::toggle_pill(cx, active))
                                                    .small()
                                                    .label(format!("{c}×"))
                                                    .on_click(cx.listener(move |app, _, _, cx| {
                                                        if let Some(ActivePopupModal::AgentFlows(
                                                            m,
                                                        )) = app.popup_modal.as_mut()
                                                        {
                                                            m.concurrency = c;
                                                            cx.notify();
                                                        }
                                                    }))
                                                }),
                                            ),
                                        ),
                                ),
                        ),
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
                                        .child(Input::new(&af.save_name_input)),
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
                                af.expanded_flow_name.as_deref() == Some(fl.name.as_str());
                            let fn_exp = fl.name.clone();
                            let fn_run = fl.name.clone();
                            let fn_del = fl.name.clone();
                            let fn_for_steps = fl.name.clone();
                            let vars = crate::flows::extract_flow_vars(&fl);
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

        ActivePopupModal::Synchronizer(sync_st) => {
            let live_sync = crate::launcher::current_synchronizer_status();
            let running_profiles: Vec<(String, String, String, u16)> = app
                .profiles
                .iter()
                .filter_map(|p| {
                    if let Some(crate::models::ProfileStatus::Running(rt)) = app.statuses.get(&p.id)
                    {
                        Some((p.id.clone(), p.short_id(), p.name.clone(), rt.cdp_port))
                    } else {
                        None
                    }
                })
                .collect();
            let effective_master_id = sync_st
                .master_id
                .clone()
                .filter(|mid| running_profiles.iter().any(|(id, _, _, _)| id == mid))
                .or_else(|| running_profiles.first().map(|(id, _, _, _)| id.clone()));
            let follower_count = running_profiles
                .iter()
                .filter(|(id, _, _, _)| {
                    Some(id.as_str()) != effective_master_id.as_deref()
                        && sync_st.follower_ids.contains(id)
                })
                .count();

            v_flex()
                .w(px(540.))
                .p_5()
                .gap_3p5()
                .rounded_lg()
                .bg(BonTheme::bg_elevated())
                .border_1()
                .border_color(BonTheme::border())
                .child(
                    h_flex()
                        .w_full()
                        .justify_between()
                        .items_center()
                        .child(
                            h_flex()
                                .gap_2()
                                .items_center()
                                .child(
                                    div()
                                        .text_base()
                                        .font_bold()
                                        .text_color(BonTheme::text_primary())
                                        .child(format!(
                                            "{}  Multi-Profile Synchronizer (1-to-N)",
                                            SfSymbol::LINK
                                        )),
                                )
                                .children(live_sync.active.then(|| {
                                    div()
                                        .px_2()
                                        .py_0p5()
                                        .rounded_full()
                                        .bg(BonTheme::success_bg())
                                        .text_xs()
                                        .font_semibold()
                                        .text_color(BonTheme::success())
                                        .child(format!(
                                            "LIVE • {} events",
                                            live_sync.mirrored_events
                                        ))
                                })),
                        )
                        .child(
                            Button::new("sync-modal-close")
                                .ghost()
                                .small()
                                .label(SfSymbol::XMARK)
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.close_popup_modal(cx);
                                })),
                        ),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(BonTheme::text_secondary())
                        .child(
                            "Mirror mouse clicks (viewport-scaled), wheel scrolling, keyboard typing, and URL navigation from 1 Master window to all Follower windows in real time.",
                        ),
                )
                .child(if running_profiles.len() < 2 {
                    v_flex()
                        .w_full()
                        .p_4()
                        .gap_1p5()
                        .rounded_md()
                        .bg(BonTheme::bg_well())
                        .border_1()
                        .border_color(BonTheme::border())
                        .items_center()
                        .child(
                            div()
                                .text_sm()
                                .font_semibold()
                                .text_color(BonTheme::warning())
                                .child("Launch at least 2 profiles to start Synchronizer"),
                        )
                        .child(
                            div()
                                .text_xs()
                                .text_color(BonTheme::text_secondary())
                                .child(format!(
                                    "Currently running: {} profile(s)",
                                    running_profiles.len()
                                )),
                        )
                        .into_any_element()
                } else {
                    v_flex()
                        .w_full()
                        .gap_3()
                        .child(
                            v_flex()
                                .w_full()
                                .gap_1p5()
                                .child(field_label("1. Master Profile (you control this window)"))
                                .child(
                                    h_flex().w_full().gap_1p5().flex_wrap().children(
                                        running_profiles.iter().map(|(id, sid, name, _)| {
                                            let is_master =
                                                effective_master_id.as_deref() == Some(id.as_str());
                                            let id_click = id.clone();
                                            Button::new(SharedString::from(format!(
                                                "sync-master-{sid}"
                                            )))
                                            .with_variant(BonTheme::toggle_pill(cx, is_master))
                                            .small()
                                            .label(format!("{name} (#{sid})"))
                                            .on_click(cx.listener(move |app, _, _, cx| {
                                                if let Some(ActivePopupModal::Synchronizer(st)) =
                                                    app.popup_modal.as_mut()
                                                {
                                                    st.master_id = Some(id_click.clone());
                                                    st.follower_ids.remove(&id_click);
                                                    cx.notify();
                                                }
                                            }))
                                        }),
                                    ),
                                ),
                        )
                        .child(
                            v_flex()
                                .w_full()
                                .gap_1p5()
                                .child(
                                    div()
                                        .text_xs()
                                        .font_semibold()
                                        .text_color(BonTheme::text_secondary())
                                        .child(format!(
                                            "2. Follower Profiles ({follower_count} selected)"
                                        )),
                                )
                                .child(
                                    h_flex().w_full().gap_1p5().flex_wrap().children(
                                        running_profiles
                                            .iter()
                                            .filter(|(id, _, _, _)| {
                                                Some(id.as_str()) != effective_master_id.as_deref()
                                            })
                                            .map(|(id, sid, name, _)| {
                                                let checked = sync_st.follower_ids.contains(id);
                                                let id_toggle = id.clone();
                                                Button::new(SharedString::from(format!(
                                                    "sync-flw-{sid}"
                                                )))
                                                .with_variant(BonTheme::toggle_pill(cx, checked))
                                                .small()
                                                .label(if checked {
                                                    format!(
                                                        "{}  {name} (#{sid})",
                                                        SfSymbol::CHECKMARK
                                                    )
                                                } else {
                                                    format!("{name} (#{sid})")
                                                })
                                                .on_click(cx.listener(move |app, _, _, cx| {
                                                    if let Some(ActivePopupModal::Synchronizer(
                                                        st,
                                                    )) = app.popup_modal.as_mut()
                                                    {
                                                        if !st.follower_ids.remove(&id_toggle) {
                                                            st.follower_ids
                                                                .insert(id_toggle.clone());
                                                        }
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
                                .items_center()
                                .justify_between()
                                .child(
                                    Button::new("sync-auto-tile-toggle")
                                        .with_variant(BonTheme::toggle_pill(
                                            cx,
                                            sync_st.auto_tile,
                                        ))
                                        .small()
                                        .label(if sync_st.auto_tile {
                                            format!(
                                                "{}  Auto-tile windows side-by-side on start",
                                                SfSymbol::CHECKMARK
                                            )
                                        } else {
                                            "Auto-tile windows side-by-side on start".to_string()
                                        })
                                        .on_click(cx.listener(|app, _, _, cx| {
                                            if let Some(ActivePopupModal::Synchronizer(st)) =
                                                app.popup_modal.as_mut()
                                            {
                                                st.auto_tile = !st.auto_tile;
                                                cx.notify();
                                            }
                                        })),
                                ),
                        )
                        .into_any_element()
                })
                .child(
                    h_flex()
                        .w_full()
                        .pt_2()
                        .border_t_1()
                        .border_color(BonTheme::border())
                        .justify_between()
                        .items_center()
                        .child(if live_sync.active {
                            Button::new("sync-stop-live")
                                .danger()
                                .small()
                                .label(format!(
                                    "{}  Stop Live Sync (#{})",
                                    SfSymbol::STOP_FILL,
                                    live_sync.master_short_id
                                ))
                                .on_click(cx.listener(|app, _, _, cx| {
                                    app.stop_synchronizer_ui(cx);
                                }))
                                .into_any_element()
                        } else {
                            div().into_any_element()
                        })
                        .child(
                            h_flex()
                                .gap_2()
                                .child(
                                    Button::new("sync-cancel-btn")
                                        .with_variant(BonTheme::row_action(cx))
                                        .small()
                                        .label("Close")
                                        .on_click(cx.listener(|app, _, _, cx| {
                                            app.close_popup_modal(cx);
                                        })),
                                )
                                .child(
                                    Button::new("sync-start-btn")
                                        .with_variant(BonTheme::primary_cta(cx))
                                        .small()
                                        .disabled(follower_count == 0)
                                        .label(format!(
                                            "{}  Start Sync (1 → {follower_count})",
                                            SfSymbol::PLAY_FILL
                                        ))
                                        .on_click(cx.listener(|app, _, _, cx| {
                                            app.start_synchronizer_from_modal(cx);
                                        })),
                                ),
                        ),
                )
        }
    };

    let modal_anim_id = SharedString::from(format!("popup-modal-{anim_key}"));
    let backdrop_anim_id = SharedString::from(format!("popup-backdrop-{anim_key}"));

    div()
        .absolute()
        .top_0()
        .left_0()
        .size_full()
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
                |this, delta| this.opacity(delta).mt(px((1.0 - delta) * 10.0)),
            ),
        )
        .with_animation(
            backdrop_anim_id,
            BonTheme::ui_enter_anim(),
            |this, delta| {
                this.bg(AnimationPhase(delta).interpolate_clamped(
                    Hsla::from(rgba(0x00000000)),
                    Hsla::from(rgba(0x00000080)),
                ))
            },
        )
        .into_any_element()
}
