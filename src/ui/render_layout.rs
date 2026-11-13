use super::*;

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
        let active_view = self.active_view;
        let sub_tab = self.profile_sub_tab;
        let popup_modal = self.popup_modal.clone();
        let group_count = self.cached_group_counts.len();
        let selected_group = self.selected_group.clone();
        let (kernel_dot, kernel_label) = match &self.kernel_info {
            Some(_) => (BonTheme::success(), "Chromium 148 Online".to_string()),
            None => (BonTheme::warning(), "Engine Missing".to_string()),
        };

        let is_editing_existing = active_view == WorkspaceView::EditProfile
            && self.modal.as_ref().is_some_and(|m| m.draft.is_edit);
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
                    .pt_0()
                    .pb_3p5()
                    .px_3()
                    .justify_between()
                    .bg(BonTheme::bg_sidebar())
                    .border_r_1()
                    .border_color(BonTheme::border())
                    .child(
                        v_flex()
                            .w_full()
                            .gap_0()
                            // Native macOS Titlebar Drag Strip above Sidebar Logo
                            .child(
                                div()
                                    .id("sidebar-titlebar-drag")
                                    .w_full()
                                    .h(px(44.))
                                    .flex_shrink_0()
                                    .window_control_area(WindowControlArea::Drag)
                                    .on_double_click(|_, window, _| window.titlebar_double_click()),
                            )
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
                                    .border_1()
                                    .border_color(if is_creating_profile {
                                        BonTheme::accent()
                                    } else {
                                        BonTheme::border()
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
                                        move |this, phase| {
                                            this.bg(phase.interpolate_clamped(
                                                BonTheme::bg_elevated(),
                                                BonTheme::accent(),
                                            ))
                                            .hover(move |s| {
                                                if is_creating_profile {
                                                    s.bg(rgb(0x2997ff))
                                                } else {
                                                    s.bg(rgb(0x36363b))
                                                        .border_color(BonTheme::border_active())
                                                }
                                            })
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
                            .child({
                                let installing = self.installing_kernel;
                                h_flex()
                                    .px_2()
                                    .py_1()
                                    .rounded_md()
                                    .bg(rgba(0xffffff08))
                                    .justify_between()
                                    .items_center()
                                    .child(
                                        h_flex()
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
                                                    .child(if installing {
                                                        "Updating Kernel...".to_string()
                                                    } else {
                                                        kernel_label
                                                    }),
                                            ),
                                    )
                                    .children(self.kernel_info.is_some().then(|| {
                                        Button::new("btn-reinstall-kernel")
                                            .ghost()
                                            .xsmall()
                                            .disabled(installing)
                                            .label(SfSymbol::ARROW_CLOCKWISE)
                                            .on_click(cx.listener(|app, _, _, cx| {
                                                app.install_kernel_opts(true, cx);
                                            }))
                                    }))
                            }),
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
                            .id("workspace-header-bar")
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
                            .window_control_area(WindowControlArea::Drag)
                            .on_double_click(|_, window, _| window.titlebar_double_click())
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
                                        let api_port = self.http_api_port;
                                        let lbl = match api_port {
                                            Some(p) => format!("\u{100a7c}  API :{p}"),
                                            None => "\u{100a7c}  Local API".to_string(),
                                        };
                                        Button::new("top-toggle-http-api")
                                            .with_variant(BonTheme::toggle_pill(
                                                cx,
                                                api_port.is_some(),
                                            ))
                                            .small()
                                            .label(lbl)
                                            .on_click(cx.listener(|app, _, _, cx| {
                                                app.toggle_http_api_server(cx);
                                            }))
                                    })
                                    .child({
                                        let flow_cnt = self.saved_flows.len();
                                        Button::new("top-open-flows")
                                            .with_variant(BonTheme::row_action(cx))
                                            .small()
                                            .label(format!("{}  Flows ({flow_cnt})", SfSymbol::PLAY_FILL))
                                            .on_click(cx.listener(|app, _, window, cx| {
                                                app.open_agent_flows_modal(None, window, cx);
                                            }))
                                    })
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
                                render_groups_subtab_view(self, cx).into_any_element()
                            } else if sub_tab == ProfileSubTab::Trash {
                                render_trash_table(self, cx).into_any_element()
                            } else {
                                let checked_count = self.checked_profile_ids.len();
                                let checked_running_count = self
                                    .checked_profile_ids
                                    .iter()
                                    .filter(|id| {
                                        matches!(
                                            self.statuses.get(*id),
                                            Some(
                                                ProfileStatus::Running(_) | ProfileStatus::Starting
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
                                                        Button::new("top-clean-cache-btn")
                                                            .with_variant(BonTheme::row_action(cx))
                                                            .small()
                                                            .label("\u{1002af}  Clean Cache")
                                                            .on_click(cx.listener(
                                                                |app, _, _, cx| {
                                                                    app.request_clean_checked_cache(
                                                                        cx,
                                                                    );
                                                                },
                                                            )),
                                                    )
                                                    .child({
                                                        let app_imp_csv = app_entity.clone();
                                                        let app_imp_json = app_entity.clone();
                                                        let app_imp_zip = app_entity.clone();
                                                        let app_exp_csv = app_entity.clone();
                                                        let app_exp_json = app_entity.clone();
                                                        Button::new("top-import-export-menu")
                                                            .with_variant(BonTheme::row_action(cx))
                                                            .small()
                                                            .label(format!(
                                                                "{}  Import / Export \u{25be}",
                                                                SfSymbol::ARROW_UP_DOC
                                                            ))
                                                            .dropdown_menu_with_anchor(
                                                                Anchor::TopRight,
                                                                move |menu, _window, _cx| {
                                                                    let ic = app_imp_csv.clone();
                                                                    let ij = app_imp_json.clone();
                                                                    let iz = app_imp_zip.clone();
                                                                    let ec = app_exp_csv.clone();
                                                                    let ej = app_exp_json.clone();
                                                                    menu.min_w(px(195.))
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                "\u{10023b}   Import Backup (.zip)…",
                                                                            )
                                                                            .on_click(
                                                                                move |_, window, cx| {
                                                                                    iz.update(cx, |app, cx| {
                                                                                        app.open_import_backup_zip_modal(window, cx);
                                                                                    });
                                                                                },
                                                                            ),
                                                                        )
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                "\u{10023b}   Import CSV…",
                                                                            )
                                                                            .on_click(
                                                                                move |_, window, cx| {
                                                                                    ic.update(cx, |app, cx| {
                                                                                        app.pick_and_import_csv_ui(window, cx);
                                                                                    });
                                                                                },
                                                                            ),
                                                                        )
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                "\u{10023b}   Import JSON…",
                                                                            )
                                                                            .on_click(
                                                                                move |_, window, cx| {
                                                                                    ij.update(cx, |app, cx| {
                                                                                        app.pick_and_import_json_ui(window, cx);
                                                                                    });
                                                                                },
                                                                            ),
                                                                        )
                                                                        .separator()
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                "\u{10023d}   Export CSV",
                                                                            )
                                                                            .on_click(
                                                                                move |_, _, cx| {
                                                                                    ec.update(cx, |app, cx| {
                                                                                        app.export_profiles_csv_ui(cx);
                                                                                    });
                                                                                },
                                                                            ),
                                                                        )
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                "\u{10023d}   Export All JSON",
                                                                            )
                                                                            .on_click(
                                                                                move |_, _, cx| {
                                                                                    ej.update(cx, |app, cx| {
                                                                                        app.export_all_profiles_backup(cx);
                                                                                    });
                                                                                },
                                                                            ),
                                                                        )
                                                                },
                                                            )
                                                    })
                                                    .children((!self.show_detail_drawer).then(
                                                        || {
                                                            Button::new("reopen-detail-drawer")
                                                                .with_variant(BonTheme::row_action(
                                                                    cx,
                                                                ))
                                                                .small()
                                                                .label(format!(
                                                                    "{}  Detail",
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
                                        h_flex()
                                            .w_full()
                                            .px_2p5()
                                            .py_1p5()
                                            .rounded_lg()
                                            .bg(BonTheme::bg_elevated())
                                            .border_1()
                                            .border_color(BonTheme::border())
                                            .justify_between()
                                            .items_center()
                                            .gap_2()
                                            // Left: Selection Pill + Lifecycle + Grouped Actions
                                            .child(
                                                h_flex()
                                                    .gap_1p5()
                                                    .flex_wrap()
                                                    .items_center()
                                                    // 1. Selection counter + clear
                                                    .child(
                                                        Button::new("batch-clear-sel")
                                                            .ghost()
                                                            .small()
                                                            .label(format!(
                                                                "{checked_count} selected  {}",
                                                                SfSymbol::XMARK
                                                            ))
                                                            .on_click(cx.listener(
                                                                |app, _, _, cx| {
                                                                    app.checked_profile_ids.clear();
                                                                    cx.notify();
                                                                },
                                                            )),
                                                    )
                                                    .child(
                                                        div()
                                                            .w(px(1.))
                                                            .h(px(16.))
                                                            .bg(BonTheme::border()),
                                                    )
                                                    // 2. Lifecycle: Start / Stop
                                                    .children((checked_stopped_count > 0).then(
                                                        || {
                                                            Button::new("batch-launch-sel")
                                                                .with_variant(
                                                                    BonTheme::primary_cta(cx),
                                                                )
                                                                .small()
                                                                .label(format!(
                                                                    "{}  Start ({checked_stopped_count})",
                                                                    SfSymbol::PLAY_FILL,
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
                                                                    "{}  Stop ({checked_running_count})",
                                                                    SfSymbol::STOP_FILL,
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
                                                    .child(
                                                        div()
                                                            .w(px(1.))
                                                            .h(px(16.))
                                                            .bg(BonTheme::border()),
                                                    )
                                                    // 3. Organization & Metadata
                                                    .child(
                                                        Button::new("batch-assign-grp-btn")
                                                            .with_variant(BonTheme::row_action(cx))
                                                            .small()
                                                            .label(format!(
                                                                "{}  Group",
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
                                                    .child(
                                                        Button::new("batch-tags-note-btn")
                                                            .with_variant(BonTheme::row_action(cx))
                                                            .small()
                                                            .label(format!(
                                                                "{}  Tags & Note",
                                                                SfSymbol::TAG_FILL
                                                            ))
                                                            .on_click(cx.listener(
                                                                |app, _, window, cx| {
                                                                    app.open_quick_meta_modal(
                                                                        None, window, cx,
                                                                    );
                                                                },
                                                            )),
                                                    )
                                                    // 4. Proxy Dropdown (`Check proxy`, `Rotate IP`, `Update proxy`)
                                                    .child({
                                                        let app_chk = app_entity.clone();
                                                        let app_rot = app_entity.clone();
                                                        let app_upd = app_entity.clone();
                                                        Button::new("batch-check-proxy-sel")
                                                            .with_variant(BonTheme::row_action(cx))
                                                            .small()
                                                            .label(format!(
                                                                "{}  Proxy \u{25be}",
                                                                SfSymbol::CHECKMARK_SHIELD
                                                            ))
                                                            .dropdown_menu_with_anchor(
                                                                Anchor::TopLeft,
                                                                move |menu, _window, _cx| {
                                                                    let c1 = app_chk.clone();
                                                                    let c2 = app_rot.clone();
                                                                    let c3 = app_upd.clone();
                                                                    menu.min_w(px(185.))
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                format!(
                                                                                    "{}   Check Proxy",
                                                                                    SfSymbol::CHECKMARK_SHIELD
                                                                                ),
                                                                            )
                                                                            .on_click(
                                                                                move |_, _, cx| {
                                                                                    c1.update(cx, |app, cx| {
                                                                                        app.check_proxies_for_checked(cx);
                                                                                    });
                                                                                },
                                                                            ),
                                                                        )
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                "\u{1002af}   Rotate IP",
                                                                            )
                                                                            .on_click(
                                                                                move |_, _, cx| {
                                                                                    c2.update(cx, |app, cx| {
                                                                                        app.rotate_proxies_for_checked(cx);
                                                                                    });
                                                                                },
                                                                            ),
                                                                        )
                                                                        .separator()
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                format!(
                                                                                    "{}   Update Proxy…",
                                                                                    SfSymbol::SLIDER_HORIZONTAL_3
                                                                                ),
                                                                            )
                                                                            .on_click(
                                                                                move |_, _, cx| {
                                                                                    c3.update(cx, |app, cx| {
                                                                                        app.popup_modal = Some(
                                                                                            ActivePopupModal::UpdateProxy,
                                                                                        );
                                                                                        cx.notify();
                                                                                    });
                                                                                },
                                                                            ),
                                                                        )
                                                                },
                                                            )
                                                    })
                                                    // 5. Fingerprint & Config Dropdown (`Update profiles`, `Reseed`)
                                                    .child({
                                                        let app_upd_prof = app_entity.clone();
                                                        let app_reseed = app_entity.clone();
                                                        Button::new("batch-update-profiles-btn")
                                                            .with_variant(BonTheme::row_action(cx))
                                                            .small()
                                                            .label(format!(
                                                                "{}  Fingerprint \u{25be}",
                                                                SfSymbol::SLIDER_HORIZONTAL_3
                                                            ))
                                                            .dropdown_menu_with_anchor(
                                                                Anchor::TopLeft,
                                                                move |menu, _window, _cx| {
                                                                    let u1 = app_upd_prof.clone();
                                                                    let r1 = app_reseed.clone();
                                                                    menu.min_w(px(195.))
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                format!(
                                                                                    "{}   Update OS / Hardware…",
                                                                                    SfSymbol::SLIDER_HORIZONTAL_3
                                                                                ),
                                                                            )
                                                                            .on_click(
                                                                                move |_, _, cx| {
                                                                                    u1.update(cx, |app, cx| {
                                                                                        app.popup_modal = Some(
                                                                                            ActivePopupModal::UpdateProfiles,
                                                                                        );
                                                                                        cx.notify();
                                                                                    });
                                                                                },
                                                                            ),
                                                                        )
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                format!(
                                                                                    "{}   Reseed Fingerprint",
                                                                                    SfSymbol::ARROW_CLOCKWISE
                                                                                ),
                                                                            )
                                                                            .on_click(
                                                                                move |_, window, cx| {
                                                                                    r1.update(cx, |app, cx| {
                                                                                        app.reseed_checked_profiles(window, cx);
                                                                                    });
                                                                                },
                                                                            ),
                                                                        )
                                                                },
                                                            )
                                                    })
                                                    // 6. Automation & Live Browser Dropdown (`Run Flow`, `Cookie Robot`, `Arrange`, `Sync Clipboard`, `Broadcast 2FA`)
                                                    .child({
                                                        let app_flow = app_entity.clone();
                                                        let app_robot = app_entity.clone();
                                                        let app_arr = app_entity.clone();
                                                        let app_clip = app_entity.clone();
                                                        let app_totp = app_entity.clone();
                                                        let has_running = checked_running_count > 0;
                                                        Button::new("batch-run-flow-btn")
                                                            .with_variant(BonTheme::outline_blue(
                                                                cx,
                                                            ))
                                                            .small()
                                                            .label(format!(
                                                                "{}  Automate \u{25be}",
                                                                SfSymbol::BOLT_FILL
                                                            ))
                                                            .dropdown_menu_with_anchor(
                                                                Anchor::TopLeft,
                                                                move |menu, _window, _cx| {
                                                                    let f1 = app_flow.clone();
                                                                    let rb = app_robot.clone();
                                                                    let ar = app_arr.clone();
                                                                    let cl = app_clip.clone();
                                                                    let tp = app_totp.clone();
                                                                    menu.min_w(px(210.))
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                format!(
                                                                                    "{}   Run Agent Flow…",
                                                                                    SfSymbol::PLAY_FILL
                                                                                ),
                                                                            )
                                                                            .on_click(
                                                                                move |_, window, cx| {
                                                                                    f1.update(cx, |app, cx| {
                                                                                        app.open_agent_flows_modal(None, window, cx);
                                                                                    });
                                                                                },
                                                                            ),
                                                                        )
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                "\u{1002e6}   Cookie Robot (Warm-up)…",
                                                                            )
                                                                            .on_click(
                                                                                move |_, window, cx| {
                                                                                    rb.update(cx, |app, cx| {
                                                                                        app.open_cookie_robot_modal(None, window, cx);
                                                                                    });
                                                                                },
                                                                            ),
                                                                        )
                                                                        .separator()
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                format!(
                                                                                    "{}   Arrange Windows ({checked_running_count})",
                                                                                    SfSymbol::PC
                                                                                ),
                                                                            )
                                                                            .disabled(!has_running)
                                                                            .on_click(
                                                                                move |_, _, cx| {
                                                                                    ar.update(cx, |app, cx| {
                                                                                        app.popup_modal = Some(
                                                                                            ActivePopupModal::ArrangeWindows,
                                                                                        );
                                                                                        cx.notify();
                                                                                    });
                                                                                },
                                                                            ),
                                                                        )
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                "\u{100241}   Sync Clipboard to Running",
                                                                            )
                                                                            .disabled(!has_running)
                                                                            .on_click(
                                                                                move |_, _, cx| {
                                                                                    cl.update(cx, |app, cx| {
                                                                                        app.sync_clipboard_to_checked_running(cx);
                                                                                    });
                                                                                },
                                                                            ),
                                                                        )
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                "\u{1003a0}   Broadcast 2FA to Running",
                                                                            )
                                                                            .disabled(!has_running)
                                                                            .on_click(
                                                                                move |_, _, cx| {
                                                                                    tp.update(cx, |app, cx| {
                                                                                        app.broadcast_totp_to_checked_running(cx);
                                                                                    });
                                                                                },
                                                                            ),
                                                                        )
                                                                },
                                                            )
                                                    }),
                                            )
                                            // Right: Overflow Copy/Export + Direct Trash Button
                                            .child(
                                                h_flex()
                                                    .gap_1p5()
                                                    .flex_shrink_0()
                                                    .items_center()
                                                    .child({
                                                        let app_ids = app_entity.clone();
                                                        let app_names = app_entity.clone();
                                                        let app_zip = app_entity.clone();
                                                        let app_exp = app_entity.clone();
                                                        Button::new("batch-more-dots")
                                                            .with_variant(BonTheme::row_action(cx))
                                                            .small()
                                                            .label(SfSymbol::ELLIPSIS)
                                                            .dropdown_menu_with_anchor(
                                                                Anchor::TopRight,
                                                                move |menu, _window, _cx| {
                                                                    let a1 = app_ids.clone();
                                                                    let a2 = app_names.clone();
                                                                    let az = app_zip.clone();
                                                                    let a3 = app_exp.clone();
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
                                                                                "\u{100241}   Copy Names",
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
                                                                        .separator()
                                                                        .item(
                                                                            PopupMenuItem::new(
                                                                                "\u{10023d}   Export Backup (.zip)",
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
                                                                },
                                                            )
                                                    })
                                                    .child(
                                                        Button::new("batch-trash-sel")
                                                            .with_variant(
                                                                BonTheme::outline_danger(cx),
                                                            )
                                                            .small()
                                                            .label(format!(
                                                                "{}  Trash",
                                                                SfSymbol::TRASH
                                                            ))
                                                            .on_click(cx.listener(
                                                                |app, _, _, cx| {
                                                                    app.request_delete(
                                                                        PendingDeleteAction::CheckedProfiles,
                                                                        cx,
                                                                    );
                                                                },
                                                            )),
                                                    ),
                                            )
                                            .with_animation(
                                                "batch-action-bar-enter",
                                                BonTheme::ui_enter_anim(),
                                                |this, delta| {
                                                    this.opacity(delta).mt(px((1.0 - delta) * -4.0))
                                                },
                                            )
                                    }))
                                    // GenLogin Table + Right-Hand `Detail` Drawer
                                    .child({
                                        let filtered_indices = self.filtered_profile_indices_rc();
                                        render_profile_table(self, filtered_indices, cx)
                                    })
                                    .into_any_element()
                            })
                            .into_any_element(),
                        WorkspaceView::Proxies => {
                            render_proxies_view(self, cx).into_any_element()
                        }
                        WorkspaceView::EditProfile => {
                            if let Some(modal) = self.modal.as_ref() {
                                render_edit_profile_view(
                                    modal,
                                    &self.saved_groups,
                                    &self.cached_proxy_group_counts,
                                    &self.saved_proxies,
                                    cx,
                                )
                                .into_any_element()
                            } else {
                                div().child("No profile loaded").into_any_element()
                            }
                        }
                        WorkspaceView::Extensions => {
                            render_extensions_view(self, cx).into_any_element()
                        }
                    }),
            )
            )
            // Full-Window Centered Modal Overlay (with dark backdrop)
            .children(popup_modal.map(|kind| render_popup_modal(kind, self, cx)))
            // Floating Bottom-Right Toast Notification (auto-dismisses after 3.2s)
            .children(self.banner_message.as_ref().map(|msg| {
                let is_err = crate::models::contains_ignore_ascii_case(msg, "failed")
                    || crate::models::contains_ignore_ascii_case(msg, "error")
                    || crate::models::contains_ignore_ascii_case(msg, "blocked")
                    || crate::models::contains_ignore_ascii_case(msg, "invalid")
                    || crate::models::contains_ignore_ascii_case(msg, "cannot");
                let is_loading = msg.ends_with("...");
                let (accent_color, icon_bg, icon_str) = if is_err {
                    (BonTheme::danger(), BonTheme::danger_bg(), SfSymbol::XMARK_CIRCLE_FILL)
                } else if is_loading {
                    (BonTheme::info(), BonTheme::info_bg(), SfSymbol::ARROW_TRIANGLE_2_CIRCLEPATH)
                } else {
                    (BonTheme::success(), BonTheme::success_bg(), SfSymbol::CHECKMARK_CIRCLE_FILL)
                };
                let banner_id = SharedString::from("toast-banner-container");
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
                        BonTheme::ui_enter_anim(),
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
