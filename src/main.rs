mod control;
mod archive;
mod bookmarks;
mod cookies;
mod db;
mod extensions;
mod flows;
mod geoip;
mod launcher;
mod models;
mod proxy_tunnel;
mod ui;

use gpui_kit::assets::Assets;
use gpui_kit::component::input::{Copy, Cut, Escape, Paste, Redo, SelectAll, Undo};
use gpui_kit::component::theme::{Theme, ThemeMode};
use gpui_kit::*;

use crate::db::Database;
use crate::launcher::RuntimeSupervisor;
use crate::ui::{
    ArrangeWindowsAction, BonLoginApp, CloseWindowOrModal, CopyAgentCliSelectedAction,
    DeleteSelectedAction, FocusSearchAction, LaunchOrStopSelectedAction, MinimizeWindow,
    NewProfileAction, OpenFlowsAction, QuickAddAction, QuitApp, RefreshWorkspaceAction,
    StopAllProfilesAction, SwitchToExtensionsAction, SwitchToProfilesAction, SwitchToProxiesAction,
    ToggleDetailDrawerAction, WorkspaceView, ZoomWindow,
};
fn main() {
    if std::env::args_os().nth(1).is_some()
        && let Some(res) = crate::control::try_run_cli()
    {
        if let Err(e) = res {
            eprintln!(
                "{}",
                serde_json::json!({
                    "ok": false,
                    "error": e.to_string(),
                })
            );
            std::process::exit(1);
        }
        return;
    }

    let tokio_rt = crate::control::build_tokio_runtime();
    let tokio_handle = tokio_rt.handle().clone();
    let db = Database::open_default().expect("Failed to open bonlogin.sqlite3");

    let supervisor = RuntimeSupervisor::new_in(db.root_dir());
    let cleanup_supervisor = supervisor.clone();
    let app = gpui_kit::application().with_assets(Assets);

    app.run(move |cx| {
        gpui_kit::init(cx);
        Theme::change(ThemeMode::Dark, None, cx);
        Theme::update(cx, |theme| {
            theme.font_family = "SF Pro".into();
            theme.input = rgb(0x52525b).into();
            theme.ring = rgb(0x0a84ff).into();
            theme.caret = rgb(0x0a84ff).into();
            theme.selection = rgba(0x0a84ff55).into();
        });
        cx.activate(true);

        let quit_sup = supervisor.clone();
        cx.on_app_quit(move |_| {
            let sup = quit_sup.clone();
            async move {
                sup.stop_all();
            }
        })
        .detach();

        cx.on_window_closed(|cx, _| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();

        cx.bind_keys([
            KeyBinding::new("cmd-q", QuitApp, None),
            KeyBinding::new("cmd-w", CloseWindowOrModal, None),
            KeyBinding::new("cmd-m", MinimizeWindow, None),
            KeyBinding::new("cmd-n", NewProfileAction, None),
            KeyBinding::new("cmd-shift-n", QuickAddAction, None),
            KeyBinding::new("cmd-f", FocusSearchAction, None),
            KeyBinding::new("cmd-r", RefreshWorkspaceAction, None),
            KeyBinding::new("cmd-b", ToggleDetailDrawerAction, None),
            KeyBinding::new("cmd-1", SwitchToProfilesAction, None),
            KeyBinding::new("cmd-2", SwitchToProxiesAction, None),
            KeyBinding::new("cmd-3", SwitchToExtensionsAction, None),
            KeyBinding::new("cmd-l", LaunchOrStopSelectedAction, None),
            KeyBinding::new("cmd-shift-c", CopyAgentCliSelectedAction, None),
            KeyBinding::new("cmd-backspace", DeleteSelectedAction, None),
            KeyBinding::new("escape", Escape, None),
        ]);

        cx.set_menus([
            Menu::new("BonLogin").items([
                MenuItem::os_submenu("Services", SystemMenuType::Services),
                MenuItem::separator(),
                MenuItem::action("Quit BonLogin", QuitApp),
            ]),
            Menu::new("File").items([
                MenuItem::action("New Profile", NewProfileAction),
                MenuItem::action("Quick Add Profiles…", QuickAddAction),
                MenuItem::separator(),
                MenuItem::action("Launch / Stop Selected", LaunchOrStopSelectedAction),
                MenuItem::action("Copy Agent CLI", CopyAgentCliSelectedAction),
                MenuItem::action("Delete Selected Profile", DeleteSelectedAction),
                MenuItem::separator(),
                MenuItem::action("Sync Workspace", RefreshWorkspaceAction),
                MenuItem::action("Stop All Running Browsers", StopAllProfilesAction),
                MenuItem::separator(),
                MenuItem::action("Close", CloseWindowOrModal),
            ]),
            Menu::new("Edit").items([
                MenuItem::os_action("Undo", Undo, OsAction::Undo),
                MenuItem::os_action("Redo", Redo, OsAction::Redo),
                MenuItem::separator(),
                MenuItem::os_action("Cut", Cut, OsAction::Cut),
                MenuItem::os_action("Copy", Copy, OsAction::Copy),
                MenuItem::os_action("Paste", Paste, OsAction::Paste),
                MenuItem::os_action("Select All", SelectAll, OsAction::SelectAll),
                MenuItem::separator(),
                MenuItem::action("Find…", FocusSearchAction),
            ]),
            Menu::new("View").items([
                MenuItem::action("Profiles", SwitchToProfilesAction),
                MenuItem::action("Proxies", SwitchToProxiesAction),
                MenuItem::action("Extensions", SwitchToExtensionsAction),
                MenuItem::separator(),
                MenuItem::action("Agent Flows…", OpenFlowsAction),
                MenuItem::action("Toggle Inspector Drawer", ToggleDetailDrawerAction),
            ]),
            Menu::new("Window").items([
                MenuItem::action("Minimize", MinimizeWindow),
                MenuItem::action("Zoom", ZoomWindow),
                MenuItem::separator(),
                MenuItem::action("Arrange Running Browsers…", ArrangeWindowsAction),
            ]),
        ]);

        cx.set_dock_menu(vec![
            MenuItem::action("New Profile", NewProfileAction),
            MenuItem::action("Quick Add Profiles…", QuickAddAction),
            MenuItem::separator(),
            MenuItem::action("Stop All Running Browsers", StopAllProfilesAction),
        ]);

        let initial_bounds = crate::db::load_window_bounds_in(db.root_dir())
            .map(crate::ui::saved_to_window_bounds)
            .unwrap_or_else(|| WindowBounds::centered(size(px(1420.), px(840.)), cx));
        let window_options = WindowOptions {
            window_bounds: Some(initial_bounds),
            window_min_size: Some(size(px(980.), px(620.))),
            titlebar: Some(TitlebarOptions {
                title: Some("BonLogin".into()),
                appears_transparent: true,
                traffic_light_position: Some(point(px(16.), px(16.))),
            }),
            window_background: WindowBackgroundAppearance::Blurred,
            app_id: Some("com.bonlogin.app".into()),
            ..Default::default()
        };

        let sup = supervisor.clone();
        let handle = tokio_handle.clone();
        let (win_handle, app_entity) = gpui_kit::open_window(window_options, cx, move |window, cx| {
            window.activate_window();
            cx.new(|cx| BonLoginApp::new(db, handle, sup, window, cx))
        })
        .expect("Failed to open BonLogin window");

        cx.on_action(|_: &QuitApp, cx| {
            cx.quit();
        });
        cx.on_action({
            let win_handle = win_handle;
            let app_entity = app_entity.clone();
            move |_: &CloseWindowOrModal, cx| {
                let _ = win_handle.update(cx, |_, window, cx| {
                    app_entity.update(cx, |app, cx| {
                        app.handle_close_window_or_modal(window, cx);
                    });
                });
            }
        });
        cx.on_action({
            let win_handle = win_handle;
            move |_: &MinimizeWindow, cx| {
                let _ = win_handle.update(cx, |_, window, _| {
                    window.minimize_window();
                });
            }
        });
        cx.on_action({
            let win_handle = win_handle;
            move |_: &ZoomWindow, cx| {
                let _ = win_handle.update(cx, |_, window, _| {
                    window.zoom_window();
                });
            }
        });
        cx.on_action({
            let win_handle = win_handle;
            let app_entity = app_entity.clone();
            move |_: &NewProfileAction, cx| {
                let _ = win_handle.update(cx, |_, window, cx| {
                    app_entity.update(cx, |app, cx| {
                        app.popup_modal = None;
                        app.open_create_modal(window, cx);
                    });
                });
            }
        });
        cx.on_action({
            let app_entity = app_entity.clone();
            move |_: &QuickAddAction, cx| {
                app_entity.update(cx, |app, cx| {
                    app.popup_modal = Some(crate::ui::ActivePopupModal::QuickAdd);
                    cx.notify();
                });
            }
        });
        cx.on_action({
            let win_handle = win_handle;
            let app_entity = app_entity.clone();
            move |_: &FocusSearchAction, cx| {
                let _ = win_handle.update(cx, |_, window, cx| {
                    app_entity.update(cx, |app, cx| {
                        app.focus_active_search(window, cx);
                    });
                });
            }
        });
        cx.on_action({
            let app_entity = app_entity.clone();
            move |_: &RefreshWorkspaceAction, cx| {
                app_entity.update(cx, |app, cx| {
                    app.refresh_workspace_shortcut(cx);
                });
            }
        });
        cx.on_action({
            let app_entity = app_entity.clone();
            move |_: &ToggleDetailDrawerAction, cx| {
                app_entity.update(cx, |app, cx| {
                    app.show_detail_drawer = !app.show_detail_drawer;
                    cx.notify();
                });
            }
        });
        cx.on_action({
            let app_entity = app_entity.clone();
            move |_: &SwitchToProfilesAction, cx| {
                app_entity.update(cx, |app, cx| {
                    app.popup_modal = None;
                    app.active_view = WorkspaceView::Profiles;
                    cx.notify();
                });
            }
        });
        cx.on_action({
            let app_entity = app_entity.clone();
            move |_: &SwitchToProxiesAction, cx| {
                app_entity.update(cx, |app, cx| {
                    app.popup_modal = None;
                    app.active_view = WorkspaceView::Proxies;
                    cx.notify();
                });
            }
        });
        cx.on_action({
            let app_entity = app_entity.clone();
            move |_: &SwitchToExtensionsAction, cx| {
                app_entity.update(cx, |app, cx| {
                    app.popup_modal = None;
                    app.active_view = WorkspaceView::Extensions;
                    cx.notify();
                });
            }
        });
        cx.on_action({
            let app_entity = app_entity.clone();
            move |_: &ArrangeWindowsAction, cx| {
                app_entity.update(cx, |app, cx| {
                    app.popup_modal = Some(crate::ui::ActivePopupModal::ArrangeWindows);
                    cx.notify();
                });
            }
        });
        cx.on_action({
            let win_handle = win_handle;
            let app_entity = app_entity.clone();
            move |_: &OpenFlowsAction, cx| {
                let _ = win_handle.update(cx, |_, window, cx| {
                    app_entity.update(cx, |app, cx| {
                        app.open_agent_flows_modal(None, window, cx);
                    });
                });
            }
        });
        cx.on_action({
            let app_entity = app_entity.clone();
            move |_: &StopAllProfilesAction, cx| {
                app_entity.update(cx, |app, cx| {
                    app.stop_all_running_profiles(cx);
                });
            }
        });
        cx.on_action({
            let app_entity = app_entity.clone();
            move |_: &LaunchOrStopSelectedAction, cx| {
                app_entity.update(cx, |app, cx| {
                    app.launch_or_stop_selected(cx);
                });
            }
        });
        cx.on_action({
            let app_entity = app_entity.clone();
            move |_: &CopyAgentCliSelectedAction, cx| {
                app_entity.update(cx, |app, cx| {
                    app.copy_agent_cli_selected(cx);
                });
            }
        });
        cx.on_action({
            let win_handle = win_handle;
            let app_entity = app_entity.clone();
            move |_: &DeleteSelectedAction, cx| {
                let _ = win_handle.update(cx, |_, window, cx| {
                    app_entity.update(cx, |app, cx| {
                        app.delete_selected(window, cx);
                    });
                });
            }
        });
        cx.on_action({
            let win_handle = win_handle;
            let app_entity = app_entity.clone();
            move |_: &Escape, cx| {
                let _ = win_handle.update(cx, |_, window, cx| {
                    app_entity.update(cx, |app, cx| {
                        app.handle_escape_shortcut(window, cx);
                    });
                });
            }
        });

        cx.activate(true);
    });

    cleanup_supervisor.stop_all();
}
