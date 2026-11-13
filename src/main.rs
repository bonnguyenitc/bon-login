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
use gpui_kit::component::theme::{Theme, ThemeMode};
use gpui_kit::*;

use crate::db::Database;
use crate::launcher::RuntimeSupervisor;
use crate::ui::BonLoginApp;
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

        let window_options = WindowOptions {
            window_bounds: Some(WindowBounds::centered(size(px(1420.), px(840.)), cx)),
            titlebar: Some(TitlebarOptions {
                title: None,
                appears_transparent: true,
                traffic_light_position: Some(point(px(16.), px(16.))),
            }),
            window_background: WindowBackgroundAppearance::Blurred,
            ..Default::default()
        };

        let sup = supervisor.clone();
        let handle = tokio_handle.clone();
        gpui_kit::open_window(window_options, cx, move |window, cx| {
            window.activate_window();
            cx.new(|cx| BonLoginApp::new(db, handle, sup, window, cx))
        })
        .expect("Failed to open BonLogin window");
        cx.activate(true);
    });

    cleanup_supervisor.stop_all();
}
