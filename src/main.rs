pub mod db;
pub mod geoip;
pub mod launcher;
pub mod models;
pub mod proxy_tunnel;
pub mod ui;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use gpui_kit::assets::Assets;
use gpui_kit::component::theme::{Theme, ThemeMode};
use gpui_kit::*;

use crate::db::Database;
use crate::launcher::RunningProcess;
use crate::ui::BonLoginApp;

fn main() {
    let tokio_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to start Tokio runtime");
    let tokio_handle = tokio_rt.handle().clone();

    if let Some(res) = crate::launcher::try_run_cli(&tokio_handle) {
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
    let db = Database::open_default().expect("Failed to open bonlogin.sqlite3");

    let running_processes: Arc<Mutex<HashMap<String, RunningProcess>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let cleanup_processes = running_processes.clone();

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

        let quit_procs = running_processes.clone();
        cx.on_app_quit(move |_| {
            let procs = quit_procs.clone();
            async move {
                if let Ok(mut map) = procs.lock() {
                    for (_, mut proc) in map.drain() {
                        proc.stop_gracefully();
                    }
                }
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

        let procs = running_processes.clone();
        let handle = tokio_handle.clone();
        gpui_kit::open_window(window_options, cx, move |window, cx| {
            window.activate_window();
            cx.new(|cx| BonLoginApp::new(db, handle, procs, window, cx))
        })
        .expect("Failed to open BonLogin window");
        cx.activate(true);
    });

    if let Ok(mut map) = cleanup_processes.lock() {
        for (_, mut proc) in map.drain() {
            proc.stop_gracefully();
        }
    }
}
