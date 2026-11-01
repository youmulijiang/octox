#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod asset;
mod autocomplete;
mod config;
mod engines;
mod export;
mod mcp;
mod translate;
mod ui;

use std::time::Duration;

use gpui::{
    App, AppContext, Application, Bounds, Focusable, KeyBinding, TitlebarOptions, WindowBounds,
    WindowOptions, px, size,
};

use crate::app::{CloseOverlay, OctoxApp, Quit, SuggestAccept, SuggestNext, SuggestPrev};
use crate::config::Config;
use crate::ui::icons::Assets;
use crate::ui::input::{
    Backspace, Copy, Cut, Delete, End, Home, Left, Paste, Right, SelectAll, SelectLeft,
    SelectRight, Submit,
};
use crate::ui::{Theme, set_active_theme};

fn main() {
    // MCP 模式：stdio 服务，不打开窗口；stdout 只承载 JSON-RPC。
    if std::env::args().any(|a| a == "--mcp") {
        mcp::run_server();
        return;
    }

    let smoke = std::env::args().any(|a| a == "--smoke");
    let demo = std::env::args().any(|a| a == "--demo");
    Application::new()
        .with_assets(Assets)
        .run(move |cx: &mut App| {
            cx.bind_keys([
                KeyBinding::new("backspace", Backspace, None),
                KeyBinding::new("delete", Delete, None),
                KeyBinding::new("left", Left, None),
                KeyBinding::new("right", Right, None),
                KeyBinding::new("shift-left", SelectLeft, None),
                KeyBinding::new("shift-right", SelectRight, None),
                KeyBinding::new("ctrl-a", SelectAll, None),
                KeyBinding::new("cmd-a", SelectAll, None),
                KeyBinding::new("ctrl-v", Paste, None),
                KeyBinding::new("cmd-v", Paste, None),
                KeyBinding::new("ctrl-c", Copy, None),
                KeyBinding::new("cmd-c", Copy, None),
                KeyBinding::new("ctrl-x", Cut, None),
                KeyBinding::new("cmd-x", Cut, None),
                KeyBinding::new("home", Home, None),
                KeyBinding::new("end", End, None),
                KeyBinding::new("enter", Submit, None),
                KeyBinding::new("up", SuggestPrev, None),
                KeyBinding::new("down", SuggestNext, None),
                KeyBinding::new("tab", SuggestAccept, None),
                KeyBinding::new("escape", CloseOverlay, None),
                KeyBinding::new("ctrl-q", Quit, None),
                KeyBinding::new("cmd-q", Quit, None),
            ]);
            cx.on_action(|_: &Quit, cx| cx.quit());

            // 主题先于首帧激活，避免开窗闪错色。
            let theme = if Config::load().theme == "light" {
                Theme::LIGHT
            } else {
                Theme::DARK
            };
            set_active_theme(theme);

            let bounds = Bounds::centered(None, size(px(1280.), px(800.)), cx);
            let window = cx
                .open_window(
                    WindowOptions {
                        window_bounds: Some(WindowBounds::Windowed(bounds)),
                        window_min_size: Some(size(px(640.), px(480.))),
                        titlebar: Some(TitlebarOptions {
                            title: Some("Octox — 测绘引擎聚合搜索".into()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    |_, cx| cx.new(|cx| OctoxApp::new(cx).with_demo(demo)),
                )
                .expect("open main window");
            cx.activate(true);

            window
                .update(cx, |root, window, cx| {
                    let query_focus = root.query_input.focus_handle(cx);
                    window.focus(&query_focus);
                })
                .ok();

            // 冒烟自检：开窗 3 秒后自动退出，验证渲染栈可正常启动。
            if smoke {
                cx.spawn(async move |cx| {
                    cx.background_executor().timer(Duration::from_secs(3)).await;
                    let _ = cx.update(|cx| cx.quit());
                })
                .detach();
            }
        });
}
