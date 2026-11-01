//! 引擎模式下拉框（搜索框左侧段）。
//!
//! 单选语义：FOFA / Hunter / Quake / 聚合引擎 四选一。
//! 聚合模式下参与哪些引擎由设置中的 `aggregate_engines` 决定（默认全部），
//! 本组件只持有模式并对外发 `Changed` 事件（高内聚：不感知配置细节）。
//!
//! 关闭时机：「点外部关闭」挂在弹层自身（而非触发按钮所在的根节点）上——
//! 弹层绝对定位在根节点命中区域之外，若挂在根节点上，点击选项也会被判定为
//! 外点而提前关闭，导致选项永远无法选中。

use gpui::{
    ClickEvent, Context, EventEmitter, MouseDownEvent, Pixels, Point, Render, SharedString, Window,
    deferred, div, prelude::*, px, rgb,
};

use crate::asset::Engine;
use crate::ui::icons::{self, icon};
use crate::ui::theme;

/// 搜索模式：单引擎（原生语法直通）或聚合（公共语法 + 方言翻译）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchMode {
    Single(Engine),
    Aggregate,
}

pub struct EngineDropdown {
    mode: SearchMode,
    open: bool,
    /// 外点关闭时记录的按下坐标：若触发按钮随后的 click 与之同源（同一次按下），
    /// 说明该点击已被关闭逻辑消费，按钮不再 toggle（否则会关了又开）。
    dismissed_down: Option<Point<Pixels>>,
}

#[derive(Debug)]
pub enum DropdownEvent {
    /// 模式切换。
    Changed,
}

impl EngineDropdown {
    pub fn new() -> Self {
        Self {
            mode: SearchMode::Aggregate,
            open: false,
            dismissed_down: None,
        }
    }

    pub fn mode(&self) -> SearchMode {
        self.mode
    }

    pub fn is_aggregate(&self) -> bool {
        self.mode == SearchMode::Aggregate
    }

    fn label(&self) -> &'static str {
        match self.mode {
            SearchMode::Single(e) => e.name(),
            SearchMode::Aggregate => "聚合引擎",
        }
    }

    fn mode_accent(&self) -> u32 {
        match self.mode {
            SearchMode::Single(e) => e.accent(),
            SearchMode::Aggregate => theme().accent,
        }
    }

    fn set_mode(&mut self, mode: SearchMode, cx: &mut Context<Self>) {
        if self.mode != mode {
            self.mode = mode;
            cx.emit(DropdownEvent::Changed);
        }
        self.open = false;
        cx.notify();
    }
}

impl Render for EngineDropdown {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .relative()
            .h_full()
            .flex_shrink_0()
            .child(
                div()
                    .id("engine-dd-btn")
                    .flex()
                    .items_center()
                    .gap_1()
                    .w(px(124.))
                    .h_full()
                    .pl_2()
                    .pr_1()
                    .border_r_1()
                    .border_color(rgb(if self.open {
                        theme().accent
                    } else {
                        theme().border
                    }))
                    .bg(rgb(if self.open {
                        theme().panel
                    } else {
                        theme().panel_alt
                    }))
                    .cursor_pointer()
                    .hover(|s| s.bg(rgb(theme().row_hover)))
                    .text_size(px(12.))
                    .text_color(rgb(theme().text))
                    .child(div().size_2().rounded_full().bg(rgb(self.mode_accent())))
                    .child(div().flex_1().truncate().child(self.label()))
                    .child(icon(icons::CHEVRON_DOWN, 12., theme().muted))
                    .on_click(cx.listener(|this, event: &ClickEvent, _, cx| {
                        if let ClickEvent::Mouse(click) = event
                            && this.dismissed_down.take() == Some(click.down.position)
                        {
                            return;
                        }
                        this.open = !this.open;
                        cx.notify();
                    })),
            )
            .when(self.open, |d| {
                // 单选选项：三个引擎 + 聚合引擎。
                let mut options: Vec<(SearchMode, &'static str, u32)> = Engine::ALL
                    .iter()
                    .map(|e| (SearchMode::Single(*e), e.name(), e.accent()))
                    .collect();
                options.push((SearchMode::Aggregate, "聚合引擎", theme().accent));

                d.child(deferred(
                    div()
                        .absolute()
                        .left(px(0.))
                        .top(px(32.))
                        .w(px(176.))
                        .flex()
                        .flex_col()
                        .py_1()
                        .rounded_md()
                        .border_1()
                        .border_color(rgb(theme().border))
                        .bg(rgb(theme().panel))
                        .shadow_lg()
                        // 遮蔽弹层下层的命中（结果行等），点击交给弹层自身。
                        .occlude()
                        .on_mouse_down_out(cx.listener(|this, event: &MouseDownEvent, _, cx| {
                            this.open = false;
                            this.dismissed_down = Some(event.position);
                            cx.notify();
                        }))
                        .children(options.into_iter().enumerate().map(
                            |(idx, (mode, name, accent))| {
                                let active = self.mode == mode;
                                div()
                                    .id(SharedString::from(format!("mode-item-{idx}")))
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .px_2()
                                    .py_1()
                                    .text_size(px(12.))
                                    .cursor_pointer()
                                    .hover(|s| s.bg(rgb(theme().row_hover)))
                                    .on_click(
                                        cx.listener(move |this, _, _, cx| this.set_mode(mode, cx)),
                                    )
                                    .child(
                                        div().w(px(14.)).flex().justify_center().children(
                                            active.then(|| icon(icons::CHECK, 12., accent)),
                                        ),
                                    )
                                    .child(div().size_2().rounded_full().bg(rgb(if active {
                                        accent
                                    } else {
                                        theme().border
                                    })))
                                    .child(name)
                            },
                        )),
                ))
            })
    }
}

impl EventEmitter<DropdownEvent> for EngineDropdown {}
