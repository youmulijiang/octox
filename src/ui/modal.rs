//! 模态弹层公共壳：全屏遮罩 + 居中面板。
//!
//! 设置 / 规则等弹层共用同一开合与视觉模式，避免各处复制样式。

use gpui::{Div, Stateful, Styled, div, prelude::*, px, rgb, rgba};

use crate::ui::theme;

/// 全屏遮罩（`occlude` 拦截下层点击）。
/// 面板高度超过窗口时整层可纵向滚动；横向留边让面板在窄窗口内收缩。
/// 调用方继续链 `.key_context(..).on_action(关闭动作)` 与 `.child(panel(..))`。
pub fn overlay(id: &'static str) -> Stateful<Div> {
    div()
        .id(id)
        .absolute()
        .inset_0()
        .size_full()
        .bg(rgba(0x0000008c))
        .flex()
        .justify_center()
        // 顶端对齐：避免 flex 交叉轴 stretch 把面板拉满整窗高度。
        .items_start()
        .px_2()
        .overflow_y_scroll()
        .occlude()
}

/// 居中面板壳：宽度超出窗口时自动收缩（`max_w_full`）。
pub fn panel(width: f32) -> Div {
    div()
        .mt(px(120.))
        .mb(px(24.))
        .w(px(width))
        .max_w_full()
        .flex()
        .flex_col()
        .gap_2()
        .p_4()
        .rounded_lg()
        .bg(rgb(theme().panel))
        .border_1()
        .border_color(rgb(theme().border))
        .shadow_lg()
}
