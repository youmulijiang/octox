pub mod dropdown;
pub mod icons;
pub mod input;
pub mod modal;
pub mod syntax;

use std::sync::RwLock;

use gpui::{Div, Styled, div, prelude::*, px, rgb};

/// 应用配色 token（参考 shadcn/ui 的 zinc 中性色 + blue 主色体系）。
///
/// 组件只按语义 token 取色，深浅两套配色自动适配；
/// 运行期经 `theme()` 读取激活主题，`set_active_theme` 切换
/// （设置 → 外观，选择持久化于 config.theme）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    /// 窗口底色。
    pub bg: u32,
    /// 头部 / 表头 / 状态栏等面板底色（card）。
    pub panel: u32,
    /// 次级按钮 / 未选中片底色（secondary）。
    pub panel_alt: u32,
    pub panel_alt_hover: u32,
    pub input_bg: u32,
    pub row_hover: u32,
    pub border: u32,
    pub text: u32,
    pub muted: u32,
    pub accent: u32,
    pub accent_hover: u32,
    pub ok: u32,
    pub danger: u32,
    /// 输入框占位文本色（placeholder）。
    pub placeholder: u32,
    /// 文本选区 / 选中行高亮，含 alpha（0xRRGGBBAA）。
    pub selection: u32,
}

impl Theme {
    /// 深色：shadcn zinc dark（zinc-950/900/800）+ blue-500 accent。
    pub const DARK: Self = Self {
        bg: 0x09090b,
        panel: 0x18181b,
        panel_alt: 0x27272a,
        panel_alt_hover: 0x3f3f46,
        input_bg: 0x131316,
        row_hover: 0x1f1f23,
        border: 0x27272a,
        text: 0xfafafa,
        muted: 0xa1a1aa,
        accent: 0x3b82f6,
        accent_hover: 0x2563eb,
        ok: 0x22c55e,
        danger: 0xef4444,
        placeholder: 0x52525b,
        selection: 0x3b82f640,
    };

    /// 浅色：shadcn zinc light（白底 + zinc 灰阶）+ blue-600 accent。
    pub const LIGHT: Self = Self {
        bg: 0xffffff,
        panel: 0xfafafa,
        panel_alt: 0xf4f4f5,
        panel_alt_hover: 0xe4e4e7,
        input_bg: 0xffffff,
        row_hover: 0xf4f4f5,
        border: 0xe4e4e7,
        text: 0x09090b,
        muted: 0x71717a,
        accent: 0x2563eb,
        accent_hover: 0x1d4ed8,
        ok: 0x16a34a,
        danger: 0xdc2626,
        placeholder: 0xa1a1aa,
        selection: 0x2563eb26,
    };
}

static ACTIVE_THEME: RwLock<Theme> = RwLock::new(Theme::DARK);

/// 当前激活主题（样式期随时可读）。
pub fn theme() -> Theme {
    *ACTIVE_THEME.read().expect("theme lock poisoned")
}

/// 切换激活主题（调用方负责持久化 config.theme 并刷新视图）。
pub fn set_active_theme(theme: Theme) {
    *ACTIVE_THEME.write().expect("theme lock poisoned") = theme;
}

/// 通用按钮样式；调用方继续链 `.id(...)` 与 `.on_click(...)`。
pub fn button(label: impl Into<String>, primary: bool) -> Div {
    let t = theme();
    let (bg, hover) = if primary {
        (t.accent, t.accent_hover)
    } else {
        (t.panel_alt, t.panel_alt_hover)
    };
    div()
        .px_2()
        .py_1()
        .rounded_md()
        .text_size(px(13.))
        .text_color(rgb(if primary { 0xffffff } else { t.text }))
        .bg(rgb(bg))
        .cursor_pointer()
        .hover(move |s| s.bg(rgb(hover)))
        .child(label.into())
}

/// 设置面板等处的小节标签。
pub fn field_label(text: &str) -> Div {
    div()
        .text_size(px(12.))
        .text_color(rgb(theme().muted))
        .child(text.to_string())
}
