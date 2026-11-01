//! 内嵌 SVG 图标与资产源。
//!
//! 图标以 `include_bytes!` 编译进二进制（release 无外部文件依赖）；
//! gpui 的 `svg()` 会用 `text_color` 为整张图着色，因此只需维护单色路径。

use std::borrow::Cow;

use gpui::{AssetSource, SharedString, prelude::*, px, rgb, svg};

pub const CHEVRON_DOWN: &str = "icons/chevron-down.svg";
pub const SEARCH: &str = "icons/search.svg";
pub const STAR: &str = "icons/star.svg";
pub const BOOK: &str = "icons/book.svg";
pub const TRASH: &str = "icons/trash.svg";
pub const CHECK: &str = "icons/check.svg";
pub const GEAR: &str = "icons/gear.svg";

pub struct Assets;

impl AssetSource for Assets {
    fn load(&self, path: &str) -> gpui::Result<Option<Cow<'static, [u8]>>> {
        let data: &'static [u8] = match path {
            CHEVRON_DOWN => include_bytes!("../../assets/icons/chevron-down.svg"),
            SEARCH => include_bytes!("../../assets/icons/search.svg"),
            STAR => include_bytes!("../../assets/icons/star.svg"),
            BOOK => include_bytes!("../../assets/icons/book.svg"),
            TRASH => include_bytes!("../../assets/icons/trash.svg"),
            CHECK => include_bytes!("../../assets/icons/check.svg"),
            GEAR => include_bytes!("../../assets/icons/gear.svg"),
            _ => return Ok(None),
        };
        Ok(Some(Cow::Borrowed(data)))
    }

    fn list(&self, _path: &str) -> gpui::Result<Vec<SharedString>> {
        Ok(vec![])
    }
}

/// 渲染一个单色图标。
pub fn icon(path: &'static str, size_px: f32, color: u32) -> impl IntoElement {
    svg().path(path).size(px(size_px)).text_color(rgb(color))
}
