//! 查询语句自动补全：纯逻辑，无 gpui / 网络依赖，可独立单测。
//!
//! 思路：取光标前正在输入的 token（以空白 / 逻辑符为界），
//! - token 不含 `=` → 补全字段名（插入 `field="`）
//! - token 含 `=`  → 按已知字段补全常用值（插入完整 `field="value"`）

use std::ops::Range;

/// 一条补全项：`insert` 将整段替换当前 token；`hint` 为右侧灰字说明。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completion {
    pub insert: String,
    pub hint: &'static str,
}

const FIELDS: &[(&str, &str, bool)] = &[
    ("app=\"", "组件名，如 app=\"weblogic\"", true),
    ("title=\"", "网页标题", true),
    ("ip=\"", "IP / CIDR", true),
    ("port=", "端口，如 port=7001", true),
    ("host=\"", "主机名（域名或 IP）", true),
    ("domain=\"", "域名及子域名", true),
    ("protocol=\"", "协议 http/https/ssh/rdp", true),
    ("server=\"", "HTTP Server 响应头", true),
    ("os=\"", "操作系统 windows/linux", true),
    ("country=\"", "国家/地区码 CN/US/HK", true),
    ("city=\"", "城市", true),
    ("org=\"", "组织/单位", true),
    ("status_code=", "HTTP 状态码，如 200", true),
    ("body=\"", "网页正文关键词", true),
    ("cert=\"", "证书内容模糊匹配", true),
    ("favicon=\"", "favicon 图标 hash", true),
    ("banner=\"", "服务横幅，如 SSH-2.0", true),
    ("after=\"", "更新时间晚于，如 2026-01-01", true),
    ("before=\"", "更新时间早于", true),
    ("is_ipv6=", "仅 IPv6 资产 true/false", true),
    ("is_cloud=", "云上资产 true/false", true),
    ("header=\"", "HTTP 响应头（单引擎语法）", false),
    ("icp=\"", "ICP 备案号（单引擎语法）", false),
];

const VALUES: &[(&str, &[&str], bool)] = &[
    (
        "app",
        &[
            "weblogic", "tomcat", "nginx", "apache", "iis", "jenkins", "gitlab", "nacos", "zabbix",
        ],
        true,
    ),
    ("country", &["CN", "US", "HK", "JP", "SG", "DE", "KR"], true),
    (
        "protocol",
        &[
            "http", "https", "ssh", "rdp", "redis", "mysql", "smb", "ftp",
        ],
        true,
    ),
    (
        "port",
        &[
            "80", "443", "22", "3389", "8080", "7001", "6379", "9200", "3306",
        ],
        true,
    ),
    ("os", &["windows", "linux"], true),
    (
        "server",
        &["nginx", "apache", "iis", "tomcat", "openresty"],
        true,
    ),
    (
        "title",
        &["登录", "后台", "管理", "index", "dashboard", "login"],
        true,
    ),
    (
        "status_code",
        &["200", "301", "302", "401", "403", "404", "500", "502"],
        true,
    ),
    ("is_ipv6", &["true", "false"], true),
    ("is_cloud", &["true", "false"], true),
];

const MAX_ITEMS: usize = 8;

/// 光标（文本末尾）前当前 token 的字节范围。token 边界：空白、&、|、括号。
pub fn current_token_range(text: &str) -> Range<usize> {
    let start = text
        .char_indices()
        .rev()
        .take_while(|(_, c)| !matches!(c, ' ' | '\t' | '&' | '|' | '(' | ')'))
        .map(|(i, _)| i)
        .last()
        .unwrap_or(text.len());
    start..text.len()
}

/// 给出当前文本下应展示的补全列表；为空表示不展示弹层。
///
/// `common_only` 为聚合搜索模式（多引擎）时只提示公共字段。
pub fn completions(text: &str, common_only: bool) -> Vec<Completion> {
    let range = current_token_range(text);
    let token = &text[range];
    let token_lc = token.to_lowercase();

    if let Some((key, value)) = token.split_once('=') {
        // 值已用引号闭合（引号内有内容）→ 视为输入完成，不再提示。
        if value.len() > 1 && value.ends_with('"') {
            return vec![];
        }
        let value_lc = value.trim_matches('"').to_lowercase();
        return VALUES
            .iter()
            .find(|(k, _, _)| *k == key.trim().to_lowercase().as_str())
            .filter(|(_, _, common)| !common_only || *common)
            .map(|(key, values, _)| {
                values
                    .iter()
                    .filter(|v| value_lc.is_empty() || v.to_lowercase().starts_with(&value_lc))
                    .take(MAX_ITEMS)
                    .map(|v| Completion {
                        insert: format!("{key}=\"{v}\""),
                        hint: "常用值",
                    })
                    .collect()
            })
            .unwrap_or_default();
    }

    let source: Box<dyn Iterator<Item = &(&str, &str, bool)>> = if token_lc.is_empty() {
        Box::new(
            FIELDS
                .iter()
                .filter(|(_, _, common)| !common_only || *common)
                .take(6),
        )
    } else {
        Box::new(FIELDS.iter().filter(|(f, _, common)| {
            (!common_only || *common) && f.to_lowercase().starts_with(&token_lc)
        }))
    };
    source
        .take(MAX_ITEMS)
        .map(|(f, hint, _)| Completion {
            insert: (*f).to_string(),
            hint,
        })
        .collect()
}

/// 把补全项拼回文本：将 `current_token_range(text)` 替换为 `insert`。
pub fn apply(text: &str, insert: &str) -> String {
    let range = current_token_range(text);
    let mut out = String::with_capacity(text.len() + insert.len());
    out.push_str(&text[..range.start]);
    out.push_str(insert);
    out.push_str(&text[range.end..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_range_respects_delimiters() {
        assert_eq!(current_token_range("app=\"x\""), 0..7);
        assert_eq!(current_token_range("country=\"CN\" "), 13..13);
        assert_eq!(current_token_range("a && ti"), 5..7);
        assert_eq!(current_token_range("a | (por"), 5..8);
        assert_eq!(current_token_range(""), 0..0);
    }

    #[test]
    fn closed_value_suppresses_suggestions() {
        assert!(completions("country=\"CN\"", false).is_empty());
        // 刚打出开引号时仍应提示常用值；值未闭合时继续按前缀过滤。
        assert!(!completions("country=\"", false).is_empty());
        assert!(!completions("country=\"CN", false).is_empty());
    }

    #[test]
    fn completes_field_names() {
        let c = completions("cou", false);
        assert!(!c.is_empty());
        assert_eq!(c[0].insert, "country=\"");
        let c = completions("", false);
        assert_eq!(c.len(), 6);
    }

    #[test]
    fn common_mode_hides_native_only_fields() {
        // header / icp 为单引擎方言字段，聚合模式不提示。
        assert!(completions("he", true).is_empty());
        assert!(!completions("he", false).is_empty());
        assert!(completions("ic", true).is_empty());
        // host / server / org 已是公共字段，聚合模式正常提示。
        assert!(!completions("ho", true).is_empty());
        assert!(
            completions("cou", true)
                .iter()
                .any(|c| c.insert == "country=\"")
        );
    }

    #[test]
    fn completes_known_values() {
        let c = completions("country=\"", false);
        assert!(c.iter().any(|x| x.insert == "country=\"CN\""));
        let c = completions("port=7", false);
        assert!(c.iter().any(|x| x.insert == "port=\"7001\""));
        assert!(c.iter().all(|x| x.insert.ends_with('"')));
        // 状态码 / 布尔字段可补全常用值。
        assert!(
            completions("status_code=", true)
                .iter()
                .any(|x| x.insert == "status_code=\"200\"")
        );
        assert!(
            completions("is_ipv6=", true)
                .iter()
                .any(|x| x.insert == "is_ipv6=\"true\"")
        );
    }

    #[test]
    fn unknown_key_or_prefix_is_empty() {
        assert!(completions("foo=\"", false).is_empty());
        assert!(completions("zzz", false).is_empty());
    }

    #[test]
    fn apply_replaces_current_token() {
        assert_eq!(apply("a && cou", "country=\""), "a && country=\"");
        assert_eq!(apply("port=", "port=\"7001\""), "port=\"7001\"");
    }
}
