//! 公共查询语法与各引擎方言翻译。
//!
//! 聚合搜索（同时选择 ≥2 个引擎）时，查询语句只允许使用所有参与引擎共有的
//! 语法子集（公共字段 + `&&` / `||` 组合）。本模块把公共语法解析为 AST，再按
//! 各引擎方言渲染（`CommonField::t` 按 `Engine::index()` 索引模板，空串表示
//! 该引擎不支持此字段，渲染时明确报错）；单引擎模式不走翻译，直接使用该引擎
//! 原生语法。
//!
//! 纯逻辑模块，无 gpui / 网络依赖，可独立单测。

use crate::asset::Engine;

/// 公共字段表：聚合搜索允许的字段及各引擎写法模板（`{v}` 为值占位，
/// 空串 = 该引擎不支持；顺序与 `Engine::ALL` 严格一致）。
pub struct CommonField {
    pub field: &'static str,
    pub desc: &'static str,
    /// 各引擎写法模板，按 `Engine::ALL` 下标索引。
    pub t: [&'static str; Engine::COUNT],
}

pub const COMMON_FIELDS: &[CommonField] = &[
    CommonField {
        field: "ip",
        desc: "IP / CIDR 网段",
        t: [
            "ip=\"{v}\"",
            "ip=\"{v}\"",
            "ip:\"{v}\"",
            "ip:{v}",
            "ip:{v}",
            "ip=\"{v}\"",
            "ip===\"{v}\"",
            "ip=\"{v}\"",
            "entity:ip_addresses ip:{v}",
            "ip:{v}",
        ],
    },
    CommonField {
        field: "port",
        desc: "端口（数字）",
        t: [
            "port={v}",
            "port=\"{v}\"",
            "port:{v}",
            "port:{v}",
            "port:{v}",
            "port=\"{v}\"",
            "port===\"{v}\"",
            "port=\"{v}\"",
            "",
            "services.port:{v}",
        ],
    },
    CommonField {
        field: "title",
        desc: "网页标题",
        t: [
            "title=\"{v}\"",
            "web.title=\"{v}\"",
            "title:\"{v}\"",
            "",
            "title:\"{v}\"",
            "title=\"{v}\"",
            "title===\"{v}\"",
            "title=\"{v}\"",
            "",
            "services.http.response.html_title:\"{v}\"",
        ],
    },
    CommonField {
        field: "domain",
        desc: "域名及子域名",
        t: [
            "domain=\"{v}\"",
            "domain.suffix=\"{v}\"",
            "domain:\"{v}\"",
            "",
            "site:{v}",
            "domain=\"{v}\"",
            "domain===\"{v}\"",
            "domain=\"{v}\"",
            "entity:domains domain:{v}",
            "dns.names:{v}",
        ],
    },
    CommonField {
        field: "app",
        desc: "组件名（取值参考各平台组件库）",
        t: [
            "app=\"{v}\"",
            "app.name=\"{v}\"",
            "app:\"{v}\"",
            "",
            "app:{v}",
            "app=\"{v}\"",
            "",
            "",
            "",
            "services.software:{v}",
        ],
    },
    CommonField {
        field: "protocol",
        desc: "协议 http/https/ssh/rdp/redis/mysql",
        t: [
            "protocol=\"{v}\"",
            "protocol=\"{v}\"",
            "service:{v}",
            "",
            "service:{v}",
            "protocol=\"{v}\"",
            "",
            "service=\"{v}\"",
            "",
            "services.service_name:{v}",
        ],
    },
    CommonField {
        field: "country",
        desc: "国家/地区码（ISO2，自动映射）",
        t: [
            "country=\"{v}\"",
            "country=\"{v}\"",
            "country:{v}",
            "country:{v}",
            "country:{v}",
            "country=\"{v}\"",
            "",
            "country=\"{v}\"",
            "",
            "location.country:{v}",
        ],
    },
    CommonField {
        field: "city",
        desc: "城市",
        t: [
            "city=\"{v}\"",
            "city=\"{v}\"",
            "city:{v}",
            "city:{v}",
            "city:{v}",
            "city=\"{v}\"",
            "",
            "city=\"{v}\"",
            "",
            "location.city:{v}",
        ],
    },
    CommonField {
        field: "os",
        desc: "操作系统 windows/linux",
        t: [
            "os=\"{v}\"",
            "os=\"{v}\"",
            "os:{v}",
            "os:{v}",
            "os:{v}",
            "",
            "",
            "",
            "",
            "",
        ],
    },
    CommonField {
        field: "host",
        desc: "主机名（域名或 IP）",
        t: [
            "host=\"{v}\"",
            "hostname=\"{v}\"",
            "hostname:\"{v}\"",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ],
    },
    CommonField {
        field: "server",
        desc: "HTTP Server 响应头，如 nginx",
        t: [
            "server=\"{v}\"",
            "header.server=\"{v}\"",
            "server:\"{v}\"",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ],
    },
    CommonField {
        field: "org",
        desc: "组织/单位",
        t: [
            "org=\"{v}\"",
            "ip.company=\"{v}\"",
            "owner:\"{v}\"",
            "org:\"{v}\"",
            "",
            "",
            "",
            "",
            "",
            "autonomous_system.description:{v}",
        ],
    },
    CommonField {
        field: "status_code",
        desc: "HTTP 状态码，如 200",
        t: [
            "status_code=\"{v}\"",
            "http.status=\"{v}\"",
            "http_status:\"{v}\"",
            "",
            "",
            "status_code=\"{v}\"",
            "",
            "",
            "",
            "services.http.response.status_code:{v}",
        ],
    },
    CommonField {
        field: "body",
        desc: "网页正文关键词",
        t: [
            "body=\"{v}\"",
            "web.body=\"{v}\"",
            "response:\"{v}\"",
            "",
            "",
            "",
            "",
            "",
            "",
            "services.http.response.body:\"{v}\"",
        ],
    },
    CommonField {
        field: "cert",
        desc: "证书内容模糊匹配",
        t: [
            "cert=\"{v}\"",
            "cert=\"{v}\"",
            "cert:\"{v}\"",
            "",
            "",
            "cert=\"{v}\"",
            "",
            "",
            "",
            "",
        ],
    },
    CommonField {
        field: "favicon",
        desc: "favicon 图标 hash",
        t: [
            "icon_hash=\"{v}\"",
            "web.icon=\"{v}\"",
            "favicon:\"{v}\"",
            "",
            "iconhash:\"{v}\"",
            "",
            "",
            "",
            "",
            "",
        ],
    },
    CommonField {
        field: "banner",
        desc: "服务横幅（含非 HTTP 服务），如 SSH-2.0",
        t: [
            "banner=\"{v}\"",
            "banner=\"{v}\"",
            "banner:\"{v}\"",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ],
    },
    CommonField {
        field: "after",
        desc: "更新时间晚于（yyyy-MM-dd）",
        t: [
            "after=\"{v}\"",
            "after=\"{v}\"",
            "after:\"{v}\"",
            "after:{v}",
            "after:\"{v}\"",
            "after=\"{v}\"",
            "",
            "",
            "",
            "",
        ],
    },
    CommonField {
        field: "before",
        desc: "更新时间早于（yyyy-MM-dd）",
        t: [
            "before=\"{v}\"",
            "before=\"{v}\"",
            "before:\"{v}\"",
            "before:{v}",
            "before:\"{v}\"",
            "before=\"{v}\"",
            "",
            "",
            "",
            "",
        ],
    },
    CommonField {
        field: "is_ipv6",
        desc: "仅 IPv6 资产（true/false）",
        t: [
            "is_ipv6=\"{v}\"",
            "isipv6=\"{v}\"",
            "is_ipv6:\"{v}\"",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ],
    },
    CommonField {
        field: "is_cloud",
        desc: "云上资产（true/false）",
        t: [
            "is_cloud=\"{v}\"",
            "iscloud=\"{v}\"",
            "is_cloud:\"{v}\"",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ],
    },
];

/// ISO2 → Quake 国家英文名；未收录的值原样透传。
const QUAKE_COUNTRY: &[(&str, &str)] = &[
    ("CN", "China"),
    ("US", "United States"),
    ("HK", "Hong Kong"),
    ("MO", "Macao"),
    ("TW", "Taiwan"),
    ("JP", "Japan"),
    ("KR", "South Korea"),
    ("SG", "Singapore"),
    ("DE", "Germany"),
    ("FR", "France"),
    ("GB", "United Kingdom"),
    ("RU", "Russia"),
    ("IN", "India"),
    ("CA", "Canada"),
    ("AU", "Australia"),
    ("BR", "Brazil"),
];

/// 公共语法 AST。`&&` 优先级高于 `||`。
#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    Term { field: String, value: String },
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
}

/// 解析公共语法。失败时给出面向用户、可操作的错误说明。
pub fn parse_common(query: &str) -> Result<Node, String> {
    let tokens = tokenize(query)?;
    let mut parser = Parser { tokens, pos: 0 };
    let node = parser.parse_or()?;
    if parser.pos < parser.tokens.len() {
        return Err("语法错误：表达式之后有多余内容（示例：ip=\"1.2.3.4\" && port=80）".into());
    }
    Ok(node)
}

/// 解析并按引擎方言渲染（一步式便捷入口；主流程用 parse_common + render 分步调用）。
#[allow(dead_code)]
pub fn translate(query: &str, engine: Engine) -> Result<String, String> {
    render(&parse_common(query)?, engine)
}

/// 把公共语法 AST 渲染为某引擎的查询语句。
pub fn render(node: &Node, engine: Engine) -> Result<String, String> {
    match node {
        Node::Term { field, value } => {
            let cf = COMMON_FIELDS
                .iter()
                .find(|f| f.field == field)
                .ok_or_else(|| format!("未知公共字段 `{field}`"))?;
            let mut value = value.clone();
            let template = cf.t[engine.index()];
            if template.is_empty() {
                return Err(format!(
                    "{} 不支持公共字段 `{}` — 请切单引擎使用其原生语法",
                    engine.name(),
                    cf.field
                ));
            }
            match engine {
                Engine::Fofa => {
                    if cf.field == "os" {
                        value = capitalize(&value);
                    }
                }
                // Quake / Censys 的国家字段使用英文全名。
                Engine::Quake | Engine::Censys => {
                    if cf.field == "country" {
                        value = quake_country(&value);
                    }
                }
                _ => {}
            }
            if cf.field == "is_ipv6" || cf.field == "is_cloud" {
                value = value.to_lowercase();
            }
            Ok(template.replace("{v}", &value))
        }
        Node::And(a, b) => Ok(format!(
            "{} {} {}",
            render(a, engine)?,
            connector(engine, true),
            render(b, engine)?
        )),
        Node::Or(a, b) => Ok(format!(
            "{} {} {}",
            render(a, engine)?,
            connector(engine, false),
            render(b, engine)?
        )),
    }
}

fn connector(engine: Engine, and: bool) -> &'static str {
    match (engine, and) {
        (Engine::Quake, true) => "AND",
        (Engine::Quake, false) => "OR",
        (_, true) => "&&",
        (_, false) => "||",
    }
}

fn quake_country(value: &str) -> String {
    let upper = value.to_uppercase();
    QUAKE_COUNTRY
        .iter()
        .find(|(code, _)| *code == upper)
        .map(|(_, name)| name.to_string())
        .unwrap_or_else(|| value.to_string())
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

#[derive(Debug, PartialEq)]
enum Tok {
    Term { field: String, value: String },
    And,
    Or,
}

fn tokenize(query: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = query.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '&' && i + 1 < chars.len() && chars[i + 1] == '&' {
            toks.push(Tok::And);
            i += 2;
            continue;
        }
        if c == '|' && i + 1 < chars.len() && chars[i + 1] == '|' {
            toks.push(Tok::Or);
            i += 2;
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len()
                && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '.')
            {
                i += 1;
            }
            let field: String = chars[start..i].iter().collect();
            if i >= chars.len() || chars[i] != '=' {
                return Err(format!(
                    "字段 `{field}` 后缺少 `=`（示例：ip=\"1.2.3.4\" && port=80）"
                ));
            }
            i += 1;
            let value = if i < chars.len() && chars[i] == '"' {
                i += 1;
                let vs = i;
                while i < chars.len() && chars[i] != '"' {
                    i += 1;
                }
                if i >= chars.len() {
                    return Err("引号未闭合".into());
                }
                let v: String = chars[vs..i].iter().collect();
                i += 1;
                v
            } else {
                let vs = i;
                while i < chars.len()
                    && !chars[i].is_whitespace()
                    && chars[i] != '&'
                    && chars[i] != '|'
                {
                    i += 1;
                }
                if vs == i {
                    return Err(format!("字段 `{field}` 缺少值"));
                }
                chars[vs..i].iter().collect()
            };
            validate_term(&field, &value)?;
            toks.push(Tok::Term { field, value });
            continue;
        }
        return Err(format!(
            "无法识别的字符 `{c}` — 公共语法仅支持 `字段=值` 与 `&&` / `||`"
        ));
    }
    Ok(toks)
}

fn validate_term(field: &str, value: &str) -> Result<(), String> {
    let cf = COMMON_FIELDS
        .iter()
        .find(|f| f.field == field)
        .ok_or_else(|| {
            format!(
                "`{field}` 不在公共字段内 — 可用：{}",
                COMMON_FIELDS
                    .iter()
                    .map(|f| f.field)
                    .collect::<Vec<_>>()
                    .join(" / ")
            )
        })?;
    if cf.field == "port" && value.parse::<u32>().is_err() {
        return Err(format!("port 需为数字，得到 `{value}`"));
    }
    Ok(())
}

struct Parser {
    tokens: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos)
    }

    fn parse_or(&mut self) -> Result<Node, String> {
        let mut left = self.parse_and()?;
        while self.peek() == Some(&Tok::Or) {
            self.pos += 1;
            let right = self.parse_and()?;
            left = Node::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Node, String> {
        let mut left = self.parse_term()?;
        while self.peek() == Some(&Tok::And) {
            self.pos += 1;
            let right = self.parse_term()?;
            left = Node::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_term(&mut self) -> Result<Node, String> {
        match self.peek() {
            Some(Tok::Term { field, value }) => {
                let node = Node::Term {
                    field: field.clone(),
                    value: value.clone(),
                };
                self.pos += 1;
                Ok(node)
            }
            Some(_) => {
                Err("语法错误：此处应为 `字段=值`（示例：ip=\"1.2.3.4\" && port=80）".into())
            }
            None => Err("查询语句为空".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_binds_tighter_than_or() {
        let n = parse_common("ip=\"1.1.1.1\" && port=80 || title=\"x\"").unwrap();
        assert_eq!(
            n,
            Node::Or(
                Box::new(Node::And(
                    Box::new(Node::Term {
                        field: "ip".into(),
                        value: "1.1.1.1".into()
                    }),
                    Box::new(Node::Term {
                        field: "port".into(),
                        value: "80".into()
                    })
                )),
                Box::new(Node::Term {
                    field: "title".into(),
                    value: "x".into()
                })
            )
        );
    }

    #[test]
    fn translates_to_each_dialect() {
        let q = "ip=\"1.2.3.4\" && port=80";
        assert_eq!(
            translate(q, Engine::Fofa).unwrap(),
            "ip=\"1.2.3.4\" && port=80"
        );
        assert_eq!(
            translate(q, Engine::Hunter).unwrap(),
            "ip=\"1.2.3.4\" && port=\"80\""
        );
        assert_eq!(
            translate(q, Engine::Quake).unwrap(),
            "ip:\"1.2.3.4\" AND port:80"
        );
    }

    #[test]
    fn translates_or_and_field_mappings() {
        let q = "title=\"a\" || title=\"b\"";
        assert_eq!(
            translate(q, Engine::Quake).unwrap(),
            "title:\"a\" OR title:\"b\""
        );
        assert_eq!(
            translate(q, Engine::Hunter).unwrap(),
            "web.title=\"a\" || web.title=\"b\""
        );
        assert_eq!(
            translate("protocol=\"https\"", Engine::Quake).unwrap(),
            "service:https"
        );
        assert_eq!(
            translate("domain=\"qq.com\"", Engine::Hunter).unwrap(),
            "domain.suffix=\"qq.com\""
        );
    }

    #[test]
    fn maps_country_and_capitalizes_os() {
        assert_eq!(
            translate("country=\"CN\"", Engine::Quake).unwrap(),
            "country:China"
        );
        assert_eq!(
            translate("os=\"windows\"", Engine::Fofa).unwrap(),
            "os=\"Windows\""
        );
        assert_eq!(
            translate("country=\"zz\"", Engine::Quake).unwrap(),
            "country:zz"
        );
    }

    #[test]
    fn rejects_non_common_and_bad_values() {
        assert!(
            translate("web.title=\"x\"", Engine::Fofa)
                .unwrap_err()
                .contains("不在公共字段内")
        );
        assert!(
            translate("port=abc", Engine::Fofa)
                .unwrap_err()
                .contains("port 需为数字")
        );
        assert!(
            translate("ip=", Engine::Fofa)
                .unwrap_err()
                .contains("缺少值")
        );
        assert!(
            translate("ip=\"1.2.3.4", Engine::Fofa)
                .unwrap_err()
                .contains("引号未闭合")
        );
        assert!(
            translate("ip=\"1.2.3.4\" title=\"x\"", Engine::Fofa)
                .unwrap_err()
                .contains("多余内容")
        );
    }

    #[test]
    fn bare_values_are_accepted() {
        assert_eq!(
            translate("port=443 && protocol=https", Engine::Quake).unwrap(),
            "port:443 AND service:https"
        );
    }

    #[test]
    fn extended_common_fields_translate() {
        assert_eq!(
            translate("status_code=\"404\"", Engine::Hunter).unwrap(),
            "http.status=\"404\""
        );
        assert_eq!(
            translate("body=\"后台\"", Engine::Quake).unwrap(),
            "response:\"后台\""
        );
        assert_eq!(
            translate("favicon=\"123456\"", Engine::Fofa).unwrap(),
            "icon_hash=\"123456\""
        );
        assert_eq!(
            translate("org=\"Tencent\"", Engine::Hunter).unwrap(),
            "ip.company=\"Tencent\""
        );
        assert_eq!(
            translate("org=\"Tencent\"", Engine::Quake).unwrap(),
            "owner:\"Tencent\""
        );
    }

    #[test]
    fn all_engines_render_common_terms() {
        // 所有引擎都能渲染 ip 与 port（VirusTotal 不支持 port）。
        for engine in Engine::ALL {
            let r = translate("ip=\"1.2.3.4\"", engine).unwrap();
            assert!(!r.is_empty());
        }
        assert!(
            translate("port=80", Engine::VirusTotal)
                .unwrap_err()
                .contains("不支持公共字段")
        );
    }

    #[test]
    fn boolean_values_are_normalized() {
        assert_eq!(
            translate("is_ipv6=True", Engine::Fofa).unwrap(),
            "is_ipv6=\"true\""
        );
        assert_eq!(
            translate("is_cloud=FALSE", Engine::Hunter).unwrap(),
            "iscloud=\"false\""
        );
        assert_eq!(
            translate("is_ipv6=true", Engine::Quake).unwrap(),
            "is_ipv6:\"true\""
        );
    }
}
