pub mod censys;
pub mod daydaymap;
pub mod fofa;
pub mod hunter;
pub mod quake;
pub mod shodan;
pub mod threatbook;
pub mod virustotal;
pub mod zone0;
pub mod zoomeye;

use std::fmt;

use serde_json::Value;

use crate::asset::Engine;
use crate::config::Config;

/// 单引擎一次查询的归一化结果。
#[derive(Debug)]
pub struct SearchResult {
    pub total: u64,
    pub assets: Vec<crate::asset::Asset>,
    /// 平台返回的剩余配额（如有）。
    pub quota: Option<String>,
}

#[derive(Debug)]
pub enum EngineError {
    /// 网络层错误（DNS/连接/超时/HTTP 非 2xx）。
    Http(String),
    /// 平台业务错误（error=true / code!=0，含配额不足、key 无效等）。
    Api(String),
    /// 响应不符合预期结构。
    Parse(String),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::Http(m) => write!(f, "网络错误: {m}"),
            EngineError::Api(m) => write!(f, "{m}"),
            EngineError::Parse(m) => write!(f, "响应解析失败: {m}"),
        }
    }
}

pub type Result<T> = std::result::Result<T, EngineError>;

impl Engine {
    /// 发起一次查询。分页语义已归一化：`page` 从 1 开始，`size` 为每页条数。
    pub fn search(
        self,
        config: &Config,
        query: &str,
        page: u32,
        size: u32,
    ) -> Result<SearchResult> {
        match self {
            Engine::Fofa => fofa::search(config, query, page, size),
            Engine::Hunter => hunter::search(config, query, page, size),
            Engine::Quake => quake::search(config, query, page, size),
            Engine::Shodan => shodan::search(config, query, page, size),
            Engine::ZoomEye => zoomeye::search(config, query, page, size),
            Engine::ThreatBook => threatbook::search(config, query, page, size),
            Engine::Zone0 => zone0::search(config, query, page, size),
            Engine::DayDayMap => daydaymap::search(config, query, page, size),
            Engine::VirusTotal => virustotal::search(config, query, page, size),
            Engine::Censys => censys::search(config, query, page, size),
        }
    }
}

/// HTTP 客户端：超时与代理来自设置（搜索 Tab 可自由调整）。
fn http_agent(settings: &Config) -> ureq::Agent {
    let mut builder = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(
            settings.request_timeout_secs.clamp(1, 600),
        )))
        .http_status_as_error(false);
    if settings.proxy_enabled {
        let url = settings.proxy_url.trim();
        if !url.is_empty() {
            match ureq::Proxy::new(url) {
                Ok(proxy) => builder = builder.proxy(Some(proxy)),
                Err(e) => eprintln!("octox: 代理配置无效（{url}）：{e}"),
            }
        }
    }
    ureq::Agent::new_with_config(builder.build())
}

fn fetch_json(settings: &Config, url: &str) -> Result<Value> {
    fetch_json_with_headers(settings, url, &[])
}

/// 带自定义请求头的 GET（ZoomEye / VirusTotal 等以请求头认证的平台）。
fn fetch_json_with_headers(
    settings: &Config,
    url: &str,
    headers: &[(&str, &str)],
) -> Result<Value> {
    let mut request = http_agent(settings)
        .get(url)
        .header("User-Agent", "octox/0.1");
    for (key, value) in headers {
        request = request.header(*key, *value);
    }
    let response = request
        .call()
        .map_err(|e| EngineError::Http(e.to_string()))?;
    read_body_json(response)
}

fn post_json(
    settings: &Config,
    url: &str,
    headers: &[(&str, &str)],
    body: &Value,
) -> Result<Value> {
    let mut request = http_agent(settings)
        .post(url)
        .header("User-Agent", "octox/0.1");
    for (key, value) in headers {
        request = request.header(*key, *value);
    }
    let response = request
        .send_json(body)
        .map_err(|e| EngineError::Http(e.to_string()))?;
    read_body_json(response)
}

fn read_body_json(response: ureq::http::Response<ureq::Body>) -> Result<Value> {
    let status = response.status().as_u16();
    let body = response
        .into_body()
        .read_to_string()
        .map_err(|e| EngineError::Http(e.to_string()))?;
    if !(200..300).contains(&status) {
        return Err(EngineError::Http(format!(
            "HTTP {status}: {}",
            truncate(&body, 120)
        )));
    }
    serde_json::from_str(&body)
        .map_err(|e| EngineError::Parse(format!("{} ({})", truncate(&body, 120), e)))
}

pub(crate) fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let t: String = s.chars().take(max_chars).collect();
        format!("{t}…")
    }
}

/// 宽松取值：字符串原样、数字/布尔转字符串、Null 与缺失为 `-`。
pub(crate) fn sval(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "-".to_string(),
        other => other.to_string(),
    }
}

pub(crate) fn field(obj: &Value, key: &str) -> String {
    obj.get(key).map(sval).unwrap_or_else(|| "-".to_string())
}

/// 按路径逐层取嵌套字段（如 &["service", "http", "title"]）。
pub(crate) fn sget<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = v;
    for p in path {
        cur = cur.get(*p)?;
    }
    Some(cur)
}

/// 一条候选扩展字段：展示标签 + JSON 取值路径（+ FOFA fields 参数名）。
pub(crate) struct ExtraSpec {
    pub label: &'static str,
    pub path: &'static [&'static str],
    /// FOFA `fields` 参数的字段名（仅 FOFA 使用，其他引擎为空）。
    pub fofa_field: &'static str,
}

/// 各引擎的候选扩展字段目录（用户可在引擎抽屉里勾选显示/隐藏）。
pub(crate) fn extra_catalog(engine: Engine) -> &'static [ExtraSpec] {
    const EMPTY: &[ExtraSpec] = &[];
    match engine {
        Engine::Fofa => &[
            ExtraSpec {
                label: "ICP 备案",
                path: &["icp"],
                fofa_field: "icp",
            },
            ExtraSpec {
                label: "服务横幅",
                path: &["banner"],
                fofa_field: "banner",
            },
        ],
        Engine::Hunter => &[
            ExtraSpec {
                label: "域名",
                path: &["domain"],
                fofa_field: "",
            },
            ExtraSpec {
                label: "省份",
                path: &["province"],
                fofa_field: "",
            },
            ExtraSpec {
                label: "城市",
                path: &["city"],
                fofa_field: "",
            },
            ExtraSpec {
                label: "运营商",
                path: &["isp"],
                fofa_field: "",
            },
            ExtraSpec {
                label: "编号",
                path: &["number"],
                fofa_field: "",
            },
        ],
        Engine::Quake => &[
            ExtraSpec {
                label: "域名",
                path: &["domain"],
                fofa_field: "",
            },
            ExtraSpec {
                label: "省份",
                path: &["location", "province_cn"],
                fofa_field: "",
            },
            ExtraSpec {
                label: "运营商",
                path: &["isp"],
                fofa_field: "",
            },
            ExtraSpec {
                label: "favicon",
                path: &["favicon"],
                fofa_field: "",
            },
        ],
        Engine::Shodan => &[
            ExtraSpec {
                label: "操作系统",
                path: &["os"],
                fofa_field: "",
            },
            ExtraSpec {
                label: "主机名",
                path: &["hostnames"],
                fofa_field: "",
            },
            ExtraSpec {
                label: "ASN",
                path: &["asn"],
                fofa_field: "",
            },
            ExtraSpec {
                label: "运营商",
                path: &["isp"],
                fofa_field: "",
            },
        ],
        Engine::ZoomEye => &[
            ExtraSpec {
                label: "网站",
                path: &["site"],
                fofa_field: "",
            },
            ExtraSpec {
                label: "端口协议",
                path: &["portinfo", "service"],
                fofa_field: "",
            },
        ],
        Engine::ThreatBook => &[
            ExtraSpec {
                label: "省份",
                path: &["ip", "location", "region"],
                fofa_field: "",
            },
            ExtraSpec {
                label: "运营商",
                path: &["ip", "isp"],
                fofa_field: "",
            },
            ExtraSpec {
                label: "ASN",
                path: &["ip", "asn", "number"],
                fofa_field: "",
            },
        ],
        Engine::Zone0 => EMPTY,
        Engine::DayDayMap => &[
            ExtraSpec {
                label: "域名",
                path: &["domain"],
                fofa_field: "",
            },
            ExtraSpec {
                label: "传输层",
                path: &["protocol"],
                fofa_field: "",
            },
        ],
        Engine::VirusTotal => &[
            ExtraSpec {
                label: "实体类型",
                path: &["type"],
                fofa_field: "",
            },
            ExtraSpec {
                label: "所属",
                path: &["attributes", "as_owner"],
                fofa_field: "",
            },
        ],
        Engine::Censys => &[
            ExtraSpec {
                label: "主机名",
                path: &["dns", "names"],
                fofa_field: "",
            },
            ExtraSpec {
                label: "ASN",
                path: &["autonomous_system", "asn"],
                fofa_field: "",
            },
        ],
    }
}

/// 从引擎 JSON 提取特有字段：按目录顺序取值，`enabled` 为 None 时全部收录
///（默认行为），否则仅收录用户勾选的标签。值存在、非空且非 "-" 才收录，保序去重。
pub(crate) fn extract_extras(
    item: &Value,
    catalog: &[ExtraSpec],
    enabled: Option<&[String]>,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for spec in catalog {
        if let Some(list) = enabled
            && !list.iter().any(|l| l == spec.label)
        {
            continue;
        }
        if out.iter().any(|(l, _)| l == spec.label) {
            continue;
        }
        let Some(raw) = sget(item, spec.path) else {
            continue;
        };
        // 数组（如 Shodan hostnames / Censys dns.names）拼接为逗号分隔文本。
        let value = match raw {
            Value::Array(list) => list
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", "),
            other => sval(other),
        };
        let value = value.trim().to_string();
        if !value.is_empty() && value != "-" {
            out.push((spec.label.to_string(), value));
        }
    }
    out
}

pub(crate) fn dash_or(s: String) -> String {
    if s.trim().is_empty() {
        "-".to_string()
    } else {
        s
    }
}
