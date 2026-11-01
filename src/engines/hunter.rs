use serde_json::{Value, json};

use super::{
    EngineError, Result, SearchResult, dash_or, extra_catalog, extract_extras, fetch_json, field,
    sval,
};
use crate::asset::{Asset, Engine};
use crate::config::Config;

const ENDPOINT: &str = "https://hunter.qianxin.com/openApi/search";

/// Hunter openApi：search 为 URL 编码的 JSON。
/// 官方文档语义：`start` 为页码（1 起），`limit` 为每页数量（≤100）。
/// 注：官方帮助中心为 JS 页面无法在线抓取核对，若平台报参数错误需回到此
/// 处核对（候选语义：start 为起始记录偏移）。
pub(crate) fn build_search_param(query: &str, page: u32, size: u32) -> String {
    json!({ "query": query, "start": page, "limit": size.min(100) }).to_string()
}

pub(crate) fn build_url(api_key: &str, query: &str, page: u32, size: u32) -> String {
    format!(
        "{ENDPOINT}?api-key={}&search={}&is_web_search=3",
        urlencoding::encode(api_key),
        urlencoding::encode(&build_search_param(query, page, size)),
    )
}

pub(crate) fn search(config: &Config, query: &str, page: u32, size: u32) -> Result<SearchResult> {
    let creds = &config.hunter;
    if creds.api_key.trim().is_empty() {
        return Err(EngineError::Api(
            "Hunter: 未配置 api-key（右上角设置）".into(),
        ));
    }
    let url = build_url(&creds.api_key, query, page, size);
    let value = fetch_json(config, &url)?;
    let enabled = config.extra_enabled(Engine::Hunter).map(|v| v.as_slice());
    parse_response(&value, enabled)
}

/// 成功响应：`{"code":200,"data":{"total":N,"rest_quota":"...","arr":[...]}}`。
pub(crate) fn parse_response(v: &Value, enabled: Option<&[String]>) -> Result<SearchResult> {
    let code = v.get("code").and_then(Value::as_i64).unwrap_or(-1);
    if code != 200 {
        let msg = v
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("未知错误");
        return Err(EngineError::Api(format!("Hunter: {msg}")));
    }
    let data = v.get("data").cloned().unwrap_or(Value::Null);
    let total = data.get("total").and_then(Value::as_u64).unwrap_or(0);
    let quota = data
        .get("rest_quota")
        .map(sval)
        .filter(|s| !s.is_empty() && s != "-");
    let arr = data
        .get("arr")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut assets = Vec::with_capacity(arr.len());
    for item in &arr {
        let component = item
            .get("component")
            .and_then(Value::as_array)
            .map(|comps| {
                comps
                    .iter()
                    .filter_map(|c| match c.as_array() {
                        Some(pair) if pair.len() >= 2 => {
                            Some(format!("{} {}", sval(&pair[0]), sval(&pair[1])))
                        }
                        Some(pair) if !pair.is_empty() => Some(sval(&pair[0])),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        assets.push(Asset {
            engine: Engine::Hunter,
            host: field(item, "host"),
            ip: field(item, "ip"),
            port: field(item, "port"),
            protocol: field(item, "protocol"),
            title: field(item, "web_title"),
            domain: field(item, "domain"),
            component: dash_or(component),
            org: "-".into(),
            country: "-".into(),
            city: "-".into(),
            status_code: field(item, "status_code"),
            updated_at: field(item, "updated_at"),
            url: field(item, "url"),
            // 引擎特有列：按用户勾选的扩展字段目录收录。
            extras: extract_extras(item, extra_catalog(Engine::Hunter), enabled),
        });
    }
    Ok(SearchResult {
        total,
        assets,
        quota,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn search_param_uses_page_number_semantics() {
        let p = build_search_param("weblogic", 3, 50);
        let v: Value = serde_json::from_str(&p).unwrap();
        assert_eq!(v["query"], "weblogic");
        assert_eq!(v["start"], 3);
        assert_eq!(v["limit"], 50);
        let p2 = build_search_param("q", 1, 500);
        assert_eq!(serde_json::from_str::<Value>(&p2).unwrap()["limit"], 100);
    }

    #[test]
    fn build_url_encodes_search_json() {
        let url = build_url("key-1", "app:x", 1, 20);
        assert!(url.starts_with(ENDPOINT));
        assert!(url.contains("api-key=key-1"));
        assert!(url.contains("is_web_search=3"));
        let decoded = urlencoding::decode(url.split("search=").nth(1).unwrap()).unwrap();
        assert!(decoded.contains("\"start\":1"));
    }

    #[test]
    fn parse_success_response() {
        let v = json!({
            "code": 200, "message": "success",
            "data": {
                "total": 2, "rest_quota": "980",
                "arr": [
                    {"ip": "5.6.7.8", "port": 443, "domain": "a.com", "protocol": "https",
                     "host": "a.com", "path": "/", "url": "https://a.com/", "web_title": "Title A",
                     "component": [["Nginx", "1.18"]], "status_code": 200,
                     "updated_at": "2026-01-01 00:00:00",
                     "province": "浙江", "city": "杭州", "isp": "电信"},
                    {"ip": "5.6.7.9", "port": 80, "web_title": "B"}
                ]
            }
        });
        let r = parse_response(&v, None).unwrap();
        assert_eq!(r.total, 2);
        assert_eq!(r.quota.as_deref(), Some("980"));
        let a = &r.assets[0];
        assert_eq!(a.engine, Engine::Hunter);
        assert_eq!(a.port, "443");
        assert_eq!(a.status_code, "200");
        assert_eq!(a.component, "Nginx 1.18");
        assert_eq!(r.assets[1].component, "-");
        assert_eq!(r.assets[1].host, "-");
        // 引擎特有列：Hunter 返回的省份/城市/运营商
        assert_eq!(r.assets[0].extras_lookup("省份"), "浙江");
        assert_eq!(r.assets[0].extras_lookup("城市"), "杭州");
        assert_eq!(r.assets[0].extras_lookup("运营商"), "电信");
        assert_eq!(r.assets[0].extras_lookup("域名"), "a.com");
        assert_eq!(r.assets[1].extras_lookup("省份"), "-");
    }

    #[test]
    fn parse_platform_error() {
        let v = json!({"code": 401, "message": "api-key error"});
        assert!(
            parse_response(&v, None)
                .unwrap_err()
                .to_string()
                .contains("api-key error")
        );
    }
}
