//! DayDayMap 洞察 API（POST https://www.daydaymap.com/api/v1/raymap/search/all）。
//!
//! 认证头 `api-key`；`keyword` 为查询语句的 Base64（标准编码）。
//! 限制：page × page_size ≤ 10000。

use base64::Engine as _;
use serde_json::{Value, json};

use super::{
    EngineError, Result, SearchResult, dash_or, extra_catalog, extract_extras, field, post_json,
};
use crate::asset::{Asset, Engine};
use crate::config::Config;

const ENDPOINT: &str = "https://www.daydaymap.com/api/v1/raymap/search/all";

pub(crate) fn encode_keyword(query: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(query.as_bytes())
}

pub(crate) fn build_body(query: &str, page: u32, size: u32) -> Value {
    json!({
        "page": page.max(1),
        "page_size": size.clamp(1, 1000),
        "keyword": encode_keyword(query),
    })
}

pub(crate) fn search(config: &Config, query: &str, page: u32, size: u32) -> Result<SearchResult> {
    let creds = &config.daydaymap;
    if creds.api_key.trim().is_empty() {
        return Err(EngineError::Api(
            "DayDayMap: 未配置 api-key（右上角设置）".into(),
        ));
    }
    let body = build_body(query, page, size);
    let value = post_json(
        config,
        ENDPOINT,
        &[("api-key", creds.api_key.trim())],
        &body,
    )?;
    let enabled = config
        .extra_enabled(Engine::DayDayMap)
        .map(|v| v.as_slice());
    parse_response(&value, enabled)
}

/// 成功响应：`{"code":200,"data":{"list":[...],"total":N},"msg":"..."}`。
pub(crate) fn parse_response(v: &Value, enabled: Option<&[String]>) -> Result<SearchResult> {
    let code = v.get("code").and_then(Value::as_i64).unwrap_or(-1);
    if code != 200 {
        let msg = v.get("msg").and_then(Value::as_str).unwrap_or("未知错误");
        return Err(EngineError::Api(format!("DayDayMap: {msg}")));
    }
    let data = v.get("data").cloned().unwrap_or(Value::Null);
    let total = data.get("total").and_then(Value::as_u64).unwrap_or(0);
    let rows = data
        .get("list")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut assets = Vec::with_capacity(rows.len());
    for item in &rows {
        let ip = field(item, "ip");
        let domain = field(item, "domain");
        let host = if domain != "-" {
            domain.clone()
        } else {
            ip.clone()
        };
        let port = field(item, "port");
        let service = field(item, "service");
        let protocol = if service != "-" {
            service.clone()
        } else {
            field(item, "protocol")
        };
        let url = if (protocol == "http" || protocol == "https") && host != "-" {
            dash_or(format!("{protocol}://{host}:{port}"))
        } else {
            "-".to_string()
        };
        let server = field(item, "server");
        assets.push(Asset {
            engine: Engine::DayDayMap,
            host: dash_or(host),
            ip,
            port,
            protocol,
            title: dash_or(field(item, "title")),
            domain: dash_or(domain.clone()),
            component: dash_or(server),
            org: "-".into(),
            country: dash_or(field(item, "country")),
            city: dash_or(field(item, "city")),
            status_code: "-".into(),
            updated_at: field(item, "time_stamp"),
            url,
            // 引擎特有列：按用户勾选的扩展字段目录收录。
            extras: extract_extras(item, extra_catalog(Engine::DayDayMap), enabled),
        });
    }
    Ok(SearchResult {
        total,
        assets,
        quota: None,
        next_cursor: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keyword_is_standard_base64() {
        assert_eq!(encode_keyword("port=\"80\""), "cG9ydD0iODAi");
    }

    #[test]
    fn build_body_caps_size() {
        let b = build_body("port=\"80\"", 2, 5000);
        assert_eq!(b["page"], 2);
        assert_eq!(b["page_size"], 1000);
        assert_eq!(b["keyword"], encode_keyword("port=\"80\""));
    }

    #[test]
    fn parse_success_response() {
        let v = json!({
            "code": 200, "msg": "检索成功",
            "data": {"list": [
                {"ip": "1.1.1.1", "port": 80, "protocol": "tcp", "domain": "example.com",
                 "title": "Example", "country": "美国", "service": "http", "server": "nginx",
                 "time_stamp": "2024-03-24T05:17:03+08:00"}
            ], "total": 9}
        });
        let r = parse_response(&v, None).unwrap();
        assert_eq!(r.total, 9);
        let a = &r.assets[0];
        assert_eq!(a.host, "example.com");
        assert_eq!(a.protocol, "http");
        assert_eq!(a.component, "nginx");
        assert_eq!(a.extras_lookup("域名"), "example.com");
        assert_eq!(a.extras_lookup("传输层"), "tcp");
    }

    #[test]
    fn parse_platform_error() {
        let v = json!({"code": 2001, "msg": "请检查api-key是否正确"});
        assert!(
            parse_response(&v, None)
                .unwrap_err()
                .to_string()
                .contains("api-key")
        );
    }
}
