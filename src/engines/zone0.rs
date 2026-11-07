//! 0.zone 零零信安 API（POST https://0.zone/api/plug/data/）。
//!
//! 请求体：`{title, title_type, company, page, pagesize, key}`；
//! `title_type` 取 site（信息系统）。⚠️ 响应字段官方未在公开 demo 中给出，
//! 解析为防御式多路径取值；如遇字段缺失需回到此处核对真实结构。

use serde_json::{Value, json};

use super::{EngineError, Result, SearchResult, dash_or, field, post_json};
use crate::asset::{Asset, Engine};
use crate::config::Config;

const ENDPOINT: &str = "https://0.zone/api/plug/data/";

pub(crate) fn build_body(query: &str, page: u32, size: u32, key: &str) -> Value {
    json!({
        "title": query,
        "title_type": "site",
        "company": "",
        "page": page.max(1),
        "pagesize": size.clamp(1, 100),
        "key": key,
    })
}

pub(crate) fn search(config: &Config, query: &str, page: u32, size: u32) -> Result<SearchResult> {
    let creds = &config.zone0;
    if creds.api_key.trim().is_empty() {
        return Err(EngineError::Api("0.zone: 未配置 key（右上角设置）".into()));
    }
    let body = build_body(query, page, size, creds.api_key.trim());
    let value = post_json(config, ENDPOINT, &[], &body)?;
    parse_response(&value)
}

/// 成功响应（官方 demo 未公开结构，防御式解析）：
/// `{code:?, data:{list|records|data:[...], total|count:N}}`。
pub(crate) fn parse_response(v: &Value) -> Result<SearchResult> {
    let code = v.get("code").and_then(Value::as_i64).unwrap_or(-1);
    if code != 0 && code != 200 {
        let msg = v
            .get("message")
            .or_else(|| v.get("msg"))
            .and_then(Value::as_str)
            .unwrap_or("未知错误");
        return Err(EngineError::Api(format!("0.zone: {msg}")));
    }
    let data = v.get("data").cloned().unwrap_or(Value::Null);
    let rows_container = if data.is_array() { data.clone() } else { data };
    let rows = ["list", "records", "data", "rows"]
        .iter()
        .find_map(|k| rows_container.get(k).and_then(Value::as_array).cloned())
        .or_else(|| rows_container.as_array().cloned())
        .unwrap_or_default();
    let total = ["total", "count", "total_count"]
        .iter()
        .find_map(|k| rows_container.get(k).and_then(Value::as_u64))
        .unwrap_or(0);
    let mut assets = Vec::with_capacity(rows.len());
    for item in &rows {
        let ip = field(item, "ip");
        let domain = field(item, "domain");
        let host = if field(item, "host") != "-" {
            field(item, "host")
        } else if domain != "-" {
            domain.clone()
        } else {
            ip.clone()
        };
        let port = field(item, "port");
        let protocol = field(item, "protocol");
        let url = if (protocol == "http" || protocol == "https") && host != "-" {
            dash_or(format!("{protocol}://{host}:{port}"))
        } else {
            field(item, "url")
        };
        assets.push(Asset {
            engine: Engine::Zone0,
            host: dash_or(host),
            ip,
            port,
            protocol,
            title: dash_or(field(item, "title")),
            domain: dash_or(domain),
            component: "-".into(),
            org: dash_or(field(item, "company")),
            country: dash_or(field(item, "country")),
            city: dash_or(field(item, "city")),
            status_code: field(item, "status_code"),
            updated_at: field(item, "updated_at"),
            url,
            extras: Vec::new(),
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
    fn build_body_uses_site_type_and_key() {
        let b = build_body("domain===\"qq.com\"", 2, 500, "my-key");
        assert_eq!(b["title"], "domain===\"qq.com\"");
        assert_eq!(b["title_type"], "site");
        assert_eq!(b["page"], 2);
        assert_eq!(b["pagesize"], 100);
        assert_eq!(b["key"], "my-key");
    }

    #[test]
    fn parse_list_shape() {
        let v = json!({
            "code": 200,
            "data": {"list": [
                {"ip": "1.2.3.4", "port": 443, "protocol": "https", "domain": "a.com",
                 "title": "Page", "country": "中国"}
            ], "total": 7}
        });
        let r = parse_response(&v).unwrap();
        assert_eq!(r.total, 7);
        let a = &r.assets[0];
        assert_eq!(a.engine, Engine::Zone0);
        assert_eq!(a.host, "a.com");
        assert_eq!(a.title, "Page");
    }

    #[test]
    fn parse_records_shape_and_error() {
        let v = json!({"code": 200, "data": {"records": [{"ip": "1.1.1.1"}], "count": 1}});
        let r = parse_response(&v).unwrap();
        assert_eq!(r.total, 1);
        assert_eq!(r.assets[0].ip, "1.1.1.1");
        let err = parse_response(&json!({"code": 401, "message": "key 无效"}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("key 无效"));
    }
}
