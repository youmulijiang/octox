//! ZoomEye API（GET https://api.zoomeye.hk/host/search）。
//!
//! 认证头 `API-KEY`；查询语句为 ZoomEye 原生语法原样透传。
//! 注：国际站为 api.zoomeye.hk；如遇端点变更需回到此处核对。

use serde_json::Value;

use super::{
    EngineError, Result, SearchResult, dash_or, extra_catalog, extract_extras, field, sget, sval,
};
use crate::asset::{Asset, Engine};
use crate::config::Config;

const ENDPOINT: &str = "https://api.zoomeye.hk/host/search";

pub(crate) fn build_url(query: &str, page: u32) -> String {
    format!(
        "{ENDPOINT}?query={}&page={page}",
        urlencoding::encode(query),
    )
}

pub(crate) fn search(config: &Config, query: &str, page: u32, _size: u32) -> Result<SearchResult> {
    let creds = &config.zoomeye;
    if creds.api_key.trim().is_empty() {
        return Err(EngineError::Api(
            "ZoomEye: 未配置 api-key（右上角设置）".into(),
        ));
    }
    let url = build_url(query, page.max(1));
    let value = super::fetch_json_with_headers(config, &url, &[("API-KEY", creds.api_key.trim())])?;
    let enabled = config.extra_enabled(Engine::ZoomEye).map(|v| v.as_slice());
    parse_response(&value, enabled)
}

/// 成功响应：`{"status":200,"matches":[...],"total":N}`。
pub(crate) fn parse_response(v: &Value, enabled: Option<&[String]>) -> Result<SearchResult> {
    let status = v.get("status").and_then(Value::as_i64).unwrap_or(-1);
    if status != 200 {
        let msg = v
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("未知错误");
        return Err(EngineError::Api(format!("ZoomEye: {msg}")));
    }
    let total = v.get("total").and_then(Value::as_u64).unwrap_or(0);
    let rows = v
        .get("matches")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut assets = Vec::with_capacity(rows.len());
    for item in &rows {
        let ip = sget(item, &["ip"]).map(sval).unwrap_or_else(|| "-".into());
        let site = sget(item, &["site"])
            .map(sval)
            .unwrap_or_else(|| "-".into());
        let port = sget(item, &["portinfo", "port"])
            .map(sval)
            .unwrap_or_else(|| "-".into());
        let service = sget(item, &["portinfo", "service"])
            .map(sval)
            .unwrap_or_else(|| "-".into());
        let host = if site != "-" && !site.is_empty() {
            site.clone()
        } else {
            ip.clone()
        };
        let url = if service == "http" || service == "https" {
            dash_or(format!("{service}://{host}:{port}"))
        } else {
            "-".to_string()
        };
        assets.push(Asset {
            engine: Engine::ZoomEye,
            host: dash_or(host),
            ip,
            port,
            protocol: service.clone(),
            title: dash_or(sget(item, &["title"]).map(sval).unwrap_or_default()),
            domain: "-".into(),
            component: "-".into(),
            org: "-".into(),
            country: sget(item, &["geolocation", "country"])
                .map(sval)
                .unwrap_or_else(|| "-".into()),
            city: sget(item, &["geolocation", "city"])
                .map(sval)
                .unwrap_or_else(|| "-".into()),
            status_code: "-".into(),
            updated_at: field(item, "updated_at"),
            url,
            // 引擎特有列：按用户勾选的扩展字段目录收录。
            extras: extract_extras(item, extra_catalog(Engine::ZoomEye), enabled),
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
    fn build_url_encodes_query() {
        let url = build_url("app:nginx", 3);
        assert!(url.starts_with(ENDPOINT));
        assert!(url.contains("query=app%3Anginx"));
        assert!(url.contains("page=3"));
    }

    #[test]
    fn parse_success_response() {
        let v = json!({
            "status": 200, "total": 500,
            "matches": [
                {"ip": "1.2.3.4", "site": "example.com", "title": "Home",
                 "portinfo": {"port": 443, "service": "https"},
                 "geolocation": {"country": "United States", "city": "Seattle"},
                 "updated_at": "2026-01-01"}
            ]
        });
        let r = parse_response(&v, None).unwrap();
        assert_eq!(r.total, 500);
        let a = &r.assets[0];
        assert_eq!(a.host, "example.com");
        assert_eq!(a.port, "443");
        assert_eq!(a.protocol, "https");
        assert_eq!(a.title, "Home");
        assert_eq!(a.url, "https://example.com:443");
        assert_eq!(a.extras_lookup("网站"), "example.com");
    }

    #[test]
    fn parse_platform_error() {
        let v = json!({"status": 401, "message": "unauthorized"});
        assert!(
            parse_response(&v, None)
                .unwrap_err()
                .to_string()
                .contains("unauthorized")
        );
    }
}
