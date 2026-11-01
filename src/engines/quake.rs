use serde_json::{Value, json};

use super::{
    EngineError, Result, SearchResult, dash_or, extra_catalog, extract_extras, field, post_json,
    sget, sval,
};
use crate::asset::{Asset, Engine};
use crate::config::Config;

const ENDPOINT: &str = "https://quake.360.net/api/v3/search/quake_service";

/// Quake 分页为 0 起始偏移：start = (page-1) * size。
pub(crate) fn start_offset(page: u32, size: u32) -> u32 {
    page.saturating_sub(1).saturating_mul(size)
}

pub(crate) fn build_body(query: &str, page: u32, size: u32) -> Value {
    let size = size.min(100);
    json!({
        "query": query,
        "start": start_offset(page, size),
        "size": size,
        "latest": true,
    })
}

pub(crate) fn search(config: &Config, query: &str, page: u32, size: u32) -> Result<SearchResult> {
    let creds = &config.quake;
    if creds.token.trim().is_empty() {
        return Err(EngineError::Api("Quake: 未配置 token（右上角设置）".into()));
    }
    let body = build_body(query, page, size);
    let value = post_json(
        config,
        ENDPOINT,
        &[("X-QuakeToken", creds.token.trim())],
        &body,
    )?;
    let enabled = config.extra_enabled(Engine::Quake).map(|v| v.as_slice());
    parse_response(&value, enabled)
}

/// 成功响应：`{"code":0,"data":[...],"meta":{"pagination":{"count":n,"total":N}}}`。
pub(crate) fn parse_response(v: &Value, enabled: Option<&[String]>) -> Result<SearchResult> {
    let code = v.get("code").and_then(Value::as_i64).unwrap_or(-1);
    if code != 0 {
        let msg = v
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("未知错误");
        return Err(EngineError::Api(format!("Quake: {msg}")));
    }
    let total = v
        .pointer("/meta/pagination/total")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let items = v
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut assets = Vec::with_capacity(items.len());
    for item in &items {
        let title = sget(item, &["service", "http", "title"])
            .map(sval)
            .unwrap_or_default();
        let server = sget(item, &["service", "http", "server"])
            .map(sval)
            .unwrap_or_default();
        let service_name = sget(item, &["service", "name"])
            .map(sval)
            .unwrap_or_default();
        let transport = field(item, "transport");
        let protocol = if service_name != "-" && !service_name.is_empty() {
            service_name
        } else {
            transport
        };
        let host = field(item, "hostname");
        let ip = field(item, "ip");
        let port = field(item, "port");
        let host = if host == "-" { ip.clone() } else { host };
        let url = if (title != "-" && !title.is_empty()) && (port == "80" || port == "443") {
            let scheme = if port == "443" { "https" } else { "http" };
            dash_or(format!("{scheme}://{host}:{port}"))
        } else {
            "-".to_string()
        };
        let org = item
            .get("org")
            .or_else(|| item.get("organization"))
            .map(sval)
            .unwrap_or_else(|| "-".into());
        assets.push(Asset {
            engine: Engine::Quake,
            host: dash_or(host),
            ip,
            port,
            protocol,
            title: dash_or(title),
            domain: field(item, "domain"),
            component: dash_or(server),
            org,
            country: sget(item, &["location", "country_cn"])
                .map(sval)
                .unwrap_or_else(|| "-".into()),
            city: sget(item, &["location", "city_cn"])
                .map(sval)
                .unwrap_or_else(|| "-".into()),
            status_code: sget(item, &["service", "http", "status_code"])
                .map(sval)
                .unwrap_or_else(|| "-".into()),
            updated_at: field(item, "timestamp"),
            url,
            // 引擎特有列：按用户勾选的扩展字段目录收录。
            extras: extract_extras(item, extra_catalog(Engine::Quake), enabled),
        });
    }
    Ok(SearchResult {
        total,
        assets,
        quota: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pagination_is_zero_based_offset() {
        assert_eq!(start_offset(1, 50), 0);
        assert_eq!(start_offset(2, 50), 50);
        assert_eq!(start_offset(3, 50), 100);
        assert_eq!(start_offset(0, 50), 0);
    }

    #[test]
    fn body_caps_size_and_sets_latest() {
        let b = build_body("port:\"7001\"", 2, 500);
        assert_eq!(b["start"], 100);
        assert_eq!(b["size"], 100);
        assert_eq!(b["latest"], true);
    }

    #[test]
    fn parse_success_response() {
        let v = json!({
            "code": 0, "message": "Successful.",
            "data": [
                {"ip": "9.9.9.9", "port": 80, "hostname": "b.com", "transport": "tcp",
                 "service": {"name": "http", "http": {"title": "Page B", "server": "Apache", "status_code": 200}},
                 "location": {"country_cn": "中国", "city_cn": "杭州", "province_cn": "浙江"},
                 "timestamp": "2026-03-03 12:00:00", "org": "ACME", "isp": "移动",
                 "favicon": "1234567"}
            ],
            "meta": {"pagination": {"count": 1, "total": 12345}}
        });
        let r = parse_response(&v, None).unwrap();
        assert_eq!(r.total, 12345);
        let a = &r.assets[0];
        assert_eq!(a.engine, Engine::Quake);
        assert_eq!(a.host, "b.com");
        assert_eq!(a.protocol, "http");
        assert_eq!(a.title, "Page B");
        assert_eq!(a.component, "Apache");
        assert_eq!(a.country, "中国");
        assert_eq!(a.city, "杭州");
        assert_eq!(a.org, "ACME");
        assert_eq!(a.url, "http://b.com:80");
        // 引擎特有列：Quake 返回的省份/运营商/favicon
        assert_eq!(a.extras_lookup("省份"), "浙江");
        assert_eq!(a.extras_lookup("运营商"), "移动");
        assert_eq!(a.extras_lookup("favicon"), "1234567");
        assert_eq!(a.extras_lookup("域名"), "-");
    }

    #[test]
    fn parse_platform_error() {
        let v = json!({"code": 401, "message": "token invalid"});
        assert!(
            parse_response(&v, None)
                .unwrap_err()
                .to_string()
                .contains("token invalid")
        );
    }
}
