//! Shodan API（https://api.shodan.io/shodan/host/search）。
//!
//! 固定每页 100 条（无 size 参数），`size` 仅用于语义对齐；查询语句为
//! Shodan 原生语法原样透传。

use serde_json::Value;

use super::{
    EngineError, Result, SearchResult, dash_or, extra_catalog, extract_extras, fetch_json, field,
    sget, sval,
};
use crate::asset::{Asset, Engine};
use crate::config::Config;

const ENDPOINT: &str = "https://api.shodan.io/shodan/host/search";

pub(crate) fn build_url(api_key: &str, query: &str, page: u32) -> String {
    format!(
        "{ENDPOINT}?key={}&query={}&page={page}",
        urlencoding::encode(api_key),
        urlencoding::encode(query),
    )
}

pub(crate) fn search(config: &Config, query: &str, page: u32, _size: u32) -> Result<SearchResult> {
    let creds = &config.shodan;
    if creds.api_key.trim().is_empty() {
        return Err(EngineError::Api(
            "Shodan: 未配置 api-key（右上角设置）".into(),
        ));
    }
    let url = build_url(creds.api_key.trim(), query, page.max(1));
    let value = fetch_json(config, &url)?;
    let enabled = config.extra_enabled(Engine::Shodan).map(|v| v.as_slice());
    parse_response(&value, enabled)
}

/// 成功响应：`{"matches":[...],"total":N}`。
pub(crate) fn parse_response(v: &Value, enabled: Option<&[String]>) -> Result<SearchResult> {
    if let Some(err) = v.get("error").and_then(Value::as_str) {
        return Err(EngineError::Api(format!("Shodan: {err}")));
    }
    let total = v.get("total").and_then(Value::as_u64).unwrap_or(0);
    let rows = v
        .get("matches")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut assets = Vec::with_capacity(rows.len());
    for item in &rows {
        let ip = field(item, "ip_str");
        let hostnames = item
            .get("hostnames")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let host = if hostnames.is_empty() {
            ip.clone()
        } else {
            hostnames.clone()
        };
        let port = field(item, "port");
        let transport = field(item, "transport");
        let url = if transport == "tcp" && (port == "80" || port == "443") {
            let scheme = if port == "443" { "https" } else { "http" };
            dash_or(format!("{scheme}://{host}:{port}"))
        } else {
            "-".to_string()
        };
        let country = sget(item, &["location", "country_name"])
            .map(sval)
            .unwrap_or_else(|| "-".into());
        let city = sget(item, &["location", "city"])
            .map(sval)
            .unwrap_or_else(|| "-".into());
        assets.push(Asset {
            engine: Engine::Shodan,
            host: dash_or(host),
            ip,
            port,
            protocol: transport,
            title: "-".into(),
            domain: field(item, "domain"),
            component: dash_or(field(item, "product")),
            org: dash_or(field(item, "org")),
            country,
            city,
            status_code: "-".into(),
            updated_at: field(item, "timestamp"),
            url,
            // 引擎特有列：按用户勾选的扩展字段目录收录。
            extras: extract_extras(item, extra_catalog(Engine::Shodan), enabled),
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
    fn build_url_encodes_query() {
        let url = build_url("k", "port:80 country:US", 2);
        assert!(url.starts_with(ENDPOINT));
        assert!(url.contains("key=k"));
        assert!(url.contains("query=port%3A80%20country%3AUS"));
        assert!(url.contains("page=2"));
    }

    #[test]
    fn parse_success_response() {
        let v = json!({
            "total": 100,
            "matches": [
                {"ip_str": "8.8.8.8", "port": 53, "transport": "udp", "product": "dnsmasq",
                 "org": "Google", "os": "Linux", "hostnames": ["dns.google"], "asn": "AS15169",
                 "isp": "Google LLC",
                 "location": {"country_name": "United States", "city": "Mountain View"},
                 "timestamp": "2026-01-01T00:00:00"}
            ]
        });
        let r = parse_response(&v, None).unwrap();
        assert_eq!(r.total, 100);
        let a = &r.assets[0];
        assert_eq!(a.engine, Engine::Shodan);
        assert_eq!(a.host, "dns.google");
        assert_eq!(a.ip, "8.8.8.8");
        assert_eq!(a.protocol, "udp");
        assert_eq!(a.component, "dnsmasq");
        assert_eq!(a.org, "Google");
        assert_eq!(a.country, "United States");
        assert_eq!(a.extras_lookup("操作系统"), "Linux");
        assert_eq!(a.extras_lookup("ASN"), "AS15169");
    }

    #[test]
    fn parse_platform_error() {
        let v = json!({"error": "invalid key"});
        assert!(
            parse_response(&v, None)
                .unwrap_err()
                .to_string()
                .contains("invalid key")
        );
    }
}
