//! Censys API v2（GET https://search.censys.io/api/v2/hosts/search）。
//!
//! 认证：Basic（api-id:api-secret）；查询参数 `{q, per_page, cursor}`；
//! 查询语句为 Censys 原生语法（`services.port: 443` 等字段路径式）原样透传。

use base64::Engine as _;
use serde_json::Value;

use super::{
    EngineError, Result, SearchResult, dash_or, extra_catalog, extract_extras, field, sget, sval,
};
use crate::asset::{Asset, Engine};
use crate::config::Config;

const ENDPOINT: &str = "https://search.censys.io/api/v2/hosts/search";

pub(crate) fn build_auth(api_id: &str, api_secret: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("{api_id}:{api_secret}").as_bytes())
}

pub(crate) fn build_url(query: &str, size: u32, cursor: Option<&str>) -> String {
    let mut url = format!(
        "{ENDPOINT}?q={}&per_page={}",
        urlencoding::encode(query),
        size.clamp(1, 100)
    );
    if let Some(cursor) = cursor.filter(|s| !s.is_empty()) {
        url.push_str(&format!("&cursor={}", urlencoding::encode(cursor)));
    }
    url
}

pub(crate) fn search(
    config: &Config,
    query: &str,
    size: u32,
    cursor: Option<&str>,
) -> Result<SearchResult> {
    let creds = &config.censys;
    if creds.api_id.trim().is_empty() || creds.api_secret.trim().is_empty() {
        return Err(EngineError::Api(
            "Censys: 未配置 api-id / api-secret（右上角设置）".into(),
        ));
    }
    let url = build_url(query, size, cursor);
    let auth = build_auth(creds.api_id.trim(), creds.api_secret.trim());
    let value = super::fetch_json_with_headers(
        config,
        &url,
        &[("Authorization", &format!("Basic {auth}"))],
    )?;
    let enabled = config.extra_enabled(Engine::Censys).map(|v| v.as_slice());
    parse_response(&value, enabled)
}

/// 成功响应：`{"code":200,"result":{"total":N,"hits":[...]}}`。
pub(crate) fn parse_response(v: &Value, enabled: Option<&[String]>) -> Result<SearchResult> {
    let code = v.get("code").and_then(Value::as_i64).unwrap_or(-1);
    if code != 200 {
        let msg = v
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("未知错误");
        return Err(EngineError::Api(format!("Censys: {msg}")));
    }
    let result = v.get("result").cloned().unwrap_or(Value::Null);
    let total = result.get("total").and_then(Value::as_u64).unwrap_or(0);
    let rows = result
        .get("hits")
        .and_then(Value::as_array)
        .ok_or_else(|| EngineError::Parse("Censys: 缺少 hits 数组".into()))?;
    let mut assets = Vec::with_capacity(rows.len());
    for item in rows {
        let ip = sget(item, &["ip"]).map(sval).unwrap_or_else(|| "-".into());
        // 每个服务独立保留；没有服务的主机仍保留一行。
        let services = item
            .get("services")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let services = if services.is_empty() {
            vec![Value::Null]
        } else {
            services
        };
        for service in services {
            let port = sget(&service, &["port"])
                .map(sval)
                .unwrap_or_else(|| "-".into());
            let transport = sget(&service, &["transport_protocol"])
                .map(sval)
                .unwrap_or_else(|| "-".into());
            let service_name = sget(&service, &["service_name"])
                .map(sval)
                .unwrap_or_default();
            let title = sget(&service, &["http", "response", "html_title"])
                .map(sval)
                .unwrap_or_default();
            let software = sget(&service, &["software"])
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(|s| s.get("name").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let url = if (port == "80" || port == "443") && ip != "-" {
                let scheme = if port == "443" { "https" } else { "http" };
                dash_or(format!("{scheme}://{ip}:{port}"))
            } else {
                "-".to_string()
            };
            let dns_names = sget(item, &["dns", "names"])
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let host = if dns_names.is_empty() {
                ip.clone()
            } else {
                dns_names.clone()
            };
            assets.push(Asset {
                engine: Engine::Censys,
                host: dash_or(host),
                ip: ip.clone(),
                port,
                protocol: if service_name.is_empty() {
                    transport
                } else {
                    service_name
                },
                title: dash_or(title),
                domain: dash_or(
                    dns_names
                        .split(',')
                        .next()
                        .unwrap_or("-")
                        .trim()
                        .to_string(),
                ),
                component: dash_or(software),
                org: sget(item, &["autonomous_system", "description"])
                    .map(sval)
                    .unwrap_or_else(|| "-".into()),
                country: sget(item, &["location", "country"])
                    .map(sval)
                    .unwrap_or_else(|| "-".into()),
                city: sget(item, &["location", "city"])
                    .map(sval)
                    .unwrap_or_else(|| "-".into()),
                status_code: sget(&service, &["http", "response", "status_code"])
                    .map(sval)
                    .unwrap_or_else(|| "-".into()),
                updated_at: field(item, "last_updated_at"),
                url,
                // 引擎特有列：按用户勾选的扩展字段目录收录。
                extras: extract_extras(item, extra_catalog(Engine::Censys), enabled),
            });
        }
    }
    Ok(SearchResult {
        total,
        assets,
        quota: None,
        next_cursor: result
            .pointer("/links/next")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn preserves_all_services_and_next_cursor() {
        let r = parse_response(
            &json!({"code":200,"result":{"total":2,"links":{"next":"opaque"},
            "hits":[{"ip":"192.0.2.1","services":[{"port":80},{"port":443}]},
                    {"ip":"192.0.2.2","services":[]}]}}),
            None,
        )
        .unwrap();
        assert_eq!(r.total, 2);
        assert_eq!(r.assets.len(), 3);
        assert_eq!(r.assets[0].port, "80");
        assert_eq!(r.assets[1].port, "443");
        assert_eq!(r.assets[2].ip, "192.0.2.2");
        assert_eq!(r.next_cursor.as_deref(), Some("opaque"));
        assert!(parse_response(&json!({"code":200,"result":{}}), None).is_err());
    }

    #[test]
    fn auth_is_basic_base64() {
        assert_eq!(build_auth("id", "secret"), "aWQ6c2VjcmV0");
    }

    #[test]
    fn build_url_clamps_per_page() {
        let url = build_url("services.port: 443", 500, Some("next+token"));
        assert!(url.contains("per_page=100"));
        assert!(url.contains("cursor=next%2Btoken"));
        assert!(!url.contains("&page="));
    }

    #[test]
    fn parse_success_response() {
        let v = json!({
            "code": 200,
            "result": {
                "total": 321,
                "hits": [
                    {"ip": "8.8.8.8",
                     "services": [{"port": 53, "transport_protocol": "udp", "service_name": "DNS",
                                   "software": [{"name": "dnsmasq"}],
                                   "http": {"response": {"status_code": 200, "html_title": "DNS"}}}],
                     "dns": {"names": ["dns.google"]},
                     "autonomous_system": {"asn": 15169, "description": "GOOGLE"},
                     "location": {"country": "United States", "city": "Mountain View"},
                     "last_updated_at": "2026-01-01"}
                ]
            }
        });
        let r = parse_response(&v, None).unwrap();
        assert_eq!(r.total, 321);
        let a = &r.assets[0];
        assert_eq!(a.host, "dns.google");
        assert_eq!(a.port, "53");
        assert_eq!(a.protocol, "DNS");
        assert_eq!(a.component, "dnsmasq");
        assert_eq!(a.status_code, "200");
        assert_eq!(a.extras_lookup("ASN"), "15169");
    }

    #[test]
    fn parse_platform_error() {
        let v = json!({"code": 401, "error": {"message": "Unauthorized"}});
        assert!(
            parse_response(&v, None)
                .unwrap_err()
                .to_string()
                .contains("Unauthorized")
        );
    }
}
