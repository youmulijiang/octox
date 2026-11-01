//! Censys API v2（POST https://search.censys.io/api/v2/hosts/search）。
//!
//! 认证：Basic（api-id:api-secret）；请求体 `{q, per_page, page}`；
//! 查询语句为 Censys 原生语法（`services.port: 443` 等字段路径式）原样透传。

use base64::Engine as _;
use serde_json::{Value, json};

use super::{
    EngineError, Result, SearchResult, dash_or, extra_catalog, extract_extras, field, sget, sval,
};
use crate::asset::{Asset, Engine};
use crate::config::Config;

const ENDPOINT: &str = "https://search.censys.io/api/v2/hosts/search";

pub(crate) fn build_auth(api_id: &str, api_secret: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("{api_id}:{api_secret}").as_bytes())
}

pub(crate) fn build_body(query: &str, page: u32, size: u32) -> Value {
    json!({
        "q": query,
        "page": page.max(1),
        "per_page": size.clamp(1, 100),
    })
}

pub(crate) fn search(config: &Config, query: &str, page: u32, size: u32) -> Result<SearchResult> {
    let creds = &config.censys;
    if creds.api_id.trim().is_empty() || creds.api_secret.trim().is_empty() {
        return Err(EngineError::Api(
            "Censys: 未配置 api-id / api-secret（右上角设置）".into(),
        ));
    }
    let body = build_body(query, page, size);
    let auth = build_auth(creds.api_id.trim(), creds.api_secret.trim());
    let value = super::post_json(
        config,
        ENDPOINT,
        &[("Authorization", &format!("Basic {auth}"))],
        &body,
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
        .cloned()
        .unwrap_or_default();
    let mut assets = Vec::with_capacity(rows.len());
    for item in &rows {
        let ip = sget(item, &["ip"]).map(sval).unwrap_or_else(|| "-".into());
        // 取第一个服务的端口 / 协议 / 标题 / 软件。
        let service = item
            .get("services")
            .and_then(Value::as_array)
            .and_then(|list| list.first().cloned())
            .unwrap_or(Value::Null);
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
            ip,
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
    fn auth_is_basic_base64() {
        assert_eq!(build_auth("id", "secret"), "aWQ6c2VjcmV0");
    }

    #[test]
    fn build_body_clamps_per_page() {
        let b = build_body("services.port: 443", 3, 500);
        assert_eq!(b["q"], "services.port: 443");
        assert_eq!(b["page"], 3);
        assert_eq!(b["per_page"], 100);
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
