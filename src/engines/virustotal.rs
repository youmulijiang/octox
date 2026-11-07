//! VirusTotal Intelligence Search（GET https://www.virustotal.com/api/v3/intelligence/search）。
//!
//! 认证头 `x-apikey`。⚠️ 结构化搜索为 VT Intelligence 付费能力，
//! 免费 API Key 会得到 401/403 的明确报错。响应为混合实体
//! （ip_addresses / domains / urls / files），映射为泛化资产。

use serde_json::Value;

use super::{
    EngineError, Result, SearchResult, dash_or, extra_catalog, extract_extras, field, sget, sval,
};
use crate::asset::{Asset, Engine};
use crate::config::Config;

const ENDPOINT: &str = "https://www.virustotal.com/api/v3/intelligence/search";

pub(crate) fn build_url(query: &str, limit: u32, cursor: Option<&str>) -> String {
    let mut url = format!(
        "{ENDPOINT}?query={}&limit={}",
        urlencoding::encode(query),
        limit.clamp(1, 100)
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
    let creds = &config.virustotal;
    if creds.api_key.trim().is_empty() {
        return Err(EngineError::Api(
            "VirusTotal: 未配置 x-apikey（右上角设置）".into(),
        ));
    }
    let url = build_url(query, size, cursor);
    let value =
        super::fetch_json_with_headers(config, &url, &[("x-apikey", creds.api_key.trim())])?;
    let enabled = config
        .extra_enabled(Engine::VirusTotal)
        .map(|v| v.as_slice());
    parse_response(&value, enabled)
}

/// 成功响应：`{"data":[{type,id,attributes}],"meta":{"pagination":{...}}}`。
pub(crate) fn parse_response(v: &Value, enabled: Option<&[String]>) -> Result<SearchResult> {
    if let Some(err) = v.get("error") {
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("未知错误");
        return Err(EngineError::Api(format!("VirusTotal: {msg}")));
    }
    let total = v
        .pointer("/meta/pagination/count")
        .or_else(|| v.pointer("/meta/count"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let rows = v
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| EngineError::Parse("VirusTotal: 缺少 data 数组".into()))?;
    let mut assets = Vec::with_capacity(rows.len());
    for item in rows {
        let entity_type = field(item, "type");
        let id = field(item, "id");
        // 实体泛化：IP → host=ip；域名 → host=domain；其余以 id 展示。
        let (host, ip, domain) = match entity_type.as_str() {
            "ip_address" | "ip_addresses" => (id.clone(), id.clone(), "-".to_string()),
            "domain" | "domains" => (id.clone(), "-".to_string(), id.clone()),
            _ => (id.clone(), "-".to_string(), "-".to_string()),
        };
        let url = match entity_type.as_str() {
            "ip_address" | "ip_addresses" => {
                dash_or(format!("https://www.virustotal.com/gui/ip-address/{host}"))
            }
            "domain" | "domains" => {
                dash_or(format!("https://www.virustotal.com/gui/domain/{host}"))
            }
            "file" | "files" => dash_or(format!("https://www.virustotal.com/gui/file/{host}")),
            "url" | "urls" => dash_or(format!("https://www.virustotal.com/gui/url/{host}")),
            _ => "-".to_string(),
        };
        let as_owner = sget(item, &["attributes", "as_owner"])
            .map(sval)
            .unwrap_or_default();
        let country = sget(item, &["attributes", "country"])
            .map(sval)
            .unwrap_or_else(|| "-".into());
        assets.push(Asset {
            engine: Engine::VirusTotal,
            host: dash_or(host),
            ip,
            port: "-".into(),
            protocol: "-".into(),
            title: "-".into(),
            domain: dash_or(domain),
            component: "-".into(),
            org: dash_or(as_owner.clone()),
            country,
            city: "-".into(),
            status_code: "-".into(),
            updated_at: sget(item, &["attributes", "last_modification_date"])
                .map(sval)
                .unwrap_or_else(|| "-".into()),
            url,
            // 引擎特有列：按用户勾选的扩展字段目录收录。
            extras: extract_extras(item, extra_catalog(Engine::VirusTotal), enabled),
        });
    }
    Ok(SearchResult {
        total,
        assets,
        quota: None,
        next_cursor: v
            .pointer("/meta/cursor")
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
    fn cursor_is_opaque_and_returned_for_next_page() {
        let url = build_url("entity:domain", 20, Some("token+/="));
        assert!(url.contains("cursor=token%2B%2F%3D"));
        assert!(!url.contains("offset="));
        assert!(!build_url("test", 20, None).contains("cursor="));
        let r = parse_response(&json!({"data": [], "meta": {"cursor": "token+/="}}), None).unwrap();
        assert_eq!(r.next_cursor.as_deref(), Some("token+/="));
        assert!(parse_response(&json!({"meta": {}}), None).is_err());
        let error = Engine::VirusTotal
            .search(&Config::default(), "test", 2, 20)
            .unwrap_err();
        assert!(error.to_string().contains("next_cursor"));
    }

    #[test]
    fn build_url_encodes_query() {
        let url = build_url("entity:domain domain:baidu.com", 40, None);
        assert!(url.starts_with(ENDPOINT));
        assert!(!url.contains("apikey"));
        assert!(url.contains("limit=40"));
    }

    #[test]
    fn parse_mixed_entities() {
        let v = json!({
            "data": [
                {"type": "ip_address", "id": "1.2.3.4",
                 "attributes": {"as_owner": "Google LLC", "country": "US"}},
                {"type": "domain", "id": "example.com",
                 "attributes": {"last_modification_date": 1735689600}}
            ],
            "meta": {"pagination": {"count": 2}}
        });
        let r = parse_response(&v, None).unwrap();
        assert_eq!(r.total, 2);
        let ip_asset = &r.assets[0];
        assert_eq!(ip_asset.host, "1.2.3.4");
        assert_eq!(ip_asset.org, "Google LLC");
        assert_eq!(ip_asset.extras_lookup("实体类型"), "ip_address");
        let domain_asset = &r.assets[1];
        assert_eq!(domain_asset.domain, "example.com");
        assert_eq!(domain_asset.extras_lookup("所属"), "-");
    }

    #[test]
    fn parse_error_payload() {
        let v = json!({"error": {"message": "Private Intelligence required"}});
        assert!(
            parse_response(&v, None)
                .unwrap_err()
                .to_string()
                .contains("Private Intelligence")
        );
    }
}
