use base64::Engine as _;
use serde_json::Value;

use super::{EngineError, Result, SearchResult, dash_or, extra_catalog, fetch_json, sval};
use crate::asset::{Asset, Engine};
use crate::config::Config;

/// 基础字段（与解析顺序严格对应，0..=10）；改动任一处需同步另一处。
const BASE_FIELDS: &str =
    "host,ip,port,title,domain,protocol,server,org,country,city,lastupdatetime";

const ENDPOINT: &str = "https://fofa.info/api/v1/search/all";

/// FOFA 要求查询语句做标准 Base64（RFC 4648，含填充）。
pub(crate) fn qbase64(query: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(query.as_bytes())
}

/// `extra_fields` 为在基础字段之后追加的 FOFA 字段名（来自扩展字段目录，
/// 按用户勾选；顺序与解析一一对应）。
pub(crate) fn build_url(
    email: &str,
    key: &str,
    query: &str,
    page: u32,
    size: u32,
    full: bool,
    extra_fields: &[&str],
) -> String {
    let mut fields = BASE_FIELDS.to_string();
    for name in extra_fields {
        fields.push(',');
        fields.push_str(name);
    }
    format!(
        "{ENDPOINT}?email={}&key={}&qbase64={}&page={page}&size={size}&fields={fields_enc}{full_suffix}",
        urlencoding::encode(email),
        urlencoding::encode(key),
        urlencoding::encode(&qbase64(query)),
        fields_enc = urlencoding::encode(&fields),
        full_suffix = if full { "&full=true" } else { "" },
    )
}

pub(crate) fn search(config: &Config, query: &str, page: u32, size: u32) -> Result<SearchResult> {
    let creds = &config.fofa;
    if creds.email.trim().is_empty() || creds.key.trim().is_empty() {
        return Err(EngineError::Api(
            "FOFA: 未配置 email/key（右上角设置）".into(),
        ));
    }
    // 扩展字段目录：按用户勾选拼进 fields 参数（可能需要相应字段权限）。
    let enabled = config.extra_enabled(Engine::Fofa).map(|v| v.as_slice());
    let selected: Vec<&'static str> = extra_catalog(Engine::Fofa)
        .iter()
        .filter(|spec| enabled.map_or(true, |en| en.iter().any(|l| l == spec.label)))
        .map(|spec| spec.fofa_field)
        .collect();
    let url = build_url(
        &creds.email,
        &creds.key,
        query,
        page,
        size.min(1000),
        config.fofa_full,
        &selected,
    );
    let value = fetch_json(config, &url)?;
    parse_response(&value, &selected)
}

/// `results` 为二维数组，前 11 列与 BASE_FIELDS 一致，其后为按
/// `extra_fields` 顺序追加的扩展字段。
pub(crate) fn parse_response(v: &Value, extra_fields: &[&str]) -> Result<SearchResult> {
    if v.get("error").and_then(Value::as_bool).unwrap_or(false) {
        let msg = v
            .get("errmsg")
            .and_then(Value::as_str)
            .unwrap_or("未知错误");
        return Err(EngineError::Api(format!("FOFA: {msg}")));
    }
    let total = v.get("size").and_then(Value::as_u64).unwrap_or(0);
    let rows = v
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut assets = Vec::with_capacity(rows.len());
    for row in &rows {
        let f = |i: usize| {
            row.get(i)
                .map(sval)
                .map(dash_or)
                .unwrap_or_else(|| "-".into())
        };
        let host = f(0);
        let protocol = f(5);
        let url = if protocol == "http" || protocol == "https" {
            dash_or(format!("{protocol}://{host}"))
        } else {
            "-".to_string()
        };
        assets.push(Asset {
            engine: Engine::Fofa,
            host: dash_or(host),
            ip: f(1),
            port: f(2),
            protocol,
            title: f(3),
            domain: f(4),
            component: dash_or(f(6)),
            org: f(7),
            country: f(8),
            city: f(9),
            status_code: "-".into(),
            updated_at: f(10),
            url,
            // 引擎特有列：域名为基础字段恒显示；其余按 fields 追加顺序取值。
            extras: {
                let mut extras = Vec::new();
                let domain = f(4);
                if domain != "-" {
                    extras.push(("域名".to_string(), domain));
                }
                let catalog = extra_catalog(Engine::Fofa);
                for (i, name) in extra_fields.iter().enumerate() {
                    if let Some(spec) = catalog.iter().find(|spec| spec.fofa_field == *name) {
                        let value = f(11 + i);
                        if value != "-" {
                            extras.push((spec.label.to_string(), value));
                        }
                    }
                }
                extras
            },
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
    fn qbase64_matches_rfc4648() {
        assert_eq!(qbase64("index"), "aW5kZXg=");
        assert_eq!(qbase64("app=\"weblogic\""), "YXBwPSJ3ZWJsb2dpYyI=");
    }

    #[test]
    fn build_url_encodes_query() {
        let url = build_url("a@b.com", "k+/=", "app=\"test\"", 2, 50, false, &[]);
        assert!(url.contains("email=a%40b.com"));
        assert!(url.contains("key=k%2B%2F%3D"));
        assert!(url.contains("page=2"));
        assert!(url.contains("size=50"));
        assert!(!url.contains("full=true"));
    }

    #[test]
    fn build_url_appends_full_and_extra_fields() {
        let url = build_url("a@b.com", "k", "q", 1, 20, true, &["icp", "banner"]);
        assert!(url.contains("full=true"));
        // 追加字段按用户勾选拼在基础字段之后（逗号被 URL 编码为 %2C）。
        assert!(url.contains("lastupdatetime%2Cicp%2Cbanner"));
    }

    #[test]
    fn parse_results_by_field_order() {
        let v = json!({
            "error": false, "size": 2, "page": 1,
            "results": [
                ["example.com:7001", "1.2.3.4", "7001", "控制台", "example.com", "http", "nginx", "Org Ltd", "China", "Beijing", "2026-01-01 00:00:00"],
                ["1.2.3.5:443", "1.2.3.5", "443", "Home", "", "https", "", "Acme", "China", "Shanghai", "2026-02-02 10:00:00"]
            ]
        });
        let r = parse_response(&v, &[]).unwrap();
        assert_eq!(r.total, 2);
        assert_eq!(r.assets.len(), 2);
        let a = &r.assets[0];
        assert_eq!(a.engine, Engine::Fofa);
        assert_eq!(a.host, "example.com:7001");
        assert_eq!(a.ip, "1.2.3.4");
        assert_eq!(a.port, "7001");
        assert_eq!(a.title, "控制台");
        assert_eq!(a.url, "http://example.com:7001");
        assert_eq!(r.assets[1].domain, "-");
        assert_eq!(r.assets[1].url, "https://1.2.3.5:443");
        // 引擎特有列：域名（首行有值、次行为空 → 并集中仅一列）
        assert_eq!(r.assets[0].extras_lookup("域名"), "example.com");
        assert_eq!(r.assets[1].extras_lookup("域名"), "-");
    }

    #[test]
    fn parse_platform_error() {
        let v = json!({"error": true, "errmsg": "-815 Invalid parameter"});
        let err = parse_response(&v, &[]).unwrap_err().to_string();
        assert!(err.contains("-815"));
    }

    #[test]
    fn parse_missing_results_is_empty() {
        let r = parse_response(&json!({"error": false, "size": 0}), &[]).unwrap();
        assert_eq!(r.total, 0);
        assert!(r.assets.is_empty());
    }
}
