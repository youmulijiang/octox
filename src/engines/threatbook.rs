//! 微步在线 ThreatBook 资产测绘 API（GET https://api.threatbook.cn/v3/internet_assets/query）。
//!
//! 认证参数 `apikey`；`syntax` 为 ThreatBook 原生查询语句（`=` 语法，正向锚点约束）。

use serde_json::Value;

use super::{
    EngineError, Result, SearchResult, dash_or, extra_catalog, extract_extras, fetch_json, field,
    sget, sval,
};
use crate::asset::{Asset, Engine};
use crate::config::Config;

const ENDPOINT: &str = "https://api.threatbook.cn/v3/internet_assets/query";

pub(crate) fn build_url(api_key: &str, query: &str, page: u32, size: u32) -> String {
    format!(
        "{ENDPOINT}?apikey={}&syntax={}&page={page}&size={}",
        urlencoding::encode(api_key),
        urlencoding::encode(query),
        size.clamp(1, 100),
    )
}

pub(crate) fn search(config: &Config, query: &str, page: u32, size: u32) -> Result<SearchResult> {
    let creds = &config.threatbook;
    if creds.api_key.trim().is_empty() {
        return Err(EngineError::Api(
            "ThreatBook: 未配置 apikey（右上角设置）".into(),
        ));
    }
    let url = build_url(creds.api_key.trim(), query, page.max(1), size);
    let value = fetch_json(config, &url)?;
    let enabled = config
        .extra_enabled(Engine::ThreatBook)
        .map(|v| v.as_slice());
    parse_response(&value, enabled)
}

/// 成功响应：`{"response_code":0,"data":{"total_count":N,"data":[...]}}`。
pub(crate) fn parse_response(v: &Value, enabled: Option<&[String]>) -> Result<SearchResult> {
    let code = v.get("response_code").and_then(Value::as_i64).unwrap_or(-1);
    if code != 0 {
        let msg = v
            .get("verbose_msg")
            .and_then(Value::as_str)
            .unwrap_or("未知错误");
        return Err(EngineError::Api(format!("ThreatBook: {msg}")));
    }
    let data = v.get("data").cloned().unwrap_or(Value::Null);
    let total = data.get("total_count").and_then(Value::as_u64).unwrap_or(0);
    let rows = data
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut assets = Vec::with_capacity(rows.len());
    for item in &rows {
        let ip = sget(item, &["ip", "ip"])
            .map(sval)
            .unwrap_or_else(|| "-".into());
        let host = field(item, "host");
        let host = if host == "-" { ip.clone() } else { host };
        let port = field(item, "port");
        let protocol = field(item, "protocol");
        let domain = sget(item, &["domain", "domain"])
            .map(sval)
            .unwrap_or_default();
        let host = if host == "-" && domain != "-" {
            domain.clone()
        } else {
            host
        };
        let url = if (protocol == "http" || protocol == "https") && host != "-" {
            dash_or(format!("{protocol}://{host}:{port}"))
        } else {
            "-".to_string()
        };
        let application = item.get("application").map(sval).unwrap_or_default();
        assets.push(Asset {
            engine: Engine::ThreatBook,
            host: dash_or(host),
            ip,
            port,
            protocol,
            title: dash_or(field(item, "web_title")),
            domain: dash_or(domain),
            component: dash_or(application),
            org: sget(item, &["ip", "asn", "organisation"])
                .map(sval)
                .unwrap_or_else(|| "-".into()),
            country: sget(item, &["ip", "location", "country"])
                .map(sval)
                .unwrap_or_else(|| "-".into()),
            city: sget(item, &["ip", "location", "city"])
                .map(sval)
                .unwrap_or_else(|| "-".into()),
            status_code: field(item, "status_code"),
            updated_at: field(item, "last_scan_time"),
            url,
            // 引擎特有列：按用户勾选的扩展字段目录收录。
            extras: extract_extras(item, extra_catalog(Engine::ThreatBook), enabled),
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
    fn build_url_encodes_syntax() {
        let url = build_url("k", "ip=\"1.1.1.1\"", 2, 200);
        assert!(url.starts_with(ENDPOINT));
        assert!(url.contains("apikey=k"));
        assert!(url.contains("syntax=ip%3D%221.1.1.1%22"));
        assert!(url.contains("page=2"));
        assert!(url.contains("size=100"));
    }

    #[test]
    fn parse_success_response() {
        let v = json!({
            "response_code": 0, "verbose_msg": "OK",
            "data": {
                "total_count": 42,
                "data": [
                    {"ip": {"ip": "1.2.3.4", "location": {"country": "中国", "region": "浙江", "city": "杭州"},
                            "isp": "电信", "asn": {"number": "AS4134", "organisation": "China Telecom"}},
                     "port": 443, "protocol": "https", "web_title": "Login",
                     "domain": {"domain": "example.com"}, "host": "example.com",
                     "application": "Nginx", "status_code": 200, "last_scan_time": 1735689600}
                ]
            }
        });
        let r = parse_response(&v, None).unwrap();
        assert_eq!(r.total, 42);
        let a = &r.assets[0];
        assert_eq!(a.ip, "1.2.3.4");
        assert_eq!(a.title, "Login");
        assert_eq!(a.domain, "example.com");
        assert_eq!(a.org, "China Telecom");
        assert_eq!(a.status_code, "200");
        assert_eq!(a.extras_lookup("省份"), "浙江");
        assert_eq!(a.extras_lookup("运营商"), "电信");
    }

    #[test]
    fn parse_platform_error() {
        let v = json!({"response_code": -1, "verbose_msg": "查询条件过于宽泛"});
        assert!(
            parse_response(&v, None)
                .unwrap_err()
                .to_string()
                .contains("过于宽泛")
        );
    }
}
