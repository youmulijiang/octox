//! 独立小工具：favicon hash 计算与 URL → HTTP Host 头解析。
//!
//! favicon hash 与 FOFA `icon_hash` / Shodan `http.favicon.hash` 同款算法：
//! 抓取站点图标 → base64 编码 → MurmurHash3（x86 32 位，seed 0，取有符号值）。

use base64::Engine as _;

use crate::config::Config;
use crate::engines::http_agent;

/// 解析后的目标站点。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// scheme://host[:port]（端口按用户输入保留）。
    pub origin: String,
    /// HTTP Host 头取值：host[:port]，scheme 默认端口自动省略；IPv6 保留方括号。
    pub host_header: String,
    /// 输入中携带的路径与查询（含前导 /，无则空）。
    pub path: String,
}

impl Target {
    /// 补全 scheme 后的完整 URL。
    pub fn url(&self) -> String {
        format!("{}{}", self.origin, self.path)
    }
}

/// 解析用户输入的 URL / host。缺 scheme 时按 http 处理；
/// 支持带路径、查询、用户信息（user:pass@）与 IPv6 字面量（[::1]:8080）。
pub fn parse_target(input: &str) -> Result<Target, String> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err("输入为空".into());
    }
    let (scheme, rest) = if let Some(r) = raw.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = raw.strip_prefix("http://") {
        ("http", r)
    } else if raw.contains("://") {
        return Err(format!("仅支持 http/https 地址: {raw}"));
    } else {
        ("http", raw)
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let path = &rest[authority_end..];
    if authority.is_empty() {
        return Err(format!("无法解析主机: {raw}"));
    }
    // 去掉用户信息（user:pass@host）。
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let (host_raw, port) = if let Some(inner) = authority.strip_prefix('[') {
        let Some(end) = inner.find(']') else {
            return Err("IPv6 地址缺少右括号".into());
        };
        let host = &inner[..end];
        let port = inner[end + 1..].strip_prefix(':');
        (format!("[{host}]"), port)
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (authority.to_string(), None),
        }
    };
    let port = port.filter(|p| !p.is_empty());
    if host_raw.is_empty() {
        return Err(format!("无法解析主机: {raw}"));
    }
    if let Some(p) = &port
        && p.parse::<u16>().is_err()
    {
        return Err(format!("端口无效: {p}"));
    }
    let default_port = if scheme == "https" { "443" } else { "80" };
    let host_header = match port {
        Some(p) if p != default_port => format!("{host_raw}:{p}"),
        _ => host_raw.clone(),
    };
    let origin = match port {
        Some(p) => format!("{scheme}://{host_raw}:{p}"),
        None => format!("{scheme}://{host_raw}"),
    };
    Ok(Target {
        origin,
        host_header,
        path: path.to_string(),
    })
}

/// 从 URL / host 文本提取 HTTP Host 头；解析失败返回 None。
pub fn host_header(input: &str) -> Option<String> {
    parse_target(input).ok().map(|t| t.host_header)
}

/// MurmurHash3 x86 32 位（seed 0），与 Python mmh3、FOFA / Shodan 的 favicon
/// hash 计算一致。
pub fn murmur3_32(data: &[u8]) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut h: u32 = 0;
    let (chunks, tail) = data.as_chunks::<4>();
    for chunk in chunks {
        let k = u32::from_le_bytes(*chunk);
        h ^= k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h = h.rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64);
    }
    // 尾部不足 4 字节按小端补齐（首字节为最低位）。
    let mut k = 0u32;
    for (i, b) in tail.iter().enumerate() {
        k ^= u32::from(*b) << (8 * i);
    }
    h ^= k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
    h ^= data.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

/// FOFA / Shodan 的 icon hash：base64(图标字节) 按 76 字符一行补换行后再做 mmh3，
/// 取有符号 32 位值。与社区通用脚本 `mmh3.hash(codecs.encode(icon, "base64"))`
/// 完全对齐（注意换行参与哈希，无换行的标准 base64 会得到不同结果）。
pub fn icon_hash_of_base64(b64: &str) -> i32 {
    murmur3_32(mime_wrap(b64).as_bytes()) as i32
}

/// 按 76 字符一行补换行（含末行换行），对齐 Python `codecs.encode(x, "base64")`。
fn mime_wrap(b64: &str) -> String {
    let mut out = String::with_capacity(b64.len() + b64.len() / 76 + 2);
    for chunk in b64.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 恒为 ASCII"));
        out.push('\n');
    }
    out
}

/// favicon hash 计算结果。
#[derive(Debug, Clone)]
pub struct FaviconHash {
    /// 实际抓取的图标 URL（data: 内联时标注来源页）。
    pub icon_url: String,
    /// FOFA `icon_hash` / Shodan `http.favicon.hash` 的取值。
    pub hash: i32,
}

/// 通过 URL 计算 favicon hash。抓取顺序：
/// 1. 输入本身像图标地址（路径含 favicon 或图片扩展名）时直接抓取；
/// 2. 站点根 `/favicon.ico`；
/// 3. 输入 URL 原样；
/// 4. 以上全失败时退回主页 HTML 中 `<link rel=...icon...>` 指向的图标（含 data: 内联）。
pub fn favicon_hash(settings: &Config, input: &str) -> Result<FaviconHash, String> {
    let target = parse_target(input)?;
    let lower_path = target.path.to_ascii_lowercase();
    let mut candidates: Vec<String> = Vec::new();
    if looks_like_icon_path(&lower_path) {
        candidates.push(target.url());
    }
    candidates.push(format!("{}/favicon.ico", target.origin));
    if !target.path.is_empty() && !candidates.contains(&target.url()) {
        candidates.push(target.url());
    }
    let agent = http_agent(settings);
    for url in &candidates {
        if let Some(out) = fetch_icon_hash(&agent, url) {
            return Ok(out);
        }
    }
    // 站点把 /favicon.ico 404 掉时，从主页 HTML 找真实图标地址。
    if let Some((source, b64)) = inline_icon_from_homepage(&agent, &target.origin) {
        return Ok(FaviconHash {
            icon_url: source,
            hash: icon_hash_of_base64(&b64),
        });
    }
    for url in icon_links_from_homepage(&agent, &target.origin) {
        if let Some(out) = fetch_icon_hash(&agent, &url) {
            return Ok(out);
        }
    }
    Err(format!(
        "未能抓取到 favicon（已尝试 {}）。可改填图标的完整地址重试",
        candidates.join("、")
    ))
}

/// 路径是否像图标文件本身。
fn looks_like_icon_path(path_lower: &str) -> bool {
    path_lower.contains("favicon")
        || [
            ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".bmp", ".avif",
        ]
        .iter()
        .any(|ext| path_lower.ends_with(ext))
}

/// 抓取单个图标并计算 hash；候选不可用（非 2xx / 空内容 / 返回的是网页）时返回 None。
fn fetch_icon_hash(agent: &ureq::Agent, url: &str) -> Option<FaviconHash> {
    let response = agent
        .get(url)
        .header("User-Agent", "octox/0.1")
        .call()
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let content_type = response
        .headers()
        .get(ureq::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let body = response.into_body().read_to_vec().ok()?;
    // 图标极少超过 2 MiB，超限多半是兜底页。
    if body.is_empty() || body.len() > 2 * 1024 * 1024 {
        return None;
    }
    // 404 兜底页 / SPA 返回 HTML 时视为失败；SVG 图标靠 Content-Type 区分。
    if content_type.contains("text/html")
        || content_type.contains("xhtml")
        || (content_type.is_empty() && looks_like_html(&body))
    {
        return None;
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(&body);
    Some(FaviconHash {
        icon_url: url.to_string(),
        hash: icon_hash_of_base64(&b64),
    })
}

/// 字节内容是否像 HTML 文档。
fn looks_like_html(body: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&body[..body.len().min(256)]).to_ascii_lowercase();
    head.contains("<!doctype html") || head.contains("<html")
}

/// 主页 HTML 中 `<link rel=...icon...>` 指向的图标地址（相对地址已补全）。
fn icon_links_from_homepage(agent: &ureq::Agent, origin: &str) -> Vec<String> {
    let Some(html) = fetch_homepage_html(agent, origin) else {
        return Vec::new();
    };
    scan_icon_hrefs(&html, 8)
        .iter()
        .map(|href| resolve_url(origin, href))
        .collect()
}

/// 主页 HTML 中第一个 data: 内联图标（data:image/...;base64,xxx），返回 (来源标注, base64)。
fn inline_icon_from_homepage(agent: &ureq::Agent, origin: &str) -> Option<(String, String)> {
    let html = fetch_homepage_html(agent, origin)?;
    let hrefs = scan_icon_hrefs(&html, 8);
    hrefs.into_iter().find_map(|href| {
        let idx = href.find("base64,")?;
        let b64 = href[idx + "base64,".len()..].trim().to_string();
        (!b64.is_empty()).then_some((format!("{origin}（页面内联 data URI）"), b64))
    })
}

fn fetch_homepage_html(agent: &ureq::Agent, origin: &str) -> Option<String> {
    let response = agent
        .get(origin)
        .header("User-Agent", "octox/0.1")
        .call()
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.into_body().read_to_string().ok()
}

/// 在 HTML 中找含 icon 的 `<link>` 标签 href（最多 `max` 个，去重保序）。
fn scan_icon_hrefs(html: &str, max: usize) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while out.len() < max {
        let Some(start) = lower[cursor..].find("<link") else {
            break;
        };
        let tag_start = cursor + start;
        let tag_end = html[tag_start..]
            .find('>')
            .map_or(html.len(), |i| tag_start + i);
        let tag = &html[tag_start..tag_end];
        cursor = tag_end;
        let rel = tag_attr(&tag.to_ascii_lowercase(), "rel").unwrap_or_default();
        if !rel.contains("icon") {
            continue;
        }
        if let Some(href) = tag_attr(tag, "href") {
            let href = href.trim();
            if !href.is_empty() && !out.iter().any(|h| h == href) {
                out.push(href.to_string());
            }
        }
    }
    out
}

/// 取标签里某个属性的值（支持双引号 / 单引号 / 裸值）。
fn tag_attr(tag: &str, attr: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let key = format!("{attr}=");
    let pos = lower.find(&key)? + key.len();
    let rest = tag[pos..].trim_start();
    match rest.chars().next()? {
        '"' => rest[1..].split('"').next().map(str::to_string),
        '\'' => rest[1..].split('\'').next().map(str::to_string),
        _ => rest.split_whitespace().next().map(str::to_string),
    }
}

/// 相对地址补全（够用即可：不处理 ../ 之类的复杂场景）。
fn resolve_url(origin: &str, href: &str) -> String {
    if href.starts_with("http://") || href.starts_with("https://") {
        href.to_string()
    } else if let Some(rest) = href.strip_prefix("//") {
        let scheme = origin.split_once(':').map_or("http", |(s, _)| s);
        format!("{scheme}://{rest}")
    } else if href.starts_with('/') {
        format!("{origin}{href}")
    } else {
        format!("{origin}/{href}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn murmur3_matches_reference_vectors() {
        // 维基百科 MurmurHash 词条给出的 x86 32 位标准测试向量（seed 0）。
        assert_eq!(murmur3_32(b""), 0);
        assert_eq!(murmur3_32(b"hello"), 0x248bfa47);
    }

    #[test]
    fn parse_target_fills_scheme_and_keeps_port() {
        let t = parse_target("example.com/path?q=1").unwrap();
        assert_eq!(t.origin, "http://example.com");
        assert_eq!(t.host_header, "example.com");
        assert_eq!(t.path, "/path?q=1");
        assert_eq!(t.url(), "http://example.com/path?q=1");

        let t = parse_target("https://example.com:8443").unwrap();
        assert_eq!(t.origin, "https://example.com:8443");
        assert_eq!(t.host_header, "example.com:8443");

        // 默认端口不进 Host 头。
        let t = parse_target("http://example.com:80").unwrap();
        assert_eq!(t.host_header, "example.com");

        let t = parse_target("http://user:pass@1.2.3.4:8080").unwrap();
        assert_eq!(t.host_header, "1.2.3.4:8080");

        let t = parse_target("http://[::1]:8080/x").unwrap();
        assert_eq!(t.host_header, "[::1]:8080");
        assert_eq!(t.origin, "http://[::1]:8080");
    }

    #[test]
    fn parse_target_rejects_bad_input() {
        assert!(parse_target("").is_err());
        assert!(parse_target("ftp://example.com").is_err());
        assert!(parse_target("http://example.com:notaport").is_err());
        assert!(parse_target("http://[::1:8080").is_err());
    }

    #[test]
    fn scan_icon_hrefs_extracts_icon_links() {
        let html = r#"
            <link rel="stylesheet" href="/style.css">
            <link rel="shortcut icon" href="/static/favicon.ico">
            <link rel='apple-touch-icon' href=/touch.png>
            <link rel="icon" href="data:image/png;base64,iVBORw0KGgo=">
        "#;
        let hrefs = scan_icon_hrefs(html, 8);
        assert_eq!(hrefs.len(), 3);
        assert_eq!(hrefs[0], "/static/favicon.ico");
        assert_eq!(hrefs[1], "/touch.png");
        assert!(hrefs[2].starts_with("data:image/png;base64,"));

        assert!(scan_icon_hrefs("<link rel=\"stylesheet\" href=\"/a.css\">", 8).is_empty());
    }

    #[test]
    fn resolve_url_joins_origin() {
        assert_eq!(
            resolve_url("https://a.com", "https://b.com/x.ico"),
            "https://b.com/x.ico"
        );
        assert_eq!(
            resolve_url("https://a.com", "//cdn.b.com/x.ico"),
            "https://cdn.b.com/x.ico"
        );
        assert_eq!(
            resolve_url("https://a.com", "/s/x.ico"),
            "https://a.com/s/x.ico"
        );
        assert_eq!(resolve_url("http://a.com", "x.ico"), "http://a.com/x.ico");
    }

    #[test]
    fn looks_like_icon_path_matches_extensions() {
        assert!(looks_like_icon_path("/favicon.ico"));
        // 调用方传入前会先转小写。
        assert!(looks_like_icon_path("/s/logo.png"));
        assert!(!looks_like_icon_path("/index.html"));
    }

    #[test]
    fn mime_wrap_matches_python_codecs_base64() {
        // Python: codecs.encode(b"hello", "base64") -> b"aGVsbG8=\n"
        assert_eq!(mime_wrap("aGVsbG8="), "aGVsbG8=\n");
        // 80 字符（60 字节数据）在 76 字符处断行。
        let long = "QQ".repeat(60);
        assert_eq!(
            mime_wrap(&long),
            format!("{}\n{}\n", &long[..76], &long[76..])
        );
        assert_eq!(mime_wrap(""), "");
    }
}
