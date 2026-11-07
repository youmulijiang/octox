//! 最小 MCP（Model Context Protocol）stdio Server。
//!
//! `octox --mcp` 启动后，通过 stdin / stdout 以换行分隔的 JSON-RPC 2.0 与
//! MCP 客户端（Claude Desktop、Zed、Cherry Studio 等）通信，把三引擎搜索与
//! 收藏能力作为工具暴露。无窗口、无第三方 MCP 依赖，stdout 只输出协议报文。
//!
//! 支持方法：initialize / ping / tools/list / tools/call；
//! 工具：search、list_engines、list_favorites、add_favorite。
//!
//! 两种运行方式：
//! - stdio：`octox --mcp`，由 MCP 客户端拉起，stdin/stdout 通信；
//! - TCP：GUI 内菜单栏 / 设置页开启，监听 127.0.0.1:{port}，
//!   同样为换行分隔 JSON-RPC，GUI 运行期间对外提供服务。

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::asset::{Asset, Engine};
use crate::config::{Config, parse_tags};
use crate::search::{self, SearchPlan};

/// 启动 stdio MCP 服务：逐行读取请求、写出响应，stdin 关闭时退出。
pub fn run_server() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if let Some(response) = handle_line(&line) {
            write_message(&mut out, response);
        }
    }
}

/// 在 127.0.0.1:{port} 启动 TCP MCP 服务（GUI 内开关；port=0 时由系统分配）。
/// 返回实际绑定端口、关闭标记与接受循环线程句柄；置位标记后循环在 ≤100ms 内退出。
pub fn start_tcp_server(port: u16) -> std::io::Result<(u16, Arc<AtomicBool>, JoinHandle<()>)> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let bound = listener.local_addr()?.port();
    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = shutdown.clone();
    let handle = std::thread::spawn(move || {
        let _ = listener.set_nonblocking(true);
        loop {
            if flag.load(Ordering::Relaxed) {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let flag = flag.clone();
                    std::thread::spawn(move || handle_connection(stream, flag));
                }
                // 非阻塞轮询，保证能及时响应关闭标记。
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(_) => break,
            }
        }
    });
    Ok((bound, shutdown, handle))
}

fn handle_connection(stream: TcpStream, shutdown: Arc<AtomicBool>) {
    let Ok(mut out) = stream.try_clone() else {
        return;
    };
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let Ok(line) = line else { break };
        if let Some(response) = handle_line(&line) {
            write_message(&mut out, response);
        }
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
    }
}

/// 处理一行 JSON-RPC：请求返回响应报文；通知 / 空行返回 None。
fn handle_line(line: &str) -> Option<Value> {
    if line.trim().is_empty() {
        return None;
    }
    let Ok(msg) = serde_json::from_str::<Value>(line) else {
        return Some(
            json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "Parse error"}}),
        );
    };
    // 无 id 的为通知（initialized / cancelled 等），不响应。
    let id = msg.get("id").cloned()?;
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let response = match method {
        "initialize" => Ok(json!({
            "protocolVersion": msg["params"]["protocolVersion"]
                .as_str()
                .unwrap_or("2025-03-26"),
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": "octox", "version": env!("CARGO_PKG_VERSION")},
            "instructions": "测绘引擎聚合搜索（FOFA/Hunter/Quake/Shodan/ZoomEye/ThreatBook/0.zone/DayDayMap/VirusTotal/Censys）；engine=all 时使用公共语法并自动翻译为各引擎方言。",
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools_manifest()})),
        "tools/call" => call_tool(msg.get("params").unwrap_or(&Value::Null)),
        _ => Err((-32601i64, format!("Method not found: {method}"))),
    };
    Some(match response {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err((code, message)) => {
            json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
        }
    })
}

fn write_message<W: Write>(out: &mut W, message: Value) {
    writeln!(out, "{message}").ok();
    out.flush().ok();
}

fn tools_manifest() -> Value {
    json!([
        {
            "name": "search",
            "description": "跨测绘引擎（FOFA / Hunter / Quake / Shodan / ZoomEye / ThreatBook / 0.zone / DayDayMap / VirusTotal / Censys）搜索资产。engine=all 时使用公共语法（字段=值，支持 && || 组合）并自动翻译为各引擎方言；单引擎时查询语句原样使用该引擎原生语法。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "engine": {"type": "string", "enum": ["fofa", "hunter", "quake", "shodan", "zoomeye", "threatbook", "zone0", "daydaymap", "virustotal", "censys", "all"], "description": "目标引擎；all = 按设置中参与聚合的引擎"},
                    "query": {"type": "string", "description": "查询语句，如 ip=\"1.2.3.4\" && port=80"},
                    "page": {"type": "integer", "minimum": 1, "description": "页码，默认 1（受最大页数设置限制）"},
                    "size": {"type": "integer", "minimum": 1, "maximum": 100, "description": "请求每页条数；Shodan 固定 100，ZoomEye 固定 20"},
                    "cursors": {"type": "object", "additionalProperties": {"type": "string"}, "description": "后续页将上一页各引擎的 next_cursor 按引擎名传入，如 virustotal、censys；保持 query 和 size 不变"}
                },
                "required": ["engine", "query"]
            }
        },
        {
            "name": "list_engines",
            "description": "查看引擎凭证配置状态与聚合参与设置。",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "list_favorites",
            "description": "列出收藏的查询语句（含标签与描述）。",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "add_favorite",
            "description": "新增或更新收藏的查询语句（同语句重复添加会更新标签/描述）。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "查询语句"},
                    "tags": {"type": "array", "items": {"type": "string"}, "description": "标签，可空"},
                    "note": {"type": "string", "description": "描述，可空"}
                },
                "required": ["query"]
            }
        }
    ])
}

/// tools/call 分发。业务失败以 isError 内容返回（而非协议错误），便于客户端展示。
fn call_tool(params: &Value) -> Result<Value, (i64, String)> {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let outcome = match name {
        "search" => tool_search(&args),
        "list_engines" => tool_list_engines(),
        "list_favorites" => tool_list_favorites(),
        "add_favorite" => tool_add_favorite(&args),
        _ => return Err((-32602, format!("未知工具 `{name}`"))),
    };
    let (text, is_error) = match outcome {
        Ok(text) => (text, false),
        Err(message) => (message, true),
    };
    Ok(json!({
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    }))
}

fn search_parameters(args: &Value, config: &Config) -> Result<(u32, u32), String> {
    let integer = |key: &str, default: u64, max: u64| -> Result<u32, String> {
        let value = match args.get(key) {
            None => default,
            Some(v) => v.as_u64().ok_or_else(|| format!("{key} 必须为正整数"))?,
        };
        if value == 0 || value > max {
            return Err(format!("{key} 必须在 1..={max} 之间"));
        }
        Ok(value as u32)
    };
    Ok((
        integer("page", 1, config.max_pages.max(1) as u64)?,
        integer("size", config.page_size.clamp(1, 100) as u64, 100)?,
    ))
}

fn tool_search(args: &Value) -> Result<String, String> {
    let engine = match args.get("engine") {
        None => "all",
        Some(v) => v.as_str().ok_or("engine 必须为引擎名称字符串")?,
    };
    if let Some(cursors) = args.get("cursors") {
        let cursors = cursors
            .as_object()
            .ok_or("cursors 必须为引擎名到游标的对象")?;
        if cursors.values().any(|v| !v.is_string()) {
            return Err("游标必须为字符串".into());
        }
    }
    let query = args
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if query.is_empty() {
        return Err("query 不能为空".into());
    }
    let config = Config::load();
    let (page, size) = search_parameters(args, &config)?;
    let single = match engine {
        "all" => None,
        name => Some(
            Engine::ALL
                .iter()
                .copied()
                .find(|e| {
                    e.name().to_lowercase() == name || (name == "zone0" && *e == Engine::Zone0)
                })
                .ok_or_else(|| format!("未知引擎：{name}"))?,
        ),
    };
    let plan = SearchPlan::prepare(&config, &query, single)?;
    let cursors = args.get("cursors").and_then(Value::as_object);
    let mut report = Map::new();
    report.insert("query".into(), json!(query));
    report.insert("page".into(), json!(page));
    report.insert("size".into(), json!(size));
    // 与 GUI 一样并发执行，并按配置错峰；结果按引擎顺序输出。
    let entries = std::thread::scope(|scope| {
        let mut tasks = Vec::new();
        let mut sequence = 0;
        for (engine, prepared) in plan.queries {
            let cfg = &config;
            let key = if engine == Engine::Zone0 {
                "zone0".to_string()
            } else {
                engine.name().to_lowercase()
            };
            let cursor = cursors.and_then(|c| c.get(&key)).and_then(Value::as_str);
            let delay = if prepared.is_ok() {
                let n = sequence;
                sequence += 1;
                cfg.request_delay_secs.min(60) * n
            } else {
                0
            };
            tasks.push(scope.spawn(move || {
                let entry = match prepared {
                    Err(e) => json!({"error": e}),
                    Ok(engine_query) => {
                        if delay > 0 {
                            std::thread::sleep(Duration::from_secs(delay));
                        }
                        match engine.search_page(cfg, &engine_query, page, size, cursor) {
                            Ok(sr) => json!({"query": engine_query, "total": sr.total,
                                "quota": sr.quota, "next_cursor": sr.next_cursor,
                                "has_more": search::has_more(engine, &sr, page, size),
                                "page_size": engine.effective_size(size),
                                "assets": sr.assets.iter().map(asset_json).collect::<Vec<_>>() }),
                            Err(e) => json!({"error": e.to_string()}),
                        }
                    }
                };
                (key, entry)
            }));
        }
        tasks
            .into_iter()
            .map(|t| t.join().map_err(|_| "搜索任务异常退出".to_string()))
            .collect::<Result<Vec<_>, _>>()
    })?;
    for (key, entry) in entries {
        report.insert(key, entry);
    }
    Ok(Value::Object(report).to_string())
}

fn tool_list_engines() -> Result<String, String> {
    let config = Config::load();
    let engines: Vec<Value> = Engine::ALL
        .iter()
        .enumerate()
        .map(|(i, e)| {
            json!({
                "engine": e.name(),
                "creds_ready": config.creds_ready(*e),
                "in_aggregate": config.aggregate_engines[i],
            })
        })
        .collect();
    Ok(json!({
        "max_pages": config.max_pages,
        "engines": engines,
    })
    .to_string())
}

fn tool_list_favorites() -> Result<String, String> {
    let config = Config::load();
    Ok(json!({
        "favorites": config.favorites.iter().map(|f| json!({
            "query": f.query,
            "tags": f.tags,
            "note": f.note,
        })).collect::<Vec<_>>(),
    })
    .to_string())
}

fn tool_add_favorite(args: &Value) -> Result<String, String> {
    let query = args
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if query.is_empty() {
        return Err("query 不能为空".into());
    }
    let tags: Vec<String> = args
        .get("tags")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .or_else(|| {
            args.get("tags")
                .and_then(Value::as_str)
                .map(|s| parse_tags(s))
        })
        .unwrap_or_default();
    let note = args
        .get("note")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();

    let mut config = Config::load();
    let created = config.favorite_add(&query, tags.clone(), &note);
    if !created {
        // 已存在：更新标签/描述。
        if let Some(fav) = config.favorites.iter_mut().find(|f| f.query == query) {
            fav.tags = tags.clone();
            fav.note = note.clone();
        }
    }
    config.save().map_err(|e| format!("保存收藏失败: {e}"))?;
    Ok(if created {
        format!("已新增收藏: {query}")
    } else {
        format!("收藏已存在，已更新标签/描述: {query}")
    })
}

fn asset_json(asset: &Asset) -> Value {
    json!({
        "engine": asset.engine.name(),
        "host": asset.host,
        "ip": asset.ip,
        "port": asset.port,
        "protocol": asset.protocol,
        "title": asset.title,
        "component": asset.component,
        "org": asset.org,
        "country": asset.country,
        "city": asset.city,
        "status_code": asset.status_code,
        "updated_at": asset.updated_at,
        "url": asset.url,
        "extras": asset.extras.iter().cloned().collect::<Vec<(String, String)>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_out_of_range_pages_without_wrapping_or_clamping() {
        let config = Config::default();
        for v in [
            json!(0),
            json!(-1),
            json!(1.5),
            json!(4294967297_u64),
            json!(6),
        ] {
            assert!(search_parameters(&json!({"page":v}), &config).is_err());
        }
        assert_eq!(search_parameters(&json!({}), &config).unwrap(), (1, 20));
        assert!(search_parameters(&json!({"size":101}), &config).is_err());
        assert!(
            tool_search(&json!({"engine":"typo","query":"port=80"}))
                .unwrap_err()
                .contains("未知引擎")
        );
    }

    #[test]
    fn manifest_exposes_four_tools() {
        let tools = tools_manifest();
        assert_eq!(tools.as_array().unwrap().len(), 4);
        assert!(tools.to_string().contains("\"search\""));
    }

    #[test]
    fn unknown_tool_is_protocol_error() {
        let err = call_tool(&json!({"name": "nope"})).unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[test]
    fn tcp_server_round_trip() {
        let (port, shutdown, _handle) = start_tcp_server(0).unwrap();
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        writeln!(
            stream,
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-03-26"}}}}"#
        )
        .unwrap();
        stream.flush().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains("octox"), "unexpected response: {line}");
        assert!(line.contains(r#""id":1"#));
        shutdown.store(true, Ordering::Relaxed);
    }

    #[test]
    fn add_favorite_requires_query() {
        let result = call_tool(&json!({"name": "add_favorite", "arguments": {}})).unwrap();
        assert_eq!(result["isError"], json!(true));
    }
}
