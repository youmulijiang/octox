use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize};

use crate::asset::Engine;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FofaCreds {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub key: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HunterCreds {
    #[serde(default)]
    pub api_key: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuakeCreds {
    #[serde(default)]
    pub token: String,
}

/// 单 Key 凭证（Shodan / ZoomEye / ThreatBook / 0.zone / DayDayMap / VirusTotal）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimpleCreds {
    #[serde(default)]
    pub api_key: String,
}

/// Censys 双凭证（api-id + api-secret，Basic 认证）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CensysCreds {
    #[serde(default)]
    pub api_id: String,
    #[serde(default)]
    pub api_secret: String,
}

/// 一条收藏的查询语句：语句 + 标签 + 描述。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Favorite {
    pub query: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub note: String,
}

/// 兼容旧版 `Vec<String>` 收藏：字符串升级为无标签/描述的结构，其余字段不受影响。
fn deserialize_favorites<'de, D>(deserializer: D) -> Result<Vec<Favorite>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw: Vec<serde_json::Value> = Deserialize::deserialize(deserializer)?;
    Ok(raw
        .into_iter()
        .map(|v| {
            if let Ok(query) = serde_json::from_value::<String>(v.clone()) {
                Favorite {
                    query,
                    tags: Vec::new(),
                    note: String::new(),
                }
            } else {
                serde_json::from_value::<Favorite>(v).unwrap_or(Favorite {
                    query: String::new(),
                    tags: Vec::new(),
                    note: String::new(),
                })
            }
        })
        .filter(|f| !f.query.is_empty())
        .collect())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub fofa: FofaCreds,
    #[serde(default)]
    pub hunter: HunterCreds,
    #[serde(default)]
    pub quake: QuakeCreds,
    #[serde(default)]
    pub shodan: SimpleCreds,
    #[serde(default)]
    pub zoomeye: SimpleCreds,
    #[serde(default)]
    pub threatbook: SimpleCreds,
    #[serde(default)]
    pub zone0: SimpleCreds,
    #[serde(default)]
    pub daydaymap: SimpleCreds,
    #[serde(default)]
    pub virustotal: SimpleCreds,
    #[serde(default)]
    pub censys: CensysCreds,
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    /// 允许翻到的最大页数（分页上限，1 起）。
    #[serde(default = "default_max_pages")]
    pub max_pages: u32,
    /// 引擎请求间隔（秒，0 = 并发；用于规避聚合查询限频）。
    #[serde(default)]
    pub request_delay_secs: u64,
    /// 单次 HTTP 请求超时（秒）。
    #[serde(default = "default_timeout_secs")]
    pub request_timeout_secs: u64,
    /// FOFA：是否搜索全量历史数据（消耗 F 点）。
    #[serde(default)]
    pub fofa_full: bool,
    /// 各引擎扩展字段显示开关（键 = 引擎名；缺省 = 全部目录字段都显示）。
    #[serde(default)]
    pub extra_fields: std::collections::BTreeMap<String, Vec<String>>,
    /// HTTP 代理地址（如 http://127.0.0.1:7890；空 = 直连）。
    #[serde(default)]
    pub proxy_url: String,
    /// 是否启用代理。
    #[serde(default)]
    pub proxy_enabled: bool,
    /// 聚合模式下参与搜索的引擎（按 Engine::ALL 顺序，长度 10）。
    /// 兼容旧版长度 3 的配置：不足处补 false（新引擎默认不参与聚合）。
    #[serde(
        default = "default_aggregate_engines",
        deserialize_with = "deserialize_aggregate_engines"
    )]
    pub aggregate_engines: [bool; Engine::COUNT],
    /// 主题："dark"（默认，shadcn zinc dark）或 "light"（shadcn zinc light）。
    #[serde(default = "default_theme")]
    pub theme: String,
    /// MCP TCP 服务是否开启（GUI 内菜单栏 / 设置页切换，重启应用自动恢复）。
    #[serde(default)]
    pub mcp_enabled: bool,
    /// MCP TCP 服务端口（监听 127.0.0.1）。
    #[serde(default = "default_mcp_port")]
    pub mcp_port: u16,
    /// 结果表显示的列（列 key 列表；缺省全部显示）。
    #[serde(default = "default_columns")]
    pub columns: Vec<String>,
    /// 收藏的查询语句（最新在前）。
    #[serde(default, deserialize_with = "deserialize_favorites")]
    pub favorites: Vec<Favorite>,
}

fn default_page_size() -> u32 {
    20
}

fn default_max_pages() -> u32 {
    5
}

fn default_timeout_secs() -> u64 {
    30
}

fn default_aggregate_engines() -> [bool; Engine::COUNT] {
    let mut flags = [false; Engine::COUNT];
    // 默认沿用聚合语义的三家中文引擎；新引擎需手动勾选。
    flags[0] = true;
    flags[1] = true;
    flags[2] = true;
    flags
}

/// 兼容旧版 `[bool; 3]`：按位拷贝，不足补 false，超长截断。
fn deserialize_aggregate_engines<'de, D>(deserializer: D) -> Result<[bool; Engine::COUNT], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw: Vec<bool> = Deserialize::deserialize(deserializer)?;
    let mut flags = [false; Engine::COUNT];
    for (i, v) in raw.into_iter().take(Engine::COUNT).enumerate() {
        flags[i] = v;
    }
    // 至少保留一个参与引擎，避免旧配置迁移后聚合空转。
    if !flags.iter().any(|v| *v) {
        flags[0] = true;
    }
    Ok(flags)
}

fn default_theme() -> String {
    "dark".to_string()
}

fn default_mcp_port() -> u16 {
    7737
}

fn default_columns() -> Vec<String> {
    [
        "engine",
        "host",
        "ip",
        "port",
        "protocol",
        "title",
        "component",
        "org",
        "location",
        "time",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            fofa: FofaCreds::default(),
            hunter: HunterCreds::default(),
            quake: QuakeCreds::default(),
            shodan: SimpleCreds::default(),
            zoomeye: SimpleCreds::default(),
            threatbook: SimpleCreds::default(),
            zone0: SimpleCreds::default(),
            daydaymap: SimpleCreds::default(),
            virustotal: SimpleCreds::default(),
            censys: CensysCreds::default(),
            page_size: default_page_size(),
            max_pages: default_max_pages(),
            request_delay_secs: 0,
            request_timeout_secs: default_timeout_secs(),
            fofa_full: false,
            extra_fields: std::collections::BTreeMap::new(),
            proxy_url: String::new(),
            proxy_enabled: false,
            aggregate_engines: default_aggregate_engines(),
            theme: default_theme(),
            mcp_enabled: false,
            mcp_port: default_mcp_port(),
            columns: default_columns(),
            favorites: Vec::new(),
        }
    }
}

/// 解析标签输入：逗号（中英文）/ 空白分隔，去空去重。
pub fn parse_tags(input: &str) -> Vec<String> {
    let mut tags = Vec::new();
    for part in input.split([',', '，', ' ', '\t']) {
        let tag = part.trim();
        if !tag.is_empty() && !tags.iter().any(|t| t == tag) {
            tags.push(tag.to_string());
        }
    }
    tags
}

impl Config {
    /// 配置文件路径：%APPDATA%/octox/config.json（失败时退化为当前目录）。
    pub fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("octox")
            .join("config.json")
    }

    /// 读取配置；文件不存在或损坏时返回默认值（首次保存时会生成文件）。
    pub fn load() -> Self {
        std::fs::read_to_string(Self::config_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> io::Result<()> {
        let path = Self::config_path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(
            path,
            serde_json::to_string_pretty(self).expect("serialize config"),
        )
    }

    /// 引擎凭证是否已配置。
    pub fn creds_ready(&self, engine: crate::asset::Engine) -> bool {
        use crate::asset::Engine;
        match engine {
            Engine::Fofa => !self.fofa.email.trim().is_empty() && !self.fofa.key.trim().is_empty(),
            Engine::Hunter => !self.hunter.api_key.trim().is_empty(),
            Engine::Quake => !self.quake.token.trim().is_empty(),
            Engine::Shodan => !self.shodan.api_key.trim().is_empty(),
            Engine::ZoomEye => !self.zoomeye.api_key.trim().is_empty(),
            Engine::ThreatBook => !self.threatbook.api_key.trim().is_empty(),
            Engine::Zone0 => !self.zone0.api_key.trim().is_empty(),
            Engine::DayDayMap => !self.daydaymap.api_key.trim().is_empty(),
            Engine::VirusTotal => !self.virustotal.api_key.trim().is_empty(),
            Engine::Censys => {
                !self.censys.api_id.trim().is_empty() && !self.censys.api_secret.trim().is_empty()
            }
        }
    }

    /// 引擎扩展字段开关：None = 用户未定制（目录全开）。
    pub fn extra_enabled(&self, engine: Engine) -> Option<&Vec<String>> {
        self.extra_fields.get(engine.name())
    }

    /// 翻转某引擎某扩展字段的显示；首次操作时以全目录初始化。
    pub fn toggle_extra_field(&mut self, engine: Engine, label: &str, catalog: &[String]) {
        let entry = self
            .extra_fields
            .entry(engine.name().to_string())
            .or_insert_with(|| catalog.to_vec());
        if let Some(pos) = entry.iter().position(|l| l == label) {
            entry.remove(pos);
        } else {
            entry.push(label.to_string());
        }
    }

    /// 收藏中出现过的所有标签（去重，按出现顺序）。
    pub fn favorite_tags(&self) -> Vec<String> {
        let mut tags = Vec::new();
        for fav in &self.favorites {
            for tag in &fav.tags {
                if !tags.iter().any(|t| t == tag) {
                    tags.push(tag.clone());
                }
            }
        }
        tags
    }

    /// 新增收藏（插到最前）；已存在同语句时返回 false 不重复插入。
    pub fn favorite_add(&mut self, query: &str, tags: Vec<String>, note: &str) -> bool {
        if query.is_empty() || self.favorites.iter().any(|f| f.query == query) {
            return false;
        }
        self.favorites.insert(
            0,
            Favorite {
                query: query.to_string(),
                tags,
                note: note.to_string(),
            },
        );
        true
    }

    /// 按语句删除收藏，返回是否删除了条目。
    pub fn favorite_remove(&mut self, query: &str) -> bool {
        let before = self.favorites.len();
        self.favorites.retain(|f| f.query != query);
        self.favorites.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tags_splits_and_dedupes() {
        assert_eq!(
            parse_tags("后台, 邮件，OA  后台"),
            vec!["后台".to_string(), "邮件".to_string(), "OA".to_string()]
        );
        assert!(parse_tags("  ").is_empty());
    }

    #[test]
    fn favorites_round_trip_and_migrate_from_strings() {
        let old = r#"{"favorites":["ip=\"1.2.3.4\"","port=80"]}"#;
        let config: Config = serde_json::from_str(old).unwrap();
        assert_eq!(config.favorites.len(), 2);
        assert_eq!(config.favorites[0].query, "ip=\"1.2.3.4\"");
        assert!(config.favorites[0].tags.is_empty());

        let mut config = config;
        assert!(config.favorite_add("port=443", parse_tags("端口"), "常用"));
        assert!(!config.favorite_add("port=443", vec![], "")); // 去重
        assert_eq!(config.favorites[0].note, "常用");

        let text = serde_json::to_string(&config).unwrap();
        let mut again: Config = serde_json::from_str(&text).unwrap();
        assert_eq!(again.favorites.len(), 3);
        assert_eq!(again.favorites[0].tags, vec!["端口".to_string()]);
        assert!(again.favorite_remove("port=443"));
        assert_eq!(again.favorites.len(), 2);
    }

    #[test]
    fn legacy_fields_keep_defaults_when_absent() {
        let config: Config = serde_json::from_str("{}").unwrap();
        assert_eq!(config.max_pages, 5);
        assert_eq!(config.theme, "dark");
        assert_eq!(config.columns.len(), 10);
    }
}
