use serde::{Deserialize, Serialize};

/// 支持的测绘引擎。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Engine {
    Fofa,
    Hunter,
    Quake,
    Shodan,
    ZoomEye,
    ThreatBook,
    Zone0,
    DayDayMap,
    VirusTotal,
    Censys,
}

impl Engine {
    pub const ALL: [Engine; 10] = [
        Engine::Fofa,
        Engine::Hunter,
        Engine::Quake,
        Engine::Shodan,
        Engine::ZoomEye,
        Engine::ThreatBook,
        Engine::Zone0,
        Engine::DayDayMap,
        Engine::VirusTotal,
        Engine::Censys,
    ];

    pub const COUNT: usize = 10;

    /// 引擎在 ALL 中的下标（配置数组 / 公共语法模板表按此索引）。
    pub fn index(self) -> usize {
        Self::ALL.iter().position(|e| *e == self).unwrap_or(0)
    }

    pub fn name(self) -> &'static str {
        match self {
            Engine::Fofa => "FOFA",
            Engine::Hunter => "Hunter",
            Engine::Quake => "Quake",
            Engine::Shodan => "Shodan",
            Engine::ZoomEye => "ZoomEye",
            Engine::ThreatBook => "ThreatBook",
            Engine::Zone0 => "0.zone",
            Engine::DayDayMap => "DayDayMap",
            Engine::VirusTotal => "VirusTotal",
            Engine::Censys => "Censys",
        }
    }

    /// 引擎主题色（0xRRGGBB）。
    pub fn accent(self) -> u32 {
        match self {
            Engine::Fofa => 0xe0503a,
            Engine::Hunter => 0x3f8cff,
            Engine::Quake => 0xf0a030,
            Engine::Shodan => 0xd94f88,
            Engine::ZoomEye => 0x2fbfa5,
            Engine::ThreatBook => 0x8a63f0,
            Engine::Zone0 => 0x4caf6e,
            Engine::DayDayMap => 0xb8863b,
            Engine::VirusTotal => 0x5c6bc0,
            Engine::Censys => 0x26a0c4,
        }
    }
}

/// 三引擎归一化后的资产记录；缺失字段一律为 `-`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub engine: Engine,
    pub host: String,
    pub ip: String,
    pub port: String,
    pub protocol: String,
    pub title: String,
    pub domain: String,
    pub component: String,
    pub org: String,
    pub country: String,
    pub city: String,
    pub status_code: String,
    pub updated_at: String,
    pub url: String,
    /// 引擎特有字段（标准列之外的展示信息，如 FOFA 域名、Hunter 省份、
    /// Quake favicon）。`Vec<(标签, 值)>` 保序；单引擎模式下表格动态追加这些列。
    #[serde(default)]
    pub extras: Vec<(String, String)>,
}

impl Asset {
    /// 取扩展字段值（缺省 "-"）。
    pub fn extras_lookup<'a>(&'a self, label: &str) -> &'a str {
        self.extras
            .iter()
            .find(|(l, _)| l == label)
            .map(|(_, v)| v.as_str())
            .unwrap_or("-")
    }

    #[allow(dead_code)]
    pub fn empty(engine: Engine) -> Self {
        Self {
            engine,
            host: "-".into(),
            ip: "-".into(),
            port: "-".into(),
            protocol: "-".into(),
            title: "-".into(),
            domain: "-".into(),
            component: "-".into(),
            org: "-".into(),
            country: "-".into(),
            city: "-".into(),
            status_code: "-".into(),
            updated_at: "-".into(),
            url: "-".into(),
            extras: Vec::new(),
        }
    }
}
