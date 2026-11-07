use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use gpui::{
    Animation, AnimationExt, ClickEvent, ClipboardItem, Context, Div, Entity, MouseButton,
    MouseDownEvent, Render, SharedString, Stateful, Window, actions, deferred, div, ease_out_quint,
    linear_color_stop, linear_gradient, prelude::*, px, rgb, rgba, uniform_list,
};

use crate::asset::{Asset, Engine};
use crate::autocomplete::{self, Completion};
use crate::config::{Config, parse_tags};
use crate::engines::{self, SearchResult};
use crate::export;
use crate::mcp;
use crate::search::{self, PageCache, SearchPlan};
use crate::tools;
use crate::translate;
use crate::ui::dropdown::{DropdownEvent, EngineDropdown, SearchMode};
use crate::ui::icons::{self, icon};
use crate::ui::input::{InputEvent, TextInput};
use crate::ui::modal::{overlay, panel};
use crate::ui::syntax;
use crate::ui::{Theme, button, field_label, theme};

actions!(
    octox,
    [CloseOverlay, Quit, SuggestNext, SuggestPrev, SuggestAccept]
);

const FAVORITE_COLOR: u32 = 0xf5c518;

// 结果表列宽（px）；宽度为 0 表示弹性列。
const COL_ENGINE: f32 = 92.;
const COL_HOST: f32 = 200.;
const COL_IP: f32 = 128.;
const COL_PORT: f32 = 52.;
const COL_PROTO: f32 = 64.;
const COL_COMP: f32 = 120.;
const COL_ORG: f32 = 140.;
const COL_LOC: f32 = 120.;
const COL_TIME: f32 = 150.;

/// 引擎特有列（单引擎结果集自动追加）的宽度。
const EXTRA_COL_WIDTH: f32 = 120.;

pub struct ColumnDef {
    pub key: &'static str,
    pub label: &'static str,
    pub width: f32,
}

const COLUMNS: &[ColumnDef] = &[
    ColumnDef {
        key: "engine",
        label: "引擎",
        width: COL_ENGINE,
    },
    ColumnDef {
        key: "host",
        label: "Host",
        width: COL_HOST,
    },
    ColumnDef {
        key: "ip",
        label: "IP",
        width: COL_IP,
    },
    ColumnDef {
        key: "port",
        label: "端口",
        width: COL_PORT,
    },
    ColumnDef {
        key: "protocol",
        label: "协议",
        width: COL_PROTO,
    },
    ColumnDef {
        key: "title",
        label: "标题",
        width: 0.,
    },
    ColumnDef {
        key: "component",
        label: "组件",
        width: COL_COMP,
    },
    ColumnDef {
        key: "org",
        label: "组织",
        width: COL_ORG,
    },
    ColumnDef {
        key: "location",
        label: "位置",
        width: COL_LOC,
    },
    ColumnDef {
        key: "time",
        label: "更新时间",
        width: COL_TIME,
    },
];

const SETTINGS_TABS: [&str; 5] = ["账户凭证", "搜索", "显示", "外观", "MCP 接入"];

/// 外观页主题卡片：（显示名，config.theme 值，配色）。
const THEME_PRESETS: [(&str, &str, Theme); 2] = [
    ("深色", "dark", Theme::DARK),
    ("浅色", "light", Theme::LIGHT),
];

/// 窄窗口阈值：低于该宽度收纳次要 UI（副标题、按钮文字）。
const NARROW_WIDTH: f32 = 900.;

/// 通知气泡类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Error,
    Ok,
    Info,
}

/// 右下角通知气泡：错误等即时弹出，数秒后自动消失。
pub struct Toast {
    id: u64,
    kind: ToastKind,
    message: String,
}

/// 小工具 favicon 计算状态机。
#[derive(Debug, Clone)]
enum ToolFaviconState {
    Idle,
    Loading,
    Done { icon_url: String, hash: i32 },
    Failed(String),
}

pub struct OctoxApp {
    pub query_input: Entity<TextInput>,
    engine_dropdown: Entity<EngineDropdown>,
    fofa_email: Entity<TextInput>,
    fofa_key: Entity<TextInput>,
    hunter_key: Entity<TextInput>,
    quake_token: Entity<TextInput>,
    shodan_key: Entity<TextInput>,
    zoomeye_key: Entity<TextInput>,
    threatbook_key: Entity<TextInput>,
    zone0_key: Entity<TextInput>,
    daydaymap_key: Entity<TextInput>,
    vt_key: Entity<TextInput>,
    censys_id: Entity<TextInput>,
    censys_secret: Entity<TextInput>,
    pagesize_input: Entity<TextInput>,
    maxpages_input: Entity<TextInput>,
    delay_input: Entity<TextInput>,
    timeout_input: Entity<TextInput>,
    proxy_input: Entity<TextInput>,
    fav_query_input: Entity<TextInput>,
    fav_tags_input: Entity<TextInput>,
    fav_note_input: Entity<TextInput>,
    tool_url_input: Entity<TextInput>,
    config: Config,
    results: Vec<Asset>,
    selected: Option<usize>,
    totals: [Option<u64>; Engine::COUNT],
    errors: [Option<String>; Engine::COUNT],
    quotas: [Option<String>; Engine::COUNT],
    pending: usize,
    loading: bool,
    page: u32,
    active_size: u32,
    last_query: String,
    page_cache: PageCache,
    next_pages: [bool; Engine::COUNT],
    cancelled: Arc<AtomicBool>,
    extra_labels: Vec<String>,
    show_search_details: bool,
    detail_expanded: bool,
    search_gen: u64,
    show_settings: bool,
    settings_tab: usize,
    show_rules: bool,
    show_favorites: bool,
    /// 收藏夹管理器的标签过滤（None = 全部）。
    favorites_filter: Option<String>,
    show_fav_dialog: bool,
    /// 收藏对话框正在编辑的语句（None = 新增）。
    fav_dialog_existing: Option<String>,
    /// 小工具弹层开关与 favicon 计算状态（tool_gen 丢弃过期结果）。
    show_tools: bool,
    tool_favicon_state: ToolFaviconState,
    tool_gen: u64,
    suggestions: Vec<Completion>,
    suggest_active: Option<usize>,
    status: String,
    /// 当前窗口尺寸（每帧刷新），用于响应式布局与弹窗定位。
    viewport_width: f32,
    viewport_height: f32,
    toasts: Vec<Toast>,
    toast_seq: u64,
    /// 右键上下文菜单：（行索引，弹出位置）。
    context_menu: Option<(usize, gpui::Point<gpui::Pixels>)>,
    /// 表格多选行（Ctrl/Cmd+点击切换，Shift+点击范围选择）。
    multi_selected: std::collections::BTreeSet<usize>,
    /// 多选锚点行（Shift 范围选择起点）。
    row_anchor: Option<usize>,
    /// 右侧滑入的引擎配置抽屉（当前配置的引擎；None = 关闭）。
    show_engine_drawer: Option<Engine>,
    /// MCP TCP 服务运行标记（None = 未运行）。
    mcp_shutdown: Option<Arc<AtomicBool>>,
    #[allow(dead_code)]
    mcp_handle: Option<JoinHandle<()>>,
}

impl OctoxApp {
    pub fn new(cx: &mut Context<Self>) -> Self {
        let config = Config::load();
        let query_input = cx.new(|cx| {
            TextInput::new(
                "输入查询语句，如 ip=\"1.2.3.4\" && port=80；聚合模式仅支持公共语法…",
                cx,
            )
            .plain()
        });
        let mk = |placeholder: &str, value: &str, cx: &mut Context<Self>| {
            cx.new(|cx| {
                let mut input = TextInput::new(placeholder, cx);
                input.set_text(value, cx);
                input
            })
        };
        let fofa_email = mk("email", &config.fofa.email, cx);
        let fofa_key = mk("key", &config.fofa.key, cx);
        let hunter_key = mk("api-key", &config.hunter.api_key, cx);
        let quake_token = mk("X-QuakeToken", &config.quake.token, cx);
        let shodan_key = mk("api-key", &config.shodan.api_key, cx);
        let zoomeye_key = mk("API-KEY", &config.zoomeye.api_key, cx);
        let threatbook_key = mk("apikey", &config.threatbook.api_key, cx);
        let zone0_key = mk("key", &config.zone0.api_key, cx);
        let daydaymap_key = mk("api-key", &config.daydaymap.api_key, cx);
        let vt_key = mk("x-apikey", &config.virustotal.api_key, cx);
        let censys_id = mk("api-id", &config.censys.api_id, cx);
        let censys_secret = mk("api-secret", &config.censys.api_secret, cx);
        let pagesize_input = mk("100", &config.page_size.to_string(), cx);
        let maxpages_input = mk("5", &config.max_pages.to_string(), cx);
        let delay_input = mk("0", &config.request_delay_secs.to_string(), cx);
        let timeout_input = mk("30", &config.request_timeout_secs.to_string(), cx);
        let proxy_input = mk("http://127.0.0.1:7890", &config.proxy_url, cx);
        let fav_query_input = mk("查询语句", "", cx);
        let fav_tags_input = mk("标签，逗号分隔，如: 后台,邮件", "", cx);
        let fav_note_input = mk("一句话描述用途（可空）", "", cx);
        let tool_url_input = cx.new(|cx| {
            TextInput::new(
                "站点 URL 或 host，如 https://example.com 或 1.2.3.4:8080",
                cx,
            )
            .plain()
        });
        let engine_dropdown = cx.new(|_| EngineDropdown::new());

        cx.subscribe(
            &query_input,
            |this, _emitter, event: &InputEvent, cx| match event {
                InputEvent::Submitted => this.on_query_submitted(cx),
                InputEvent::Changed => this.update_suggestions(cx),
            },
        )
        .detach();
        // 搜索参数：回车应用并保存（数值越界或非法时弹通知）。
        cx.subscribe(&pagesize_input, |this, _, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Submitted) {
                let text = this.pagesize_input.read(cx).text().to_string();
                this.apply_numeric(
                    &text,
                    1,
                    100,
                    "每页条数",
                    |s, v| {
                        s.config.page_size = v as u32;
                    },
                    cx,
                );
            }
        })
        .detach();
        cx.subscribe(&maxpages_input, |this, _, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Submitted) {
                let text = this.maxpages_input.read(cx).text().to_string();
                this.apply_numeric(
                    &text,
                    1,
                    1000,
                    "最大翻页数",
                    |s, v| {
                        s.config.max_pages = v as u32;
                    },
                    cx,
                );
            }
        })
        .detach();
        cx.subscribe(&delay_input, |this, _, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Submitted) {
                let text = this.delay_input.read(cx).text().to_string();
                this.apply_numeric(
                    &text,
                    0,
                    60,
                    "请求间隔",
                    |s, v| {
                        s.config.request_delay_secs = v;
                    },
                    cx,
                );
            }
        })
        .detach();
        cx.subscribe(&timeout_input, |this, _, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Submitted) {
                let text = this.timeout_input.read(cx).text().to_string();
                this.apply_numeric(
                    &text,
                    5,
                    300,
                    "请求超时",
                    |s, v| {
                        s.config.request_timeout_secs = v;
                    },
                    cx,
                );
            }
        })
        .detach();
        cx.subscribe(&proxy_input, |this, _, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Submitted) {
                this.apply_proxy(this.proxy_input.read(cx).text().to_string(), cx);
            }
        })
        .detach();
        // 小工具：回车直接计算 favicon hash。
        cx.subscribe(&tool_url_input, |this, _, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Submitted) {
                this.compute_favicon(cx);
            }
        })
        .detach();
        cx.subscribe(
            &engine_dropdown,
            |this, _emitter, event: &DropdownEvent, cx| {
                match event {
                    // 模式切换（单引擎 ↔ 聚合）时补全字典与规则弹层随之刷新。
                    DropdownEvent::Changed => {
                        this.cancel_search(cx);
                        this.page = 1;
                        this.page_cache.clear();
                        this.next_pages = [false; Engine::COUNT];
                        this.update_suggestions(cx);
                    }
                }
            },
        )
        .detach();

        let mut app = Self {
            query_input,
            engine_dropdown,
            fofa_email,
            fofa_key,
            hunter_key,
            quake_token,
            shodan_key,
            zoomeye_key,
            threatbook_key,
            zone0_key,
            daydaymap_key,
            vt_key,
            censys_id,
            censys_secret,
            pagesize_input,
            maxpages_input,
            delay_input,
            timeout_input,
            proxy_input,
            fav_query_input,
            fav_tags_input,
            fav_note_input,
            tool_url_input,
            config,
            results: Vec::new(),
            selected: None,
            totals: [None; Engine::COUNT],
            errors: [const { None }; Engine::COUNT],
            quotas: [const { None }; Engine::COUNT],
            pending: 0,
            loading: false,
            page: 1,
            active_size: 20,
            last_query: String::new(),
            page_cache: PageCache::default(),
            next_pages: [false; Engine::COUNT],
            cancelled: Arc::new(AtomicBool::new(false)),
            extra_labels: Vec::new(),
            show_search_details: false,
            detail_expanded: false,
            search_gen: 0,
            show_settings: false,
            settings_tab: 0,
            show_rules: false,
            show_favorites: false,
            favorites_filter: None,
            show_fav_dialog: false,
            fav_dialog_existing: None,
            show_tools: false,
            tool_favicon_state: ToolFaviconState::Idle,
            tool_gen: 0,
            suggestions: Vec::new(),
            suggest_active: None,
            status: "就绪 — 首次使用请先点击右上角 ⚙ 设置引擎凭证".into(),
            viewport_width: 1280.,
            viewport_height: 800.,
            toasts: Vec::new(),
            toast_seq: 0,
            context_menu: None,
            multi_selected: std::collections::BTreeSet::new(),
            row_anchor: None,
            show_engine_drawer: None,
            mcp_shutdown: None,
            mcp_handle: None,
        };
        // 上次会话开启了 MCP TCP 服务则自动恢复。
        if app.config.mcp_enabled && app.start_mcp_server().is_ok() {
            app.status = format!(
                "就绪 — MCP 服务已开启：127.0.0.1:{}（TCP）",
                app.config.mcp_port
            );
        }
        app
    }

    /// 演示模式（--demo）：注入示例资产，用于截图与无凭证体验。
    pub fn with_demo(mut self, demo: bool) -> Self {
        if !demo {
            return self;
        }
        let mk = |engine: Engine,
                  host: &str,
                  ip: &str,
                  port: &str,
                  protocol: &str,
                  title: &str,
                  component: &str,
                  org: &str,
                  country: &str,
                  city: &str,
                  status: &str,
                  time: &str,
                  url: &str,
                  extras: Vec<(&str, &str)>| Asset {
            engine,
            host: host.into(),
            ip: ip.into(),
            port: port.into(),
            protocol: protocol.into(),
            title: title.into(),
            domain: "-".into(),
            component: component.into(),
            org: org.into(),
            country: country.into(),
            city: city.into(),
            status_code: status.into(),
            updated_at: time.into(),
            url: url.into(),
            extras: extras
                .into_iter()
                .map(|(l, v)| (l.to_string(), v.to_string()))
                .collect(),
        };
        let _ = self.config.page_size;
        self.results = vec![
            mk(
                Engine::Fofa,
                "www.example-portal.cn",
                "203.0.113.10",
                "443",
                "https",
                "运维管理平台",
                "Nginx",
                "浙江云帆网络科技有限公司",
                "中国",
                "杭州",
                "200",
                "2026-10-31 13:00:00",
                "https://www.example-portal.cn",
                vec![("域名", "example-portal.cn")],
            ),
            mk(
                Engine::Fofa,
                "mail.corp-demo.cn",
                "203.0.113.21",
                "80",
                "http",
                "企业邮箱登录",
                "Tengine",
                "北京华信科技有限公司",
                "中国",
                "北京",
                "200",
                "2026-10-31 13:00:00",
                "http://mail.corp-demo.cn",
                vec![("域名", "corp-demo.cn")],
            ),
            mk(
                Engine::Hunter,
                "vpn.demo-corp.com",
                "198.51.100.35",
                "443",
                "https",
                "SSL VPN 门户",
                "深信服 VPN",
                "-",
                "-",
                "-",
                "200",
                "2026-10-31 12:40:00",
                "https://vpn.demo-corp.com",
                vec![
                    ("域名", "demo-corp.com"),
                    ("省份", "广东"),
                    ("城市", "深圳"),
                    ("运营商", "电信"),
                ],
            ),
            mk(
                Engine::Hunter,
                "gitlab.demo-corp.com",
                "198.51.100.36",
                "8443",
                "https",
                "GitLab",
                "GitLab 16.5",
                "-",
                "-",
                "-",
                "302",
                "2026-10-31 12:40:00",
                "https://gitlab.demo-corp.com:8443",
                vec![
                    ("域名", "demo-corp.com"),
                    ("省份", "广东"),
                    ("运营商", "电信"),
                ],
            ),
            mk(
                Engine::Quake,
                "api.demo-cloud.cn",
                "203.0.113.52",
                "8080",
                "http",
                "API 网关",
                "Kong",
                "上海云启信息技术有限公司",
                "中国",
                "上海",
                "200",
                "2026-10-30 21:10:00",
                "http://api.demo-cloud.cn:8080",
                vec![("省份", "上海"), ("运营商", "联通")],
            ),
            mk(
                Engine::Quake,
                "oa.demo-cloud.cn",
                "203.0.113.53",
                "80",
                "http",
                "协同办公系统",
                "Apache",
                "上海云启信息技术有限公司",
                "中国",
                "上海",
                "200",
                "2026-10-30 21:10:00",
                "http://oa.demo-cloud.cn",
                vec![("运营商", "联通")],
            ),
            mk(
                Engine::Shodan,
                "ns1.demo-host.net",
                "192.0.2.10",
                "53",
                "udp",
                "-",
                "BIND",
                "Cloudflare, Inc.",
                "United States",
                "Ashburn",
                "-",
                "2026-10-29T09:00:00Z",
                "-",
                vec![("操作系统", "Linux"), ("ASN", "AS13335")],
            ),
            mk(
                Engine::Shodan,
                "203.0.113.77",
                "203.0.113.77",
                "22",
                "tcp",
                "-",
                "OpenSSH 8.9",
                "Akamai Technologies",
                "Japan",
                "Tokyo",
                "-",
                "2026-10-28T18:30:00Z",
                "-",
                vec![("ASN", "AS20940")],
            ),
            mk(
                Engine::Censys,
                "edge.demo-assets.io",
                "192.0.2.88",
                "443",
                "HTTPS",
                "Edge Console",
                "Envoy",
                "Amazon.com",
                "United States",
                "Seattle",
                "200",
                "2026-10-27",
                "https://edge.demo-assets.io",
                vec![("主机名", "edge.demo-assets.io"), ("ASN", "16509")],
            ),
            mk(
                Engine::DayDayMap,
                "static.demo-cdn.cn",
                "203.0.113.90",
                "443",
                "https",
                "静态资源中心",
                "Caddy",
                "-",
                "中国",
                "广州",
                "200",
                "2026-10-26 08:00:00",
                "https://static.demo-cdn.cn",
                vec![("域名", "demo-cdn.cn")],
            ),
            mk(
                Engine::Fofa,
                "portal.demo-edu.cn",
                "203.0.113.101",
                "443",
                "https",
                "教务管理系统",
                "Tomcat",
                "江苏示范数据中心",
                "中国",
                "南京",
                "200",
                "2026-10-31 11:00:00",
                "https://portal.demo-edu.cn",
                vec![("域名", "demo-edu.cn")],
            ),
            mk(
                Engine::Fofa,
                "sso.demo-bank.cn",
                "203.0.113.102",
                "443",
                "https",
                "统一身份认证",
                "WebLogic",
                "华银信息科技股份有限公司",
                "中国",
                "成都",
                "200",
                "2026-10-31 10:30:00",
                "https://sso.demo-bank.cn",
                vec![("域名", "demo-bank.cn")],
            ),
            mk(
                Engine::Hunter,
                "nacos.demo-corp.com",
                "198.51.100.41",
                "8848",
                "http",
                "Nacos 控制台",
                "Nacos 2.2",
                "-",
                "-",
                "-",
                "200",
                "2026-10-31 12:40:00",
                "http://nacos.demo-corp.com:8848",
                vec![("省份", "广东"), ("运营商", "电信")],
            ),
            mk(
                Engine::Quake,
                "kibana.demo-cloud.cn",
                "203.0.113.54",
                "5601",
                "http",
                "Kibana",
                "Elasticsearch",
                "上海云启信息技术有限公司",
                "中国",
                "上海",
                "200",
                "2026-10-30 21:10:00",
                "http://kibana.demo-cloud.cn:5601",
                vec![("省份", "上海")],
            ),
            mk(
                Engine::Shodan,
                "203.0.113.120",
                "203.0.113.120",
                "3389",
                "tcp",
                "-",
                "Microsoft Terminal Services",
                "Microsoft Corporation",
                "United States",
                "Redmond",
                "-",
                "2026-10-27T12:00:00Z",
                "-",
                vec![("操作系统", "Windows Server 2019")],
            ),
            mk(
                Engine::Censys,
                "api.demo-metrics.io",
                "192.0.2.93",
                "9090",
                "HTTP",
                "Prometheus Metrics",
                "Prometheus",
                "DigitalOcean, LLC",
                "United States",
                "New York",
                "200",
                "2026-10-25",
                "http://api.demo-metrics.io:9090",
                vec![("ASN", "14061")],
            ),
            mk(
                Engine::DayDayMap,
                "img.demo-cdn.cn",
                "203.0.113.91",
                "443",
                "https",
                "图片服务",
                "OpenResty",
                "-",
                "中国",
                "广州",
                "200",
                "2026-10-24 20:00:00",
                "https://img.demo-cdn.cn",
                vec![("域名", "demo-cdn.cn")],
            ),
            mk(
                Engine::Fofa,
                "vpn.demo-edu.cn",
                "203.0.113.103",
                "8888",
                "https",
                "EasyConnect",
                "EasyConnect",
                "江苏示范数据中心",
                "中国",
                "南京",
                "200",
                "2026-10-31 11:00:00",
                "https://vpn.demo-edu.cn:8888",
                vec![("域名", "demo-edu.cn")],
            ),
            mk(
                Engine::Hunter,
                "jenkins.demo-corp.com",
                "198.51.100.42",
                "8080",
                "http",
                "Jenkins CI",
                "Jenkins 2.4",
                "-",
                "-",
                "-",
                "403",
                "2026-10-31 12:40:00",
                "http://jenkins.demo-corp.com:8080",
                vec![("省份", "广东"), ("运营商", "电信")],
            ),
        ];
        self.extra_labels = self.collect_extra_columns();
        self.selected = Some(0);
        self.status = "演示模式 — 示例数据仅用于展示（--demo）".into();
        self
    }

    // ---------- 搜索编排 ----------

    fn query(&self, cx: &Context<Self>) -> String {
        self.query_input.read(cx).text().trim().to_string()
    }

    fn on_query_submitted(&mut self, cx: &mut Context<Self>) {
        if self.suggest_active.is_some() {
            self.accept_suggestion(cx);
        } else {
            self.fresh_search(cx);
        }
    }

    fn cancel_search(&mut self, cx: &mut Context<Self>) {
        self.cancelled.store(true, Ordering::Relaxed);
        self.search_gen += 1;
        self.pending = 0;
        self.loading = false;
        self.status = "已停止等待；已发送的请求可能仍由平台处理".into();
        cx.notify();
    }

    fn persist_config(&mut self, cx: &mut Context<Self>) {
        if let Err(e) = self.config.save() {
            self.push_toast(ToastKind::Error, format!("设置未能保存：{e}"), cx);
        }
    }

    fn fresh_search(&mut self, cx: &mut Context<Self>) {
        self.page_cache.clear();
        self.start_search(cx);
    }

    fn change_page(&mut self, page: u32, cx: &mut Context<Self>) {
        if self.query(cx) != self.last_query {
            self.fresh_search(cx);
        } else {
            self.page = page;
            self.start_search(cx);
        }
    }

    fn start_search(&mut self, cx: &mut Context<Self>) {
        self.suggestions.clear();
        self.suggest_active = None;
        self.context_menu = None;
        let query = self.query(cx);
        let single = match self.engine_dropdown.read(cx).mode() {
            SearchMode::Single(e) => Some(e),
            SearchMode::Aggregate => None,
        };
        // 先验证输入，不清除上一轮可用结果。
        let plan = match SearchPlan::prepare(&self.config, &query, single) {
            Ok(plan) => plan,
            Err(e) => {
                self.status = e;
                cx.notify();
                return;
            }
        };
        let key = SearchPlan::cache_key(&self.config, &query, single);
        if self.page_cache.reset_if_changed(key) {
            self.page = 1;
        }
        self.cancel_search(cx);
        self.cancelled = Arc::new(AtomicBool::new(false));
        self.last_query = query;
        self.page = self.page.clamp(1, self.config.max_pages.max(1));
        let generation = self.search_gen;
        self.results.clear();
        self.extra_labels.clear();
        self.selected = None;
        self.multi_selected.clear();
        self.row_anchor = None;
        self.totals = [None; Engine::COUNT];
        self.errors = [const { None }; Engine::COUNT];
        self.quotas = [const { None }; Engine::COUNT];
        self.next_pages = [false; Engine::COUNT];
        let page = self.page;
        let size = self.config.page_size.clamp(1, 100);
        self.active_size = size;
        let mut seq = 0;
        for (engine, query) in plan.queries {
            let idx = engine.index();
            let engine_query = match query {
                Ok(q) => q,
                Err(e) => {
                    self.errors[idx] = Some(e);
                    continue;
                }
            };
            if let Some(cached) = self.page_cache.get(engine, page).cloned() {
                self.on_engine_result(engine, Ok(cached), cx);
                continue;
            }
            let previous = self.page_cache.get(engine, page.saturating_sub(1));
            if let Some(previous) = previous {
                if !search::has_more(engine, previous, page - 1, size) {
                    self.totals[idx] = Some(previous.total);
                    self.quotas[idx] = previous.quota.clone();
                    // 记录耗尽页，后面的聚合页也不再请求此引擎。
                    self.page_cache.insert(
                        engine,
                        page,
                        SearchResult {
                            total: previous.total,
                            assets: Vec::new(),
                            quota: previous.quota.clone(),
                            next_cursor: None,
                        },
                    );
                    continue;
                }
            }
            let cursor = previous.and_then(|r| r.next_cursor.clone());
            self.pending += 1;
            let stagger = self.config.request_delay_secs.min(60) * seq;
            seq += 1;
            let cfg = self.config.clone();
            let cancelled = self.cancelled.clone();
            cx.spawn(async move |this, cx| {
                if stagger > 0 {
                    cx.background_executor()
                        .timer(Duration::from_secs(stagger))
                        .await;
                }
                if cancelled.load(Ordering::Relaxed) {
                    return;
                }
                let result = cx
                    .background_executor()
                    .spawn(async move {
                        if cancelled.load(Ordering::Relaxed) {
                            return None;
                        }
                        Some(engine.search_page(&cfg, &engine_query, page, size, cursor.as_deref()))
                    })
                    .await;
                let Some(result) = result else {
                    return;
                };
                let _ = this.update(cx, move |app, cx| {
                    if app.search_gen != generation {
                        return;
                    }
                    app.pending = app.pending.saturating_sub(1);
                    app.on_engine_result(engine, result, cx);
                    if app.pending == 0 {
                        app.loading = false;
                        app.finalize_status();
                    }
                    cx.notify();
                });
            })
            .detach();
        }
        self.loading = self.pending > 0;
        if self.loading {
            self.status = format!("查询中…第 {page} 页 · {} 个引擎等待完成", self.pending);
        } else {
            self.finalize_status();
        }
        cx.notify();
    }

    fn on_engine_result(
        &mut self,
        engine: Engine,
        result: engines::Result<SearchResult>,
        cx: &mut Context<Self>,
    ) {
        let idx = Engine::ALL.iter().position(|e| *e == engine).unwrap_or(0);
        match result {
            Ok(sr) => {
                self.next_pages[idx] = search::has_more(engine, &sr, self.page, self.active_size);
                self.page_cache.insert(engine, self.page, sr.clone());
                self.totals[idx] = Some(sr.total);
                self.quotas[idx] = sr.quota;
                self.results.extend(sr.assets);
                self.extra_labels = self.collect_extra_columns();
            }
            Err(e) => {
                self.errors[idx] = Some(e.to_string());
                self.push_toast(
                    ToastKind::Error,
                    format!("{} 查询失败：{e}", engine.name()),
                    cx,
                );
            }
        }
    }

    fn finalize_status(&mut self) {
        let parts: Vec<String> = Engine::ALL
            .iter()
            .enumerate()
            .filter(|(i, _)| self.totals[*i].is_some() || self.errors[*i].is_some())
            .map(|(i, engine)| match (&self.errors[i], &self.totals[i]) {
                (Some(e), _) => format!("{} ✗ {e}", engine.name()),
                (None, Some(t)) => format!("{} {} 条", engine.name(), t),
                (None, None) => format!("{} —", engine.name()),
            })
            .collect();
        self.show_search_details = self.errors.iter().any(Option::is_some);
        self.status = if parts.is_empty() {
            "就绪".into()
        } else {
            parts.join("   ·   ")
        };
    }

    // ---------- 自动补全 ----------

    fn update_suggestions(&mut self, cx: &mut Context<Self>) {
        let text = self.query_input.read(cx).text().to_string();
        let common_only = self.engine_dropdown.read(cx).is_aggregate();
        self.suggestions = autocomplete::completions(&text, common_only);
        self.suggest_active = if self.suggestions.is_empty() {
            None
        } else {
            Some(0)
        };
        cx.notify();
    }

    fn accept_suggestion(&mut self, cx: &mut Context<Self>) {
        let Some(idx) = self.suggest_active else {
            return;
        };
        let Some(insert) = self.suggestions.get(idx).map(|c| c.insert.clone()) else {
            return;
        };
        let text = self.query_input.read(cx).text().to_string();
        let next = autocomplete::apply(&text, &insert);
        self.query_input
            .update(cx, |input, cx| input.set_text(&next, cx));
        cx.notify();
    }

    fn on_suggest_next(&mut self, _: &SuggestNext, _: &mut Window, cx: &mut Context<Self>) {
        if self.suggestions.is_empty() {
            return;
        }
        let active = self
            .suggest_active
            .map(|i| (i + 1) % self.suggestions.len())
            .unwrap_or(0);
        self.suggest_active = Some(active);
        cx.notify();
    }

    fn on_suggest_prev(&mut self, _: &SuggestPrev, _: &mut Window, cx: &mut Context<Self>) {
        if self.suggestions.is_empty() {
            return;
        }
        let len = self.suggestions.len();
        let active = self
            .suggest_active
            .map(|i| (i + len - 1) % len)
            .unwrap_or(0);
        self.suggest_active = Some(active);
        cx.notify();
    }

    fn on_suggest_accept(&mut self, _: &SuggestAccept, _: &mut Window, cx: &mut Context<Self>) {
        self.accept_suggestion(cx);
    }

    // ---------- 列显示 / 外观 / 分页设置 ----------

    fn column_visible(&self, key: &str) -> bool {
        self.config.columns.iter().any(|k| k == key)
    }

    /// 按配置顺序返回可见列；窄窗口下次要列自动收起（宽度恢复后自动回来，
    /// 设置开关不受影响）。
    fn visible_columns(&self) -> impl Iterator<Item = &'static ColumnDef> {
        COLUMNS
            .iter()
            .filter(|c| self.column_visible(c.key) && !self.auto_hidden(c.key))
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// 响应式收列：按窗口宽度逐档收起低优先级列（阈值 ≈ 累计列宽）。
    fn auto_hidden(&self, key: &str) -> bool {
        let w = self.viewport_width;
        match key {
            "time" => w < 1150.,
            "location" => w < 1040.,
            "org" => w < 950.,
            "component" => w < 850.,
            "protocol" => w < 760.,
            "ip" => w < 660.,
            _ => false,
        }
    }

    fn narrow(&self) -> bool {
        self.viewport_width < NARROW_WIDTH
    }

    /// 标题列为弹性列：宽度 = 窗口宽 - 其余可见列宽 - 行内边距，最窄 160。
    /// 定宽后单元格可做像素级预截断，杜绝文字越界。
    fn title_width(&self) -> f32 {
        let extras = self.extra_columns().len() as f32 * EXTRA_COL_WIDTH;
        let others: f32 = self
            .visible_columns()
            .filter(|c| c.width != 0.)
            .map(|c| c.width)
            .sum::<f32>()
            + extras;
        (self.viewport_width - 16. - others).max(160.)
    }

    /// 引擎特有列：结果集全部来自同一引擎时，取各行扩展字段的并集
    /// （保序、最多 4 列）；聚合结果不追加，窄窗口自动收起。
    fn extra_columns(&self) -> Vec<String> {
        if self.narrow() {
            Vec::new()
        } else {
            self.extra_labels.clone()
        }
    }

    fn collect_extra_columns(&self) -> Vec<String> {
        if self.results.is_empty() {
            return Vec::new();
        }
        let first = self.results[0].engine;
        if !self.results.iter().all(|a| a.engine == first) {
            return Vec::new();
        }
        let mut labels: Vec<String> = Vec::new();
        for asset in &self.results {
            for (label, _) in &asset.extras {
                if !labels.contains(label) && labels.len() < 4 {
                    labels.push(label.clone());
                }
            }
        }
        labels
    }

    /// 数值设置：回车应用，越界/非法弹通知；应用后立即保存。
    fn apply_numeric(
        &mut self,
        text: &str,
        min: u64,
        max: u64,
        label: &str,
        apply: impl FnOnce(&mut Self, u64),
        cx: &mut Context<Self>,
    ) {
        match text.trim().parse::<u64>() {
            Ok(v) if (min..=max).contains(&v) => {
                apply(self, v);
                self.persist_config(cx);
                self.status = format!("{label} 已应用：{v}");
            }
            _ => self.push_toast(
                ToastKind::Error,
                format!("{label} 需为 {min}–{max} 之间的数字"),
                cx,
            ),
        }
        cx.notify();
    }

    /// 代理设置：启用且地址非空时走代理（ureq Proxy）。
    fn apply_proxy(&mut self, url: String, cx: &mut Context<Self>) {
        let url = url.trim().to_string();
        if self.config.proxy_enabled && url.is_empty() {
            self.push_toast(ToastKind::Error, "代理地址不能为空".into(), cx);
        } else {
            self.config.proxy_url = url.clone();
            self.persist_config(cx);
            self.status = if url.is_empty() {
                "代理地址已清空（仍为关闭状态）".into()
            } else {
                format!("代理地址已应用：{url}")
            };
        }
        cx.notify();
    }

    fn toggle_proxy(&mut self, cx: &mut Context<Self>) {
        self.config.proxy_enabled = !self.config.proxy_enabled;
        if self.config.proxy_enabled && self.config.proxy_url.trim().is_empty() {
            self.push_toast(
                ToastKind::Error,
                "请先填写代理地址（如 http://127.0.0.1:7890）".into(),
                cx,
            );
            self.config.proxy_enabled = false;
        } else {
            let state = if self.config.proxy_enabled {
                "已开启"
            } else {
                "已关闭"
            };
            self.status = format!("代理{state}");
            self.persist_config(cx);
        }
        cx.notify();
    }

    fn toggle_column(&mut self, key: &'static str, cx: &mut Context<Self>) {
        if let Some(pos) = self.config.columns.iter().position(|k| k == key) {
            self.config.columns.remove(pos);
        } else {
            self.config.columns.push(key.to_string());
        }
        self.persist_config(cx);
        cx.notify();
    }

    fn show_all_columns(&mut self, cx: &mut Context<Self>) {
        self.config.columns = COLUMNS.iter().map(|c| c.key.to_string()).collect();
        self.persist_config(cx);
        cx.notify();
    }

    fn set_theme(&mut self, key: &'static str, palette: Theme, cx: &mut Context<Self>) {
        crate::ui::set_active_theme(palette);
        self.config.theme = key.to_string();
        self.persist_config(cx);
        cx.notify();
    }

    // ---------- MCP 服务 ----------

    fn mcp_running(&self) -> bool {
        self.mcp_shutdown.is_some()
    }

    fn start_mcp_server(&mut self) -> Result<(), String> {
        let (_port, shutdown, handle) =
            mcp::start_tcp_server(self.config.mcp_port).map_err(|e| e.to_string())?;
        self.mcp_shutdown = Some(shutdown);
        self.mcp_handle = Some(handle);
        Ok(())
    }

    /// 菜单栏 / 设置页共用的开关：开启 TCP 服务并持久化，关闭时停止线程。
    fn toggle_mcp(&mut self, cx: &mut Context<Self>) {
        if self.mcp_running() {
            if let Some(flag) = &self.mcp_shutdown {
                flag.store(true, Ordering::Relaxed);
            }
            self.mcp_shutdown = None;
            self.mcp_handle = None;
            self.config.mcp_enabled = false;
            self.persist_config(cx);
            self.status = "MCP 服务已关闭".into();
        } else {
            match self.start_mcp_server() {
                Ok(()) => {
                    self.config.mcp_enabled = true;
                    self.persist_config(cx);
                    self.status =
                        format!("MCP 服务已开启 — 127.0.0.1:{}（TCP）", self.config.mcp_port);
                    self.push_toast(
                        ToastKind::Info,
                        format!("MCP 服务已开启：127.0.0.1:{}（TCP）", self.config.mcp_port),
                        cx,
                    );
                }
                Err(e) => {
                    self.push_toast(
                        ToastKind::Error,
                        format!("MCP 服务启动失败（端口 {}）：{e}", self.config.mcp_port),
                        cx,
                    );
                }
            }
        }
        cx.notify();
    }

    // ---------- 右键上下文菜单 ----------

    fn open_context_menu(
        &mut self,
        row: usize,
        position: gpui::Point<gpui::Pixels>,
        cx: &mut Context<Self>,
    ) {
        self.context_menu = Some((row, position));
        cx.notify();
    }

    fn close_context_menu(&mut self, cx: &mut Context<Self>) {
        if self.context_menu.take().is_some() {
            cx.notify();
        }
    }

    /// 右键菜单：复制行数据 / 复制 URL / 浏览器打开。
    fn render_context_menu(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let Some((row, position)) = self.context_menu else {
            return div().into_any_element();
        };
        let Some(asset) = self.results.get(row) else {
            self.context_menu = None;
            return div().into_any_element();
        };
        // 定位在窗口右下象限时向内收，避免溢出窗口。
        let x = f32::from(position.x).min((self.viewport_width - 200.).max(0.));
        let y = f32::from(position.y).min((self.viewport_height - 150.).max(0.));
        let location = format!("{} {}", asset.country, asset.city);

        let json_text = serde_json::to_string_pretty(asset).unwrap_or_default();
        let tsv_text = [
            asset.engine.name().to_string(),
            asset.host.clone(),
            asset.ip.clone(),
            asset.port.clone(),
            asset.protocol.clone(),
            asset.title.clone(),
            asset.component.clone(),
            asset.org.clone(),
            location,
            asset.updated_at.clone(),
            asset.url.clone(),
        ]
        .join("\t");
        let url = asset.url.clone();
        let url_open = asset.url.clone();
        let url_usable = asset.url != "-" && !asset.url.trim().is_empty();
        let item = |id: String, label: &str, enabled: bool| {
            div()
                .id(SharedString::from(id))
                .px_2()
                .py_1()
                .text_size(px(12.))
                .text_color(rgb(if enabled { theme().text } else { theme().muted }))
                .when(enabled, |d| {
                    d.cursor_pointer().hover(|s| s.bg(rgb(theme().row_hover)))
                })
                .child(label.to_string())
        };
        let mut items: Vec<gpui::AnyElement> = Vec::new();

        // 多选操作（Ctrl/Cmd+点击或 Shift+点击选择后出现）。
        let multi_count = self.multi_selected.len();
        if multi_count > 1 {
            items.push(
                item(
                    "ctx-copy-multi-tsv".into(),
                    &format!("复制所选 {multi_count} 行（TSV，含表头）"),
                    true,
                )
                .on_click(cx.listener(|this, _, _, cx| {
                    this.copy_selected_rows(false, cx);
                    this.close_context_menu(cx);
                }))
                .into_any_element(),
            );
            items.push(
                item("ctx-copy-multi-json".into(), "复制所选（JSON）", true)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.copy_selected_rows(true, cx);
                        this.close_context_menu(cx);
                    }))
                    .into_any_element(),
            );
            items.push(
                item("ctx-clear-selection".into(), "清除选择", true)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.multi_selected.clear();
                        this.close_context_menu(cx);
                    }))
                    .into_any_element(),
            );
            items.push(
                div()
                    .mx_1()
                    .my_1()
                    .h(px(1.))
                    .bg(rgb(theme().border))
                    .into_any_element(),
            );
        }

        items.push(
            item("ctx-select-all".into(), "全选（当前结果）", true)
                .on_click(cx.listener(|this, _, _, cx| {
                    this.multi_selected = (0..this.results.len()).collect();
                    this.close_context_menu(cx);
                }))
                .into_any_element(),
        );
        items.push(
            item("ctx-copy-json".into(), "复制该行（JSON）", true)
                .on_click(cx.listener(move |this, _, _, cx| {
                    cx.write_to_clipboard(ClipboardItem::new_string(json_text.clone()));
                    this.close_context_menu(cx);
                }))
                .into_any_element(),
        );
        items.push(
            item("ctx-copy-tsv".into(), "复制该行（TSV）", true)
                .on_click(cx.listener(move |this, _, _, cx| {
                    cx.write_to_clipboard(ClipboardItem::new_string(tsv_text.clone()));
                    this.close_context_menu(cx);
                }))
                .into_any_element(),
        );
        // Host 头：优先从 URL 解析，URL 不可用时退回 Host 列。
        let host_header =
            tools::host_header(&asset.url).or_else(|| tools::host_header(&asset.host));
        if let Some(host) = host_header {
            items.push(
                item("ctx-copy-host".into(), "复制 Host 头", true)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        cx.write_to_clipboard(ClipboardItem::new_string(host.clone()));
                        this.close_context_menu(cx);
                    }))
                    .into_any_element(),
            );
        }
        if url_usable {
            items.push(
                item("ctx-copy-url".into(), "复制 URL", true)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        cx.write_to_clipboard(ClipboardItem::new_string(url.clone()));
                        this.close_context_menu(cx);
                    }))
                    .into_any_element(),
            );
            items.push(
                div()
                    .mx_1()
                    .my_1()
                    .h(px(1.))
                    .bg(rgb(theme().border))
                    .into_any_element(),
            );
            items.push(
                item("ctx-open-url".into(), "在浏览器打开 URL", true)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        cx.open_url(url_open.trim());
                        this.close_context_menu(cx);
                    }))
                    .into_any_element(),
            );
        }

        deferred(
            div()
                .id("ctx-menu")
                .absolute()
                .left(px(x))
                .top(px(y))
                .w(px(200.))
                .flex()
                .flex_col()
                .py_1()
                .rounded_md()
                .border_1()
                .border_color(rgb(theme().border))
                .bg(rgb(theme().panel))
                .shadow_lg()
                // 遮蔽下层命中；点击菜单外任意处关闭。
                .occlude()
                .on_mouse_down_out(cx.listener(|this, _: &MouseDownEvent, _, cx| {
                    this.close_context_menu(cx);
                }))
                .children(items),
        )
        .into_any_element()
    }

    // ---------- 表格多选 ----------

    /// 行点击：普通点击单选并清空多选；Ctrl/Cmd 切换；Shift 从锚点范围选择。
    fn on_row_clicked(&mut self, i: usize, ctrl: bool, shift: bool, cx: &mut Context<Self>) {
        self.selected = Some(i);
        if ctrl {
            if !self.multi_selected.remove(&i) {
                self.multi_selected.insert(i);
            }
        } else if shift {
            let anchor = self.row_anchor.unwrap_or(i);
            let (start, end) = if anchor <= i {
                (anchor, i)
            } else {
                (i, anchor)
            };
            for row in start..=end {
                self.multi_selected.insert(row);
            }
        } else {
            self.multi_selected.clear();
            self.multi_selected.insert(i);
        }
        self.row_anchor = Some(i);
        cx.notify();
    }

    /// 单行 TSV（多选复用同一格式）。
    fn row_tsv(asset: &Asset) -> String {
        [
            asset.engine.name().to_string(),
            asset.host.clone(),
            asset.ip.clone(),
            asset.port.clone(),
            asset.protocol.clone(),
            asset.title.clone(),
            asset.component.clone(),
            asset.org.clone(),
            format!("{} {}", asset.country, asset.city),
            asset.updated_at.clone(),
            asset.url.clone(),
        ]
        .join("	")
    }

    fn copy_selected_rows(&mut self, as_json: bool, cx: &mut Context<Self>) {
        let rows: Vec<&Asset> = self
            .multi_selected
            .iter()
            .filter_map(|i| self.results.get(*i))
            .collect();
        if rows.is_empty() {
            return;
        }
        let text = if as_json {
            serde_json::to_string_pretty(&rows).unwrap_or_default()
        } else {
            let mut out =
                String::from("引擎\tHost\tIP\t端口\t协议\t标题\t组件\t组织\t位置\t更新时间\tURL\n");
            for asset in &rows {
                out.push_str(&Self::row_tsv(asset));
                out.push('\n');
            }
            out
        };
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        self.status = format!("已复制 {} 行到剪贴板", rows.len());
        cx.notify();
    }

    // ---------- 引擎配置抽屉 ----------

    /// 打开引擎抽屉（同时关闭设置面板，避免共享凭证输入框被双重渲染）。
    fn open_engine_drawer(&mut self, engine: Option<Engine>, cx: &mut Context<Self>) {
        if engine.is_some() {
            self.show_settings = false;
        }
        self.show_engine_drawer = engine;
        cx.notify();
    }

    fn close_engine_drawer(&mut self, cx: &mut Context<Self>) {
        if self.show_engine_drawer.take().is_some() {
            cx.notify();
        }
    }

    /// 测试引擎连通性：发起一次 1 条结果的查询，结果以气泡反馈。
    fn test_engine_connection(&mut self, engine: Engine, cx: &mut Context<Self>) {
        if !self.config.creds_ready(engine) {
            self.push_toast(
                ToastKind::Error,
                format!("{} 尚未配置凭证", engine.name()),
                cx,
            );
            cx.notify();
            return;
        }
        // 各引擎的原生语法探活语句（1 条结果即可验证凭证）。
        let query = match engine {
            Engine::Fofa | Engine::Hunter => "ip=\"1.1.1.1\"".to_string(),
            Engine::Quake => "ip:\"1.1.1.1\"".to_string(),
            Engine::Shodan => "ip:1.1.1.1".to_string(),
            Engine::ZoomEye => "ip:1.1.1.1".to_string(),
            Engine::ThreatBook => "ip=\"1.1.1.1\"".to_string(),
            Engine::Zone0 => "domain===\"qq.com\"".to_string(),
            Engine::DayDayMap => "ip=\"1.1.1.1\"".to_string(),
            Engine::VirusTotal => "entity:ip_addresses ip:1.1.1.1".to_string(),
            Engine::Censys => "ip:1.1.1.1".to_string(),
        };
        let cfg = self.config.clone();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move { engine.search(&cfg, &query, 1, 1) })
                .await;
            let _ = this.update(cx, |this, cx| {
                match result {
                    Ok(sr) => {
                        let quota = sr
                            .quota
                            .as_ref()
                            .map(|q| format!("，余量 {q}"))
                            .unwrap_or_default();
                        this.status =
                            format!("{} 连接成功 — 共 {} 条{quota}", engine.name(), sr.total);
                        this.push_toast(ToastKind::Ok, format!("{} 连接成功", engine.name()), cx);
                    }
                    Err(e) => {
                        this.push_toast(
                            ToastKind::Error,
                            format!("{} 连接失败：{e}", engine.name()),
                            cx,
                        );
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// 右侧滑入的引擎配置抽屉：未覆盖区域罩渐变雾面遮罩，苹果风格。
    fn render_engine_drawer(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let Some(engine) = self.show_engine_drawer else {
            return div().into_any_element();
        };
        let accent = engine.accent();
        let name = engine.name();

        // 内容按模式装配：单引擎 = 凭证 + 参与聚合 + 测试连接。
        let mut body = div().flex().flex_col().gap_2().mt_2();
        // 各引擎的凭证输入（引擎抽屉与设置面板共享输入框实体）。
        let fields: Vec<(&'static str, Entity<TextInput>)> = match engine {
            Engine::Fofa => vec![
                ("FOFA email — fofa.info 个人中心", self.fofa_email.clone()),
                ("FOFA key", self.fofa_key.clone()),
            ],
            Engine::Hunter => vec![(
                "Hunter api-key — hunter.qianxin.com 个人中心",
                self.hunter_key.clone(),
            )],
            Engine::Quake => vec![(
                "Quake X-QuakeToken — quake.360.net 个人中心",
                self.quake_token.clone(),
            )],
            Engine::Shodan => vec![(
                "Shodan api-key — shodan.io/account",
                self.shodan_key.clone(),
            )],
            Engine::ZoomEye => vec![(
                "ZoomEye API-KEY — zoomeye.org 个人信息",
                self.zoomeye_key.clone(),
            )],
            Engine::ThreatBook => vec![(
                "ThreatBook apikey — x.threatbook.com",
                self.threatbook_key.clone(),
            )],
            Engine::Zone0 => vec![("0.zone key — 0.zone/apply", self.zone0_key.clone())],
            Engine::DayDayMap => vec![("DayDayMap api-key — 个人中心", self.daydaymap_key.clone())],
            Engine::VirusTotal => vec![(
                "VirusTotal x-apikey — virustotal.com（结构化搜索需 Intelligence 订阅）",
                self.vt_key.clone(),
            )],
            Engine::Censys => vec![
                (
                    "Censys api-id — search.censys.io/account",
                    self.censys_id.clone(),
                ),
                ("Censys api-secret", self.censys_secret.clone()),
            ],
        };
        for (label, input) in fields {
            body = body.child(field_label(label)).child(input);
        }
        // FOFA：全量历史数据（消耗 F 点）开关。
        if engine == Engine::Fofa {
            body = body.child(field_label("FOFA 数据范围")).child(
                select_chip(
                    if self.config.fofa_full {
                        "全量历史数据（消耗 F 点）"
                    } else {
                        "最近数据（免费）"
                    },
                    self.config.fofa_full,
                    theme().ok,
                )
                .id("fofa-full-toggle")
                .on_click(cx.listener(|this, _, _, cx| {
                    this.config.fofa_full = !this.config.fofa_full;
                    this.persist_config(cx);
                    this.status = if this.config.fofa_full {
                        "FOFA 已切换为全量历史数据（查询将消耗 F 点）".into()
                    } else {
                        "FOFA 已切换为最近数据（不消耗 F 点）".into()
                    };
                    cx.notify();
                })),
            );
        }

        // 扩展字段勾选：目录来自各引擎（空目录的引擎不显示本节）。
        let catalog = engines::extra_catalog(engine);
        if !catalog.is_empty() {
            let chips: Vec<gpui::AnyElement> = catalog
                .iter()
                .map(|spec| {
                    let on = self
                        .config
                        .extra_enabled(engine)
                        .map_or(true, |list| list.iter().any(|l| l == spec.label));
                    select_chip(spec.label, on, theme().accent)
                        .id(SharedString::from(format!(
                            "extra-{}-{}",
                            engine.name(),
                            spec.label
                        )))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            let names: Vec<String> = engines::extra_catalog(engine)
                                .iter()
                                .map(|spec| spec.label.to_string())
                                .collect();
                            this.config.toggle_extra_field(engine, spec.label, &names);
                            this.persist_config(cx);
                            cx.notify();
                        }))
                        .into_any_element()
                })
                .collect();
            body = body
                .child(field_label("扩展字段"))
                .child(div().flex().flex_wrap().gap_2().children(chips));
        }

        let agg_idx = Engine::ALL.iter().position(|e| *e == engine).unwrap_or(0);
        let agg_on = self.config.aggregate_engines[agg_idx];
        body = body
            .child(field_label("参与聚合引擎"))
            .child(
                select_chip(if agg_on { "已参与" } else { "未参与" }, agg_on, accent)
                    .id(SharedString::from(format!("drawer-agg-{name}")))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        let idx = Engine::ALL.iter().position(|e| *e == engine).unwrap_or(0);
                        this.config.aggregate_engines[idx] = !this.config.aggregate_engines[idx];
                        if !this.config.aggregate_engines.iter().any(|v| *v) {
                            this.config.aggregate_engines[idx] = true;
                        }
                        this.persist_config(cx);
                        cx.notify();
                    })),
            )
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .mt_2()
                    .child(
                        button("测试连接", false)
                            .id("drawer-test")
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.test_engine_connection(engine, cx);
                            })),
                    )
                    .child(
                        button("保存凭证", true)
                            .id("drawer-save")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.apply_creds(cx);
                                cx.notify();
                            })),
                    ),
            )
            .child(
                div()
                    .text_size(px(11.))
                    .text_color(rgb(theme().muted))
                    .child("凭证保存在本地 config.json"),
            );

        // 渐变雾面遮罩：靠抽屉一侧更浓，向左渐淡（近似毛玻璃的雾面层次）。
        // 遮罩随抽屉同步淡入（alpha × delta），消除首帧瞬现的跳变。
        let scrim = div()
            .id("drawer-scrim")
            .absolute()
            .inset_0()
            .occlude()
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _: &MouseDownEvent, _, cx| {
                    this.close_engine_drawer(cx);
                }),
            )
            .with_animation(
                "drawer-scrim-anim",
                Animation::new(Duration::from_millis(280)).with_easing(ease_out_quint()),
                move |scrim, delta| {
                    let strong = (0xa0 as f32 * delta) as u32;
                    let soft = (0x30 as f32 * delta) as u32;
                    scrim.bg(linear_gradient(
                        90.,
                        linear_color_stop(rgba(strong), 1.),
                        linear_color_stop(rgba(soft), 0.),
                    ))
                },
            );

        let drawer = div()
            .id("engine-drawer")
            .absolute()
            .right(px(0.))
            .top(px(0.))
            .bottom(px(0.))
            .w(px(380.))
            .max_w(px(self.viewport_width.min(380.)))
            .flex()
            .flex_col()
            .p_4()
            .bg(rgb(theme().panel))
            .border_l_1()
            .border_color(rgb(theme().border))
            .shadow_lg()
            .occlude()
            .key_context("EngineDrawer")
            .on_action(cx.listener(|this, _: &CloseOverlay, _, cx| {
                this.close_engine_drawer(cx);
            }))
            .on_mouse_down_out(cx.listener(|this, _: &MouseDownEvent, _, cx| {
                this.close_engine_drawer(cx);
            }))
            .child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .text_size(px(15.))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(div().size_2().rounded_full().bg(rgb(accent)))
                            .child(format!("{name} 引擎配置")),
                    )
                    .child(button("✕", false).id("drawer-close").on_click(cx.listener(
                        |this, _, _, cx| {
                            this.close_engine_drawer(cx);
                        },
                    ))),
            )
            .child(body)
            // 右侧滑入：起点为负 right（完全在屏幕外），ease_out_quint 缓动 280ms。
            // 注意 right(380) 会把 380px 宽的抽屉留在屏幕中部，必须用负值才是屏幕外。
            .with_animation(
                "engine-drawer-anim",
                Animation::new(Duration::from_millis(280)).with_easing(ease_out_quint()),
                move |drawer, delta| drawer.right(px(-380. * (1. - delta))),
            );

        div()
            .absolute()
            .inset_0()
            .child(scrim)
            .child(drawer)
            .into_any_element()
    }

    // ---------- 通知气泡 ----------

    /// 右下角弹出通知；数秒后自动消失，最多同时保留 5 条。
    fn push_toast(&mut self, kind: ToastKind, message: String, cx: &mut Context<Self>) {
        self.toast_seq += 1;
        let id = self.toast_seq;
        self.toasts.push(Toast { id, kind, message });
        if self.toasts.len() > 5 {
            self.toasts.remove(0);
        }
        cx.notify();
        cx.spawn(async move |this, cx| {
            cx.background_executor().timer(Duration::from_secs(6)).await;
            let _ = this.update(cx, |this, cx| {
                this.toasts.retain(|t| t.id != id);
                cx.notify();
            });
        })
        .detach();
    }

    fn close_toast(&mut self, id: u64, cx: &mut Context<Self>) {
        self.toasts.retain(|t| t.id != id);
        cx.notify();
    }

    /// 右下角通知气泡堆叠（最新在下，聊天软件样式）。
    fn render_toasts(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        if self.toasts.is_empty() {
            return div().into_any_element();
        }
        let width = (self.viewport_width - 24.).max(280.);
        div()
            .absolute()
            .bottom(px(40.))
            .right(px(12.))
            .flex()
            .flex_col()
            .gap_2()
            .w(px(380.))
            .max_w(px(width))
            .children(self.toasts.iter().map(|toast| {
                let (color, title) = match toast.kind {
                    ToastKind::Error => (theme().danger, "出错了"),
                    ToastKind::Ok => (theme().ok, "操作成功"),
                    ToastKind::Info => (theme().accent, "提示"),
                };
                let id = toast.id;
                div()
                    .id(SharedString::from(format!("toast-{id}")))
                    .flex()
                    .gap_2()
                    .p_2()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(theme().border))
                    .bg(rgb(theme().panel))
                    .shadow_lg()
                    // 默认交叉轴 stretch：色条自动撑满行高。
                    .child(div().w(px(3.)).rounded_full().bg(rgb(color)))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .gap(px(2.))
                            .child(div().text_size(px(11.)).text_color(rgb(color)).child(title))
                            .child(
                                div()
                                    .text_size(px(12.))
                                    .text_color(rgb(theme().text))
                                    .child(toast.message.clone()),
                            ),
                    )
                    .child(
                        div()
                            .id(SharedString::from(format!("toast-x-{id}")))
                            .px_1()
                            .rounded_sm()
                            .cursor_pointer()
                            .text_size(px(11.))
                            .text_color(rgb(theme().muted))
                            .hover(|s| s.bg(rgb(theme().row_hover)))
                            .child("✕")
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.close_toast(id, cx);
                            })),
                    )
            }))
            .into_any_element()
    }

    // ---------- 收藏 ----------

    fn is_favorited(&self, cx: &Context<Self>) -> bool {
        let q = self.query(cx);
        !q.is_empty() && self.config.favorites.iter().any(|f| f.query == q)
    }

    /// 打开收藏对话框：`existing` 为 None 时新增（预填当前查询语句），
    /// 否则编辑该语句的标签/描述。
    fn open_fav_dialog(&mut self, existing: Option<String>, cx: &mut Context<Self>) {
        let fav = existing
            .as_ref()
            .and_then(|q| self.config.favorites.iter().find(|f| &f.query == q));
        let (tags, note) = fav
            .map(|f| (f.tags.join(", "), f.note.clone()))
            .unwrap_or_default();
        let query = existing.clone().unwrap_or_else(|| self.query(cx));
        self.fav_query_input
            .update(cx, |input, cx| input.set_text(&query, cx));
        self.fav_tags_input
            .update(cx, |input, cx| input.set_text(&tags, cx));
        self.fav_note_input
            .update(cx, |input, cx| input.set_text(&note, cx));
        self.fav_dialog_existing = existing;
        self.show_fav_dialog = true;
        cx.notify();
    }

    fn save_fav_dialog(&mut self, cx: &mut Context<Self>) {
        let query = self.fav_query_input.read(cx).text().trim().to_string();
        if query.is_empty() {
            self.status = "收藏语句不能为空".into();
            cx.notify();
            return;
        }
        let tags = parse_tags(self.fav_tags_input.read(cx).text());
        let note = self.fav_note_input.read(cx).text().trim().to_string();
        let existing = self.fav_dialog_existing.clone();
        match existing {
            Some(old) => {
                if let Some(fav) = self.config.favorites.iter_mut().find(|f| f.query == old) {
                    fav.query = query.clone();
                    fav.tags = tags.clone();
                    fav.note = note.clone();
                } else {
                    self.config.favorite_add(&query, tags.clone(), &note);
                }
                self.status = format!("已更新收藏: {query}");
            }
            None => {
                if !self.config.favorite_add(&query, tags.clone(), &note)
                    && let Some(fav) = self.config.favorites.iter_mut().find(|f| f.query == query)
                {
                    fav.tags = tags.clone();
                    fav.note = note.clone();
                    self.status = format!("收藏已存在，已更新标签/描述: {query}");
                } else {
                    self.status = format!("已收藏: {query}");
                }
            }
        }
        if let Err(e) = self.config.save() {
            self.status = format!("收藏保存失败: {e}");
        }
        self.show_fav_dialog = false;
        self.fav_dialog_existing = None;
        cx.notify();
    }

    fn delete_favorite(&mut self, query: String, cx: &mut Context<Self>) {
        if self.config.favorite_remove(&query) {
            self.status = format!("已删除收藏: {query}");
            self.persist_config(cx);
        }
        cx.notify();
    }

    /// 使用收藏：填入搜索框并关闭所有收藏弹层。
    fn use_favorite(&mut self, query: String, cx: &mut Context<Self>) {
        self.query_input
            .update(cx, |input, cx| input.set_text(&query, cx));
        self.show_favorites = false;
        self.show_fav_dialog = false;
        cx.notify();
    }

    // ---------- 聚合引擎配置 ----------

    /// 聚合模式下参与搜索的引擎名（设置中的 aggregate_engines）。
    fn aggregate_engine_names(&self) -> String {
        Engine::ALL
            .iter()
            .enumerate()
            .filter(|(i, _)| self.config.aggregate_engines[*i])
            .map(|(_, e)| e.name())
            .collect::<Vec<_>>()
            .join(" · ")
    }

    /// 设置面板：聚合引擎参与开关（立即保存，至少保留一个）。
    fn render_aggregate_chips(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .id("aggregate-chips")
            // 溢出处理：横向滚动（flex 子项须禁用收缩，否则会被压缩裁剪而非溢出）。
            .overflow_x_scroll()
            .flex()
            .gap_2()
            .pb_1()
            .children(Engine::ALL.iter().enumerate().map(|(idx, engine)| {
                select_chip(
                    engine.name(),
                    self.config.aggregate_engines[idx],
                    engine.accent(),
                )
                .flex_shrink_0()
                .id(SharedString::from(format!("agg-{}", engine.name())))
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.config.aggregate_engines[idx] = !this.config.aggregate_engines[idx];
                    // 至少保留一个参与引擎，避免聚合模式空转。
                    if !this.config.aggregate_engines.iter().any(|v| *v) {
                        this.config.aggregate_engines[idx] = true;
                    }
                    this.persist_config(cx);
                    cx.notify();
                }))
            }))
    }

    // ---------- 设置面板 ----------

    fn open_settings(&mut self, cx: &mut Context<Self>) {
        // 设置面板与引擎抽屉共用凭证输入框实体，二者互斥渲染。
        self.show_engine_drawer = None;
        self.fofa_email.update(cx, |input, cx| {
            input.set_text(&self.config.fofa.email.clone(), cx)
        });
        self.fofa_key.update(cx, |input, cx| {
            input.set_text(&self.config.fofa.key.clone(), cx)
        });
        self.hunter_key.update(cx, |input, cx| {
            input.set_text(&self.config.hunter.api_key.clone(), cx)
        });
        self.quake_token.update(cx, |input, cx| {
            input.set_text(&self.config.quake.token.clone(), cx)
        });
        self.shodan_key.update(cx, |input, cx| {
            input.set_text(&self.config.shodan.api_key.clone(), cx)
        });
        self.zoomeye_key.update(cx, |input, cx| {
            input.set_text(&self.config.zoomeye.api_key.clone(), cx)
        });
        self.threatbook_key.update(cx, |input, cx| {
            input.set_text(&self.config.threatbook.api_key.clone(), cx)
        });
        self.zone0_key.update(cx, |input, cx| {
            input.set_text(&self.config.zone0.api_key.clone(), cx)
        });
        self.daydaymap_key.update(cx, |input, cx| {
            input.set_text(&self.config.daydaymap.api_key.clone(), cx)
        });
        self.vt_key.update(cx, |input, cx| {
            input.set_text(&self.config.virustotal.api_key.clone(), cx)
        });
        self.censys_id.update(cx, |input, cx| {
            input.set_text(&self.config.censys.api_id.clone(), cx)
        });
        self.censys_secret.update(cx, |input, cx| {
            input.set_text(&self.config.censys.api_secret.clone(), cx)
        });
        self.pagesize_input.update(cx, |input, cx| {
            let text = self.config.page_size.to_string();
            input.set_text(&text, cx)
        });
        self.maxpages_input.update(cx, |input, cx| {
            let text = self.config.max_pages.to_string();
            input.set_text(&text, cx)
        });
        self.delay_input.update(cx, |input, cx| {
            let text = self.config.request_delay_secs.to_string();
            input.set_text(&text, cx)
        });
        self.timeout_input.update(cx, |input, cx| {
            let text = self.config.request_timeout_secs.to_string();
            input.set_text(&text, cx)
        });
        self.proxy_input.update(cx, |input, cx| {
            let text = self.config.proxy_url.clone();
            input.set_text(&text, cx)
        });
        self.show_settings = true;
        cx.notify();
    }

    /// 从输入框读取并保存引擎凭证（设置面板与引擎抽屉共用）。
    fn apply_creds(&mut self, cx: &mut Context<Self>) {
        self.config.fofa.email = self.fofa_email.read(cx).text().trim().to_string();
        self.config.fofa.key = self.fofa_key.read(cx).text().trim().to_string();
        self.config.hunter.api_key = self.hunter_key.read(cx).text().trim().to_string();
        self.config.quake.token = self.quake_token.read(cx).text().trim().to_string();
        self.config.shodan.api_key = self.shodan_key.read(cx).text().trim().to_string();
        self.config.zoomeye.api_key = self.zoomeye_key.read(cx).text().trim().to_string();
        self.config.threatbook.api_key = self.threatbook_key.read(cx).text().trim().to_string();
        self.config.zone0.api_key = self.zone0_key.read(cx).text().trim().to_string();
        self.config.daydaymap.api_key = self.daydaymap_key.read(cx).text().trim().to_string();
        self.config.virustotal.api_key = self.vt_key.read(cx).text().trim().to_string();
        self.config.censys.api_id = self.censys_id.read(cx).text().trim().to_string();
        self.config.censys.api_secret = self.censys_secret.read(cx).text().trim().to_string();
        match self.config.save() {
            Ok(()) => {
                self.status = format!("配置已保存: {}", Config::config_path().display());
                self.push_toast(ToastKind::Ok, "凭证已保存".into(), cx);
            }
            Err(e) => {
                self.status = format!("保存失败: {e}");
                self.push_toast(ToastKind::Error, format!("凭证保存失败：{e}"), cx);
            }
        };
    }

    fn save_settings(&mut self, cx: &mut Context<Self>) {
        self.apply_creds(cx);
        self.show_settings = false;
        cx.notify();
    }

    // ---------- 渲染 ----------

    fn render_header(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .h(px(44.))
            .px_3()
            .flex()
            .items_center()
            .justify_between()
            .border_b_1()
            .border_color(rgb(theme().border))
            .bg(rgb(theme().panel))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .text_size(px(16.))
                    .child("🐙 Octox")
                    // 窄窗口收起副标题，给按钮区让位。
                    .when(!self.narrow(), |d| {
                        d.child(
                            div()
                                .text_size(px(12.))
                                .text_color(rgb(theme().muted))
                                .child("十引擎 · 网络资产聚合搜索"),
                        )
                    }),
            )
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        div()
                            .id("mcp-toggle")
                            .flex()
                            .items_center()
                            .gap_1()
                            .px_2()
                            .py_1()
                            .rounded_md()
                            .text_size(px(12.))
                            .cursor_pointer()
                            .border_1()
                            .border_color(rgb(if self.mcp_running() {
                                theme().accent
                            } else {
                                theme().border
                            }))
                            .bg(rgb(theme().panel_alt))
                            .text_color(rgb(if self.mcp_running() {
                                theme().accent
                            } else {
                                theme().muted
                            }))
                            .hover(|s| s.border_color(rgb(theme().accent)))
                            .child(div().size_2().rounded_full().bg(rgb(if self.mcp_running() {
                                theme().ok
                            } else {
                                theme().muted
                            })))
                            .child("MCP")
                            .on_click(cx.listener(|this, _, _, cx| this.toggle_mcp(cx))),
                    )
                    .child(
                        button("★ 收藏夹", false)
                            .id("open-favorites")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.favorites_filter = None;
                                this.show_favorites = true;
                                cx.notify();
                            })),
                    )
                    .child(
                        button("导出 CSV", false)
                            .id("export-csv")
                            .on_click(cx.listener(|this, _, _, cx| {
                                if this.results.is_empty() {
                                    this.status = "当前无结果可导出".into();
                                    cx.notify();
                                    return;
                                }
                                match export::export_csv(&this.results) {
                                    Ok(path) => {
                                        this.status = format!("已导出 CSV: {}", path.display());
                                        this.push_toast(
                                            ToastKind::Ok,
                                            format!("已导出 CSV → {}", path.display()),
                                            cx,
                                        );
                                    }
                                    Err(e) => {
                                        this.status = format!("导出失败: {e}");
                                        this.push_toast(
                                            ToastKind::Error,
                                            format!("CSV 导出失败：{e}"),
                                            cx,
                                        );
                                    }
                                }
                                cx.notify();
                            })),
                    )
                    .child(
                        button("导出 JSON", false)
                            .id("export-json")
                            .on_click(cx.listener(|this, _, _, cx| {
                                if this.results.is_empty() {
                                    this.status = "当前无结果可导出".into();
                                    cx.notify();
                                    return;
                                }
                                match export::export_json(&this.results) {
                                    Ok(path) => {
                                        this.status = format!("已导出 JSON: {}", path.display());
                                        this.push_toast(
                                            ToastKind::Ok,
                                            format!("已导出 JSON → {}", path.display()),
                                            cx,
                                        );
                                    }
                                    Err(e) => {
                                        this.status = format!("导出失败: {e}");
                                        this.push_toast(
                                            ToastKind::Error,
                                            format!("JSON 导出失败：{e}"),
                                            cx,
                                        );
                                    }
                                }
                                cx.notify();
                            })),
                    )
                    .child(
                        button("🧰 小工具", false)
                            .id("open-tools")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.show_tools = true;
                                cx.notify();
                            })),
                    )
                    .child(
                        button("⚙ 设置", false)
                            .id("open-settings")
                            .on_click(cx.listener(|this, _, _, cx| this.open_settings(cx))),
                    ),
            )
    }

    /// 搜索栏：[引擎下拉][输入框+补全][收藏][规则][搜索]。
    fn render_search_bar(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .relative()
            .px_3()
            .py_2()
            .flex()
            .flex_col()
            .border_b_1()
            .border_color(rgb(theme().border))
            .bg(rgb(theme().panel))
            .key_context("SearchBar")
            .on_action(cx.listener(Self::on_suggest_next))
            .on_action(cx.listener(Self::on_suggest_prev))
            .on_action(cx.listener(Self::on_suggest_accept))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .items_center()
                    // 输入组：下拉框与文本框连体（共享边框圆角容器）
                    .child(
                        div()
                            .flex()
                            .flex_1()
                            .min_w_0()
                            .h(px(32.))
                            .border_1()
                            .rounded_md()
                            .overflow_hidden()
                            .border_color(rgb(theme().border))
                            .bg(rgb(theme().input_bg))
                            .child(self.engine_dropdown.clone())
                            .child(
                                div()
                                    .id("engine-config-btn")
                                    .w(px(30.))
                                    .h_full()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .hover(|s| {
                                        s.text_color(rgb(theme().accent)).bg(rgb(theme().row_hover))
                                    })
                                    .child(icon(icons::GEAR, 14., theme().muted))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        let mode = this.engine_dropdown.read(cx).mode();
                                        match mode {
                                            SearchMode::Single(e) => {
                                                this.open_engine_drawer(Some(e), cx);
                                            }
                                            // 聚合模式没有单一引擎可配，转到设置的搜索 Tab。
                                            SearchMode::Aggregate => {
                                                this.settings_tab = 1;
                                                this.open_settings(cx);
                                            }
                                        }
                                    })),
                            )
                            .child(div().flex_1().min_w_0().child(self.query_input.clone())),
                    )
                    .child(self.render_favorite_button(cx))
                    .child(self.render_rules_button(cx))
                    .child(
                        button(
                            if self.loading {
                                "重新搜索"
                            } else {
                                "搜索"
                            },
                            true,
                        )
                        .id("search")
                        .on_click(cx.listener(|this, _, _, cx| this.fresh_search(cx))),
                    ),
            )
            .when(self.loading, |d| {
                d.child(
                    button("停止查询", false)
                        .id("cancel-search")
                        .on_click(cx.listener(|this, _, _, cx| this.cancel_search(cx))),
                )
            })
            .child(self.render_suggestion_popup(cx))
    }

    /// 收藏按钮：打开「收藏语句」对话框，可附标签与描述；★ 颜色与文案表达当前语句是否已收藏。
    fn render_favorite_button(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let favorited = self.is_favorited(cx);
        div().flex_shrink_0().child(
            div()
                .id("fav-btn")
                .flex()
                .items_center()
                .gap_1()
                .px_2()
                .py(px(6.5))
                .rounded_md()
                .border_1()
                .border_color(rgb(theme().border))
                .bg(rgb(theme().input_bg))
                .cursor_pointer()
                .hover(|s| s.border_color(rgb(theme().accent)))
                .text_size(px(12.))
                .text_color(rgb(theme().text))
                .child(icon(
                    icons::STAR,
                    14.,
                    if favorited {
                        FAVORITE_COLOR
                    } else {
                        theme().muted
                    },
                ))
                // 窄窗口只留图标，节省搜索栏横向空间。
                .when(!self.narrow(), |d| {
                    d.child(if favorited { "已收藏" } else { "收藏" })
                })
                .on_click(cx.listener(|this, _, _, cx| {
                    let current = this.query(cx);
                    if current.is_empty() {
                        this.status = "先输入查询语句再收藏".into();
                        cx.notify();
                        return;
                    }
                    let existing = this
                        .config
                        .favorites
                        .iter()
                        .find(|f| f.query == current)
                        .map(|f| f.query.clone());
                    this.open_fav_dialog(existing, cx);
                })),
        )
    }

    fn render_rules_button(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        div().flex_shrink_0().child(
            div()
                .id("rules-btn")
                .flex()
                .items_center()
                .gap_1()
                .px_2()
                .py(px(6.5))
                .rounded_md()
                .border_1()
                .border_color(rgb(theme().border))
                .bg(rgb(theme().input_bg))
                .cursor_pointer()
                .hover(|s| s.border_color(rgb(theme().accent)))
                .text_size(px(12.))
                .text_color(rgb(theme().text))
                .child(icon(icons::BOOK, 14., theme().muted))
                .when(!self.narrow(), |d| d.child("规则"))
                .on_click(cx.listener(|this, _, _, cx| {
                    this.show_rules = true;
                    cx.notify();
                })),
        )
    }

    /// 补全弹层。以搜索栏为定位父级：左缘对齐文本输入（px_3 12 + 引擎下拉 124），
    /// 顶缘紧贴输入行（行 8..40）下方，`deferred` 保证绘制在结果表之上——
    /// 不能包一层行内 div 再绝对定位，那样参照点会落在搜索栏末尾而整体下坠错位。
    fn render_suggestion_popup(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        if self.suggestions.is_empty() || self.suggest_active.is_none() {
            return div().into_any_element();
        }
        let active = self.suggest_active.unwrap_or(0);
        deferred(
            div()
                .id("suggest-popup")
                .absolute()
                .left(px(136.))
                .top(px(42.))
                .w(px(460.))
                .flex()
                .flex_col()
                .py_1()
                .rounded_md()
                .border_1()
                .border_color(rgb(theme().border))
                .bg(rgb(theme().panel))
                .shadow_lg()
                // 遮蔽弹层下层的命中（结果行等），点击弹层外则收起补全。
                .occlude()
                .on_mouse_down_out(cx.listener(|this, _: &MouseDownEvent, _, cx| {
                    this.suggestions.clear();
                    this.suggest_active = None;
                    cx.notify();
                }))
                .children(self.suggestions.iter().enumerate().map(|(i, c)| {
                    div()
                        .id(SharedString::from(format!("suggest-{i}")))
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_2()
                        .px_2()
                        .py_1()
                        .text_size(px(12.))
                        .cursor_pointer()
                        .when(i == active, |r| r.bg(rgba((theme().accent << 8) | 0x33)))
                        .when(i != active, |r| r.hover(|s| s.bg(rgb(theme().row_hover))))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.suggest_active = Some(i);
                            this.accept_suggestion(cx);
                        }))
                        .child(div().text_color(rgb(theme().text)).child(c.insert.clone()))
                        .child(
                            div()
                                .text_color(rgb(theme().muted))
                                .text_size(px(11.))
                                .child(c.hint),
                        )
                })),
        )
        .into_any_element()
    }

    fn table_width(&self) -> f32 {
        self.visible_columns()
            .map(|c| {
                if c.width == 0. {
                    self.title_width()
                } else {
                    c.width
                }
            })
            .sum::<f32>()
            + self.extra_columns().len() as f32 * EXTRA_COL_WIDTH
            + 16.
    }

    fn render_table_header(&self) -> impl IntoElement {
        div()
            .min_w(px(self.table_width()))
            .flex_shrink_0()
            .flex()
            .items_center()
            .h(px(28.))
            .px_2()
            .text_size(px(12.))
            .text_color(rgb(theme().muted))
            .bg(rgb(theme().panel))
            .border_b_1()
            .border_color(rgb(theme().border))
            .children({
                let title_w = self.title_width();
                let mut cells: Vec<gpui::AnyElement> = self
                    .visible_columns()
                    .map(|c| match c.width {
                        0. => cell(c.label, title_w).into_any_element(),
                        w => cell(c.label, w).into_any_element(),
                    })
                    .collect();
                for label in self.extra_columns() {
                    cells.push(cell(&label, EXTRA_COL_WIDTH).into_any_element());
                }
                cells
            })
    }

    fn render_results(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity();
        let count = self.results.len();
        let body: gpui::AnyElement = if count == 0 {
            div()
                .flex()
                .flex_1()
                .min_h_0()
                .items_center()
                .justify_center()
                .text_color(rgb(theme().muted))
                .text_size(px(13.))
                .child(if self.loading {
                    "查询中…".to_string()
                } else {
                    if self.errors.iter().any(Option::is_some) {
                        "查询未获得结果，请展开引擎状态查看错误或配置凭证".to_string()
                    } else if !self.last_query.is_empty() {
                        "没有匹配结果，请调整条件或返回上一页".to_string()
                    } else {
                        "输入查询语句开始搜索；首次使用请先配置引擎凭证".to_string()
                    }
                })
                .into_any_element()
        } else {
            uniform_list("results", count, move |range, _window, cx| {
                let this = view.read(cx);
                range
                    .map(|i| render_result_row(this, i, view.clone()))
                    .collect::<Vec<_>>()
            })
            .flex_1()
            .min_h_0()
            .min_w(px(self.table_width()))
            .into_any_element()
        };

        div()
            .id("results-table-scroll")
            .overflow_x_scroll()
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .w_full()
            .child(self.render_table_header())
            .child(body)
    }

    fn render_detail(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let selected = self.selected.and_then(|i| self.results.get(i));
        let mut fields = Vec::new();
        if let Some(a) = selected {
            fields = vec![
                format!("URL: {}", a.url),
                format!("Host: {}", a.host),
                format!("IP: {} · 端口: {} · 协议: {}", a.ip, a.port, a.protocol),
                format!("标题: {}", a.title),
                format!("组件: {}", a.component),
                format!("组织: {}", a.org),
                format!("状态: {} · 更新时间: {}", a.status_code, a.updated_at),
            ];
            fields.extend(
                a.extras
                    .iter()
                    .map(|(key, value)| format!("{key}: {value}")),
            );
        }
        div()
            .flex()
            .flex_col()
            .flex_shrink_0()
            .bg(rgb(theme().panel))
            .border_t_1()
            .border_color(rgb(theme().border))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .px_2()
                    .h(px(30.))
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(rgb(theme().muted))
                            .child(if selected.is_some() {
                                "已选择资产 · 展开查看完整字段（点击字段复制）"
                            } else {
                                "点击结果行查看详情"
                            }),
                    )
                    .child(
                        button(
                            if self.detail_expanded {
                                "收起详情"
                            } else {
                                "展开详情"
                            },
                            false,
                        )
                        .id("toggle-detail")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.detail_expanded = !this.detail_expanded;
                            cx.notify();
                        })),
                    ),
            )
            .when(self.detail_expanded, |d| {
                d.child(
                    div()
                        .id("asset-detail")
                        .h(px(170.))
                        .overflow_y_scroll()
                        .px_3()
                        .py_2()
                        .text_size(px(12.))
                        .children(fields.into_iter().enumerate().map(|(i, field)| {
                            div()
                                .id(SharedString::from(format!("detail-field-{i}")))
                                .py_1()
                                .child(field.clone())
                                .cursor_pointer()
                                .on_click(move |_, _, cx| {
                                    cx.write_to_clipboard(ClipboardItem::new_string(field.clone()))
                                })
                        })),
                )
            })
    }

    fn render_search_details(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let states: Vec<_> = Engine::ALL
            .iter()
            .copied()
            .filter_map(|e| {
                let i = e.index();
                if let Some(error) = &self.errors[i] {
                    Some((e, format!("失败：{error}")))
                } else {
                    self.totals[i].map(|total| {
                        (
                            e,
                            format!(
                                "总量 {total} · 本页 {} 条 · {}",
                                self.results.iter().filter(|a| a.engine == e).count(),
                                if self.next_pages[i] {
                                    "有后续页"
                                } else {
                                    "已到末页"
                                }
                            ),
                        )
                    })
                }
            })
            .collect();
        div()
            .flex()
            .flex_col()
            .flex_shrink_0()
            .border_b_1()
            .border_color(rgb(theme().border))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_2()
                    .py_1()
                    .child(
                        button(
                            if self.show_search_details {
                                "收起引擎状态"
                            } else {
                                "展开引擎状态"
                            },
                            false,
                        )
                        .id("search-details-toggle")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.show_search_details = !this.show_search_details;
                            cx.notify();
                        })),
                    )
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(rgb(theme().muted))
                            .child(format!(
                                "本页 {} 条 · {} 个失败 · {} 个等待完成",
                                self.results.len(),
                                self.errors.iter().filter(|e| e.is_some()).count(),
                                self.pending
                            )),
                    )
                    .child(
                        button("重试失败", false)
                            .id("retry-errors")
                            .on_click(cx.listener(|this, _, _, cx| {
                                if !this.loading && this.errors.iter().any(Option::is_some) {
                                    this.start_search(cx);
                                }
                            })),
                    ),
            )
            .when(self.show_search_details, |d| {
                d.child(
                    div()
                        .id("engine-status-list")
                        .max_h(px(150.))
                        .overflow_y_scroll()
                        .px_3()
                        .py_1()
                        .children(states.into_iter().map(|(e, text)| {
                            div()
                                .py_1()
                                .text_size(px(12.))
                                .child(format!("{}：{text}", e.name()))
                        })),
                )
            })
    }

    fn render_status_bar(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let status_color = if self.loading {
            theme().accent
        } else if self.errors.iter().any(Option::is_some) {
            theme().danger
        } else {
            theme().ok
        };
        let quotas = Engine::ALL
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                self.quotas[i]
                    .as_ref()
                    .map(|q| format!("{} 余量 {}", e.name(), q))
            })
            .collect::<Vec<_>>();
        let max_pages = self.config.max_pages.max(1);
        let at_max = self.loading || self.page >= max_pages || !self.next_pages.iter().any(|v| *v);

        div()
            .h(px(30.))
            .px_2()
            .flex()
            .items_center()
            .justify_between()
            .bg(rgb(theme().panel))
            .border_t_1()
            .border_color(rgb(theme().border))
            .child(
                div()
                    .flex_1()
                    .truncate()
                    .text_size(px(12.))
                    .text_color(rgb(status_color))
                    .child(self.status.clone()),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .children(quotas.iter().map(|q| {
                        div()
                            .text_size(px(11.))
                            .text_color(rgb(theme().muted))
                            .child(q.clone())
                    }))
                    .child(
                        button(
                            format!(
                                "请求 {} / 引擎 · 本页 {} 条",
                                self.active_size,
                                self.results.len()
                            ),
                            false,
                        )
                        .id("page-size")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.settings_tab = 1;
                            this.open_settings(cx);
                        })),
                    )
                    .child(
                        button("‹ 上一页", false)
                            .id("prev-page")
                            .when(self.page <= 1 || self.loading, |b| b.opacity(0.4))
                            .on_click(cx.listener(|this, _, _, cx| {
                                if this.page > 1 && !this.loading {
                                    this.change_page(this.page - 1, cx);
                                }
                            })),
                    )
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(rgb(theme().text))
                            .child(format!("第 {} 页 · 上限 {max_pages}", self.page)),
                    )
                    .child(
                        button("下一页 ›", false)
                            .id("next-page")
                            .when(at_max, |b| b.opacity(0.4))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                if !at_max {
                                    this.change_page(this.page + 1, cx);
                                } else {
                                    this.status = format!(
                                        "没有可继续翻页的结果，或已达页数上限 {}",
                                        this.config.max_pages
                                    );
                                    cx.notify();
                                }
                            })),
                    ),
            )
    }

    fn render_settings_overlay(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let tabs: Vec<gpui::AnyElement> = SETTINGS_TABS
            .iter()
            .enumerate()
            .map(|(i, label)| {
                div()
                    .id(SharedString::from(format!("settings-tab-{i}")))
                    .flex_shrink_0()
                    .px_2()
                    .py_1()
                    .rounded_sm()
                    .text_size(px(12.))
                    .cursor_pointer()
                    .when(self.settings_tab == i, |d| d.bg(rgb(theme().panel_alt)))
                    .text_color(rgb(if self.settings_tab == i {
                        theme().text
                    } else {
                        theme().muted
                    }))
                    .hover(|s| s.text_color(rgb(theme().text)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.settings_tab = i;
                        cx.notify();
                    }))
                    .child(*label)
                    .into_any_element()
            })
            .collect();

        let body: gpui::AnyElement = match self.settings_tab {
            0 => self.render_settings_creds(cx).into_any_element(),
            1 => self.render_settings_search(cx).into_any_element(),
            2 => self.render_settings_display(cx).into_any_element(),
            3 => self.render_settings_appearance(cx).into_any_element(),
            _ => self.render_settings_mcp(cx).into_any_element(),
        };

        let scroll = div()
            .id("settings-body")
            .max_h(px(420.))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap_2()
            .pr_1()
            .child(body);

        overlay("settings-overlay")
            .key_context("SettingsOverlay")
            .on_action(cx.listener(|this, _: &CloseOverlay, _, cx| {
                this.show_settings = false;
                cx.notify();
            }))
            .child(
                panel(640.)
                    .child(
                        div()
                            .flex()
                            .justify_between()
                            .items_center()
                            .text_size(px(15.))
                            .child("设置")
                            .child(
                                button("✕", false)
                                    .id("settings-close")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.show_settings = false;
                                        cx.notify();
                                    })),
                            ),
                    )
                    .child(
                        div()
                            .id("settings-tabs")
                            .flex()
                            .gap_1()
                            .border_b_1()
                            .border_color(rgb(theme().border))
                            .pb_2()
                            .overflow_x_scroll()
                            .children(tabs),
                    )
                    .child(scroll)
                    // 凭证需要显式保存；其余 Tab 即时生效，无需页脚按钮。
                    .children((self.settings_tab == 0).then(|| {
                        div()
                            .flex()
                            .justify_end()
                            .gap_2()
                            .mt_2()
                            .child(button("取消", false).id("settings-cancel").on_click(
                                cx.listener(|this, _, _, cx| {
                                    this.show_settings = false;
                                    cx.notify();
                                }),
                            ))
                            .child(
                                button("保存凭证", true)
                                    .id("settings-save")
                                    .on_click(cx.listener(|this, _, _, cx| this.save_settings(cx))),
                            )
                    })),
            )
    }

    fn render_settings_creds(&mut self, _cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .gap_2()
            .child(field_label("FOFA（email + key）"))
            .child(self.fofa_email.clone())
            .child(self.fofa_key.clone())
            .child(field_label("Hunter 鹰图（api-key）"))
            .child(self.hunter_key.clone())
            .child(field_label("Quake 360（X-QuakeToken）"))
            .child(self.quake_token.clone())
            .child(field_label("Shodan（api-key）"))
            .child(self.shodan_key.clone())
            .child(field_label("ZoomEye（API-KEY）"))
            .child(self.zoomeye_key.clone())
            .child(field_label("ThreatBook 微步（apikey）"))
            .child(self.threatbook_key.clone())
            .child(field_label("0.zone 零零信安（key）"))
            .child(self.zone0_key.clone())
            .child(field_label("DayDayMap 洞察（api-key）"))
            .child(self.daydaymap_key.clone())
            .child(field_label(
                "VirusTotal（x-apikey，结构化搜索需 Intelligence）",
            ))
            .child(self.vt_key.clone())
            .child(field_label("Censys（api-id + api-secret）"))
            .child(self.censys_id.clone())
            .child(self.censys_secret.clone())
    }

    fn render_settings_search(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let num_setting = |label: &'static str, input: &Entity<TextInput>, unit: &'static str| {
            div()
                .flex()
                .items_center()
                .gap_1()
                .child(
                    div()
                        .text_size(px(12.))
                        .text_color(rgb(theme().accent))
                        .child(label),
                )
                .child(div().w(px(64.)).child(input.clone()))
                .child(
                    div()
                        .text_size(px(12.))
                        .text_color(rgb(theme().muted))
                        .child(unit),
                )
        };

        div()
            .flex()
            .flex_col()
            .gap_2()
            .child(field_label("搜索参数（回车应用）"))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap_3()
                    .child(num_setting("每页", &self.pagesize_input, "条"))
                    .child(num_setting("上限", &self.maxpages_input, "页"))
                    .child(num_setting("延迟", &self.delay_input, "秒"))
                    .child(num_setting("超时", &self.timeout_input, "秒"))
                    .child(
                        div().flex().items_center().gap_1().child(
                            select_chip(
                                if self.config.proxy_enabled {
                                    "代理 已开启"
                                } else {
                                    "代理 已关闭"
                                },
                                self.config.proxy_enabled,
                                theme().ok,
                            )
                            .id("proxy-toggle")
                            .on_click(cx.listener(|this, _, _, cx| this.toggle_proxy(cx))),
                        ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(rgb(theme().accent))
                            .child("代理"),
                    )
                    .child(div().w(px(240.)).child(self.proxy_input.clone()))
                    .child(
                        div()
                            .text_size(px(11.))
                            .text_color(rgb(theme().muted))
                            .child("回车应用，支持 http/https/socks5"),
                    ),
            )
            .child(field_label(
                "聚合引擎 — 「聚合引擎」模式下参与搜索的引擎（默认全部）",
            ))
            .child(self.render_aggregate_chips(cx))
    }

    fn render_settings_display(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let chips: Vec<gpui::AnyElement> = COLUMNS
            .iter()
            .map(|c| {
                select_chip(c.label, self.column_visible(c.key), theme().accent)
                    .id(SharedString::from(format!("col-{}", c.key)))
                    .on_click(cx.listener(move |this, _, _, cx| this.toggle_column(c.key, cx)))
                    .into_any_element()
            })
            .collect();

        div()
            .flex()
            .flex_col()
            .gap_2()
            .child(field_label("结果表显示的列（点击开关）"))
            .child(
                div()
                    .text_size(px(11.))
                    .text_color(rgb(theme().muted))
                    .child("单引擎模式自动追加引擎特有列"),
            )
            .child(div().flex().flex_wrap().gap_2().children(chips))
            .child(
                div().flex().justify_end().child(
                    button("全部显示", false)
                        .id("cols-reset")
                        .on_click(cx.listener(|this, _, _, cx| this.show_all_columns(cx))),
                ),
            )
    }

    fn render_settings_appearance(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let cards: Vec<gpui::AnyElement> = THEME_PRESETS
            .iter()
            .map(|(name, key, palette)| {
                let selected = self.config.theme == *key;
                div()
                    .id(SharedString::from(format!("theme-{}", key)))
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_2()
                    .py_1()
                    .rounded_md()
                    .text_size(px(12.))
                    .cursor_pointer()
                    .border_1()
                    .border_color(rgb(if selected {
                        theme().accent
                    } else {
                        theme().border
                    }))
                    .bg(rgb(theme().panel_alt))
                    // 配色预览：底色 / 面板 / 主色 三点示意。
                    .child(
                        div()
                            .size_3()
                            .rounded_sm()
                            .border_1()
                            .border_color(rgb(theme().border))
                            .bg(rgb(palette.bg)),
                    )
                    .child(div().size_3().rounded_sm().bg(rgb(palette.panel)))
                    .child(div().size_3().rounded_sm().bg(rgb(palette.accent)))
                    .child(*name)
                    .on_click(cx.listener(move |this, _, _, cx| this.set_theme(key, *palette, cx)))
                    .into_any_element()
            })
            .collect();

        div()
            .flex()
            .flex_col()
            .gap_2()
            .child(field_label("主题"))
            .child(div().flex().flex_wrap().gap_2().children(cards))
    }

    fn render_settings_mcp(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "octox.exe".to_string());
        let snippet_lines = [
            "{".to_string(),
            "  \"mcpServers\": {".to_string(),
            format!("    \"octox\": {{ \"command\": \"{exe}\", \"args\": [\"--mcp\"] }}"),
            "  }}".to_string(),
            "}".to_string(),
        ];
        let snippet_text = snippet_lines.join("\n");

        let running = self.mcp_running();
        div()
            .flex()
            .flex_col()
            .gap_2()
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(rgb(theme().text))
                    .child("将 Octox 作为 MCP Server 接入 MCP 客户端（Claude / Zed / Cherry Studio 等），AI 即可直接调用三引擎搜索与收藏。"),
            )
            .child(field_label("TCP 服务 — GUI 运行期间在本机端口提供工具（菜单栏可快捷开关）"))
            .child(
                select_chip(
                    &if running {
                        format!("已开启 · 127.0.0.1:{}", self.config.mcp_port)
                    } else {
                        "已关闭".to_string()
                    },
                    running,
                    theme().accent,
                )
                .id("mcp-toggle-settings")
                .on_click(cx.listener(|this, _, _, cx| this.toggle_mcp(cx))),
            )
            .child(field_label("提供工具"))
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(rgb(theme().muted))
                    .child("search · list_engines · list_favorites · add_favorite"),
            )
            .child(field_label("客户端配置示例（命令 + --mcp 参数）"))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .p_2()
                    .rounded_md()
                    .bg(rgb(theme().input_bg))
                    .children(snippet_lines.iter().map(|line| {
                        div()
                            .text_size(px(11.))
                            .text_color(rgb(theme().muted))
                            .child(line.clone())
                    })),
            )
            .child(
                div()
                    .flex()
                    .justify_end()
                    .child(
                        button("复制配置 JSON", false)
                            .id("copy-mcp")
                            .on_click(cx.listener(move |this, _, _, cx| {
                                cx.write_to_clipboard(ClipboardItem::new_string(snippet_text.clone()));
                                this.status = "MCP 客户端配置已复制到剪贴板".into();
                                cx.notify();
                            })),
                    ),
            )
    }

    /// 收藏夹管理器：标签过滤 + 使用 / 编辑 / 删除。
    fn render_favorites_manager(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let total = self.config.favorites.len();
        let filter = self.favorites_filter.clone();
        let tags = self.config.favorite_tags();

        let mut tag_row = div().flex().flex_wrap().gap_1().child(
            select_chip("全部", filter.is_none(), theme().accent)
                .id("favtag-all")
                .on_click(cx.listener(|this, _, _, cx| {
                    this.favorites_filter = None;
                    cx.notify();
                })),
        );
        for tag in &tags {
            let selected = filter.as_ref() == Some(tag);
            tag_row = tag_row.child(
                select_chip(tag, selected, theme().accent)
                    .id(SharedString::from(format!("favtag-{tag}")))
                    .on_click(cx.listener({
                        let tag = tag.clone();
                        move |this, _, _, cx| {
                            this.favorites_filter = Some(tag.clone());
                            cx.notify();
                        }
                    })),
            );
        }

        let favorites = self.config.favorites.clone();
        let rows: Vec<gpui::AnyElement> = favorites
            .iter()
            .enumerate()
            .filter(|(_, f)| filter.as_ref().map_or(true, |t| f.tags.contains(t)))
            .map(|(i, fav)| {
                let mut meta = div().flex().items_center().gap_1().min_w_0();
                for tag in &fav.tags {
                    meta = meta.child(tag_chip(tag));
                }
                if !fav.note.is_empty() {
                    meta = meta.child(
                        div()
                            .min_w_0()
                            .truncate()
                            .text_size(px(11.))
                            .text_color(rgb(theme().muted))
                            .child(fav.note.clone()),
                    );
                }
                let query = fav.query.clone();
                let edit_query = fav.query.clone();
                let del_query = fav.query.clone();
                div()
                    .id(SharedString::from(format!("favm-{i}")))
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_2()
                    .py_1()
                    .rounded_sm()
                    .cursor_pointer()
                    .hover(|s| s.bg(rgb(theme().row_hover)))
                    .on_click(
                        cx.listener(move |this, _, _, cx| this.use_favorite(query.clone(), cx)),
                    )
                    .child(icon(icons::SEARCH, 12., theme().muted))
                    .child(
                        div()
                            .flex_col()
                            .flex_1()
                            .min_w_0()
                            .gap(px(2.))
                            .child(
                                div()
                                    .truncate()
                                    .text_size(px(12.))
                                    .text_color(rgb(theme().text))
                                    .child(fav.query.clone()),
                            )
                            .child(meta),
                    )
                    .child(
                        div()
                            .id(SharedString::from(format!("favm-edit-{i}")))
                            .px_1()
                            .rounded_sm()
                            .cursor_pointer()
                            .text_size(px(12.))
                            .text_color(rgb(theme().muted))
                            .hover(|s| s.bg(rgb(theme().border)))
                            .child("✎")
                            .on_click(cx.listener(move |this, _, _, cx| {
                                cx.stop_propagation();
                                this.open_fav_dialog(Some(edit_query.clone()), cx);
                            })),
                    )
                    .child(
                        div()
                            .id(SharedString::from(format!("favm-del-{i}")))
                            .p_1()
                            .rounded_sm()
                            .cursor_pointer()
                            .hover(|s| s.bg(rgb(theme().border)))
                            .child(icon(icons::TRASH, 12., theme().muted))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                cx.stop_propagation();
                                this.delete_favorite(del_query.clone(), cx);
                            })),
                    )
                    .into_any_element()
            })
            .collect();

        overlay("favorites-overlay")
            .key_context("FavoritesOverlay")
            .on_action(cx.listener(|this, _: &CloseOverlay, _, cx| {
                this.show_favorites = false;
                cx.notify();
            }))
            .child(
                panel(680.)
                    .child(
                        div()
                            .flex()
                            .justify_between()
                            .items_center()
                            .text_size(px(15.))
                            .child(format!("★ 收藏夹 · {total} 条"))
                            .child(
                                button("✕", false)
                                    .id("favorites-close")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.show_favorites = false;
                                        cx.notify();
                                    })),
                            ),
                    )
                    .child(tag_row)
                    .child(
                        div()
                            .id("favorites-list")
                            .max_h(px(440.))
                            .overflow_y_scroll()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .pr_1()
                            .children(if rows.is_empty() {
                                vec![
                                    div()
                                        .px_2()
                                        .py_3()
                                        .text_size(px(12.))
                                        .text_color(rgb(theme().muted))
                                        .child("暂无收藏 — 输入查询语句后点击搜索栏 ★ 收藏")
                                        .into_any_element(),
                                ]
                            } else {
                                rows
                            }),
                    )
                    .child(
                        div()
                            .flex()
                            .justify_end()
                            .gap_2()
                            .mt_1()
                            .child(
                                button("★ 收藏当前语句", false)
                                    .id("favorites-add-current")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        let current = this.query(cx);
                                        if current.is_empty() {
                                            this.status = "先输入查询语句再收藏".into();
                                            cx.notify();
                                            return;
                                        }
                                        let existing = this
                                            .config
                                            .favorites
                                            .iter()
                                            .find(|f| f.query == current)
                                            .map(|f| f.query.clone());
                                        this.open_fav_dialog(existing, cx);
                                    })),
                            )
                            .child(
                                button("关闭", false)
                                    .id("favorites-ok")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.show_favorites = false;
                                        cx.notify();
                                    })),
                            ),
                    ),
            )
    }

    /// 收藏对话框：语句 + 标签 + 描述；编辑模式可删除。
    fn render_fav_dialog(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let editing = self.fav_dialog_existing.clone();
        let mut footer = div().flex().justify_end().gap_2().mt_2();
        if let Some(old) = editing.clone() {
            footer = footer.child(button("删除收藏", false).id("fav-dialog-delete").on_click(
                cx.listener(move |this, _, _, cx| {
                    this.show_fav_dialog = false;
                    this.fav_dialog_existing = None;
                    this.delete_favorite(old.clone(), cx);
                }),
            ));
        }
        footer = footer
            .child(
                button("取消", false)
                    .id("fav-dialog-cancel")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.show_fav_dialog = false;
                        this.fav_dialog_existing = None;
                        cx.notify();
                    })),
            )
            .child(
                button("保存", true)
                    .id("fav-dialog-save")
                    .on_click(cx.listener(|this, _, _, cx| this.save_fav_dialog(cx))),
            );

        overlay("fav-dialog")
            .key_context("FavDialog")
            .on_action(cx.listener(|this, _: &CloseOverlay, _, cx| {
                this.show_fav_dialog = false;
                this.fav_dialog_existing = None;
                cx.notify();
            }))
            .child(
                panel(520.)
                    .child(
                        div()
                            .flex()
                            .justify_between()
                            .items_center()
                            .text_size(px(15.))
                            .child(if editing.is_some() {
                                "编辑收藏"
                            } else {
                                "新增收藏"
                            })
                            .child(button("✕", false).id("fav-dialog-close").on_click(
                                cx.listener(|this, _, _, cx| {
                                    this.show_fav_dialog = false;
                                    this.fav_dialog_existing = None;
                                    cx.notify();
                                }),
                            )),
                    )
                    .child(field_label("查询语句"))
                    .child(self.fav_query_input.clone())
                    .child(field_label("标签（逗号 / 空格分隔，可空）"))
                    .child(self.fav_tags_input.clone())
                    .child(field_label("描述（可空）"))
                    .child(self.fav_note_input.clone())
                    .child(footer),
            )
    }

    // ---------- 小工具 ----------

    /// 写剪贴板并弹通知（小工具结果区各复制按钮共用）。
    fn copy_text(&mut self, text: String, label: &str, cx: &mut Context<Self>) {
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        self.push_toast(ToastKind::Ok, format!("已复制{label}"), cx);
        cx.notify();
    }

    /// 计算 favicon hash：抓图标在后台线程做，`tool_gen` 丢弃过期结果。
    fn compute_favicon(&mut self, cx: &mut Context<Self>) {
        let input = self.tool_url_input.read(cx).text().trim().to_string();
        if input.is_empty() {
            self.status = "先在输入框填 URL 再计算 favicon hash".into();
            cx.notify();
            return;
        }
        let cfg = self.config.clone();
        self.tool_gen += 1;
        let generation = self.tool_gen;
        self.tool_favicon_state = ToolFaviconState::Loading;
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move { tools::favicon_hash(&cfg, &input) })
                .await;
            let _ = this.update(cx, move |app, cx| {
                if app.tool_gen != generation {
                    return;
                }
                app.tool_favicon_state = match result {
                    Ok(out) => ToolFaviconState::Done {
                        icon_url: out.icon_url,
                        hash: out.hash,
                    },
                    Err(e) => ToolFaviconState::Failed(e),
                };
                cx.notify();
            });
        })
        .detach();
    }

    /// 复制输入 URL 解析出的 HTTP Host 头（默认端口自动省略）。
    fn copy_tool_host(&mut self, cx: &mut Context<Self>) {
        let input = self.tool_url_input.read(cx).text().trim().to_string();
        match tools::parse_target(&input) {
            Ok(target) => {
                cx.write_to_clipboard(ClipboardItem::new_string(target.host_header.clone()));
                self.push_toast(
                    ToastKind::Ok,
                    format!("已复制 Host 头 → {}", target.host_header),
                    cx,
                );
            }
            Err(e) => self.push_toast(ToastKind::Error, e, cx),
        }
        cx.notify();
    }

    /// 小工具弹层：favicon hash 计算 + Host 头复制。
    fn render_tools_dialog(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let host_header = tools::host_header(self.tool_url_input.read(cx).text());
        let mut dlg = panel(560.)
            .child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .text_size(px(15.))
                    .child("🧰 小工具")
                    .child(button("✕", false).id("tools-close").on_click(cx.listener(
                        |this, _, _, cx| {
                            this.show_tools = false;
                            cx.notify();
                        },
                    ))),
            )
            .child(field_label(
                "Favicon Hash（抓取站点图标 → base64 → mmh3，FOFA / Shodan 同款算法）",
            ))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().flex_1().min_w_0().child(self.tool_url_input.clone()))
                    .child(
                        button(
                            if matches!(self.tool_favicon_state, ToolFaviconState::Loading) {
                                "计算中…"
                            } else {
                                "计算"
                            },
                            true,
                        )
                        .id("tools-favicon-compute")
                        .on_click(cx.listener(|this, _, _, cx| this.compute_favicon(cx))),
                    ),
            );
        dlg = match &self.tool_favicon_state {
            ToolFaviconState::Idle => dlg.child(
                div()
                    .text_size(px(12.))
                    .text_color(rgb(theme().muted))
                    .child("输入站点 URL 或 host，点击「计算」；也可直接填图标的完整地址。"),
            ),
            ToolFaviconState::Loading => dlg.child(
                div()
                    .text_size(px(12.))
                    .text_color(rgb(theme().accent))
                    .child("正在抓取图标…"),
            ),
            ToolFaviconState::Failed(e) => dlg.child(
                div()
                    .text_size(px(12.))
                    .text_color(rgb(theme().danger))
                    .child(e.clone()),
            ),
            ToolFaviconState::Done { icon_url, hash } => {
                let hash = *hash;
                let hash_text = hash.to_string();
                let fofa_stmt = format!("icon_hash=\"{hash}\"");
                let shodan_stmt = format!("http.favicon.hash:{hash}");
                dlg.child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(field_label("icon_hash"))
                                .child(
                                    div()
                                        .text_size(px(14.))
                                        .text_color(rgb(theme().ok))
                                        .child(hash_text.clone()),
                                ),
                        )
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(rgb(theme().muted))
                                .truncate()
                                .child(format!("来源：{icon_url}")),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap_2()
                        .child(tool_copy_chip("tools-copy-hash", "复制 hash").on_click(
                            cx.listener(move |this, _, _, cx| {
                                this.copy_text(hash.to_string(), "hash", cx);
                            }),
                        ))
                        .child(
                            tool_copy_chip("tools-copy-fofa", "复制 FOFA 语句").on_click(
                                cx.listener(move |this, _, _, cx| {
                                    this.copy_text(fofa_stmt.clone(), "FOFA 语句", cx);
                                }),
                            ),
                        )
                        .child(
                            tool_copy_chip("tools-copy-shodan", "复制 Shodan 语句").on_click(
                                cx.listener(move |this, _, _, cx| {
                                    this.copy_text(shodan_stmt.clone(), "Shodan 语句", cx);
                                }),
                            ),
                        ),
                )
            }
        };
        // 全屏遮罩 + 居中面板；Esc 关闭。
        overlay("tools")
            .key_context("ToolsDialog")
            .on_action(cx.listener(|this, _: &CloseOverlay, _, cx| {
                this.show_tools = false;
                cx.notify();
            }))
            .child(
                dlg.child(field_label(
                    "Host 头（从上方 URL 解析，scheme 默认端口自动省略）",
                ))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .h(px(32.))
                                .px_2()
                                .flex()
                                .items_center()
                                .rounded_md()
                                .border_1()
                                .border_color(rgb(theme().border))
                                .bg(rgb(theme().input_bg))
                                .text_size(px(13.))
                                .truncate()
                                .child(match host_header {
                                    Some(h) => h,
                                    None => "—（无法从输入解析出主机）".to_string(),
                                }),
                        )
                        .child(
                            button("复制 Host 头", false)
                                .id("tools-copy-host")
                                .on_click(cx.listener(|this, _, _, cx| this.copy_tool_host(cx))),
                        ),
                )
                .child(div().flex().justify_end().mt_1().child(
                    button("关闭", false).id("tools-done").on_click(cx.listener(
                        |this, _, _, cx| {
                            this.show_tools = false;
                            cx.notify();
                        },
                    )),
                )),
            )
    }

    fn render_rules_overlay(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let mode = self.engine_dropdown.read(cx).mode();

        // 规则跟随模式：单引擎只显示该引擎的完整语法；聚合模式只显示公共语法。
        let mut sections: Vec<gpui::AnyElement> = Vec::new();
        match mode {
            SearchMode::Aggregate => {
                let rows: Vec<gpui::AnyElement> = translate::COMMON_FIELDS
                    .iter()
                    .map(|cf| {
                        let fill = format!("{}=\"", cf.field);
                        let text = format!("{}=\"…\"", cf.field);
                        div()
                            .id(SharedString::from(format!("rule-common-{}", cf.field)))
                            .flex()
                            .items_center()
                            .gap_2()
                            .px_2()
                            .py_1()
                            .rounded_sm()
                            .cursor_pointer()
                            .hover(|s| s.bg(rgb(theme().row_hover)))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.query_input
                                    .update(cx, |input, cx| input.set_text(&fill, cx));
                                cx.notify();
                            }))
                            .child(
                                div()
                                    .w(px(230.))
                                    .flex_shrink_0()
                                    .truncate()
                                    .text_size(px(12.))
                                    .text_color(rgb(theme().text))
                                    .child(text),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .truncate()
                                    .text_size(px(11.))
                                    .text_color(rgb(theme().muted))
                                    .child(format!("{}（自动转换为各引擎写法）", cf.desc)),
                            )
                            .into_any_element()
                    })
                    .collect();
                sections.push(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(
                            div()
                                .text_size(px(13.))
                                .text_color(rgb(theme().accent))
                                .child("公共语法 — 聚合引擎"),
                        )
                        .children(rows)
                        .into_any_element(),
                );
            }
            SearchMode::Single(engine) => {
                let idx = Engine::ALL.iter().position(|e| *e == engine).unwrap_or(0);
                let engine_syntax = &syntax::SYNTAX[idx];
                let rows: Vec<gpui::AnyElement> = engine_syntax
                    .rules
                    .iter()
                    .map(|rule| {
                        let text = rule.syntax.to_string();
                        div()
                            .id(SharedString::from(format!(
                                "rule-{}-{}",
                                engine_syntax.engine, rule.syntax
                            )))
                            .flex()
                            .items_center()
                            .gap_2()
                            .px_2()
                            .py_1()
                            .rounded_sm()
                            .cursor_pointer()
                            .hover(|s| s.bg(rgb(theme().row_hover)))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.query_input
                                    .update(cx, |input, cx| input.set_text(&text, cx));
                                cx.notify();
                            }))
                            .child(
                                div()
                                    .w(px(230.))
                                    .flex_shrink_0()
                                    .truncate()
                                    .text_size(px(12.))
                                    .text_color(rgb(theme().text))
                                    .child(rule.syntax),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .truncate()
                                    .text_size(px(11.))
                                    .text_color(rgb(theme().muted))
                                    .child(rule.desc),
                            )
                            .into_any_element()
                    })
                    .collect();
                sections.push(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(
                            div()
                                .text_size(px(13.))
                                .text_color(rgb(engine_syntax.accent))
                                .child(engine_syntax.engine),
                        )
                        .children(rows)
                        .into_any_element(),
                );
            }
        }

        let title = match mode {
            SearchMode::Aggregate => "测绘查询语法规则 — 公共语法（聚合引擎）".to_string(),
            SearchMode::Single(engine) => format!("测绘查询语法规则 — {}", engine.name()),
        };
        let header =
            div()
                .flex()
                .justify_between()
                .items_center()
                .text_size(px(15.))
                .child(title)
                .child(button("✕", false).id("rules-close").on_click(cx.listener(
                    |this, _, _, cx| {
                        this.show_rules = false;
                        cx.notify();
                    },
                )));

        let footer =
            div()
                .flex()
                .justify_between()
                .items_center()
                .mt_1()
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(rgb(theme().muted))
                        .child(match mode {
                            SearchMode::Aggregate => format!(
                                "聚合模式（参与：{}）：公共语法将自动转换为各引擎方言",
                                self.aggregate_engine_names()
                            ),
                            SearchMode::Single(engine) => {
                                format!("{} 原生语法，不做转换", engine.name())
                            }
                        }),
                )
                .child(button("关闭", false).id("rules-ok").on_click(cx.listener(
                    |this, _, _, cx| {
                        this.show_rules = false;
                        cx.notify();
                    },
                )));

        let scroll = div()
            .id("rules-scroll")
            .max_h(px(520.))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap_3()
            .pr_1()
            .children(sections);

        overlay("rules-overlay")
            .key_context("RulesOverlay")
            .on_action(cx.listener(|this, _: &CloseOverlay, _, cx| {
                this.show_rules = false;
                cx.notify();
            }))
            .child(panel(680.).child(header).child(scroll).child(footer))
    }
}

fn render_result_row(app: &OctoxApp, i: usize, view: Entity<OctoxApp>) -> impl IntoElement + use<> {
    let asset = &app.results[i];
    let selected = app.selected == Some(i) || app.multi_selected.contains(&i);
    let location = if asset.country == "-" {
        asset.city.clone()
    } else if asset.city == "-" {
        asset.country.clone()
    } else {
        format!("{} {}", asset.country, asset.city)
    };
    let mut row = div()
        .id(SharedString::from(format!("row-{i}")))
        .flex()
        .flex_row()
        .items_center()
        .h(px(26.))
        .px_2()
        .text_size(px(12.))
        .when(selected, |d| d.bg(rgba((theme().accent << 8) | 0x2a)))
        .when(!selected, |d| d.hover(|s| s.bg(rgb(theme().row_hover))))
        .on_click({
            let view = view.clone();
            move |event: &ClickEvent, _, cx| {
                let modifiers = event.modifiers();
                view.update(cx, |this, cx| {
                    this.close_context_menu(cx);
                    this.on_row_clicked(
                        i,
                        modifiers.control || modifiers.platform,
                        modifiers.shift,
                        cx,
                    );
                });
            }
        })
        // 右键弹出该行的上下文菜单（复制行数据 / 复制 / 打开 URL）。
        .on_mouse_down(MouseButton::Right, {
            let view = view.clone();
            move |event: &MouseDownEvent, _, cx| {
                view.update(cx, |this, cx| {
                    this.selected = Some(i);
                    this.open_context_menu(i, event.position, cx);
                });
            }
        });
    // 列顺序与表头一致，按设置的显示列渲染。
    for column in app.visible_columns() {
        let w = column.width;
        let element: gpui::AnyElement = match column.key {
            "engine" => engine_tag(asset.engine).into_any_element(),
            "host" => cell(&asset.host, w).into_any_element(),
            "ip" => cell(&asset.ip, w).into_any_element(),
            "port" => cell(&asset.port, w).into_any_element(),
            "protocol" => cell(&asset.protocol, w).into_any_element(),
            "title" => cell(&asset.title, app.title_width()).into_any_element(),
            "component" => cell(&asset.component, w).into_any_element(),
            "org" => cell(&asset.org, w).into_any_element(),
            "location" => cell(&location, w).into_any_element(),
            "time" => cell(&asset.updated_at, w).into_any_element(),
            _ => cell("-", w).into_any_element(),
        };
        row = row.child(element);
    }
    // 单引擎结果集：追加该引擎的特有字段列（缺失记 "-"）。
    for label in app.extra_columns() {
        let value = Asset::extras_lookup(asset, &label);
        row = row.child(cell(value, EXTRA_COL_WIDTH));
    }
    row
}

fn engine_tag(engine: Engine) -> impl IntoElement {
    let accent = engine.accent();
    div()
        .w(px(COL_ENGINE - 6.))
        .flex_shrink_0()
        .flex()
        .justify_center()
        .py(px(1.))
        .mr_1()
        .rounded_sm()
        .bg(rgba((accent << 8) | 0x2a))
        .text_color(rgb(accent))
        .text_size(px(11.))
        .child(engine.name())
}

/// 估算字符显示宽度（px @ 12px 字号）：CJK / 全角 ≈ 12，其余 ≈ 6.5。
fn char_width(c: char) -> f32 {
    const WIDE: [(u32, u32); 8] = [
        (0x1100, 0x115F),
        (0x2E80, 0xA4CF),
        (0xAC00, 0xD7A3),
        (0xF900, 0xFAFF),
        (0xFE30, 0xFE4F),
        (0xFF00, 0xFF60),
        (0xFFE0, 0xFFE6),
        (0x3000, 0x303F),
    ];
    let v = c as u32;
    if WIDE.iter().any(|(a, b)| v >= *a && v <= *b) {
        12.
    } else {
        6.5
    }
}

/// 按像素预算截断文本并补省略号——单元格文字永不越界（gpui 的
/// text_overflow 省略号在本表格场景不生效，改为渲染前确定性截断）。
fn clip_to_width(text: &str, max_px: f32) -> String {
    let ellipsis_w = 6.5;
    let mut width = 0.;
    let mut out = String::new();
    for c in text.chars() {
        let w = char_width(c);
        if width + w > max_px - ellipsis_w {
            out.push('…');
            return out;
        }
        width += w;
        out.push(c);
    }
    out
}

fn cell(text: &str, w: f32) -> impl IntoElement {
    div()
        .w(px(w))
        .flex_shrink_0()
        .min_w_0()
        // 列间留 8px 内边距，截断文字不会紧贴下一列造成“溢出”错觉。
        .pr_2()
        .truncate()
        .text_color(rgb(theme().text))
        .child(clip_to_width(text, w - 8.))
}

/// 可选中状态的小开关片（选中时用 accent 高亮）。调用方继续链 `.id(..).on_click(..)`。
fn select_chip(label: &str, selected: bool, accent: u32) -> Div {
    div()
        .flex()
        .items_center()
        .px_2()
        .py_1()
        .rounded_md()
        .text_size(px(12.))
        .cursor_pointer()
        .border_1()
        .border_color(rgb(if selected { accent } else { theme().border }))
        // 选中底色须用 rgba：rgb() 只取低 24 位，会把 alpha 字节截掉导致颜色整体错位。
        .bg(if selected {
            rgba((accent << 8) | 0x26)
        } else {
            rgba((theme().panel_alt << 8) | 0xff)
        })
        .text_color(rgb(if selected { accent } else { theme().muted }))
        .child(label.to_string())
}

/// 收藏夹内的小标签片。
fn tag_chip(label: &str) -> Div {
    div()
        .px_1()
        .rounded_sm()
        .text_size(px(10.))
        .text_color(rgb(theme().muted))
        .border_1()
        .border_color(rgb(theme().border))
        .child(label.to_string())
}

/// 小工具结果区的复制按钮片（调用方继续链 `.on_click(..)`）。
fn tool_copy_chip(id: &'static str, label: &str) -> Stateful<Div> {
    div()
        .id(id)
        .px_2()
        .py_1()
        .rounded_md()
        .text_size(px(12.))
        .cursor_pointer()
        .border_1()
        .border_color(rgb(theme().border))
        .bg(rgb(theme().panel_alt))
        .hover(|s| s.border_color(rgb(theme().accent)))
        .child(label.to_string())
}

impl Render for OctoxApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        // 响应式依据：每帧记录窗口尺寸，供列收纳 / 按钮收纳 / 弹窗定位。
        let viewport = window.viewport_size();
        self.viewport_width = f32::from(viewport.width);
        self.viewport_height = f32::from(viewport.height);
        div()
            .relative()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(theme().bg))
            .text_color(rgb(theme().text))
            .font_family("Segoe UI")
            .child(self.render_header(cx))
            .child(self.render_search_bar(cx))
            .child(self.render_search_details(cx))
            .child(self.render_results(cx))
            .child(self.render_detail(cx))
            .child(self.render_status_bar(cx))
            .children(self.show_rules.then(|| self.render_rules_overlay(cx)))
            .children(self.show_settings.then(|| self.render_settings_overlay(cx)))
            .children(
                self.show_favorites
                    .then(|| self.render_favorites_manager(cx)),
            )
            .children(self.show_fav_dialog.then(|| self.render_fav_dialog(cx)))
            .children(self.show_tools.then(|| self.render_tools_dialog(cx)))
            .children(
                self.show_engine_drawer
                    .is_some()
                    .then(|| self.render_engine_drawer(cx)),
            )
            .child(self.render_context_menu(cx))
            .child(self.render_toasts(cx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip_keeps_short_text() {
        assert_eq!(clip_to_width("abc", 100.), "abc");
        assert_eq!(clip_to_width("", 100.), "");
        assert_eq!(clip_to_width("短文本", 100.), "短文本");
    }

    #[test]
    fn clip_truncates_with_ellipsis_at_budget() {
        let long = "a".repeat(100);
        let clipped = clip_to_width(&long, 100.);
        assert!(clipped.ends_with('…'));
        // 截断后宽度不超过预算（省略号计入）
        let width: f32 = clipped.chars().map(char_width).sum();
        assert!(width <= 100. + 0.01, "width {width}");
        // CJK 按两倍宽计费：同样预算下字符数更少
        let cjk = "测".repeat(100);
        let clipped = clip_to_width(&cjk, 100.);
        assert!(clipped.chars().count() <= 8 + 1);
    }
}
