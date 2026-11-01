# Octox 设计文档（design.md）

## 1. 总体架构

```
┌──────────────────────────── GPUI 主线程（UI 实体树） ───────────────────────────┐
│  OctoxApp (Render)                                                             │
│   ├─ SearchInput  ×N（查询框 + 设置面板各输入框，FocusHandle + 键盘编辑）          │
│   ├─ ResultsTable（统一资产表，overflow_y_scroll）                                │
│   ├─ SettingsOverlay（条件渲染的模态覆盖层）                                       │
│   └─ StatusBar（加载/错误/配额/分页）                                              │
│        │ cx.spawn(每引擎一个 Task)                                                │
│        ▼ AsyncApp.update(this, ...) 回写实体状态                                  │
│  GPUI BackgroundExecutor（线程池）: engine.run(...) —— 同步 HTTP（ureq）          │
└────────────────────────────────────────────────────────────────────────────────┘
```

- **UI 单向数据流**：用户事件 → `OctoxApp` 状态变更 → `cx.notify()` 重绘。
- **并发模型**：每次搜索为每个启用引擎派生一个 `cx.spawn` 任务；HTTP 用同步
  `ureq` 在 `background_executor` 线程执行；完成后 `this.update()` 回写。
  旧结果用 `search_generation` 计数器丢弃。
- **无 Action/KeyBinding 复杂度**：按钮用 `on_click`，键盘在获得焦点的输入组件内处理。

## 2. 模块划分

| 模块 | 职责 |
|---|---|
| `main.rs` | 启动 Application、开窗、`--smoke` 自检退出 |
| `asset.rs` | 统一资产模型 `Asset`、`Engine` 枚举（着色/命名） |
| `config.rs` | `Config`（三引擎凭证 + 偏好），加载/保存 `%APPDATA%/octox/config.json` |
| `engines/mod.rs` | `SearchResult{total,assets,quota}`、分页归一化、并发入口 |
| `engines/fofa.rs` | FOFA `/api/v1/search/all` 客户端（qbase64 + fields 顺序解析） |
| `engines/hunter.rs` | Hunter `/openApi/search` 客户端（search JSON + code!=200 错误） |
| `engines/quake.rs` | Quake `/api/v3/search/quake_service` 客户端（POST + X-QuakeToken） |
| `export.rs` | CSV（BOM）/ JSON 导出 |
| `ui/mod.rs` | 主题（暗色）与通用小组件（按钮/开关片） |
| `ui/input.rs` | 单行文本输入组件（焦点、光标编辑、粘贴、Enter 提交事件） |
| `app.rs` | 根视图：布局、搜索编排、设置面板、分页、导出 |

依赖：`gpui`（crates.io）、`serde`/`serde_json`、`ureq`(json) 、`csv`、`chrono`、`dirs`、`futures`（join_all）。

## 3. 引擎 API 契约

统一入参：`query`（各引擎原生语法）、`page`（1 起）、`size`（10–100）。
统一出参：`SearchResult { total: u64, assets: Vec<Asset>, quota: Option<String> }`。

### 3.1 FOFA
- `GET https://fofa.info/api/v1/search/all`
- 参数：`email`、`key`、`qbase64` = base64(query)、`page`、`size`、
  `fields=host,ip,port,title,domain,protocol,server,org,country,city,lastupdatetime`
- 响应：`{"error":false,"size":<total>,"results":[[f0,f1,...],...]}`；
  `{"error":true,"errmsg":"..."}` 为失败。解析按 fields 顺序取数组下标。

### 3.2 Hunter（鹰图）
- `GET https://hunter.qianxin.com/openApi/search`
- 参数：`api-key`；`search` = URL 编码 JSON `{"query":"...","start":<页码,1 起>,"limit":<size>}`；
  附 `is_web_search=3`（全部资产）。
- 响应：`{"code":200,"data":{"total":N,"rest_quota":"...","arr":[{ip,port,domain,
  protocol,host,path,url,web_title,component:[[name,ver],...],status_code,updated_at}]}}`；
  `code!=200` 时 `message` 为错误文本。

### 3.3 Quake（360）
- `POST https://quake.360.net/api/v3/search/quake_service`，头 `X-QuakeToken`。
- 体：`{"query":"...","start":<(page-1)*size>,"size":<size>,"latest":true}`
- 响应：`{"code":0,"data":[{ip,port,hostname,transport,service:{name,http:{title,
  server,status_code}},location:{country_cn,city_cn},timestamp,org}]}`、
  `"meta":{"pagination":{"count":n,"total":N}}`；`code!=0` 时 `message` 为错误文本。

### 3.4 统一资产模型

```rust
pub struct Asset {
    pub engine: Engine, pub host: String, pub ip: String, pub port: String,
    pub protocol: String, pub title: String, pub domain: String,
    pub component: String, pub org: String, pub country: String, pub city: String,
    pub status_code: String, pub updated_at: String, pub url: String,
}
```
所有字段 `String`，缺失统一置 `-`，渲染与导出零分支。

## 4. 配置文件

路径：`dirs::config_dir()/octox/config.json`（Windows: `%APPDATA%\octox\config.json`）。

```json
{
  "fofa":   { "email": "", "key": "" },
  "hunter": { "api_key": "" },
  "quake":  { "token": "" },
  "page_size": 20
}
```

首次运行自动生成默认配置；字段缺失时按 serde 默认值兜底。

## 5. UI 布局（1280×800 暗色）

```
┌ Header:  🐙 Octox — 测绘引擎聚合搜索          [导出CSV] [导出JSON] [⚙ 设置] ┐
├ Search:  [ 输入查询语句…                        ] (F)(H)(Q) [20/页] [🔍 搜索] ┤
├ Table header: 引擎 | Host | IP | 端口 | 协议 | 标题 | 组件 | 组织 | 位置 | 更新时间 ┤
├ Rows (overflow_y_scroll, hover 高亮, 点击选中)                                  ┤
├ Detail: 选中行的 url / component / status_code / updated_at                     ┤
└ StatusBar: 状态·错误·配额(FOFA/Hunter/Quake)      ‹ 上一页 | 第 N 页 | 下一页 ›   ┘
```

- 引擎色：FOFA `#e0503a`、Hunter `#3f8cff`、Quake `#f0a030`；主色 `#4f8cff`，
  背景 `#0f1318` / 面板 `#171c23`，文字 `#d6dee6` / 弱化 `#7f8b99`。
- 设置覆盖层：绝对定位 + 半透明遮罩 `occlude()`，Esc 或取消关闭。

## 6. 错误处理

| 场景 | 行为 |
|---|---|
| 查询为空 / 全部引擎未启用 | 状态栏提示，不发起请求 |
| HTTP/超时错误 | `Result` 左值 → 状态栏 `引擎名: 错误`，其余引擎照常 |
| 平台业务错误（error/code） | 同上，附带平台 message（含配额不足） |
| JSON 解析失败 | 同上，保留原始截断摘要（前 120 字符） |

## 7. 风险与缓解

| 风险 | 缓解 |
|---|---|
| GPUI Windows 端成熟度 / API 快速演进 | 锁定 crates.io 发布版；以 vendored 源码为准写代码；`--smoke` 自检启动路径 |
| 输入法（IME） | v1 支持粘贴，IME 列入后续版本（gpui `EntityInputHandler`） |
| 平台返回结构变化 | serde 宽松解析（`Value` 导航 + 默认值），解析失败给出可读错误 |
|Hunter start 语义文档不可在线核验 | 实现为页码（1 起）并在代码注释标注来源与验证方法 |

## 8. 测试策略

- 单测（无需网络）：qbase64 编码、Hunter search 参数序列化、Quake 分页偏移、
  三引擎响应解析（内嵌 fixture JSON）、CSV 导出内容。
- 冒烟：`--smoke` 开窗 3 秒自退，验证 GPUI Windows 渲染栈可启动。
