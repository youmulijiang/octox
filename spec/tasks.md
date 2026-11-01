# Octox 任务清单（tasks.md）

> 实现顺序即依赖顺序；每阶段完成后勾选。

## Phase 1 基础设施
- [x] T1.1 初始化 cargo 项目，接入 gpui（crates.io）
- [x] T1.2 核对 gpui vendored API（open_window/Render/spawn/KeyStroke/Clipboard）
- [x] T1.3 接入 serde/serde_json/ureq/csv/chrono/dirs/futures

## Phase 2 领域层（无 UI，可独立测试）
- [x] T2.1 `asset.rs`：Engine 枚举 + 统一 Asset 模型
- [x] T2.2 `config.rs`：配置加载/保存/默认生成
- [x] T2.3 `engines/fofa.rs` + fixture 单测
- [x] T2.4 `engines/hunter.rs` + fixture 单测
- [x] T2.5 `engines/quake.rs` + fixture 单测
- [x] T2.6 `export.rs`：CSV(BOM)/JSON 导出 + 单测

## Phase 3 UI 层
- [x] T3.1 `ui/input.rs`：可编辑单行输入（焦点/光标/粘贴/Enter 提交）
- [x] T3.2 `ui/mod.rs`：主题与按钮/开关片组件
- [x] T3.3 `app.rs`：整体布局 + 搜索编排（多引擎并发、代际防串扰）
- [x] T3.4 结果表 + 选中详情 + 分页
- [x] T3.5 设置覆盖层（凭证读写回填）
- [x] T3.6 状态栏（加载/错误/配额）

## Phase 4 验证
- [x] T4.1 `cargo build` 通过（Windows/MSVC）
- [x] T4.2 `cargo test` 全绿
- [x] T4.3 `--smoke` 启动自检通过
- [ ] T4.4 人工验收：填入真实 Key 查询三平台（需用户 Key）

## 变更记录
- v1.0（2026-10-31）：初版规格与全部 Phase 1–3 实现落地；T4.4 待用户以真实 Key 验收。
- v1.1（2026-10-31）：搜索栏改版 —
  - 引擎选项卡 → 搜索框左侧多选下拉框（独立组件 `ui/dropdown.rs`，`Changed` 事件解耦）
  - 输入框右侧新增「规则」按钮：三引擎语法速查弹层（数据源 `ui/syntax.rs`，点语法行直接填入）
  - 新增「收藏」按钮：收藏当前语句 / 收藏夹查看 / 填入 / 删除，持久化于 `config.favorites`
  - 搜索框自动补全弹层：字段名 + 常用值两级补全，↑↓ 选择、Enter/Tab 接受（纯逻辑 `autocomplete.rs`，含单测）
  - SVG 图标经 `include_bytes!` 内嵌（`ui/icons.rs` 资产源 + `AssetSource` 注册）
  - 弹层用 `deferred()` 延迟绘制置顶；模态壳抽为 `ui/modal.rs` 复用；单测 21 项全绿
- v1.2（2026-10-31）：聚合搜索 —
  - 下拉框与文本框合并为连体输入组控件（输入框新增 `plain` 模式嵌入共享边框容器）
  - 新增 `translate.rs`：公共语法（字段交集 + &&/||）解析为 AST 并按引擎方言渲染，
    ISO2 国家码自动映射 Quake 国家中文名/英文名，FOFA os 值自动首字母大写
  - 聚合模式（≥2 引擎）搜索前统一校验公共语法，失败即阻止并提示；单引擎模式直通原生语法
  - 规则弹层跟随所选引擎过滤；聚合模式下顶部展示「公共语法」节
  - 补全字典按模式切换（聚合=仅公共字段；单引擎=完整字典）；单测 28 项全绿
- v1.3（2026-10-31）：模式单选化 —
  - 下拉框由多选引擎改为单选模式：FOFA / Hunter / Quake / 聚合引擎 四选一
  - 选哪个引擎就用哪个引擎原生语法搜索；规则弹层只显示该引擎的完整语法（标题注明引擎）
  - 「聚合引擎」模式的参与引擎在设置中配置（aggregate_engines，默认全部，至少保留一个，即时保存）
  - 聚合模式规则弹层仅显示公共语法节，页脚提示参与引擎列表；单测 28 项全绿
