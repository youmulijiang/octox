//! GUI 与 MCP 共用的查询准备、分页判定与会话缓存。
use crate::{asset::Engine, config::Config, engines::SearchResult, translate};
use std::collections::BTreeMap;

pub struct SearchPlan {
    pub queries: Vec<(Engine, Result<String, String>)>,
}

impl SearchPlan {
    pub fn cache_key(config: &Config, query: &str, single: Option<Engine>) -> String {
        let mut settings = serde_json::to_value(config).expect("config serialization");
        if let Some(object) = settings.as_object_mut() {
            for key in [
                "favorites",
                "theme",
                "columns",
                "mcp_enabled",
                "mcp_port",
                "max_pages",
                "request_delay_secs",
            ] {
                object.remove(key);
            }
        }
        format!("{query}\n{single:?}\n{settings}")
    }

    /// None 明确表示公共语法聚合模式，即使只启用一个引擎。
    pub fn prepare(config: &Config, query: &str, single: Option<Engine>) -> Result<Self, String> {
        if query.trim().is_empty() {
            return Err("请输入查询语句".into());
        }
        let parsed = if single.is_none() {
            Some(
                translate::parse_common(query)
                    .map_err(|e| format!("聚合搜索仅支持公共语法：{e}"))?,
            )
        } else {
            None
        };
        let engines: Vec<_> = single.map(|e| vec![e]).unwrap_or_else(|| {
            Engine::ALL
                .iter()
                .copied()
                .filter(|e| config.aggregate_engines[e.index()])
                .collect()
        });
        if engines.is_empty() {
            return Err("聚合模式没有参与引擎，请在设置中勾选".into());
        }
        let queries = engines
            .into_iter()
            .map(|e| {
                let q = if !config.creds_ready(e) {
                    Err("未配置凭证（右上角设置）".into())
                } else if let Some(node) = &parsed {
                    translate::render(node, e)
                } else {
                    Ok(query.to_owned())
                };
                (e, q)
            })
            .collect();
        Ok(Self { queries })
    }
}

pub fn has_more(engine: Engine, result: &SearchResult, page: u32, size: u32) -> bool {
    if engine.uses_cursor() {
        return result.next_cursor.is_some();
    }
    !result.assets.is_empty() && (page as u64) * (engine.effective_size(size) as u64) < result.total
}

#[derive(Default)]
pub struct PageCache {
    key: String,
    pages: [BTreeMap<u32, SearchResult>; Engine::COUNT],
}
impl PageCache {
    pub fn reset_if_changed(&mut self, key: String) -> bool {
        if self.key == key {
            return false;
        }
        self.key = key;
        self.pages.iter_mut().for_each(BTreeMap::clear);
        true
    }
    pub fn get(&self, engine: Engine, page: u32) -> Option<&SearchResult> {
        self.pages[engine.index()].get(&page)
    }
    pub fn insert(&mut self, engine: Engine, page: u32, result: SearchResult) {
        self.pages[engine.index()].insert(page, result);
    }
    pub fn clear(&mut self) {
        self.key.clear();
        self.pages.iter_mut().for_each(BTreeMap::clear);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn settings_key_ignores_appearance_but_tracks_search_parameters() {
        let mut c = Config::default();
        let key = SearchPlan::cache_key(&c, "port=80", None);
        c.theme = "light".into();
        assert_eq!(key, SearchPlan::cache_key(&c, "port=80", None));
        c.page_size = 50;
        assert_ne!(key, SearchPlan::cache_key(&c, "port=80", None));
        assert_ne!(
            key,
            SearchPlan::cache_key(&c, "port=80", Some(Engine::Fofa))
        );
    }

    #[test]
    fn aggregate_with_one_engine_still_translates() {
        let mut c = Config::default();
        c.aggregate_engines = [false; Engine::COUNT];
        c.aggregate_engines[Engine::Quake.index()] = true;
        c.quake.token = "test".into();
        let p = SearchPlan::prepare(&c, "port=443", None).unwrap();
        assert_eq!(p.queries[0].1.as_ref().unwrap(), "port:443");
        assert!(SearchPlan::prepare(&c, "port:443", None).is_err());
        assert_eq!(
            SearchPlan::prepare(&c, "port:443", Some(Engine::Quake))
                .unwrap()
                .queries[0]
                .1
                .as_ref()
                .unwrap(),
            "port:443"
        );
    }
    #[test]
    fn cursor_controls_pagination_even_without_total() {
        let r = SearchResult {
            total: 0,
            assets: vec![],
            quota: None,
            next_cursor: Some("next".into()),
        };
        assert!(has_more(Engine::VirusTotal, &r, 1, 20));
        assert!(!has_more(Engine::Fofa, &r, 1, 20));
    }
    #[test]
    fn changing_query_clears_cached_pages() {
        let mut c = PageCache::default();
        assert!(c.reset_if_changed("a".into()));
        c.insert(
            Engine::VirusTotal,
            1,
            SearchResult {
                total: 0,
                assets: vec![],
                quota: None,
                next_cursor: Some("a".into()),
            },
        );
        assert!(!c.reset_if_changed("a".into()));
        assert!(c.get(Engine::VirusTotal, 1).is_some());
        assert!(c.reset_if_changed("b".into()));
        assert!(c.get(Engine::VirusTotal, 1).is_none());
    }
}
