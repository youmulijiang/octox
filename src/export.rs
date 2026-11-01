use std::io::Write;
use std::path::PathBuf;

use crate::asset::Asset;

pub const HEADERS: [&str; 14] = [
    "引擎",
    "Host",
    "IP",
    "端口",
    "协议",
    "标题",
    "组件",
    "组织",
    "国家",
    "城市",
    "状态码",
    "更新时间",
    "URL",
    "域名",
];

/// 所有资产扩展字段标签的并集（保序）。
fn extra_labels(assets: &[Asset]) -> Vec<String> {
    let mut labels: Vec<String> = Vec::new();
    for a in assets {
        for (label, _) in &a.extras {
            if !labels.contains(label) {
                labels.push(label.clone());
            }
        }
    }
    labels
}

fn row(a: &Asset) -> [String; 14] {
    [
        a.engine.name().to_string(),
        a.host.clone(),
        a.ip.clone(),
        a.port.clone(),
        a.protocol.clone(),
        a.title.clone(),
        a.component.clone(),
        a.org.clone(),
        a.country.clone(),
        a.city.clone(),
        a.status_code.clone(),
        a.updated_at.clone(),
        a.url.clone(),
        a.domain.clone(),
    ]
}

fn default_exports_dir() -> PathBuf {
    dirs::document_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("octox-exports")
}

/// 导出 CSV（UTF-8 with BOM，Excel 直接打开不乱码）。
pub fn export_csv(assets: &[Asset]) -> std::io::Result<PathBuf> {
    export_csv_to(default_exports_dir(), assets)
}

pub fn export_csv_to(dir: PathBuf, assets: &[Asset]) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!(
        "octox-{}.csv",
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    ));
    let mut file = std::fs::File::create(&path)?;
    file.write_all(&[0xEF, 0xBB, 0xBF])?;
    let mut writer = csv::Writer::from_writer(file);
    let labels = extra_labels(assets);
    writer.write_record(
        HEADERS
            .iter()
            .copied()
            .chain(labels.iter().map(String::as_str)),
    )?;
    for a in assets {
        let base = row(a);
        let mut record: Vec<String> = base.into_iter().collect();
        record.extend(
            labels
                .iter()
                .map(|label| a.extras_lookup(label).to_string()),
        );
        writer.write_record(&record)?;
    }
    writer.flush()?;
    Ok(path)
}

/// 导出 JSON。
pub fn export_json(assets: &[Asset]) -> std::io::Result<PathBuf> {
    export_json_to(default_exports_dir(), assets)
}

pub fn export_json_to(dir: PathBuf, assets: &[Asset]) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!(
        "octox-{}.json",
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    ));
    std::fs::write(
        &path,
        serde_json::to_string_pretty(assets).expect("serialize assets"),
    )?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::Engine;

    fn sample() -> Vec<Asset> {
        let mut a = Asset::empty(Engine::Fofa);
        a.host = "example.com:8080".into();
        a.ip = "1.2.3.4".into();
        a.port = "8080".into();
        a.title = "标题,含逗号".into();
        vec![a]
    }

    #[test]
    fn csv_export_writes_bom_and_rows() {
        let dir = std::env::temp_dir().join(format!("octox-test-csv-{}", std::process::id()));
        let path = export_csv_to(dir, &sample()).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.starts_with(&[0xEF, 0xBB, 0xBF]));
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("引擎,Host,IP,端口"));
        assert!(text.contains("标题,含逗号"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn json_export_round_trips() {
        let dir = std::env::temp_dir().join(format!("octox-test-json-{}", std::process::id()));
        let path = export_json_to(dir, &sample()).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let back: Vec<Asset> = serde_json::from_str(&text).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].ip, "1.2.3.4");
        std::fs::remove_file(&path).ok();
    }
}
