//! 三引擎查询语法速查数据（纯数据，供「规则」弹层展示与测试）。
//!
//! 规则按各平台官方语法文档整理；单引擎模式下查询语句原样透传，
//! 因此这里覆盖得越全，单引擎模式可用的语法就越多。

pub struct SyntaxRule {
    pub syntax: &'static str,
    pub desc: &'static str,
}

pub struct EngineSyntax {
    pub engine: &'static str,
    pub accent: u32,
    pub rules: &'static [SyntaxRule],
}

macro_rules! rule {
    ($s:expr, $d:expr) => {
        SyntaxRule {
            syntax: $s,
            desc: $d,
        }
    };
}

pub const SYNTAX: &[EngineSyntax] = &[
    EngineSyntax {
        engine: "FOFA",
        accent: 0xe0503a,
        rules: &[
            rule!("app=\"weblogic\"", "组件名"),
            rule!("title=\"登录\"", "网页标题"),
            rule!("body=\"后台管理\"", "网页正文关键词"),
            rule!("header=\"Server: nginx\"", "HTTP 响应头内容"),
            rule!("ip=\"1.2.3.0/24\"", "IP 或 CIDR 网段"),
            rule!("port=7001", "端口"),
            rule!("host=\"example.com\"", "主机名（域名或 IP）"),
            rule!("domain=\"qq.com\"", "域名及子域名"),
            rule!("protocol=\"https\"", "协议"),
            rule!("server=\"nginx\"", "HTTP Server 响应头"),
            rule!("status_code=\"404\"", "HTTP 状态码"),
            rule!("cert=\"baidu\"", "证书内容模糊匹配"),
            rule!("cert.subject=\"example.com\"", "证书主题"),
            rule!("cert.issuer=\"DigiCert\"", "证书颁发者"),
            rule!("icon_hash=\"-247530517\"", "favicon 图标 hash"),
            rule!("os=\"Windows\"", "操作系统"),
            rule!("country=\"CN\"", "国家/地区码"),
            rule!("region=\"Hebei\"", "州/省"),
            rule!("city=\"Beijing\"", "城市"),
            rule!("org=\"Tencent\"", "组织/单位"),
            rule!("isp=\"China Telecom\"", "运营商"),
            rule!("as_number=4134", "ASN 编号"),
            rule!("as_organization=\"CERNET\"", "ASN 组织"),
            rule!("icp=\"京ICP备xxxx号\"", "ICP 备案号"),
            rule!("fid=\"sV3f9hB1sB\"", "网站指纹"),
            rule!("js_name=\"jquery\"", "JS 代码文件名"),
            rule!("js_md5=\"xxxx\"", "JS 代码 MD5"),
            rule!("cname=\"xxx.cloudflare.com\"", "CNAME 记录"),
            rule!("cloud_name=\"Aliyun\"", "云服务名"),
            rule!("banner=\"SSH-2.0\"", "非 HTTP 服务横幅"),
            rule!("type=\"subdomain\"", "数据类型（subdomain/av/service…）"),
            rule!("is_domain=true", "是否解析出域名"),
            rule!("is_ipv6=true", "是否 IPv6"),
            rule!("is_cloud=true", "是否云上资产"),
            rule!("is_fraud=false", "排除诈骗/仿冒"),
            rule!("is_honeypot=false", "排除蜜罐"),
            rule!("ip_ports=\"80,443/24\"", "IP 关联端口组合"),
            rule!("port_size=\"2\"", "开放端口数量"),
            rule!("after=\"2026-01-01\"", "更新时间晚于（before 为早于）"),
            rule!("a && b / a || b / !a", "逻辑组合：与 / 或 / 非"),
        ],
    },
    EngineSyntax {
        engine: "Hunter 鹰图",
        accent: 0x3f8cff,
        rules: &[
            rule!("web.title=\"后台\"", "网页标题"),
            rule!("web.body=\"登录\"", "网页正文"),
            rule!("web.header=\"nginx\"", "HTTP 响应头内容"),
            rule!("web.icon=\"xxxx\"", "favicon 图标 hash"),
            rule!("ip=\"1.2.3.4\"", "IP，支持网段"),
            rule!("\"1.2.3.4:80\"", "ip:port 组合"),
            rule!("port=\"80\"", "端口"),
            rule!("protocol=\"https\"", "协议"),
            rule!("hostname=\"www.example.com\"", "主机名"),
            rule!("domain=\"a.qq.com\"", "完整域名/子域名"),
            rule!("domain.suffix=\"qq.com\"", "主域名"),
            rule!("app.name=\"Nginx\"", "组件名"),
            rule!("app.version=\"1.2\"", "组件版本"),
            rule!("app.category=\"服务器\"", "组件分类"),
            rule!("header.server=\"nginx\"", "HTTP 响应头字段"),
            rule!("http.status=\"200\"", "HTTP 状态码"),
            rule!("banner=\"SSH-2.0\"", "服务横幅"),
            rule!("cert=\"baidu\"", "证书模糊匹配"),
            rule!("cert.subject=\"example.com\"", "证书主题"),
            rule!("cert.issuer=\"DigiCert\"", "证书颁发者"),
            rule!("cert.sn=\"xxxx\"", "证书序列号"),
            rule!("os=\"windows\"", "操作系统"),
            rule!("country=\"CN\"", "国家/地区码"),
            rule!("ip.province=\"浙江\"", "省份"),
            rule!("ip.city=\"杭州\"", "城市"),
            rule!("ip.company=\"Alibaba\"", "公司/单位"),
            rule!("ip.isp=\"移动\"", "运营商"),
            rule!("asn=\"4837\"", "ASN 编号"),
            rule!("isipv6=\"true\"", "是否 IPv6"),
            rule!("iscloud=\"true\"", "是否云上资产"),
            rule!("after=\"2026-01-01\"", "更新时间晚于（before 为早于）"),
            rule!("a && b / a || b", "逻辑组合：与 / 或"),
        ],
    },
    EngineSyntax {
        engine: "Quake 360",
        accent: 0xf0a030,
        rules: &[
            rule!("response:\"weblogic\"", "原始响应内容"),
            rule!("title:\"后台\"", "网页标题"),
            rule!("app:\"Nginx\"", "组件名"),
            rule!("cat:\"CMS\"", "服务分类"),
            rule!("service:http", "服务类型"),
            rule!("port:7001", "端口"),
            rule!("ip:\"1.2.3.4\"", "IP"),
            rule!("hostname:\"example.com\"", "主机名"),
            rule!("domain:\"qq.com\"", "域名"),
            rule!("favicon:\"740352133\"", "favicon 图标 hash"),
            rule!("cert:\"baidu\"", "证书模糊匹配"),
            rule!("cert.subject.cn:\"example.com\"", "证书主题 CN"),
            rule!("cert.issuer.org:\"DigiCert\"", "证书颁发者组织"),
            rule!(
                "country:\"China\"",
                "国家（亦可用 location.country_cn:\"中国\"）"
            ),
            rule!("province:\"Zhejiang\"", "省份"),
            rule!("city:\"Hangzhou\"", "城市"),
            rule!("owner:\"Alibaba\"", "单位/组织"),
            rule!("isp:\"电信\"", "运营商"),
            rule!("os:\"windows\"", "操作系统"),
            rule!("server:\"nginx\"", "HTTP Server"),
            rule!("http_status:\"200\"", "HTTP 状态码"),
            rule!("is_ipv6:\"true\"", "是否 IPv6"),
            rule!("is_cloud:\"true\"", "是否云上资产"),
            rule!("after:\"2026-01-01\"", "更新时间晚于（before 为早于）"),
            rule!("AND / OR / NOT", "逻辑组合（大写）"),
        ],
    },
    EngineSyntax {
        engine: "Shodan",
        accent: 0xd94f88,
        rules: &[
            rule!("ip:1.2.3.4", "IP"),
            rule!("port:80", "端口"),
            rule!("hostname:example.com", "主机名"),
            rule!("product:nginx", "产品/组件"),
            rule!("org:\"Google LLC\"", "组织"),
            rule!("country:CN", "国家（ISO2）"),
            rule!("city:\"Beijing\"", "城市"),
            rule!("os:Windows", "操作系统"),
            rule!("http.title:\"后台\"", "网页标题"),
            rule!("http.status:200", "HTTP 状态码"),
            rule!("asn:AS4134", "ASN"),
            rule!("a && b / a || b / !a", "逻辑组合：与 / 或 / 非"),
        ],
    },
    EngineSyntax {
        engine: "ZoomEye",
        accent: 0x2fbfa5,
        rules: &[
            rule!("ip:1.2.3.4", "IP"),
            rule!("port:80", "端口"),
            rule!("site:example.com", "站点/域名"),
            rule!("title:\"后台\"", "网页标题"),
            rule!("app:\"Nginx\"", "组件"),
            rule!("service:http", "服务类型"),
            rule!("country:cn", "国家"),
            rule!("os:windows", "操作系统"),
            rule!("after:\"2026-01-01\"", "更新时间晚于（before 为早于）"),
            rule!("iconhash:\"xxxx\"", "favicon 图标 hash"),
            rule!("a && b / a || b", "逻辑组合：与 / 或"),
        ],
    },
    EngineSyntax {
        engine: "ThreatBook",
        accent: 0x8a63f0,
        rules: &[
            rule!("ip=\"1.1.1.1\"", "IP（正向锚点，每个分支需含 =）"),
            rule!("domain=\"qq.com\"", "域名"),
            rule!("app=\"weblogic\"", "组件"),
            rule!("country=\"中国\"", "国家"),
            rule!("title=\"后台\"", "网页标题"),
            rule!("cert=\"DigiCert\"", "证书"),
            rule!("asn=\"AS4134\"", "ASN"),
            rule!("a && b / a || b", "逻辑组合：与 / 或"),
        ],
    },
    EngineSyntax {
        engine: "0.zone",
        accent: 0x4caf6e,
        rules: &[
            rule!("domain===\"qq.com\"", "域名（=== 逐字符匹配，双引号包裹）"),
            rule!("ip===\"1.2.3.4\"", "IP"),
            rule!("port===\"443\"", "端口"),
            rule!("title===\"后台\"", "标题"),
            rule!("html_banner===\"__next\"", "HTML 横幅"),
            rule!(
                "site / domain / apk / email / code",
                "搜索类型（title_type）"
            ),
        ],
    },
    EngineSyntax {
        engine: "DayDayMap",
        accent: 0xb8863b,
        rules: &[
            rule!("ip=\"1.1.1.1\"", "IP"),
            rule!("port=\"80\"", "端口"),
            rule!("domain=\"qq.com\"", "域名"),
            rule!("title=\"后台\"", "网页标题"),
            rule!("service=\"http\"", "服务类型"),
            rule!("a && b", "逻辑组合（page × size ≤ 10000）"),
        ],
    },
    EngineSyntax {
        engine: "VirusTotal",
        accent: 0x5c6bc0,
        rules: &[
            rule!("entity:ip_addresses ip:1.2.3.4", "IP 实体"),
            rule!("entity:domains domain:qq.com", "域名实体"),
            rule!("entity:files p:443+", "文件实体（需 Intelligence 订阅）"),
            rule!("crowdsourced IDS rules", "社区 IDS 规则数"),
        ],
    },
    EngineSyntax {
        engine: "Censys",
        accent: 0x26a0c4,
        rules: &[
            rule!("ip:1.2.3.4", "IP"),
            rule!("services.port: 443", "端口（字段路径式）"),
            rule!("services.service_name: HTTP", "服务名"),
            rule!("dns.names: example.com", "主机名/域名"),
            rule!("services.http.response.html_title: \"后台\"", "网页标题"),
            rule!("autonomous_system.description: \"GOOGLE\"", "ASN 组织"),
            rule!("location.country: \"United States\"", "国家（英文全名）"),
            rule!("services.software: nginx", "软件/组件"),
            rule!("a and b / a or b / not a", "逻辑组合（and / or / not）"),
        ],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engines_have_expanded_rules() {
        // 与 Engine::ALL 对齐：10 个引擎各有一套原生语法速查。
        assert_eq!(SYNTAX.len(), 10);
        // 对齐官方语法后的规则数量应明显多于最初版本。
        assert!(SYNTAX[0].rules.len() >= 30);
        assert!(SYNTAX[1].rules.len() >= 25);
        assert!(SYNTAX[2].rules.len() >= 20);
        for engine in &SYNTAX[3..] {
            assert!(!engine.rules.is_empty());
        }
    }

    #[test]
    fn rules_have_unique_syntax_within_engine() {
        for engine in SYNTAX {
            let mut seen = std::collections::HashSet::new();
            for r in engine.rules {
                assert!(seen.insert(r.syntax), "duplicate rule {}", r.syntax);
            }
        }
    }
}
