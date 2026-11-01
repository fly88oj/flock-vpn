//! Golden-file 配置生成测试（R8/R12；docs/design.md §3.9 接缝 / §7-M2 完成标准）。
//!
//! - **R8（双栈自举）**：同一 crate 内两套独立生成器（ChmlFrp INI / 原版 TOML），
//!   各自与官方发行包样本比对；
//! - **R12（合规红线）**：面板生成的 proxy 参数逐字段/逐字节透传——服务端 CheckProxy
//!   与面板记录逐项比对，不一致即拒（frp-compat §2.3）；admin 注入只许碰 `[common]`。
//!
//! golden 样本逐字节复制自（`.tmp` 在 gitignore 内，故入库于本目录）：
//! - `chmlfrp_panel.frpc.ini` ← `.tmp/chmlfrpc/ChmlFrp-0.51.2_251023_linux_amd64/frpc.ini`
//!   （面板/发行包 v0.51.2 INI 方言；磁盘形态 CRLF 系 Windows 侧解包所致，对比按行尾归一）；
//! - `original.frpc.toml` ← `.tmp/frp_0.71.1_linux_amd64/frpc.toml`（v0.71.1 TOML 方言）。

use chml_frpc::config::{
    augment_chmlfrp_admin, parse_ini, ChmlFrpIniConfig, OriginalTomlConfig, WebServerSection,
};
use chml_frpc::AdminCommon;

const GOLDEN_INI: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/chmlfrp_panel.frpc.ini"
);
const GOLDEN_TOML: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/original.frpc.toml"
);

/// 行尾归一（CRLF → LF）：INI 样本磁盘形态为 CRLF，生成器 canonical 输出为 LF。
fn normalize(text: &str) -> String {
    text.replace("\r\n", "\n")
}

fn golden_ini() -> String {
    normalize(&std::fs::read_to_string(GOLDEN_INI).expect("golden INI 样本在位"))
}

fn golden_toml() -> String {
    normalize(&std::fs::read_to_string(GOLDEN_TOML).expect("golden TOML 样本在位"))
}

// ---------------------------------------------------------------------------
// ChmlFrp INI（R8：`ChmlFrpIniConfig` ↔ 官方样本）
// ---------------------------------------------------------------------------

#[test]
fn chmlfrp_ini_generator_matches_sample_byte_for_byte() {
    // 样本字段：[common] server_addr/server_port + [ssh] type/local_ip/local_port/remote_port
    let rendered = ChmlFrpIniConfig::new("127.0.0.1", 7000)
        .tcp_proxy("ssh", "127.0.0.1", 22, 6000)
        .render();
    assert_eq!(
        rendered,
        golden_ini(),
        "ChmlFrp INI 生成与面板样本不一致（R12 红线）"
    );
}

#[test]
fn chmlfrp_ini_generator_matches_sample_field_by_field() {
    let rendered = ChmlFrpIniConfig::new("127.0.0.1", 7000)
        .tcp_proxy("ssh", "127.0.0.1", 22, 6000)
        .render();
    let gen = parse_ini(&rendered).expect("生成物可解析");
    let sample = parse_ini(&golden_ini()).expect("样本可解析");
    assert_eq!(
        gen, sample,
        "逐字段比对失败：节集合/字段序/字段值任一不一致"
    );
}

#[test]
fn chmlfrp_ini_generator_extends_common_without_touching_proxy_layout() {
    // 托管层真实用法：common 加 admin/凭据档，proxy 节保持样本形态。
    let rendered = ChmlFrpIniConfig::new("node.example.net", 7000)
        .common("user", "token-6e447a2e28fdb4d0")
        .common("token", "panel-token")
        .common("tls_enable", "true")
        .tcp_proxy("ssh", "127.0.0.1", 22, 6000)
        .render();
    let parsed = parse_ini(&rendered).unwrap();
    assert_eq!(parsed.get("common", "user"), Some("token-6e447a2e28fdb4d0"));
    assert_eq!(parsed.get("common", "tls_enable"), Some("true"));
    // proxy 节字段与样本逐项一致（CheckProxy 比对面）
    assert_eq!(parsed.get("ssh", "type"), Some("tcp"));
    assert_eq!(parsed.get("ssh", "local_ip"), Some("127.0.0.1"));
    assert_eq!(parsed.get("ssh", "local_port"), Some("22"));
    assert_eq!(parsed.get("ssh", "remote_port"), Some("6000"));
}

// ---------------------------------------------------------------------------
// 原版 TOML（R8：`OriginalTomlConfig` ↔ 官方样本）
// ---------------------------------------------------------------------------

#[test]
fn original_toml_generator_matches_sample_byte_for_byte() {
    let rendered = OriginalTomlConfig::new("127.0.0.1", 7000)
        .tcp_proxy("test-tcp", "127.0.0.1", 22, 6000)
        .render();
    assert_eq!(rendered, golden_toml(), "原版 TOML 生成与官方样本不一致");
}

#[test]
fn original_toml_generator_matches_sample_field_by_field() {
    let rendered = OriginalTomlConfig::new("127.0.0.1", 7000)
        .tcp_proxy("test-tcp", "127.0.0.1", 22, 6000)
        .render();
    let gen: toml::Table = rendered.parse().expect("生成物是合法 TOML");
    let sample: toml::Table = golden_toml().parse().expect("样本是合法 TOML");
    assert_eq!(gen, sample, "逐字段比对失败（toml::Table 深比较）");
}

#[test]
fn original_toml_generator_full_form_roundtrip() {
    // 服务端真实用法：auth + webServer（admin 探测）+ tcp proxy；生成物必须可被
    // 只读解析路径（parse_original_toml → original_probe_targets）消化。
    let rendered = OriginalTomlConfig::new("frps.example.net", 7000)
        .auth_token("secret-token")
        .web_server(WebServerSection {
            addr: "127.0.0.1".into(),
            port: 7400,
            user: Some("admin".into()),
            password: Some("pw".into()),
        })
        .tcp_proxy("vpn", "127.0.0.1", 9443, 23000)
        .render();
    let table: toml::Table = rendered.parse().unwrap();
    assert_eq!(table["auth"]["token"].as_str(), Some("secret-token"));
    assert_eq!(table["webServer"]["port"].as_integer(), Some(7400));
    let targets = chml_frpc::config::original_probe_targets(&table);
    assert_eq!(targets.admin.as_ref().unwrap().addr.port(), 7400);
    assert_eq!(
        targets.local_tunnel,
        Some("127.0.0.1:9443".parse().unwrap())
    );
}

// ---------------------------------------------------------------------------
// R12 红线：面板 proxy 参数透传（admin 注入只碰 [common]）
// ---------------------------------------------------------------------------

#[test]
fn r12_panel_proxy_params_pass_through_untouched_on_golden_sample() {
    let sample = golden_ini();
    let admin = AdminCommon {
        addr: "127.0.0.1".parse().unwrap(),
        port: 7400,
        user: "admin".into(),
        password: "probe-pw".into(),
    };
    let managed = augment_chmlfrp_admin(&sample, &admin).expect("admin 注入");

    // proxy 节（[ssh] 起至文件尾）逐字节一致
    let tail_src = &sample[sample.find("[ssh]").unwrap()..];
    let tail_out = &managed[managed.find("[ssh]").unwrap()..];
    assert_eq!(tail_src, tail_out, "R12 红线被破：proxy 节被改写");

    // [common] 得到 admin 四键，样本原字段不动
    let parsed = parse_ini(&managed).unwrap();
    assert_eq!(parsed.get("common", "admin_addr"), Some("127.0.0.1"));
    assert_eq!(parsed.get("common", "admin_port"), Some("7400"));
    assert_eq!(parsed.get("common", "admin_user"), Some("admin"));
    assert_eq!(parsed.get("common", "admin_pwd"), Some("probe-pw"));
    assert_eq!(parsed.get("common", "server_addr"), Some("127.0.0.1"));
    assert_eq!(parsed.get("common", "server_port"), Some("7000"));
}

#[test]
fn r12_admin_injection_is_idempotent() {
    let sample = golden_ini();
    let admin = AdminCommon {
        addr: "127.0.0.1".parse().unwrap(),
        port: 7400,
        user: "admin".into(),
        password: "probe-pw".into(),
    };
    let once = augment_chmlfrp_admin(&sample, &admin).unwrap();
    let twice = augment_chmlfrp_admin(&once, &admin).unwrap();
    assert_eq!(once, twice, "重复注入不得改写 proxy 节或增殖字段");
}
