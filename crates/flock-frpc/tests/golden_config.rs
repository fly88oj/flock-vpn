//! Golden-file config generation tests (R8/R12; docs/design.md §3.9 seam /
//! §7-M2 completion criteria).
//!
//! - **R8 (dual-stack bootstrap)**: two independent generators inside one
//!   crate (ChmlFrp INI / original TOML), each compared against the official
//!   release-archive sample;
//! - **R12 (compliance red line)**: panel-generated proxy parameters pass
//!   through field by field / byte for byte — the server-side CheckProxy
//!   compares them item by item against the panel records; any mismatch is
//!   rejected (frp-compat §2.3); admin injection may touch `[common]` only.
//!
//! Golden samples copied byte for byte from (`.tmp` is gitignored, so they
//! are checked in under this directory):
//! - `chmlfrp_panel.frpc.ini` ←
//!   `.tmp/chmlfrpc/ChmlFrp-0.51.2_251023_linux_amd64/frpc.ini` (the
//!   panel/release v0.51.2 INI dialect; the on-disk CRLF shape is an
//!   artifact of unpacking on Windows; comparison normalizes line endings);
//! - `original.frpc.toml` ← `.tmp/frp_0.71.1_linux_amd64/frpc.toml` (the
//!   v0.71.1 TOML dialect).

use flock_frpc::config::{
    augment_chmlfrp_admin, parse_ini, ChmlFrpIniConfig, OriginalTomlConfig, WebServerSection,
};
use flock_frpc::AdminCommon;

const GOLDEN_INI: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/chmlfrp_panel.frpc.ini"
);
const GOLDEN_TOML: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/original.frpc.toml"
);

/// Line-ending normalization (CRLF → LF): the INI sample's on-disk shape is
/// CRLF; the generator's canonical output is LF.
fn normalize(text: &str) -> String {
    text.replace("\r\n", "\n")
}

fn golden_ini() -> String {
    normalize(&std::fs::read_to_string(GOLDEN_INI).expect("golden INI sample in place"))
}

fn golden_toml() -> String {
    normalize(&std::fs::read_to_string(GOLDEN_TOML).expect("golden TOML sample in place"))
}

// ---------------------------------------------------------------------------
// ChmlFrp INI (R8: `ChmlFrpIniConfig` ↔ official sample)
// ---------------------------------------------------------------------------

#[test]
fn chmlfrp_ini_generator_matches_sample_byte_for_byte() {
    // Sample fields: [common] server_addr/server_port + [ssh]
    // type/local_ip/local_port/remote_port.
    let rendered = ChmlFrpIniConfig::new("127.0.0.1", 7000)
        .tcp_proxy("ssh", "127.0.0.1", 22, 6000)
        .render();
    assert_eq!(
        rendered,
        golden_ini(),
        "ChmlFrp INI generation differs from the panel sample (R12 red line)"
    );
}

#[test]
fn chmlfrp_ini_generator_matches_sample_field_by_field() {
    let rendered = ChmlFrpIniConfig::new("127.0.0.1", 7000)
        .tcp_proxy("ssh", "127.0.0.1", 22, 6000)
        .render();
    let gen = parse_ini(&rendered).expect("generated output parseable");
    let sample = parse_ini(&golden_ini()).expect("sample parseable");
    assert_eq!(
        gen, sample,
        "field-by-field comparison failed: section set/field order/field values diverge"
    );
}

#[test]
fn chmlfrp_ini_generator_extends_common_without_touching_proxy_layout() {
    // The supervision layer's real usage: extend common with admin/credential
    // fields while the proxy section keeps the sample's shape (common now
    // returns Result — injection defense; legitimate input passes via
    // expect).
    let rendered = ChmlFrpIniConfig::new("node.example.net", 7000)
        .common("user", "token-6e447a2e28fdb4d0")
        .expect("legitimate common key-value")
        .common("token", "panel-token")
        .expect("legitimate common key-value")
        .common("tls_enable", "true")
        .expect("legitimate common key-value")
        .tcp_proxy("ssh", "127.0.0.1", 22, 6000)
        .render();
    let parsed = parse_ini(&rendered).unwrap();
    assert_eq!(parsed.get("common", "user"), Some("token-6e447a2e28fdb4d0"));
    assert_eq!(parsed.get("common", "tls_enable"), Some("true"));
    // Proxy section fields match the sample item by item (the CheckProxy
    // comparison surface).
    assert_eq!(parsed.get("ssh", "type"), Some("tcp"));
    assert_eq!(parsed.get("ssh", "local_ip"), Some("127.0.0.1"));
    assert_eq!(parsed.get("ssh", "local_port"), Some("22"));
    assert_eq!(parsed.get("ssh", "remote_port"), Some("6000"));
}

// ---------------------------------------------------------------------------
// Original TOML (R8: `OriginalTomlConfig` ↔ official sample)
// ---------------------------------------------------------------------------

#[test]
fn original_toml_generator_matches_sample_byte_for_byte() {
    let rendered = OriginalTomlConfig::new("127.0.0.1", 7000)
        .tcp_proxy("test-tcp", "127.0.0.1", 22, 6000)
        .render();
    assert_eq!(
        rendered,
        golden_toml(),
        "original TOML generation differs from the official sample"
    );
}

#[test]
fn original_toml_generator_matches_sample_field_by_field() {
    let rendered = OriginalTomlConfig::new("127.0.0.1", 7000)
        .tcp_proxy("test-tcp", "127.0.0.1", 22, 6000)
        .render();
    let gen: toml::Table = rendered.parse().expect("generated output is valid TOML");
    let sample: toml::Table = golden_toml().parse().expect("sample is valid TOML");
    assert_eq!(
        gen, sample,
        "field-by-field comparison failed (toml::Table deep compare)"
    );
}

#[test]
fn original_toml_generator_full_form_roundtrip() {
    // The server's real usage: auth + webServer (admin probing) + tcp proxy;
    // the generated output must be digestible by the read-only parsing path
    // (parse_original_toml → original_probe_targets).
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
    let targets = flock_frpc::config::original_probe_targets(&table);
    assert_eq!(targets.admin.as_ref().unwrap().addr.port(), 7400);
    assert_eq!(
        targets.local_tunnel,
        Some("127.0.0.1:9443".parse().unwrap())
    );
}

// ---------------------------------------------------------------------------
// R12 red line: panel proxy parameter pass-through (admin injection touches
// [common] only)
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
    let managed = augment_chmlfrp_admin(&sample, &admin).expect("admin injection");

    // The proxy section ([ssh] to end of file) is byte-for-byte identical.
    let tail_src = &sample[sample.find("[ssh]").unwrap()..];
    let tail_out = &managed[managed.find("[ssh]").unwrap()..];
    assert_eq!(
        tail_src, tail_out,
        "R12 red line broken: proxy section rewritten"
    );

    // [common] receives the four admin keys; the sample's original fields
    // are untouched.
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
    assert_eq!(
        once, twice,
        "repeated injection must not rewrite the proxy section or grow fields"
    );
}
