//! M8 webui static assets embedding (docs/design.md §7-M8.1/§M8.6 —— include_dir,
//! fixed at build time).
//!
//! M8b batch: the full SPA asset set —— `index.html / app.js / i18n.js /
//! styles.css` + `vendor/{alpine.min.js, uplot.min.js, uplot.css,
//! flock_pake.js, flock_pake.wasm}` and the two MIT LICENSE files. The SPA
//! fallback (unknown non-/api paths → index.html) lives in
//! [`super::api`]'s `static_route`.
//!
//! Cache-Control (§M8.1): assets are `no-cache` (a single-binary upgrade
//! refreshes everything, no fingerprinted filenames needed); the API-side
//! `no-store` is handled uniformly by [`super::http::Response::json`].

use include_dir::{include_dir, Dir};

/// Embedded asset directory (`src/webui/assets/`).
pub static ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/src/webui/assets");

/// content-type by file extension (the fixed mapping surface of §M8.4).
pub fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "wasm" => "application/wasm",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Entry file for `GET /`.
pub fn index() -> &'static [u8] {
    ASSETS
        .get_file("index.html")
        .map(|f| f.contents())
        .unwrap_or_default()
}

/// `GET /static/<path>` (path traversal rejected: only exact matches against
/// embedded file names; `..`/absolute paths/nested separators are naturally
/// unreachable under Dir lookup semantics —— the filesystem is never touched).
/// The vendor/ subdirectory is addressed via '/' path segments (include_dir
/// Dir::get_file semantics).
pub fn static_file(path: &str) -> Option<&'static [u8]> {
    if path.contains("..") || path.starts_with('/') || path.contains('\\') {
        return None;
    }
    ASSETS.get_file(path).map(|f| f.contents())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(path: &str) -> &'static str {
        std::str::from_utf8(static_file(path).unwrap_or_else(|| panic!("{path} in bundle")))
            .expect("utf-8")
    }

    /// M8.6 asset manifest is complete (vendor subdirectory holds the vendored
    /// libraries + the wasm artifact + the glue).
    #[test]
    fn asset_manifest_complete() {
        for path in [
            "index.html",
            "app.js",
            "i18n.js",
            "styles.css",
            "vendor/alpine.min.js",
            "vendor/uplot.min.js",
            "vendor/uplot.css",
            "vendor/flock_pake.js",
            "vendor/flock_pake.wasm",
            "vendor/LICENSE.alpinejs.txt",
            "vendor/LICENSE.uplot.txt",
        ] {
            let f = static_file(path).unwrap_or_else(|| panic!("{path} missing"));
            assert!(!f.is_empty(), "{path} empty file");
        }
        // Vendored library identity anchors (version header comments).
        assert!(
            text("vendor/uplot.min.js").contains("v1.6.9"),
            "uPlot 1.6.9"
        );
        assert!(
            text("vendor/LICENSE.alpinejs.txt").contains("MIT"),
            "Alpine MIT"
        );
        assert!(
            text("vendor/LICENSE.uplot.txt").contains("MIT"),
            "uPlot MIT"
        );
        // wasm artifact magic bytes (\0asm + 32-bit version 1).
        let wasm = static_file("vendor/flock_pake.wasm").unwrap();
        assert_eq!(&wasm[..4], b"\0asm", "wasm magic");
        assert!(
            wasm.len() > 500_000,
            "wasm artifact magnitude (actual {}B)",
            wasm.len()
        );
        // content-type mapping (§M8.4).
        assert_eq!(content_type("a.html"), "text/html; charset=utf-8");
        assert_eq!(content_type("a.js"), "text/javascript; charset=utf-8");
        assert_eq!(content_type("a.css"), "text/css; charset=utf-8");
        assert_eq!(content_type("a.wasm"), "application/wasm");
        assert_eq!(content_type("x"), "application/octet-stream");
    }

    /// SPA skeleton: the Alpine root component + all seven route sections are
    /// in index.html (the M8.6 page set —— login/set-password/dashboard/peers/
    /// users/audit/settings; audit became a separate page in the M8b task
    /// split, folded out of settings in the original design).
    #[test]
    fn index_has_all_routes_and_vendor_scripts() {
        let idx = index();
        let s = std::str::from_utf8(idx).expect("utf-8");
        assert!(s.contains("x-data=\"flockApp()\""), "Alpine root");
        for route in [
            "route==='login'",
            "route==='set-password'",
            "route==='dashboard'",
            "route==='peers'",
            "route==='users'",
            "route==='audit'",
            "route==='settings'",
        ] {
            assert!(s.contains(route), "route section {route} missing");
        }
        for asset in [
            "/static/styles.css",
            "/static/i18n.js",
            "/static/vendor/uplot.min.js",
            "/static/vendor/uplot.css",
            "/static/vendor/flock_pake.js",
            "/static/vendor/alpine.min.js",
        ] {
            assert!(s.contains(asset), "asset reference {asset} missing");
        }
        // Offline discipline: no external URL references (zero CDN ——
        // everything through /static embedded assets).
        assert!(
            !s.contains("http://") && !s.contains("https://"),
            "no external URL references"
        );
        // The CSRF double-gate / error-envelope surface is in app.js (test
        // below); the modal and toast containers are in the skeleton.
        assert!(
            s.contains("modal-overlay") && s.contains("toast-stack"),
            "modal/toast containers"
        );
        // data-label columns (the semantic-label surface for the mobile card
        // degradation).
        assert!(s.contains("data-label="), "data-label column annotations");
    }

    /// Responsive three-tier assertions (hard requirement 1 written into
    /// self-tests): the breakpoint system (media queries 1200/1024/768), touch
    /// targets ≥44px, table→card degradation, no horizontal scrolling at any
    /// viewport (overflow-x clip).
    #[test]
    fn styles_responsive_breakpoints_and_degradation() {
        let css = text("styles.css");
        // Three tiers: <1200 drawer-izes, <1024 collapses low-priority
        // columns, <768 card-izes.
        assert!(
            css.contains("(max-width: 1199.98px)"),
            "tablet breakpoint (sidebar → drawer)"
        );
        assert!(
            css.contains("(min-width: 1200px)"),
            "desktop breakpoint (fixed sidebar)"
        );
        assert!(
            css.contains("(max-width: 1023.98px)"),
            "narrow-tablet tier (low-priority columns collapse)"
        );
        assert!(
            css.contains("(max-width: 767.98px)"),
            "mobile breakpoint (table → cards)"
        );
        // No horizontal scrolling: html/body overflow-x clip.
        assert!(
            css.contains("overflow-x: clip"),
            "html/body horizontal overflow clipped (no horizontal scroll)"
        );
        // Touch targets ≥44px (coarse pointer + mobile-tier backstop).
        assert!(
            css.contains("(pointer: coarse)"),
            "coarse-pointer touch tier"
        );
        assert!(css.contains("min-height: 44px"), "44px touch targets");
        // Table → card degradation: data-label pseudo-element expansion + the
        // card row shape (the retained VIP/status/actions surface is
        // guaranteed by the combination of index.html's data-label columns +
        // these rules).
        assert!(
            css.contains("content: attr(data-label)"),
            "td::before data-label"
        );
        assert!(
            css.contains(".table thead { display: none; }"),
            "mobile tier hides the table head"
        );
        // The breakpoint table is documented in comments (documentation
        // surface).
        assert!(
            css.contains("Desktop"),
            "breakpoint table comment (desktop)"
        );
        assert!(css.contains("Tablet"), "breakpoint table comment (tablet)");
        assert!(css.contains("Mobile"), "breakpoint table comment (mobile)");
        // Login page centered across the three tiers.
        assert!(css.contains(".auth-wrap"), "auth centered layout");
        // Design-system token surface.
        for token in [
            "--bg:",
            "--surface:",
            "--accent:",
            "--r-lg:",
            "--shadow-1:",
            "--fs-xl:",
        ] {
            assert!(css.contains(token), "token {token}");
        }
    }

    /// app.js contract surface: API wrapper (error envelope + CSRF double
    /// gate + 401 redirect to login), hash routing, the full wasm OPAQUE
    /// flow, and uPlot local timezone + resize.
    #[test]
    fn app_js_api_and_auth_flow_anchors() {
        let js = text("app.js");
        // CSRF double gate (POST headers).
        assert!(js.contains("X-Flock-Web"), "CSRF double-gate header");
        assert!(js.contains("application/json"), "JSON content-type");
        // Error-envelope parsing + 429 retry hint.
        assert!(js.contains("error.code"), "error envelope parsing");
        assert!(js.contains("retry_after_secs"), "429 retry_after");
        assert!(js.contains("not_logged_in"), "401 surface");
        // The four OPAQUE steps.
        assert!(js.contains("loginBegin"), "ke1");
        assert!(js.contains("login-begin"), "login-begin API");
        assert!(
            js.contains("identity_pub"),
            "anchor verification material (bootstrap)"
        );
        assert!(js.contains("loginFinish"), "ke3 (wasm anchor verification)");
        assert!(js.contains("login-finish"), "login-finish API");
        // Password bootstrap flow.
        assert!(
            js.contains("pwBegin") && js.contains("pwFinish"),
            "pw-begin/commit flow"
        );
        assert!(js.contains("profile: 0"), "profile always 0 (Owasp19MiB)");
        // Hash routing + 60s polling + uPlot.
        assert!(js.contains("hashchange"), "hash routing");
        assert!(js.contains("60000"), "60s polling");
        assert!(
            js.contains("uPlot") || js.contains("uplotTooltip"),
            "uPlot integration"
        );
        assert!(js.contains("Date(v * 1000)"), "local-timezone ticks");
        assert!(
            js.contains("addEventListener('resize'"),
            "chart width adaptation"
        );
    }

    /// i18n discipline: all UI copy lives in i18n.js packs (anchored key set +
    /// the full error-code key set). English is the default language; the zh
    /// pack is the only Simplified-Chinese surface in the project.
    #[test]
    fn i18n_dictionary_covers_error_codes_and_pages() {
        let js = text("i18n.js");
        for key in [
            "'err.login_failed'",
            "'err.user_disabled'",
            "'err.rate_limited'",
            "'err.anchor'",
            "'err.bad_token'",
            "'err.cannot_demote_self'",
            "'err.invalid_state'",
            "'err.password_exists'",
            "'login.title'",
            "'setpw.title'",
            "'dash.chart'",
            "'peers.confirm.revoke.title'",
            "'users.token.body'",
            "'audit.action.peer.kick'",
            "'settings.subtitle'",
        ] {
            assert!(js.contains(key), "i18n key {key} missing");
        }
        // All 11 audit action vocabulary entries covered (§M8.4, fixed).
        for action in [
            "session.login",
            "session.logout",
            "user.create",
            "user.disable",
            "user.enable",
            "user.reset_password",
            "user.set_admin",
            "peer.revoke",
            "peer.disable",
            "peer.enable",
            "peer.kick",
        ] {
            assert!(
                js.contains(&format!("'audit.action.{action}'")),
                "audit vocabulary {action}"
            );
        }
    }

    /// Parses one i18n pack (`var <name> = { … };`) into its (key, value)
    /// entries —— one per line, `'key': 'value',`.
    fn pack_entries(js: &str, name: &str) -> Vec<(String, String)> {
        let start = js
            .find(&format!("var {name} = {{"))
            .unwrap_or_else(|| panic!("pack {name} not found"));
        let end = js[start..]
            .find("\n  };")
            .map(|i| start + i)
            .unwrap_or_else(|| panic!("pack {name} unterminated"));
        js[start..end]
            .lines()
            .filter_map(|l| {
                let l = l.trim();
                let rest = l.strip_prefix('\'')?;
                let key = rest.split('\'').next()?;
                let rest = rest.split_once("': '")?.1;
                let val = rest.strip_suffix("',")?;
                Some((key.to_string(), val.to_string()))
            })
            .collect()
    }

    /// Multi-language pack discipline: the en (default) and zh packs carry
    /// strictly identical key sets (every entry translated, no drift in either
    /// direction); each pack's keys are unique.
    #[test]
    fn i18n_packs_en_zh_key_sets_match() {
        let js = text("i18n.js");
        let en = pack_entries(js, "EN");
        let zh = pack_entries(js, "ZH_CN");
        assert!(!en.is_empty(), "en pack parsed");
        assert!(!zh.is_empty(), "zh pack parsed");

        fn uniq<'a>(
            entries: &'a [(String, String)],
            pack: &str,
        ) -> std::collections::HashSet<&'a str> {
            let set: std::collections::HashSet<&str> =
                entries.iter().map(|(k, _)| k.as_str()).collect();
            assert_eq!(
                set.len(),
                entries.len(),
                "{pack} keys must be unique (duplicates present)"
            );
            set
        }
        let en_set = uniq(&en, "en");
        let zh_set = uniq(&zh, "zh");

        let mut missing_in_zh: Vec<&str> = en_set.difference(&zh_set).copied().collect();
        missing_in_zh.sort_unstable();
        assert!(
            missing_in_zh.is_empty(),
            "zh pack missing keys (must mirror en): {missing_in_zh:?}"
        );
        let mut extra_in_zh: Vec<&str> = zh_set.difference(&en_set).copied().collect();
        extra_in_zh.sort_unstable();
        assert!(
            extra_in_zh.is_empty(),
            "zh pack has extra keys (must mirror en): {extra_in_zh:?}"
        );
    }

    /// zh pack completeness spot checks: a small representative entry set is
    /// present, every value is non-empty, and every value (except the
    /// locale-independent language names lang.*) actually contains Han
    /// characters —— the zh pack is the only place Simplified Chinese is
    /// allowed in the assets.
    #[test]
    fn i18n_zh_pack_entries_present_and_translated() {
        let js = text("i18n.js");
        let zh = pack_entries(js, "ZH_CN");
        for key in [
            "app.name",
            "login.title",
            "setpw.title",
            "err.login_failed",
            "peers.confirm.revoke.title",
            "audit.action.peer.kick",
            "app.language",
        ] {
            assert!(
                zh.iter().any(|(k, _)| k == key),
                "zh pack entry {key} missing"
            );
        }
        let has_han = |s: &str| s.chars().any(|c| ('\u{4E00}'..='\u{9FFF}').contains(&c));
        for (key, val) in &zh {
            assert!(!val.is_empty(), "zh value for {key} is empty");
            if key.starts_with("lang.") || key == "peers.col.vip" {
                continue; // locale-independent: language endonyms, the VIP proper noun
            }
            assert!(
                has_han(val),
                "zh value for {key} contains no Han characters: {val:?}"
            );
        }
    }

    /// Language-switcher anchors: the Lang control exists on the login page
    /// and in settings, persists via FLOCK_SET_LANG (localStorage), and the
    /// bootstrap `lang` field is consumed as the initial hint.
    #[test]
    fn lang_switcher_anchors() {
        let html = std::str::from_utf8(index()).expect("utf-8");
        let js = text("i18n.js");
        let app = text("app.js");
        // Switcher controls (login page + settings).
        assert_eq!(
            html.matches("x-model=\"lang\"").count(),
            2,
            "Lang select on login page and settings"
        );
        assert!(
            html.contains("t('lang.en')") && html.contains("t('lang.zh')"),
            "option labels via keys"
        );
        assert!(html.contains("t('app.language')"), "visible label via key");
        // Persistence + hint plumbing in i18n.js / app.js.
        assert!(
            js.contains("localStorage"),
            "choice persisted to localStorage"
        );
        assert!(js.contains("FLOCK_SET_LANG"), "switch entry point");
        assert!(
            js.contains("FLOCK_APPLY_BOOTSTRAP_LANG"),
            "bootstrap hint entry point"
        );
        assert!(app.contains("setLang"), "app-side switch handler");
        // English is the default pack; zh is the alternative.
        let first_pack = js.find("var EN = {").expect("en pack");
        let zh_pack = js.find("var ZH_CN = {").expect("zh pack");
        assert!(first_pack < zh_pack, "en pack declared first (default)");
        assert!(
            html.contains("<html lang=\"en\">"),
            "document lang defaults to en"
        );
    }

    /// wasm glue contract: default wasm path, full C-ABI export names, error
    /// code mapping, entropy injection; expected-length validation of
    /// fixed-size anchor material + the zero-length writeParam short circuit
    /// (review item 7 —— short hex/b64 does not overread, empty parameters
    /// never touch the dangling pointer).
    #[test]
    fn pake_glue_c_abi_anchors() {
        let js = text("vendor/flock_pake.js");
        assert!(
            js.contains("/static/vendor/flock_pake.wasm"),
            "wasm fetch path"
        );
        for sym in [
            "sr_wasm_inject_entropy",
            "sr_wasm_alloc",
            "sr_wasm_free",
            "sr_web_login_begin",
            "sr_web_login_finish",
            "sr_web_pw_begin",
            "sr_web_pw_finish",
        ] {
            assert!(js.contains(sym), "C-ABI symbol {sym}");
        }
        assert!(
            js.contains("crypto.getRandomValues"),
            "entropy injection source"
        );
        // -1..-4 error-code mapping surface.
        for code in ["no_entropy", "pake", "anchor", "capacity"] {
            assert!(js.contains(code), "error code {code}");
        }
        // Expected-length validation of fixed-size material (server_id 16B /
        // identity_pub 32B / bind 16B / sig 64B —— the shim copies with
        // fixed::<N>(); short inputs would overread).
        assert!(js.contains("decHex(a.server_id_hex, 16)"), "server_id 16B");
        assert!(
            js.contains("decB64(a.identity_pub_b64, 32)"),
            "identity_pub 32B"
        );
        assert!(
            js.contains("decHex(a.bind_token_hex, 16)"),
            "bind_token 16B"
        );
        assert!(
            js.contains("decHex(a.anchor_sig_hex, 64)"),
            "anchor_sig 64B"
        );
        assert!(
            js.contains("hex.length !== expect * 2"),
            "short/long hex rejected"
        );
        // writeParam zero-length short circuit (sr_wasm_alloc(0) = dangling
        // pointer).
        assert!(
            js.contains("bytes.length === 0"),
            "writeParam zero-length short circuit"
        );
    }

    /// /static lookup: existing files hit (including the vendor/ subdirectory);
    /// misses fall through to the SPA fallback handled by api.rs (only the
    /// lookup semantics are asserted here); traversal attempts ⇒ None (no fs
    /// surface).
    #[test]
    fn static_file_lookup_and_traversal_rejected() {
        assert!(static_file("index.html").is_some());
        assert!(static_file("vendor/alpine.min.js").is_some());
        assert!(static_file("nope.js").is_none());
        assert!(static_file("../assets.rs").is_none(), "traversal rejected");
        assert!(static_file("/etc/passwd").is_none());
        assert!(static_file("..\\assets.rs").is_none());
        assert!(
            static_file("vendor/../../Cargo.toml").is_none(),
            "nested traversal rejected"
        );
    }

    /// round2 dual-review fix anchors (chart/drawer + items 3–9): at least one
    /// stable anchor each, as regression guards —— keep this table in sync
    /// when touching those surfaces.
    #[test]
    fn round2_review_fix_anchors() {
        let js = text("app.js");
        let css = text("styles.css");
        let html = std::str::from_utf8(index()).expect("utf-8");
        let i18n = text("i18n.js");

        // 1 chart: explicit time ticks (always 4–6), Y value range always
        // starting at 0, full units, two-series legend (hand-drawn DOM +
        // single-point line colors + live readouts).
        assert!(
            js.contains("timeTickSplits"),
            "explicit X-axis tick surface"
        );
        assert!(
            js.contains("[0, hi - lo < 1 ? hi + 1 : hi]"),
            "Y range always 0-based (0-value headroom does not push out 0)"
        );
        assert!(
            js.contains("CHART_TX_COLOR"),
            "single-point line-color definition"
        );
        assert!(js.contains("legendTx"), "legend live readouts");
        assert!(html.contains("chart-legend"), "hand-drawn legend DOM");
        assert!(css.contains(".chart-legend"), "legend styles");
        assert!(
            !js.contains("fmtBpsAxis"),
            "compact unit form (60.0 M) dropped —— Y axis/tooltip/stat cards share fmtBps"
        );

        // 2 drawer: panel layer above the scrim (real defect: old sidebar z50
        // < scrim z55, scrim covered the panel making content all-black) +
        // 12px right rounding + a more visible open-state shadow.
        assert!(css.contains("z-index: 56"), "drawer 56 > scrim 55");
        assert!(css.contains("0 12px 12px 0"), "12px right rounding");
        assert!(
            css.contains("box-shadow: 12px 0 40px rgba(0, 0, 0, 0.55)"),
            "open-state rightward shadow"
        );

        // 3 tablet (768–1199) inline actions ≥44px hit area + refresh button
        // uniform across tiers (btn-sm dropped).
        assert!(
            css.contains("max-width: 1199.98px) and (min-width: 768px)"),
            "tablet breakpoint inline actions 44px"
        );
        assert!(
            !html.contains("btn-outline btn-sm"),
            "refresh button no longer 30px desktop / 44px mobile mismatch"
        );

        // 4 accounts page self-row guard (remove-admin / disable greyed out;
        // reset password kept).
        assert!(js.contains("isSelf(u)"), "self-row detection");
        assert!(
            html.contains("users.act.self.blocked"),
            "greyed-out title hint"
        );
        assert!(i18n.contains("'users.act.self.blocked'"), "i18n key");

        // 5 status column, three shapes: header "Status/Online" + legend
        // (dot = online / text = lifecycle).
        assert!(i18n.contains("'peers.col.status.legend'"), "legend key");
        assert!(
            html.contains("t('peers.col.status.legend')"),
            "header/cell title legend"
        );

        // 6 password badge: "Not set" amber-outlined pill.
        assert!(
            css.contains(".badge-outline-warn") && html.contains("badge-outline-warn"),
            "amber-outlined pill"
        );

        // 7 audit high-risk actions: "OK" badge uses the amber tier.
        assert!(
            js.contains("auditHighRisk") && js.contains("auditResultBadge"),
            "high-risk vocabulary + badge routing"
        );

        // 8 desktop dashboard: cluster card and servers area side by side +
        // the cluster card's three equal segments.
        assert!(
            css.contains(".dash-top") && html.contains("dash-top"),
            "top two columns"
        );
        assert!(html.contains("kv-cols"), "cluster card three segments");
        assert!(i18n.contains("'dash.cluster.id'"), "cluster-id key");

        // 9 micro-batch: no mid-word breaks / ID chip underline offset / toast
        // with reason pass-through / modal warning icon (tabular-nums covered
        // by the existing .num rule, no new surface).
        assert!(css.contains("word-break: keep-all"), "no mid-word breaks");
        assert!(
            css.contains("text-underline-offset: 2px"),
            "ID chip underline offset"
        );
        assert!(
            js.contains("serverMessage"),
            "error envelope message pass-through"
        );
        assert!(html.contains("modal-title-ico"), "modal title warning icon");
    }
}
