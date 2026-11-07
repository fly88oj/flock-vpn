//! M8 webui 静态资产内嵌（docs/design.md §7-M8.1/§M8.6——include_dir 定死）。
//!
//! M8b 批次：全量 SPA 资产——`index.html / app.js / i18n.js / styles.css` +
//! `vendor/{alpine.min.js, uplot.min.js, uplot.css, flock_pake.js, flock_pake.wasm}`
//! 与两份 MIT LICENSE。SPA fallback（未知非 /api 路径 → index.html）在
//! [`super::api`] 的 `static_route`。
//!
//! Cache-Control（§M8.1）：资产 `no-cache`（单二进制升级即全量刷新，无指纹文件名
//! 需求）；API 侧 `no-store` 由 [`super::http::Response::json`] 统一承担。

use include_dir::{include_dir, Dir};

/// 内嵌资产目录（`src/webui/assets/`）。
pub static ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/src/webui/assets");

/// 按扩展名给 content-type（§M8.4 定死的映射面）。
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

/// `GET /` 的入口文件。
pub fn index() -> &'static [u8] {
    ASSETS
        .get_file("index.html")
        .map(|f| f.contents())
        .unwrap_or_default()
}

/// `GET /static/<path>`（路径遍历拒绝：仅精确匹配内嵌文件名，`..`/绝对路径/嵌套
/// 分隔在 Dir 查找语义下天然不可达——不触碰文件系统）。vendor/ 子目录经 '/' 路径
/// 段寻径（include_dir Dir::get_file 语义）。
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
        std::str::from_utf8(static_file(path).unwrap_or_else(|| panic!("{path} 在库")))
            .expect("utf-8")
    }

    /// M8.6 资产清单全在库（vendor 子目录含 vendored 库 + wasm 产物 + 胶水）。
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
            let f = static_file(path).unwrap_or_else(|| panic!("{path} 缺失"));
            assert!(!f.is_empty(), "{path} 空文件");
        }
        // vendored 库身份锚（版本头注释）。
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
        // wasm 产物魔数（\0asm + 32 位版本 1）。
        let wasm = static_file("vendor/flock_pake.wasm").unwrap();
        assert_eq!(&wasm[..4], b"\0asm", "wasm 魔数");
        assert!(
            wasm.len() > 500_000,
            "wasm 产物量级（实际 {}B）",
            wasm.len()
        );
        // content-type 映射（§M8.4）。
        assert_eq!(content_type("a.html"), "text/html; charset=utf-8");
        assert_eq!(content_type("a.js"), "text/javascript; charset=utf-8");
        assert_eq!(content_type("a.css"), "text/css; charset=utf-8");
        assert_eq!(content_type("a.wasm"), "application/wasm");
        assert_eq!(content_type("x"), "application/octet-stream");
    }

    /// SPA 骨架：Alpine 根组件 + 七个路由段全部在 index.html（M8.6 页面集——
    /// login/set-password/dashboard/peers/users/audit/settings；audit 独立成页为
    /// M8b 任务拆分，设计原文并入 settings）。
    #[test]
    fn index_has_all_routes_and_vendor_scripts() {
        let idx = index();
        let s = std::str::from_utf8(idx).expect("utf-8");
        assert!(s.contains("x-data=\"flockApp()\""), "Alpine 根");
        for route in [
            "route==='login'",
            "route==='set-password'",
            "route==='dashboard'",
            "route==='peers'",
            "route==='users'",
            "route==='audit'",
            "route==='settings'",
        ] {
            assert!(s.contains(route), "路由段 {route} 缺失");
        }
        for asset in [
            "/static/styles.css",
            "/static/i18n.js",
            "/static/vendor/uplot.min.js",
            "/static/vendor/uplot.css",
            "/static/vendor/flock_pake.js",
            "/static/vendor/alpine.min.js",
        ] {
            assert!(s.contains(asset), "资产引用 {asset} 缺失");
        }
        // 离线纪律：无外源 URL 引用（零 CDN——全部经 /static 内嵌资产）。
        assert!(
            !s.contains("http://") && !s.contains("https://"),
            "无外源 URL 引用"
        );
        // CSRF 双门槛/错误信封面在 app.js（下述测试），模态与 Toast 容器在骨架。
        assert!(
            s.contains("modal-overlay") && s.contains("toast-stack"),
            "模态/Toast 容器"
        );
        // data-label 列（手机档卡片降级的语义标签面）。
        assert!(s.contains("data-label="), "data-label 列标注");
    }

    /// 响应式三档断言（硬性要求 1 写进自测）：断点系统（媒体查询 1200/1024/768）、
    /// 触控目标 ≥44px、表格→卡片降级、任何视口无横向滚动（overflow-x clip）。
    #[test]
    fn styles_responsive_breakpoints_and_degradation() {
        let css = text("styles.css");
        // 三档断点：<1200 抽屉化、<1024 低优先列收起、<768 卡片化。
        assert!(
            css.contains("(max-width: 1199.98px)"),
            "平板断点（侧栏→抽屉）"
        );
        assert!(css.contains("(min-width: 1200px)"), "桌面断点（固定侧栏）");
        assert!(
            css.contains("(max-width: 1023.98px)"),
            "平板窄档（低优先列收起）"
        );
        assert!(
            css.contains("(max-width: 767.98px)"),
            "手机断点（表格→卡片）"
        );
        // 无横向滚动：html/body overflow-x clip。
        assert!(
            css.contains("overflow-x: clip"),
            "html/body 横向溢出裁剪（无横向滚动）"
        );
        // 触控目标 ≥44px（粗指针 + 手机档兜底）。
        assert!(css.contains("(pointer: coarse)"), "粗指针触控档");
        assert!(css.contains("min-height: 44px"), "44px 触控目标");
        // 表格→卡片降级：data-label 伪元素展开 + 卡片行形态（VIP/状态/操作保留面
        //由 index.html data-label 列 + 本规则的组合保证）。
        assert!(
            css.contains("content: attr(data-label)"),
            "td::before data-label"
        );
        assert!(
            css.contains(".table thead { display: none; }"),
            "手机档隐藏表头"
        );
        // 断点表以注释写明（文档面）。
        assert!(css.contains("桌面"), "断点表注释（桌面）");
        assert!(css.contains("平板"), "断点表注释（平板）");
        assert!(css.contains("手机"), "断点表注释（手机）");
        // 登录页三档居中。
        assert!(css.contains(".auth-wrap"), "auth 居中形态");
        // 设计系统 tokens 面。
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

    /// app.js 契约面：API 封装（错误信封 + CSRF 双门槛 + 401 跳登录）、hash 路由、
    /// wasm OPAQUE 全流程调用、uPlot 本地时区 + resize。
    #[test]
    fn app_js_api_and_auth_flow_anchors() {
        let js = text("app.js");
        // CSRF 双门槛（POST 头）。
        assert!(js.contains("X-Flock-Web"), "CSRF 双门槛头");
        assert!(js.contains("application/json"), "JSON content-type");
        // 错误信封解析 + 429 重试提示。
        assert!(js.contains("error.code"), "错误信封解析");
        assert!(js.contains("retry_after_secs"), "429 retry_after");
        assert!(js.contains("not_logged_in"), "401 面");
        // OPAQUE 全流程四步。
        assert!(js.contains("loginBegin"), "ke1");
        assert!(js.contains("login-begin"), "login-begin API");
        assert!(js.contains("identity_pub"), "anchor 验签材料（bootstrap）");
        assert!(js.contains("loginFinish"), "ke3（wasm anchor 验签）");
        assert!(js.contains("login-finish"), "login-finish API");
        // 口令引导流。
        assert!(
            js.contains("pwBegin") && js.contains("pwFinish"),
            "pw-begin/commit 流"
        );
        assert!(js.contains("profile: 0"), "profile 恒 0（Owasp19MiB）");
        // hash 路由 + 60s 轮询 + uPlot。
        assert!(js.contains("hashchange"), "hash 路由");
        assert!(js.contains("60000"), "60s 轮询");
        assert!(
            js.contains("uPlot") || js.contains("uplotTooltip"),
            "uPlot 集成"
        );
        assert!(js.contains("Date(v * 1000)"), "本地时区刻度");
        assert!(js.contains("addEventListener('resize'"), "图表宽度自适应");
    }

    /// i18n 纪律：全部中文文案集中 i18n.js 单字典（锚定关键键 + 错误码键全集）。
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
            assert!(js.contains(key), "i18n 键 {key} 缺失");
        }
        // 11 个审计 action 词表全覆盖（§M8.4 定死）。
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
                "审计词表 {action}"
            );
        }
    }

    /// wasm 胶水契约：默认 wasm 路径、C-ABI 导出全名、错误码映射、熵注入；定长
    /// anchor 材料的期望长度校验 + 0 长度写参短路（🟢 评审项 7——短 hex/b64 不
    /// 越界、空参不触 dangling 指针）。
    #[test]
    fn pake_glue_c_abi_anchors() {
        let js = text("vendor/flock_pake.js");
        assert!(
            js.contains("/static/vendor/flock_pake.wasm"),
            "wasm 取用路径"
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
            assert!(js.contains(sym), "C-ABI 符号 {sym}");
        }
        assert!(js.contains("crypto.getRandomValues"), "熵注入源");
        // -1..-4 错误码映射面。
        for code in ["no_entropy", "pake", "anchor", "capacity"] {
            assert!(js.contains(code), "错误码 {code}");
        }
        // 定长材料的期望长度校验（server_id 16B / identity_pub 32B / bind 16B /
        // sig 64B——垫片 fixed::<N>() 定长拷贝，短输入越界读）。
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
        assert!(js.contains("hex.length !== expect * 2"), "短/长 hex 报错");
        // writeParam 0 长度短路（sr_wasm_alloc(0) = dangling 指针）。
        assert!(js.contains("bytes.length === 0"), "writeParam 0 长度短路");
    }

    /// /static 查找：存在文件命中（含 vendor/ 子目录）；不存在走 SPA fallback 由
    /// api.rs 承担（此处仅断言查找语义）；遍历尝试 ⇒ None（无 fs 面）。
    #[test]
    fn static_file_lookup_and_traversal_rejected() {
        assert!(static_file("index.html").is_some());
        assert!(static_file("vendor/alpine.min.js").is_some());
        assert!(static_file("nope.js").is_none());
        assert!(static_file("../assets.rs").is_none(), "遍历拒");
        assert!(static_file("/etc/passwd").is_none());
        assert!(static_file("..\\assets.rs").is_none());
        assert!(
            static_file("vendor/../../Cargo.toml").is_none(),
            "嵌套遍历拒"
        );
    }

    /// round2 双评审修复锚（🔴 图表/抽屉 + 确认项 3–9）：每项至少一个稳定锚点，
    /// 防回归——改动这些面时同步更新本表。
    #[test]
    fn round2_review_fix_anchors() {
        let js = text("app.js");
        let css = text("styles.css");
        let html = std::str::from_utf8(index()).expect("utf-8");
        let i18n = text("i18n.js");

        // 🔴 1 图表：显式时间刻度（恒 4–6 个）、Y 恒 0 起点值域、完整单位、
        // 双系列图例（DOM 自绘 + 线色单点定义 + 实时读数）。
        assert!(js.contains("timeTickSplits"), "X 轴显式刻度面");
        assert!(
            js.contains("[0, hi - lo < 1 ? hi + 1 : hi]"),
            "Y 值域恒 0 起点（0 值抬头不挤掉 0）"
        );
        assert!(js.contains("CHART_TX_COLOR"), "线色单点定义");
        assert!(js.contains("legendTx"), "图例实时读数");
        assert!(html.contains("chart-legend"), "自绘图例 DOM");
        assert!(css.contains(".chart-legend"), "图例样式");
        assert!(
            !js.contains("fmtBpsAxis"),
            "紧凑单位形（60.0 M）已弃用——Y 轴/tooltip/统计卡同源 fmtBps"
        );

        // 🔴 2 抽屉：面板层级高于遮罩（真缺陷：旧 sidebar z50 < scrim z55，
        // 遮罩盖面板致内容全黑）+ 右缘 12px 圆角 + 更明显开态投影。
        assert!(css.contains("z-index: 56"), "抽屉 56 > 遮罩 55");
        assert!(css.contains("0 12px 12px 0"), "右缘 12px 圆角");
        assert!(
            css.contains("box-shadow: 12px 0 40px rgba(0, 0, 0, 0.55)"),
            "开态右向投影"
        );

        // 3 平板（768–1199）行内操作 ≥44px 命中 + 刷新按钮三档统一（弃 btn-sm）。
        assert!(
            css.contains("max-width: 1199.98px) and (min-width: 768px)"),
            "平板断点行内操作 44px"
        );
        assert!(
            !html.contains("btn-outline btn-sm"),
            "刷新按钮不再桌面 30/手机 44 参差"
        );

        // 4 账号页自身行防护（取消管理员/禁用置灰；重置口令保留）。
        assert!(js.contains("isSelf(u)"), "自身行判定");
        assert!(html.contains("users.act.self.blocked"), "置灰 title 提示");
        assert!(i18n.contains("'users.act.self.blocked'"), "i18n 键");

        // 5 状态列三形态：列名「状态/在线」+ 图例说明（圆点=在线/文字=生命周期）。
        assert!(i18n.contains("'peers.col.status.legend'"), "图例说明键");
        assert!(
            html.contains("t('peers.col.status.legend')"),
            "表头/单元格 title 图例"
        );

        // 6 口令徽标：「未设置」琥珀描边胶囊。
        assert!(
            css.contains(".badge-outline-warn") && html.contains("badge-outline-warn"),
            "琥珀描边胶囊"
        );

        // 7 审计高危 action 的「成功」徽标用琥珀档。
        assert!(
            js.contains("auditHighRisk") && js.contains("auditResultBadge"),
            "高危词表 + 徽标分流"
        );

        // 8 桌面 dashboard：集群卡与服务器区两列并排 + 集群卡三段等距三列。
        assert!(
            css.contains(".dash-top") && html.contains("dash-top"),
            "顶部两列"
        );
        assert!(html.contains("kv-cols"), "集群卡三段三列");
        assert!(i18n.contains("'dash.cluster.id'"), "集群标识键");

        // 9 微项批：词内不断行 / ID 芯片下划线偏移 / Toast 带原因透传 / 模态
        // 警示图标（tabular-nums 由既有 .num 规则覆盖，无新增面）。
        assert!(css.contains("word-break: keep-all"), "中文词内不断行");
        assert!(
            css.contains("text-underline-offset: 2px"),
            "ID 芯片下划线偏移"
        );
        assert!(js.contains("serverMessage"), "错误信封 message 透传");
        assert!(html.contains("modal-title-ico"), "模态标题警示图标");
    }
}
