//! M8 webui 静态资产内嵌（docs/design.md §7-M8.1/§M8.6——include_dir 定死）。
//!
//! M8a 批次：**最小壳页**（index.html 单文件——登录表单占位 + 「M8b 前端未装配」
//! 文案 + 调通 `/api/bootstrap` 的 JS 一行），使 W 系断言（资产可下载/壳页起跑）
//! 在前端装配前即可运行。M8b 落全量资产清单（app.js/i18n.js/style.css/
//! flock_pake.{js,wasm}/vendor/*——§M8.6）。
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
/// 分隔在 Dir 查找语义下天然不可达——不触碰文件系统）。
pub fn static_file(path: &str) -> Option<&'static [u8]> {
    if path.contains("..") || path.starts_with('/') || path.contains('\\') {
        return None;
    }
    ASSETS.get_file(path).map(|f| f.contents())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 壳页在库且带 M8b 文案与 bootstrap 调用（W 系断言的资产面锚点）。
    #[test]
    fn shell_index_embedded_with_notice_and_bootstrap_probe() {
        let idx = index();
        let text = std::str::from_utf8(idx).expect("utf-8");
        assert!(text.contains("M8b 前端未装配"), "文案锚点");
        assert!(text.contains("/api/bootstrap"), "bootstrap 探测 JS");
        assert!(text.contains("登录"), "登录表单占位");
        // content-type 映射（§M8.4）。
        assert_eq!(content_type("a.html"), "text/html; charset=utf-8");
        assert_eq!(content_type("a.js"), "text/javascript; charset=utf-8");
        assert_eq!(content_type("a.css"), "text/css; charset=utf-8");
        assert_eq!(content_type("a.wasm"), "application/wasm");
        assert_eq!(content_type("x"), "application/octet-stream");
    }

    /// /static 查找：存在文件命中；不存在/遍历尝试 ⇒ None（无 fs 面）。
    #[test]
    fn static_file_lookup_and_traversal_rejected() {
        assert!(static_file("index.html").is_some());
        assert!(static_file("nope.js").is_none());
        assert!(static_file("../assets.rs").is_none(), "遍历拒");
        assert!(static_file("/etc/passwd").is_none());
        assert!(static_file("..\\assets.rs").is_none());
    }
}
