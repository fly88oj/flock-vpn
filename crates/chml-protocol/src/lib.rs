//! # chml-protocol
//!
//! ChmlVPN 与 showroom 共享的协议契约层（docs/design.md §1）。本批次（M1 骨架）交付：
//!
//! - [`kem`]：X25519 + ML-KEM-768 混合 KEM（§1.3.3a / §3.1，P0-1、P0-7）；
//! - [`envelope`]：文件信封 v2（§1.3.3b / §3.2，P0-3；`legacy` feature 下 v1 只读兼容）；
//! - [`sig`]：SR-SIG1 兼容五函数 + `KeyProfile` kid 分派（§1.3.2 / §1.3.3g / §3.3，P2-12）。
//!
//! feature 矩阵（§1.3.1）：默认 = 全 VPN 档；`legacy` / `anchor` / `pq-sign` / `wasm` 默认关
//! （`anchor` / `pq-sign` / `wasm` 本批次仅占位，见各 feature 注释）。
//!
//! 依赖代际（§1.3.2，P1-6）：aes-gcm 0.11.1 / ed25519-dalek 3.0.0 / rand 0.9 新代码；
//! ml-kem 0.3.3 + x25519-dalek 3.0.0（§1.3.3a）。
//!
//! 版本收口（§1.2）：本 crate 再导出其锁定的 `ed25519_dalek` / `x25519_dalek` / `ml_kem` /
//! `rand`（`legacy` 下另含 `rsa`），两项目不得另引版本——下游直接复用，避免类型不兼容。

#![forbid(unsafe_code)]

pub mod envelope;
pub mod kem;
pub mod sig;

// 兼容常量（§1.3.2 工具/常量面；showroom-common lib.rs:51-55 原值）
pub use envelope::{KEY_LEN, NONCE_LEN, SEG, TAG_LEN};
#[cfg(feature = "legacy")]
pub use envelope::WRAP_LEN;

// 兼容工具（§1.3.2；showroom-common lib.rs:57-79 同语义）
pub use sig::{nonce_hex, sha256_hex, sha256_hex_stream};

// SR-SIG1 时间窗（§1.3.2；showroom-common lib.rs:48 原值）
pub use sig::SIG_WINDOW_SECS;

/// 版本收口再导出（§1.2）。
pub use {ed25519_dalek, ml_kem, rand, x25519_dalek};
#[cfg(feature = "legacy")]
pub use rsa;
