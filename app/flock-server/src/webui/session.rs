//! M8 webui 会话表（docs/design.md §7-M8.3——参数逐字：32B 随机 sid、TTL、上限 256
//! 淘汰最旧、惰性过期 + 60s 清扫）。
//!
//! 进程内存 per-server（**不进 Raft**）：server-a 的 VIP 登录得到的 cookie 对
//! server-b 无效（cookie 本就按 host 域隔离）——在 b 上重新登录即可（设计写明）。
//!
//! 时钟注入：全部方法收 `now_unix`（清扫任务/登录 handler 注入真实墙钟；单测注入
//! 定点时钟——退避/过期曲线确定性可测）。

use std::collections::HashMap;

use flock_protocol::rand;

/// 会话表上限（超限按 iat 淘汰最旧——断言面）。
pub const SESSION_CAP: usize = 256;
/// 清扫周期（惰性过期之外的兜底——腾出被死会话占据的槽位）。
pub const SWEEP_PERIOD: std::time::Duration = std::time::Duration::from_secs(60);

/// 会话来源（login-finish 时按 RemoteAddr 定档；两类都合法、都记录——不拒绝跨段
/// 重用 cookie，按需求原语义；/api/me 与审计行回显）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Loopback,
    Vpn,
}

impl Origin {
    /// JSON 回显值（§M8.4 `/api/me` 的 origin 字段）。
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Loopback => "loopback",
            Origin::Vpn => "vpn",
        }
    }
}

/// 会话行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub user: String,
    pub admin: bool,
    pub origin: Origin,
    pub iat_unix: u64,
    pub exp_unix: u64,
}

/// 会话表（`Mutex<HashMap<sid, Session>>`；sid = 32B 随机 hex 64 字符）。
#[derive(Default)]
pub struct Sessions {
    inner: std::sync::Mutex<HashMap<String, Session>>,
}

impl Sessions {
    pub fn new() -> Self {
        Self::default()
    }

    /// 签发会话（32B 随机 sid）；超上限先按 iat 淘汰最旧。
    pub fn issue(
        &self,
        user: &str,
        admin: bool,
        origin: Origin,
        now_unix: u64,
        ttl_secs: u64,
    ) -> String {
        let mut g = self.inner.lock().expect("sessions poisoned");
        evict_to_cap(&mut g);
        // 32B 随机（256bit）；hex 64 字符。碰撞（2^-256）不构成现实路径——重取即可。
        let sid = loop {
            let s = hex::encode(rand::random::<[u8; 32]>());
            if !g.contains_key(&s) {
                break s;
            }
        };
        g.insert(
            sid.clone(),
            Session {
                user: user.to_string(),
                admin,
                origin,
                iat_unix: now_unix,
                exp_unix: now_unix.saturating_add(ttl_secs),
            },
        );
        sid
    }

    /// 查会话（惰性过期：命中即验 exp——过期返回 None 但行仍在，待清扫/复用槽位）。
    pub fn lookup(&self, sid: &str, now_unix: u64) -> Option<Session> {
        let g = self.inner.lock().expect("sessions poisoned");
        g.get(sid).filter(|s| s.exp_unix > now_unix).cloned()
    }

    /// 删除会话（logout）。返回是否存在（含已过期行——同名删除语义）。
    pub fn logout(&self, sid: &str) -> bool {
        self.inner
            .lock()
            .expect("sessions poisoned")
            .remove(sid)
            .is_some()
    }

    /// 清扫过期行（60s 周期任务；返回清出条数——测试面）。
    pub fn sweep(&self, now_unix: u64) -> usize {
        let mut g = self.inner.lock().expect("sessions poisoned");
        let before = g.len();
        g.retain(|_, s| s.exp_unix > now_unix);
        before - g.len()
    }

    /// 在册行数（含未过期的惰性行——诊断/测试面）。
    pub fn len(&self) -> usize {
        self.inner.lock().expect("sessions poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 上限淘汰：超 [`SESSION_CAP`] 按 iat 淘汰最旧（iat 同刻任取一席——毫秒级同刻
/// 属边界态，逐出哪一席语义等价：均为同刻签发的死会话）。
fn evict_to_cap(g: &mut HashMap<String, Session>) {
    while g.len() >= SESSION_CAP {
        let Some(oldest) = g
            .iter()
            .min_by_key(|(_, s)| s.iat_unix)
            .map(|(sid, _)| sid.clone())
        else {
            break;
        };
        g.remove(&oldest);
    }
}

/// Set-Cookie 值（§M8.3 逐字：HttpOnly + SameSite=Strict + Path=/ + Max-Age=TTL；
/// **无 Secure**——无 TLS，信任域声明 §M8.7）。
pub fn set_cookie_value(sid: &str, ttl_secs: u64) -> String {
    format!("flock_session={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={ttl_secs}")
}

/// logout 的同名删除 cookie（Max-Age=0）。
pub fn clear_cookie_value() -> String {
    "flock_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".to_string()
}

// ============================================================================
// 单元测试（§M8.9：签发/命中/过期拒/logout 删/256 上限淘汰最旧/惰性+周期清扫）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_lookup_and_expiry() {
        let s = Sessions::new();
        let sid = s.issue("alice", true, Origin::Loopback, 1000, 3600);
        assert_eq!(sid.len(), 64, "sid = 32B hex 64 字符");
        assert!(sid.bytes().all(|b| b.is_ascii_hexdigit()));

        let sess = s.lookup(&sid, 1000).expect("命中");
        assert_eq!(sess.user, "alice");
        assert!(sess.admin);
        assert_eq!(sess.origin, Origin::Loopback);
        assert_eq!(sess.exp_unix, 4600);

        // 惰性过期：exp 时刻起拒（> exp 才有效——exp 本身已过期）。
        assert!(s.lookup(&sid, 4600).is_none(), "exp 即失效");
        assert!(s.lookup(&sid, 4599).is_some(), "exp 前一秒有效");

        // 未知 sid。
        assert!(s.lookup(&"0".repeat(64), 1000).is_none());
    }

    #[test]
    fn logout_removes() {
        let s = Sessions::new();
        let sid = s.issue("alice", false, Origin::Vpn, 0, 100);
        assert!(s.logout(&sid));
        assert!(s.lookup(&sid, 0).is_none(), "logout 即删");
        assert!(!s.logout(&sid), "二次 logout = 无此行");
    }

    /// 256 上限：第 256 个签发前淘汰最旧（iat 升序淘汰；iat 同刻按 sid 序确定性）。
    #[test]
    fn cap_256_evicts_oldest_by_iat() {
        let s = Sessions::new();
        let first = s.issue("u0", false, Origin::Loopback, 100, 10_000);
        for i in 1..SESSION_CAP - 1 {
            s.issue(&format!("u{i}"), false, Origin::Loopback, 200, 10_000);
        }
        assert_eq!(s.len(), SESSION_CAP - 1);
        // 第 256 席：仍不淘汰（上限即 256）。
        let edge = s.issue("u-edge", false, Origin::Loopback, 250, 10_000);
        assert_eq!(s.len(), SESSION_CAP, "恰 256 在册（不淘汰）");
        assert!(s.lookup(&first, 300).is_some(), "256 内最旧仍在");
        // 第 257 席：签发前淘汰最旧（u0@100）。
        let _new = s.issue("u-new", false, Origin::Loopback, 300, 10_000);
        assert_eq!(s.len(), SESSION_CAP, "超限淘汰后维持 256");
        assert!(s.lookup(&first, 300).is_none(), "最旧（iat=100）被淘汰");
        // 其余存活（含上一席 edge）。
        assert!(s.lookup(&edge, 300).is_some());
        assert!(s.lookup(&_new, 300).is_some());
    }

    /// 周期清扫：过期行清出、未过期保留；返回清出数。
    #[test]
    fn sweep_removes_expired_only() {
        let s = Sessions::new();
        let alive = s.issue("alive", false, Origin::Loopback, 0, 1000);
        let _dead = s.issue("dead", false, Origin::Vpn, 0, 10);
        assert_eq!(s.len(), 2);
        // now=100：dead 过期（exp=10）、alive 未过期（exp=1000）。
        assert_eq!(s.sweep(100), 1);
        assert_eq!(s.len(), 1);
        assert!(s.lookup(&alive, 100).is_some());
        // 惰性行 sweep 后也腾出（cap 断言不依赖 sweep 的另一路径）。
        assert_eq!(s.sweep(2000), 1, "alive 到期后清扫清出");
        assert!(s.is_empty());
    }

    /// cookie 串逐字（§M8.3：HttpOnly/SameSite=Strict/Path=//Max-Age；无 Secure）。
    #[test]
    fn cookie_strings_literal() {
        let v = set_cookie_value("ab", 28800);
        assert_eq!(
            v,
            "flock_session=ab; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800"
        );
        assert!(!v.contains("Secure"), "无 Secure（无 TLS，§M8.7）");
        let c = clear_cookie_value();
        assert!(c.starts_with("flock_session=;"));
        assert!(c.ends_with("Max-Age=0"), "{c}");
    }
}
