//! M8 webui 访问控制（docs/design.md §7-M8.2/M8.3/M8.4/M8.7）：
//!
//! - **来源矩阵**（W-A1–W-A4）：`127.0.0.0/8`（含 ::1）与 `100.64.0.0/10` 放行；
//!   其余 403 `forbidden_origin`（纵深防御——根本机制是未绑定 LAN/公网）。
//!   `X-Forwarded-For` **一律忽略**（客户端可伪造；不支持反代部署）；
//! - **CSRF 双门槛**（变更类 = 全部 POST）：`X-Flock-Web: 1` **且** `Content-Type:
//!   application/json`——缺头 ⇒ 400（不泄漏是 CSRF 拦截）；
//! - **角色矩阵**（路由静态面：公共/登录/管理三档；「先会话后角色」的先后由
//!   api.rs 分发序承担）；
//! - **登录退避**（按用户名 15min 滑窗：第 5 次失败起锁 30s、每再失败翻倍、封顶
//!   900s；成功或窗净空即清零——注入时钟可测）；
//! - **per-IP 令牌桶**（login-begin/pw-begin：10 次/min，突发 10）；
//! - **审计环**（内存最近 200 条 + stderr 同步留痕；11 个 action 词表 + result
//!   三态；不记口令/令牌/票据字节）。
//!
//! 全部组件进程内存、独立时钟入参——无 Raft/无持久化（设计定死）。

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};

use super::session::Origin;

// ============================================================================
// 来源矩阵（W-A1–W-A4）
// ============================================================================

/// `100.64.0.0/10`（RFC 6598 CGNAT 段 = 本 VPN 的 VIP 池，§2.1）。
fn in_vpn_segment(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 100 && (o[1] & 0xC0) == 0x40 // 64..=127
        }
        IpAddr::V6(_) => false,
    }
}

/// 来源分类（`X-Forwarded-For` 不参与——一律以连接 RemoteAddr 判定，W-A4）。
/// None = 越界来源（403 `forbidden_origin` 面）。
pub fn classify_origin(remote: &SocketAddr) -> Option<Origin> {
    match remote.ip() {
        IpAddr::V4(v4) if v4.is_loopback() => Some(Origin::Loopback), // 127.0.0.0/8
        IpAddr::V6(v6) if v6.is_loopback() => Some(Origin::Loopback), // ::1
        ip if in_vpn_segment(ip) => Some(Origin::Vpn),
        _ => None,
    }

    // 注：127.0.0.0/8 与 100.64.0.0/10 不相交（is_loopback 先判），两档各自记录。
}

// ============================================================================
// CSRF 双门槛（§M8.4——变更类 = 全部 POST）
// ============================================================================

/// POST 的 CSRF 双门槛：`X-Flock-Web: 1` 且 `Content-Type: application/json`
///（前缀匹配 `application/json`——charset 参数合法）。true = 放行。
pub fn csrf_gate_ok(method: &str, x_flock_web: Option<&str>, content_type: Option<&str>) -> bool {
    if method != "POST" {
        return true;
    }
    let has_gate = x_flock_web.map(|v| v.trim() == "1").unwrap_or(false);
    let is_json = content_type
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json")
        })
        .unwrap_or(false);
    has_gate && is_json
}

// ============================================================================
// 角色矩阵（路由静态面——三态枚举的判定源）
// ============================================================================

/// 端点角色档（§M8.4 逐端点；「先会话后角色」在 api.rs 分发序）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// 公共（login-begin/finish、pw-begin/commit、bootstrap、静态资产——静态资产
    /// 不经本枚举，由 api.rs 直接路由）。
    Public,
    /// 登录即可（只读面 + logout + me）。
    LoggedIn,
    /// admin。
    Admin,
    /// 未知 `/api/*` 路径（404）。
    Unknown,
}

/// 按 method+path 定角色档（管理写路径按前缀分派：`/api/users/{u}/*` 与
/// `/api/peers/{id}/*` 的四个动作端点全为 Admin）。
pub fn required_role(method: &str, path: &str) -> Role {
    let m_get = method == "GET";
    let m_post = method == "POST";
    match path {
        "/api/bootstrap" if m_get => Role::Public,
        "/api/login-begin" | "/api/login-finish" | "/api/pw-begin" | "/api/pw-commit" if m_post => {
            Role::Public
        }
        "/api/logout" if m_post => Role::LoggedIn,
        "/api/me" | "/api/peers" | "/api/dashboard/summary" | "/api/config" if m_get => {
            Role::LoggedIn
        }
        "/api/dashboard/series" if m_get => Role::LoggedIn,
        "/api/users" if m_get => Role::Admin,
        "/api/users" if m_post => Role::Admin,
        "/api/audit" if m_get => Role::Admin,
        _ => {
            // /api/users/{u}/disable|enable|reset-password|admin（POST，Admin）
            // /api/peers/{device_id}/revoke|disable|enable|kick（POST，Admin）
            if m_post {
                if let Some(rest) = path.strip_prefix("/api/users/") {
                    if rest.contains('/')
                        && matches!(
                            rest.rsplit('/').next().unwrap_or(""),
                            "disable" | "enable" | "reset-password" | "admin"
                        )
                    {
                        return Role::Admin;
                    }
                }
                if let Some(rest) = path.strip_prefix("/api/peers/") {
                    if rest.contains('/')
                        && matches!(
                            rest.rsplit('/').next().unwrap_or(""),
                            "revoke" | "disable" | "enable" | "kick"
                        )
                    {
                        return Role::Admin;
                    }
                }
            }
            Role::Unknown
        }
    }
}

// ============================================================================
// 登录退避（按用户名；注入时钟）
// ============================================================================

/// 滑窗（15min）。
const FAIL_WINDOW_SECS: u64 = 15 * 60;
/// 起锁阈值（第 5 次失败起锁定）。
const LOCK_THRESHOLD: usize = 5;
/// 起锁时长（30s；每再失败翻倍）。
const LOCK_BASE_SECS: u64 = 30;
/// 封顶（900s）。
const LOCK_MAX_SECS: u64 = 900;

/// 按用户名失败记账。
#[derive(Default)]
struct FailState {
    /// 窗内失败时刻（unix 秒；升序推入）。
    fails: Vec<u64>,
    /// 当前锁定时长（翻倍基；0 = 未锁）。
    lock_secs: u64,
}

/// 登录退避器（进程内存；`Mutex<HashMap<user, FailState>>`）。
#[derive(Default)]
pub struct LoginBackoff {
    inner: std::sync::Mutex<HashMap<String, FailState>>,
}

impl LoginBackoff {
    pub fn new() -> Self {
        Self::default()
    }

    /// 锁定检查：Some(retry_after_secs) = 当前锁定中（不消费失败）。
    pub fn check(&self, user: &str, now_unix: u64) -> Option<u64> {
        let g = self.inner.lock().expect("backoff poisoned");
        let st = g.get(user)?;
        // 锁定窗 = 自最近一次失败起 lock_secs。
        let last = *st.fails.last()?;
        let until = last.saturating_add(st.lock_secs);
        (now_unix < until).then(|| until - now_unix)
    }

    /// 记一次失败（窗净空后重新起算；第 5 次失败起锁 30s，每再失败翻倍封顶 900）。
    pub fn on_failure(&self, user: &str, now_unix: u64) {
        let mut g = self.inner.lock().expect("backoff poisoned");
        let st = g.entry(user.to_string()).or_default();
        // 15min 滑窗净空（含锁定过后的残留失败）。
        st.fails
            .retain(|t| now_unix.saturating_sub(*t) < FAIL_WINDOW_SECS);
        st.fails.push(now_unix);
        if st.fails.len() >= LOCK_THRESHOLD {
            // 第 5 次失败：30s；其后每再失败翻倍（len=5→30, 6→60, 7→120 …封顶 900）。
            let excess = st.fails.len() - LOCK_THRESHOLD;
            st.lock_secs = LOCK_BASE_SECS
                .saturating_mul(1u64 << excess.min(6))
                .min(LOCK_MAX_SECS);
        }
    }

    /// 成功清零（窗与锁全清）。
    pub fn on_success(&self, user: &str) {
        self.inner.lock().expect("backoff poisoned").remove(user);
    }
}

// ============================================================================
// per-IP 令牌桶（login-begin/pw-begin；10/min 突发 10）
// ============================================================================

/// 桶容量（突发 10）。
const BUCKET_BURST: f64 = 10.0;
/// 回填速率（10/min）。
const BUCKET_RATE_PER_SEC: f64 = 10.0 / 60.0;

/// 令牌桶（进程内存；`Mutex<HashMap<IpAddr, (tokens, last)>>`）。
#[derive(Default)]
pub struct IpBuckets {
    inner: std::sync::Mutex<HashMap<IpAddr, (f64, u64)>>,
}

impl IpBuckets {
    pub fn new() -> Self {
        Self::default()
    }

    /// 取一枚令牌：true = 放行；false = 超速（429，retry_after 按 满-token 回填时距）。
    pub fn allow(&self, ip: IpAddr, now_unix: u64) -> Result<(), u64> {
        let mut g = self.inner.lock().expect("buckets poisoned");
        let (tokens, last) = g.get(&ip).copied().unwrap_or((BUCKET_BURST, now_unix));
        let elapsed = now_unix.saturating_sub(last) as f64;
        let filled = (tokens + elapsed * BUCKET_RATE_PER_SEC).min(BUCKET_BURST);
        if filled >= 1.0 {
            g.insert(ip, (filled - 1.0, now_unix));
            Ok(())
        } else {
            let need = 1.0 - filled;
            let retry = (need / BUCKET_RATE_PER_SEC).ceil() as u64;
            g.insert(ip, (filled, now_unix));
            Err(retry.max(1))
        }
    }
}

// ============================================================================
// 审计环（§M8.7-4：内存 200 条 + stderr；action 词表定死）
// ============================================================================

/// 审计环容量。
pub const AUDIT_CAP: usize = 200;

/// action 词表（§M8.4 定死 11 个）。
pub const AUDIT_ACTIONS: [&str; 11] = [
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
];

/// 审计行（不记口令/令牌/票据字节——§M8.7-4 红线）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub ts: u64,
    pub user: String,
    pub action: String,
    pub target: String,
    pub origin: Origin,
    pub result: &'static str, // "ok" | "denied" | "error"
}

/// 审计环（`Mutex<VecDeque>` + stderr 同步行——journald 接管，与既有 flock-server:
/// 日志同通道）。
#[derive(Default)]
pub struct AuditLog {
    inner: std::sync::Mutex<VecDeque<AuditEntry>>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// 记一行（stderr 同步留痕 + 内存环；环满挤最旧）。
    pub fn record(
        &self,
        ts: u64,
        user: &str,
        action: &str,
        target: &str,
        origin: Origin,
        result: &'static str,
    ) {
        debug_assert!(AUDIT_ACTIONS.contains(&action), "action 词表外: {action}");
        let entry = AuditEntry {
            ts,
            user: user.to_string(),
            action: action.to_string(),
            target: target.to_string(),
            origin,
            result,
        };
        // stderr（journald）：固定单行格式，诊断可 grep；不打印凭据字节。
        eprintln!(
            "flock-server: webui audit ts={ts} user={user} action={action} target={target} origin={} result={result}",
            origin.as_str()
        );
        let mut g = self.inner.lock().expect("audit poisoned");
        if g.len() >= AUDIT_CAP {
            g.pop_front();
        }
        g.push_back(entry);
    }

    /// 快照（新→旧，§M8.4 `/api/audit`）。
    pub fn entries_newest_first(&self) -> Vec<AuditEntry> {
        let g = self.inner.lock().expect("audit poisoned");
        g.iter().rev().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("audit poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ============================================================================
// 单元测试（§M8.9：来源矩阵/CSRF/角色三态/退避曲线/令牌桶/审计环）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// W-A1–W-A3 来源矩阵：127.0.0.0/8（含 127.3.2.1）与 ::1 放 Loopback；
    /// 100.64.0.0/10（含段首/段尾/中段）放 Vpn；其余（RFC1918/公网/其它回环外
    /// IPv6/链路本地）拒。
    #[test]
    fn origin_matrix() {
        for ok_lb in ["127.0.0.1:1", "127.3.2.1:2", "127.255.255.254:3", "[::1]:4"] {
            assert_eq!(
                classify_origin(&addr(ok_lb)),
                Some(Origin::Loopback),
                "{ok_lb} ⇒ loopback"
            );
        }
        for ok_vpn in [
            "100.64.0.1:9",
            "100.64.0.11:9",
            "100.100.1.2:9",
            "100.127.255.254:9",
        ] {
            assert_eq!(
                classify_origin(&addr(ok_vpn)),
                Some(Origin::Vpn),
                "{ok_vpn} ⇒ vpn"
            );
        }
        // /10 段外邻位（100.63.x / 100.128.x）拒。
        for bad in [
            "192.168.1.5:1",
            "10.0.0.1:1",
            "8.8.8.8:53",
            "100.63.255.254:1",
            "100.128.0.1:1",
            "[fe80::1]:1",
            "[2001:db8::1]:1",
            "169.254.1.1:1",
        ] {
            assert_eq!(classify_origin(&addr(bad)), None, "{bad} ⇒ 拒（403 面）");
        }
    }

    /// CSRF 双门槛：POST 缺自定义头 400；有头缺 JSON content-type 400；双齐放行；
    /// GET 不设槛；`application/json; charset=utf-8` 前缀合法。
    #[test]
    fn csrf_double_gate() {
        let ct_json = Some("application/json");
        let gate = Some("1");
        assert!(csrf_gate_ok("POST", gate, ct_json), "双齐放行");
        assert!(csrf_gate_ok(
            "POST",
            gate,
            Some("application/json; charset=utf-8")
        ));
        assert!(!csrf_gate_ok("POST", None, ct_json), "缺 X-Flock-Web");
        assert!(!csrf_gate_ok("POST", Some("0"), ct_json), "值非 1");
        assert!(!csrf_gate_ok("POST", gate, Some("text/plain")), "缺 JSON");
        assert!(!csrf_gate_ok("POST", gate, None), "缺 content-type");
        assert!(!csrf_gate_ok("POST", gate, Some("application/json+xml")),);
        assert!(csrf_gate_ok("GET", None, None), "GET 不设槛");
    }

    /// 角色矩阵逐端点枚举（§M8.4 全 22 端点 + 方法错档 + 未知路径）。
    #[test]
    fn role_matrix_all_endpoints() {
        // 公共 5。
        for (m, p) in [
            ("GET", "/api/bootstrap"),
            ("POST", "/api/login-begin"),
            ("POST", "/api/login-finish"),
            ("POST", "/api/pw-begin"),
            ("POST", "/api/pw-commit"),
        ] {
            assert_eq!(required_role(m, p), Role::Public, "{m} {p}");
        }
        // 登录 6。
        for (m, p) in [
            ("GET", "/api/me"),
            ("POST", "/api/logout"),
            ("GET", "/api/peers"),
            ("GET", "/api/dashboard/summary"),
            ("GET", "/api/dashboard/series"),
            ("GET", "/api/config"),
        ] {
            assert_eq!(required_role(m, p), Role::LoggedIn, "{m} {p}");
        }
        // 管理 11（含路径参数形）。
        for (m, p) in [
            ("GET", "/api/users"),
            ("POST", "/api/users"),
            ("GET", "/api/audit"),
            ("POST", "/api/users/bob/disable"),
            ("POST", "/api/users/bob/enable"),
            ("POST", "/api/users/bob/reset-password"),
            ("POST", "/api/users/bob/admin"),
            ("POST", "/api/peers/abcd/revoke"),
            ("POST", "/api/peers/abcd/disable"),
            ("POST", "/api/peers/abcd/enable"),
            ("POST", "/api/peers/abcd/kick"),
        ] {
            assert_eq!(required_role(m, p), Role::Admin, "{m} {p}");
        }
        // 方法错档（同路径异方法 = 未知——分发层 405）与未知路径。
        for (m, p) in [
            ("GET", "/api/login-begin"),
            ("POST", "/api/bootstrap"),
            ("PUT", "/api/users"),
            ("GET", "/api/users/bob/disable"),
            ("POST", "/api/peers/abcd/rename"),
            ("GET", "/api/nope"),
        ] {
            assert_eq!(required_role(m, p), Role::Unknown, "{m} {p}");
        }
    }

    /// 退避曲线（注入时钟）：4 次失败不锁；第 5 次锁 30s；再失败翻倍 60/120/240/
    /// 480/960→封顶 900；成功清零；窗净空（15min 无失败）重置。
    #[test]
    fn login_backoff_curve() {
        let b = LoginBackoff::new();
        let mut t = 1_000u64;
        // ① 1–4 次失败：不锁。
        for i in 1..5 {
            b.on_failure("alice", t);
            assert!(
                b.check("alice", t + 1).is_none(),
                "第 {i} 次失败不锁（阈值 5）"
            );
            t += 10;
        }
        // ② 第 5 次：锁 30s。
        b.on_failure("alice", t);
        assert_eq!(b.check("alice", t), Some(30));
        assert_eq!(b.check("alice", t + 29), Some(1));
        assert!(b.check("alice", t + 30).is_none(), "锁到期即放");
        // ③ 再失败翻倍：60/120/240/480；第 10 次（excess=5）960 → 封顶 900。
        for expect in [60u64, 120, 240, 480] {
            t += 60;
            b.on_failure("alice", t);
            assert_eq!(b.check("alice", t), Some(expect), "翻倍至 {expect}");
        }
        t += 60;
        b.on_failure("alice", t);
        assert_eq!(b.check("alice", t), Some(900), "封顶 900");
        // ④ 成功清零（即使锁定期内——成功即证明合法用户拿回了账号）。
        b.on_success("alice");
        assert!(b.check("alice", t).is_none());
        // ⑤ 窗净空重置：4 失败 + 跨窗（>15min）后再失败 = 新窗第 1 次（不锁）。
        let b2 = LoginBackoff::new();
        let t0 = 10_000u64;
        for i in 0..4 {
            b2.on_failure("bob", t0 + i);
        }
        b2.on_failure("bob", t0 + FAIL_WINDOW_SECS + 1);
        assert!(
            b2.check("bob", t0 + FAIL_WINDOW_SECS + 2).is_none(),
            "窗净空后重新起算"
        );
        // ⑥ 不同用户互不影响。
        assert!(b2.check("carol", t0).is_none());
    }

    /// 令牌桶（注入时钟）：突发 10 枚即时放行；第 11 枚拒（429 面）；按 10/min
    /// 回填（6s 回 1 枚）；不同 IP 独立桶。
    #[test]
    fn ip_token_bucket() {
        let b = IpBuckets::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let t0 = 100u64;
        // 突发 10 枚：同刻取（离散时钟下无回填掺入——曲线本身在回填用例验证）。
        for i in 0..10 {
            assert!(b.allow(ip, t0).is_ok(), "突发 10 内第 {} 枚放行", i + 1);
        }
        assert!(b.allow(ip, t0).is_err(), "第 11 枚拒");
        // 同刻重试仍拒（无回填）。
        assert!(b.allow(ip, t0).is_err());
        // 6s 回填 ≈1 枚（10/min ⇒ 6s/枚；浮点取整保守——7s 后必满 1 枚）。
        assert!(b.allow(ip, t0 + 7).is_ok(), "回填一枚");
        assert!(b.allow(ip, t0 + 7).is_err(), "再取仍需等");
        // 不同 IP 独立桶。
        let ip2: IpAddr = "127.0.0.2".parse().unwrap();
        assert!(b.allow(ip2, t0).is_ok());
    }

    /// 审计环：stderr 同步 + 内存 ≤200 + 新→旧序 + denied 行亦留痕。
    #[test]
    fn audit_ring_cap_and_order() {
        let a = AuditLog::new();
        let t0 = 7u64;
        a.record(t0, "alice", "session.login", "alice", Origin::Vpn, "ok");
        a.record(
            t0 + 1,
            "bob",
            "user.create",
            "carol",
            Origin::Loopback,
            "denied",
        );
        let es = a.entries_newest_first();
        assert_eq!(es.len(), 2);
        assert_eq!(es[0].action, "user.create", "新→旧");
        assert_eq!(es[0].result, "denied", "denied 也记录");
        assert_eq!(es[1].origin, Origin::Vpn);
        // 环 200 上限（挤最旧）。
        for i in 0..AUDIT_CAP + 37 {
            a.record(
                t0 + i as u64 + 2,
                "u",
                "peer.kick",
                "dev",
                Origin::Loopback,
                "ok",
            );
        }
        assert_eq!(a.len(), AUDIT_CAP, "环上限 200");
        assert_eq!(a.entries_newest_first()[0].ts, t0 + AUDIT_CAP as u64 + 38);
    }
}
