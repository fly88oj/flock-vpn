//! apply 回调钩子（§2.2 吊销传播界 + vpn-mesh §5.2 租约冲突）。
//!
//! 每台服务器在**自己的日志 apply 回调**里：
//! (a) 推进 revocation_epoch、失效记录缓存（由 [`crate::sm`] 维护）；
//! (b) **杀死本地该设备会话**（[`SyncHooks::on_revocation_applied`]——装配层注入会话
//!     管理器；本 crate 提供 registry 与测试记录器）；
//! (c) 清拒其票据（票据 epoch < 当前 epoch 即拒——[`crate::ticket`] 消费 epoch）。
//!
//! 租约冲突（新者胜 + 旧端踢会话）：[`SyncHooks::on_lease_evicted`]。

use std::sync::{Arc, Mutex};

use crate::state::RevocationEffect;

/// 吊销传播事件（apply 回调现场产出）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationEvent {
    pub device: [u8; 32],
    pub new_epoch: u64,
    /// 触发转移的日志 index（定位与断言用）。
    pub log_index: u64,
}

/// 装配层注入的本地副作用钩子（默认全空；server 装配批次接会话管理器）。
pub trait SyncHooks: Send + Sync + 'static {
    /// 吊销/禁用已在本节点 apply：杀本地该设备会话 + 清拒票据。
    fn on_revocation_applied(&self, _ev: RevocationEvent) {}
    /// 该设备的在线租约被更新的租约取代（新者胜）：踢出本地会话。
    fn on_lease_evicted(&self, _device: &[u8; 32]) {}
}

/// 钩子注册表（状态机 apply 与租约冲突路径调用；内部 `Arc` 共享——SM 核与 LeaseTable
/// 可共用同一实例，注册一次全网关生效）。
#[derive(Clone, Default)]
pub struct HookRegistry {
    hooks: Arc<Mutex<Vec<Arc<dyn SyncHooks>>>>,
}

impl HookRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册一个钩子。
    pub fn add(&self, h: Arc<dyn SyncHooks>) {
        self.hooks.lock().expect("hook registry").push(h);
    }

    /// 触发吊销传播钩子（幂等：每条阻断性转移恰好一次）。
    pub fn fire_revocation(&self, ev: RevocationEffect, log_index: u64) {
        let event = RevocationEvent { device: ev.device, new_epoch: ev.new_epoch, log_index };
        for h in self.hooks.lock().expect("hook registry").iter() {
            h.on_revocation_applied(event);
        }
    }

    /// 触发租约冲突踢出钩子。
    pub fn fire_lease_evict(&self, device: &[u8; 32]) {
        for h in self.hooks.lock().expect("hook registry").iter() {
            h.on_lease_evicted(device);
        }
    }
}

impl std::fmt::Debug for HookRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookRegistry")
            .field("n", &self.hooks.lock().expect("hook registry").len())
            .finish()
    }
}

/// 测试记录器（cluster 断言用：epoch 前进 + 杀会话钩子时序）。
#[derive(Debug, Default)]
pub struct HookRecorder {
    pub revocations: Mutex<Vec<RevocationEvent>>,
    pub evictions: Mutex<Vec<[u8; 32]>>,
}

impl HookRecorder {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn revocations(&self) -> Vec<RevocationEvent> {
        self.revocations.lock().expect("revocations").clone()
    }

    pub fn evictions(&self) -> Vec<[u8; 32]> {
        self.evictions.lock().expect("evictions").clone()
    }

    /// 指定设备的吊销事件数。
    pub fn revocation_count(&self, device: &[u8; 32]) -> usize {
        self.revocations().iter().filter(|e| &e.device == device).count()
    }
}

impl SyncHooks for HookRecorder {
    fn on_revocation_applied(&self, ev: RevocationEvent) {
        self.revocations.lock().expect("revocations").push(ev);
    }
    fn on_lease_evicted(&self, device: &[u8; 32]) {
        self.evictions.lock().expect("evictions").push(*device);
    }
}
