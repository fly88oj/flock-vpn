//! admin loopback 端点（docs/design.md §3.11 进程入口的运维面）。
//!
//! 邀请签发/兑换/设备注册/吊销等 NetState 写操作的**进程内单写者入口**：redb 由服务进程
//! 独占写，CLI 子命令（`invite`/`redeem`/`device-add`/`revoke`）经此 TCP 端点进入
//! （127.0.0.1 绑定 = 认证边界；容器形态不映射宿主——`docker compose exec` 走容器网络）。
//! M4 起这些操作迁移进 Raft 管理操作（§3.10 admin_op，须集群根密钥签名）。

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::control::DevicePubs;
use crate::netstate::{NetState, RedeemRequest};
use crate::server::ServerCore;

/// 单条 admin 消息上限。
const MAX_ADMIN_MSG: usize = 256 * 1024;

async fn send_msg<S: AsyncWrite + Unpin, M: Serialize>(io: &mut S, msg: &M) -> std::io::Result<()> {
    let bytes = postcard::to_allocvec(msg).map_err(|e| std::io::Error::other(e.to_string()))?;
    if bytes.len() > MAX_ADMIN_MSG {
        return Err(std::io::Error::other("admin msg too large"));
    }
    io.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    io.write_all(&bytes).await?;
    io.flush().await
}

async fn recv_msg<S: AsyncRead + Unpin, M: for<'de> Deserialize<'de>>(
    io: &mut S,
) -> std::io::Result<M> {
    let mut hdr = [0u8; 4];
    io.read_exact(&mut hdr).await?;
    let len = u32::from_le_bytes(hdr) as usize;
    if len == 0 || len > MAX_ADMIN_MSG {
        return Err(std::io::Error::other("admin frame length"));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    postcard::from_bytes(&buf).map_err(|e| std::io::Error::other(e.to_string()))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AdminRequest {
    /// 签发邀请（返回 v3 邀请文件全文 b64）。
    Invite { ttl_secs: u64 },
    /// 兑换邀请（无既有会话时的开户路径：管理操作语义，§1.3.3f）。
    Redeem {
        invite_b64: String,
        username: String,
        device: DevicePubs,
    },
    /// 直接注册设备（TOFU 流程的服务器侧预置；管理操作）。
    DeviceAdd {
        username: String,
        device: DevicePubs,
    },
    /// 吊销设备（推进 epoch + 杀本地会话）。
    Revoke { device: [u8; 32] },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AdminResponse {
    Invite { invite_b64: String },
    Redeemed { device_id: [u8; 32], vip: [u8; 4] },
    DeviceAdded { device_id: [u8; 32], vip: [u8; 4] },
    Revoked { epoch: u64 },
    Err { msg: String },
}

fn b64_encode(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(b)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let t = s.trim();
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(t)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(t))
        .map_err(|e| format!("b64: {e}"))
}

/// 启动 admin 端点（返回任务句柄；绑定失败即 Err）。
pub async fn serve(
    core: std::sync::Arc<ServerCore>,
    bind: std::net::SocketAddr,
) -> std::io::Result<JoinHandle<()>> {
    let listener = TcpListener::bind(bind).await?;
    Ok(tokio::spawn(async move {
        loop {
            let Ok((mut io, _)) = listener.accept().await else {
                return;
            };
            let core = core.clone();
            tokio::spawn(async move {
                let _ = handle_conn(&core, &mut io).await;
            });
        }
    }))
}

async fn handle_conn(core: &ServerCore, io: &mut TcpStream) -> std::io::Result<()> {
    let req: AdminRequest = recv_msg(io).await?;
    let resp = dispatch(core, req);
    send_msg(io, &resp).await
}

fn dispatch(core: &ServerCore, req: AdminRequest) -> AdminResponse {
    let net: &dyn NetState = &*core.store;
    match req {
        AdminRequest::Invite { ttl_secs } => match core.mint_invite(ttl_secs) {
            Ok(bytes) => AdminResponse::Invite {
                invite_b64: b64_encode(&bytes),
            },
            Err(e) => AdminResponse::Err { msg: e },
        },
        AdminRequest::Redeem {
            invite_b64,
            username,
            device,
        } => {
            let invite = match b64_decode(&invite_b64) {
                Ok(v) => v,
                Err(e) => return AdminResponse::Err { msg: e },
            };
            match net.redeem_invite(RedeemRequest {
                invite_bytes: &invite,
                username: &username,
                device_x25519: device.x25519,
                device_ed25519: device.ed25519,
                expected_root_pub: *core.identity.root_pub.as_bytes(),
                expected_cluster_id: core.identity.cluster_id.0,
                now_unix: chml_protocol::trust::now_unix(),
            }) {
                Ok(out) => AdminResponse::Redeemed {
                    device_id: out.device_id,
                    vip: out.vip,
                },
                Err(e) => AdminResponse::Err { msg: e.to_string() },
            }
        }
        AdminRequest::DeviceAdd { username, device } => {
            match net.register_device(&username, device.x25519, device.ed25519) {
                Ok(row) => AdminResponse::DeviceAdded {
                    device_id: chml_protocol::session::DeviceId(
                        *chml_protocol::ed25519_dalek::VerifyingKey::from_bytes(&device.ed25519)
                            .expect("32B ed25519")
                            .as_bytes(),
                    )
                    .0,
                    vip: row.vip,
                },
                Err(e) => AdminResponse::Err { msg: e.to_string() },
            }
        }
        AdminRequest::Revoke { device } => {
            let id = chml_protocol::session::DeviceId(device);
            match net.revoke(&id) {
                Ok(epoch) => {
                    core.sessions.kill(&device);
                    AdminResponse::Revoked { epoch }
                }
                Err(e) => AdminResponse::Err { msg: e.to_string() },
            }
        }
    }
}

/// admin 客户端（CLI 子命令用；一请求一连接）。
pub async fn client(
    addr: std::net::SocketAddr,
    req: AdminRequest,
) -> Result<AdminResponse, String> {
    let mut io = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    send_msg(&mut io, &req).await.map_err(|e| e.to_string())?;
    let resp: AdminResponse = recv_msg(&mut io).await.map_err(|e| e.to_string())?;
    Ok(resp)
}
