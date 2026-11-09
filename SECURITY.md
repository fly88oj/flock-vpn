# 安全策略（SECURITY）

适用范围：本仓（fly88oj/flock-vpn）的 flock-server / flock-client / flock-frpc /
flock-sync 及 deploy/ 部署资产。密码学协议本体（kem/envelope/sig/pake/session/mux/
compress/trust/roster）在独立仓 [fly88oj/flock-protocol](https://github.com/fly88oj/flock-protocol)——
协议层漏洞请到该仓报告。

## 报告渠道

**GitHub 私有漏洞报告（Private Vulnerability Reporting）**：

1. 打开 <https://github.com/fly88oj/flock-vpn/security/advisories>
2. 「Report a vulnerability」→ 填写复现步骤 / 影响面 / 建议修复

或经仓库 Security 标签页进入。请**勿**对未修复漏洞开公开 issue/PR/讨论。
响应目标：72 小时内确认，修复窗口按严重度评估，修复后公开致谢（除非你要求匿名）。

## 支持版本

| 版本 | 状态 |
|---|---|
| main（0.1.x 开发线） | 支持 |
| 旧 tag | 不支持 |

## 威胁边界摘要

完整论述见 [docs/design.md §2.5](docs/design.md#25-威胁模型边界明确声明防止安全主张被误读为-peer-级-e2e)。
报告前请先对照——以下四条是**已声明的接受边界**，不算漏洞：

1. **跨 peer 流量在接入服务器明文**：首版 hub-and-spoke，客户端互访流量在接入服务器
   解密后转发；任一台在册服务器可观察/篡改经其转发的跨 peer 流量（与 Tailscale
   「协调服务器无法解密」根本不同）。peer 间端到端 overlay 加密列入路线图。
2. **任一服务器可离线字典全部口令**：攻破任一台在册服务器即得 OPRF key，可对全部
   用户口令离线字典（OPAQUE aPAKE 模型固有；argon2id 是唯一减速带）。OPRF key
   门限化列入路线图。
3. **TOFU 不防首登在线 MITM**：首次连接的信任建立残余风险；组织场景强制邀请文件。
4. **中转与链路观察者**：FRP 中转/链路观察者只见密文与长度（长度侧信道对策 =
   压缩档位）；ChmlFrp 面板凭据通道风险见设计 §5。

链路形态（Direct 直连 / FRP 中转）对协议层完全同构：任何链路上第三方只见本协议
密文。超出上述边界的破坏（如伪造会话、跨设备解密、重放成功、在线口令字典）属于
本政策受理范围。
