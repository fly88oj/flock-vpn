# 多机组网实测（multinode-test）——Windows Docker × jowency LXD 真机

- 日期：2026-11-07；仓库 HEAD `b9217c3`（main）；执行面：Windows 10（Docker Desktop
  29.8.2 / WSL2，非提升 Git Bash）+ jowency（Ubuntu 26.04，LXD 5.21.9，lxdbr0
  10.100.0.0/24 NAT）。
- 资产：`deploy/multinode/`（README 有复刻步骤）；断言脚本
  `deploy/multinode/multinode_assert.sh`（退出码 0=全 PASS / 1=有 FAIL /
  2=bootstrap 失败 / 64=用法错）。
- 二进制：HEAD 源码经 `Dockerfile.buildbin`（rust:1.98-slim-bookworm，release
  --locked + strip）构建三个 Linux amd64 产物，tar-over-ssh 流式分发 jowency
  （sha256 双侧一致：`flock-client 05dd874a…`、`flock-server-direct 7d1dc954…`、
  `flock-server-mp 9d2b1134…`）。镜像复用 `flock/client:e2e`、`flock/server:e2e-a`
  只取工具面，**二进制以 HEAD 构建产物覆盖挂载**。

## 0. 连通性探针（第一步必做）与防火墙前置

| 探针 | 方法 | 结果 |
|---|---|---|
| Windows→jowency 入站 | jowency `python3` 监听 :19443；Windows Docker `nc` 连入 | **通**（服务端收到 `PROBE1_RECV_FROM ('192.168.31.244', 63683)`，载荷往返一致） |
| jowency→Windows 入站 | Windows `docker run -p 0.0.0.0:19444` echo；jowency `nc` | **通**（echo 全文往返：`payload-ack`） |

**Windows 入站可用 ⇒ 场景二保持原拓扑（server-1 在 Windows Docker）不降级**；
netsh 防火墙补测命令已备于真机清单（deploy/multinode/README.md「防火墙前置」）。

环境拦截实录（任务给定假设「LXD 容器出站直达 LAN」与实测不符，两道既有拦截，
测试窗口临时放行、测毕回收）：

1. jowency `nft ip filter DOCKER-USER` 既设 `iifname "lxdbr0" ip daddr
   192.168.0.0/16 ct state new drop`（计数实测 +14 命中）——拦 LXD→Windows
   （场景二 flock-s2→server-1 的 Raft 拨号 :9500、c6 端点等价直连 :9443）。
   临时放行（仅 dst=192.168.31.244、tcp 9443/9500，`comment "flock-mn-test-temp"`，
   handle 194）；测毕按 handle 原样删除（清理节确认）。
2. jowency `ufw` default deny incoming 且「LAN trusted」不含 10.100.0.0/24——拦
   LXD 容器→宿主发布口（场景一 LXD 客户端→:9443、场景二→frps :7000/:24000）。
   临时放行 3 条 `allow in on lxdbr0 to any port {9443,7000,24000}/tcp
   comment "flock-mn-test"`；测毕 `ufw delete` 同文三条（清理节确认）。

另：jowency 双 LAN IP（ssh 侧 .221 / 到 Windows 的路由 src .46）——proxy/frps 均
听 0.0.0.0，端点统一钉 .221（`JOW_LAN_IP` 环境变量，见 lxd-setup.sh 头注）。

## 1. 场景一【单 Server · Direct】——S1–S3 全 PASS（PASS=4 FAIL=0）

拓扑：flock-s1（jowency LXD，Direct :9443，proxy device 发布 .221:9443；VIP
100.64.0.1，tun0 + rp_filter 由服务端自配）+ 客户端 ×4（Windows Docker
flock-wc1/wc2 + LXD flock-c3/c4；全部 m7 admin 开户路径：gen-keys → device-add
→ invite → ingest → vip → login → service daemon）。客户端均直连
192.168.31.221:9443（Docker bridge → LAN → LXD proxy）。

### S1 全网状 ping 矩阵（每格 3 包；实测值）

| src | dst | VIP | 丢包 | avg rtt(ms) | 路径 | 结果 |
|---|---|---|---|---|---|---|
| wc1 | wc2 | 100.64.0.3 | 0% | 112.368 | 同宿主 | PASS |
| wc1 | c3 | 100.64.0.4 | 0% | 116.803 | 跨机 Win-Docker→LXD | PASS |
| wc1 | c4 | 100.64.0.5 | 0% | 151.815 | 跨机 Win-Docker→LXD | PASS |
| wc1 | server | 100.64.0.1 | 0% | 84.262 | 跨机 Win-Docker→LXD | PASS |
| wc2 | wc1 | 100.64.0.2 | 0% | 46.3 | 同宿主 | PASS |
| wc2 | c3 | 100.64.0.4 | 0% | 87.477 | 跨机 Win-Docker→LXD | PASS |
| wc2 | c4 | 100.64.0.5 | 0% | 106.581 | 跨机 Win-Docker→LXD | PASS |
| wc2 | server | 100.64.0.1 | 0% | 50.017 | 跨机 Win-Docker→LXD | PASS |
| c3 | wc1 | 100.64.0.2 | 0% | 111.531 | 跨机 LXD→Win-Docker | PASS |
| c3 | wc2 | 100.64.0.3 | 0% | 92.859 | 跨机 LXD→Win-Docker | PASS |
| c3 | c4 | 100.64.0.5 | 0% | 69.396 | 同宿主 | PASS |
| c3 | server | 100.64.0.1 | 0% | 37.901 | 跨机 LXD→Win-Docker | PASS |
| c4 | wc1 | 100.64.0.2 | 0% | 75.101 | 跨机 LXD→Win-Docker | PASS |
| c4 | wc2 | 100.64.0.3 | 0% | 82.931 | 跨机 LXD→Win-Docker | PASS |
| c4 | c3 | 100.64.0.4 | 0% | 76.886 | 同宿主 | PASS |
| c4 | server | 100.64.0.1 | 0% | 45.95 | 跨机 LXD→Win-Docker | PASS |
| server(s1) | wc1 | 100.64.0.2 | 0% | 82.347 | LXD 本机 | PASS |
| server(s1) | wc2 | 100.64.0.3 | 0% | 82.291 | LXD 本机 | PASS |
| server(s1) | c3 | 100.64.0.4 | 0% | 34.184 | LXD 本机 | PASS |
| server(s1) | c4 | 100.64.0.5 | 0% | 47.436 | LXD 本机 | PASS |

**[PASS] S1 | 全网状：4 客户端 ×（server+3 peer）+ server→4 客户端，全部 0 丢包**（20/20 格）。
跨机（Win-Docker↔LXD）avg rtt 实测带宽 46–192ms（Wi-Fi LAN + Docker NAT + LXD
proxy 多跳），同宿主对照 34–152ms。

### S2 peers 名册（任一客户端含全部 5 节点；hostname/账户/在线/延迟非 —）

`flock-client peers` 实测输出（wc1 视角）：

```
VIP        | 主机名                 | 账户                   | 类型     | 状态 | 延迟(ms) | ↓流量(B/s) | ↑流量(B/s)
----------------------------------------------------------------------------------------------------
100.64.0.1 | 192.168.31.221:9443 | 15334125528595525502 | server | 在线 | 68     | 80       | 87
100.64.0.2 | flock-wc1(self)     | mncw1                | device | 在线 | —      | 12       | 11
100.64.0.3 | flock-wc2           | mncw2                | device | 在线 | 135    | 25       | 24
100.64.0.4 | flock-c3            | mnc3                 | device | 在线 | 104    | 31       | 28
100.64.0.5 | flock-c4            | mnc4                 | device | 在线 | 104    | 36       | 34
```

c3 视角同构 5 行（self 行换位；server 行延迟 50ms、其余 device 行 100–144ms 全非 —）。
**[PASS] S2-w / S2-l**（--json 机读档断言：rows=5、offline=0、非自身行 latency_ms 全非空）。

### S3 VIP 分配表

| 节点 | 位置 | VIP |
|---|---|---|
| flock-s1（server） | jowency LXD | 100.64.0.1（固定） |
| flock-wc1 | Windows Docker | 100.64.0.2 |
| flock-wc2 | Windows Docker | 100.64.0.3 |
| flock-c3 | jowency LXD | 100.64.0.4 |
| flock-c4 | jowency LXD | 100.64.0.5 |

**[PASS] S3**（4 客户端 VIP 唯一，分配序 .2→.5 与 device-add 顺序一致）。
服务端 stats（断言后捕获）：`epoch=0 sessions_online=4 tun_vip=100.64.0.1`；
`src_vip_mismatches=26`（无 kill/断会话；来源未逐包归因——观测计数如实记录，
不在本断言集内）。

## 2. 场景二【双 Server · 跨机 Raft + 双传输】——R1–R5 全 PASS（PASS=6 FAIL=0）

拓扑：server-1 = flock-srv1（Windows Docker；Direct，发布 0.0.0.0:9443 + Raft
0.0.0.0:9500；VIP .1）；server-2 = flock-s2（jowency LXD；Frp 接入——宿主 frps
:7000，进程内 flock-frpc 注册用户口 24000，Raft :9500 经 proxy device 发布；VIP .2）。
`init-cluster --voters 2 --endpoints 192.168.31.244:9443,192.168.31.221:24000`
（cluster_id daf9930b…）→ 双侧 enroll → cluster-bootstrap（经 srv1 admin 提交，
2-voter quorum 跨真实网络）。客户端：flock-2w1/2w2（Windows Docker → server-1
直连）、flock-c5/c6（LXD → frps 用户口 24000）；开户全部经 s2 admin（device-add +
cluster-invite 根签 v3）——本身即「任一台等价服务」的证据。

### R1 Raft 跨机一致性（两 server stats 摘录）

| 字段 | srv1（Win-Docker） | s2（LXD/Frp） |
|---|---|---|
| epoch | 0 | 0 |
| leader | 2 | 2 |
| node_id | 1 | 2 |
| sessions_online | 2 | 2 |
| tun_vip | 100.64.0.1 | 100.64.0.2 |
| ic_dial_ok/err | 1/0 | 5/0 |
| ic_rpc_ok/err | 133/0 | 298/0 |
| lease_entries | 6 | 6 |

**[PASS] R1**：epoch/leader 双侧一致；同一注册表由 R4（经 s2 吊销 srv1 侧会话立杀）
与 R5（双侧名册一致）复核。

### R2 跨服转发矩阵（srv1 侧 ↔ srv2 侧；ForwardEnvelope 经真实网络，每格 3 包）

| src | src 侧 | dst | dst 侧 | VIP | 丢包 | avg rtt(ms) | 结果 |
|---|---|---|---|---|---|---|---|
| 2w1 | srv1直连 | c5 | srv2中转 | 100.64.0.13 | 0% | 91.361 | PASS |
| c5 | srv2中转 | 2w1 | srv1直连 | 100.64.0.11 | 0% | 123.223 | PASS |
| 2w1 | srv1直连 | c6 | srv2中转 | 100.64.0.14 | 0% | 144.427 | PASS |
| c6 | srv2中转 | 2w1 | srv1直连 | 100.64.0.11 | 0% | 138.218 | PASS |
| 2w2 | srv1直连 | c5 | srv2中转 | 100.64.0.13 | 0% | 93.578 | PASS |
| c5 | srv2中转 | 2w2 | srv1直连 | 100.64.0.12 | 0% | 108.579 | PASS |
| 2w2 | srv1直连 | c6 | srv2中转 | 100.64.0.14 | 0% | 118.539 | PASS |
| c6 | srv2中转 | 2w2 | srv1直连 | 100.64.0.12 | 0% | 113.6 | PASS |
| 2w1 | srv1直连 | 2w2 | srv1直连 | 100.64.0.12 | 0% | 36.432 | PASS（同侧对照） |
| c5 | srv2中转 | c6 | srv2中转 | 100.64.0.14 | 0% | 63.46 | PASS（同侧对照） |

**[PASS] R2**：跨服 8 对全部 0 丢包。

### R3 任意端点等价

c6 由 frps 用户口 24000 切 server-1 直连口 192.168.31.244:9443（LXD→Windows 直连，
经临时 nft 例外）：重连后 `已连接 192.168.31.244:9443`，**VIP 不变（100.64.0.14）**、
名册行数一致、ping server-1 VIP 通。**[PASS] R3**。

### R4 吊销跨机传播 ≤5s（经 s2 admin 吊销 srv1 侧 2w2）

实测 **409ms**（前次全量复跑 446ms / 647ms）：revoke 经 s2 提交（Raft 跨机 commit）
→ srv1 `sessions_online 3→2`（apply 回调杀会话）→ epoch `0→1`（s2 视角可见）→
15s 观察窗 2w2 无新「已连接」（新握手被拒；客户端重连日志持续 `拨号失败`）。
**[PASS] R4**。

### R5 双侧 peers 名册（吊销行按设计出名册）

`flock-client peers` 实测（2w1=srv1 侧；c5=srv2 侧同构）：

```
VIP         | 主机名                  | 账户    | 类型     | 状态 | 延迟(ms)
-----------------------------------------------------------------------
100.64.0.1  | 192.168.31.244:9443  | 1     | server | 在线 | 96
100.64.0.2  | 192.168.31.221:24000 | 2     | server | 在线 | —
100.64.0.11 | flock-2w1(self)      | mn2w1 | device | 在线 | —
100.64.0.13 | flock-c5             | mn2c5 | device | 在线 | 99
100.64.0.14 | flock-c6             | mn2c6 | device | 在线 | 102
```

**[PASS] R5-w / R5-l**。语义校准（源码 server.rs:897「名册 = Active 行快照」）：
吊销的 2w2（.12）**不出名册**（注册表留档审计、IP 永不复用——R4 epoch/杀会话面复核），
双侧各 5 行 = 2 server + 3 Active 客户端，行集合一致。

两处设计内行为（如实记录，非缺陷）：
- **远端 server 行延迟 —**：client ping 非接入 server 的 VIP 按 §2.2 转发判定 4
  回 ICMP unreachable（server 非「设备租约」转发目标；实测 2w1→.2、c5→.1 均
  `+3 errors 100% loss`），名册探测超时 ⇒ 延迟列 —。
- **吊销后名册 TicketBad 瞬窗**：全局 revocation_epoch 前进使在途票据全部失效
  （票据 epoch 检查），daemon 25s 重登保持窗内 peers 报
  `TicketBad: ticket rejected`，窗后自愈（实测 `login ok … epoch=1` 恢复）；
  断言脚本按 m7（commit 76241a2）先例做了有界重试。

## 3. 真机清单（本会话未执行，留待人工）

1. **Windows 宿主节点（非 Docker 入网）**：管理员 PowerShell 运行
   `deploy/multinode/windows-host-node.ps1`（自动：取/编译
   `target\release\flock-client.exe`、生成 %ProgramData%\FlockVPN\client.toml 指向
   场景一 server、经 ssh 对 flock-s1 执行 device-add/invite、UAC 自提权、
   `flock-client run`、ping 矩阵输出；本会话 shell 非提升故未执行）。
2. **Windows 入站防火墙补测**（仅探针被拦的环境）：管理员运行
   `netsh advfirewall firewall add rule name="flock-mn" dir=in action=allow protocol=TCP localport=9443,9500`。
3. **场景二降级拓扑复刻**（Windows 入站不可用时）：两台 server 均落 LXD（各 proxy
   device 发布），Windows 只跑出站客户端——配置改法见 deploy/multinode/README.md。

## 4. 清理确认（测毕执行，双侧）

- LXD：`flock-s1/s2/c3/c4/c5/c6` 六容器 `lxc delete --force`（proxy device 随容器
  消亡）；frps 进程停；`~/flock-mn`（二进制/集群材料/日志）收走。既有容器
  （dmgvm、krymux-a/b/c、l2ctest、uesktop-ui-audit）零触碰。
- nft 临时例外：`nft delete rule ip filter DOCKER-USER handle 194`（删后 `nft -a
  list chain` 确认只剩既设三条 drop，计数回到放行前语义）。
- ufw 临时规则：`ufw delete allow in on lxdbr0 to any port {9443,7000,24000} proto
  tcp comment "flock-mn-test"` 三条。
- Windows Docker：flock-* 容器与 flock-mn-* 命名卷全删（win-docker-cleanup.sh，
  down -v 语义）；`.tmp/flock-mn` 运行状态删除。
