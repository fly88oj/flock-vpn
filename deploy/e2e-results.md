# M5 e2e 实测结果（docs/design.md §6.3 A1–A16）

- 执行：2026-11-01 15:45:03 起；主机 = Windows + Docker Desktop 29.8.2（WSL2）；脚本 deploy/e2e_assert.sh
- 拓扑：deploy/e2e.yml——三网隔离（flockpub 172.28.0.0/24 / srvmesh 172.29.0.0/24 / link-a·b 各 /29）；frps-a/b = 原版 frp 0.71.1 + frpc-a/b 边车；server-a/b/c = 3 voter（Frp/Frp/Direct 混布，srvmesh 服务器-服务器 profile 互连）；client-1/2/3 钉死 frps-a:23000 / frps-b:23001 / 172.28.0.22:9443
- VIP：server a/b/c = 100.64.0.1/100.64.0.2/100.64.0.3；client 1/2/3 = 100.64.0.11/100.64.0.17/100.64.0.13（Raft 分配，从 .11 起）

| 结果 | 断言 | 说明 |
|---|---|---|
| PASS|A1|256 字节全集 + 1MiB 随机经 frps-a:23100 与 frps-b:23101 echo 往返 sha256 一致 |
| PASS|A2|同服 ping 100.64.0.1 与跨服互 ping（c1↔c2）均 3/3 0% 丢包 |
| PASS|A3|tun0 mtu=1280；-s 1252 -M do 通（1252+28=1280） |
| PASS|A4|iperf3 sender = 518 Mbits/sec（≥ 100） |
| PASS|A5|6s 切 frps-b:23001（全新握手），ping 100.64.0.2 恢复，VIP 不变（100.64.0.11），I0 未出现（server-b 无 TOFU 日志） |
| PASS|A6|≤5s（实测 1s 内）：server-b 会话被杀（apply 回调）、epoch 前进（server-b 视角 2→3）、新握手被拒（15s 观察窗无新连接） |
| PASS|A7-A2|停 a 后同服（c1→B、c3→C）与跨服（c2↔c3 经 B→C FRWD）全 0 丢包 |
| PASS|A7-A6|≤5s（实测 1s 内）：server-b 会话被杀（apply 回调）、epoch 前进（server-c 视角 3→4）、新握手被拒（15s 观察窗无新连接） |
| PASS|A7|重选举 5s（≤15s，leader=node2）；A2/A6 重跑通过；server-a 恢复并重回集群；client-1 回钉死端点 |
| PASS|A8|100 流 × 60s × 4KiB 双向无错（hundred_streams_sixty_seconds_sustained 真执行 ok） |
| PASS|A9|双侧 27s 检出 dead-link 进入重连；网络恢复 + re-pin 后 ping 恢复（≤30s 预算） |
| PASS|A10|300s 负载 rekey 3 次（≥2）；最小逐秒区间 320.24 Mbps（无 >1s 平台） |
| PASS|A11|中转字节量 zeros=4750000B ≈ random=4750000B（差 <5% ⇒ 压缩未启用）；compress 单测（默认关/非膨胀回退）全绿 |
| PASS|A12|重放拒+计数、伪造 ≤N 存活/100 次断链 复跑通过（2/2 套） |
| PASS|A13|172.28.0.20/.21:9443 均不可达（Frp 形态两台不挂 flockpub——拓扑有效性） |
| PASS|A14|FRWD 计数 0→4；srvmesh 断后互 ping 断/本服通、恢复回通；伪造 src 违例 +20 且 client-2 未收到（捕获面对照有效） |
| PASS|A15|迁移后 1s（≤35s）client-1→client-2 ping 恢复；locate 重定向计数未动（租约事件推送 ≤1s 先于陈旧窗生效；redirect 路径由 flock-sync forward 单测覆盖） |
| PASS|A16|直连会话（无 I0，端点 172.28.0.22:9443）；ping 100.64.0.3 与 c1/c2↔c3 互 ping 0 丢包（Direct↔Frp 跨服同构）；server-c 无 frp 进程、无边车 |

PASS=18 FAIL=0

脚注（如实记录）：
1. client-2 终值 VIP 高于 .12：A6/A7-A6 两次吊销各消耗一个设备身份（吊销终态、IP 不复用），
   脚本以「新设备身份 re-enroll」复活通道；A15 迁移断言按当时 VIP 执行。
2. A15 的 locate 重定向计数若未动：迁移恢复（实测 1s）由租约事件推送（≤1s）在陈旧窗生效前
   完成——NOT_HERE→location_query 路径未被触发时如实记录；该路径由 flock-sync tests/forward
   单测覆盖。
3. A8/A11/A12 为设计指定的单测复跑入口（A8：session_mux #[ignore] 档 100 流×60s，以 --ignored
   真执行——判据要求具名测试 ok 且 ≥1 passed，空跑不得记 PASS；A11：compress 档；A12：replay/forge）。
4. 实测暴露并修复的三处产品缺陷：redb vote 编解码不对称（tests/store_reopen 回归）；长寿命
   会话租约蒸发（lease_refresh_loop TTL/3 续期）；互连全局锁跨网络 await + 无拨号预算（锁外
   拨号 + TcpFabric 3s 预算）。
5. link-a/b 网段为 /29：Docker bridge 需网关+广播各占一位，/30 撑不起「网关 + 边车 + server」
   三元（隔离语义不变）。