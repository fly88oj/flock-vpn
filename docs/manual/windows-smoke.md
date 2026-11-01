# Windows 真机 --smoke 记录（docs/design.md §7-M3 手工清单）

> 2026-11-02 项目更名 ChmlVPN → **Flock VPN**：本文命令示例与输出样例中的二进制名（flock-client/flock-server）、容器/网络名（flock-m3-*）、路径（/etc/flock、/var/lib/flock）已按新命名同步；仓库目录更名 `E:\Works\FlockVPN` 经 junction 过渡（记录时目录名为 ChmlVPN；收尾步骤见 dir-rename-final.md）。

- 日期：2026-11-01
- 真机：Windows 10 Pro 26H2（build 26300，x64），管理员身份 **否**（`net session` → `ADMIN=no`；清单要求如实记录，不提权重跑）
- Docker：Docker Desktop 29.8.2（`docker info --format '{{.ServerVersion}}'`）
- 仓库：`E:\Works\FlockVPN` @ main 306688f（记录时为 ChmlVPN）
- 结论先行：**wintun 适配器创建与 `route add` 均要求管理员权限；非提升 shell 下分别报 `os error 5（拒绝访问）` 与「请求的操作需要提升」**。清单中依赖 tun 设备的三项（route print 路由、真机 tun MTU、经中转 ping server VIP）在非提升会话下**受阻**，受阻点与证据逐项列于 §4；其余项（拓扑、引导、wintun.dll 行为、宿主单测）已实测。容器内同版本数据面对照组全通（§5）。

---

## 1. 前置准备

### 1.1 wintun.dll（R13：随程序分发官方签名 DLL）

仓库不携带 wintun.dll（`find . -iname wintun*` 无结果），从官方构建取 0.14.1：

```
$ curl -fsSL -o wintun-0.14.1.zip https://www.wintun.net/builds/wintun-0.14.1.zip
$ sha256sum wintun-0.14.1.zip
07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51 *wintun-0.14.1.zip
$ unzip -o -q wintun-0.14.1.zip -d extracted     # 提取于全新目录 .tmp/wintun-dl/
$ cp .tmp/wintun-dl/extracted/wintun/bin/amd64/wintun.dll target/debug/wintun.dll
```

签名校验（PowerShell `Get-AuthenticodeSignature`）：`Status=Valid`，签名者
`CN=WireGuard LLC, O=WireGuard LLC, L=Boulder, S=Colorado, C=US`（427552 字节，amd64）。

tun-rs（锁定 2.8.16）在 Windows 侧经 `libloading` 运行时加载 `wintun.dll`
（默认文件名，`tun-rs-2.8.16/src/platform/windows/device.rs:48`：
`config.wintun_file.as_deref().unwrap_or("wintun.dll")`），放在可执行文件同目录
（`target/debug/`）即可被加载——本次实测 DLL 加载成功（若加载失败会是模块找不到类
错误，而非 §3 观察到的 error 5）。

### 1.2 拓扑：m3.yml 端口映射宿主

committed `deploy/m3.yml` 原不映射宿主（注释「用户口 27500/27501 容器网内可达，不映
射宿主」）。为满足本清单「宿主 client 指向 localhost 映射端点」，给 `frps` 服务加了仅
回环的端口映射（`git diff deploy/m3.yml` = 7 insertions, 1 deletion）：

```yaml
    ports:
      - "127.0.0.1:27500:27500"
      - "127.0.0.1:27501:27501"
```

`server-m3.toml` 的 advertise 端点是容器视角（`frps:27500`），宿主不可解析。按 M2
`server-frp.toml` 同形态（「M2 客户端在宿主 ⇒ 127.0.0.1 映射口」）把宿主视角变体
`.tmp/server-m3-host.toml`（唯一差异：`advertise_endpoint = "127.0.0.1:27500"`、
`extra_endpoints = ["127.0.0.1:27501"]`）运行时注入后重启 server：

```
$ export MSYS_NO_PATHCONV=1
$ docker compose -f deploy/m3.yml up -d
 Container flock-m3-frps-1 Recreated / Started（新增 127.0.0.1:27500-27501 映射）
$ docker compose -f deploy/m3.yml cp .tmp/server-m3-host.toml server:/etc/flock/server.toml
$ docker compose -f deploy/m3.yml restart server
$ docker compose -f deploy/m3.yml ps --format '{{.Name}} {{.Status}} {{.Ports}}'
flock-m3-frps-1   Up  127.0.0.1:27500-27501->27500-27501/tcp
flock-m3-server-1 Up
flock-m3-client-1 Up
```

server 就绪（日志）：`dataplane up: tun tun0 vip 100.64.0.1 route 100.64.0.0/16 +
rp_filter=1`、`listening on 0.0.0.0:9443 (mode: frp)`。宿主回环连通性：

```
PS> Test-NetConnection 127.0.0.1 -Port 27500
TcpTestSucceeded : True
```

### 1.3 宿主 client 测试配置与引导

测试配置 `.tmp/host-client.toml`（指向 localhost 映射端点）：

```toml
state_dir = "E:/Works/FlockVPN/.tmp/host-client-state"
tun_name = "tun0"
mtu = 1280
endpoints = ["127.0.0.1:27500", "127.0.0.1:27501"]
```

引导序（与 m3_assert.sh 同序，宿主侧手工）：

```
$ cargo run -p flock-client -- --config .tmp/host-client.toml gen-keys
device-id=2b7ddf35560aca5528e53f138393822e7f800333c9735ebeb3517a27052d017b
device-x=b+PDQoL3xTKMxgxumlunRkKLYWeL+0i9P96tB2tC5Uo
device-ed=XVFeoYKi5OA/PoDGa60ObX1bTCmJHbn1/Hcq7zg40c4

$ docker compose -f deploy/m3.yml exec -T server flock-server \
    --config /etc/flock/server.toml device-add \
    --user winhost --device-x "b+PDQoL3…" --device-ed "XVFeoYKi…"
device_id=5d515ea182a2e4e03f3e80c66bad0e6d7d5b4c29891db9f5fc772aef3838d1ce
vip=100.64.0.3                       # 容器 client 已占 100.64.0.2，本机分配 .3

$ docker compose -f deploy/m3.yml exec -T server flock-server \
    --config /etc/flock/server.toml invite --ttl-secs 86400 > .tmp/host-invite.b64
$ printf '100.64.0.3' > .tmp/host-client-state/vip

$ cargo run -p flock-client -- --config .tmp/host-client.toml invite .tmp/host-invite.b64
invite ok: cluster=d638c699732c629abeedb52dd1e722fc endpoints=2（已钉扎根公钥 + 存目录）
```

`endpoints=2` 即注入的宿主视角目录（127.0.0.1:27500 + 27501）——config 的端点覆盖与
目录一致（`override_endpoints` 端点↔材料同签校验可过，app/flock-client/src/main.rs:218-233）。

## 2. --smoke 实测

按清单命令形态（`--config` 与 `--smoke` 顺序无关，main.rs:58-85 解析）：

```
$ cargo run -p flock-client -- --smoke --config .tmp/host-client.toml
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.14s
     Running `target\debug\flock-client.exe --smoke --config .tmp/host-client.toml`
flock-client: tun: tun-rs create tun0: 拒绝访问。 (os error 5)
error: process didn't exit successfully: … (exit code: 2)
```

- `--smoke` 路径（main.rs:137-162）：`TunIo::open`（建 wintun 适配器）→ 打印
  `tun: tun0 mtu=1280 vip=…` → `route::apply` → 睡 2s → 拆设备。
- **实测在第一步（tun-rs `build_sync` 建适配器，tun.rs:99-104）即以 Windows
  error 5（ERROR_ACCESS_DENIED，拒绝访问）失败**，退出码 2；因此 tun 打印、路由
  Unsupported 打印、`smoke done` 均未到达。

## 3. wintun.dll 首次驱动安装/适配器创建的管理员权限行为（重点记录）

- 本机 **wintun 内核驱动已预装且在运行**（非本次清单首装；来源推断为本机 Tailscale——
  适配器列表含 `Tailscale Tunnel`）：
  ```
  $ sc query wintun
  SERVICE_NAME: wintun
          TYPE               : 1  KERNEL_DRIVER
          STATE              : 4  RUNNING
  PS> Get-CimInstance Win32_SystemDriver | ? {$_.Name -match 'wintun'}
  Name    State    PathName
  wintun  Running  C:\WINDOWS\system32\drivers\wintun.sys
  PS> (Get-Item C:\Windows\System32\drivers\wintun.sys).VersionInfo
  FileVersion : 0.14   ProductVersion : 0.14   CompanyName : WireGuard LLC
  ```
- 行为结论：**即便驱动已在驱动库且运行中，非提升进程调用 `WintunCreateAdapter`
  （经 tun-rs `DeviceBuilder::build_sync`）仍被拒——`os error 5 拒绝访问`**；即
  wintun 适配器「创建」这一步本身要求管理员权限，与驱动是否已首装无关。DLL 本体
  加载（含签名验证）不需要管理员——本次由普通用户权限进程加载成功后走到适配器
  创建才被拒。真机上的「首装」形态（驱动未在库时 `WintunCreateAdapter` 触发驱动
  安装）本机无法复现（驱动已存在），未验证——如实标注。

## 4. 清单逐项结果

| 清单项 | 结果 | 证据 |
|---|---|---|
| wintun 设备创建行为 | **受阻（权限）**：非提升 shell 创建报 `os error 5（拒绝访问）`，进程退出码 2；无适配器残留（`Get-NetAdapter` 无 tun0/wintun 新项） | §2 输出 |
| 路由注入（route print 100.64.0.0/10） | **受阻（权限）**，双重：① 代码路径——Windows 上 `route::apply` 本就返回显式 `Unsupported` 并给手工指令（route.rs:84-92：`route add 100.64.0.0/16 mask 255.255.0.0 <vip> metric 5`；smoke 中因 tun 先失败未打印，宿主单测 `route::tests::non_linux_apply_is_explicit_unsupported` 实测覆盖该路径）；② 手工注入——非提升 `route add` 被系统拒绝（下）。route print 全表 **无** 100.64.0.0 网段路由 | 下两块输出 |
| tun MTU 1280 | **受阻（同 tun 创建）**：spec 层 MTU=1280 已进配置与 `TunSpec`（config.rs:19-21 缺省 1280；tun.rs:33 `MTU=1280`），但真机接口级 MTU 需设备存活才能观测（`netsh interface ipv4 show subinterface`），非提升下设备建不出，未测得 | §2 |
| 经中转 ping 通 server VIP | **受阻（同 tun 创建）**：宿主 `ping 100.64.0.1` 2 发 0 收 100% 丢（无 tun/无路由，走默认网关黑洞）；中转 TCP 路径本身宿主可达（`Test-NetConnection 127.0.0.1:27500 → True`），容器内同版本数据面经同一 frps 中转 ping 通（§5 对照组） | 本节输出 |
| wintun.dll 首次驱动安装的管理员权限行为 | **已记录**（§3）：DLL 加载无需管理员；适配器创建需要（error 5）；驱动已预装（wintun.sys 0.14 RUNNING），真「首装」形态未验证 | §3 |

手工路由注入实测（两种前缀形态均试；`route.rs` 指令的 /16 形态 + §7-M5 清单的 /10 形态）：

```
$ route add 100.64.0.0 mask 255.255.0.0 100.64.0.3 metric 5
请求的操作需要提升。
rc=1
$ route add 100.64.0.0 mask 255.192.0.0 100.64.0.3 metric 5
请求的操作需要提升。
rc=1
```

宿主 ping（受阻佐证）：

```
$ ping -n 2 -w 2000 100.64.0.1
请求超时。×2
100.64.0.1 的 Ping 统计信息: 数据包: 已发送 = 2, 已接收 = 0, 丢失 = 2 (100% 丢失)
```

宿主单测（§7-M3「Windows 主机上 `cargo test -p flock-client`」，含路由 Unsupported
路径的真实执行）：

```
$ cargo test -p flock-client
test route::tests::non_linux_apply_is_explicit_unsupported ... ok
test route::tests::plan_defaults_to_100_64_slash16 ... ok
test route::tests::pool_mask_dotted ... ok
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.63s
```

## 5. 容器对照组（Linux 容器，同拓扑同二进制语义；非宿主清单项）

同一 m3 拓扑的容器 client（VIP 100.64.0.2，经 frps 中转）日志与实测：

```
client-1 | flock-client: tun tun0 mtu=1280 vip=100.64.0.2
client-1 | flock-client: route 100.64.0.0/16 → tun0 + rp_filter=1
client-1 | flock-client: 已连接 frps:27500（server=f2220c4ee069b62c93554fa5cdf05e09）
$ docker compose -f deploy/m3.yml exec -T client ip addr show tun0
3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1280 …
    inet 100.64.0.2/32 scope global tun0
$ docker compose -f deploy/m3.yml exec -T client ping -c 3 -W 3 100.64.0.1
3 packets transmitted, 3 received, 0% packet loss, rtt min/avg/max = 8.220/35.302/52.428 ms
```

即：客户端代码路径（tun-rs MTU 1280 + /16 池路由 + 经 frps 中转数据面）在容器内全通；
宿主受阻点收敛为 **Windows 权限面（适配器创建 + route add）**，而非客户端逻辑。

## 6. 受阻项汇总与高权限补测指引

受阻根因单一：**当前会话非管理员**。清单要求不提权，故以下留待管理员会话补测：

1. 管理员终端重跑 `cargo run -p flock-client -- --smoke --config .tmp/host-client.toml`
   ——预期 wintun 适配器创建成功（驱动已在库）→ 打印 `tun: tun0 mtu=1280 vip=100.64.0.3`
   → route 行打印 Windows `Unsupported`（含手工指令，属预期行为而非失败）→ 2s 后拆设备；
   期间另开终端 `netsh interface ipv4 show subinterface` 看 tun0 MTU=1280、
   `Get-NetAdapter` 看 wintun 适配器出现/消失（tun-rs Drop 拆除）。
2. 管理员 `route add 100.64.0.0 mask 255.192.0.0 100.64.0.3 metric 5`
   （§7-M5 的 /10 断言形态；代码指令为 /16，见 route.rs:87）+ 若 `route add … <vip>`
   因网关不在链上被拒，先 `netsh interface ip add address "tun0" 100.64.0.3
   255.255.255.255` 或改用 `route add … 0.0.0.0 IF <tun0 ifindex>`——本次未能验证该
   分支（权限受阻），补测时按实际报错调整。
3. 管理员会话跑 `run` 模式（同配置）建立会话后 `ping 100.64.0.1`（经 127.0.0.1:27500
   中转；宿主→frps→server tun VIP）。
4. 「驱动未预装时的首装行为」（UAC/驱动签名弹窗与否）本机无法复现（wintun.sys 已在
   库），需一台干净 Windows 真机补记。

## 7. 清理

记录完成后已执行：

```
$ docker compose -f deploy/m3.yml down -v
```

（输出见记录尾；含 server-state/client-state 卷删除与 flock-m3net 网络删除。）
仓库内新增/改动：`deploy/m3.yml`（+7/-1，frps 宿主回环映射）；`.tmp/` 下测试工件
（host-client-state、host-client.toml、host-invite.b64、server-m3-host.toml、wintun-dl/）
为 gitignore 范围的一次性物，未入库。
