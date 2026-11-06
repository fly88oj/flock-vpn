# deploy/multinode —— 真·多机组网实测（Windows 本机 Docker × 远端 jowency LXD）

结果与证据：`docs/manual/multinode-test.md`（实测日期 2026-11-07，HEAD b9217c3）。
拓扑范式沿用 `deploy/` 既有资产（`Dockerfile.server-direct` 的 Direct 形态、
`e2e.yml/e2e_assert.sh` 的 init-cluster/enroll/cluster-bootstrap 引导、
`m3/m7_assert.sh` 的 device-add→invite→login 开户路径——跨机化）。

## 拓扑

```
场景一【单 Server · Direct】（S1–S3）
  Windows 宿主 192.168.31.244 ── Docker bridge
    ├─ flock-wc1 / flock-wc2（flock-client，service daemon）
  jowency 192.168.31.221 ── LXD（lxdbr0 10.100.0.0/24 NAT）
    ├─ flock-s1（flock-server，Direct :9443；proxy device 发布宿主 0.0.0.0:9443）
    ├─ flock-c3 / flock-c4（flock-client）
  客户端全部直连 192.168.31.221:9443；全网状 ping（20 格）+ peers 名册 5 节点。

场景二【双 Server · 跨机 Raft + 双传输】（R1–R5）
  server-1 = flock-srv1（Windows Docker；Direct，发布 0.0.0.0:9443 客户端口
             + 0.0.0.0:9500 Raft 织物口）
  server-2 = flock-s2（jowency LXD；Frp 接入——宿主 frps :7000/:24000，进程内
             flock-frpc 注册；Raft :9500 经 proxy device 发布）
  2-voter init-cluster --endpoints 192.168.31.244:9443,192.168.31.221:24000
  客户端两侧分布：flock-2w1/2w2（→server-1 直连）、flock-c5/c6（→frps 用户口 24000）。
```

## 防火墙前置（jowency，必读）

实测环境有两道既有拦截，**测试窗口内需临时放行、测毕回收**（下述命令与回收见
`lxd-cleanup.sh` 头注与 multinode-test.md「环境拦截实录」）：

1. `nft` 表 `ip filter` 的 `DOCKER-USER` 链有既设规则 `iifname lxdbr0 → 10/8,
   172.16/12, 192.168/16 ct state new drop`（拦 LXD 容器到私网——场景二的
   flock-s2 → server-1 Raft 拨号、c6 换端点直连均被拦）：
   ```sh
   # 放行（仅 dst=Windows 宿主 + 本测端口；记 handle，测毕 nft delete rule 按原样回收）
   sudo nft insert rule ip filter DOCKER-USER iifname "lxdbr0" ip daddr <WIN_IP> \
        tcp dport { 9443, 9500 } ct state new counter accept comment "flock-mn-test-temp"
   ```
2. `ufw` default deny incoming：LXD 容器源（10.100.0.0/24）到宿主发布口不在
   「LAN trusted 192.168.0.0/16」内（容器→宿主 INPUT 面被拦——场景一 LXD 客户端、
   场景二 frps 用户口/注册口）：
   ```sh
   sudo ufw allow in on lxdbr0 to any port 9443  proto tcp comment "flock-mn-test"
   sudo ufw allow in on lxdbr0 to any port 7000  proto tcp comment "flock-mn-test"
   sudo ufw allow in on lxdbr0 to any port 24000 proto tcp comment "flock-mn-test"
   # 回收：sudo ufw delete allow <同上三条全文>
   ```

Windows 入站探针（第一步必做）：`docker run -d -p 0.0.0.0:19444:19444 alpine …nc -l…`
后自 jowency `nc -w5 <WIN_IP> 19444`。**本环境实测双向通**（Windows 入站可用），
场景二保持「server-1 在 Windows Docker」的原拓扑不降级。若入站被拦：
场景二改为两台 server 均在 LXD（各 proxy device 发布端口，仍跨容器）+ Windows Docker
只跑出站客户端；且真机补测防火墙放行（管理员）：
`netsh advfirewall firewall add rule name="flock-mn" dir=in action=allow protocol=TCP localport=9443,9500`

## 复刻步骤

```sh
# 0) 构建 Linux amd64 发布二进制（三个：单服 Direct 档 / multi-primary 档 / client）
docker buildx build -f deploy/multinode/Dockerfile.buildbin \
    --output type=local,dest=deploy/multinode/out .
# 1) 流式分发到 jowency（tar over ssh；scp/lxc pull 会静默截断大文件）
tar -C deploy/multinode/out -cf - flock-server-direct flock-server-mp flock-client \
  | ssh jowency@192.168.31.221 "mkdir -p ~/flock-mn/bin && tar -C ~/flock-mn/bin -xf - && chmod +x ~/flock-mn/bin/*"
tar -C .tmp/frp_0.71.1_linux_amd64 -cf - frps frpc \
  | ssh jowency@192.168.31.221 "tar -C ~/flock-mn/bin -xf - && chmod +x ~/flock-mn/bin/frp*"
tar -C deploy/multinode -cf - lxd-setup.sh server-*.toml frps-mn.toml client.toml.example \
  | ssh jowency@192.168.31.221 "mkdir -p ~/flock-mn/assets && tar -C ~/flock-mn/assets -xf -"
# 2) 防火墙前置（见上节）
# 3) 供应
ssh jowency@192.168.31.221 "JOW_LAN_IP=192.168.31.221 bash ~/flock-mn/assets/lxd-setup.sh 1"
bash deploy/multinode/win-docker-setup.sh 1
# 4) 断言（bootstrap 幂等 + S1–S3；退出码 0/1/2/64）
bash deploy/multinode/multinode_assert.sh 1
# 场景二：lxd-setup.sh 2 / win-docker-setup.sh 2 / multinode_assert.sh 2（R1–R5）
# 5) 收尾（两侧）
ssh jowency@192.168.31.221 "bash ~/flock-mn/assets/lxd-cleanup.sh"   # 或 --keep-files
bash deploy/multinode/win-docker-cleanup.sh
```

## 资产清单

| 文件 | 作用 |
|---|---|
| `Dockerfile.buildbin` | Linux amd64 发布二进制构建（依赖层缓存；两档 server + client，strip） |
| `server-s1-direct.toml` | 场景一 server 配置模板（Direct、无 [sync]） |
| `server-2w-direct-mp.toml` | 场景二 server-1（Windows Docker，Direct + 跨机 raft_peers） |
| `server-2s-frp-mp.toml` | 场景二 server-2（LXD，Frp→frps:24000 + 跨机 raft_peers） |
| `frps-mn.toml` | 场景二 frps（jowency 宿主，bind 7000） |
| `client.toml.example` | 客户端配置模板（endpoints 钉死 + [auth] username） |
| `lxd-setup.sh` / `lxd-cleanup.sh` | jowency 侧供应/清理（经 ssh；幂等；只动 flock-*） |
| `win-docker-setup.sh` / `win-docker-cleanup.sh` | Windows Docker 侧供应/清理（HEAD 二进制覆盖挂载 + 命名卷） |
| `multinode_assert.sh` | 断言（S1–S3/R1–R5；矩阵+名册+Raft+吊销；退出码 0=全PASS/1=有FAIL/2=bootstrap失败/64=用法） |
| `windows-host-node.ps1` | Windows 宿主（非 Docker）一键入网节点（真机清单用，需管理员） |

## 真机清单（未在本会话执行的部分）

- Windows 宿主节点（非 Docker）：`deploy/multinode/windows-host-node.ps1`（管理员
  PowerShell；编译/取 `target\release\flock-client.exe`、配置指向场景一 server、
  UAC 自提权、`flock-client run`、输出 ping 矩阵）。
- Windows 入站防火墙放行（仅当探针被拦时）：`netsh advfirewall firewall add rule
  name="flock-mn" dir=in action=allow protocol=TCP localport=9443,9500`（管理员）。
- 场景二若需「两台 server 都在 LXD」的降级拓扑：把 server-2w 配置照
  server-2s 模式改 advertise/proxy 发布即可（raft_peers 端点同步改 jowency 侧）。
