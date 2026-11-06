# 服务安装手册（M6：daemon 侧 + 托盘；docs/design.md §7-M6）

> 覆盖：Windows/Linux/macOS 的服务安装/卸载、托盘自启注册、提权要求、退出语义、
> 无 GUI 行为。`flock-client install` / `uninstall` / `service` / `status` / `tray`
> 子命令。托盘 UI 已随 M6 第二阶段实现（设计 §7-M6.7；IPC 契约
> `app/flock-client/src/ipc.rs`）。

## 0. 双进程模型速览（§7-M6.1）

| 进程 | 上下文 | 职责 |
|---|---|---|
| `flock-client service` | 系统服务（开机自启、无 GUI） | 全部 supervise/数据面 + 控制 IPC 服务端 |
| `flock-client tray` | 用户会话（登录自启） | 仅托盘（三项菜单：连接状态/VPN IP/退出）；经 IPC 查询/控制 |

Windows 服务跑在 session 0 无法创建托盘——双进程是硬约束；Linux/macOS 同构
（systemd system unit / LaunchDaemon 与用户会话分离）。

## 1. 通用

```
flock-client install [--user|--service] [--config <client.toml>]   # 缺省两者
flock-client uninstall [--user|--service]
flock-client service [--config <client.toml>]                      # 前台跑 daemon（服务管理器拉起）
flock-client status                                                 # 单次 Status 查询并打印
```

- 安装把**安装时**的 `--config` 路径（解析为绝对路径）写进服务定义——SCM 工作目录
  是 system32、systemd/launchd 不继承 shell CWD，**配置必须绝对路径**（用相对路径
  安装时 `install` 自动按 CWD 解析，但安装后移动目录会断）。
- 卸载/重装幂等：`install` 先删旧服务定义再建；`uninstall` 对不存在的项跳过。
- `status` 无 daemon 时退出码 2（token 文件缺失或控制面不可达，错误信息区分两者）。

## 2. Windows

| 项 | 内容 |
|---|---|
| 服务名 | `flock-client`（LocalSystem、OWN_PROCESS、SERVICE_AUTO_START） |
| 命令行 | `<exe> service --config <abs>`（exe = 执行 install 时的二进制路径） |
| 失败恢复 | 第 1/2 次失败重启（延迟 5s），第 3 次起不再动作；计数 24h 重置 |
| 事件日志 | 源 `flock-client` 注册进 Application 日志（HKLM，随 install）；服务启停/错误落事件日志；无消息 DLL ⇒ 消息以插入串呈现（模板 DLL 列后续打磨项） |
| 托盘自启 | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 值 `flock-client-tray` = `"<exe>" tray`（exe 加引号——空格路径安全；**无需提权**） |
| 控制 IPC | 命名管道 `\\.\pipe\flock-client-control`，显式 DACL：SYSTEM + Administrators + 交互用户组（IU）；token 文件 `%ProgramData%\flock\control-token`（ACL：Users 读） |

**提权**：服务安装/卸载需管理员（打开 SCM 的 CREATE_SERVICE/DELETE 权限）。非提升
会话运行 `install`/`uninstall --service` 会得到明确错误提示——先例与流程参照
`docs/manual/windows-smoke.md`（本仓库 Windows 真机清单记录惯例：如实记录是否提升，
不提权重跑）。托盘自启注册（`install --user`）不需要管理员。

**真机手工清单（待管理员会话执行，M6 验收项）**：
1. [ ] 提升会话：`flock-client install` → `sc query flock-client`（RUNNING）、
   `sc qc flock-client`（AUTO_START、二进制路径含 `service --config <abs>`）；
2. [ ] 重启机器 → 服务自启、`flock-client status` 返回快照；
3. [ ] `flock-client status` → `state=connected`（接入服务器可达时）；托盘注销
   `flock-client uninstall --user` 后 Run 键清除；
4. [ ] 事件查看器 Application 日志出现源 `flock-client` 的启停事件；
5. [ ] 服务在跑时 `flock-client uninstall`：先 SCM Stop（优雅停服）再删定义。

**终端直跑**：`flock-client service` 在非 SCM 上下文（终端/容器）自动回落前台
daemon（日志直连 stderr）——调试形态，与 Unix `service` 子命令同义。

## 3. Linux（systemd）

| 项 | 内容 |
|---|---|
| 单元 | `/etc/systemd/flock-client.service`（install 渲染；样例 `deploy/systemd/flock-client.service`） |
| 关键指令 | `WantedBy=multi-user.target`、`After=network-online.target` + `Wants=`、`Restart=on-failure`、`RestartSec=5`、`ExecStart=<exe> service --config <abs>` |
| 安装动作 | 写单元 → `systemctl daemon-reload` → `systemctl enable --now flock-client` |
| 托盘自启 | `~/.config/autostart/flock-client-tray.desktop` |
| 控制 IPC | Unix socket `/run/flock/client.sock`（0660；目录 /run/flock 0755）；token `/var/lib/flock/client/control-token`（0640 root） |

**提权**：写 `/etc/systemd` 与 systemctl 动作需 root——非 root 时错误信息带 sudo
提示（`sudo flock-client install`）。

**组授权（可选，放开非 root 控制）**：缺省 root:root（即装即用 = 仅 root 可控）。
要让 tray 用户查询/停服，把 `control_group = "flock"`（组需先建）写进 client.toml——
daemon 启动时对 token 与 socket 尝试 chgrp 到该组（仅查本地 /etc/group 或数字 gid，
失败告警不阻断）。

**容器注意**：`systemctl enable` 需 systemd 运行（PID 1 为 systemd）；dev/test 容器
无 systemd ⇒ 安装命令报错即如实返回（单元渲染已由单测覆盖，宿主可跑
`flock-client service` 验证 daemon 行为本身）。

## 4. macOS（launchd）——**未验证（本机无设备）**

| 项 | 内容 |
|---|---|
| daemon | `/Library/LaunchDaemons/com.flockvpn.client.plist`（RunAtLoad、**无 KeepAlive**；样例 `deploy/launchd/com.flockvpn.client.plist`） |
| 安装动作 | 写 plist → `launchctl load -w <path>`（卸载 `unload -w` + 删文件） |
| 托盘自启 | `~/Library/LaunchAgents/com.flockvpn.client-tray.plist`（RunAtLoad）+ `launchctl load -w` |
| 控制 IPC | 同 Linux 布局（/run/flock/client.sock、/var/lib/flock/client/control-token） |

**提权**：LaunchDaemon 写入/加载需 root（sudo 提示同 Linux）。**本机无 macOS 设备
⇒ 本节全部标注未验证**（渲染与命令序列有单测/审阅，真机清单留位）：
1. [ ] `sudo flock-client install` → `sudo launchctl list | grep flockvpn`；
2. [ ] 重启 → daemon 自启 + `flock-client status`；
3. [ ] Shutdown 后 launchd 不复活（无 KeepAlive）。

## 5. 退出语义（§7-M6.1，三平台一致）

- 托盘「退出」菜单 = 停 VPN + 托盘进程退出：对 daemon 发 `CtrlReq::Shutdown`（带
  token）→ daemon 优雅停服：断会话（隧道 GoAway/FIN、对端见会话终止）→ 停数据面 →
  拆 tun → 进程退出码 0。
- **服务保持已安装**，下次开机自启；优雅停服**不复活**（systemd `Restart=on-failure`
  只对失败退出、launchd 无 KeepAlive、Windows 恢复策略只挂失败码）。
- 信号：SIGTERM/SIGINT（Unix）与 SCM Stop（Windows）走同一优雅停服路径。
- 再启动：systemd `systemctl start flock-client` / `sc start flock-client` /
  `launchctl load`，或重启机器。

## 6. 无 GUI 行为

- `flock-client service` 无任何 GUI 依赖（feature 门控 `tray` 不进 daemon 路径；
  `--no-default-features` 构建档为无头服务器形态——托盘子命令不编入）。
- `flock-client tray` 的 GUI 探测：Linux 检查 `DISPLAY`/`WAYLAND_DISPLAY` 至少其一
  + 会话 DBus（`DBUS_SESSION_BUS_ADDRESS` 或 `$XDG_RUNTIME_DIR/bus`），缺任一 ⇒
  日志「未检测到 GUI 会话，托盘未启动」**退出码 0**；Windows/macOS 托盘创建失败
  同样优雅退出（不 panic）。托盘缺席时：`status` 子命令提供等价查询（输出
  state/vip/endpoint/epoch/uptime）。
- tray feature 的平台默认差异（cargo 无法表达按平台 default features）见设计
  §7-M6.5 限制声明：GUI 依赖（tray-icon/objc2*/ksni）已全部按 target 门控挂
  optional、由 `tray` feature 拉起——Linux 默认构建零 GUI 依赖面，无头发布档用
  `--no-default-features`。

## 7. 托盘真机清单（M6 第二阶段；自动化盲区，待用户目视确认）

`flock-client tray` 的 IPC 面（轮询/文案投影/退出裁决顺序/Shutdown 停服）已由单测
（真传输 IPC mock）与宿主 Windows 真进程实测（mock daemon 落位真端点/token：
tray ≥10s 存活无 panic、2s 刷新日志、与 `flock-client status` 状态一致、对 token
`Shutdown` ⇒ daemon 退出 + tray 转显「服务未运行」并继续重试）覆盖。**目视项无法
自动化**，逐项确认：

1. [ ] **图标出现**：启动 daemon（真拓扑或 §2 服务）后运行 `flock-client tray`——
   系统托盘出现 flock 图标（32×32 深青圆角底 + 白色雁阵箭头）；tooltip 显示状态
   摘要（如「Flock VPN：已连接 · frps-a:23000 · VPN IP 100.64.0.11」）；
2. [ ] **菜单三项**：右键图标——「连接状态：…」「VPN IP：…」两项置灰只读 +
   「退出」可点；
3. [ ] **文字刷新**：daemon 状态变化（连接/断开/停服）后 ≤2s 菜单文字跟随
   （停服时显示「连接状态：服务未运行」「VPN IP：—」）；
4. [ ] **退出动作**：点「退出」⇒ daemon 优雅停服（`flock-client status` 不可达、
   服务仍已安装）+ 托盘图标消失、托盘进程退出（退出码 0）；
5. [ ] daemon 不在时启动 `flock-client tray`：图标仍在、菜单显示「服务未运行」，
   起 daemon 后 ≤2s 恢复真实状态（token 自动重载——daemon 重启换 token 场景同）。
6. [ ] （Linux 桌面真机）有 GUI 会话托盘出现（KDE/GNOME+扩展）；无头主机
   `flock-client tray` 打「未检测到 GUI 会话，托盘未启动」退出码 0。
7. [ ] （macOS，无设备未验证）托盘出现 + 退出语义同上；`cargo check --target
   aarch64-apple-darwin -p flock-client --features tray` 编译级核验（本会话工具链
   下载过慢未完成，待有环境补跑）。
8. [ ] （Windows 真机 daemon 联测）提升会话起真服务（§2 清单）后重跑 1–5 项——
   非提升会话 wintun/路由注入受阻（windows-smoke.md 先例），本会话实测以
   mock daemon 在 IPC 面替代。
9. [ ] **（M7 `peers` 真机）**提升会话起真服务 + 真拓扑后：`flock-client login`
   （口令引导）→ `flock-client peers` 表格出现（含服务器与远端 peer 条目、延迟列
   数字——raw ICMP 需管理员/服务上下文；容器 Linux 路径已由 `deploy/m7_assert.sh`
   实测，Windows/macOS raw 面真机确认在此）→ `peers --json` 可被 `jq` 解析 →
   iperf3 跑流后 `↓/↑流量` 列非 0（EWMA 收敛窗 ~10s）。

## 8. 已验证/未验证边界（如实）

| 面 | 状态 |
|---|---|
| IPC 契约/服务端/客户端（ duplex mock + Windows 命名管道真回环） | 单测通过（宿主） |
| daemon 装配与 Shutdown 语义（mock tun + 真 IPC） | 单测通过（宿主；`daemon_loop_shutdown_via_ipc`） |
| 托盘核心逻辑（文案投影全分支/token 失效重载/轮询恢复/退出顺序真传输 IPC mock/图标像素） | 单测通过（宿主，`tray::tests` 9 项） |
| 托盘 Windows 真进程（mock daemon 真端点/token 落位） | 实测通过（宿主：存活/刷新日志/状态一致/Shutdown 停服转「服务未运行」；目视项 → §7 清单） |
| 托盘平台后端编译面 | Windows 宿主编译+clippy 全绿；Linux 容器档（--features tray 含 ksni / --no-default-features）check+clippy 全绿；macOS **未验证**（无设备；aarch64-apple-darwin 工具链下载过慢未及编译级核验，API 按 crate 源核对，§7 清单） |
| Windows HKCU Run 注册/注销往返 | 单测通过（宿主，非提升） |
| Windows SCM 服务安装/卸载/自启/恢复策略 | **编译级验证**；真机需管理员 → §2 清单 |
| Windows 事件日志事件上报 | 代码路径编译级 + 未注册源时事件仍落日志；真机确认 → §2 清单 |
| Linux systemd 单元渲染 | 单测通过（宿主）；写入/enable 执行面需 root+systemd（容器无 systemd 报错如实） |
| Unix socket 服务端/权限 | 单测通过（Linux 容器档随 linux 编译面；本宿主为 Windows，socket 单测在 Unix 宿主跑） |
| Linux 桌面托盘（ksni/SNI 宿主）真机 | **未验证**（容器档仅编译面；§7 清单第 6 项） |
| macOS 全链路 | **未验证**（无设备；渲染/命令序列单测+审阅，§4/§7 清单留位） |
| M7 peers 全链（登录保持/名册拉取/raw ICMP 延迟/流量列） | **容器实测通过**（Linux root，`deploy/m7_assert.sh`）；单测面（登录态机 pake 双端/毒化重连/表格渲染/IPC 契约/探测中位）宿主通过；Windows/macOS raw ICMP 真机 → §7 清单第 9 项 |
