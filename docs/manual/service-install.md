# 服务安装手册（M6 第一阶段：daemon 侧；docs/design.md §7-M6）

> 覆盖：Windows/Linux/macOS 的服务安装/卸载、托盘自启注册、提权要求、退出语义、
> 无 GUI 行为。`flock-client install` / `uninstall` / `service` / `status` 子命令。
> 托盘 UI 本身属 M6 第二阶段（本阶段的 `tray` 子命令为 feature 门控占位入口；IPC
> 契约见 `app/flock-client/src/ipc.rs`，托盘工程直接 `use flock_client::ipc::*`）。

## 0. 双进程模型速览（§7-M6.1）

| 进程 | 上下文 | 职责 |
|---|---|---|
| `flock-client service` | 系统服务（开机自启、无 GUI） | 全部 supervise/数据面 + 控制 IPC 服务端 |
| `flock-client tray` | 用户会话（登录自启） | 仅托盘；经 IPC 查询/控制（第二阶段） |

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
| 托盘自启 | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 值 `flock-client-tray` = `<exe> tray`（**无需提权**） |
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
- 托盘缺席时：`status` 子命令提供等价查询（输出 state/vip/endpoint/epoch/uptime）。
- tray feature 的平台默认差异（cargo 无法表达按平台 default features）见设计
  §7-M6.5 限制声明：三平台 default 一致含 tray，但 GUI 依赖第二阶段按 target 门控
  挂入；Linux 无头发布档用 `--no-default-features`。

## 7. 已验证/未验证边界（如实）

| 面 | 状态 |
|---|---|
| IPC 契约/服务端/客户端（ duplex mock + Windows 命名管道真回环） | 单测通过（宿主） |
| daemon 装配与 Shutdown 语义（mock tun + 真 IPC） | 单测通过（宿主；`daemon_loop_shutdown_via_ipc`） |
| Windows HKCU Run 注册/注销往返 | 单测通过（宿主，非提升） |
| Windows SCM 服务安装/卸载/自启/恢复策略 | **编译级验证**；真机需管理员 → §2 清单 |
| Windows 事件日志事件上报 | 代码路径编译级 + 未注册源时事件仍落日志；真机确认 → §2 清单 |
| Linux systemd 单元渲染 | 单测通过（宿主）；写入/enable 执行面需 root+systemd（容器无 systemd 报错如实） |
| Unix socket 服务端/权限 | 单测通过（Linux 容器档随 linux 编译面；本宿主为 Windows，socket 单测在 Unix 宿主跑） |
| macOS 全链路 | **未验证**（无设备；渲染/命令序列单测+审阅，§4 清单留位） |
