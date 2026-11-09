// i18n.js —— M8 Web UI copy dictionaries (multi-language packs; §M8.1).
//
// Two packs with strictly identical key sets: `en` (default) and `zh`
// (Simplified Chinese —— the only place Chinese is allowed in this project).
// All UI copy lives in this single file; adding another language means adding
// one pack here, with no API changes.
//
// Conventions: templates always fetch copy via window.t(key) (a missing key
// falls back to displaying the key itself —— recognizable during development);
// parameterized copy uses {name} placeholders, replaced via t(key, {name: value}).
//
// Language selection order:
//  1. localStorage("flock.lang") —— the explicit user choice made via the Lang
//     switcher (login page / settings); always wins once set;
//  2. the /api/bootstrap `lang` field —— server-side initial hint, applied by
//     app.js as soon as bootstrap arrives (only when no choice is stored);
//  3. navigator.language (initial guess before bootstrap resolves);
//  4. "en" (default fallback).
(function () {
  'use strict';

  var EN = {
    // —— General ——
    'app.name': 'Flock Admin Console',
    'app.loading': 'Loading…',
    'app.retry': 'Retry',
    'app.empty': 'No data yet',
    'app.error': 'Failed to load',
    'app.logout': 'Sign out',
    'app.copy': 'Copy',
    'app.copied': 'Copied',
    'app.copy.full': 'Click to copy the full ID',
    'app.confirm': 'Confirm',
    'app.cancel': 'Cancel',
    'app.close': 'Close',
    'app.admin': 'Admin',
    'app.user': 'User',
    'app.server': 'Server',
    'app.device': 'Device',
    'app.online': 'Online',
    'app.offline': 'Offline',
    'app.yes': 'Yes',
    'app.no': 'No',
    'app.refresh': 'Refresh',
    'app.noperm.title': 'No permission',
    'app.noperm.body': 'Your account does not have access to this page (administrator role required).',
    'app.language': 'Language',

    // —— Navigation ——
    'nav.dashboard': 'Dashboard',
    'nav.peers': 'Devices',
    'nav.users': 'Accounts',
    'nav.audit': 'Audit',
    'nav.settings': 'Settings',
    'nav.menu': 'Menu',
    'nav.session.expire': 'Session expires in {time}',
    'nav.session.expired': 'Session expired',
    'nav.origin.loopback': 'Local login',
    'nav.origin.vpn': 'VPN login',

    // —— Language names (switcher options) ——
    'lang.en': 'English',
    'lang.zh': 'Chinese',

    // —— Login page ——
    'login.title': 'Sign in to Flock Admin Console',
    'login.subtitle': 'Sign in with an administrator account; new users should set a password via a bootstrap token first.',
    'login.bootstrap.cluster': 'Cluster',
    'login.bootstrap.server': 'Server',
    'login.username': 'Username',
    'login.username.ph': 'Username',
    'login.password': 'Password',
    'login.password.ph': 'Password',
    'login.submit': 'Sign in',
    'login.busy': 'Verifying…',
    'login.bootstrap.unreachable': 'Cannot reach the admin interface (/api/bootstrap unreachable)',
    'login.setpw': 'First sign-in / password reset?',
    'login.setpw.go': 'Go to set password',
    'err.login_failed': 'Incorrect username or password.',
    'err.user_disabled': 'This account has been disabled; contact an administrator.',
    'err.rate_limited': 'Too many attempts; retry in {secs} seconds.',
    'err.anchor': 'Server identity verification failed (you may be connected to the wrong server); access it via the correct local or VPN address.',
    'err.pake': 'The authentication protocol failed; please retry.',
    'err.no_entropy': 'Random entropy is not ready; refresh the page and retry.',
    'err.wasm': 'The authentication module (wasm) failed to load; refresh the page and retry.',
    'err.network': 'Network error; check the connection and retry.',
    'err.bad_request': 'Invalid request.',
    'err.forbidden': 'You do not have permission to perform this operation.',
    'err.not_found': 'Target not found.',
    'err.internal': 'Internal server error; please retry later.',
    'err.user_exists': 'Username already exists.',
    'err.password_exists': 'A password is already set (ask an administrator to issue a new bootstrap token to reset it).',
    'err.invalid_state': 'This operation is not allowed in the current state (terminal devices cannot be enabled).',
    'err.cannot_demote_self': 'You cannot remove your own administrator role.',
    'err.bad_token': 'The bootstrap token is invalid or already used.',

    // —— Set-password page ——
    'setpw.title': 'Set password',
    'setpw.subtitle': 'Set a new password with the one-time bootstrap token delivered by an administrator (first-time setup and reset share this page).',
    'setpw.username': 'Username',
    'setpw.token': 'Bootstrap token',
    'setpw.token.ph': '32-character hexadecimal token',
    'setpw.newpass': 'New password',
    'setpw.newpass2': 'Confirm new password',
    'setpw.submit': 'Set password',
    'setpw.busy': 'Setting…',
    'setpw.mismatch': 'The two passwords do not match.',
    'setpw.empty': 'Please fill in all fields.',
    'setpw.done': 'Password set; you can sign in now.',
    'setpw.go.login': 'Go to sign in',

    // —— Dashboard ——
    'dash.cluster': 'Cluster',
    'dash.subtitle': 'Cluster {cluster} · live status and traffic (60s polling)',
    // One of the three cluster-card segments (round2 review item 8): cluster
    // identity (first 8 hex chars, full value in the title tooltip)
    'dash.cluster.id': 'Cluster ID',
    'dash.cluster.epoch': 'Epoch',
    'dash.cluster.mode': 'Sync mode',
    'dash.servers': 'Servers',
    'dash.servers.leader': 'Leader',
    'dash.servers.follower': 'Follower',
    'dash.servers.node': 'Node {id}',
    'dash.totals': 'Totals',
    'dash.totals.devices': 'Devices',
    'dash.totals.devices_active': 'Active devices',
    'dash.totals.devices_online': 'Online devices',
    'dash.totals.users': 'Accounts',
    'dash.totals.tx': 'Total TX rate',
    'dash.totals.rx': 'Total RX rate',
    'dash.self': 'This server',
    'dash.self.uptime': 'Up {dur}',
    'dash.self.server_id': 'Server ID',
    'dash.chart': 'Device traffic',
    'dash.chart.select': 'Select device (VIP)',
    'dash.chart.time': 'Time',
    'dash.chart.tx': 'TX',
    'dash.chart.rx': 'RX',
    'dash.chart.empty': 'No traffic samples for this device yet (the chart restarts after a server restart).',
    'dash.chart.hint': 'Sampled every minute, last 2 hours.',

    // —— Devices page ——
    'peers.title': 'Devices',
    'peers.subtitle': 'All devices and servers, ascending by VIP.',
    'peers.col.vip': 'VIP',
    'peers.col.hostname': 'Hostname',
    'peers.col.owner': 'Account',
    'peers.col.kind': 'Kind',
    // Status column, three shapes (round2 review item 5): header "Status/Online";
    // the hover legend explains the decoupled semantics dot = online state,
    // text = lifecycle status
    'peers.col.status': 'Status/Online',
    'peers.col.status.legend': 'Dot = online state; text = lifecycle status',
    'peers.col.lastseen': 'Last active',
    'peers.col.traffic': 'Traffic (↑TX / ↓RX)',
    'peers.col.actions': 'Actions',
    'peers.lastseen.never': 'Never',
    'peers.hostname.unreported': 'Not reported',
    'peers.empty': 'No registered devices yet; devices appear here after completing enrollment.',
    'peers.status.active': 'Active',
    'peers.status.disabled': 'Disabled',
    'peers.status.revoked': 'Revoked',
    'peers.status.expired': 'Expired',
    'peers.act.revoke': 'Revoke',
    'peers.act.disable': 'Disable',
    'peers.act.enable': 'Enable',
    'peers.act.kick': 'Kick',
    'peers.act.terminal': 'Terminal-state devices cannot be revoked or re-enabled',
    'peers.confirm.revoke.title': 'Revoke device',
    'peers.confirm.revoke.body': 'Revocation moves the device into a terminal state with no recovery (the epoch advances and online sessions drop immediately). Revoke {vip} ({host})?',
    'peers.confirm.disable.title': 'Disable device',
    'peers.confirm.disable.body': 'While disabled the device cannot connect; it can be re-enabled at any time. Disable {vip} ({host})?',
    'peers.confirm.enable.title': 'Enable device',
    'peers.confirm.enable.body': 'Allow {vip} ({host}) to connect again?',
    'peers.confirm.kick.title': 'Kick device',
    'peers.confirm.kick.body': 'Best-effort disconnect of the sessions on this server (not a ban: the device may reconnect automatically; use disable/revoke to cut it off for good). Kick {vip} ({host})?',
    'peers.result.ok': 'Operation successful.',
    'peers.result.epoch': 'Operation successful (epoch {epoch}).',

    // —— Accounts page ——
    'users.title': 'Accounts',
    'users.subtitle': 'Accounts, roles and password bootstrap (one-time tokens are shown only at issuance).',
    'users.create.title': 'Create account',
    'users.create.name': 'Username',
    'users.create.name.ph': '1–32 chars: letters/digits/_.-',
    'users.create.submit': 'Create & issue token',
    'users.col.username': 'Username',
    'users.col.role': 'Role',
    'users.col.disabled': 'Status',
    'users.col.password': 'Password',
    'users.col.devices': 'Devices',
    'users.col.actions': 'Actions',
    'users.disabled.yes': 'Disabled',
    'users.disabled.no': 'Active',
    'users.password.set': 'Set',
    'users.password.none': 'Not set',
    'users.empty': 'No accounts yet; create an account and hand the bootstrap token to the user.',
    'users.act.disable': 'Disable',
    'users.act.enable': 'Enable',
    'users.act.disabled.disabled': 'A disabled account cannot be disabled again; enable it first',
    'users.act.resetpw': 'Reset password',
    'users.act.setadmin': 'Make admin',
    'users.act.unsetadmin': 'Remove admin',
    // Self-row guard (round2 review item 4): tooltip for the greyed-out
    // remove-admin / disable buttons
    'users.act.self.blocked': 'Cannot perform this on the current signed-in account',
    'users.confirm.disable.title': 'Disable account',
    'users.confirm.disable.body': 'While disabled, {user} cannot sign in via Web or the control plane (existing sessions are not revoked retroactively). Disable?',
    'users.confirm.setadmin.title': 'Change administrator role',
    'users.confirm.setadmin.body': 'Change the role of {user} to {role}?',
    'users.role.admin': 'Administrator',
    'users.role.plain': 'Regular user',
    'users.token.title.create': 'Account created',
    'users.token.title.reset': 'Password reset',
    'users.token.body': 'One-time bootstrap token (shown only this once):',
    'users.token.hint': 'Deliver it to {user} out of band: have them open the "Set password" page and enter this token with a new password to activate; on reset the old password stops working immediately.',
    'users.token.go': 'Open the set-password page on this machine',
    'users.me': '(signed in)',

    // —— Audit page ——
    'audit.title': 'Audit',
    'audit.subtitle': 'Latest 200 administrative operations (new→old; no passwords/tokens/ticket bytes are recorded).',
    'audit.col.time': 'Time',
    'audit.col.user': 'Operator',
    'audit.col.action': 'Action',
    'audit.col.target': 'Target',
    'audit.col.origin': 'Origin',
    'audit.col.result': 'Result',
    'audit.empty': 'No audit records yet; administrative operations will appear here.',
    'audit.action.session.login': 'Sign-in',
    'audit.action.session.logout': 'Sign-out',
    'audit.action.user.create': 'Create account',
    'audit.action.user.disable': 'Disable account',
    'audit.action.user.enable': 'Enable account',
    'audit.action.user.reset_password': 'Reset password',
    'audit.action.user.set_admin': 'Change role',
    'audit.action.peer.revoke': 'Revoke device',
    'audit.action.peer.disable': 'Disable device',
    'audit.action.peer.enable': 'Enable device',
    'audit.action.peer.kick': 'Kick device',
    'audit.result.ok': 'OK',
    'audit.result.denied': 'Denied',
    'audit.result.error': 'Error',

    // —— Settings page ——
    'settings.title': 'Settings',
    'settings.subtitle': 'Read-only summary of the running configuration (field whitelist —— no keys, no root material).',
    'settings.listen_mode': 'Listen mode',
    'settings.advertise_endpoint': 'Advertised endpoint',
    'settings.sync_mode': 'Sync mode',
    'settings.ticket_ttl_secs': 'Ticket TTL (seconds)',
    'settings.peer_retention_days': 'Device retention (days)',
    'settings.max_sessions': 'Session limit',
    'settings.webui.port': 'Web port',
    'settings.webui.session_ttl_secs': 'Session TTL (seconds)',
    'settings.mode.direct': 'Direct',
    'settings.mode.frp': 'Relay (frp)',
    'settings.sync.single': 'Single server',
    'settings.sync.raft': 'Multi-primary Raft',

    // —— Units / formatting ——
    'fmt.seconds': '{n}s',
    'fmt.minutes': '{n}m',
    'fmt.hours': '{n}h',
    'fmt.days': '{n}d',
    'fmt.ago.now': 'just now',
    'fmt.ago': '{dur} ago',
  };

  // —— zh-CN pack —— the ONLY place Simplified Chinese is allowed in this
  // project; its key set must stay strictly identical to the en pack's
  // (asserted by the webui asset tests).
  var ZH_CN = {
    // —— 通用 ——
    'app.name': 'Flock 管理控制台',
    'app.loading': '加载中…',
    'app.retry': '重试',
    'app.empty': '暂无数据',
    'app.error': '加载失败',
    'app.logout': '退出登录',
    'app.copy': '复制',
    'app.copied': '已复制',
    'app.copy.full': '点击复制完整编号',
    'app.confirm': '确认',
    'app.cancel': '取消',
    'app.close': '关闭',
    'app.admin': '管理员',
    'app.user': '用户',
    'app.server': '服务器',
    'app.device': '设备',
    'app.online': '在线',
    'app.offline': '离线',
    'app.yes': '是',
    'app.no': '否',
    'app.refresh': '刷新',
    'app.noperm.title': '无权限',
    'app.noperm.body': '当前账户没有访问该页面的权限（需要管理员角色）。',
    'app.language': '语言',

    // —— 导航 ——
    'nav.dashboard': '仪表盘',
    'nav.peers': '设备',
    'nav.users': '账号',
    'nav.audit': '审计',
    'nav.settings': '设置',
    'nav.menu': '菜单',
    'nav.session.expire': '会话 {time} 后过期',
    'nav.session.expired': '会话已过期',
    'nav.origin.loopback': '本机登录',
    'nav.origin.vpn': 'VPN 登录',

    // —— 语言名（切换控件选项）——
    'lang.en': 'English',
    'lang.zh': '中文',

    // —— 登录页 ——
    'login.title': '登录 Flock 管理控制台',
    'login.subtitle': '使用管理账号登录；新用户请先经引导令牌设置口令。',
    'login.bootstrap.cluster': '集群',
    'login.bootstrap.server': '服务器',
    'login.username': '用户名',
    'login.username.ph': '用户名',
    'login.password': '口令',
    'login.password.ph': '口令',
    'login.submit': '登录',
    'login.busy': '正在验证…',
    'login.bootstrap.unreachable': '无法连接管理接口（/api/bootstrap 不可达）',
    'login.setpw': '首次登录 / 重置口令？',
    'login.setpw.go': '前往设置口令',
    'err.login_failed': '用户名或口令错误。',
    'err.user_disabled': '该账户已被禁用，请联系管理员。',
    'err.rate_limited': '尝试过于频繁，请 {secs} 秒后重试。',
    'err.anchor': '服务器身份验证失败（可能连接到了错误的服务器），请经正确的本机或 VPN 地址访问。',
    'err.pake': '认证协议执行失败，请重试。',
    'err.no_entropy': '随机熵未就绪，请刷新页面重试。',
    'err.wasm': '认证模块（wasm）加载失败，请刷新页面重试。',
    'err.network': '网络错误，请检查连接后重试。',
    'err.bad_request': '请求无效。',
    'err.forbidden': '没有执行该操作的权限。',
    'err.not_found': '目标不存在。',
    'err.internal': '服务器内部错误，请稍后重试。',
    'err.user_exists': '用户名已存在。',
    'err.password_exists': '口令已设置（如需重置请让管理员重新签发引导令牌）。',
    'err.invalid_state': '当前状态不允许该操作（终态设备不可启用）。',
    'err.cannot_demote_self': '不能取消自己的管理员角色。',
    'err.bad_token': '引导令牌无效或已被使用。',

    // —— 设置口令页 ——
    'setpw.title': '设置口令',
    'setpw.subtitle': '使用管理员交付的一次性引导令牌设置新口令（首次设置与重置共用本页）。',
    'setpw.username': '用户名',
    'setpw.token': '引导令牌',
    'setpw.token.ph': '32 位十六进制令牌',
    'setpw.newpass': '新口令',
    'setpw.newpass2': '确认新口令',
    'setpw.submit': '设置口令',
    'setpw.busy': '正在设置…',
    'setpw.mismatch': '两次输入的口令不一致。',
    'setpw.empty': '请填写全部字段。',
    'setpw.done': '口令设置成功，现在可以登录了。',
    'setpw.go.login': '前往登录',

    // —— 仪表盘 ——
    'dash.cluster': '集群',
    'dash.subtitle': '集群 {cluster} · 实时状态与流量（60s 轮询）',
    // 集群卡三段之一（round2 评审项 8）：集群标识（hex 前 8 位，title 全值）
    'dash.cluster.id': '集群标识',
    'dash.cluster.epoch': '纪元（epoch）',
    'dash.cluster.mode': '同步模式',
    'dash.servers': '服务器',
    'dash.servers.leader': '主（leader）',
    'dash.servers.follower': '从（follower）',
    'dash.servers.node': '节点 {id}',
    'dash.totals': '总览',
    'dash.totals.devices': '设备总数',
    'dash.totals.devices_active': '在册设备（active）',
    'dash.totals.devices_online': '在线设备',
    'dash.totals.users': '账户数',
    'dash.totals.tx': '发送速率合计',
    'dash.totals.rx': '接收速率合计',
    'dash.self': '本服务器',
    'dash.self.uptime': '已运行 {dur}',
    'dash.self.server_id': '服务器标识',
    'dash.chart': '设备流量',
    'dash.chart.select': '选择设备（VIP）',
    'dash.chart.time': '时间',
    'dash.chart.tx': '发送',
    'dash.chart.rx': '接收',
    'dash.chart.empty': '该设备暂无流量样本（服务重启后曲线重新累计）。',
    'dash.chart.hint': '每分钟采样，最近 2 小时。',

    // —— 设备页 ——
    'peers.title': '设备',
    'peers.subtitle': '全部设备与服务器，VIP 升序。',
    'peers.col.vip': 'VIP',
    'peers.col.hostname': '主机名',
    'peers.col.owner': '账户',
    'peers.col.kind': '类型',
    // 状态列三形态（round2 评审项 5）：列名「状态/在线」；legend 悬停图例说明
    // 圆点=在线状态、文字=生命周期状态的解耦语义
    'peers.col.status': '状态/在线',
    'peers.col.status.legend': '圆点=在线状态；文字=生命周期状态',
    'peers.col.lastseen': '最后活跃',
    'peers.col.traffic': '流量（↑发送 / ↓接收）',
    'peers.col.actions': '操作',
    'peers.lastseen.never': '从未',
    'peers.hostname.unreported': '未上报',
    'peers.empty': '尚无注册设备；设备完成入网注册后会出现在这里。',
    'peers.status.active': '正常',
    'peers.status.disabled': '已禁用',
    'peers.status.revoked': '已吊销',
    'peers.status.expired': '已过期',
    'peers.act.revoke': '吊销',
    'peers.act.disable': '禁用',
    'peers.act.enable': '启用',
    'peers.act.kick': '强制下线',
    'peers.act.terminal': '终态设备不可吊销/启用',
    'peers.confirm.revoke.title': '吊销设备',
    'peers.confirm.revoke.body': '吊销后设备进入终态、不可恢复（epoch 推进、在线会话立即断开）。确定吊销 {vip}（{host}）？',
    'peers.confirm.disable.title': '禁用设备',
    'peers.confirm.disable.body': '禁用后设备无法接入，可随时重新启用。确定禁用 {vip}（{host}）？',
    'peers.confirm.enable.title': '启用设备',
    'peers.confirm.enable.body': '重新允许 {vip}（{host}）接入？',
    'peers.confirm.kick.title': '强制下线',
    'peers.confirm.kick.body': '尽力断开本机上的会话（不封禁：设备可能自动重连上线；确定断离请用禁用/吊销）。确定让 {vip}（{host}）下线？',
    'peers.result.ok': '操作成功。',
    'peers.result.epoch': '操作成功（epoch {epoch}）。',

    // —— 账号页 ——
    'users.title': '账号',
    'users.subtitle': '账户、角色与口令引导（一次性令牌仅在签发时展示一次）。',
    'users.create.title': '创建账号',
    'users.create.name': '用户名',
    'users.create.name.ph': '1–32 位字母/数字/_.-',
    'users.create.submit': '创建并签发令牌',
    'users.col.username': '用户名',
    'users.col.role': '角色',
    'users.col.disabled': '状态',
    'users.col.password': '口令',
    'users.col.devices': '设备数',
    'users.col.actions': '操作',
    'users.disabled.yes': '已禁用',
    'users.disabled.no': '正常',
    'users.password.set': '已设置',
    'users.password.none': '未设置',
    'users.empty': '尚无账户；创建账号并签发引导令牌后交付用户。',
    'users.act.disable': '禁用',
    'users.act.enable': '启用',
    'users.act.disabled.disabled': '已禁用账户不可再禁用，先启用',
    'users.act.resetpw': '重置口令',
    'users.act.setadmin': '设为管理员',
    'users.act.unsetadmin': '取消管理员',
    // 自身行防护（round2 评审项 4）：取消管理员/禁用按钮置灰的 title 提示
    'users.act.self.blocked': '不能对当前登录账户执行',
    'users.confirm.disable.title': '禁用账户',
    'users.confirm.disable.body': '禁用后 {user} 的 Web 与控制流登录将被阻断（已建立会话不追溯）。确定禁用？',
    'users.confirm.setadmin.title': '变更管理员角色',
    'users.confirm.setadmin.body': '将 {user} 的角色变更为{role}？',
    'users.role.admin': '管理员',
    'users.role.plain': '普通用户',
    'users.token.title.create': '账号已创建',
    'users.token.title.reset': '口令已重置',
    'users.token.body': '一次性引导令牌（仅本次展示）：',
    'users.token.hint': '请线下交付给 {user}：让其打开「设置口令」页输入该令牌与新口令完成激活；重置场景下旧口令即刻失效。',
    'users.token.go': '在本机打开设置口令页',
    'users.me': '（当前登录）',

    // —— 审计页 ——
    'audit.title': '审计',
    'audit.subtitle': '最近 200 条管理操作（新→旧；不记录口令/令牌/票据字节）。',
    'audit.col.time': '时间',
    'audit.col.user': '操作者',
    'audit.col.action': '操作',
    'audit.col.target': '目标',
    'audit.col.origin': '来源',
    'audit.col.result': '结果',
    'audit.empty': '暂无审计记录；管理操作会在此留痕。',
    'audit.action.session.login': '登录',
    'audit.action.session.logout': '登出',
    'audit.action.user.create': '创建账号',
    'audit.action.user.disable': '禁用账号',
    'audit.action.user.enable': '启用账号',
    'audit.action.user.reset_password': '重置口令',
    'audit.action.user.set_admin': '变更角色',
    'audit.action.peer.revoke': '吊销设备',
    'audit.action.peer.disable': '禁用设备',
    'audit.action.peer.enable': '启用设备',
    'audit.action.peer.kick': '强制下线',
    'audit.result.ok': '成功',
    'audit.result.denied': '拒绝',
    'audit.result.error': '错误',

    // —— 设置页 ——
    'settings.title': '设置',
    'settings.subtitle': '运行配置只读摘要（字段白名单——无密钥/无根材料）。',
    'settings.listen_mode': '接入模式',
    'settings.advertise_endpoint': '对外端点',
    'settings.sync_mode': '同步模式',
    'settings.ticket_ttl_secs': '票据 TTL（秒）',
    'settings.peer_retention_days': '设备保留（天）',
    'settings.max_sessions': '会话上限',
    'settings.webui.port': 'Web 端口',
    'settings.webui.session_ttl_secs': '会话 TTL（秒）',
    'settings.mode.direct': '直连（direct）',
    'settings.mode.frp': '中转（frp）',
    'settings.sync.single': '单服（single）',
    'settings.sync.raft': '多主 Raft（raft）',

    // —— 单位/格式 ——
    'fmt.seconds': '{n} 秒',
    'fmt.minutes': '{n} 分钟',
    'fmt.hours': '{n} 小时',
    'fmt.days': '{n} 天',
    'fmt.ago.now': '刚刚',
    'fmt.ago': '{dur}前',
  };

  var PACKS = { en: EN, zh: ZH_CN };
  var STORAGE_KEY = 'flock.lang';

  // BCP-47-ish tag → pack id ('' when unsupported): zh / zh-CN / zh_TW → 'zh';
  // en / en-US → 'en'.
  function normalize(tag) {
    var s = String(tag || '').toLowerCase();
    if (s === 'zh' || s.indexOf('zh-') === 0 || s.indexOf('zh_') === 0) { return 'zh'; }
    if (s === 'en' || s.indexOf('en-') === 0 || s.indexOf('en_') === 0) { return 'en'; }
    return '';
  }

  // Stored explicit choice ('' when absent or storage unavailable).
  function storedLang() {
    try { return normalize(window.localStorage.getItem(STORAGE_KEY)); } catch (e) { return ''; }
  }

  // Initial pick before bootstrap arrives: stored choice → browser locale → 'en'.
  var lang = storedLang()
    || normalize(navigator.language || (navigator.languages && navigator.languages[0]) || '')
    || 'en';

  window.FLOCK_I18N = PACKS;
  window.FLOCK_LANG = function () { return lang; };

  window.t = function (key, params) {
    var s = (PACKS[lang] && PACKS[lang][key]) || EN[key] || key;
    if (params) {
      Object.keys(params).forEach(function (k) {
        s = s.split('{' + k + '}').join(String(params[k]));
      });
    }
    return s;
  };

  // Explicit switch (Lang control): activate the pack and persist the choice.
  // Returns the active language ('' when the requested tag is unsupported).
  window.FLOCK_SET_LANG = function (tag) {
    var n = normalize(tag);
    if (!n) { return ''; }
    if (n !== lang) { lang = n; }
    try { window.localStorage.setItem(STORAGE_KEY, n); } catch (e) { /* storage unavailable —— session-only */ }
    return lang;
  };

  // Bootstrap `lang` field —— the server's initial hint. Applies only while no
  // explicit choice is stored (a user pick always wins). Returns the active
  // language after applying the hint.
  window.FLOCK_APPLY_BOOTSTRAP_LANG = function (tag) {
    if (storedLang()) { return lang; }
    var n = normalize(tag);
    if (n) { lang = n; }
    return lang;
  };
})();
