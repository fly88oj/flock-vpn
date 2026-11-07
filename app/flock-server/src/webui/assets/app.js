// app.js —— M8 Web UI 应用核心（Alpine.js 根组件 + API 封装 + uPlot 集成，§M8.6）。
//
// 职责：
//  - hash 路由（手写，无路由库）：#/login | #/set-password | #/dashboard | #/peers |
//    #/users | #/audit | #/settings；未知路由回落 dashboard（未登录回落 login）。
//  - 会话状态：boot 时 GET /api/me 验活恢复；任何 API 401 ⇒ 回登录页。
//  - API 封装：统一错误信封 {error:{code,message[,retry_after_secs]}} 解析；
//    POST 恒带 X-Flock-Web: 1 + Content-Type: application/json（CSRF 双门槛）。
//  - wasm OPAQUE：登录/设置口令全程经 window.FlockPake（C-ABI 垫片胶水），
//    anchor 用 /api/bootstrap 的 identity_pub 在 wasm 内验签。
//  - uPlot 流量曲线：本地时区刻度 + 触控/鼠标 tooltip；容器宽自适应 + resize。
(function () {
  'use strict';

  // —— 图表双系列色（🔴 round2 评审项 1）：曲线描边与自绘图例色片单点定义，
  // 图例颜色恒与线一致（防两处 hex 漂移）。 ——
  const CHART_TX_COLOR = '#4f8cff';
  const CHART_RX_COLOR = '#3fb972';

  // —— API 封装（错误信封解析）——
  async function api(method, path, body) {
    const headers = {};
    if (method === 'POST') {
      headers['X-Flock-Web'] = '1';
      headers['Content-Type'] = 'application/json';
    }
    let resp;
    try {
      resp = await fetch(path, {
        method: method,
        headers: headers,
        credentials: 'same-origin',
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (e) {
      const err = new Error('network');
      err.code = 'network';
      throw err;
    }
    let data = null;
    try { data = await resp.json(); } catch (e) { /* 非 JSON（网络层/空体） */ }
    if (!resp.ok) {
      const err = new Error((data && data.error && data.error.code) || 'http_' + resp.status);
      err.code = (data && data.error && data.error.code) || 'http_' + resp.status;
      err.status = resp.status;
      // 服务端信封的 message（英文诊断短语）透传——错误 Toast 括注原因
      //（round2 评审项 9：中文主文案仍走 i18n err.*）。
      err.serverMessage = (data && data.error && data.error.message) || '';
      err.retryAfter = data && data.error && data.error.retry_after_secs;
      throw err;
    }
    return data;
  }

  function flockApp() {
    return {
      // ================= 全局态 =================
      booted: false,
      authed: false,
      route: 'login',
      me: null,
      bootstrap: null,
      bootstrapOk: false,
      navOpen: false,
      toasts: [],
      toastSeq: 1,
      confirmModal: null,
      tokenModal: null,
      copied: false,
      actionBusy: false,
      busyKey: '',

      // 登录
      loginUser: '',
      loginPass: '',
      loginBusy: false,
      loginError: '',
      loginRetrySecs: 0,
      retryTimer: null,

      // 设置口令
      pwUser: '',
      pwToken: '',
      pwPass: '',
      pwPass2: '',
      pwBusy: false,
      pwError: '',

      // 仪表盘
      summary: null,
      dashError: false,
      dashBusy: false,
      chartVip: '',
      series: null,
      uplot: null,
      pollTimer: null,
      resizeBound: null,
      // 自绘图例实时读数（🔴 round2 评审项 1）：hover 时与 tooltip 同源取值，
      // 离开画布/换序列回落 '--'。
      legendTx: '--',
      legendRx: '--',

      // 设备
      peers: [],
      peersLoaded: false,
      peersBusy: false,
      peersError: '',

      // 账号
      users: [],
      usersForbidden: false,
      usersError: '',
      usersBusy: false,
      createUserName: '',
      createUserBusy: false,
      createUserError: '',

      // 审计
      audit: [],
      auditLoaded: false,
      auditForbidden: false,
      auditError: '',
      auditBusy: false,

      // 设置
      config: null,

      get isAdmin() { return !!(this.me && this.me.admin); },

      // 当前登录用户自身行判定（round2 评审项 4）：取消管理员/禁用对自身
      // 前端置灰（后端 409 cannot_demote_self 已兜底）；重置口令保留可用。
      isSelf(u) { return !!(this.me && u && u.username === this.me.user); },

      // ================= 启动与路由 =================
      async boot() {
        window.addEventListener('hashchange', () => this.navigate());
        // bootstrap（公共面）——登录页展示集群标识；wasm 预热并行。
        api('GET', '/api/bootstrap').then((b) => {
          this.bootstrap = b;
          this.bootstrapOk = true;
        }).catch(() => { this.bootstrapOk = false; });
        if (window.FlockPake) { window.FlockPake.init().catch(() => {}); }
        // 会话验活：401 ⇒ 登录页。
        try {
          this.me = await api('GET', '/api/me');
          this.authed = true;
        } catch (e) {
          this.authed = false;
          this.me = null;
        }
        this.booted = true;
        this.navigate();
      },

      navigate() {
        const hash = (location.hash || '').replace(/^#\/?/, '').split('?')[0];
        const known = ['login', 'set-password', 'dashboard', 'peers', 'users', 'audit', 'settings'];
        let route = known.indexOf(hash) >= 0 ? hash : '';
        // 公共页（login/set-password）之外的页面需登录。
        if (!this.authed && route !== 'login' && route !== 'set-password') {
          route = 'login';
        }
        if (!route) { route = this.authed ? 'dashboard' : 'login'; }
        // 已登录访问登录页 ⇒ 回仪表盘（切账号请先登出）。
        if (this.authed && route === 'login') { route = 'dashboard'; }
        // 管理页守卫（非 admin 直击 → 留给页面数据的 403 呈现「无权限」态）。
        this.route = route;
        this.navOpen = false;
        this.confirmModal = null;
        this.tokenModal = null;
        this.stopPolling();
        if (route === 'dashboard' && this.authed) { this.loadDashboard(); this.startPolling(); }
        if (route === 'peers' && this.authed) { this.loadPeers(); }
        if (route === 'users' && this.authed) { this.loadUsers(); }
        if (route === 'audit' && this.authed) { this.loadAudit(); }
        if (route === 'settings' && this.authed) { this.loadConfig(); }
      },

      onEsc() {
        this.navOpen = false;
        this.confirmModal = null;
      },

      handleAuthErr(e) {
        if (e && (e.status === 401 || e.code === 'not_logged_in')) {
          this.authed = false;
          this.me = null;
          this.route = 'login';
          return true;
        }
        return false;
      },

      // ================= Toast =================
      toast(kind, text) {
        const id = this.toastSeq++;
        this.toasts.push({ id: id, kind: kind, text: text });
        setTimeout(() => { this.toasts = this.toasts.filter((x) => x.id !== id); }, 4200);
      },

      // ================= 登录（wasm OPAQUE 全流程）=================
      async submitLogin() {
        if (this.loginBusy) { return; }
        const user = this.loginUser.trim();
        const pass = this.loginPass;
        if (!user || !pass) {
          this.loginError = 'empty';
          return;
        }
        this.loginBusy = true;
        this.loginError = '';
        try {
          if (!window.FlockPake) { throw { code: 'wasm' }; }
          await window.FlockPake.init();
          if (!this.bootstrap) {
            const b = await api('GET', '/api/bootstrap');
            this.bootstrap = b;
            this.bootstrapOk = true;
          }
          // ① ke1（wasm，熵池驱动）
          const ke1 = await window.FlockPake.loginBegin(user, pass);
          // ② login-begin → ke2 + anchor 四件套
          const r = await api('POST', '/api/login-begin', { user: user, ke1_b64: ke1 });
          // ③ wasm 内 anchor 验签（identity_pub 来自 bootstrap）→ ke3
          const ke3 = await window.FlockPake.loginFinish({
            ke2_b64: r.ke2_b64,
            server_id_hex: r.server_id,
            identity_pub_b64: this.bootstrap.identity_pub,
            bind_token_hex: r.bind_token,
            anchor_sig_hex: r.anchor_sig,
          });
          // ④ login-finish → 会话 cookie（浏览器自动持有）
          const me = await api('POST', '/api/login-finish', { user: user, ke3_b64: ke3 });
          this.me = { user: me.user, admin: me.admin, origin: '', expires_unix: 0 };
          try { this.me = await api('GET', '/api/me'); } catch (e) { /* me 已有基本态 */ }
          this.authed = true;
          this.loginPass = '';
          location.hash = '#/dashboard';
          if (location.hash === '#/dashboard') { this.navigate(); }
        } catch (e) {
          this.loginError = e.code || 'network';
          if (e.retryAfter) { this.startRetryCountdown(e.retryAfter); }
        } finally {
          this.loginBusy = false;
        }
      },

      startRetryCountdown(secs) {
        if (this.retryTimer) { clearInterval(this.retryTimer); }
        this.loginRetrySecs = secs;
        this.retryTimer = setInterval(() => {
          this.loginRetrySecs -= 1;
          if (this.loginRetrySecs <= 0) {
            clearInterval(this.retryTimer);
            this.retryTimer = null;
          }
        }, 1000);
      },

      get loginErrorText() {
        if (this.loginError === 'empty') { return t('setpw.empty'); }
        if (!this.loginError) { return ''; }
        if (this.loginError === 'rate_limited') {
          return t('err.rate_limited', { secs: Math.max(1, this.loginRetrySecs) });
        }
        // wasm -2 在登录语境≈错口令（客户端 finish 拒——与 401 login_failed 同文案，
        // 不泄漏具体阶段）。
        if (this.loginError === 'pake') { return t('err.login_failed'); }
        return t('err.' + this.loginError);
      },

      async logout() {
        try { await api('POST', '/api/logout', {}); } catch (e) { /* 尽力 */ }
        this.authed = false;
        this.me = null;
        this.stopPolling();
        location.hash = '#/login';
        if (location.hash === '#/login') { this.navigate(); }
      },

      // ================= 设置口令（pw-begin/commit 引导流）=================
      async submitSetPw() {
        if (this.pwBusy) { return; }
        const user = this.pwUser.trim();
        const token = this.pwToken.trim();
        const pass = this.pwPass;
        if (!user || !token || !pass) { this.pwError = 'empty'; return; }
        if (pass !== this.pwPass2) { this.pwError = 'mismatch'; return; }
        this.pwBusy = true;
        this.pwError = '';
        try {
          if (!window.FlockPake) { throw { code: 'wasm' }; }
          await window.FlockPake.init();
          const m1 = await window.FlockPake.pwBegin(user, pass);
          const r = await api('POST', '/api/pw-begin', { user: user, token: token, m1_b64: m1 });
          const record = await window.FlockPake.pwFinish(r.m2_b64);
          await api('POST', '/api/pw-commit', { user: user, token: token, record_b64: record, profile: 0 });
          this.pwToken = ''; this.pwPass = ''; this.pwPass2 = '';
          this.toast('ok', t('setpw.done'));
          location.hash = '#/login';
          if (location.hash === '#/login') { this.navigate(); }
        } catch (e) {
          this.pwError = e.code || 'network';
        } finally {
          this.pwBusy = false;
        }
      },

      get pwErrorText() {
        if (this.pwError === 'empty') { return t('setpw.empty'); }
        if (this.pwError === 'mismatch') { return t('setpw.mismatch'); }
        return this.pwError ? t('err.' + this.pwError) : '';
      },

      prefillPwUser() {
        if (this.tokenModal) { this.pwUser = this.tokenModal.user; }
      },

      // ================= 仪表盘 =================
      async loadDashboard() {
        this.dashBusy = true;
        this.dashError = false;
        try {
          // 先加载 peers（图表候选源）再取 summary——修复登录后首进 dashboard 的
          // chartVip 空竞态（🔴 UI 评审项 4：旧行为在 peers 未就绪时取默认选中，
          // chartVip 永不回填 → 图表空态直至手动刷新）。
          await this.loadPeersQuiet();
          this.summary = await api('GET', '/api/dashboard/summary');
          this.pickDefaultChartVip();
          await this.loadSeries();
        } catch (e) {
          if (!this.handleAuthErr(e)) { this.dashError = true; }
        } finally {
          this.dashBusy = false;
        }
      },

      // 默认选中：第一台在线设备（无在线则第一台候选）；已有有效选中保持不变。
      pickDefaultChartVip() {
        const ps = this.chartPeers();
        if (this.chartVip && ps.some((p) => p.vip === this.chartVip)) { return; }
        const pick = ps.find((p) => p.kind === 'device' && p.online) || ps[0];
        this.chartVip = pick ? pick.vip : '';
      },

      startPolling() {
        this.stopPolling();
        this.pollTimer = setInterval(async () => {
          if (this.route !== 'dashboard') { this.stopPolling(); return; }
          try {
            this.summary = await api('GET', '/api/dashboard/summary');
            await this.loadSeries();
          } catch (e) {
            if (this.handleAuthErr(e)) { this.stopPolling(); }
          }
        }, 60000);
      },

      stopPolling() {
        if (this.pollTimer) { clearInterval(this.pollTimer); this.pollTimer = null; }
      },

      chartPeers() {
        // 曲线候选：全部 peers（设备 + 服务器），VIP 升序（服务端已排序）。
        return this.peers || [];
      },

      seriesEmpty() {
        return !this.series || !this.series.points || this.series.points.length === 0;
      },

      async loadPeersQuiet() {
        try { this.peers = (await api('GET', '/api/peers')).peers || []; }
        catch (e) { if (this.handleAuthErr(e)) { throw e; } }
      },

      async loadSeries() {
        if (!this.chartVip) { return; }
        try {
          this.series = await api('GET', '/api/dashboard/series?vip=' + encodeURIComponent(this.chartVip));
          this.renderChart();
        } catch (e) {
          if (this.handleAuthErr(e)) { return; }
          this.series = null;
          this.renderChart();
        }
      },

      renderChart() {
        const el = document.getElementById('traffic-chart');
        if (!el || !window.uPlot) { return; }
        const points = (this.series && this.series.points) || [];
        const ts = points.map((p) => p.t);
        const tx = points.map((p) => p.tx_bps);
        const rx = points.map((p) => p.rx_bps);
        const isNarrow = window.matchMedia('(max-width: 767.98px)').matches;
        const height = isNarrow ? 190 : 250;
        const tooltip = document.getElementById('chart-tooltip');
        const hhmm = (v) => {
          const d = new Date(v * 1000);
          return d.getHours().toString().padStart(2, '0') + ':' + d.getMinutes().toString().padStart(2, '0');
        };
        const hhmmss = (v) => {
          const d = new Date(v * 1000);
          const p = (n) => n.toString().padStart(2, '0');
          return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
        };

        // X 轴显式刻度（🔴 round2 评审项 1）：不依赖 uPlot 自动时间分度（标签
        // 密度随宽度/字体浮动，round2 桌面全页截图曾表现为零可见时间刻度）——
        // 自产等间隔「整分」刻度，任何视口恒 4–6 个。
        const timeTickSplits = (u, axisIdx, min, max) => {
          const span = max - min;
          // 目标刻度数：约 150px/刻度的标签预算取整，再夹到 4–6。
          const target = Math.min(6, Math.max(4, Math.floor(u.width / 150)));
          // 步长梯：60s 采样数据 1 分钟起的最小可读步长；窗口 ≤2h 封顶 2h 档。
          const steps = [60, 120, 300, 600, 900, 1800, 3600, 7200];
          const step = steps.find((s) => span / s <= target) || steps[steps.length - 1];
          const out = [];
          for (let v = Math.ceil(min / step) * step; v <= max; v += step) { out.push(v); }
          // 退化保护（span < step 的极窄序列）：首尾兜底两刻度。
          return out.length >= 2 ? out : [min, max];
        };

        const opts = {
          width: el.clientWidth || 600,
          height: height,
          padding: [8, 8, 0, 8],
          cursor: { drag: { x: false, y: false } },
          // uPlot 内建图例关闭（🔴 round2 评审项 1）：双系列图例改 DOM 自绘
          //（index.html .chart-legend）——桌面/手机一致呈现，不被画布层吞掉。
          legend: { show: false },
          plugins: [uplotTooltip(tooltip, this)],
          scales: {
            x: { time: true },
            // Y 恒从 0 起（🔴 round2 评审项 1：0 刻度线常驻轴面）；平坦/全 0 序列
            // 保持 round1 的 1 单位抬头（0 值系列 ≥1.5px 可见），抬头值域形
            // [0, hi+1]——+1 不再把 0 挤出轴。
            y: { range: (u, lo, hi) => [0, hi - lo < 1 ? hi + 1 : hi] },
          },
          axes: [
            {
              // —— X 轴（时间）——
              // time:true 只声明语义（刻度面由 splits/values 自管）。
              time: true,
              // 轴线弱灰；网格 5% 白——不与曲线抢对比度。
              stroke: '#8a93a1',
              grid: { show: true, stroke: 'rgba(255,255,255,0.05)' },
              ticks: { stroke: '#303a4e' },
              // 显式 splits：4–6 个等间隔整分刻度（见上 timeTickSplits 注释）。
              splits: timeTickSplits,
              // 本地时区：unix 秒 → Date 本地格式化（uPlot 数值轴默认 UTC 面——显式覆写）。
              // 标签按「唯一分钟」去重（60s 采样下相邻刻度可能落同一分钟——
              // 显式 splits 下不会发生，保留为防御性去重）。
              values: (u, vals) => {
                const seen = {};
                return vals.map((v) => {
                  if (v == null) { return ''; }
                  const s = hhmm(v);
                  if (seen[s]) { return ''; }
                  seen[s] = true;
                  return s;
                });
              },
            },
            {
              // —— Y 轴（速率）——
              stroke: '#8a93a1',
              // 轴宽预算 68px：「20.0 Mbps」「500 Kbps」完整单位标签的最长形
              //（🔴 round2 评审项 1：弃用「60.0 M」紧凑形，单位写法全 UI 统一）。
              size: 68,
              grid: { show: true, stroke: 'rgba(255,255,255,0.05)' },
              ticks: { stroke: '#303a4e' },
              // 刻度与统计卡/tooltip 同源 fmtBps（完整 bps/Kbps/Mbps/Gbps）。
              values: (u, vals) => vals.map((v) => fmtBps(v)),
            },
          ],
          series: [
            // x 系列标签：uPlot 默认 "Time" →「时间」（🟡 UI 评审项 12；图例已
            // 自绘，此 label 仅存语义面）。
            { label: t('dash.chart.time'), values: (u, v) => (v == null ? '--' : hhmmss(v)) },
            { label: t('dash.chart.tx'), stroke: CHART_TX_COLOR, width: 1.6, fill: 'rgba(79,140,255,0.10)', points: { show: false }, values: (u, v) => (v == null ? '--' : fmtBps(v)) },
            { label: t('dash.chart.rx'), stroke: CHART_RX_COLOR, width: 1.6, fill: 'rgba(63,185,114,0.08)', points: { show: false }, values: (u, v) => (v == null ? '--' : fmtBps(v)) },
          ],
        };

        if (!this.uplot) {
          this.uplot = new uPlot(opts, [ts, tx, rx], el);
          this.resizeBound = () => {
            if (this.uplot && el.clientWidth) {
              this.uplot.setSize({ width: el.clientWidth, height: this.uplot.height });
            }
          };
          window.addEventListener('resize', this.resizeBound);
        } else {
          this.uplot.setData([ts, tx, rx]);
        }
      },

      // ================= 设备 =================
      async loadPeers() {
        this.peersBusy = true;
        this.peersError = '';
        try {
          const r = await api('GET', '/api/peers');
          this.peers = r.peers || [];
          this.peersLoaded = true;
        } catch (e) {
          if (!this.handleAuthErr(e)) { this.peersError = e.code || 'network'; }
        } finally {
          this.peersBusy = false;
        }
      },

      confirmPeer(p, action) {
        const key = 'peers.confirm.' + action;
        // 确认按钮色阶（🟡 UI 评审项 14）：吊销=红（终态）；禁用=琥珀（警示）；
        // 其余（启用/强制下线）=主色。
        const level = { revoke: 'danger', disable: 'warn' }[action] || null;
        this.confirmModal = {
          kind: 'peer', action: action, peer: p,
          title: t(key + '.title'),
          body: t(key + '.body', { vip: p.vip, host: this.hostName(p.hostname) || p.vip }),
          level: level,
        };
      },

      async doConfirmed() {
        const m = this.confirmModal;
        if (!m) { return; }
        this.actionBusy = true;
        try {
          if (m.kind === 'peer') { await this.peerOp(m.peer, m.action); }
          if (m.kind === 'user-disable') { await this.userOp(m.user, 'disable'); }
          if (m.kind === 'user-admin') { await this.userOp(m.user, 'admin', m.admin); }
        } finally {
          this.actionBusy = false;
          this.confirmModal = null;
        }
      },

      async peerOp(p, action) {
        try {
          const r = await api('POST', '/api/peers/' + p.device_id + '/' + action, {});
          this.toast('ok', r && r.epoch != null ? t('peers.result.epoch', { epoch: r.epoch }) : t('peers.result.ok'));
          await this.loadPeers();
          if (this.route === 'dashboard') { await this.loadPeersQuiet(); }
        } catch (e) {
          if (!this.handleAuthErr(e)) { this.toast('err', t('err.' + (e.code || 'network'))); }
        }
      },

      // ================= 账号 =================
      async loadUsers() {
        this.usersBusy = true;
        this.usersError = '';
        this.usersForbidden = false;
        try {
          const r = await api('GET', '/api/users');
          this.users = r.users || [];
        } catch (e) {
          if (this.handleAuthErr(e)) { return; }
          if (e.code === 'forbidden') { this.usersForbidden = true; }
          else { this.usersError = e.code || 'network'; }
        } finally {
          this.usersBusy = false;
        }
      },

      async createUser() {
        const name = this.createUserName.trim();
        if (!name) { this.createUserError = t('setpw.empty'); return; }
        this.createUserBusy = true;
        this.createUserError = '';
        try {
          const r = await api('POST', '/api/users', { username: name });
          this.createUserName = '';
          this.tokenModal = { title: 'users.token.title.create', token: r.pw_bootstrap_token, user: r.username };
          this.copied = false;
          await this.loadUsers();
        } catch (e) {
          if (this.handleAuthErr(e)) { return; }
          this.createUserError = t('err.' + (e.code || 'network'));
        } finally {
          this.createUserBusy = false;
        }
      },

      confirmUserDisable(u) {
        this.confirmModal = {
          kind: 'user-disable', user: u,
          title: t('users.confirm.disable.title'),
          body: t('users.confirm.disable.body', { user: u.username }),
          level: 'warn', // 警示级：琥珀（与吊销红同阶梯——🟡 UI 评审项 14）
        };
      },

      confirmUserAdmin(u, admin) {
        this.confirmModal = {
          kind: 'user-admin', user: u, admin: admin,
          title: t('users.confirm.setadmin.title'),
          body: t('users.confirm.setadmin.body', { user: u.username, role: admin ? t('users.role.admin') : t('users.role.plain') }),
          level: admin ? null : 'warn',
        };
      },

      async userEnable(u) {
        this.busyKey = u.username;
        try { await this.userOp(u, 'enable'); }
        finally { this.busyKey = ''; }
      },

      async userResetPw(u) {
        this.busyKey = u.username;
        try {
          const r = await api('POST', '/api/users/' + u.username + '/reset-password', {});
          this.tokenModal = { title: 'users.token.title.reset', token: r.pw_bootstrap_token, user: u.username };
          this.copied = false;
          this.toast('info', t('users.token.title.reset'));
          await this.loadUsers();
        } catch (e) {
          if (!this.handleAuthErr(e)) { this.toast('err', t('err.' + (e.code || 'network'))); }
        } finally {
          this.busyKey = '';
        }
      },

      async userOp(u, action, body) {
        try {
          await api('POST', '/api/users/' + u.username + '/' + action, body || {});
          this.toast('ok', t('peers.result.ok'));
          await this.loadUsers();
        } catch (e) {
          if (!this.handleAuthErr(e)) { this.toast('err', t('err.' + (e.code || 'network'))); }
        }
      },

      async copyToken() {
        if (!this.tokenModal) { return; }
        try {
          await navigator.clipboard.writeText(this.tokenModal.token);
          this.copied = true;
        } catch (e) {
          // 剪贴板 API 不可用（非安全上下文 http://）——退化为全选提示。
          this.toast('info', this.tokenModal.token);
        }
      },

      // ================= 审计 =================
      async loadAudit() {
        this.auditBusy = true;
        this.auditError = '';
        this.auditForbidden = false;
        try {
          const r = await api('GET', '/api/audit');
          this.audit = r.entries || [];
          this.auditLoaded = true;
        } catch (e) {
          if (this.handleAuthErr(e)) { return; }
          if (e.code === 'forbidden') { this.auditForbidden = true; }
          else { this.auditError = e.code || 'network'; }
        } finally {
          this.auditBusy = false;
        }
      },

      // ================= 设置 =================
      async loadConfig() {
        try { this.config = await api('GET', '/api/config'); }
        catch (e) { this.handleAuthErr(e); }
      },

      // ================= 展示工具 =================
      t: function (key, params) { return window.t(key, params); },

      errMsg(code) { return t('err.' + (code || 'network')); },

      // 错误文案带原因（round2 评审项 9）：API 错误信封的 message（英文诊断
      // 短语，如 "cannot demote self"）透传为括注；中文主文案仍走 i18n err.*。
      errText(e) {
        const base = t('err.' + ((e && e.code) || 'network'));
        const why = e && e.serverMessage;
        return why && why !== base ? base + '（' + why + '）' : base;
      },

      // 图例色片取线色常量（🔴 round2 评审项 1：模板 :style 绑定用）。
      chartTxColor() { return CHART_TX_COLOR; },
      chartRxColor() { return CHART_RX_COLOR; },

      shortId(id) { return id ? id.slice(0, 8) : '—'; },

      shortTarget(s) { return s && s.length > 16 ? s.slice(0, 8) + '…' : (s || '—'); },

      // —— u64 标识（字符串形态下发，🔴 UI 评审项 1）——
      // node_id 等 >2^53 的 u64 标识以字符串往返；展示统一「前 4…后 4」截断，
      // title 悬停给全值（4 位分组），点击复制。≥10 位阈值：node_id 实际
      // 19~20 位（u64 均匀分布），纯数字用户名（≤32 位合法字符集）不误判。
      isNumId(s) { return typeof s === 'string' && /^\d{10,}$/.test(s); },

      shortNum(s) { return this.isNumId(s) ? s.slice(0, 4) + '…' + s.slice(-4) : (s || '—'); },

      // 4 位分组（从右起断组）：8458693432428654888 → 845 8693 4324 2865 4888，
      // mono + tabular-nums 下等宽对齐。
      groupNum(s) {
        if (!this.isNumId(s)) { return s || ''; }
        return s.replace(/\B(?=(\d{4})+(?!\d))/g, ' ');
      },

      // 表格/卡片里的可复制标识芯片：文字为截断形，title 全值分组形。
      idChipTitle(s) { return this.groupNum(s) + ' · ' + t('app.copy.full'); },

      copyText(text) {
        const v = String(text || '');
        const done = () => this.toast('ok', t('app.copied'));
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(v).then(done, () => { this.toast('info', v); });
        } else {
          // 剪贴板 API 不可用（非安全上下文 http://）——退化为 toast 展示全值。
          this.toast('info', v);
        }
      },

      statusBadge(s) {
        return { active: 'badge-success', disabled: 'badge-warn', revoked: 'badge-danger', expired: 'badge-muted' }[s] || 'badge-muted';
      },

      resultBadge(r) {
        // 语义分离（🟡 UI 评审项 10）：琥珀仅用于警示操作——审计「拒绝/错误」一律红。
        return { ok: 'badge-success', denied: 'badge-danger', error: 'badge-danger' }[r] || 'badge-muted';
      },

      // 审计高危 action 词表（round2 评审项 7）：吊销/禁用/重置口令/角色变更等
      // 破坏性或敏感操作即使结果「成功」也用琥珀档——绿色只留给常规/低危操作
      //（登录/登出/创建/启用等）。set_admin 覆盖设/取消两个方向（词表不区分，
      // 权限变更本身即高危）。
      auditHighRisk(action) {
        return !!{
          'peer.revoke': 1, 'peer.disable': 1, 'user.disable': 1,
          'user.reset_password': 1, 'user.set_admin': 1,
        }[action];
      },

      auditResultBadge(e) {
        if (e && e.result === 'ok' && this.auditHighRisk(e.action)) { return 'badge-warn'; }
        return this.resultBadge(e && e.result);
      },

      // 统计卡速率值：数值 + 小一号弱化单位（🟡 UI 评审项 6：<small>Mbps</small>）。
      // 自产 HTML（无用户输入面）——x-html 安全。
      fmtBpsStat(v) {
        const s = fmtBps(v);
        const i = s.lastIndexOf(' ');
        return i < 0 ? s : s.slice(0, i) + '<small>' + s.slice(i + 1) + '</small>';
      },

      sessionRemainText() {
        if (!this.me || !this.me.expires_unix) { return ''; }
        const remain = this.me.expires_unix - Math.floor(Date.now() / 1000);
        if (remain <= 0) { return t('nav.session.expired'); }
        return t('nav.session.expire', { time: fmtDur(remain) });
      },

      // 主机名占位（🟡 UI 评审项 15）：服务端 (unknown)（目录未收敛的远端服务器）
      // →「未上报」弱灰展示。
      hostName(h) { return h && h !== '(unknown)' ? h : t('peers.hostname.unreported'); },
      hostUnknown(h) { return !h || h === '(unknown)'; },

      fmtBps(v) { return fmtBps(v); },
      fmtDur(s) { return fmtDur(s); },
      fmtAgo(unix) { return fmtAgo(unix); },
      fmtTime(unix) {
        const d = new Date(unix * 1000);
        const p = (n) => n.toString().padStart(2, '0');
        return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
      },
    };
  }

  // —— uPlot tooltip 插件（鼠标 + 触控统一；本地时区）——
  // uPlot 1.6.9 的实例**不暴露 u.over**（u-select 挂载点在库内闭包）——旧实现读
  // u.over.getBoundingClientRect() 恒抛 TypeError，tooltip 卡在图表盒左上角
  //（🔴 UI 评审项 4）。正确 API 面：u.root（根节点）+ u.bbox（绘图区盒，相对
  // root 的 CSS 像素）+ u.cursor.left/top（相对绘图区）——三者合成 .chart-box
  // 内坐标，与自管 div 定位一致。
  function uplotTooltip(el, ctx) {
    return {
      hooks: {
        setCursor: (u) => {
          if (!el) { return; }
          const idx = u.cursor.idx;
          if (idx == null || u.cursor.left == null || !u.data[0] || u.data[0].length === 0) {
            el.style.display = 'none';
            ctx.legendTx = '--';
            ctx.legendRx = '--';
            return;
          }
          const ts = u.data[0][idx];
          const tx = u.data[1][idx] || 0;
          const rx = u.data[2][idx] || 0;
          const d = new Date(ts * 1000);
          const p = (n) => n.toString().padStart(2, '0');
          el.innerHTML =
            '<b>' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds()) + '</b><br>' +
            t('dash.chart.tx') + ' ' + fmtBps(tx) + '<br>' +
            t('dash.chart.rx') + ' ' + fmtBps(rx);
          // 自绘图例实时读数（🔴 round2 评审项 1）：与 tooltip 同源同单位。
          ctx.legendTx = fmtBps(tx);
          ctx.legendRx = fmtBps(rx);
          el.style.display = 'block';
          const host = el.parentElement; // .chart-box（tooltip 与图同容器）
          const hostRect = host.getBoundingClientRect();
          const rootRect = u.root.getBoundingClientRect();
          const plotLeft = rootRect.left - hostRect.left + (u.bbox ? u.bbox.left : 0) + u.cursor.left;
          const plotTop = rootRect.top - hostRect.top + (u.bbox ? u.bbox.top : 0) + u.cursor.top;
          const left = Math.min(Math.max(plotLeft + 12, 4), hostRect.width - el.offsetWidth - 4);
          const top = Math.min(Math.max(plotTop - el.offsetHeight - 10, 4), hostRect.height - el.offsetHeight - 4);
          el.style.left = left + 'px';
          el.style.top = Math.max(top, 4) + 'px';
        },
        setScale: () => {
          if (el) { el.style.display = 'none'; }
          ctx.legendTx = '--';
          ctx.legendRx = '--';
        },
      },
    };
  }

  // —— 格式化工具 ——
  // 速率完整单位形（🔴 round2 评审项 1：图表 Y 轴 / tooltip / 统计卡三处同源，
  // 单位写法统一 bps/Kbps/Mbps/Gbps——不再有「60.0 M」紧凑形）。
  function fmtBps(v) {
    v = Number(v) || 0;
    if (v < 1000) { return Math.round(v) + ' bps'; }
    const units = ['Kbps', 'Mbps', 'Gbps', 'Tbps'];
    let u = -1;
    let x = v;
    do { x /= 1000; u++; } while (x >= 1000 && u < units.length - 1);
    return (x >= 100 ? x.toFixed(0) : x >= 10 ? x.toFixed(1) : x.toFixed(2)) + ' ' + units[u];
  }

  function fmtDur(secs) {
    secs = Math.max(0, Math.floor(secs || 0));
    if (secs < 60) { return t('fmt.seconds', { n: secs }); }
    if (secs < 3600) { return t('fmt.minutes', { n: Math.floor(secs / 60) }); }
    if (secs < 86400) { return t('fmt.hours', { n: Math.floor(secs / 3600) }); }
    return t('fmt.days', { n: Math.floor(secs / 86400) });
  }

  function fmtAgo(unix) {
    if (!unix) { return t('peers.lastseen.never'); }
    const diff = Math.floor(Date.now() / 1000) - unix;
    if (diff < 5) { return t('fmt.ago.now'); }
    if (diff < 60) { return t('fmt.ago', { dur: t('fmt.seconds', { n: diff }) }); }
    if (diff < 3600) { return t('fmt.ago', { dur: t('fmt.minutes', { n: Math.floor(diff / 60) }) }); }
    if (diff < 86400) { return t('fmt.ago', { dur: t('fmt.hours', { n: Math.floor(diff / 3600) }) }); }
    return t('fmt.ago', { dur: t('fmt.days', { n: Math.floor(diff / 86400) }) });
  }

  window.flockApp = flockApp;
})();
