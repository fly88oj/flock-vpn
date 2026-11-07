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
          this.summary = await api('GET', '/api/dashboard/summary');
          if (!this.chartVip) {
            const ps = this.chartPeers();
            this.chartVip = ps.length ? ps[0].vip : '';
          }
          await this.loadPeersQuiet();
          await this.loadSeries();
        } catch (e) {
          if (!this.handleAuthErr(e)) { this.dashError = true; }
        } finally {
          this.dashBusy = false;
        }
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

        const opts = {
          width: el.clientWidth || 600,
          height: height,
          padding: [8, 8, 0, 8],
          cursor: { drag: { x: false, y: false } },
          legend: { show: true },
          plugins: [uplotTooltip(tooltip, this)],
          scales: { x: { time: true }, y: {} },
          axes: [
            {
              time: true,
              stroke: '#8a94a8',
              grid: { show: true, stroke: 'rgba(255,255,255,0.05)' },
              ticks: { stroke: '#303a4e' },
              // 本地时区：unix 秒 → Date 本地格式化（uPlot 数值轴默认 UTC 面——显式覆写）。
              values: (u, vals) => vals.map((v) => {
                const d = new Date(v * 1000);
                return d.getHours().toString().padStart(2, '0') + ':' + d.getMinutes().toString().padStart(2, '0');
              }),
            },
            {
              stroke: '#8a94a8',
              size: 56,
              grid: { show: true, stroke: 'rgba(255,255,255,0.05)' },
              ticks: { stroke: '#303a4e' },
              values: (u, vals) => vals.map((v) => fmtBps(v, true)),
            },
          ],
          series: [
            {},
            { label: t('dash.chart.tx'), stroke: '#4f8cff', width: 1.6, fill: 'rgba(79,140,255,0.10)', points: { show: false } },
            { label: t('dash.chart.rx'), stroke: '#3fb972', width: 1.6, fill: 'rgba(63,185,114,0.08)', points: { show: false } },
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
        this.confirmModal = {
          kind: 'peer', action: action, peer: p,
          title: t(key + '.title'),
          body: t(key + '.body', { vip: p.vip, host: p.hostname || p.vip }),
          danger: action === 'revoke',
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
          danger: false,
        };
      },

      confirmUserAdmin(u, admin) {
        this.confirmModal = {
          kind: 'user-admin', user: u, admin: admin,
          title: t('users.confirm.setadmin.title'),
          body: t('users.confirm.setadmin.body', { user: u.username, role: admin ? t('users.role.admin') : t('users.role.plain') }),
          danger: !admin,
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

      shortId(id) { return id ? id.slice(0, 8) : '—'; },

      shortTarget(s) { return s && s.length > 16 ? s.slice(0, 8) + '…' : (s || '—'); },

      // —— u64 标识（字符串形态下发，🔴 UI 评审项 1）——
      // node_id 等 >2^53 的 u64 标识以字符串往返；展示统一「前 4…后 4」截断，
      // title 悬停给全值（4 位分组），点击复制。
      isNumId(s) { return typeof s === 'string' && /^\d{5,}$/.test(s); },

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
        return { ok: 'badge-success', denied: 'badge-warn', error: 'badge-danger' }[r] || 'badge-muted';
      },

      sessionRemainText() {
        if (!this.me || !this.me.expires_unix) { return ''; }
        const remain = this.me.expires_unix - Math.floor(Date.now() / 1000);
        if (remain <= 0) { return t('nav.session.expired'); }
        return t('nav.session.expire', { time: fmtDur(remain) });
      },

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
  function uplotTooltip(el, ctx) {
    return {
      hooks: {
        setCursor: (u) => {
          if (!el) { return; }
          const idx = u.cursor.idx;
          if (idx == null || !u.data[0] || u.data[0].length === 0) {
            el.style.display = 'none';
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
          el.style.display = 'block';
          const box = u.over.getBoundingClientRect();
          const left = Math.min(Math.max(u.cursor.left + 12, 4), box.width - el.offsetWidth - 4);
          const top = Math.min(Math.max(u.cursor.top - el.offsetHeight - 10, 4), box.height - el.offsetHeight - 4);
          el.style.left = left + 'px';
          el.style.top = Math.max(top, 4) + 'px';
        },
        setScale: () => { if (el) { el.style.display = 'none'; } },
      },
    };
  }

  // —— 格式化工具 ——
  function fmtBps(v, axis) {
    v = Number(v) || 0;
    if (v < 1000) { return axis ? String(Math.round(v)) : Math.round(v) + ' bps'; }
    const units = ['Kbps', 'Mbps', 'Gbps', 'Tbps'];
    let u = -1;
    let x = v;
    do { x /= 1000; u++; } while (x >= 1000 && u < units.length - 1);
    return (x >= 100 ? x.toFixed(0) : x >= 10 ? x.toFixed(1) : x.toFixed(2)) + (axis ? '' : ' ' + units[u]);
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
