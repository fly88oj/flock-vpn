// app.js —— M8 Web UI application core (Alpine.js root component + API wrapper +
// uPlot integration, §M8.6).
//
// Responsibilities:
//  - hash routing (hand-rolled, no router lib): #/login | #/set-password |
//    #/dashboard | #/peers | #/users | #/audit | #/settings; unknown routes fall
//    back to dashboard (login when unauthenticated).
//  - session state: boot probes GET /api/me to restore; any API 401 ⇒ back to
//    the login page.
//  - API wrapper: unified error envelope {error:{code,message[,retry_after_secs]}}
//    parsing; POST always carries X-Flock-Web: 1 + Content-Type: application/json
//    (CSRF double gate).
//  - wasm OPAQUE: login / set-password run entirely through window.FlockPake
//    (C-ABI shim glue); the anchor is verified inside wasm against
//    /api/bootstrap's identity_pub.
//  - uPlot traffic chart: local-timezone ticks + touch/mouse tooltip;
//    container-width adaptive + resize.
//  - language: i18n.js packs (en default + zh); the Lang switcher (login page /
//    settings) persists the choice to localStorage; the bootstrap `lang` field
//    acts as the initial hint on first visit (see i18n.js header).
(function () {
  'use strict';

  // —— Chart two-series colors (round2 review item 1): line strokes and the
  // hand-drawn legend swatches are defined in one place, so legend colors
  // always match the lines (prevents hex drift between the two). ——
  const CHART_TX_COLOR = '#4f8cff';
  const CHART_RX_COLOR = '#3fb972';

  // —— API wrapper (error envelope parsing) ——
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
    try { data = await resp.json(); } catch (e) { /* not JSON (network layer / empty body) */ }
    if (!resp.ok) {
      const err = new Error((data && data.error && data.error.code) || 'http_' + resp.status);
      err.code = (data && data.error && data.error.code) || 'http_' + resp.status;
      err.status = resp.status;
      // The server envelope's message (English diagnostic phrase) is passed
      // through —— error toasts annotate the reason with it (round2 review
      // item 9: the localized main copy still comes from i18n err.*).
      err.serverMessage = (data && data.error && data.error.message) || '';
      err.retryAfter = data && data.error && data.error.retry_after_secs;
      throw err;
    }
    return data;
  }

  function flockApp() {
    return {
      // ================= Global state =================
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

      // Active UI language (pack id from i18n.js: 'en' | 'zh'). Reactive: the
      // t() method reads this.lang so a switch re-renders every copy binding.
      lang: (window.FLOCK_LANG && window.FLOCK_LANG()) || 'en',

      // Login
      loginUser: '',
      loginPass: '',
      loginBusy: false,
      loginError: '',
      loginRetrySecs: 0,
      retryTimer: null,

      // Set password
      pwUser: '',
      pwToken: '',
      pwPass: '',
      pwPass2: '',
      pwBusy: false,
      pwError: '',

      // Dashboard
      summary: null,
      dashError: false,
      dashBusy: false,
      chartVip: '',
      series: null,
      uplot: null,
      pollTimer: null,
      resizeBound: null,
      // Hand-drawn legend live readouts (round2 review item 1): on hover they
      // read from the same source as the tooltip; leaving the canvas or
      // switching the series falls back to '--'.
      legendTx: '--',
      legendRx: '--',

      // Devices
      peers: [],
      peersLoaded: false,
      peersBusy: false,
      peersError: '',

      // Accounts
      users: [],
      usersForbidden: false,
      usersError: '',
      usersBusy: false,
      createUserName: '',
      createUserBusy: false,
      createUserError: '',

      // Audit
      audit: [],
      auditLoaded: false,
      auditForbidden: false,
      auditError: '',
      auditBusy: false,

      // Settings
      config: null,

      get isAdmin() { return !!(this.me && this.me.admin); },

      // Self-row detection for the signed-in user (round2 review item 4):
      // remove-admin / disable are greyed out for self on the frontend (the
      // backend 409 cannot_demote_self remains the backstop); reset password
      // stays available.
      isSelf(u) { return !!(this.me && u && u.username === this.me.user); },

      // ================= Language =================
      // Switch the active pack + persist the choice (localStorage); then sync
      // <html lang> and the document title. Templates re-render automatically
      // because t() depends on this.lang.
      setLang(l) {
        const applied = window.FLOCK_SET_LANG(l);
        if (applied && applied !== this.lang) {
          this.lang = applied;
          this.applyLangToDocument();
        }
      },

      applyLangToDocument() {
        document.documentElement.lang = this.lang === 'zh' ? 'zh-CN' : 'en';
        document.title = window.t('app.name');
      },

      // ================= Boot & routing =================
      async boot() {
        window.addEventListener('hashchange', () => this.navigate());
        this.applyLangToDocument();
        // bootstrap (public surface) —— the login page shows the cluster
        // identity; wasm warm-up runs in parallel. The bootstrap `lang` field
        // is the server's initial hint (ignored once a choice is stored).
        api('GET', '/api/bootstrap').then((b) => {
          this.bootstrap = b;
          this.bootstrapOk = true;
          const hinted = window.FLOCK_APPLY_BOOTSTRAP_LANG(b && b.lang);
          if (hinted !== this.lang) {
            this.lang = hinted;
            this.applyLangToDocument();
          }
        }).catch(() => { this.bootstrapOk = false; });
        if (window.FlockPake) { window.FlockPake.init().catch(() => {}); }
        // Session probe: 401 ⇒ login page.
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
        // Pages beyond the public ones (login/set-password) require a session.
        if (!this.authed && route !== 'login' && route !== 'set-password') {
          route = 'login';
        }
        if (!route) { route = this.authed ? 'dashboard' : 'login'; }
        // Signed-in users hitting the login page ⇒ back to dashboard (sign out
        // first to switch accounts).
        if (this.authed && route === 'login') { route = 'dashboard'; }
        // Admin page guard (non-admin direct hit → left for the page data's
        // 403 to render the "no permission" state).
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

      // ================= Login (full wasm OPAQUE flow) =================
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
          // ① ke1 (wasm, entropy-pool driven)
          const ke1 = await window.FlockPake.loginBegin(user, pass);
          // ② login-begin → ke2 + the anchor four-tuple
          const r = await api('POST', '/api/login-begin', { user: user, ke1_b64: ke1 });
          // ③ anchor signature verified inside wasm (identity_pub from
          //    bootstrap) → ke3
          const ke3 = await window.FlockPake.loginFinish({
            ke2_b64: r.ke2_b64,
            server_id_hex: r.server_id,
            identity_pub_b64: this.bootstrap.identity_pub,
            bind_token_hex: r.bind_token,
            anchor_sig_hex: r.anchor_sig,
          });
          // ④ login-finish → session cookie (held automatically by the browser)
          const me = await api('POST', '/api/login-finish', { user: user, ke3_b64: ke3 });
          this.me = { user: me.user, admin: me.admin, origin: '', expires_unix: 0 };
          try { this.me = await api('GET', '/api/me'); } catch (e) { /* me already has the basic state */ }
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
        // wasm -2 in the login context ≈ wrong password (client-side finish
        // rejected —— same copy as the 401 login_failed, leaking no phase
        // detail).
        if (this.loginError === 'pake') { return t('err.login_failed'); }
        return t('err.' + this.loginError);
      },

      async logout() {
        try { await api('POST', '/api/logout', {}); } catch (e) { /* best effort */ }
        this.authed = false;
        this.me = null;
        this.stopPolling();
        location.hash = '#/login';
        if (location.hash === '#/login') { this.navigate(); }
      },

      // ================= Set password (pw-begin/commit bootstrap flow) =================
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

      // ================= Dashboard =================
      async loadDashboard() {
        this.dashBusy = true;
        this.dashError = false;
        try {
          // Load peers first (chart candidate source) then summary —— fixes
          // the empty-chartVip race on the first dashboard entry after login
          // (UI review item 4: the old behavior picked a default selection
          // while peers were not ready yet, chartVip was never backfilled →
          // empty chart until a manual refresh).
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

      // Default selection: the first online device (or the first candidate
      // when none is online); an existing valid selection is kept.
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
        // Chart candidates: all peers (devices + servers), ascending by VIP
        // (already sorted server-side).
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

        // Explicit X-axis ticks (round2 review item 1): do not rely on uPlot's
        // automatic time division (label density floats with width/font —— the
        // round2 full-page desktop screenshot once showed zero visible time
        // ticks) —— produce evenly spaced "whole-minute" ticks, always 4–6 of
        // them in any viewport.
        const timeTickSplits = (u, axisIdx, min, max) => {
          const span = max - min;
          // Target tick count: round a label budget of ~150px/tick, then clamp
          // to 4–6.
          const target = Math.min(6, Math.max(4, Math.floor(u.width / 150)));
          // Step ladder: smallest readable step for 60s-sampled data starts at
          // 1 minute; capped at the 2h tier for windows ≤2h.
          const steps = [60, 120, 300, 600, 900, 1800, 3600, 7200];
          const step = steps.find((s) => span / s <= target) || steps[steps.length - 1];
          const out = [];
          for (let v = Math.ceil(min / step) * step; v <= max; v += step) { out.push(v); }
          // Degenerate guard (extremely narrow series where span < step):
          // fall back to first/last ticks.
          return out.length >= 2 ? out : [min, max];
        };

        const opts = {
          width: el.clientWidth || 600,
          height: height,
          padding: [8, 8, 0, 8],
          cursor: { drag: { x: false, y: false } },
          // uPlot's built-in legend is off (round2 review item 1): the
          // two-series legend is hand-drawn DOM (index.html .chart-legend) ——
          // identical on desktop and mobile, never swallowed by the canvas
          // layer.
          legend: { show: false },
          plugins: [uplotTooltip(tooltip, this)],
          scales: {
            x: { time: true },
            // Y always starts at 0 (round2 review item 1: the 0 gridline is a
            // permanent axis feature); flat / all-zero series keep round1's
            // 1-unit headroom (a 0-valued series stays ≥1.5px visible), with
            // the value range shaped [0, hi+1] —— the +1 no longer squeezes 0
            // out of the axis.
            y: { range: (u, lo, hi) => [0, hi - lo < 1 ? hi + 1 : hi] },
          },
          axes: [
            {
              // —— X axis (time) ——
              // time:true only declares semantics (the tick face is managed
              // by splits/values).
              time: true,
              // Faint-grey axis line; 5% white grid —— no contrast competition
              // with the lines.
              stroke: '#8a93a1',
              grid: { show: true, stroke: 'rgba(255,255,255,0.05)' },
              ticks: { stroke: '#303a4e' },
              // Explicit splits: 4–6 evenly spaced whole-minute ticks (see the
              // timeTickSplits comment above).
              splits: timeTickSplits,
              // Local timezone: unix seconds → Date local formatting (uPlot's
              // numeric-axis default is the UTC face —— explicitly overridden).
              // Labels deduplicated by "unique minute" (adjacent ticks can
              // land in the same minute at 60s sampling —— cannot happen with
              // explicit splits; kept as defensive dedup).
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
              // —— Y axis (rate) ——
              stroke: '#8a93a1',
              // Axis width budget 68px: the longest shape of full-unit labels
              // like "20.0 Mbps" / "500 Kbps" (round2 review item 1: the
              // compact "60.0 M" form is dropped, unit spelling is uniform
              // across the UI).
              size: 68,
              grid: { show: true, stroke: 'rgba(255,255,255,0.05)' },
              ticks: { stroke: '#303a4e' },
              // Ticks share fmtBps with the stat cards / tooltip (full
              // bps/Kbps/Mbps/Gbps).
              values: (u, vals) => vals.map((v) => fmtBps(v)),
            },
          ],
          series: [
            // x series label: uPlot's default "Time" → localized (UI review
            // item 12; the legend is hand-drawn, this label is semantic only).
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

      // ================= Devices =================
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
        // Confirm-button color tiers (UI review item 14): revoke = red
        // (terminal); disable = amber (warning); the rest (enable / kick) =
        // primary.
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
          if (!this.handleAuthErr(e)) { this.toast('err', this.errText(e)); }
        }
      },

      // ================= Accounts =================
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
          level: 'warn', // warning tier: amber (same ladder as revoke red —— UI review item 14)
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
          if (!this.handleAuthErr(e)) { this.toast('err', this.errText(e)); }
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
          if (!this.handleAuthErr(e)) { this.toast('err', this.errText(e)); }
        }
      },

      async copyToken() {
        if (!this.tokenModal) { return; }
        try {
          await navigator.clipboard.writeText(this.tokenModal.token);
          this.copied = true;
        } catch (e) {
          // Clipboard API unavailable (insecure context http://) —— fall back
          // to showing the full value.
          this.toast('info', this.tokenModal.token);
        }
      },

      // ================= Audit =================
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

      // ================= Settings =================
      async loadConfig() {
        try { this.config = await api('GET', '/api/config'); }
        catch (e) { this.handleAuthErr(e); }
      },

      // ================= Display helpers =================
      t: function (key, params) {
        void this.lang; // reactive dependency —— re-renders on language switch
        return window.t(key, params);
      },

      errMsg(code) { return t('err.' + (code || 'network')); },

      // Error copy with reason (round2 review item 9): the API error
      // envelope's message (English diagnostic phrase, e.g. "cannot demote
      // self") is passed through as a parenthetical; the localized main copy
      // still comes from i18n err.*.
      errText(e) {
        const base = t('err.' + ((e && e.code) || 'network'));
        const why = e && e.serverMessage;
        return why && why !== base ? base + ' (' + why + ')' : base;
      },

      // Legend swatches read the line-color constants (round2 review item 1:
      // used by the template's :style bindings).
      chartTxColor() { return CHART_TX_COLOR; },
      chartRxColor() { return CHART_RX_COLOR; },

      shortId(id) { return id ? id.slice(0, 8) : '—'; },

      shortTarget(s) { return s && s.length > 16 ? s.slice(0, 8) + '…' : (s || '—'); },

      // —— u64 identifiers (delivered as strings, UI review item 1) ——
      // node_id and other >2^53 u64 identifiers round-trip as strings;
      // display is uniformly "first 4…last 4" truncated, with the full value
      // (4-digit grouped) in the hover title, click to copy. ≥10 digit
      // threshold: node_id is actually 19–20 digits (uniform u64), pure-digit
      // usernames (≤32 legal charset) never misclassify.
      isNumId(s) { return typeof s === 'string' && /^\d{10,}$/.test(s); },

      shortNum(s) { return this.isNumId(s) ? s.slice(0, 4) + '…' + s.slice(-4) : (s || '—'); },

      // 4-digit grouping (groups broken from the right):
      // 8458693432428654888 → 845 8693 4324 2865 4888, monospace + tabular-nums
      // for even alignment.
      groupNum(s) {
        if (!this.isNumId(s)) { return s || ''; }
        return s.replace(/\B(?=(\d{4})+(?!\d))/g, ' ');
      },

      // Copyable ID chip inside tables/cards: truncated text, grouped full
      // value in the title.
      idChipTitle(s) { return this.groupNum(s) + ' · ' + t('app.copy.full'); },

      copyText(text) {
        const v = String(text || '');
        const done = () => this.toast('ok', t('app.copied'));
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(v).then(done, () => { this.toast('info', v); });
        } else {
          // Clipboard API unavailable (insecure context http://) —— fall back
          // to a toast showing the full value.
          this.toast('info', v);
        }
      },

      statusBadge(s) {
        return { active: 'badge-success', disabled: 'badge-warn', revoked: 'badge-danger', expired: 'badge-muted' }[s] || 'badge-muted';
      },

      resultBadge(r) {
        // Semantic separation (UI review item 10): amber is reserved for
        // warning-tier operations —— audit "denied"/"error" are always red.
        return { ok: 'badge-success', denied: 'badge-danger', error: 'badge-danger' }[r] || 'badge-muted';
      },

      // High-risk audit action vocabulary (round2 review item 7): destructive
      // or sensitive operations (revoke / disable / reset password / role
      // change) use the amber tier even when the result is "ok" —— green is
      // reserved for routine / low-risk operations (login / logout / create /
      // enable, etc.). set_admin covers both directions (the vocabulary does
      // not distinguish; a permission change is itself high-risk).
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

      // Stat-card rate values: number + smaller subdued unit (UI review item
      // 6: <small>Mbps</small>). Self-produced HTML (no user-input surface)
      // —— safe for x-html.
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

      // Hostname placeholder (UI review item 15): the server's "(unknown)"
      // (remote servers not yet converged in the directory) → "Not reported"
      // shown in subdued grey.
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

  // —— uPlot tooltip plugin (unified mouse + touch; local timezone) ——
  // uPlot 1.6.9 instances do **not expose u.over** (the u-select mount point
  // is closed over inside the library) —— the old implementation reading
  // u.over.getBoundingClientRect() always threw TypeError, leaving the
  // tooltip stuck in the chart box's top-left corner (UI review item 4). The
  // correct API surface: u.root (root node) + u.bbox (plot-area box, CSS
  // pixels relative to root) + u.cursor.left/top (relative to the plot area)
  // —— the three combine into coordinates inside .chart-box, matching the
  // self-managed div positioning.
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
          // Hand-drawn legend live readouts (round2 review item 1): same
          // source and units as the tooltip.
          ctx.legendTx = fmtBps(tx);
          ctx.legendRx = fmtBps(rx);
          el.style.display = 'block';
          const host = el.parentElement; // .chart-box (tooltip shares the chart container)
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

  // —— Formatting helpers ——
  // Full-unit rate formatting (round2 review item 1: chart Y axis / tooltip /
  // stat cards share one source; unit spelling is uniformly
  // bps/Kbps/Mbps/Gbps —— no more compact "60.0 M" forms).
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
