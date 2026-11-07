// flock_pake.js —— M8b wasm C-ABI 胶水（docs/design.md §7-M8.6；手写，无 wasm-bindgen）。
//
// 职责：WebAssembly.instantiate(/static/vendor/flock_pake.wasm) → 注入熵
//（crypto.getRandomValues 64B，启动即调）→ 暴露 Promise API：
//   FlockPake.init()                                  就绪（幂等；失败 reject {code:'wasm'}
//   FlockPake.loginBegin(user, pw)        -> ke1_b64  reject {code:'no_entropy'|'pake'}
//   FlockPake.loginFinish(a)              -> ke3_b64  a={ke2_b64, server_id_hex,
//                                                     identity_pub_b64, bind_token_hex,
//                                                     anchor_sig_hex}
//                                                     reject {code:'anchor'|'pake'|...}
//   FlockPake.pwBegin(user, pw)           -> m1_b64
//   FlockPake.pwFinish(m2_b64)            -> record_b64
// 错误码面（垫片 §M8.6）：-1 未注入熵 / -2 pake 失败 / -3 anchor 验签拒 / -4 out 容量不足。
//
// 内存纪律：每次调用经 sr_wasm_alloc 拷参 → 调垫片 → 读返回（memory.buffer 在
// 线性内存增长后会 detach——读侧每次重建 Uint8Array 视图）→ sr_wasm_free 配对释放。
// argon2（m=19MiB t=2）主线程 ~100ms 量级——按钮 spinner 态承担（v1 不引 worker，
// §M8.6 如实声明）。
(function () {
  'use strict';

  var OUT_CAP = 64 * 1024; // 与垫片单测同值的 out 缓冲
  var instance = null;     // WebAssembly.Instance
  var ready = null;        // Promise<void>（init 幂等）

  function exports() { return instance.exports; }

  // —— 内存工具（每次重建视图：buffer 可增长/detach）——
  function writeParam(bytes) {
    var ptr = exports().sr_wasm_alloc(bytes.length);
    new Uint8Array(exports().memory.buffer, ptr, bytes.length).set(bytes);
    return { ptr: ptr, len: bytes.length };
  }
  function freeParam(p) { exports().sr_wasm_free(p.ptr, p.len); }
  function readCStr(ptr) {
    var mem = new Uint8Array(exports().memory.buffer);
    var end = ptr;
    while (mem[end] !== 0) { end++; if (end - ptr > OUT_CAP) { throw new Error('unterminated'); } }
    var out = new Uint8Array(end - ptr);
    out.set(mem.subarray(ptr, end));
    return new TextDecoder('utf-8').decode(out);
  }
  function encUtf8(s) { return new TextEncoder().encode(s); }
  function decHex(hex) {
    if (hex.length % 2 !== 0) { throw new Error('bad hex'); }
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  }
  function decB64(b64) {
    var s = atob(b64);
    var out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) { out[i] = s.charCodeAt(i); }
    return out;
  }

  var ERR_OF = { 1: 'no_entropy', 2: 'pake', 3: 'anchor', 4: 'capacity' };
  function rcToReject(rc) { return { code: ERR_OF[-rc] || 'pake' }; }

  // —— 四个协议调用（同步 C-ABI；Promise 包装留给调用方统一的 UI 态）——
  function loginBegin(user, pw) {
    var u = writeParam(encUtf8(user)), p = writeParam(encUtf8(pw));
    var out = exports().sr_wasm_alloc(OUT_CAP);
    var rc;
    try {
      rc = exports().sr_web_login_begin(u.ptr, u.len, p.ptr, p.len, out, OUT_CAP);
      if (rc !== 0) { throw rcToReject(rc); }
      return readCStr(out);
    } finally {
      exports().sr_wasm_free(out, OUT_CAP);
      freeParam(p); freeParam(u);
    }
  }

  function loginFinish(a) {
    var ke2 = writeParam(encUtf8(a.ke2_b64));
    var sid = writeParam(decHex(a.server_id_hex));
    var pub = writeParam(decB64(a.identity_pub_b64));
    var bind = writeParam(decHex(a.bind_token_hex));
    var sig = writeParam(decHex(a.anchor_sig_hex));
    var out = exports().sr_wasm_alloc(OUT_CAP);
    var rc;
    try {
      rc = exports().sr_web_login_finish(
        ke2.ptr, ke2.len, sid.ptr, pub.ptr, bind.ptr, sig.ptr, out, OUT_CAP);
      if (rc !== 0) { throw rcToReject(rc); }
      return readCStr(out);
    } finally {
      exports().sr_wasm_free(out, OUT_CAP);
      freeParam(sig); freeParam(bind); freeParam(pub); freeParam(sid); freeParam(ke2);
    }
  }

  function pwBegin(user, pw) {
    var u = writeParam(encUtf8(user)), p = writeParam(encUtf8(pw));
    var out = exports().sr_wasm_alloc(OUT_CAP);
    var rc;
    try {
      rc = exports().sr_web_pw_begin(u.ptr, u.len, p.ptr, p.len, out, OUT_CAP);
      if (rc !== 0) { throw rcToReject(rc); }
      return readCStr(out);
    } finally {
      exports().sr_wasm_free(out, OUT_CAP);
      freeParam(p); freeParam(u);
    }
  }

  function pwFinish(m2) {
    var m = writeParam(encUtf8(m2));
    var out = exports().sr_wasm_alloc(OUT_CAP);
    var rc;
    try {
      rc = exports().sr_web_pw_finish(m.ptr, m.len, out, OUT_CAP);
      if (rc !== 0) { throw rcToReject(rc); }
      return readCStr(out);
    } finally {
      exports().sr_wasm_free(out, OUT_CAP);
      freeParam(m);
    }
  }

  // —— init：实例化 + 熵注入（一次；幂等）——
  //
  // 传递依赖垫面：flock-protocol 的 yamux→web-time 在 wasm32 引入 wasm-bindgen
  // 占位导入（__wbindgen_* / 带哈希后缀的 __wbg_*）。OPAQUE/pake 路径不经过
  // yamux（不可达），但 WebAssembly.instantiate 要求全部导入可满足 ⇒ 按
  // Module.imports() 逐项动态建惰性 stub（名称哈希随版本漂移也不破——不硬编码
  // 符号名）；throw 语义的占位（名字含 throw）给抛错 stub，growth 语义返回 0。
  function stubImports(mod) {
    var importObject = {};
    WebAssembly.Module.imports(mod).forEach(function (imp) {
      if (imp.kind !== 'function') { return; }
      var table = importObject[imp.module] || (importObject[imp.module] = {});
      if (/throw/.test(imp.name)) {
        table[imp.name] = function () { throw new Error('wasm-bindgen shim path reached: ' + imp.name); };
      } else if (/grow/.test(imp.name)) {
        table[imp.name] = function () { return 0; };
      } else {
        table[imp.name] = function () { /* pake 路径不可达——惰性空实现 */ };
      }
    });
    return importObject;
  }

  function initOnce(url) {
    if (ready) { return ready; }
    ready = fetch(url || '/static/vendor/flock_pake.wasm')
      .then(function (r) {
        if (!r.ok) { throw new Error('http ' + r.status); }
        return r.arrayBuffer();
      })
      .then(function (bytes) { return WebAssembly.compile(bytes); })
      .then(function (mod) {
        instance = new WebAssembly.Instance(mod, stubImports(mod));
        // 启动即注入熵（≥32B；64B 双份折叠面）——垫片与 getrandom 两池同刻种。
        var ent = new Uint8Array(64);
        crypto.getRandomValues(ent);
        var p = writeParam(ent);
        try { exports().sr_wasm_inject_entropy(p.ptr, p.len); }
        finally { freeParam(p); }
      })
      .catch(function (e) {
        ready = null; // 失败可重试
        throw { code: 'wasm', detail: String(e && e.message || e) };
      });
    return ready;
  }

  // 微任务延迟包装：让调用方先渲染 spinner（OPAQUE 的 argon2 在主线程同步阻塞）。
  function soon(fn) {
    return new Promise(function (resolve, reject) {
      setTimeout(function () {
        try { resolve(fn()); } catch (e) { reject(e instanceof Error ? { code: 'pake', detail: String(e) } : e); }
      }, 30);
    });
  }

  window.FlockPake = {
    init: initOnce,
    loginBegin: function (user, pw) { return initOnce().then(function () { return soon(function () { return loginBegin(user, pw); }); }); },
    loginFinish: function (a) { return initOnce().then(function () { return soon(function () { return loginFinish(a); }); }); },
    pwBegin: function (user, pw) { return initOnce().then(function () { return soon(function () { return pwBegin(user, pw); }); }); },
    pwFinish: function (m2) { return initOnce().then(function () { return soon(function () { return pwFinish(m2); }); }); },
  };
})();
