// flock_pake.js —— M8b wasm C-ABI glue (docs/design.md §7-M8.6; hand-written,
// no wasm-bindgen).
//
// Responsibilities: WebAssembly.instantiate(/static/vendor/flock_pake.wasm) →
// inject entropy (crypto.getRandomValues 64B, called at startup) → expose the
// Promise API:
//   FlockPake.init()                                  ready (idempotent; failure rejects {code:'wasm'}
//   FlockPake.loginBegin(user, pw)        -> ke1_b64  reject {code:'no_entropy'|'pake'}
//   FlockPake.loginFinish(a)              -> ke3_b64  a={ke2_b64, server_id_hex,
//                                                     identity_pub_b64, bind_token_hex,
//                                                     anchor_sig_hex}
//                                                     reject {code:'anchor'|'pake'|...}
//   FlockPake.pwBegin(user, pw)           -> m1_b64
//   FlockPake.pwFinish(m2_b64)            -> record_b64
// Error-code surface (shim §M8.6): -1 entropy not injected / -2 pake failure /
// -3 anchor verification rejected / -4 out capacity insufficient.
//
// Memory discipline: every call copies parameters via sr_wasm_alloc → invokes
// the shim → reads the return value (memory.buffer detaches after linear
// memory growth —— the read side rebuilds the Uint8Array view every time) →
// paired release via sr_wasm_free.
// argon2 (m=19MiB t=2) costs ~100ms on the main thread —— covered by the
// button spinner state (no worker in v1, declared as-is in §M8.6).
(function () {
  'use strict';

  var OUT_CAP = 64 * 1024; // out buffer, same value as the shim's unit tests
  var instance = null;     // WebAssembly.Instance
  var ready = null;        // Promise<void> (init is idempotent)

  function exports() { return instance.exports; }

  // —— Memory helpers (views rebuilt every time: the buffer can grow/detach) ——
  function writeParam(bytes) {
    if (bytes.length === 0) {
      return { ptr: 0, len: 0 }; // zero-length short circuit: sr_wasm_alloc(0)
    }                            // returns a dangling pointer, and Uint8Array
                                 // construction would RangeError —— empty
                                 // parameters pass the null sentinel directly
    var ptr = exports().sr_wasm_alloc(bytes.length);
    new Uint8Array(exports().memory.buffer, ptr, bytes.length).set(bytes);
    return { ptr: ptr, len: bytes.length };
  }
  function freeParam(p) { if (p.ptr !== 0) { exports().sr_wasm_free(p.ptr, p.len); } }
  function readCStr(ptr) {
    var mem = new Uint8Array(exports().memory.buffer);
    var end = ptr;
    while (mem[end] !== 0) { end++; if (end - ptr > OUT_CAP) { throw new Error('unterminated'); } }
    var out = new Uint8Array(end - ptr);
    out.set(mem.subarray(ptr, end));
    return new TextDecoder('utf-8').decode(out);
  }
  function encUtf8(s) { return new TextEncoder().encode(s); }
  // decHex/decB64 expected-length validation: the shim side copies with
  // fixed::<N>() —— short inputs would read adjacent memory out of bounds, so
  // verify "exactly expect bytes" up front (odd length / non-hex characters /
  // short hex error out without overreading).
  function decHex(hex, expect) {
    if (hex.length !== expect * 2 || /[^0-9a-fA-F]/.test(hex)) {
      throw new Error('bad hex (want ' + expect * 2 + ' chars)');
    }
    var out = new Uint8Array(expect);
    for (var i = 0; i < expect; i++) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  }
  function decB64(b64, expect) {
    var s = atob(b64);
    if (s.length !== expect) { throw new Error('bad b64 (want ' + expect + ' bytes)'); }
    var out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) { out[i] = s.charCodeAt(i); }
    return out;
  }

  var ERR_OF = { 1: 'no_entropy', 2: 'pake', 3: 'anchor', 4: 'capacity' };
  function rcToReject(rc) { return { code: ERR_OF[-rc] || 'pake' }; }

  // —— The four protocol calls (synchronous C-ABI; Promise wrapping is left to
  // the caller for a uniform UI state) ——
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
    var sid = writeParam(decHex(a.server_id_hex, 16));      // server_id 16B
    var pub = writeParam(decB64(a.identity_pub_b64, 32));   // Ed25519 verify key 32B
    var bind = writeParam(decHex(a.bind_token_hex, 16));    // bind_token 16B
    var sig = writeParam(decHex(a.anchor_sig_hex, 64));     // anchor signature 64B
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

  // —— init: instantiate + entropy injection (once; idempotent) ——
  //
  // Transitive-dependency shim surface: flock-protocol's yamux→web-time pulls
  // wasm-bindgen placeholder imports into wasm32 (__wbindgen_* / hash-suffixed
  // __wbg_*). The OPAQUE/pake path never goes through yamux (unreachable), but
  // WebAssembly.instantiate requires every import to be satisfiable ⇒ build a
  // lazy stub per entry via Module.imports() (name hashes drifting across
  // versions cannot break it —— no hardcoded symbol names); placeholders with
  // throw semantics (name containing throw) get a throwing stub, growth
  // semantics return 0.
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
        table[imp.name] = function () { /* unreachable on the pake path —— lazy no-op */ };
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
        // Entropy injected at startup (≥32B; 64B covers the double-fold
        // surface) —— seeds the shim and getrandom pools at the same instant.
        var ent = new Uint8Array(64);
        crypto.getRandomValues(ent);
        var p = writeParam(ent);
        try { exports().sr_wasm_inject_entropy(p.ptr, p.len); }
        finally { freeParam(p); }
      })
      .catch(function (e) {
        ready = null; // retriable on failure
        throw { code: 'wasm', detail: String(e && e.message || e) };
      });
    return ready;
  }

  // Microtask-delay wrapper: lets the caller render the spinner first
  // (OPAQUE's argon2 blocks the main thread synchronously).
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
