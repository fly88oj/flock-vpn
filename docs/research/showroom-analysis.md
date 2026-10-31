# Showroom 协议层剖析（应用层加密 / 压缩 / 认证）

> 目标：盘点 `E:\Works\showroom` 中运行在 FRP 中转（明文链路）之上的应用层安全协议，
> 作为后续抽象为独立 Rust 库（ChmlVPN 协议层）的底子。
> 证据格式：`文件:行号`，全部来自本次实际读取的源码 / 文档；版本号来自 `Cargo.lock`。
> 剖析日期：2026-10-31。

---

## 0. 总体定位

Showroom 的安全前提：控制面流量可能经不可信明文链路（公网隧道、无 TLS 反代），
**不依赖传输层**——认证、完整性、机密性全部实现在应用层（docs/security.md:5）。
协议层集中在一个 crate：`showroom-common`（lib.rs 头注释自述为"协议契约层"，
showroom-common/src/lib.rs:1-2），由 `showroomctl`（服务端）与 `showroom`（CLI 客户端）
与 wasm 控制台三方共用。原生目标 `forbid(unsafe_code)`，仅 wasm32 垫片例外（lib.rs:4-5）。

协议层由四块构成：

| 模块 | 职责 | 规范出处 |
|---|---|---|
| SR-SIG1 请求签名（lib.rs:175-340） | 每次 HTTP 请求的 Ed25519 认证 + 防重放 | SPEC.md §1 |
| 加密信封 v1（lib.rs:342-473） | 大载荷混合加密（RSA 封装 + AES-GCM 分段流） | SPEC.md §2、security.md §2 |
| OPAQUE 登录（opaque.rs 全文件） | 密码认证 AKE（盲化 OPRF，密码永不上线） | SPEC.md §16、RFC 9380 |
| 实时下行流（showroomctl/src/streams.rs） | ndjson 流式桥接（非加密，但属协议契约 §10.4） | SPEC.md §10.4 |

---

## 1. 算法清单表

| # | 用途 | 算法 / 参数 | 实现 | 证据 |
|---|---|---|---|---|
| 1 | **请求签名（SR-SIG1）** | Ed25519（签名密钥=裸 32B seed）；canonical = `SR-SIG1\n<user>\n<ts>\n<nonce>\n<METHOD>\n<path_with_query>\n<sha256_hex(body)>`；Authorization 值 `SR-SIG1 <user>:<ts>:<nonce>:<sig_b64url>`（base64url 无 padding） | `ed25519-dalek` SigningKey/Verifier；`build_canonical`/`sign`/`sign_prehashed`/`verify`/`verify_with_hash` | lib.rs:222-231（canonical）、lib.rs:235-261（签名）、SPEC.md:8-10、security.md:13-29 |
| 2 | **信封密钥封装** | RSA-3072-OAEP（OAEP with SHA-256），封 32B 一次性 AES 密钥，定长 384B 头 | `rsa` crate `Oaep::new::<Sha256>()`；`PlatformKeys::generate`（RSA-3072） | lib.rs:347-349、lib.rs:385-393、lib.rs:429-431；SPEC.md:18 |
| 3 | **信封 AEAD** | AES-256-GCM，96-bit nonce，128-bit tag；密钥一次性随机 32B | `aes-gcm` Aes256Gcm；`seal`/`open` | lib.rs:51-53、lib.rs:396-411、lib.rs:453-457 |
| 4 | **信封分段** | 明文按 4MiB 一段，每段独立 `[12B 随机 nonce][密文‖16B tag]`；无 AAD；段边界即流式边界 | 常量 `SEG=4*1024*1024`；每段新随机 nonce（非计数器） | lib.rs:54、lib.rs:403-404；security.md:58 |
| 5 | **登录 AKE** | OPAQUE（RFC 9380，`opaque-ke` 3.0.0），Suite = Ristretto255（OPRF 群 + KE 群）+ TripleDH + **Identity KSF**（硬化外置，见 #6）；标识 client=user、server=`b"showroom-server"`、credential_identifier=user；未知用户走 crate 原生 dummy 假记录（ke2 同形，防枚举） | `opaque_ke::CipherSuite for Suite` | opaque.rs:32-39、opaque.rs:42、opaque.rs:74-76、opaque.rs:192-211；SPEC.md:239-254 |
| 6 | **口令硬化（rwd）** | argon2id，m=19456 KiB / t=2 / p=1（OWASP 档），输出 32B；盐 = `b"showroom-opaque-v1" + user`（常数前缀+用户名，用户名进盐使同密码跨账号派生不同）；在 OPRF 盲化**前**执行；有固定向量测试防 native/wasm 漂移 | `argon2::Argon2::hash_password_into`；`rwd()` | opaque.rs:53、opaque.rs:56-70、opaque.rs:298-312 |
| 7 | **压缩** | zstd level **19**（高压缩），压**加密前**（先压后密，不泄熵）；上行（docker save 管道）与下行（pg_dump -Fc 外包）均 zstd-19；服务端解包按魔数自适应：zstd `28 B5 2F FD` / gzip `1F 8B 08` / 裸流直通 | CLI `IMPORT_ZSTD_LEVEL=19`；dump `DUMP_ZSTD_LEVEL=19`；`MagicSink` | showroom/src/main.rs:318、showroomctl/src/dbmaint.rs:157-158、unpack.rs:15-30、security.md:86-88 |
| 8 | **哈希** | SHA-256 全场景：请求体哈希进签名（含流式 64KiB 缓冲版）、kid 派生（公钥 sha256 前 8 hex）、信封 EtM 完整性（签名覆盖整个密文哈希） | `sha2::Sha256`；`sha256_hex` / `sha256_hex_stream` | lib.rs:57-72、security.md:45、security.md:84 |
| 9 | **随机数（原生）** | `rand::rngs::OsRng`（rand 0.8）：Ed25519 seed、信封 k、每段 nonce、RSA keygen、OPAQUE（rng 以参数注入，`RngCore+CryptoRng`） | lib.rs:23-24、lib.rs:77、lib.rs:180-183、lib.rs:384、opaque.rs:89-92 | 
| 10 | **随机数（wasm32）** | getrandom 无该目标默认后端 → 注册自定义后端桥到 JS 注入熵池（`sr_entropy`），驱动全局 `StdRng`（ChaCha12 CSPRNG）；seal 会话支持确定性 seed 供断点续传重放 | lib.rs:38-42、wasm_shim.rs:22-26 | 
| 11 | **时间窗抗重放** | `\|now − ts\| ≤ 300s`（常量 `SIG_WINDOW_SECS`），绝对值判定；服务端验签前先过窗 | lib.rs:47-48、lib.rs:326-328；SPEC.md:12 |
| 12 | **nonce 抗重放** | per-user nonce 查重：`HashMap<"user:nonce", 过期时刻>`，插入时惰性清理（`retain(exp > now)`），条目寿命=窗口期；服务重启清零（SPEC 明示可接受）。注意：nonce 生成与查重都在**调用方**，common 只回传 `Verified.nonce` | serve.rs:34-36、serve.rs:913-922、lib.rs:289-290；SPEC.md:12 |
| 13 | **名字/标识校验** | project `^[a-zA-Z0-9][a-zA-Z0-9-]{0,30}$`（§11 放宽）+ 保留名 `v2/_api/_bootstrap/_console`；user 等辅助名沿用小写 `^[a-z0-9][a-z0-9-]{0,30}$`；docker tag 规则；随机项目名 `[a-zA-Z0-9]{8}`（OsRng） | `names::*`（手写匹配，无 regex 依赖） | lib.rs:103-173 |
| 14 | **编码惯例** | 签名=base64url 无 pad；OPAQUE 报文/落盘=base64 标准字母表无 pad；kid/nonce/哈希=hex | lib.rs:20-21、opaque.rs:18-19、opaque.rs:8-9 | 
| 15 | **registry 凭据**（外围） | bcrypt cost 10 入 htpasswd（协议层外，但属密钥体系一环） | showroomctl | security.md:139、security.md:157 |

**发现的一处规范-实现偏差（如实记录）**：SPEC.md:8 与 security.md:21 均写 nonce 为
"16 个 hex 字符（8 随机字节）"，但实现 `nonce_hex()` 生成 **16 随机字节 → 32 hex 字符**
（lib.rs:74-79）；`verify_with_hash` 对 nonce 只要求非空（lib.rs:319），不校验长度。
实现比规范更保守（熵翻倍），但抽库时应以实现为准并回改文档，否则两端口径会漂移。

---

## 2. 公共 API 面清单（抽象成库要保住的接缝）

以下为 `showroom-common` 的全部 `pub` 项（showroom-common/src/lib.rs、opaque.rs；wasm_shim
为 wasm32 专属 C-ABI 垫片不列入库接缝）：

### 常量
- `SIG_WINDOW_SECS: i64 = 300`（lib.rs:48）
- `KEY_LEN = 32`、`NONCE_LEN = 12`、`TAG_LEN = 16`、`SEG = 4MiB`、`WRAP_LEN = 384`（lib.rs:51-55，pub 供 wasm 垫片与控制台 JS 长度核算复用）
- `opaque::SERVER_ID: &[u8] = b"showroom-server"`（opaque.rs:42）
- `opaque::RWD_LEN: usize = 32`（opaque.rs:56）
- `names::RESERVED: [&str; 4]`（lib.rs:133）

### 类型
- `Result<T> = std::result::Result<T, Box<dyn Error>>`（lib.rs:45；seal/open 另用 `io::Result`）
- `UserKey(SigningKey)`——Ed25519 用户密钥（lib.rs:177）
- `Verified { user, ts, nonce }`（lib.rs:263-268）
- `AuthError { Format | Stale | BadSignature }`（lib.rs:270-287，impl Display+Error）
- `PlatformKeys(RsaPrivateKey)`——平台 RSA-3072 密钥对（lib.rs:344）
- `opaque::Suite`——CipherSuite 定义（opaque.rs:32-39）
- `opaque::server_types::{Setup, Record}`——服务端句柄别名（opaque.rs:45-49）

### 函数——哈希 / 随机 / 落盘
- `sha256_hex(&[u8]) -> String`、`sha256_hex_stream(impl Read) -> io::Result<String>`（64KiB 缓冲，lib.rs:57-72）
- `nonce_hex() -> String`（lib.rs:75-79）
- `write_private(&Path, &[u8]) -> io::Result<()>`（0600 落盘，仅原生，lib.rs:82-99）

### 函数——SR-SIG1
- `UserKey::generate / from_seed_file / save_seed(仅原生) / pub_string / from_pub_string`（lib.rs:180-218）
- `build_canonical(user, ts, nonce, method, path_with_query, body_sha256_hex) -> String`（lib.rs:222-231）
- `sign(user, &UserKey, method, path_with_query, body, now_unix, nonce) -> String`（lib.rs:235-245）
- `sign_prehashed(...body_sha256_hex...)`——大文件先流式哈希再签（lib.rs:249-261）
- `verify(auth_value, &[VerifyingKey], method, path, body, now) -> Result<Verified, AuthError>`（lib.rs:291-300）
- `verify_with_hash(...body_sha_hex...)`——与 verify 同语义，import 等不留 body 的调用方复用（lib.rs:304-340）

### 函数——信封 v1
- `PlatformKeys::generate / save_pem(仅原生) / load_pem / public_pem`（lib.rs:347-373）
- `seal(&RsaPublicKey, impl Read, impl Write) -> io::Result<u64>`（返回写出总字节，lib.rs:378-412）
- `open(&RsaPrivateKey, impl Read, impl Write) -> io::Result<u64>`（返回明文总字节，lib.rs:416-461）

### 函数——OPAQUE（opaque.rs）
- 客户端：`login_start(rng, pw, user)`、`login_finish(state, pw, user, ke2_b64)`、`reg_start(rng, pw, user)`、`reg_finish(rng, state, pw, user, m2_b64)`（opaque.rs:89-150）
- 服务端：`server_setup_new(rng)`、`server_setup_load(b64)`、`server_reg_start`、`server_reg_canonical`、`server_record_from_b64`、`server_login_start(rng, setup, Option<&Record>, ke1, user)`、`server_login_finish(state_bytes, ke3_b64)`（opaque.rs:156-221）
- 硬化：`rwd(pw, user) -> [u8; 32]`（opaque.rs:60-70）

### 名字校验（names 模块，lib.rs:103-173）
- `valid_project / valid_aux / valid_tag / check_project / check_aux / check_tag / random_project`

### 再导出
- `pub use {ed25519_dalek, rsa}`（lib.rs:32）——下游直接复用 common 锁定的版本，避免另引版本导致类型不兼容。**抽库时这个"版本收口"语义必须保留**。

### 协议层之上的调用方约定（不在 common 内，抽库需一并界定边界）
- nonce 生成/查重、bind_token（60s 单次）都在 serve.rs（serve.rs:34-44、913-951）；
- kid 派生与命中定位（单把复验）在 serve.rs:938-946；
- 压缩管道与魔数解包在调用方（showroom/src/main.rs、dbmaint.rs、unpack.rs）——common 刻意不含 zstd（lib.rs:377 注释）。

---

## 3. 依赖表

来自 showroom-common/Cargo.toml（10-31）与 Cargo.lock 实际锁定版本：

| crate | 声明 | 锁定版本 | 用途 | 备注 |
|---|---|---|---|---|
| `ed25519-dalek` | `2` | 2.2.0 | SR-SIG1 签名/验签 | 被 `pub use` 再导出 |
| `rsa` | `0.9` | 0.9.10 | RSA-3072-OAEP-SHA256 封装、PKCS#8 PEM | 被 `pub use` 再导出；纯 Rust（无 C） |
| `aes-gcm` | `0.10` | 0.10.3 | AES-256-GCM 分段 AEAD | 带 aead/generic_array 再导出 |
| `sha2` | `0.10` | 0.10.9 | SHA-256 | |
| `rand` | `0.8` | 0.8.8 | OsRng / StdRng / Alphanumeric | 0.8 系（非 0.9），抽库时注意 API 代差 |
| `base64` | `0.22` | 0.22.1（树内另有 0.23.1 属其他依赖） | 签名/OPAQUE 编码 | Engine API |
| `hex` | `0.4` | 0.4.3 | nonce/kid/哈希输出 | |
| `opaque-ke` | `3`, default-features=false, features=["ristretto255-voprf"] | 3.0.0 | OPAQUE AKE | 关 default 免 getrandom"js"（wasm 约束） |
| `argon2` | `0.5`, default-features=false, features=["alloc"] | 0.5.3 | rwd 口令硬化 | 纯 Rust 可交叉 wasm32；仅用 `hash_password_into` |
| `curve25519-dalek` | （传递） | 4.1.3 | ristretto255 群运算 | workspace 对其单列 -O3 |
| `getrandom` | `0.2` features=["custom"]，**仅 wasm32 目标** | 0.2.17 | 自定义熵后端桥 | Cargo.toml:28-30 |
| `zstd` | `0.13`，**仅 wasm32 目标**（common 内） | 0.13.3 | 浏览器压缩会话（sr_zstd_*） | 原生解压消费方在 showroomctl/showroom 各自依赖 |

调用方补充：showroomctl 另原生依赖 `zstd`（解包）与 `flate2`（gzip 降级路径，unpack.rs:40）。
workspace Cargo.toml 对 rsa/num-bigint-dig/curve25519-dalek/opaque-ke/argon2/aes/aes-gcm/ctr/
ghash/polyval/sha2/zstd 逐包钉 `opt-level=3`（Cargo.toml:27-61），并 `[profile.test] opt-level=1`
（注释实测：8MiB aes-gcm 在 -O0 下 0.61s vs -O1 0.013s，46×）——**这些性能归因对抽库后的
基准测试设置有直接参考价值**。

---

## 4. 流式分段细节

### 4.1 加密信封的字节布局与分段循环

```
[384B RSA-OAEP-SHA256(k)] || 每段{ [12B 随机 nonce][AES-256-GCM 密文 ‖ 16B tag] }，段=4MiB 明文
总长度不变量：384 + n + ceil(n/4MiB) × (12+16)   （n=压缩后明文字节数）
```
（布局：lib.rs:376、security.md:54-71；不变量测试断言：lib.rs:578）

`seal`（lib.rs:378-412）流式语义：
- 每次调用生成一次性 32B k（OsRng），RSA-OAEP 封装后**校验定长 384B**再写头（lib.rs:388-393）；
- 单分配 4MiB 缓冲，`read_full` 循环（管道短读安全，lib.rs:464-473）填满一段→新随机 nonce→
  encrypt→写 nonce+密文（lib.rs:398-411）；**末段可短于 4MiB**（n>0 即成段）；
- 空输入合法：仅 384B 头，对应 0 字节明文（lib.rs:414-415）；
- 返回写出总字节数（含头）。

`open`（lib.rs:416-461）流式语义：
- `BufReader::with_capacity(SEG+NONCE_LEN+TAG_LEN)`（≈4MiB+28，lib.rs:421）——内存恒定约
  "两个 SEG 缓冲"量级（seal 一个、open 两个）；
- 头不足 384B / unwrap 后非 32B / nonce 截断 / 段 < tag 长 / tag 校验失败 → 全部 io::Error
  （不 panic，lib.rs:423-457）；
- 段边界上的干净 EOF 收尾（读到 0 字节 nonce 即结束，lib.rs:441-442）；
- **截断容错的固有边界**：解密逐段进行，`out` 是流式写入，前段已写出后段失败时不回滚
  （调用方以整个信封的 SR-SIG1 哈希做先验完整性，security.md:84——EtM：先验签后解密）。

每段独立随机 nonce + 一次性随机密钥：无计数器/无 AAD/无段序号。安全性依赖"信封一次性"
（同一 k 从不复用，security.md:133），抽库时若要支持密钥复用需改造为 deterministic
nonce 或密钥派生。

### 4.2 传输层分段（信封之上）

- **上行分片导入（§8.1/§8.3）**：信封原始字节切片按 **8MB/片** 顺序追加
  （`POST /_api/import-chunk`，每片独立 SR-SIG1、哈希覆盖该片；seq 连续 + total 强制，
  SPEC.md:88-95、SPEC.md:102）；wasm 侧 `sr_seal_begin_seed` 用确定性 seed 重放已传分片
  （同 seed+同 push 序列 ⇒ 逐字节相同信封，wasm_shim.rs:24-26）。
- **下行 db-dump 三段式（§10.4）**：服务端 `pg_dump -Z0 -Fc → zstd-19 → seal` 流式写
  `_tmp/<id>.bin`（内存恒定 ~4MiB；明文 >256MB → E_QUOTA，dbmaint.rs:243-272、SPEC.md:143）；
  客户端按 **≤4MB chunk**（`DUMP_CHUNK_MAX = 4<<20`，dbmaint.rs:155）循环拉取，读完最后一片
  服务端即删会话（SPEC.md:144）。
- **ndjson 实时下行（streams.rs）**：`GET /_api/logs-stream`（docker logs -f 桥接）与
  `GET /_api/events`（docker events 过滤 start/stop/die/health_status）；每行一个 JSON
  `{"t":unix_ms,"l":...}` / `{"t","e","actor"}`；30s 心跳 `{"hb":true}` 防代理断连
  （streams.rs:28、67-70）；客户端断开→发送失败→kill_wait 子进程收尸（streams.rs:105-129）；
  stdout+stderr 双流合并、非 UTF-8 日志 lossy 转换（streams.rs:116）。

### 4.3 压缩流的自适应解包

解密产物三种形态按前 4 字节魔数一次性路由：zstd 帧 `28 B5 2F FD`（浏览器逐 push 独立帧
拼接流 / CLI zstd / 服务端 zstd-19）、gzip `1F 8B 08`（浏览器降级）、裸流（docker save tar、
pg_dump -Fc "PGDMP"）直通（unpack.rs:1-30、36-42）。不足 4B 的残流 flush 直通交下游报错。
zstd 帧边界=push 边界、输出仅由 (level, 输入) 决定（无随机性）→ 断点续传重放逐字节一致
（wasm_shim.rs:28-34）。

---

## 5. 密钥文件与生命周期

服务端根：`/srv/showroom`（state 布局 SPEC.md:49-62）；客户端根：`~/.showroom`。

| 密钥/凭据 | 文件 | 格式与权限 | 生成 | 生命周期 / 轮换 | 证据 |
|---|---|---|---|---|---|
| 发布者 Ed25519 私钥 | 客户端 `~/.showroom/id_ed25519` | 裸 32B seed，0600 | `UserKey::generate`（OsRng seed）→ `save_seed`（write_private 0600，覆盖时收紧旧权限） | 轮换=`keygen --force`+重新登记；控制台登录则由密码绑定自动生成/复用（localStorage，P1 试验档） | lib.rs:180-200、lib.rs:83-99、security.md:44、SPEC.md:101 |
| 发布者公钥（多把） | 服务端 `state/tokens/<user>/<kid>.pub` | ed25519 公钥串 `ed25519:<b64>`，kid=公钥 sha256 前 8 hex | user-add / OPAQUE key-bind | `key-rm` 单把吊销；验签对名下全部公钥试签，命中 kid 记身份（whoami/admin 判定） | security.md:45-46、serve.rs:932-946、SPEC.md:55 |
| 管理员标记 | `state/tokens/<user>/<kid>.admin` | 空文件存在即管理员 | 管理员授权 / user-add --admin | key-admin 收权；标记在钥匙不在账号 | security.md:94-95、serve.rs:956-962 |
| 密码绑定标记 | `state/tokens/<user>/<kid>.bound` | 空文件=密码绑定钥匙 | OPAQUE login → bind_token(60s 单次) → key-bind（SR-SIG1 按 body 内**候选**公钥验签） | keep-N GC：按 .pub mtime 保最近 `BOUND_KEYS_MAX`（默认 5）把；无 .bound 的 CI 公钥不受 GC；logout --purge → key-selfrm（只能删自己） | SPEC.md:247-249、SPEC.md:257-269、serve.rs:43-44、serve.rs:862-895 | 
| 平台 RSA-3072 对 | 服务端 `state/platform_rsa`（PKCS#8 PEM 0600）+ `platform_rsa.pub`；公钥分发到客户端 `~/.showroom/platform_rsa.pub` | PKCS#8 PEM；save_pem 私钥 0600、公钥常规写 | `PlatformKeys::generate`（RSA-3072）/ `init-keys`；serve 启动缺失自动生成 | 轮换=删文件+init-keys+重新分发公钥（切断历史信封可解性）；泄露处置见 threat#10 | lib.rs:347-359、serve.rs:113-115、security.md:155、SPEC.md:23 |
| 一次性 RSA-3072（下行 dump） | 客户端进程内，**不落盘** | 进程内生成，公钥 PEM 上行 | 每次 dump 天然轮换 | 备份端到端加密：平台生成信封后自身无法解密 | security.md:78-80、security.md:156、wasm_shim.rs:17-20 |
| 服务端 OPRF key | `state/opaque.key` | b64，0600 | `server_setup_new`；serve 启动缺失自动生成（同 platform_rsa 模式） | 常驻（轮换会使全部 pass.opaque 失效——抽库时需明确此耦合） | SPEC.md:245、serve.rs:117-120、ops.rs:568-575 |
| OPAQUE 注册记录 | `state/users/<u>/pass.opaque` | b64，0600（写入前经 `server_reg_canonical` 规范化） | pw-begin/pw-commit（登录态改密）或管理员 passwd-set | 原子替换；user-revoke 连 users 目录整删 | SPEC.md:246、serve.rs:312-314、ops.rs:595、opaque.rs:178-182 |
| registry 凭据 | `state/users/<u>/reg.cred`（0600 明文）+ htpasswd（bcrypt cost 10） | basic_auth | user-add / 登录后 `/_api/reg-cred` 下发 | user-revoke 同步失效；与登录密码**分开发放**（论证见 plan-16 §1.3） | security.md:139、security.md:157、SPEC.md:248-249 |
| 展项 DB 凭据 | `state/projects/<project>.env`（0600） | 键值 env（DB_PASSWORD 随机） | publish 首建注入 | db reset 重发（密码不变） | security.md:158、SPEC.md:57-58 |

内存态密钥材料（随进程，不入表）：信封一次性 k（seal/open 期间）；OPAQUE 在途登录态
（ke2/ke3 间，服务重启丢失可接受，SPEC.md:275）；bind_token（60s 单次，serve.rs:43-44）；
nonce 查重表（重启清零可接受，SPEC.md:12）。

---

## 6. 抽象成独立库的注意点（基于以上事实）

1. **接缝清晰**：lib.rs 的 SR-SIG1+信封与 opaque.rs 的 OPAQUE 互相零依赖，可拆两 crate
   或一 crate 两 feature；`names` 与协议无关可留可去。
2. **刻意留给调用方的四件事**：nonce 查重、bind_token、压缩管道（common 不含 zstd，
   lib.rs:377）、kid 派生——抽库时要么补进库要么在文档钉死为调用方契约。
3. **跨 wasm 的三条硬约束**已解决且值得原样带走：getrandom custom 后端桥、opaque-ke
   关 default features、argon2 纯 Rust（Cargo.toml:18-29 注释）。
4. **同栈互操作策略**：两端同 crate 同 Suite 定义 + rwd 固定向量测试防漂移
   （opaque.rs:5-6、294-297）——库化后向量测试就是跨版本兼容的守门员。
5. 已知边界（如实声明）：明文 HTTP 首登无信任锚，主动 MITM 可中继 login-finish 并登记
   自己的公钥（SPEC.md:285-286）；UnknownUser 假记录在响应长度/时序上有统计残差
   （SPEC.md:287-288）；wasm localStorage 存 seed 属 P1 试验档（security.md:144）。
