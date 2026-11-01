# 目录更名收尾步骤（ChmlVPN → FlockVPN）

2026-11-02 项目更名 Flock VPN 时，仓库目录因开发会话占用无法直接改名，过渡方案：

- 真实目录仍为 `E:\Works\ChmlVPN`；
- `E:\Works\FlockVPN` 是指向它的 **junction**（宿主机两路径等价；**Docker 挂载内 junction 不可见**，容器命令必须走 `/mnt/Works/ChmlVPN` 真实路径）；
- `E:\Works\.cargo\config.toml` 的 patch path 与 showroom 迁移文档中的容器门禁命令因此暂用 `ChmlVPN` 路径。

**关闭占用该目录的会话/程序后，执行以下三步完成收尾**（cmd）：

```bat
rmdir E:\Works\FlockVPN                 :: 只删 junction，不动真实目录
ren  E:\Works\ChmlVPN FlockVPN          :: 真实目录改名
```

然后两处字符串替换 `ChmlVPN` → `FlockVPN`：

1. `E:\Works\.cargo\config.toml`：`path = "ChmlVPN/crates/flock-protocol"` 与注释；
2. `E:\Works\showroom\docs\flock-protocol-migration.md`：容器门禁命令中的 `/mnt/Works/ChmlVPN` 与 `../ChmlVPN` 表述。

验证（任一通过即可）：

```sh
cd /e/Works/FlockVPN && cargo test --workspace --all-features
MSYS_NO_PATHCONV=1 docker run --rm -v "E:\Works:/mnt/Works" -e CARGO_TARGET_DIR=/mnt/Works/FlockVPN/.tmp/sr-target -w /mnt/Works/FlockVPN rust:1-bookworm cargo test --manifest-path ../showroom/Cargo.toml --workspace
```
