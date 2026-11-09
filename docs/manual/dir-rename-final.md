# Directory-rename closing steps (ChmlVPN → FlockVPN)

When the project was renamed Flock VPN on 2026-11-02, the repository directory could not be
renamed directly because a development session held it open; the transitional arrangement:

- the real directory remains `E:\Works\ChmlVPN`;
- `E:\Works\FlockVPN` is a **junction** pointing at it (the two paths are equivalent on the host;
  **junctions are not visible inside Docker mounts**, so container commands must use the real
  path `/mnt/Works/ChmlVPN`);
- the patch path in `E:\Works\.cargo\config.toml` and the container gate commands in the showroom
  migration doc therefore temporarily use the `ChmlVPN` path.

**After closing the sessions/programs occupying the directory, run the following steps to finish**
(cmd):

```bat
rmdir E:\Works\FlockVPN                 :: removes only the junction; the real directory is untouched
ren  E:\Works\ChmlVPN FlockVPN          :: renames the real directory
```

Then replace the string `ChmlVPN` → `FlockVPN` in two places:

1. `E:\Works\.cargo\config.toml`: `path = "ChmlVPN/crates/flock-protocol"` and the comment;
2. `E:\Works\showroom\docs\flock-protocol-migration.md`: the `/mnt/Works/ChmlVPN` and
   `../ChmlVPN` mentions in the container gate commands.

Verification (either passing is enough):

```sh
cd /e/Works/FlockVPN && cargo test --workspace --all-features
MSYS_NO_PATHCONV=1 docker run --rm -v "E:\Works:/mnt/Works" -e CARGO_TARGET_DIR=/mnt/Works/FlockVPN/.tmp/sr-target -w /mnt/Works/FlockVPN rust:1-bookworm cargo test --manifest-path ../showroom/Cargo.toml --workspace
```
