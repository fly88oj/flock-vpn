//! Programmatic tray icon (32×32 flock style: a rounded-square base + three
//! "flock formation" forward chevrons).
//!
//! Selection (of the two routes the requirement offered, the latter: **the
//! simplest programmatic RGBA generation, no asset file**):
//! - `tray_icon::Icon::from_rgba` and `ksni::Icon` (ARGB32) both consume
//!   **raw pixels** — PNG is only an interchange format; drawing via the
//!   image crate and storing a PNG into the tree would add (1) a binary-
//!   asset diff/review surface and (2) a PNG decode dependency on the
//!   build/load path; the icon shape itself has just two levels (rounded
//!   base + chevrons), a hand-written SDF coverage (subpixel
//!   antialiasing) is ~twenty lines, and it is **pixel-level assertable**
//!   (transparent corners/opaque center/foreground pixel
//!   count/determinism) — more testable than "what the PNG looks like".

/// Icon edge length (requirement wording "32×32").
pub const ICON_SIZE: u32 = 32;

/// Base color: deep teal (the flock brand's "flock/waters" imagery;
/// legible on both light and dark taskbars).
const BG: [f32; 3] = [15.0 / 255.0, 98.0 / 255.0, 92.0 / 255.0];
/// Foreground: near-white (the flock chevrons).
const FLOCK: [f32; 3] = [235.0 / 255.0, 248.0 / 255.0, 245.0 / 255.0];

/// Rounded-square parameters (center/half-extent/corner radius, in pixels).
const SQUARE: (f32, f32, f32, f32) = (15.5, 15.5, 14.0, 7.0);
/// Flock chevrons: tip / half-width / opening angle (radians). Forward = +x
/// (flying right).
const CHEVRONS: [((f32, f32), f32, f32); 3] = [
    ((21.5, 16.0), 1.7, 0.7), // lead bird (right, slightly low)
    ((15.0, 9.5), 1.3, 0.7),  // follower (upper left)
    ((15.0, 22.5), 1.3, 0.7), // follower (lower left)
];

/// Point-to-segment distance (the AA sampling primitive).
fn seg_dist(px: f32, py: f32, ax: f32, ay: f32, bx: f32, by: f32) -> f32 {
    let abx = bx - ax;
    let aby = by - ay;
    let len2 = abx * abx + aby * aby;
    let t = (((px - ax) * abx + (py - ay) * aby) / len2).clamp(0.0, 1.0);
    let dx = px - (ax + t * abx);
    let dy = py - (ay + t * aby);
    (dx * dx + dy * dy).sqrt()
}

/// Rounded-square coverage (1px edge antialiasing; 0 outside).
fn square_alpha(x: f32, y: f32) -> f32 {
    let (cx, cy, half, r) = SQUARE;
    let qx = (x - cx).abs() - (half - r);
    let qy = (y - cy).abs() - (half - r);
    let dx = qx.max(0.0);
    let dy = qy.max(0.0);
    let sdf = (dx * dx + dy * dy).sqrt() + qx.max(qy).min(0.0) - r;
    (0.5 - sdf).clamp(0.0, 1.0)
}

/// Coverage of one flock chevron: two arm segments opening ±angle backwards
/// from the tip.
fn chevron_alpha(x: f32, y: f32, tip: (f32, f32), half_w: f32, angle: f32) -> f32 {
    let (tx, ty) = tip;
    let len = 5.5_f32;
    let (dx, dy) = (angle.cos(), angle.sin());
    let a = (tx - len * dx, ty - len * dy);
    let b = (tx - len * dx, ty + len * dy);
    let da = seg_dist(x, y, tx, ty, a.0, a.1);
    let db = seg_dist(x, y, tx, ty, b.0, b.1);
    let d = da.min(db);
    (half_w + 0.5 - d).clamp(0.0, 1.0)
}

/// Generate the 32×32 straight (non-premultiplied) RGBA.
pub fn flock_rgba() -> Vec<u8> {
    let mut rgba = Vec::with_capacity((ICON_SIZE * ICON_SIZE * 4) as usize);
    for y in 0..ICON_SIZE {
        for x in 0..ICON_SIZE {
            let (px, py) = (x as f32, y as f32);
            let bg = square_alpha(px, py);
            let fg = CHEVRONS
                .iter()
                .map(|&(tip, hw, ang)| chevron_alpha(px, py, tip, hw, ang))
                .fold(0.0f32, f32::max);
            let mix = |c: usize| ((1.0 - fg) * BG[c] + fg * FLOCK[c]) * 255.0;
            rgba.extend_from_slice(&[mix(0) as u8, mix(1) as u8, mix(2) as u8, (bg * 255.0) as u8]);
        }
    }
    rgba
}

/// RGBA → ksni `Icon`'s ARGB32 (network byte order: A R G B per pixel, each
/// one byte big-endian).
pub fn rgba_to_argb32_network_order(rgba: &[u8]) -> Vec<u8> {
    let (chunks, remainder) = rgba.as_chunks::<4>();
    assert!(remainder.is_empty(), "RGBA length must be a multiple of 4");
    chunks
        .iter()
        .flat_map(|p| [p[3], p[0], p[1], p[2]])
        .collect()
}

// ============================================================================
// Unit tests (pixel invariants: size/transparent corners/opaque
// center/foreground presence/determinism/ARGB reorder)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_size_and_transparent_corners() {
        let rgba = flock_rgba();
        assert_eq!(rgba.len(), (ICON_SIZE * ICON_SIZE * 4) as usize);
        // The four corners lie outside the rounded square ⇒ transparent
        // (alpha < 26/255 ≈ 0.1).
        for (x, y) in [(0u32, 0u32), (31, 0), (0, 31), (31, 31)] {
            let a = rgba[((y * ICON_SIZE + x) * 4 + 3) as usize];
            assert!(
                a < 26,
                "corner ({x},{y}) must be near-transparent, got alpha={a}"
            );
        }
        // Center opaque (base surface covers it).
        let a = rgba[((16 * ICON_SIZE + 16) * 4 + 3) as usize];
        assert!(a > 229, "center must be opaque, got alpha={a}");
    }

    #[test]
    fn icon_has_flock_foreground_pixels() {
        let rgba = flock_rgba();
        // Foreground (near-white flock chevron) pixels: three chevrons ⇒ at
        // least several dozen (half_w≈1.3~1.7, both arms ≈5.5px).
        let fg = rgba
            .as_chunks::<4>()
            .0
            .iter()
            .filter(|p| p[3] > 200 && p[0] > 200 && p[1] > 200 && p[2] > 200)
            .count();
        assert!(fg >= 30, "too few flock foreground pixels: {fg}");
        // But not the full frame (the base color remains) — guards against
        // degradation into a solid white block.
        assert!(fg < 300, "abnormal foreground ratio (painted over?): {fg}");
    }

    #[test]
    fn icon_deterministic_and_argb_reorder() {
        // Determinism: two generations byte-identical (no random/time
        // input).
        assert_eq!(flock_rgba(), flock_rgba());
        // ARGB32 reorder: first pixel A=Rgba[3], R=Rgba[0], …
        let rgba = flock_rgba();
        let argb = rgba_to_argb32_network_order(&rgba);
        assert_eq!(argb.len(), rgba.len());
        assert_eq!(&argb[0..4], &[rgba[3], rgba[0], rgba[1], rgba[2]]);
    }
}
