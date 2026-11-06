//! 程序化托盘图标（32×32 flock 风格：圆角方底 + 三只「雁阵」前向箭头）。
//!
//! 选型（需求给的两条路取后者：**最简 RGBA 程序化生成，无资产文件**）：
//! - `tray_icon::Icon::from_rgba` 与 `ksni::Icon`（ARGB32）都吃**原始像素**——PNG 只是
//!   中转格式，走 image crate 绘制再存 PNG 入库徒增 (1) 二进制资产 diff/评审面、
//!   (2) build/load 链路上的 PNG 解码依赖；图标形状本身只有两级（圆角底+箭头），
//!   手写 SDF 覆盖率（亚像素抗锯齿）二十几行即可，且**像素级可断言**（角透明/中心
//!   不透明/前景像素数/确定性），比「PNG 长什么样」更可测。

/// 图标边长（需求措辞「32×32」）。
pub const ICON_SIZE: u32 = 32;

/// 底色：深青（flock 品牌「雁群/水域」意象；托盘深浅色任务栏均可辨）。
const BG: [f32; 3] = [15.0 / 255.0, 98.0 / 255.0, 92.0 / 255.0];
/// 前景：近白（雁形箭头）。
const FLOCK: [f32; 3] = [235.0 / 255.0, 248.0 / 255.0, 245.0 / 255.0];

/// 圆角方形参数（中心/半边长/圆角半径，单位：像素）。
const SQUARE: (f32, f32, f32, f32) = (15.5, 15.5, 14.0, 7.0);
/// 雁形箭头：tip（尖端）/ 半宽 / 张角（弧度）。前向 = +x（朝右飞行）。
const CHEVRONS: [((f32, f32), f32, f32); 3] = [
    ((21.5, 16.0), 1.7, 0.7), // 头雁（居右偏下）
    ((15.0, 9.5), 1.3, 0.7),  // 随雁（左上）
    ((15.0, 22.5), 1.3, 0.7), // 随雁（左下）
];

/// 点到线段距离（AA 采样基元）。
fn seg_dist(px: f32, py: f32, ax: f32, ay: f32, bx: f32, by: f32) -> f32 {
    let abx = bx - ax;
    let aby = by - ay;
    let len2 = abx * abx + aby * aby;
    let t = (((px - ax) * abx + (py - ay) * aby) / len2).clamp(0.0, 1.0);
    let dx = px - (ax + t * abx);
    let dy = py - (ay + t * aby);
    (dx * dx + dy * dy).sqrt()
}

/// 圆角方形覆盖率（1px 边缘抗锯齿；外部 0）。
fn square_alpha(x: f32, y: f32) -> f32 {
    let (cx, cy, half, r) = SQUARE;
    let qx = (x - cx).abs() - (half - r);
    let qy = (y - cy).abs() - (half - r);
    let dx = qx.max(0.0);
    let dy = qy.max(0.0);
    let sdf = (dx * dx + dy * dy).sqrt() + qx.max(qy).min(0.0) - r;
    (0.5 - sdf).clamp(0.0, 1.0)
}

/// 单只雁形箭头覆盖率：两条臂线段自尖端向后张开 ±angle。
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

/// 生成 32×32 straight（非预乘）RGBA。
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

/// RGBA → ksni `Icon` 的 ARGB32（network byte order：A R G B 逐字节大端序）。
pub fn rgba_to_argb32_network_order(rgba: &[u8]) -> Vec<u8> {
    let (chunks, remainder) = rgba.as_chunks::<4>();
    assert!(remainder.is_empty(), "RGBA 长度须为 4 的倍数");
    chunks
        .iter()
        .flat_map(|p| [p[3], p[0], p[1], p[2]])
        .collect()
}

// ============================================================================
// 单元测试（像素不变量：尺寸/角透明/中心不透明/前景存在/确定性/ARGB 换序）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_size_and_transparent_corners() {
        let rgba = flock_rgba();
        assert_eq!(rgba.len(), (ICON_SIZE * ICON_SIZE * 4) as usize);
        // 四角在圆角方形外 ⇒ 透明（alpha < 26/255 ≈ 0.1）。
        for (x, y) in [(0u32, 0u32), (31, 0), (0, 31), (31, 31)] {
            let a = rgba[((y * ICON_SIZE + x) * 4 + 3) as usize];
            assert!(a < 26, "角 ({x},{y}) 须近透明，得 alpha={a}");
        }
        // 中心不透明（底面覆盖）。
        let a = rgba[((16 * ICON_SIZE + 16) * 4 + 3) as usize];
        assert!(a > 229, "中心须不透明，得 alpha={a}");
    }

    #[test]
    fn icon_has_flock_foreground_pixels() {
        let rgba = flock_rgba();
        // 前景（近白雁形）像素：三支箭头 ⇒ 至少数十个（half_w≈1.3~1.7、双臂≈5.5px）。
        let fg = rgba
            .as_chunks::<4>()
            .0
            .iter()
            .filter(|p| p[3] > 200 && p[0] > 200 && p[1] > 200 && p[2] > 200)
            .count();
        assert!(fg >= 30, "雁形前景像素过少：{fg}");
        // 但不满幅（底色仍在）——防「整块白」退化。
        assert!(fg < 300, "前景占比异常（画满？）：{fg}");
    }

    #[test]
    fn icon_deterministic_and_argb_reorder() {
        // 确定性：两次生成逐字节一致（无随机/时间输入）。
        assert_eq!(flock_rgba(), flock_rgba());
        // ARGB32 换序：首像素 A=Rgba[3]、R=Rgba[0]……
        let rgba = flock_rgba();
        let argb = rgba_to_argb32_network_order(&rgba);
        assert_eq!(argb.len(), rgba.len());
        assert_eq!(&argb[0..4], &[rgba[3], rgba[0], rgba[1], rgba[2]]);
    }
}
