//! 压缩档位与帧格式（§1.3.3e / §3.7，P0-4、P1-7）。
//!
//! - **默认关闭**（`Mode::Off`）；按策略/按流开启——VORACLE/CRIME/BREACH 前提在 ChmlVPN
//!   成立（FRP 中转即长度观察点，compression-2026 §3.2），开启时配输出填充。
//! - 档位（compression-2026 §0/§2 实测映射）：`<128B` 直通（40B 反膨胀 122.5%、120B 零收益）；
//!   Interactive/Bulk = zstd-1（帧级同 codec；Bulk 的分块/上下文复用属流式层，后续批次）；
//!   Archive = zstd-19 仅归档档；[`Algorithm::Lz4`]（lz4_flex 0.14）作 CPU 受限备选。
//! - **非膨胀回退 MUST**（RFC 3173 §2.2）：试压不缩小即发明文；「连续失败自适应停试」
//!   是有状态策略，属流式层（本帧 API 无状态，如实声明）。
//! - 先压后密顺序不变（RFC 3173 §1）；压缩发生在记录层 payload 内（调用方：先
//!   `compress_frame` 再进 AEAD）。
//! - 填充联动：`PadPolicy::Multiple16` 把帧总长补到 16B 倍数（起步值；可调桶化属上层策略）。
//! - dictID 协商**占位**：帧头留 `dict_id` 槽位（0=无字典）；字典训练/分发/dictID 进握手
//!   扩展属握手层（§3.7 接缝），本批次不接内容。
//!
//! 帧格式（15B 头）：
//!
//! ```text
//! [1B flags][4B dict_id LE][4B orig_len LE][4B payload_len LE][payload …len][pad 0x00…]
//! flags: bit0 = 已压缩；bits1..=2 = 算法（0=zstd, 1=lz4）；bits3..=7 = 保留 0
//! pad  : 帧尾 0x00 填充（payload_len 之外的尾字节必须全 0，读者按此校验）
//! ```

use core::fmt;

/// 直通阈值：明文 < 128B 不试压（compression-2026 §0 实测反膨胀/零收益）。
pub const PASSTHROUGH_MIN: usize = 128;
/// 帧头长度。
pub const FRAME_HEADER_LEN: usize = 13;

/// 帧错误三态：格式非法 / 尾填充非零 / 解压失败（含长度不符）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressError {
    /// 帧头截断/长度越界/保留位非零。
    MalformedFrame(&'static str),
    /// 尾部填充字节非零（帧被篡改或拼接）。
    BadPadding,
    /// 解压失败或 orig_len 不符。
    DecompressFailed,
}

impl fmt::Display for CompressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompressError::MalformedFrame(m) => write!(f, "compress frame: {m}"),
            CompressError::BadPadding => f.write_str("compress frame: non-zero padding bytes"),
            CompressError::DecompressFailed => f.write_str("compress frame: decompress failed"),
        }
    }
}

impl std::error::Error for CompressError {}

/// 压缩档位（§1.3.3e）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// 默认：不压不填，恒直通。
    #[default]
    Off,
    /// 交互流：zstd-1（低延迟；小报文字典档位属握手层占位）。
    Interactive,
    /// 批量流：zstd-1（帧级同 Interactive；分块 16–64KB/flush/上下文复用属流式层）。
    Bulk,
    /// 归档档：zstd-19（仅离线归档；CPU/时延最高）。
    Archive,
}

/// 输出填充（长度观察点缓解；与压缩档联动开启）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PadPolicy {
    /// 不填充（默认；Off 档恒不填）。
    #[default]
    Off,
    /// 帧总长补齐 16B 倍数（起步值；桶化可调属上层）。
    Multiple16,
}

/// 压缩算法（lz4_flex 0.14 = CPU 受限端备选，compression-2026 §0）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    /// zstd 0.14.3（默认）。
    #[default]
    Zstd,
    /// lz4 块压缩（无 zstd 硬件加速/CPU 受限场景）。
    Lz4,
}

/// 字典引用（**dictID 协商占位**）：`dict_id` 进帧头槽位供握手层比对版本一致性；
/// 字典内容训练与分发属握手层（§3.7 接缝），本批次不接压缩路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DictRef {
    /// 0 = 无字典；非 0 = 握手层协商的字典版本 id（仅透传比对）。
    pub dict_id: u32,
}

/// 压缩策略（§1.3.3e 结构 + 填充联动字段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CompressPolicy {
    pub mode: Mode,
    pub padding: PadPolicy,
    pub alg: Algorithm,
    pub dict: DictRef,
}

impl CompressPolicy {
    /// 全直通策略（`Mode::Off`）。
    pub fn off() -> Self {
        Self::default()
    }
}

fn zstd_level(mode: Mode) -> i32 {
    match mode {
        Mode::Archive => 19,
        Mode::Interactive | Mode::Bulk | Mode::Off => 1,
    }
}

fn flags(compressed: bool, alg: Algorithm) -> u8 {
    let c = u8::from(compressed);
    let a = match alg {
        Algorithm::Zstd => 0u8,
        Algorithm::Lz4 => 1u8,
    };
    c | (a << 1)
}

/// 压缩一帧：按策略试压，**试压不缩即发明文**（RFC 3173 §2.2 非膨胀回退 MUST），
/// `Mode::Off` 或明文 < [`PASSTHROUGH_MIN`] 恒直通；填充按 [`PadPolicy`] 追加 0x00。
///
/// 返回完整帧字节（含 13B 头）。同输入同策略输出确定（无随机性）。
pub fn compress_frame(policy: &CompressPolicy, plain: &[u8]) -> Vec<u8> {
    let passthrough = policy.mode == Mode::Off || plain.len() < PASSTHROUGH_MIN;
    let payload: Vec<u8>;
    let compressed: bool;

    if passthrough {
        payload = plain.to_vec();
        compressed = false;
    } else {
        let candidate = match policy.alg {
            Algorithm::Zstd => zstd::bulk::compress(plain, zstd_level(policy.mode))
                .expect("zstd compress: 输入长度上限内恒成功"),
            Algorithm::Lz4 => lz4_flex::block::compress(plain),
        };
        if candidate.len() < plain.len() {
            payload = candidate;
            compressed = true;
        } else {
            // 非膨胀回退：试压未缩小 ⇒ 明文（flags 记 0，解压侧直取）
            payload = plain.to_vec();
            compressed = false;
        }
    }

    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len() + 16);
    frame.push(flags(compressed, policy.alg));
    frame.extend_from_slice(&policy.dict.dict_id.to_le_bytes());
    frame.extend_from_slice(&(plain.len() as u32).to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);

    // 填充联动：Off 模式不填；开启压缩的档位按 16B 倍数补齐帧总长
    if policy.mode != Mode::Off && policy.padding == PadPolicy::Multiple16 {
        while frame.len() % 16 != 0 {
            frame.push(0);
        }
    }
    frame
}

/// 解压一帧（[`compress_frame`] 逆）。校验：头长度/保留位、payload 边界、尾填充全零、
/// 解压产物长度 == orig_len。任何不符返回 [`CompressError`]（不 panic）。
pub fn decompress_frame(frame: &[u8]) -> Result<Vec<u8>, CompressError> {
    if frame.len() < FRAME_HEADER_LEN {
        return Err(CompressError::MalformedFrame("truncated header"));
    }
    let fl = frame[0];
    if fl & 0xF8 != 0 {
        return Err(CompressError::MalformedFrame("reserved flag bits set"));
    }
    let compressed = fl & 1 != 0;
    let alg = match (fl >> 1) & 0b11 {
        0 => Algorithm::Zstd,
        1 => Algorithm::Lz4,
        _ => return Err(CompressError::MalformedFrame("unknown algorithm id")),
    };
    let _dict_id = u32::from_le_bytes(frame[1..5].try_into().expect("13B header"));
    let orig_len = u32::from_le_bytes(frame[5..9].try_into().expect("13B header")) as usize;
    let payload_len = u32::from_le_bytes(frame[9..13].try_into().expect("13B header")) as usize;
    let payload_end = FRAME_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(CompressError::MalformedFrame("payload length overflow"))?;
    if frame.len() < payload_end {
        return Err(CompressError::MalformedFrame("payload truncated"));
    }
    // 尾填充必须全零（payload 之外的所有字节）
    if frame[payload_end..].iter().any(|&b| b != 0) {
        return Err(CompressError::BadPadding);
    }
    let payload = &frame[FRAME_HEADER_LEN..payload_end];

    let out = if compressed {
        match alg {
            Algorithm::Zstd => zstd::bulk::decompress(payload, orig_len)
                .map_err(|_| CompressError::DecompressFailed)?,
            Algorithm::Lz4 => lz4_flex::block::decompress(payload, orig_len)
                .map_err(|_| CompressError::DecompressFailed)?,
        }
    } else {
        payload.to_vec()
    };
    if out.len() != orig_len {
        return Err(CompressError::DecompressFailed);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lorem(n: usize) -> Vec<u8> {
        // 可压缩模式文本（重复句子），模拟真实负载
        let sentence = b"the quick brown fox jumps over the lazy dog; ";
        (0..n).map(|i| sentence[i % sentence.len()]).collect()
    }

    fn policy(mode: Mode) -> CompressPolicy {
        CompressPolicy { mode, ..CompressPolicy::default() }
    }

    // M1 守门：<128B 直通
    #[test]
    fn small_input_passthrough() {
        for mode in [Mode::Interactive, Mode::Bulk, Mode::Archive] {
            for len in [0usize, 1, 40, 127] {
                let plain = lorem(len);
                let frame = compress_frame(&policy(mode), &plain);
                assert_eq!(frame[0] & 1, 0, "mode={mode:?} len={len}: <128B 必须直通");
                let out = decompress_frame(&frame).unwrap();
                assert_eq!(out, plain);
            }
        }
    }

    // M1 守门：试压不缩回退明文（incompressible 输入）
    #[test]
    fn incompressible_falls_back_to_plaintext() {
        // 伪随机字节（确定性 LCG）：zstd/lz4 都压不动
        let mut x = 0x12345678u32;
        let plain: Vec<u8> = (0..64 * 1024)
            .map(|_| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                (x >> 24) as u8
            })
            .collect();
        for alg in [Algorithm::Zstd, Algorithm::Lz4] {
            let p = CompressPolicy { mode: Mode::Bulk, alg, ..CompressPolicy::default() };
            let frame = compress_frame(&p, &plain);
            assert_eq!(frame[0] & 1, 0, "alg={alg:?}: 试压不缩必须回退明文");
            assert_eq!(decompress_frame(&frame).unwrap(), plain);
        }
    }

    // 可压缩输入：各档往返 + 压缩标志
    #[test]
    fn compress_roundtrip_all_modes() {
        let plain = lorem(64 * 1024);
        for mode in [Mode::Interactive, Mode::Bulk, Mode::Archive] {
            for alg in [Algorithm::Zstd, Algorithm::Lz4] {
                let p = CompressPolicy { mode, alg, ..CompressPolicy::default() };
                let frame = compress_frame(&p, &plain);
                assert_eq!(frame[0] & 1, 1, "mode={mode:?} alg={alg:?}: 可压缩输入应压缩");
                assert!(frame.len() < plain.len() + FRAME_HEADER_LEN, "压缩后应小于明文+头");
                let out = decompress_frame(&frame).unwrap();
                assert_eq!(out, plain);
            }
        }
        // Archive(19) 压得比 Interactive(1) 更小或相等（同 zstd codec 单调性抽查）
        let f_i = compress_frame(&policy(Mode::Interactive), &plain);
        let f_a = compress_frame(&policy(Mode::Archive), &plain);
        assert!(f_a.len() <= f_i.len());
    }

    // Off 档：恒直通、不填充
    #[test]
    fn off_mode_never_compresses_or_pads() {
        let plain = lorem(4096);
        let frame = compress_frame(&CompressPolicy {
            mode: Mode::Off,
            padding: PadPolicy::Multiple16,
            ..CompressPolicy::default()
        }, &plain);
        assert_eq!(frame[0], 0);
        assert_eq!(frame.len(), FRAME_HEADER_LEN + plain.len(), "Off 档不填充");
        assert_eq!(decompress_frame(&frame).unwrap(), plain);
    }

    // 填充联动：16B 倍数 + 尾零校验
    #[test]
    fn padding_to_multiple_of_16() {
        let plain = lorem(300); // 300B 可压缩（重复模式）
        for mode in [Mode::Interactive, Mode::Bulk, Mode::Archive] {
            let p = CompressPolicy { mode, padding: PadPolicy::Multiple16, ..CompressPolicy::default() };
            let frame = compress_frame(&p, &plain);
            assert_eq!(frame.len() % 16, 0, "mode={mode:?}: 帧总长 16B 倍数");
            assert_eq!(decompress_frame(&frame).unwrap(), plain);
        }
        // 填充 + 直通回退路径（小输入 + 填充开启）
        let small = lorem(50);
        let p = CompressPolicy { mode: Mode::Interactive, padding: PadPolicy::Multiple16, ..CompressPolicy::default() };
        let frame = compress_frame(&p, &small);
        assert_eq!(frame.len() % 16, 0);
        assert_eq!(decompress_frame(&frame).unwrap(), small);
    }

    // dictID 占位：进帧头、往返保留
    #[test]
    fn dict_id_placeholder_passes_through() {
        let plain = lorem(1024);
        let p = CompressPolicy {
            mode: Mode::Interactive,
            dict: DictRef { dict_id: 0xDEADBEEF },
            ..CompressPolicy::default()
        };
        let frame = compress_frame(&p, &plain);
        assert_eq!(&frame[1..5], &0xDEADBEEF_u32.to_le_bytes(), "dictID 槽位透传（协商占位）");
        assert_eq!(decompress_frame(&frame).unwrap(), plain);
    }

    // 负向量：篡改头/填充/载荷必须报错
    #[test]
    fn malformed_frames_rejected() {
        let plain = lorem(2048);
        let frame = compress_frame(&policy(Mode::Bulk), &plain);

        assert_eq!(
            decompress_frame(&frame[..12]),
            Err(CompressError::MalformedFrame("truncated header"))
        );

        let mut t = frame.clone();
        t[0] |= 0x08; // 保留位
        assert_eq!(
            decompress_frame(&t),
            Err(CompressError::MalformedFrame("reserved flag bits set"))
        );

        // 载荷翻转（解压失败或长度不符）
        let mut t2 = frame.clone();
        let last = t2.len() - 1;
        t2[last] ^= 0x01;
        assert!(matches!(decompress_frame(&t2), Err(CompressError::DecompressFailed)));

        // 填充区写非零
        let p = CompressPolicy { mode: Mode::Interactive, padding: PadPolicy::Multiple16, ..CompressPolicy::default() };
        let padded = compress_frame(&p, &plain);
        let mut t3 = padded.clone();
        let last3 = t3.len() - 1;
        t3[last3] = 0x01;
        assert_eq!(decompress_frame(&t3), Err(CompressError::BadPadding));

        // orig_len 篡改（直通帧）
        let mut t4 = compress_frame(&CompressPolicy::default(), b"plain-frame-bytes!");
        t4[5] ^= 0x01;
        assert!(matches!(decompress_frame(&t4), Err(CompressError::DecompressFailed)));
    }

    // 帧头自描述：payload_len 与 orig_len 语义
    #[test]
    fn header_fields_semantics() {
        let plain = lorem(512);
        let frame = compress_frame(&policy(Mode::Interactive), &plain);
        let orig = u32::from_le_bytes(frame[5..9].try_into().unwrap()) as usize;
        let plen = u32::from_le_bytes(frame[9..13].try_into().unwrap()) as usize;
        assert_eq!(orig, plain.len());
        assert!(plen < orig, "可压缩输入的 payload 应小于原文");
        assert!(frame.len() >= FRAME_HEADER_LEN + plen);
    }
}
