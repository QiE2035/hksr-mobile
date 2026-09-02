//! AOB 特征码扫描与 MobileUI 启用
//!
//! 特征码随游戏版本变化，版本更新后"所有 pattern 均未匹配"时优先更新 [`MOBILE_UI_PATTERNS`]

use anyhow::{Result, bail};
use log::info;
use memchr::memchr;
use windows::Win32::Foundation::HANDLE;

use crate::win;

/// 启用 MobileUI 时写入目标地址的固定值
const MOBILE_UI_ENABLED: u32 = 2;

/// 单个 AOB 特征码
pub struct AobPattern {
    /// 特征码字节序列（支持 `??` 通配符）
    pub pattern: &'static str,
    /// 匹配位置到 `C7 05 <rel32>` 中 rel32 字节位置的偏移
    pub rel32_offset: usize,
}

/// 各版本特征码，按发布时间从新到旧排列（第一个匹配即生效）
const MOBILE_UI_PATTERNS: &[AobPattern] = &[
    AobPattern {
        pattern: "80 B9 ?? ?? ?? ?? 00 0F 84 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 20 5E C3",
        rel32_offset: 15,
    },
    AobPattern {
        pattern: "80 B9 ?? ?? ?? ?? 00 74 ?? C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 20 5E C3",
        rel32_offset: 11,
    },
    AobPattern {
        pattern: "75 05 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 28 C3",
        rel32_offset: 9,
    },
];

/// 在目标进程 il2cpp 节数据中按特征码匹配并写入值 2，启用 MobileUI
///
/// - `module_base`: GameAssembly.dll 在目标进程中的基地址
/// - `il2cpp_rva`: il2cpp 节相对基地址的 RVA
/// - `il2cpp_data`: 已从目标进程读出的 il2cpp 节数据
pub fn enable_mobile_ui(
    process: HANDLE,
    module_base: usize,
    il2cpp_rva: u32,
    il2cpp_data: &[u8],
) -> Result<()> {
    for aob in MOBILE_UI_PATTERNS {
        let Some(pos) = scan_pattern(il2cpp_data, aob.pattern) else {
            continue; // 该版本特征码不匹配，尝试下一个
        };

        // rel32_pos 指向 `C7 05` 指令后的 rel32 字节位置
        let rel32_pos = pos + aob.rel32_offset;
        if rel32_pos + 4 > il2cpp_data.len() {
            bail!("pattern 命中但 rel32 越界");
        }

        // RIP 相对寻址：目标 = 指令结束位置 + rel32。
        // 既有实现未回读 rel32（历史版本该偏移恒为 0，直接取指令结束地址），保持行为一致
        let target = module_base + il2cpp_rva as usize + rel32_pos + 4;

        let value = MOBILE_UI_ENABLED.to_le_bytes();
        win::write_process_memory(process, target, &value)?;
        info!(
            "MobileUI 已启用: 写入值 {} 到 0x{:X}",
            MOBILE_UI_ENABLED, target
        );
        return Ok(());
    }
    bail!("所有 UI pattern 均未匹配，请检查游戏版本")
}

/// 在 `data` 中搜索支持 `?` 通配符的 AOB 特征码，返回匹配位置
///
/// 特征码格式：`"80 B9 ?? ?? ?? ?? 00"`，`??` 表示任意字节。
/// 用 memchr 加速首字节定位，随后逐字节比对
fn scan_pattern(data: &[u8], pattern: &str) -> Option<usize> {
    let bytes = parse_pattern(pattern)?;
    let wildcards: Vec<bool> = bytes.iter().map(|b| b.is_wildcard).collect();

    // 取第一个固定字节作为扫描锚点
    let first_val = bytes.iter().find(|b| !b.is_wildcard).map(|b| b.value)?;

    let mut pos = 0;
    while pos < data.len() {
        let Some(offset) = memchr(first_val, &data[pos..]) else {
            break;
        };
        let abs = pos + offset;
        if match_at(data, abs, &bytes, &wildcards) {
            return Some(abs);
        }
        pos = abs + 1;
    }
    None
}

/// 特征码字节
#[derive(Clone, Copy)]
struct Byte {
    value: u8,
    is_wildcard: bool,
}

/// 将 hex 字符串特征码解析为字节数组
fn parse_pattern(pattern: &str) -> Option<Vec<Byte>> {
    pattern
        .split_whitespace()
        .map(|token| {
            if token == "??" || token == "?" {
                Some(Byte {
                    value: 0,
                    is_wildcard: true,
                })
            } else {
                let value = u8::from_str_radix(token, 16).ok()?;
                Some(Byte {
                    value,
                    is_wildcard: false,
                })
            }
        })
        .collect()
}

/// 检查 `data[offset..]` 是否完整匹配特征码（通配位置跳过比对）
fn match_at(data: &[u8], offset: usize, bytes: &[Byte], wildcards: &[bool]) -> bool {
    if offset + bytes.len() > data.len() {
        return false;
    }
    bytes
        .iter()
        .zip(wildcards)
        .enumerate()
        .all(|(i, (b, &wc))| wc || data[offset + i] == b.value)
}
