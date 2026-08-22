use anyhow::{bail, Result};
use memchr::memchr;
use windows_sys::Win32::Foundation::HANDLE;

use crate::win;

/// AOB pattern scan：在 data 中搜索支持 `?` 通配符的 pattern
///
/// pattern 格式：`"80 B9 ?? ?? ?? ?? 00"`，`??` 表示任意字节
pub fn scan_pattern(data: &[u8], pattern: &str) -> Option<usize> {
    let bytes = parse_pattern(pattern)?;
    let wildcards = build_wildcard_mask(&bytes);

    let first_fixed = bytes.iter().enumerate().find(|(_, b)| !b.is_wildcard).map(|(i, _)| i)?;
    let first_val = bytes[first_fixed].value;

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

#[derive(Clone, Copy)]
struct Byte {
    value: u8,
    is_wildcard: bool,
}

/// 将 hex 字符串 pattern 解析为字节数组
fn parse_pattern(pattern: &str) -> Option<Vec<Byte>> {
    pattern
        .split_whitespace()
        .map(|token| {
            if token == "??" || token == "?" {
                Some(Byte { value: 0, is_wildcard: true })
            } else {
                let v = u8::from_str_radix(token, 16).ok()?;
                Some(Byte { value: v, is_wildcard: false })
            }
        })
        .collect()
}

/// 构建通配符掩码：wildcards[i] == true 表示 bytes[i] 是通配字节
fn build_wildcard_mask(bytes: &[Byte]) -> Vec<bool> {
    bytes.iter().map(|b| b.is_wildcard).collect()
}

/// 检查 data[offset..] 是否匹配 pattern
fn match_at(data: &[u8], offset: usize, bytes: &[Byte], wildcards: &[bool]) -> bool {
    if offset + bytes.len() > data.len() {
        return false;
    }
    for (i, (b, &wc)) in bytes.iter().zip(wildcards).enumerate() {
        if !wc && data[offset + i] != b.value {
            return false;
        }
    }
    true
}

/// 在目标进程中启用 MobileUI：pattern scan il2cpp 节 -> 写入值 2
pub fn enable_mobile_ui(
    process: HANDLE,
    remote_module_base: usize,
    il2cpp_rva: u32,
    il2cpp_data: &[u8],
) -> Result<()> {
    let patterns = [
        // 最新版本
        ("80 B9 ?? ?? ?? ?? 00 0F 84 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 20 5E C3", 15usize),
        // 较旧版本
        ("80 B9 ?? ?? ?? ?? 00 74 ?? C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 20 5E C3", 11),
        // 更旧版本
        ("75 05 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 28 C3", 9),
    ];

    for (pattern, offset) in &patterns {
        if let Some(match_pos) = scan_pattern(il2cpp_data, pattern) {
            // tar_addr = match_pos + offset（对应 C++ 中 address + offset 的位置）
            let tar_addr_local = match_pos + offset;

            // 读取 i32 RIP 相对偏移（C7 05 后的 rel32）
            if tar_addr_local + 4 > il2cpp_data.len() {
                bail!("pattern 匹配但偏移越界");
            }
            // let rip_offset = i32::from_le_bytes([
            //     il2cpp_data[tar_addr_local],
            //     il2cpp_data[tar_addr_local + 1],
            //     il2cpp_data[tar_addr_local + 2],
            //     il2cpp_data[tar_addr_local + 3],
            // ]);

            // RIP 相对寻址：target = rip + rel32 + 4
            // rip_offset 可能是负数（向前引用），用 i64 避免溢出
            let target_remote = (remote_module_base as i64
                + il2cpp_rva as i64
                + tar_addr_local as i64
                // + rip_offset as i64
                + 4) as usize;

            // 写入值 2（4 字节）
            let value = 2u32.to_le_bytes();
            win::write_process_memory(process, target_remote, &value)?;

            println!(
                "[+] MobileUI 已启用: 写入值 2 到 0x{:X}",
                target_remote
            );
            return Ok(());
        }
    }

    bail!("所有 UI pattern 均未匹配，请检查游戏版本")
}
