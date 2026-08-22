//! 游戏进程检测与终止
//!
//! 用途：解锁器启动前检测已存在的 StarRail 进程并询问是否终止。
//! 覆盖场景：上次运行被强杀（Ctrl+C / taskkill）残留的挂起进程，
//! 以及用户手动打开的游戏实例（终止前需要用户确认）。

use anyhow::{Result, bail};
use log::info;
use std::path::Path;
use windows_sys::Win32::System::ProcessStatus::EnumProcesses;
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, QueryFullProcessImageNameW,
    TerminateProcess,
};

use crate::win::OwnedHandle;

/// 查找当前所有 StarRail.exe 进程的 PID
pub fn find_game_processes() -> Result<Vec<u32>> {
    // 一次性查询全部进程 PID（数组不够时按返回值截断，Windows 下足够容纳）
    let mut pids = vec![0u32; 4096];
    let mut needed = 0u32;
    if unsafe { EnumProcesses(pids.as_mut_ptr(), (pids.len() * 4) as u32, &mut needed) } == 0 {
        bail!("EnumProcesses 失败: {}", std::io::Error::last_os_error());
    }
    pids.truncate(needed as usize / 4);

    let mut found = Vec::new();
    for &pid in &pids {
        if pid != 0 && is_starrail(pid) {
            found.push(pid);
        }
    }
    Ok(found)
}

/// 检测现有游戏进程并询问是否终止全部；确认后逐一终止
///
/// 上次启动被强杀可能残留挂起的游戏进程，阻塞后续正常运行；
/// 正常运行的游戏实例终止前也需要用户确认。直接回车 = 全部终止。
pub fn prompt_kill_game_processes() -> Result<()> {
    use std::io::Write;

    let pids = find_game_processes()?;
    if pids.is_empty() {
        return Ok(());
    }

    let pid_list = pids
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    println!("检测到 {} 个 StarRail 进程 (PID: {})", pids.len(), pid_list);
    print!("是否终止全部 StarRail 进程?[Y/n] ");
    std::io::stdout().flush().ok();

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    let answer = input.trim().to_lowercase();
    if answer.is_empty() || answer.starts_with('y') {
        for pid in &pids {
            if terminate(*pid) {
                info!("已终止残留游戏进程 (PID: {})", pid);
            } else {
                info!("终止失败 (PID: {})", pid);
            }
        }
    }
    Ok(())
}

/// 判断 PID 是否为 StarRail.exe（对比可执行文件名，防御 PID 复用）
fn is_starrail(pid: u32) -> bool {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return false;
    }
    let _guard = OwnedHandle(handle);

    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    if unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len) } == 0 {
        return false;
    }
    let exe_path = String::from_utf16_lossy(&buf[..len as usize]);
    Path::new(&exe_path)
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("StarRail.exe"))
}

/// 强制终止指定 PID 的进程
fn terminate(pid: u32) -> bool {
    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
    if handle.is_null() {
        return false;
    }
    let _guard = OwnedHandle(handle);
    let ok = unsafe { TerminateProcess(handle, 1) };
    ok != 0
}
