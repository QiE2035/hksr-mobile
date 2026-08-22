//! 管理员权限检测与自动提权（UAC）
//!
//! 游戏进程须以与启动器相同或更低的权限运行才可被注入；
//! 若游戏以管理员权限启动（或需要更高权限），启动器必须以管理员身份运行。
//! 非管理员时通过 `ShellExecuteExW` + `runas` 以管理员身份重启自身。

use anyhow::{Context, Result, bail};
use log::info;
use windows_sys::Win32::UI::Shell::{
    IsUserAnAdmin, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use crate::win::to_wide_string;

/// 当前进程是否以管理员权限运行
///
/// `IsUserAnAdmin` 返回非零表示调用进程属于管理员组且令牌已提权。
pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

/// 若当前非管理员，则通过 UAC 弹窗以管理员身份重启自身并退出当前进程
///
/// `self_exe` 为当前可执行文件路径；`args` 为原始命令行参数（不含 exe 本身）。
/// 重启时把当前参数原样透传给新实例，失败则返回 Err。
pub fn ensure_admin(self_exe: &str, args: &[String]) -> Result<()> {
    if is_admin() {
        return Ok(());
    }

    info!("检测到未以管理员身份运行，正在通过 UAC 申请提权...");

    // 以 runas verb 启动自身（触发 UAC 弹窗），透传原始参数
    let params = rebuild_command_line(args);
    // 宽字符串须绑定为局部变量，使其存活至 ShellExecuteExW 调用之后（避免悬垂指针）
    let verb = to_wide_string("runas");
    let file = to_wide_string(self_exe);
    let param = params.as_deref().map(to_wide_string);

    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = param
        .as_ref()
        .map(|p| p.as_ptr())
        .unwrap_or(std::ptr::null());
    info.nShow = SW_SHOWNORMAL;

    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok == 0 {
        bail!("UAC 提权失败: {}", std::io::Error::last_os_error());
    }

    // 提权实例已拉起，当前进程退出，避免与提权实例重复执行注入
    info!("已触发 UAC 提权，退出当前未提权进程");
    std::process::exit(0);
}

/// 获取命令行参数（含 `argv[0]` 之外的原始参数部分）
///
/// 使用 `std::env::args_os` 并转换为 UTF-16 字符串以兼容非 Unicode 路径。
pub fn raw_args() -> Vec<String> {
    std::env::args_os()
        .skip(1) // 跳过 exe 路径
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

/// 获取当前可执行文件的完整路径
pub fn current_exe() -> Result<String> {
    std::env::current_exe()
        .with_context(|| "无法获取当前可执行文件路径")?
        .to_str()
        .map(String::from)
        .context("当前可执行文件路径包含无效 Unicode")
}

/// 把参数列表重建为一个符合 `CommandLineToArgvW` 规则的命令行字符串
///
/// 含空格的参数会被包进引号（与 `CreateProcess` 的命令行解析规则一致），
/// 避免 `--game-path "E:\xxx.exe"` 这类带空格路径在提权重启时被拆开。
fn rebuild_command_line(args: &[String]) -> Option<String> {
    if args.is_empty() {
        return None;
    }
    let quoted = args
        .iter()
        .map(|a| {
            if a.is_empty() {
                "\"\"".to_string()
            } else if a.contains(' ') || a.contains('\t') {
                format!("\"{}\"", a.replace('"', "\\\""))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    Some(quoted)
}

#[cfg(test)]
mod tests {
    use super::rebuild_command_line;

    #[test]
    fn plain_args_unchanged() {
        let args = vec!["-v".to_string(), "--game-path".to_string()];
        assert_eq!(rebuild_command_line(&args).unwrap(), "-v --game-path");
    }

    #[test]
    fn spaced_path_gets_quoted() {
        let args = vec![
            "--game-path".to_string(),
            r"E:\Games\崩坏 星穹铁道\StarRail.exe".to_string(),
        ];
        assert_eq!(
            rebuild_command_line(&args).unwrap(),
            "--game-path \"E:\\Games\\崩坏 星穹铁道\\StarRail.exe\""
        );
    }

    #[test]
    fn empty_args_none() {
        assert_eq!(rebuild_command_line(&[]), None);
    }
}
