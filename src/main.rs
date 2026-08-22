mod cli;
mod config;
mod inject;
mod pe;
mod win;

use anyhow::{Context, Result, bail};
use clap::Parser;
use std::path::PathBuf;

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        // 错误退出时清理挂起的进程由 run() 内部的 guard 处理
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = cli::Args::parse();

    // 1. 加载配置
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(config::Config::default_path);
    let mut cfg = config::Config::load(&config_path)
        .with_context(|| format!("加载配置失败: {}", config_path.display()))?;

    // 2. 解析游戏路径：CLI > 配置文件 > 注册表
    let game_path = resolve_game_path(&args, &mut cfg, &config_path)?;

    println!("[*] 游戏路径: {}", game_path.display());

    // 3. 创建挂起的进程（失败时自动清理）
    println!("[*] 启动游戏进程（挂起）...");
    let (process, _thread, pid) = win::create_process_suspended(&game_path)?;
    let mut _guard = ProcessGuard::new(process.0);
    println!("[+] 进程已创建 (PID: {})", pid);

    // 4. 在挂起的进程中注入 GameAssembly.dll（CreateRemoteThread + LoadLibraryW）
    //    这样注入完成后主线程尚未执行，写入发生在 game 代码启动之前
    let game_dir = game_path.parent().context("无法获取游戏目录")?;
    let ga_dll_path = game_dir.join("GameAssembly.dll");
    println!("[*] 注入 {}...", ga_dll_path.display());
    let ga_base = win::inject_dll(process.0, ga_dll_path.to_str().context("路径无效")?)?;
    println!("[+] GameAssembly.dll 基地址: 0x{:X}", ga_base);

    // 5. 解析 PE 头
    println!("[*] 解析 PE 头...");
    let pe_header = win::read_process_memory(process.0, ga_base, 0x1000)?;
    let pe = pe::parse(&pe_header)?;
    println!(
        "[+] SizeOfImage: 0x{:X}, {} 个节区",
        pe.size_of_image,
        pe.sections.len()
    );

    // 6. 读取完整镜像
    let pe_full = win::read_process_memory(process.0, ga_base, pe.size_of_image)?;

    // 7. 查找 il2cpp 节
    let il2cpp = pe
        .sections
        .iter()
        .find(|s| s.name_str() == "il2cpp" || s.name_str() == ".il2cpp")
        .context("未找到 il2cpp 节区")?;

    println!("[+] il2cpp 节: {}", il2cpp);

    // 8. 截取 il2cpp 节数据
    let il2cpp_end = il2cpp.rva + il2cpp.virtual_size;
    if il2cpp_end > pe_full.len() {
        bail!("il2cpp 节超出读取范围");
    }
    let il2cpp_data = &pe_full[il2cpp.rva..il2cpp_end];
    println!("[+] 读取 il2cpp 节: {} 字节", il2cpp_data.len());

    // 9. pattern scan + 写入值 2
    inject::enable_mobile_ui(process.0, ga_base, il2cpp.rva as u32, il2cpp_data)?;

    // 10. 恢复主线程
    println!("[*] 恢复游戏进程...");
    win::resume_thread(_thread.0)?;
    _guard.suppress();
    println!("[+] 游戏已启动，MobileUI 已启用！");

    Ok(())
}

/// 解析游戏路径：CLI > 配置 > 注册表
fn resolve_game_path(
    args: &cli::Args,
    cfg: &mut config::Config,
    config_path: &std::path::Path,
) -> Result<PathBuf> {
    // CLI 参数优先
    if let Some(ref p) = args.game_path {
        if p.exists() {
            cfg.game_path = Some(p.clone());
            cfg.save(config_path).ok();
            return Ok(p.clone());
        }
        bail!("指定的游戏路径不存在: {}", p.display());
    }

    // 配置文件
    if let Some(ref p) = cfg.game_path {
        if p.exists() {
            return Ok(p.clone());
        }
        eprintln!("[!] 配置中的路径已失效: {}", p.display());
    }

    // 注册表
    println!("[*] 从注册表查找游戏路径...");
    if let Some(p) = config::find_game_path_from_registry() {
        println!("[+] 注册表找到: {}", p.display());
        cfg.game_path = Some(p.clone());
        cfg.save(config_path).ok();
        return Ok(p);
    }

    bail!("未找到游戏路径，请通过 --game-path 指定")
}

/// 错误时自动终止挂起进程的 guard
struct ProcessGuard {
    handle: windows_sys::Win32::Foundation::HANDLE,
    suppressed: bool,
}

impl ProcessGuard {
    fn new(handle: windows_sys::Win32::Foundation::HANDLE) -> Self {
        Self {
            handle,
            suppressed: false,
        }
    }
    /// 标记为成功，Drop 时不终止进程
    fn suppress(&mut self) {
        self.suppressed = true;
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if !self.suppressed {
            unsafe {
                windows_sys::Win32::System::Threading::TerminateProcess(self.handle, 1);
            }
        }
    }
}
