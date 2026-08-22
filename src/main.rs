//! 崩坏：星穹铁道 MobileUI 启动器
//!
//! 流程：解析 CLI → 加载配置 → 解析游戏路径（CLI > 配置文件 > 注册表）→
//! 创建挂起进程 → 注入 GameAssembly.dll → 定位 il2cpp 节 → pattern scan 写入值 2
//! → 恢复主线程。所有注入写入发生在游戏代码启动之前

mod cli;
mod config;
mod inject;
mod process;
mod win;

use anyhow::{Context, Result, bail};
use clap::Parser;
use log::{error, info, warn};
use std::path::PathBuf;

fn main() {
    let args = cli::Args::parse();
    init_logger(args.verbose);

    if let Err(e) = run(&args) {
        error!("{:#}", e);
        std::process::exit(1);
    }
}

/// 初始化日志：默认 Info 级别，`-v` 开启 Debug（显示 ntdll 解析等诊断信息）
fn init_logger(verbose: bool) {
    env_logger::Builder::new()
        .filter_level(if verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        })
        // goblin 对超出头部范围的可选数据目录（debug/reloc/load config 等）
        // 在宽松模式下会打印容错 WARN，属预期行为，静音以免干扰
        .filter_module("goblin", log::LevelFilter::Error)
        .format_timestamp(None)
        .format_target(false)
        .init();
}

fn run(args: &cli::Args) -> Result<()> {
    // 1. 加载配置
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(config::Config::default_path);
    let mut cfg = config::Config::load(&config_path)
        .with_context(|| format!("加载配置失败: {}", config_path.display()))?;

    // 2. 解析游戏路径：CLI > 配置文件 > 注册表
    let game_path = resolve_game_path(args, &mut cfg, &config_path)?;
    info!("游戏路径: {}", game_path.display());

    // 3. 检测与配置路径匹配的游戏进程并询问是否终止（上次被强杀可能残留挂起进程）
    process::prompt_kill_game_processes(&game_path)?;

    // 4. 创建挂起进程（RAII：出错自动终止，防止残留挂起的游戏进程）
    info!("启动游戏进程（挂起）...");
    let mut process = win::SuspendedProcess::create(&game_path)?;
    info!("进程已创建 (PID: {})", process.pid());
    let handle = process.handle();

    // 4. 注入 GameAssembly.dll（主线程尚未执行，写入发生在游戏代码启动之前）
    let game_dir = game_path.parent().context("无法获取游戏目录")?;
    let ga_dll_path = game_dir.join("GameAssembly.dll");
    info!("注入 {}...", ga_dll_path.display());
    let ga_base = win::inject_dll(handle, ga_dll_path.to_str().context("路径无效")?)?;

    // 5. 解析 PE 头，定位 il2cpp 节
    info!("解析 PE 头...");
    let header = win::read_process_memory(handle, ga_base, 0x1000)?;
    // 只关心 PE 头与节区表：import 目录的数据超出 0x1000 头部范围，关闭其解析
    // （否则 goblin 会按文件偏移读取越界报错）；其余数据目录为可选解析，
    // 宽松模式下解析失败仅告警不中断
    let opts = goblin::pe::options::ParseOptions::default()
        .with_parse_mode(goblin::pe::options::ParseMode::Permissive)
        .with_parse_imports(false);
    let pe = goblin::pe::PE::parse_with_opts(&header, &opts).context("解析 PE 头失败")?;
    let size_of_image = pe
        .header
        .optional_header
        .as_ref()
        .context("PE 头缺少 OptionalHeader")?
        .windows_fields
        .size_of_image as usize;
    info!(
        "SizeOfImage: 0x{:X}, {} 个节区",
        size_of_image,
        pe.sections.len()
    );

    // 6. 读取完整镜像并截取 il2cpp 节数据
    let image = win::read_process_memory(handle, ga_base, size_of_image)?;
    let il2cpp = pe
        .sections
        .iter()
        .find(|s| s.name.starts_with(b"il2cpp") || s.name.starts_with(b".il2cpp"))
        .context("未找到 il2cpp 节区")?;

    let rva = il2cpp.virtual_address as usize;
    let size = il2cpp.virtual_size as usize;
    if rva + size > image.len() {
        bail!("il2cpp 节超出读取范围");
    }
    info!("il2cpp 节: RVA=0x{:X}, size=0x{:X}", rva, size);
    let il2cpp_data = &image[rva..rva + size];

    // 7. pattern scan + 写入值 2（启用 MobileUI）
    inject::enable_mobile_ui(handle, ga_base, rva as u32, il2cpp_data)?;

    // 8. 恢复主线程，游戏正常启动
    info!("恢复游戏进程...");
    process.resume()?;
    info!("游戏已启动，MobileUI 已启用！");
    Ok(())
}

/// 解析游戏路径，优先级：CLI 参数 > 配置文件 > 注册表
///
/// CLI 参数与注册表命中后自动回写配置文件（失败不阻断流程）
fn resolve_game_path(
    args: &cli::Args,
    cfg: &mut config::Config,
    config_path: &std::path::Path,
) -> Result<PathBuf> {
    // CLI 参数优先
    if let Some(p) = &args.game_path {
        if p.exists() {
            cfg.game_path = Some(p.clone());
            cfg.save(config_path).ok();
            return Ok(p.clone());
        }
        bail!("指定的游戏路径不存在: {}", p.display());
    }

    // 配置文件
    if let Some(p) = &cfg.game_path {
        if p.exists() {
            return Ok(p.clone());
        }
        warn!("配置中的路径已失效: {}", p.display());
    }

    // 注册表
    info!("从注册表查找游戏路径...");
    if let Some(p) = config::find_game_path_from_registry() {
        info!("注册表找到: {}", p.display());
        cfg.game_path = Some(p.clone());
        cfg.save(config_path).ok();
        return Ok(p);
    }

    bail!("未找到游戏路径，请通过 --game-path 指定")
}
