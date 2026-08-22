use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "hksr-mobile", about = "崩坏：星穹铁道 MobileUI 启动器")]
pub struct Args {
    /// 直接指定游戏 exe 路径（可选，缺省从配置/注册表获取）
    #[arg(short, long)]
    pub game_path: Option<PathBuf>,

    /// 指定配置文件路径（可选，缺省与 exe 同目录）
    #[arg(short, long)]
    pub config: Option<PathBuf>,
}
