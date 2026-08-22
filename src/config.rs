//! 配置读写与游戏路径解析

use anyhow::{Context, Result};
use log::debug;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Config {
    /// 崩铁安装路径（包含 exe 的目录）
    pub game_path: Option<PathBuf>,
}

impl Config {
    /// 从 TOML 文件加载配置
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("读取配置文件失败: {}", path.display()))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| format!("解析配置文件失败: {}", path.display()))?;
        Ok(config)
    }

    /// 保存配置到 TOML 文件
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self).context("序列化配置失败")?;
        std::fs::write(path, content)
            .with_context(|| format!("写入配置文件失败: {}", path.display()))?;
        Ok(())
    }

    /// 查找默认配置文件路径（当前工作目录下的 hksr-mobile.toml）
    pub fn default_path() -> PathBuf {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("hksr-mobile.toml")
    }
}

/// 从注册表获取崩铁游戏路径（CN 服优先，其次 Global 服）
///
/// 注册表键格式：`HKEY_CURRENT_USER\Software\{vendor}\HYP\1_<n>\{game_key}`
/// 版本号 `1_<n>` 在 1_0..1_9 范围内逐一尝试
pub fn find_game_path_from_registry() -> Option<PathBuf> {
    const REGIONS: &[(&str, &str)] = &[
        ("miHoYo", "hkrpg_cn"),          // 国服
        ("Cognosphere", "hkrpg_global"), // 国际服
    ];

    for &(vendor, game_key) in REGIONS {
        if let Some(path) = find_in_region(vendor, game_key) {
            return Some(path);
        }
    }
    None
}

/// 在指定厂商/分区的注册表基路径下遍历版本号查找游戏路径
fn find_in_region(vendor: &str, game_key: &str) -> Option<PathBuf> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    for rev in 0..10 {
        let subkey = format!("Software\\{}\\HYP\\1_{}\\{}", vendor, rev, game_key);
        let Ok(key) = hkcu.open_subkey(&subkey) else {
            continue; // 该版本号键不存在，尝试下一个
        };
        let Ok(install_dir) = key.get_value::<String, _>("GameInstallPath") else {
            continue;
        };
        let install_dir = PathBuf::from(install_dir.trim_end_matches('\0'));
        let game_path = install_dir.join("StarRail.exe");
        if game_path.exists() {
            debug!("注册表命中: {}", subkey);
            return Some(game_path);
        }
    }
    None
}
