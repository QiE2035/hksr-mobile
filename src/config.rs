use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER,
    KEY_READ, RRF_RT_REG_SZ,
};

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    /// 崩铁安装路径（包含 exe 的目录）
    pub game_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self { game_path: None }
    }
}

impl Config {
    /// 从 TOML 文件加载配置
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("读取配置文件失败: {}", path.display()))?;
        let config: Config =
            toml::from_str(&content).with_context(|| format!("解析配置文件失败: {}", path.display()))?;
        Ok(config)
    }

    /// 保存配置到 TOML 文件
    pub fn save(&self, path: &Path) -> Result<()> {
        let content =
            toml::to_string_pretty(self).context("序列化配置失败")?;
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

/// 从注册表获取崩铁游戏路径
pub fn find_game_path_from_registry() -> Option<PathBuf> {
    let mut cn_base = [0u16; 64];
    let cn_prefix = wide_string("Software\\miHoYo\\HYP\\1_?");
    cn_base[..cn_prefix.len()].copy_from_slice(&cn_prefix);

    let mut global_base = [0u16; 64];
    let global_prefix = wide_string("Software\\Cognosphere\\HYP\\1_?");
    global_base[..global_prefix.len()].copy_from_slice(&global_prefix);

    // 查找 CN 版本号
    let mut cn_found = false;
    for i in 0..10 {
        cn_base[22] = b'0' as u16 + i;
        let mut hkey: HKEY = std::ptr::null_mut();
        let ret = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                cn_base.as_ptr(),
                0,
                KEY_READ,
                &mut hkey,
            )
        };
        if ret == ERROR_SUCCESS {
            unsafe { RegCloseKey(hkey) };
            cn_found = true;
            break;
        }
    }

    // 查找 Global 版本号
    let mut global_found = false;
    for i in 0..10 {
        global_base[27] = b'0' as u16 + i;
        let mut hkey: HKEY = std::ptr::null_mut();
        let ret = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                global_base.as_ptr(),
                0,
                KEY_READ,
                &mut hkey,
            )
        };
        if ret == ERROR_SUCCESS {
            unsafe { RegCloseKey(hkey) };
            global_found = true;
            break;
        }
    }

    if !cn_found && !global_found {
        return None;
    }

    // 优先 CN，其次 Global
    let subkeys = if cn_found {
        vec![(&cn_base[..], "hkrpg_cn")]
    } else {
        vec![(&global_base[..], "hkrpg_global")]
    };

    for (base, subkey) in &subkeys {
        let mut full_key = base.to_vec();
        let subkey_wide = wide_string(subkey);
        // 去掉 base 末尾的 null，拼接 subkey
        let base_len = full_key.iter().position(|&c| c == 0).unwrap_or(full_key.len());
        full_key.truncate(base_len);
        full_key.extend_from_slice(&subkey_wide);
        full_key.push(0);

        let mut hkey: HKEY = std::ptr::null_mut();
        let ret = unsafe {
            RegOpenKeyExW(HKEY_CURRENT_USER, full_key.as_ptr(), 0, KEY_READ, &mut hkey)
        };
        if ret != ERROR_SUCCESS {
            continue;
        }

        // 读取 GameInstallPath
        let mut path_buf = [0u16; 0x8000];
        let mut path_len = (path_buf.len() * 2) as u32;
        let ret = unsafe {
            RegGetValueW(
                hkey,
                std::ptr::null(),
                wide_string("GameInstallPath").as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                path_buf.as_mut_ptr() as *mut _,
                &mut path_len,
            )
        };
        unsafe { RegCloseKey(hkey) };

        if ret != ERROR_SUCCESS {
            continue;
        }

        // 转换为 Rust 字符串
        let u16_slice = &path_buf[..path_len as usize / 2];
        let path_str = String::from_utf16_lossy(u16_slice);
        let path_str = path_str.trim_end_matches('\0');
        let install_dir = PathBuf::from(path_str);

        let game_path = install_dir.join("StarRail.exe");
        if game_path.exists() {
            return Some(game_path);
        }
    }

    None
}

/// 将 &str 转为 null 结尾的 UTF-16 Vec
fn wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
