# 崩坏：星穹铁道 MobileUI 启动器（Rust）

Windows 版崩坏：星穹铁道 MobileUI 启动器。以挂起状态创建游戏进程 → 注入 GameAssembly.dll → 在 il2cpp 节中 pattern scan 定位地址 → 写入值 `2`（启用 MobileUI）→ 恢复主线程。注入写入发生在游戏代码启动之前。

本项目的实现思路参考 C++ 版 [Genshin_StarRail_fps_unlocker](https://github.com/winTEuser/Genshin_StarRail_fps_unlocker)（原神/崩铁帧率解锁器），将注入与 pattern scan 思路用 Rust 重新实现，仅保留 MobileUI 启用功能。

## 工作原理

1. 检测与配置路径匹配的游戏进程，若存在（含上次被强杀残留的挂起进程）则询问是否终止
2. `CreateProcessW` 以挂起状态（`CREATE_SUSPENDED`）启动游戏
3. 注入 GameAssembly.dll：iced-x86 生成 shellcode 执行 `kernel32!LoadLibraryW` 并回写 64 位基址，由公开 API `CreateRemoteThread` 驱动（无 syscall 桩、无手写机器码）
4. 解析 PE 头，定位 il2cpp 节
5. 在 il2cpp 节内 pattern scan 定位 MobileUI 开关地址，写入值 `2`
6. 恢复主线程，游戏正常启动且 MobileUI 已启用；出错时自动终止挂起进程清理

## 构建

仅支持 Windows 64 位，需要 Rust 工具链（edition 2024）。

```powershell
cargo build            # Debug
cargo build --release  # Release
```

产物：`target\release\hksr-mobile.exe`

## 版本号约定

- 基础版本在 `Cargo.toml`（当前 `0.1.0`）；本地 `cargo build`（dev）产物即基础版本
- CI 构建自动注入 `0.1.0-ci.<commit 前 7 位>`，产物作为 Actions artifact 保留 30 天
- 推送 `v*` 标签触发 GitHub Release（如 `v0.1.0`），exe 随 Release 页发布

## 使用

游戏必须由本工具启动（不支持手动启动后附加），运行需管理员权限。

```
hksr-mobile.exe --game-path "E:\...\StarRail.exe"
```

- `--game-path`：直接指定游戏 exe 路径（优先级最高，命中后自动回写配置文件）
- `--config`：指定配置文件路径（缺省为当前目录下的 `hksr-mobile.toml`）
- `-v`（`--verbose`）：显示调试日志（shellcode 生成、PE 解析等诊断信息）

游戏路径解析顺序：命令行参数 > 配置文件 > 注册表（CN 服 `miHoYo\HYP`，Global 服 `Cognosphere\HYP`）。

启动前若检测到与配置路径匹配的游戏进程（包括上次被强杀残留的挂起进程），会询问是否全部终止——直接回车 = 终止，输入 `n` = 跳过。

## 注意事项

- 游戏版本更新后 AOB 签名会变化，提示"所有 UI pattern 均未匹配"时需更新 `src/inject.rs` 中的 patterns
- 配置文件 `hksr-mobile.toml`（含本机游戏路径）不参与版本控制
- 本项目仅供学习交流，请勿用于倒卖
