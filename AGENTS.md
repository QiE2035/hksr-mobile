# AGENTS.md

Windows 版崩坏：星穹铁道 MobileUI 启动器（Rust）。原理：以挂起状态创建游戏进程 → 注入 GameAssembly.dll → 在 il2cpp 节中 pattern scan 定位地址 → 写入值 `2`（启用 MobileUI）→ 恢复主线程。注入写入发生在游戏代码启动之前。本项目没有自动化测试，验证方式为编译 + 对真实游戏运行。

## 构建（Windows，仅 x64）

```powershell
cargo build            # Debug
cargo build --release  # Release
cargo run -- --game-path "E:\...\StarRail.exe"
```

运行时需管理员权限（`CreateProcessW` 注入）。游戏必须由本工具启动，不能手动启动后附加。

## 架构

- `src/main.rs` — 入口流程：解析 CLI → 加载配置 → 解析游戏路径（CLI > 配置文件 > 注册表）→ 创建挂起进程 → 注入 DLL → 读 PE 头 → 找 il2cpp 节 → pattern scan 写值 → 恢复线程；`ProcessGuard`（RAII）在出错时自动 TerminateProcess 清理挂起进程
- `src/cli.rs` — clap 参数：`--game-path` / `--config`（注意：`--game-path` 命中后会自动回写配置文件）
- `src/config.rs` — TOML 配置读写；注册表回退查找 `HKEY_CURRENT_USER\Software\miHoYo\HYP\1_?\hkrpg_cn\GameInstallPath`（CN 优先）与 `Software\Cognosphere\HYP\1_?\hkrpg_global`（Global）
- `src/inject.rs` — AOB pattern scan（`??` 通配符，memchr 加速首字节，见 `scan_pattern`）；`enable_mobile_ui` 按 pattern 数组顺序匹配并写入值 2
- `src/pe.rs` — 手写 PE 头解析（仅取节名/RVA/VirtualSize，同时支持 PE32/PE32+）
- `src/win.rs` — windows-sys 封装：挂起创建进程、读写远程内存、resume；`inject_dll` 用 iced-x86 生成远程 shellcode 走 LdrLoadDll，并从 ntdll 动态解析 NtCreateThreadEx 的 syscall 号生成本地 syscall 桩（绕用户态 hook）

## 沿用约定与踩坑记录

1. **游戏版本更新 = pattern 失效**：AOB 签名随游戏二进制变化，"所有 UI pattern 均未匹配"时优先检查/更新 `inject.rs` 的 `patterns` 数组（顺序最新→最旧；`offset` 指向 `C7 05` 后的 rel32 位置，改动需与 RIP 相对寻址计算联动，当前 target = base + rva + pos + 4）
2. **windows-sys 是 feature 门控**：win.rs/main.rs 用到某个 Win32 API 时，必须同步向 Cargo.toml 的 `windows-sys` features 追加对应 feature（如 `Win32_System_Threading`），否则编译报 unresolved import
3. **`hksr-mobile.toml` 被 .gitignore**：它是本地配置（含本机游戏路径），不应提交；配置不存在时用默认值，程序会自动创建
4. **Rust 依赖一律通过 `cargo add` 添加**，禁止手写 Cargo.toml 的 `[dependencies]`
5. **风格**：源码注释与运行输出用中文；输出约定 `[*]` 进行中 / `[+]` 成功 / `[!]` 警告 / `[DEBUG]` 调试；edition 2024
6. **修改 PE/注入逻辑后必须真机验证**：内存写入、shellcode 偏移等改动无法用常规测试覆盖，潜在 bug 表现为"游戏闪退"或"MobileUI 未生效"
