# AGENTS.md

Windows 版崩坏：星穹铁道 MobileUI 启动器（Rust）。原理：以挂起状态创建游戏进程 → 注入 GameAssembly.dll → 在 il2cpp 节中 pattern scan 定位地址 → 写入值 `2`（启用 MobileUI）→ 恢复主线程。注入写入发生在游戏代码启动之前。本项目没有自动化测试，验证方式为编译 + 对真实游戏运行。

## 构建（Windows，仅 x64）

```powershell
cargo build            # Debug
cargo build --release  # Release
cargo run -- --game-path "E:\...\StarRail.exe"
```

运行时需管理员权限（`CreateProcessW` 注入），但**不要求**由工具强制提权：`src/admin.rs` 在流程最前检测 `IsUserAnAdmin`，非管理员时用 `ShellExecuteExW` + `runas` 通过 UAC 以管理员身份重启自身（透传原始参数）并退出当前进程。游戏必须由本工具启动，不能手动启动后附加。

## CI 与版本号

- 工作流 `.github/workflows/ci.yml`：推送到 `master` / `dev` / `simplify-inject` 与 PR 触发；`cargo fmt --check` + `cargo clippy --all-targets -- -D warnings` + Debug/Release 双构建
- 构建产物经 upload-artifact 保留 30 天（`hksr-mobile-<版本>-x64`）；推送 `v*` 标签时发布 GitHub Release
- 版本区分：CI 构建 = `<基础版本>-ci.<sha7>`（写入 Cargo.toml 后编译）；本地 dev = 基础版本；release = 标签号（如 `v0.1.0` → `0.1.0`）

## 架构

- `src/main.rs` — 入口流程：初始化日志（env_logger，`-v` 开 Debug）→ 解析 CLI → 管理员提权保障（`admin::ensure_admin`）→ 加载配置 → 解析游戏路径（CLI > 配置文件 > 注册表）→ 检测游戏进程并询问清理 → 创建挂起进程 → 注入 DLL → goblin 解析 PE 头 → 找 il2cpp 节 → pattern scan 写值 → 恢复线程
- `src/admin.rs` — 管理员权限检测与自动提权：`is_admin`（`IsUserAnAdmin`）、`ensure_admin`（非管理员时 `ShellExecuteExW` + `runas` 以管理员身份重启自身并退出）、`rebuild_command_line`（按 `CommandLineToArgvW` 规则重建参数，含空格路径会加引号，避免提权重启时拆坏 `--game-path`）
- `src/cli.rs` — clap 参数：`--game-path` / `--config` / `-v`（注意：`--game-path` 命中后会自动回写配置文件）
- `src/config.rs` — TOML 配置读写（serde + toml）；注册表回退用 **winreg** 查找 `HKEY_CURRENT_USER\Software\miHoYo\HYP\1_?\hkrpg_cn\GameInstallPath`（CN 优先）与 `Software\Cognosphere\HYP\1_?\hkrpg_global`（Global）
- `src/inject.rs` — AOB pattern scan（`??` 通配符，memchr 加速首字节，见 `scan_pattern`）；`AobPattern` 结构体数组 `MOBILE_UI_PATTERNS` 按顺序匹配并写入值 2
- `src/process.rs` — **EnumProcesses** 枚举与配置 `game_path` 匹配的游戏进程；`prompt_kill_game_processes` 启动前交互询问是否全部终止（回车 = 终止，n = 跳过）
- `src/win.rs` — windows crate 封装：`SuspendedProcess`（挂起进程 RAII，未 resume 时 Drop 自动终止）、`RemoteAlloc`（远程内存 RAII）、读写远程内存；`inject_dll` 用 iced-x86 生成 shellcode 执行 `kernel32!LoadLibraryW` 并回写 64 位基址，由公开 API `CreateRemoteThread` 驱动（无 syscall 桩）；shellcode 生成/执行封装在 `build_inject_shellcode` / `execute_remote_code`

## 沿用约定与踩坑记录

1. **游戏版本更新 = pattern 失效**：AOB 签名随游戏二进制变化，"所有 UI pattern 均未匹配"时优先检查/更新 `inject.rs` 的 `MOBILE_UI_PATTERNS`（顺序最新→最旧；`rel32_offset` 指向 `C7 05` 后的 rel32 位置，改动需与 RIP 相对寻址计算联动，当前 target = base + rva + pos + offset + 4）
2. **windows crate 是 feature 门控**：用到某个 Win32 API 时，必须同步向 Cargo.toml 的 `windows` features 追加对应 feature（如 `Win32_System_Threading`），否则编译报 unresolved import；当前保留实际用到的 10 个 feature（Foundation / Security / System_Diagnostics_Debug / LibraryLoader / Memory / ProcessStatus / Registry / Threading / UI_Shell / UI_WindowsAndMessaging）。注意：`CreateProcessW` / `CreateRemoteThread` 的签名引用 `SECURITY_ATTRIBUTES`，除 `Win32_System_Threading` 外还需 `Win32_Security`；`ShellExecuteExW` 与 `SHELLEXECUTEINFOW` 除 `Win32_UI_Shell` 外还需 `Win32_System_Registry`，`SW_SHOWNORMAL` 需要 `Win32_UI_WindowsAndMessaging`；`GetProcAddress` 的 `lpprocname` 是 ANSI 的 `PCSTR`（非 `PCWSTR`）。与 windows-sys 的差异：句柄是新类型 `HANDLE`（`is_invalid()` 同时覆盖 0 与 -1），多数可失败 API 返回 `windows_core::Result`，宽字符串参数用 `PCWSTR`/`PWSTR` 包装
3. **`hksr-mobile.toml` 被 .gitignore**：它是本地配置（含本机游戏路径），不应提交；配置不存在时用默认值，程序会自动创建
4. **Rust 依赖一律通过 `cargo add` 添加**，禁止手写 Cargo.toml 的 `[dependencies]`；PE 解析用 goblin、注册表用 winreg、日志用 log + env_logger、shellcode 用 iced-x86，不重复造轮子
5. **风格**：源码注释与运行输出用中文；输出统一走 `log` crate（info 流程 / warn 警告 / error 错误 / debug 诊断），仅交互询问用 `println!`/`read_line`；edition 2024，`cargo fmt` + `cargo clippy` 保持零警告
6. **修改 PE/注入逻辑后必须真机验证**：内存写入、shellcode 偏移等改动无法用常规测试覆盖，潜在 bug 表现为"游戏闪退"或"MobileUI 未生效"
7. **本机反作弊环境下 Toolhelp 快照 API 会卡死**：`CreateToolhelp32Snapshot`（Process32/Module32 系列）实测数分钟不返回，进程枚举一律用 **EnumProcesses**（psapi）+ `QueryFullProcessImageNameW`；模块基址获取用 shellcode 回写 64 位，不依赖模块枚举
8. **注入方案与分支**：`simplify-inject` 为 iced-x86 shellcode + `CreateRemoteThread`（无 syscall 桩）；master 仍为 ntdll syscall 桩 + LdrLoadDll 旧方案；两方案均已真机验证。`LoadLibraryW` 返回值经线程退出码会截断为 32 位，基址必须 64 位回写
