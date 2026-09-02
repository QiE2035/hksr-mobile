//! Windows 进程 / 内存 / 注入操作封装
//!
//! - 挂起进程创建（RAII，Drop 自动清理）
//! - 远程进程内存读写
//! - DLL 注入：iced-x86 生成 shellcode 执行 `kernel32!LoadLibraryW` 并回写 64 位基址，
//!   由公开 API `CreateRemoteThread` 驱动

use anyhow::{Context, Result, anyhow, bail};
use log::{debug, info, warn};
use std::ffi::c_void;
use std::path::Path;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, CreateRemoteThread, LPTHREAD_START_ROUTINE,
    PROCESS_INFORMATION, ResumeThread, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};
use windows::core::{PCSTR, PCWSTR, PWSTR};

/// RAII 句柄包装：Drop 时自动 `CloseHandle`
pub struct OwnedHandle(pub HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // HANDLE::is_invalid 同时覆盖空指针与 INVALID_HANDLE_VALUE
        if !self.0.is_invalid() {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

/// 以挂起状态启动的受管游戏进程
///
/// Drop 时若调用方未显式 `resume()`，自动终止进程，避免残留挂起的游戏进程
pub struct SuspendedProcess {
    process: OwnedHandle,
    thread: OwnedHandle,
    pid: u32,
    resumed: bool,
}

impl SuspendedProcess {
    /// 以挂起状态（`CREATE_SUSPENDED`）启动游戏进程
    pub fn create(game_path: &Path) -> Result<Self> {
        let mut path_wide = to_wide_string(game_path.to_str().context("路径包含无效 Unicode")?);
        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();

        unsafe {
            CreateProcessW(
                PCWSTR::null(),
                Some(PWSTR(path_wide.as_mut_ptr())),
                None,
                None,
                false,
                CREATE_SUSPENDED,
                None,
                PCWSTR::null(),
                &si,
                &mut pi,
            )
        }
        .map_err(|e| anyhow!("CreateProcessW 失败: {e}"))?;

        Ok(Self {
            process: OwnedHandle(pi.hProcess),
            thread: OwnedHandle(pi.hThread),
            pid: pi.dwProcessId,
            resumed: false,
        })
    }

    /// 进程 PID
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// 进程句柄（供读写内存 / 注入等操作使用）
    pub fn handle(&self) -> HANDLE {
        self.process.0
    }

    /// 恢复主线程继续运行；成功后 Drop 不再终止进程
    pub fn resume(&mut self) -> Result<()> {
        let ret = unsafe { ResumeThread(self.thread.0) };
        if ret == u32::MAX {
            bail!("ResumeThread 失败: {}", std::io::Error::last_os_error());
        }
        self.resumed = true;
        Ok(())
    }
}

impl Drop for SuspendedProcess {
    fn drop(&mut self) {
        if !self.resumed {
            warn!("启动流程中断，终止挂起的游戏进程 (PID: {})", self.pid);
            let _ = unsafe { TerminateProcess(self.process.0, 1) };
        }
    }
}

/// 目标进程内内存分配（RAII）：Drop 时自动 `VirtualFreeEx`
pub struct RemoteAlloc {
    process: HANDLE,
    /// 分配的内存地址
    pub ptr: usize,
}

impl RemoteAlloc {
    /// 在目标进程内分配可读写内存
    pub fn new(process: HANDLE, size: usize) -> Result<Self> {
        use windows::Win32::System::Memory::{
            MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx,
        };
        let ptr = unsafe {
            VirtualAllocEx(
                process,
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if ptr.is_null() {
            bail!("VirtualAllocEx 失败 (size=0x{:X})", size);
        }
        Ok(Self {
            process,
            ptr: ptr as usize,
        })
    }
}

impl Drop for RemoteAlloc {
    fn drop(&mut self) {
        use windows::Win32::System::Memory::{MEM_RELEASE, VirtualFreeEx};
        let _ = unsafe { VirtualFreeEx(self.process, self.ptr as *mut _, 0, MEM_RELEASE) };
    }
}

/// 读取目标进程内存
pub fn read_process_memory(process: HANDLE, base_addr: usize, size: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    let mut bytes_read = 0usize;

    unsafe {
        ReadProcessMemory(
            process,
            base_addr as *const _,
            buf.as_mut_ptr() as *mut _,
            size,
            Some(&mut bytes_read),
        )
    }
    .map_err(|e| anyhow!("ReadProcessMemory 失败 (addr=0x{:X}): {e}", base_addr))?;

    buf.truncate(bytes_read);
    Ok(buf)
}

/// 写入目标进程内存
pub fn write_process_memory(process: HANDLE, base_addr: usize, data: &[u8]) -> Result<()> {
    let mut bytes_written = 0usize;

    unsafe {
        WriteProcessMemory(
            process,
            base_addr as *const _,
            data.as_ptr() as *const _,
            data.len(),
            Some(&mut bytes_written),
        )
    }
    .map_err(|e| anyhow!("WriteProcessMemory 失败 (addr=0x{:X}): {e}", base_addr))?;
    Ok(())
}

/// 将 DLL 注入到（挂起）进程中，返回 DLL 加载基址
///
/// 流程：解析 `LoadLibraryW` 地址 → 远程分配路径/结果/shellcode 缓冲 →
/// 生成注入 shellcode（[`build_inject_shellcode`]）→ 远程执行（[`execute_remote_code`]）→
/// 读取回写的 64 位基址
pub fn inject_dll(process: HANDLE, dll_path: &str) -> Result<usize> {
    // 1. 解析 LoadLibraryW 地址（系统 DLL 在全部进程中基址一致，直接取本机即可）
    let load_library = kernel32_symbol("LoadLibraryW").context("获取 LoadLibraryW 地址失败")?;

    // 2. 远程分配缓冲区：路径（UTF-16 含结尾零）/ 64 位结果 / 可执行 shellcode
    let path_mem = RemoteAlloc::new(process, utf16_bytes(dll_path).len())?;
    let result_mem = RemoteAlloc::new(process, 8)?;
    let code_mem = RemoteAlloc::new(process, 0x1000)?;
    write_process_memory(process, path_mem.ptr, &utf16_bytes(dll_path))?;

    // 3. 生成注入 shellcode 并在目标进程内执行
    let code = build_inject_shellcode(path_mem.ptr, load_library, result_mem.ptr)?;
    execute_remote_code(process, code_mem.ptr, &code)?;

    // 4. 读取 shellcode 回写的 64 位基址（线程退出码仅 32 位，不能由其获取）
    let result = read_process_memory(process, result_mem.ptr, 8)?;
    let base = u64::from_le_bytes(result.try_into().unwrap()) as usize;
    if base == 0 {
        bail!("LoadLibraryW 加载 DLL 失败");
    }
    info!("DLL 加载基址: 0x{:X}", base);
    Ok(base)
}

/// 生成 DLL 注入 shellcode：`call LoadLibraryW(path)`，将 64 位 HMODULE 回写结果缓冲
///
/// 汇编逻辑（由 iced-x86 汇编生成，避免手写机器码）：
/// ```asm
/// sub rsp, 0x28        ; 影子空间 + 栈对齐
/// mov rcx, path        ; LoadLibraryW 参数：路径指针
/// mov rax, LoadLibraryW
/// call rax
/// mov rbx, result
/// mov [rbx], rax       ; 回写 64 位基址
/// add rsp, 0x28
/// ret
/// ```
fn build_inject_shellcode(
    path_addr: usize,
    load_library_addr: usize,
    result_addr: usize,
) -> Result<Vec<u8>> {
    use iced_x86::code_asm::*;

    let mut asm = asm_result(CodeAssembler::new(64))?;
    asm_result(asm.sub(rsp, 0x28))?; // 影子空间 + 栈对齐
    asm_result(asm.mov(rcx, path_addr as u64))?;
    asm_result(asm.mov(rax, load_library_addr as u64))?;
    asm_result(asm.call(rax))?;
    asm_result(asm.mov(rbx, result_addr as u64))?;
    asm_result(asm.mov(qword_ptr(rbx), rax))?; // 回写 64 位基址
    asm_result(asm.add(rsp, 0x28))?;
    asm_result(asm.ret())?;
    let code = asm_result(asm.assemble(0u64))?;
    debug!("远程 shellcode 长度: {}", code.len());
    Ok(code)
}

/// 便捷错误转换：将汇编生成错误包装为 anyhow 错误
fn asm_result<T, E: std::fmt::Display>(e: Result<T, E>) -> Result<T> {
    e.map_err(|err| anyhow::anyhow!("生成 shellcode 失败: {err}"))
}

/// 在目标进程内写入 shellcode 并创建远程线程执行，等待执行完成
fn execute_remote_code(process: HANDLE, code_addr: usize, code: &[u8]) -> Result<()> {
    use windows::Win32::System::Memory::{
        PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtectEx,
    };

    write_process_memory(process, code_addr, code)?;

    // 将 shellcode 内存改为可执行
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtectEx(
            process,
            code_addr as *const _,
            0x1000,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    }
    .map_err(|e| anyhow!("VirtualProtectEx 失败: {e}"))?;

    // 创建远程线程执行 shellcode（挂起状态仅影响主线程，新线程可正常调度）
    type ThreadStart = unsafe extern "system" fn(*mut c_void) -> u32;
    let remote_fn: LPTHREAD_START_ROUTINE =
        Some(unsafe { std::mem::transmute::<usize, ThreadStart>(code_addr) });
    let mut thread_id = 0u32;
    let thread =
        unsafe { CreateRemoteThread(process, None, 0, remote_fn, None, 0, Some(&mut thread_id)) }
            .map_err(|e| anyhow!("CreateRemoteThread 失败: {e}"))?;
    let thread = OwnedHandle(thread);

    if unsafe { WaitForSingleObject(thread.0, 30000) } != WAIT_OBJECT_0 {
        bail!("等待注入线程超时");
    }
    Ok(())
}

/// 解析 kernel32 导出符号地址（`GetModuleHandleW` + `GetProcAddress`）
fn kernel32_symbol(name: &str) -> Option<usize> {
    module_symbol("kernel32.dll", name)
}

/// 解析指定模块导出符号地址
fn module_symbol(module: &str, name: &str) -> Option<usize> {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    let Ok(handle) = (unsafe { GetModuleHandleW(PCWSTR(to_wide_string(module).as_ptr())) }) else {
        return None;
    };
    let mut symbol = name.as_bytes().to_vec();
    symbol.push(0); // null 结尾
    unsafe { GetProcAddress(handle, PCSTR(symbol.as_ptr())) }.map(|f| f as usize)
}

/// 将 `&str` 转为 null 结尾的 UTF-16 字节序列（小端）
fn utf16_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(|c| c.to_le_bytes())
        .collect()
}

/// 将 `&str` 转为 null 结尾的 UTF-16 `Vec<u16>`
pub(crate) fn to_wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
