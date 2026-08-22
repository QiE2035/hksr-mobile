//! Windows 进程 / 内存 / 注入操作封装
//!
//! - 挂起进程创建（RAII，Drop 自动清理）
//! - 远程进程内存读写
//! - DLL 注入：iced-x86 生成 shellcode 执行 `kernel32!LoadLibraryW` 并回写 64 位基址，
//!   由公开 API `CreateRemoteThread` 驱动

use anyhow::{Context, Result, bail};
use log::{debug, info, warn};
use std::ffi::c_void;
use std::path::Path;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, PROCESS_INFORMATION, ResumeThread, STARTUPINFOW,
    TerminateProcess,
};

/// RAII 句柄包装：Drop 时自动 `CloseHandle`
pub struct OwnedHandle(pub HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
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
        let path_wide = to_wide_string(game_path.to_str().context("路径包含无效 Unicode")?);
        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        let ret = unsafe {
            CreateProcessW(
                std::ptr::null(),
                path_wide.as_ptr() as *mut u16,
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
                CREATE_SUSPENDED,
                std::ptr::null_mut(),
                std::ptr::null(),
                &si,
                &mut pi,
            )
        };
        if ret == 0 {
            bail!("CreateProcessW 失败: {}", std::io::Error::last_os_error());
        }

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
            unsafe { TerminateProcess(self.process.0, 1) };
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
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx,
        };
        let ptr = unsafe {
            VirtualAllocEx(
                process,
                std::ptr::null_mut(),
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
        use windows_sys::Win32::System::Memory::{MEM_RELEASE, VirtualFreeEx};
        unsafe { VirtualFreeEx(self.process, self.ptr as *mut _, 0, MEM_RELEASE) };
    }
}

/// 读取目标进程内存
pub fn read_process_memory(process: HANDLE, base_addr: usize, size: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    let mut bytes_read = 0usize;

    let ret = unsafe {
        ReadProcessMemory(
            process,
            base_addr as *const _,
            buf.as_mut_ptr() as *mut _,
            size,
            &mut bytes_read,
        )
    };
    if ret == 0 {
        bail!(
            "ReadProcessMemory 失败 (addr=0x{:X}): {}",
            base_addr,
            std::io::Error::last_os_error()
        );
    }

    buf.truncate(bytes_read);
    Ok(buf)
}

/// 写入目标进程内存
pub fn write_process_memory(process: HANDLE, base_addr: usize, data: &[u8]) -> Result<()> {
    let mut bytes_written = 0usize;

    let ret = unsafe {
        WriteProcessMemory(
            process,
            base_addr as *const _,
            data.as_ptr() as *const _,
            data.len(),
            &mut bytes_written,
        )
    };
    if ret == 0 {
        bail!(
            "WriteProcessMemory 失败 (addr=0x{:X}): {}",
            base_addr,
            std::io::Error::last_os_error()
        );
    }
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
    use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtectEx};
    use windows_sys::Win32::System::Threading::{CreateRemoteThread, WaitForSingleObject};

    write_process_memory(process, code_addr, code)?;

    // 将 shellcode 内存改为可执行
    let mut old_protect = 0u32;
    let ok = unsafe {
        VirtualProtectEx(
            process,
            code_addr as *mut _,
            0x1000,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    };
    if ok == 0 {
        bail!("VirtualProtectEx 失败: {}", std::io::Error::last_os_error());
    }

    // 创建远程线程执行 shellcode（挂起状态仅影响主线程，新线程可正常调度）
    type ThreadStart = unsafe extern "system" fn(*mut c_void) -> u32;
    let remote_fn: ThreadStart = unsafe { std::mem::transmute(code_addr) };
    let mut thread_id = 0u32;
    let thread = unsafe {
        CreateRemoteThread(
            process,
            std::ptr::null_mut(),
            0,
            Some(remote_fn),
            std::ptr::null_mut(),
            0,
            &mut thread_id,
        )
    };
    if thread.is_null() {
        bail!(
            "CreateRemoteThread 失败: {}",
            std::io::Error::last_os_error()
        );
    }
    let thread = OwnedHandle(thread);

    if unsafe { WaitForSingleObject(thread.0, 30000) } != 0 {
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
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    let handle = unsafe { GetModuleHandleW(to_wide_string(module).as_ptr()) };
    if handle.is_null() {
        return None;
    }
    let mut symbol = name.as_bytes().to_vec();
    symbol.push(0); // null 结尾
    unsafe { GetProcAddress(handle, symbol.as_ptr()) }.map(|f| f as usize)
}

/// 将 `&str` 转为 null 结尾的 UTF-16 字节序列（小端）
fn utf16_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(|c| c.to_le_bytes())
        .collect()
}

/// 将 `&str` 转为 null 结尾的 UTF-16 `Vec<u16>`
fn to_wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
