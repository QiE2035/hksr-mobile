//! Windows 进程 / 内存 / 注入操作封装
//!
//! - 挂起进程创建（RAII，Drop 自动清理）
//! - 远程进程内存读写
//! - DLL 注入：远程 shellcode 走 `LdrLoadDll`，经 ntdll 动态解析 syscall 号的本地
//!   `NtCreateThreadEx` 桩创建远程线程，绕过用户态 hook

use anyhow::{Context, Result, bail};
use log::{debug, info, warn};
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
/// 流程：解析 ntdll 符号 → 生成 syscall 桩 → 目标进程内准备远程环境 → 创建远程线程执行
/// 调用 `LdrLoadDll` 的 shellcode → 等待完成 → 读取基址
pub fn inject_dll(process: HANDLE, dll_path: &str) -> Result<usize> {
    use windows_sys::Win32::System::Memory::{MEM_RELEASE, VirtualFree};

    // 1. 解析 ntdll 关键符号与 syscall 号
    let ldr_load_dll = ntdll_symbol("LdrLoadDll").context("获取 LdrLoadDll 地址失败")?;
    let nt_create = ntdll_symbol("NtCreateThreadEx").context("获取 NtCreateThreadEx 地址失败")?;
    let syscall_num = resolve_syscall_number(nt_create)?;

    // 验证地址在目标进程中可读，提前诊断注入可行性
    if let Ok(data) = read_process_memory(process, ldr_load_dll, 8) {
        debug!("LdrLoadDll 在目标进程中可读: {:02x?}", data);
    } else {
        bail!("LdrLoadDll 在目标进程中不可读，无法继续");
    }

    // 2. 生成本地 syscall 桩并执行注入
    let stub = build_syscall_stub(syscall_num)?;
    let result = create_and_wait_dll(process, stub, ldr_load_dll, dll_path);
    // 桩仅本次调用使用，无论成败都释放
    unsafe { VirtualFree(stub as *mut _, 0, MEM_RELEASE) };
    result
}

/// 在目标进程内准备远程环境并等待 `LdrLoadDll` 执行完成，返回 DLL 基址
fn create_and_wait_dll(
    process: HANDLE,
    stub: usize,
    ldr_load_dll: usize,
    dll_path: &str,
) -> Result<usize> {
    use iced_x86::code_asm::*;
    use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtectEx};
    use windows_sys::Win32::System::Threading::{GetExitCodeThread, WaitForSingleObject};

    // 远程内存按 RAII 管理，异常路径自动释放
    let shellcode_mem = RemoteAlloc::new(process, 0x1000)?;
    let result_mem = RemoteAlloc::new(process, 0x1000)?;
    let path_mem = RemoteAlloc::new(process, utf16_bytes(dll_path).len())?;
    let uni_mem = RemoteAlloc::new(process, 0x20)?;

    // 路径 UTF-16（含结尾零）与 UNICODE_STRING
    let path_bytes = utf16_bytes(dll_path);
    write_process_memory(process, path_mem.ptr, &path_bytes)?;
    write_process_memory(
        process,
        uni_mem.ptr,
        &build_unicode_string(path_bytes.len(), path_mem.ptr),
    )?;

    // 组装远程 shellcode：call LdrLoadDll(NULL, NULL, &path, &result)
    let mut asm = CodeAssembler::new(64).unwrap();
    asm.sub(rsp, 0x28).unwrap(); // 影子空间 + 栈对齐
    asm.mov(rax, ldr_load_dll as u64).unwrap();
    asm.xor(rcx, rcx).unwrap(); // DllPath = NULL
    asm.xor(rdx, rdx).unwrap(); // DllCharacteristics = NULL
    asm.mov(r8, uni_mem.ptr as u64).unwrap(); // DllName = &UNICODE_STRING
    asm.mov(r9, result_mem.ptr as u64).unwrap(); // DllHandle = 输出指针
    asm.call(rax).unwrap();
    asm.add(rsp, 0x28).unwrap();
    asm.ret().unwrap();
    let code = asm.assemble(0u64).unwrap();
    debug!("远程 shellcode 长度: {}", code.len());

    write_process_memory(process, shellcode_mem.ptr, &code)?;
    // 回读验证（仅诊断，不影响流程）
    if read_process_memory(process, shellcode_mem.ptr, code.len())? != code {
        warn!("写入 shellcode 回读不一致");
    }

    // 将 shellcode 内存改为可执行
    let mut old_protect = 0u32;
    let ok = unsafe {
        VirtualProtectEx(
            process,
            shellcode_mem.ptr as *mut _,
            0x1000,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    };
    if ok == 0 {
        bail!("VirtualProtectEx 失败: {}", std::io::Error::last_os_error());
    }

    // 创建远程线程执行 shellcode
    let thread = create_remote_thread(process, stub, shellcode_mem.ptr)?;
    if unsafe { WaitForSingleObject(thread.0, 30000) } != 0 {
        bail!("等待注入线程超时");
    }
    let mut exit_code = 0u32;
    unsafe { GetExitCodeThread(thread.0, &mut exit_code) };
    debug!("注入线程退出码: 0x{:08X}", exit_code);

    // 读取 DLL 基址
    let result_data = read_process_memory(process, result_mem.ptr, 8)?;
    let base = u64::from_le_bytes(result_data.try_into().unwrap()) as usize;
    if base == 0 {
        bail!(
            "LdrLoadDll 返回 NULL，DLL 加载失败 (exit code: 0x{:08X})",
            exit_code
        );
    }
    info!("DLL 加载基址: 0x{:X}", base);
    Ok(base)
}

/// 通过本地 syscall 桩在目标进程内创建线程执行远程代码
fn create_remote_thread(
    process: HANDLE,
    stub: usize,
    shellcode_addr: usize,
) -> Result<OwnedHandle> {
    type NtCreateThreadExFn = unsafe extern "system" fn(
        *mut HANDLE,
        u32,
        *mut u8,
        HANDLE,
        *const u8,
        *mut u8,
        u32,
        usize,
        usize,
        usize,
        *mut u8,
    ) -> i32;

    let nt_create_thread_ex: NtCreateThreadExFn = unsafe { std::mem::transmute(stub) };
    let mut thread: HANDLE = std::ptr::null_mut();
    let status = unsafe {
        nt_create_thread_ex(
            &mut thread,
            0x1FFFFF,
            std::ptr::null_mut(),
            process,
            std::ptr::with_exposed_provenance::<u8>(shellcode_addr),
            std::ptr::null_mut(),
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
        )
    };
    if status < 0 {
        bail!("NtCreateThreadEx 失败: NTSTATUS 0x{:08X}", status as u32);
    }
    Ok(OwnedHandle(thread))
}

/// 解析 ntdll 导出符号地址（`GetModuleHandleW` + `GetProcAddress`）
fn ntdll_symbol(name: &str) -> Option<usize> {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    let ntdll = unsafe { GetModuleHandleW(to_wide_string("ntdll.dll").as_ptr()) };
    if ntdll.is_null() {
        return None;
    }
    let mut symbol = name.as_bytes().to_vec();
    symbol.push(0); // null 结尾
    unsafe { GetProcAddress(ntdll, symbol.as_ptr()) }.map(|f| f as usize)
}

/// 从 ntdll 函数开头解析 syscall number（扫描 `B8 <imm32>` 即 `mov eax, imm32`）
fn resolve_syscall_number(func: usize) -> Result<u32> {
    let code = unsafe { std::slice::from_raw_parts(func as *const u8, 32) };
    debug!("NtCreateThreadEx 前 32 字节: {:02x?}", code);
    code.windows(5)
        .find(|w| w[0] == 0xB8)
        .map(|w| u32::from_le_bytes([w[1], w[2], w[3], w[4]]))
        .context("无法从 ntdll 解析 NtCreateThreadEx syscall number")
}

/// 生成本地 `NtCreateThreadEx` syscall 桩（`mov eax, num; mov r10, rcx; syscall; ret`）
///
/// 返回可执行代码地址，调用方须在不再使用时 `VirtualFree` 释放
fn build_syscall_stub(syscall_num: u32) -> Result<usize> {
    use iced_x86::code_asm::*;
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc,
    };

    let mut stub = CodeAssembler::new(64).unwrap();
    stub.mov(eax, syscall_num).unwrap();
    stub.mov(r10, rcx).unwrap();
    stub.syscall().unwrap();
    stub.ret().unwrap();
    let code = stub.assemble(0u64).unwrap();

    let mem = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if mem.is_null() {
        bail!("VirtualAlloc 分配 syscall 桩失败");
    }
    unsafe {
        std::ptr::copy_nonoverlapping(code.as_ptr(), mem as *mut u8, code.len());
    }
    Ok(mem as usize)
}

/// 构造 `UNICODE_STRING`（16 字节：Length + MaximumLength + Buffer）
fn build_unicode_string(total_bytes: usize, buffer_addr: usize) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0..2].copy_from_slice(&(total_bytes as u16 - 2).to_le_bytes()); // Length（不含结尾零）
    buf[2..4].copy_from_slice(&(total_bytes as u16).to_le_bytes()); // MaximumLength
    buf[8..16].copy_from_slice(&(buffer_addr as u64).to_le_bytes()); // Buffer
    buf
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
