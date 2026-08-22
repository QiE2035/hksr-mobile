use anyhow::{Context, Result, bail};
use std::path::Path;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, PROCESS_INFORMATION, ResumeThread, STARTUPINFOW,
};

/// RAII 句柄包装
pub struct OwnedHandle(pub HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// 创建挂起的进程
pub fn create_process_suspended(path: &Path) -> Result<(OwnedHandle, OwnedHandle, u32)> {
    let path_wide = to_wide_string(path.to_str().context("路径包含无效 Unicode")?);
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

    Ok((
        OwnedHandle(pi.hProcess),
        OwnedHandle(pi.hThread),
        pi.dwProcessId,
    ))
}

/// 读取远程进程内存
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

/// 写入远程进程内存
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

/// 恢复挂起的线程
pub fn resume_thread(thread: HANDLE) -> Result<()> {
    let ret = unsafe { ResumeThread(thread) };
    if ret == u32::MAX {
        bail!("ResumeThread 失败: {}", std::io::Error::last_os_error());
    }
    Ok(())
}
/// 将 DLL 注入到挂起进程中（使用 LdrLoadDll）
///
/// # 参数
/// - `process`: 目标进程句柄（需具有 PROCESS_CREATE_THREAD、PROCESS_VM_OPERATION、PROCESS_VM_WRITE、PROCESS_VM_READ 等权限）
/// - `dll_path`: 要注入的 DLL 路径（绝对路径）
///
/// # 返回
/// - `Ok(usize)`: 加载的 DLL 基址
/// - `Err`: 错误描述
pub fn inject_dll(process: HANDLE, dll_path: &str) -> Result<usize> {
    use iced_x86::code_asm::*;

    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, VirtualAlloc,
        VirtualAllocEx, VirtualFree, VirtualFreeEx, VirtualProtectEx,
    };
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    // ========== 1. 获取 LdrLoadDll 地址（当前进程） ==========
    let ntdll = unsafe { GetModuleHandleW(to_wide_string("ntdll.dll").as_ptr()) };
    if ntdll.is_null() {
        bail!("获取 ntdll 句柄失败");
    }
    let ldr_load_dll_addr = unsafe { GetProcAddress(ntdll, b"LdrLoadDll\0".as_ptr()) };
    let Some(ldr_load_dll_addr) = ldr_load_dll_addr else {
        bail!("获取 LdrLoadDll 地址失败");
    };
    eprintln!(
        "[DEBUG] LdrLoadDll address: 0x{:016X}",
        ldr_load_dll_addr as usize
    );

    // 验证地址在目标进程中是否可读（可选，但有助于诊断）
    if let Ok(data) = read_process_memory(process, ldr_load_dll_addr as usize, 8) {
        eprintln!("[DEBUG] LdrLoadDll readable in target: {:02x?}", data);
    } else {
        bail!("LdrLoadDll 在目标进程中不可读，无法继续");
    }

    // ========== 2. 从 ntdll 动态解析 NtCreateThreadEx 的 syscall number ==========
    let nt_create_addr = unsafe { GetProcAddress(ntdll, b"NtCreateThreadEx\0".as_ptr()) };
    let Some(nt_create_addr) = nt_create_addr else {
        bail!("获取 NtCreateThreadEx 地址失败");
    };
    let code_bytes = unsafe { std::slice::from_raw_parts(nt_create_addr as *const u8, 32) };
    eprintln!("[DEBUG] NtCreateThreadEx 前32字节: {:02x?}", code_bytes);
    let syscall_num = code_bytes
        .windows(5)
        .find(|w| w[0] == 0xB8)
        .map(|w| u32::from_le_bytes([w[1], w[2], w[3], w[4]]))
        .context("无法从 ntdll 解析 NtCreateThreadEx syscall number")?;
    eprintln!("[DEBUG] NtCreateThreadEx syscall number: {}", syscall_num);

    // ========== 3. 生成本地 syscall 桩（用于 NtCreateThreadEx） ==========
    let mut stub_asm = CodeAssembler::new(64).unwrap();
    stub_asm.mov(eax, syscall_num).unwrap();
    stub_asm.mov(r10, rcx).unwrap();
    stub_asm.syscall().unwrap();
    stub_asm.ret().unwrap();
    let stub_code = stub_asm.assemble(0u64).unwrap();

    let stub_mem = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    } as usize;
    if stub_mem == 0 {
        bail!("VirtualAlloc 分配 syscall 桩失败");
    }
    unsafe {
        std::ptr::copy_nonoverlapping(stub_code.as_ptr(), stub_mem as *mut u8, stub_code.len());
    }

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
    let nt_create_thread_ex: NtCreateThreadExFn = unsafe { std::mem::transmute(stub_mem) };

    // ========== 4. 准备远程内存 ==========
    // 路径 UTF-16 编码（含结尾零）
    let path_utf16: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
    let path_bytes = unsafe {
        std::slice::from_raw_parts(path_utf16.as_ptr() as *const u8, path_utf16.len() * 2)
    };

    // 分配远程内存
    let shellcode_buf = unsafe {
        VirtualAllocEx(
            process,
            std::ptr::null_mut(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    } as usize;
    let result_buf = unsafe {
        VirtualAllocEx(
            process,
            std::ptr::null_mut(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    } as usize;
    let path_buf = unsafe {
        VirtualAllocEx(
            process,
            std::ptr::null_mut(),
            path_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    } as usize;
    // UNICODE_STRING 结构：16 字节（Length + MaximumLength + Buffer）
    let uni_str_buf = unsafe {
        VirtualAllocEx(
            process,
            std::ptr::null_mut(),
            0x20,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    } as usize;
    if shellcode_buf == 0 || result_buf == 0 || path_buf == 0 || uni_str_buf == 0 {
        bail!("VirtualAllocEx 分配失败");
    }

    // 写入路径
    write_process_memory(process, path_buf, path_bytes)?;

    // 路径 UTF-16 编码（含结尾零）
    let path_utf16: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
    let path_bytes = unsafe {
        std::slice::from_raw_parts(path_utf16.as_ptr() as *const u8, path_utf16.len() * 2)
    };
    let total_bytes = path_bytes.len(); // 包含结尾零
    let len_without_null = total_bytes - 2; // 去掉结尾的两个字节（0x00 0x00）
    let len_wchar = len_without_null as u16; // 字节数，不含结尾零

    // 构造 UNICODE_STRING
    let uni_str_bytes: [u8; 16] = {
        let mut buf = [0u8; 16];
        buf[0..2].copy_from_slice(&len_wchar.to_le_bytes()); // Length
        buf[2..4].copy_from_slice(&(total_bytes as u16).to_le_bytes()); // MaximumLength
        buf[8..16].copy_from_slice(&(path_buf as u64).to_le_bytes()); // Buffer
        buf
    };
    write_process_memory(process, uni_str_buf, &uni_str_bytes)?;

    // ========== 5. 生成远程 shellcode（调用 LdrLoadDll） ==========

    let mut remote_asm = CodeAssembler::new(64).unwrap();
    remote_asm.sub(rsp, 0x28).unwrap(); // 影子空间 + 对齐
    remote_asm.mov(rax, ldr_load_dll_addr as u64).unwrap();
    remote_asm.xor(rcx, rcx).unwrap(); // DllPath = NULL
    remote_asm.xor(rdx, rdx).unwrap(); // DllCharacteristics = NULL
    remote_asm.mov(r8, uni_str_buf as u64).unwrap(); // DllName (UNICODE_STRING*)
    remote_asm.mov(r9, result_buf as u64).unwrap(); // DllHandle (输出指针)
    remote_asm.call(rax).unwrap();
    remote_asm.add(rsp, 0x28).unwrap();
    remote_asm.ret().unwrap();

    let remote_shellcode = remote_asm.assemble(0u64).unwrap();
    eprintln!(
        "[DEBUG] Remote shellcode length: {}",
        remote_shellcode.len()
    );

    // 写入 shellcode
    write_process_memory(process, shellcode_buf, &remote_shellcode)?;
    // 回读验证（可选）
    let read_back = read_process_memory(process, shellcode_buf, remote_shellcode.len())?;
    if read_back != remote_shellcode {
        eprintln!("[WARN] 写入 shellcode 回读不一致");
    }

    // 修改 shellcode 内存为可执行
    let mut old_protect = 0u32;
    let prot_result = unsafe {
        VirtualProtectEx(
            process,
            shellcode_buf as *mut _,
            0x1000,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    };
    if prot_result == 0 {
        bail!("VirtualProtectEx 失败: {}", std::io::Error::last_os_error());
    }
    eprintln!(
        "[DEBUG] VirtualProtectEx succeeded, old protect: 0x{:08X}",
        old_protect
    );

    // ========== 6. 通过 syscall 桩调用 NtCreateThreadEx ==========
    let mut hthread: HANDLE = std::ptr::null_mut();
    let status = unsafe {
        nt_create_thread_ex(
            &mut hthread,
            0x1FFFFF,
            std::ptr::null_mut(),
            process,
            std::ptr::with_exposed_provenance::<u8>(shellcode_buf),
            std::ptr::null_mut(),
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
        )
    };
    // 释放本地的 syscall 桩
    unsafe {
        VirtualFree(stub_mem as *mut _, 0, MEM_RELEASE);
    }
    if status < 0 {
        unsafe {
            VirtualFreeEx(process, shellcode_buf as *mut _, 0, MEM_RELEASE);
            VirtualFreeEx(process, result_buf as *mut _, 0, MEM_RELEASE);
            VirtualFreeEx(process, path_buf as *mut _, 0, MEM_RELEASE);
            VirtualFreeEx(process, uni_str_buf as *mut _, 0, MEM_RELEASE);
        }
        bail!("NtCreateThreadEx 失败: NTSTATUS 0x{:08X}", status as u32);
    }
    let _guard = OwnedHandle(hthread);

    // ========== 7. 等待线程完成 ==========
    if unsafe { WaitForSingleObject(hthread, 30000) } != 0 {
        bail!("等待线程超时");
    }

    // 获取线程退出码（仅用于诊断）
    let mut exit_code = 0u32;
    unsafe { windows_sys::Win32::System::Threading::GetExitCodeThread(hthread, &mut exit_code) };
    eprintln!("[DEBUG] 线程退出码: 0x{:08X}", exit_code);

    // ========== 8. 读取 DLL 基址 ==========
    let result_data = read_process_memory(process, result_buf, 8)?;
    let base = u64::from_le_bytes(result_data.try_into().unwrap()) as usize;
    if base == 0 {
        // 可能是 LdrLoadDll 失败，或返回 NULL
        bail!(
            "LdrLoadDll 返回 NULL，DLL 加载失败 (exit code: 0x{:08X})",
            exit_code
        );
    }
    eprintln!("[+] DLL 基地址: 0x{:X}", base);

    // ========== 9. 清理远程内存 ==========
    unsafe {
        VirtualFreeEx(process, shellcode_buf as *mut _, 0, MEM_RELEASE);
        VirtualFreeEx(process, result_buf as *mut _, 0, MEM_RELEASE);
        VirtualFreeEx(process, path_buf as *mut _, 0, MEM_RELEASE);
        VirtualFreeEx(process, uni_str_buf as *mut _, 0, MEM_RELEASE);
    }

    Ok(base)
}
/// 将 &str 转为 null 结尾的 UTF-16 Vec
fn to_wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
