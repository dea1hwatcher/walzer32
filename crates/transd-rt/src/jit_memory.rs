/// JitMemory — platform-aware allocator for executable JIT code pages.
///
/// Lifecycle:
///   1. Allocate a page with RW permissions (mmap / VirtualAlloc)
///   2. Write AArch64 machine code into it
///   3. Commit: switch to R+X and flush I-cache
///   4. Execute via function pointer
///   5. Drop: free the page (munmap / VirtualFree)

#[cfg(unix)]
use std::ptr;

/// Minimum allocation granularity (4 KB on all ARM64 Linux/Android kernels)
pub const PAGE_SIZE: usize = 4096;

fn align_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

// ──────────────────────────────────────────────────────────────────────────────
// Unix / Android path (mmap + mprotect + dc cvau / ic ivau)
// ──────────────────────────────────────────────────────────────────────────────
#[cfg(unix)]
pub struct JitPage {
    ptr: *mut u8,
    capacity: usize,
    write_cursor: usize,
    committed: bool,
}

#[cfg(unix)]
unsafe impl Send for JitPage {}
#[cfg(unix)]
unsafe impl Sync for JitPage {}

#[cfg(unix)]
impl JitPage {
    /// Allocate a RW anonymous page of at least `min_size` bytes.
    pub fn allocate(min_size: usize) -> std::io::Result<Self> {
        use libc::{
            MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE, mmap,
        };
        let cap = align_up(min_size.max(PAGE_SIZE), PAGE_SIZE);
        let ptr = unsafe {
            mmap(
                ptr::null_mut(),
                cap,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            ptr: ptr as *mut u8,
            capacity: cap,
            write_cursor: 0,
            committed: false,
        })
    }

    /// Append raw bytes into the page buffer (must be called before commit).
    pub fn write(&mut self, code: &[u8]) -> std::io::Result<usize> {
        assert!(!self.committed, "JitPage: write after commit");
        let offset = self.write_cursor;
        let end = offset + code.len();
        if end > self.capacity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "JIT page capacity exceeded",
            ));
        }
        unsafe {
            ptr::copy_nonoverlapping(code.as_ptr(), self.ptr.add(offset), code.len());
        }
        self.write_cursor = end;
        Ok(offset)
    }

    /// Flush I-cache for the written region and switch to R+X.
    /// After this call the page must not be written to.
    pub fn commit(&mut self) -> std::io::Result<()> {
        use libc::{PROT_EXEC, PROT_READ, mprotect};
        // Flush I-cache for range [ptr, ptr + write_cursor)
        if self.write_cursor > 0 {
            flush_icache(self.ptr, self.write_cursor);
        }
        let ret =
            unsafe { mprotect(self.ptr as *mut libc::c_void, self.capacity, PROT_READ | PROT_EXEC) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        self.committed = true;
        Ok(())
    }

    /// Return a raw function pointer to the code at `byte_offset`.
    ///
    /// # Safety
    /// The page must be committed and the code at the given offset must be
    /// valid AArch64 instructions with a conforming ABI.
    pub unsafe fn fn_ptr<F: Copy>(&self, byte_offset: usize) -> F {
        assert!(self.committed, "JitPage: fn_ptr called before commit");
        assert!(byte_offset < self.write_cursor);
        let raw = unsafe { self.ptr.add(byte_offset) } as usize;
        // Transmute usize → fn pointer of the caller's function type.
        // This is the canonical unsafe pattern for JIT-generated code.
        unsafe { std::mem::transmute_copy(&raw) }
    }

    pub fn is_committed(&self) -> bool {
        self.committed
    }

    pub fn len(&self) -> usize {
        self.write_cursor
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Return raw pointer to the byte at `offset` within this page.
    /// # Safety: `offset` must be `< write_cursor`.
    pub unsafe fn code_ptr_at(&self, offset: usize) -> *const u8 {
        unsafe { self.ptr.add(offset) }
    }
}

#[cfg(unix)]
impl Drop for JitPage {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                libc::munmap(self.ptr as *mut libc::c_void, self.capacity);
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Windows path (VirtualAlloc PAGE_EXECUTE_READWRITE) — dev-host only
// ──────────────────────────────────────────────────────────────────────────────
#[cfg(windows)]
pub struct JitPage {
    ptr: *mut u8,
    capacity: usize,
    write_cursor: usize,
    committed: bool,
}

#[cfg(windows)]
unsafe impl Send for JitPage {}
#[cfg(windows)]
unsafe impl Sync for JitPage {}

#[cfg(windows)]
impl JitPage {
    pub fn allocate(min_size: usize) -> std::io::Result<Self> {
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc,
        };
        let cap = align_up(min_size.max(4096), 4096);
        let ptr = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                cap,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if ptr.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            ptr: ptr as *mut u8,
            capacity: cap,
            write_cursor: 0,
            committed: false,
        })
    }

    pub fn write(&mut self, code: &[u8]) -> std::io::Result<usize> {
        assert!(!self.committed, "JitPage: write after commit");
        let offset = self.write_cursor;
        let end = offset + code.len();
        if end > self.capacity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "JIT page capacity exceeded",
            ));
        }
        unsafe {
            std::ptr::copy_nonoverlapping(code.as_ptr(), self.ptr.add(offset), code.len());
        }
        self.write_cursor = end;
        Ok(offset)
    }

    /// On Windows (x86-64 dev host) the I-cache flush is handled by the CPU
    /// hardware coherency; mprotect is not needed since we used EXECUTE_READWRITE.
    pub fn commit(&mut self) -> std::io::Result<()> {
        // On x86-64 Windows the CPU handles I-D cache coherence automatically.
        // On an AArch64 Windows host this would require FlushInstructionCache(),
        // but dev-host testing is x86-64 only for now.
        self.committed = true;
        Ok(())
    }

    /// # Safety
    pub unsafe fn fn_ptr<F: Copy>(&self, byte_offset: usize) -> F {
        assert!(self.committed);
        assert!(byte_offset < self.write_cursor);
        let raw = unsafe { self.ptr.add(byte_offset) } as usize;
        unsafe { std::mem::transmute_copy(&raw) }
    }

    pub fn is_committed(&self) -> bool {
        self.committed
    }

    pub fn len(&self) -> usize {
        self.write_cursor
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Return raw pointer to the byte at `offset` within this page.
    /// # Safety: `offset` must be `< write_cursor`.
    pub unsafe fn code_ptr_at(&self, offset: usize) -> *const u8 {
        unsafe { self.ptr.add(offset) }
    }
}

#[cfg(windows)]
impl Drop for JitPage {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            use windows_sys::Win32::System::Memory::{MEM_RELEASE, VirtualFree};
            unsafe {
                VirtualFree(self.ptr as *mut _, 0, MEM_RELEASE);
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// I-Cache flush (AArch64 Linux/Android)
// ──────────────────────────────────────────────────────────────────────────────

/// Flush D-cache and invalidate I-cache for the byte range [ptr, ptr+len).
///
/// This is mandatory after writing JIT code into RW memory and before
/// switching to R+X and executing it on AArch64.
///
/// The sequence is: `dc cvau` → `dsb ish` → `ic ivau` → `dsb ish` → `isb`
/// per the ARM Architecture Reference Manual B2.2.5 (cache maintenance).
#[cfg(all(unix, target_arch = "aarch64"))]
pub fn flush_icache(ptr: *mut u8, len: usize) {
    // Cache line size: read CTR_EL0 bits[19:16] (DminLine) for D-cache,
    // bits[3:0] (IminLine) for I-cache.  Both are typically 64 bytes on
    // modern Cortex-A/X cores.  We conservatively use 64-byte strides.
    const CACHE_LINE: usize = 64;

    let start = ptr as usize;
    let end = start + len;

    // Step 1: DC CVAU — clean D-cache line to Point of Unification (PoU)
    let mut addr = start & !(CACHE_LINE - 1);
    while addr < end {
        unsafe {
            std::arch::asm!(
                "dc cvau, {0}",
                in(reg) addr,
                options(nostack, preserves_flags)
            );
        }
        addr += CACHE_LINE;
    }

    // Step 2: DSB ISH — ensure DC CVAUs are visible to I-cache maintenance
    unsafe {
        std::arch::asm!("dsb ish", options(nostack, preserves_flags));
    }

    // Step 3: IC IVAU — invalidate I-cache line to PoU
    addr = start & !(CACHE_LINE - 1);
    while addr < end {
        unsafe {
            std::arch::asm!(
                "ic ivau, {0}",
                in(reg) addr,
                options(nostack, preserves_flags)
            );
        }
        addr += CACHE_LINE;
    }

    // Step 4: DSB ISH — ensure IC IVAUs are complete
    unsafe {
        std::arch::asm!("dsb ish", options(nostack, preserves_flags));
    }

    // Step 5: ISB — pipeline flush so next fetch sees the new instructions
    unsafe {
        std::arch::asm!("isb", options(nostack, preserves_flags));
    }
}

/// No-op I-cache flush on non-AArch64 Unix hosts (x86-64 dev host).
/// x86-64 maintains I-D cache coherence in hardware; no explicit flush needed.
#[cfg(all(unix, not(target_arch = "aarch64")))]
pub fn flush_icache(_ptr: *mut u8, _len: usize) {
    // x86-64: hardware-coherent caches — no-op intentional
}

/// Stub for Windows build (dev host only; real flush happens via FlushInstructionCache on AArch64 Windows).
#[cfg(windows)]
pub fn flush_icache(_ptr: *mut u8, _len: usize) {}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    /// Verify JitPage can allocate, write, commit, and free without errors.
    /// Actual execution test is AArch64-only (skipped on x86-64 dev host).
    #[test]
    fn test_jit_page_alloc_write_commit() {
        let mut page = JitPage::allocate(PAGE_SIZE).expect("JitPage::allocate failed");
        assert!(page.capacity() >= PAGE_SIZE);

        // Write dummy bytes (NOP sled is 0xD503201F on AArch64, 0x90 on x86-64)
        let nops = [0u8; 16];
        let offset = page.write(&nops).expect("write failed");
        assert_eq!(offset, 0);
        assert_eq!(page.len(), 16);

        page.commit().expect("commit failed");
    }

    /// On AArch64 hosts: write `mov w0, #42; ret` and call it.
    /// On other hosts: skip the call but verify the page is created correctly.
    #[test]
    fn test_jit_executable_page() {
        let mut page = JitPage::allocate(PAGE_SIZE).expect("allocate");

        // AArch64 machine code:
        //   MOV W0, #42  =>  0xD2800540  (movz w0, #42)
        //   RET          =>  0xD65F03C0
        let code: [u8; 8] = [
            0x40, 0x05, 0x80, 0xD2, // movz w0, #42
            0xC0, 0x03, 0x5F, 0xD6, // ret
        ];
        page.write(&code).expect("write");
        page.commit().expect("commit");

        #[cfg(target_arch = "aarch64")]
        {
            type Fn42 = unsafe extern "C" fn() -> u32;
            let f: Fn42 = unsafe { page.fn_ptr(0) };
            let result = unsafe { f() };
            assert_eq!(result, 42, "JIT-executed AArch64 code returned wrong value");
        }

        // On non-AArch64: just verify no crash during alloc/commit/drop
        drop(page);
    }

    #[test]
    fn test_jit_page_overflow_returns_error() {
        let mut page = JitPage::allocate(PAGE_SIZE).expect("allocate");
        let big = vec![0u8; PAGE_SIZE + 1];
        let result = page.write(&big);
        assert!(result.is_err(), "Expected overflow error");
    }

    #[test]
    fn test_flush_icache_noop_on_host() {
        // Should not panic or fault on any platform
        let mut buf = [0u8; 64];
        flush_icache(buf.as_mut_ptr(), buf.len());
    }
}
