use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use byteorder::{ByteOrder, LittleEndian};
use crate::addr::GuestAddr;
use crate::memory::{Memory, MemoryError, PROT_EXEC, PROT_READ, PROT_WRITE};

pub const ARENA_4GB_SIZE: usize = 0x1_0000_0000; // 4 GB (4,294,967,296 bytes)
pub const PAGE_SIZE: usize = 4096;
pub const TOTAL_PAGES: usize = 0x10_0000; // 1,048,576 pages for 4GB
pub const BITMAP_WORDS: usize = TOTAL_PAGES / 64; // 16,384 words = 128KB

#[cfg(windows)]
mod os {
    use std::ffi::c_void;
    pub const MEM_COMMIT: u32 = 0x1000;
    pub const MEM_RESERVE: u32 = 0x2000;
    pub const MEM_DECOMMIT: u32 = 0x4000;
    pub const MEM_RELEASE: u32 = 0x8000;
    pub const PAGE_NOACCESS: u32 = 0x01;
    pub const PAGE_READWRITE: u32 = 0x04;

    unsafe extern "system" {
        pub fn VirtualAlloc(
            lpAddress: *mut c_void,
            dwSize: usize,
            flAllocationType: u32,
            flProtect: u32,
        ) -> *mut c_void;
        pub fn VirtualFree(lpAddress: *mut c_void, dwSize: usize, dwFreeType: u32) -> i32;
        pub fn VirtualProtect(
            lpAddress: *mut c_void,
            dwSize: usize,
            flNewProtect: u32,
            lpflOldProtect: *mut u32,
        ) -> i32;
    }
}

#[cfg(unix)]
mod os {
    use std::ffi::c_void;
    pub const PROT_NONE: i32 = 0;
    pub const PROT_READ: i32 = 1;
    pub const PROT_WRITE: i32 = 2;
    pub const MAP_PRIVATE: i32 = 0x02;
    pub const MAP_ANONYMOUS: i32 = 0x20;

    unsafe extern "C" {
        pub fn mmap(
            addr: *mut c_void,
            length: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> *mut c_void;
        pub fn munmap(addr: *mut c_void, length: usize) -> i32;
        pub fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
    }
}

/// A contiguous 4GB virtual memory arena for zero-overhead 32-bit guest addressing.
///
/// Any guest virtual address `A in [0, 2^32-1]` maps directly to host address `base_ptr + A`
/// with 0 instruction offset calculations, 0 wrapping checks, and 0 boundary branches in JIT hot paths.
pub struct ArenaMemory {
    base_ptr: *mut u8,
    committed_bitmap: Vec<u64>,
    committed_count: usize,
    page_protections: HashMap<u32, u8>,
}

unsafe impl Send for ArenaMemory {}
unsafe impl Sync for ArenaMemory {}

impl ArenaMemory {
    /// Reserves a 4GB contiguous virtual address space
    pub fn new() -> Result<Self, MemoryError> {
        #[cfg(windows)]
        {
            let ptr = unsafe {
                os::VirtualAlloc(
                    std::ptr::null_mut(),
                    ARENA_4GB_SIZE,
                    os::MEM_RESERVE,
                    os::PAGE_NOACCESS,
                )
            };
            if ptr.is_null() {
                return Err(MemoryError::Unmapped(GuestAddr::new(0)));
            }
            Ok(Self {
                base_ptr: ptr as *mut u8,
                committed_bitmap: vec![0u64; BITMAP_WORDS],
                committed_count: 0,
                page_protections: HashMap::new(),
            })
        }

        #[cfg(unix)]
        {
            let ptr = unsafe {
                os::mmap(
                    std::ptr::null_mut(),
                    ARENA_4GB_SIZE,
                    os::PROT_NONE,
                    os::MAP_PRIVATE | os::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if ptr == (-1isize as *mut std::ffi::c_void) || ptr.is_null() {
                return Err(MemoryError::Unmapped(GuestAddr::new(0)));
            }
            Ok(Self {
                base_ptr: ptr as *mut u8,
                committed_bitmap: vec![0u64; BITMAP_WORDS],
                committed_count: 0,
                page_protections: HashMap::new(),
            })
        }
    }

    #[inline(always)]
    fn is_committed_pfn(&self, pfn: u32) -> bool {
        let p = pfn as usize;
        if p < TOTAL_PAGES {
            let word = p >> 6;
            let mask = 1u64 << (p & 63);
            (self.committed_bitmap[word] & mask) != 0
        } else {
            false
        }
    }

    #[inline(always)]
    fn check_access(&self, addr: GuestAddr, len: usize, write: bool) -> Result<(), MemoryError> {
        let start_pfn = addr.as_u32() >> 12;
        let end_addr = addr.as_u32().saturating_add(len.max(1) as u32 - 1);
        let end_pfn = end_addr >> 12;

        for pfn in start_pfn..=end_pfn {
            if !self.is_committed_pfn(pfn) {
                return Err(MemoryError::Unmapped(GuestAddr::new(pfn << 12)));
            }
            if !self.page_protections.is_empty() {
                let prot = self.page_protections.get(&pfn).copied().unwrap_or(0x7);
                if write {
                    if (prot & (PROT_WRITE as u8)) == 0 {
                        return Err(MemoryError::PermissionDenied { addr, write: true });
                    }
                } else {
                    if (prot & (PROT_READ as u8)) == 0 {
                        return Err(MemoryError::PermissionDenied { addr, write: false });
                    }
                }
            }
        }
        Ok(())
    }

    #[inline(always)]
    fn check_committed(&self, addr: GuestAddr, len: usize) -> Result<(), MemoryError> {
        self.check_access(addr, len, false)
    }

    /// Commits physical backing for the guest address range `[addr, addr + len)`
    pub fn commit_range(&mut self, addr: GuestAddr, len: usize) -> Result<(), MemoryError> {
        if len == 0 {
            return Ok(());
        }
        let page_start = (addr.as_u32() & !0xFFF) as usize;
        let page_end = ((addr.as_u32().saturating_add(len as u32 - 1)) | 0xFFF) as usize;
        let commit_len = (page_end - page_start) + 1;

        #[cfg(windows)]
        unsafe {
            let target_ptr = self.base_ptr.add(page_start);
            let res = os::VirtualAlloc(
                target_ptr as *mut _,
                commit_len,
                os::MEM_COMMIT,
                os::PAGE_READWRITE,
            );
            if res.is_null() {
                return Err(MemoryError::Unmapped(addr));
            }
        }

        #[cfg(unix)]
        unsafe {
            let target_ptr = self.base_ptr.add(page_start);
            let res = os::mprotect(
                target_ptr as *mut _,
                commit_len,
                os::PROT_READ | os::PROT_WRITE,
            );
            if res != 0 {
                return Err(MemoryError::Unmapped(addr));
            }
        }

        let start_pfn = (page_start >> 12) as u32;
        let end_pfn = (page_end >> 12) as u32;
        for pfn in start_pfn..=end_pfn {
            let p = pfn as usize;
            if p < TOTAL_PAGES {
                let word = p >> 6;
                let mask = 1u64 << (p & 63);
                if (self.committed_bitmap[word] & mask) == 0 {
                    self.committed_bitmap[word] |= mask;
                    self.committed_count += 1;
                }
            }
        }
        Ok(())
    }

    /// Changes page protection permissions on committed pages (e.g. for write-protecting code pages)
    pub fn mprotect(&mut self, addr: GuestAddr, len: usize, prot: u32) -> Result<(), MemoryError> {
        if len == 0 {
            return Ok(());
        }
        let page_start = (addr.as_u32() & !0xFFF) as usize;
        let page_end = ((addr.as_u32().saturating_add(len.max(1) as u32 - 1)) | 0xFFF) as usize;
        let prot_len = (page_end - page_start) + 1;

        let start_pfn = (page_start >> 12) as u32;
        let end_pfn = (page_end >> 12) as u32;

        for pfn in start_pfn..=end_pfn {
            if !self.is_committed_pfn(pfn) {
                return Err(MemoryError::Unmapped(addr));
            }
        }

        let read = (prot & PROT_READ) != 0;
        let write = (prot & PROT_WRITE) != 0;
        let exec = (prot & PROT_EXEC) != 0;

        #[cfg(windows)]
        unsafe {
            let fl_protect = match (exec, read, write) {
                (true, _, true) => 0x40,      // PAGE_EXECUTE_READWRITE
                (true, true, false) => 0x20, // PAGE_EXECUTE_READ
                (true, false, false) => 0x10,// PAGE_EXECUTE
                (false, true, true) => os::PAGE_READWRITE,
                (false, true, false) => 0x02, // PAGE_READONLY
                (false, false, _) => os::PAGE_NOACCESS,
            };
            let mut old_protect = 0u32;
            let target_ptr = self.base_ptr.add(page_start);
            let res = os::VirtualProtect(target_ptr as *mut _, prot_len, fl_protect, &mut old_protect);
            if res == 0 {
                return Err(MemoryError::Unmapped(addr));
            }
        }

        #[cfg(unix)]
        unsafe {
            let mut unix_prot = os::PROT_NONE;
            if read {
                unix_prot |= os::PROT_READ;
            }
            if write {
                unix_prot |= os::PROT_WRITE;
            }
            if exec {
                unix_prot |= 4; // PROT_EXEC
            }
            let target_ptr = self.base_ptr.add(page_start);
            let res = os::mprotect(target_ptr as *mut _, prot_len, unix_prot);
            if res != 0 {
                return Err(MemoryError::Unmapped(addr));
            }
        }

        for pfn in start_pfn..=end_pfn {
            self.page_protections.insert(pfn, (prot & 0x7) as u8);
        }

        Ok(())
    }

    /// Queries the protection flags for a given guest address
    pub fn get_protection(&self, addr: GuestAddr) -> u32 {
        let pfn = addr.as_u32() >> 12;
        self.page_protections
            .get(&pfn)
            .copied()
            .map(|p| p as u32)
            .unwrap_or(PROT_READ | PROT_WRITE | PROT_EXEC)
    }

    /// Legacy protect_range helper
    pub fn protect_range(&mut self, addr: GuestAddr, len: usize, read: bool, write: bool) -> Result<(), MemoryError> {
        let mut prot = 0;
        if read {
            prot |= PROT_READ;
        }
        if write {
            prot |= PROT_WRITE;
        }
        self.mprotect(addr, len, prot)
    }

    /// Decommits and releases physical backing for the range
    pub fn decommit_range(&mut self, addr: GuestAddr, len: usize) -> Result<(), MemoryError> {
        if len == 0 {
            return Ok(());
        }
        let page_start = (addr.as_u32() & !0xFFF) as usize;
        let page_end = ((addr.as_u32().saturating_add(len as u32 - 1)) | 0xFFF) as usize;
        let decommit_len = (page_end - page_start) + 1;

        #[cfg(windows)]
        unsafe {
            let target_ptr = self.base_ptr.add(page_start);
            let _ = os::VirtualFree(target_ptr as *mut _, decommit_len, os::MEM_DECOMMIT);
        }

        #[cfg(unix)]
        unsafe {
            let target_ptr = self.base_ptr.add(page_start);
            let _ = os::mprotect(target_ptr as *mut _, decommit_len, os::PROT_NONE);
        }

        let start_pfn = (page_start >> 12) as u32;
        let end_pfn = (page_end >> 12) as u32;
        for pfn in start_pfn..=end_pfn {
            let p = pfn as usize;
            if p < TOTAL_PAGES {
                let word = p >> 6;
                let mask = 1u64 << (p & 63);
                if (self.committed_bitmap[word] & mask) != 0 {
                    self.committed_bitmap[word] &= !mask;
                    self.committed_count -= 1;
                }
            }
            self.page_protections.remove(&pfn);
        }
        Ok(())
    }

    pub fn is_page_committed(&self, pfn: u32) -> bool {
        self.is_committed_pfn(pfn)
    }

    pub fn committed_page_count(&self) -> usize {
        self.committed_count
    }
}

impl Drop for ArenaMemory {
    fn drop(&mut self) {
        if !self.base_ptr.is_null() {
            #[cfg(windows)]
            unsafe {
                os::VirtualFree(self.base_ptr as *mut _, 0, os::MEM_RELEASE);
            }

            #[cfg(unix)]
            unsafe {
                os::munmap(self.base_ptr as *mut _, ARENA_4GB_SIZE);
            }
        }
    }
}

impl Memory for ArenaMemory {
    fn read_u8(&self, addr: GuestAddr) -> Result<u8, MemoryError> {
        self.check_committed(addr, 1)?;
        unsafe { Ok(*self.base_ptr.add(addr.as_u32() as usize)) }
    }

    fn read_u16(&self, addr: GuestAddr) -> Result<u16, MemoryError> {
        self.check_committed(addr, 2)?;
        unsafe {
            Ok(LittleEndian::read_u16(std::slice::from_raw_parts(
                self.base_ptr.add(addr.as_u32() as usize),
                2,
            )))
        }
    }

    fn read_u32(&self, addr: GuestAddr) -> Result<u32, MemoryError> {
        self.check_committed(addr, 4)?;
        unsafe {
            Ok(LittleEndian::read_u32(std::slice::from_raw_parts(
                self.base_ptr.add(addr.as_u32() as usize),
                4,
            )))
        }
    }

    fn read_u64(&self, addr: GuestAddr) -> Result<u64, MemoryError> {
        self.check_committed(addr, 8)?;
        unsafe {
            Ok(LittleEndian::read_u64(std::slice::from_raw_parts(
                self.base_ptr.add(addr.as_u32() as usize),
                8,
            )))
        }
    }

    fn write_u8(&mut self, addr: GuestAddr, val: u8) -> Result<(), MemoryError> {
        self.check_access(addr, 1, true)?;
        unsafe {
            *self.base_ptr.add(addr.as_u32() as usize) = val;
        }
        crate::GlobalExclusiveMonitor::global().clear_all(addr.as_u32());
        Ok(())
    }

    fn write_u16(&mut self, addr: GuestAddr, val: u16) -> Result<(), MemoryError> {
        self.check_access(addr, 2, true)?;
        unsafe {
            LittleEndian::write_u16(
                std::slice::from_raw_parts_mut(self.base_ptr.add(addr.as_u32() as usize), 2),
                val,
            );
        }
        crate::GlobalExclusiveMonitor::global().clear_all(addr.as_u32());
        Ok(())
    }

    fn write_u32(&mut self, addr: GuestAddr, val: u32) -> Result<(), MemoryError> {
        self.check_access(addr, 4, true)?;
        unsafe {
            LittleEndian::write_u32(
                std::slice::from_raw_parts_mut(self.base_ptr.add(addr.as_u32() as usize), 4),
                val,
            );
        }
        crate::GlobalExclusiveMonitor::global().clear_all(addr.as_u32());
        Ok(())
    }

    fn write_u64(&mut self, addr: GuestAddr, val: u64) -> Result<(), MemoryError> {
        self.check_access(addr, 8, true)?;
        unsafe {
            LittleEndian::write_u64(
                std::slice::from_raw_parts_mut(self.base_ptr.add(addr.as_u32() as usize), 8),
                val,
            );
        }
        crate::GlobalExclusiveMonitor::global().clear_all(addr.as_u32());
        Ok(())
    }

    fn read_bytes(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), MemoryError> {
        self.check_access(addr, buf.len(), false)?;
        unsafe {
            buf.copy_from_slice(std::slice::from_raw_parts(
                self.base_ptr.add(addr.as_u32() as usize),
                buf.len(),
            ));
        }
        Ok(())
    }

    fn write_bytes(&mut self, addr: GuestAddr, buf: &[u8]) -> Result<(), MemoryError> {
        self.check_access(addr, buf.len(), true)?;
        unsafe {
            std::slice::from_raw_parts_mut(self.base_ptr.add(addr.as_u32() as usize), buf.len())
                .copy_from_slice(buf);
        }
        crate::GlobalExclusiveMonitor::global().clear_all(addr.as_u32());
        Ok(())
    }

    fn mprotect(&mut self, addr: GuestAddr, len: usize, prot: u32) -> Result<(), MemoryError> {
        self.mprotect(addr, len, prot)
    }

    fn commit_range(&mut self, addr: GuestAddr, len: usize) -> Result<(), MemoryError> {
        ArenaMemory::commit_range(self, addr, len)
    }

    fn get_protection(&self, addr: GuestAddr) -> u32 {
        self.get_protection(addr)
    }

    #[inline(always)]
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.base_ptr
    }

    fn atomic_cmpxchg_u32(
        &mut self,
        addr: GuestAddr,
        expected: u32,
        new: u32,
    ) -> Result<u32, MemoryError> {
        self.check_committed(addr, 4)?;
        unsafe {
            let atomic_ptr = self.base_ptr.add(addr.as_u32() as usize) as *const std::sync::atomic::AtomicU32;
            let res = (*atomic_ptr).compare_exchange(
                expected,
                new,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            );
            match res {
                Ok(prev) => Ok(prev),
                Err(actual) => Ok(actual),
            }
        }
    }
}

/// Thread-safe reference-counted wrapper around ArenaMemory for multi-threaded DBT execution
#[derive(Clone)]
pub struct SharedArenaMemory {
    inner: Arc<RwLock<ArenaMemory>>,
}

impl SharedArenaMemory {
    pub fn new() -> Result<Self, MemoryError> {
        Ok(Self {
            inner: Arc::new(RwLock::new(ArenaMemory::new()?)),
        })
    }

    pub fn commit_range(&self, addr: GuestAddr, len: usize) -> Result<(), MemoryError> {
        self.inner.write().unwrap().commit_range(addr, len)
    }

    pub fn decommit_range(&self, addr: GuestAddr, len: usize) -> Result<(), MemoryError> {
        self.inner.write().unwrap().decommit_range(addr, len)
    }

    pub fn is_page_committed(&self, pfn: u32) -> bool {
        self.inner.read().unwrap().is_page_committed(pfn)
    }
}

impl Memory for SharedArenaMemory {
    fn read_u8(&self, addr: GuestAddr) -> Result<u8, MemoryError> {
        self.inner.read().unwrap().read_u8(addr)
    }

    fn read_u16(&self, addr: GuestAddr) -> Result<u16, MemoryError> {
        self.inner.read().unwrap().read_u16(addr)
    }

    fn read_u32(&self, addr: GuestAddr) -> Result<u32, MemoryError> {
        self.inner.read().unwrap().read_u32(addr)
    }

    fn read_u64(&self, addr: GuestAddr) -> Result<u64, MemoryError> {
        self.inner.read().unwrap().read_u64(addr)
    }

    fn write_u8(&mut self, addr: GuestAddr, val: u8) -> Result<(), MemoryError> {
        self.inner.write().unwrap().write_u8(addr, val)
    }

    fn write_u16(&mut self, addr: GuestAddr, val: u16) -> Result<(), MemoryError> {
        self.inner.write().unwrap().write_u16(addr, val)
    }

    fn write_u32(&mut self, addr: GuestAddr, val: u32) -> Result<(), MemoryError> {
        self.inner.write().unwrap().write_u32(addr, val)
    }

    fn write_u64(&mut self, addr: GuestAddr, val: u64) -> Result<(), MemoryError> {
        self.inner.write().unwrap().write_u64(addr, val)
    }

    fn read_bytes(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), MemoryError> {
        self.inner.read().unwrap().read_bytes(addr, buf)
    }

    fn write_bytes(&mut self, addr: GuestAddr, buf: &[u8]) -> Result<(), MemoryError> {
        self.inner.write().unwrap().write_bytes(addr, buf)
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.inner.write().unwrap().as_mut_ptr()
    }

    fn atomic_cmpxchg_u32(&mut self, addr: GuestAddr, expected: u32, new: u32) -> Result<u32, MemoryError> {
        self.inner.write().unwrap().atomic_cmpxchg_u32(addr, expected, new)
    }

    fn commit_range(&mut self, addr: GuestAddr, len: usize) -> Result<(), MemoryError> {
        self.inner.write().unwrap().commit_range(addr, len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arena_memory_alloc_commit_and_access() {
        let mut arena = ArenaMemory::new().expect("Failed to allocate 4GB arena");
        assert_eq!(arena.committed_page_count(), 0);

        let test_addr = GuestAddr::new(0x2000_1000);
        // Uncommitted access fails
        assert!(arena.read_u32(test_addr).is_err());

        // Commit 8KB (2 pages) around 0x2000_1000
        arena.commit_range(test_addr, 8192).unwrap();
        assert!(arena.is_page_committed(0x2000_1000 >> 12));
        assert!(arena.is_page_committed(0x2000_2000 >> 12));

        // Write and read
        arena.write_u32(test_addr, 0xDEAD_BEEF).unwrap();
        assert_eq!(arena.read_u32(test_addr).unwrap(), 0xDEAD_BEEF);

        // Atomic compare-exchange
        let old = arena.atomic_cmpxchg_u32(test_addr, 0xDEAD_BEEF, 0xCAFE_BABE).unwrap();
        assert_eq!(old, 0xDEAD_BEEF);
        assert_eq!(arena.read_u32(test_addr).unwrap(), 0xCAFE_BABE);

        // Decommit
        arena.decommit_range(test_addr, 8192).unwrap();
        assert!(!arena.is_page_committed(0x2000_1000 >> 12));
        assert!(arena.read_u32(test_addr).is_err());
    }

    #[test]
    fn test_shared_arena_memory_concurrent() {
        let shared = SharedArenaMemory::new().unwrap();
        let target = GuestAddr::new(0x3000_0000);
        shared.commit_range(target, 4096).unwrap();

        let mut child1 = shared.clone();
        let handle = std::thread::spawn(move || {
            child1.write_u32(target, 0x1234_5678).unwrap();
        });
        handle.join().unwrap();

        assert_eq!(shared.read_u32(target).unwrap(), 0x1234_5678);
    }
}
