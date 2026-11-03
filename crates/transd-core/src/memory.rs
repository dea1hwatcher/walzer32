use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

use crate::addr::GuestAddr;

pub const PROT_NONE: u32 = 0;
pub const PROT_READ: u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC: u32 = 4;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum MemoryError {
    #[error("Unmapped memory access at {0}")]
    Unmapped(GuestAddr),
    #[error("Misaligned memory access at {addr} (expected {align}-byte alignment)")]
    Misaligned { addr: GuestAddr, align: u32 },
    #[error("Permission denied at {addr} (write={write})")]
    PermissionDenied { addr: GuestAddr, write: bool },
}

pub trait Memory {
    fn read_u8(&self, addr: GuestAddr) -> Result<u8, MemoryError>;
    fn read_u16(&self, addr: GuestAddr) -> Result<u16, MemoryError>;
    fn read_u32(&self, addr: GuestAddr) -> Result<u32, MemoryError>;
    fn read_u64(&self, addr: GuestAddr) -> Result<u64, MemoryError>;

    fn write_u8(&mut self, addr: GuestAddr, val: u8) -> Result<(), MemoryError>;
    fn write_u16(&mut self, addr: GuestAddr, val: u16) -> Result<(), MemoryError>;
    fn write_u32(&mut self, addr: GuestAddr, val: u32) -> Result<(), MemoryError>;
    fn write_u64(&mut self, addr: GuestAddr, val: u64) -> Result<(), MemoryError>;

    fn read_bytes(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), MemoryError>;
    fn write_bytes(&mut self, addr: GuestAddr, buf: &[u8]) -> Result<(), MemoryError>;

    /// Returns direct raw pointer to host memory buffer if available
    fn as_mut_ptr(&mut self) -> *mut u8 {
        std::ptr::null_mut()
    }

    /// Changes protection flags (PROT_READ, PROT_WRITE, PROT_EXEC) for the given guest range
    fn mprotect(&mut self, _addr: GuestAddr, _len: usize, _prot: u32) -> Result<(), MemoryError> {
        Ok(())
    }

    /// Commits virtual pages in memory for the given guest range (default is no-op)
    fn commit_range(&mut self, _addr: GuestAddr, _len: usize) -> Result<(), MemoryError> {
        Ok(())
    }

    /// Queries the protection flags for a given guest address
    fn get_protection(&self, _addr: GuestAddr) -> u32 {
        PROT_READ | PROT_WRITE | PROT_EXEC
    }

    fn atomic_cmpxchg_u32(&mut self, addr: GuestAddr, expected: u32, new: u32) -> Result<u32, MemoryError> {
        let cur = self.read_u32(addr)?;
        if cur == expected {
            self.write_u32(addr, new)?;
        }
        Ok(cur)
    }
}

/// Simple Flat Memory for testing and reference emulation
#[derive(Clone, Debug)]
pub struct FlatMemory {
    base: GuestAddr,
    data: Vec<u8>,
    page_protections: HashMap<u32, u8>,
}

impl FlatMemory {
    pub fn new(base: GuestAddr, size: usize) -> Self {
        Self {
            base,
            data: vec![0; size],
            page_protections: HashMap::new(),
        }
    }

    #[inline(always)]
    fn check_access(&self, addr: GuestAddr, len: usize, write: bool) -> Result<usize, MemoryError> {
        let b = self.base.as_u32();
        let a = addr.as_u32();
        if a >= b && (a as usize + len) <= (b as usize + self.data.len()) {
            if !self.page_protections.is_empty() {
                let start_pfn = a >> 12;
                let end_pfn = (a.saturating_add(len.max(1) as u32 - 1)) >> 12;
                for pfn in start_pfn..=end_pfn {
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
            Ok((a - b) as usize)
        } else {
            Err(MemoryError::Unmapped(addr))
        }
    }

    #[inline(always)]
    pub fn offset(&self, addr: GuestAddr) -> Result<usize, MemoryError> {
        self.check_access(addr, 1, false)
    }
}

impl Memory for FlatMemory {
    fn read_u8(&self, addr: GuestAddr) -> Result<u8, MemoryError> {
        let off = self.check_access(addr, 1, false)?;
        Ok(self.data[off])
    }

    fn read_u16(&self, addr: GuestAddr) -> Result<u16, MemoryError> {
        let off = self.check_access(addr, 2, false)?;
        Ok(LittleEndian::read_u16(&self.data[off..off + 2]))
    }

    fn read_u32(&self, addr: GuestAddr) -> Result<u32, MemoryError> {
        let off = self.check_access(addr, 4, false)?;
        Ok(LittleEndian::read_u32(&self.data[off..off + 4]))
    }

    fn read_u64(&self, addr: GuestAddr) -> Result<u64, MemoryError> {
        let off = self.check_access(addr, 8, false)?;
        Ok(LittleEndian::read_u64(&self.data[off..off + 8]))
    }

    fn write_u8(&mut self, addr: GuestAddr, val: u8) -> Result<(), MemoryError> {
        let off = self.check_access(addr, 1, true)?;
        self.data[off] = val;
        Ok(())
    }

    fn write_u16(&mut self, addr: GuestAddr, val: u16) -> Result<(), MemoryError> {
        let off = self.check_access(addr, 2, true)?;
        LittleEndian::write_u16(&mut self.data[off..off + 2], val);
        Ok(())
    }

    fn write_u32(&mut self, addr: GuestAddr, val: u32) -> Result<(), MemoryError> {
        let off = self.check_access(addr, 4, true)?;
        LittleEndian::write_u32(&mut self.data[off..off + 4], val);
        Ok(())
    }

    fn write_u64(&mut self, addr: GuestAddr, val: u64) -> Result<(), MemoryError> {
        let off = self.check_access(addr, 8, true)?;
        LittleEndian::write_u64(&mut self.data[off..off + 8], val);
        Ok(())
    }

    fn read_bytes(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), MemoryError> {
        let off = self.check_access(addr, buf.len(), false)?;
        buf.copy_from_slice(&self.data[off..off + buf.len()]);
        Ok(())
    }

    fn write_bytes(&mut self, addr: GuestAddr, buf: &[u8]) -> Result<(), MemoryError> {
        let off = self.check_access(addr, buf.len(), true)?;
        self.data[off..off + buf.len()].copy_from_slice(buf);
        Ok(())
    }

    fn mprotect(&mut self, addr: GuestAddr, len: usize, prot: u32) -> Result<(), MemoryError> {
        if len == 0 {
            return Ok(());
        }
        let b = self.base.as_u32();
        let a = addr.as_u32();
        if a < b || (a as usize + len) > (b as usize + self.data.len()) {
            return Err(MemoryError::Unmapped(addr));
        }
        let start_pfn = a >> 12;
        let end_pfn = (a.saturating_add(len.max(1) as u32 - 1)) >> 12;
        for pfn in start_pfn..=end_pfn {
            self.page_protections.insert(pfn, (prot & 0x7) as u8);
        }
        Ok(())
    }

    fn get_protection(&self, addr: GuestAddr) -> u32 {
        let pfn = addr.as_u32() >> 12;
        self.page_protections
            .get(&pfn)
            .copied()
            .map(|p| p as u32)
            .unwrap_or(PROT_READ | PROT_WRITE | PROT_EXEC)
    }

    #[inline(always)]
    fn as_mut_ptr(&mut self) -> *mut u8 {
        ((self.data.as_mut_ptr() as usize).wrapping_sub(self.base.as_u32() as usize)) as *mut u8
    }
}

/// Thread-safe shared guest memory for concurrent DBT execution
#[derive(Clone)]
pub struct SharedMemory {
    inner: Arc<RwLock<FlatMemory>>,
}

impl SharedMemory {
    pub fn new(base: GuestAddr, size: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(FlatMemory::new(base, size))),
        }
    }

    pub fn from_flat(flat: FlatMemory) -> Self {
        Self {
            inner: Arc::new(RwLock::new(flat)),
        }
    }
}

impl Memory for SharedMemory {
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

    fn mprotect(&mut self, addr: GuestAddr, len: usize, prot: u32) -> Result<(), MemoryError> {
        self.inner.write().unwrap().mprotect(addr, len, prot)
    }

    fn get_protection(&self, addr: GuestAddr) -> u32 {
        self.inner.read().unwrap().get_protection(addr)
    }

    fn atomic_cmpxchg_u32(&mut self, addr: GuestAddr, expected: u32, new: u32) -> Result<u32, MemoryError> {
        let mut guard = self.inner.write().unwrap();
        let cur = guard.read_u32(addr)?;
        if cur == expected {
            guard.write_u32(addr, new)?;
        }
        Ok(cur)
    }
}
