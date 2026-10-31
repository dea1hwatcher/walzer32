use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

use crate::addr::GuestAddr;

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
}

/// Simple Flat Memory for testing and reference emulation
pub struct FlatMemory {
    base: GuestAddr,
    data: Vec<u8>,
}

impl FlatMemory {
    pub fn new(base: GuestAddr, size: usize) -> Self {
        Self {
            base,
            data: vec![0; size],
        }
    }

    #[inline(always)]
    fn offset(&self, addr: GuestAddr) -> Result<usize, MemoryError> {
        let b = self.base.as_u32();
        let a = addr.as_u32();
        if a >= b && (a as usize) < (b as usize + self.data.len()) {
            Ok((a - b) as usize)
        } else {
            Err(MemoryError::Unmapped(addr))
        }
    }
}

impl Memory for FlatMemory {
    fn read_u8(&self, addr: GuestAddr) -> Result<u8, MemoryError> {
        let off = self.offset(addr)?;
        Ok(self.data[off])
    }

    fn read_u16(&self, addr: GuestAddr) -> Result<u16, MemoryError> {
        let off = self.offset(addr)?;
        if off + 2 <= self.data.len() {
            Ok(LittleEndian::read_u16(&self.data[off..off + 2]))
        } else {
            Err(MemoryError::Unmapped(addr))
        }
    }

    fn read_u32(&self, addr: GuestAddr) -> Result<u32, MemoryError> {
        let off = self.offset(addr)?;
        if off + 4 <= self.data.len() {
            Ok(LittleEndian::read_u32(&self.data[off..off + 4]))
        } else {
            Err(MemoryError::Unmapped(addr))
        }
    }

    fn read_u64(&self, addr: GuestAddr) -> Result<u64, MemoryError> {
        let off = self.offset(addr)?;
        if off + 8 <= self.data.len() {
            Ok(LittleEndian::read_u64(&self.data[off..off + 8]))
        } else {
            Err(MemoryError::Unmapped(addr))
        }
    }

    fn write_u8(&mut self, addr: GuestAddr, val: u8) -> Result<(), MemoryError> {
        let off = self.offset(addr)?;
        self.data[off] = val;
        Ok(())
    }

    fn write_u16(&mut self, addr: GuestAddr, val: u16) -> Result<(), MemoryError> {
        let off = self.offset(addr)?;
        if off + 2 <= self.data.len() {
            LittleEndian::write_u16(&mut self.data[off..off + 2], val);
            Ok(())
        } else {
            Err(MemoryError::Unmapped(addr))
        }
    }

    fn write_u32(&mut self, addr: GuestAddr, val: u32) -> Result<(), MemoryError> {
        let off = self.offset(addr)?;
        if off + 4 <= self.data.len() {
            LittleEndian::write_u32(&mut self.data[off..off + 4], val);
            Ok(())
        } else {
            Err(MemoryError::Unmapped(addr))
        }
    }

    fn write_u64(&mut self, addr: GuestAddr, val: u64) -> Result<(), MemoryError> {
        let off = self.offset(addr)?;
        if off + 8 <= self.data.len() {
            LittleEndian::write_u64(&mut self.data[off..off + 8], val);
            Ok(())
        } else {
            Err(MemoryError::Unmapped(addr))
        }
    }

    fn read_bytes(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), MemoryError> {
        let off = self.offset(addr)?;
        if off + buf.len() <= self.data.len() {
            buf.copy_from_slice(&self.data[off..off + buf.len()]);
            Ok(())
        } else {
            Err(MemoryError::Unmapped(addr))
        }
    }

    fn write_bytes(&mut self, addr: GuestAddr, buf: &[u8]) -> Result<(), MemoryError> {
        let off = self.offset(addr)?;
        if off + buf.len() <= self.data.len() {
            self.data[off..off + buf.len()].copy_from_slice(buf);
            Ok(())
        } else {
            Err(MemoryError::Unmapped(addr))
        }
    }
}
