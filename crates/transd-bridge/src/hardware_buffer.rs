use std::collections::HashMap;
use transd_core::{GuestAddr, Memory, MemoryError, Reg};
use transd_elf::SymbolResolver;

pub const HARDWARE_BUFFER_SVC_MAGIC: u32 = 0xAB0000;

// AHardwareBuffer Formats
pub const AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM: u32 = 1;
pub const AHARDWAREBUFFER_FORMAT_R8G8B8X8_UNORM: u32 = 2;
pub const AHARDWAREBUFFER_FORMAT_R8G8B8_UNORM: u32 = 3;
pub const AHARDWAREBUFFER_FORMAT_R5G6B5_UNORM: u32 = 4;
pub const AHARDWAREBUFFER_FORMAT_R16G16B16A16_FLOAT: u32 = 0x16;
pub const AHARDWAREBUFFER_FORMAT_RGBA_8888: u32 = 1;

// AHardwareBuffer Usage Flags
pub const AHARDWAREBUFFER_USAGE_CPU_READ_NEVER: u64 = 0;
pub const AHARDWAREBUFFER_USAGE_CPU_READ_RARELY: u64 = 2;
pub const AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN: u64 = 3;
pub const AHARDWAREBUFFER_USAGE_CPU_WRITE_NEVER: u64 = 0;
pub const AHARDWAREBUFFER_USAGE_CPU_WRITE_RARELY: u64 = 2 << 4;
pub const AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN: u64 = 3 << 4;
pub const AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE: u64 = 1 << 8;
pub const AHARDWAREBUFFER_USAGE_GPU_COLOR_OUTPUT: u64 = 1 << 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HardwareBufferFuncId {
    Allocate = 1,
    Acquire = 2,
    Release = 3,
    Describe = 4,
    Lock = 5,
    Unlock = 6,
    GetId = 7,
}

impl HardwareBufferFuncId {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::Allocate),
            2 => Some(Self::Acquire),
            3 => Some(Self::Release),
            4 => Some(Self::Describe),
            5 => Some(Self::Lock),
            6 => Some(Self::Unlock),
            7 => Some(Self::GetId),
            _ => None,
        }
    }
}

/// An allocated Android Hardware Buffer descriptor and its backing memory
#[derive(Debug, Clone)]
pub struct HardwareBufferEntry {
    pub handle: u32,
    pub width: u32,
    pub height: u32,
    pub layers: u32,
    pub format: u32,
    pub usage: u64,
    pub stride: u32,
    pub backing_addr: GuestAddr,
    pub byte_size: usize,
    pub ref_count: u32,
    pub locked: bool,
}

/// Bridge for Android NDK AHardwareBuffer C API (`libandroid.so`)
pub struct HardwareBufferBridge {
    pub stub_base: GuestAddr,
    pub heap_current: GuestAddr,
    pub heap_limit: GuestAddr,
    symbol_table: HashMap<String, GuestAddr>,
    pub buffers: HashMap<u32, HardwareBufferEntry>,
    next_handle: u32,
    pub total_allocated_bytes: u64,
}

impl HardwareBufferBridge {
    pub fn new(stub_base: GuestAddr, heap_start: GuestAddr, heap_size: u32) -> Self {
        let mut bridge = Self {
            stub_base,
            heap_current: heap_start,
            heap_limit: heap_start.add(heap_size),
            symbol_table: HashMap::new(),
            buffers: HashMap::new(),
            next_handle: 0xB000_0001,
            total_allocated_bytes: 0,
        };

        bridge.register_known_symbols();
        bridge
    }

    pub fn with_stub_base(stub_base: GuestAddr) -> Self {
        Self::new(stub_base, stub_base.add(0x1000), 0x20_0000)
    }

    fn register_known_symbols(&mut self) {
        let symbols = [
            ("AHardwareBuffer_allocate", HardwareBufferFuncId::Allocate),
            ("AHardwareBuffer_acquire", HardwareBufferFuncId::Acquire),
            ("AHardwareBuffer_release", HardwareBufferFuncId::Release),
            ("AHardwareBuffer_describe", HardwareBufferFuncId::Describe),
            ("AHardwareBuffer_lock", HardwareBufferFuncId::Lock),
            ("AHardwareBuffer_unlock", HardwareBufferFuncId::Unlock),
            ("AHardwareBuffer_getId", HardwareBufferFuncId::GetId),
        ];

        for (name, id) in symbols {
            let addr = self.stub_base.add((id as u32) * 8);
            self.symbol_table.insert(name.to_string(), addr);
        }
    }

    /// Installs stub code into guest memory
    pub fn install_stubs(&self, mem: &mut impl Memory) -> Result<(), MemoryError> {
        for &id in &[
            HardwareBufferFuncId::Allocate,
            HardwareBufferFuncId::Acquire,
            HardwareBufferFuncId::Release,
            HardwareBufferFuncId::Describe,
            HardwareBufferFuncId::Lock,
            HardwareBufferFuncId::Unlock,
            HardwareBufferFuncId::GetId,
        ] {
            let addr = self.stub_base.add((id as u32) * 8);
            let svc_code = 0xEF00_0000 | (HARDWARE_BUFFER_SVC_MAGIC | (id as u32));
            let bx_lr = 0xE12F_FF1E;

            mem.write_u32(addr, svc_code)?;
            mem.write_u32(addr.add(4), bx_lr)?;
        }
        Ok(())
    }

    /// Handles an incoming AHardwareBuffer SVC invocation
    pub fn handle_svc(
        &mut self,
        svc_imm: u32,
        cpu: &mut transd_core::CpuState,
        mem: &mut impl Memory,
    ) -> Result<bool, MemoryError> {
        if (svc_imm & 0xFF0000) != HARDWARE_BUFFER_SVC_MAGIC {
            return Ok(false);
        }

        let func_id_raw = svc_imm & 0xFFFF;
        let func_id = match HardwareBufferFuncId::from_u32(func_id_raw) {
            Some(id) => id,
            None => return Ok(false),
        };

        match func_id {
            HardwareBufferFuncId::Allocate => {
                let desc_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let out_buf_ptr = GuestAddr::new(cpu.reg(Reg::R1));

                if desc_ptr.as_u32() == 0 || out_buf_ptr.as_u32() == 0 {
                    cpu.set_reg(Reg::R0, (-22i32) as u32); // -EINVAL
                    return Ok(true);
                }

                let width = mem.read_u32(desc_ptr)?;
                let height = mem.read_u32(desc_ptr.add(4))?;
                let layers = mem.read_u32(desc_ptr.add(8))?.max(1);
                let format = mem.read_u32(desc_ptr.add(12))?;
                let usage_lo = mem.read_u32(desc_ptr.add(16))?;
                let usage_hi = mem.read_u32(desc_ptr.add(20))?;
                let usage = ((usage_hi as u64) << 32) | (usage_lo as u64);

                let stride = (width + 15) & !15;
                let bpp = if format == AHARDWAREBUFFER_FORMAT_R8G8B8_UNORM { 3 } else { 4 };
                let byte_size = (stride * height * bpp * layers) as usize;

                let align_size = (byte_size + 15) & !15;
                if self.heap_current.add(align_size as u32) > self.heap_limit {
                    cpu.set_reg(Reg::R0, (-12i32) as u32); // -ENOMEM
                    return Ok(true);
                }

                let backing_addr = self.heap_current;
                self.heap_current = self.heap_current.add(align_size as u32);
                self.total_allocated_bytes += byte_size as u64;

                // Zero out allocated backing memory
                let zero_buf = vec![0u8; byte_size.min(4096)];
                let mut rem = byte_size;
                let mut cur = backing_addr;
                while rem > 0 {
                    let chunk = rem.min(zero_buf.len());
                    mem.write_bytes(cur, &zero_buf[..chunk])?;
                    cur = cur.add(chunk as u32);
                    rem -= chunk;
                }

                let handle = self.next_handle;
                self.next_handle = self.next_handle.wrapping_add(1);

                self.buffers.insert(
                    handle,
                    HardwareBufferEntry {
                        handle,
                        width,
                        height,
                        layers,
                        format,
                        usage,
                        stride,
                        backing_addr,
                        byte_size,
                        ref_count: 1,
                        locked: false,
                    },
                );

                mem.write_u32(out_buf_ptr, handle)?;
                cpu.set_reg(Reg::R0, 0); // ANDROID_SUCCESS
            }
            HardwareBufferFuncId::Acquire => {
                let handle = cpu.reg(Reg::R0);
                if let Some(buf) = self.buffers.get_mut(&handle) {
                    buf.ref_count += 1;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            HardwareBufferFuncId::Release => {
                let handle = cpu.reg(Reg::R0);
                if let Some(buf) = self.buffers.get_mut(&handle) {
                    if buf.ref_count > 0 {
                        buf.ref_count -= 1;
                    }
                    if buf.ref_count == 0 {
                        self.buffers.remove(&handle);
                    }
                }
                cpu.set_reg(Reg::R0, 0);
            }
            HardwareBufferFuncId::Describe => {
                let handle = cpu.reg(Reg::R0);
                let out_desc_ptr = GuestAddr::new(cpu.reg(Reg::R1));

                if let Some(buf) = self.buffers.get(&handle) {
                    if out_desc_ptr.as_u32() != 0 {
                        mem.write_u32(out_desc_ptr, buf.width)?;
                        mem.write_u32(out_desc_ptr.add(4), buf.height)?;
                        mem.write_u32(out_desc_ptr.add(8), buf.layers)?;
                        mem.write_u32(out_desc_ptr.add(12), buf.format)?;
                        mem.write_u32(out_desc_ptr.add(16), (buf.usage & 0xFFFF_FFFF) as u32)?;
                        mem.write_u32(out_desc_ptr.add(20), (buf.usage >> 32) as u32)?;
                        mem.write_u32(out_desc_ptr.add(24), buf.stride)?;
                        mem.write_u32(out_desc_ptr.add(28), 0)?; // rfu0
                        mem.write_u32(out_desc_ptr.add(32), 0)?; // rfu1
                    }
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, (-22i32) as u32);
                }
            }
            HardwareBufferFuncId::Lock => {
                let handle = cpu.reg(Reg::R0);
                let sp = GuestAddr::new(cpu.sp());
                let _rect_ptr = mem.read_u32(sp)?;
                let out_addr_ptr = GuestAddr::new(mem.read_u32(sp.add(4))?);

                if let Some(buf) = self.buffers.get_mut(&handle) {
                    if out_addr_ptr.as_u32() != 0 {
                        mem.write_u32(out_addr_ptr, buf.backing_addr.as_u32())?;
                        buf.locked = true;
                        cpu.set_reg(Reg::R0, 0);
                    } else {
                        cpu.set_reg(Reg::R0, (-22i32) as u32);
                    }
                } else {
                    cpu.set_reg(Reg::R0, (-22i32) as u32);
                }
            }
            HardwareBufferFuncId::Unlock => {
                let handle = cpu.reg(Reg::R0);
                let fence_ptr = GuestAddr::new(cpu.reg(Reg::R1));

                if let Some(buf) = self.buffers.get_mut(&handle) {
                    buf.locked = false;
                    if fence_ptr.as_u32() != 0 {
                        let _ = mem.write_u32(fence_ptr, 0); // No fence needed
                    }
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, (-22i32) as u32);
                }
            }
            HardwareBufferFuncId::GetId => {
                let handle = cpu.reg(Reg::R0);
                let out_id_ptr = GuestAddr::new(cpu.reg(Reg::R1));

                if let Some(buf) = self.buffers.get(&handle) {
                    if out_id_ptr.as_u32() != 0 {
                        mem.write_u32(out_id_ptr, buf.handle)?;
                        mem.write_u32(out_id_ptr.add(4), 0)?;
                    }
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, (-22i32) as u32);
                }
            }
        }

        Ok(true)
    }
}

impl SymbolResolver for HardwareBufferBridge {
    fn resolve(&self, name: &str) -> Option<GuestAddr> {
        self.symbol_table.get(name).copied()
    }
}
