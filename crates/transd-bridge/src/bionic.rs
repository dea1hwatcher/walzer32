use std::collections::HashMap;
use transd_core::{GuestAddr, Memory, MemoryError, Reg};
use transd_elf::{DsoRegistry, SymbolResolver, RTLD_DEFAULT, RTLD_NEXT};

pub const BIONIC_SVC_MAGIC: u32 = 0xB10000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BionicFuncId {
    AndroidLogPrint = 1,
    AndroidLogWrite = 2,
    Malloc = 3,
    Free = 4,
    Calloc = 5,
    Realloc = 6,
    Memcpy = 7,
    Memset = 8,
    Memcmp = 9,
    Strlen = 10,
    Strcmp = 11,
    Strcpy = 12,
    Abort = 13,

    // Threading & Mutexes
    PthreadCreate = 20,
    PthreadJoin = 21,
    PthreadSelf = 22,
    PthreadMutexInit = 23,
    PthreadMutexLock = 24,
    PthreadMutexUnlock = 25,
    PthreadMutexDestroy = 26,
    PthreadOnce = 27,
    AeabiReadTp = 28,

    // Memory protection
    Mprotect = 30,

    // libm math intrinsics (Single-precision f32)
    Sinf = 40,
    Cosf = 41,
    Tanf = 42,
    Atan2f = 43,
    Sqrtf = 44,
    Powf = 45,
    Expf = 46,
    Logf = 47,
    Floorf = 48,
    Ceilf = 49,
    Fabsf = 50,

    // libm math intrinsics (Double-precision f64)
    Sin = 51,
    Cos = 52,
    Tan = 53,
    Atan2 = 54,
    Sqrt = 55,
    Pow = 56,
    Exp = 57,
    Log = 58,
    Floor = 59,
    Ceil = 60,
    Fabs = 61,

    // Dynamic Linking (libdl)
    Dlopen = 70,
    Dlsym = 71,
    Dlclose = 72,
    Dlerror = 73,
}

impl BionicFuncId {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::AndroidLogPrint),
            2 => Some(Self::AndroidLogWrite),
            3 => Some(Self::Malloc),
            4 => Some(Self::Free),
            5 => Some(Self::Calloc),
            6 => Some(Self::Realloc),
            7 => Some(Self::Memcpy),
            8 => Some(Self::Memset),
            9 => Some(Self::Memcmp),
            10 => Some(Self::Strlen),
            11 => Some(Self::Strcmp),
            12 => Some(Self::Strcpy),
            13 => Some(Self::Abort),
            20 => Some(Self::PthreadCreate),
            21 => Some(Self::PthreadJoin),
            22 => Some(Self::PthreadSelf),
            23 => Some(Self::PthreadMutexInit),
            24 => Some(Self::PthreadMutexLock),
            25 => Some(Self::PthreadMutexUnlock),
            26 => Some(Self::PthreadMutexDestroy),
            27 => Some(Self::PthreadOnce),
            28 => Some(Self::AeabiReadTp),
            30 => Some(Self::Mprotect),
            40 => Some(Self::Sinf),
            41 => Some(Self::Cosf),
            42 => Some(Self::Tanf),
            43 => Some(Self::Atan2f),
            44 => Some(Self::Sqrtf),
            45 => Some(Self::Powf),
            46 => Some(Self::Expf),
            47 => Some(Self::Logf),
            48 => Some(Self::Floorf),
            49 => Some(Self::Ceilf),
            50 => Some(Self::Fabsf),
            51 => Some(Self::Sin),
            52 => Some(Self::Cos),
            53 => Some(Self::Tan),
            54 => Some(Self::Atan2),
            55 => Some(Self::Sqrt),
            56 => Some(Self::Pow),
            57 => Some(Self::Exp),
            58 => Some(Self::Log),
            59 => Some(Self::Floor),
            60 => Some(Self::Ceil),
            61 => Some(Self::Fabs),
            70 => Some(Self::Dlopen),
            71 => Some(Self::Dlsym),
            72 => Some(Self::Dlclose),
            73 => Some(Self::Dlerror),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ThreadDescriptor {
    pub id: u32,
    pub start_routine: GuestAddr,
    pub arg: u32,
    pub stack_top: GuestAddr,
    pub tls_ptr: GuestAddr,
    pub retval: Option<u32>,
    pub joined: bool,
}

#[derive(Debug, Clone)]
pub struct LogMessage {
    pub priority: u32,
    pub tag: String,
    pub text: String,
}

/// Provides Bionic C standard library stubs and forwarding for 32-bit guest code
pub struct BionicBridge {
    pub stub_base: GuestAddr,
    pub heap_current: GuestAddr,
    pub heap_limit: GuestAddr,
    symbol_table: HashMap<String, GuestAddr>,
    pub logs: Vec<LogMessage>,

    pub next_thread_id: u32,
    pub current_thread_id: u32,
    pub threads: HashMap<u32, ThreadDescriptor>,

    pub dso_registry: DsoRegistry,
    pub last_dlerror: Option<String>,
    pub dlerror_addr: GuestAddr,
}

impl BionicBridge {
    pub fn new(stub_base: GuestAddr, heap_start: GuestAddr, heap_size: u32) -> Self {
        let mut bridge = Self {
            stub_base,
            heap_current: heap_start,
            heap_limit: heap_start.add(heap_size),
            symbol_table: HashMap::new(),
            logs: Vec::new(),
            next_thread_id: 1,
            current_thread_id: 1,
            threads: HashMap::new(),
            dso_registry: DsoRegistry::new(),
            last_dlerror: None,
            dlerror_addr: stub_base.add(0x800),
        };

        bridge.register_known_symbols();
        bridge
    }

    /// Registers a loaded DSO into the in-process linker registry
    pub fn register_library(&mut self, lib: transd_elf::LoadedLibrary) -> u32 {
        self.dso_registry.register(lib)
    }

    fn register_known_symbols(&mut self) {
        let funcs = [
            ("__android_log_print", BionicFuncId::AndroidLogPrint),
            ("__android_log_write", BionicFuncId::AndroidLogWrite),
            ("malloc", BionicFuncId::Malloc),
            ("free", BionicFuncId::Free),
            ("calloc", BionicFuncId::Calloc),
            ("realloc", BionicFuncId::Realloc),
            ("memcpy", BionicFuncId::Memcpy),
            ("memset", BionicFuncId::Memset),
            ("memcmp", BionicFuncId::Memcmp),
            ("strlen", BionicFuncId::Strlen),
            ("strcmp", BionicFuncId::Strcmp),
            ("strcpy", BionicFuncId::Strcpy),
            ("abort", BionicFuncId::Abort),
            ("pthread_create", BionicFuncId::PthreadCreate),
            ("pthread_join", BionicFuncId::PthreadJoin),
            ("pthread_self", BionicFuncId::PthreadSelf),
            ("pthread_mutex_init", BionicFuncId::PthreadMutexInit),
            ("pthread_mutex_lock", BionicFuncId::PthreadMutexLock),
            ("pthread_mutex_unlock", BionicFuncId::PthreadMutexUnlock),
            ("pthread_mutex_destroy", BionicFuncId::PthreadMutexDestroy),
            ("pthread_once", BionicFuncId::PthreadOnce),
            ("__aeabi_read_tp", BionicFuncId::AeabiReadTp),
            ("mprotect", BionicFuncId::Mprotect),

            // libm math intrinsics (Single-precision f32)
            ("sinf", BionicFuncId::Sinf),
            ("cosf", BionicFuncId::Cosf),
            ("tanf", BionicFuncId::Tanf),
            ("atan2f", BionicFuncId::Atan2f),
            ("sqrtf", BionicFuncId::Sqrtf),
            ("powf", BionicFuncId::Powf),
            ("expf", BionicFuncId::Expf),
            ("logf", BionicFuncId::Logf),
            ("floorf", BionicFuncId::Floorf),
            ("ceilf", BionicFuncId::Ceilf),
            ("fabsf", BionicFuncId::Fabsf),

            // libm math intrinsics (Double-precision f64)
            ("sin", BionicFuncId::Sin),
            ("cos", BionicFuncId::Cos),
            ("tan", BionicFuncId::Tan),
            ("atan2", BionicFuncId::Atan2),
            ("sqrt", BionicFuncId::Sqrt),
            ("pow", BionicFuncId::Pow),
            ("exp", BionicFuncId::Exp),
            ("log", BionicFuncId::Log),
            ("floor", BionicFuncId::Floor),
            ("ceil", BionicFuncId::Ceil),
            ("fabs", BionicFuncId::Fabs),

            // Dynamic Linking (libdl)
            ("dlopen", BionicFuncId::Dlopen),
            ("dlsym", BionicFuncId::Dlsym),
            ("dlclose", BionicFuncId::Dlclose),
            ("dlerror", BionicFuncId::Dlerror),
        ];

        for (name, id) in funcs {
            let addr = self.stub_base.add((id as u32) * 8);
            self.symbol_table.insert(name.to_string(), addr);
        }
    }

    /// Initializes stub code into memory at stub_base
    pub fn install_stubs(&self, mem: &mut impl Memory) -> Result<(), MemoryError> {
        for &id in &[
            BionicFuncId::AndroidLogPrint,
            BionicFuncId::AndroidLogWrite,
            BionicFuncId::Malloc,
            BionicFuncId::Free,
            BionicFuncId::Calloc,
            BionicFuncId::Realloc,
            BionicFuncId::Memcpy,
            BionicFuncId::Memset,
            BionicFuncId::Memcmp,
            BionicFuncId::Strlen,
            BionicFuncId::Strcmp,
            BionicFuncId::Strcpy,
            BionicFuncId::Abort,
            BionicFuncId::PthreadCreate,
            BionicFuncId::PthreadJoin,
            BionicFuncId::PthreadSelf,
            BionicFuncId::PthreadMutexInit,
            BionicFuncId::PthreadMutexLock,
            BionicFuncId::PthreadMutexUnlock,
            BionicFuncId::PthreadMutexDestroy,
            BionicFuncId::PthreadOnce,
            BionicFuncId::AeabiReadTp,
            BionicFuncId::Mprotect,
            BionicFuncId::Sinf,
            BionicFuncId::Cosf,
            BionicFuncId::Tanf,
            BionicFuncId::Atan2f,
            BionicFuncId::Sqrtf,
            BionicFuncId::Powf,
            BionicFuncId::Expf,
            BionicFuncId::Logf,
            BionicFuncId::Floorf,
            BionicFuncId::Ceilf,
            BionicFuncId::Fabsf,
            BionicFuncId::Sin,
            BionicFuncId::Cos,
            BionicFuncId::Tan,
            BionicFuncId::Atan2,
            BionicFuncId::Sqrt,
            BionicFuncId::Pow,
            BionicFuncId::Exp,
            BionicFuncId::Log,
            BionicFuncId::Floor,
            BionicFuncId::Ceil,
            BionicFuncId::Fabs,
            BionicFuncId::Dlopen,
            BionicFuncId::Dlsym,
            BionicFuncId::Dlclose,
            BionicFuncId::Dlerror,
        ] {
            let addr = self.stub_base.add((id as u32) * 8);
            let svc_code = 0xEF00_0000 | (BIONIC_SVC_MAGIC | (id as u32)); // SVC #(BIONIC_SVC_MAGIC | id)
            let bx_lr = 0xE12F_FF1E; // BX lr

            mem.write_u32(addr, svc_code)?;
            mem.write_u32(addr.add(4), bx_lr)?;
        }
        Ok(())
    }

    /// Handles a Bionic SVC call invoked by 32-bit guest code
    pub fn handle_svc(
        &mut self,
        svc_imm: u32,
        cpu: &mut transd_core::CpuState,
        mem: &mut impl Memory,
    ) -> Result<bool, MemoryError> {
        if (svc_imm & 0xFF0000) != BIONIC_SVC_MAGIC {
            return Ok(false); // Not a Bionic SVC
        }

        let func_id_raw = svc_imm & 0xFFFF;
        let func_id = match BionicFuncId::from_u32(func_id_raw) {
            Some(id) => id,
            None => return Ok(false),
        };

        match func_id {
            BionicFuncId::Malloc => {
                let size = cpu.reg(Reg::R0);
                let align_size = (size + 7) & !7; // 8-byte alignment
                if self.heap_current.add(align_size) <= self.heap_limit {
                    let ptr = self.heap_current;
                    self.heap_current = self.heap_current.add(align_size);
                    cpu.set_reg(Reg::R0, ptr.as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0); // Out of memory
                }
            }
            BionicFuncId::Free => {
                // In simple bump allocator free is no-op
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::Calloc => {
                let num = cpu.reg(Reg::R0);
                let size = cpu.reg(Reg::R1);
                let total = num.wrapping_mul(size);
                let align_size = (total + 7) & !7;
                if self.heap_current.add(align_size) <= self.heap_limit {
                    let ptr = self.heap_current;
                    self.heap_current = self.heap_current.add(align_size);
                    let zeroes = vec![0u8; align_size as usize];
                    mem.write_bytes(ptr, &zeroes)?;
                    cpu.set_reg(Reg::R0, ptr.as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::Memcpy => {
                let dst = GuestAddr::new(cpu.reg(Reg::R0));
                let src = GuestAddr::new(cpu.reg(Reg::R1));
                let count = cpu.reg(Reg::R2) as usize;

                let mut buf = vec![0u8; count];
                mem.read_bytes(src, &mut buf)?;
                mem.write_bytes(dst, &buf)?;
                // Returns dst
            }
            BionicFuncId::Memset => {
                let dst = GuestAddr::new(cpu.reg(Reg::R0));
                let val = (cpu.reg(Reg::R1) & 0xFF) as u8;
                let count = cpu.reg(Reg::R2) as usize;

                let buf = vec![val; count];
                mem.write_bytes(dst, &buf)?;
                // Returns dst
            }
            BionicFuncId::Strlen => {
                let str_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let mut len = 0u32;
                while mem.read_u8(str_ptr.add(len))? != 0 {
                    len += 1;
                }
                cpu.set_reg(Reg::R0, len);
            }
            BionicFuncId::Strcpy => {
                let dst = GuestAddr::new(cpu.reg(Reg::R0));
                let src = GuestAddr::new(cpu.reg(Reg::R1));
                let mut idx = 0u32;
                loop {
                    let byte = mem.read_u8(src.add(idx))?;
                    mem.write_u8(dst.add(idx), byte)?;
                    if byte == 0 {
                        break;
                    }
                    idx += 1;
                }
            }
            BionicFuncId::AndroidLogPrint => {
                let prio = cpu.reg(Reg::R0);
                let tag_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let fmt_addr = GuestAddr::new(cpu.reg(Reg::R2));

                let tag = Self::read_c_string(mem, tag_addr)?;
                let fmt = Self::read_c_string(mem, fmt_addr)?;

                self.logs.push(LogMessage {
                    priority: prio,
                    tag,
                    text: fmt,
                });

                cpu.set_reg(Reg::R0, 1); // Success
            }
            BionicFuncId::AndroidLogWrite => {
                let prio = cpu.reg(Reg::R0);
                let tag_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let text_addr = GuestAddr::new(cpu.reg(Reg::R2));

                let tag = Self::read_c_string(mem, tag_addr)?;
                let text = Self::read_c_string(mem, text_addr)?;

                self.logs.push(LogMessage {
                    priority: prio,
                    tag,
                    text,
                });

                cpu.set_reg(Reg::R0, 1);
            }
            BionicFuncId::Abort => {
                return Err(MemoryError::Unmapped(GuestAddr::new(0xDEAD_DEAD)));
            }
            BionicFuncId::PthreadCreate => {
                let thread_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let _attr = cpu.reg(Reg::R1);
                let start_routine = GuestAddr::new(cpu.reg(Reg::R2));
                let arg = cpu.reg(Reg::R3);

                let tid = self.next_thread_id;
                self.next_thread_id += 1;

                // Allocate thread stack: 256 KB
                let stack_size = 256 * 1024;
                let stack_base = self.heap_current;
                self.heap_current = self.heap_current.add(stack_size);
                let stack_top = stack_base.add(stack_size - 8);

                // Allocate TLS: 1024 bytes
                let tls_ptr = self.heap_current;
                self.heap_current = self.heap_current.add(1024);

                let desc = ThreadDescriptor {
                    id: tid,
                    start_routine,
                    arg,
                    stack_top,
                    tls_ptr,
                    retval: None,
                    joined: false,
                };
                self.threads.insert(tid, desc);

                if thread_ptr.as_u32() != 0 {
                    mem.write_u32(thread_ptr, tid)?;
                }

                cpu.set_reg(Reg::R0, 0); // 0 = Success
            }
            BionicFuncId::PthreadJoin => {
                let tid = cpu.reg(Reg::R0);
                let retval_ptr = GuestAddr::new(cpu.reg(Reg::R1));

                if let Some(desc) = self.threads.get_mut(&tid) {
                    desc.joined = true;
                    if retval_ptr.as_u32() != 0 {
                        mem.write_u32(retval_ptr, desc.retval.unwrap_or(0))?;
                    }
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 3); // ESRCH
                }
            }
            BionicFuncId::PthreadSelf => {
                cpu.set_reg(Reg::R0, self.current_thread_id);
            }
            BionicFuncId::PthreadMutexInit => {
                let mutex_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if mutex_ptr.as_u32() != 0 {
                    mem.write_u32(mutex_ptr, 0)?; // 0 = Unlocked
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::PthreadMutexLock => {
                let mutex_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if mutex_ptr.as_u32() != 0 {
                    mem.write_u32(mutex_ptr, 1)?; // 1 = Locked
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::PthreadMutexUnlock => {
                let mutex_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if mutex_ptr.as_u32() != 0 {
                    mem.write_u32(mutex_ptr, 0)?; // 0 = Unlocked
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::PthreadMutexDestroy => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::PthreadOnce => {
                let once_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if once_ptr.as_u32() != 0 {
                    mem.write_u32(once_ptr, 1)?;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::AeabiReadTp => {
                cpu.set_reg(Reg::R0, cpu.tls_ptr);
            }
            BionicFuncId::Mprotect => {
                let addr = GuestAddr::new(cpu.reg(Reg::R0));
                let len = cpu.reg(Reg::R1) as usize;
                let prot = cpu.reg(Reg::R2);
                let page_addr = GuestAddr::new(addr.as_u32() & !0xFFF);
                let page_offset = (addr.as_u32() & 0xFFF) as usize;
                let aligned_len = (len + page_offset + 0xFFF) & !0xFFF;
                match mem.mprotect(page_addr, aligned_len, prot) {
                    Ok(()) => cpu.set_reg(Reg::R0, 0),
                    Err(_) => cpu.set_reg(Reg::R0, (-12i32) as u32), // -ENOMEM
                }
            }

            // ── Math intrinsics (Single-precision f32) ─────────────────────────
            BionicFuncId::Sinf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.sin(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Cosf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.cos(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Tanf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.tan(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Atan2f => {
                let y = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R1)), true);
                let res = cpu.sanitize_f32(y.atan2(x), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Sqrtf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.sqrt(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Powf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let y = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R1)), true);
                let res = cpu.sanitize_f32(x.powf(y), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Expf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.exp(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Logf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.ln(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Floorf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.floor(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Ceilf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.ceil(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Fabsf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.abs(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }

            // ── Math intrinsics (Double-precision f64) ─────────────────────────
            BionicFuncId::Sin => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.sin(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Cos => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.cos(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Tan => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.tan(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Atan2 => {
                let y_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x_bits = (cpu.reg(Reg::R2) as u64) | ((cpu.reg(Reg::R3) as u64) << 32);
                let y = cpu.sanitize_f64(f64::from_bits(y_bits), true);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(y.atan2(x), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Sqrt => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.sqrt(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Pow => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let y_bits = (cpu.reg(Reg::R2) as u64) | ((cpu.reg(Reg::R3) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let y = cpu.sanitize_f64(f64::from_bits(y_bits), true);
                let res = cpu.sanitize_f64(x.powf(y), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Exp => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.exp(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Log => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.ln(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Floor => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.floor(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Ceil => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.ceil(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Fabs => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.abs(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }

            // ── Dynamic Linking (libdl) ─────────────────────────────────────────
            BionicFuncId::Dlopen => {
                let filename_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let _flags = cpu.reg(Reg::R1);

                if filename_ptr.as_u32() == 0 {
                    cpu.set_reg(Reg::R0, RTLD_DEFAULT);
                } else {
                    let filename = Self::read_c_string(mem, filename_ptr)?;
                    let basename = filename.rsplit('/').next().unwrap_or(&filename);

                    if basename == "libc.so"
                        || basename == "libm.so"
                        || basename == "libdl.so"
                        || basename == "liblog.so"
                    {
                        cpu.set_reg(Reg::R0, 0xB100_0001);
                    } else if let Some((h, _)) = self.dso_registry.find_by_soname(basename) {
                        cpu.set_reg(Reg::R0, h);
                    } else if let Some((h, _)) = self.dso_registry.find_by_soname(&filename) {
                        cpu.set_reg(Reg::R0, h);
                    } else {
                        self.last_dlerror =
                            Some(format!("dlopen failed: library \"{}\" not found", filename));
                        cpu.set_reg(Reg::R0, 0);
                    }
                }
            }
            BionicFuncId::Dlsym => {
                let handle = cpu.reg(Reg::R0);
                let symbol_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let sym_name = Self::read_c_string(mem, symbol_ptr)?;

                let resolved = if handle == RTLD_DEFAULT || handle == 0xFFFF_FFFF {
                    self.dso_registry
                        .dlsym(RTLD_DEFAULT, &sym_name, None)
                        .or_else(|| self.symbol_table.get(&sym_name).copied())
                } else if handle == RTLD_NEXT {
                    self.dso_registry
                        .dlsym(RTLD_NEXT, &sym_name, None)
                } else if handle == 0xB100_0001 {
                    self.symbol_table.get(&sym_name).copied()
                } else {
                    self.dso_registry
                        .dlsym(handle, &sym_name, None)
                        .or_else(|| self.symbol_table.get(&sym_name).copied())
                };

                if let Some(addr) = resolved {
                    cpu.set_reg(Reg::R0, addr.as_u32());
                } else {
                    self.last_dlerror = Some(format!("undefined symbol \"{}\"", sym_name));
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::Dlclose => {
                let handle = cpu.reg(Reg::R0);
                if handle == RTLD_DEFAULT
                    || handle == 0xB100_0001
                    || self.dso_registry.get(handle).is_some()
                {
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    self.last_dlerror = Some(format!("invalid library handle {}", handle));
                    cpu.set_reg(Reg::R0, u32::MAX);
                }
            }
            BionicFuncId::Dlerror => {
                if let Some(err) = self.last_dlerror.take() {
                    let mut bytes = err.into_bytes();
                    bytes.push(0);
                    if bytes.len() > 512 {
                        bytes.truncate(511);
                        bytes.push(0);
                    }
                    mem.write_bytes(self.dlerror_addr, &bytes)?;
                    cpu.set_reg(Reg::R0, self.dlerror_addr.as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            _ => {}
        }

        Ok(true)
    }

    fn read_c_string(mem: &impl Memory, addr: GuestAddr) -> Result<String, MemoryError> {
        let mut bytes = Vec::new();
        let mut cur = addr;
        loop {
            let b = mem.read_u8(cur)?;
            if b == 0 {
                break;
            }
            bytes.push(b);
            cur = cur.add(1);
        }
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}

impl SymbolResolver for BionicBridge {
    fn resolve(&self, name: &str) -> Option<GuestAddr> {
        if let Some(&addr) = self.symbol_table.get(name) {
            return Some(addr);
        }
        self.dso_registry.resolve(name)
    }
}
