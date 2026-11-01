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
    Memmove = 14,
    Strncmp = 15,
    Strncpy = 16,
    Strcat = 17,
    Strncat = 18,
    Strchr = 19,

    Strrchr = 100,
    Strstr = 101,
    Strtol = 102,
    Strtoul = 103,
    Atoi = 104,
    Snprintf = 105,
    Sprintf = 106,

    ClockGettime = 110,
    Gettimeofday = 111,

    CxaAtexit = 120,
    CxaFinalize = 121,

    StackChkFail = 130,

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

    // Signal Handling (POSIX / Bionic)
    Sigaction = 80,
    Sigprocmask = 81,
    Sigaltstack = 82,
    Raise = 83,
    RtSigreturn = 84,

    // System Properties
    SystemPropertyGet = 90,
    SystemPropertyFind = 91,
    SystemPropertyRead = 92,
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
            14 => Some(Self::Memmove),
            15 => Some(Self::Strncmp),
            16 => Some(Self::Strncpy),
            17 => Some(Self::Strcat),
            18 => Some(Self::Strncat),
            19 => Some(Self::Strchr),
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
            80 => Some(Self::Sigaction),
            81 => Some(Self::Sigprocmask),
            82 => Some(Self::Sigaltstack),
            83 => Some(Self::Raise),
            84 => Some(Self::RtSigreturn),
            90 => Some(Self::SystemPropertyGet),
            91 => Some(Self::SystemPropertyFind),
            92 => Some(Self::SystemPropertyRead),
            100 => Some(Self::Strrchr),
            101 => Some(Self::Strstr),
            102 => Some(Self::Strtol),
            103 => Some(Self::Strtoul),
            104 => Some(Self::Atoi),
            105 => Some(Self::Snprintf),
            106 => Some(Self::Sprintf),
            110 => Some(Self::ClockGettime),
            111 => Some(Self::Gettimeofday),
            120 => Some(Self::CxaAtexit),
            121 => Some(Self::CxaFinalize),
            130 => Some(Self::StackChkFail),
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
    pub signal_state: transd_rt::signals::SignalState,
    pub properties: crate::property::PropertyStore,
    pub stack_chk_guard_addr: GuestAddr,
    pub stack_chk_failed: bool,
    pub atexit_handlers: Vec<(GuestAddr, u32, GuestAddr)>,
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
            signal_state: transd_rt::signals::SignalState::new(),
            properties: crate::property::PropertyStore::new(stub_base.add(0x1000), 0x4000),
            stack_chk_guard_addr: stub_base.add(0x700),
            stack_chk_failed: false,
            atexit_handlers: Vec::new(),
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

            // Signal Handling (POSIX / Bionic)
            ("sigaction", BionicFuncId::Sigaction),
            ("sigprocmask", BionicFuncId::Sigprocmask),
            ("sigaltstack", BionicFuncId::Sigaltstack),
            ("raise", BionicFuncId::Raise),
            ("__rt_sigreturn", BionicFuncId::RtSigreturn),

            // System Properties
            ("__system_property_get", BionicFuncId::SystemPropertyGet),
            ("__system_property_find", BionicFuncId::SystemPropertyFind),
            ("__system_property_read", BionicFuncId::SystemPropertyRead),

            // Additional C runtime & Memory
            ("memmove", BionicFuncId::Memmove),
            ("strncmp", BionicFuncId::Strncmp),
            ("strncpy", BionicFuncId::Strncpy),
            ("strcat", BionicFuncId::Strcat),
            ("strncat", BionicFuncId::Strncat),
            ("strchr", BionicFuncId::Strchr),
            ("strrchr", BionicFuncId::Strrchr),
            ("strstr", BionicFuncId::Strstr),
            ("strtol", BionicFuncId::Strtol),
            ("strtoul", BionicFuncId::Strtoul),
            ("atoi", BionicFuncId::Atoi),
            ("snprintf", BionicFuncId::Snprintf),
            ("sprintf", BionicFuncId::Sprintf),

            // POSIX Timing
            ("clock_gettime", BionicFuncId::ClockGettime),
            ("gettimeofday", BionicFuncId::Gettimeofday),

            // C++ ABI & Stack Protector
            ("__cxa_atexit", BionicFuncId::CxaAtexit),
            ("__cxa_finalize", BionicFuncId::CxaFinalize),
            ("__stack_chk_fail", BionicFuncId::StackChkFail),
        ];

        for (name, id) in funcs {
            let addr = self.stub_base.add((id as u32) * 8);
            self.symbol_table.insert(name.to_string(), addr);
        }

        // Export __stack_chk_guard canary variable
        self.symbol_table.insert("__stack_chk_guard".to_string(), self.stack_chk_guard_addr);
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
            BionicFuncId::Sigaction,
            BionicFuncId::Sigprocmask,
            BionicFuncId::Sigaltstack,
            BionicFuncId::Raise,
            BionicFuncId::RtSigreturn,
            BionicFuncId::SystemPropertyGet,
            BionicFuncId::SystemPropertyFind,
            BionicFuncId::SystemPropertyRead,
            BionicFuncId::Memmove,
            BionicFuncId::Strncmp,
            BionicFuncId::Strncpy,
            BionicFuncId::Strcat,
            BionicFuncId::Strncat,
            BionicFuncId::Strchr,
            BionicFuncId::Strrchr,
            BionicFuncId::Strstr,
            BionicFuncId::Strtol,
            BionicFuncId::Strtoul,
            BionicFuncId::Atoi,
            BionicFuncId::Snprintf,
            BionicFuncId::Sprintf,
            BionicFuncId::ClockGettime,
            BionicFuncId::Gettimeofday,
            BionicFuncId::CxaAtexit,
            BionicFuncId::CxaFinalize,
            BionicFuncId::StackChkFail,
        ] {
            let addr = self.stub_base.add((id as u32) * 8);
            let svc_code = 0xEF00_0000 | (BIONIC_SVC_MAGIC | (id as u32)); // SVC #(BIONIC_SVC_MAGIC | id)
            let bx_lr = 0xE12F_FF1E; // BX lr

            mem.write_u32(addr, svc_code)?;
            mem.write_u32(addr.add(4), bx_lr)?;
        }
        // Initialize stack protector canary word
        mem.write_u32(self.stack_chk_guard_addr, 0x000A_0DFF)?;
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
            BionicFuncId::Sigaction => {
                let sig = cpu.reg(Reg::R0);
                let act_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let oldact_ptr = GuestAddr::new(cpu.reg(Reg::R2));

                let new_act = if act_ptr.as_u32() != 0 {
                    match transd_rt::signals::GuestSigaction::read_from_mem(mem, act_ptr, 8) {
                        Ok(a) => Some(a),
                        Err(_) => {
                            cpu.set_reg(Reg::R0, (-14i32) as u32);
                            return Ok(true);
                        }
                    }
                } else {
                    None
                };

                match self.signal_state.set_action(sig, new_act) {
                    Ok(old_act) => {
                        if oldact_ptr.as_u32() != 0 {
                            if old_act.write_to_mem(mem, oldact_ptr, 8).is_err() {
                                cpu.set_reg(Reg::R0, (-14i32) as u32);
                                return Ok(true);
                            }
                        }
                        cpu.set_reg(Reg::R0, 0);
                    }
                    Err(err) => {
                        cpu.set_reg(Reg::R0, err as u32);
                    }
                }
            }
            BionicFuncId::Sigprocmask => {
                let how = cpu.reg(Reg::R0);
                let set_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let oldset_ptr = GuestAddr::new(cpu.reg(Reg::R2));

                let set = if set_ptr.as_u32() != 0 {
                    let low = match mem.read_u32(set_ptr) {
                        Ok(v) => v as u64,
                        Err(_) => {
                            cpu.set_reg(Reg::R0, (-14i32) as u32);
                            return Ok(true);
                        }
                    };
                    let high = match mem.read_u32(set_ptr.add(4)) {
                        Ok(v) => v as u64,
                        Err(_) => {
                            cpu.set_reg(Reg::R0, (-14i32) as u32);
                            return Ok(true);
                        }
                    };
                    Some((high << 32) | low)
                } else {
                    None
                };

                match self.signal_state.sigprocmask(how, set) {
                    Ok(old_mask) => {
                        if oldset_ptr.as_u32() != 0 {
                            if mem.write_u32(oldset_ptr, old_mask as u32).is_err()
                                || mem.write_u32(oldset_ptr.add(4), (old_mask >> 32) as u32).is_err()
                            {
                                cpu.set_reg(Reg::R0, (-14i32) as u32);
                                return Ok(true);
                            }
                        }
                        cpu.set_reg(Reg::R0, 0);
                    }
                    Err(err) => {
                        cpu.set_reg(Reg::R0, err as u32);
                    }
                }
            }
            BionicFuncId::Sigaltstack => {
                let ss_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let oss_ptr = GuestAddr::new(cpu.reg(Reg::R1));

                let new_ss = if ss_ptr.as_u32() != 0 {
                    match transd_rt::signals::GuestStackT::read_from_mem(mem, ss_ptr) {
                        Ok(ss) => Some(ss),
                        Err(_) => {
                            cpu.set_reg(Reg::R0, (-14i32) as u32);
                            return Ok(true);
                        }
                    }
                } else {
                    None
                };

                match self.signal_state.sigaltstack(new_ss, cpu.sp()) {
                    Ok(old_ss) => {
                        if oss_ptr.as_u32() != 0 {
                            if old_ss.write_to_mem(mem, oss_ptr).is_err() {
                                cpu.set_reg(Reg::R0, (-14i32) as u32);
                                return Ok(true);
                            }
                        }
                        cpu.set_reg(Reg::R0, 0);
                    }
                    Err(err) => {
                        cpu.set_reg(Reg::R0, err as u32);
                    }
                }
            }
            BionicFuncId::Raise => {
                let sig = cpu.reg(Reg::R0);
                let old_pc = cpu.pc();
                cpu.set_pc(old_pc.add(4)); // Advance past SVC so sigreturn resumes at BX lr
                let rt_sigreturn_stub = self.stub_base.add((BionicFuncId::RtSigreturn as u32) * 8);
                match self.signal_state.deliver_signal(sig, None, cpu, mem, Some(rt_sigreturn_stub)) {
                    Ok(true) => {
                        // Signal delivered: CPU state (PC, SP, LR, R0-R2) adjusted to run handler
                    }
                    Ok(false) => {
                        cpu.set_pc(old_pc);
                        cpu.set_reg(Reg::R0, 0);
                    }
                    Err(_) => {
                        cpu.set_pc(old_pc);
                        cpu.set_reg(Reg::R0, (-14i32) as u32);
                    }
                }
            }
            BionicFuncId::RtSigreturn => {
                match self.signal_state.restore_sigreturn(cpu, mem) {
                    Ok(()) => {}
                    Err(_) => {
                        cpu.set_reg(Reg::R0, (-14i32) as u32);
                    }
                }
            }
            BionicFuncId::SystemPropertyGet => {
                let name_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let value_out = GuestAddr::new(cpu.reg(Reg::R1));
                let name = Self::read_c_string(mem, name_addr)?;
                let len = self.properties.system_property_get(&name, value_out, mem)?;
                cpu.set_reg(Reg::R0, len as u32);
            }
            BionicFuncId::SystemPropertyFind => {
                let name_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let name = Self::read_c_string(mem, name_addr)?;
                let pi_addr = self.properties.system_property_find(&name, mem)?;
                cpu.set_reg(Reg::R0, pi_addr.as_u32());
            }
            BionicFuncId::SystemPropertyRead => {
                let pi_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let name_out = GuestAddr::new(cpu.reg(Reg::R1));
                let val_out = GuestAddr::new(cpu.reg(Reg::R2));
                let len = self.properties.system_property_read(pi_addr, name_out, val_out, mem)?;
                cpu.set_reg(Reg::R0, len as u32);
            }
            BionicFuncId::Memmove => {
                let dst = GuestAddr::new(cpu.reg(Reg::R0));
                let src = GuestAddr::new(cpu.reg(Reg::R1));
                let count = cpu.reg(Reg::R2) as usize;
                let mut buf = vec![0u8; count];
                mem.read_bytes(src, &mut buf)?;
                mem.write_bytes(dst, &buf)?;
                cpu.set_reg(Reg::R0, dst.as_u32());
            }
            BionicFuncId::Strncmp => {
                let s1_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let s2_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let n = cpu.reg(Reg::R2) as usize;
                let mut diff = 0i32;
                for i in 0..n {
                    let b1 = mem.read_u8(s1_addr.add(i as u32))?;
                    let b2 = mem.read_u8(s2_addr.add(i as u32))?;
                    if b1 != b2 {
                        diff = (b1 as i32) - (b2 as i32);
                        break;
                    }
                    if b1 == 0 {
                        break;
                    }
                }
                cpu.set_reg(Reg::R0, diff as u32);
            }
            BionicFuncId::Strncpy => {
                let dst_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let src_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let n = cpu.reg(Reg::R2) as usize;
                let mut reached_null = false;
                for i in 0..n {
                    let b = if reached_null {
                        0
                    } else {
                        let byte = mem.read_u8(src_addr.add(i as u32))?;
                        if byte == 0 {
                            reached_null = true;
                        }
                        byte
                    };
                    mem.write_u8(dst_addr.add(i as u32), b)?;
                }
                cpu.set_reg(Reg::R0, dst_addr.as_u32());
            }
            BionicFuncId::Strcat => {
                let dst_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let src_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let mut dst_len = 0u32;
                while mem.read_u8(dst_addr.add(dst_len))? != 0 {
                    dst_len += 1;
                }
                let mut src_idx = 0u32;
                loop {
                    let b = mem.read_u8(src_addr.add(src_idx))?;
                    mem.write_u8(dst_addr.add(dst_len + src_idx), b)?;
                    if b == 0 {
                        break;
                    }
                    src_idx += 1;
                }
                cpu.set_reg(Reg::R0, dst_addr.as_u32());
            }
            BionicFuncId::Strncat => {
                let dst_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let src_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let n = cpu.reg(Reg::R2) as u32;
                let mut dst_len = 0u32;
                while mem.read_u8(dst_addr.add(dst_len))? != 0 {
                    dst_len += 1;
                }
                let mut i = 0u32;
                while i < n {
                    let b = mem.read_u8(src_addr.add(i))?;
                    if b == 0 {
                        break;
                    }
                    mem.write_u8(dst_addr.add(dst_len + i), b)?;
                    i += 1;
                }
                mem.write_u8(dst_addr.add(dst_len + i), 0)?;
                cpu.set_reg(Reg::R0, dst_addr.as_u32());
            }
            BionicFuncId::Strchr => {
                let s_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let c = (cpu.reg(Reg::R1) & 0xFF) as u8;
                let mut idx = 0u32;
                let mut found = 0u32;
                loop {
                    let b = mem.read_u8(s_addr.add(idx))?;
                    if b == c {
                        found = s_addr.add(idx).as_u32();
                        break;
                    }
                    if b == 0 {
                        break;
                    }
                    idx += 1;
                }
                cpu.set_reg(Reg::R0, found);
            }
            BionicFuncId::Strrchr => {
                let s_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let c = (cpu.reg(Reg::R1) & 0xFF) as u8;
                let mut idx = 0u32;
                let mut last_found = 0u32;
                loop {
                    let b = mem.read_u8(s_addr.add(idx))?;
                    if b == c {
                        last_found = s_addr.add(idx).as_u32();
                    }
                    if b == 0 {
                        break;
                    }
                    idx += 1;
                }
                cpu.set_reg(Reg::R0, last_found);
            }
            BionicFuncId::Strstr => {
                let haystack_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let needle_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let haystack = Self::read_c_string(mem, haystack_addr)?;
                let needle = Self::read_c_string(mem, needle_addr)?;
                let res = if needle.is_empty() {
                    haystack_addr.as_u32()
                } else if let Some(pos) = haystack.find(&needle) {
                    haystack_addr.add(pos as u32).as_u32()
                } else {
                    0
                };
                cpu.set_reg(Reg::R0, res);
            }
            BionicFuncId::Strtol => {
                let s_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let endptr_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let base = cpu.reg(Reg::R2);
                let s = Self::read_c_string(mem, s_addr)?;
                let trimmed = s.trim_start();
                let consumed_ws = s.len() - trimmed.len();
                let (res, consumed) = parse_strtol(trimmed, base);
                if endptr_addr.as_u32() != 0 {
                    mem.write_u32(endptr_addr, s_addr.as_u32() + (consumed_ws + consumed) as u32)?;
                }
                cpu.set_reg(Reg::R0, res as u32);
            }
            BionicFuncId::Strtoul => {
                let s_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let endptr_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let base = cpu.reg(Reg::R2);
                let s = Self::read_c_string(mem, s_addr)?;
                let trimmed = s.trim_start();
                let consumed_ws = s.len() - trimmed.len();
                let (res, consumed) = parse_strtoul(trimmed, base);
                if endptr_addr.as_u32() != 0 {
                    mem.write_u32(endptr_addr, s_addr.as_u32() + (consumed_ws + consumed) as u32)?;
                }
                cpu.set_reg(Reg::R0, res);
            }
            BionicFuncId::Atoi => {
                let s_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let s = Self::read_c_string(mem, s_addr)?;
                let val = s.trim().parse::<i32>().unwrap_or(0);
                cpu.set_reg(Reg::R0, val as u32);
            }
            BionicFuncId::Snprintf => {
                let buf_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let size = cpu.reg(Reg::R1) as usize;
                let fmt_addr = GuestAddr::new(cpu.reg(Reg::R2));
                let fmt = Self::read_c_string(mem, fmt_addr)?;
                let r3 = cpu.reg(Reg::R3);
                let sp = GuestAddr::new(cpu.reg(Reg::SP));
                let formatted = format_c_string_args(&fmt, &[r3], sp, mem)?;
                let bytes = formatted.as_bytes();
                let total_len = bytes.len();
                if size > 0 && buf_addr.as_u32() != 0 {
                    let to_copy = std::cmp::min(total_len, size - 1);
                    mem.write_bytes(buf_addr, &bytes[..to_copy])?;
                    mem.write_u8(buf_addr.add(to_copy as u32), 0)?;
                }
                cpu.set_reg(Reg::R0, total_len as u32);
            }
            BionicFuncId::Sprintf => {
                let buf_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let fmt_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let fmt = Self::read_c_string(mem, fmt_addr)?;
                let r2 = cpu.reg(Reg::R2);
                let r3 = cpu.reg(Reg::R3);
                let sp = GuestAddr::new(cpu.reg(Reg::SP));
                let formatted = format_c_string_args(&fmt, &[r2, r3], sp, mem)?;
                let bytes = formatted.as_bytes();
                let total_len = bytes.len();
                if buf_addr.as_u32() != 0 {
                    mem.write_bytes(buf_addr, bytes)?;
                    mem.write_u8(buf_addr.add(total_len as u32), 0)?;
                }
                cpu.set_reg(Reg::R0, total_len as u32);
            }
            BionicFuncId::ClockGettime => {
                let _clk_id = cpu.reg(Reg::R0);
                let tp = GuestAddr::new(cpu.reg(Reg::R1));
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                if tp.as_u32() != 0 {
                    mem.write_u32(tp, now.as_secs() as u32)?;
                    mem.write_u32(tp.add(4), now.subsec_nanos())?;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::Gettimeofday => {
                let tv = GuestAddr::new(cpu.reg(Reg::R0));
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                if tv.as_u32() != 0 {
                    mem.write_u32(tv, now.as_secs() as u32)?;
                    mem.write_u32(tv.add(4), now.subsec_micros())?;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::CxaAtexit => {
                let func = GuestAddr::new(cpu.reg(Reg::R0));
                let arg = cpu.reg(Reg::R1);
                let dso = GuestAddr::new(cpu.reg(Reg::R2));
                self.atexit_handlers.push((func, arg, dso));
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::CxaFinalize => {
                let dso = GuestAddr::new(cpu.reg(Reg::R0));
                if dso.as_u32() == 0 {
                    self.atexit_handlers.clear();
                } else {
                    self.atexit_handlers.retain(|(_, _, d)| *d != dso);
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::StackChkFail => {
                self.stack_chk_failed = true;
                self.logs.push(LogMessage {
                    priority: 6,
                    tag: "DEBUG".to_string(),
                    text: "*** stack smashing detected ***: terminated".to_string(),
                });
                return Err(MemoryError::Unmapped(GuestAddr::new(0xDEAD_CAFE)));
            }
            _ => {}
        }

        Ok(true)
    }

    fn read_c_string(mem: &(impl Memory + ?Sized), addr: GuestAddr) -> Result<String, MemoryError> {
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

fn format_c_string_args(
    fmt: &str,
    args: &[u32],
    extra_sp: GuestAddr,
    mem: &(impl Memory + ?Sized),
) -> Result<String, MemoryError> {
    let mut out = String::new();
    let mut chars = fmt.chars().peekable();
    let mut arg_idx = 0usize;

    let next_arg = |idx: &mut usize| -> Result<u32, MemoryError> {
        let val = if *idx < args.len() {
            args[*idx]
        } else {
            let offset = (*idx - args.len()) as u32 * 4;
            mem.read_u32(extra_sp.add(offset))?
        };
        *idx += 1;
        Ok(val)
    };

    while let Some(ch) = chars.next() {
        if ch == '%' {
            match chars.next() {
                Some('%') => out.push('%'),
                Some('s') => {
                    let addr = GuestAddr::new(next_arg(&mut arg_idx)?);
                    let s = BionicBridge::read_c_string(mem, addr)?;
                    out.push_str(&s);
                }
                Some('d') | Some('i') => {
                    let val = next_arg(&mut arg_idx)? as i32;
                    out.push_str(&val.to_string());
                }
                Some('u') => {
                    let val = next_arg(&mut arg_idx)?;
                    out.push_str(&val.to_string());
                }
                Some('x') => {
                    let val = next_arg(&mut arg_idx)?;
                    out.push_str(&format!("{:x}", val));
                }
                Some('X') => {
                    let val = next_arg(&mut arg_idx)?;
                    out.push_str(&format!("{:X}", val));
                }
                Some('p') => {
                    let val = next_arg(&mut arg_idx)?;
                    out.push_str(&format!("0x{:08x}", val));
                }
                Some('c') => {
                    let val = (next_arg(&mut arg_idx)? & 0xFF) as u8;
                    out.push(val as char);
                }
                Some(other) => {
                    out.push('%');
                    out.push(other);
                }
                None => out.push('%'),
            }
        } else {
            out.push(ch);
        }
    }
    Ok(out)
}

fn parse_strtol(s: &str, base: u32) -> (i32, usize) {
    let s_bytes = s.as_bytes();
    if s_bytes.is_empty() {
        return (0, 0);
    }
    let (is_neg, start_idx) = match s_bytes[0] {
        b'-' => (true, 1),
        b'+' => (false, 1),
        _ => (false, 0),
    };
    let remaining = &s[start_idx..];
    let radix = if base == 0 {
        if remaining.starts_with("0x") || remaining.starts_with("0X") {
            16
        } else if remaining.starts_with('0') && remaining.len() > 1 {
            8
        } else {
            10
        }
    } else {
        base
    };
    let to_parse = if radix == 16 && (remaining.starts_with("0x") || remaining.starts_with("0X")) {
        &remaining[2..]
    } else {
        remaining
    };
    let mut consumed = 0;
    for ch in to_parse.chars() {
        if ch.is_digit(radix) {
            consumed += 1;
        } else {
            break;
        }
    }
    let full_consumed = (s.len() - to_parse.len()) + consumed;
    let num_slice = &to_parse[..consumed];
    let val = i64::from_str_radix(num_slice, radix).unwrap_or(0);
    let final_val = if is_neg { -val } else { val };
    (final_val as i32, full_consumed)
}

fn parse_strtoul(s: &str, base: u32) -> (u32, usize) {
    let (val, consumed) = parse_strtol(s, base);
    (val as u32, consumed)
}
