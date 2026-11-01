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

    // Thread-Local Storage Keys (pthread_key_t)
    PthreadKeyCreate = 140,
    PthreadKeyDelete = 141,
    PthreadSetspecific = 142,
    PthreadGetspecific = 143,

    // Condition Variables (pthread_cond_t)
    PthreadCondInit = 150,
    PthreadCondWait = 151,
    PthreadCondTimedwait = 152,
    PthreadCondSignal = 153,
    PthreadCondBroadcast = 154,
    PthreadCondDestroy = 155,

    // Read-Write Locks (pthread_rwlock_t)
    PthreadRwlockInit = 160,
    PthreadRwlockRdlock = 161,
    PthreadRwlockWrlock = 162,
    PthreadRwlockUnlock = 163,
    PthreadRwlockDestroy = 164,

    // Process & Thread Identity
    Getpid = 170,
    Gettid = 171,
    Getuid = 172,
    Geteuid = 173,
    Getgid = 174,
    Getegid = 175,

    // Environment & Scheduling
    Getenv = 180,
    Setenv = 181,
    SchedYield = 182,
    Nanosleep = 183,
    Usleep = 184,

    // POSIX Semaphores (semaphore.h)
    SemInit = 190,
    SemWait = 191,
    SemTrywait = 192,
    SemPost = 193,
    SemGetvalue = 194,
    SemDestroy = 195,

    // Thread & Mutex Attributes & Detach (pthread.h)
    PthreadAttrInit = 200,
    PthreadAttrDestroy = 201,
    PthreadAttrSetstacksize = 202,
    PthreadAttrGetstacksize = 203,
    PthreadAttrSetdetachstate = 204,
    PthreadDetach = 205,
    PthreadMutexattrInit = 206,
    PthreadMutexattrDestroy = 207,
    PthreadMutexattrSettype = 208,

    // Exception Unwinding & Error Strings
    GnuUnwindFindExidx = 210,
    Strerror = 211,
    StrerrorR = 212,

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
            140 => Some(Self::PthreadKeyCreate),
            141 => Some(Self::PthreadKeyDelete),
            142 => Some(Self::PthreadSetspecific),
            143 => Some(Self::PthreadGetspecific),
            150 => Some(Self::PthreadCondInit),
            151 => Some(Self::PthreadCondWait),
            152 => Some(Self::PthreadCondTimedwait),
            153 => Some(Self::PthreadCondSignal),
            154 => Some(Self::PthreadCondBroadcast),
            155 => Some(Self::PthreadCondDestroy),
            160 => Some(Self::PthreadRwlockInit),
            161 => Some(Self::PthreadRwlockRdlock),
            162 => Some(Self::PthreadRwlockWrlock),
            163 => Some(Self::PthreadRwlockUnlock),
            164 => Some(Self::PthreadRwlockDestroy),
            170 => Some(Self::Getpid),
            171 => Some(Self::Gettid),
            172 => Some(Self::Getuid),
            173 => Some(Self::Geteuid),
            174 => Some(Self::Getgid),
            175 => Some(Self::Getegid),
            180 => Some(Self::Getenv),
            181 => Some(Self::Setenv),
            182 => Some(Self::SchedYield),
            183 => Some(Self::Nanosleep),
            184 => Some(Self::Usleep),
            190 => Some(Self::SemInit),
            191 => Some(Self::SemWait),
            192 => Some(Self::SemTrywait),
            193 => Some(Self::SemPost),
            194 => Some(Self::SemGetvalue),
            195 => Some(Self::SemDestroy),
            200 => Some(Self::PthreadAttrInit),
            201 => Some(Self::PthreadAttrDestroy),
            202 => Some(Self::PthreadAttrSetstacksize),
            203 => Some(Self::PthreadAttrGetstacksize),
            204 => Some(Self::PthreadAttrSetdetachstate),
            205 => Some(Self::PthreadDetach),
            206 => Some(Self::PthreadMutexattrInit),
            207 => Some(Self::PthreadMutexattrDestroy),
            208 => Some(Self::PthreadMutexattrSettype),
            210 => Some(Self::GnuUnwindFindExidx),
            211 => Some(Self::Strerror),
            212 => Some(Self::StrerrorR),
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
    pub strerror_addr: GuestAddr,
    pub signal_state: transd_rt::signals::SignalState,
    pub properties: crate::property::PropertyStore,
    pub stack_chk_guard_addr: GuestAddr,
    pub stack_chk_failed: bool,
    pub atexit_handlers: Vec<(GuestAddr, u32, GuestAddr)>,
    pub pthread_keys: HashMap<u32, Option<GuestAddr>>,
    pub pthread_specific: HashMap<(u32, u32), u32>,
    pub next_key_id: u32,
    pub env_vars: HashMap<String, String>,
    pub env_addrs: HashMap<String, GuestAddr>,
    pub pid: u32,
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
            strerror_addr: stub_base.add(0x900),
            signal_state: transd_rt::signals::SignalState::new(),
            properties: crate::property::PropertyStore::new(stub_base.add(0x1000), 0x4000),
            stack_chk_guard_addr: stub_base.add(0x700),
            stack_chk_failed: false,
            atexit_handlers: Vec::new(),
            pthread_keys: HashMap::new(),
            pthread_specific: HashMap::new(),
            next_key_id: 1,
            env_vars: {
                let mut env = HashMap::new();
                env.insert("ANDROID_DATA".to_string(), "/data".to_string());
                env.insert("ANDROID_ROOT".to_string(), "/system".to_string());
                env.insert("PATH".to_string(), "/sbin:/system/sbin:/system/bin:/system/xbin".to_string());
                env.insert("TMPDIR".to_string(), "/data/local/tmp".to_string());
                env.insert("LD_LIBRARY_PATH".to_string(), "/system/lib:/vendor/lib".to_string());
                env
            },
            env_addrs: HashMap::new(),
            pid: 1000,
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

            // Thread-Local Storage Keys
            ("pthread_key_create", BionicFuncId::PthreadKeyCreate),
            ("pthread_key_delete", BionicFuncId::PthreadKeyDelete),
            ("pthread_setspecific", BionicFuncId::PthreadSetspecific),
            ("pthread_getspecific", BionicFuncId::PthreadGetspecific),

            // Condition Variables
            ("pthread_cond_init", BionicFuncId::PthreadCondInit),
            ("pthread_cond_wait", BionicFuncId::PthreadCondWait),
            ("pthread_cond_timedwait", BionicFuncId::PthreadCondTimedwait),
            ("pthread_cond_signal", BionicFuncId::PthreadCondSignal),
            ("pthread_cond_broadcast", BionicFuncId::PthreadCondBroadcast),
            ("pthread_cond_destroy", BionicFuncId::PthreadCondDestroy),

            // Read-Write Locks
            ("pthread_rwlock_init", BionicFuncId::PthreadRwlockInit),
            ("pthread_rwlock_rdlock", BionicFuncId::PthreadRwlockRdlock),
            ("pthread_rwlock_wrlock", BionicFuncId::PthreadRwlockWrlock),
            ("pthread_rwlock_unlock", BionicFuncId::PthreadRwlockUnlock),
            ("pthread_rwlock_destroy", BionicFuncId::PthreadRwlockDestroy),

            // Process & Thread Identity
            ("getpid", BionicFuncId::Getpid),
            ("gettid", BionicFuncId::Gettid),
            ("getuid", BionicFuncId::Getuid),
            ("geteuid", BionicFuncId::Geteuid),
            ("getgid", BionicFuncId::Getgid),
            ("getegid", BionicFuncId::Getegid),

            // Environment & Scheduling
            ("getenv", BionicFuncId::Getenv),
            ("setenv", BionicFuncId::Setenv),
            ("sched_yield", BionicFuncId::SchedYield),
            ("nanosleep", BionicFuncId::Nanosleep),
            ("usleep", BionicFuncId::Usleep),

            // POSIX Semaphores
            ("sem_init", BionicFuncId::SemInit),
            ("sem_wait", BionicFuncId::SemWait),
            ("sem_trywait", BionicFuncId::SemTrywait),
            ("sem_post", BionicFuncId::SemPost),
            ("sem_getvalue", BionicFuncId::SemGetvalue),
            ("sem_destroy", BionicFuncId::SemDestroy),

            // Thread & Mutex Attributes & Detach
            ("pthread_attr_init", BionicFuncId::PthreadAttrInit),
            ("pthread_attr_destroy", BionicFuncId::PthreadAttrDestroy),
            ("pthread_attr_setstacksize", BionicFuncId::PthreadAttrSetstacksize),
            ("pthread_attr_getstacksize", BionicFuncId::PthreadAttrGetstacksize),
            ("pthread_attr_setdetachstate", BionicFuncId::PthreadAttrSetdetachstate),
            ("pthread_detach", BionicFuncId::PthreadDetach),
            ("pthread_mutexattr_init", BionicFuncId::PthreadMutexattrInit),
            ("pthread_mutexattr_destroy", BionicFuncId::PthreadMutexattrDestroy),
            ("pthread_mutexattr_settype", BionicFuncId::PthreadMutexattrSettype),

            // Exception Unwinding & Error Strings
            ("__gnu_Unwind_Find_exidx", BionicFuncId::GnuUnwindFindExidx),
            ("strerror", BionicFuncId::Strerror),
            ("strerror_r", BionicFuncId::StrerrorR),
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
            BionicFuncId::PthreadKeyCreate,
            BionicFuncId::PthreadKeyDelete,
            BionicFuncId::PthreadSetspecific,
            BionicFuncId::PthreadGetspecific,
            BionicFuncId::PthreadCondInit,
            BionicFuncId::PthreadCondWait,
            BionicFuncId::PthreadCondTimedwait,
            BionicFuncId::PthreadCondSignal,
            BionicFuncId::PthreadCondBroadcast,
            BionicFuncId::PthreadCondDestroy,
            BionicFuncId::PthreadRwlockInit,
            BionicFuncId::PthreadRwlockRdlock,
            BionicFuncId::PthreadRwlockWrlock,
            BionicFuncId::PthreadRwlockUnlock,
            BionicFuncId::PthreadRwlockDestroy,
            BionicFuncId::Getpid,
            BionicFuncId::Gettid,
            BionicFuncId::Getuid,
            BionicFuncId::Geteuid,
            BionicFuncId::Getgid,
            BionicFuncId::Getegid,
            BionicFuncId::Getenv,
            BionicFuncId::Setenv,
            BionicFuncId::SchedYield,
            BionicFuncId::Nanosleep,
            BionicFuncId::Usleep,
            BionicFuncId::SemInit,
            BionicFuncId::SemWait,
            BionicFuncId::SemTrywait,
            BionicFuncId::SemPost,
            BionicFuncId::SemGetvalue,
            BionicFuncId::SemDestroy,
            BionicFuncId::PthreadAttrInit,
            BionicFuncId::PthreadAttrDestroy,
            BionicFuncId::PthreadAttrSetstacksize,
            BionicFuncId::PthreadAttrGetstacksize,
            BionicFuncId::PthreadAttrSetdetachstate,
            BionicFuncId::PthreadDetach,
            BionicFuncId::PthreadMutexattrInit,
            BionicFuncId::PthreadMutexattrDestroy,
            BionicFuncId::PthreadMutexattrSettype,
            BionicFuncId::GnuUnwindFindExidx,
            BionicFuncId::Strerror,
            BionicFuncId::StrerrorR,
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
            BionicFuncId::PthreadKeyCreate => {
                let key_out = GuestAddr::new(cpu.reg(Reg::R0));
                let dtor = cpu.reg(Reg::R1);
                let dtor_opt = if dtor != 0 { Some(GuestAddr::new(dtor)) } else { None };
                let key = self.next_key_id;
                self.next_key_id += 1;
                self.pthread_keys.insert(key, dtor_opt);
                if key_out.as_u32() != 0 {
                    mem.write_u32(key_out, key)?;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::PthreadKeyDelete => {
                let key = cpu.reg(Reg::R0);
                self.pthread_keys.remove(&key);
                self.pthread_specific.retain(|&(_, k), _| k != key);
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::PthreadSetspecific => {
                let key = cpu.reg(Reg::R0);
                let val = cpu.reg(Reg::R1);
                if !self.pthread_keys.contains_key(&key) {
                    cpu.set_reg(Reg::R0, 22); // EINVAL
                } else {
                    self.pthread_specific.insert((self.current_thread_id, key), val);
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::PthreadGetspecific => {
                let key = cpu.reg(Reg::R0);
                let val = self.pthread_specific.get(&(self.current_thread_id, key)).copied().unwrap_or(0);
                cpu.set_reg(Reg::R0, val);
            }
            BionicFuncId::PthreadCondInit => {
                let cond_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if cond_ptr.as_u32() != 0 {
                    mem.write_u32(cond_ptr, 0)?;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::PthreadCondWait | BionicFuncId::PthreadCondTimedwait => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::PthreadCondSignal | BionicFuncId::PthreadCondBroadcast | BionicFuncId::PthreadCondDestroy => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::PthreadRwlockInit => {
                let rw_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if rw_ptr.as_u32() != 0 {
                    mem.write_u32(rw_ptr, 0)?;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::PthreadRwlockRdlock | BionicFuncId::PthreadRwlockWrlock
            | BionicFuncId::PthreadRwlockUnlock | BionicFuncId::PthreadRwlockDestroy => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::Getpid => {
                cpu.set_reg(Reg::R0, self.pid);
            }
            BionicFuncId::Gettid => {
                cpu.set_reg(Reg::R0, self.current_thread_id);
            }
            BionicFuncId::Getuid | BionicFuncId::Geteuid | BionicFuncId::Getgid | BionicFuncId::Getegid => {
                cpu.set_reg(Reg::R0, 10000); // AID_APP_START
            }
            BionicFuncId::Getenv => {
                let name_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if name_ptr.as_u32() == 0 {
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    let name = Self::read_c_string(mem, name_ptr)?;
                    if let Some(val) = self.env_vars.get(&name).cloned() {
                        let addr = if let Some(&cached_addr) = self.env_addrs.get(&name) {
                            cached_addr
                        } else {
                            let alloc_addr = self.heap_current;
                            let val_bytes = val.as_bytes();
                            let alloc_len = val_bytes.len() + 1;
                            let aligned_len = (alloc_len + 7) & !7;
                            self.heap_current = self.heap_current.add(aligned_len as u32);
                            mem.write_bytes(alloc_addr, val_bytes)?;
                            mem.write_u8(alloc_addr.add(val_bytes.len() as u32), 0)?;
                            self.env_addrs.insert(name, alloc_addr);
                            alloc_addr
                        };
                        cpu.set_reg(Reg::R0, addr.as_u32());
                    } else {
                        cpu.set_reg(Reg::R0, 0);
                    }
                }
            }
            BionicFuncId::Setenv => {
                let name_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let val_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let overwrite = cpu.reg(Reg::R2);
                if name_ptr.as_u32() == 0 || val_ptr.as_u32() == 0 {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF); // -1
                } else {
                    let name = Self::read_c_string(mem, name_ptr)?;
                    let val = Self::read_c_string(mem, val_ptr)?;

                    if overwrite != 0 || !self.env_vars.contains_key(&name) {
                        self.env_vars.insert(name.clone(), val);
                        self.env_addrs.remove(&name);
                    }
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::SchedYield => {
                std::thread::yield_now();
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::Nanosleep => {
                let req_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let rem_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if req_ptr.as_u32() != 0 {
                    let tv_sec = mem.read_u32(req_ptr)?;
                    let tv_nsec = mem.read_u32(req_ptr.add(4))?;
                    let total_nanos = (tv_sec as u64) * 1_000_000_000 + (tv_nsec as u64);
                    let sleep_nanos = total_nanos.min(10_000_000);
                    if sleep_nanos > 0 {
                        std::thread::sleep(std::time::Duration::from_nanos(sleep_nanos));
                    }
                }
                if rem_ptr.as_u32() != 0 {
                    mem.write_u32(rem_ptr, 0)?;
                    mem.write_u32(rem_ptr.add(4), 0)?;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::Usleep => {
                let usec = cpu.reg(Reg::R0) as u64;
                let sleep_micros = usec.min(10_000);
                if sleep_micros > 0 {
                    std::thread::sleep(std::time::Duration::from_micros(sleep_micros));
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::SemInit => {
                let sem_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let value = cpu.reg(Reg::R2);
                if sem_ptr.as_u32() != 0 {
                    mem.write_u32(sem_ptr, value)?;
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::SemWait => {
                let sem_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if sem_ptr.as_u32() != 0 {
                    let val = mem.read_u32(sem_ptr)?;
                    if val > 0 {
                        mem.write_u32(sem_ptr, val - 1)?;
                    }
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::SemTrywait => {
                let sem_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if sem_ptr.as_u32() != 0 {
                    let val = mem.read_u32(sem_ptr)?;
                    if val > 0 {
                        mem.write_u32(sem_ptr, val - 1)?;
                        cpu.set_reg(Reg::R0, 0);
                    } else {
                        cpu.set_reg(Reg::R0, 0xFFFF_FFFF); // -1 (EAGAIN)
                    }
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::SemPost => {
                let sem_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if sem_ptr.as_u32() != 0 {
                    let val = mem.read_u32(sem_ptr)?;
                    mem.write_u32(sem_ptr, val.saturating_add(1))?;
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::SemGetvalue => {
                let sem_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let sval_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if sem_ptr.as_u32() != 0 && sval_ptr.as_u32() != 0 {
                    let val = mem.read_u32(sem_ptr)?;
                    mem.write_u32(sval_ptr, val)?;
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::SemDestroy => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::PthreadAttrInit => {
                let attr_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if attr_ptr.as_u32() != 0 {
                    mem.write_u32(attr_ptr, 0)?; // flags / detachstate = 0 (JOINABLE)
                    mem.write_u32(attr_ptr.add(4), 0)?; // stackbase
                    mem.write_u32(attr_ptr.add(8), 1024 * 1024)?; // default stacksize = 1MB
                    mem.write_u32(attr_ptr.add(12), 4096)?; // guardsize = 4KB
                    mem.write_u32(attr_ptr.add(16), 0)?; // sched_policy
                    mem.write_u32(attr_ptr.add(20), 0)?; // sched_priority
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 22); // EINVAL
                }
            }
            BionicFuncId::PthreadAttrDestroy => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::PthreadAttrSetstacksize => {
                let attr_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let stacksize = cpu.reg(Reg::R1);
                if attr_ptr.as_u32() != 0 {
                    mem.write_u32(attr_ptr.add(8), stacksize)?;
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 22); // EINVAL
                }
            }
            BionicFuncId::PthreadAttrGetstacksize => {
                let attr_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let stacksize_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if attr_ptr.as_u32() != 0 && stacksize_ptr.as_u32() != 0 {
                    let sz = mem.read_u32(attr_ptr.add(8))?;
                    mem.write_u32(stacksize_ptr, sz)?;
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 22); // EINVAL
                }
            }
            BionicFuncId::PthreadAttrSetdetachstate => {
                let attr_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let detachstate = cpu.reg(Reg::R1);
                if attr_ptr.as_u32() != 0 {
                    mem.write_u32(attr_ptr, detachstate)?;
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 22); // EINVAL
                }
            }
            BionicFuncId::PthreadDetach => {
                let thread_id = cpu.reg(Reg::R0);
                if let Some(desc) = self.threads.get_mut(&thread_id) {
                    desc.joined = true;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::PthreadMutexattrInit => {
                let attr_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if attr_ptr.as_u32() != 0 {
                    mem.write_u32(attr_ptr, 0)?;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::PthreadMutexattrDestroy => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::PthreadMutexattrSettype => {
                let attr_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let mtype = cpu.reg(Reg::R1);
                if attr_ptr.as_u32() != 0 {
                    mem.write_u32(attr_ptr, mtype)?;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::GnuUnwindFindExidx => {
                let pc = GuestAddr::new(cpu.reg(Reg::R0));
                let pcount_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if let Some(lib) = self.dso_registry.find_by_pc(pc) {
                    if let Some(exidx_addr) = lib.exidx_addr {
                        if pcount_ptr.as_u32() != 0 {
                            mem.write_u32(pcount_ptr, lib.exidx_count as u32)?;
                        }
                        cpu.set_reg(Reg::R0, exidx_addr.as_u32());
                    } else {
                        if pcount_ptr.as_u32() != 0 {
                            mem.write_u32(pcount_ptr, 0)?;
                        }
                        cpu.set_reg(Reg::R0, 0);
                    }
                } else {
                    if pcount_ptr.as_u32() != 0 {
                        mem.write_u32(pcount_ptr, 0)?;
                    }
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::Strerror => {
                let errnum = cpu.reg(Reg::R0);
                let err_str = Self::errnum_to_str(errnum);
                let bytes = err_str.as_bytes();
                mem.write_bytes(self.strerror_addr, bytes)?;
                mem.write_u8(self.strerror_addr.add(bytes.len() as u32), 0)?;
                cpu.set_reg(Reg::R0, self.strerror_addr.as_u32());
            }
            BionicFuncId::StrerrorR => {
                let errnum = cpu.reg(Reg::R0);
                let buf_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let buflen = cpu.reg(Reg::R2);
                if buf_ptr.as_u32() == 0 || buflen == 0 {
                    cpu.set_reg(Reg::R0, 22); // EINVAL
                } else {
                    let err_str = Self::errnum_to_str(errnum);
                    let bytes = err_str.as_bytes();
                    let copy_len = (buflen - 1).min(bytes.len() as u32) as usize;
                    mem.write_bytes(buf_ptr, &bytes[..copy_len])?;
                    mem.write_u8(buf_ptr.add(copy_len as u32), 0)?;
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            _ => {}
        }

        Ok(true)
    }

    fn errnum_to_str(errnum: u32) -> &'static str {
        match errnum {
            0 => "Success",
            1 => "Operation not permitted",
            2 => "No such file or directory",
            9 => "Bad file descriptor",
            11 => "Resource temporarily unavailable",
            12 => "Cannot allocate memory",
            13 => "Permission denied",
            14 => "Bad address",
            16 => "Device or resource busy",
            22 => "Invalid argument",
            _ => "Unknown error",
        }
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
