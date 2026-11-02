use std::collections::{HashMap, VecDeque};
use transd_core::{GuestAddr, Memory, MemoryError, Reg};
use transd_elf::{DsoRegistry, SymbolResolver};
pub use transd_elf::{RTLD_DEFAULT, RTLD_NEXT};

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

    // Dynamic Linker Iteration
    DlIteratePhdr = 220,

    // Atomic Builtins (__atomic_* / __sync_*)
    AtomicFetchAdd4 = 230,
    AtomicFetchSub4 = 231,
    AtomicFetchAnd4 = 232,
    AtomicFetchOr4 = 233,
    AtomicFetchXor4 = 234,
    AtomicLoad4 = 235,
    AtomicStore4 = 236,
    AtomicCompareExchange4 = 237,
    AtomicExchange4 = 238,

    // Sync builtins (__sync_*)
    SyncValCompareAndSwap4 = 240,
    SyncBoolCompareAndSwap4 = 241,
    SyncFetchAndAdd4 = 242,
    SyncFetchAndSub4 = 243,

    // POSIX Sockets (sys/socket.h)
    Socket = 250,
    SocketConnect = 251,
    SocketBind = 252,
    SocketListen = 253,
    SocketAccept = 254,
    SocketSend = 255,
    SocketRecv = 256,
    SocketSendto = 257,
    SocketRecvfrom = 258,
    SocketShutdown = 259,
    SocketClose = 260,
    SocketGetSockname = 261,
    SocketGetPeername = 262,
    SocketSetsockopt = 263,
    SocketGetsockopt = 264,
    Htons = 265,
    Htonl = 266,
    Ntohs = 267,
    Ntohl = 268,
    InetAton = 269,
    InetNtoa = 270,

    // Pipe & raw I/O
    Pipe = 280,
    Read = 281,
    Write = 282,

    // Extended allocator
    MallocUsableSize = 285,
    Memalign = 286,
    PosixMemalign = 287,

    // pthread barriers
    PthreadBarrierInit = 290,
    PthreadBarrierWait = 291,
    PthreadBarrierDestroy = 292,

    // High-resolution timed sleep
    ClockNanosleep = 300,

    // FD duplication
    Dup = 310,
    Dup2 = 311,

    // File-descriptor control
    Fcntl = 320,

    // I/O multiplexing
    Select = 330,
    Poll = 331,

    // Name/address resolution
    Getaddrinfo = 340,
    Freeaddrinfo = 341,
    Getnameinfo = 342,
    Gethostbyname = 343,
    GethostbynameR = 344,

    // Network interface enumeration
    Getifaddrs = 350,
    Freeifaddrs = 351,

    // Process group / session
    Setsid = 360,
    Getpgrp = 361,
    Setpgid = 362,

    // File System & Directory Operations
    Open = 370,
    Openat = 371,
    Lseek = 372,
    Lseek64 = 373,
    Stat = 374,
    Stat64 = 375,
    Fstat = 376,
    Fstat64 = 377,
    Lstat = 378,
    Lstat64 = 379,
    Fstatat = 380,
    Access = 381,
    Faccessat = 382,
    Mkdir = 383,
    Mkdirat = 384,
    Unlink = 385,
    Unlinkat = 386,
    Getcwd = 387,
    Chdir = 388,
    Readlink = 389,
    Readlinkat = 390,
    Rename = 391,
    Renameat = 392,
    Ftruncate = 393,
    Ftruncate64 = 394,

    // Extended libm (Single-precision f32)
    Atanf = 400,
    Asinf = 401,
    Acosf = 402,
    Sinhf = 403,
    Coshf = 404,
    Tanhf = 405,
    Log10f = 406,
    Log2f = 407,
    Exp2f = 408,
    Fmodf = 409,
    Roundf = 410,
    Truncf = 411,
    Hypotf = 412,
    Copysignf = 413,
    Cbrtf = 414,
    Ldexpf = 415,

    // Extended libm (Double-precision f64)
    Atan = 420,
    Asin = 421,
    Acos = 422,
    Sinh = 423,
    Cosh = 424,
    Tanh = 425,
    Log10 = 426,
    Log2 = 427,
    Exp2 = 428,
    Fmod = 429,
    Round = 430,
    Trunc = 431,
    Hypot = 432,
    Copysign = 433,
    Cbrt = 434,
    Ldexp = 435,

    // Directory enumeration
    Opendir  = 440,
    Closedir = 441,
    Readdir  = 442,
    Readdir64 = 443,
    Fdopendir = 444,
    Dirfd    = 445,
    Rewinddir = 446,
    Telldir  = 447,
    Seekdir  = 448,

    // String & Printf family (Stage 64)
    Printf    = 450,
    Fprintf   = 451,
    Sscanf    = 452,
    Vprintf   = 453,
    Vfprintf  = 454,
    Vsprintf  = 455,
    Vsnprintf = 456,
    Asprintf  = 457,
    Vasprintf = 458,
    Strtof    = 459,
    Strtod    = 460,
    Strtold   = 461,
    Strdup    = 462,
    Strndup   = 463,
    Strtok    = 464,
    StrtokR   = 465,
    Strpbrk   = 466,
    Strcspn   = 467,
    Strspn    = 468,
    Memmem    = 469,

    // Character classification & Locale / Wide-Char (Stage 65)
    Isalnum   = 470,
    Isalpha   = 471,
    Isblank   = 472,
    Iscntrl   = 473,
    Isdigit   = 474,
    Isgraph   = 475,
    Islower   = 476,
    Isprint   = 477,
    Ispunct   = 478,
    Isspace   = 479,
    Isupper   = 480,
    Isxdigit  = 481,
    Tolower   = 482,
    Toupper   = 483,
    Isascii   = 484,
    Toascii   = 485,
    Setlocale = 486,
    Localeconv = 487,
    Mbstowcs  = 488,
    Wcstombs  = 489,
    Mbtowc    = 490,
    Wctomb    = 491,
    Wcslen    = 492,
    Wcscpy    = 493,
    Wcscmp    = 494,

    // Time & Date (Stage 66)
    Time        = 500,
    Difftime    = 501,
    Clock       = 502,
    Times       = 503,
    Gmtime      = 504,
    GmtimeR     = 505,
    Localtime   = 506,
    LocaltimeR  = 507,
    Mktime      = 508,
    Asctime     = 509,
    AsctimeR    = 510,
    Ctime       = 511,
    CtimeR      = 512,
    Strftime    = 513,
    Strptime    = 514,

    // Memory-Mapped I/O (Stage 67)
    Mmap        = 520,
    Mmap64      = 521,
    Munmap      = 522,
    Madvise     = 523,
    Msync       = 524,
    Mremap      = 525,
    Mlock       = 526,
    Munlock     = 527,
    Mlockall    = 528,
    Munlockall  = 529,
    Mincore     = 530,

    // Dynamic Linker & Android Log Extensions (Stage 68)
    AndroidDlopenExt     = 540,
    Dladdr               = 541,
    Dladdr1              = 542,
    AndroidLogAssert     = 543,
    AndroidLogBufPrint   = 544,
    AndroidLogBufWrite   = 545,
    AndroidLogVprint     = 546,
    AndroidLogIsLoggable = 547,
    Assert               = 548,
    Assert2              = 549,

    // Bionic System Properties & Runtime Extensions (Stage 69)
    SystemPropertySet        = 550,
    SystemPropertyAreaInit   = 551,
    SystemPropertyAdd        = 552,
    SystemPropertyUpdate     = 553,
    SystemPropertyWait       = 554,
    SystemPropertyWaitAny    = 555,
    SystemPropertySerial     = 556,
    SystemPropertyForeach    = 557,
    AndroidSetAbortMessage   = 558,
    AndroidGetAbortMessage   = 559,

    // Exception Handling & Unwinding (Stage 70)
    UnwindRaiseException   = 560,
    UnwindForcedUnwind     = 561,
    UnwindDeleteException  = 562,
    UnwindResume           = 563,
    UnwindGetGR            = 564,
    UnwindSetGR            = 565,
    UnwindGetIP            = 566,
    UnwindSetIP            = 567,
    AeabiUnwindCppPr0      = 568,
    AeabiUnwindCppPr1      = 569,
    AeabiUnwindCppPr2      = 570,
    CxaBeginCleanup        = 571,
    CxaEndCleanup          = 572,
    UnwindBacktrace        = 573,
    UnwindComplete         = 574,

    // POSIX Network & Socket Extensions (Stage 71)
    InetNtop               = 580,
    InetPton               = 581,
    GaiStrerror            = 582,
    Getservbyname          = 583,
    Getservbyport          = 584,
    Getprotobyname         = 585,
    Getprotobynumber       = 586,
    Socketpair             = 587,
    EpollCreate            = 588,
    EpollCreate1           = 589,
    EpollCtl               = 590,
    EpollWait              = 591,
    EpollPwait             = 592,
    Pselect                = 593,
    Ppoll                  = 594,

    // High-Resolution Timers & POSIX Signals Extensions (Stage 72)
    TimerCreate          = 600,
    TimerSettime         = 601,
    TimerGettime         = 602,
    TimerGetoverrun      = 603,
    TimerDelete          = 604,
    Sigpending           = 605,
    Sigsuspend           = 606,
    Sigwait              = 607,
    Sigtimedwait         = 608,
    Sigwaitinfo          = 609,

    // Process Resource Limits & System Info (Stage 73)
    Getrlimit            = 620,
    Getrlimit64          = 621,
    Setrlimit            = 622,
    Setrlimit64          = 623,
    Prlimit              = 624,
    Prlimit64            = 625,
    Sysinfo              = 626,
    Getpagesize          = 627,
    GetNprocs            = 628,
    GetNprocsConf        = 629,
    Sysconf              = 630,

    // Extended Filesystem & Path APIs (Stage 74)
    Symlink              = 640,
    Symlinkat            = 641,
    Link                 = 642,
    Linkat               = 643,
    Chmod                = 644,
    Fchmod               = 645,
    Fchmodat             = 646,
    Chown                = 647,
    Fchown               = 648,
    Lchown               = 649,
    Fchownat             = 650,
    Mknod                = 651,
    Mknodat              = 652,
    Sync                 = 653,
    Fsync                = 654,
    Fdatasync            = 655,
    Pipe2                = 656,
    Dup3                 = 657,
    Statfs               = 658,
    Statfs64             = 659,
    Fstatfs              = 660,
    Fstatfs64            = 661,
    Statvfs              = 662,
    Fstatvfs             = 663,

    // Terminal / TTY & IOCTL APIs (Stage 75)
    Isatty               = 670,
    Ttyname              = 671,
    TtynameR             = 672,
    Tcgetattr            = 673,
    Tcsetattr            = 674,
    Tcflush              = 675,
    Tcsendbreak          = 676,
    Tcdrain              = 677,
    Tcflow               = 678,
    Cfgetispeed          = 679,
    Cfgetospeed          = 680,
    Cfsetispeed          = 681,
    Cfsetospeed          = 682,
    Cfmakeraw            = 683,
    Ioctl                = 684,

    // System Event Tracing & Android Trace (Stage 76)
    AtraceBeginBody         = 690,
    AtraceEndBody           = 691,
    AtraceAsyncBeginBody    = 692,
    AtraceAsyncEndBody      = 693,
    AtraceSetTracingEnabled = 694,
    AtraceInit              = 695,
    AtraceIntBody           = 696,
    AtraceInt64Body         = 697,
    AtraceGetEnabledTags    = 698,

    // EventFD & POSIX Asynchronous I/O APIs (Stage 77)
    Eventfd              = 710,
    EventfdRead          = 711,
    EventfdWrite         = 712,
    AioRead              = 713,
    AioWrite             = 714,
    AioError             = 715,
    AioReturn            = 716,
    AioSuspend           = 717,
    AioCancel            = 718,

    // POSIX Extended Capabilities & Credentials (Stage 78)
    Capget               = 730,
    Capset               = 731,
    Getgroups            = 732,
    Setgroups            = 733,
    Getresuid            = 734,
    Getresgid            = 735,
    Setresuid            = 736,
    Setresgid            = 737,
    Setreuid             = 738,
    Setregid             = 739,

    // CPU Affinity & Multi-core Thread Scheduling APIs (Stage 79)
    SchedSetaffinity    = 750,
    SchedGetaffinity    = 751,
    SchedGetcpu         = 752,
    SchedSetscheduler   = 753,
    SchedGetscheduler   = 754,
    SchedSetparam       = 755,
    SchedGetparam       = 756,
    SchedGetPriorityMin = 757,
    SchedGetPriorityMax = 758,
    SchedRrGetInterval  = 759,

    // POSIX Shared Memory, Anonymous Files & Android Ashmem (Stage 80)
    ShmOpen             = 770,
    ShmUnlink           = 771,
    MemfdCreate         = 772,
    AshmemCreateRegion  = 773,
    AshmemSetProtRegion = 774,
    AshmemGetProtRegion = 775,
    AshmemGetSizeRegion = 776,
    AshmemPinRegion     = 777,
    AshmemUnpinRegion   = 778,

    // Advanced Signal Masking & Extended Pthread APIs (Stage 81)
    PthreadSigmask      = 790,
    Sigqueue            = 791,
    PthreadKill         = 792,
    PthreadSetnameNp    = 793,
    PthreadGetnameNp    = 794,
    PthreadEqual        = 795,
    PthreadGetattrNp    = 796,

    // Android Memory Management & Security Log Extensions (Stage 82)
    AndroidMallopt             = 810,
    MallocInfo                 = 811,
    Mallinfo                   = 812,
    AndroidLogBwrite           = 813,
    AndroidLogSecurityBwrite   = 814,
    AndroidLogBtwrite          = 815,

    // POSIX Message Queues (Stage 83)
    MqOpen         = 830,
    MqClose        = 831,
    MqUnlink       = 832,
    MqSend         = 833,
    MqReceive      = 834,
    MqTimedsend    = 835,
    MqTimedreceive = 836,
    MqGetattr      = 837,
    MqSetattr      = 838,

    // Extended Network Interface Discovery (Stage 84)
    IfNametoindex   = 850,
    IfIndextoname   = 851,
    IfNameindex     = 852,
    IfFreenameindex = 853,

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
            220 => Some(Self::DlIteratePhdr),
            230 => Some(Self::AtomicFetchAdd4),
            231 => Some(Self::AtomicFetchSub4),
            232 => Some(Self::AtomicFetchAnd4),
            233 => Some(Self::AtomicFetchOr4),
            234 => Some(Self::AtomicFetchXor4),
            235 => Some(Self::AtomicLoad4),
            236 => Some(Self::AtomicStore4),
            237 => Some(Self::AtomicCompareExchange4),
            238 => Some(Self::AtomicExchange4),
            240 => Some(Self::SyncValCompareAndSwap4),
            241 => Some(Self::SyncBoolCompareAndSwap4),
            242 => Some(Self::SyncFetchAndAdd4),
            243 => Some(Self::SyncFetchAndSub4),
            250 => Some(Self::Socket),
            251 => Some(Self::SocketConnect),
            252 => Some(Self::SocketBind),
            253 => Some(Self::SocketListen),
            254 => Some(Self::SocketAccept),
            255 => Some(Self::SocketSend),
            256 => Some(Self::SocketRecv),
            257 => Some(Self::SocketSendto),
            258 => Some(Self::SocketRecvfrom),
            259 => Some(Self::SocketShutdown),
            260 => Some(Self::SocketClose),
            261 => Some(Self::SocketGetSockname),
            262 => Some(Self::SocketGetPeername),
            263 => Some(Self::SocketSetsockopt),
            264 => Some(Self::SocketGetsockopt),
            265 => Some(Self::Htons),
            266 => Some(Self::Htonl),
            267 => Some(Self::Ntohs),
            268 => Some(Self::Ntohl),
            269 => Some(Self::InetAton),
            270 => Some(Self::InetNtoa),
            280 => Some(Self::Pipe),
            281 => Some(Self::Read),
            282 => Some(Self::Write),
            285 => Some(Self::MallocUsableSize),
            286 => Some(Self::Memalign),
            287 => Some(Self::PosixMemalign),
            290 => Some(Self::PthreadBarrierInit),
            291 => Some(Self::PthreadBarrierWait),
            292 => Some(Self::PthreadBarrierDestroy),
            300 => Some(Self::ClockNanosleep),
            310 => Some(Self::Dup),
            311 => Some(Self::Dup2),
            320 => Some(Self::Fcntl),
            330 => Some(Self::Select),
            331 => Some(Self::Poll),
            340 => Some(Self::Getaddrinfo),
            341 => Some(Self::Freeaddrinfo),
            342 => Some(Self::Getnameinfo),
            343 => Some(Self::Gethostbyname),
            344 => Some(Self::GethostbynameR),
            350 => Some(Self::Getifaddrs),
            351 => Some(Self::Freeifaddrs),
            360 => Some(Self::Setsid),
            361 => Some(Self::Getpgrp),
            362 => Some(Self::Setpgid),
            370 => Some(Self::Open),
            371 => Some(Self::Openat),
            372 => Some(Self::Lseek),
            373 => Some(Self::Lseek64),
            374 => Some(Self::Stat),
            375 => Some(Self::Stat64),
            376 => Some(Self::Fstat),
            377 => Some(Self::Fstat64),
            378 => Some(Self::Lstat),
            379 => Some(Self::Lstat64),
            380 => Some(Self::Fstatat),
            381 => Some(Self::Access),
            382 => Some(Self::Faccessat),
            383 => Some(Self::Mkdir),
            384 => Some(Self::Mkdirat),
            385 => Some(Self::Unlink),
            386 => Some(Self::Unlinkat),
            387 => Some(Self::Getcwd),
            388 => Some(Self::Chdir),
            389 => Some(Self::Readlink),
            390 => Some(Self::Readlinkat),
            391 => Some(Self::Rename),
            392 => Some(Self::Renameat),
            393 => Some(Self::Ftruncate),
            394 => Some(Self::Ftruncate64),
            400 => Some(Self::Atanf),
            401 => Some(Self::Asinf),
            402 => Some(Self::Acosf),
            403 => Some(Self::Sinhf),
            404 => Some(Self::Coshf),
            405 => Some(Self::Tanhf),
            406 => Some(Self::Log10f),
            407 => Some(Self::Log2f),
            408 => Some(Self::Exp2f),
            409 => Some(Self::Fmodf),
            410 => Some(Self::Roundf),
            411 => Some(Self::Truncf),
            412 => Some(Self::Hypotf),
            413 => Some(Self::Copysignf),
            414 => Some(Self::Cbrtf),
            415 => Some(Self::Ldexpf),
            420 => Some(Self::Atan),
            421 => Some(Self::Asin),
            422 => Some(Self::Acos),
            423 => Some(Self::Sinh),
            424 => Some(Self::Cosh),
            425 => Some(Self::Tanh),
            426 => Some(Self::Log10),
            427 => Some(Self::Log2),
            428 => Some(Self::Exp2),
            429 => Some(Self::Fmod),
            430 => Some(Self::Round),
            431 => Some(Self::Trunc),
            432 => Some(Self::Hypot),
            433 => Some(Self::Copysign),
            434 => Some(Self::Cbrt),
            435 => Some(Self::Ldexp),
            440 => Some(Self::Opendir),
            441 => Some(Self::Closedir),
            442 => Some(Self::Readdir),
            443 => Some(Self::Readdir64),
            444 => Some(Self::Fdopendir),
            445 => Some(Self::Dirfd),
            446 => Some(Self::Rewinddir),
            447 => Some(Self::Telldir),
            448 => Some(Self::Seekdir),
            450 => Some(Self::Printf),
            451 => Some(Self::Fprintf),
            452 => Some(Self::Sscanf),
            453 => Some(Self::Vprintf),
            454 => Some(Self::Vfprintf),
            455 => Some(Self::Vsprintf),
            456 => Some(Self::Vsnprintf),
            457 => Some(Self::Asprintf),
            458 => Some(Self::Vasprintf),
            459 => Some(Self::Strtof),
            460 => Some(Self::Strtod),
            461 => Some(Self::Strtold),
            462 => Some(Self::Strdup),
            463 => Some(Self::Strndup),
            464 => Some(Self::Strtok),
            465 => Some(Self::StrtokR),
            466 => Some(Self::Strpbrk),
            467 => Some(Self::Strcspn),
            468 => Some(Self::Strspn),
            469 => Some(Self::Memmem),
            470 => Some(Self::Isalnum),
            471 => Some(Self::Isalpha),
            472 => Some(Self::Isblank),
            473 => Some(Self::Iscntrl),
            474 => Some(Self::Isdigit),
            475 => Some(Self::Isgraph),
            476 => Some(Self::Islower),
            477 => Some(Self::Isprint),
            478 => Some(Self::Ispunct),
            479 => Some(Self::Isspace),
            480 => Some(Self::Isupper),
            481 => Some(Self::Isxdigit),
            482 => Some(Self::Tolower),
            483 => Some(Self::Toupper),
            484 => Some(Self::Isascii),
            485 => Some(Self::Toascii),
            486 => Some(Self::Setlocale),
            487 => Some(Self::Localeconv),
            488 => Some(Self::Mbstowcs),
            489 => Some(Self::Wcstombs),
            490 => Some(Self::Mbtowc),
            491 => Some(Self::Wctomb),
            492 => Some(Self::Wcslen),
            493 => Some(Self::Wcscpy),
            494 => Some(Self::Wcscmp),
            500 => Some(Self::Time),
            501 => Some(Self::Difftime),
            502 => Some(Self::Clock),
            503 => Some(Self::Times),
            504 => Some(Self::Gmtime),
            505 => Some(Self::GmtimeR),
            506 => Some(Self::Localtime),
            507 => Some(Self::LocaltimeR),
            508 => Some(Self::Mktime),
            509 => Some(Self::Asctime),
            510 => Some(Self::AsctimeR),
            511 => Some(Self::Ctime),
            512 => Some(Self::CtimeR),
            513 => Some(Self::Strftime),
            514 => Some(Self::Strptime),
            520 => Some(Self::Mmap),
            521 => Some(Self::Mmap64),
            522 => Some(Self::Munmap),
            523 => Some(Self::Madvise),
            524 => Some(Self::Msync),
            525 => Some(Self::Mremap),
            526 => Some(Self::Mlock),
            527 => Some(Self::Munlock),
            528 => Some(Self::Mlockall),
            529 => Some(Self::Munlockall),
            530 => Some(Self::Mincore),
            540 => Some(Self::AndroidDlopenExt),
            541 => Some(Self::Dladdr),
            542 => Some(Self::Dladdr1),
            543 => Some(Self::AndroidLogAssert),
            544 => Some(Self::AndroidLogBufPrint),
            545 => Some(Self::AndroidLogBufWrite),
            546 => Some(Self::AndroidLogVprint),
            547 => Some(Self::AndroidLogIsLoggable),
            548 => Some(Self::Assert),
            549 => Some(Self::Assert2),
            550 => Some(Self::SystemPropertySet),
            551 => Some(Self::SystemPropertyAreaInit),
            552 => Some(Self::SystemPropertyAdd),
            553 => Some(Self::SystemPropertyUpdate),
            554 => Some(Self::SystemPropertyWait),
            555 => Some(Self::SystemPropertyWaitAny),
            556 => Some(Self::SystemPropertySerial),
            557 => Some(Self::SystemPropertyForeach),
            558 => Some(Self::AndroidSetAbortMessage),
            559 => Some(Self::AndroidGetAbortMessage),
            560 => Some(Self::UnwindRaiseException),
            561 => Some(Self::UnwindForcedUnwind),
            562 => Some(Self::UnwindDeleteException),
            563 => Some(Self::UnwindResume),
            564 => Some(Self::UnwindGetGR),
            565 => Some(Self::UnwindSetGR),
            566 => Some(Self::UnwindGetIP),
            567 => Some(Self::UnwindSetIP),
            568 => Some(Self::AeabiUnwindCppPr0),
            569 => Some(Self::AeabiUnwindCppPr1),
            570 => Some(Self::AeabiUnwindCppPr2),
            571 => Some(Self::CxaBeginCleanup),
            572 => Some(Self::CxaEndCleanup),
            573 => Some(Self::UnwindBacktrace),
            574 => Some(Self::UnwindComplete),
            580 => Some(Self::InetNtop),
            581 => Some(Self::InetPton),
            582 => Some(Self::GaiStrerror),
            583 => Some(Self::Getservbyname),
            584 => Some(Self::Getservbyport),
            585 => Some(Self::Getprotobyname),
            586 => Some(Self::Getprotobynumber),
            587 => Some(Self::Socketpair),
            588 => Some(Self::EpollCreate),
            589 => Some(Self::EpollCreate1),
            590 => Some(Self::EpollCtl),
            591 => Some(Self::EpollWait),
            592 => Some(Self::EpollPwait),
            593 => Some(Self::Pselect),
            594 => Some(Self::Ppoll),
            600 => Some(Self::TimerCreate),
            601 => Some(Self::TimerSettime),
            602 => Some(Self::TimerGettime),
            603 => Some(Self::TimerGetoverrun),
            604 => Some(Self::TimerDelete),
            605 => Some(Self::Sigpending),
            606 => Some(Self::Sigsuspend),
            607 => Some(Self::Sigwait),
            608 => Some(Self::Sigtimedwait),
            609 => Some(Self::Sigwaitinfo),
            620 => Some(Self::Getrlimit),
            621 => Some(Self::Getrlimit64),
            622 => Some(Self::Setrlimit),
            623 => Some(Self::Setrlimit64),
            624 => Some(Self::Prlimit),
            625 => Some(Self::Prlimit64),
            626 => Some(Self::Sysinfo),
            627 => Some(Self::Getpagesize),
            628 => Some(Self::GetNprocs),
            629 => Some(Self::GetNprocsConf),
            630 => Some(Self::Sysconf),
            640 => Some(Self::Symlink),
            641 => Some(Self::Symlinkat),
            642 => Some(Self::Link),
            643 => Some(Self::Linkat),
            644 => Some(Self::Chmod),
            645 => Some(Self::Fchmod),
            646 => Some(Self::Fchmodat),
            647 => Some(Self::Chown),
            648 => Some(Self::Fchown),
            649 => Some(Self::Lchown),
            650 => Some(Self::Fchownat),
            651 => Some(Self::Mknod),
            652 => Some(Self::Mknodat),
            653 => Some(Self::Sync),
            654 => Some(Self::Fsync),
            655 => Some(Self::Fdatasync),
            656 => Some(Self::Pipe2),
            657 => Some(Self::Dup3),
            658 => Some(Self::Statfs),
            659 => Some(Self::Statfs64),
            660 => Some(Self::Fstatfs),
            661 => Some(Self::Fstatfs64),
            662 => Some(Self::Statvfs),
            663 => Some(Self::Fstatvfs),
            670 => Some(Self::Isatty),
            671 => Some(Self::Ttyname),
            672 => Some(Self::TtynameR),
            673 => Some(Self::Tcgetattr),
            674 => Some(Self::Tcsetattr),
            675 => Some(Self::Tcflush),
            676 => Some(Self::Tcsendbreak),
            677 => Some(Self::Tcdrain),
            678 => Some(Self::Tcflow),
            679 => Some(Self::Cfgetispeed),
            680 => Some(Self::Cfgetospeed),
            681 => Some(Self::Cfsetispeed),
            682 => Some(Self::Cfsetospeed),
            683 => Some(Self::Cfmakeraw),
            684 => Some(Self::Ioctl),
            690 => Some(Self::AtraceBeginBody),
            691 => Some(Self::AtraceEndBody),
            692 => Some(Self::AtraceAsyncBeginBody),
            693 => Some(Self::AtraceAsyncEndBody),
            694 => Some(Self::AtraceSetTracingEnabled),
            695 => Some(Self::AtraceInit),
            696 => Some(Self::AtraceIntBody),
            697 => Some(Self::AtraceInt64Body),
            698 => Some(Self::AtraceGetEnabledTags),
            710 => Some(Self::Eventfd),
            711 => Some(Self::EventfdRead),
            712 => Some(Self::EventfdWrite),
            713 => Some(Self::AioRead),
            714 => Some(Self::AioWrite),
            715 => Some(Self::AioError),
            716 => Some(Self::AioReturn),
            717 => Some(Self::AioSuspend),
            718 => Some(Self::AioCancel),
            730 => Some(Self::Capget),
            731 => Some(Self::Capset),
            732 => Some(Self::Getgroups),
            733 => Some(Self::Setgroups),
            734 => Some(Self::Getresuid),
            735 => Some(Self::Getresgid),
            736 => Some(Self::Setresuid),
            737 => Some(Self::Setresgid),
            738 => Some(Self::Setreuid),
            739 => Some(Self::Setregid),
            750 => Some(Self::SchedSetaffinity),
            751 => Some(Self::SchedGetaffinity),
            752 => Some(Self::SchedGetcpu),
            753 => Some(Self::SchedSetscheduler),
            754 => Some(Self::SchedGetscheduler),
            755 => Some(Self::SchedSetparam),
            756 => Some(Self::SchedGetparam),
            757 => Some(Self::SchedGetPriorityMin),
            758 => Some(Self::SchedGetPriorityMax),
            759 => Some(Self::SchedRrGetInterval),
            770 => Some(Self::ShmOpen),
            771 => Some(Self::ShmUnlink),
            772 => Some(Self::MemfdCreate),
            773 => Some(Self::AshmemCreateRegion),
            774 => Some(Self::AshmemSetProtRegion),
            775 => Some(Self::AshmemGetProtRegion),
            776 => Some(Self::AshmemGetSizeRegion),
            777 => Some(Self::AshmemPinRegion),
            778 => Some(Self::AshmemUnpinRegion),
            790 => Some(Self::PthreadSigmask),
            791 => Some(Self::Sigqueue),
            792 => Some(Self::PthreadKill),
            793 => Some(Self::PthreadSetnameNp),
            794 => Some(Self::PthreadGetnameNp),
            795 => Some(Self::PthreadEqual),
            796 => Some(Self::PthreadGetattrNp),
            810 => Some(Self::AndroidMallopt),
            811 => Some(Self::MallocInfo),
            812 => Some(Self::Mallinfo),
            813 => Some(Self::AndroidLogBwrite),
            814 => Some(Self::AndroidLogSecurityBwrite),
            815 => Some(Self::AndroidLogBtwrite),
            830 => Some(Self::MqOpen),
            831 => Some(Self::MqClose),
            832 => Some(Self::MqUnlink),
            833 => Some(Self::MqSend),
            834 => Some(Self::MqReceive),
            835 => Some(Self::MqTimedsend),
            836 => Some(Self::MqTimedreceive),
            837 => Some(Self::MqGetattr),
            838 => Some(Self::MqSetattr),
            850 => Some(Self::IfNametoindex),
            851 => Some(Self::IfIndextoname),
            852 => Some(Self::IfNameindex),
            853 => Some(Self::IfFreenameindex),
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
pub struct PosixTimer {
    pub clockid: u32,
    pub sigev_signo: u32,
    pub interval_sec: u32,
    pub interval_nsec: u32,
    pub value_sec: u32,
    pub value_nsec: u32,
    pub overrun_count: u32,
}

#[derive(Debug, Clone)]
pub struct EpollRegistration {
    pub fd: u32,
    pub events: u32,
    pub data: u64,
}

#[derive(Debug, Clone)]
pub struct LogMessage {
    pub priority: u32,
    pub tag: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtraceEvent {
    Begin(String),
    End,
    AsyncBegin(String, i32),
    AsyncEnd(String, i32),
    Counter(String, i64),
}

/// Provides Bionic C standard library stubs and forwarding for 32-bit guest code
pub struct BionicBridge {
    pub stub_base: GuestAddr,
    pub heap_current: GuestAddr,
    pub heap_limit: GuestAddr,
    pub symbol_table: HashMap<String, GuestAddr>,
    pub logs: Vec<LogMessage>,

    pub next_thread_id: u32,
    pub current_thread_id: u32,
    pub threads: HashMap<u32, ThreadDescriptor>,
    pub thread_names: HashMap<u32, String>,
    // POSIX Message Queues table: mqdes -> (name, queue of (message_bytes, priority))
    pub mqueue_table: HashMap<u32, (String, VecDeque<(Vec<u8>, u32)>)>,
    pub next_mqdes: u32,

    pub dso_registry: DsoRegistry,
    pub last_dlerror: Option<String>,
    pub dlerror_addr: GuestAddr,
    pub strerror_addr: GuestAddr,
    pub abort_message: Option<String>,
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
    // Socket descriptor table: guest_fd -> (host_family, host_type, is_connected)
    pub socket_fds: HashMap<u32, (i32, i32, bool)>,
    pub epoll_fds: HashMap<u32, Vec<EpollRegistration>>,
    pub timers: HashMap<u32, PosixTimer>,
    pub next_timer_id: u32,
    pub rlimits: HashMap<u32, (u64, u64)>,
    pub next_socket_fd: u32,
    // Inlined net buffer for inet_ntoa result
    pub inet_ntoa_addr: GuestAddr,
    pub ttyname_addr: GuestAddr,
    pub atrace_enabled: bool,
    pub atrace_events: Vec<AtraceEvent>,
    // Eventfd descriptor table: guest_fd -> (counter, flags)
    pub eventfd_table: HashMap<u32, (u64, u32)>,
    pub next_eventfd: u32,
    // Pipe descriptor table: guest_read_fd -> guest_write_fd, plus a small in-process buffer
    pub pipe_fds: HashMap<u32, (u32, Vec<u8>)>, // read_fd -> (write_fd, buffer)
    pub next_pipe_fd: u32,
    // Directory handle table: guest_dir_handle -> (vfs_path, entry_index)
    pub dir_handles: std::collections::HashMap<u32, (String, usize)>,
    pub next_dir_handle: u32,
    // strtok internal saved pointer (R0=0 means "continue from saved")
    pub strtok_saved: Option<GuestAddr>,
    pub mmap_current: GuestAddr,
    pub mmap_regions: std::collections::HashMap<u32, usize>,
    pub vfs: transd_rt::vfs::VirtualFileSystem,
    pub cwd: String,
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
            thread_names: HashMap::new(),
            mqueue_table: HashMap::new(),
            next_mqdes: 400,
            dso_registry: DsoRegistry::new(),
            last_dlerror: None,
            dlerror_addr: stub_base.add(0x800),
            strerror_addr: stub_base.add(0x900),
            abort_message: None,
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
            socket_fds: HashMap::new(),
            epoll_fds: HashMap::new(),
            timers: HashMap::new(),
            next_timer_id: 1,
            rlimits: {
                let mut m = HashMap::new();
                m.insert(0, (u64::MAX, u64::MAX)); // RLIMIT_CPU
                m.insert(1, (u64::MAX, u64::MAX)); // RLIMIT_FSIZE
                m.insert(2, (u64::MAX, u64::MAX)); // RLIMIT_DATA
                m.insert(3, (8 * 1024 * 1024, 8 * 1024 * 1024)); // RLIMIT_STACK (8 MB)
                m.insert(4, (0, u64::MAX)); // RLIMIT_CORE
                m.insert(5, (u64::MAX, u64::MAX)); // RLIMIT_RSS
                m.insert(6, (1024, 1024)); // RLIMIT_NPROC
                m.insert(7, (1024, 4096)); // RLIMIT_NOFILE
                m.insert(8, (65536, 65536)); // RLIMIT_MEMLOCK
                m.insert(9, (u64::MAX, u64::MAX)); // RLIMIT_AS
                m
            },
            next_socket_fd: 10, // Guest FDs start at 10 to avoid clash with 0/1/2
            inet_ntoa_addr: stub_base.add(0xA00),
            ttyname_addr: stub_base.add(0xC00),
            atrace_enabled: false,
            atrace_events: Vec::new(),
            eventfd_table: HashMap::new(),
            next_eventfd: 300,
            pipe_fds: HashMap::new(),
            next_pipe_fd: 100, // Guest pipe FDs start at 100
            dir_handles: std::collections::HashMap::new(),
            next_dir_handle: 200, // Guest DIR* handles start at 200
            strtok_saved: None,
            mmap_current: GuestAddr::new(0x7100_0000),
            mmap_regions: std::collections::HashMap::new(),
            vfs: transd_rt::vfs::VirtualFileSystem::new(),
            cwd: "/data/data/com.transd.app".to_string(),
        };

        bridge.register_known_symbols();
        bridge
    }

    /// Allocates an aligned buffer from the guest heap, returning GuestAddr(0) on OOM
    pub fn heap_alloc(&mut self, size: u32) -> GuestAddr {
        let align_size = (size + 7) & !7;
        if self.heap_current.add(align_size) <= self.heap_limit {
            let ptr = self.heap_current;
            self.heap_current = self.heap_current.add(align_size);
            ptr
        } else {
            GuestAddr::new(0)
        }
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

            // Dynamic Linker Iteration
            ("dl_iterate_phdr", BionicFuncId::DlIteratePhdr),

            // Atomic Builtins
            ("__atomic_fetch_add_4", BionicFuncId::AtomicFetchAdd4),
            ("__atomic_fetch_sub_4", BionicFuncId::AtomicFetchSub4),
            ("__atomic_fetch_and_4", BionicFuncId::AtomicFetchAnd4),
            ("__atomic_fetch_or_4", BionicFuncId::AtomicFetchOr4),
            ("__atomic_fetch_xor_4", BionicFuncId::AtomicFetchXor4),
            ("__atomic_load_4", BionicFuncId::AtomicLoad4),
            ("__atomic_store_4", BionicFuncId::AtomicStore4),
            ("__atomic_compare_exchange_4", BionicFuncId::AtomicCompareExchange4),
            ("__atomic_exchange_4", BionicFuncId::AtomicExchange4),
            ("__sync_val_compare_and_swap_4", BionicFuncId::SyncValCompareAndSwap4),
            ("__sync_bool_compare_and_swap_4", BionicFuncId::SyncBoolCompareAndSwap4),
            ("__sync_fetch_and_add_4", BionicFuncId::SyncFetchAndAdd4),
            ("__sync_fetch_and_sub_4", BionicFuncId::SyncFetchAndSub4),

            // POSIX Sockets
            ("socket", BionicFuncId::Socket),
            ("connect", BionicFuncId::SocketConnect),
            ("bind", BionicFuncId::SocketBind),
            ("listen", BionicFuncId::SocketListen),
            ("accept", BionicFuncId::SocketAccept),
            ("send", BionicFuncId::SocketSend),
            ("recv", BionicFuncId::SocketRecv),
            ("sendto", BionicFuncId::SocketSendto),
            ("recvfrom", BionicFuncId::SocketRecvfrom),
            ("shutdown", BionicFuncId::SocketShutdown),
            ("close", BionicFuncId::SocketClose),
            ("getsockname", BionicFuncId::SocketGetSockname),
            ("getpeername", BionicFuncId::SocketGetPeername),
            ("setsockopt", BionicFuncId::SocketSetsockopt),
            ("getsockopt", BionicFuncId::SocketGetsockopt),
            ("htons", BionicFuncId::Htons),
            ("htonl", BionicFuncId::Htonl),
            ("ntohs", BionicFuncId::Ntohs),
            ("ntohl", BionicFuncId::Ntohl),
            ("inet_aton", BionicFuncId::InetAton),
            ("inet_ntoa", BionicFuncId::InetNtoa),
            ("pipe", BionicFuncId::Pipe),
            ("read", BionicFuncId::Read),
            ("write", BionicFuncId::Write),
            ("malloc_usable_size", BionicFuncId::MallocUsableSize),
            ("memalign", BionicFuncId::Memalign),
            ("posix_memalign", BionicFuncId::PosixMemalign),
            ("pthread_barrier_init", BionicFuncId::PthreadBarrierInit),
            ("pthread_barrier_wait", BionicFuncId::PthreadBarrierWait),
            ("pthread_barrier_destroy", BionicFuncId::PthreadBarrierDestroy),
            ("clock_nanosleep", BionicFuncId::ClockNanosleep),
            ("dup", BionicFuncId::Dup),
            ("dup2", BionicFuncId::Dup2),
            ("fcntl", BionicFuncId::Fcntl),
            ("select", BionicFuncId::Select),
            ("poll", BionicFuncId::Poll),
            ("getaddrinfo", BionicFuncId::Getaddrinfo),
            ("freeaddrinfo", BionicFuncId::Freeaddrinfo),
            ("getnameinfo", BionicFuncId::Getnameinfo),
            ("gethostbyname", BionicFuncId::Gethostbyname),
            ("gethostbyname_r", BionicFuncId::GethostbynameR),
            ("getifaddrs", BionicFuncId::Getifaddrs),
            ("freeifaddrs", BionicFuncId::Freeifaddrs),
            ("setsid", BionicFuncId::Setsid),
            ("getpgrp", BionicFuncId::Getpgrp),
            ("setpgid", BionicFuncId::Setpgid),
            ("open", BionicFuncId::Open),
            ("openat", BionicFuncId::Openat),
            ("lseek", BionicFuncId::Lseek),
            ("lseek64", BionicFuncId::Lseek64),
            ("stat", BionicFuncId::Stat),
            ("stat64", BionicFuncId::Stat64),
            ("fstat", BionicFuncId::Fstat),
            ("fstat64", BionicFuncId::Fstat64),
            ("lstat", BionicFuncId::Lstat),
            ("lstat64", BionicFuncId::Lstat64),
            ("fstatat", BionicFuncId::Fstatat),
            ("fstatat64", BionicFuncId::Fstatat),
            ("access", BionicFuncId::Access),
            ("faccessat", BionicFuncId::Faccessat),
            ("mkdir", BionicFuncId::Mkdir),
            ("mkdirat", BionicFuncId::Mkdirat),
            ("unlink", BionicFuncId::Unlink),
            ("unlinkat", BionicFuncId::Unlinkat),
            ("getcwd", BionicFuncId::Getcwd),
            ("chdir", BionicFuncId::Chdir),
            ("readlink", BionicFuncId::Readlink),
            ("readlinkat", BionicFuncId::Readlinkat),
            ("rename", BionicFuncId::Rename),
            ("renameat", BionicFuncId::Renameat),
            ("ftruncate", BionicFuncId::Ftruncate),
            ("ftruncate64", BionicFuncId::Ftruncate64),
            ("atanf", BionicFuncId::Atanf),
            ("asinf", BionicFuncId::Asinf),
            ("acosf", BionicFuncId::Acosf),
            ("sinhf", BionicFuncId::Sinhf),
            ("coshf", BionicFuncId::Coshf),
            ("tanhf", BionicFuncId::Tanhf),
            ("log10f", BionicFuncId::Log10f),
            ("log2f", BionicFuncId::Log2f),
            ("exp2f", BionicFuncId::Exp2f),
            ("fmodf", BionicFuncId::Fmodf),
            ("roundf", BionicFuncId::Roundf),
            ("truncf", BionicFuncId::Truncf),
            ("hypotf", BionicFuncId::Hypotf),
            ("copysignf", BionicFuncId::Copysignf),
            ("cbrtf", BionicFuncId::Cbrtf),
            ("ldexpf", BionicFuncId::Ldexpf),
            ("atan", BionicFuncId::Atan),
            ("asin", BionicFuncId::Asin),
            ("acos", BionicFuncId::Acos),
            ("sinh", BionicFuncId::Sinh),
            ("cosh", BionicFuncId::Cosh),
            ("tanh", BionicFuncId::Tanh),
            ("log10", BionicFuncId::Log10),
            ("log2", BionicFuncId::Log2),
            ("exp2", BionicFuncId::Exp2),
            ("fmod", BionicFuncId::Fmod),
            ("round", BionicFuncId::Round),
            ("trunc", BionicFuncId::Trunc),
            ("hypot", BionicFuncId::Hypot),
            ("copysign", BionicFuncId::Copysign),
            ("cbrt", BionicFuncId::Cbrt),
            ("ldexp", BionicFuncId::Ldexp),
            ("opendir",   BionicFuncId::Opendir),
            ("closedir",  BionicFuncId::Closedir),
            ("readdir",   BionicFuncId::Readdir),
            ("readdir64", BionicFuncId::Readdir64),
            ("fdopendir", BionicFuncId::Fdopendir),
            ("dirfd",     BionicFuncId::Dirfd),
            ("rewinddir", BionicFuncId::Rewinddir),
            ("telldir",   BionicFuncId::Telldir),
            ("seekdir",   BionicFuncId::Seekdir),
            ("printf",    BionicFuncId::Printf),
            ("fprintf",   BionicFuncId::Fprintf),
            ("sscanf",    BionicFuncId::Sscanf),
            ("vprintf",   BionicFuncId::Vprintf),
            ("vfprintf",  BionicFuncId::Vfprintf),
            ("vsprintf",  BionicFuncId::Vsprintf),
            ("vsnprintf", BionicFuncId::Vsnprintf),
            ("asprintf",  BionicFuncId::Asprintf),
            ("vasprintf", BionicFuncId::Vasprintf),
            ("strtof",    BionicFuncId::Strtof),
            ("strtod",    BionicFuncId::Strtod),
            ("strtold",   BionicFuncId::Strtold),
            ("strdup",    BionicFuncId::Strdup),
            ("strndup",   BionicFuncId::Strndup),
            ("strtok",    BionicFuncId::Strtok),
            ("strtok_r",  BionicFuncId::StrtokR),
            ("strpbrk",   BionicFuncId::Strpbrk),
            ("strcspn",   BionicFuncId::Strcspn),
            ("strspn",    BionicFuncId::Strspn),
            ("memmem",    BionicFuncId::Memmem),
            ("isalnum",   BionicFuncId::Isalnum),
            ("isalpha",   BionicFuncId::Isalpha),
            ("isblank",   BionicFuncId::Isblank),
            ("iscntrl",   BionicFuncId::Iscntrl),
            ("isdigit",   BionicFuncId::Isdigit),
            ("isgraph",   BionicFuncId::Isgraph),
            ("islower",   BionicFuncId::Islower),
            ("isprint",   BionicFuncId::Isprint),
            ("ispunct",   BionicFuncId::Ispunct),
            ("isspace",   BionicFuncId::Isspace),
            ("isupper",   BionicFuncId::Isupper),
            ("isxdigit",  BionicFuncId::Isxdigit),
            ("tolower",   BionicFuncId::Tolower),
            ("toupper",   BionicFuncId::Toupper),
            ("isascii",   BionicFuncId::Isascii),
            ("toascii",   BionicFuncId::Toascii),
            ("setlocale", BionicFuncId::Setlocale),
            ("localeconv", BionicFuncId::Localeconv),
            ("mbstowcs",  BionicFuncId::Mbstowcs),
            ("wcstombs",  BionicFuncId::Wcstombs),
            ("mbtowc",    BionicFuncId::Mbtowc),
            ("wctomb",    BionicFuncId::Wctomb),
            ("wcslen",    BionicFuncId::Wcslen),
            ("wcscpy",    BionicFuncId::Wcscpy),
            ("wcscmp",      BionicFuncId::Wcscmp),
            ("time",        BionicFuncId::Time),
            ("difftime",    BionicFuncId::Difftime),
            ("clock",       BionicFuncId::Clock),
            ("times",       BionicFuncId::Times),
            ("gmtime",      BionicFuncId::Gmtime),
            ("gmtime_r",    BionicFuncId::GmtimeR),
            ("localtime",   BionicFuncId::Localtime),
            ("localtime_r", BionicFuncId::LocaltimeR),
            ("mktime",      BionicFuncId::Mktime),
            ("asctime",     BionicFuncId::Asctime),
            ("asctime_r",   BionicFuncId::AsctimeR),
            ("ctime",       BionicFuncId::Ctime),
            ("ctime_r",     BionicFuncId::CtimeR),
            ("strftime",    BionicFuncId::Strftime),
            ("strptime",    BionicFuncId::Strptime),
            ("mmap",        BionicFuncId::Mmap),
            ("mmap64",      BionicFuncId::Mmap64),
            ("munmap",      BionicFuncId::Munmap),
            ("madvise",     BionicFuncId::Madvise),
            ("msync",       BionicFuncId::Msync),
            ("mremap",      BionicFuncId::Mremap),
            ("mlock",       BionicFuncId::Mlock),
            ("munlock",     BionicFuncId::Munlock),
            ("mlockall",    BionicFuncId::Mlockall),
            ("munlockall",  BionicFuncId::Munlockall),
            ("mincore",     BionicFuncId::Mincore),
            ("android_dlopen_ext",        BionicFuncId::AndroidDlopenExt),
            ("dladdr",                    BionicFuncId::Dladdr),
            ("dladdr1",                   BionicFuncId::Dladdr1),
            ("__android_log_assert",      BionicFuncId::AndroidLogAssert),
            ("__android_log_buf_print",   BionicFuncId::AndroidLogBufPrint),
            ("__android_log_buf_write",   BionicFuncId::AndroidLogBufWrite),
            ("__android_log_vprint",      BionicFuncId::AndroidLogVprint),
            ("__android_log_is_loggable", BionicFuncId::AndroidLogIsLoggable),
            ("__assert",                  BionicFuncId::Assert),
            ("__assert2",                 BionicFuncId::Assert2),
            ("__system_property_set",       BionicFuncId::SystemPropertySet),
            ("__system_property_area_init", BionicFuncId::SystemPropertyAreaInit),
            ("__system_property_add",       BionicFuncId::SystemPropertyAdd),
            ("__system_property_update",    BionicFuncId::SystemPropertyUpdate),
            ("__system_property_wait",      BionicFuncId::SystemPropertyWait),
            ("__system_property_wait_any",  BionicFuncId::SystemPropertyWaitAny),
            ("__system_property_serial",    BionicFuncId::SystemPropertySerial),
            ("__system_property_foreach",   BionicFuncId::SystemPropertyForeach),
            ("android_set_abort_message",   BionicFuncId::AndroidSetAbortMessage),
            ("android_get_abort_message",   BionicFuncId::AndroidGetAbortMessage),
            ("_Unwind_RaiseException",      BionicFuncId::UnwindRaiseException),
            ("_Unwind_ForcedUnwind",        BionicFuncId::UnwindForcedUnwind),
            ("_Unwind_DeleteException",     BionicFuncId::UnwindDeleteException),
            ("_Unwind_Resume",              BionicFuncId::UnwindResume),
            ("_Unwind_GetGR",               BionicFuncId::UnwindGetGR),
            ("_Unwind_SetGR",               BionicFuncId::UnwindSetGR),
            ("_Unwind_GetIP",               BionicFuncId::UnwindGetIP),
            ("_Unwind_SetIP",               BionicFuncId::UnwindSetIP),
            ("__aeabi_unwind_cpp_pr0",      BionicFuncId::AeabiUnwindCppPr0),
            ("__aeabi_unwind_cpp_pr1",      BionicFuncId::AeabiUnwindCppPr1),
            ("__aeabi_unwind_cpp_pr2",      BionicFuncId::AeabiUnwindCppPr2),
            ("__cxa_begin_cleanup",         BionicFuncId::CxaBeginCleanup),
            ("__cxa_end_cleanup",           BionicFuncId::CxaEndCleanup),
            ("_Unwind_Backtrace",           BionicFuncId::UnwindBacktrace),
            ("_Unwind_Complete",            BionicFuncId::UnwindComplete),
            ("inet_ntop",                   BionicFuncId::InetNtop),
            ("inet_pton",                   BionicFuncId::InetPton),
            ("gai_strerror",                BionicFuncId::GaiStrerror),
            ("getservbyname",               BionicFuncId::Getservbyname),
            ("getservbyport",               BionicFuncId::Getservbyport),
            ("getprotobyname",              BionicFuncId::Getprotobyname),
            ("getprotobynumber",            BionicFuncId::Getprotobynumber),
            ("socketpair",                  BionicFuncId::Socketpair),
            ("epoll_create",                BionicFuncId::EpollCreate),
            ("epoll_create1",               BionicFuncId::EpollCreate1),
            ("epoll_ctl",                   BionicFuncId::EpollCtl),
            ("epoll_wait",                  BionicFuncId::EpollWait),
            ("epoll_pwait",                 BionicFuncId::EpollPwait),
            ("pselect",                     BionicFuncId::Pselect),
            ("ppoll",                       BionicFuncId::Ppoll),
            ("timer_create",                BionicFuncId::TimerCreate),
            ("timer_settime",               BionicFuncId::TimerSettime),
            ("timer_gettime",               BionicFuncId::TimerGettime),
            ("timer_getoverrun",            BionicFuncId::TimerGetoverrun),
            ("timer_delete",                BionicFuncId::TimerDelete),
            ("sigpending",                  BionicFuncId::Sigpending),
            ("sigsuspend",                  BionicFuncId::Sigsuspend),
            ("sigwait",                     BionicFuncId::Sigwait),
            ("sigtimedwait",                BionicFuncId::Sigtimedwait),
            ("sigwaitinfo",                 BionicFuncId::Sigwaitinfo),
            ("getrlimit",                   BionicFuncId::Getrlimit),
            ("getrlimit64",                 BionicFuncId::Getrlimit64),
            ("setrlimit",                   BionicFuncId::Setrlimit),
            ("setrlimit64",                 BionicFuncId::Setrlimit64),
            ("prlimit",                     BionicFuncId::Prlimit),
            ("prlimit64",                   BionicFuncId::Prlimit64),
            ("sysinfo",                     BionicFuncId::Sysinfo),
            ("getpagesize",                 BionicFuncId::Getpagesize),
            ("get_nprocs",                  BionicFuncId::GetNprocs),
            ("get_nprocs_conf",             BionicFuncId::GetNprocsConf),
            ("sysconf",                     BionicFuncId::Sysconf),
            ("symlink",                     BionicFuncId::Symlink),
            ("symlinkat",                   BionicFuncId::Symlinkat),
            ("link",                        BionicFuncId::Link),
            ("linkat",                      BionicFuncId::Linkat),
            ("chmod",                       BionicFuncId::Chmod),
            ("fchmod",                      BionicFuncId::Fchmod),
            ("fchmodat",                    BionicFuncId::Fchmodat),
            ("chown",                       BionicFuncId::Chown),
            ("fchown",                      BionicFuncId::Fchown),
            ("lchown",                      BionicFuncId::Lchown),
            ("fchownat",                    BionicFuncId::Fchownat),
            ("mknod",                       BionicFuncId::Mknod),
            ("mknodat",                     BionicFuncId::Mknodat),
            ("sync",                        BionicFuncId::Sync),
            ("fsync",                       BionicFuncId::Fsync),
            ("fdatasync",                   BionicFuncId::Fdatasync),
            ("pipe2",                       BionicFuncId::Pipe2),
            ("dup3",                        BionicFuncId::Dup3),
            ("statfs",                      BionicFuncId::Statfs),
            ("statfs64",                    BionicFuncId::Statfs64),
            ("fstatfs",                     BionicFuncId::Fstatfs),
            ("fstatfs64",                   BionicFuncId::Fstatfs64),
            ("statvfs",                     BionicFuncId::Statvfs),
            ("fstatvfs",                    BionicFuncId::Fstatvfs),
            ("isatty",                      BionicFuncId::Isatty),
            ("ttyname",                     BionicFuncId::Ttyname),
            ("ttyname_r",                   BionicFuncId::TtynameR),
            ("tcgetattr",                   BionicFuncId::Tcgetattr),
            ("tcsetattr",                   BionicFuncId::Tcsetattr),
            ("tcflush",                     BionicFuncId::Tcflush),
            ("tcsendbreak",                 BionicFuncId::Tcsendbreak),
            ("tcdrain",                     BionicFuncId::Tcdrain),
            ("tcflow",                      BionicFuncId::Tcflow),
            ("cfgetispeed",                 BionicFuncId::Cfgetispeed),
            ("cfgetospeed",                 BionicFuncId::Cfgetospeed),
            ("cfsetispeed",                 BionicFuncId::Cfsetispeed),
            ("cfsetospeed",                 BionicFuncId::Cfsetospeed),
            ("cfmakeraw",                   BionicFuncId::Cfmakeraw),
            ("ioctl",                       BionicFuncId::Ioctl),
            ("atrace_begin_body",           BionicFuncId::AtraceBeginBody),
            ("atrace_end_body",             BionicFuncId::AtraceEndBody),
            ("atrace_async_begin_body",     BionicFuncId::AtraceAsyncBeginBody),
            ("atrace_async_end_body",       BionicFuncId::AtraceAsyncEndBody),
            ("atrace_set_tracing_enabled",  BionicFuncId::AtraceSetTracingEnabled),
            ("atrace_init",                 BionicFuncId::AtraceInit),
            ("atrace_int_body",             BionicFuncId::AtraceIntBody),
            ("atrace_int64_body",           BionicFuncId::AtraceInt64Body),
            ("atrace_get_enabled_tags",     BionicFuncId::AtraceGetEnabledTags),
            ("ATrace_beginSection",         BionicFuncId::AtraceBeginBody),
            ("ATrace_endSection",           BionicFuncId::AtraceEndBody),
            ("ATrace_setCounter",           BionicFuncId::AtraceInt64Body),
            ("ATrace_isEnabled",            BionicFuncId::AtraceGetEnabledTags),
            ("eventfd",                     BionicFuncId::Eventfd),
            ("eventfd_read",                BionicFuncId::EventfdRead),
            ("eventfd_write",               BionicFuncId::EventfdWrite),
            ("aio_read",                    BionicFuncId::AioRead),
            ("aio_write",                   BionicFuncId::AioWrite),
            ("aio_error",                   BionicFuncId::AioError),
            ("aio_return",                  BionicFuncId::AioReturn),
            ("aio_suspend",                 BionicFuncId::AioSuspend),
            ("aio_cancel",                  BionicFuncId::AioCancel),
            ("capget",                      BionicFuncId::Capget),
            ("capset",                      BionicFuncId::Capset),
            ("getgroups",                   BionicFuncId::Getgroups),
            ("setgroups",                   BionicFuncId::Setgroups),
            ("getresuid",                   BionicFuncId::Getresuid),
            ("getresgid",                   BionicFuncId::Getresgid),
            ("setresuid",                   BionicFuncId::Setresuid),
            ("setresgid",                   BionicFuncId::Setresgid),
            ("setreuid",                    BionicFuncId::Setreuid),
            ("setregid",                    BionicFuncId::Setregid),
            ("sched_setaffinity",           BionicFuncId::SchedSetaffinity),
            ("sched_getaffinity",           BionicFuncId::SchedGetaffinity),
            ("sched_getcpu",                BionicFuncId::SchedGetcpu),
            ("sched_setscheduler",          BionicFuncId::SchedSetscheduler),
            ("sched_getscheduler",          BionicFuncId::SchedGetscheduler),
            ("sched_setparam",              BionicFuncId::SchedSetparam),
            ("sched_getparam",              BionicFuncId::SchedGetparam),
            ("sched_get_priority_min",      BionicFuncId::SchedGetPriorityMin),
            ("sched_get_priority_max",      BionicFuncId::SchedGetPriorityMax),
            ("sched_rr_get_interval",       BionicFuncId::SchedRrGetInterval),
            ("shm_open",                    BionicFuncId::ShmOpen),
            ("shm_unlink",                  BionicFuncId::ShmUnlink),
            ("memfd_create",                BionicFuncId::MemfdCreate),
            ("ashmem_create_region",        BionicFuncId::AshmemCreateRegion),
            ("ashmem_set_prot_region",      BionicFuncId::AshmemSetProtRegion),
            ("ashmem_get_prot_region",      BionicFuncId::AshmemGetProtRegion),
            ("ashmem_get_size_region",      BionicFuncId::AshmemGetSizeRegion),
            ("ashmem_pin_region",           BionicFuncId::AshmemPinRegion),
            ("ashmem_unpin_region",         BionicFuncId::AshmemUnpinRegion),
            ("pthread_sigmask",             BionicFuncId::PthreadSigmask),
            ("sigqueue",                    BionicFuncId::Sigqueue),
            ("pthread_kill",                BionicFuncId::PthreadKill),
            ("pthread_setname_np",          BionicFuncId::PthreadSetnameNp),
            ("pthread_getname_np",          BionicFuncId::PthreadGetnameNp),
            ("pthread_equal",               BionicFuncId::PthreadEqual),
            ("pthread_getattr_np",          BionicFuncId::PthreadGetattrNp),
            ("android_mallopt",             BionicFuncId::AndroidMallopt),
            ("malloc_info",                 BionicFuncId::MallocInfo),
            ("mallinfo",                    BionicFuncId::Mallinfo),
            ("__android_log_bwrite",         BionicFuncId::AndroidLogBwrite),
            ("__android_log_security_bwrite", BionicFuncId::AndroidLogSecurityBwrite),
            ("__android_log_btwrite",        BionicFuncId::AndroidLogBtwrite),
            ("mq_open",                      BionicFuncId::MqOpen),
            ("mq_close",                     BionicFuncId::MqClose),
            ("mq_unlink",                    BionicFuncId::MqUnlink),
            ("mq_send",                      BionicFuncId::MqSend),
            ("mq_receive",                   BionicFuncId::MqReceive),
            ("mq_timedsend",                 BionicFuncId::MqTimedsend),
            ("mq_timedreceive",              BionicFuncId::MqTimedreceive),
            ("mq_getattr",                   BionicFuncId::MqGetattr),
            ("mq_setattr",                   BionicFuncId::MqSetattr),
            ("if_nametoindex",               BionicFuncId::IfNametoindex),
            ("if_indextoname",               BionicFuncId::IfIndextoname),
            ("if_nameindex",                 BionicFuncId::IfNameindex),
            ("if_freenameindex",             BionicFuncId::IfFreenameindex),
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
            BionicFuncId::DlIteratePhdr,
            BionicFuncId::AtomicFetchAdd4,
            BionicFuncId::AtomicFetchSub4,
            BionicFuncId::AtomicFetchAnd4,
            BionicFuncId::AtomicFetchOr4,
            BionicFuncId::AtomicFetchXor4,
            BionicFuncId::AtomicLoad4,
            BionicFuncId::AtomicStore4,
            BionicFuncId::AtomicCompareExchange4,
            BionicFuncId::AtomicExchange4,
            BionicFuncId::SyncValCompareAndSwap4,
            BionicFuncId::SyncBoolCompareAndSwap4,
            BionicFuncId::SyncFetchAndAdd4,
            BionicFuncId::SyncFetchAndSub4,
            BionicFuncId::Socket,
            BionicFuncId::SocketConnect,
            BionicFuncId::SocketBind,
            BionicFuncId::SocketListen,
            BionicFuncId::SocketAccept,
            BionicFuncId::SocketSend,
            BionicFuncId::SocketRecv,
            BionicFuncId::SocketSendto,
            BionicFuncId::SocketRecvfrom,
            BionicFuncId::SocketShutdown,
            BionicFuncId::SocketClose,
            BionicFuncId::SocketGetSockname,
            BionicFuncId::SocketGetPeername,
            BionicFuncId::SocketSetsockopt,
            BionicFuncId::SocketGetsockopt,
            BionicFuncId::Htons,
            BionicFuncId::Htonl,
            BionicFuncId::Ntohs,
            BionicFuncId::Ntohl,
            BionicFuncId::InetAton,
            BionicFuncId::InetNtoa,
            BionicFuncId::Pipe,
            BionicFuncId::Read,
            BionicFuncId::Write,
            BionicFuncId::MallocUsableSize,
            BionicFuncId::Memalign,
            BionicFuncId::PosixMemalign,
            BionicFuncId::PthreadBarrierInit,
            BionicFuncId::PthreadBarrierWait,
            BionicFuncId::PthreadBarrierDestroy,
            BionicFuncId::ClockNanosleep,
            BionicFuncId::Dup,
            BionicFuncId::Dup2,
            BionicFuncId::Fcntl,
            BionicFuncId::Select,
            BionicFuncId::Poll,
            BionicFuncId::Getaddrinfo,
            BionicFuncId::Freeaddrinfo,
            BionicFuncId::Getnameinfo,
            BionicFuncId::Gethostbyname,
            BionicFuncId::GethostbynameR,
            BionicFuncId::Getifaddrs,
            BionicFuncId::Freeifaddrs,
            BionicFuncId::Setsid,
            BionicFuncId::Getpgrp,
            BionicFuncId::Setpgid,
            BionicFuncId::Open,
            BionicFuncId::Openat,
            BionicFuncId::Lseek,
            BionicFuncId::Lseek64,
            BionicFuncId::Stat,
            BionicFuncId::Stat64,
            BionicFuncId::Fstat,
            BionicFuncId::Fstat64,
            BionicFuncId::Lstat,
            BionicFuncId::Lstat64,
            BionicFuncId::Fstatat,
            BionicFuncId::Access,
            BionicFuncId::Faccessat,
            BionicFuncId::Mkdir,
            BionicFuncId::Mkdirat,
            BionicFuncId::Unlink,
            BionicFuncId::Unlinkat,
            BionicFuncId::Getcwd,
            BionicFuncId::Chdir,
            BionicFuncId::Readlink,
            BionicFuncId::Readlinkat,
            BionicFuncId::Rename,
            BionicFuncId::Renameat,
            BionicFuncId::Ftruncate,
            BionicFuncId::Ftruncate64,
            BionicFuncId::Atanf,
            BionicFuncId::Asinf,
            BionicFuncId::Acosf,
            BionicFuncId::Sinhf,
            BionicFuncId::Coshf,
            BionicFuncId::Tanhf,
            BionicFuncId::Log10f,
            BionicFuncId::Log2f,
            BionicFuncId::Exp2f,
            BionicFuncId::Fmodf,
            BionicFuncId::Roundf,
            BionicFuncId::Truncf,
            BionicFuncId::Hypotf,
            BionicFuncId::Copysignf,
            BionicFuncId::Cbrtf,
            BionicFuncId::Ldexpf,
            BionicFuncId::Atan,
            BionicFuncId::Asin,
            BionicFuncId::Acos,
            BionicFuncId::Sinh,
            BionicFuncId::Cosh,
            BionicFuncId::Tanh,
            BionicFuncId::Log10,
            BionicFuncId::Log2,
            BionicFuncId::Exp2,
            BionicFuncId::Fmod,
            BionicFuncId::Round,
            BionicFuncId::Trunc,
            BionicFuncId::Hypot,
            BionicFuncId::Copysign,
            BionicFuncId::Cbrt,
            BionicFuncId::Ldexp,
            // Directory enumeration (Stage 63)
            BionicFuncId::Opendir,
            BionicFuncId::Closedir,
            BionicFuncId::Readdir,
            BionicFuncId::Readdir64,
            BionicFuncId::Fdopendir,
            BionicFuncId::Dirfd,
            BionicFuncId::Rewinddir,
            BionicFuncId::Telldir,
            BionicFuncId::Seekdir,
            // String & Printf family (Stage 64)
            BionicFuncId::Printf,
            BionicFuncId::Fprintf,
            BionicFuncId::Sscanf,
            BionicFuncId::Vprintf,
            BionicFuncId::Vfprintf,
            BionicFuncId::Vsprintf,
            BionicFuncId::Vsnprintf,
            BionicFuncId::Asprintf,
            BionicFuncId::Vasprintf,
            BionicFuncId::Strtof,
            BionicFuncId::Strtod,
            BionicFuncId::Strtold,
            BionicFuncId::Strdup,
            BionicFuncId::Strndup,
            BionicFuncId::Strtok,
            BionicFuncId::StrtokR,
            BionicFuncId::Strpbrk,
            BionicFuncId::Strcspn,
            BionicFuncId::Strspn,
            BionicFuncId::Memmem,
            BionicFuncId::Isalnum,
            BionicFuncId::Isalpha,
            BionicFuncId::Isblank,
            BionicFuncId::Iscntrl,
            BionicFuncId::Isdigit,
            BionicFuncId::Isgraph,
            BionicFuncId::Islower,
            BionicFuncId::Isprint,
            BionicFuncId::Ispunct,
            BionicFuncId::Isspace,
            BionicFuncId::Isupper,
            BionicFuncId::Isxdigit,
            BionicFuncId::Tolower,
            BionicFuncId::Toupper,
            BionicFuncId::Isascii,
            BionicFuncId::Toascii,
            BionicFuncId::Setlocale,
            BionicFuncId::Localeconv,
            BionicFuncId::Mbstowcs,
            BionicFuncId::Wcstombs,
            BionicFuncId::Mbtowc,
            BionicFuncId::Wctomb,
            BionicFuncId::Wcslen,
            BionicFuncId::Wcscpy,
            BionicFuncId::Wcscmp,
            BionicFuncId::Time,
            BionicFuncId::Difftime,
            BionicFuncId::Clock,
            BionicFuncId::Times,
            BionicFuncId::Gmtime,
            BionicFuncId::GmtimeR,
            BionicFuncId::Localtime,
            BionicFuncId::LocaltimeR,
            BionicFuncId::Mktime,
            BionicFuncId::Asctime,
            BionicFuncId::AsctimeR,
            BionicFuncId::Ctime,
            BionicFuncId::CtimeR,
            BionicFuncId::Strftime,
            BionicFuncId::Strptime,
            BionicFuncId::Mmap,
            BionicFuncId::Mmap64,
            BionicFuncId::Munmap,
            BionicFuncId::Madvise,
            BionicFuncId::Msync,
            BionicFuncId::Mremap,
            BionicFuncId::Mlock,
            BionicFuncId::Munlock,
            BionicFuncId::Mlockall,
            BionicFuncId::Munlockall,
            BionicFuncId::Mincore,
            BionicFuncId::AndroidDlopenExt,
            BionicFuncId::Dladdr,
            BionicFuncId::Dladdr1,
            BionicFuncId::AndroidLogAssert,
            BionicFuncId::AndroidLogBufPrint,
            BionicFuncId::AndroidLogBufWrite,
            BionicFuncId::AndroidLogVprint,
            BionicFuncId::AndroidLogIsLoggable,
            BionicFuncId::Assert,
            BionicFuncId::Assert2,
            BionicFuncId::SystemPropertySet,
            BionicFuncId::SystemPropertyAreaInit,
            BionicFuncId::SystemPropertyAdd,
            BionicFuncId::SystemPropertyUpdate,
            BionicFuncId::SystemPropertyWait,
            BionicFuncId::SystemPropertyWaitAny,
            BionicFuncId::SystemPropertySerial,
            BionicFuncId::SystemPropertyForeach,
            BionicFuncId::AndroidSetAbortMessage,
            BionicFuncId::AndroidGetAbortMessage,
            BionicFuncId::UnwindRaiseException,
            BionicFuncId::UnwindForcedUnwind,
            BionicFuncId::UnwindDeleteException,
            BionicFuncId::UnwindResume,
            BionicFuncId::UnwindGetGR,
            BionicFuncId::UnwindSetGR,
            BionicFuncId::UnwindGetIP,
            BionicFuncId::UnwindSetIP,
            BionicFuncId::AeabiUnwindCppPr0,
            BionicFuncId::AeabiUnwindCppPr1,
            BionicFuncId::AeabiUnwindCppPr2,
            BionicFuncId::CxaBeginCleanup,
            BionicFuncId::CxaEndCleanup,
            BionicFuncId::UnwindBacktrace,
            BionicFuncId::UnwindComplete,
            BionicFuncId::InetNtop,
            BionicFuncId::InetPton,
            BionicFuncId::GaiStrerror,
            BionicFuncId::Getservbyname,
            BionicFuncId::Getservbyport,
            BionicFuncId::Getprotobyname,
            BionicFuncId::Getprotobynumber,
            BionicFuncId::Socketpair,
            BionicFuncId::EpollCreate,
            BionicFuncId::EpollCreate1,
            BionicFuncId::EpollCtl,
            BionicFuncId::EpollWait,
            BionicFuncId::EpollPwait,
            BionicFuncId::Pselect,
            BionicFuncId::Ppoll,
            BionicFuncId::TimerCreate,
            BionicFuncId::TimerSettime,
            BionicFuncId::TimerGettime,
            BionicFuncId::TimerGetoverrun,
            BionicFuncId::TimerDelete,
            BionicFuncId::Sigpending,
            BionicFuncId::Sigsuspend,
            BionicFuncId::Sigwait,
            BionicFuncId::Sigtimedwait,
            BionicFuncId::Sigwaitinfo,
            BionicFuncId::Getrlimit,
            BionicFuncId::Getrlimit64,
            BionicFuncId::Setrlimit,
            BionicFuncId::Setrlimit64,
            BionicFuncId::Prlimit,
            BionicFuncId::Prlimit64,
            BionicFuncId::Sysinfo,
            BionicFuncId::Getpagesize,
            BionicFuncId::GetNprocs,
            BionicFuncId::GetNprocsConf,
            BionicFuncId::Sysconf,
            BionicFuncId::Symlink,
            BionicFuncId::Symlinkat,
            BionicFuncId::Link,
            BionicFuncId::Linkat,
            BionicFuncId::Chmod,
            BionicFuncId::Fchmod,
            BionicFuncId::Fchmodat,
            BionicFuncId::Chown,
            BionicFuncId::Fchown,
            BionicFuncId::Lchown,
            BionicFuncId::Fchownat,
            BionicFuncId::Mknod,
            BionicFuncId::Mknodat,
            BionicFuncId::Sync,
            BionicFuncId::Fsync,
            BionicFuncId::Fdatasync,
            BionicFuncId::Pipe2,
            BionicFuncId::Dup3,
            BionicFuncId::Statfs,
            BionicFuncId::Statfs64,
            BionicFuncId::Fstatfs,
            BionicFuncId::Fstatfs64,
            BionicFuncId::Statvfs,
            BionicFuncId::Fstatvfs,
            BionicFuncId::Isatty,
            BionicFuncId::Ttyname,
            BionicFuncId::TtynameR,
            BionicFuncId::Tcgetattr,
            BionicFuncId::Tcsetattr,
            BionicFuncId::Tcflush,
            BionicFuncId::Tcsendbreak,
            BionicFuncId::Tcdrain,
            BionicFuncId::Tcflow,
            BionicFuncId::Cfgetispeed,
            BionicFuncId::Cfgetospeed,
            BionicFuncId::Cfsetispeed,
            BionicFuncId::Cfsetospeed,
            BionicFuncId::Cfmakeraw,
            BionicFuncId::Ioctl,
            BionicFuncId::AtraceBeginBody,
            BionicFuncId::AtraceEndBody,
            BionicFuncId::AtraceAsyncBeginBody,
            BionicFuncId::AtraceAsyncEndBody,
            BionicFuncId::AtraceSetTracingEnabled,
            BionicFuncId::AtraceInit,
            BionicFuncId::AtraceIntBody,
            BionicFuncId::AtraceInt64Body,
            BionicFuncId::AtraceGetEnabledTags,
            BionicFuncId::Eventfd,
            BionicFuncId::EventfdRead,
            BionicFuncId::EventfdWrite,
            BionicFuncId::AioRead,
            BionicFuncId::AioWrite,
            BionicFuncId::AioError,
            BionicFuncId::AioReturn,
            BionicFuncId::AioSuspend,
            BionicFuncId::AioCancel,
            BionicFuncId::Capget,
            BionicFuncId::Capset,
            BionicFuncId::Getgroups,
            BionicFuncId::Setgroups,
            BionicFuncId::Getresuid,
            BionicFuncId::Getresgid,
            BionicFuncId::Setresuid,
            BionicFuncId::Setresgid,
            BionicFuncId::Setreuid,
            BionicFuncId::Setregid,
            BionicFuncId::SchedSetaffinity,
            BionicFuncId::SchedGetaffinity,
            BionicFuncId::SchedGetcpu,
            BionicFuncId::SchedSetscheduler,
            BionicFuncId::SchedGetscheduler,
            BionicFuncId::SchedSetparam,
            BionicFuncId::SchedGetparam,
            BionicFuncId::SchedGetPriorityMin,
            BionicFuncId::SchedGetPriorityMax,
            BionicFuncId::SchedRrGetInterval,
            BionicFuncId::ShmOpen,
            BionicFuncId::ShmUnlink,
            BionicFuncId::MemfdCreate,
            BionicFuncId::AshmemCreateRegion,
            BionicFuncId::AshmemSetProtRegion,
            BionicFuncId::AshmemGetProtRegion,
            BionicFuncId::AshmemGetSizeRegion,
            BionicFuncId::AshmemPinRegion,
            BionicFuncId::AshmemUnpinRegion,
            BionicFuncId::PthreadSigmask,
            BionicFuncId::Sigqueue,
            BionicFuncId::PthreadKill,
            BionicFuncId::PthreadSetnameNp,
            BionicFuncId::PthreadGetnameNp,
            BionicFuncId::PthreadEqual,
            BionicFuncId::PthreadGetattrNp,
            BionicFuncId::AndroidMallopt,
            BionicFuncId::MallocInfo,
            BionicFuncId::Mallinfo,
            BionicFuncId::AndroidLogBwrite,
            BionicFuncId::AndroidLogSecurityBwrite,
            BionicFuncId::AndroidLogBtwrite,
            BionicFuncId::MqOpen,
            BionicFuncId::MqClose,
            BionicFuncId::MqUnlink,
            BionicFuncId::MqSend,
            BionicFuncId::MqReceive,
            BionicFuncId::MqTimedsend,
            BionicFuncId::MqTimedreceive,
            BionicFuncId::MqGetattr,
            BionicFuncId::MqSetattr,
            BionicFuncId::IfNametoindex,
            BionicFuncId::IfIndextoname,
            BionicFuncId::IfNameindex,
            BionicFuncId::IfFreenameindex,
        ] {
            let addr = self.stub_base.add((id as u32) * 8);
            let svc_code = 0xEF00_0000 | (BIONIC_SVC_MAGIC | (id as u32)); // SVC #(BIONIC_SVC_MAGIC | id)
            let bx_lr = 0xE12F_FF1E; // BX lr

            mem.write_u32(addr, svc_code)?;
            mem.write_u32(addr.add(4), bx_lr)?;
        }
        // Initialize stack protector canary word
        mem.write_u32(self.stack_chk_guard_addr, 0x000A_0DFF)?;

        // Initialize locale strings & localeconv structure
        let locale_str_addr = self.stub_base.add(0xB00);
        let dot_addr        = self.stub_base.add(0xB10);
        let empty_addr      = self.stub_base.add(0xB18);
        let lconv_addr      = self.stub_base.add(0xB40);

        mem.write_bytes(locale_str_addr, b"C.UTF-8\0")?;
        mem.write_bytes(dot_addr, b".\0")?;
        mem.write_u8(empty_addr, 0)?;

        // decimal_point -> dot_addr
        mem.write_u32(lconv_addr, dot_addr.as_u32())?;
        // thousands_sep through negative_sign (9 pointers) -> empty_addr
        for i in 1..10 {
            mem.write_u32(lconv_addr.add((i * 4) as u32), empty_addr.as_u32())?;
        }
        // numeric / monetary formats: 127 (CHAR_MAX)
        for i in 40..48 {
            mem.write_u8(lconv_addr.add(i as u32), 127)?;
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
            BionicFuncId::Dlopen | BionicFuncId::AndroidDlopenExt => {
                let filename_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let _flags = cpu.reg(Reg::R1);
                let extinfo_ptr = GuestAddr::new(cpu.reg(Reg::R2));

                let mut resolved_fd_filename = None;
                if func_id == BionicFuncId::AndroidDlopenExt && filename_ptr.as_u32() == 0 && extinfo_ptr.as_u32() != 0 {
                    let ext_flags = mem.read_u32(extinfo_ptr).unwrap_or(0);
                    // ANDROID_DLEXT_USE_LIBRARY_FD = 0x10
                    if (ext_flags & 0x10) != 0 {
                        if let Ok(lib_fd) = mem.read_u32(extinfo_ptr.add(16)) {
                            if let Some(path) = self.vfs.fd_path(lib_fd) {
                                resolved_fd_filename = Some(path.to_string());
                            }
                        }
                    }
                }

                if filename_ptr.as_u32() == 0 && resolved_fd_filename.is_none() {
                    cpu.set_reg(Reg::R0, RTLD_DEFAULT);
                } else {
                    let filename = if let Some(f) = resolved_fd_filename {
                        f
                    } else {
                        Self::read_c_string(mem, filename_ptr)?
                    };
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
            BionicFuncId::Sigprocmask | BionicFuncId::PthreadSigmask => {
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
            BionicFuncId::SystemPropertySet => {
                let name_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let val_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let name = Self::read_c_string(mem, name_addr)?;
                let val = Self::read_c_string(mem, val_addr)?;
                let res = self.properties.system_property_set(&name, &val, mem)?;
                cpu.set_reg(Reg::R0, res as u32);
            }
            BionicFuncId::SystemPropertyAreaInit => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::SystemPropertyAdd => {
                let name_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let namelen = cpu.reg(Reg::R1) as usize;
                let val_addr = GuestAddr::new(cpu.reg(Reg::R2));
                let valuelen = cpu.reg(Reg::R3) as usize;

                let mut name_bytes = vec![0u8; namelen.min(32)];
                mem.read_bytes(name_addr, &mut name_bytes)?;
                let name = String::from_utf8_lossy(&name_bytes).trim_end_matches('\0').to_string();

                let mut val_bytes = vec![0u8; valuelen.min(92)];
                mem.read_bytes(val_addr, &mut val_bytes)?;
                let val = String::from_utf8_lossy(&val_bytes).trim_end_matches('\0').to_string();

                let res = self.properties.system_property_set(&name, &val, mem)?;
                cpu.set_reg(Reg::R0, res as u32);
            }
            BionicFuncId::SystemPropertyUpdate => {
                let pi_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let val_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let val = Self::read_c_string(mem, val_addr)?;
                let res = self.properties.system_property_update(pi_addr, &val, mem)?;
                cpu.set_reg(Reg::R0, res as u32);
            }
            BionicFuncId::SystemPropertyWait | BionicFuncId::SystemPropertyWaitAny => {
                let pi_addr = if func_id == BionicFuncId::SystemPropertyWait {
                    GuestAddr::new(cpu.reg(Reg::R0))
                } else {
                    GuestAddr::new(0)
                };
                let seq_addr = if func_id == BionicFuncId::SystemPropertyWait {
                    GuestAddr::new(cpu.reg(Reg::R1))
                } else {
                    GuestAddr::new(cpu.reg(Reg::R0))
                };
                let new_seq_addr = if func_id == BionicFuncId::SystemPropertyWait {
                    GuestAddr::new(cpu.reg(Reg::R2))
                } else {
                    GuestAddr::new(cpu.reg(Reg::R1))
                };

                let old_seq = if seq_addr.as_u32() != 0 {
                    mem.read_u32(seq_addr).unwrap_or(0)
                } else {
                    0
                };
                let next_seq = if pi_addr.as_u32() != 0 {
                    let cur = mem.read_u32(pi_addr.add(32)).unwrap_or(1);
                    if cur == old_seq { cur.wrapping_add(1) } else { cur }
                } else {
                    old_seq.wrapping_add(1)
                };
                if new_seq_addr.as_u32() != 0 {
                    mem.write_u32(new_seq_addr, next_seq)?;
                }
                cpu.set_reg(Reg::R0, 1);
            }
            BionicFuncId::SystemPropertySerial => {
                let pi_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let serial = self.properties.system_property_serial(pi_addr, mem)?;
                cpu.set_reg(Reg::R0, serial);
            }
            BionicFuncId::SystemPropertyForeach => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::AndroidSetAbortMessage => {
                let msg_addr = GuestAddr::new(cpu.reg(Reg::R0));
                if msg_addr.as_u32() != 0 {
                    let msg = Self::read_c_string(mem, msg_addr).unwrap_or_default();
                    let abort_buf = self.stub_base.add(0xF00);
                    let bytes = msg.as_bytes();
                    let len = bytes.len().min(240);
                    mem.write_u32(abort_buf, len as u32)?;
                    mem.write_bytes(abort_buf.add(4), &bytes[..len])?;
                    mem.write_u8(abort_buf.add(4 + len as u32), 0)?;
                    self.abort_message = Some(msg.clone());
                    self.logs.push(LogMessage {
                        priority: 7, // ANDROID_LOG_FATAL
                        tag: "abort".to_string(),
                        text: msg,
                    });
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::AndroidGetAbortMessage => {
                if self.abort_message.is_some() {
                    cpu.set_reg(Reg::R0, self.stub_base.add(0xF00).as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }

            // Exception Handling & Unwinding (Stage 70)
            BionicFuncId::UnwindRaiseException | BionicFuncId::UnwindForcedUnwind => {
                // Returns _URC_END_OF_STACK (5) in absence of personality/unwind handler
                cpu.set_reg(Reg::R0, 5);
            }
            BionicFuncId::UnwindDeleteException => {
                let exc_addr = GuestAddr::new(cpu.reg(Reg::R0));
                if exc_addr.as_u32() != 0 {
                    let _ = mem.write_u32(exc_addr.add(8), 0);
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::UnwindResume => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::UnwindGetGR => {
                let ctx_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let idx = cpu.reg(Reg::R1);
                if ctx_addr.as_u32() != 0 && idx < 16 {
                    let val = mem.read_u32(ctx_addr.add(idx * 4)).unwrap_or(0);
                    cpu.set_reg(Reg::R0, val);
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::UnwindSetGR => {
                let ctx_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let idx = cpu.reg(Reg::R1);
                let val = cpu.reg(Reg::R2);
                if ctx_addr.as_u32() != 0 && idx < 16 {
                    let _ = mem.write_u32(ctx_addr.add(idx * 4), val);
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::UnwindGetIP => {
                let ctx_addr = GuestAddr::new(cpu.reg(Reg::R0));
                if ctx_addr.as_u32() != 0 {
                    let pc = mem.read_u32(ctx_addr.add(15 * 4)).unwrap_or(0);
                    cpu.set_reg(Reg::R0, pc & !1);
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::UnwindSetIP => {
                let ctx_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let val = cpu.reg(Reg::R1);
                if ctx_addr.as_u32() != 0 {
                    let _ = mem.write_u32(ctx_addr.add(15 * 4), val);
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::AeabiUnwindCppPr0 | BionicFuncId::AeabiUnwindCppPr1 | BionicFuncId::AeabiUnwindCppPr2 => {
                // Personality routines return _URC_CONTINUE_UNWIND (8)
                cpu.set_reg(Reg::R0, 8);
            }
            BionicFuncId::CxaBeginCleanup | BionicFuncId::CxaEndCleanup => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::UnwindBacktrace => {
                // Returns _URC_END_OF_STACK (5)
                cpu.set_reg(Reg::R0, 5);
            }
            BionicFuncId::UnwindComplete => {
                cpu.set_reg(Reg::R0, 0);
            }

            // POSIX Network & Socket Extensions (Stage 71)
            BionicFuncId::InetNtop => {
                let af = cpu.reg(Reg::R0) as i32;
                let src_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let dst_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                let size = cpu.reg(Reg::R3);

                if af == 2 && src_ptr.as_u32() != 0 && dst_ptr.as_u32() != 0 {
                    let mut b = [0u8; 4];
                    mem.read_bytes(src_ptr, &mut b)?;
                    let s = format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
                    let bytes = s.as_bytes();
                    if (bytes.len() + 1) as u32 <= size {
                        mem.write_bytes(dst_ptr, bytes)?;
                        mem.write_u8(dst_ptr.add(bytes.len() as u32), 0)?;
                        cpu.set_reg(Reg::R0, dst_ptr.as_u32());
                    } else {
                        cpu.set_reg(Reg::R0, 0);
                    }
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::InetPton => {
                let af = cpu.reg(Reg::R0) as i32;
                let src_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let dst_ptr = GuestAddr::new(cpu.reg(Reg::R2));

                if af == 2 && src_ptr.as_u32() != 0 && dst_ptr.as_u32() != 0 {
                    let s = Self::read_c_string(mem, src_ptr).unwrap_or_default();
                    if let Ok(addr) = s.parse::<std::net::Ipv4Addr>() {
                        mem.write_bytes(dst_ptr, &addr.octets())?;
                        cpu.set_reg(Reg::R0, 1);
                    } else {
                        cpu.set_reg(Reg::R0, 0);
                    }
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::GaiStrerror => {
                let errcode = cpu.reg(Reg::R0);
                let msg = match errcode {
                    0 => "Success",
                    1 => "Address family for hostname not supported",
                    2 => "Temporary failure in name resolution",
                    3 => "Bad value for ai_flags",
                    4 => "Non-recoverable failure in name resolution",
                    5 => "ai_family not supported",
                    6 => "Memory allocation failure",
                    7 => "No address associated with hostname",
                    8 => "hostname nor servname provided, or not known",
                    9 => "servname not supported for ai_socktype",
                    10 => "ai_socktype not supported",
                    11 => "System error returned in errno",
                    _ => "Unknown error",
                };
                let bytes = msg.as_bytes();
                mem.write_bytes(self.strerror_addr, bytes)?;
                mem.write_u8(self.strerror_addr.add(bytes.len() as u32), 0)?;
                cpu.set_reg(Reg::R0, self.strerror_addr.as_u32());
            }
            BionicFuncId::Getservbyname => {
                let name_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let name = if name_ptr.as_u32() != 0 {
                    Self::read_c_string(mem, name_ptr).unwrap_or_default()
                } else {
                    String::new()
                };

                let port_opt = match name.as_str() {
                    "http" => Some(80u16),
                    "https" => Some(443u16),
                    "ftp" => Some(21u16),
                    "ssh" => Some(22u16),
                    "domain" | "dns" => Some(53u16),
                    "smtp" => Some(25u16),
                    "ntp" => Some(123u16),
                    _ => None,
                };

                if let Some(port) = port_opt {
                    let s_addr = self.stub_base.add(0xF40);
                    let name_buf = self.stub_base.add(0xF60);
                    let proto_buf = self.stub_base.add(0xF70);

                    let mut nb = name.as_bytes().to_vec();
                    nb.push(0);
                    mem.write_bytes(name_buf, &nb)?;
                    mem.write_bytes(proto_buf, b"tcp\0")?;

                    mem.write_u32(s_addr, name_buf.as_u32())?;
                    mem.write_u32(s_addr.add(4), 0)?;
                    mem.write_u32(s_addr.add(8), (port.to_be() as i32) as u32)?;
                    mem.write_u32(s_addr.add(12), proto_buf.as_u32())?;

                    cpu.set_reg(Reg::R0, s_addr.as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::Getservbyport => {
                let raw_port = cpu.reg(Reg::R0) as u16;
                let host_port = u16::from_be(raw_port);

                let name_opt = match host_port {
                    80 => Some("http"),
                    443 => Some("https"),
                    21 => Some("ftp"),
                    22 => Some("ssh"),
                    53 => Some("domain"),
                    25 => Some("smtp"),
                    123 => Some("ntp"),
                    _ => None,
                };

                if let Some(name) = name_opt {
                    let s_addr = self.stub_base.add(0xF40);
                    let name_buf = self.stub_base.add(0xF60);
                    let proto_buf = self.stub_base.add(0xF70);

                    let mut nb = name.as_bytes().to_vec();
                    nb.push(0);
                    mem.write_bytes(name_buf, &nb)?;
                    mem.write_bytes(proto_buf, b"tcp\0")?;

                    mem.write_u32(s_addr, name_buf.as_u32())?;
                    mem.write_u32(s_addr.add(4), 0)?;
                    mem.write_u32(s_addr.add(8), (raw_port as i32) as u32)?;
                    mem.write_u32(s_addr.add(12), proto_buf.as_u32())?;

                    cpu.set_reg(Reg::R0, s_addr.as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::Getprotobyname => {
                let name_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let name = if name_ptr.as_u32() != 0 {
                    Self::read_c_string(mem, name_ptr).unwrap_or_default()
                } else {
                    String::new()
                };

                let proto_opt = match name.as_str() {
                    "ip" => Some(0u32),
                    "icmp" => Some(1u32),
                    "tcp" => Some(6u32),
                    "udp" => Some(17u32),
                    "ipv6" => Some(41u32),
                    _ => None,
                };

                if let Some(proto) = proto_opt {
                    let p_addr = self.stub_base.add(0xF80);
                    let name_buf = self.stub_base.add(0xFA0);

                    let mut nb = name.as_bytes().to_vec();
                    nb.push(0);
                    mem.write_bytes(name_buf, &nb)?;

                    mem.write_u32(p_addr, name_buf.as_u32())?;
                    mem.write_u32(p_addr.add(4), 0)?;
                    mem.write_u32(p_addr.add(8), proto)?;

                    cpu.set_reg(Reg::R0, p_addr.as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::Getprotobynumber => {
                let proto = cpu.reg(Reg::R0);
                let name_opt = match proto {
                    0 => Some("ip"),
                    1 => Some("icmp"),
                    6 => Some("tcp"),
                    17 => Some("udp"),
                    41 => Some("ipv6"),
                    _ => None,
                };

                if let Some(name) = name_opt {
                    let p_addr = self.stub_base.add(0xF80);
                    let name_buf = self.stub_base.add(0xFA0);

                    let mut nb = name.as_bytes().to_vec();
                    nb.push(0);
                    mem.write_bytes(name_buf, &nb)?;

                    mem.write_u32(p_addr, name_buf.as_u32())?;
                    mem.write_u32(p_addr.add(4), 0)?;
                    mem.write_u32(p_addr.add(8), proto)?;

                    cpu.set_reg(Reg::R0, p_addr.as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::Socketpair => {
                let domain = cpu.reg(Reg::R0) as i32;
                let sock_type = cpu.reg(Reg::R1) as i32;
                let _proto = cpu.reg(Reg::R2);
                let sv_ptr = GuestAddr::new(cpu.reg(Reg::R3));

                if sv_ptr.as_u32() != 0 {
                    let fd1 = self.next_socket_fd;
                    self.next_socket_fd += 1;
                    let fd2 = self.next_socket_fd;
                    self.next_socket_fd += 1;

                    self.socket_fds.insert(fd1, (domain, sock_type, true));
                    self.socket_fds.insert(fd2, (domain, sock_type, true));

                    mem.write_u32(sv_ptr, fd1)?;
                    mem.write_u32(sv_ptr.add(4), fd2)?;
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::EpollCreate | BionicFuncId::EpollCreate1 => {
                let epfd = self.next_socket_fd;
                self.next_socket_fd += 1;
                self.epoll_fds.insert(epfd, Vec::new());
                cpu.set_reg(Reg::R0, epfd);
            }
            BionicFuncId::EpollCtl => {
                let epfd = cpu.reg(Reg::R0);
                let op = cpu.reg(Reg::R1);
                let target_fd = cpu.reg(Reg::R2);
                let event_ptr = GuestAddr::new(cpu.reg(Reg::R3));

                if let Some(regs) = self.epoll_fds.get_mut(&epfd) {
                    match op {
                        1 => { // EPOLL_CTL_ADD
                            let events = if event_ptr.as_u32() != 0 {
                                mem.read_u32(event_ptr).unwrap_or(0)
                            } else {
                                0
                            };
                            let data = if event_ptr.as_u32() != 0 {
                                (mem.read_u32(event_ptr.add(4)).unwrap_or(0) as u64)
                                    | ((mem.read_u32(event_ptr.add(8)).unwrap_or(0) as u64) << 32)
                            } else {
                                0
                            };
                            regs.retain(|r| r.fd != target_fd);
                            regs.push(EpollRegistration {
                                fd: target_fd,
                                events,
                                data,
                            });
                            cpu.set_reg(Reg::R0, 0);
                        }
                        2 => { // EPOLL_CTL_DEL
                            regs.retain(|r| r.fd != target_fd);
                            cpu.set_reg(Reg::R0, 0);
                        }
                        3 => { // EPOLL_CTL_MOD
                            if let Some(r) = regs.iter_mut().find(|r| r.fd == target_fd) {
                                if event_ptr.as_u32() != 0 {
                                    r.events = mem.read_u32(event_ptr).unwrap_or(0);
                                    r.data = (mem.read_u32(event_ptr.add(4)).unwrap_or(0) as u64)
                                        | ((mem.read_u32(event_ptr.add(8)).unwrap_or(0) as u64) << 32);
                                }
                                cpu.set_reg(Reg::R0, 0);
                            } else {
                                cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                            }
                        }
                        _ => cpu.set_reg(Reg::R0, 0xFFFF_FFFF),
                    }
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::EpollWait | BionicFuncId::EpollPwait => {
                let epfd = cpu.reg(Reg::R0);
                let events_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let maxevents = cpu.reg(Reg::R2);

                if let Some(regs) = self.epoll_fds.get(&epfd) {
                    let count = regs.len().min(maxevents as usize);
                    for (i, r) in regs.iter().take(count).enumerate() {
                        let slot = events_ptr.add((i as u32) * 12);
                        mem.write_u32(slot, r.events)?;
                        mem.write_u32(slot.add(4), r.data as u32)?;
                        mem.write_u32(slot.add(8), (r.data >> 32) as u32)?;
                    }
                    cpu.set_reg(Reg::R0, count as u32);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::Pselect => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::Ppoll => {
                cpu.set_reg(Reg::R0, 0);
            }

            // High-Resolution Timers & POSIX Signals Extensions (Stage 72)
            BionicFuncId::TimerCreate => {
                let clockid = cpu.reg(Reg::R0);
                let sevp = GuestAddr::new(cpu.reg(Reg::R1));
                let timerid_ptr = GuestAddr::new(cpu.reg(Reg::R2));

                let sigev_signo = if sevp.as_u32() != 0 {
                    mem.read_u32(sevp.add(4)).unwrap_or(14) // default SIGALRM = 14
                } else {
                    14
                };

                let timerid = self.next_timer_id;
                self.next_timer_id += 1;

                self.timers.insert(timerid, PosixTimer {
                    clockid,
                    sigev_signo,
                    interval_sec: 0,
                    interval_nsec: 0,
                    value_sec: 0,
                    value_nsec: 0,
                    overrun_count: 0,
                });

                if timerid_ptr.as_u32() != 0 {
                    mem.write_u32(timerid_ptr, timerid)?;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::TimerSettime => {
                let timerid = cpu.reg(Reg::R0);
                let _flags = cpu.reg(Reg::R1);
                let new_val_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                let old_val_ptr = GuestAddr::new(cpu.reg(Reg::R3));

                if let Some(timer) = self.timers.get_mut(&timerid) {
                    if old_val_ptr.as_u32() != 0 {
                        mem.write_u32(old_val_ptr, timer.interval_sec)?;
                        mem.write_u32(old_val_ptr.add(4), timer.interval_nsec)?;
                        mem.write_u32(old_val_ptr.add(8), timer.value_sec)?;
                        mem.write_u32(old_val_ptr.add(12), timer.value_nsec)?;
                    }
                    if new_val_ptr.as_u32() != 0 {
                        timer.interval_sec = mem.read_u32(new_val_ptr).unwrap_or(0);
                        timer.interval_nsec = mem.read_u32(new_val_ptr.add(4)).unwrap_or(0);
                        timer.value_sec = mem.read_u32(new_val_ptr.add(8)).unwrap_or(0);
                        timer.value_nsec = mem.read_u32(new_val_ptr.add(12)).unwrap_or(0);
                    }
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::TimerGettime => {
                let timerid = cpu.reg(Reg::R0);
                let curr_val_ptr = GuestAddr::new(cpu.reg(Reg::R1));

                if let Some(timer) = self.timers.get(&timerid) {
                    if curr_val_ptr.as_u32() != 0 {
                        mem.write_u32(curr_val_ptr, timer.interval_sec)?;
                        mem.write_u32(curr_val_ptr.add(4), timer.interval_nsec)?;
                        mem.write_u32(curr_val_ptr.add(8), timer.value_sec)?;
                        mem.write_u32(curr_val_ptr.add(12), timer.value_nsec)?;
                    }
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::TimerGetoverrun => {
                let timerid = cpu.reg(Reg::R0);
                if let Some(timer) = self.timers.get(&timerid) {
                    cpu.set_reg(Reg::R0, timer.overrun_count);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::TimerDelete => {
                let timerid = cpu.reg(Reg::R0);
                if self.timers.remove(&timerid).is_some() {
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::Sigpending => {
                let set_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if set_ptr.as_u32() != 0 {
                    let pending = self.signal_state.pending_mask;
                    mem.write_u32(set_ptr, pending as u32)?;
                    mem.write_u32(set_ptr.add(4), (pending >> 32) as u32)?;
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::Sigsuspend => {
                // Temporarily unblocks signals and waits. Stub: return -1 with EINTR
                cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
            }
            BionicFuncId::Sigwait => {
                let set_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let sig_ptr = GuestAddr::new(cpu.reg(Reg::R1));

                if set_ptr.as_u32() != 0 {
                    let low = mem.read_u32(set_ptr).unwrap_or(0);
                    let sig = if low != 0 {
                        low.trailing_zeros() + 1
                    } else {
                        14 // default SIGALRM
                    };
                    if sig_ptr.as_u32() != 0 {
                        mem.write_u32(sig_ptr, sig)?;
                    }
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 22); // EINVAL
                }
            }
            BionicFuncId::Sigtimedwait | BionicFuncId::Sigwaitinfo => {
                let set_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let info_ptr = GuestAddr::new(cpu.reg(Reg::R1));

                if set_ptr.as_u32() != 0 {
                    let low = mem.read_u32(set_ptr).unwrap_or(0);
                    let sig = if low != 0 {
                        low.trailing_zeros() + 1
                    } else {
                        14
                    };
                    if info_ptr.as_u32() != 0 {
                        mem.write_u32(info_ptr, sig)?; // si_signo
                        mem.write_u32(info_ptr.add(4), 0)?; // si_errno
                        mem.write_u32(info_ptr.add(8), 0)?; // si_code
                    }
                    cpu.set_reg(Reg::R0, sig);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }

            // Process Resource Limits & System Info (Stage 73)
            BionicFuncId::Getrlimit | BionicFuncId::Getrlimit64 => {
                let res = cpu.reg(Reg::R0);
                let rlp = GuestAddr::new(cpu.reg(Reg::R1));
                let (cur, max) = self.rlimits.get(&res).copied().unwrap_or((u64::MAX, u64::MAX));

                if rlp.as_u32() != 0 {
                    if func_id == BionicFuncId::Getrlimit {
                        let cur32 = if cur > u32::MAX as u64 { u32::MAX } else { cur as u32 };
                        let max32 = if max > u32::MAX as u64 { u32::MAX } else { max as u32 };
                        mem.write_u32(rlp, cur32)?;
                        mem.write_u32(rlp.add(4), max32)?;
                    } else {
                        mem.write_u32(rlp, cur as u32)?;
                        mem.write_u32(rlp.add(4), (cur >> 32) as u32)?;
                        mem.write_u32(rlp.add(8), max as u32)?;
                        mem.write_u32(rlp.add(12), (max >> 32) as u32)?;
                    }
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::Setrlimit | BionicFuncId::Setrlimit64 => {
                let res = cpu.reg(Reg::R0);
                let rlp = GuestAddr::new(cpu.reg(Reg::R1));

                if rlp.as_u32() != 0 {
                    let (cur, max) = if func_id == BionicFuncId::Setrlimit {
                        let c = mem.read_u32(rlp).unwrap_or(0) as u64;
                        let m = mem.read_u32(rlp.add(4)).unwrap_or(0) as u64;
                        (c, m)
                    } else {
                        let c = (mem.read_u32(rlp).unwrap_or(0) as u64)
                            | ((mem.read_u32(rlp.add(4)).unwrap_or(0) as u64) << 32);
                        let m = (mem.read_u32(rlp.add(8)).unwrap_or(0) as u64)
                            | ((mem.read_u32(rlp.add(12)).unwrap_or(0) as u64) << 32);
                        (c, m)
                    };
                    self.rlimits.insert(res, (cur, max));
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::Prlimit | BionicFuncId::Prlimit64 => {
                let _pid = cpu.reg(Reg::R0);
                let res = cpu.reg(Reg::R1);
                let new_lim = GuestAddr::new(cpu.reg(Reg::R2));
                let old_lim = GuestAddr::new(cpu.reg(Reg::R3));

                let (cur, max) = self.rlimits.get(&res).copied().unwrap_or((u64::MAX, u64::MAX));

                if old_lim.as_u32() != 0 {
                    if func_id == BionicFuncId::Prlimit {
                        let cur32 = if cur > u32::MAX as u64 { u32::MAX } else { cur as u32 };
                        let max32 = if max > u32::MAX as u64 { u32::MAX } else { max as u32 };
                        mem.write_u32(old_lim, cur32)?;
                        mem.write_u32(old_lim.add(4), max32)?;
                    } else {
                        mem.write_u32(old_lim, cur as u32)?;
                        mem.write_u32(old_lim.add(4), (cur >> 32) as u32)?;
                        mem.write_u32(old_lim.add(8), max as u32)?;
                        mem.write_u32(old_lim.add(12), (max >> 32) as u32)?;
                    }
                }

                if new_lim.as_u32() != 0 {
                    let (nc, nm) = if func_id == BionicFuncId::Prlimit {
                        let c = mem.read_u32(new_lim).unwrap_or(0) as u64;
                        let m = mem.read_u32(new_lim.add(4)).unwrap_or(0) as u64;
                        (c, m)
                    } else {
                        let c = (mem.read_u32(new_lim).unwrap_or(0) as u64)
                            | ((mem.read_u32(new_lim.add(4)).unwrap_or(0) as u64) << 32);
                        let m = (mem.read_u32(new_lim.add(8)).unwrap_or(0) as u64)
                            | ((mem.read_u32(new_lim.add(12)).unwrap_or(0) as u64) << 32);
                        (c, m)
                    };
                    self.rlimits.insert(res, (nc, nm));
                }

                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::Sysinfo => {
                let info_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if info_ptr.as_u32() != 0 {
                    mem.write_u32(info_ptr, 3600)?; // uptime = 1 hour
                    mem.write_u32(info_ptr.add(4), 65536)?; // loads[0]
                    mem.write_u32(info_ptr.add(8), 65536)?; // loads[1]
                    mem.write_u32(info_ptr.add(12), 65536)?; // loads[2]
                    mem.write_u32(info_ptr.add(16), 0x8000_0000)?; // totalram = 2 GB
                    mem.write_u32(info_ptr.add(20), 0x4000_0000)?; // freeram = 1 GB
                    mem.write_u32(info_ptr.add(24), 0)?; // sharedram
                    mem.write_u32(info_ptr.add(28), 0)?; // bufferram
                    mem.write_u32(info_ptr.add(32), 0)?; // totalswap
                    mem.write_u32(info_ptr.add(36), 0)?; // freeswap
                    mem.write_u16(info_ptr.add(40), 42)?; // procs
                    mem.write_u16(info_ptr.add(42), 0)?; // pad
                    mem.write_u32(info_ptr.add(44), 0)?; // totalhigh
                    mem.write_u32(info_ptr.add(48), 0)?; // freehigh
                    mem.write_u32(info_ptr.add(52), 1)?; // mem_unit = 1 byte
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::Getpagesize => {
                cpu.set_reg(Reg::R0, 4096);
            }
            BionicFuncId::GetNprocs | BionicFuncId::GetNprocsConf => {
                let nprocs = std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(4);
                cpu.set_reg(Reg::R0, nprocs);
            }
            BionicFuncId::Sysconf => {
                let name = cpu.reg(Reg::R0);
                let nprocs = std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(4);
                let val = match name {
                    0 => 131072,   // _SC_ARG_MAX
                    1 => 1024,     // _SC_CHILD_MAX
                    2 | 6 => 100,  // _SC_CLK_TCK
                    3 => 65536,    // _SC_NGROUPS_MAX
                    4 | 5 => 1024, // _SC_OPEN_MAX
                    29 | 30 | 39 | 40 => 4096, // _SC_PAGESIZE / _SC_PAGE_SIZE
                    85 => 1048576, // _SC_PHYS_PAGES (4GB / 4KB)
                    86 => 524288,  // _SC_AVPHYS_PAGES (2GB / 4KB)
                    96 => nprocs,  // _SC_NPROCESSORS_CONF
                    97 => nprocs,  // _SC_NPROCESSORS_ONLN
                    _ => 0xFFFF_FFFF,
                };
                cpu.set_reg(Reg::R0, val);
            }

            // Extended Filesystem & Path APIs (Stage 74)
            BionicFuncId::Symlink | BionicFuncId::Symlinkat |
            BionicFuncId::Link | BionicFuncId::Linkat |
            BionicFuncId::Chmod | BionicFuncId::Fchmod | BionicFuncId::Fchmodat |
            BionicFuncId::Chown | BionicFuncId::Fchown | BionicFuncId::Lchown | BionicFuncId::Fchownat |
            BionicFuncId::Mknod | BionicFuncId::Mknodat |
            BionicFuncId::Sync | BionicFuncId::Fsync | BionicFuncId::Fdatasync => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::Pipe2 => {
                let arr_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let _flags = cpu.reg(Reg::R1);
                let read_fd  = self.next_pipe_fd;
                let write_fd = self.next_pipe_fd + 1;
                self.next_pipe_fd += 2;
                self.pipe_fds.insert(read_fd, (write_fd, Vec::new()));
                if arr_ptr.as_u32() != 0 {
                    mem.write_u32(arr_ptr, read_fd)?;
                    mem.write_u32(arr_ptr.add(4), write_fd)?;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::Dup3 => {
                let old_fd = cpu.reg(Reg::R0);
                let new_fd = cpu.reg(Reg::R1);
                let _flags = cpu.reg(Reg::R2);
                if old_fd == new_fd {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF); // EINVAL per POSIX
                } else {
                    cpu.set_reg(Reg::R0, new_fd);
                }
            }
            BionicFuncId::Statfs | BionicFuncId::Statfs64 | BionicFuncId::Fstatfs | BionicFuncId::Fstatfs64 |
            BionicFuncId::Statvfs | BionicFuncId::Fstatvfs => {
                let buf_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if buf_ptr.as_u32() != 0 {
                    // struct statfs / statvfs:
                    // 0: f_type (0xEF53 = ext4)
                    // 4: f_bsize (4096)
                    // 8: f_blocks (10485760 = 40GB)
                    // 12: f_bfree (5242880 = 20GB)
                    // 16: f_bavail (5242880)
                    // 20: f_files (1000000)
                    // 24: f_ffree (900000)
                    // 28: f_fsid.val[0]
                    // 32: f_fsid.val[1]
                    // 36: f_namelen (255)
                    // 40: f_frsize (4096)
                    // 44: f_flags (0)
                    mem.write_u32(buf_ptr, 0xEF53)?;
                    mem.write_u32(buf_ptr.add(4), 4096)?;
                    mem.write_u32(buf_ptr.add(8), 10_485_760)?;
                    mem.write_u32(buf_ptr.add(12), 5_242_880)?;
                    mem.write_u32(buf_ptr.add(16), 5_242_880)?;
                    mem.write_u32(buf_ptr.add(20), 1_000_000)?;
                    mem.write_u32(buf_ptr.add(24), 900_000)?;
                    mem.write_u32(buf_ptr.add(28), 0)?;
                    mem.write_u32(buf_ptr.add(32), 0)?;
                    mem.write_u32(buf_ptr.add(36), 255)?;
                    mem.write_u32(buf_ptr.add(40), 4096)?;
                    mem.write_u32(buf_ptr.add(44), 0)?;
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            // Terminal / TTY & IOCTL APIs (Stage 75)
            BionicFuncId::Isatty => {
                let fd = cpu.reg(Reg::R0);
                if fd <= 2 {
                    cpu.set_reg(Reg::R0, 1);
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::Ttyname => {
                let fd = cpu.reg(Reg::R0);
                if fd <= 2 {
                    let dev_pts = b"/dev/pts/0\0";
                    mem.write_bytes(self.ttyname_addr, dev_pts)?;
                    cpu.set_reg(Reg::R0, self.ttyname_addr.as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::TtynameR => {
                let fd = cpu.reg(Reg::R0);
                let buf_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let buflen = cpu.reg(Reg::R2);
                if fd > 2 {
                    cpu.set_reg(Reg::R0, 25); // ENOTTY
                } else if buflen < 11 {
                    cpu.set_reg(Reg::R0, 34); // ERANGE
                } else if buf_ptr.as_u32() != 0 {
                    let dev_pts = b"/dev/pts/0\0";
                    mem.write_bytes(buf_ptr, dev_pts)?;
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 14); // EFAULT
                }
            }
            BionicFuncId::Tcgetattr => {
                let termios_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if termios_ptr.as_u32() != 0 {
                    // struct termios:
                    // 0:  c_iflag (ICRNL | IXON = 0x0500)
                    // 4:  c_oflag (OPOST | ONLCR = 0x0005)
                    // 8:  c_cflag (B38400 | CS8 | CREAD = 0x00BF)
                    // 12: c_lflag (ISIG | ICANON | ECHO | ECHOE = 0x8A3B)
                    // 16: c_line (0)
                    // 17..48: c_cc (32 bytes control characters)
                    mem.write_u32(termios_ptr, 0x0500)?;
                    mem.write_u32(termios_ptr.add(4), 0x0005)?;
                    mem.write_u32(termios_ptr.add(8), 0x00BF)?;
                    mem.write_u32(termios_ptr.add(12), 0x8A3B)?;
                    mem.write_u8(termios_ptr.add(16), 0)?;
                    let mut cc = [0u8; 32];
                    cc[5] = 0; // VTIME
                    cc[6] = 1; // VMIN
                    mem.write_bytes(termios_ptr.add(17), &cc)?;
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::Tcsetattr | BionicFuncId::Tcflush | BionicFuncId::Tcsendbreak |
            BionicFuncId::Tcdrain | BionicFuncId::Tcflow => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::Cfgetispeed | BionicFuncId::Cfgetospeed => {
                let termios_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if termios_ptr.as_u32() != 0 {
                    let c_cflag = mem.read_u32(termios_ptr.add(8))?;
                    let speed = c_cflag & 0x100F;
                    cpu.set_reg(Reg::R0, speed);
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::Cfsetispeed | BionicFuncId::Cfsetospeed => {
                let termios_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let speed = cpu.reg(Reg::R1);
                if termios_ptr.as_u32() != 0 {
                    let c_cflag = mem.read_u32(termios_ptr.add(8))?;
                    let updated = (c_cflag & !0x100F) | (speed & 0x100F);
                    mem.write_u32(termios_ptr.add(8), updated)?;
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::Cfmakeraw => {
                let termios_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if termios_ptr.as_u32() != 0 {
                    let iflag = mem.read_u32(termios_ptr)?;
                    let oflag = mem.read_u32(termios_ptr.add(4))?;
                    let cflag = mem.read_u32(termios_ptr.add(8))?;
                    let lflag = mem.read_u32(termios_ptr.add(12))?;

                    mem.write_u32(termios_ptr, iflag & !0x05FF)?;
                    mem.write_u32(termios_ptr.add(4), oflag & !0x0001)?;
                    mem.write_u32(termios_ptr.add(8), (cflag & !0x0130) | 0x0030)?;
                    mem.write_u32(termios_ptr.add(12), lflag & !0x804B)?;
                    mem.write_u8(termios_ptr.add(17 + 5), 0)?;
                    mem.write_u8(termios_ptr.add(17 + 6), 1)?;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::Ioctl => {
                let _fd = cpu.reg(Reg::R0);
                let request = cpu.reg(Reg::R1);
                let argp = GuestAddr::new(cpu.reg(Reg::R2));
                match request {
                    0x5413 => {
                        // TIOCGWINSZ: struct winsize { ws_row, ws_col, ws_xpixel, ws_ypixel }
                        if argp.as_u32() != 0 {
                            mem.write_u16(argp, 24)?;
                            mem.write_u16(argp.add(2), 80)?;
                            mem.write_u16(argp.add(4), 0)?;
                            mem.write_u16(argp.add(6), 0)?;
                        }
                        cpu.set_reg(Reg::R0, 0);
                    }
                    0x541B => {
                        // FIONREAD
                        if argp.as_u32() != 0 {
                            mem.write_u32(argp, 0)?;
                        }
                        cpu.set_reg(Reg::R0, 0);
                    }
                    0x5401 => {
                        // TCGETS
                        if argp.as_u32() != 0 {
                            mem.write_u32(argp, 0x0500)?;
                            mem.write_u32(argp.add(4), 0x0005)?;
                            mem.write_u32(argp.add(8), 0x00BF)?;
                            mem.write_u32(argp.add(12), 0x8A3B)?;
                            mem.write_u8(argp.add(16), 0)?;
                        }
                        cpu.set_reg(Reg::R0, 0);
                    }
                    _ => {
                        cpu.set_reg(Reg::R0, 0);
                    }
                }
            }
            // System Event Tracing & Android Trace (Stage 76)
            BionicFuncId::AtraceInit => {
                // Initialize tracing state, default no-op per Bionic
            }
            BionicFuncId::AtraceSetTracingEnabled => {
                let enabled = cpu.reg(Reg::R0) != 0;
                self.atrace_enabled = enabled;
            }
            BionicFuncId::AtraceGetEnabledTags => {
                if self.atrace_enabled {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                    cpu.set_reg(Reg::R1, 0xFFFF_FFFF);
                } else {
                    cpu.set_reg(Reg::R0, 0);
                    cpu.set_reg(Reg::R1, 0);
                }
            }
            BionicFuncId::AtraceBeginBody => {
                let name_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if self.atrace_enabled && name_ptr.as_u32() != 0 {
                    let name = Self::read_c_string(mem, name_ptr)?;
                    self.atrace_events.push(AtraceEvent::Begin(name));
                }
            }
            BionicFuncId::AtraceEndBody => {
                if self.atrace_enabled {
                    self.atrace_events.push(AtraceEvent::End);
                }
            }
            BionicFuncId::AtraceAsyncBeginBody => {
                let name_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let cookie = cpu.reg(Reg::R1) as i32;
                if self.atrace_enabled && name_ptr.as_u32() != 0 {
                    let name = Self::read_c_string(mem, name_ptr)?;
                    self.atrace_events.push(AtraceEvent::AsyncBegin(name, cookie));
                }
            }
            BionicFuncId::AtraceAsyncEndBody => {
                let name_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let cookie = cpu.reg(Reg::R1) as i32;
                if self.atrace_enabled && name_ptr.as_u32() != 0 {
                    let name = Self::read_c_string(mem, name_ptr)?;
                    self.atrace_events.push(AtraceEvent::AsyncEnd(name, cookie));
                }
            }
            BionicFuncId::AtraceIntBody => {
                let name_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let value = cpu.reg(Reg::R1) as i32;
                if self.atrace_enabled && name_ptr.as_u32() != 0 {
                    let name = Self::read_c_string(mem, name_ptr)?;
                    self.atrace_events.push(AtraceEvent::Counter(name, value as i64));
                }
            }
            BionicFuncId::AtraceInt64Body => {
                let name_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let low = cpu.reg(Reg::R2) as u64;
                let high = cpu.reg(Reg::R3) as u64;
                let value = (high << 32) | low;
                if self.atrace_enabled && name_ptr.as_u32() != 0 {
                    let name = Self::read_c_string(mem, name_ptr)?;
                    self.atrace_events.push(AtraceEvent::Counter(name, value as i64));
                }
            }
            // EventFD & POSIX Asynchronous I/O APIs (Stage 77)
            BionicFuncId::Eventfd => {
                let initval = cpu.reg(Reg::R0);
                let flags = cpu.reg(Reg::R1);
                let fd = self.next_eventfd;
                self.next_eventfd += 1;
                self.eventfd_table.insert(fd, (initval as u64, flags));
                cpu.set_reg(Reg::R0, fd);
            }
            BionicFuncId::EventfdRead => {
                let fd = cpu.reg(Reg::R0);
                let val_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if let Some((counter, flags)) = self.eventfd_table.get_mut(&fd) {
                    let val = if *flags & 1 != 0 {
                        if *counter > 0 {
                            *counter -= 1;
                            1u64
                        } else {
                            0u64
                        }
                    } else {
                        let c = *counter;
                        *counter = 0;
                        c
                    };
                    if val_ptr.as_u32() != 0 {
                        mem.write_u32(val_ptr, (val & 0xFFFF_FFFF) as u32)?;
                        mem.write_u32(val_ptr.add(4), (val >> 32) as u32)?;
                    }
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::EventfdWrite => {
                let fd = cpu.reg(Reg::R0);
                let low = cpu.reg(Reg::R2) as u64;
                let high = cpu.reg(Reg::R3) as u64;
                let val = if low == 0 && high == 0 && cpu.reg(Reg::R1) != 0 {
                    cpu.reg(Reg::R1) as u64
                } else {
                    (high << 32) | low
                };
                if let Some((counter, _flags)) = self.eventfd_table.get_mut(&fd) {
                    *counter = (*counter).saturating_add(val);
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::AioRead | BionicFuncId::AioWrite | BionicFuncId::AioError |
            BionicFuncId::AioSuspend => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::AioReturn => {
                let aiocbp = GuestAddr::new(cpu.reg(Reg::R0));
                if aiocbp.as_u32() != 0 {
                    let nbytes = mem.read_u32(aiocbp.add(20)).unwrap_or(0);
                    cpu.set_reg(Reg::R0, nbytes);
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::AioCancel => {
                cpu.set_reg(Reg::R0, 2); // AIO_ALLDONE
            }
            // POSIX Extended Capabilities & Credentials (Stage 78)
            BionicFuncId::Capget => {
                let hdrp = GuestAddr::new(cpu.reg(Reg::R0));
                let datap = GuestAddr::new(cpu.reg(Reg::R1));
                if hdrp.as_u32() != 0 {
                    mem.write_u32(hdrp, 0x2008_0522)?; // _LINUX_CAPABILITY_VERSION_3
                }
                if datap.as_u32() != 0 {
                    mem.write_u32(datap, 0)?;
                    mem.write_u32(datap.add(4), 0)?;
                    mem.write_u32(datap.add(8), 0)?;
                    mem.write_u32(datap.add(12), 0)?;
                    mem.write_u32(datap.add(16), 0)?;
                    mem.write_u32(datap.add(20), 0)?;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::Capset | BionicFuncId::Setgroups |
            BionicFuncId::Setresuid | BionicFuncId::Setresgid |
            BionicFuncId::Setreuid | BionicFuncId::Setregid => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::Getgroups => {
                let size = cpu.reg(Reg::R0) as usize;
                let list_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if size == 0 {
                    cpu.set_reg(Reg::R0, 1);
                } else if list_ptr.as_u32() != 0 {
                    mem.write_u32(list_ptr, 10000)?; // AID_APP_START
                    cpu.set_reg(Reg::R0, 1);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::Getresuid | BionicFuncId::Getresgid => {
                let r_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let e_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let s_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                if r_ptr.as_u32() != 0 {
                    mem.write_u32(r_ptr, 10000)?;
                }
                if e_ptr.as_u32() != 0 {
                    mem.write_u32(e_ptr, 10000)?;
                }
                if s_ptr.as_u32() != 0 {
                    mem.write_u32(s_ptr, 10000)?;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            // CPU Affinity & Multi-core Thread Scheduling APIs (Stage 79)
            BionicFuncId::SchedSetaffinity => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::SchedGetaffinity => {
                let _pid = cpu.reg(Reg::R0);
                let cpusetsize = cpu.reg(Reg::R1) as usize;
                let mask_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                if mask_ptr.as_u32() != 0 {
                    let nprocs = std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(4);
                    let mask = if nprocs >= 32 { 0xFFFF_FFFF } else { (1u32 << nprocs) - 1 };
                    mem.write_u32(mask_ptr, mask)?;
                    if cpusetsize > 4 {
                        for i in 4..cpusetsize {
                            mem.write_u8(mask_ptr.add(i as u32), 0)?;
                        }
                    }
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::SchedGetcpu => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::SchedGetscheduler => {
                cpu.set_reg(Reg::R0, 0); // SCHED_OTHER (0)
            }
            BionicFuncId::SchedSetscheduler | BionicFuncId::SchedSetparam => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::SchedGetparam => {
                let param_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if param_ptr.as_u32() != 0 {
                    mem.write_u32(param_ptr, 0)?; // sched_priority = 0
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::SchedGetPriorityMin => {
                let policy = cpu.reg(Reg::R0);
                let min_pri = if policy == 1 || policy == 2 { 1 } else { 0 };
                cpu.set_reg(Reg::R0, min_pri);
            }
            BionicFuncId::SchedGetPriorityMax => {
                let policy = cpu.reg(Reg::R0);
                let max_pri = if policy == 1 || policy == 2 { 99 } else { 0 };
                cpu.set_reg(Reg::R0, max_pri);
            }
            BionicFuncId::SchedRrGetInterval => {
                let tp_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if tp_ptr.as_u32() != 0 {
                    mem.write_u32(tp_ptr, 0)?; // tv_sec = 0
                    mem.write_u32(tp_ptr.add(4), 10_000_000)?; // tv_nsec = 10ms
                }
                cpu.set_reg(Reg::R0, 0);
            }
            // POSIX Shared Memory, Anonymous Files & Android Ashmem (Stage 80)
            BionicFuncId::ShmOpen => {
                let name_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let oflag = cpu.reg(Reg::R1);
                let _mode = cpu.reg(Reg::R2);
                let name = if name_ptr.as_u32() != 0 {
                    Self::read_c_string(mem, name_ptr).unwrap_or_else(|_| "shm".to_string())
                } else {
                    "shm".to_string()
                };
                let fd = match self.vfs.open("/dev/ashmem", oflag) {
                    Ok(fd) => {
                        if let Some(region) = self.vfs.ashmem_regions.get_mut(&fd) {
                            region.name = format!("/dev/shm/{}", name.trim_start_matches('/'));
                        }
                        fd
                    }
                    Err(_) => 0xFFFF_FFFF,
                };
                cpu.set_reg(Reg::R0, fd);
            }
            BionicFuncId::ShmUnlink => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::MemfdCreate => {
                let name_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let _flags = cpu.reg(Reg::R1);
                let name = if name_ptr.as_u32() != 0 {
                    Self::read_c_string(mem, name_ptr).unwrap_or_else(|_| "memfd".to_string())
                } else {
                    "memfd".to_string()
                };
                let fd = match self.vfs.open("/dev/ashmem", 2) {
                    Ok(fd) => {
                        if let Some(region) = self.vfs.ashmem_regions.get_mut(&fd) {
                            region.name = name;
                        }
                        fd
                    }
                    Err(_) => 0xFFFF_FFFF,
                };
                cpu.set_reg(Reg::R0, fd);
            }
            BionicFuncId::AshmemCreateRegion => {
                let name_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let size = cpu.reg(Reg::R1) as usize;
                let name = if name_ptr.as_u32() != 0 {
                    Self::read_c_string(mem, name_ptr).unwrap_or_else(|_| "ashmem".to_string())
                } else {
                    "ashmem".to_string()
                };
                let fd = match self.vfs.open("/dev/ashmem", 2) {
                    Ok(fd) => {
                        if let Some(region) = self.vfs.ashmem_regions.get_mut(&fd) {
                            region.name = name;
                            region.size = size;
                            if let Ok(mut lock) = region.data.lock() {
                                lock.resize(size, 0);
                            }
                            region.is_initialized = true;
                        }
                        fd
                    }
                    Err(_) => 0xFFFF_FFFF,
                };
                cpu.set_reg(Reg::R0, fd);
            }
            BionicFuncId::AshmemSetProtRegion => {
                let fd = cpu.reg(Reg::R0);
                let prot = cpu.reg(Reg::R1);
                if let Some(region) = self.vfs.ashmem_regions.get_mut(&fd) {
                    region.prot_mask = prot;
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::AshmemGetProtRegion => {
                let fd = cpu.reg(Reg::R0);
                if let Some(region) = self.vfs.ashmem_regions.get(&fd) {
                    cpu.set_reg(Reg::R0, region.prot_mask);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::AshmemGetSizeRegion => {
                let fd = cpu.reg(Reg::R0);
                if let Some(region) = self.vfs.ashmem_regions.get(&fd) {
                    cpu.set_reg(Reg::R0, region.size as u32);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::AshmemPinRegion | BionicFuncId::AshmemUnpinRegion => {
                cpu.set_reg(Reg::R0, 0);
            }
            // Advanced Signal Masking & Extended Pthread APIs (Stage 81)
            BionicFuncId::Sigqueue | BionicFuncId::PthreadKill => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::PthreadSetnameNp => {
                let thread = cpu.reg(Reg::R0);
                let name_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if name_ptr.as_u32() != 0 {
                    if let Ok(name) = Self::read_c_string(mem, name_ptr) {
                        self.thread_names.insert(thread, name);
                    }
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::PthreadGetnameNp => {
                let thread = cpu.reg(Reg::R0);
                let buf_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let buflen = cpu.reg(Reg::R2) as usize;
                let name = self.thread_names.get(&thread).map(|s| s.as_str()).unwrap_or("main");
                let bytes = name.as_bytes();
                if bytes.len() + 1 > buflen {
                    cpu.set_reg(Reg::R0, 34); // ERANGE
                } else if buf_ptr.as_u32() != 0 {
                    mem.write_bytes(buf_ptr, bytes)?;
                    mem.write_u8(buf_ptr.add(bytes.len() as u32), 0)?;
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 14); // EFAULT
                }
            }
            BionicFuncId::PthreadEqual => {
                let t1 = cpu.reg(Reg::R0);
                let t2 = cpu.reg(Reg::R1);
                cpu.set_reg(Reg::R0, if t1 == t2 { 1 } else { 0 });
            }
            BionicFuncId::PthreadGetattrNp => {
                let attr_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if attr_ptr.as_u32() != 0 {
                    mem.write_u32(attr_ptr, 0)?; // flags / detachstate
                    mem.write_u32(attr_ptr.add(4), 0x7000_0000)?; // stackaddr
                    mem.write_u32(attr_ptr.add(8), 0x0010_0000)?; // stacksize (1MB)
                    mem.write_u32(attr_ptr.add(12), 4096)?; // guardsize
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            // Android Memory Management & Security Log Extensions (Stage 82)
            BionicFuncId::AndroidMallopt => {
                cpu.set_reg(Reg::R0, 1);
            }
            BionicFuncId::MallocInfo => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::Mallinfo => {
                let ret_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if ret_ptr.as_u32() != 0 {
                    let heap_used = self.heap_current.as_u32().saturating_sub(0x0002_0000);
                    let heap_free = self.heap_limit.as_u32().saturating_sub(self.heap_current.as_u32());
                    mem.write_u32(ret_ptr, heap_used)?; // arena
                    mem.write_u32(ret_ptr.add(4), 1)?; // ordblks
                    mem.write_u32(ret_ptr.add(8), 0)?; // smblks
                    mem.write_u32(ret_ptr.add(12), 0)?; // hblks
                    mem.write_u32(ret_ptr.add(16), 0)?; // usmblks
                    mem.write_u32(ret_ptr.add(20), 0)?; // fsmblks
                    mem.write_u32(ret_ptr.add(24), heap_used)?; // uordblks
                    mem.write_u32(ret_ptr.add(28), heap_free)?; // fordblks
                    mem.write_u32(ret_ptr.add(32), 0)?; // keepcost
                    mem.write_u32(ret_ptr.add(36), 0)?;
                }
                cpu.set_reg(Reg::R0, ret_ptr.as_u32());
            }
            BionicFuncId::AndroidLogBwrite | BionicFuncId::AndroidLogSecurityBwrite => {
                let len = cpu.reg(Reg::R2);
                cpu.set_reg(Reg::R0, len);
            }
            BionicFuncId::AndroidLogBtwrite => {
                let len = cpu.reg(Reg::R3);
                cpu.set_reg(Reg::R0, len);
            }
            // POSIX Message Queues (Stage 83)
            BionicFuncId::MqOpen => {
                let name_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let _oflag = cpu.reg(Reg::R1);
                let name = if name_ptr.as_u32() != 0 {
                    Self::read_c_string(mem, name_ptr).unwrap_or_else(|_| "mq".to_string())
                } else {
                    "mq".to_string()
                };
                let mqdes = self.next_mqdes;
                self.next_mqdes += 1;
                self.mqueue_table.insert(mqdes, (name, VecDeque::new()));
                cpu.set_reg(Reg::R0, mqdes);
            }
            BionicFuncId::MqClose => {
                let mqdes = cpu.reg(Reg::R0);
                self.mqueue_table.remove(&mqdes);
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::MqUnlink => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::MqSend | BionicFuncId::MqTimedsend => {
                let mqdes = cpu.reg(Reg::R0);
                let msg_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let msg_len = cpu.reg(Reg::R2) as usize;
                let prio = cpu.reg(Reg::R3);
                if let Some((_, queue)) = self.mqueue_table.get_mut(&mqdes) {
                    let mut buf = vec![0u8; msg_len];
                    if msg_len > 0 && msg_ptr.as_u32() != 0 {
                        mem.read_bytes(msg_ptr, &mut buf)?;
                    }
                    queue.push_back((buf, prio));
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::MqReceive | BionicFuncId::MqTimedreceive => {
                let mqdes = cpu.reg(Reg::R0);
                let msg_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let max_len = cpu.reg(Reg::R2) as usize;
                let prio_ptr = GuestAddr::new(cpu.reg(Reg::R3));
                if let Some((_, queue)) = self.mqueue_table.get_mut(&mqdes) {
                    if let Some((msg, prio)) = queue.pop_front() {
                        let count = msg.len().min(max_len);
                        if msg_ptr.as_u32() != 0 && count > 0 {
                            mem.write_bytes(msg_ptr, &msg[..count])?;
                        }
                        if prio_ptr.as_u32() != 0 {
                            mem.write_u32(prio_ptr, prio)?;
                        }
                        cpu.set_reg(Reg::R0, count as u32);
                    } else {
                        cpu.set_reg(Reg::R0, 0);
                    }
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::MqGetattr => {
                let mqdes = cpu.reg(Reg::R0);
                let attr_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if let Some((_, queue)) = self.mqueue_table.get(&mqdes) {
                    if attr_ptr.as_u32() != 0 {
                        mem.write_u32(attr_ptr, 0)?; // mq_flags
                        mem.write_u32(attr_ptr.add(4), 10)?; // mq_maxmsg
                        mem.write_u32(attr_ptr.add(8), 8192)?; // mq_msgsize
                        mem.write_u32(attr_ptr.add(12), queue.len() as u32)?; // mq_curmsgs
                    }
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::MqSetattr => {
                cpu.set_reg(Reg::R0, 0);
            }
            // Extended Network Interface Discovery (Stage 84)
            BionicFuncId::IfNametoindex => {
                let name_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let idx = if name_ptr.as_u32() != 0 {
                    if let Ok(name) = Self::read_c_string(mem, name_ptr) {
                        match name.as_str() {
                            "lo" => 1,
                            "wlan0" => 2,
                            "rmnet0" => 3,
                            "eth0" => 4,
                            _ => 0,
                        }
                    } else {
                        0
                    }
                } else {
                    0
                };
                cpu.set_reg(Reg::R0, idx);
            }
            BionicFuncId::IfIndextoname => {
                let ifindex = cpu.reg(Reg::R0);
                let ifname_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let name_opt: Option<&[u8]> = match ifindex {
                    1 => Some(b"lo\0"),
                    2 => Some(b"wlan0\0"),
                    3 => Some(b"rmnet0\0"),
                    4 => Some(b"eth0\0"),
                    _ => None,
                };
                if let Some(bytes) = name_opt {
                    if ifname_ptr.as_u32() != 0 {
                        mem.write_bytes(ifname_ptr, bytes)?;
                        cpu.set_reg(Reg::R0, ifname_ptr.as_u32());
                    } else {
                        cpu.set_reg(Reg::R0, 0);
                    }
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::IfNameindex => {
                let base = self.stub_base.add(0xD00);
                // struct if_nameindex { unsigned int if_index; char *if_name; };
                // 1: lo
                mem.write_u32(base, 1)?;
                mem.write_u32(base.add(4), base.add(0x40).as_u32())?;
                mem.write_bytes(base.add(0x40), b"lo\0")?;

                // 2: wlan0
                mem.write_u32(base.add(8), 2)?;
                mem.write_u32(base.add(12), base.add(0x50).as_u32())?;
                mem.write_bytes(base.add(0x50), b"wlan0\0")?;

                // 3: rmnet0
                mem.write_u32(base.add(16), 3)?;
                mem.write_u32(base.add(20), base.add(0x60).as_u32())?;
                mem.write_bytes(base.add(0x60), b"rmnet0\0")?;

                // Terminator { 0, NULL }
                mem.write_u32(base.add(24), 0)?;
                mem.write_u32(base.add(28), 0)?;

                cpu.set_reg(Reg::R0, base.as_u32());
            }
            BionicFuncId::IfFreenameindex => {
                cpu.set_reg(Reg::R0, 0);
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
            BionicFuncId::DlIteratePhdr => {
                // dl_iterate_phdr(callback, data)
                // callback: fn(*const dl_phdr_info, size_t, *mut void) -> i32
                // dl_phdr_info: { dlpi_addr: u32, dlpi_name_ptr: u32, dlpi_phdr: u32, dlpi_phnum: u16 }
                // We stub this: iterate all loaded libraries, call back for each.
                // For simplicity in DBT: we return 0 (no libraries enumerated, callback not invoked)
                // This matches Android behavior when no phdr callback has been registered.
                // Real unwind stacks use __gnu_Unwind_Find_exidx instead.
                cpu.set_reg(Reg::R0, 0);
            }

            // --- Atomic Builtins ---
            BionicFuncId::AtomicFetchAdd4 => {
                // __atomic_fetch_add_4(ptr, val, memorder) -> old_val
                let ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let val = cpu.reg(Reg::R1);
                if ptr.as_u32() != 0 {
                    let old = mem.read_u32(ptr)?;
                    mem.write_u32(ptr, old.wrapping_add(val))?;
                    cpu.set_reg(Reg::R0, old);
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::AtomicFetchSub4 => {
                let ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let val = cpu.reg(Reg::R1);
                if ptr.as_u32() != 0 {
                    let old = mem.read_u32(ptr)?;
                    mem.write_u32(ptr, old.wrapping_sub(val))?;
                    cpu.set_reg(Reg::R0, old);
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::AtomicFetchAnd4 => {
                let ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let val = cpu.reg(Reg::R1);
                if ptr.as_u32() != 0 {
                    let old = mem.read_u32(ptr)?;
                    mem.write_u32(ptr, old & val)?;
                    cpu.set_reg(Reg::R0, old);
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::AtomicFetchOr4 => {
                let ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let val = cpu.reg(Reg::R1);
                if ptr.as_u32() != 0 {
                    let old = mem.read_u32(ptr)?;
                    mem.write_u32(ptr, old | val)?;
                    cpu.set_reg(Reg::R0, old);
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::AtomicFetchXor4 => {
                let ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let val = cpu.reg(Reg::R1);
                if ptr.as_u32() != 0 {
                    let old = mem.read_u32(ptr)?;
                    mem.write_u32(ptr, old ^ val)?;
                    cpu.set_reg(Reg::R0, old);
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::AtomicLoad4 => {
                // __atomic_load_4(ptr, memorder) -> val
                let ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if ptr.as_u32() != 0 {
                    let val = mem.read_u32(ptr)?;
                    cpu.set_reg(Reg::R0, val);
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::AtomicStore4 => {
                // __atomic_store_4(ptr, val, memorder)
                let ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let val = cpu.reg(Reg::R1);
                if ptr.as_u32() != 0 {
                    mem.write_u32(ptr, val)?;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::AtomicCompareExchange4 => {
                // __atomic_compare_exchange_4(ptr, expected_ptr, desired, weak, success_mo, fail_mo) -> bool
                let ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let expected_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let desired = cpu.reg(Reg::R2);
                if ptr.as_u32() != 0 && expected_ptr.as_u32() != 0 {
                    let current = mem.read_u32(ptr)?;
                    let expected = mem.read_u32(expected_ptr)?;
                    if current == expected {
                        mem.write_u32(ptr, desired)?;
                        cpu.set_reg(Reg::R0, 1); // true: success
                    } else {
                        mem.write_u32(expected_ptr, current)?; // update expected to current
                        cpu.set_reg(Reg::R0, 0); // false: failure
                    }
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::AtomicExchange4 => {
                // __atomic_exchange_4(ptr, val, memorder) -> old_val
                let ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let val = cpu.reg(Reg::R1);
                if ptr.as_u32() != 0 {
                    let old = mem.read_u32(ptr)?;
                    mem.write_u32(ptr, val)?;
                    cpu.set_reg(Reg::R0, old);
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::SyncValCompareAndSwap4 => {
                // __sync_val_compare_and_swap_4(ptr, old, new) -> old_value
                let ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let expected = cpu.reg(Reg::R1);
                let desired = cpu.reg(Reg::R2);
                if ptr.as_u32() != 0 {
                    let current = mem.read_u32(ptr)?;
                    if current == expected {
                        mem.write_u32(ptr, desired)?;
                    }
                    cpu.set_reg(Reg::R0, current);
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::SyncBoolCompareAndSwap4 => {
                // __sync_bool_compare_and_swap_4(ptr, old, new) -> bool
                let ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let expected = cpu.reg(Reg::R1);
                let desired = cpu.reg(Reg::R2);
                if ptr.as_u32() != 0 {
                    let current = mem.read_u32(ptr)?;
                    if current == expected {
                        mem.write_u32(ptr, desired)?;
                        cpu.set_reg(Reg::R0, 1);
                    } else {
                        cpu.set_reg(Reg::R0, 0);
                    }
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::SyncFetchAndAdd4 => {
                // __sync_fetch_and_add_4(ptr, val) -> old_val
                let ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let val = cpu.reg(Reg::R1);
                if ptr.as_u32() != 0 {
                    let old = mem.read_u32(ptr)?;
                    mem.write_u32(ptr, old.wrapping_add(val))?;
                    cpu.set_reg(Reg::R0, old);
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::SyncFetchAndSub4 => {
                // __sync_fetch_and_sub_4(ptr, val) -> old_val
                let ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let val = cpu.reg(Reg::R1);
                if ptr.as_u32() != 0 {
                    let old = mem.read_u32(ptr)?;
                    mem.write_u32(ptr, old.wrapping_sub(val))?;
                    cpu.set_reg(Reg::R0, old);
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }

            // --- POSIX Sockets ---
            BionicFuncId::Socket => {
                // socket(domain, type, protocol) -> fd or -1
                let domain = cpu.reg(Reg::R0) as i32;
                let sock_type = cpu.reg(Reg::R1) as i32;
                // Allocate a guest FD; record (domain, type, not-connected)
                let fd = self.next_socket_fd;
                self.next_socket_fd += 1;
                self.socket_fds.insert(fd, (domain, sock_type, false));
                cpu.set_reg(Reg::R0, fd);
            }
            BionicFuncId::SocketConnect => {
                // connect(sockfd, addr, addrlen) -> 0 or -1
                let fd = cpu.reg(Reg::R0);
                if let Some(entry) = self.socket_fds.get_mut(&fd) {
                    entry.2 = true; // mark connected
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF); // -1 EBADF
                }
            }
            BionicFuncId::SocketBind => {
                // bind(sockfd, addr, addrlen) -> 0 or -1
                let fd = cpu.reg(Reg::R0);
                if self.socket_fds.contains_key(&fd) {
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::SocketListen => {
                // listen(sockfd, backlog) -> 0 or -1
                let fd = cpu.reg(Reg::R0);
                if self.socket_fds.contains_key(&fd) {
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::SocketAccept => {
                // accept(sockfd, addr, addrlen) -> new_fd or -1
                let fd = cpu.reg(Reg::R0);
                if self.socket_fds.contains_key(&fd) {
                    let new_fd = self.next_socket_fd;
                    self.next_socket_fd += 1;
                    let entry = *self.socket_fds.get(&fd).unwrap();
                    self.socket_fds.insert(new_fd, (entry.0, entry.1, true));
                    cpu.set_reg(Reg::R0, new_fd);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::SocketSend | BionicFuncId::SocketSendto => {
                // send(sockfd, buf, len, flags) -> bytes_sent or -1
                let fd = cpu.reg(Reg::R0);
                let len = cpu.reg(Reg::R2);
                if self.socket_fds.contains_key(&fd) {
                    cpu.set_reg(Reg::R0, len); // pretend all bytes sent
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::SocketRecv | BionicFuncId::SocketRecvfrom => {
                // recv(sockfd, buf, len, flags) -> bytes_received or -1
                // Stub: return 0 bytes (EOF / no data)
                let fd = cpu.reg(Reg::R0);
                if self.socket_fds.contains_key(&fd) {
                    cpu.set_reg(Reg::R0, 0); // 0 = EOF / no data available
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::SocketShutdown => {
                // shutdown(sockfd, how) -> 0 or -1
                let fd = cpu.reg(Reg::R0);
                if let Some(entry) = self.socket_fds.get_mut(&fd) {
                    entry.2 = false;
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::SocketClose => {
                // close(fd) -> 0 or -1
                let fd = cpu.reg(Reg::R0);
                if self.socket_fds.remove(&fd).is_some()
                    || self.epoll_fds.remove(&fd).is_some()
                    || self.pipe_fds.remove(&fd).is_some()
                    || self.eventfd_table.remove(&fd).is_some()
                    || self.vfs.close(fd).is_ok()
                {
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF); // EBADF
                }
            }
            BionicFuncId::SocketGetSockname | BionicFuncId::SocketGetPeername => {
                // getsockname(sockfd, addr, addrlen) -> 0 or -1
                // Writes minimal sockaddr_in (AF_INET=2, port=0, addr=127.0.0.1)
                let fd = cpu.reg(Reg::R0);
                let addr_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let addrlen_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                if self.socket_fds.contains_key(&fd) && addr_ptr.as_u32() != 0 {
                    mem.write_u16(addr_ptr, 2)?; // AF_INET = 2
                    mem.write_u16(addr_ptr.add(2), 0)?; // port = 0
                    mem.write_u32(addr_ptr.add(4), 0x0100_007F)?; // 127.0.0.1 in network byte order
                    if addrlen_ptr.as_u32() != 0 {
                        mem.write_u32(addrlen_ptr, 16)?; // sizeof(sockaddr_in)
                    }
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::SocketSetsockopt => {
                // setsockopt(sockfd, level, optname, optval, optlen) -> 0 or -1
                let fd = cpu.reg(Reg::R0);
                if self.socket_fds.contains_key(&fd) {
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::SocketGetsockopt => {
                // getsockopt(sockfd, level, optname, optval, optlen) -> 0 or -1
                let fd = cpu.reg(Reg::R0);
                if self.socket_fds.contains_key(&fd) {
                    let optval_ptr = GuestAddr::new(cpu.reg(Reg::R3));
                    let optlen_ptr = GuestAddr::new(cpu.reg(Reg::R3).wrapping_add(4));
                    if optval_ptr.as_u32() != 0 {
                        mem.write_u32(optval_ptr, 0)?;
                    }
                    if optlen_ptr.as_u32() != 0 {
                        mem.write_u32(optlen_ptr, 4)?;
                    }
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                }
            }
            BionicFuncId::Htons => {
                let val = cpu.reg(Reg::R0) as u16;
                cpu.set_reg(Reg::R0, val.to_be() as u32);
            }
            BionicFuncId::Htonl => {
                let val = cpu.reg(Reg::R0);
                cpu.set_reg(Reg::R0, val.to_be());
            }
            BionicFuncId::Ntohs => {
                let val = cpu.reg(Reg::R0) as u16;
                cpu.set_reg(Reg::R0, u16::from_be(val) as u32);
            }
            BionicFuncId::Ntohl => {
                let val = cpu.reg(Reg::R0);
                cpu.set_reg(Reg::R0, u32::from_be(val));
            }
            BionicFuncId::InetAton => {
                // inet_aton(cp, inp) -> 1 on success, 0 on failure
                let cp_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let inp_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if cp_ptr.as_u32() != 0 {
                    let s = Self::read_c_string(mem, cp_ptr)?;
                    let parts: Vec<&str> = s.trim().split('.').collect();
                    if parts.len() == 4 {
                        let octets: Vec<u8> = parts.iter()
                            .filter_map(|p| p.parse::<u8>().ok())
                            .collect();
                        if octets.len() == 4 {
                            let addr = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
                            if inp_ptr.as_u32() != 0 {
                                mem.write_u32(inp_ptr, addr)?;
                            }
                            cpu.set_reg(Reg::R0, 1);
                        } else {
                            cpu.set_reg(Reg::R0, 0);
                        }
                    } else {
                        cpu.set_reg(Reg::R0, 0);
                    }
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::InetNtoa => {
                // inet_ntoa(in) -> *const c_char (static buffer)
                // Input: u32 in network byte order in R0
                let addr_be = cpu.reg(Reg::R0);
                let b = addr_be.to_be_bytes();
                let s = format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
                let bytes = s.as_bytes();
                mem.write_bytes(self.inet_ntoa_addr, bytes)?;
                mem.write_u8(self.inet_ntoa_addr.add(bytes.len() as u32), 0)?;
                cpu.set_reg(Reg::R0, self.inet_ntoa_addr.as_u32());
            }
            // ── Stage 59: pipe / read / write ─────────────────────────────
            BionicFuncId::Pipe => {
                // pipe(int pipefd[2]) -> 0; stores read_fd and write_fd at pipefd[0] and pipefd[1]
                let arr_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let read_fd  = self.next_pipe_fd;
                let write_fd = self.next_pipe_fd + 1;
                self.next_pipe_fd += 2;
                self.pipe_fds.insert(read_fd, (write_fd, Vec::new()));
                if arr_ptr.as_u32() != 0 {
                    mem.write_u32(arr_ptr, read_fd)?;
                    mem.write_u32(arr_ptr.add(4), write_fd)?;
                }
                cpu.set_reg(Reg::R0, 0);
            }

            BionicFuncId::Read => {
                // read(fd, buf, count) -> bytes read
                let fd      = cpu.reg(Reg::R0);
                let buf_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let count   = cpu.reg(Reg::R2) as usize;
                if let Some((_write_fd, buf)) = self.pipe_fds.get_mut(&fd) {
                    let n = count.min(buf.len());
                    let data: Vec<u8> = buf.drain(..n).collect();
                    for (i, b) in data.iter().enumerate() {
                        mem.write_u8(buf_ptr.add(i as u32), *b)?;
                    }
                    cpu.set_reg(Reg::R0, n as u32);
                } else if let Some((counter, flags)) = self.eventfd_table.get_mut(&fd) {
                    if count >= 8 {
                        let val = if *flags & 1 != 0 {
                            if *counter > 0 {
                                *counter -= 1;
                                1u64
                            } else {
                                0u64
                            }
                        } else {
                            let c = *counter;
                            *counter = 0;
                            c
                        };
                        mem.write_u32(buf_ptr, (val & 0xFFFF_FFFF) as u32)?;
                        mem.write_u32(buf_ptr.add(4), (val >> 32) as u32)?;
                        cpu.set_reg(Reg::R0, 8);
                    } else {
                        cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                    }
                } else {
                    let mut tmp = vec![0u8; count];
                    match self.vfs.read(fd, &mut tmp) {
                        Ok(n) => {
                            for i in 0..n {
                                mem.write_u8(buf_ptr.add(i as u32), tmp[i])?;
                            }
                            cpu.set_reg(Reg::R0, n as u32);
                        }
                        Err(_) => {
                            cpu.set_reg(Reg::R0, 0);
                        }
                    }
                }
            }

            BionicFuncId::Write => {
                // write(fd, buf, count) -> bytes written
                let fd      = cpu.reg(Reg::R0);
                let buf_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let count   = cpu.reg(Reg::R2) as usize;
                let read_fd_opt = self.pipe_fds.iter()
                    .find(|(_, (w, _))| *w == fd)
                    .map(|(r, _)| *r);
                if let Some(read_fd) = read_fd_opt {
                    let mut data = Vec::with_capacity(count);
                    for i in 0..count {
                        data.push(mem.read_u8(buf_ptr.add(i as u32))?);
                    }
                    if let Some((_, buf)) = self.pipe_fds.get_mut(&read_fd) {
                        buf.extend_from_slice(&data);
                    }
                    cpu.set_reg(Reg::R0, count as u32);
                } else if let Some((counter, _flags)) = self.eventfd_table.get_mut(&fd) {
                    if count >= 8 {
                        let low = mem.read_u32(buf_ptr)? as u64;
                        let high = mem.read_u32(buf_ptr.add(4))? as u64;
                        let val = (high << 32) | low;
                        *counter = (*counter).saturating_add(val);
                        cpu.set_reg(Reg::R0, 8);
                    } else {
                        cpu.set_reg(Reg::R0, 0xFFFF_FFFF);
                    }
                } else if fd == 1 || fd == 2 {
                    // stdout / stderr: consumed
                    cpu.set_reg(Reg::R0, count as u32);
                } else {
                    let mut data = Vec::with_capacity(count);
                    for i in 0..count {
                        data.push(mem.read_u8(buf_ptr.add(i as u32))?);
                    }
                    match self.vfs.write(fd, &data) {
                        Ok(n) => cpu.set_reg(Reg::R0, n as u32),
                        Err(_) => cpu.set_reg(Reg::R0, count as u32),
                    }
                }
            }

            // ── Stage 59: Extended allocator ──────────────────────────────
            BionicFuncId::MallocUsableSize => {
                // malloc_usable_size(ptr) -> 0 (conservative stub)
                cpu.set_reg(Reg::R0, 0);
            }

            BionicFuncId::Memalign => {
                // memalign(alignment, size) -> aligned pointer from heap
                // We align our heap_current up to the requested alignment.
                let alignment = cpu.reg(Reg::R0) as u64;
                let size      = cpu.reg(Reg::R1);
                let align = if alignment.is_power_of_two() && alignment >= 4 { alignment as u32 } else { 4 };
                // Round up heap_current to alignment
                let cur = self.heap_current.as_u32();
                let aligned = (cur + align - 1) & !(align - 1);
                let ptr = GuestAddr::new(aligned);
                self.heap_current = ptr.add(size.max(4));
                if self.heap_current.as_u32() > self.heap_limit.as_u32() {
                    cpu.set_reg(Reg::R0, 0); // OOM
                } else {
                    cpu.set_reg(Reg::R0, ptr.as_u32());
                }
            }

            BionicFuncId::PosixMemalign => {
                // posix_memalign(memptr**, alignment, size) -> 0 on success
                let memptr_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let alignment  = cpu.reg(Reg::R1) as u64;
                let size       = cpu.reg(Reg::R2);
                let align = if alignment.is_power_of_two() && alignment >= 4 { alignment as u32 } else { 4 };
                let cur = self.heap_current.as_u32();
                let aligned = (cur + align - 1) & !(align - 1);
                let ptr = GuestAddr::new(aligned);
                self.heap_current = ptr.add(size.max(4));
                if self.heap_current.as_u32() > self.heap_limit.as_u32() {
                    cpu.set_reg(Reg::R0, 12); // ENOMEM
                } else {
                    if memptr_ptr.as_u32() != 0 {
                        mem.write_u32(memptr_ptr, ptr.as_u32())?;
                    }
                    cpu.set_reg(Reg::R0, 0);
                }
            }

            // ── Stage 59: pthread_barrier_* ───────────────────────────────
            BionicFuncId::PthreadBarrierInit => {
                // pthread_barrier_init(barrier*, attr*, count) -> 0
                // Store count at barrier+0, current at barrier+4 (= count for fresh barrier)
                let barrier_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let count = cpu.reg(Reg::R2);
                if barrier_ptr.as_u32() != 0 {
                    mem.write_u32(barrier_ptr, count)?;
                    mem.write_u32(barrier_ptr.add(4), count)?;
                }
                cpu.set_reg(Reg::R0, 0);
            }

            BionicFuncId::PthreadBarrierWait => {
                // pthread_barrier_wait(barrier*) -> 0 (or PTHREAD_BARRIER_SERIAL_THREAD = -1)
                // In a single-threaded stub: just decrement counter, return SERIAL when it hits 0.
                let barrier_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if barrier_ptr.as_u32() != 0 {
                    let count   = mem.read_u32(barrier_ptr)?;
                    let current = mem.read_u32(barrier_ptr.add(4))?;
                    let next = current.saturating_sub(1);
                    if next == 0 {
                        // Reset barrier
                        mem.write_u32(barrier_ptr.add(4), count)?;
                        cpu.set_reg(Reg::R0, u32::MAX); // PTHREAD_BARRIER_SERIAL_THREAD (-1 as u32)
                    } else {
                        mem.write_u32(barrier_ptr.add(4), next)?;
                        cpu.set_reg(Reg::R0, 0);
                    }
                } else {
                    cpu.set_reg(Reg::R0, 22); // EINVAL
                }
            }

            BionicFuncId::PthreadBarrierDestroy => {
                // pthread_barrier_destroy(barrier*) -> 0
                cpu.set_reg(Reg::R0, 0);
            }

            // ── Stage 59: clock_nanosleep ─────────────────────────────────
            BionicFuncId::ClockNanosleep => {
                // clock_nanosleep(clockid, flags, *req, *rem) -> 0
                // Stub: immediately return success (no actual sleep in DBT context)
                cpu.set_reg(Reg::R0, 0);
            }
            // ── Stage 60: FD duplication ──────────────────────────────────
            BionicFuncId::Dup => {
                // dup(oldfd) -> newfd (clone of oldfd)
                let old_fd = cpu.reg(Reg::R0);
                // Check socket table
                let is_socket = self.socket_fds.contains_key(&old_fd);
                // Check pipe table (read or write side)
                let is_pipe_read = self.pipe_fds.contains_key(&old_fd);
                let is_pipe_write = self.pipe_fds.values().any(|(w, _)| *w == old_fd);
                if is_socket {
                    let info = self.socket_fds[&old_fd];
                    let new_fd = self.next_socket_fd;
                    self.next_socket_fd += 1;
                    self.socket_fds.insert(new_fd, info);
                    cpu.set_reg(Reg::R0, new_fd);
                } else if is_pipe_read {
                    // Duplicate read end: share the same buffer via new read FD
                    let new_read = self.next_pipe_fd;
                    let _new_write = self.next_pipe_fd + 1;
                    self.next_pipe_fd += 2;
                    let (_w, buf) = &self.pipe_fds[&old_fd];
                    let buf_clone = buf.clone();
                    let write_fd = *_w;
                    self.pipe_fds.insert(new_read, (write_fd, buf_clone));
                    cpu.set_reg(Reg::R0, new_read);
                } else if is_pipe_write {
                    // Duplicate write end: just alias (stub: return a new fd, same pipe semantics)
                    cpu.set_reg(Reg::R0, self.next_socket_fd);
                    self.next_socket_fd += 1;
                } else {
                    // Unknown fd: return new sequential fd (stub passthrough)
                    let new_fd = self.next_socket_fd;
                    self.next_socket_fd += 1;
                    cpu.set_reg(Reg::R0, new_fd);
                }
            }

            BionicFuncId::Dup2 => {
                // dup2(oldfd, newfd) -> newfd
                // Stub: close newfd if open (no-op for us), then alias it to oldfd.
                let _old_fd = cpu.reg(Reg::R0);
                let new_fd  = cpu.reg(Reg::R1);
                cpu.set_reg(Reg::R0, new_fd);
            }

            // ── Stage 60: fcntl ───────────────────────────────────────────
            BionicFuncId::Fcntl => {
                // fcntl(fd, cmd, ...) stub
                // F_GETFL = 3 -> return O_RDWR (2)
                // F_SETFL = 4 -> return 0
                // F_GETFD = 1 -> return 0 (no FD_CLOEXEC)
                // F_SETFD = 2 -> return 0
                // All others  -> return 0
                let cmd = cpu.reg(Reg::R1);
                let ret = match cmd {
                    1 => 0,   // F_GETFD
                    2 => 0,   // F_SETFD
                    3 => 2,   // F_GETFL -> O_RDWR
                    4 => 0,   // F_SETFL
                    _ => 0,
                };
                cpu.set_reg(Reg::R0, ret);
            }

            // ── Stage 60: select / poll ────────────────────────────────────
            BionicFuncId::Select => {
                // select(nfds, readfds, writefds, exceptfds, timeout) -> 0 (nothing ready)
                cpu.set_reg(Reg::R0, 0);
            }

            BionicFuncId::Poll => {
                // poll(fds, nfds, timeout) -> 0 (timeout, nothing ready)
                cpu.set_reg(Reg::R0, 0);
            }

            // ── Stage 60: name/address resolution ─────────────────────────
            BionicFuncId::Getaddrinfo => {
                let node_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let serv_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let hints_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                let res_ptr = GuestAddr::new(cpu.reg(Reg::R3));

                if res_ptr.as_u32() == 0 {
                    cpu.set_reg(Reg::R0, 3); // EAI_BADFLAGS
                } else if node_ptr.as_u32() == 0 && serv_ptr.as_u32() == 0 {
                    cpu.set_reg(Reg::R0, 11); // EAI_AGAIN (both node and serv NULL)
                } else {
                    let node = if node_ptr.as_u32() != 0 {
                        Self::read_c_string(mem, node_ptr).unwrap_or_default()
                    } else {
                        "127.0.0.1".to_string()
                    };
                    let serv = if serv_ptr.as_u32() != 0 {
                        Self::read_c_string(mem, serv_ptr).unwrap_or_default()
                    } else {
                        "80".to_string()
                    };

                    let port: u16 = serv.parse().unwrap_or(80);
                    let mut ip_bytes = [127u8, 0, 0, 1];
                    if let Ok(addr) = node.parse::<std::net::Ipv4Addr>() {
                        ip_bytes = addr.octets();
                    }

                    let socktype = if hints_ptr.as_u32() != 0 {
                        mem.read_u32(hints_ptr.add(8)).unwrap_or(1) // SOCK_STREAM = 1
                    } else {
                        1
                    };

                    let alloc_addr = self.heap_alloc(48);
                    if alloc_addr.as_u32() != 0 {
                        let ai_addr = alloc_addr.add(32);
                        // struct addrinfo (32 bytes)
                        mem.write_u32(alloc_addr, 0)?; // ai_flags
                        mem.write_u32(alloc_addr.add(4), 2)?; // ai_family = AF_INET (2)
                        mem.write_u32(alloc_addr.add(8), socktype)?; // ai_socktype
                        mem.write_u32(alloc_addr.add(12), 6)?; // ai_protocol = IPPROTO_TCP (6)
                        mem.write_u32(alloc_addr.add(16), 16)?; // ai_addrlen = 16
                        mem.write_u32(alloc_addr.add(20), ai_addr.as_u32())?; // ai_addr
                        mem.write_u32(alloc_addr.add(24), 0)?; // ai_canonname
                        mem.write_u32(alloc_addr.add(28), 0)?; // ai_next

                        // struct sockaddr_in (16 bytes) at ai_addr
                        mem.write_u16(ai_addr, 2)?; // sin_family = AF_INET (2)
                        mem.write_u16(ai_addr.add(2), port.to_be())?; // sin_port (network byte order)
                        mem.write_bytes(ai_addr.add(4), &ip_bytes)?; // sin_addr
                        mem.write_bytes(ai_addr.add(8), &[0u8; 8])?; // sin_zero

                        mem.write_u32(res_ptr, alloc_addr.as_u32())?;
                        cpu.set_reg(Reg::R0, 0); // Success!
                    } else {
                        cpu.set_reg(Reg::R0, 6); // EAI_MEMORY
                    }
                }
            }

            BionicFuncId::Freeaddrinfo => {
                // freeaddrinfo(res) -> void (no-op stub)
                cpu.set_reg(Reg::R0, 0);
            }

            BionicFuncId::Getnameinfo => {
                // getnameinfo(sa, salen, host, hostlen, serv, servlen, flags) -> EAI_AGAIN
                cpu.set_reg(Reg::R0, 11); // EAI_AGAIN
            }

            BionicFuncId::Gethostbyname => {
                // gethostbyname(name) -> NULL (not found)
                cpu.set_reg(Reg::R0, 0);
            }

            BionicFuncId::GethostbynameR => {
                // gethostbyname_r(name, ret, buf, buflen, result, h_errnop) -> ENOENT (2)
                // Write NULL into *result
                let result_ptr = GuestAddr::new(cpu.reg(Reg::R3));
                if result_ptr.as_u32() != 0 {
                    mem.write_u32(result_ptr, 0)?;
                }
                cpu.set_reg(Reg::R0, 2); // ENOENT
            }

            // ── Stage 60: network interface enumeration ────────────────────
            BionicFuncId::Getifaddrs => {
                // getifaddrs(ifap) -> -1 (ENOTSUP stub — no interfaces in DBT context)
                let ifap_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if ifap_ptr.as_u32() != 0 {
                    mem.write_u32(ifap_ptr, 0)?; // *ifap = NULL
                }
                cpu.set_reg(Reg::R0, u32::MAX); // -1 ENOTSUP
            }

            BionicFuncId::Freeifaddrs => {
                // freeifaddrs(ifa) -> void (no-op)
                cpu.set_reg(Reg::R0, 0);
            }

            // ── Stage 60: process group / session ─────────────────────────
            BionicFuncId::Setsid => {
                // setsid() -> pid (stub: return guest pid)
                cpu.set_reg(Reg::R0, self.pid);
            }

            BionicFuncId::Getpgrp => {
                // getpgrp() -> pid
                cpu.set_reg(Reg::R0, self.pid);
            }

            BionicFuncId::Setpgid => {
                // setpgid(pid, pgid) -> 0
                cpu.set_reg(Reg::R0, 0);
            }
            // ── Stage 61: POSIX File System & Directory APIs ─────────────
            BionicFuncId::Open => {
                // open(path, flags, mode) -> fd or -1
                let path_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let flags = cpu.reg(Reg::R1);
                if path_ptr.as_u32() != 0 {
                    let path = Self::read_c_string(mem, path_ptr)?;
                    match self.vfs.open(&path, flags) {
                        Ok(fd) => cpu.set_reg(Reg::R0, fd),
                        Err(_) => cpu.set_reg(Reg::R0, u32::MAX),
                    }
                } else {
                    cpu.set_reg(Reg::R0, u32::MAX);
                }
            }

            BionicFuncId::Openat => {
                // openat(dirfd, path, flags, mode) -> fd or -1
                let path_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let flags = cpu.reg(Reg::R2);
                if path_ptr.as_u32() != 0 {
                    let path = Self::read_c_string(mem, path_ptr)?;
                    match self.vfs.open(&path, flags) {
                        Ok(fd) => cpu.set_reg(Reg::R0, fd),
                        Err(_) => cpu.set_reg(Reg::R0, u32::MAX),
                    }
                } else {
                    cpu.set_reg(Reg::R0, u32::MAX);
                }
            }

            BionicFuncId::Lseek => {
                // lseek(fd, offset, whence) -> new offset or -1
                let fd = cpu.reg(Reg::R0);
                let offset = cpu.reg(Reg::R1) as i32 as i64;
                let whence = cpu.reg(Reg::R2) as i32;
                match self.vfs.seek(fd, offset, whence) {
                    Ok(new_pos) => cpu.set_reg(Reg::R0, new_pos as u32),
                    Err(_) => cpu.set_reg(Reg::R0, u32::MAX),
                }
            }

            BionicFuncId::Lseek64 => {
                // lseek64(fd, offset64, whence) -> new offset64 or -1
                let fd = cpu.reg(Reg::R0);
                let (offset, whence) = if cpu.reg(Reg::R3) <= 2 {
                    let lo = cpu.reg(Reg::R1) as u64;
                    let hi = cpu.reg(Reg::R2) as u64;
                    ((lo | (hi << 32)) as i64, cpu.reg(Reg::R3) as i32)
                } else {
                    let lo = cpu.reg(Reg::R2) as u64;
                    let hi = cpu.reg(Reg::R3) as u64;
                    let sp = GuestAddr::new(cpu.sp());
                    let w = mem.read_u32(sp).unwrap_or(0) as i32;
                    ((lo | (hi << 32)) as i64, w)
                };
                match self.vfs.seek(fd, offset, whence) {
                    Ok(new_pos) => {
                        cpu.set_reg(Reg::R0, new_pos as u32);
                        cpu.set_reg(Reg::R1, (new_pos >> 32) as u32);
                    }
                    Err(_) => {
                        cpu.set_reg(Reg::R0, u32::MAX);
                        cpu.set_reg(Reg::R1, u32::MAX);
                    }
                }
            }

            BionicFuncId::Stat | BionicFuncId::Stat64 | BionicFuncId::Lstat | BionicFuncId::Lstat64 => {
                // stat/stat64/lstat/lstat64(path, buf) -> 0 or -1
                let path_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let buf_ptr  = GuestAddr::new(cpu.reg(Reg::R1));
                if path_ptr.as_u32() != 0 && buf_ptr.as_u32() != 0 {
                    let path = Self::read_c_string(mem, path_ptr)?;
                    match self.vfs.stat64(&path) {
                        Ok(st) => {
                            st.write_to_memory(mem, buf_ptr)?;
                            cpu.set_reg(Reg::R0, 0);
                        }
                        Err(_) => {
                            cpu.set_reg(Reg::R0, u32::MAX);
                        }
                    }
                } else {
                    cpu.set_reg(Reg::R0, u32::MAX);
                }
            }

            BionicFuncId::Fstat | BionicFuncId::Fstat64 => {
                // fstat/fstat64(fd, buf) -> 0 or -1
                let fd = cpu.reg(Reg::R0);
                let buf_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if buf_ptr.as_u32() != 0 {
                    match self.vfs.fstat64(fd) {
                        Ok(st) => {
                            st.write_to_memory(mem, buf_ptr)?;
                            cpu.set_reg(Reg::R0, 0);
                        }
                        Err(_) => {
                            cpu.set_reg(Reg::R0, u32::MAX);
                        }
                    }
                } else {
                    cpu.set_reg(Reg::R0, u32::MAX);
                }
            }

            BionicFuncId::Fstatat => {
                // fstatat(dirfd, path, buf, flags) -> 0 or -1
                let path_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let buf_ptr  = GuestAddr::new(cpu.reg(Reg::R2));
                if path_ptr.as_u32() != 0 && buf_ptr.as_u32() != 0 {
                    let path = Self::read_c_string(mem, path_ptr)?;
                    match self.vfs.stat64(&path) {
                        Ok(st) => {
                            st.write_to_memory(mem, buf_ptr)?;
                            cpu.set_reg(Reg::R0, 0);
                        }
                        Err(_) => {
                            cpu.set_reg(Reg::R0, u32::MAX);
                        }
                    }
                } else {
                    cpu.set_reg(Reg::R0, u32::MAX);
                }
            }

            BionicFuncId::Access => {
                // access(path, mode) -> 0 or -1
                let path_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if path_ptr.as_u32() != 0 {
                    let path = Self::read_c_string(mem, path_ptr)?;
                    if self.vfs.get_file(&path).is_some()
                        || path.starts_with("/proc")
                        || path.starts_with("/sys")
                        || path.starts_with("/system")
                        || path.starts_with("/data")
                    {
                        cpu.set_reg(Reg::R0, 0);
                    } else {
                        cpu.set_reg(Reg::R0, u32::MAX);
                    }
                } else {
                    cpu.set_reg(Reg::R0, u32::MAX);
                }
            }

            BionicFuncId::Faccessat => {
                // faccessat(dirfd, path, mode, flags) -> 0 or -1
                let path_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if path_ptr.as_u32() != 0 {
                    let path = Self::read_c_string(mem, path_ptr)?;
                    if self.vfs.get_file(&path).is_some()
                        || path.starts_with("/proc")
                        || path.starts_with("/sys")
                        || path.starts_with("/system")
                        || path.starts_with("/data")
                    {
                        cpu.set_reg(Reg::R0, 0);
                    } else {
                        cpu.set_reg(Reg::R0, u32::MAX);
                    }
                } else {
                    cpu.set_reg(Reg::R0, u32::MAX);
                }
            }

            BionicFuncId::Mkdir | BionicFuncId::Mkdirat => {
                // mkdir(path, mode) -> 0 (stub)
                cpu.set_reg(Reg::R0, 0);
            }

            BionicFuncId::Unlink | BionicFuncId::Unlinkat => {
                // unlink(path) -> 0 (stub)
                cpu.set_reg(Reg::R0, 0);
            }

            BionicFuncId::Getcwd => {
                // getcwd(buf, size) -> buf or NULL
                let buf_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let size = cpu.reg(Reg::R1) as usize;
                if buf_ptr.as_u32() != 0 && size > self.cwd.len() {
                    let bytes = self.cwd.as_bytes();
                    for (i, b) in bytes.iter().enumerate() {
                        mem.write_u8(buf_ptr.add(i as u32), *b)?;
                    }
                    mem.write_u8(buf_ptr.add(bytes.len() as u32), 0)?;
                    cpu.set_reg(Reg::R0, buf_ptr.as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }

            BionicFuncId::Chdir => {
                // chdir(path) -> 0 or -1
                let path_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if path_ptr.as_u32() != 0 {
                    let path = Self::read_c_string(mem, path_ptr)?;
                    self.cwd = path;
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, u32::MAX);
                }
            }

            BionicFuncId::Readlink | BionicFuncId::Readlinkat => {
                // readlink(path, buf, bufsiz) / readlinkat(dirfd, path, buf, bufsiz) -> count or -1
                let (path_ptr, buf_ptr, bufsiz) = if func_id == BionicFuncId::Readlinkat {
                    (GuestAddr::new(cpu.reg(Reg::R1)), GuestAddr::new(cpu.reg(Reg::R2)), cpu.reg(Reg::R3) as usize)
                } else {
                    (GuestAddr::new(cpu.reg(Reg::R0)), GuestAddr::new(cpu.reg(Reg::R1)), cpu.reg(Reg::R2) as usize)
                };
                if path_ptr.as_u32() != 0 && buf_ptr.as_u32() != 0 {
                    let path = Self::read_c_string(mem, path_ptr)?;
                    if path == "/proc/self/exe" {
                        let target = b"/system/bin/app_process32";
                        let len = target.len().min(bufsiz);
                        for i in 0..len {
                            mem.write_u8(buf_ptr.add(i as u32), target[i])?;
                        }
                        cpu.set_reg(Reg::R0, len as u32);
                    } else {
                        cpu.set_reg(Reg::R0, u32::MAX);
                    }
                } else {
                    cpu.set_reg(Reg::R0, u32::MAX);
                }
            }

            BionicFuncId::Rename | BionicFuncId::Renameat => {
                // rename(old, new) -> 0 (stub)
                cpu.set_reg(Reg::R0, 0);
            }

            BionicFuncId::Ftruncate | BionicFuncId::Ftruncate64 => {
                let fd = cpu.reg(Reg::R0);
                let len = cpu.reg(Reg::R1) as usize;
                if let Some(region) = self.vfs.ashmem_regions.get_mut(&fd) {
                    region.size = len;
                    if let Ok(mut lock) = region.data.lock() {
                        lock.resize(len, 0);
                    }
                    region.is_initialized = true;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            // ── Stage 62: Extended libm (Single-precision f32) ───────────
            BionicFuncId::Atanf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.atan(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Asinf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.asin(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Acosf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.acos(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Sinhf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.sinh(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Coshf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.cosh(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Tanhf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.tanh(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Log10f => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.log10(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Log2f => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.log2(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Exp2f => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.exp2(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Fmodf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let y = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R1)), true);
                let res = cpu.sanitize_f32(if y == 0.0 { f32::NAN } else { x % y }, false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Roundf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.round(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Truncf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.trunc(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Hypotf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let y = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R1)), true);
                let res = cpu.sanitize_f32(x.hypot(y), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Copysignf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let y = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R1)), true);
                let res = cpu.sanitize_f32(x.copysign(y), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Cbrtf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let res = cpu.sanitize_f32(x.cbrt(), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }
            BionicFuncId::Ldexpf => {
                let x = cpu.sanitize_f32(f32::from_bits(cpu.reg(Reg::R0)), true);
                let exp = cpu.reg(Reg::R1) as i32;
                let res = cpu.sanitize_f32(x * 2.0_f32.powi(exp), false);
                cpu.set_reg(Reg::R0, res.to_bits());
                cpu.set_s_reg(0, res);
            }

            // ── Stage 62: Extended libm (Double-precision f64) ───────────
            BionicFuncId::Atan => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.atan(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Asin => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.asin(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Acos => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.acos(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Sinh => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.sinh(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Cosh => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.cosh(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Tanh => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.tanh(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Log10 => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.log10(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Log2 => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.log2(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Exp2 => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.exp2(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Fmod => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let y_bits = (cpu.reg(Reg::R2) as u64) | ((cpu.reg(Reg::R3) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let y = cpu.sanitize_f64(f64::from_bits(y_bits), true);
                let res = cpu.sanitize_f64(if y == 0.0 { f64::NAN } else { x % y }, false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Round => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.round(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Trunc => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.trunc(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Hypot => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let y_bits = (cpu.reg(Reg::R2) as u64) | ((cpu.reg(Reg::R3) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let y = cpu.sanitize_f64(f64::from_bits(y_bits), true);
                let res = cpu.sanitize_f64(x.hypot(y), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Copysign => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let y_bits = (cpu.reg(Reg::R2) as u64) | ((cpu.reg(Reg::R3) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let y = cpu.sanitize_f64(f64::from_bits(y_bits), true);
                let res = cpu.sanitize_f64(x.copysign(y), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Cbrt => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x.cbrt(), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }
            BionicFuncId::Ldexp => {
                let x_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
                let exp = cpu.reg(Reg::R2) as i32;
                let x = cpu.sanitize_f64(f64::from_bits(x_bits), true);
                let res = cpu.sanitize_f64(x * 2.0_f64.powi(exp), false);
                let res_bits = res.to_bits();
                cpu.set_reg(Reg::R0, res_bits as u32);
                cpu.set_reg(Reg::R1, (res_bits >> 32) as u32);
                cpu.set_d_reg(0, res);
            }





            // ── Stage 63: Directory enumeration ─────────────────────────────
            BionicFuncId::Opendir => {
                // opendir(const char *name) -> DIR* (guest handle, 0 on error)
                let path_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let path = Self::read_c_string(mem, path_ptr).unwrap_or_default();
                // Check if VFS has any entry with this prefix
                let norm = if path.ends_with('/') { path.clone() } else { format!("{}/", path) };
                let exists = self.vfs.list_dir(&norm).is_some()
                    || self.vfs.list_dir(&path).is_some()
                    || path == "/" || path == "/proc" || path == "/sys" || path == "/data";
                if exists {
                    let handle = self.next_dir_handle;
                    self.next_dir_handle += 1;
                    let dir_path = if path.ends_with('/') { path } else { format!("{}/", path) };
                    self.dir_handles.insert(handle, (dir_path, 0));
                    cpu.set_reg(Reg::R0, handle);
                } else {
                    cpu.set_reg(Reg::R0, 0); // NULL = error
                }
            }
            BionicFuncId::Closedir => {
                // closedir(DIR *dirp) -> int (0 ok, -1 err)
                let handle = cpu.reg(Reg::R0);
                if self.dir_handles.remove(&handle).is_some() {
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, u32::MAX); // -1
                }
            }
            BionicFuncId::Readdir | BionicFuncId::Readdir64 => {
                // readdir(DIR *dirp) -> struct dirent* (0 at end)
                // We write a 280-byte dirent into a fixed scratch area and return its address.
                // Layout (ARM32 dirent64): ino(8), off(8), reclen(2), type(1), name[256]
                let handle = cpu.reg(Reg::R0);
                if let Some((dir_path, idx)) = self.dir_handles.get_mut(&handle) {
                    let entries = self.vfs.list_dir(dir_path).unwrap_or_default();
                    if *idx < entries.len() {
                        let name = entries[*idx].clone();
                        *idx += 1;
                        // Write dirent into static scratch area: stub_base + 0x1800
                        let dirent_addr = self.stub_base.add(0x1800);
                        // ino = idx as u64
                        let ino: u64 = *idx as u64;
                        mem.write_u32(dirent_addr,               ino as u32)?;
                        mem.write_u32(dirent_addr.add(4),        (ino >> 32) as u32)?;
                        // off = 0
                        mem.write_u32(dirent_addr.add(8),        0)?;
                        mem.write_u32(dirent_addr.add(12),       0)?;
                        // reclen = 280
                        mem.write_u16(dirent_addr.add(16),       280u16)?;
                        // type = 8 (DT_REG) or 4 (DT_DIR) — assume DT_REG for simplicity
                        mem.write_u8(dirent_addr.add(18),        8u8)?;
                        // name (null-terminated)
                        let name_addr = dirent_addr.add(19);
                        let nb = name.as_bytes();
                        let len = nb.len().min(255);
                        for i in 0..len {
                            mem.write_u8(name_addr.add(i as u32), nb[i])?;
                        }
                        mem.write_u8(name_addr.add(len as u32), 0)?;
                        cpu.set_reg(Reg::R0, dirent_addr.as_u32());
                    } else {
                        cpu.set_reg(Reg::R0, 0); // end of directory
                    }
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::Fdopendir => {
                // fdopendir(int fd) -> DIR*  — we synthesise a path from VFS fd
                let guest_fd = cpu.reg(Reg::R0);
                let path = self.vfs.fd_path(guest_fd).unwrap_or_default();
                if !path.is_empty() {
                    let handle = self.next_dir_handle;
                    self.next_dir_handle += 1;
                    let dir_path = if path.ends_with('/') { path } else { format!("{}/", path) };
                    self.dir_handles.insert(handle, (dir_path, 0));
                    cpu.set_reg(Reg::R0, handle);
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::Dirfd => {
                // dirfd(DIR *dirp) -> int fd  — return -1 (not backed by real fd)
                cpu.set_reg(Reg::R0, u32::MAX);
            }
            BionicFuncId::Rewinddir => {
                // rewinddir(DIR *dirp) — reset index to 0
                let handle = cpu.reg(Reg::R0);
                if let Some((_, idx)) = self.dir_handles.get_mut(&handle) {
                    *idx = 0;
                }
            }
            BionicFuncId::Telldir => {
                // telldir(DIR *dirp) -> long  — return current index
                let handle = cpu.reg(Reg::R0);
                let pos = self.dir_handles.get(&handle).map(|(_, i)| *i as u32).unwrap_or(0);
                cpu.set_reg(Reg::R0, pos);
            }
            BionicFuncId::Seekdir => {
                // seekdir(DIR *dirp, long loc)
                let handle = cpu.reg(Reg::R0);
                let loc = cpu.reg(Reg::R1) as usize;
                if let Some((_, idx)) = self.dir_handles.get_mut(&handle) {
                    *idx = loc;
                }
            }
            // ── Stage 64: String & Printf family ────────────────────────────

            // printf(fmt, ...) → writes formatted string to bridge.logs, returns char count
            BionicFuncId::Printf | BionicFuncId::Vprintf => {
                let fmt_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let fmt = Self::read_c_string(mem, fmt_ptr).unwrap_or_default();
                let len = fmt.len() as u32;
                self.logs.push(LogMessage {
                    priority: 3,
                    tag: "stdout".to_string(),
                    text: fmt,
                });
                cpu.set_reg(Reg::R0, len);
            }

            // fprintf(FILE* stream, fmt, ...) → same as printf but ignores stream
            BionicFuncId::Fprintf | BionicFuncId::Vfprintf => {
                let fmt_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let fmt = Self::read_c_string(mem, fmt_ptr).unwrap_or_default();
                let len = fmt.len() as u32;
                self.logs.push(LogMessage {
                    priority: 3,
                    tag: "stderr".to_string(),
                    text: fmt,
                });
                cpu.set_reg(Reg::R0, len);
            }

            // sscanf(str, fmt, ...) → stub returning 0 (no items matched)
            BionicFuncId::Sscanf => {
                cpu.set_reg(Reg::R0, 0);
            }

            // vsprintf(buf, fmt, va_list) → copy fmt into buf
            BionicFuncId::Vsprintf => {
                let buf_ptr  = GuestAddr::new(cpu.reg(Reg::R0));
                let fmt_ptr  = GuestAddr::new(cpu.reg(Reg::R1));
                let fmt = Self::read_c_string(mem, fmt_ptr).unwrap_or_default();
                let bytes = fmt.as_bytes();
                for (i, &b) in bytes.iter().enumerate() {
                    mem.write_u8(buf_ptr.add(i as u32), b)?;
                }
                mem.write_u8(buf_ptr.add(bytes.len() as u32), 0)?;
                cpu.set_reg(Reg::R0, bytes.len() as u32);
            }

            // vsnprintf(buf, size, fmt, va_list) → copy fmt into buf up to size
            BionicFuncId::Vsnprintf => {
                let buf_ptr  = GuestAddr::new(cpu.reg(Reg::R0));
                let size     = cpu.reg(Reg::R1) as usize;
                let fmt_ptr  = GuestAddr::new(cpu.reg(Reg::R2));
                let fmt = Self::read_c_string(mem, fmt_ptr).unwrap_or_default();
                let bytes = fmt.as_bytes();
                let to_write = if size > 0 { (bytes.len()).min(size - 1) } else { 0 };
                for i in 0..to_write {
                    mem.write_u8(buf_ptr.add(i as u32), bytes[i])?;
                }
                if size > 0 {
                    mem.write_u8(buf_ptr.add(to_write as u32), 0)?;
                }
                cpu.set_reg(Reg::R0, bytes.len() as u32);
            }

            // asprintf(char** strp, fmt, ...) → allocate heap buffer with fmt copy
            BionicFuncId::Asprintf | BionicFuncId::Vasprintf => {
                let strp_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let fmt_ptr  = GuestAddr::new(cpu.reg(Reg::R1));
                let fmt = Self::read_c_string(mem, fmt_ptr).unwrap_or_default();
                let bytes = fmt.as_bytes();
                let buf = self.heap_alloc(bytes.len() as u32 + 1);
                if buf.as_u32() != 0 {
                    for (i, &b) in bytes.iter().enumerate() {
                        mem.write_u8(buf.add(i as u32), b)?;
                    }
                    mem.write_u8(buf.add(bytes.len() as u32), 0)?;
                    if strp_ptr.as_u32() != 0 {
                        mem.write_u32(strp_ptr, buf.as_u32())?;
                    }
                    cpu.set_reg(Reg::R0, bytes.len() as u32);
                } else {
                    cpu.set_reg(Reg::R0, u32::MAX); // -1 on error
                }
            }

            // strtof(str, endptr) → parse f32
            BionicFuncId::Strtof => {
                let s_ptr    = GuestAddr::new(cpu.reg(Reg::R0));
                let endptr   = GuestAddr::new(cpu.reg(Reg::R1));
                let s = Self::read_c_string(mem, s_ptr).unwrap_or_default();
                let s_trim = s.trim_start();
                let (val, consumed) = parse_f64_prefix(s_trim);
                if endptr.as_u32() != 0 {
                    let end_addr = if consumed > 0 {
                        let spaces = (s.len() - s_trim.len()) as u32;
                        s_ptr.add(spaces + consumed as u32)
                    } else {
                        s_ptr
                    };
                    mem.write_u32(endptr, end_addr.as_u32())?;
                }
                let vf = val as f32;
                cpu.set_reg(Reg::R0, vf.to_bits());
                cpu.set_s_reg(0, vf);
            }

            // strtod(str, endptr) → parse f64
            BionicFuncId::Strtod | BionicFuncId::Strtold => {
                let s_ptr    = GuestAddr::new(cpu.reg(Reg::R0));
                let endptr   = GuestAddr::new(cpu.reg(Reg::R1));
                let s = Self::read_c_string(mem, s_ptr).unwrap_or_default();
                let s_trim = s.trim_start();
                let (val, consumed) = parse_f64_prefix(s_trim);
                if endptr.as_u32() != 0 {
                    let end_addr = if consumed > 0 {
                        let spaces = (s.len() - s_trim.len()) as u32;
                        s_ptr.add(spaces + consumed as u32)
                    } else {
                        s_ptr
                    };
                    mem.write_u32(endptr, end_addr.as_u32())?;
                }
                let bits = val.to_bits();
                cpu.set_reg(Reg::R0, bits as u32);
                cpu.set_reg(Reg::R1, (bits >> 32) as u32);
                cpu.set_d_reg(0, val);
            }

            // strdup(s) → heap-allocate copy
            BionicFuncId::Strdup => {
                let s_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let s = Self::read_c_string(mem, s_ptr).unwrap_or_default();
                let bytes = s.as_bytes();
                let buf = self.heap_alloc(bytes.len() as u32 + 1);
                if buf.as_u32() != 0 {
                    for (i, &b) in bytes.iter().enumerate() {
                        mem.write_u8(buf.add(i as u32), b)?;
                    }
                    mem.write_u8(buf.add(bytes.len() as u32), 0)?;
                }
                cpu.set_reg(Reg::R0, buf.as_u32());
            }

            // strndup(s, n) → heap-allocate up to n bytes
            BionicFuncId::Strndup => {
                let s_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let n     = cpu.reg(Reg::R1) as usize;
                let s = Self::read_c_string(mem, s_ptr).unwrap_or_default();
                let bytes = s.as_bytes();
                let len = bytes.len().min(n);
                let buf = self.heap_alloc(len as u32 + 1);
                if buf.as_u32() != 0 {
                    for i in 0..len {
                        mem.write_u8(buf.add(i as u32), bytes[i])?;
                    }
                    mem.write_u8(buf.add(len as u32), 0)?;
                }
                cpu.set_reg(Reg::R0, buf.as_u32());
            }

            // strtok(str, delim) / strtok_r(str, delim, saveptr)
            BionicFuncId::Strtok => {
                let str_ptr   = GuestAddr::new(cpu.reg(Reg::R0));
                let delim_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let delim = Self::read_c_string(mem, delim_ptr).unwrap_or_default();
                let cur = if str_ptr.as_u32() != 0 {
                    str_ptr
                } else if let Some(saved) = self.strtok_saved {
                    saved
                } else {
                    cpu.set_reg(Reg::R0, 0);
                    return Ok(true);
                };
                // Skip leading delimiters
                let s = Self::read_c_string(mem, cur).unwrap_or_default();
                let s_after_lead = s.trim_start_matches(|c: char| delim.contains(c));
                if s_after_lead.is_empty() {
                    self.strtok_saved = None;
                    cpu.set_reg(Reg::R0, 0);
                    return Ok(true);
                }
                let lead_skip = (s.len() - s_after_lead.len()) as u32;
                let token_start = cur.add(lead_skip);
                let token_len = s_after_lead.find(|c: char| delim.contains(c)).unwrap_or(s_after_lead.len());
                if token_len < s_after_lead.len() {
                    mem.write_u8(token_start.add(token_len as u32), 0)?;
                    self.strtok_saved = Some(token_start.add(token_len as u32 + 1));
                } else {
                    self.strtok_saved = None;
                }
                cpu.set_reg(Reg::R0, token_start.as_u32());
            }

            BionicFuncId::StrtokR => {
                let str_ptr    = GuestAddr::new(cpu.reg(Reg::R0));
                let delim_ptr  = GuestAddr::new(cpu.reg(Reg::R1));
                let saveptr    = GuestAddr::new(cpu.reg(Reg::R2));
                let delim = Self::read_c_string(mem, delim_ptr).unwrap_or_default();
                let saved_val = if saveptr.as_u32() != 0 { mem.read_u32(saveptr).unwrap_or(0) } else { 0 };
                let cur = if str_ptr.as_u32() != 0 {
                    str_ptr
                } else if saved_val != 0 {
                    GuestAddr::new(saved_val)
                } else {
                    cpu.set_reg(Reg::R0, 0);
                    return Ok(true);
                };
                let s = Self::read_c_string(mem, cur).unwrap_or_default();
                let s_after_lead = s.trim_start_matches(|c: char| delim.contains(c));
                if s_after_lead.is_empty() {
                    if saveptr.as_u32() != 0 {
                        mem.write_u32(saveptr, 0)?;
                    }
                    cpu.set_reg(Reg::R0, 0);
                    return Ok(true);
                }
                let lead_skip = (s.len() - s_after_lead.len()) as u32;
                let token_start = cur.add(lead_skip);
                let token_len = s_after_lead.find(|c: char| delim.contains(c)).unwrap_or(s_after_lead.len());
                if token_len < s_after_lead.len() {
                    mem.write_u8(token_start.add(token_len as u32), 0)?;
                    if saveptr.as_u32() != 0 {
                        mem.write_u32(saveptr, token_start.add(token_len as u32 + 1).as_u32())?;
                    }
                } else {
                    if saveptr.as_u32() != 0 {
                        mem.write_u32(saveptr, 0)?;
                    }
                }
                cpu.set_reg(Reg::R0, token_start.as_u32());
            }

            // strpbrk(s, accept) → pointer to first char in s that is in accept, or NULL
            BionicFuncId::Strpbrk => {
                let s_ptr      = GuestAddr::new(cpu.reg(Reg::R0));
                let accept_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let s      = Self::read_c_string(mem, s_ptr).unwrap_or_default();
                let accept = Self::read_c_string(mem, accept_ptr).unwrap_or_default();
                if let Some(pos) = s.find(|c: char| accept.contains(c)) {
                    cpu.set_reg(Reg::R0, s_ptr.add(pos as u32).as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }

            // strcspn(s, reject) → length of prefix not containing any char in reject
            BionicFuncId::Strcspn => {
                let s_ptr      = GuestAddr::new(cpu.reg(Reg::R0));
                let reject_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let s      = Self::read_c_string(mem, s_ptr).unwrap_or_default();
                let reject = Self::read_c_string(mem, reject_ptr).unwrap_or_default();
                let span = s.find(|c: char| reject.contains(c)).unwrap_or(s.len());
                cpu.set_reg(Reg::R0, span as u32);
            }

            // strspn(s, accept) → length of prefix containing only chars in accept
            BionicFuncId::Strspn => {
                let s_ptr      = GuestAddr::new(cpu.reg(Reg::R0));
                let accept_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let s      = Self::read_c_string(mem, s_ptr).unwrap_or_default();
                let accept = Self::read_c_string(mem, accept_ptr).unwrap_or_default();
                let span = s.find(|c: char| !accept.contains(c)).unwrap_or(s.len());
                cpu.set_reg(Reg::R0, span as u32);
            }

            // memmem(haystack, haystacklen, needle, needlelen) → pointer or NULL
            BionicFuncId::Memmem => {
                let hay_ptr  = GuestAddr::new(cpu.reg(Reg::R0));
                let hay_len  = cpu.reg(Reg::R1) as usize;
                let ndl_ptr  = GuestAddr::new(cpu.reg(Reg::R2));
                let ndl_len  = cpu.reg(Reg::R3) as usize;
                if ndl_len == 0 {
                    cpu.set_reg(Reg::R0, hay_ptr.as_u32());
                } else if hay_len < ndl_len {
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    let mut hay = vec![0u8; hay_len];
                    for i in 0..hay_len {
                        hay[i] = mem.read_u8(hay_ptr.add(i as u32)).unwrap_or(0);
                    }
                    let mut ndl = vec![0u8; ndl_len];
                    for i in 0..ndl_len {
                        ndl[i] = mem.read_u8(ndl_ptr.add(i as u32)).unwrap_or(0);
                    }
                    if let Some(pos) = hay.windows(ndl_len).position(|w| w == ndl.as_slice()) {
                        cpu.set_reg(Reg::R0, hay_ptr.add(pos as u32).as_u32());
                    } else {
                        cpu.set_reg(Reg::R0, 0);
                    }
                }
            }
            // ── Stage 65: Character Classification & Locale / Wide-Char ────
            BionicFuncId::Isalnum => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_alphanumeric() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Isalpha => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_alphabetic() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Isblank => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { let b = c as u8; b == b' ' || b == b'\t' } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Iscntrl => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_control() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Isdigit => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_digit() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Isgraph => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_graphic() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Islower => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_lowercase() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Isprint => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { let b = c as u8; b.is_ascii_graphic() || b == b' ' } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Ispunct => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_punctuation() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Isspace => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_whitespace() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Isupper => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_uppercase() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Isxdigit => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_hexdigit() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Tolower => {
                let c = cpu.reg(Reg::R0) as i32;
                let res = if (0..=255).contains(&c) { (c as u8).to_ascii_lowercase() as u32 } else { c as u32 };
                cpu.set_reg(Reg::R0, res);
            }
            BionicFuncId::Toupper => {
                let c = cpu.reg(Reg::R0) as i32;
                let res = if (0..=255).contains(&c) { (c as u8).to_ascii_uppercase() as u32 } else { c as u32 };
                cpu.set_reg(Reg::R0, res);
            }
            BionicFuncId::Isascii => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = (0..=127).contains(&c);
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Toascii => {
                let c = cpu.reg(Reg::R0);
                cpu.set_reg(Reg::R0, c & 0x7F);
            }
            BionicFuncId::Setlocale => {
                let locale_addr = self.stub_base.add(0xB00);
                cpu.set_reg(Reg::R0, locale_addr.as_u32());
            }
            BionicFuncId::Localeconv => {
                let lconv_addr = self.stub_base.add(0xB40);
                cpu.set_reg(Reg::R0, lconv_addr.as_u32());
            }
            BionicFuncId::Mbstowcs => {
                let dest_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let src_ptr  = GuestAddr::new(cpu.reg(Reg::R1));
                let n        = cpu.reg(Reg::R2) as usize;
                let s = Self::read_c_string(mem, src_ptr).unwrap_or_default();
                let chars: Vec<u32> = s.chars().map(|c| c as u32).collect();
                if dest_ptr.as_u32() == 0 {
                    cpu.set_reg(Reg::R0, chars.len() as u32);
                } else {
                    let to_write = chars.len().min(n);
                    for i in 0..to_write {
                        mem.write_u32(dest_ptr.add((i * 4) as u32), chars[i])?;
                    }
                    if to_write < n {
                        mem.write_u32(dest_ptr.add((to_write * 4) as u32), 0)?;
                    }
                    cpu.set_reg(Reg::R0, to_write as u32);
                }
            }
            BionicFuncId::Wcstombs => {
                let dest_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let src_ptr  = GuestAddr::new(cpu.reg(Reg::R1));
                let n        = cpu.reg(Reg::R2) as usize;
                let mut wchars = Vec::new();
                let mut i = 0u32;
                loop {
                    let wc = mem.read_u32(src_ptr.add(i * 4)).unwrap_or(0);
                    if wc == 0 { break; }
                    wchars.push(wc);
                    i += 1;
                }
                let mut bytes = Vec::new();
                for wc in wchars {
                    if let Some(ch) = char::from_u32(wc) {
                        let mut buf = [0u8; 4];
                        bytes.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                    } else {
                        bytes.push(b'?');
                    }
                }
                if dest_ptr.as_u32() == 0 {
                    cpu.set_reg(Reg::R0, bytes.len() as u32);
                } else {
                    let to_write = bytes.len().min(n);
                    for j in 0..to_write {
                        mem.write_u8(dest_ptr.add(j as u32), bytes[j])?;
                    }
                    if to_write < n {
                        mem.write_u8(dest_ptr.add(to_write as u32), 0)?;
                    }
                    cpu.set_reg(Reg::R0, to_write as u32);
                }
            }
            BionicFuncId::Mbtowc => {
                let pwc_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let s_ptr   = GuestAddr::new(cpu.reg(Reg::R1));
                let n       = cpu.reg(Reg::R2) as usize;
                if s_ptr.as_u32() == 0 {
                    cpu.set_reg(Reg::R0, 0);
                } else if n == 0 {
                    cpu.set_reg(Reg::R0, u32::MAX);
                } else {
                    let b = mem.read_u8(s_ptr)?;
                    if b == 0 {
                        if pwc_ptr.as_u32() != 0 {
                            mem.write_u32(pwc_ptr, 0)?;
                        }
                        cpu.set_reg(Reg::R0, 0);
                    } else {
                        if pwc_ptr.as_u32() != 0 {
                            mem.write_u32(pwc_ptr, b as u32)?;
                        }
                        cpu.set_reg(Reg::R0, 1);
                    }
                }
            }
            BionicFuncId::Wctomb => {
                let s_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let wc    = cpu.reg(Reg::R1);
                if s_ptr.as_u32() == 0 {
                    cpu.set_reg(Reg::R0, 0);
                } else if wc == 0 {
                    mem.write_u8(s_ptr, 0)?;
                    cpu.set_reg(Reg::R0, 1);
                } else if let Some(ch) = char::from_u32(wc) {
                    let mut buf = [0u8; 4];
                    let enc = ch.encode_utf8(&mut buf).as_bytes();
                    for (i, &b) in enc.iter().enumerate() {
                        mem.write_u8(s_ptr.add(i as u32), b)?;
                    }
                    cpu.set_reg(Reg::R0, enc.len() as u32);
                } else {
                    cpu.set_reg(Reg::R0, u32::MAX);
                }
            }
            BionicFuncId::Wcslen => {
                let s_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let mut len = 0u32;
                loop {
                    let wc = mem.read_u32(s_ptr.add(len * 4)).unwrap_or(0);
                    if wc == 0 { break; }
                    len += 1;
                }
                cpu.set_reg(Reg::R0, len);
            }
            BionicFuncId::Wcscpy => {
                let dest_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let src_ptr  = GuestAddr::new(cpu.reg(Reg::R1));
                let mut i = 0u32;
                loop {
                    let wc = mem.read_u32(src_ptr.add(i * 4)).unwrap_or(0);
                    mem.write_u32(dest_ptr.add(i * 4), wc)?;
                    if wc == 0 { break; }
                    i += 1;
                }
                cpu.set_reg(Reg::R0, dest_ptr.as_u32());
            }
            BionicFuncId::Wcscmp => {
                let s1_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let s2_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let mut i = 0u32;
                let res = loop {
                    let c1 = mem.read_u32(s1_ptr.add(i * 4)).unwrap_or(0);
                    let c2 = mem.read_u32(s2_ptr.add(i * 4)).unwrap_or(0);
                    if c1 != c2 || c1 == 0 {
                        break (c1 as i32) - (c2 as i32);
                    }
                    i += 1;
                };
                cpu.set_reg(Reg::R0, res as u32);
            }
            // ── Stage 66: Time & Date APIs ─────────────────────────────────
            BionicFuncId::Time => {
                let tloc = GuestAddr::new(cpu.reg(Reg::R0));
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as u32;
                if tloc.as_u32() != 0 {
                    mem.write_u32(tloc, now)?;
                }
                cpu.set_reg(Reg::R0, now);
            }
            BionicFuncId::Difftime => {
                let t1 = cpu.reg(Reg::R0) as i64;
                let t0 = cpu.reg(Reg::R1) as i64;
                let diff = (t1 - t0) as f64;
                let bits = diff.to_bits();
                cpu.set_reg(Reg::R0, bits as u32);
                cpu.set_reg(Reg::R1, (bits >> 32) as u32);
                cpu.set_d_reg(0, diff);
            }
            BionicFuncId::Clock => {
                let elapsed = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros() as u32;
                cpu.set_reg(Reg::R0, elapsed);
            }
            BionicFuncId::Times => {
                let buf = GuestAddr::new(cpu.reg(Reg::R0));
                let elapsed = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u32;
                if buf.as_u32() != 0 {
                    mem.write_u32(buf, elapsed / 2)?;
                    mem.write_u32(buf.add(4), elapsed / 4)?;
                    mem.write_u32(buf.add(8), 0)?;
                    mem.write_u32(buf.add(12), 0)?;
                }
                cpu.set_reg(Reg::R0, elapsed);
            }
            BionicFuncId::Gmtime | BionicFuncId::GmtimeR => {
                let time_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let out_ptr = if func_id == BionicFuncId::GmtimeR {
                    GuestAddr::new(cpu.reg(Reg::R1))
                } else {
                    self.stub_base.add(0xB80)
                };
                let secs = if time_ptr.as_u32() != 0 {
                    mem.read_u32(time_ptr).unwrap_or(0) as i64
                } else {
                    0
                };
                let (sec, min, hour, mday, mon, year, wday, yday) = secs_to_tm(secs);
                write_tm_struct(mem, out_ptr, sec, min, hour, mday, mon, year, wday, yday, 0)?;
                cpu.set_reg(Reg::R0, out_ptr.as_u32());
            }
            BionicFuncId::Localtime | BionicFuncId::LocaltimeR => {
                let time_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let out_ptr = if func_id == BionicFuncId::LocaltimeR {
                    GuestAddr::new(cpu.reg(Reg::R1))
                } else {
                    self.stub_base.add(0xBC0)
                };
                let secs = if time_ptr.as_u32() != 0 {
                    mem.read_u32(time_ptr).unwrap_or(0) as i64
                } else {
                    0
                };
                let (sec, min, hour, mday, mon, year, wday, yday) = secs_to_tm(secs);
                write_tm_struct(mem, out_ptr, sec, min, hour, mday, mon, year, wday, yday, 0)?;
                cpu.set_reg(Reg::R0, out_ptr.as_u32());
            }
            BionicFuncId::Mktime => {
                let tm_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if tm_ptr.as_u32() != 0 {
                    let sec  = mem.read_u32(tm_ptr)? as i32;
                    let min  = mem.read_u32(tm_ptr.add(4))? as i32;
                    let hour = mem.read_u32(tm_ptr.add(8))? as i32;
                    let mday = mem.read_u32(tm_ptr.add(12))? as i32;
                    let mon  = mem.read_u32(tm_ptr.add(16))? as i32;
                    let year = mem.read_u32(tm_ptr.add(20))? as i32;
                    let secs = tm_to_secs(year, mon, mday, hour, min, sec);
                    let (s, mi, h, md, mo, y, wd, yd) = secs_to_tm(secs);
                    write_tm_struct(mem, tm_ptr, s, mi, h, md, mo, y, wd, yd, 0)?;
                    cpu.set_reg(Reg::R0, secs as u32);
                } else {
                    cpu.set_reg(Reg::R0, u32::MAX);
                }
            }
            BionicFuncId::Asctime | BionicFuncId::AsctimeR => {
                let tm_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let out_ptr = if func_id == BionicFuncId::AsctimeR {
                    GuestAddr::new(cpu.reg(Reg::R1))
                } else {
                    self.stub_base.add(0xC00)
                };
                if tm_ptr.as_u32() != 0 && out_ptr.as_u32() != 0 {
                    let sec  = mem.read_u32(tm_ptr).unwrap_or(0);
                    let min  = mem.read_u32(tm_ptr.add(4)).unwrap_or(0);
                    let hour = mem.read_u32(tm_ptr.add(8)).unwrap_or(0);
                    let mday = mem.read_u32(tm_ptr.add(12)).unwrap_or(1);
                    let mon  = mem.read_u32(tm_ptr.add(16)).unwrap_or(0);
                    let year = mem.read_u32(tm_ptr.add(20)).unwrap_or(70) + 1900;
                    let wday = mem.read_u32(tm_ptr.add(24)).unwrap_or(0);
                    let days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
                    let mons = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
                    let day_str = days.get(wday as usize % 7).unwrap_or(&"Sun");
                    let mon_str = mons.get(mon as usize % 12).unwrap_or(&"Jan");
                    let s = format!("{} {} {:2} {:02}:{:02}:{:02} {}\n", day_str, mon_str, mday, hour, min, sec, year);
                    let bytes = s.as_bytes();
                    for (i, &b) in bytes.iter().enumerate() {
                        mem.write_u8(out_ptr.add(i as u32), b)?;
                    }
                    mem.write_u8(out_ptr.add(bytes.len() as u32), 0)?;
                    cpu.set_reg(Reg::R0, out_ptr.as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::Ctime | BionicFuncId::CtimeR => {
                let time_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let out_ptr = if func_id == BionicFuncId::CtimeR {
                    GuestAddr::new(cpu.reg(Reg::R1))
                } else {
                    self.stub_base.add(0xC00)
                };
                if time_ptr.as_u32() != 0 && out_ptr.as_u32() != 0 {
                    let secs = mem.read_u32(time_ptr).unwrap_or(0) as i64;
                    let (sec, min, hour, mday, mon, year_since_1900, wday, _) = secs_to_tm(secs);
                    let year = year_since_1900 + 1900;
                    let days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
                    let mons = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
                    let day_str = days.get(wday as usize % 7).unwrap_or(&"Sun");
                    let mon_str = mons.get(mon as usize % 12).unwrap_or(&"Jan");
                    let s = format!("{} {} {:2} {:02}:{:02}:{:02} {}\n", day_str, mon_str, mday, hour, min, sec, year);
                    let bytes = s.as_bytes();
                    for (i, &b) in bytes.iter().enumerate() {
                        mem.write_u8(out_ptr.add(i as u32), b)?;
                    }
                    mem.write_u8(out_ptr.add(bytes.len() as u32), 0)?;
                    cpu.set_reg(Reg::R0, out_ptr.as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::Strftime => {
                let s_ptr   = GuestAddr::new(cpu.reg(Reg::R0));
                let max     = cpu.reg(Reg::R1) as usize;
                let fmt_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                let tm_ptr  = GuestAddr::new(cpu.reg(Reg::R3));
                let fmt = Self::read_c_string(mem, fmt_ptr).unwrap_or_default();
                if tm_ptr.as_u32() == 0 || s_ptr.as_u32() == 0 || max == 0 {
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    let sec  = mem.read_u32(tm_ptr).unwrap_or(0);
                    let min  = mem.read_u32(tm_ptr.add(4)).unwrap_or(0);
                    let hour = mem.read_u32(tm_ptr.add(8)).unwrap_or(0);
                    let mday = mem.read_u32(tm_ptr.add(12)).unwrap_or(1);
                    let mon  = mem.read_u32(tm_ptr.add(16)).unwrap_or(0);
                    let year = mem.read_u32(tm_ptr.add(20)).unwrap_or(70) + 1900;
                    let wday = mem.read_u32(tm_ptr.add(24)).unwrap_or(0);
                    let yday = mem.read_u32(tm_ptr.add(28)).unwrap_or(0);
                    let days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
                    let mons = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
                    let day_str = days.get(wday as usize % 7).unwrap_or(&"Sun");
                    let mon_str = mons.get(mon as usize % 12).unwrap_or(&"Jan");

                    let mut out = String::new();
                    let mut chars = fmt.chars().peekable();
                    while let Some(c) = chars.next() {
                        if c == '%' {
                            match chars.next() {
                                Some('Y') => out.push_str(&format!("{:04}", year)),
                                Some('y') => out.push_str(&format!("{:02}", year % 100)),
                                Some('m') => out.push_str(&format!("{:02}", mon + 1)),
                                Some('d') => out.push_str(&format!("{:02}", mday)),
                                Some('e') => out.push_str(&format!("{:2}", mday)),
                                Some('H') => out.push_str(&format!("{:02}", hour)),
                                Some('M') => out.push_str(&format!("{:02}", min)),
                                Some('S') => out.push_str(&format!("{:02}", sec)),
                                Some('F') => out.push_str(&format!("{:04}-{:02}-{:02}", year, mon + 1, mday)),
                                Some('T') => out.push_str(&format!("{:02}:{:02}:{:02}", hour, min, sec)),
                                Some('R') => out.push_str(&format!("{:02}:{:02}", hour, min)),
                                Some('a') => out.push_str(day_str),
                                Some('b') | Some('h') => out.push_str(mon_str),
                                Some('j') => out.push_str(&format!("{:03}", yday + 1)),
                                Some('w') => out.push_str(&format!("{}", wday)),
                                Some('u') => out.push_str(&format!("{}", if wday == 0 { 7 } else { wday })),
                                Some('%') => out.push('%'),
                                Some(other) => { out.push('%'); out.push(other); }
                                None => out.push('%'),
                            }
                        } else {
                            out.push(c);
                        }
                    }

                    let bytes = out.as_bytes();
                    if bytes.len() < max {
                        for (i, &b) in bytes.iter().enumerate() {
                            mem.write_u8(s_ptr.add(i as u32), b)?;
                        }
                        mem.write_u8(s_ptr.add(bytes.len() as u32), 0)?;
                        cpu.set_reg(Reg::R0, bytes.len() as u32);
                    } else {
                        cpu.set_reg(Reg::R0, 0);
                    }
                }
            }
            BionicFuncId::Strptime => {
                let s_ptr   = GuestAddr::new(cpu.reg(Reg::R0));
                let fmt_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let tm_ptr  = GuestAddr::new(cpu.reg(Reg::R2));
                let s = Self::read_c_string(mem, s_ptr).unwrap_or_default();
                let fmt = Self::read_c_string(mem, fmt_ptr).unwrap_or_default();
                let consumed = parse_strptime_simple(&s, &fmt, mem, tm_ptr);
                if consumed > 0 {
                    cpu.set_reg(Reg::R0, s_ptr.add(consumed as u32).as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            // ── Stage 67: Memory-Mapped I/O APIs ───────────────────────────
            BionicFuncId::Mmap | BionicFuncId::Mmap64 => {
                let req_addr = cpu.reg(Reg::R0);
                let len      = cpu.reg(Reg::R1) as usize;
                let prot     = cpu.reg(Reg::R2);
                let _flags   = cpu.reg(Reg::R3);
                let sp       = GuestAddr::new(cpu.reg(Reg::SP));
                let fd       = if sp.as_u32() >= 0x1000 { mem.read_u32(sp).unwrap_or(u32::MAX) } else { u32::MAX };

                if len == 0 {
                    cpu.set_reg(Reg::R0, u32::MAX); // MAP_FAILED
                } else {
                    let aligned_len = (len + 0xFFF) & !0xFFF;
                    let map_addr = if req_addr != 0 {
                        GuestAddr::new(req_addr)
                    } else {
                        let addr = self.mmap_current;
                        self.mmap_current = self.mmap_current.add(aligned_len as u32);
                        addr
                    };

                    let _ = mem.commit_range(map_addr, aligned_len);
                    let _ = mem.mprotect(map_addr, aligned_len, prot);

                    if let Some(ashmem) = self.vfs.ashmem_regions.get(&fd) {
                        if let Ok(lock) = ashmem.data.lock() {
                            let copy_len = aligned_len.min(lock.len());
                            if copy_len > 0 {
                                let _ = mem.write_bytes(map_addr, &lock[..copy_len]);
                            }
                        }
                    }

                    self.mmap_regions.insert(map_addr.as_u32(), aligned_len);
                    cpu.set_reg(Reg::R0, map_addr.as_u32());
                }
            }
            BionicFuncId::Munmap => {
                let addr = cpu.reg(Reg::R0);
                let _len = cpu.reg(Reg::R1) as usize;
                self.mmap_regions.remove(&addr);
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::Madvise => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::Msync => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::Mremap => {
                let old_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let old_size = cpu.reg(Reg::R1) as usize;
                let new_size = cpu.reg(Reg::R2) as usize;
                if old_addr.as_u32() == 0 || new_size == 0 {
                    cpu.set_reg(Reg::R0, u32::MAX);
                } else if new_size <= old_size {
                    self.mmap_regions.insert(old_addr.as_u32(), new_size);
                    cpu.set_reg(Reg::R0, old_addr.as_u32());
                } else {
                    let aligned_new = (new_size + 0xFFF) & !0xFFF;
                    let new_addr = self.mmap_current;
                    self.mmap_current = self.mmap_current.add(aligned_new as u32);
                    let _ = mem.commit_range(new_addr, aligned_new);
                    let _ = mem.mprotect(new_addr, aligned_new, 0x3);
                    let copy_len = old_size.min(new_size);
                    let mut buf = vec![0u8; copy_len];
                    if mem.read_bytes(old_addr, &mut buf).is_ok() {
                        let _ = mem.write_bytes(new_addr, &buf);
                    }
                    self.mmap_regions.remove(&old_addr.as_u32());
                    self.mmap_regions.insert(new_addr.as_u32(), aligned_new);
                    cpu.set_reg(Reg::R0, new_addr.as_u32());
                }
            }
            BionicFuncId::Mlock | BionicFuncId::Munlock | BionicFuncId::Mlockall | BionicFuncId::Munlockall => {
                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::Mincore => {
                let _addr    = GuestAddr::new(cpu.reg(Reg::R0));
                let length   = cpu.reg(Reg::R1) as usize;
                let vec_ptr  = GuestAddr::new(cpu.reg(Reg::R2));
                if vec_ptr.as_u32() != 0 {
                    let pages = (length + 4095) / 4096;
                    for i in 0..pages {
                        let _ = mem.write_u8(vec_ptr.add(i as u32), 1);
                    }
                }
                cpu.set_reg(Reg::R0, 0);
            }

            // Dynamic Linker inspection (Stage 68)
            BionicFuncId::Dladdr | BionicFuncId::Dladdr1 => {
                let query_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let info_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                if func_id == BionicFuncId::Dladdr1 {
                    let extra_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                    if extra_ptr.as_u32() != 0 {
                        let _ = mem.write_u32(extra_ptr, 0);
                    }
                }

                if info_ptr.as_u32() == 0 {
                    cpu.set_reg(Reg::R0, 0);
                } else if let Some(lib) = self.dso_registry.find_by_pc(query_addr) {
                    let fname = lib.soname.as_deref().unwrap_or("libapp.so");
                    let fbase = lib.load_base.as_u32();

                    let mut best_sym: Option<(&str, GuestAddr)> = None;
                    for (sym_name, &sym_addr) in &lib.symbols {
                        if sym_addr <= query_addr {
                            match best_sym {
                                Some((_, best_addr)) if sym_addr > best_addr => {
                                    best_sym = Some((sym_name.as_str(), sym_addr));
                                }
                                None => {
                                    best_sym = Some((sym_name.as_str(), sym_addr));
                                }
                                _ => {}
                            }
                        }
                    }

                    let mut fname_bytes = fname.as_bytes().to_vec();
                    fname_bytes.push(0);
                    let fname_buf = self.stub_base.add(0xD00);
                    mem.write_bytes(fname_buf, &fname_bytes)?;

                    let (dli_sname, dli_saddr) = if let Some((sname, saddr)) = best_sym {
                        let mut sname_bytes = sname.as_bytes().to_vec();
                        sname_bytes.push(0);
                        let sname_buf = self.stub_base.add(0xE00);
                        mem.write_bytes(sname_buf, &sname_bytes)?;
                        (sname_buf.as_u32(), saddr.as_u32())
                    } else {
                        (0, 0)
                    };

                    mem.write_u32(info_ptr, fname_buf.as_u32())?;
                    mem.write_u32(info_ptr.add(4), fbase)?;
                    mem.write_u32(info_ptr.add(8), dli_sname)?;
                    mem.write_u32(info_ptr.add(12), dli_saddr)?;

                    cpu.set_reg(Reg::R0, 1);
                } else {
                    let mut found_sym: Option<(&str, GuestAddr)> = None;
                    for (name, &saddr) in &self.symbol_table {
                        if saddr == query_addr {
                            found_sym = Some((name.as_str(), saddr));
                            break;
                        }
                    }

                    if let Some((sname, saddr)) = found_sym {
                        let fname_buf = self.stub_base.add(0xD00);
                        mem.write_bytes(fname_buf, b"libc.so ")?;

                        let sname_buf = self.stub_base.add(0xE00);
                        let mut sname_bytes = sname.as_bytes().to_vec();
                        sname_bytes.push(0);
                        mem.write_bytes(sname_buf, &sname_bytes)?;

                        mem.write_u32(info_ptr, fname_buf.as_u32())?;
                        mem.write_u32(info_ptr.add(4), self.stub_base.as_u32())?;
                        mem.write_u32(info_ptr.add(8), sname_buf.as_u32())?;
                        mem.write_u32(info_ptr.add(12), saddr.as_u32())?;

                        cpu.set_reg(Reg::R0, 1);
                    } else {
                        cpu.set_reg(Reg::R0, 0);
                    }
                }
            }

            // Android Log & Assertion Extensions (Stage 68)
            BionicFuncId::AndroidLogAssert => {
                let cond_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let tag_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let fmt_addr = GuestAddr::new(cpu.reg(Reg::R2));

                let cond = if cond_addr.as_u32() != 0 {
                    Self::read_c_string(mem, cond_addr).unwrap_or_default()
                } else {
                    String::new()
                };
                let tag = if tag_addr.as_u32() != 0 {
                    Self::read_c_string(mem, tag_addr).unwrap_or_else(|_| "assertion".to_string())
                } else {
                    "assertion".to_string()
                };
                let fmt = if fmt_addr.as_u32() != 0 {
                    Self::read_c_string(mem, fmt_addr).unwrap_or_default()
                } else {
                    String::new()
                };

                let text = if !cond.is_empty() && !fmt.is_empty() {
                    format!("{}: {}", cond, fmt)
                } else if !cond.is_empty() {
                    format!("assertion \"{}\" failed", cond)
                } else {
                    fmt
                };

                self.logs.push(LogMessage {
                    priority: 7, // ANDROID_LOG_FATAL
                    tag,
                    text,
                });

                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::AndroidLogBufPrint => {
                let _buf_id = cpu.reg(Reg::R0);
                let prio = cpu.reg(Reg::R1);
                let tag_addr = GuestAddr::new(cpu.reg(Reg::R2));
                let fmt_addr = GuestAddr::new(cpu.reg(Reg::R3));

                let tag = Self::read_c_string(mem, tag_addr).unwrap_or_default();
                let fmt = Self::read_c_string(mem, fmt_addr).unwrap_or_default();

                self.logs.push(LogMessage {
                    priority: prio,
                    tag,
                    text: fmt,
                });

                cpu.set_reg(Reg::R0, 1);
            }
            BionicFuncId::AndroidLogBufWrite => {
                let _buf_id = cpu.reg(Reg::R0);
                let prio = cpu.reg(Reg::R1);
                let tag_addr = GuestAddr::new(cpu.reg(Reg::R2));
                let text_addr = GuestAddr::new(cpu.reg(Reg::R3));

                let tag = Self::read_c_string(mem, tag_addr).unwrap_or_default();
                let text = Self::read_c_string(mem, text_addr).unwrap_or_default();

                self.logs.push(LogMessage {
                    priority: prio,
                    tag,
                    text,
                });

                cpu.set_reg(Reg::R0, 1);
            }
            BionicFuncId::AndroidLogVprint => {
                let prio = cpu.reg(Reg::R0);
                let tag_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let fmt_addr = GuestAddr::new(cpu.reg(Reg::R2));
                let _ap = cpu.reg(Reg::R3);

                let tag = Self::read_c_string(mem, tag_addr).unwrap_or_default();
                let fmt = Self::read_c_string(mem, fmt_addr).unwrap_or_default();

                self.logs.push(LogMessage {
                    priority: prio,
                    tag,
                    text: fmt,
                });

                cpu.set_reg(Reg::R0, 1);
            }
            BionicFuncId::AndroidLogIsLoggable => {
                let prio = cpu.reg(Reg::R0);
                let _tag_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let def_prio = cpu.reg(Reg::R2);

                let is_loggable = if prio >= def_prio { 1 } else { 0 };
                cpu.set_reg(Reg::R0, is_loggable);
            }
            BionicFuncId::Assert => {
                let file_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let line = cpu.reg(Reg::R1);
                let msg_addr = GuestAddr::new(cpu.reg(Reg::R2));

                let file = Self::read_c_string(mem, file_addr).unwrap_or_default();
                let msg = Self::read_c_string(mem, msg_addr).unwrap_or_default();

                self.logs.push(LogMessage {
                    priority: 7, // ANDROID_LOG_FATAL
                    tag: "assert".to_string(),
                    text: format!("{}:{}: assertion failed: {}", file, line, msg),
                });

                cpu.set_reg(Reg::R0, 0);
            }
            BionicFuncId::Assert2 => {
                let file_addr = GuestAddr::new(cpu.reg(Reg::R0));
                let line = cpu.reg(Reg::R1);
                let func_addr = GuestAddr::new(cpu.reg(Reg::R2));
                let msg_addr = GuestAddr::new(cpu.reg(Reg::R3));

                let file = Self::read_c_string(mem, file_addr).unwrap_or_default();
                let func = Self::read_c_string(mem, func_addr).unwrap_or_default();
                let msg = Self::read_c_string(mem, msg_addr).unwrap_or_default();

                self.logs.push(LogMessage {
                    priority: 7, // ANDROID_LOG_FATAL
                    tag: "assert".to_string(),
                    text: format!("{}:{}: {}: assertion failed: {}", file, line, func, msg),
                });

                cpu.set_reg(Reg::R0, 0);
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

fn parse_f64_prefix(s: &str) -> (f64, usize) {
    if s.is_empty() {
        return (0.0, 0);
    }
    let lower = s.to_ascii_lowercase();
    let (sign_str, rest) = if lower.starts_with('+') {
        ("+", &lower[1..])
    } else if lower.starts_with('-') {
        ("-", &lower[1..])
    } else {
        ("", lower.as_str())
    };

    if rest.starts_with("infinity") {
        let len = sign_str.len() + 8;
        let val = if sign_str == "-" { f64::NEG_INFINITY } else { f64::INFINITY };
        return (val, len);
    }
    if rest.starts_with("inf") {
        let len = sign_str.len() + 3;
        let val = if sign_str == "-" { f64::NEG_INFINITY } else { f64::INFINITY };
        return (val, len);
    }
    if rest.starts_with("nan") {
        let len = sign_str.len() + 3;
        return (f64::NAN, len);
    }

    let bytes = s.as_bytes();
    let mut end = 0;
    let mut has_exp = false;
    let mut has_dot = false;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'+' || b == b'-' {
            if i == 0 || (has_exp && (bytes[i - 1] == b'e' || bytes[i - 1] == b'E')) {
                end = i + 1;
            } else {
                break;
            }
        } else if b == b'.' {
            if !has_dot && !has_exp {
                has_dot = true;
                end = i + 1;
            } else {
                break;
            }
        } else if b == b'e' || b == b'E' {
            if !has_exp && i > 0 && (bytes[i - 1].is_ascii_digit() || bytes[i - 1] == b'.') {
                has_exp = true;
                end = i + 1;
            } else {
                break;
            }
        } else if b.is_ascii_digit() {
            end = i + 1;
        } else {
            break;
        }
    }

    while end > 0 {
        let slice = &s[..end];
        if let Ok(val) = slice.parse::<f64>() {
            return (val, end);
        }
        let norm = if slice.starts_with('.') {
            format!("0{}", slice)
        } else if slice.starts_with("+.") {
            format!("+0{}", &slice[1..])
        } else if slice.starts_with("-.") {
            format!("-0{}", &slice[1..])
        } else {
            slice.to_string()
        };
        if let Ok(val) = norm.parse::<f64>() {
            return (val, end);
        }
        end -= 1;
    }
    (0.0, 0)
}

fn secs_to_tm(secs: i64) -> (i32, i32, i32, i32, i32, i32, i32, i32) {
    let s = secs.rem_euclid(86400) as i32;
    let sec = s % 60;
    let min = (s / 60) % 60;
    let hour = s / 3600;

    let mut days = secs.div_euclid(86400) as i32;
    let wday = (days + 4).rem_euclid(7);

    let mut year = 1970;
    loop {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if is_leap { 366 } else { 365 };
        if days >= days_in_year {
            days -= days_in_year;
            year += 1;
        } else if days < 0 {
            year -= 1;
            let prev_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
            days += if prev_leap { 366 } else { 365 };
        } else {
            break;
        }
    }
    let yday = days;
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let month_days = [31, if is_leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mon = 0;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        mon += 1;
    }
    let mday = days + 1;
    (sec, min, hour, mday, mon, year - 1900, wday, yday)
}

fn tm_to_secs(year_since_1900: i32, mon: i32, mday: i32, hour: i32, min: i32, sec: i32) -> i64 {
    let year = year_since_1900 + 1900;
    let mut days = 0i64;
    for y in 1970..year {
        let is_leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        days += if is_leap { 366 } else { 365 };
    }
    for y in (year..1970).rev() {
        let is_leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        days -= if is_leap { 366 } else { 365 };
    }
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let month_days = [31, if is_leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 0..(mon as usize).min(11) {
        days += month_days[m] as i64;
    }
    days += (mday - 1) as i64;
    days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec as i64)
}

fn write_tm_struct(
    mem: &mut impl Memory,
    addr: GuestAddr,
    sec: i32,
    min: i32,
    hour: i32,
    mday: i32,
    mon: i32,
    year: i32,
    wday: i32,
    yday: i32,
    isdst: i32,
) -> Result<(), MemoryError> {
    mem.write_u32(addr, sec as u32)?;
    mem.write_u32(addr.add(4), min as u32)?;
    mem.write_u32(addr.add(8), hour as u32)?;
    mem.write_u32(addr.add(12), mday as u32)?;
    mem.write_u32(addr.add(16), mon as u32)?;
    mem.write_u32(addr.add(20), year as u32)?;
    mem.write_u32(addr.add(24), wday as u32)?;
    mem.write_u32(addr.add(28), yday as u32)?;
    mem.write_u32(addr.add(32), isdst as u32)?;
    mem.write_u32(addr.add(36), 0)?;
    mem.write_u32(addr.add(40), 0)?;
    Ok(())
}

fn parse_strptime_simple(s: &str, fmt: &str, mem: &mut impl Memory, tm_ptr: GuestAddr) -> usize {
    let mut s_idx = 0;
    let s_chars: Vec<char> = s.chars().collect();
    let fmt_chars: Vec<char> = fmt.chars().collect();
    let mut f_idx = 0;

    let mut year = 1970;
    let mut mon = 0;
    let mut mday = 1;
    let mut hour = 0;
    let mut min = 0;
    let mut sec = 0;

    while f_idx < fmt_chars.len() && s_idx < s_chars.len() {
        if fmt_chars[f_idx] == '%' && f_idx + 1 < fmt_chars.len() {
            f_idx += 1;
            let spec = fmt_chars[f_idx];
            f_idx += 1;
            let mut num_str = String::new();
            while s_idx < s_chars.len() && s_chars[s_idx].is_ascii_digit() {
                num_str.push(s_chars[s_idx]);
                s_idx += 1;
            }
            let val = num_str.parse::<i32>().unwrap_or(0);
            match spec {
                'Y' => year = val,
                'm' => mon = (val - 1).max(0),
                'd' => mday = val,
                'H' => hour = val,
                'M' => min = val,
                'S' => sec = val,
                _ => {}
            }
        } else {
            if s_chars[s_idx] == fmt_chars[f_idx] {
                s_idx += 1;
                f_idx += 1;
            } else {
                return 0;
            }
        }
    }

    if tm_ptr.as_u32() != 0 {
        let (s, mi, h, md, mo, y, wd, yd) = secs_to_tm(tm_to_secs(year - 1900, mon, mday, hour, min, sec));
        let _ = write_tm_struct(mem, tm_ptr, s, mi, h, md, mo, y, wd, yd, 0);
    }
    s_idx
}
