use transd_core::Reg;

/// Linux ARM32 System Call Numbers (passed in r7)
pub mod nr {
    pub const RESTART_SYSCALL: u32 = 0;
    pub const EXIT: u32 = 1;
    pub const FORK: u32 = 2;
    pub const READ: u32 = 3;
    pub const WRITE: u32 = 4;
    pub const OPEN: u32 = 5;
    pub const CLOSE: u32 = 6;
    pub const LSEEK: u32 = 19;
    pub const GETPID: u32 = 20;
    pub const GETUID: u32 = 24;
    pub const ACCESS: u32 = 33;
    pub const KILL: u32 = 37;
    pub const BRK: u32 = 45;
    pub const IOCTL: u32 = 54;
    pub const MUNMAP: u32 = 91;
    pub const SIGRETURN: u32 = 119;
    pub const CLONE: u32 = 120;
    pub const UNAME: u32 = 122;
    pub const MPROTECT: u32 = 125;
    pub const _LLSEEK: u32 = 140;
    pub const WRITEV: u32 = 146;
    pub const NANOSLEEP: u32 = 162;
    pub const RT_SIGRETURN: u32 = 173;
    pub const RT_SIGACTION: u32 = 174;
    pub const RT_SIGPROCMASK: u32 = 175;
    pub const RT_SIGPENDING: u32 = 176;
    pub const RT_SIGTIMEDWAIT: u32 = 177;
    pub const RT_SIGQUEUEINFO: u32 = 178;
    pub const RT_SIGSUSPEND: u32 = 179;
    pub const SIGALTSTACK: u32 = 186;
    pub const GETTIMEOFDAY: u32 = 78;
    pub const MMAP2: u32 = 192;
    pub const STAT64: u32 = 195;
    pub const LSTAT64: u32 = 196;
    pub const FSTAT64: u32 = 197;
    pub const GETTID: u32 = 224;
    pub const TKILL: u32 = 238;
    pub const FUTEX: u32 = 240;
    pub const CLOCK_GETTIME: u32 = 263;
    pub const TGKILL: u32 = 268;
    pub const OPENAT: u32 = 322;
    pub const FSTATAT64: u32 = 327;
    pub const FACCESSAT: u32 = 334;
    pub const ARM_CACHE_FLUSH: u32 = 0xF0002;
    pub const ARM_SET_TLS: u32 = 0xF0005;
    pub const MEMFD_CREATE: u32 = 385;
}

/// Linux Android Ashmem ioctl commands
pub mod ashmem_cmd {
    pub const ASHMEM_SET_NAME: u32 = 0x41007701;
    pub const ASHMEM_GET_NAME: u32 = 0x81007702;
    pub const ASHMEM_SET_SIZE: u32 = 0x40047703;
    pub const ASHMEM_SET_SIZE_64: u32 = 0x40087703;
    pub const ASHMEM_GET_SIZE: u32 = 0x7704;
    pub const ASHMEM_SET_PROT_MASK: u32 = 0x40047705;
    pub const ASHMEM_SET_PROT_MASK_64: u32 = 0x40087705;
    pub const ASHMEM_GET_PROT_MASK: u32 = 0x7706;
    pub const ASHMEM_IS_INITIALIZED: u32 = 0x770B;
}

/// Linux Futex operation constants
pub mod futex_op {
    pub const WAIT: u32 = 0;
    pub const WAKE: u32 = 1;
    pub const FD: u32 = 2;
    pub const REQUEUE: u32 = 3;
    pub const CMP_REQUEUE: u32 = 4;
    pub const WAKE_OP: u32 = 5;
    pub const PRIVATE_FLAG: u32 = 128;
}

/// Syscall invocation arguments in ARM32 ABI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallArgs {
    pub nr: u32,
    pub arg0: u32, // r0
    pub arg1: u32, // r1
    pub arg2: u32, // r2
    pub arg3: u32, // r3
    pub arg4: u32, // r4
    pub arg5: u32, // r5
}

impl SyscallArgs {
    pub fn from_cpu(cpu: &transd_core::CpuState) -> Self {
        Self {
            nr: cpu.reg(Reg::R7),
            arg0: cpu.reg(Reg::R0),
            arg1: cpu.reg(Reg::R1),
            arg2: cpu.reg(Reg::R2),
            arg3: cpu.reg(Reg::R3),
            arg4: cpu.reg(Reg::R4),
            arg5: cpu.reg(Reg::R5),
        }
    }
}

/// Returns true if the syscall is eligible for SA_RESTART rewinding upon signal interruption.
/// Timed calls (nanosleep, timed futex, etc.) must NOT restart.
pub fn is_restartable_syscall(nr: u32, arg3: u32) -> bool {
    match nr {
        nr::READ | nr::WRITE | nr::OPEN | nr::CLOSE | nr::IOCTL | nr::WRITEV | nr::OPENAT => true,
        nr::FUTEX => {
            // arg3 is timeout pointer. Untimed futex (timeout == 0) is restartable.
            arg3 == 0
        }
        _ => false,
    }
}
