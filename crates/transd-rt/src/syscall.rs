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
    pub const BRK: u32 = 45;
    pub const IOCTL: u32 = 54;
    pub const MUNMAP: u32 = 91;
    pub const CLONE: u32 = 120;
    pub const UNAME: u32 = 122;
    pub const MPROTECT: u32 = 125;
    pub const _LLSEEK: u32 = 140;
    pub const WRITEV: u32 = 146;
    pub const NANOSLEEP: u32 = 162;
    pub const GETTIMEOFDAY: u32 = 78;
    pub const MMAP2: u32 = 192;
    pub const STAT64: u32 = 195;
    pub const LSTAT64: u32 = 196;
    pub const FSTAT64: u32 = 197;
    pub const GETTID: u32 = 224;
    pub const FUTEX: u32 = 240;
    pub const CLOCK_GETTIME: u32 = 263;
    pub const TGKILL: u32 = 268;
    pub const OPENAT: u32 = 322;
    pub const FSTATAT64: u32 = 327;
    pub const FACCESSAT: u32 = 334;
    pub const ARM_CACHE_FLUSH: u32 = 0xF0002;
    pub const ARM_SET_TLS: u32 = 0xF0005;
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
