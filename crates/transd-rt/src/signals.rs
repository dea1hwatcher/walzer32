/// POSIX Signal Handling, Page Fault Translation, and Fault Isolation for Transd DBT.
///
/// Under 64-bit Android ART runtime, a crash inside a legacy 32-bit library (such as a
/// NULL-pointer dereference or out-of-bounds access) would normally trigger a host SIGSEGV
/// and terminate the entire application.
///
/// Transd intercepts SIGSEGV, SIGBUS, and SIGILL via `sigaction(..., SA_SIGINFO | SA_ONSTACK)`.
/// If the faulting address `si_addr` falls within the guest virtual memory arena or guard pages,
/// Transd synthesizes a guest exception / Data Abort trap rather than crashing the host process.

use byteorder::{ByteOrder, LittleEndian};
use std::sync::atomic::{AtomicBool, Ordering};
use transd_core::{CpuState, GuestAddr, Memory, MemoryError, Reg};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultOrigin {
    /// Attempt to access NULL or first page (0x0..0x1000)
    GuestNullPointer { fault_addr: usize },
    /// Write trap to a write-protected guest code page (Self-Modifying Code)
    GuestCodeWriteTrap { fault_addr: usize, guest_addr: GuestAddr },
    /// Out-of-bounds or invalid access within guest memory arena
    GuestArenaViolation { fault_addr: usize, guest_addr: GuestAddr },
    /// Fault occurred outside guest arena (real host crash)
    HostInternal { fault_addr: usize },
}

/// Manages guest virtual memory bounds and fault classification
#[derive(Debug, Clone)]
pub struct SignalManager {
    arena_base: usize,
    arena_size: usize,
    guard_size: usize,
    handlers_installed: bool,
}

static SIGNAL_HANDLERS_ACTIVE: AtomicBool = AtomicBool::new(false);

thread_local! {
    pub static LAST_GUEST_FAULT: std::cell::RefCell<Option<FaultOrigin>> = const { std::cell::RefCell::new(None) };
}

impl SignalManager {
    pub fn new(arena_base: usize, arena_size: usize) -> Self {
        Self {
            arena_base,
            arena_size,
            guard_size: 4096,
            handlers_installed: false,
        }
    }

    pub fn with_guard(arena_base: usize, arena_size: usize, guard_size: usize) -> Self {
        Self {
            arena_base,
            arena_size,
            guard_size,
            handlers_installed: false,
        }
    }

    /// Classifies a host fault address into guest vs host origin
    pub fn classify_fault(&self, fault_addr: usize) -> FaultOrigin {
        // Null pointer check (first 4KB page)
        if fault_addr < 0x1000 {
            return FaultOrigin::GuestNullPointer { fault_addr };
        }

        // Inside guest arena
        if fault_addr >= self.arena_base && fault_addr < (self.arena_base + self.arena_size) {
            let offset = fault_addr - self.arena_base;
            return FaultOrigin::GuestArenaViolation {
                fault_addr,
                guest_addr: GuestAddr::new(offset as u32),
            };
        }

        // Inside guard page immediately following arena
        if fault_addr >= (self.arena_base + self.arena_size)
            && fault_addr < (self.arena_base + self.arena_size + self.guard_size)
        {
            let offset = fault_addr - self.arena_base;
            return FaultOrigin::GuestArenaViolation {
                fault_addr,
                guest_addr: GuestAddr::new(offset as u32),
            };
        }

        FaultOrigin::HostInternal { fault_addr }
    }

    /// Classifies a fault address with write and code-page awareness for SMC write trapping
    pub fn classify_fault_with_access(
        &self,
        fault_addr: usize,
        is_write: bool,
        is_code_page: bool,
    ) -> FaultOrigin {
        let base_origin = self.classify_fault(fault_addr);
        match base_origin {
            FaultOrigin::GuestArenaViolation { fault_addr, guest_addr } if is_write && is_code_page => {
                FaultOrigin::GuestCodeWriteTrap { fault_addr, guest_addr }
            }
            other => other,
        }
    }

    /// Evaluates whether a host fault represents an SMC write trap and returns the guest address
    pub fn is_smc_write_trap(&self, fault_addr: usize, is_write: bool, is_code_page: bool) -> Option<GuestAddr> {
        match self.classify_fault_with_access(fault_addr, is_write, is_code_page) {
            FaultOrigin::GuestCodeWriteTrap { guest_addr, .. } => Some(guest_addr),
            _ => None,
        }
    }

    /// Installs POSIX signal handlers on Unix/Android targets
    pub fn install_handlers(&mut self) -> Result<(), String> {
        if SIGNAL_HANDLERS_ACTIVE.swap(true, Ordering::SeqCst) {
            self.handlers_installed = true;
            return Ok(());
        }

        #[cfg(unix)]
        {
            use libc::{sigaction, sigaltstack, stack_t, c_void, SIGBUS, SIGILL, SIGSEGV, SA_ONSTACK, SA_SIGINFO, SIGSTKSZ};
            use std::mem;

            // 1. Allocate alternate signal stack (to survive guest stack overflow)
            let mut alt_stack: stack_t = unsafe { mem::zeroed() };
            let stack_storage = Box::leak(vec![0u8; SIGSTKSZ * 2].into_boxed_slice());
            alt_stack.ss_sp = stack_storage.as_mut_ptr() as *mut c_void;
            alt_stack.ss_size = stack_storage.len();
            alt_stack.ss_flags = 0;

            if unsafe { sigaltstack(&alt_stack, std::ptr::null_mut()) } != 0 {
                return Err("Failed to setup sigaltstack".into());
            }

            // 2. Configure sigaction handler
            let mut sa: sigaction = unsafe { mem::zeroed() };
            sa.sa_sigaction = host_signal_handler as *const () as usize;
            sa.sa_flags = SA_SIGINFO | SA_ONSTACK;

            unsafe {
                if sigaction(SIGSEGV, &sa, std::ptr::null_mut()) != 0 {
                    return Err("Failed to install SIGSEGV handler".into());
                }
                if sigaction(SIGBUS, &sa, std::ptr::null_mut()) != 0 {
                    return Err("Failed to install SIGBUS handler".into());
                }
                if sigaction(SIGILL, &sa, std::ptr::null_mut()) != 0 {
                    return Err("Failed to install SIGILL handler".into());
                }
            }
        }

        self.handlers_installed = true;
        Ok(())
    }

    pub fn is_installed(&self) -> bool {
        self.handlers_installed
    }
}

// ── Linux / Android ARM32 Signal Definitions ─────────────────────────────────

pub mod signal_nr {
    pub const SIGHUP: u32 = 1;
    pub const SIGINT: u32 = 2;
    pub const SIGQUIT: u32 = 3;
    pub const SIGILL: u32 = 4;
    pub const SIGTRAP: u32 = 5;
    pub const SIGABRT: u32 = 6;
    pub const SIGBUS: u32 = 7;
    pub const SIGFPE: u32 = 8;
    pub const SIGKILL: u32 = 9;
    pub const SIGUSR1: u32 = 10;
    pub const SIGSEGV: u32 = 11;
    pub const SIGUSR2: u32 = 12;
    pub const SIGPIPE: u32 = 13;
    pub const SIGALRM: u32 = 14;
    pub const SIGTERM: u32 = 15;
    pub const SIGCHLD: u32 = 17;
    pub const SIGCONT: u32 = 18;
    pub const SIGSTOP: u32 = 19;
    pub const SIGSYS: u32 = 31;
    pub const NSIG: u32 = 64;
}

pub mod sig_actions {
    pub const SIG_DFL: u32 = 0;
    pub const SIG_IGN: u32 = 1;
}

pub mod sa_flags {
    pub const SA_NOCLDSTOP: u32 = 0x0000_0001;
    pub const SA_NOCLDWAIT: u32 = 0x0000_0002;
    pub const SA_SIGINFO: u32 = 0x0000_0004;
    pub const SA_RESTORER: u32 = 0x0400_0000;
    pub const SA_ONSTACK: u32 = 0x0800_0000;
    pub const SA_RESTART: u32 = 0x1000_0000;
    pub const SA_NODEFER: u32 = 0x4000_0000;
    pub const SA_RESETHAND: u32 = 0x8000_0000;
}

pub mod sig_stack {
    pub const SS_ONSTACK: i32 = 1;
    pub const SS_DISABLE: i32 = 2;
    pub const MINSIGSTKSZ: u32 = 2048;
    pub const SIGSTKSZ: u32 = 8192;
}

pub mod sigprocmask_how {
    pub const SIG_BLOCK: u32 = 0;
    pub const SIG_UNBLOCK: u32 = 1;
    pub const SIG_SETMASK: u32 = 2;
}

/// Linux ARM32 `struct sigaction` (20 bytes for rt_sigaction with 64-bit mask)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestSigaction {
    pub sa_handler: u32,
    pub sa_flags: u32,
    pub sa_restorer: u32,
    pub sa_mask: u64,
}

impl Default for GuestSigaction {
    fn default() -> Self {
        Self {
            sa_handler: sig_actions::SIG_DFL,
            sa_flags: 0,
            sa_restorer: 0,
            sa_mask: 0,
        }
    }
}

impl GuestSigaction {
    pub fn read_from_mem(mem: &(impl Memory + ?Sized), addr: GuestAddr, sigsetsize: usize) -> Result<Self, MemoryError> {
        let sa_handler = mem.read_u32(addr)?;
        let sa_flags = mem.read_u32(addr.add(4))?;
        let sa_restorer = mem.read_u32(addr.add(8))?;
        let sa_mask = if sigsetsize >= 8 {
            let low = mem.read_u32(addr.add(12))? as u64;
            let high = mem.read_u32(addr.add(16))? as u64;
            (high << 32) | low
        } else if sigsetsize >= 4 {
            mem.read_u32(addr.add(12))? as u64
        } else {
            0
        };
        Ok(Self {
            sa_handler,
            sa_flags,
            sa_restorer,
            sa_mask,
        })
    }

    pub fn write_to_mem(&self, mem: &mut (impl Memory + ?Sized), addr: GuestAddr, sigsetsize: usize) -> Result<(), MemoryError> {
        mem.write_u32(addr, self.sa_handler)?;
        mem.write_u32(addr.add(4), self.sa_flags)?;
        mem.write_u32(addr.add(8), self.sa_restorer)?;
        if sigsetsize >= 8 {
            mem.write_u32(addr.add(12), self.sa_mask as u32)?;
            mem.write_u32(addr.add(16), (self.sa_mask >> 32) as u32)?;
        } else if sigsetsize >= 4 {
            mem.write_u32(addr.add(12), self.sa_mask as u32)?;
        }
        Ok(())
    }
}

/// Linux ARM32 `stack_t` (12 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestStackT {
    pub ss_sp: u32,
    pub ss_flags: i32,
    pub ss_size: u32,
}

impl Default for GuestStackT {
    fn default() -> Self {
        Self {
            ss_sp: 0,
            ss_flags: sig_stack::SS_DISABLE,
            ss_size: 0,
        }
    }
}

impl GuestStackT {
    pub fn is_enabled(&self) -> bool {
        (self.ss_flags & sig_stack::SS_DISABLE) == 0 && self.ss_size > 0
    }

    pub fn read_from_mem(mem: &(impl Memory + ?Sized), addr: GuestAddr) -> Result<Self, MemoryError> {
        let ss_sp = mem.read_u32(addr)?;
        let ss_flags = mem.read_u32(addr.add(4))? as i32;
        let ss_size = mem.read_u32(addr.add(8))?;
        Ok(Self {
            ss_sp,
            ss_flags,
            ss_size,
        })
    }

    pub fn write_to_mem(&self, mem: &mut (impl Memory + ?Sized), addr: GuestAddr) -> Result<(), MemoryError> {
        mem.write_u32(addr, self.ss_sp)?;
        mem.write_u32(addr.add(4), self.ss_flags as u32)?;
        mem.write_u32(addr.add(8), self.ss_size)?;
        Ok(())
    }
}

/// Linux ARM32 `siginfo_t` (128 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestSigInfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub si_addr: u32,
}

impl GuestSigInfo {
    pub fn write_to_mem(&self, mem: &mut (impl Memory + ?Sized), addr: GuestAddr) -> Result<(), MemoryError> {
        let mut buf = [0u8; 128];
        LittleEndian::write_i32(&mut buf[0..4], self.si_signo);
        LittleEndian::write_i32(&mut buf[4..8], self.si_errno);
        LittleEndian::write_i32(&mut buf[8..12], self.si_code);
        LittleEndian::write_u32(&mut buf[12..16], self.si_addr);
        mem.write_bytes(addr, &buf)
    }
}

/// Linux ARM32 `sigcontext` (84 bytes, 21 words)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GuestSigContext {
    pub trap_no: u32,
    pub error_code: u32,
    pub oldmask: u32,
    pub arm_r0: u32,
    pub arm_r1: u32,
    pub arm_r2: u32,
    pub arm_r3: u32,
    pub arm_r4: u32,
    pub arm_r5: u32,
    pub arm_r6: u32,
    pub arm_r7: u32,
    pub arm_r8: u32,
    pub arm_r9: u32,
    pub arm_r10: u32,
    pub arm_fp: u32,
    pub arm_ip: u32,
    pub arm_sp: u32,
    pub arm_lr: u32,
    pub arm_pc: u32,
    pub arm_cpsr: u32,
    pub fault_address: u32,
}

impl GuestSigContext {
    pub fn write_to_mem(&self, mem: &mut (impl Memory + ?Sized), addr: GuestAddr) -> Result<(), MemoryError> {
        let mut buf = [0u8; 84];
        LittleEndian::write_u32(&mut buf[0..4], self.trap_no);
        LittleEndian::write_u32(&mut buf[4..8], self.error_code);
        LittleEndian::write_u32(&mut buf[8..12], self.oldmask);
        LittleEndian::write_u32(&mut buf[12..16], self.arm_r0);
        LittleEndian::write_u32(&mut buf[16..20], self.arm_r1);
        LittleEndian::write_u32(&mut buf[20..24], self.arm_r2);
        LittleEndian::write_u32(&mut buf[24..28], self.arm_r3);
        LittleEndian::write_u32(&mut buf[28..32], self.arm_r4);
        LittleEndian::write_u32(&mut buf[32..36], self.arm_r5);
        LittleEndian::write_u32(&mut buf[36..40], self.arm_r6);
        LittleEndian::write_u32(&mut buf[40..44], self.arm_r7);
        LittleEndian::write_u32(&mut buf[44..48], self.arm_r8);
        LittleEndian::write_u32(&mut buf[48..52], self.arm_r9);
        LittleEndian::write_u32(&mut buf[52..56], self.arm_r10);
        LittleEndian::write_u32(&mut buf[56..60], self.arm_fp);
        LittleEndian::write_u32(&mut buf[60..64], self.arm_ip);
        LittleEndian::write_u32(&mut buf[64..68], self.arm_sp);
        LittleEndian::write_u32(&mut buf[68..72], self.arm_lr);
        LittleEndian::write_u32(&mut buf[72..76], self.arm_pc);
        LittleEndian::write_u32(&mut buf[76..80], self.arm_cpsr);
        LittleEndian::write_u32(&mut buf[80..84], self.fault_address);
        mem.write_bytes(addr, &buf)
    }

    pub fn read_from_mem(mem: &(impl Memory + ?Sized), addr: GuestAddr) -> Result<Self, MemoryError> {
        let mut buf = [0u8; 84];
        mem.read_bytes(addr, &mut buf)?;
        Ok(Self {
            trap_no: LittleEndian::read_u32(&buf[0..4]),
            error_code: LittleEndian::read_u32(&buf[4..8]),
            oldmask: LittleEndian::read_u32(&buf[8..12]),
            arm_r0: LittleEndian::read_u32(&buf[12..16]),
            arm_r1: LittleEndian::read_u32(&buf[16..20]),
            arm_r2: LittleEndian::read_u32(&buf[20..24]),
            arm_r3: LittleEndian::read_u32(&buf[24..28]),
            arm_r4: LittleEndian::read_u32(&buf[28..32]),
            arm_r5: LittleEndian::read_u32(&buf[32..36]),
            arm_r6: LittleEndian::read_u32(&buf[36..40]),
            arm_r7: LittleEndian::read_u32(&buf[40..44]),
            arm_r8: LittleEndian::read_u32(&buf[44..48]),
            arm_r9: LittleEndian::read_u32(&buf[48..52]),
            arm_r10: LittleEndian::read_u32(&buf[52..56]),
            arm_fp: LittleEndian::read_u32(&buf[56..60]),
            arm_ip: LittleEndian::read_u32(&buf[60..64]),
            arm_sp: LittleEndian::read_u32(&buf[64..68]),
            arm_lr: LittleEndian::read_u32(&buf[68..72]),
            arm_pc: LittleEndian::read_u32(&buf[72..76]),
            arm_cpsr: LittleEndian::read_u32(&buf[76..80]),
            fault_address: LittleEndian::read_u32(&buf[80..84]),
        })
    }
}

/// Linux ARM32 `ucontext_t` (112 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GuestUContext {
    pub uc_flags: u32,
    pub uc_link: u32,
    pub uc_stack: GuestStackT,
    pub uc_mcontext: GuestSigContext,
    pub uc_sigmask: u64,
}

impl GuestUContext {
    pub fn write_to_mem(&self, mem: &mut (impl Memory + ?Sized), addr: GuestAddr) -> Result<(), MemoryError> {
        mem.write_u32(addr, self.uc_flags)?;
        mem.write_u32(addr.add(4), self.uc_link)?;
        self.uc_stack.write_to_mem(mem, addr.add(8))?;
        self.uc_mcontext.write_to_mem(mem, addr.add(20))?;
        mem.write_u32(addr.add(104), self.uc_sigmask as u32)?;
        mem.write_u32(addr.add(108), (self.uc_sigmask >> 32) as u32)?;
        Ok(())
    }

    pub fn read_from_mem(mem: &(impl Memory + ?Sized), addr: GuestAddr) -> Result<Self, MemoryError> {
        let uc_flags = mem.read_u32(addr)?;
        let uc_link = mem.read_u32(addr.add(4))?;
        let uc_stack = GuestStackT::read_from_mem(mem, addr.add(8))?;
        let uc_mcontext = GuestSigContext::read_from_mem(mem, addr.add(20))?;
        let low = mem.read_u32(addr.add(104))? as u64;
        let high = mem.read_u32(addr.add(108))? as u64;
        let uc_sigmask = (high << 32) | low;
        Ok(Self {
            uc_flags,
            uc_link,
            uc_stack,
            uc_mcontext,
            uc_sigmask,
        })
    }
}

/// Process-wide signal registration, masks, and signal frame delivery state
#[derive(Debug, Clone)]
pub struct SignalState {
    pub actions: [GuestSigaction; 65],
    pub blocked_mask: u64,
    pub pending_mask: u64,
    pub alt_stack: GuestStackT,
}

impl Default for SignalState {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalState {
    pub fn new() -> Self {
        Self {
            actions: [GuestSigaction::default(); 65],
            blocked_mask: 0,
            pending_mask: 0,
            alt_stack: GuestStackT::default(),
        }
    }

    /// Sets or queries a signal action. Returns old action or -EINVAL (-22).
    pub fn set_action(&mut self, sig: u32, act: Option<GuestSigaction>) -> Result<GuestSigaction, i32> {
        if sig == 0 || sig > signal_nr::NSIG || sig == signal_nr::SIGKILL || sig == signal_nr::SIGSTOP {
            return Err(-22); // -EINVAL
        }
        let old = self.actions[sig as usize];
        if let Some(new_act) = act {
            self.actions[sig as usize] = new_act;
        }
        Ok(old)
    }

    pub fn get_action(&self, sig: u32) -> Option<GuestSigaction> {
        if sig > 0 && sig <= signal_nr::NSIG {
            Some(self.actions[sig as usize])
        } else {
            None
        }
    }

    /// Modifies the signal mask (SIG_BLOCK = 0, SIG_UNBLOCK = 1, SIG_SETMASK = 2).
    /// Returns previous mask.
    pub fn sigprocmask(&mut self, how: u32, set: Option<u64>) -> Result<u64, i32> {
        let old_mask = self.blocked_mask;
        if let Some(s) = set {
            match how {
                sigprocmask_how::SIG_BLOCK => {
                    self.blocked_mask |= s;
                }
                sigprocmask_how::SIG_UNBLOCK => {
                    self.blocked_mask &= !s;
                }
                sigprocmask_how::SIG_SETMASK => {
                    self.blocked_mask = s;
                }
                _ => return Err(-22), // -EINVAL
            }
            // SIGKILL and SIGSTOP cannot be blocked
            let unblockable = (1u64 << (signal_nr::SIGKILL - 1)) | (1u64 << (signal_nr::SIGSTOP - 1));
            self.blocked_mask &= !unblockable;
        }
        Ok(old_mask)
    }

    /// Configures or queries an alternate signal stack.
    /// Returns previous stack configuration.
    pub fn sigaltstack(&mut self, new_ss: Option<GuestStackT>, current_sp: u32) -> Result<GuestStackT, i32> {
        let old_ss = self.alt_stack;
        if let Some(ss) = new_ss {
            // Check if currently executing on alternate stack
            if old_ss.is_enabled()
                && current_sp >= old_ss.ss_sp
                && current_sp < (old_ss.ss_sp.wrapping_add(old_ss.ss_size))
            {
                return Err(-1); // -EPERM
            }

            if (ss.ss_flags & sig_stack::SS_DISABLE) == 0 && ss.ss_size < sig_stack::MINSIGSTKSZ {
                return Err(-12); // -ENOMEM
            }

            self.alt_stack = ss;
        }
        Ok(old_ss)
    }

    /// Delivers a signal into the guest by constructing an ARM Linux rt_sigframe
    /// on the appropriate stack, setting up registers, and pointing PC to handler.
    /// Returns `true` if delivered, `false` if ignored or default action.
    pub fn deliver_signal(
        &mut self,
        sig: u32,
        fault_addr: Option<u32>,
        cpu: &mut CpuState,
        mem: &mut (impl Memory + ?Sized),
        restorer_override: Option<GuestAddr>,
    ) -> Result<bool, MemoryError> {
        if sig == 0 || sig > signal_nr::NSIG {
            return Ok(false);
        }

        let act = self.actions[sig as usize];
        if act.sa_handler == sig_actions::SIG_IGN {
            return Ok(false);
        }
        if act.sa_handler == sig_actions::SIG_DFL {
            return Ok(false);
        }

        // Determine destination stack
        let target_sp = if (act.sa_flags & sa_flags::SA_ONSTACK) != 0 && self.alt_stack.is_enabled() {
            self.alt_stack.ss_sp.wrapping_add(self.alt_stack.ss_size)
        } else {
            cpu.sp()
        };

        // Align frame to 8 bytes and allocate 256-byte frame
        // [sp..sp+128]: GuestSigInfo (128 bytes)
        // [sp+128..sp+240]: GuestUContext (112 bytes)
        // [sp+240..sp+248]: rt_sigreturn trampoline (8 bytes)
        let frame_sp = GuestAddr::new((target_sp.wrapping_sub(256)) & !7);

        // 1. Write siginfo_t
        let siginfo = GuestSigInfo {
            si_signo: sig as i32,
            si_errno: 0,
            si_code: 1, // e.g. SEGV_MAPERR / SI_USER
            si_addr: fault_addr.unwrap_or(0),
        };
        siginfo.write_to_mem(mem, frame_sp)?;

        // 2. Write ucontext_t
        let sigcontext = GuestSigContext {
            trap_no: 0,
            error_code: 0,
            oldmask: self.blocked_mask as u32,
            arm_r0: cpu.reg(Reg::R0),
            arm_r1: cpu.reg(Reg::R1),
            arm_r2: cpu.reg(Reg::R2),
            arm_r3: cpu.reg(Reg::R3),
            arm_r4: cpu.reg(Reg::R4),
            arm_r5: cpu.reg(Reg::R5),
            arm_r6: cpu.reg(Reg::R6),
            arm_r7: cpu.reg(Reg::R7),
            arm_r8: cpu.reg(Reg::R8),
            arm_r9: cpu.reg(Reg::R9),
            arm_r10: cpu.reg(Reg::R10),
            arm_fp: cpu.reg(Reg::R11),
            arm_ip: cpu.reg(Reg::R12),
            arm_sp: cpu.sp(),
            arm_lr: cpu.lr(),
            arm_pc: cpu.pc().as_u32(),
            arm_cpsr: cpu.cpsr.bits(),
            fault_address: fault_addr.unwrap_or(0),
        };

        let ucontext = GuestUContext {
            uc_flags: 0,
            uc_link: 0,
            uc_stack: self.alt_stack,
            uc_mcontext: sigcontext,
            uc_sigmask: self.blocked_mask,
        };
        ucontext.write_to_mem(mem, frame_sp.add(128))?;

        // 3. Write on-stack rt_sigreturn trampoline:
        // MOV r7, #173 (0xE3A0_70AD)
        // SVC #0       (0xEF00_0000)
        mem.write_u32(frame_sp.add(240), 0xE3A0_70AD)?;
        mem.write_u32(frame_sp.add(244), 0xEF00_0000)?;

        let restorer = if let Some(ov) = restorer_override {
            ov
        } else if (act.sa_flags & sa_flags::SA_RESTORER) != 0 && act.sa_restorer != 0 {
            GuestAddr::new(act.sa_restorer)
        } else {
            frame_sp.add(240)
        };

        // 4. Update CPU registers to enter signal handler
        cpu.set_reg(Reg::R0, sig);
        if (act.sa_flags & sa_flags::SA_SIGINFO) != 0 {
            cpu.set_reg(Reg::R1, frame_sp.as_u32());
            cpu.set_reg(Reg::R2, frame_sp.add(128).as_u32());
        }
        cpu.set_lr(restorer.as_u32());
        cpu.set_sp(frame_sp.as_u32());
        cpu.set_pc(GuestAddr::new(act.sa_handler));

        // 5. Update blocked signal mask
        self.blocked_mask |= act.sa_mask;
        if (act.sa_flags & sa_flags::SA_NODEFER) == 0 {
            self.blocked_mask |= 1u64 << (sig - 1);
        }

        if (act.sa_flags & sa_flags::SA_RESETHAND) != 0 {
            self.actions[sig as usize].sa_handler = sig_actions::SIG_DFL;
        }

        Ok(true)
    }

    /// Restores guest CPU state and signal mask from `ucontext_t` on the stack during rt_sigreturn.
    pub fn restore_sigreturn(&mut self, cpu: &mut CpuState, mem: &(impl Memory + ?Sized)) -> Result<(), MemoryError> {
        let sp = GuestAddr::new(cpu.sp());
        // Find ucontext: if sp points to frame base, ucontext is at sp + 128
        let ucontext_addr = if mem.read_u32(sp.add(240)).unwrap_or(0) == 0xE3A0_70AD {
            sp.add(128)
        } else if mem.read_u32(sp.add(112)).unwrap_or(0) == 0xE3A0_70AD {
            sp
        } else {
            sp.add(128)
        };

        let ucontext = GuestUContext::read_from_mem(mem, ucontext_addr)?;
        cpu.set_reg(Reg::R0, ucontext.uc_mcontext.arm_r0);
        cpu.set_reg(Reg::R1, ucontext.uc_mcontext.arm_r1);
        cpu.set_reg(Reg::R2, ucontext.uc_mcontext.arm_r2);
        cpu.set_reg(Reg::R3, ucontext.uc_mcontext.arm_r3);
        cpu.set_reg(Reg::R4, ucontext.uc_mcontext.arm_r4);
        cpu.set_reg(Reg::R5, ucontext.uc_mcontext.arm_r5);
        cpu.set_reg(Reg::R6, ucontext.uc_mcontext.arm_r6);
        cpu.set_reg(Reg::R7, ucontext.uc_mcontext.arm_r7);
        cpu.set_reg(Reg::R8, ucontext.uc_mcontext.arm_r8);
        cpu.set_reg(Reg::R9, ucontext.uc_mcontext.arm_r9);
        cpu.set_reg(Reg::R10, ucontext.uc_mcontext.arm_r10);
        cpu.set_reg(Reg::R11, ucontext.uc_mcontext.arm_fp);
        cpu.set_reg(Reg::R12, ucontext.uc_mcontext.arm_ip);
        cpu.set_sp(ucontext.uc_mcontext.arm_sp);
        cpu.set_lr(ucontext.uc_mcontext.arm_lr);
        cpu.set_pc(GuestAddr::new(ucontext.uc_mcontext.arm_pc));
        cpu.cpsr = transd_core::Cpsr::from_bits_retain(ucontext.uc_mcontext.arm_cpsr);
        self.blocked_mask = ucontext.uc_sigmask;

        Ok(())
    }
}

#[cfg(unix)]
extern "C" fn host_signal_handler(sig: libc::c_int, info: *mut libc::siginfo_t, _ucontext: *mut libc::c_void) {
    let fault_addr = if !info.is_null() {
        unsafe { (*info).si_addr() as usize }
    } else {
        0
    };
    eprintln!("CRITICAL: host_signal_handler caught signal {} at fault_addr 0x{:x}", sig, fault_addr);
    std::process::abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_null_pointer() {
        let mgr = SignalManager::new(0x7000_0000, 0x1000_0000);
        assert_eq!(
            mgr.classify_fault(0x0),
            FaultOrigin::GuestNullPointer { fault_addr: 0x0 }
        );
        assert_eq!(
            mgr.classify_fault(0x400),
            FaultOrigin::GuestNullPointer { fault_addr: 0x400 }
        );
    }

    #[test]
    fn test_classify_guest_arena_access() {
        let base = 0x7000_0000;
        let size = 0x1000_0000; // 256MB
        let mgr = SignalManager::new(base, size);

        let fault = base + 0x0040_0000; // +4MB into arena
        assert_eq!(
            mgr.classify_fault(fault),
            FaultOrigin::GuestArenaViolation {
                fault_addr: fault,
                guest_addr: GuestAddr::new(0x0040_0000),
            }
        );
    }

    #[test]
    fn test_classify_host_internal() {
        let base = 0x7000_0000;
        let size = 0x1000_0000;
        let mgr = SignalManager::new(base, size);

        // Outside arena and guard page
        let fault = 0x9000_0000;
        assert_eq!(
            mgr.classify_fault(fault),
            FaultOrigin::HostInternal { fault_addr: fault }
        );
    }

    #[test]
    fn test_classify_guest_code_write_trap() {
        let base = 0x7000_0000;
        let size = 0x1000_0000;
        let mgr = SignalManager::new(base, size);

        let fault = base + 0x0010_2000;
        let origin = mgr.classify_fault_with_access(fault, true, true);
        assert_eq!(
            origin,
            FaultOrigin::GuestCodeWriteTrap {
                fault_addr: fault,
                guest_addr: GuestAddr::new(0x0010_2000),
            }
        );
    }

    #[test]
    fn test_install_handlers_idempotent() {
        let mut mgr = SignalManager::new(0x7000_0000, 0x1000_0000);
        assert!(mgr.install_handlers().is_ok());
        assert!(mgr.is_installed());
    }

    #[test]
    fn test_guest_sigaction_serialization() {
        use transd_core::FlatMemory;
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x1000);
        let act = GuestSigaction {
            sa_handler: 0x4000_1234,
            sa_flags: sa_flags::SA_SIGINFO | sa_flags::SA_ONSTACK,
            sa_restorer: 0x4000_5678,
            sa_mask: 0x0123_4567_89AB_CDEF,
        };

        let addr = GuestAddr::new(0x1050);
        act.write_to_mem(&mut mem, addr, 8).unwrap();
        let loaded = GuestSigaction::read_from_mem(&mem, addr, 8).unwrap();
        assert_eq!(act, loaded);
    }

    #[test]
    fn test_signal_state_masks_and_registration() {
        let mut state = SignalState::new();

        // Register action for SIGSEGV
        let act = GuestSigaction {
            sa_handler: 0x2000_1000,
            sa_flags: sa_flags::SA_SIGINFO,
            sa_restorer: 0,
            sa_mask: 1 << (signal_nr::SIGBUS - 1),
        };
        let old = state.set_action(signal_nr::SIGSEGV, Some(act)).unwrap();
        assert_eq!(old.sa_handler, sig_actions::SIG_DFL);
        assert_eq!(state.get_action(signal_nr::SIGSEGV).unwrap(), act);

        // SIGKILL / SIGSTOP cannot be modified
        assert_eq!(state.set_action(signal_nr::SIGKILL, Some(act)), Err(-22));
        assert_eq!(state.set_action(signal_nr::SIGSTOP, Some(act)), Err(-22));

        // Test sigprocmask (BLOCK, UNBLOCK, SETMASK)
        let mask1 = 1u64 << (signal_nr::SIGINT - 1);
        let prev = state.sigprocmask(sigprocmask_how::SIG_BLOCK, Some(mask1)).unwrap();
        assert_eq!(prev, 0);
        assert_eq!(state.blocked_mask, mask1);

        let mask2 = 1u64 << (signal_nr::SIGQUIT - 1);
        state.sigprocmask(sigprocmask_how::SIG_BLOCK, Some(mask2)).unwrap();
        assert_eq!(state.blocked_mask, mask1 | mask2);

        state.sigprocmask(sigprocmask_how::SIG_UNBLOCK, Some(mask1)).unwrap();
        assert_eq!(state.blocked_mask, mask2);

        // SIGKILL / SIGSTOP cannot be blocked
        let unblockable = 1u64 << (signal_nr::SIGKILL - 1);
        state.sigprocmask(sigprocmask_how::SIG_SETMASK, Some(unblockable)).unwrap();
        assert_eq!(state.blocked_mask, 0);
    }

    #[test]
    fn test_alternate_signal_stack() {
        let mut state = SignalState::new();
        assert!(!state.alt_stack.is_enabled());

        // Attempting size < MINSIGSTKSZ (2048) returns -ENOMEM (-12)
        let too_small = GuestStackT {
            ss_sp: 0x3000_0000,
            ss_flags: 0,
            ss_size: 1024,
        };
        assert_eq!(state.sigaltstack(Some(too_small), 0x2000_0000), Err(-12));

        // Valid altstack
        let valid_ss = GuestStackT {
            ss_sp: 0x3000_0000,
            ss_flags: 0,
            ss_size: 8192,
        };
        let prev = state.sigaltstack(Some(valid_ss), 0x2000_0000).unwrap();
        assert_eq!(prev.ss_flags, sig_stack::SS_DISABLE);
        assert!(state.alt_stack.is_enabled());

        // Modifying stack while executing on it returns -EPERM (-1)
        assert_eq!(state.sigaltstack(Some(valid_ss), 0x3000_1000), Err(-1));
    }

    #[test]
    fn test_signal_frame_delivery_and_restore_roundtrip() {
        use transd_core::FlatMemory;
        let mut mem = FlatMemory::new(GuestAddr::new(0x2000_0000), 0x40_000);
        let mut cpu = CpuState::new();

        // Initial CPU state before signal
        cpu.set_reg(Reg::R0, 111);
        cpu.set_reg(Reg::R1, 222);
        cpu.set_reg(Reg::R7, 777);
        cpu.set_sp(0x2002_0000);
        cpu.set_lr(0x2000_8888);
        cpu.set_pc(GuestAddr::new(0x2000_0100));

        let mut state = SignalState::new();
        let handler_addr = 0x2000_0500;
        let act = GuestSigaction {
            sa_handler: handler_addr,
            sa_flags: sa_flags::SA_SIGINFO,
            sa_restorer: 0,
            sa_mask: 1 << (signal_nr::SIGUSR1 - 1),
        };
        state.set_action(signal_nr::SIGSEGV, Some(act)).unwrap();

        // Deliver SIGSEGV (fault address = 0xDEAD_BEEF)
        let delivered = state
            .deliver_signal(signal_nr::SIGSEGV, Some(0xDEAD_BEEF), &mut cpu, &mut mem, None)
            .unwrap();
        assert!(delivered);

        // Verification of handler entry state
        assert_eq!(cpu.pc(), GuestAddr::new(handler_addr));
        assert_eq!(cpu.reg(Reg::R0), signal_nr::SIGSEGV);
        let siginfo_addr = GuestAddr::new(cpu.reg(Reg::R1));
        let ucontext_addr = GuestAddr::new(cpu.reg(Reg::R2));
        assert_eq!(ucontext_addr, siginfo_addr.add(128));
        assert_eq!(cpu.lr(), siginfo_addr.add(240).as_u32()); // points to trampoline

        // Verify siginfo contents in guest memory
        assert_eq!(mem.read_u32(siginfo_addr).unwrap(), signal_nr::SIGSEGV);
        assert_eq!(mem.read_u32(siginfo_addr.add(12)).unwrap(), 0xDEAD_BEEF);

        // Verify trampoline instructions at lr
        assert_eq!(mem.read_u32(GuestAddr::new(cpu.lr())).unwrap(), 0xE3A0_70AD); // MOV r7, #173
        assert_eq!(mem.read_u32(GuestAddr::new(cpu.lr()).add(4)).unwrap(), 0xEF00_0000); // SVC #0

        // Mask should now block SIGSEGV and SIGUSR1
        assert_ne!(state.blocked_mask & (1 << (signal_nr::SIGSEGV - 1)), 0);
        assert_ne!(state.blocked_mask & (1 << (signal_nr::SIGUSR1 - 1)), 0);

        // Simulate handler returning: invoke restore_sigreturn
        state.restore_sigreturn(&mut cpu, &mem).unwrap();

        // All pre-signal registers restored!
        assert_eq!(cpu.reg(Reg::R0), 111);
        assert_eq!(cpu.reg(Reg::R1), 222);
        assert_eq!(cpu.reg(Reg::R7), 777);
        assert_eq!(cpu.sp(), 0x2002_0000);
        assert_eq!(cpu.lr(), 0x2000_8888);
        assert_eq!(cpu.pc(), GuestAddr::new(0x2000_0100));
        assert_eq!(state.blocked_mask, 0); // Original mask restored!
    }
}
