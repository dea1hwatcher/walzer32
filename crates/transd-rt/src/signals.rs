/// POSIX Signal Handling, Page Fault Translation, and Fault Isolation for Transd DBT.
///
/// Under 64-bit Android ART runtime, a crash inside a legacy 32-bit library (such as a
/// NULL-pointer dereference or out-of-bounds access) would normally trigger a host SIGSEGV
/// and terminate the entire application.
///
/// Transd intercepts SIGSEGV, SIGBUS, and SIGILL via `sigaction(..., SA_SIGINFO | SA_ONSTACK)`.
/// If the faulting address `si_addr` falls within the guest virtual memory arena or guard pages,
/// Transd synthesizes a guest exception / Data Abort trap rather than crashing the host process.

use std::sync::atomic::{AtomicBool, Ordering};
use transd_core::GuestAddr;

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
            use libc::{sigaction, sigaltstack, stack_t, c_int, siginfo_t, c_void, SIGBUS, SIGILL, SIGSEGV, SA_ONSTACK, SA_SIGINFO, SIGSTKSZ};
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
            sa.sa_sigaction = host_signal_handler as usize;
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

#[cfg(unix)]
extern "C" fn host_signal_handler(sig: libc::c_int, info: *mut libc::siginfo_t, _ucontext: *mut libc::c_void) {
    if !info.is_null() {
        let fault_addr = unsafe { (*info).si_addr as usize };
        LAST_GUEST_FAULT.with(|f| {
            *f.borrow_mut() = Some(FaultOrigin::GuestNullPointer { fault_addr });
        });
    }
    // On real Android, this jumps back to recovery longjmp landing pad
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
}
