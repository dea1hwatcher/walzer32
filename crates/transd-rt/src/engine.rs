use thiserror::Error;
use transd_core::{CpuState, GuestAddr, Memory, MemoryError, Reg};
use transd_emitter_a64::{A64Compiler, PatchTarget};
use transd_interp::{InterpError, Interpreter, StepResult};
use transd_ir::{Lifter, SuperblockOptimizer, TraceBuilder};
use crate::cache::JitCache;
use crate::futex::{FutexError, FutexManager};
use crate::jit_pool::JitPool;
use crate::syscall::{futex_op, nr, SyscallArgs};

#[derive(Error, Debug)]
pub enum EngineError {
    #[error("Memory error: {0}")]
    Memory(#[from] MemoryError),
    #[error("Interpreter error: {0}")]
    Interp(#[from] InterpError),
    #[error("Execution trapped: {0}")]
    Trap(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineStepResult {
    Continue,
    Syscall(SyscallArgs),
    Halted { exit_code: u32 },
    Breakpoint { imm: u16 },
}

pub trait SyscallHandler: Send {
    fn handle_syscall(
        &mut self,
        args: SyscallArgs,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<Option<u32>, EngineError>;

    fn vfs(&self) -> Option<&crate::vfs::VirtualFileSystem> {
        None
    }

    fn vfs_mut(&mut self) -> Option<&mut crate::vfs::VirtualFileSystem> {
        None
    }

    fn set_mmap_base(&mut self, _base: GuestAddr) {}

    fn signal_state(&self) -> Option<&crate::signals::SignalState> {
        None
    }

    fn signal_state_mut(&mut self) -> Option<&mut crate::signals::SignalState> {
        None
    }
}

pub struct DefaultSyscallHandler {
    pub stdout_capture: Vec<u8>,
    pub futex: FutexManager,
    pub tid: u32,
    pub vfs: crate::vfs::VirtualFileSystem,
    pub brk: u32,
    pub mmap_current: GuestAddr,
    pub signal_state: crate::signals::SignalState,
}

impl Default for DefaultSyscallHandler {
    fn default() -> Self {
        Self {
            stdout_capture: Vec::new(),
            futex: FutexManager::new(),
            tid: 1000,
            vfs: crate::vfs::VirtualFileSystem::new(),
            brk: 0x4000_0000,
            mmap_current: GuestAddr::new(0x7100_0000),
            signal_state: crate::signals::SignalState::new(),
        }
    }
}

impl DefaultSyscallHandler {
    pub fn with_futex(futex: FutexManager, tid: u32) -> Self {
        Self {
            stdout_capture: Vec::new(),
            futex,
            tid,
            vfs: crate::vfs::VirtualFileSystem::new(),
            brk: 0x4000_0000,
            mmap_current: GuestAddr::new(0x7100_0000),
            signal_state: crate::signals::SignalState::new(),
        }
    }

    pub fn with_vfs(vfs: crate::vfs::VirtualFileSystem) -> Self {
        Self {
            stdout_capture: Vec::new(),
            futex: FutexManager::new(),
            tid: 1000,
            vfs,
            brk: 0x4000_0000,
            mmap_current: GuestAddr::new(0x7100_0000),
            signal_state: crate::signals::SignalState::new(),
        }
    }

    pub fn set_mmap_base(&mut self, base: GuestAddr) {
        self.mmap_current = base;
    }
}

fn write_utsname(mem: &mut dyn Memory, addr: GuestAddr) -> Result<(), transd_core::MemoryError> {
    let mut bytes = [0u8; 390];
    let fill = |slice: &mut [u8], s: &str| {
        let b = s.as_bytes();
        let len = b.len().min(64);
        slice[..len].copy_from_slice(&b[..len]);
        slice[len] = 0;
    };
    fill(&mut bytes[0..65], "Linux");
    fill(&mut bytes[65..130], "localhost");
    fill(&mut bytes[130..195], "4.14.180-transd");
    fill(&mut bytes[195..260], "#1 SMP PREEMPT 2026");
    fill(&mut bytes[260..325], "armv7l");
    fill(&mut bytes[325..390], "localdomain");
    mem.write_bytes(addr, &bytes)
}

impl SyscallHandler for DefaultSyscallHandler {
    fn handle_syscall(
        &mut self,
        args: SyscallArgs,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<Option<u32>, EngineError> {
        match args.nr {
            nr::EXIT => {
                // Exit with code in arg0
                Ok(Some(args.arg0))
            }
            nr::WRITE => {
                // write(fd, buf, count)
                let fd = args.arg0;
                let buf_addr = GuestAddr::new(args.arg1);
                let count = args.arg2 as usize;

                if fd == 1 || fd == 2 {
                    // stdout / stderr
                    let mut data = vec![0u8; count];
                    if mem.read_bytes(buf_addr, &mut data).is_ok() {
                        self.stdout_capture.extend_from_slice(&data);
                    }
                }
                cpu.set_reg(Reg::R0, count as u32);
                Ok(None)
            }
            nr::GETPID => {
                cpu.set_reg(Reg::R0, 1000);
                Ok(None)
            }
            nr::GETTID => {
                cpu.set_reg(Reg::R0, self.tid);
                Ok(None)
            }
            nr::ARM_SET_TLS => {
                cpu.tls_ptr = args.arg0;
                cpu.set_reg(Reg::R0, 0);
                Ok(None)
            }
            nr::ARM_CACHE_FLUSH => {
                // ARM Linux cacheflush syscall: arg0 = start, arg1 = end, arg2 = flags
                // Success returns 0
                cpu.set_reg(Reg::R0, 0);
                Ok(None)
            }
            nr::OPEN => {
                let path_addr = GuestAddr::new(args.arg0);
                let flags = args.arg1;
                match crate::vfs::read_cstring_from_mem(mem, path_addr, 4096) {
                    Ok(path) => match self.vfs.open(&path, flags) {
                        Ok(fd) => cpu.set_reg(Reg::R0, fd),
                        Err(err) => cpu.set_reg(Reg::R0, err as u32),
                    },
                    Err(_) => cpu.set_reg(Reg::R0, (-14i32) as u32), // -EFAULT
                }
                Ok(None)
            }
            nr::OPENAT => {
                let path_addr = GuestAddr::new(args.arg1);
                let flags = args.arg2;
                match crate::vfs::read_cstring_from_mem(mem, path_addr, 4096) {
                    Ok(path) => match self.vfs.open(&path, flags) {
                        Ok(fd) => cpu.set_reg(Reg::R0, fd),
                        Err(err) => cpu.set_reg(Reg::R0, err as u32),
                    },
                    Err(_) => cpu.set_reg(Reg::R0, (-14i32) as u32), // -EFAULT
                }
                Ok(None)
            }
            nr::CLOSE => {
                let fd = args.arg0;
                match self.vfs.close(fd) {
                    Ok(()) => cpu.set_reg(Reg::R0, 0),
                    Err(err) => cpu.set_reg(Reg::R0, err as u32),
                }
                Ok(None)
            }
            nr::READ => {
                let fd = args.arg0;
                let buf_addr = GuestAddr::new(args.arg1);
                let count = args.arg2 as usize;
                if fd >= 3 {
                    let mut temp = vec![0u8; count];
                    match self.vfs.read(fd, &mut temp) {
                        Ok(n) => {
                            if mem.write_bytes(buf_addr, &temp[..n]).is_ok() {
                                cpu.set_reg(Reg::R0, n as u32);
                            } else {
                                cpu.set_reg(Reg::R0, (-14i32) as u32); // -EFAULT
                            }
                        }
                        Err(err) => cpu.set_reg(Reg::R0, err as u32),
                    }
                } else {
                    cpu.set_reg(Reg::R0, 0); // Stdin EOF
                }
                Ok(None)
            }
            nr::LSEEK => {
                let fd = args.arg0;
                let offset = (args.arg1 as i32) as i64;
                let whence = args.arg2 as i32;
                match self.vfs.seek(fd, offset, whence) {
                    Ok(pos) => cpu.set_reg(Reg::R0, pos as u32),
                    Err(err) => cpu.set_reg(Reg::R0, err as u32),
                }
                Ok(None)
            }
            nr::_LLSEEK => {
                let fd = args.arg0;
                let offset_high = args.arg1 as u64;
                let offset_low = args.arg2 as u64;
                let offset = ((offset_high << 32) | offset_low) as i64;
                let result_ptr = GuestAddr::new(args.arg3);
                let whence = args.arg4 as i32;
                match self.vfs.seek(fd, offset, whence) {
                    Ok(pos) => {
                        let bytes = pos.to_le_bytes();
                        if mem.write_bytes(result_ptr, &bytes).is_ok() {
                            cpu.set_reg(Reg::R0, 0);
                        } else {
                            cpu.set_reg(Reg::R0, (-14i32) as u32); // -EFAULT
                        }
                    }
                    Err(err) => cpu.set_reg(Reg::R0, err as u32),
                }
                Ok(None)
            }
            nr::FSTAT64 => {
                let fd = args.arg0;
                let statbuf_addr = GuestAddr::new(args.arg1);
                match self.vfs.fstat64(fd) {
                    Ok(st) => match st.write_to_memory(mem, statbuf_addr) {
                        Ok(()) => cpu.set_reg(Reg::R0, 0),
                        Err(_) => cpu.set_reg(Reg::R0, (-14i32) as u32), // -EFAULT
                    },
                    Err(err) => cpu.set_reg(Reg::R0, err as u32),
                }
                Ok(None)
            }
            nr::STAT64 | nr::LSTAT64 => {
                let path_addr = GuestAddr::new(args.arg0);
                let statbuf_addr = GuestAddr::new(args.arg1);
                match crate::vfs::read_cstring_from_mem(mem, path_addr, 4096) {
                    Ok(path) => match self.vfs.stat64(&path) {
                        Ok(st) => match st.write_to_memory(mem, statbuf_addr) {
                            Ok(()) => cpu.set_reg(Reg::R0, 0),
                            Err(_) => cpu.set_reg(Reg::R0, (-14i32) as u32), // -EFAULT
                        },
                        Err(err) => cpu.set_reg(Reg::R0, err as u32),
                    },
                    Err(_) => cpu.set_reg(Reg::R0, (-14i32) as u32), // -EFAULT
                }
                Ok(None)
            }
            nr::FSTATAT64 => {
                let path_addr = GuestAddr::new(args.arg1);
                let statbuf_addr = GuestAddr::new(args.arg2);
                match crate::vfs::read_cstring_from_mem(mem, path_addr, 4096) {
                    Ok(path) => match self.vfs.stat64(&path) {
                        Ok(st) => match st.write_to_memory(mem, statbuf_addr) {
                            Ok(()) => cpu.set_reg(Reg::R0, 0),
                            Err(_) => cpu.set_reg(Reg::R0, (-14i32) as u32), // -EFAULT
                        },
                        Err(err) => cpu.set_reg(Reg::R0, err as u32),
                    },
                    Err(_) => cpu.set_reg(Reg::R0, (-14i32) as u32), // -EFAULT
                }
                Ok(None)
            }
            nr::ACCESS => {
                let path_addr = GuestAddr::new(args.arg0);
                match crate::vfs::read_cstring_from_mem(mem, path_addr, 4096) {
                    Ok(path) => match self.vfs.stat64(&path) {
                        Ok(_) => cpu.set_reg(Reg::R0, 0),
                        Err(err) => cpu.set_reg(Reg::R0, err as u32),
                    },
                    Err(_) => cpu.set_reg(Reg::R0, (-14i32) as u32),
                }
                Ok(None)
            }
            nr::FACCESSAT => {
                let path_addr = GuestAddr::new(args.arg1);
                match crate::vfs::read_cstring_from_mem(mem, path_addr, 4096) {
                    Ok(path) => match self.vfs.stat64(&path) {
                        Ok(_) => cpu.set_reg(Reg::R0, 0),
                        Err(err) => cpu.set_reg(Reg::R0, err as u32),
                    },
                    Err(_) => cpu.set_reg(Reg::R0, (-14i32) as u32),
                }
                Ok(None)
            }
            nr::BRK => {
                let req_brk = args.arg0;
                if req_brk == 0 || req_brk < self.brk {
                    cpu.set_reg(Reg::R0, self.brk);
                } else {
                    self.brk = req_brk;
                    cpu.set_reg(Reg::R0, self.brk);
                }
                Ok(None)
            }
            nr::UNAME => {
                let addr = GuestAddr::new(args.arg0);
                match write_utsname(mem, addr) {
                    Ok(()) => cpu.set_reg(Reg::R0, 0),
                    Err(_) => cpu.set_reg(Reg::R0, (-14i32) as u32), // -EFAULT
                }
                Ok(None)
            }
            nr::FUTEX => {
                let uaddr = GuestAddr::new(args.arg0);
                let op = args.arg1 & !futex_op::PRIVATE_FLAG;
                let val = args.arg2;
                match op {
                    futex_op::WAIT => {
                        match self.futex.wait(mem, uaddr, val, None) {
                            Ok(()) => cpu.set_reg(Reg::R0, 0),
                            Err(FutexError::WouldBlock) => cpu.set_reg(Reg::R0, (-11i32) as u32),
                            Err(FutexError::TimedOut) => cpu.set_reg(Reg::R0, (-110i32) as u32),
                            Err(_) => cpu.set_reg(Reg::R0, (-14i32) as u32),
                        }
                    }
                    futex_op::WAKE => {
                        let woken = self.futex.wake(uaddr, val);
                        cpu.set_reg(Reg::R0, woken);
                    }
                    futex_op::REQUEUE => {
                        let uaddr2 = GuestAddr::new(args.arg4);
                        let requeue_count = args.arg3;
                        let woken = self.futex.requeue(uaddr, val, requeue_count, uaddr2);
                        cpu.set_reg(Reg::R0, woken);
                    }
                    _ => {
                        cpu.set_reg(Reg::R0, (-38i32) as u32);
                    }
                }
                Ok(None)
            }
            nr::MPROTECT => {
                let addr = GuestAddr::new(args.arg0);
                let len = args.arg1 as usize;
                let prot = args.arg2;
                let page_addr = GuestAddr::new(addr.as_u32() & !0xFFF);
                let page_offset = (addr.as_u32() & 0xFFF) as usize;
                let aligned_len = (len + page_offset + 0xFFF) & !0xFFF;
                match mem.mprotect(page_addr, aligned_len, prot) {
                    Ok(()) => cpu.set_reg(Reg::R0, 0),
                    Err(_) => cpu.set_reg(Reg::R0, (-12i32) as u32), // -ENOMEM
                }
                Ok(None)
            }
            nr::IOCTL => {
                let fd = args.arg0;
                let cmd = args.arg1;
                let arg = args.arg2;
                match self.vfs.ioctl(fd, cmd, arg, mem) {
                    Ok(val) => cpu.set_reg(Reg::R0, val),
                    Err(err) => cpu.set_reg(Reg::R0, (-err) as u32),
                }
                Ok(None)
            }
            nr::MEMFD_CREATE => {
                let name_addr = GuestAddr::new(args.arg0);
                let flags = args.arg1;
                let name = crate::vfs::read_cstring_from_mem(mem, name_addr, 256)
                    .unwrap_or_else(|_| "memfd".to_string());
                match self.vfs.create_memfd(&name, flags) {
                    Ok(fd) => cpu.set_reg(Reg::R0, fd),
                    Err(err) => cpu.set_reg(Reg::R0, (-err) as u32),
                }
                Ok(None)
            }
            nr::MMAP2 => {
                let req_addr = args.arg0;
                let len = args.arg1 as usize;
                let prot = args.arg2;
                let _flags = args.arg3;
                let fd = args.arg4;
                let _pgoff = args.arg5;

                let aligned_len = (len + 0xFFF) & !0xFFF;
                let map_addr = if req_addr != 0 {
                    GuestAddr::new(req_addr)
                } else {
                    let addr = self.mmap_current;
                    self.mmap_current = self.mmap_current.add(aligned_len as u32);
                    addr
                };

                // If fd corresponds to an ashmem region, copy its initial data into guest memory
                if let Some(ashmem) = self.vfs.ashmem_regions.get(&fd) {
                    if let Ok(lock) = ashmem.data.lock() {
                        let copy_len = aligned_len.min(lock.len());
                        if copy_len > 0 {
                            let _ = mem.write_bytes(map_addr, &lock[..copy_len]);
                        }
                    }
                }

                let _ = mem.mprotect(map_addr, aligned_len, prot);
                cpu.set_reg(Reg::R0, map_addr.as_u32());
                Ok(None)
            }
            nr::MUNMAP => {
                let _addr = GuestAddr::new(args.arg0);
                let _len = args.arg1 as usize;
                cpu.set_reg(Reg::R0, 0); // Success
                Ok(None)
            }
            nr::RT_SIGACTION => {
                let sig = args.arg0;
                let act_ptr = GuestAddr::new(args.arg1);
                let oldact_ptr = GuestAddr::new(args.arg2);
                let sigsetsize = args.arg3 as usize;

                let new_act = if act_ptr.as_u32() != 0 {
                    match crate::signals::GuestSigaction::read_from_mem(mem, act_ptr, sigsetsize) {
                        Ok(a) => Some(a),
                        Err(_) => {
                            cpu.set_reg(Reg::R0, (-14i32) as u32); // -EFAULT
                            return Ok(None);
                        }
                    }
                } else {
                    None
                };

                match self.signal_state.set_action(sig, new_act) {
                    Ok(old_act) => {
                        if oldact_ptr.as_u32() != 0 {
                            if old_act.write_to_mem(mem, oldact_ptr, sigsetsize).is_err() {
                                cpu.set_reg(Reg::R0, (-14i32) as u32);
                                return Ok(None);
                            }
                        }
                        cpu.set_reg(Reg::R0, 0);
                    }
                    Err(err) => {
                        cpu.set_reg(Reg::R0, err as u32);
                    }
                }
                Ok(None)
            }
            nr::RT_SIGPROCMASK => {
                let how = args.arg0;
                let set_ptr = GuestAddr::new(args.arg1);
                let oldset_ptr = GuestAddr::new(args.arg2);
                let sigsetsize = args.arg3 as usize;

                let set = if set_ptr.as_u32() != 0 {
                    let val = if sigsetsize >= 8 {
                        let low = match mem.read_u32(set_ptr) {
                            Ok(v) => v as u64,
                            Err(_) => {
                                cpu.set_reg(Reg::R0, (-14i32) as u32);
                                return Ok(None);
                            }
                        };
                        let high = match mem.read_u32(set_ptr.add(4)) {
                            Ok(v) => v as u64,
                            Err(_) => {
                                cpu.set_reg(Reg::R0, (-14i32) as u32);
                                return Ok(None);
                            }
                        };
                        (high << 32) | low
                    } else if sigsetsize >= 4 {
                        match mem.read_u32(set_ptr) {
                            Ok(v) => v as u64,
                            Err(_) => {
                                cpu.set_reg(Reg::R0, (-14i32) as u32);
                                return Ok(None);
                            }
                        }
                    } else {
                        0
                    };
                    Some(val)
                } else {
                    None
                };

                match self.signal_state.sigprocmask(how, set) {
                    Ok(old_mask) => {
                        if oldset_ptr.as_u32() != 0 {
                            if sigsetsize >= 8 {
                                if mem.write_u32(oldset_ptr, old_mask as u32).is_err()
                                    || mem.write_u32(oldset_ptr.add(4), (old_mask >> 32) as u32).is_err()
                                {
                                    cpu.set_reg(Reg::R0, (-14i32) as u32);
                                    return Ok(None);
                                }
                            } else if sigsetsize >= 4 {
                                if mem.write_u32(oldset_ptr, old_mask as u32).is_err() {
                                    cpu.set_reg(Reg::R0, (-14i32) as u32);
                                    return Ok(None);
                                }
                            }
                        }
                        cpu.set_reg(Reg::R0, 0);
                    }
                    Err(err) => {
                        cpu.set_reg(Reg::R0, err as u32);
                    }
                }
                Ok(None)
            }
            nr::SIGALTSTACK => {
                let ss_ptr = GuestAddr::new(args.arg0);
                let oss_ptr = GuestAddr::new(args.arg1);

                let new_ss = if ss_ptr.as_u32() != 0 {
                    match crate::signals::GuestStackT::read_from_mem(mem, ss_ptr) {
                        Ok(ss) => Some(ss),
                        Err(_) => {
                            cpu.set_reg(Reg::R0, (-14i32) as u32);
                            return Ok(None);
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
                                return Ok(None);
                            }
                        }
                        cpu.set_reg(Reg::R0, 0);
                    }
                    Err(err) => {
                        cpu.set_reg(Reg::R0, err as u32);
                    }
                }
                Ok(None)
            }
            nr::RT_SIGRETURN | nr::SIGRETURN => {
                match self.signal_state.restore_sigreturn(cpu, mem) {
                    Ok(()) => {}
                    Err(_) => {
                        cpu.set_reg(Reg::R0, (-14i32) as u32);
                    }
                }
                Ok(None)
            }
            nr::KILL | nr::TKILL | nr::TGKILL => {
                let sig = if args.nr == nr::TGKILL { args.arg2 } else { args.arg1 };
                match self.signal_state.deliver_signal(sig, None, cpu, mem, None) {
                    Ok(_) => cpu.set_reg(Reg::R0, 0),
                    Err(_) => cpu.set_reg(Reg::R0, (-14i32) as u32),
                }
                Ok(None)
            }
            _ => {
                // Return -ENOSYS (-38) for unhandled syscalls
                cpu.set_reg(Reg::R0, (-38i32) as u32);
                Ok(None)
            }
        }
    }

    fn vfs(&self) -> Option<&crate::vfs::VirtualFileSystem> {
        Some(&self.vfs)
    }

    fn vfs_mut(&mut self) -> Option<&mut crate::vfs::VirtualFileSystem> {
        Some(&mut self.vfs)
    }

    fn set_mmap_base(&mut self, base: GuestAddr) {
        self.mmap_current = base;
    }

    fn signal_state(&self) -> Option<&crate::signals::SignalState> {
        Some(&self.signal_state)
    }

    fn signal_state_mut(&mut self) -> Option<&mut crate::signals::SignalState> {
        Some(&mut self.signal_state)
    }
}

pub struct DbtEngine<M: Memory> {
    pub cpu: CpuState,
    pub mem: M,
    pub cache: JitCache,
    pub pool: JitPool,
    pub syscall_handler: Box<dyn SyscallHandler>,
    pub total_insts_executed: u64,
    pub telemetry: crate::telemetry::TelemetryManager,
    pub async_jit: Option<crate::async_jit::AsyncJit>,
    pub smc_guard_pages: bool,
}

impl<M: Memory> DbtEngine<M> {
    pub fn new(mem: M) -> Self {
        Self {
            cpu: CpuState::new(),
            mem,
            cache: JitCache::new(),
            pool: JitPool::new(),
            syscall_handler: Box::new(DefaultSyscallHandler::default()),
            total_insts_executed: 0,
            telemetry: crate::telemetry::TelemetryManager::new(),
            async_jit: None,
            smc_guard_pages: false,
        }
    }

    /// Delivers a guest signal or exception (SIGSEGV, SIGBUS, SIGILL, etc.)
    /// to a registered guest signal handler if available.
    /// Returns Ok(true) if the signal was delivered to a guest handler,
    /// or Ok(false) if unhandled (default crash / terminate).
    pub fn handle_guest_fault(
        &mut self,
        sig: u32,
        fault_addr: Option<u32>,
    ) -> Result<bool, EngineError> {
        if let Some(signal_state) = self.syscall_handler.signal_state_mut() {
            let handled = signal_state
                .deliver_signal(sig, fault_addr, &mut self.cpu, &mut self.mem, None)
                .map_err(EngineError::Memory)?;
            Ok(handled)
        } else {
            Ok(false)
        }
    }

    /// Enables or disables hardware/memory SMC guard page write-protection
    pub fn enable_smc_guard_pages(&mut self, enable: bool) {
        self.smc_guard_pages = enable;
    }

    /// Protects the code pages containing the basic block from write access
    pub fn protect_code_pages_for(&mut self, addr: GuestAddr, size: usize) {
        if self.smc_guard_pages {
            let start_page = addr.as_u32() >> 12;
            let end_addr = addr.as_u32().saturating_add(size.max(1) as u32 - 1);
            let end_page = end_addr >> 12;
            for pfn in start_page..=end_page {
                let page_addr = GuestAddr::new(pfn << 12);
                let _ = self.mem.mprotect(page_addr, 4096, transd_core::PROT_READ | transd_core::PROT_EXEC);
            }
        }
    }

    /// Handles an SMC write trap when a store attempts to write to a write-protected code page.
    /// Invalidates all JIT blocks residing on that page, restores write permissions, and flushes icache.
    /// Returns true if the fault was an SMC trap successfully handled; false otherwise.
    pub fn handle_write_fault(&mut self, fault_addr: GuestAddr) -> bool {
        let pfn = fault_addr.as_u32() >> 12;
        if self.cache.is_code_page(pfn) {
            let invalidated = self.cache.invalidate_page(pfn);
            let page_start = GuestAddr::new(pfn << 12);
            let _ = self.mem.mprotect(
                page_start,
                4096,
                transd_core::PROT_READ | transd_core::PROT_WRITE | transd_core::PROT_EXEC,
            );
            self.telemetry.record_smc_trap();
            return invalidated > 0;
        }
        false
    }

    /// Initializes a new DBT engine with asynchronous background JIT compilation enabled
    pub fn with_async_jit(mem: M, config: crate::async_jit::AsyncJitConfig) -> Self {
        let mut engine = Self::new(mem);
        engine.enable_async_jit(config);
        engine
    }

    /// Enables multi-core background asynchronous JIT compilation
    pub fn enable_async_jit(&mut self, config: crate::async_jit::AsyncJitConfig) {
        self.async_jit = Some(crate::async_jit::AsyncJit::new(config));
    }

    /// Disables background asynchronous JIT compilation and cleanly joins worker threads
    pub fn disable_async_jit(&mut self) {
        if let Some(mut jit) = self.async_jit.take() {
            jit.shutdown();
        }
    }

    /// Polls and promotes any completed background JIT superblocks into executable pool and cache.
    /// Returns the number of superblocks promoted.
    pub fn poll_background_jit(&mut self) -> usize {
        if let Some(jit) = &mut self.async_jit {
            let results = jit.drain_results();
            let mut count = 0;
            for res in results {
                if self.cache.lookup(res.entry).is_some() && !self.cache.has_superblock(res.entry) {
                    if let Ok(committed) = self.pool.commit_block(&res.compiled.code_bytes) {
                        self.cache.insert_superblock(res.entry, res.compiled, committed.code_ptr);
                        self.telemetry.record_tier2_compilation();
                        count += 1;
                    }
                }
            }
            count
        } else {
            0
        }
    }

    /// Waits for all currently queued background JIT compilations to complete and promotes them.
    pub fn flush_async_jit(&mut self, timeout: std::time::Duration) -> usize {
        if let Some(jit) = &self.async_jit {
            let _ = jit.wait_for_idle(timeout);
        }
        self.poll_background_jit()
    }

    /// Returns telemetry and statistics for the background JIT compilation pool if enabled.
    pub fn async_jit_stats(&self) -> Option<crate::async_jit::AsyncJitStats> {
        self.async_jit.as_ref().map(|j| j.stats())
    }

    /// Access the Virtual File System (VFS) of the engine
    pub fn vfs(&self) -> Option<&crate::vfs::VirtualFileSystem> {
        self.syscall_handler.vfs()
    }

    /// Access the Virtual File System (VFS) of the engine mutably
    pub fn vfs_mut(&mut self) -> Option<&mut crate::vfs::VirtualFileSystem> {
        self.syscall_handler.vfs_mut()
    }

    /// Sets the dynamic virtual base address for anonymous mmap allocations
    pub fn set_mmap_base(&mut self, base: GuestAddr) {
        self.syscall_handler.set_mmap_base(base);
    }

    /// Captures a structured Android Tombstone crash dump from current CPU and memory state
    pub fn capture_tombstone(
        &self,
        signal: crate::tombstone::TombstoneSignal,
        libraries: &[crate::tombstone::LibraryInfo],
        thread_name: &str,
        pid: u32,
        tid: u32,
        abort_msg: Option<&str>,
    ) -> crate::tombstone::TombstoneReport {
        crate::tombstone::TombstoneReport::capture(
            &self.cpu,
            &self.mem,
            signal,
            libraries,
            thread_name,
            pid,
            tid,
            abort_msg,
        )
    }

    /// Renders an on-screen ASCII performance telemetry HUD overlay
    pub fn render_telemetry_hud(&self) -> String {
        self.telemetry.render_hud_overlay()
    }

    /// Imports pre-compiled AOT blocks and superblocks from disk cache into executable JIT pool
    pub fn import_aot_cache(&mut self, aot: &crate::aot_cache::AotDiskCache) -> Result<usize, crate::aot_cache::AotCacheError> {
        aot.apply_to_engine(self)
    }

    /// Exports all compiled blocks and superblocks into an AotDiskCache
    pub fn export_aot_cache(&self, binary_hash: [u8; 32], build_id: [u8; 20]) -> crate::aot_cache::AotDiskCache {
        crate::aot_cache::AotDiskCache::extract_from_engine(self, binary_hash, build_id)
    }

    /// Loads an AOT cache file from disk, verifying expected hash if provided
    pub fn load_aot_cache_file(
        &mut self,
        path: impl AsRef<std::path::Path>,
        expected_hash: Option<&[u8; 32]>,
    ) -> Result<usize, crate::aot_cache::AotCacheError> {
        let aot = crate::aot_cache::AotDiskCache::load_from_file(path)?;
        if let Some(expected) = expected_hash {
            if &aot.header.binary_hash != expected {
                let exp_str = expected.iter().map(|b| format!("{b:02x}")).collect();
                let act_str = aot.header.binary_hash.iter().map(|b| format!("{b:02x}")).collect();
                return Err(crate::aot_cache::AotCacheError::HashMismatch {
                    expected: exp_str,
                    actual: act_str,
                });
            }
        }
        self.import_aot_cache(&aot)
    }

    /// Saves the current engine compiled blocks to an AOT cache file on disk
    pub fn save_aot_cache_file(
        &self,
        path: impl AsRef<std::path::Path>,
        binary_hash: [u8; 32],
        build_id: [u8; 20],
    ) -> Result<(), crate::aot_cache::AotCacheError> {
        let aot = self.export_aot_cache(binary_hash, build_id);
        aot.save_to_file(path)
    }

    /// Performs Ahead-Of-Time (AOT) pre-compilation from known entry points
    pub fn precompile_aot(&mut self, entry_points: &[GuestAddr], max_blocks: usize) -> usize {
        crate::aot_cache::AotScanner::compile_reachable(self, entry_points, max_blocks)
    }

    /// Single step execution through DBT pipeline.
    /// On AArch64 devices, dispatches natively to compiled machine code.
    /// On dev-host x86_64, uses the verified interpreter execution engine.
    pub fn step(&mut self) -> Result<EngineStepResult, EngineError> {
        let pc = self.cpu.pc();
        let is_thumb = self.cpu.is_thumb();

        // 0. Poll background JIT results and promote completed superblocks
        self.poll_background_jit();

        // 1. JIT Compilation Check (lift, compile, and commit basic block)
        if self.cache.lookup(pc).is_none() {
            self.telemetry.record_cache_miss();
            let start_t = std::time::Instant::now();
            if let Ok(block) = Lifter::lift_block(&self.mem, pc, is_thumb) {
                let compiled = A64Compiler::compile(&block);
                let compile_us = start_t.elapsed().as_micros() as u64;
                self.telemetry.record_compilation(compile_us.max(1));
                let guest_size = compiled.guest_byte_size;
                if let Ok(committed) = self.pool.commit_block(&compiled.code_bytes) {
                    self.cache.insert_committed(pc, compiled, committed.code_ptr);
                } else {
                    self.cache.insert(pc, compiled);
                }
                self.protect_code_pages_for(pc, guest_size);
            }
        } else {
            self.telemetry.record_cache_hit();
            // 1b. Tier-2 JIT Superblock Promotion for hot loops and traces
            if self.cache.record_exec(pc) && !self.cache.has_superblock(pc) {
                if let Some(jit) = &self.async_jit {
                    // Offload trace building and optimization to background thread pool
                    if let Some(code) = crate::async_jit::CodeSnapshot::capture(&self.mem, pc, jit.config().code_window_size) {
                        jit.enqueue(pc, is_thumb, code);
                    }
                } else {
                    // Synchronous Tier-2 fallback when async JIT is not enabled
                    if let Ok(mut sb) = TraceBuilder::build_trace(&self.mem, pc, is_thumb) {
                        if sb.block_count > 1 || sb.is_loop {
                            SuperblockOptimizer::optimize(&mut sb);
                            let compiled = A64Compiler::compile_superblock(&sb);
                            self.telemetry.record_tier2_compilation();
                            if let Ok(committed) = self.pool.commit_block(&compiled.code_bytes) {
                                self.cache.insert_superblock(pc, compiled, committed.code_ptr);
                            }
                        }
                    }
                }
            }
        }

        // 2. Direct AArch64 execution dispatch if running on ARM64 silicon
        #[cfg(target_arch = "aarch64")]
        {
            if let Some(host_ptr) = self.cache.lookup_ptr(pc) {
                let _ = self.pool.flush_current();
                type JitFn = unsafe extern "C" fn(cpu: *mut CpuState, mem_base: *mut u8) -> u64;
                let jit_fn: JitFn = unsafe { std::mem::transmute(host_ptr.0) };
                let mem_base = self.mem.as_mut_ptr();
                let res = unsafe { jit_fn(&mut self.cpu as *mut _, mem_base) };

                let exit_reason = (res >> 32) as u64;
                let exit_payload = res as u32;

                match exit_reason {
                    transd_emitter_a64::EXIT_REASON_DIRECT | transd_emitter_a64::EXIT_REASON_INDIRECT => {
                        self.cpu.set_pc(GuestAddr::new(exit_payload));
                        let inst_count = self.cache.lookup(pc).map(|b| b.inst_count as u64).unwrap_or(1);
                        self.total_insts_executed += inst_count;
                        return Ok(EngineStepResult::Continue);
                    }
                    transd_emitter_a64::EXIT_REASON_SVC => {
                        let inst_count = self.cache.lookup(pc).map(|b| b.inst_count as u64).unwrap_or(1);
                        self.total_insts_executed += inst_count;
                        let args = SyscallArgs::from_cpu(&self.cpu);
                        if args.nr == nr::ARM_CACHE_FLUSH {
                            let start = GuestAddr::new(args.arg0);
                            let len = (args.arg1.saturating_sub(args.arg0)) as usize;
                            self.cache.invalidate_range(start, len);
                        }
                        if let Some(exit_code) = self
                            .syscall_handler
                            .handle_syscall(args, &mut self.cpu, &mut self.mem)?
                        {
                            return Ok(EngineStepResult::Halted { exit_code });
                        } else {
                            return Ok(EngineStepResult::Syscall(args));
                        }
                    }
                    transd_emitter_a64::EXIT_REASON_BKPT => {
                        let inst_count = self.cache.lookup(pc).map(|b| b.inst_count as u64).unwrap_or(1);
                        self.total_insts_executed += inst_count;
                        return Ok(EngineStepResult::Breakpoint { imm: exit_payload as u16 });
                    }
                    _ => {}
                }
            }
        }

        // 3. Fallback: Step execution using the verified interpreter engine
        let step_res = match Interpreter::step(&mut self.cpu, &mut self.mem) {
            Err(InterpError::Memory(MemoryError::PermissionDenied { addr, write: true })) => {
                if self.handle_write_fault(addr) {
                    Interpreter::step(&mut self.cpu, &mut self.mem)?
                } else {
                    return Err(EngineError::Memory(MemoryError::PermissionDenied { addr, write: true }));
                }
            }
            res => res?,
        };
        self.total_insts_executed += 1;
        self.telemetry.record_instructions(1);

        match step_res {
            StepResult::Continue | StepResult::Branch { .. } => Ok(EngineStepResult::Continue),
            StepResult::Bkpt { imm } => Ok(EngineStepResult::Breakpoint { imm }),
            StepResult::Svc { .. } => {
                let args = SyscallArgs::from_cpu(&self.cpu);
                if args.nr == nr::ARM_CACHE_FLUSH {
                    let start = GuestAddr::new(args.arg0);
                    let len = (args.arg1.saturating_sub(args.arg0)) as usize;
                    self.cache.invalidate_range(start, len);
                }
                if let Some(exit_code) = self
                    .syscall_handler
                    .handle_syscall(args, &mut self.cpu, &mut self.mem)?
                {
                    Ok(EngineStepResult::Halted { exit_code })
                } else {
                    Ok(EngineStepResult::Syscall(args))
                }
            }
        }
    }

    /// Invalidates all JIT compiled blocks overlapping the given guest virtual address range
    pub fn invalidate_range(&mut self, start: GuestAddr, len: usize) -> usize {
        self.cache.invalidate_range(start, len)
    }

    /// Flushes and resets the entire JIT code cache
    pub fn invalidate_all(&mut self) {
        if let Some(jit) = &self.async_jit {
            jit.clear();
        }
        self.cache.clear();
    }

    /// Writes u32 to guest memory with automatic Self-Modifying Code (SMC) cache invalidation
    pub fn write_guest_u32(&mut self, addr: GuestAddr, val: u32) -> Result<(), transd_core::MemoryError> {
        match self.mem.write_u32(addr, val) {
            Ok(()) => {
                self.cache.invalidate_range(addr, 4);
                Ok(())
            }
            Err(MemoryError::PermissionDenied { addr: fault_addr, write: true }) => {
                if self.handle_write_fault(fault_addr) {
                    self.mem.write_u32(addr, val)?;
                    self.cache.invalidate_range(addr, 4);
                    Ok(())
                } else {
                    Err(MemoryError::PermissionDenied { addr: fault_addr, write: true })
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Writes a slice of bytes to guest memory with automatic Self-Modifying Code (SMC) cache invalidation
    pub fn write_guest_bytes(&mut self, addr: GuestAddr, buf: &[u8]) -> Result<(), transd_core::MemoryError> {
        match self.mem.write_bytes(addr, buf) {
            Ok(()) => {
                self.cache.invalidate_range(addr, buf.len());
                Ok(())
            }
            Err(MemoryError::PermissionDenied { addr: fault_addr, write: true }) => {
                if self.handle_write_fault(fault_addr) {
                    self.mem.write_bytes(addr, buf)?;
                    self.cache.invalidate_range(addr, buf.len());
                    Ok(())
                } else {
                    Err(MemoryError::PermissionDenied { addr: fault_addr, write: true })
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Links and chains direct branches between two compiled blocks in executable memory
    pub fn chain_blocks(&mut self, src_addr: GuestAddr, dst_addr: GuestAddr) -> bool {
        if let (Some(src_ptr), Some(dst_ptr)) = (self.cache.lookup_ptr(src_addr), self.cache.lookup_ptr(dst_addr)) {
            if let Some(src_block) = self.cache.lookup(src_addr) {
                for site in &src_block.patch_sites {
                    let target = match site.target {
                        PatchTarget::Direct(t) => t,
                        PatchTarget::BranchTaken { target, .. } => target,
                        PatchTarget::BranchFallthrough(t) => t,
                    };
                    if target == dst_addr {
                        let src_code = src_ptr.0 as usize + site.byte_offset;
                        let dst_code = dst_ptr.0 as usize + transd_emitter_a64::PROLOGUE_BYTE_SIZE;
                        let offset_bytes = (dst_code as isize) - (src_code as isize);
                        if offset_bytes % 4 == 0 {
                            let offset_words = (offset_bytes / 4) as i32;
                            if (-0x0200_0000..=0x01FF_FFFF).contains(&offset_words) {
                                unsafe {
                                    let slice = std::slice::from_raw_parts_mut(src_code as *mut u8, 4);
                                    match site.target {
                                        PatchTarget::Direct(_) | PatchTarget::BranchFallthrough(_) => {
                                            A64Compiler::patch_direct_branch(slice, 0, offset_words);
                                        }
                                        PatchTarget::BranchTaken { cond, .. } => {
                                            A64Compiler::patch_cond_branch(slice, 0, cond, offset_words);
                                        }
                                    }
                                    crate::jit_memory::flush_icache(slice.as_mut_ptr(), 4);
                                }
                                self.telemetry.record_chained_jump();
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Runs until the guest application exits or max_steps is reached
    pub fn run(&mut self, max_steps: u64) -> Result<u32, EngineError> {
        let mut steps = 0;
        while steps < max_steps {
            match self.step()? {
                EngineStepResult::Continue | EngineStepResult::Syscall(_) => {
                    steps += 1;
                }
                EngineStepResult::Halted { exit_code } => {
                    self.poll_background_jit();
                    return Ok(exit_code);
                }
                EngineStepResult::Breakpoint { imm } => {
                    return Err(EngineError::Trap(format!("Breakpoint #{imm} hit")));
                }
            }
        }

        self.poll_background_jit();
        Err(EngineError::Trap("Max execution steps reached".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transd_core::FlatMemory;

    #[test]
    fn test_dbt_engine_run_program() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);

        // A small ARM32 program:
        // 0x1000: MOV r0, #42     (0xE3A0002A) -> Exit code 42
        // 0x1004: MOV r7, #1      (0xE3A07001) -> Syscall __NR_exit (1)
        // 0x1008: SVC 0           (0xEF000000)
        mem.write_u32(GuestAddr::new(0x1000), 0xE3A0_002A).unwrap();
        mem.write_u32(GuestAddr::new(0x1004), 0xE3A0_7001).unwrap();
        mem.write_u32(GuestAddr::new(0x1008), 0xEF00_0000).unwrap();

        let mut engine = DbtEngine::new(mem);
        engine.cpu.set_pc(GuestAddr::new(0x1000));

        let exit_code = engine.run(100).unwrap();
        assert_eq!(exit_code, 42);
        assert_eq!(engine.total_insts_executed, 3);
        // Verify that JIT cache was populated
        assert!(engine.cache.count() > 0);
    }

    #[test]
    fn test_dbt_engine_write_syscall() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);

        // String "Hello" at 0x1500
        mem.write_bytes(GuestAddr::new(0x1500), b"Hello").unwrap();

        // 0x1000: MOV r0, #1       (0xE3A00001) -> fd = 1 (stdout)
        // 0x1004: MOV r1, #0x1500  (0xE3A01C15) -> buf = 0x1500 (imm 0x15 rot 24 = 0x1500)
        // 0x1008: MOV r2, #5       (0xE3A02005) -> count = 5
        // 0x100C: MOV r7, #4       (0xE3A07004) -> sys_write (4)
        // 0x1010: SVC 0            (0xEF000000)
        // 0x1014: MOV r0, #0       (0xE3A00000) -> exit(0)
        // 0x1018: MOV r7, #1       (0xE3A07001) -> sys_exit
        // 0x101C: SVC 0            (0xEF000000)
        mem.write_u32(GuestAddr::new(0x1000), 0xE3A0_0001).unwrap();
        mem.write_u32(GuestAddr::new(0x1004), 0xE3A0_1C15).unwrap();
        mem.write_u32(GuestAddr::new(0x1008), 0xE3A0_2005).unwrap();
        mem.write_u32(GuestAddr::new(0x100C), 0xE3A0_7004).unwrap();
        mem.write_u32(GuestAddr::new(0x1010), 0xEF00_0000).unwrap();
        mem.write_u32(GuestAddr::new(0x1014), 0xE3A0_0000).unwrap();
        mem.write_u32(GuestAddr::new(0x1018), 0xE3A0_7001).unwrap();
        mem.write_u32(GuestAddr::new(0x101C), 0xEF00_0000).unwrap();

        let mut engine = DbtEngine::new(mem);
        engine.cpu.set_pc(GuestAddr::new(0x1000));

        let exit_code = engine.run(100).unwrap();
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_dbt_engine_jit_pool_and_chaining() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);

        // Block 1 at 0x1000:
        // 0x1000: MOV r0, #10     (0xE3A0000A)
        // 0x1004: B +8 (to 0x1014) (0xEA000002) -> offset = +2 words (target 0x1004 + 8 + 8 = 0x1014)
        mem.write_u32(GuestAddr::new(0x1000), 0xE3A0_000A).unwrap();
        mem.write_u32(GuestAddr::new(0x1004), 0xEA00_0002).unwrap();

        // Block 2 at 0x1014:
        // 0x1014: MOV r0, #42     (0xE3A0002A)
        // 0x1018: MOV r7, #1      (0xE3A07001) -> sys_exit
        // 0x101C: SVC 0           (0xEF000000)
        mem.write_u32(GuestAddr::new(0x1014), 0xE3A0_002A).unwrap();
        mem.write_u32(GuestAddr::new(0x1018), 0xE3A0_7001).unwrap();
        mem.write_u32(GuestAddr::new(0x101C), 0xEF00_0000).unwrap();

        let mut engine = DbtEngine::new(mem);
        engine.cpu.set_pc(GuestAddr::new(0x1000));

        let exit_code = engine.run(100).unwrap();
        assert_eq!(exit_code, 42);

        // Verify that code was committed to JIT pool
        assert!(engine.pool.total_bytes > 0);
        assert!(engine.cache.lookup_ptr(GuestAddr::new(0x1000)).is_some());
        assert!(engine.cache.lookup_ptr(GuestAddr::new(0x1014)).is_some());

        // Test dynamic block chaining between committed blocks
        let chained = engine.chain_blocks(GuestAddr::new(0x1000), GuestAddr::new(0x1014));
        assert!(chained);
    }
}
