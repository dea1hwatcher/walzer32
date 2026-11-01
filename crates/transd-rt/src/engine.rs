use thiserror::Error;
use transd_core::{CpuState, GuestAddr, Memory, MemoryError, Reg};
use transd_emitter_a64::{A64Compiler, PatchTarget};
use transd_interp::{InterpError, Interpreter, StepResult};
use transd_ir::Lifter;
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

    fn vfs_mut(&mut self) -> Option<&mut crate::vfs::VirtualFileSystem> {
        None
    }
}

pub struct DefaultSyscallHandler {
    pub stdout_capture: Vec<u8>,
    pub futex: FutexManager,
    pub tid: u32,
    pub vfs: crate::vfs::VirtualFileSystem,
    pub brk: u32,
}

impl Default for DefaultSyscallHandler {
    fn default() -> Self {
        Self {
            stdout_capture: Vec::new(),
            futex: FutexManager::new(),
            tid: 1000,
            vfs: crate::vfs::VirtualFileSystem::new(),
            brk: 0x4000_0000,
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
        }
    }

    pub fn with_vfs(vfs: crate::vfs::VirtualFileSystem) -> Self {
        Self {
            stdout_capture: Vec::new(),
            futex: FutexManager::new(),
            tid: 1000,
            vfs,
            brk: 0x4000_0000,
        }
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
            _ => {
                // Return -ENOSYS (-38) for unhandled syscalls
                cpu.set_reg(Reg::R0, (-38i32) as u32);
                Ok(None)
            }
        }
    }

    fn vfs_mut(&mut self) -> Option<&mut crate::vfs::VirtualFileSystem> {
        Some(&mut self.vfs)
    }
}

pub struct DbtEngine<M: Memory> {
    pub cpu: CpuState,
    pub mem: M,
    pub cache: JitCache,
    pub pool: JitPool,
    pub syscall_handler: Box<dyn SyscallHandler>,
    pub total_insts_executed: u64,
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
        }
    }

    /// Access the Virtual File System (VFS) of the engine
    pub fn vfs_mut(&mut self) -> Option<&mut crate::vfs::VirtualFileSystem> {
        self.syscall_handler.vfs_mut()
    }

    /// Single step execution through DBT pipeline.
    /// On AArch64 devices, dispatches natively to compiled machine code.
    /// On dev-host x86_64, uses the verified interpreter execution engine.
    pub fn step(&mut self) -> Result<EngineStepResult, EngineError> {
        let pc = self.cpu.pc();
        let is_thumb = self.cpu.is_thumb();

        // 1. JIT Compilation Check (lift, compile, and commit basic block)
        if self.cache.lookup(pc).is_none() {
            if let Ok(block) = Lifter::lift_block(&self.mem, pc, is_thumb) {
                let compiled = A64Compiler::compile(&block);
                if let Ok(committed) = self.pool.commit_block(&compiled.code_bytes) {
                    self.cache.insert_committed(pc, compiled, committed.code_ptr);
                } else {
                    self.cache.insert(pc, compiled);
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
        let step_res = Interpreter::step(&mut self.cpu, &mut self.mem)?;
        self.total_insts_executed += 1;

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
        self.cache.clear();
    }

    /// Writes u32 to guest memory with automatic Self-Modifying Code (SMC) cache invalidation
    pub fn write_guest_u32(&mut self, addr: GuestAddr, val: u32) -> Result<(), transd_core::MemoryError> {
        self.mem.write_u32(addr, val)?;
        self.cache.invalidate_range(addr, 4);
        Ok(())
    }

    /// Writes a slice of bytes to guest memory with automatic Self-Modifying Code (SMC) cache invalidation
    pub fn write_guest_bytes(&mut self, addr: GuestAddr, buf: &[u8]) -> Result<(), transd_core::MemoryError> {
        self.mem.write_bytes(addr, buf)?;
        self.cache.invalidate_range(addr, buf.len());
        Ok(())
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
                    return Ok(exit_code);
                }
                EngineStepResult::Breakpoint { imm } => {
                    return Err(EngineError::Trap(format!("Breakpoint #{imm} hit")));
                }
            }
        }

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
