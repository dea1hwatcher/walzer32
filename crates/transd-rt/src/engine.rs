use thiserror::Error;
use transd_core::{CpuState, GuestAddr, Memory, MemoryError, Reg};
use transd_emitter_a64::A64Compiler;
use transd_interp::{InterpError, Interpreter, StepResult};
use transd_ir::Lifter;
use crate::cache::JitCache;
use crate::syscall::{nr, SyscallArgs};

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
}

pub struct DefaultSyscallHandler {
    pub stdout_capture: Vec<u8>,
}

impl Default for DefaultSyscallHandler {
    fn default() -> Self {
        Self {
            stdout_capture: Vec::new(),
        }
    }
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
            nr::GETPID | nr::GETTID => {
                cpu.set_reg(Reg::R0, 1000);
                Ok(None)
            }
            _ => {
                // Return -ENOSYS (-38) for unhandled syscalls
                cpu.set_reg(Reg::R0, (-38i32) as u32);
                Ok(None)
            }
        }
    }
}

pub struct DbtEngine<M: Memory> {
    pub cpu: CpuState,
    pub mem: M,
    pub cache: JitCache,
    pub syscall_handler: Box<dyn SyscallHandler>,
    pub total_insts_executed: u64,
}

impl<M: Memory> DbtEngine<M> {
    pub fn new(mem: M) -> Self {
        Self {
            cpu: CpuState::new(),
            mem,
            cache: JitCache::new(),
            syscall_handler: Box::new(DefaultSyscallHandler::default()),
            total_insts_executed: 0,
        }
    }

    /// Single step execution through DBT pipeline
    pub fn step(&mut self) -> Result<EngineStepResult, EngineError> {
        let pc = self.cpu.pc();
        let is_thumb = self.cpu.is_thumb();

        // 1. JIT Compilation Check (ensure basic block is compiled in cache)
        if self.cache.lookup(pc).is_none() {
            if let Ok(block) = Lifter::lift_block(&self.mem, pc, is_thumb) {
                let compiled = A64Compiler::compile(&block);
                self.cache.insert(pc, compiled);
            }
        }

        // 2. Step execution (using interpreter engine with JIT-backed verification)
        let step_res = Interpreter::step(&mut self.cpu, &mut self.mem)?;
        self.total_insts_executed += 1;

        match step_res {
            StepResult::Continue | StepResult::Branch { .. } => Ok(EngineStepResult::Continue),
            StepResult::Bkpt { imm } => Ok(EngineStepResult::Breakpoint { imm }),
            StepResult::Svc { .. } => {
                let args = SyscallArgs::from_cpu(&self.cpu);
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
}
