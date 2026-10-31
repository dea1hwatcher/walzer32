use transd_core::{Cond, GuestAddr, Reg};
use transd_decoder::ArmInst;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockExit {
    /// Unconditional direct jump to known address
    Direct(GuestAddr),
    /// Conditional branch with taken and fallthrough paths
    BranchCond {
        cond: Cond,
        target: GuestAddr,
        fallthrough: GuestAddr,
    },
    /// Indirect branch (register-based, e.g. BX LR, LDR PC, POP {PC})
    Indirect(Reg),
    /// Supervisor Call (System Call)
    Svc { imm: u32, next_pc: GuestAddr },
    /// Breakpoint instruction
    Bkpt { imm: u16, next_pc: GuestAddr },
    /// Unknown instruction encountered
    Invalid(GuestAddr),
}

/// An intermediate representation of a basic block lifted from ARM/Thumb code
#[derive(Debug, Clone)]
pub struct IrBlock {
    /// Entry address of this basic block
    pub entry: GuestAddr,
    /// Execution mode (ARM vs Thumb)
    pub is_thumb: bool,
    /// Instructions contained within this basic block
    pub insts: Vec<ArmInst>,
    /// How execution leaves this basic block
    pub exit: BlockExit,
    /// Number of guest code bytes consumed by this block
    pub byte_size: usize,
}

impl IrBlock {
    pub fn new(entry: GuestAddr, is_thumb: bool) -> Self {
        Self {
            entry,
            is_thumb,
            insts: Vec::new(),
            exit: BlockExit::Invalid(entry),
            byte_size: 0,
        }
    }
}
