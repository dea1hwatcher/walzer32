use walzer32_core::{Cond, GuestAddr, Reg};
use walzer32_decoder::ArmInst;

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
    /// Conditional indirect branch (e.g. BX<cond> LR, LDR<cond> PC, [SP])
    IndirectCond {
        cond: Cond,
        rm: Reg,
        fallthrough: GuestAddr,
    },
    /// Supervisor Call (System Call)
    Svc { imm: u32, next_pc: GuestAddr },
    /// Breakpoint instruction
    Bkpt { imm: u16, next_pc: GuestAddr },
    /// Compare and branch (CBZ / CBNZ)
    CompareBranch {
        is_nonzero: bool,
        rn: Reg,
        target: GuestAddr,
        fallthrough: GuestAddr,
    },
    /// Table branch (TBB / TBH)
    TableBranch {
        is_halfword: bool,
        rn: Reg,
        rm: Reg,
        inst_pc: GuestAddr,
    },
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
    /// Exact guest address of each instruction in this basic block
    pub inst_addrs: Vec<GuestAddr>,
    /// How execution leaves this basic block
    pub exit: BlockExit,
    /// Number of guest code bytes consumed by this block
    pub byte_size: usize,
    /// Whether this basic block terminates with a subroutine call (BL, BLX)
    pub is_call: bool,
}

impl IrBlock {
    pub fn new(entry: GuestAddr, is_thumb: bool) -> Self {
        Self {
            entry,
            is_thumb,
            insts: Vec::new(),
            inst_addrs: Vec::new(),
            exit: BlockExit::Invalid(entry),
            byte_size: 0,
            is_call: false,
        }
    }

    /// Resolves the guest address for the instruction at `idx`
    pub fn inst_pc(&self, idx: usize) -> GuestAddr {
        if let Some(&addr) = self.inst_addrs.get(idx) {
            addr
        } else if self.is_thumb {
            self.entry.add((idx * 2) as u32)
        } else {
            self.entry.add((idx * 4) as u32)
        }
    }

    /// Computes the architectural PC read value for instruction `idx` (+8 for ARM, +4 for Thumb)
    pub fn pc_read_val(&self, idx: usize) -> u32 {
        let addr = self.inst_pc(idx).as_u32();
        if self.is_thumb {
            addr + 4
        } else {
            addr + 8
        }
    }

    /// Computes PC value for PC-relative memory operations (+8 for ARM, (addr + 4) & !3 for Thumb)
    pub fn pc_mem_read_val(&self, idx: usize) -> u32 {
        let addr = self.inst_pc(idx).as_u32();
        if self.is_thumb {
            (addr + 4) & !3
        } else {
            addr + 8
        }
    }
}
