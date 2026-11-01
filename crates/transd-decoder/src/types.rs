use transd_core::{Cond, Reg};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AluOp {
    And, // 0000: Rd = Rn & Op2
    Eor, // 0001: Rd = Rn ^ Op2
    Sub, // 0010: Rd = Rn - Op2
    Rsb, // 0011: Rd = Op2 - Rn (Reverse Subtract)
    Add, // 0100: Rd = Rn + Op2
    Adc, // 0101: Rd = Rn + Op2 + C
    Sbc, // 0110: Rd = Rn - Op2 - !C
    Rsc, // 0111: Rd = Op2 - Rn - !C
    Tst, // 1000: Rn & Op2 (sets flags)
    Teq, // 1001: Rn ^ Op2 (sets flags)
    Cmp, // 1010: Rn - Op2 (sets flags)
    Cmn, // 1011: Rn + Op2 (sets flags)
    Orr, // 1100: Rd = Rn | Op2
    Mov, // 1101: Rd = Op2
    Bic, // 1110: Rd = Rn & ~Op2
    Mvn, // 1111: Rd = ~Op2
}

impl AluOp {
    #[inline(always)]
    pub fn is_test(self) -> bool {
        matches!(self, AluOp::Tst | AluOp::Teq | AluOp::Cmp | AluOp::Cmn)
    }

    #[inline(always)]
    pub fn is_unary(self) -> bool {
        matches!(self, AluOp::Mov | AluOp::Mvn)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShiftType {
    Lsl = 0b00,
    Lsr = 0b01,
    Asr = 0b10,
    Ror = 0b11,
    Rrx, // Rotate right with extend through C
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShiftAmount {
    Imm(u8),
    Reg(Reg),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shift {
    pub shift_type: ShiftType,
    pub amount: ShiftAmount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand2 {
    Imm(u32),
    Reg {
        rm: Reg,
        shift: Shift,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemSize {
    Byte = 1,
    Halfword = 2,
    Word = 4,
    Doubleword = 8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrOffset {
    Imm(u32),
    Reg {
        rm: Reg,
        shift_type: ShiftType,
        shift_imm: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrMode {
    Offset { offset: AddrOffset, add: bool },
    PreIndex { offset: AddrOffset, add: bool },
    PostIndex { offset: AddrOffset, add: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockAddrMode {
    Ia, // Increment After (STM / LDM / POP / etc.)
    Ib, // Increment Before
    Da, // Decrement After
    Db, // Decrement Before (PUSH)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchTarget {
    Imm(i32), // PC-relative signed offset (bytes)
    Reg(Reg), // Target address in register
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MulOp {
    Mul, // Rd = Rm * Rs
    Mla, // Rd = Rm * Rs + Rn
    Mls, // Rd = Rn - Rm * Rs
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsrValue {
    Reg(Reg),
    Imm(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfpSize {
    F32,
    F64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfpOp {
    Add,
    Sub,
    Mul,
    Div,
    Abs,
    Neg,
    Sqrt,
    Cmp,
    CmpZero,
    Fma,
    Fms,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfpReg {
    S(u8), // s0..s31
    D(u8), // d0..d31
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeonOp {
    Add,
    Sub,
    Mul,
    Mla,
    Mls,
    And,
    Orr,
    Eor,
    Bic,
    Abs,
    Neg,
    Min,
    Max,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeonSize {
    I8,
    I16,
    I32,
    F32,
}

/// Decoded ARM Instruction Operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Alu {
        op: AluOp,
        set_flags: bool,
        rd: Reg,
        rn: Reg,
        op2: Operand2,
    },
    Mul {
        op: MulOp,
        set_flags: bool,
        rd: Reg,
        rn: Reg,
        rm: Reg,
        rs: Reg,
    },
    MulLong {
        signed: bool,
        accumulate: bool,
        set_flags: bool,
        rd_hi: Reg,
        rd_lo: Reg,
        rm: Reg,
        rs: Reg,
    },
    Div {
        signed: bool,
        rd: Reg,
        rn: Reg,
        rm: Reg,
    },
    Branch {
        link: bool,
        target: BranchTarget,
    },
    BranchExchange {
        link: bool,
        rm: Reg,
    },
    LoadStore {
        is_load: bool,
        size: MemSize,
        signed: bool,
        rd: Reg,
        rn: Reg,
        addr_mode: AddrMode,
    },
    LoadStoreMultiple {
        is_load: bool,
        rn: Reg,
        mode: BlockAddrMode,
        writeback: bool,
        reg_list: u16,
    },
    Svc {
        imm: u32,
    },
    Bkpt {
        imm: u16,
    },
    Clz {
        rd: Reg,
        rm: Reg,
    },
    Mrs {
        rd: Reg,
        spsr: bool,
    },
    Msr {
        spsr: bool,
        mask: u8,
        val: MsrValue,
    },
    VfpAlu {
        op: VfpOp,
        size: VfpSize,
        dst: VfpReg,
        src1: VfpReg,
        src2: VfpReg,
    },
    VfpMov {
        size: VfpSize,
        dst: VfpReg,
        src: VfpReg,
    },
    VfpMovCore {
        to_core: bool,
        core_reg: Reg,
        vfp_reg: VfpReg,
    },
    VfpMrsFpscr {
        rt: Option<Reg>, // None = APSR_nzcv (CPSR), Some(r) = general purpose register
    },
    VfpMsrFpscr {
        rt: Reg,
    },
    VfpLoadStore {
        is_load: bool,
        size: VfpSize,
        vfp_reg: VfpReg,
        rn: Reg,
        offset: i32,
    },
    AtomicLoadEx {
        rd: Reg,
        rn: Reg,
    },
    AtomicStoreEx {
        rd: Reg,
        rm: Reg,
        rn: Reg,
    },
    Clrex,
    MemoryBarrier {
        is_data: bool,
    },
    Cp15Move {
        is_mrc: bool,
        rd: Reg,
        crn: u8,
        opc1: u8,
        crm: u8,
        opc2: u8,
    },
    It {
        firstcond: Cond,
        mask: u8,
    },
    NeonAlu {
        op: NeonOp,
        size: NeonSize,
        is_quad: bool,
        dst: u8,
        src1: u8,
        src2: u8,
    },
    NeonLoadStore {
        is_load: bool,
        is_quad: bool,
        reg: u8,
        rn: Reg,
    },
    Nop,
    Unknown(u32),
}

/// A complete decoded ARM instruction with condition code
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArmInst {
    pub cond: Cond,
    pub op: Op,
    pub raw: u32,
}

impl ArmInst {
    pub const fn new(cond: Cond, op: Op, raw: u32) -> Self {
        Self { cond, op, raw }
    }
}
