use walzer32_core::{Cond, Reg};

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
pub enum BitFieldOp {
    Ubfx, // Unsigned bit field extract
    Sbfx, // Signed bit field extract
    Bfi,  // Bit field insert
    Bfc,  // Bit field clear
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteRevOp {
    Rev,   // Byte-Reverse Word
    Rev16, // Byte-Reverse Packed Halfwords
    Revsh, // Byte-Reverse Signed Halfword
    Rbit,  // Reverse Bits
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimdParallelOp {
    // Normal (sets GE[3:0] flags)
    Sadd8,
    Sadd16,
    Sasx,
    Ssax,
    Ssub8,
    Ssub16,
    Uadd8,
    Uadd16,
    Uasx,
    Usax,
    Usub8,
    Usub16,
    // Saturating
    Qadd8,
    Qadd16,
    Qasx,
    Qsax,
    Qsub8,
    Qsub16,
    Uqadd8,
    Uqadd16,
    Uqasx,
    Uqsax,
    Uqsub8,
    Uqsub16,
    // Halving (average)
    Shadd8,
    Shadd16,
    Shasx,
    Shsax,
    Shsub8,
    Shsub16,
    Uhadd8,
    Uhadd16,
    Uhasx,
    Uhsax,
    Uhsub8,
    Uhsub16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendOp {
    Sxtb,
    Sxth,
    Sxtb16,
    Uxtb,
    Uxth,
    Uxtb16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkhOp {
    Pkhbt,
    Pkhtb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DspMulOp {
    // 16x16 -> 32
    Smul { x_top: bool, y_top: bool },
    Smla { x_top: bool, y_top: bool },
    Smulw { y_top: bool },
    Smlaw { y_top: bool },
    // Dual 16x16 -> 32
    Smuad { swap: bool },
    Smusd { swap: bool },
    Smlad { swap: bool },
    Smlsd { swap: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreSatOp {
    Qadd,
    Qsub,
    Qdadd,
    Qdsub,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitSatOp {
    Ssat {
        sat_imm: u8,
        shift_type: ShiftType,
        shift_imm: u8,
    },
    Usat {
        sat_imm: u8,
        shift_type: ShiftType,
        shift_imm: u8,
    },
    Ssat16 {
        sat_imm: u8,
    },
    Usat16 {
        sat_imm: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HighMulOp {
    Smmul { round: bool },
    Smmla { round: bool },
    Smmls { round: bool },
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
    Mla,
    Mls,
    Nmul,
    Nmla,
    Nmls,
    Fnma,
    Fnms,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfpCvtOp {
    F64FromF32,
    F32FromF64,
    F32FromS32,
    F32FromU32,
    S32FromF32,
    U32FromF32,
    F64FromS32,
    F64FromU32,
    S32FromF64,
    U32FromF64,
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
    // Saturating arithmetic (Stage 43)
    Sqadd,
    Uqadd,
    Sqsub,
    Uqsub,
    Sqshl,
    Uqshl,
    // Pairwise reductions (Stage 45)
    Padd,
    Pmax,
    Pmin,
    Upmax,
    Upmin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeonPermuteOp {
    Trn,
    Zip,
    Uzp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeonRevOp {
    Rev64,
    Rev32,
    Rev16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeonCvtOp {
    F32FromS32,
    F32FromU32,
    S32FromF32,
    U32FromF32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeonWriteback {
    None,
    PostInc,
    Reg(Reg),
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
    BitField {
        op: BitFieldOp,
        rd: Reg,
        rn: Reg,
        lsb: u8,
        width: u8,
    },
    ByteRev {
        op: ByteRevOp,
        rd: Reg,
        rm: Reg,
    },
    SimdParallel {
        op: SimdParallelOp,
        rd: Reg,
        rn: Reg,
        rm: Reg,
    },
    SimdSel {
        rd: Reg,
        rn: Reg,
        rm: Reg,
    },
    SimdPkh {
        op: PkhOp,
        rd: Reg,
        rn: Reg,
        rm: Reg,
        shift: u8,
    },
    SimdExtend {
        op: ExtendOp,
        rd: Reg,
        rn: Option<Reg>,
        rm: Reg,
        rotation: u8,
    },
    Branch {
        link: bool,
        exchange: bool,
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
    VfpMovTwoCore {
        to_core: bool,
        is_double: bool,
        rt: Reg,
        rt2: Reg,
        vfp_reg: VfpReg,
    },
    DspMul {
        op: DspMulOp,
        rd: Reg,
        rn: Reg,
        rm: Reg,
        rs: Reg,
    },
    Umaal {
        rd_lo: Reg,
        rd_hi: Reg,
        rn: Reg,
        rm: Reg,
    },
    CoreSat {
        op: CoreSatOp,
        rd: Reg,
        rm: Reg,
        rn: Reg,
    },
    BitSat {
        op: BitSatOp,
        rd: Reg,
        rn: Reg,
    },
    HighMul {
        op: HighMulOp,
        rd: Reg,
        rn: Reg,
        rm: Reg,
        ra: Option<Reg>,
    },
    Movw {
        rd: Reg,
        imm: u16,
    },
    Movt {
        rd: Reg,
        imm: u16,
    },
    CompareBranch {
        is_nonzero: bool,
        rn: Reg,
        offset: u32,
    },
    TableBranch {
        is_halfword: bool,
        rn: Reg,
        rm: Reg,
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
    VfpLoadStoreMultiple {
        is_load: bool,
        is_double: bool,
        writeback: bool,
        is_add: bool,
        rn: Reg,
        start_reg: u8,
        count: u8,
    },
    VfpCvt {
        op: VfpCvtOp,
        dst: VfpReg,
        src: VfpReg,
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
        structure_elements: u8, // 1 = VLD1/VST1, 2 = VLD2/VST2, 3 = VLD3/VST3, 4 = VLD4/VST4
        reg_count: u8,          // 1, 2, 3, or 4 doubleword registers
        stride: u8,             // 1 = contiguous, 2 = spaced (e.g. d0, d2)
        size: NeonSize,
        first_reg: u8,
        rn: Reg,
        writeback: NeonWriteback,
    },
    NeonLoadStoreLane {
        is_load: bool,
        structure_elements: u8, // 1..=4
        all_lanes: bool,        // true = replicate/broadcast to all lanes
        lane: u8,               // specific lane index if !all_lanes
        size: NeonSize,
        first_reg: u8,
        stride: u8,
        rn: Reg,
        writeback: NeonWriteback,
    },
    NeonPermute {
        op: NeonPermuteOp,
        size: NeonSize,
        is_quad: bool,
        vd: u8,
        vm: u8,
    },
    NeonTbl {
        is_tbx: bool,
        vd: u8,
        vn: u8,
        len: u8, // 1..=4
        vm: u8,
    },
    NeonShiftImm {
        signed: bool,
        saturate: bool,
        size: NeonSize,
        is_quad: bool,
        shift: u8,
        vd: u8,
        vm: u8,
    },
    NeonShiftNarrow {
        signed: bool,
        dest_unsigned: bool,
        saturate: bool,
        src_size: NeonSize,
        shift: u8,
        vd: u8,
        vm: u8,
    },
    NeonPolyMul {
        vd: u8, // Q register base
        vn: u8, // D register
        vm: u8, // D register
    },
    NeonExtract {
        is_quad: bool,
        imm: u8,
        vd: u8,
        vn: u8,
        vm: u8,
    },
    NeonRev {
        op: NeonRevOp,
        size: NeonSize,
        is_quad: bool,
        vd: u8,
        vm: u8,
    },
    NeonDupScalar {
        size: NeonSize,
        index: u8,
        is_quad: bool,
        vd: u8,
        vm: u8,
    },
    NeonDupCore {
        size: NeonSize,
        is_quad: bool,
        vd: u8,
        rt: Reg,
    },
    NeonShiftWiden {
        signed: bool,
        src_size: NeonSize,
        shift: u8,
        vd: u8,
        vm: u8,
    },
    NeonCvt {
        op: NeonCvtOp,
        is_quad: bool,
        vd: u8,
        vm: u8,
    },
    VfpMovImm {
        dst: VfpReg,
        val_bits: u64,
        is_double: bool,
    },
    NeonMovImm {
        dst: u8,
        is_quad: bool,
        val64: u64,
    },
    NeonMovCoreLane {
        to_core: bool,
        core_reg: Reg,
        d_reg: u8,
        lane: u8,
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
