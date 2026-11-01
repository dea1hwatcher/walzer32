use transd_core::{
    Cond, GuestAddr, OFFSET_EXCLUSIVE, OFFSET_PC, OFFSET_TLS, OFFSET_VFP,
};
use transd_decoder::{
    AddrMode, AddrOffset, AluOp, ArmInst, BlockAddrMode, MemSize, MulOp, NeonOp, Op, Operand2,
    ShiftAmount, ShiftType, VfpOp, VfpReg, VfpSize,
};
use transd_ir::{BlockExit, IrBlock};
use crate::assembler::A64Assembler;
use crate::reg::A64Reg;

/// Exit reasons returned in upper 32-bits of x0 from a compiled JIT block
pub const EXIT_REASON_DIRECT: u64 = 0;
pub const EXIT_REASON_INDIRECT: u64 = 1;
pub const EXIT_REASON_SVC: u64 = 2;
pub const EXIT_REASON_BKPT: u64 = 3;
pub const EXIT_REASON_INVALID: u64 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchTarget {
    Direct(GuestAddr),
    BranchTaken { cond: Cond, target: GuestAddr },
    BranchFallthrough(GuestAddr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatchSite {
    /// Byte offset within code_bytes where the branch instruction is placed
    pub byte_offset: usize,
    /// Destination address and type
    pub target: PatchTarget,
}

/// Compiled JIT Block representation
#[derive(Debug, Clone)]
pub struct CompiledBlock {
    pub guest_entry: GuestAddr,
    pub is_thumb: bool,
    pub code_bytes: Vec<u8>,
    pub inst_count: usize,
    pub patch_sites: Vec<PatchSite>,
    pub exit: BlockExit,
}

pub struct A64Compiler;

impl A64Compiler {
    /// Compiles an IrBlock into AArch64 native machine code with patchable exit sites
    pub fn compile(block: &IrBlock) -> CompiledBlock {
        let mut asm = A64Assembler::new();
        let mut patch_sites = Vec::new();

        // Calling Convention:
        // x0 = pointer to CpuState
        // x1 = pointer to memory arena base (mem_base)
        // x9  = scratch 1
        // x10 = scratch 2
        // x11 = scratch 3
        // x12 = scratch 4

        for inst in &block.insts {
            Self::compile_inst(&mut asm, inst);
        }

        Self::compile_exit(&mut asm, &block.exit, &mut patch_sites);

        CompiledBlock {
            guest_entry: block.entry,
            is_thumb: block.is_thumb,
            code_bytes: asm.to_bytes(),
            inst_count: block.insts.len(),
            patch_sites,
            exit: block.exit.clone(),
        }
    }

    fn vfp_offset(reg: &VfpReg) -> u32 {
        match reg {
            VfpReg::S(idx) => (OFFSET_VFP + (*idx as usize) * 4) as u32,
            VfpReg::D(idx) => (OFFSET_VFP + (*idx as usize) * 8) as u32,
        }
    }

    fn compile_inst(asm: &mut A64Assembler, inst: &ArmInst) {
        match &inst.op {
            Op::Nop => {
                asm.nop();
            }
            Op::Alu {
                op,
                set_flags,
                rd,
                rn,
                op2,
            } => {
                // 1. Load rn into w9 (from CpuState at x0)
                let rn_offset = (rn.index() * 4) as u32;
                asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, rn_offset);

                // 2. Load op2 into w10 (applying barrel shift if register operand)
                match op2 {
                    Operand2::Imm(imm) => {
                        asm.mov_imm32(A64Reg::X10, *imm);
                    }
                    Operand2::Reg { rm, shift } => {
                        let rm_offset = (rm.index() * 4) as u32;
                        asm.ldr_w_imm(A64Reg::X10, A64Reg::X0, rm_offset);

                        match shift.amount {
                            ShiftAmount::Imm(shift_imm) => {
                                if shift_imm > 0 {
                                    match shift.shift_type {
                                        ShiftType::Lsl => asm.lsl_w_imm(A64Reg::X10, A64Reg::X10, shift_imm),
                                        ShiftType::Lsr => asm.lsr_w_imm(A64Reg::X10, A64Reg::X10, shift_imm),
                                        ShiftType::Asr => asm.asr_w_imm(A64Reg::X10, A64Reg::X10, shift_imm),
                                        ShiftType::Ror => {
                                            asm.mov_imm32(A64Reg::X12, shift_imm as u32);
                                            asm.ror_w_reg(A64Reg::X10, A64Reg::X10, A64Reg::X12);
                                        }
                                        ShiftType::Rrx => {}
                                    }
                                }
                            }
                            ShiftAmount::Reg(rs) => {
                                let rs_offset = (rs.index() * 4) as u32;
                                asm.ldr_w_imm(A64Reg::X12, A64Reg::X0, rs_offset);
                                match shift.shift_type {
                                    ShiftType::Lsl => asm.lsl_w_reg(A64Reg::X10, A64Reg::X10, A64Reg::X12),
                                    ShiftType::Lsr => asm.lsr_w_reg(A64Reg::X10, A64Reg::X10, A64Reg::X12),
                                    ShiftType::Asr => asm.asr_w_reg(A64Reg::X10, A64Reg::X10, A64Reg::X12),
                                    ShiftType::Ror => asm.ror_w_reg(A64Reg::X10, A64Reg::X10, A64Reg::X12),
                                    ShiftType::Rrx => {}
                                }
                            }
                        }
                    }
                }

                // 3. Perform ALU operation: w11 = w9 (op) w10
                match op {
                    AluOp::Add => {
                        if *set_flags {
                            asm.adds_w_reg(A64Reg::X11, A64Reg::X9, A64Reg::X10);
                        } else {
                            asm.add_w_reg(A64Reg::X11, A64Reg::X9, A64Reg::X10);
                        }
                    }
                    AluOp::Sub => {
                        if *set_flags {
                            asm.subs_w_reg(A64Reg::X11, A64Reg::X9, A64Reg::X10);
                        } else {
                            asm.sub_w_reg(A64Reg::X11, A64Reg::X9, A64Reg::X10);
                        }
                    }
                    AluOp::Rsb => {
                        if *set_flags {
                            asm.subs_w_reg(A64Reg::X11, A64Reg::X10, A64Reg::X9);
                        } else {
                            asm.sub_w_reg(A64Reg::X11, A64Reg::X10, A64Reg::X9);
                        }
                    }
                    AluOp::And => {
                        asm.and_w_reg(A64Reg::X11, A64Reg::X9, A64Reg::X10);
                    }
                    AluOp::Orr => {
                        asm.orr_w_reg(A64Reg::X11, A64Reg::X9, A64Reg::X10);
                    }
                    AluOp::Eor => {
                        asm.eor_w_reg(A64Reg::X11, A64Reg::X9, A64Reg::X10);
                    }
                    AluOp::Bic => {
                        asm.bic_w_reg(A64Reg::X11, A64Reg::X9, A64Reg::X10);
                    }
                    AluOp::Mov => {
                        asm.mov_w_reg(A64Reg::X11, A64Reg::X10);
                    }
                    AluOp::Mvn => {
                        asm.mvn_w_reg(A64Reg::X11, A64Reg::X10);
                    }
                    AluOp::Cmp => {
                        asm.cmp_w_reg(A64Reg::X9, A64Reg::X10);
                    }
                    AluOp::Cmn => {
                        asm.adds_w_reg(A64Reg::SP, A64Reg::X9, A64Reg::X10);
                    }
                    AluOp::Tst => {
                        asm.tst_w_reg(A64Reg::X9, A64Reg::X10);
                    }
                    _ => {
                        asm.mov_w_reg(A64Reg::X11, A64Reg::X10);
                    }
                }

                // 4. If not a test instruction, store w11 back into CpuState.regs[rd]
                if !op.is_test() {
                    let rd_offset = (rd.index() * 4) as u32;
                    asm.str_w_imm(A64Reg::X11, A64Reg::X0, rd_offset);
                }
            }
            Op::Mul {
                op,
                set_flags: _,
                rd,
                rn,
                rm,
                rs,
            } => {
                let rm_offset = (rm.index() * 4) as u32;
                let rs_offset = (rs.index() * 4) as u32;
                asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, rm_offset);
                asm.ldr_w_imm(A64Reg::X10, A64Reg::X0, rs_offset);

                match op {
                    MulOp::Mul => {
                        asm.mul_w_reg(A64Reg::X11, A64Reg::X9, A64Reg::X10);
                    }
                    MulOp::Mla => {
                        let rn_offset = (rn.index() * 4) as u32;
                        asm.ldr_w_imm(A64Reg::X12, A64Reg::X0, rn_offset);
                        asm.madd_w_reg(A64Reg::X11, A64Reg::X9, A64Reg::X10, A64Reg::X12);
                    }
                    MulOp::Mls => {
                        let rn_offset = (rn.index() * 4) as u32;
                        asm.ldr_w_imm(A64Reg::X12, A64Reg::X0, rn_offset);
                        asm.msub_w_reg(A64Reg::X11, A64Reg::X9, A64Reg::X10, A64Reg::X12);
                    }
                }
                let rd_offset = (rd.index() * 4) as u32;
                asm.str_w_imm(A64Reg::X11, A64Reg::X0, rd_offset);
            }
            Op::Div {
                signed,
                rd,
                rn,
                rm,
            } => {
                let rn_offset = (rn.index() * 4) as u32;
                let rm_offset = (rm.index() * 4) as u32;
                asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, rn_offset);
                asm.ldr_w_imm(A64Reg::X10, A64Reg::X0, rm_offset);
                if *signed {
                    asm.sdiv_w_reg(A64Reg::X11, A64Reg::X9, A64Reg::X10);
                } else {
                    asm.udiv_w_reg(A64Reg::X11, A64Reg::X9, A64Reg::X10);
                }
                let rd_offset = (rd.index() * 4) as u32;
                asm.str_w_imm(A64Reg::X11, A64Reg::X0, rd_offset);
            }
            Op::Clz { rd, rm } => {
                let rm_offset = (rm.index() * 4) as u32;
                asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, rm_offset);
                asm.clz_w_reg(A64Reg::X11, A64Reg::X9);
                let rd_offset = (rd.index() * 4) as u32;
                asm.str_w_imm(A64Reg::X11, A64Reg::X0, rd_offset);
            }
            Op::LoadStore {
                is_load,
                size,
                signed,
                rd,
                rn,
                addr_mode,
            } => {
                // 1. Load rn into w9
                let rn_offset = (rn.index() * 4) as u32;
                asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, rn_offset);

                // 2. Compute offset into w10
                let (offset_val, add, is_post) = match addr_mode {
                    AddrMode::Offset { offset, add } => (offset, *add, false),
                    AddrMode::PreIndex { offset, add } => (offset, *add, false),
                    AddrMode::PostIndex { offset, add } => (offset, *add, true),
                };

                match offset_val {
                    AddrOffset::Imm(imm) => {
                        asm.mov_imm32(A64Reg::X10, *imm);
                    }
                    AddrOffset::Reg {
                        rm,
                        shift_type,
                        shift_imm,
                    } => {
                        let rm_offset = (rm.index() * 4) as u32;
                        asm.ldr_w_imm(A64Reg::X10, A64Reg::X0, rm_offset);
                        if *shift_imm > 0 {
                            match shift_type {
                                ShiftType::Lsl => asm.lsl_w_imm(A64Reg::X10, A64Reg::X10, *shift_imm),
                                ShiftType::Lsr => asm.lsr_w_imm(A64Reg::X10, A64Reg::X10, *shift_imm),
                                ShiftType::Asr => asm.asr_w_imm(A64Reg::X10, A64Reg::X10, *shift_imm),
                                _ => {}
                            }
                        }
                    }
                }

                // 3. Effective address into w12
                if is_post {
                    asm.mov_w_reg(A64Reg::X12, A64Reg::X9);
                    if add {
                        asm.add_w_reg(A64Reg::X9, A64Reg::X9, A64Reg::X10);
                    } else {
                        asm.sub_w_reg(A64Reg::X9, A64Reg::X9, A64Reg::X10);
                    }
                    asm.str_w_imm(A64Reg::X9, A64Reg::X0, rn_offset);
                } else {
                    if add {
                        asm.add_w_reg(A64Reg::X12, A64Reg::X9, A64Reg::X10);
                    } else {
                        asm.sub_w_reg(A64Reg::X12, A64Reg::X9, A64Reg::X10);
                    }
                    if matches!(addr_mode, AddrMode::PreIndex { .. }) {
                        asm.str_w_imm(A64Reg::X12, A64Reg::X0, rn_offset);
                    }
                }

                // 4. Compute host address X10 = X1 (mem_base) + W12 (guest_addr)
                asm.add_x_uxtw(A64Reg::X10, A64Reg::X1, A64Reg::X12);

                // 5. Load or Store
                let rd_offset = (rd.index() * 4) as u32;
                if *is_load {
                    match size {
                        MemSize::Byte => {
                            if *signed {
                                asm.ldrsb_w_imm(A64Reg::X11, A64Reg::X10, 0);
                            } else {
                                asm.ldrb_w_imm(A64Reg::X11, A64Reg::X10, 0);
                            }
                            asm.str_w_imm(A64Reg::X11, A64Reg::X0, rd_offset);
                        }
                        MemSize::Halfword => {
                            if *signed {
                                asm.ldrsh_w_imm(A64Reg::X11, A64Reg::X10, 0);
                            } else {
                                asm.ldrh_w_imm(A64Reg::X11, A64Reg::X10, 0);
                            }
                            asm.str_w_imm(A64Reg::X11, A64Reg::X0, rd_offset);
                        }
                        MemSize::Word => {
                            asm.ldr_w_imm(A64Reg::X11, A64Reg::X10, 0);
                            asm.str_w_imm(A64Reg::X11, A64Reg::X0, rd_offset);
                        }
                        MemSize::Doubleword => {
                            // LDRD: load 64-bit into Rt and Rt+1
                            asm.ldr_w_imm(A64Reg::X11, A64Reg::X10, 0);
                            asm.ldr_w_imm(A64Reg::X12, A64Reg::X10, 4);
                            asm.str_w_imm(A64Reg::X11, A64Reg::X0, rd_offset);
                            asm.str_w_imm(A64Reg::X12, A64Reg::X0, rd_offset + 4);
                        }
                    }
                } else {
                    match size {
                        MemSize::Byte => {
                            asm.ldr_w_imm(A64Reg::X11, A64Reg::X0, rd_offset);
                            asm.strb_w_imm(A64Reg::X11, A64Reg::X10, 0);
                        }
                        MemSize::Halfword => {
                            asm.ldr_w_imm(A64Reg::X11, A64Reg::X0, rd_offset);
                            asm.strh_w_imm(A64Reg::X11, A64Reg::X10, 0);
                        }
                        MemSize::Word => {
                            asm.ldr_w_imm(A64Reg::X11, A64Reg::X0, rd_offset);
                            asm.str_w_imm(A64Reg::X11, A64Reg::X10, 0);
                        }
                        MemSize::Doubleword => {
                            // STRD: store 64-bit from Rt and Rt+1
                            asm.ldr_w_imm(A64Reg::X11, A64Reg::X0, rd_offset);
                            asm.ldr_w_imm(A64Reg::X12, A64Reg::X0, rd_offset + 4);
                            asm.str_w_imm(A64Reg::X11, A64Reg::X10, 0);
                            asm.str_w_imm(A64Reg::X12, A64Reg::X10, 4);
                        }
                    }
                }
            }
            Op::LoadStoreMultiple {
                is_load,
                rn,
                mode,
                writeback,
                reg_list,
            } => {
                let rn_offset = (rn.index() * 4) as u32;
                asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, rn_offset);

                let count = reg_list.count_ones() as u32;
                if !is_load && matches!(mode, BlockAddrMode::Db) {
                    // PUSH / STMDB: decrement before
                    asm.sub_w_imm(A64Reg::X9, A64Reg::X9, (count * 4) as u16);
                    let mut cur_offset = 0u32;
                    for i in 0..16 {
                        if (reg_list & (1 << i)) != 0 {
                            asm.add_w_imm(A64Reg::X12, A64Reg::X9, cur_offset as u16);
                            asm.add_x_uxtw(A64Reg::X10, A64Reg::X1, A64Reg::X12);
                            let r_offset = (i * 4) as u32;
                            asm.ldr_w_imm(A64Reg::X11, A64Reg::X0, r_offset);
                            asm.str_w_imm(A64Reg::X11, A64Reg::X10, 0);
                            cur_offset += 4;
                        }
                    }
                    if *writeback {
                        asm.str_w_imm(A64Reg::X9, A64Reg::X0, rn_offset);
                    }
                } else if *is_load && matches!(mode, BlockAddrMode::Ia) {
                    // POP / LDMIA: increment after
                    let mut cur_offset = 0u32;
                    for i in 0..16 {
                        if (reg_list & (1 << i)) != 0 {
                            asm.add_w_imm(A64Reg::X12, A64Reg::X9, cur_offset as u16);
                            asm.add_x_uxtw(A64Reg::X10, A64Reg::X1, A64Reg::X12);
                            asm.ldr_w_imm(A64Reg::X11, A64Reg::X10, 0);
                            let r_offset = (i * 4) as u32;
                            asm.str_w_imm(A64Reg::X11, A64Reg::X0, r_offset);
                            cur_offset += 4;
                        }
                    }
                    if *writeback {
                        asm.add_w_imm(A64Reg::X9, A64Reg::X9, (count * 4) as u16);
                        asm.str_w_imm(A64Reg::X9, A64Reg::X0, rn_offset);
                    }
                }
            }
            Op::VfpAlu {
                op,
                size,
                dst,
                src1,
                src2,
            } => {
                let src1_off = Self::vfp_offset(src1);
                let src2_off = Self::vfp_offset(src2);
                let dst_off = Self::vfp_offset(dst);

                match size {
                    VfpSize::F32 => {
                        asm.ldr_s_imm(0, A64Reg::X0, src1_off);
                        asm.ldr_s_imm(1, A64Reg::X0, src2_off);
                        match op {
                            VfpOp::Add => asm.fadd_s(2, 0, 1),
                            VfpOp::Sub => asm.fsub_s(2, 0, 1),
                            VfpOp::Mul => asm.fmul_s(2, 0, 1),
                            VfpOp::Div => asm.fdiv_s(2, 0, 1),
                            VfpOp::Abs => asm.fabs_s(2, 0),
                            VfpOp::Neg => asm.fneg_s(2, 0),
                            VfpOp::Sqrt => asm.fsqrt_s(2, 0),
                            VfpOp::Cmp => asm.fcmp_s(0, 1),
                            VfpOp::CmpZero => asm.fcmp_zero_s(0),
                        }
                        if !matches!(op, VfpOp::Cmp | VfpOp::CmpZero) {
                            asm.str_s_imm(2, A64Reg::X0, dst_off);
                        }
                    }
                    VfpSize::F64 => {
                        asm.ldr_d_imm(0, A64Reg::X0, src1_off);
                        asm.ldr_d_imm(1, A64Reg::X0, src2_off);
                        match op {
                            VfpOp::Add => asm.fadd_d(2, 0, 1),
                            VfpOp::Sub => asm.fsub_d(2, 0, 1),
                            VfpOp::Mul => asm.fmul_d(2, 0, 1),
                            VfpOp::Div => asm.fdiv_d(2, 0, 1),
                            VfpOp::Abs => asm.fabs_d(2, 0),
                            VfpOp::Neg => asm.fneg_d(2, 0),
                            VfpOp::Sqrt => asm.fsqrt_d(2, 0),
                            VfpOp::Cmp => asm.fcmp_d(0, 1),
                            VfpOp::CmpZero => asm.fcmp_zero_d(0),
                        }
                        if !matches!(op, VfpOp::Cmp | VfpOp::CmpZero) {
                            asm.str_d_imm(2, A64Reg::X0, dst_off);
                        }
                    }
                }
            }
            Op::VfpMov { size, dst, src } => {
                let src_off = Self::vfp_offset(src);
                let dst_off = Self::vfp_offset(dst);
                match size {
                    VfpSize::F32 => {
                        asm.ldr_s_imm(0, A64Reg::X0, src_off);
                        asm.str_s_imm(0, A64Reg::X0, dst_off);
                    }
                    VfpSize::F64 => {
                        asm.ldr_d_imm(0, A64Reg::X0, src_off);
                        asm.str_d_imm(0, A64Reg::X0, dst_off);
                    }
                }
            }
            Op::VfpMovCore {
                to_core,
                core_reg,
                vfp_reg,
            } => {
                let vfp_off = Self::vfp_offset(vfp_reg);
                let core_off = (core_reg.index() * 4) as u32;
                if *to_core {
                    asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, vfp_off);
                    asm.str_w_imm(A64Reg::X9, A64Reg::X0, core_off);
                } else {
                    asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, core_off);
                    asm.str_w_imm(A64Reg::X9, A64Reg::X0, vfp_off);
                }
            }
            Op::AtomicLoadEx { rd, rn } => {
                let rn_offset = (rn.index() * 4) as u32;
                asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, rn_offset);
                asm.str_w_imm(A64Reg::X9, A64Reg::X0, OFFSET_EXCLUSIVE as u32);
                asm.add_x_uxtw(A64Reg::X10, A64Reg::X1, A64Reg::X9);
                asm.ldxr_w(A64Reg::X11, A64Reg::X10);
                let rd_offset = (rd.index() * 4) as u32;
                asm.str_w_imm(A64Reg::X11, A64Reg::X0, rd_offset);
            }
            Op::AtomicStoreEx { rd, rm, rn } => {
                let rn_offset = (rn.index() * 4) as u32;
                asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, rn_offset);
                asm.add_x_uxtw(A64Reg::X10, A64Reg::X1, A64Reg::X9);
                let rm_offset = (rm.index() * 4) as u32;
                asm.ldr_w_imm(A64Reg::X11, A64Reg::X0, rm_offset);
                asm.stxr_w(A64Reg::X12, A64Reg::X11, A64Reg::X10);
                let rd_offset = (rd.index() * 4) as u32;
                asm.str_w_imm(A64Reg::X12, A64Reg::X0, rd_offset);
            }
            Op::Clrex => {
                asm.clrex();
                asm.mov_imm32(A64Reg::X9, 0xFFFF_FFFF);
                asm.str_w_imm(A64Reg::X9, A64Reg::X0, OFFSET_EXCLUSIVE as u32);
            }
            Op::MemoryBarrier { .. } => {
                asm.dmb_ish();
            }
            Op::Cp15Move { is_mrc, rd, .. } => {
                let rd_offset = (rd.index() * 4) as u32;
                if *is_mrc {
                    asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, OFFSET_TLS as u32);
                    asm.str_w_imm(A64Reg::X9, A64Reg::X0, rd_offset);
                } else {
                    asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, rd_offset);
                    asm.str_w_imm(A64Reg::X9, A64Reg::X0, OFFSET_TLS as u32);
                }
            }
            Op::NeonAlu {
                op,
                dst,
                src1,
                src2,
                ..
            } => {
                let src1_off = (OFFSET_VFP + (*src1 as usize) * 8) as u32;
                let src2_off = (OFFSET_VFP + (*src2 as usize) * 8) as u32;
                let dst_off = (OFFSET_VFP + (*dst as usize) * 8) as u32;

                asm.ldr_d_imm(0, A64Reg::X0, src1_off);
                asm.ldr_d_imm(1, A64Reg::X0, src2_off);
                match op {
                    NeonOp::Add => asm.neon_add_4s(2, 0, 1),
                    NeonOp::Sub => asm.neon_sub_4s(2, 0, 1),
                    NeonOp::Mul => asm.neon_mul_4s(2, 0, 1),
                    NeonOp::And => asm.neon_and_16b(2, 0, 1),
                    NeonOp::Orr => asm.neon_orr_16b(2, 0, 1),
                    NeonOp::Eor => asm.neon_eor_16b(2, 0, 1),
                }
                asm.str_d_imm(2, A64Reg::X0, dst_off);
            }
            _ => {
                asm.nop();
            }
        }
    }

    fn compile_exit(
        asm: &mut A64Assembler,
        exit: &BlockExit,
        patch_sites: &mut Vec<PatchSite>,
    ) {
        match exit {
            BlockExit::Direct(target) => {
                // Patch site for direct branch chaining
                let site_offset = asm.cursor() * 4;
                patch_sites.push(PatchSite {
                    byte_offset: site_offset,
                    target: PatchTarget::Direct(*target),
                });

                // Default unchained fallback: return target in w0 with EXIT_REASON_DIRECT
                asm.mov_imm32(A64Reg::X0, target.as_u32());
                asm.ret(None);
            }
            BlockExit::BranchCond {
                cond,
                target,
                fallthrough,
            } => {
                // 1. Conditional branch to taken path
                let taken_site_offset = asm.cursor() * 4;
                patch_sites.push(PatchSite {
                    byte_offset: taken_site_offset,
                    target: PatchTarget::BranchTaken {
                        cond: *cond,
                        target: *target,
                    },
                });
                // B.cond to taken path (+3 instructions offset by default)
                asm.b_cond(*cond, 3);

                // 2. Fallthrough path:
                let ft_site_offset = asm.cursor() * 4;
                patch_sites.push(PatchSite {
                    byte_offset: ft_site_offset,
                    target: PatchTarget::BranchFallthrough(*fallthrough),
                });
                asm.mov_imm32(A64Reg::X0, fallthrough.as_u32());
                asm.ret(None);

                // 3. Taken path:
                asm.mov_imm32(A64Reg::X0, target.as_u32());
                asm.ret(None);
            }
            BlockExit::Indirect(rm) => {
                // Load target address from CpuState.regs[rm] into w0
                let rm_offset = (rm.index() * 4) as u32;
                asm.ldr_w_imm(A64Reg::X0, A64Reg::X0, rm_offset);
                // Set upper 32-bits to EXIT_REASON_INDIRECT
                asm.movz_w(A64Reg::X9, EXIT_REASON_INDIRECT as u16, 16);
                asm.orr_w_reg(A64Reg::X0, A64Reg::X0, A64Reg::X9);
                asm.ret(None);
            }
            BlockExit::Svc { imm, next_pc } => {
                // Update CpuState.PC to next_pc
                asm.mov_imm32(A64Reg::X9, next_pc.as_u32());
                asm.str_w_imm(A64Reg::X9, A64Reg::X0, OFFSET_PC as u32);

                // Return (EXIT_REASON_SVC << 32) | imm
                asm.mov_imm32(A64Reg::X0, *imm);
                asm.ret(None);
            }
            BlockExit::Bkpt { imm, next_pc } => {
                asm.mov_imm32(A64Reg::X9, next_pc.as_u32());
                asm.str_w_imm(A64Reg::X9, A64Reg::X0, OFFSET_PC as u32);
                asm.mov_imm32(A64Reg::X0, *imm as u32);
                asm.ret(None);
            }
            BlockExit::Invalid(addr) => {
                asm.mov_imm32(A64Reg::X0, addr.as_u32());
                asm.ret(None);
            }
        }
    }

    /// Patches an unconditional direct branch (B #offset_words) in code_bytes
    pub fn patch_direct_branch(code_bytes: &mut [u8], byte_offset: usize, offset_words: i32) {
        let imm26 = (offset_words as u32) & 0x03FF_FFFF;
        let inst = 0x1400_0000 | imm26;
        let bytes = inst.to_le_bytes();
        code_bytes[byte_offset..byte_offset + 4].copy_from_slice(&bytes);
    }

    /// Patches a conditional branch (B.cond #offset_words) in code_bytes
    pub fn patch_cond_branch(
        code_bytes: &mut [u8],
        byte_offset: usize,
        cond: Cond,
        offset_words: i32,
    ) {
        let imm19 = (offset_words as u32) & 0x7FFFF;
        let cond_field = (cond as u32) & 0xF;
        let inst = 0x5400_0000 | (imm19 << 5) | cond_field;
        let bytes = inst.to_le_bytes();
        code_bytes[byte_offset..byte_offset + 4].copy_from_slice(&bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transd_core::Reg;
    use transd_decoder::ArmInst;

    #[test]
    fn test_compile_basic_block_patch_sites() {
        let mut block = IrBlock::new(GuestAddr::new(0x8000), false);
        // ADD r0, r1, #10
        block.insts.push(ArmInst::new(
            Cond::AL,
            Op::Alu {
                op: AluOp::Add,
                set_flags: false,
                rd: Reg::R0,
                rn: Reg::R1,
                op2: Operand2::Imm(10),
            },
            0,
        ));
        block.exit = BlockExit::Direct(GuestAddr::new(0x8004));

        let compiled = A64Compiler::compile(&block);
        assert_eq!(compiled.guest_entry, GuestAddr::new(0x8000));
        assert_eq!(compiled.inst_count, 1);
        assert_eq!(compiled.patch_sites.len(), 1);
        assert_eq!(
            compiled.patch_sites[0].target,
            PatchTarget::Direct(GuestAddr::new(0x8004))
        );
        assert!(!compiled.code_bytes.is_empty());
    }

    #[test]
    fn test_compile_load_store_and_vfp() {
        let mut block = IrBlock::new(GuestAddr::new(0x9000), false);
        // LDR r0, [r1, #4]
        block.insts.push(ArmInst::new(
            Cond::AL,
            Op::LoadStore {
                is_load: true,
                size: MemSize::Word,
                signed: false,
                rd: Reg::R0,
                rn: Reg::R1,
                addr_mode: AddrMode::Offset {
                    offset: AddrOffset::Imm(4),
                    add: true,
                },
            },
            0,
        ));
        // VFP FADD s0, s1, s2
        block.insts.push(ArmInst::new(
            Cond::AL,
            Op::VfpAlu {
                op: VfpOp::Add,
                size: VfpSize::F32,
                dst: VfpReg::S(0),
                src1: VfpReg::S(1),
                src2: VfpReg::S(2),
            },
            0,
        ));
        block.exit = BlockExit::Direct(GuestAddr::new(0x9008));

        let compiled = A64Compiler::compile(&block);
        assert_eq!(compiled.inst_count, 2);
        assert!(compiled.code_bytes.len() >= 32);
    }

    #[test]
    fn test_patch_branch_encoding() {
        let mut code = vec![0u8; 16];
        // Patch offset 4 with direct branch +10 words
        A64Compiler::patch_direct_branch(&mut code, 4, 10);
        let inst = u32::from_le_bytes(code[4..8].try_into().unwrap());
        // 0x14000000 | 10 -> 0x1400000A
        assert_eq!(inst, 0x1400_000A);

        // Patch offset 8 with B.EQ +5 words
        A64Compiler::patch_cond_branch(&mut code, 8, Cond::EQ, 5);
        let inst_cond = u32::from_le_bytes(code[8..12].try_into().unwrap());
        // 0x54000000 | (5 << 5) | 0 (EQ) -> 0x540000A0
        assert_eq!(inst_cond, 0x5400_00A0);
    }
}
