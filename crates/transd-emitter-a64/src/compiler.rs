use transd_core::{
    Cond, GuestAddr, Reg, OFFSET_CPSR, OFFSET_EXCLUSIVE, OFFSET_FPSCR, OFFSET_PC, OFFSET_TLS,
    OFFSET_VFP,
};
use transd_decoder::{
    AddrMode, AddrOffset, AluOp, ArmInst, BitFieldOp, BitSatOp, BlockAddrMode, ByteRevOp, CoreSatOp, DspMulOp, ExtendOp, HighMulOp, MemSize, MulOp,
    NeonCvtOp, NeonOp, NeonPermuteOp, NeonRevOp, NeonSize, NeonWriteback, Op, Operand2, PkhOp, ShiftAmount,
    ShiftType, VfpCvtOp, VfpOp, VfpReg, VfpSize,
};
use transd_ir::{BlockExit, IrBlock, Superblock};
use crate::assembler::A64Assembler;
use crate::reg::A64Reg;

/// Exit reasons returned in upper 32-bits of x0 from a compiled JIT block
pub const EXIT_REASON_DIRECT: u64 = 0;
pub const EXIT_REASON_INDIRECT: u64 = 1;
pub const EXIT_REASON_SVC: u64 = 2;
pub const EXIT_REASON_BKPT: u64 = 3;
pub const EXIT_REASON_INVALID: u64 = 4;

/// Size in bytes of the block entry prologue (8 AArch64 instructions = 32 bytes)
pub const PROLOGUE_BYTE_SIZE: usize = 32;

/// Maps guest ARMv7 general purpose registers R0-R7 to pinned AArch64 host registers X19-X26.
/// Callee-saved in AAPCS64, preserved across block boundaries when chained directly.
#[inline(always)]
pub fn pinned_reg(reg: Reg) -> Option<A64Reg> {
    match reg {
        Reg::R0 => Some(A64Reg::X19),
        Reg::R1 => Some(A64Reg::X20),
        Reg::R2 => Some(A64Reg::X21),
        Reg::R3 => Some(A64Reg::X22),
        Reg::R4 => Some(A64Reg::X23),
        Reg::R5 => Some(A64Reg::X24),
        Reg::R6 => Some(A64Reg::X25),
        Reg::R7 => Some(A64Reg::X26),
        _ => None,
    }
}

/// Loads a guest 32-bit register.
/// If pinned (R0-R7), returns the pinned host register directly with 0 instructions emitted.
/// Otherwise loads from CpuState at [X0 + offset] into scratch.
/// Loads a guest 32-bit register with architectural PC awareness.
/// If `reg == Reg::PC`:
/// Emits `MOV scratch, #pc_val` (zero memory access latency, 100% ARM compliant).
/// If pinned (R0-R7), returns the pinned host register directly with 0 instructions emitted.
/// Otherwise loads from CpuState at [X0 + offset] into scratch.
pub fn load_guest_reg_with_pc(
    asm: &mut A64Assembler,
    scratch: A64Reg,
    reg: Reg,
    pc_val: u32,
) -> A64Reg {
    if reg == Reg::PC {
        asm.mov_imm32(scratch, pc_val);
        scratch
    } else if let Some(pinned) = pinned_reg(reg) {
        pinned
    } else {
        let offset = (reg.index() * 4) as u32;
        asm.ldr_w_imm(scratch, A64Reg::X0, offset);
        scratch
    }
}

pub fn load_guest_reg(asm: &mut A64Assembler, scratch: A64Reg, reg: Reg) -> A64Reg {
    if let Some(pinned) = pinned_reg(reg) {
        pinned
    } else {
        let offset = (reg.index() * 4) as u32;
        asm.ldr_w_imm(scratch, A64Reg::X0, offset);
        scratch
    }
}

/// Stores a 32-bit register into a guest register.
/// If pinned (R0-R7), moves into the pinned register (if not already there).
/// Otherwise stores to CpuState at [X0 + offset].
pub fn store_guest_reg(asm: &mut A64Assembler, src: A64Reg, reg: Reg) {
    if let Some(pinned) = pinned_reg(reg) {
        if src != pinned {
            asm.mov_w_reg(pinned, src);
        }
    } else {
        let offset = (reg.index() * 4) as u32;
        asm.str_w_imm(src, A64Reg::X0, offset);
    }
}

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
    pub guest_byte_size: usize,
    pub patch_sites: Vec<PatchSite>,
    pub exit: BlockExit,
}

pub struct A64Compiler;

impl A64Compiler {
    pub const PROLOGUE_BYTE_SIZE: usize = PROLOGUE_BYTE_SIZE;

    /// Compiles an IrBlock into AArch64 native machine code with register pinning and patchable exit sites
    pub fn compile(block: &IrBlock) -> CompiledBlock {
        let mut asm = A64Assembler::new();
        let mut patch_sites = Vec::new();

        // 1. Emit 8-instruction entry prologue (saves host callee-saved X19-X26, loads pinned R0-R7)
        Self::emit_prologue(&mut asm);

        // 2. Pre-scan for dead flag elimination
        let flags_needed = matches!(block.exit, BlockExit::BranchCond { cond, .. } | BlockExit::IndirectCond { cond, .. } if !cond.is_always())
            || block.insts.iter().any(|i| !i.cond.is_always());
        let last_flag_idx = if flags_needed {
            block.insts.iter().rposition(|inst| match &inst.op {
                Op::Alu { op, set_flags, .. } => *set_flags || op.is_test(),
                Op::Mul { set_flags, .. } => *set_flags,
                _ => false,
            })
        } else {
            None
        };

        // 3. Compile instructions with zero-spill register pinning and flag elimination
        for (idx, inst) in block.insts.iter().enumerate() {
            let pc_val = block.pc_read_val(idx);
            let pc_mem_val = block.pc_mem_read_val(idx);
            Self::compile_guarded_inst(&mut asm, inst, idx, flags_needed, last_flag_idx, pc_val, pc_mem_val);
        }

        // 4. Compile block exit (handles fallbacks, chaining sites, and epilogue restore)
        Self::compile_exit(&mut asm, &block.exit, &mut patch_sites);

        CompiledBlock {
            guest_entry: block.entry,
            is_thumb: block.is_thumb,
            code_bytes: asm.to_bytes(),
            inst_count: block.insts.len(),
            guest_byte_size: block.byte_size,
            patch_sites,
            exit: block.exit.clone(),
        }
    }

    /// Compiles a Superblock (trace across multiple basic blocks) into high-performance Tier-2 native code
    pub fn compile_superblock(sb: &Superblock) -> CompiledBlock {
        let mut asm = A64Assembler::new();
        let mut patch_sites = Vec::new();

        // 1. Emit entry prologue
        Self::emit_prologue(&mut asm);

        // 2. Loop header label
        let loop_start_cursor = asm.cursor();

        // 3. Compile instructions with side exit guards
        let mut side_exit_stubs = Vec::new();
        let mut se_idx = 0;

        for (idx, inst) in sb.insts.iter().enumerate() {
            while se_idx < sb.side_exits.len() && sb.side_exits[se_idx].inst_index == idx {
                let se = &sb.side_exits[se_idx];
                se_idx += 1;

                let b_cond_idx = asm.cursor();
                patch_sites.push(PatchSite {
                    byte_offset: b_cond_idx * 4,
                    target: PatchTarget::BranchTaken {
                        cond: se.cond,
                        target: se.target,
                    },
                });
                asm.b_cond(se.cond, 0); // Placeholder
                side_exit_stubs.push((b_cond_idx, se.cond, se.target));
            }

            let pc_val = sb.pc_read_val(idx);
            let pc_mem_val = sb.pc_mem_read_val(idx);
            Self::compile_guarded_inst(&mut asm, inst, idx, true, None, pc_val, pc_mem_val);
        }

        while se_idx < sb.side_exits.len() {
            let se = &sb.side_exits[se_idx];
            se_idx += 1;
            let b_cond_idx = asm.cursor();
            patch_sites.push(PatchSite {
                byte_offset: b_cond_idx * 4,
                target: PatchTarget::BranchTaken {
                    cond: se.cond,
                    target: se.target,
                },
            });
            asm.b_cond(se.cond, 0);
            side_exit_stubs.push((b_cond_idx, se.cond, se.target));
        }

        // 4. Handle final exit or loop backedge
        if sb.is_loop {
            match &sb.exit {
                BlockExit::BranchCond { cond, target, fallthrough } if *target == sb.entry => {
                    // Conditional loop backedge: B.<cond> back to loop_start_cursor
                    let cur_idx = asm.cursor();
                    let offset_words = (loop_start_cursor as i32) - (cur_idx as i32);
                    asm.b_cond(*cond, offset_words);

                    // Fallthrough path (loop exit)
                    let ft_site_offset = asm.cursor() * 4;
                    patch_sites.push(PatchSite {
                        byte_offset: ft_site_offset,
                        target: PatchTarget::BranchFallthrough(*fallthrough),
                    });
                    asm.mov_imm32(A64Reg::X9, fallthrough.as_u32());
                    Self::emit_epilogue(&mut asm);
                    asm.mov_x_reg(A64Reg::X0, A64Reg::X9);
                    asm.ret(None);
                }
                BlockExit::Direct(target) if *target == sb.entry => {
                    // Unconditional loop backedge: B back to loop_start_cursor
                    let cur_idx = asm.cursor();
                    let offset_words = (loop_start_cursor as i32) - (cur_idx as i32);
                    asm.b(offset_words);
                }
                _ => {
                    Self::compile_exit(&mut asm, &sb.exit, &mut patch_sites);
                }
            }
        } else {
            Self::compile_exit(&mut asm, &sb.exit, &mut patch_sites);
        }

        // 5. Emit side exit bailout stubs
        for (b_cond_idx, cond, target) in side_exit_stubs {
            let stub_idx = asm.cursor();
            let offset_words = (stub_idx as i32) - (b_cond_idx as i32);
            let imm19 = (offset_words as u32) & 0x7FFFF;
            let cond_field = (cond as u32) & 0xF;
            asm.patch(b_cond_idx, 0x5400_0000 | (imm19 << 5) | cond_field);

            asm.mov_imm32(A64Reg::X9, target.as_u32());
            Self::emit_epilogue(&mut asm);
            asm.mov_x_reg(A64Reg::X0, A64Reg::X9);
            asm.ret(None);
        }

        CompiledBlock {
            guest_entry: sb.entry,
            is_thumb: sb.is_thumb,
            code_bytes: asm.to_bytes(),
            inst_count: sb.insts.len(),
            guest_byte_size: sb.byte_size,
            patch_sites,
            exit: sb.exit.clone(),
        }
    }

    /// Emits the 8-instruction (32-byte) block entry prologue:
    /// 1. Saves host callee-saved registers X19-X26 on stack (SP -= 64)
    /// 2. Loads guest registers R0-R7 into pinned registers W19-W26 from CpuState (at X0)
    pub fn emit_prologue(asm: &mut A64Assembler) {
        asm.stp_x_pre(A64Reg::X19, A64Reg::X20, A64Reg::SP, -64);
        asm.stp_x_offset(A64Reg::X21, A64Reg::X22, A64Reg::SP, 16);
        asm.stp_x_offset(A64Reg::X23, A64Reg::X24, A64Reg::SP, 32);
        asm.stp_x_offset(A64Reg::X25, A64Reg::X26, A64Reg::SP, 48);

        asm.ldp_w_offset(A64Reg::X19, A64Reg::X20, A64Reg::X0, 0);
        asm.ldp_w_offset(A64Reg::X21, A64Reg::X22, A64Reg::X0, 8);
        asm.ldp_w_offset(A64Reg::X23, A64Reg::X24, A64Reg::X0, 16);
        asm.ldp_w_offset(A64Reg::X25, A64Reg::X26, A64Reg::X0, 24);
    }

    /// Emits the block exit epilogue:
    /// 1. Stores pinned registers W19-W26 back into CpuState (at X0)
    /// 2. Restores host callee-saved registers X19-X26 from stack (SP += 64)
    pub fn emit_epilogue(asm: &mut A64Assembler) {
        asm.stp_w_offset(A64Reg::X19, A64Reg::X20, A64Reg::X0, 0);
        asm.stp_w_offset(A64Reg::X21, A64Reg::X22, A64Reg::X0, 8);
        asm.stp_w_offset(A64Reg::X23, A64Reg::X24, A64Reg::X0, 16);
        asm.stp_w_offset(A64Reg::X25, A64Reg::X26, A64Reg::X0, 24);

        asm.ldp_x_offset(A64Reg::X21, A64Reg::X22, A64Reg::SP, 16);
        asm.ldp_x_offset(A64Reg::X23, A64Reg::X24, A64Reg::SP, 32);
        asm.ldp_x_offset(A64Reg::X25, A64Reg::X26, A64Reg::SP, 48);
        asm.ldp_x_post(A64Reg::X19, A64Reg::X20, A64Reg::SP, 64);
    }

    fn vfp_offset(reg: &VfpReg) -> u32 {
        match reg {
            VfpReg::S(idx) => (OFFSET_VFP + (*idx as usize) * 4) as u32,
            VfpReg::D(idx) => (OFFSET_VFP + (*idx as usize) * 8) as u32,
        }
    }

    fn compile_guarded_inst(
        asm: &mut A64Assembler,
        inst: &ArmInst,
        idx: usize,
        flags_needed: bool,
        last_flag_idx: Option<usize>,
        pc_val: u32,
        pc_mem_val: u32,
    ) {
        let skip_site = if let Some(inv_cond) = inst.cond.invert() {
            let skip_idx = asm.cursor();
            asm.b_cond(inv_cond, 0);
            Some((skip_idx, inv_cond))
        } else if inst.cond == Cond::NV {
            let skip_idx = asm.cursor();
            asm.b(0);
            Some((skip_idx, Cond::NV))
        } else {
            None
        };

        Self::compile_inst(asm, inst, idx, flags_needed, last_flag_idx, pc_val, pc_mem_val);

        if let Some((skip_idx, inv_cond)) = skip_site {
            let end_idx = asm.cursor();
            let offset_words = (end_idx as i32) - (skip_idx as i32);
            if inv_cond == Cond::NV {
                let imm26 = (offset_words as u32) & 0x03FF_FFFF;
                asm.patch(skip_idx, 0x1400_0000 | imm26);
            } else {
                let imm19 = (offset_words as u32) & 0x7FFFF;
                let cond_field = (inv_cond as u32) & 0xF;
                asm.patch(skip_idx, 0x5400_0000 | (imm19 << 5) | cond_field);
            }
        }
    }

    fn compile_inst(
        asm: &mut A64Assembler,
        inst: &ArmInst,
        idx: usize,
        flags_needed: bool,
        last_flag_idx: Option<usize>,
        pc_val: u32,
        pc_mem_val: u32,
    ) {
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
                let effective_set_flags = flags_needed
                    && (*set_flags || op.is_test())
                    && (last_flag_idx.is_none() || Some(idx) == last_flag_idx);
                if op.is_test() && !effective_set_flags {
                    // Dead test instruction eliminated!
                    return;
                }

                // 1. Destination register: if pinned, compute directly into pinned register with zero spills!
                let dst_reg = pinned_reg(*rd).unwrap_or(A64Reg::X11);

                // 2. Load rn: if pinned, returns host pinned register directly with 0 instructions
                let rn_reg = load_guest_reg_with_pc(asm, A64Reg::X9, *rn, pc_val);

                // 3. Fast-path for small immediate operands
                if let Operand2::Imm(imm) = op2 {
                    if *imm <= 0xFFF {
                        match op {
                            AluOp::Add => {
                                if effective_set_flags {
                                    asm.adds_w_imm(dst_reg, rn_reg, *imm as u16);
                                } else {
                                    asm.add_w_imm(dst_reg, rn_reg, *imm as u16);
                                }
                                if pinned_reg(*rd).is_none() {
                                    asm.str_w_imm(dst_reg, A64Reg::X0, (rd.index() * 4) as u32);
                                }
                                return;
                            }
                            AluOp::Sub => {
                                if effective_set_flags {
                                    asm.subs_w_imm(dst_reg, rn_reg, *imm as u16);
                                } else {
                                    asm.sub_w_imm(dst_reg, rn_reg, *imm as u16);
                                }
                                if pinned_reg(*rd).is_none() {
                                    asm.str_w_imm(dst_reg, A64Reg::X0, (rd.index() * 4) as u32);
                                }
                                return;
                            }
                            AluOp::Cmp => {
                                asm.cmp_w_imm(rn_reg, *imm as u16);
                                return;
                            }
                            _ => {}
                        }
                    }
                    if matches!(op, AluOp::Mov) && *imm <= 0xFFFF {
                        asm.movz_w(dst_reg, *imm as u16, 0);
                        if pinned_reg(*rd).is_none() {
                            asm.str_w_imm(dst_reg, A64Reg::X0, (rd.index() * 4) as u32);
                        }
                        return;
                    }
                }

                // 4. Load op2
                let op2_reg = match op2 {
                    Operand2::Imm(imm) => {
                        asm.mov_imm32(A64Reg::X10, *imm);
                        A64Reg::X10
                    }
                    Operand2::Reg { rm, shift } => {
                        let rm_reg = load_guest_reg_with_pc(asm, A64Reg::X10, *rm, pc_val);
                        match shift.amount {
                            ShiftAmount::Imm(shift_imm) => {
                                if shift.shift_type == ShiftType::Rrx {
                                    // RRX Rm: (C << 31) | (Rm >> 1)
                                    asm.mov_imm32(A64Reg::X11, 0x8000_0000);
                                    asm.mov_imm32(A64Reg::X12, 0);
                                    asm.csel_w(A64Reg::X11, A64Reg::X11, A64Reg::X12, Cond::CS);
                                    asm.lsr_w_imm(A64Reg::X10, rm_reg, 1);
                                    asm.orr_w_reg(A64Reg::X10, A64Reg::X10, A64Reg::X11);
                                    A64Reg::X10
                                } else if shift_imm > 0 {
                                    match shift.shift_type {
                                        ShiftType::Lsl => {
                                            asm.lsl_w_imm(A64Reg::X10, rm_reg, shift_imm);
                                            if effective_set_flags && shift_imm <= 32 {
                                                asm.ubfx_w(A64Reg::X12, rm_reg, (32 - shift_imm) as u8, 1);
                                                asm.lsl_w_imm(A64Reg::X12, A64Reg::X12, 31);
                                                asm.adds_w_reg(A64Reg::SP, A64Reg::X12, A64Reg::X12);
                                            }
                                        }
                                        ShiftType::Lsr => {
                                            asm.lsr_w_imm(A64Reg::X10, rm_reg, shift_imm);
                                            if effective_set_flags && shift_imm <= 32 {
                                                asm.ubfx_w(A64Reg::X12, rm_reg, (shift_imm - 1) as u8, 1);
                                                asm.lsl_w_imm(A64Reg::X12, A64Reg::X12, 31);
                                                asm.adds_w_reg(A64Reg::SP, A64Reg::X12, A64Reg::X12);
                                            }
                                        }
                                        ShiftType::Asr => {
                                            asm.asr_w_imm(A64Reg::X10, rm_reg, shift_imm);
                                            if effective_set_flags && shift_imm <= 32 {
                                                asm.ubfx_w(A64Reg::X12, rm_reg, (shift_imm - 1) as u8, 1);
                                                asm.lsl_w_imm(A64Reg::X12, A64Reg::X12, 31);
                                                asm.adds_w_reg(A64Reg::SP, A64Reg::X12, A64Reg::X12);
                                            }
                                        }
                                        ShiftType::Ror => {
                                            asm.mov_imm32(A64Reg::X12, shift_imm as u32);
                                            asm.ror_w_reg(A64Reg::X10, rm_reg, A64Reg::X12);
                                        }
                                        ShiftType::Rrx => unreachable!(),
                                    }
                                    A64Reg::X10
                                } else {
                                    rm_reg
                                }
                            }
                            ShiftAmount::Reg(rs) => {
                                let rs_reg = load_guest_reg_with_pc(asm, A64Reg::X12, rs, pc_val);
                                match shift.shift_type {
                                    ShiftType::Lsl => asm.lsl_w_reg(A64Reg::X10, rm_reg, rs_reg),
                                    ShiftType::Lsr => asm.lsr_w_reg(A64Reg::X10, rm_reg, rs_reg),
                                    ShiftType::Asr => asm.asr_w_reg(A64Reg::X10, rm_reg, rs_reg),
                                    ShiftType::Ror => asm.ror_w_reg(A64Reg::X10, rm_reg, rs_reg),
                                    ShiftType::Rrx => {}
                                }
                                A64Reg::X10
                            }
                        }
                    }
                };

                // 5. Perform ALU operation
                match op {
                    AluOp::Add => {
                        if effective_set_flags {
                            asm.adds_w_reg(dst_reg, rn_reg, op2_reg);
                        } else {
                            asm.add_w_reg(dst_reg, rn_reg, op2_reg);
                        }
                    }
                    AluOp::Sub => {
                        if effective_set_flags {
                            asm.subs_w_reg(dst_reg, rn_reg, op2_reg);
                        } else {
                            asm.sub_w_reg(dst_reg, rn_reg, op2_reg);
                        }
                    }
                    AluOp::Rsb => {
                        if effective_set_flags {
                            asm.subs_w_reg(dst_reg, op2_reg, rn_reg);
                        } else {
                            asm.sub_w_reg(dst_reg, op2_reg, rn_reg);
                        }
                    }
                    AluOp::And => {
                        asm.and_w_reg(dst_reg, rn_reg, op2_reg);
                    }
                    AluOp::Orr => {
                        asm.orr_w_reg(dst_reg, rn_reg, op2_reg);
                    }
                    AluOp::Eor => {
                        asm.eor_w_reg(dst_reg, rn_reg, op2_reg);
                    }
                    AluOp::Bic => {
                        asm.bic_w_reg(dst_reg, rn_reg, op2_reg);
                    }
                    AluOp::Mov => {
                        if dst_reg != op2_reg {
                            asm.mov_w_reg(dst_reg, op2_reg);
                        }
                    }
                    AluOp::Mvn => {
                        asm.mvn_w_reg(dst_reg, op2_reg);
                    }
                    AluOp::Cmp => {
                        asm.cmp_w_reg(rn_reg, op2_reg);
                    }
                    AluOp::Cmn => {
                        asm.adds_w_reg(A64Reg::SP, rn_reg, op2_reg);
                    }
                    AluOp::Tst => {
                        asm.tst_w_reg(rn_reg, op2_reg);
                    }
                    _ => {
                        if dst_reg != op2_reg {
                            asm.mov_w_reg(dst_reg, op2_reg);
                        }
                    }
                }

                // 6. Store back to CpuState only if destination register was unpinned
                if !op.is_test() && pinned_reg(*rd).is_none() {
                    let rd_offset = (rd.index() * 4) as u32;
                    asm.str_w_imm(dst_reg, A64Reg::X0, rd_offset);
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
                let rm_reg = load_guest_reg(asm, A64Reg::X9, *rm);
                let rs_reg = load_guest_reg(asm, A64Reg::X10, *rs);
                let dst_reg = pinned_reg(*rd).unwrap_or(A64Reg::X11);

                match op {
                    MulOp::Mul => {
                        asm.mul_w_reg(dst_reg, rm_reg, rs_reg);
                    }
                    MulOp::Mla => {
                        let rn_reg = load_guest_reg(asm, A64Reg::X12, *rn);
                        asm.madd_w_reg(dst_reg, rm_reg, rs_reg, rn_reg);
                    }
                    MulOp::Mls => {
                        let rn_reg = load_guest_reg(asm, A64Reg::X12, *rn);
                        asm.msub_w_reg(dst_reg, rm_reg, rs_reg, rn_reg);
                    }
                }
                if pinned_reg(*rd).is_none() {
                    let rd_offset = (rd.index() * 4) as u32;
                    asm.str_w_imm(dst_reg, A64Reg::X0, rd_offset);
                }
            }
            Op::MulLong {
                signed,
                accumulate,
                set_flags: _,
                rd_hi,
                rd_lo,
                rm,
                rs,
            } => {
                let rm_reg = load_guest_reg(asm, A64Reg::X9, *rm);
                let rs_reg = load_guest_reg(asm, A64Reg::X10, *rs);

                if *accumulate {
                    let _hi_reg = load_guest_reg(asm, A64Reg::X12, *rd_hi);
                    let lo_reg = load_guest_reg(asm, A64Reg::X13, *rd_lo);
                    asm.lsl_x_imm(A64Reg::X12, A64Reg::X12, 32);
                    asm.add_x_uxtw(A64Reg::X13, A64Reg::X12, lo_reg);

                    if *signed {
                        asm.smaddl_x(A64Reg::X11, rm_reg, rs_reg, A64Reg::X13);
                    } else {
                        asm.umaddl_x(A64Reg::X11, rm_reg, rs_reg, A64Reg::X13);
                    }
                } else {
                    if *signed {
                        asm.smull_x(A64Reg::X11, rm_reg, rs_reg);
                    } else {
                        asm.umull_x(A64Reg::X11, rm_reg, rs_reg);
                    }
                }

                store_guest_reg(asm, A64Reg::X11, *rd_lo);
                asm.lsr_x_imm(A64Reg::X12, A64Reg::X11, 32);
                store_guest_reg(asm, A64Reg::X12, *rd_hi);
            }
            Op::Umaal {
                rd_lo,
                rd_hi,
                rn,
                rm,
            } => {
                let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);
                let rm_reg = load_guest_reg(asm, A64Reg::X10, *rm);
                // X11 = Rn * Rm (unsigned 64-bit)
                asm.umull_x(A64Reg::X11, rn_reg, rm_reg);
                // Accumulate RdLo (zero-extended)
                let lo_reg = load_guest_reg(asm, A64Reg::X12, *rd_lo);
                asm.add_x_uxtw(A64Reg::X11, A64Reg::X11, lo_reg);
                // Accumulate RdHi (zero-extended)
                let hi_reg = load_guest_reg(asm, A64Reg::X12, *rd_hi);
                asm.add_x_uxtw(A64Reg::X11, A64Reg::X11, hi_reg);

                // Store lower 32 bits into RdLo
                store_guest_reg(asm, A64Reg::X11, *rd_lo);
                // Store upper 32 bits into RdHi
                asm.lsr_x_imm(A64Reg::X12, A64Reg::X11, 32);
                store_guest_reg(asm, A64Reg::X12, *rd_hi);
            }
            Op::DspMul {
                op,
                rd,
                rn,
                rm,
                rs,
            } => {
                let rm_reg = load_guest_reg(asm, A64Reg::X9, *rm);
                let rs_reg = load_guest_reg(asm, A64Reg::X10, *rs);
                let dst_reg = pinned_reg(*rd).unwrap_or(A64Reg::X11);

                match op {
                    DspMulOp::Smul { x_top, y_top } => {
                        if *x_top {
                            asm.sbfx_w(A64Reg::X12, rm_reg, 16, 16);
                        } else {
                            asm.sxth_w(A64Reg::X12, rm_reg);
                        }
                        if *y_top {
                            asm.sbfx_w(A64Reg::X13, rs_reg, 16, 16);
                        } else {
                            asm.sxth_w(A64Reg::X13, rs_reg);
                        }
                        asm.mul_w_reg(dst_reg, A64Reg::X12, A64Reg::X13);
                    }
                    DspMulOp::Smla { x_top, y_top } => {
                        if *x_top {
                            asm.sbfx_w(A64Reg::X12, rm_reg, 16, 16);
                        } else {
                            asm.sxth_w(A64Reg::X12, rm_reg);
                        }
                        if *y_top {
                            asm.sbfx_w(A64Reg::X13, rs_reg, 16, 16);
                        } else {
                            asm.sxth_w(A64Reg::X13, rs_reg);
                        }
                        let rn_reg = load_guest_reg(asm, A64Reg::X14, *rn);
                        asm.madd_w_reg(dst_reg, A64Reg::X12, A64Reg::X13, rn_reg);
                    }
                    DspMulOp::Smulw { y_top } => {
                        if *y_top {
                            asm.sbfx_w(A64Reg::X13, rs_reg, 16, 16);
                        } else {
                            asm.sxth_w(A64Reg::X13, rs_reg);
                        }
                        asm.smull_x(A64Reg::X12, rm_reg, A64Reg::X13);
                        asm.asr_x_imm(A64Reg::X12, A64Reg::X12, 16);
                        asm.mov_w_reg(dst_reg, A64Reg::X12);
                    }
                    DspMulOp::Smlaw { y_top } => {
                        if *y_top {
                            asm.sbfx_w(A64Reg::X13, rs_reg, 16, 16);
                        } else {
                            asm.sxth_w(A64Reg::X13, rs_reg);
                        }
                        asm.smull_x(A64Reg::X12, rm_reg, A64Reg::X13);
                        asm.asr_x_imm(A64Reg::X12, A64Reg::X12, 16);
                        let rn_reg = load_guest_reg(asm, A64Reg::X14, *rn);
                        asm.add_w_reg(dst_reg, A64Reg::X12, rn_reg);
                    }
                    DspMulOp::Smuad { swap } => {
                        let rs_eff = if *swap {
                            asm.ror_w(A64Reg::X15, rs_reg, 16);
                            A64Reg::X15
                        } else {
                            rs_reg
                        };
                        asm.sxth_w(A64Reg::X12, rm_reg);
                        asm.sbfx_w(A64Reg::X13, rm_reg, 16, 16);
                        asm.sxth_w(A64Reg::X14, rs_eff);
                        asm.mul_w_reg(A64Reg::X12, A64Reg::X12, A64Reg::X14);
                        asm.sbfx_w(A64Reg::X14, rs_eff, 16, 16);
                        asm.mul_w_reg(A64Reg::X13, A64Reg::X13, A64Reg::X14);
                        asm.add_w_reg(dst_reg, A64Reg::X12, A64Reg::X13);
                    }
                    DspMulOp::Smlad { swap } => {
                        let rs_eff = if *swap {
                            asm.ror_w(A64Reg::X15, rs_reg, 16);
                            A64Reg::X15
                        } else {
                            rs_reg
                        };
                        asm.sxth_w(A64Reg::X12, rm_reg);
                        asm.sbfx_w(A64Reg::X13, rm_reg, 16, 16);
                        asm.sxth_w(A64Reg::X14, rs_eff);
                        asm.mul_w_reg(A64Reg::X12, A64Reg::X12, A64Reg::X14);
                        asm.sbfx_w(A64Reg::X14, rs_eff, 16, 16);
                        asm.mul_w_reg(A64Reg::X13, A64Reg::X13, A64Reg::X14);
                        asm.add_w_reg(dst_reg, A64Reg::X12, A64Reg::X13);
                        let rn_reg = load_guest_reg(asm, A64Reg::X14, *rn);
                        asm.add_w_reg(dst_reg, dst_reg, rn_reg);
                    }
                    DspMulOp::Smusd { swap } => {
                        let rs_eff = if *swap {
                            asm.ror_w(A64Reg::X15, rs_reg, 16);
                            A64Reg::X15
                        } else {
                            rs_reg
                        };
                        asm.sxth_w(A64Reg::X12, rm_reg);
                        asm.sbfx_w(A64Reg::X13, rm_reg, 16, 16);
                        asm.sxth_w(A64Reg::X14, rs_eff);
                        asm.mul_w_reg(A64Reg::X12, A64Reg::X12, A64Reg::X14);
                        asm.sbfx_w(A64Reg::X14, rs_eff, 16, 16);
                        asm.mul_w_reg(A64Reg::X13, A64Reg::X13, A64Reg::X14);
                        asm.sub_w_reg(dst_reg, A64Reg::X12, A64Reg::X13);
                    }
                    DspMulOp::Smlsd { swap } => {
                        let rs_eff = if *swap {
                            asm.ror_w(A64Reg::X15, rs_reg, 16);
                            A64Reg::X15
                        } else {
                            rs_reg
                        };
                        asm.sxth_w(A64Reg::X12, rm_reg);
                        asm.sbfx_w(A64Reg::X13, rm_reg, 16, 16);
                        asm.sxth_w(A64Reg::X14, rs_eff);
                        asm.mul_w_reg(A64Reg::X12, A64Reg::X12, A64Reg::X14);
                        asm.sbfx_w(A64Reg::X14, rs_eff, 16, 16);
                        asm.mul_w_reg(A64Reg::X13, A64Reg::X13, A64Reg::X14);
                        asm.sub_w_reg(dst_reg, A64Reg::X12, A64Reg::X13);
                        let rn_reg = load_guest_reg(asm, A64Reg::X14, *rn);
                        asm.add_w_reg(dst_reg, dst_reg, rn_reg);
                    }
                }

                if pinned_reg(*rd).is_none() {
                    let rd_offset = (rd.index() * 4) as u32;
                    asm.str_w_imm(dst_reg, A64Reg::X0, rd_offset);
                }
            }
            Op::HighMul { op, rd, rn, rm, ra } => {
                let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);
                let rm_reg = load_guest_reg(asm, A64Reg::X10, *rm);
                let dst_reg = pinned_reg(*rd).unwrap_or(A64Reg::X11);

                asm.smull_x(A64Reg::X12, rn_reg, rm_reg);

                let round = match op {
                    HighMulOp::Smmul { round } | HighMulOp::Smmla { round } | HighMulOp::Smmls { round } => *round,
                };
                if round {
                    asm.mov_imm64(A64Reg::X13, 0x8000_0000);
                    asm.add_x_reg(A64Reg::X12, A64Reg::X12, A64Reg::X13);
                }

                asm.lsr_x_imm(A64Reg::X12, A64Reg::X12, 32);

                match op {
                    HighMulOp::Smmul { .. } => {
                        asm.mov_w_reg(dst_reg, A64Reg::X12);
                    }
                    HighMulOp::Smmla { .. } => {
                        let ra_reg = ra.map(|r| load_guest_reg(asm, A64Reg::X13, r)).unwrap_or(A64Reg::SP);
                        asm.add_w_reg(dst_reg, ra_reg, A64Reg::X12);
                    }
                    HighMulOp::Smmls { .. } => {
                        let ra_reg = ra.map(|r| load_guest_reg(asm, A64Reg::X13, r)).unwrap_or(A64Reg::SP);
                        asm.sub_w_reg(dst_reg, ra_reg, A64Reg::X12);
                    }
                }

                if pinned_reg(*rd).is_none() {
                    let rd_offset = (rd.index() * 4) as u32;
                    asm.str_w_imm(dst_reg, A64Reg::X0, rd_offset);
                }
            }
            Op::CoreSat { op, rd, rm, rn } => {
                let rm_reg = load_guest_reg(asm, A64Reg::X9, *rm);
                let rn_reg = load_guest_reg(asm, A64Reg::X10, *rn);
                let dst_reg = pinned_reg(*rd).unwrap_or(A64Reg::X11);

                match op {
                    CoreSatOp::Qadd => {
                        asm.sxtw_x(A64Reg::X12, rm_reg);
                        asm.sxtw_x(A64Reg::X13, rn_reg);
                        asm.add_x_reg(A64Reg::X14, A64Reg::X12, A64Reg::X13);

                        asm.mov_imm64(A64Reg::X12, 0x7FFF_FFFF);
                        asm.cmp_x_reg(A64Reg::X14, A64Reg::X12);
                        asm.csel_x(A64Reg::X15, A64Reg::X12, A64Reg::X14, Cond::GT);

                        asm.mov_imm64(A64Reg::X12, 0xFFFF_FFFF_8000_0000);
                        asm.cmp_x_reg(A64Reg::X15, A64Reg::X12);
                        asm.csel_x(A64Reg::X15, A64Reg::X12, A64Reg::X15, Cond::LT);

                        asm.mov_w_reg(dst_reg, A64Reg::X15);

                        asm.cmp_x_reg(A64Reg::X14, A64Reg::X15);
                        let skip_b = asm.cursor();
                        asm.b_cond(Cond::EQ, 0);
                        asm.ldr_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);
                        asm.mov_imm32(A64Reg::X13, 0x0800_0000);
                        asm.orr_w_reg(A64Reg::X12, A64Reg::X12, A64Reg::X13);
                        asm.str_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);
                        let end_idx = asm.cursor();
                        let offset = (end_idx as i32) - (skip_b as i32);
                        asm.patch(skip_b, 0x5400_0000 | (((offset as u32) & 0x7FFFF) << 5) | (Cond::EQ as u32 & 0xF));
                    }
                    CoreSatOp::Qsub => {
                        asm.sxtw_x(A64Reg::X12, rm_reg);
                        asm.sxtw_x(A64Reg::X13, rn_reg);
                        asm.sub_x_reg(A64Reg::X14, A64Reg::X12, A64Reg::X13);

                        asm.mov_imm64(A64Reg::X12, 0x7FFF_FFFF);
                        asm.cmp_x_reg(A64Reg::X14, A64Reg::X12);
                        asm.csel_x(A64Reg::X15, A64Reg::X12, A64Reg::X14, Cond::GT);

                        asm.mov_imm64(A64Reg::X12, 0xFFFF_FFFF_8000_0000);
                        asm.cmp_x_reg(A64Reg::X15, A64Reg::X12);
                        asm.csel_x(A64Reg::X15, A64Reg::X12, A64Reg::X15, Cond::LT);

                        asm.mov_w_reg(dst_reg, A64Reg::X15);

                        asm.cmp_x_reg(A64Reg::X14, A64Reg::X15);
                        let skip_b = asm.cursor();
                        asm.b_cond(Cond::EQ, 0);
                        asm.ldr_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);
                        asm.mov_imm32(A64Reg::X13, 0x0800_0000);
                        asm.orr_w_reg(A64Reg::X12, A64Reg::X12, A64Reg::X13);
                        asm.str_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);
                        let end_idx = asm.cursor();
                        let offset = (end_idx as i32) - (skip_b as i32);
                        asm.patch(skip_b, 0x5400_0000 | (((offset as u32) & 0x7FFFF) << 5) | (Cond::EQ as u32 & 0xF));
                    }
                    CoreSatOp::Qdadd => {
                        asm.sxtw_x(A64Reg::X13, rn_reg);
                        asm.lsl_x_imm(A64Reg::X14, A64Reg::X13, 1);

                        asm.mov_imm64(A64Reg::X12, 0x7FFF_FFFF);
                        asm.cmp_x_reg(A64Reg::X14, A64Reg::X12);
                        asm.csel_x(A64Reg::X10, A64Reg::X12, A64Reg::X14, Cond::GT);

                        asm.mov_imm64(A64Reg::X12, 0xFFFF_FFFF_8000_0000);
                        asm.cmp_x_reg(A64Reg::X10, A64Reg::X12);
                        asm.csel_x(A64Reg::X10, A64Reg::X12, A64Reg::X10, Cond::LT);

                        asm.cmp_x_reg(A64Reg::X14, A64Reg::X10);
                        let skip_b1 = asm.cursor();
                        asm.b_cond(Cond::EQ, 0);
                        asm.ldr_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);
                        asm.mov_imm32(A64Reg::X13, 0x0800_0000);
                        asm.orr_w_reg(A64Reg::X12, A64Reg::X12, A64Reg::X13);
                        asm.str_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);
                        let end_idx1 = asm.cursor();
                        let offset1 = (end_idx1 as i32) - (skip_b1 as i32);
                        asm.patch(skip_b1, 0x5400_0000 | (((offset1 as u32) & 0x7FFFF) << 5) | (Cond::EQ as u32 & 0xF));

                        asm.sxtw_x(A64Reg::X12, rm_reg);
                        asm.add_x_reg(A64Reg::X14, A64Reg::X12, A64Reg::X10);

                        asm.mov_imm64(A64Reg::X12, 0x7FFF_FFFF);
                        asm.cmp_x_reg(A64Reg::X14, A64Reg::X12);
                        asm.csel_x(A64Reg::X15, A64Reg::X12, A64Reg::X14, Cond::GT);

                        asm.mov_imm64(A64Reg::X12, 0xFFFF_FFFF_8000_0000);
                        asm.cmp_x_reg(A64Reg::X15, A64Reg::X12);
                        asm.csel_x(A64Reg::X15, A64Reg::X12, A64Reg::X15, Cond::LT);

                        asm.mov_w_reg(dst_reg, A64Reg::X15);

                        asm.cmp_x_reg(A64Reg::X14, A64Reg::X15);
                        let skip_b2 = asm.cursor();
                        asm.b_cond(Cond::EQ, 0);
                        asm.ldr_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);
                        asm.mov_imm32(A64Reg::X13, 0x0800_0000);
                        asm.orr_w_reg(A64Reg::X12, A64Reg::X12, A64Reg::X13);
                        asm.str_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);
                        let end_idx2 = asm.cursor();
                        let offset2 = (end_idx2 as i32) - (skip_b2 as i32);
                        asm.patch(skip_b2, 0x5400_0000 | (((offset2 as u32) & 0x7FFFF) << 5) | (Cond::EQ as u32 & 0xF));
                    }
                    CoreSatOp::Qdsub => {
                        asm.sxtw_x(A64Reg::X13, rn_reg);
                        asm.lsl_x_imm(A64Reg::X14, A64Reg::X13, 1);

                        asm.mov_imm64(A64Reg::X12, 0x7FFF_FFFF);
                        asm.cmp_x_reg(A64Reg::X14, A64Reg::X12);
                        asm.csel_x(A64Reg::X10, A64Reg::X12, A64Reg::X14, Cond::GT);

                        asm.mov_imm64(A64Reg::X12, 0xFFFF_FFFF_8000_0000);
                        asm.cmp_x_reg(A64Reg::X10, A64Reg::X12);
                        asm.csel_x(A64Reg::X10, A64Reg::X12, A64Reg::X10, Cond::LT);

                        asm.cmp_x_reg(A64Reg::X14, A64Reg::X10);
                        let skip_b1 = asm.cursor();
                        asm.b_cond(Cond::EQ, 0);
                        asm.ldr_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);
                        asm.mov_imm32(A64Reg::X13, 0x0800_0000);
                        asm.orr_w_reg(A64Reg::X12, A64Reg::X12, A64Reg::X13);
                        asm.str_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);
                        let end_idx1 = asm.cursor();
                        let offset1 = (end_idx1 as i32) - (skip_b1 as i32);
                        asm.patch(skip_b1, 0x5400_0000 | (((offset1 as u32) & 0x7FFFF) << 5) | (Cond::EQ as u32 & 0xF));

                        asm.sxtw_x(A64Reg::X12, rm_reg);
                        asm.sub_x_reg(A64Reg::X14, A64Reg::X12, A64Reg::X10);

                        asm.mov_imm64(A64Reg::X12, 0x7FFF_FFFF);
                        asm.cmp_x_reg(A64Reg::X14, A64Reg::X12);
                        asm.csel_x(A64Reg::X15, A64Reg::X12, A64Reg::X14, Cond::GT);

                        asm.mov_imm64(A64Reg::X12, 0xFFFF_FFFF_8000_0000);
                        asm.cmp_x_reg(A64Reg::X15, A64Reg::X12);
                        asm.csel_x(A64Reg::X15, A64Reg::X12, A64Reg::X15, Cond::LT);

                        asm.mov_w_reg(dst_reg, A64Reg::X15);

                        asm.cmp_x_reg(A64Reg::X14, A64Reg::X15);
                        let skip_b2 = asm.cursor();
                        asm.b_cond(Cond::EQ, 0);
                        asm.ldr_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);
                        asm.mov_imm32(A64Reg::X13, 0x0800_0000);
                        asm.orr_w_reg(A64Reg::X12, A64Reg::X12, A64Reg::X13);
                        asm.str_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);
                        let end_idx2 = asm.cursor();
                        let offset2 = (end_idx2 as i32) - (skip_b2 as i32);
                        asm.patch(skip_b2, 0x5400_0000 | (((offset2 as u32) & 0x7FFFF) << 5) | (Cond::EQ as u32 & 0xF));
                    }
                }
                store_guest_reg(asm, dst_reg, *rd);
            }
            Op::BitSat { op, rd, rn } => {
                let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);
                let dst_reg = pinned_reg(*rd).unwrap_or(A64Reg::X11);

                match op {
                    BitSatOp::Ssat { sat_imm, shift_type, shift_imm } => {
                        match shift_type {
                            ShiftType::Lsl => asm.lsl_w_imm(A64Reg::X12, rn_reg, *shift_imm),
                            ShiftType::Asr => asm.asr_w_imm(A64Reg::X12, rn_reg, *shift_imm),
                            _ => asm.mov_w_reg(A64Reg::X12, rn_reg),
                        }
                        asm.sxtw_x(A64Reg::X14, A64Reg::X12);

                        let max_val = ((1i64 << (sat_imm - 1)) - 1) as u64;
                        let min_val = (-(1i64 << (sat_imm - 1))) as u64;

                        asm.mov_imm64(A64Reg::X12, max_val);
                        asm.cmp_x_reg(A64Reg::X14, A64Reg::X12);
                        asm.csel_x(A64Reg::X15, A64Reg::X12, A64Reg::X14, Cond::GT);

                        asm.mov_imm64(A64Reg::X12, min_val);
                        asm.cmp_x_reg(A64Reg::X15, A64Reg::X12);
                        asm.csel_x(A64Reg::X15, A64Reg::X12, A64Reg::X15, Cond::LT);

                        asm.mov_w_reg(dst_reg, A64Reg::X15);

                        asm.cmp_x_reg(A64Reg::X14, A64Reg::X15);
                        let skip_b = asm.cursor();
                        asm.b_cond(Cond::EQ, 0);
                        asm.ldr_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);
                        asm.mov_imm32(A64Reg::X13, 0x0800_0000);
                        asm.orr_w_reg(A64Reg::X12, A64Reg::X12, A64Reg::X13);
                        asm.str_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);
                        let end_idx = asm.cursor();
                        let offset = (end_idx as i32) - (skip_b as i32);
                        asm.patch(skip_b, 0x5400_0000 | (((offset as u32) & 0x7FFFF) << 5) | (Cond::EQ as u32 & 0xF));
                    }
                    BitSatOp::Usat { sat_imm, shift_type, shift_imm } => {
                        match shift_type {
                            ShiftType::Lsl => asm.lsl_w_imm(A64Reg::X12, rn_reg, *shift_imm),
                            ShiftType::Asr => asm.asr_w_imm(A64Reg::X12, rn_reg, *shift_imm),
                            _ => asm.mov_w_reg(A64Reg::X12, rn_reg),
                        }
                        asm.sxtw_x(A64Reg::X14, A64Reg::X12);

                        let max_val = if *sat_imm >= 32 { 0xFFFF_FFFFu64 } else { (1u64 << sat_imm) - 1 };
                        asm.mov_imm64(A64Reg::X12, max_val);
                        asm.cmp_x_reg(A64Reg::X14, A64Reg::X12);
                        asm.csel_x(A64Reg::X15, A64Reg::X12, A64Reg::X14, Cond::GT);

                        asm.mov_imm64(A64Reg::X12, 0);
                        asm.cmp_x_reg(A64Reg::X15, A64Reg::X12);
                        asm.csel_x(A64Reg::X15, A64Reg::X12, A64Reg::X15, Cond::LT);

                        asm.mov_w_reg(dst_reg, A64Reg::X15);

                        asm.cmp_x_reg(A64Reg::X14, A64Reg::X15);
                        let skip_b = asm.cursor();
                        asm.b_cond(Cond::EQ, 0);
                        asm.ldr_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);
                        asm.mov_imm32(A64Reg::X13, 0x0800_0000);
                        asm.orr_w_reg(A64Reg::X12, A64Reg::X12, A64Reg::X13);
                        asm.str_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);
                        let end_idx = asm.cursor();
                        let offset = (end_idx as i32) - (skip_b as i32);
                        asm.patch(skip_b, 0x5400_0000 | (((offset as u32) & 0x7FFFF) << 5) | (Cond::EQ as u32 & 0xF));
                    }
                    BitSatOp::Ssat16 { sat_imm } => {
                        asm.sxth_w(A64Reg::X12, rn_reg);
                        asm.sxtw_x(A64Reg::X12, A64Reg::X12);
                        asm.asr_w_imm(A64Reg::X13, rn_reg, 16);
                        asm.sxtw_x(A64Reg::X13, A64Reg::X13);

                        let max_val = ((1i64 << (sat_imm - 1)) - 1) as u64;
                        let min_val = (-(1i64 << (sat_imm - 1))) as u64;

                        asm.mov_imm64(A64Reg::X14, max_val);
                        asm.cmp_x_reg(A64Reg::X12, A64Reg::X14);
                        asm.csel_x(A64Reg::X9, A64Reg::X14, A64Reg::X12, Cond::GT);
                        asm.mov_imm64(A64Reg::X14, min_val);
                        asm.cmp_x_reg(A64Reg::X9, A64Reg::X14);
                        asm.csel_x(A64Reg::X9, A64Reg::X14, A64Reg::X9, Cond::LT);

                        asm.mov_imm64(A64Reg::X14, max_val);
                        asm.cmp_x_reg(A64Reg::X13, A64Reg::X14);
                        asm.csel_x(A64Reg::X10, A64Reg::X14, A64Reg::X13, Cond::GT);
                        asm.mov_imm64(A64Reg::X14, min_val);
                        asm.cmp_x_reg(A64Reg::X10, A64Reg::X14);
                        asm.csel_x(A64Reg::X10, A64Reg::X14, A64Reg::X10, Cond::LT);

                        asm.uxth_w(A64Reg::X9, A64Reg::X9);
                        asm.lsl_w_imm(A64Reg::X10, A64Reg::X10, 16);
                        asm.orr_w_reg(dst_reg, A64Reg::X9, A64Reg::X10);

                        asm.cmp_x_reg(A64Reg::X12, A64Reg::X9);
                        let set_q1 = asm.cursor();
                        asm.b_cond(Cond::NE, 0);
                        asm.cmp_x_reg(A64Reg::X13, A64Reg::X10);
                        let skip_b = asm.cursor();
                        asm.b_cond(Cond::EQ, 0);

                        let q_target = asm.cursor();
                        let off1 = (q_target as i32) - (set_q1 as i32);
                        asm.patch(set_q1, 0x5400_0000 | (((off1 as u32) & 0x7FFFF) << 5) | (Cond::NE as u32 & 0xF));

                        asm.ldr_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);
                        asm.mov_imm32(A64Reg::X13, 0x0800_0000);
                        asm.orr_w_reg(A64Reg::X12, A64Reg::X12, A64Reg::X13);
                        asm.str_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);

                        let end_idx = asm.cursor();
                        let offset = (end_idx as i32) - (skip_b as i32);
                        asm.patch(skip_b, 0x5400_0000 | (((offset as u32) & 0x7FFFF) << 5) | (Cond::EQ as u32 & 0xF));
                    }
                    BitSatOp::Usat16 { sat_imm } => {
                        asm.sxth_w(A64Reg::X12, rn_reg);
                        asm.sxtw_x(A64Reg::X12, A64Reg::X12);
                        asm.asr_w_imm(A64Reg::X13, rn_reg, 16);
                        asm.sxtw_x(A64Reg::X13, A64Reg::X13);

                        let max_val = if *sat_imm >= 16 { 0xFFFFu64 } else { (1u64 << sat_imm) - 1 };

                        asm.mov_imm64(A64Reg::X14, max_val);
                        asm.cmp_x_reg(A64Reg::X12, A64Reg::X14);
                        asm.csel_x(A64Reg::X9, A64Reg::X14, A64Reg::X12, Cond::GT);
                        asm.mov_imm64(A64Reg::X14, 0);
                        asm.cmp_x_reg(A64Reg::X9, A64Reg::X14);
                        asm.csel_x(A64Reg::X9, A64Reg::X14, A64Reg::X9, Cond::LT);

                        asm.mov_imm64(A64Reg::X14, max_val);
                        asm.cmp_x_reg(A64Reg::X13, A64Reg::X14);
                        asm.csel_x(A64Reg::X10, A64Reg::X14, A64Reg::X13, Cond::GT);
                        asm.mov_imm64(A64Reg::X14, 0);
                        asm.cmp_x_reg(A64Reg::X10, A64Reg::X14);
                        asm.csel_x(A64Reg::X10, A64Reg::X14, A64Reg::X10, Cond::LT);

                        asm.uxth_w(A64Reg::X9, A64Reg::X9);
                        asm.lsl_w_imm(A64Reg::X10, A64Reg::X10, 16);
                        asm.orr_w_reg(dst_reg, A64Reg::X9, A64Reg::X10);

                        asm.cmp_x_reg(A64Reg::X12, A64Reg::X9);
                        let set_q1 = asm.cursor();
                        asm.b_cond(Cond::NE, 0);
                        asm.cmp_x_reg(A64Reg::X13, A64Reg::X10);
                        let skip_b = asm.cursor();
                        asm.b_cond(Cond::EQ, 0);

                        let q_target = asm.cursor();
                        let off1 = (q_target as i32) - (set_q1 as i32);
                        asm.patch(set_q1, 0x5400_0000 | (((off1 as u32) & 0x7FFFF) << 5) | (Cond::NE as u32 & 0xF));

                        asm.ldr_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);
                        asm.mov_imm32(A64Reg::X13, 0x0800_0000);
                        asm.orr_w_reg(A64Reg::X12, A64Reg::X12, A64Reg::X13);
                        asm.str_w_imm(A64Reg::X12, A64Reg::X0, OFFSET_CPSR as u32);

                        let end_idx = asm.cursor();
                        let offset = (end_idx as i32) - (skip_b as i32);
                        asm.patch(skip_b, 0x5400_0000 | (((offset as u32) & 0x7FFFF) << 5) | (Cond::EQ as u32 & 0xF));
                    }
                }
                store_guest_reg(asm, dst_reg, *rd);
            }
            Op::Div {
                signed,
                rd,
                rn,
                rm,
            } => {
                let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);
                let rm_reg = load_guest_reg(asm, A64Reg::X10, *rm);
                let dst_reg = pinned_reg(*rd).unwrap_or(A64Reg::X11);

                if *signed {
                    asm.sdiv_w_reg(dst_reg, rn_reg, rm_reg);
                } else {
                    asm.udiv_w_reg(dst_reg, rn_reg, rm_reg);
                }
                if pinned_reg(*rd).is_none() {
                    let rd_offset = (rd.index() * 4) as u32;
                    asm.str_w_imm(dst_reg, A64Reg::X0, rd_offset);
                }
            }
            Op::Clz { rd, rm } => {
                let rm_reg = load_guest_reg(asm, A64Reg::X9, *rm);
                let dst_reg = pinned_reg(*rd).unwrap_or(A64Reg::X11);
                asm.clz_w_reg(dst_reg, rm_reg);
                if pinned_reg(*rd).is_none() {
                    let rd_offset = (rd.index() * 4) as u32;
                    asm.str_w_imm(dst_reg, A64Reg::X0, rd_offset);
                }
            }
            Op::BitField {
                op,
                rd,
                rn,
                lsb,
                width,
            } => {
                let dst_reg = pinned_reg(*rd).unwrap_or(A64Reg::X11);
                match op {
                    BitFieldOp::Ubfx => {
                        let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);
                        asm.ubfx_w(dst_reg, rn_reg, *lsb, *width);
                    }
                    BitFieldOp::Sbfx => {
                        let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);
                        asm.sbfx_w(dst_reg, rn_reg, *lsb, *width);
                    }
                    BitFieldOp::Bfi => {
                        let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);
                        let rd_orig = load_guest_reg(asm, A64Reg::X10, *rd);
                        if dst_reg != rd_orig {
                            asm.mov_w_reg(dst_reg, rd_orig);
                        }
                        asm.bfi_w(dst_reg, rn_reg, *lsb, *width);
                    }
                    BitFieldOp::Bfc => {
                        let rd_orig = load_guest_reg(asm, A64Reg::X10, *rd);
                        let mask = if *width >= 32 {
                            0xFFFF_FFFFu32
                        } else {
                            ((1u64 << *width) - 1) as u32
                        };
                        let clear_mask = !(mask.wrapping_shl(*lsb as u32));
                        asm.mov_imm32(A64Reg::X9, clear_mask);
                        asm.and_w_reg(dst_reg, rd_orig, A64Reg::X9);
                    }
                }
                store_guest_reg(asm, dst_reg, *rd);
            }
            Op::ByteRev { op, rd, rm } => {
                let rm_reg = load_guest_reg(asm, A64Reg::X9, *rm);
                let dst_reg = pinned_reg(*rd).unwrap_or(A64Reg::X11);
                match op {
                    ByteRevOp::Rev => asm.rev_w(dst_reg, rm_reg),
                    ByteRevOp::Rev16 => asm.rev16_w(dst_reg, rm_reg),
                    ByteRevOp::Rbit => asm.rbit_w(dst_reg, rm_reg),
                    ByteRevOp::Revsh => {
                        asm.rev16_w(dst_reg, rm_reg);
                        asm.sxth_w(dst_reg, dst_reg);
                    }
                }
                store_guest_reg(asm, dst_reg, *rd);
            }
            Op::SimdPkh { op, rd, rn, rm, shift } => {
                let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);
                let rm_reg = load_guest_reg(asm, A64Reg::X10, *rm);
                let dst_reg = pinned_reg(*rd).unwrap_or(A64Reg::X11);
                match op {
                    PkhOp::Pkhbt => {
                        asm.uxth_w(dst_reg, rn_reg);
                        if *shift != 0 {
                            asm.lsl_w_imm(A64Reg::X10, rm_reg, *shift);
                        }
                        asm.bfi_w(dst_reg, A64Reg::X10, 16, 16);
                    }
                    PkhOp::Pkhtb => {
                        let eff_shift = if *shift == 0 { 32 } else { *shift };
                        asm.asr_w_imm(A64Reg::X10, rm_reg, eff_shift);
                        asm.uxth_w(A64Reg::X10, A64Reg::X10);
                        asm.mov_imm32(A64Reg::X12, 0xFFFF_0000);
                        asm.and_w_reg(dst_reg, rn_reg, A64Reg::X12);
                        asm.orr_w_reg(dst_reg, dst_reg, A64Reg::X10);
                    }
                }
                store_guest_reg(asm, dst_reg, *rd);
            }
            Op::SimdExtend { op, rd, rn, rm, rotation } => {
                let rm_reg = load_guest_reg(asm, A64Reg::X9, *rm);
                if *rotation != 0 {
                    asm.ror_w(A64Reg::X9, rm_reg, *rotation);
                }
                let ext_src = if *rotation != 0 { A64Reg::X9 } else { rm_reg };
                let dst_reg = pinned_reg(*rd).unwrap_or(A64Reg::X11);

                match op {
                    ExtendOp::Sxtb => asm.sxtb_w(dst_reg, ext_src),
                    ExtendOp::Uxtb => asm.uxtb_w(dst_reg, ext_src),
                    ExtendOp::Sxth => asm.sxth_w(dst_reg, ext_src),
                    ExtendOp::Uxth => asm.uxth_w(dst_reg, ext_src),
                    ExtendOp::Sxtb16 => {
                        asm.sxtb_w(A64Reg::X10, ext_src);
                        asm.uxth_w(A64Reg::X10, A64Reg::X10);
                        asm.lsr_w_imm(A64Reg::X12, ext_src, 16);
                        asm.sxtb_w(A64Reg::X12, A64Reg::X12);
                        asm.lsl_w_imm(A64Reg::X12, A64Reg::X12, 16);
                        asm.orr_w_reg(dst_reg, A64Reg::X10, A64Reg::X12);
                    }
                    ExtendOp::Uxtb16 => {
                        asm.uxtb_w(A64Reg::X10, ext_src);
                        asm.lsr_w_imm(A64Reg::X12, ext_src, 16);
                        asm.uxtb_w(A64Reg::X12, A64Reg::X12);
                        asm.lsl_w_imm(A64Reg::X12, A64Reg::X12, 16);
                        asm.orr_w_reg(dst_reg, A64Reg::X10, A64Reg::X12);
                    }
                }

                if let Some(rn) = rn {
                    let rn_reg = load_guest_reg(asm, A64Reg::X10, *rn);
                    match op {
                        ExtendOp::Sxtb16 | ExtendOp::Uxtb16 => {
                            // Halfword-wise parallel add
                            asm.add_w_reg(A64Reg::X12, rn_reg, dst_reg); // lo sum
                            asm.uxth_w(A64Reg::X12, A64Reg::X12);
                            asm.lsr_w_imm(A64Reg::X9, rn_reg, 16);
                            asm.lsr_w_imm(A64Reg::X11, dst_reg, 16);
                            asm.add_w_reg(A64Reg::X9, A64Reg::X9, A64Reg::X11); // hi sum
                            asm.lsl_w_imm(A64Reg::X9, A64Reg::X9, 16);
                            asm.orr_w_reg(dst_reg, A64Reg::X12, A64Reg::X9);
                        }
                        _ => {
                            asm.add_w_reg(dst_reg, rn_reg, dst_reg);
                        }
                    }
                }
                store_guest_reg(asm, dst_reg, *rd);
            }
            Op::LoadStore {
                is_load,
                size,
                signed,
                rd,
                rn,
                addr_mode,
            } => {
                // 1. Load rn (using pc_mem_val for PC-relative memory operations)
                let rn_reg = load_guest_reg_with_pc(asm, A64Reg::X9, *rn, pc_mem_val);

                // 2. Compute offset
                let (offset_val, add, is_post) = match addr_mode {
                    AddrMode::Offset { offset, add } => (offset, *add, false),
                    AddrMode::PreIndex { offset, add } => (offset, *add, false),
                    AddrMode::PostIndex { offset, add } => (offset, *add, true),
                };

                let offset_reg = match offset_val {
                    AddrOffset::Imm(imm) => {
                        if *imm == 0 {
                            None
                        } else {
                            asm.mov_imm32(A64Reg::X10, *imm);
                            Some(A64Reg::X10)
                        }
                    }
                    AddrOffset::Reg {
                        rm,
                        shift_type,
                        shift_imm,
                    } => {
                        let rm_reg = load_guest_reg_with_pc(asm, A64Reg::X10, *rm, pc_val);
                        if *shift_imm > 0 {
                            match shift_type {
                                ShiftType::Lsl => asm.lsl_w_imm(A64Reg::X10, rm_reg, *shift_imm),
                                ShiftType::Lsr => asm.lsr_w_imm(A64Reg::X10, rm_reg, *shift_imm),
                                ShiftType::Asr => asm.asr_w_imm(A64Reg::X10, rm_reg, *shift_imm),
                                _ => {}
                            }
                            Some(A64Reg::X10)
                        } else {
                            Some(rm_reg)
                        }
                    }
                };

                // 3. Effective address into W12
                if is_post {
                    asm.mov_w_reg(A64Reg::X12, rn_reg);
                    if let Some(off_r) = offset_reg {
                        if add {
                            asm.add_w_reg(A64Reg::X9, rn_reg, off_r);
                        } else {
                            asm.sub_w_reg(A64Reg::X9, rn_reg, off_r);
                        }
                    } else {
                        asm.mov_w_reg(A64Reg::X9, rn_reg);
                    }
                    store_guest_reg(asm, A64Reg::X9, *rn);
                } else {
                    if let Some(off_r) = offset_reg {
                        if add {
                            asm.add_w_reg(A64Reg::X12, rn_reg, off_r);
                        } else {
                            asm.sub_w_reg(A64Reg::X12, rn_reg, off_r);
                        }
                    } else {
                        asm.mov_w_reg(A64Reg::X12, rn_reg);
                    }
                    if matches!(addr_mode, AddrMode::PreIndex { .. }) {
                        store_guest_reg(asm, A64Reg::X12, *rn);
                    }
                }

                // 4. Single-Instruction Zero-Overhead Memory Access (UXTW Register Offset)
                let dst_reg = pinned_reg(*rd).unwrap_or(A64Reg::X11);
                if *is_load {
                    match size {
                        MemSize::Byte => {
                            if *signed {
                                asm.ldrsb_w_uxtw(dst_reg, A64Reg::X1, A64Reg::X12);
                            } else {
                                asm.ldrb_w_uxtw(dst_reg, A64Reg::X1, A64Reg::X12);
                            }
                            if pinned_reg(*rd).is_none() {
                                store_guest_reg(asm, dst_reg, *rd);
                            }
                        }
                        MemSize::Halfword => {
                            if *signed {
                                asm.ldrsh_w_uxtw(dst_reg, A64Reg::X1, A64Reg::X12);
                            } else {
                                asm.ldrh_w_uxtw(dst_reg, A64Reg::X1, A64Reg::X12);
                            }
                            if pinned_reg(*rd).is_none() {
                                store_guest_reg(asm, dst_reg, *rd);
                            }
                        }
                        MemSize::Word => {
                            asm.ldr_w_uxtw(dst_reg, A64Reg::X1, A64Reg::X12);
                            if pinned_reg(*rd).is_none() {
                                store_guest_reg(asm, dst_reg, *rd);
                            }
                        }
                        MemSize::Doubleword => {
                            asm.add_x_uxtw(A64Reg::X10, A64Reg::X1, A64Reg::X12);
                            asm.ldr_w_imm(A64Reg::X11, A64Reg::X10, 0);
                            asm.ldr_w_imm(A64Reg::X12, A64Reg::X10, 4);
                            store_guest_reg(asm, A64Reg::X11, *rd);
                            if let Some(next_rd) = Reg::from_u8((rd.index() + 1) as u8) {
                                store_guest_reg(asm, A64Reg::X12, next_rd);
                            }
                        }
                    }
                } else {
                    let src_reg = load_guest_reg_with_pc(asm, A64Reg::X11, *rd, pc_val);
                    match size {
                        MemSize::Byte => {
                            asm.strb_w_uxtw(src_reg, A64Reg::X1, A64Reg::X12);
                        }
                        MemSize::Halfword => {
                            asm.strh_w_uxtw(src_reg, A64Reg::X1, A64Reg::X12);
                        }
                        MemSize::Word => {
                            asm.str_w_uxtw(src_reg, A64Reg::X1, A64Reg::X12);
                        }
                        MemSize::Doubleword => {
                            asm.add_x_uxtw(A64Reg::X10, A64Reg::X1, A64Reg::X12);
                            let next_rd = Reg::from_u8((rd.index() + 1) as u8);
                            let src_next = next_rd.map(|r| load_guest_reg(asm, A64Reg::X12, r)).unwrap_or(A64Reg::X12);
                            asm.str_w_imm(src_reg, A64Reg::X10, 0);
                            asm.str_w_imm(src_next, A64Reg::X10, 4);
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
                let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);
                asm.mov_w_reg(A64Reg::X9, rn_reg);

                let count = reg_list.count_ones() as u32;
                if !is_load && matches!(mode, BlockAddrMode::Db) {
                    // PUSH / STMDB: decrement before
                    asm.sub_w_imm(A64Reg::X9, A64Reg::X9, (count * 4) as u16);
                    let mut cur_offset = 0u32;
                    for i in 0..16 {
                        if (reg_list & (1 << i)) != 0 {
                            let r = Reg::from_u8(i as u8).unwrap();
                            let src = load_guest_reg(asm, A64Reg::X11, r);
                            asm.add_w_imm(A64Reg::X12, A64Reg::X9, cur_offset as u16);
                            asm.add_x_uxtw(A64Reg::X10, A64Reg::X1, A64Reg::X12);
                            asm.str_w_imm(src, A64Reg::X10, 0);
                            cur_offset += 4;
                        }
                    }
                    if *writeback {
                        store_guest_reg(asm, A64Reg::X9, *rn);
                    }
                } else if *is_load && matches!(mode, BlockAddrMode::Ia) {
                    // POP / LDMIA: increment after
                    let mut cur_offset = 0u32;
                    for i in 0..16 {
                        if (reg_list & (1 << i)) != 0 {
                            let r = Reg::from_u8(i as u8).unwrap();
                            asm.add_w_imm(A64Reg::X12, A64Reg::X9, cur_offset as u16);
                            asm.add_x_uxtw(A64Reg::X10, A64Reg::X1, A64Reg::X12);
                            asm.ldr_w_imm(A64Reg::X11, A64Reg::X10, 0);
                            store_guest_reg(asm, A64Reg::X11, r);
                            cur_offset += 4;
                        }
                    }
                    if *writeback {
                        asm.add_w_imm(A64Reg::X9, A64Reg::X9, (count * 4) as u16);
                        store_guest_reg(asm, A64Reg::X9, *rn);
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
                            VfpOp::Fma | VfpOp::Mla => {
                                asm.ldr_s_imm(3, A64Reg::X0, dst_off);
                                asm.fmadd_s(2, 0, 1, 3);
                            }
                            VfpOp::Fms | VfpOp::Mls => {
                                asm.ldr_s_imm(3, A64Reg::X0, dst_off);
                                asm.fmsub_s(2, 0, 1, 3);
                            }
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
                            VfpOp::Fma | VfpOp::Mla => {
                                asm.ldr_d_imm(3, A64Reg::X0, dst_off);
                                asm.fmadd_d(2, 0, 1, 3);
                            }
                            VfpOp::Fms | VfpOp::Mls => {
                                asm.ldr_d_imm(3, A64Reg::X0, dst_off);
                                asm.fmsub_d(2, 0, 1, 3);
                            }
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
                if *to_core {
                    asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, vfp_off);
                    store_guest_reg(asm, A64Reg::X9, *core_reg);
                } else {
                    let src = load_guest_reg(asm, A64Reg::X9, *core_reg);
                    asm.str_w_imm(src, A64Reg::X0, vfp_off);
                }
            }
            Op::VfpMovTwoCore {
                to_core,
                is_double: _,
                rt,
                rt2,
                vfp_reg,
            } => {
                let vfp_off = Self::vfp_offset(vfp_reg);
                if *to_core {
                    asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, vfp_off);
                    asm.ldr_w_imm(A64Reg::X10, A64Reg::X0, vfp_off + 4);
                    store_guest_reg(asm, A64Reg::X9, *rt);
                    store_guest_reg(asm, A64Reg::X10, *rt2);
                } else {
                    let src1 = load_guest_reg(asm, A64Reg::X9, *rt);
                    let src2 = load_guest_reg(asm, A64Reg::X10, *rt2);
                    asm.str_w_imm(src1, A64Reg::X0, vfp_off);
                    asm.str_w_imm(src2, A64Reg::X0, vfp_off + 4);
                }
            }
            Op::VfpMrsFpscr { rt } => {
                match rt {
                    None => {
                        asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, OFFSET_FPSCR as u32);
                        asm.ldr_w_imm(A64Reg::X10, A64Reg::X0, OFFSET_CPSR as u32);
                        asm.mov_imm32(A64Reg::X11, 0x0FFF_FFFF);
                        asm.and_w_reg(A64Reg::X10, A64Reg::X10, A64Reg::X11);
                        asm.mov_imm32(A64Reg::X11, 0xF000_0000);
                        asm.and_w_reg(A64Reg::X9, A64Reg::X9, A64Reg::X11);
                        asm.orr_w_reg(A64Reg::X10, A64Reg::X10, A64Reg::X9);
                        asm.str_w_imm(A64Reg::X10, A64Reg::X0, OFFSET_CPSR as u32);
                    }
                    Some(r) => {
                        asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, OFFSET_FPSCR as u32);
                        store_guest_reg(asm, A64Reg::X9, *r);
                    }
                }
            }
            Op::VfpMsrFpscr { rt } => {
                let src = load_guest_reg(asm, A64Reg::X9, *rt);
                asm.str_w_imm(src, A64Reg::X0, OFFSET_FPSCR as u32);
                asm.mrs_fpcr(A64Reg::X10);
                asm.mov_imm32(A64Reg::X11, !0x03C0_0000);
                asm.and_w_reg(A64Reg::X10, A64Reg::X10, A64Reg::X11);
                asm.mov_imm32(A64Reg::X11, 0x03C0_0000);
                asm.and_w_reg(A64Reg::X12, src, A64Reg::X11);
                asm.orr_w_reg(A64Reg::X10, A64Reg::X10, A64Reg::X12);
                asm.msr_fpcr(A64Reg::X10);
            }
            Op::VfpLoadStore {
                is_load,
                size,
                vfp_reg,
                rn,
                offset,
            } => {
                let base = load_guest_reg_with_pc(asm, A64Reg::X9, *rn, pc_mem_val);
                let vfp_off = Self::vfp_offset(vfp_reg);
                if *offset >= 0 {
                    asm.add_w_imm(A64Reg::X10, base, *offset as u16);
                } else {
                    asm.sub_w_imm(A64Reg::X10, base, (-*offset) as u16);
                }
                asm.add_x_uxtw(A64Reg::X10, A64Reg::X1, A64Reg::X10);
                match size {
                    VfpSize::F32 => {
                        if *is_load {
                            asm.ldr_s_imm(0, A64Reg::X10, 0);
                            asm.str_s_imm(0, A64Reg::X0, vfp_off);
                        } else {
                            asm.ldr_s_imm(0, A64Reg::X0, vfp_off);
                            asm.str_s_imm(0, A64Reg::X10, 0);
                        }
                    }
                    VfpSize::F64 => {
                        if *is_load {
                            asm.ldr_d_imm(0, A64Reg::X10, 0);
                            asm.str_d_imm(0, A64Reg::X0, vfp_off);
                        } else {
                            asm.ldr_d_imm(0, A64Reg::X0, vfp_off);
                            asm.str_d_imm(0, A64Reg::X10, 0);
                        }
                    }
                }
            }
            Op::VfpLoadStoreMultiple {
                is_load,
                is_double,
                writeback,
                is_add,
                rn,
                start_reg,
                count,
            } => {
                let base_reg = load_guest_reg_with_pc(asm, A64Reg::X9, *rn, pc_mem_val);
                let elem_size: u32 = if *is_double { 8 } else { 4 };
                let total_bytes = (*count as u32) * elem_size;

                if *is_add {
                    asm.mov_w_reg(A64Reg::X12, base_reg);
                    if *writeback {
                        asm.add_w_imm(A64Reg::X11, base_reg, total_bytes as u16);
                        store_guest_reg(asm, A64Reg::X11, *rn);
                    }
                } else {
                    asm.sub_w_imm(A64Reg::X12, base_reg, total_bytes as u16);
                    if *writeback {
                        store_guest_reg(asm, A64Reg::X12, *rn);
                    }
                }
                asm.add_x_uxtw(A64Reg::X10, A64Reg::X1, A64Reg::X12);

                for i in 0..(*count as usize) {
                    let reg_idx = (*start_reg as usize + i) as u8;
                    let mem_off = (i as u32) * elem_size;

                    if *is_double {
                        let d_idx = reg_idx % 32;
                        let cpu_off = (OFFSET_VFP + (d_idx as usize) * 8) as u32;
                        if *is_load {
                            asm.ldr_d_imm(0, A64Reg::X10, mem_off);
                            asm.str_d_imm(0, A64Reg::X0, cpu_off);
                        } else {
                            asm.ldr_d_imm(0, A64Reg::X0, cpu_off);
                            asm.str_d_imm(0, A64Reg::X10, mem_off);
                        }
                    } else {
                        let s_idx = reg_idx % 32;
                        let cpu_off = (OFFSET_VFP + (s_idx as usize) * 4) as u32;
                        if *is_load {
                            asm.ldr_s_imm(0, A64Reg::X10, mem_off);
                            asm.str_s_imm(0, A64Reg::X0, cpu_off);
                        } else {
                            asm.ldr_s_imm(0, A64Reg::X0, cpu_off);
                            asm.str_s_imm(0, A64Reg::X10, mem_off);
                        }
                    }
                }
            }
            Op::VfpCvt { op, dst, src } => {
                let src_off = Self::vfp_offset(src);
                let dst_off = Self::vfp_offset(dst);
                match op {
                    VfpCvtOp::F64FromF32 => {
                        asm.ldr_s_imm(0, A64Reg::X0, src_off);
                        asm.fcvt_d_s(2, 0);
                        asm.str_d_imm(2, A64Reg::X0, dst_off);
                    }
                    VfpCvtOp::F32FromF64 => {
                        asm.ldr_d_imm(0, A64Reg::X0, src_off);
                        asm.fcvt_s_d(2, 0);
                        asm.str_s_imm(2, A64Reg::X0, dst_off);
                    }
                    VfpCvtOp::F32FromS32 => {
                        asm.ldr_s_imm(0, A64Reg::X0, src_off);
                        asm.scvtf_s_s(2, 0);
                        asm.str_s_imm(2, A64Reg::X0, dst_off);
                    }
                    VfpCvtOp::F32FromU32 => {
                        asm.ldr_s_imm(0, A64Reg::X0, src_off);
                        asm.ucvtf_s_s(2, 0);
                        asm.str_s_imm(2, A64Reg::X0, dst_off);
                    }
                    VfpCvtOp::S32FromF32 => {
                        asm.ldr_s_imm(0, A64Reg::X0, src_off);
                        asm.fcvtzs_s_s(2, 0);
                        asm.str_s_imm(2, A64Reg::X0, dst_off);
                    }
                    VfpCvtOp::U32FromF32 => {
                        asm.ldr_s_imm(0, A64Reg::X0, src_off);
                        asm.fcvtzu_s_s(2, 0);
                        asm.str_s_imm(2, A64Reg::X0, dst_off);
                    }
                    VfpCvtOp::F64FromS32 => {
                        asm.ldr_w_imm(A64Reg::X11, A64Reg::X0, src_off);
                        asm.scvtf_d_w(2, A64Reg::X11);
                        asm.str_d_imm(2, A64Reg::X0, dst_off);
                    }
                    VfpCvtOp::F64FromU32 => {
                        asm.ldr_w_imm(A64Reg::X11, A64Reg::X0, src_off);
                        asm.ucvtf_d_w(2, A64Reg::X11);
                        asm.str_d_imm(2, A64Reg::X0, dst_off);
                    }
                    VfpCvtOp::S32FromF64 => {
                        asm.ldr_d_imm(0, A64Reg::X0, src_off);
                        asm.fcvtzs_w_d(A64Reg::X11, 0);
                        asm.str_w_imm(A64Reg::X11, A64Reg::X0, dst_off);
                    }
                    VfpCvtOp::U32FromF64 => {
                        asm.ldr_d_imm(0, A64Reg::X0, src_off);
                        asm.fcvtzu_w_d(A64Reg::X11, 0);
                        asm.str_w_imm(A64Reg::X11, A64Reg::X0, dst_off);
                    }
                }
            }
            Op::AtomicLoadEx { rd, rn } => {
                let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);
                asm.str_w_imm(rn_reg, A64Reg::X0, OFFSET_EXCLUSIVE as u32);
                asm.add_x_uxtw(A64Reg::X10, A64Reg::X1, rn_reg);
                asm.ldxr_w(A64Reg::X11, A64Reg::X10);
                store_guest_reg(asm, A64Reg::X11, *rd);
            }
            Op::AtomicStoreEx { rd, rm, rn } => {
                let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);
                asm.add_x_uxtw(A64Reg::X10, A64Reg::X1, rn_reg);
                let rm_reg = load_guest_reg(asm, A64Reg::X11, *rm);
                asm.stxr_w(A64Reg::X12, rm_reg, A64Reg::X10);
                store_guest_reg(asm, A64Reg::X12, *rd);
            }
            Op::Clrex => {
                asm.clrex();
                asm.mov_imm32(A64Reg::X9, 0xFFFF_FFFF);
                asm.str_w_imm(A64Reg::X9, A64Reg::X0, OFFSET_EXCLUSIVE as u32);
            }
            Op::MemoryBarrier { .. } => {
                asm.dmb_ish();
            }
            Op::Cp15Move {
                is_mrc,
                rd,
                crn,
                crm,
                opc2,
                ..
            } => {
                if *crn == 13 && *crm == 0 && (*opc2 == 2 || *opc2 == 3 || *opc2 == 4) {
                    // TLS thread pointer registers (TPIDRURW / TPIDRURO / TPIDRPRW)
                    if *is_mrc {
                        asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, OFFSET_TLS as u32);
                        store_guest_reg(asm, A64Reg::X9, *rd);
                    } else {
                        let src = load_guest_reg(asm, A64Reg::X9, *rd);
                        asm.str_w_imm(src, A64Reg::X0, OFFSET_TLS as u32);
                    }
                } else if *crn == 7 {
                    // CP15 c7: Pre-ARMv7 memory barriers and cache ops (Unity Mono Boehm GC, ARMv5/v6)
                    match (*crm, *opc2) {
                        (10, 5) => {
                            // DMB (Data Memory Barrier)
                            asm.dmb_ish();
                        }
                        (10, 4) => {
                            // DSB (Data Synchronization Barrier)
                            asm.dsb_ish();
                        }
                        (5, 4) | (5, 0) | (5, 6) => {
                            // ISB (Instruction Synchronization Barrier) / I-Cache invalidate
                            asm.isb();
                        }
                        _ => {
                            // Other cache operations: memory barrier
                            asm.dmb_ish();
                        }
                    }
                } else if *is_mrc && *crn == 0 && *crm == 0 {
                    // CP15 c0: CPUID (MIDR / CTR)
                    let dst = pinned_reg(*rd).unwrap_or(A64Reg::X9);
                    let cpuid: u32 = if *opc2 == 1 { 0x8003_C003 } else { 0x412F_C0F3 };
                    asm.movz_w(dst, (cpuid & 0xFFFF) as u16, 0);
                    asm.movk_w(dst, (cpuid >> 16) as u16, 16);
                    if pinned_reg(*rd).is_none() {
                        store_guest_reg(asm, dst, *rd);
                    }
                } else if *is_mrc {
                    // Harmless read for other coprocessor registers
                    let dst = pinned_reg(*rd).unwrap_or(A64Reg::X9);
                    asm.movz_w(dst, 0, 0);
                    if pinned_reg(*rd).is_none() {
                        store_guest_reg(asm, dst, *rd);
                    }
                }
            }
            Op::Movw { rd, imm } => {
                let dst_reg = pinned_reg(*rd).unwrap_or(A64Reg::X11);
                asm.movz_w(dst_reg, *imm, 0);
                if pinned_reg(*rd).is_none() {
                    asm.str_w_imm(dst_reg, A64Reg::X0, (rd.index() * 4) as u32);
                }
            }
            Op::Movt { rd, imm } => {
                let dst_reg = pinned_reg(*rd).unwrap_or(A64Reg::X11);
                if pinned_reg(*rd).is_none() {
                    asm.ldr_w_imm(dst_reg, A64Reg::X0, (rd.index() * 4) as u32);
                }
                asm.movk_w(dst_reg, *imm, 16);
                if pinned_reg(*rd).is_none() {
                    asm.str_w_imm(dst_reg, A64Reg::X0, (rd.index() * 4) as u32);
                }
            }
            Op::NeonAlu {
                op,
                size,
                is_quad,
                dst,
                src1,
                src2,
            } => {
                let src1_off = (OFFSET_VFP + (*src1 as usize) * 8) as u32;
                let src2_off = (OFFSET_VFP + (*src2 as usize) * 8) as u32;
                let dst_off = (OFFSET_VFP + (*dst as usize) * 8) as u32;

                // Load operands
                if *is_quad {
                    asm.add_x_imm(A64Reg::X9, A64Reg::X0, src1_off as u16);
                    asm.ldr_q_imm(0, A64Reg::X9, 0);
                    asm.add_x_imm(A64Reg::X10, A64Reg::X0, src2_off as u16);
                    asm.ldr_q_imm(1, A64Reg::X10, 0);
                    if matches!(op, NeonOp::Mla | NeonOp::Mls) {
                        asm.add_x_imm(A64Reg::X9, A64Reg::X0, dst_off as u16);
                        asm.ldr_q_imm(2, A64Reg::X9, 0);
                    }
                } else {
                    asm.ldr_d_imm(0, A64Reg::X0, src1_off);
                    asm.ldr_d_imm(1, A64Reg::X0, src2_off);
                    if matches!(op, NeonOp::Mla | NeonOp::Mls) {
                        asm.ldr_d_imm(2, A64Reg::X0, dst_off);
                    }
                }

                // Perform operation
                match (op, size) {
                    // Vector Float 32-bit operations
                    (NeonOp::Add, NeonSize::F32) => asm.neon_fadd(2, 0, 1, *is_quad),
                    (NeonOp::Sub, NeonSize::F32) => asm.neon_fsub(2, 0, 1, *is_quad),
                    (NeonOp::Mul, NeonSize::F32) => asm.neon_fmul(2, 0, 1, *is_quad),
                    (NeonOp::Mla, NeonSize::F32) => asm.neon_fmla(2, 0, 1, *is_quad),
                    (NeonOp::Mls, NeonSize::F32) => asm.neon_fmls(2, 0, 1, *is_quad),
                    (NeonOp::Min, NeonSize::F32) => asm.neon_fmin(2, 0, 1, *is_quad),
                    (NeonOp::Max, NeonSize::F32) => asm.neon_fmax(2, 0, 1, *is_quad),
                    (NeonOp::Abs, NeonSize::F32) => asm.neon_fabs(2, 1, *is_quad),
                    (NeonOp::Neg, NeonSize::F32) => asm.neon_fneg(2, 1, *is_quad),

                    // Vector Bitwise operations
                    (NeonOp::And, _) => asm.neon_and(2, 0, 1, *is_quad),
                    (NeonOp::Orr, _) => asm.neon_orr(2, 0, 1, *is_quad),
                    (NeonOp::Eor, _) => asm.neon_eor(2, 0, 1, *is_quad),
                    (NeonOp::Bic, _) => asm.neon_bic(2, 0, 1, *is_quad),

                    // Vector Integer operations
                    (NeonOp::Add, _) => asm.neon_add_int(2, 0, 1, *is_quad),
                    (NeonOp::Sub, _) => asm.neon_sub_int(2, 0, 1, *is_quad),
                    (NeonOp::Mul, _) => asm.neon_mul_int(2, 0, 1, *is_quad),
                    (NeonOp::Mla, _) => {
                        let sz = match size {
                            NeonSize::I8 => 0,
                            NeonSize::I16 => 1,
                            _ => 2,
                        };
                        asm.neon_mla_int(2, 0, 1, *is_quad, sz);
                    }
                    (NeonOp::Mls, _) => {
                        let sz = match size {
                            NeonSize::I8 => 0,
                            NeonSize::I16 => 1,
                            _ => 2,
                        };
                        asm.neon_mls_int(2, 0, 1, *is_quad, sz);
                    }

                    // Saturating operations
                    (NeonOp::Sqadd, _) => {
                        let sz = match size {
                            NeonSize::I8 => 0,
                            NeonSize::I16 => 1,
                            _ => 2,
                        };
                        asm.neon_sqadd(2, 0, 1, sz, *is_quad);
                    }
                    (NeonOp::Uqadd, _) => {
                        let sz = match size {
                            NeonSize::I8 => 0,
                            NeonSize::I16 => 1,
                            _ => 2,
                        };
                        asm.neon_uqadd(2, 0, 1, sz, *is_quad);
                    }
                    (NeonOp::Sqsub, _) => {
                        let sz = match size {
                            NeonSize::I8 => 0,
                            NeonSize::I16 => 1,
                            _ => 2,
                        };
                        asm.neon_sqsub(2, 0, 1, sz, *is_quad);
                    }
                    (NeonOp::Uqsub, _) => {
                        let sz = match size {
                            NeonSize::I8 => 0,
                            NeonSize::I16 => 1,
                            _ => 2,
                        };
                        asm.neon_uqsub(2, 0, 1, sz, *is_quad);
                    }
                    (NeonOp::Sqshl, _) => {
                        let sz = match size {
                            NeonSize::I8 => 0,
                            NeonSize::I16 => 1,
                            _ => 2,
                        };
                        asm.neon_sqshl(2, 0, 1, sz, *is_quad);
                    }
                    (NeonOp::Uqshl, _) => {
                        let sz = match size {
                            NeonSize::I8 => 0,
                            NeonSize::I16 => 1,
                            _ => 2,
                        };
                        asm.neon_uqshl(2, 0, 1, sz, *is_quad);
                    }

                    // Pairwise reductions (Stage 45)
                    (NeonOp::Padd, NeonSize::F32) => asm.neon_faddp(2, 0, 1, *is_quad),
                    (NeonOp::Pmax, NeonSize::F32) => asm.neon_fmaxp(2, 0, 1, *is_quad),
                    (NeonOp::Pmin, NeonSize::F32) => asm.neon_fminp(2, 0, 1, *is_quad),
                    (NeonOp::Padd, _) => {
                        let sz = match size {
                            NeonSize::I8 => 0,
                            NeonSize::I16 => 1,
                            _ => 2,
                        };
                        asm.neon_addp(2, 0, 1, sz, *is_quad);
                    }
                    (NeonOp::Pmax, _) => {
                        let sz = match size {
                            NeonSize::I8 => 0,
                            NeonSize::I16 => 1,
                            _ => 2,
                        };
                        asm.neon_smaxp(2, 0, 1, sz, *is_quad);
                    }
                    (NeonOp::Pmin, _) => {
                        let sz = match size {
                            NeonSize::I8 => 0,
                            NeonSize::I16 => 1,
                            _ => 2,
                        };
                        asm.neon_sminp(2, 0, 1, sz, *is_quad);
                    }
                    (NeonOp::Upmax, _) => {
                        let sz = match size {
                            NeonSize::I8 => 0,
                            NeonSize::I16 => 1,
                            _ => 2,
                        };
                        asm.neon_umaxp(2, 0, 1, sz, *is_quad);
                    }
                    (NeonOp::Upmin, _) => {
                        let sz = match size {
                            NeonSize::I8 => 0,
                            NeonSize::I16 => 1,
                            _ => 2,
                        };
                        asm.neon_uminp(2, 0, 1, sz, *is_quad);
                    }

                    // Fallback
                    _ => asm.neon_and(2, 0, 1, *is_quad),
                }

                // Store result
                if *is_quad {
                    asm.add_x_imm(A64Reg::X9, A64Reg::X0, dst_off as u16);
                    asm.str_q_imm(2, A64Reg::X9, 0);
                } else {
                    asm.str_d_imm(2, A64Reg::X0, dst_off);
                }
            }
            Op::NeonLoadStore {
                is_load,
                structure_elements,
                reg_count,
                stride,
                size,
                first_reg,
                rn,
                writeback,
            } => {
                let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);
                asm.add_x_uxtw(A64Reg::X10, A64Reg::X1, rn_reg);
                let sz = match size {
                    NeonSize::I8 => 0,
                    NeonSize::I16 => 1,
                    _ => 2,
                };

                if *structure_elements == 2 && *reg_count == 4 {
                    // 2 quadword registers (128-bit each)
                    let vfp_off0 = (OFFSET_VFP + (*first_reg as usize) * 8) as u16;
                    let vfp_off1 = (OFFSET_VFP + ((*first_reg + 2) as usize) * 8) as u16;

                    if *is_load {
                        asm.neon_ld2(1, sz, A64Reg::X10, 0);
                        asm.add_x_imm(A64Reg::X9, A64Reg::X0, vfp_off0);
                        asm.str_q_imm(0, A64Reg::X9, 0);
                        asm.add_x_imm(A64Reg::X9, A64Reg::X0, vfp_off1);
                        asm.str_q_imm(1, A64Reg::X9, 0);
                    } else {
                        asm.add_x_imm(A64Reg::X9, A64Reg::X0, vfp_off0);
                        asm.ldr_q_imm(0, A64Reg::X9, 0);
                        asm.add_x_imm(A64Reg::X9, A64Reg::X0, vfp_off1);
                        asm.ldr_q_imm(1, A64Reg::X9, 0);
                        asm.neon_st2(1, sz, A64Reg::X10, 0);
                    }
                } else if *structure_elements == 1 {
                    // Sequential transfer without interleaving (VLD1 / VST1)
                    if *is_load {
                        let opcode = match *reg_count {
                            1 => 0b0111,
                            2 => 0b1010,
                            3 => 0b0110,
                            _ => 0b0010,
                        };
                        asm.neon_ld1_mult(0, opcode, sz, A64Reg::X10, 0);
                        for i in 0..*reg_count {
                            let d_idx = *first_reg + i * stride;
                            let vfp_off = (OFFSET_VFP + (d_idx as usize) * 8) as u32;
                            asm.str_d_imm(i, A64Reg::X0, vfp_off);
                        }
                    } else {
                        for i in 0..*reg_count {
                            let d_idx = *first_reg + i * stride;
                            let vfp_off = (OFFSET_VFP + (d_idx as usize) * 8) as u32;
                            asm.ldr_d_imm(i, A64Reg::X0, vfp_off);
                        }
                        let opcode = match *reg_count {
                            1 => 0b0111,
                            2 => 0b1010,
                            3 => 0b0110,
                            _ => 0b0010,
                        };
                        asm.neon_st1_mult(0, opcode, sz, A64Reg::X10, 0);
                    }
                } else {
                    // Standard 2, 3, or 4 D registers interleaved
                    if *is_load {
                        match *structure_elements {
                            2 => asm.neon_ld2(0, sz, A64Reg::X10, 0),
                            3 => asm.neon_ld3(0, sz, A64Reg::X10, 0),
                            _ => asm.neon_ld4(0, sz, A64Reg::X10, 0),
                        }
                        for i in 0..*reg_count {
                            let d_idx = *first_reg + i * stride;
                            let vfp_off = (OFFSET_VFP + (d_idx as usize) * 8) as u32;
                            asm.str_d_imm(i, A64Reg::X0, vfp_off);
                        }
                    } else {
                        for i in 0..*reg_count {
                            let d_idx = *first_reg + i * stride;
                            let vfp_off = (OFFSET_VFP + (d_idx as usize) * 8) as u32;
                            asm.ldr_d_imm(i, A64Reg::X0, vfp_off);
                        }
                        match *structure_elements {
                            2 => asm.neon_st2(0, sz, A64Reg::X10, 0),
                            3 => asm.neon_st3(0, sz, A64Reg::X10, 0),
                            _ => asm.neon_st4(0, sz, A64Reg::X10, 0),
                        }
                    }
                }

                // Writeback
                match writeback {
                    NeonWriteback::None => {},
                    NeonWriteback::PostInc => {
                        let total_bytes = (*reg_count as u16) * 8;
                        let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);
                        asm.add_x_imm(A64Reg::X9, rn_reg, total_bytes);
                        store_guest_reg(asm, A64Reg::X9, *rn);
                    }
                    NeonWriteback::Reg(rm) => {
                        let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);
                        let rm_reg = load_guest_reg(asm, A64Reg::X11, *rm);
                        asm.add_x_uxtw(A64Reg::X9, rn_reg, rm_reg);
                        store_guest_reg(asm, A64Reg::X9, *rn);
                    }
                }
            }
            Op::NeonLoadStoreLane {
                is_load,
                structure_elements,
                all_lanes,
                lane: _,
                size,
                first_reg,
                stride,
                rn,
                writeback,
            } => {
                let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);
                asm.add_x_uxtw(A64Reg::X10, A64Reg::X1, rn_reg);
                let sz = match size {
                    NeonSize::I8 => 0,
                    NeonSize::I16 => 1,
                    _ => 2,
                };
                let elem_bytes = match size {
                    NeonSize::I8 => 1u16,
                    NeonSize::I16 => 2u16,
                    _ => 4u16,
                };

                if *all_lanes && *is_load {
                    match *structure_elements {
                        1 => asm.neon_ld1r(0, sz, A64Reg::X10, 0),
                        2 => asm.neon_ld2r(0, sz, A64Reg::X10, 0),
                        3 => asm.neon_ld3r(0, sz, A64Reg::X10, 0),
                        _ => asm.neon_ld4r(0, sz, A64Reg::X10, 0),
                    }
                    for i in 0..*structure_elements {
                        let d_idx = *first_reg + i * stride;
                        let vfp_off = (OFFSET_VFP + (d_idx as usize) * 8) as u32;
                        asm.str_d_imm(i, A64Reg::X0, vfp_off);
                    }
                }

                // Writeback
                let transferred = (*structure_elements as u16) * elem_bytes;
                match writeback {
                    NeonWriteback::None => {},
                    NeonWriteback::PostInc => {
                        let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);
                        asm.add_x_imm(A64Reg::X9, rn_reg, transferred);
                        store_guest_reg(asm, A64Reg::X9, *rn);
                    }
                    NeonWriteback::Reg(rm) => {
                        let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);
                        let rm_reg = load_guest_reg(asm, A64Reg::X11, *rm);
                        asm.add_x_uxtw(A64Reg::X9, rn_reg, rm_reg);
                        store_guest_reg(asm, A64Reg::X9, *rn);
                    }
                }
            }
            Op::NeonPermute {
                op,
                size,
                is_quad,
                vd,
                vm,
            } => {
                let vd_off = (OFFSET_VFP + (*vd as usize) * 8) as u32;
                let vm_off = (OFFSET_VFP + (*vm as usize) * 8) as u32;

                if *is_quad {
                    asm.add_x_imm(A64Reg::X9, A64Reg::X0, vd_off as u16);
                    asm.ldr_q_imm(0, A64Reg::X9, 0);
                    asm.add_x_imm(A64Reg::X10, A64Reg::X0, vm_off as u16);
                    asm.ldr_q_imm(1, A64Reg::X10, 0);
                } else {
                    asm.ldr_d_imm(0, A64Reg::X0, vd_off);
                    asm.ldr_d_imm(1, A64Reg::X0, vm_off);
                }

                let sz = match size {
                    NeonSize::I8 => 0,
                    NeonSize::I16 => 1,
                    _ => 2,
                };

                match op {
                    NeonPermuteOp::Trn => {
                        asm.neon_trn1(2, 0, 1, sz, *is_quad);
                        asm.neon_trn2(3, 0, 1, sz, *is_quad);
                    }
                    NeonPermuteOp::Zip => {
                        asm.neon_zip1(2, 0, 1, sz, *is_quad);
                        asm.neon_zip2(3, 0, 1, sz, *is_quad);
                    }
                    NeonPermuteOp::Uzp => {
                        asm.neon_uzp1(2, 0, 1, sz, *is_quad);
                        asm.neon_uzp2(3, 0, 1, sz, *is_quad);
                    }
                }

                if *is_quad {
                    asm.add_x_imm(A64Reg::X9, A64Reg::X0, vd_off as u16);
                    asm.str_q_imm(2, A64Reg::X9, 0);
                    asm.add_x_imm(A64Reg::X10, A64Reg::X0, vm_off as u16);
                    asm.str_q_imm(3, A64Reg::X10, 0);
                } else {
                    asm.str_d_imm(2, A64Reg::X0, vd_off);
                    asm.str_d_imm(3, A64Reg::X0, vm_off);
                }
            }
            Op::NeonPolyMul { vd, vn, vm } => {
                let vd_off = (OFFSET_VFP + (*vd as usize) * 8) as u32;
                let vn_off = (OFFSET_VFP + (*vn as usize) * 8) as u32;
                let vm_off = (OFFSET_VFP + (*vm as usize) * 8) as u32;

                asm.ldr_d_imm(0, A64Reg::X0, vn_off);
                asm.ldr_d_imm(1, A64Reg::X0, vm_off);
                asm.neon_pmull(2, 0, 1);

                asm.add_x_imm(A64Reg::X9, A64Reg::X0, vd_off as u16);
                asm.str_q_imm(2, A64Reg::X9, 0);
            }
            Op::NeonExtract {
                is_quad,
                imm,
                vd,
                vn,
                vm,
            } => {
                let vn_off = (OFFSET_VFP + (*vn as usize) * 8) as u32;
                let vm_off = (OFFSET_VFP + (*vm as usize) * 8) as u32;
                let vd_off = (OFFSET_VFP + (*vd as usize) * 8) as u32;

                if *is_quad {
                    asm.add_x_imm(A64Reg::X9, A64Reg::X0, vn_off as u16);
                    asm.ldr_q_imm(0, A64Reg::X9, 0);
                    asm.add_x_imm(A64Reg::X10, A64Reg::X0, vm_off as u16);
                    asm.ldr_q_imm(1, A64Reg::X10, 0);
                    asm.neon_ext(2, 0, 1, *imm, true);
                    asm.add_x_imm(A64Reg::X9, A64Reg::X0, vd_off as u16);
                    asm.str_q_imm(2, A64Reg::X9, 0);
                } else {
                    asm.ldr_d_imm(0, A64Reg::X0, vn_off);
                    asm.ldr_d_imm(1, A64Reg::X0, vm_off);
                    asm.neon_ext(2, 0, 1, *imm, false);
                    asm.str_d_imm(2, A64Reg::X0, vd_off);
                }
            }
            Op::NeonRev {
                op,
                size,
                is_quad,
                vd,
                vm,
            } => {
                let vm_off = (OFFSET_VFP + (*vm as usize) * 8) as u32;
                let vd_off = (OFFSET_VFP + (*vd as usize) * 8) as u32;

                if *is_quad {
                    asm.add_x_imm(A64Reg::X9, A64Reg::X0, vm_off as u16);
                    asm.ldr_q_imm(0, A64Reg::X9, 0);
                } else {
                    asm.ldr_d_imm(0, A64Reg::X0, vm_off);
                }

                let sz = match size {
                    NeonSize::I8 => 0,
                    NeonSize::I16 => 1,
                    _ => 2,
                };

                match op {
                    NeonRevOp::Rev64 => asm.neon_rev64(2, 0, sz, *is_quad),
                    NeonRevOp::Rev32 => asm.neon_rev32(2, 0, sz, *is_quad),
                    NeonRevOp::Rev16 => asm.neon_rev16(2, 0, *is_quad),
                }

                if *is_quad {
                    asm.add_x_imm(A64Reg::X9, A64Reg::X0, vd_off as u16);
                    asm.str_q_imm(2, A64Reg::X9, 0);
                } else {
                    asm.str_d_imm(2, A64Reg::X0, vd_off);
                }
            }
            Op::NeonDupScalar {
                size,
                index,
                is_quad,
                vd,
                vm,
            } => {
                let vm_off = (OFFSET_VFP + (*vm as usize) * 8) as u32;
                let vd_off = (OFFSET_VFP + (*vd as usize) * 8) as u32;

                // Load source D register into V0
                asm.ldr_d_imm(0, A64Reg::X0, vm_off);

                let imm5 = match size {
                    NeonSize::I8 => (index << 1) | 1,
                    NeonSize::I16 => (index << 2) | 2,
                    _ => (index << 3) | 4,
                };

                asm.neon_dup_element(2, 0, imm5, *is_quad);

                if *is_quad {
                    asm.add_x_imm(A64Reg::X9, A64Reg::X0, vd_off as u16);
                    asm.str_q_imm(2, A64Reg::X9, 0);
                } else {
                    asm.str_d_imm(2, A64Reg::X0, vd_off);
                }
            }
            Op::NeonDupCore {
                size,
                is_quad,
                vd,
                rt,
            } => {
                let vd_off = (OFFSET_VFP + (*vd as usize) * 8) as u32;
                let src_reg = load_guest_reg(asm, A64Reg::X9, *rt);

                let imm5 = match size {
                    NeonSize::I8 => 1,
                    NeonSize::I16 => 2,
                    _ => 4,
                };

                asm.neon_dup_core(2, src_reg, imm5, *is_quad);

                if *is_quad {
                    asm.add_x_imm(A64Reg::X9, A64Reg::X0, vd_off as u16);
                    asm.str_q_imm(2, A64Reg::X9, 0);
                } else {
                    asm.str_d_imm(2, A64Reg::X0, vd_off);
                }
            }
            Op::NeonShiftNarrow {
                signed,
                dest_unsigned,
                saturate,
                src_size,
                shift,
                vd,
                vm,
            } => {
                let vm_off = (OFFSET_VFP + (*vm as usize) * 8) as u32;
                let vd_off = (OFFSET_VFP + (*vd as usize) * 8) as u32;

                asm.add_x_imm(A64Reg::X9, A64Reg::X0, vm_off as u16);
                asm.ldr_q_imm(0, A64Reg::X9, 0);

                let sz = match src_size {
                    NeonSize::I16 => 0,
                    NeonSize::I32 => 1,
                    _ => 2,
                };

                if *shift == 0 {
                    if !*saturate {
                        asm.neon_xtn(2, 0, sz);
                    } else if *dest_unsigned && *signed {
                        asm.neon_sqxtun(2, 0, sz);
                    } else if *signed {
                        asm.neon_sqxtn(2, 0, sz);
                    } else {
                        asm.neon_uqxtn(2, 0, sz);
                    }
                } else {
                    if !*saturate {
                        asm.neon_shrn(2, 0, sz, *shift);
                    } else if *dest_unsigned && *signed {
                        asm.neon_sqshrun(2, 0, sz, *shift);
                    } else if *signed {
                        asm.neon_sqshrn(2, 0, sz, *shift);
                    } else {
                        asm.neon_uqshrn(2, 0, sz, *shift);
                    }
                }

                asm.str_d_imm(2, A64Reg::X0, vd_off);
            }
            Op::NeonShiftWiden {
                signed,
                src_size,
                shift,
                vd,
                vm,
            } => {
                let vm_off = (OFFSET_VFP + (*vm as usize) * 8) as u32;
                let vd_off = (OFFSET_VFP + (*vd as usize) * 8) as u32;

                asm.ldr_d_imm(0, A64Reg::X0, vm_off);

                let size_shift = match src_size {
                    NeonSize::I8 => 3,
                    NeonSize::I16 => 4,
                    _ => 5,
                };

                if *signed {
                    asm.neon_sshll(2, 0, size_shift, *shift);
                } else {
                    asm.neon_ushll(2, 0, size_shift, *shift);
                }

                asm.add_x_imm(A64Reg::X9, A64Reg::X0, vd_off as u16);
                asm.str_q_imm(2, A64Reg::X9, 0);
            }
            Op::NeonCvt {
                op,
                is_quad,
                vd,
                vm,
            } => {
                let vm_off = (OFFSET_VFP + (*vm as usize) * 8) as u32;
                let vd_off = (OFFSET_VFP + (*vd as usize) * 8) as u32;

                if *is_quad {
                    asm.add_x_imm(A64Reg::X9, A64Reg::X0, vm_off as u16);
                    asm.ldr_q_imm(0, A64Reg::X9, 0);
                } else {
                    asm.ldr_d_imm(0, A64Reg::X0, vm_off);
                }

                match op {
                    NeonCvtOp::F32FromS32 => asm.neon_scvtf(2, 0, *is_quad),
                    NeonCvtOp::F32FromU32 => asm.neon_ucvtf(2, 0, *is_quad),
                    NeonCvtOp::S32FromF32 => asm.neon_fcvtzs(2, 0, *is_quad),
                    NeonCvtOp::U32FromF32 => asm.neon_fcvtzu(2, 0, *is_quad),
                }

                if *is_quad {
                    asm.add_x_imm(A64Reg::X9, A64Reg::X0, vd_off as u16);
                    asm.str_q_imm(2, A64Reg::X9, 0);
                } else {
                    asm.str_d_imm(2, A64Reg::X0, vd_off);
                }
            }
            Op::VfpMovImm { dst, val_bits, is_double } => {
                let vfp_off = Self::vfp_offset(dst);
                if *is_double {
                    asm.mov_imm64(A64Reg::X9, *val_bits);
                    asm.str_x_imm(A64Reg::X9, A64Reg::X0, vfp_off);
                } else {
                    asm.mov_imm32(A64Reg::X9, *val_bits as u32);
                    asm.str_w_imm(A64Reg::X9, A64Reg::X0, vfp_off);
                }
            }
            Op::NeonMovImm { dst, is_quad, val64 } => {
                let d0 = *dst as usize;
                if d0 < 32 {
                    let vfp_off0 = (OFFSET_VFP + d0 * 8) as u32;
                    asm.mov_imm64(A64Reg::X9, *val64);
                    asm.str_x_imm(A64Reg::X9, A64Reg::X0, vfp_off0);
                    if *is_quad && d0 + 1 < 32 {
                        let vfp_off1 = (OFFSET_VFP + (d0 + 1) * 8) as u32;
                        asm.str_x_imm(A64Reg::X9, A64Reg::X0, vfp_off1);
                    }
                }
            }
            Op::NeonMovCoreLane { to_core, core_reg, d_reg, lane } => {
                let off = (OFFSET_VFP + (*d_reg as usize) * 8 + (*lane as usize) * 4) as u32;
                if *to_core {
                    asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, off);
                    store_guest_reg(asm, A64Reg::X9, *core_reg);
                } else {
                    let src = load_guest_reg(asm, A64Reg::X9, *core_reg);
                    asm.str_w_imm(src, A64Reg::X0, off);
                }
            }
            _ => {
                // Branches and exchanges are fully handled in compile_exit; avoid spurious NOPs
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
                let site_offset = asm.cursor() * 4;
                patch_sites.push(PatchSite {
                    byte_offset: site_offset,
                    target: PatchTarget::Direct(*target),
                });

                // Default unchained fallback: returns target in X0 with EXIT_REASON_DIRECT (0)
                asm.mov_imm32(A64Reg::X9, target.as_u32());
                Self::emit_epilogue(asm);
                asm.mov_x_reg(A64Reg::X0, A64Reg::X9);
                asm.ret(None);
            }
            BlockExit::BranchCond {
                cond,
                target,
                fallthrough,
            } => {
                // 1. Conditional branch patch site to taken path
                let taken_site_offset = asm.cursor() * 4;
                patch_sites.push(PatchSite {
                    byte_offset: taken_site_offset,
                    target: PatchTarget::BranchTaken {
                        cond: *cond,
                        target: *target,
                    },
                });
                let b_cond_idx = asm.cursor();
                asm.b_cond(*cond, 0); // Placeholder, will patch with offset to taken fallback below

                // 2. Fallthrough path:
                let ft_site_offset = asm.cursor() * 4;
                patch_sites.push(PatchSite {
                    byte_offset: ft_site_offset,
                    target: PatchTarget::BranchFallthrough(*fallthrough),
                });
                asm.mov_imm32(A64Reg::X9, fallthrough.as_u32());
                Self::emit_epilogue(asm);
                asm.mov_x_reg(A64Reg::X0, A64Reg::X9);
                asm.ret(None);

                // 3. Taken path fallback:
                let taken_target_idx = asm.cursor();
                let offset_words = (taken_target_idx as i32) - (b_cond_idx as i32);
                let imm19 = (offset_words as u32) & 0x7FFFF;
                let cond_field = (*cond as u32) & 0xF;
                asm.patch(b_cond_idx, 0x5400_0000 | (imm19 << 5) | cond_field);

                asm.mov_imm32(A64Reg::X9, target.as_u32());
                Self::emit_epilogue(asm);
                asm.mov_x_reg(A64Reg::X0, A64Reg::X9);
                asm.ret(None);
            }
            BlockExit::Indirect(rm) => {
                let rm_reg = load_guest_reg(asm, A64Reg::X9, *rm);
                if rm_reg != A64Reg::X9 {
                    asm.mov_w_reg(A64Reg::X9, rm_reg);
                }
                asm.movk_x(A64Reg::X9, EXIT_REASON_INDIRECT as u16, 32);
                Self::emit_epilogue(asm);
                asm.mov_x_reg(A64Reg::X0, A64Reg::X9);
                asm.ret(None);
            }
            BlockExit::IndirectCond { cond, rm, fallthrough } => {
                let b_cond_idx = asm.cursor();
                asm.b_cond(*cond, 0);

                // Fallthrough path:
                asm.mov_imm32(A64Reg::X9, fallthrough.as_u32());
                Self::emit_epilogue(asm);
                asm.mov_x_reg(A64Reg::X0, A64Reg::X9);
                asm.ret(None);

                // Taken path (indirect branch to rm):
                let taken_target_idx = asm.cursor();
                let offset_words = (taken_target_idx as i32) - (b_cond_idx as i32);
                let imm19 = (offset_words as u32) & 0x7FFFF;
                let cond_field = (*cond as u32) & 0xF;
                asm.patch(b_cond_idx, 0x5400_0000 | (imm19 << 5) | cond_field);

                let rm_reg = load_guest_reg(asm, A64Reg::X9, *rm);
                if rm_reg != A64Reg::X9 {
                    asm.mov_w_reg(A64Reg::X9, rm_reg);
                }
                asm.movk_x(A64Reg::X9, EXIT_REASON_INDIRECT as u16, 32);
                Self::emit_epilogue(asm);
                asm.mov_x_reg(A64Reg::X0, A64Reg::X9);
                asm.ret(None);
            }
            BlockExit::Svc { imm, next_pc } => {
                asm.mov_imm32(A64Reg::X10, next_pc.as_u32());
                asm.str_w_imm(A64Reg::X10, A64Reg::X0, OFFSET_PC as u32);
                asm.mov_imm64(A64Reg::X9, (EXIT_REASON_SVC << 32) | (*imm as u64));
                Self::emit_epilogue(asm);
                asm.mov_x_reg(A64Reg::X0, A64Reg::X9);
                asm.ret(None);
            }
            BlockExit::Bkpt { imm, next_pc } => {
                asm.mov_imm32(A64Reg::X10, next_pc.as_u32());
                asm.str_w_imm(A64Reg::X10, A64Reg::X0, OFFSET_PC as u32);
                asm.mov_imm64(A64Reg::X9, (EXIT_REASON_BKPT << 32) | (*imm as u64));
                Self::emit_epilogue(asm);
                asm.mov_x_reg(A64Reg::X0, A64Reg::X9);
                asm.ret(None);
            }
            BlockExit::Invalid(addr) => {
                asm.mov_imm64(A64Reg::X9, (EXIT_REASON_INVALID << 32) | (addr.as_u32() as u64));
                Self::emit_epilogue(asm);
                asm.mov_x_reg(A64Reg::X0, A64Reg::X9);
                asm.ret(None);
            }
            BlockExit::CompareBranch {
                is_nonzero,
                rn,
                target,
                fallthrough,
            } => {
                let rn_reg = load_guest_reg(asm, A64Reg::X11, *rn);
                let cb_idx = asm.cursor();
                if *is_nonzero {
                    asm.cbnz_w(rn_reg, 0);
                } else {
                    asm.cbz_w(rn_reg, 0);
                }

                // Fallthrough path
                let ft_site_offset = asm.cursor() * 4;
                patch_sites.push(PatchSite {
                    byte_offset: ft_site_offset,
                    target: PatchTarget::BranchFallthrough(*fallthrough),
                });
                asm.mov_imm32(A64Reg::X9, fallthrough.as_u32());
                Self::emit_epilogue(asm);
                asm.mov_x_reg(A64Reg::X0, A64Reg::X9);
                asm.ret(None);

                // Taken path
                let taken_target_idx = asm.cursor();
                let offset_words = (taken_target_idx as i32) - (cb_idx as i32);
                let imm19 = (offset_words as u32) & 0x7FFFF;
                let op_code = if *is_nonzero { 0x3500_0000 } else { 0x3400_0000 };
                asm.patch(cb_idx, op_code | (imm19 << 5) | rn_reg.index());

                let taken_site_offset = asm.cursor() * 4;
                patch_sites.push(PatchSite {
                    byte_offset: taken_site_offset,
                    target: PatchTarget::Direct(*target),
                });
                asm.mov_imm32(A64Reg::X9, target.as_u32());
                Self::emit_epilogue(asm);
                asm.mov_x_reg(A64Reg::X0, A64Reg::X9);
                asm.ret(None);
            }
            BlockExit::TableBranch {
                is_halfword,
                rn,
                rm,
                inst_pc,
            } => {
                if *rn == Reg::PC {
                    let pc_val = (inst_pc.as_u32() + 4) & !3;
                    asm.mov_imm32(A64Reg::X12, pc_val);
                } else {
                    let rn_reg = load_guest_reg(asm, A64Reg::X12, *rn);
                    if rn_reg != A64Reg::X12 {
                        asm.mov_w_reg(A64Reg::X12, rn_reg);
                    }
                }
                let rm_reg = load_guest_reg(asm, A64Reg::X10, *rm);
                if *is_halfword {
                    asm.lsl_w_imm(A64Reg::X10, rm_reg, 1);
                    asm.add_w_reg(A64Reg::X12, A64Reg::X12, A64Reg::X10);
                    asm.ldrh_w_uxtw(A64Reg::X10, A64Reg::X1, A64Reg::X12);
                } else {
                    asm.add_w_reg(A64Reg::X12, A64Reg::X12, rm_reg);
                    asm.ldrb_w_uxtw(A64Reg::X10, A64Reg::X1, A64Reg::X12);
                }
                asm.lsl_w_imm(A64Reg::X10, A64Reg::X10, 1);
                asm.mov_imm32(A64Reg::X9, inst_pc.as_u32() + 4);
                asm.add_w_reg(A64Reg::X9, A64Reg::X9, A64Reg::X10);
                asm.movk_x(A64Reg::X9, EXIT_REASON_INDIRECT as u16, 32);
                Self::emit_epilogue(asm);
                asm.mov_x_reg(A64Reg::X0, A64Reg::X9);
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
    fn test_prologue_epilogue_size() {
        let mut asm = A64Assembler::new();
        A64Compiler::emit_prologue(&mut asm);
        assert_eq!(asm.to_bytes().len(), PROLOGUE_BYTE_SIZE);

        let mut asm_epi = A64Assembler::new();
        A64Compiler::emit_epilogue(&mut asm_epi);
        assert_eq!(asm_epi.to_bytes().len(), 32);
    }

    #[test]
    fn test_pinned_registers_mapping() {
        assert_eq!(pinned_reg(Reg::R0), Some(A64Reg::X19));
        assert_eq!(pinned_reg(Reg::R1), Some(A64Reg::X20));
        assert_eq!(pinned_reg(Reg::R2), Some(A64Reg::X21));
        assert_eq!(pinned_reg(Reg::R3), Some(A64Reg::X22));
        assert_eq!(pinned_reg(Reg::R4), Some(A64Reg::X23));
        assert_eq!(pinned_reg(Reg::R5), Some(A64Reg::X24));
        assert_eq!(pinned_reg(Reg::R6), Some(A64Reg::X25));
        assert_eq!(pinned_reg(Reg::R7), Some(A64Reg::X26));
        assert_eq!(pinned_reg(Reg::R8), None);
        assert_eq!(pinned_reg(Reg::SP), None);
        assert_eq!(pinned_reg(Reg::LR), None);
        assert_eq!(pinned_reg(Reg::PC), None);
    }

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
        // Patch site is after prologue (32 bytes) + 1 instruction ADD (4 bytes) = byte 36
        assert_eq!(compiled.patch_sites[0].byte_offset, 36);
        assert!(!compiled.code_bytes.is_empty());
    }

    #[test]
    fn test_flag_elimination() {
        let mut block = IrBlock::new(GuestAddr::new(0x7000), false);
        // CMP r0, #0 -> dead because block.exit is Direct (unconditional)!
        block.insts.push(ArmInst::new(
            Cond::AL,
            Op::Alu {
                op: AluOp::Cmp,
                set_flags: true,
                rd: Reg::R0,
                rn: Reg::R0,
                op2: Operand2::Imm(0),
            },
            0,
        ));
        // ADD r0, r0, #1 (unconditional)
        block.insts.push(ArmInst::new(
            Cond::AL,
            Op::Alu {
                op: AluOp::Add,
                set_flags: false,
                rd: Reg::R0,
                rn: Reg::R0,
                op2: Operand2::Imm(1),
            },
            0,
        ));
        block.exit = BlockExit::Direct(GuestAddr::new(0x7008));

        let compiled = A64Compiler::compile(&block);
        // Byte size: prologue (32) + 1 inst ADD (4) [CMP was eliminated!] + exit fallback
        assert_eq!(compiled.patch_sites[0].byte_offset, 36);
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
        assert!(compiled.code_bytes.len() >= 48);
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

    #[test]
    fn test_compile_neon_quad_and_load_store() {
        let mut block = IrBlock::new(GuestAddr::new(0x8000), false);
        // VLD1 Q0, [r0] (2 D registers)
        block.insts.push(ArmInst::new(
            Cond::AL,
            Op::NeonLoadStore {
                is_load: true,
                structure_elements: 1,
                reg_count: 2,
                stride: 1,
                size: NeonSize::I32,
                first_reg: 0,
                rn: Reg::R0,
                writeback: NeonWriteback::None,
            },
            0,
        ));
        // VMUL.F32 Q2, Q0, Q1
        block.insts.push(ArmInst::new(
            Cond::AL,
            Op::NeonAlu {
                op: NeonOp::Mul,
                size: NeonSize::F32,
                is_quad: true,
                dst: 4,
                src1: 0,
                src2: 2,
            },
            0,
        ));
        // VMLA.F32 Q2, Q0, Q1
        block.insts.push(ArmInst::new(
            Cond::AL,
            Op::NeonAlu {
                op: NeonOp::Mla,
                size: NeonSize::F32,
                is_quad: true,
                dst: 4,
                src1: 0,
                src2: 2,
            },
            0,
        ));
        // VST1 Q2, [r1] (2 D registers)
        block.insts.push(ArmInst::new(
            Cond::AL,
            Op::NeonLoadStore {
                is_load: false,
                structure_elements: 1,
                reg_count: 2,
                stride: 1,
                size: NeonSize::I32,
                first_reg: 4,
                rn: Reg::R1,
                writeback: NeonWriteback::None,
            },
            0,
        ));
        block.exit = BlockExit::Direct(GuestAddr::new(0x8010));

        let compiled = A64Compiler::compile(&block);
        assert_eq!(compiled.inst_count, 4);
        assert!(!compiled.code_bytes.is_empty());
        assert_eq!(compiled.patch_sites.len(), 1);
    }

    #[test]
    fn test_compile_superblock_with_side_exit_and_loop() {
        use transd_ir::SideExit;

        let mut sb = Superblock::new(GuestAddr::new(0x2000), false);
        // SUBS r0, r0, #1
        sb.insts.push(ArmInst::new(
            Cond::AL,
            Op::Alu {
                op: AluOp::Sub,
                set_flags: true,
                rd: Reg::R0,
                rn: Reg::R0,
                op2: Operand2::Imm(1),
            },
            0,
        ));
        // Side exit guard at inst 0: if EQ bail to 0x2010
        sb.side_exits.push(SideExit {
            inst_index: 0,
            cond: Cond::EQ,
            target: GuestAddr::new(0x2010),
        });
        // Loop backedge to 0x2000
        sb.is_loop = true;
        sb.exit = BlockExit::Direct(GuestAddr::new(0x2000));
        sb.byte_size = 8;

        let compiled = A64Compiler::compile_superblock(&sb);
        assert_eq!(compiled.guest_entry, GuestAddr::new(0x2000));
        assert!(!compiled.code_bytes.is_empty());
        assert!(!compiled.patch_sites.is_empty());
    }

    #[test]
    fn test_compile_coresat_and_bitsat() {
        let mut block = IrBlock::new(GuestAddr::new(0x5000), false);
        // QADD r0, r1, r2
        block.insts.push(ArmInst::new(
            Cond::AL,
            Op::CoreSat {
                op: CoreSatOp::Qadd,
                rd: Reg::R0,
                rm: Reg::R1,
                rn: Reg::R2,
            },
            0,
        ));
        // QDADD r3, r4, r5
        block.insts.push(ArmInst::new(
            Cond::AL,
            Op::CoreSat {
                op: CoreSatOp::Qdadd,
                rd: Reg::R3,
                rm: Reg::R4,
                rn: Reg::R5,
            },
            0,
        ));
        // SSAT r6, #16, r7
        block.insts.push(ArmInst::new(
            Cond::AL,
            Op::BitSat {
                op: BitSatOp::Ssat {
                    sat_imm: 16,
                    shift_type: ShiftType::Lsl,
                    shift_imm: 0,
                },
                rd: Reg::R6,
                rn: Reg::R7,
            },
            0,
        ));
        // USAT16 r0, #8, r1
        block.insts.push(ArmInst::new(
            Cond::AL,
            Op::BitSat {
                op: BitSatOp::Usat16 {
                    sat_imm: 8,
                },
                rd: Reg::R0,
                rn: Reg::R1,
            },
            0,
        ));
        block.exit = BlockExit::Direct(GuestAddr::new(0x5010));

        let compiled = A64Compiler::compile(&block);
        assert_eq!(compiled.inst_count, 4);
        assert!(!compiled.code_bytes.is_empty());
        assert_eq!(compiled.patch_sites.len(), 1);
    }
}
