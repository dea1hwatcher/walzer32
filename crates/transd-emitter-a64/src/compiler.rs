use transd_core::{
    Cond, GuestAddr, Reg, OFFSET_EXCLUSIVE, OFFSET_PC, OFFSET_TLS, OFFSET_VFP,
};
use transd_decoder::{
    AddrMode, AddrOffset, AluOp, ArmInst, BlockAddrMode, MemSize, MulOp, NeonOp, NeonSize, Op,
    Operand2, ShiftAmount, ShiftType, VfpOp, VfpReg, VfpSize,
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
        let flags_needed = matches!(block.exit, BlockExit::BranchCond { cond, .. } if !cond.is_always());
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
            Self::compile_inst(&mut asm, inst, idx, flags_needed, last_flag_idx);
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

            Self::compile_inst(&mut asm, inst, idx, true, None);
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

    fn compile_inst(
        asm: &mut A64Assembler,
        inst: &ArmInst,
        idx: usize,
        flags_needed: bool,
        last_flag_idx: Option<usize>,
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
                let effective_set_flags = flags_needed && (Some(idx) == last_flag_idx) && (*set_flags || op.is_test());
                if op.is_test() && !effective_set_flags {
                    // Dead test instruction eliminated!
                    return;
                }

                // 1. Destination register: if pinned, compute directly into pinned register with zero spills!
                let dst_reg = pinned_reg(*rd).unwrap_or(A64Reg::X11);

                // 2. Load rn: if pinned, returns host pinned register directly with 0 instructions
                let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);

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
                        let rm_reg = load_guest_reg(asm, A64Reg::X10, *rm);
                        match shift.amount {
                            ShiftAmount::Imm(shift_imm) => {
                                if shift_imm > 0 {
                                    match shift.shift_type {
                                        ShiftType::Lsl => asm.lsl_w_imm(A64Reg::X10, rm_reg, shift_imm),
                                        ShiftType::Lsr => asm.lsr_w_imm(A64Reg::X10, rm_reg, shift_imm),
                                        ShiftType::Asr => asm.asr_w_imm(A64Reg::X10, rm_reg, shift_imm),
                                        ShiftType::Ror => {
                                            asm.mov_imm32(A64Reg::X12, shift_imm as u32);
                                            asm.ror_w_reg(A64Reg::X10, rm_reg, A64Reg::X12);
                                        }
                                        ShiftType::Rrx => {}
                                    }
                                    A64Reg::X10
                                } else {
                                    rm_reg
                                }
                            }
                            ShiftAmount::Reg(rs) => {
                                let rs_reg = load_guest_reg(asm, A64Reg::X12, rs);
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
            Op::LoadStore {
                is_load,
                size,
                signed,
                rd,
                rn,
                addr_mode,
            } => {
                // 1. Load rn
                let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);

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
                        let rm_reg = load_guest_reg(asm, A64Reg::X10, *rm);
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
                    let src_reg = load_guest_reg(asm, A64Reg::X11, *rd);
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
                if *to_core {
                    asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, vfp_off);
                    store_guest_reg(asm, A64Reg::X9, *core_reg);
                } else {
                    let src = load_guest_reg(asm, A64Reg::X9, *core_reg);
                    asm.str_w_imm(src, A64Reg::X0, vfp_off);
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
            Op::Cp15Move { is_mrc, rd, .. } => {
                if *is_mrc {
                    asm.ldr_w_imm(A64Reg::X9, A64Reg::X0, OFFSET_TLS as u32);
                    store_guest_reg(asm, A64Reg::X9, *rd);
                } else {
                    let src = load_guest_reg(asm, A64Reg::X9, *rd);
                    asm.str_w_imm(src, A64Reg::X0, OFFSET_TLS as u32);
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
                is_quad,
                reg,
                rn,
            } => {
                let rn_reg = load_guest_reg(asm, A64Reg::X9, *rn);
                asm.add_x_uxtw(A64Reg::X10, A64Reg::X1, rn_reg);
                let vfp_off = (OFFSET_VFP + (*reg as usize) * 8) as u32;

                if *is_load {
                    if *is_quad {
                        asm.ldr_q_imm(0, A64Reg::X10, 0);
                        asm.add_x_imm(A64Reg::X9, A64Reg::X0, vfp_off as u16);
                        asm.str_q_imm(0, A64Reg::X9, 0);
                    } else {
                        asm.ldr_d_imm(0, A64Reg::X10, 0);
                        asm.str_d_imm(0, A64Reg::X0, vfp_off);
                    }
                } else {
                    if *is_quad {
                        asm.add_x_imm(A64Reg::X9, A64Reg::X0, vfp_off as u16);
                        asm.ldr_q_imm(0, A64Reg::X9, 0);
                        asm.str_q_imm(0, A64Reg::X10, 0);
                    } else {
                        asm.ldr_d_imm(0, A64Reg::X0, vfp_off);
                        asm.str_d_imm(0, A64Reg::X10, 0);
                    }
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
        // VLD1 Q0, [r0]
        block.insts.push(ArmInst::new(
            Cond::AL,
            Op::NeonLoadStore {
                is_load: true,
                is_quad: true,
                reg: 0,
                rn: Reg::R0,
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
        // VST1 Q2, [r1]
        block.insts.push(ArmInst::new(
            Cond::AL,
            Op::NeonLoadStore {
                is_load: false,
                is_quad: true,
                reg: 4,
                rn: Reg::R1,
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
}
