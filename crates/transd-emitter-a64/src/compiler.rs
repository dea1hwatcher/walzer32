use transd_core::{
    Cond, GuestAddr, OFFSET_PC,
};
use transd_decoder::{AluOp, ArmInst, Op, Operand2};
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

    fn compile_inst(asm: &mut A64Assembler, inst: &ArmInst) {
        match inst.op {
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

                // 2. Load op2 into w10
                match op2 {
                    Operand2::Imm(imm) => {
                        asm.mov_imm32(A64Reg::X10, imm);
                    }
                    Operand2::Reg { rm, .. } => {
                        let rm_offset = (rm.index() * 4) as u32;
                        asm.ldr_w_imm(A64Reg::X10, A64Reg::X0, rm_offset);
                    }
                }

                // 3. Perform ALU operation: w11 = w9 (op) w10
                match op {
                    AluOp::Add => {
                        if set_flags {
                            asm.adds_w_reg(A64Reg::X11, A64Reg::X9, A64Reg::X10);
                        } else {
                            asm.add_w_reg(A64Reg::X11, A64Reg::X9, A64Reg::X10);
                        }
                    }
                    AluOp::Sub => {
                        if set_flags {
                            asm.subs_w_reg(A64Reg::X11, A64Reg::X9, A64Reg::X10);
                        } else {
                            asm.sub_w_reg(A64Reg::X11, A64Reg::X9, A64Reg::X10);
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
                    AluOp::Cmp => {
                        asm.cmp_w_reg(A64Reg::X9, A64Reg::X10);
                    }
                    _ => {
                        asm.nop();
                    }
                }

                // 4. If not a test instruction, store w11 back into CpuState.regs[rd]
                if !op.is_test() {
                    let rd_offset = (rd.index() * 4) as u32;
                    asm.str_w_imm(A64Reg::X11, A64Reg::X0, rd_offset);
                }
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
    use transd_core::{FlatMemory, Memory};
    use transd_ir::Lifter;

    #[test]
    fn test_compile_basic_block_patch_sites() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x1000);

        // 0x1000: MOV r1, #10     (0xE3A0100A)
        // 0x1004: ADD r0, r1, #32 (0xE2810020)
        // 0x1008: B #+16          (0xEA000004) -> target 0x1020
        mem.write_u32(GuestAddr::new(0x1000), 0xE3A0_100A).unwrap();
        mem.write_u32(GuestAddr::new(0x1004), 0xE281_0020).unwrap();
        mem.write_u32(GuestAddr::new(0x1008), 0xEA00_0004).unwrap();

        let block = Lifter::lift_block(&mem, GuestAddr::new(0x1000), false).unwrap();
        let compiled = A64Compiler::compile(&block);

        assert_eq!(compiled.guest_entry, GuestAddr::new(0x1000));
        assert_eq!(compiled.inst_count, 3);
        assert_eq!(compiled.patch_sites.len(), 1);
        assert_eq!(
            compiled.patch_sites[0].target,
            PatchTarget::Direct(GuestAddr::new(0x1020))
        );
    }

    #[test]
    fn test_patch_branch_encoding() {
        let mut code = vec![0u8; 16];
        // Patch B #+4 (offset_words = 4)
        A64Compiler::patch_direct_branch(&mut code, 0, 4);
        let inst = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
        assert_eq!(inst, 0x1400_0004);

        // Patch B.NE #+2
        A64Compiler::patch_cond_branch(&mut code, 4, Cond::NE, 2);
        let inst2 = u32::from_le_bytes([code[4], code[5], code[6], code[7]]);
        assert_eq!(inst2, 0x5400_0041); // imm19=2 shifted by 5 -> 0x40, NE=1 -> 0x41
    }
}
