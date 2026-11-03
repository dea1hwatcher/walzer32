use transd_core::{GuestAddr, Memory, MemoryError, Reg};
use transd_decoder::{decode_next, AluOp, ArmInst, BranchTarget, Op, Operand2};
use crate::ir::{BlockExit, IrBlock};

pub const DEFAULT_MAX_BLOCK_INSTS: usize = 64;

pub struct Lifter;

impl Lifter {
    /// Lifts a contiguous basic block starting at `entry` until a control flow terminator
    pub fn lift_block(
        mem: &impl Memory,
        entry: GuestAddr,
        is_thumb: bool,
    ) -> Result<IrBlock, MemoryError> {
        Self::lift_block_with_limit(mem, entry, is_thumb, DEFAULT_MAX_BLOCK_INSTS)
    }

    pub fn lift_block_with_limit(
        mem: &impl Memory,
        entry: GuestAddr,
        is_thumb: bool,
        max_insts: usize,
    ) -> Result<IrBlock, MemoryError> {
        let mut block = IrBlock::new(entry, is_thumb);
        let mut cur_pc = entry;

        while block.insts.len() < max_insts {
            let (inst, len) = match decode_next(mem, cur_pc, is_thumb) {
                Ok(res) => res,
                Err(e) => {
                    if block.insts.is_empty() {
                        return Err(e);
                    } else {
                        block.exit = BlockExit::Invalid(cur_pc);
                        break;
                    }
                }
            };

            let next_pc = cur_pc.add(len as u32);
            block.insts.push(inst);
            block.inst_addrs.push(cur_pc);
            block.byte_size += len;

            // Check if this instruction terminates the basic block
            match inst.op {
                Op::Branch { link, target } => {
                    let target_addr = match target {
                        BranchTarget::Imm(offset) => {
                            let pc_base = if is_thumb { 4 } else { 8 };
                            cur_pc.add(pc_base).offset(offset)
                        }
                        BranchTarget::Reg(r) => {
                            if link {
                                let ret_addr = if is_thumb {
                                    next_pc.as_u32() | 1
                                } else {
                                    next_pc.as_u32()
                                };
                                block.insts.push(ArmInst::new(
                                    inst.cond,
                                    Op::Alu {
                                        op: AluOp::Mov,
                                        set_flags: false,
                                        rd: Reg::LR,
                                        rn: Reg::R0,
                                        op2: Operand2::Imm(ret_addr),
                                    },
                                    0,
                                ));
                                block.inst_addrs.push(cur_pc);
                            }
                            if inst.cond.is_always() {
                                block.exit = BlockExit::Indirect(r);
                            } else {
                                block.exit = BlockExit::IndirectCond {
                                    cond: inst.cond,
                                    rm: r,
                                    fallthrough: next_pc,
                                };
                            }
                            break;
                        }
                    };

                    if link {
                        let ret_addr = if is_thumb {
                            next_pc.as_u32() | 1
                        } else {
                            next_pc.as_u32()
                        };
                        block.insts.push(ArmInst::new(
                            inst.cond,
                            Op::Alu {
                                op: AluOp::Mov,
                                set_flags: false,
                                rd: Reg::LR,
                                rn: Reg::R0,
                                op2: Operand2::Imm(ret_addr),
                            },
                            0,
                        ));
                        block.inst_addrs.push(cur_pc);
                    }

                    if inst.cond.is_always() {
                        block.exit = BlockExit::Direct(target_addr);
                    } else {
                        // Conditional B<cond>
                        block.exit = BlockExit::BranchCond {
                            cond: inst.cond,
                            target: target_addr,
                            fallthrough: next_pc,
                        };
                    }
                    break;
                }
                Op::BranchExchange { link, rm } => {
                    // BX / BLX
                    if link {
                        let ret_addr = if is_thumb {
                            next_pc.as_u32() | 1
                        } else {
                            next_pc.as_u32()
                        };
                        block.insts.push(ArmInst::new(
                            inst.cond,
                            Op::Alu {
                                op: AluOp::Mov,
                                set_flags: false,
                                rd: Reg::LR,
                                rn: Reg::R0,
                                op2: Operand2::Imm(ret_addr),
                            },
                            0,
                        ));
                        block.inst_addrs.push(cur_pc);
                    }
                    if inst.cond.is_always() {
                        block.exit = BlockExit::Indirect(rm);
                    } else {
                        block.exit = BlockExit::IndirectCond {
                            cond: inst.cond,
                            rm,
                            fallthrough: next_pc,
                        };
                    }
                    break;
                }
                Op::LoadStoreMultiple { reg_list, .. } => {
                    // If loading into PC (e.g. POP {..., pc})
                    if (reg_list & (1 << Reg::PC.index())) != 0 {
                        if inst.cond.is_always() {
                            block.exit = BlockExit::Indirect(Reg::PC);
                        } else {
                            block.exit = BlockExit::IndirectCond {
                                cond: inst.cond,
                                rm: Reg::PC,
                                fallthrough: next_pc,
                            };
                        }
                        break;
                    }
                }
                Op::LoadStore { is_load, rd, .. } => {
                    // If loading into PC (e.g. LDR pc, [sp], #4)
                    if is_load && rd.is_pc() {
                        if inst.cond.is_always() {
                            block.exit = BlockExit::Indirect(Reg::PC);
                        } else {
                            block.exit = BlockExit::IndirectCond {
                                cond: inst.cond,
                                rm: Reg::PC,
                                fallthrough: next_pc,
                            };
                        }
                        break;
                    }
                }
                Op::Alu { rd, .. } => {
                    // If writing to PC (e.g. MOV pc, lr)
                    if rd.is_pc() {
                        if inst.cond.is_always() {
                            block.exit = BlockExit::Indirect(Reg::PC);
                        } else {
                            block.exit = BlockExit::IndirectCond {
                                cond: inst.cond,
                                rm: Reg::PC,
                                fallthrough: next_pc,
                            };
                        }
                        break;
                    }
                }
                Op::Svc { imm } => {
                    block.exit = BlockExit::Svc { imm, next_pc };
                    break;
                }
                Op::Bkpt { imm } => {
                    block.exit = BlockExit::Bkpt { imm, next_pc };
                    break;
                }
                Op::CompareBranch { is_nonzero, rn, offset } => {
                    let target_addr = cur_pc.add(4).offset(offset as i32);
                    block.exit = BlockExit::CompareBranch {
                        is_nonzero,
                        rn,
                        target: target_addr,
                        fallthrough: next_pc,
                    };
                    break;
                }
                Op::TableBranch { is_halfword, rn, rm } => {
                    block.exit = BlockExit::TableBranch {
                        is_halfword,
                        rn,
                        rm,
                        inst_pc: cur_pc,
                    };
                    break;
                }
                Op::Unknown(_) => {
                    block.exit = BlockExit::Invalid(cur_pc);
                    break;
                }
                _ => {}
            }

            cur_pc = next_pc;
        }

        // If limit was reached without a terminator, fallthrough to next_pc
        if let BlockExit::Invalid(_) = block.exit {
            if !block.insts.is_empty() {
                block.exit = BlockExit::Direct(cur_pc);
            }
        }

        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transd_core::{Cond, FlatMemory};

    #[test]
    fn test_lift_arm_basic_block() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x2000), 0x1000);

        // 0x2000: MOV r0, #10      (0xE3A0000A)
        // 0x2004: ADD r1, r0, #5   (0xE2801005)
        // 0x2008: BNE #+16         (0x1A000004) -> target 0x2008 + 8 + 16 = 0x2020
        mem.write_u32(GuestAddr::new(0x2000), 0xE3A0_000A).unwrap();
        mem.write_u32(GuestAddr::new(0x2004), 0xE280_1005).unwrap();
        mem.write_u32(GuestAddr::new(0x2008), 0x1A00_0004).unwrap();

        let block = Lifter::lift_block(&mem, GuestAddr::new(0x2000), false).unwrap();
        assert_eq!(block.insts.len(), 3);
        assert_eq!(block.byte_size, 12);
        assert_eq!(
            block.exit,
            BlockExit::BranchCond {
                cond: Cond::NE,
                target: GuestAddr::new(0x2020),
                fallthrough: GuestAddr::new(0x200C),
            }
        );
    }
}
