use transd_core::{GuestAddr, Memory, MemoryError, Reg};
use transd_decoder::{decode_next, BranchTarget, Op};
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
                            block.exit = BlockExit::Indirect(r);
                            break;
                        }
                    };

                    if inst.cond.is_always() {
                        if link {
                            // BL call: in a DBT, function call ends the basic block
                            block.exit = BlockExit::Direct(target_addr);
                        } else {
                            // Unconditional B
                            block.exit = BlockExit::Direct(target_addr);
                        }
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
                Op::BranchExchange { rm, .. } => {
                    // BX / BLX
                    block.exit = BlockExit::Indirect(rm);
                    break;
                }
                Op::LoadStoreMultiple { reg_list, .. } => {
                    // If loading into PC (e.g. POP {..., pc})
                    if (reg_list & (1 << Reg::PC.index())) != 0 {
                        block.exit = BlockExit::Indirect(Reg::PC);
                        break;
                    }
                }
                Op::LoadStore { is_load, rd, .. } => {
                    // If loading into PC (e.g. LDR pc, [sp], #4)
                    if is_load && rd.is_pc() {
                        block.exit = BlockExit::Indirect(Reg::PC);
                        break;
                    }
                }
                Op::Alu { rd, .. } => {
                    // If writing to PC (e.g. MOV pc, lr)
                    if rd.is_pc() {
                        block.exit = BlockExit::Indirect(Reg::PC);
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
