use transd_decoder::{AluOp, Op, Operand2, ShiftAmount, ShiftType};
use crate::superblock::Superblock;

pub struct SuperblockOptimizer;

impl SuperblockOptimizer {
    /// Applies peephole optimizations to a superblock trace:
    /// 1. Eliminates redundant self-moves: MOV rX, rX
    /// 2. Eliminates redundant consecutive inverse moves: MOV rA, rB followed by MOV rB, rA
    pub fn optimize(sb: &mut Superblock) {
        if sb.insts.is_empty() {
            return;
        }

        let mut opt_insts = Vec::with_capacity(sb.insts.len());
        let has_addrs = sb.inst_addrs.len() == sb.insts.len();
        let mut opt_addrs = if has_addrs { Vec::with_capacity(sb.inst_addrs.len()) } else { Vec::new() };
        let mut i = 0;

        while i < sb.insts.len() {
            let inst = &sb.insts[i];

            // 0. NOP elimination
            if matches!(inst.op, Op::Nop) {
                i += 1;
                continue;
            }

            // 1. Self-move elimination: MOV rX, rX (without set_flags, unshifted)
            if let Op::Alu {
                op: AluOp::Mov,
                rd,
                op2: Operand2::Reg { rm, shift },
                set_flags: false,
                ..
            } = inst.op
            {
                if rd == rm && shift.shift_type == ShiftType::Lsl && shift.amount == ShiftAmount::Imm(0) {
                    i += 1;
                    continue;
                }
            }

            // 2. Redundant inverse move: MOV rA, rB followed by MOV rB, rA
            if i + 1 < sb.insts.len() {
                let next = &sb.insts[i + 1];
                if let (
                    Op::Alu {
                        op: AluOp::Mov,
                        rd: rd1,
                        op2: Operand2::Reg { rm: rm1, shift: s1 },
                        set_flags: false,
                        ..
                    },
                    Op::Alu {
                        op: AluOp::Mov,
                        rd: rd2,
                        op2: Operand2::Reg { rm: rm2, shift: s2 },
                        set_flags: false,
                        ..
                    },
                ) = (&inst.op, &next.op)
                {
                    if *rd1 == *rm2
                        && *rm1 == *rd2
                        && s1.shift_type == ShiftType::Lsl
                        && s1.amount == ShiftAmount::Imm(0)
                        && s2.shift_type == ShiftType::Lsl
                        && s2.amount == ShiftAmount::Imm(0)
                    {
                        opt_insts.push(inst.clone());
                        if has_addrs {
                            opt_addrs.push(sb.inst_addrs[i]);
                        }
                        i += 2;
                        continue;
                    }
                }
            }

            opt_insts.push(inst.clone());
            if has_addrs {
                opt_addrs.push(sb.inst_addrs[i]);
            }
            i += 1;
        }

        sb.insts = opt_insts;
        if has_addrs {
            sb.inst_addrs = opt_addrs;
        }
    }
}
