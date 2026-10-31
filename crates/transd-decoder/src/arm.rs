use transd_core::{Cond, Reg};
use crate::types::*;

pub struct ArmDecoder;

impl ArmDecoder {
    pub fn decode(raw: u32) -> ArmInst {
        let cond_bits = ((raw >> 28) & 0xF) as u8;
        let cond = Cond::from_u8(cond_bits);

        // Handle unconditional extensions (cond == 0b1111)
        if cond_bits == 0b1111 {
            return Self::decode_unconditional(raw);
        }

        let op = Self::decode_conditional(raw);
        ArmInst::new(cond, op, raw)
    }

    fn decode_unconditional(raw: u32) -> ArmInst {
        // BLX immediate: bits [27:25] == 0b101, bit 24 is H
        if (raw >> 25) & 0x7 == 0b101 {
            let h = (raw >> 24) & 1;
            let imm24 = raw & 0x00FF_FFFF;
            // Sign-extend 24-bit offset
            let mut offset = (imm24 as i32) << 8 >> 6; // * 4
            if h != 0 {
                offset |= 2;
            }
            return ArmInst::new(
                Cond::AL,
                Op::Branch {
                    link: true,
                    target: BranchTarget::Imm(offset),
                },
                raw,
            );
        }

        // NOP (ARMv7: 0xF3202000 or similar hints)
        if (raw & 0xFFFF_FFF0) == 0xF320_2000 {
            return ArmInst::new(Cond::AL, Op::Nop, raw);
        }

        ArmInst::new(Cond::AL, Op::Unknown(raw), raw)
    }

    fn decode_conditional(raw: u32) -> Op {
        let cat = (raw >> 26) & 0x3;

        match cat {
            0b00 => Self::decode_cat0(raw),
            0b01 => Self::decode_cat1(raw),
            0b10 => Self::decode_cat2(raw),
            0b11 => Self::decode_cat3(raw),
            _ => unreachable!(),
        }
    }

    /// Category 0: ALU, Multiply, Halfword Transfers, Branch Exchange, Misc
    fn decode_cat0(raw: u32) -> Op {
        let bit4 = (raw >> 4) & 1;
        let bit7 = (raw >> 7) & 1;

        // Multiply or Halfword Transfer
        if bit4 == 1 && bit7 == 1 {
            let bits_7_4 = (raw >> 4) & 0xF;
            if bits_7_4 == 0b1001 {
                // Multiply / Multiply Long
                return Self::decode_multiply(raw);
            } else {
                // Halfword / Signed Data Transfer (LDRH, STRH, LDRSB, LDRSH)
                return Self::decode_halfword_transfer(raw);
            }
        }

        // Miscellaneous: Branch Exchange (BX, BLX), CLZ, BKPT, MRS, MSR
        let bit25 = (raw >> 25) & 1;
        if bit25 == 0 {
            let bits_24_20 = (raw >> 20) & 0x1F;
            let bits_7_4 = (raw >> 4) & 0xF;

            // BX: 0001 0010 ... 0001
            if bits_24_20 == 0b10010 && bits_7_4 == 0b0001 {
                if let Some(rm) = Reg::from_u8((raw & 0xF) as u8) {
                    return Op::BranchExchange { link: false, rm };
                }
            }

            // BLX register: 0001 0010 ... 0011
            if bits_24_20 == 0b10010 && bits_7_4 == 0b0011 {
                if let Some(rm) = Reg::from_u8((raw & 0xF) as u8) {
                    return Op::BranchExchange { link: true, rm };
                }
            }

            // CLZ: 0001 0110 ... 0001
            if bits_24_20 == 0b10110 && bits_7_4 == 0b0001 {
                let rd = Reg::from_u8(((raw >> 12) & 0xF) as u8);
                let rm = Reg::from_u8((raw & 0xF) as u8);
                if let (Some(rd), Some(rm)) = (rd, rm) {
                    return Op::Clz { rd, rm };
                }
            }

            // BKPT: 0001 0010 ... 0111
            if (raw >> 20) & 0xFF == 0b0001_0010 && bits_7_4 == 0b0111 {
                let imm12 = ((raw >> 8) & 0xFFF) << 4 | (raw & 0xF);
                return Op::Bkpt { imm: imm12 as u16 };
            }

            // MRS: 0001 0x00 ... 0000
            if (raw >> 20) & 0b11011 == 0b10000 && bits_7_4 == 0b0000 {
                let spsr = ((raw >> 22) & 1) != 0;
                if let Some(rd) = Reg::from_u8(((raw >> 12) & 0xF) as u8) {
                    return Op::Mrs { rd, spsr };
                }
            }
        }

        // Standard Data Processing (ALU)
        Self::decode_alu(raw)
    }

    /// Decodes ALU operations
    fn decode_alu(raw: u32) -> Op {
        let is_imm = ((raw >> 25) & 1) != 0;
        let opcode_bits = ((raw >> 21) & 0xF) as u8;
        let set_flags = ((raw >> 20) & 1) != 0;

        let rn = Reg::from_u8(((raw >> 16) & 0xF) as u8).unwrap_or(Reg::R0);
        let rd = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);

        let alu_op = match opcode_bits {
            0b0000 => AluOp::And,
            0b0001 => AluOp::Eor,
            0b0010 => AluOp::Sub,
            0b0011 => AluOp::Rsb,
            0b0100 => AluOp::Add,
            0b0101 => AluOp::Adc,
            0b0110 => AluOp::Sbc,
            0b0111 => AluOp::Rsc,
            0b1000 => AluOp::Tst,
            0b1001 => AluOp::Teq,
            0b1010 => AluOp::Cmp,
            0b1011 => AluOp::Cmn,
            0b1100 => AluOp::Orr,
            0b1101 => AluOp::Mov,
            0b1110 => AluOp::Bic,
            0b1111 => AluOp::Mvn,
            _ => unreachable!(),
        };

        // Check for NOP: MOV r0, r0 (0xE1A00000)
        if alu_op == AluOp::Mov && !set_flags && rd == Reg::R0 && !is_imm {
            let rm = (raw & 0xF) as u8;
            let shift_bits = (raw >> 4) & 0xFF;
            if rm == 0 && shift_bits == 0 {
                return Op::Nop;
            }
        }

        let op2 = if is_imm {
            let rot = ((raw >> 8) & 0xF) * 2;
            let imm8 = raw & 0xFF;
            Operand2::Imm(imm8.rotate_right(rot))
        } else {
            let rm = Reg::from_u8((raw & 0xF) as u8).unwrap_or(Reg::R0);
            let shift_type_bits = (raw >> 5) & 0x3;
            let shift_reg_bit = (raw >> 4) & 1;

            let shift_type = match shift_type_bits {
                0b00 => ShiftType::Lsl,
                0b01 => ShiftType::Lsr,
                0b10 => ShiftType::Asr,
                0b11 => ShiftType::Ror,
                _ => unreachable!(),
            };

            let amount = if shift_reg_bit == 1 {
                let rs = Reg::from_u8(((raw >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
                ShiftAmount::Reg(rs)
            } else {
                let imm5 = ((raw >> 7) & 0x1F) as u8;
                ShiftAmount::Imm(imm5)
            };

            let final_shift_type = if shift_type == ShiftType::Ror && amount == ShiftAmount::Imm(0) {
                ShiftType::Rrx
            } else {
                shift_type
            };

            Operand2::Reg {
                rm,
                shift: Shift {
                    shift_type: final_shift_type,
                    amount,
                },
            }
        };

        Op::Alu {
            op: alu_op,
            set_flags,
            rd,
            rn,
            op2,
        }
    }

    /// Decodes Multiply and Multiply Long
    fn decode_multiply(raw: u32) -> Op {
        let is_long = ((raw >> 23) & 1) != 0;
        let is_accumulate = ((raw >> 21) & 1) != 0;
        let set_flags = ((raw >> 20) & 1) != 0;

        let rm = Reg::from_u8((raw & 0xF) as u8).unwrap_or(Reg::R0);
        let rs = Reg::from_u8(((raw >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
        let rn = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
        let rd = Reg::from_u8(((raw >> 16) & 0xF) as u8).unwrap_or(Reg::R0);

        if is_long {
            let signed = ((raw >> 22) & 1) != 0;
            Op::MulLong {
                signed,
                accumulate: is_accumulate,
                set_flags,
                rd_hi: rd,
                rd_lo: rn,
                rm,
                rs,
            }
        } else {
            let mul_op = if is_accumulate {
                MulOp::Mla
            } else {
                MulOp::Mul
            };
            Op::Mul {
                op: mul_op,
                set_flags,
                rd,
                rn,
                rm,
                rs,
            }
        }
    }

    /// Decodes Halfword and Signed Byte/Halfword Transfers (LDRH, STRH, LDRSB, LDRSH)
    fn decode_halfword_transfer(raw: u32) -> Op {
        let p = ((raw >> 24) & 1) != 0;
        let u = ((raw >> 23) & 1) != 0;
        let is_imm = ((raw >> 22) & 1) != 0;
        let w = ((raw >> 21) & 1) != 0;
        let is_load = ((raw >> 20) & 1) != 0;
        let op_bits = (raw >> 5) & 0x3;

        let rn = Reg::from_u8(((raw >> 16) & 0xF) as u8).unwrap_or(Reg::R0);
        let rd = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);

        let (size, signed) = match op_bits {
            0b01 => (MemSize::Halfword, false), // LDRH / STRH
            0b10 => (MemSize::Byte, true),      // LDRSB
            0b11 => (MemSize::Halfword, true),  // LDRSH
            _ => (MemSize::Word, false),
        };

        let offset = if is_imm {
            let imm = (((raw >> 8) & 0xF) << 4) | (raw & 0xF);
            AddrOffset::Imm(imm)
        } else {
            let rm = Reg::from_u8((raw & 0xF) as u8).unwrap_or(Reg::R0);
            AddrOffset::Reg {
                rm,
                shift_type: ShiftType::Lsl,
                shift_imm: 0,
            }
        };

        let addr_mode = if p {
            if w {
                AddrMode::PreIndex { offset, add: u }
            } else {
                AddrMode::Offset { offset, add: u }
            }
        } else {
            AddrMode::PostIndex { offset, add: u }
        };

        Op::LoadStore {
            is_load,
            size,
            signed,
            rd,
            rn,
            addr_mode,
        }
    }

    /// Category 1: Single Data Transfer (LDR, STR, LDRB, STRB)
    fn decode_cat1(raw: u32) -> Op {
        let is_reg_offset = ((raw >> 25) & 1) != 0;
        let p = ((raw >> 24) & 1) != 0;
        let u = ((raw >> 23) & 1) != 0;
        let is_byte = ((raw >> 22) & 1) != 0;
        let w = ((raw >> 21) & 1) != 0;
        let is_load = ((raw >> 20) & 1) != 0;

        let rn = Reg::from_u8(((raw >> 16) & 0xF) as u8).unwrap_or(Reg::R0);
        let rd = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);

        let size = if is_byte {
            MemSize::Byte
        } else {
            MemSize::Word
        };

        let offset = if !is_reg_offset {
            let imm12 = raw & 0xFFF;
            AddrOffset::Imm(imm12)
        } else {
            let rm = Reg::from_u8((raw & 0xF) as u8).unwrap_or(Reg::R0);
            let shift_type_bits = (raw >> 5) & 0x3;
            let shift_imm = ((raw >> 7) & 0x1F) as u8;
            let shift_type = match shift_type_bits {
                0b00 => ShiftType::Lsl,
                0b01 => ShiftType::Lsr,
                0b10 => ShiftType::Asr,
                0b11 => ShiftType::Ror,
                _ => unreachable!(),
            };
            AddrOffset::Reg {
                rm,
                shift_type,
                shift_imm,
            }
        };

        let addr_mode = if p {
            if w {
                AddrMode::PreIndex { offset, add: u }
            } else {
                AddrMode::Offset { offset, add: u }
            }
        } else {
            AddrMode::PostIndex { offset, add: u }
        };

        Op::LoadStore {
            is_load,
            size,
            signed: false,
            rd,
            rn,
            addr_mode,
        }
    }

    /// Category 2: Block Data Transfer (LDM, STM) & Branch (B, BL)
    fn decode_cat2(raw: u32) -> Op {
        let is_branch = ((raw >> 25) & 1) != 0;

        if is_branch {
            let link = ((raw >> 24) & 1) != 0;
            let imm24 = raw & 0x00FF_FFFF;
            // Sign-extend 24-bit imm to 32 bits, shift left by 2
            let offset = ((imm24 as i32) << 8) >> 6;
            Op::Branch {
                link,
                target: BranchTarget::Imm(offset),
            }
        } else {
            // Block Data Transfer (LDM, STM)
            let p = ((raw >> 24) & 1) != 0;
            let u = ((raw >> 23) & 1) != 0;
            let writeback = ((raw >> 21) & 1) != 0;
            let is_load = ((raw >> 20) & 1) != 0;

            let rn = Reg::from_u8(((raw >> 16) & 0xF) as u8).unwrap_or(Reg::R0);
            let reg_list = (raw & 0xFFFF) as u16;

            let mode = match (p, u) {
                (false, true) => BlockAddrMode::Ia,  // Increment After
                (true, true) => BlockAddrMode::Ib,   // Increment Before
                (false, false) => BlockAddrMode::Da, // Decrement After
                (true, false) => BlockAddrMode::Db,  // Decrement Before (PUSH)
            };

            Op::LoadStoreMultiple {
                is_load,
                rn,
                mode,
                writeback,
                reg_list,
            }
        }
    }

    /// Category 3: Coprocessor, VFP, and Supervisor Call (SVC)
    fn decode_cat3(raw: u32) -> Op {
        let is_svc = ((raw >> 24) & 0xF) == 0xF;
        if is_svc {
            let imm24 = raw & 0x00FF_FFFF;
            return Op::Svc { imm: imm24 };
        }

        let cp = (raw >> 8) & 0xF;
        if cp == 10 || cp == 11 {
            return Self::decode_vfp(raw, cp == 11);
        }

        Op::Unknown(raw)
    }

    /// Decodes VFPv3 (F32 and F64) instructions
    fn decode_vfp(raw: u32, is_double: bool) -> Op {
        let size = if is_double { VfpSize::F64 } else { VfpSize::F32 };

        // VMRS APSR_nzcv, FPSCR: 0x_EF1_FA10
        if (raw & 0x0FFF_FFFF) == 0x0EF1_FA10 {
            return Op::VfpMrsFpscr;
        }

        // VMOV between core and single-precision float (s0..s31)
        // VMOV Rd, Sn (0x_E10_0A10) / VMOV Sn, Rd (0x_E00_0A10)
        if (raw & 0x0FE0_0F10) == 0x0E00_0A10 {
            let to_core = ((raw >> 20) & 1) != 0;
            let rt = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            let vn = ((raw >> 16) & 0xF) as u8;
            let n = ((raw >> 7) & 1) as u8;
            let s_idx = (vn << 1) | n;
            return Op::VfpMovCore {
                to_core,
                core_reg: rt,
                vfp_reg: VfpReg::S(s_idx),
            };
        }

        // VLDR / VSTR: bits [27:25] == 0b110, bit 24 is P, bit 23 is U
        if ((raw >> 25) & 0x7) == 0b110 {
            let is_load = ((raw >> 20) & 1) != 0;
            let u = ((raw >> 23) & 1) != 0;
            let rn = Reg::from_u8(((raw >> 16) & 0xF) as u8).unwrap_or(Reg::R0);
            let imm8 = (raw & 0xFF) as i32 * 4;
            let offset = if u { imm8 } else { -imm8 };

            let vd = ((raw >> 12) & 0xF) as u8;
            let d = ((raw >> 22) & 1) as u8;

            let vfp_reg = if is_double {
                let d_idx = (d << 4) | vd;
                VfpReg::D(d_idx)
            } else {
                let s_idx = (vd << 1) | d;
                VfpReg::S(s_idx)
            };

            return Op::VfpLoadStore {
                is_load,
                size,
                vfp_reg,
                rn,
                offset,
            };
        }

        // VFP Data Processing
        let vd = ((raw >> 12) & 0xF) as u8;
        let d = ((raw >> 22) & 1) as u8;
        let vn = ((raw >> 16) & 0xF) as u8;
        let n = ((raw >> 7) & 1) as u8;
        let vm = (raw & 0xF) as u8;
        let m = ((raw >> 5) & 1) as u8;

        let (dst, src1, src2) = if is_double {
            (
                VfpReg::D((d << 4) | vd),
                VfpReg::D((n << 4) | vn),
                VfpReg::D((m << 4) | vm),
            )
        } else {
            (
                VfpReg::S((vd << 1) | d),
                VfpReg::S((vn << 1) | n),
                VfpReg::S((vm << 1) | m),
            )
        };

        // VCMP: bits [23:20] == 0b1011, bits [11:9] == 0b101
        if ((raw >> 20) & 0xF) == 0b1011 && ((raw >> 9) & 0x7) == 0b101 {
            let with_zero = ((raw >> 16) & 1) != 0;
            let op = if with_zero {
                VfpOp::CmpZero
            } else {
                VfpOp::Cmp
            };
            return Op::VfpAlu {
                op,
                size,
                dst,
                src1: dst,
                src2,
            };
        }

        // VADD: 0x0E30_0A00 (bits [23:20] == 0b0011, bit 6 == 0)
        // VSUB: 0x0E30_0A40 (bits [23:20] == 0b0011, bit 6 == 1)
        // VMUL: 0x0E20_0A00 (bits [23:20] == 0b0010, bit 6 == 0)
        // VDIV: 0x0E80_0A00 (bits [23:20] == 0b1000, bit 6 == 0)
        let op_code = (raw >> 20) & 0xF;
        let bit6 = (raw >> 6) & 1;

        let vfp_op = match (op_code, bit6) {
            (0b0011, 0) => VfpOp::Add,
            (0b0011, 1) => VfpOp::Sub,
            (0b0010, 0) => VfpOp::Mul,
            (0b1000, 0) => VfpOp::Div,
            _ => return Op::Unknown(raw),
        };

        Op::VfpAlu {
            op: vfp_op,
            size,
            dst,
            src1,
            src2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_nop() {
        // MOV r0, r0 (0xE1A00000)
        let inst = ArmDecoder::decode(0xE1A0_0000);
        assert_eq!(inst.cond, Cond::AL);
        assert_eq!(inst.op, Op::Nop);
    }

    #[test]
    fn test_decode_add_imm() {
        // ADD r1, r2, #42 -> cond: AL, op: Add, rd: r1, rn: r2, imm: 42
        // 0xE282102A: E(AL) 2(Data imm) 8(ADD) 2(rn=r2) 1(rd=r1) 0(rot=0) 2A(42)
        let inst = ArmDecoder::decode(0xE282_102A);
        assert_eq!(inst.cond, Cond::AL);
        match inst.op {
            Op::Alu {
                op,
                set_flags,
                rd,
                rn,
                op2,
            } => {
                assert_eq!(op, AluOp::Add);
                assert!(!set_flags);
                assert_eq!(rd, Reg::R1);
                assert_eq!(rn, Reg::R2);
                assert_eq!(op2, Operand2::Imm(42));
            }
            _ => panic!("Expected ALU Add"),
        }
    }

    #[test]
    fn test_decode_sub_reg_shift() {
        // SUB r0, r1, r2, LSL #2
        // 0xE0410102: E(AL) 0(Data reg) 4(SUB) 1(rn=r1) 0(rd=r0) 00010(shift imm=2) 00(LSL) 0(shift by imm) 2(rm=r2)
        let inst = ArmDecoder::decode(0xE041_0102);
        match inst.op {
            Op::Alu {
                op,
                rd,
                rn,
                op2,
                ..
            } => {
                assert_eq!(op, AluOp::Sub);
                assert_eq!(rd, Reg::R0);
                assert_eq!(rn, Reg::R1);
                assert_eq!(
                    op2,
                    Operand2::Reg {
                        rm: Reg::R2,
                        shift: Shift {
                            shift_type: ShiftType::Lsl,
                            amount: ShiftAmount::Imm(2)
                        }
                    }
                );
            }
            _ => panic!("Expected ALU Sub"),
        }
    }

    #[test]
    fn test_decode_branch() {
        // B #+8 (relative to PC+8, so offset=8)
        // 0xEA000002 -> offset = 2 * 4 = 8
        let inst = ArmDecoder::decode(0xEA00_0002);
        assert_eq!(
            inst.op,
            Op::Branch {
                link: false,
                target: BranchTarget::Imm(8)
            }
        );

        // BL #-8
        // offset = -2 -> 0x00FFFFFE
        let inst = ArmDecoder::decode(0xEBFF_FFFE);
        assert_eq!(
            inst.op,
            Op::Branch {
                link: true,
                target: BranchTarget::Imm(-8)
            }
        );
    }

    #[test]
    fn test_decode_bx_lr() {
        // BX lr (0xE12FFF1E)
        let inst = ArmDecoder::decode(0xE12F_FF1E);
        assert_eq!(
            inst.op,
            Op::BranchExchange {
                link: false,
                rm: Reg::LR
            }
        );
    }

    #[test]
    fn test_decode_svc() {
        // SVC 0 (0xEF000000)
        let inst = ArmDecoder::decode(0xEF00_0000);
        assert_eq!(inst.op, Op::Svc { imm: 0 });
    }

    #[test]
    fn test_decode_vfp_ops() {
        // VMRS APSR_nzcv, FPSCR -> 0xEEF1FA10
        let inst = ArmDecoder::decode(0xEEF1_FA10);
        assert_eq!(inst.op, Op::VfpMrsFpscr);

        // VADD.F32 s0, s1, s2 -> 0xEE300A81
        let inst2 = ArmDecoder::decode(0xEE30_0A81);
        match inst2.op {
            Op::VfpAlu { op, size, dst, src1, src2 } => {
                assert_eq!(op, VfpOp::Add);
                assert_eq!(size, VfpSize::F32);
                assert_eq!(dst, VfpReg::S(0));
                assert_eq!(src1, VfpReg::S(1));
                assert_eq!(src2, VfpReg::S(2));
            }
            _ => panic!("Expected VFP Add"),
        }
    }

    #[test]
    fn test_decode_push_pop() {
        // PUSH {r4, lr} -> STMDB sp!, {r4, lr}
        // 0xE92D4010: E(AL) 9(cat2) 2(P=1, U=0, W=1) D(sp) 4010(mask: bit 4=r4, bit 14=lr)
        let inst = ArmDecoder::decode(0xE92D_4010);
        assert_eq!(
            inst.op,
            Op::LoadStoreMultiple {
                is_load: false,
                rn: Reg::SP,
                mode: BlockAddrMode::Db,
                writeback: true,
                reg_list: 0x4010
            }
        );

        // POP {r4, pc} -> LDMIA sp!, {r4, pc}
        // 0xE8BD8010: E(AL) 8(cat2) B(L=1, P=0, U=1, W=1) D(sp) 8010(mask: bit 4=r4, bit 15=pc)
        let inst = ArmDecoder::decode(0xE8BD_8010);
        assert_eq!(
            inst.op,
            Op::LoadStoreMultiple {
                is_load: true,
                rn: Reg::SP,
                mode: BlockAddrMode::Ia,
                writeback: true,
                reg_list: 0x8010
            }
        );
    }
}
