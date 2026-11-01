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

        // CLREX (ARMv7: 0xF57FF01F)
        if raw == 0xF57F_F01F {
            return ArmInst::new(Cond::AL, Op::Clrex, raw);
        }

        // DMB / DSB (ARMv7: 0xF57FF05x / 0xF57FF04x)
        if (raw & 0xFFFF_FFF0) == 0xF57F_F050 || (raw & 0xFFFF_FFF0) == 0xF57F_F040 {
            return ArmInst::new(Cond::AL, Op::MemoryBarrier { is_data: true }, raw);
        }

        // ISB (ARMv7: 0xF57FF06x)
        if (raw & 0xFFFF_FFF0) == 0xF57F_F060 {
            return ArmInst::new(Cond::AL, Op::MemoryBarrier { is_data: false }, raw);
        }

        // NEON Data Processing & Load/Store
        if let Some(inst) = Self::decode_neon(raw) {
            return inst;
        }

        ArmInst::new(Cond::AL, Op::Unknown(raw), raw)
    }

    /// Decodes ARM NEON (Advanced SIMD) data processing and memory operations
    pub fn decode_neon(raw: u32) -> Option<ArmInst> {
        // NEON 2-register misc (VABS.F32, VNEG.F32): 1111 0011 1 D 11 ...
        if (raw & 0xFFBF_0F80) == 0xF3B9_0700 || (raw & 0xFFBF_0F80) == 0xF3B9_0780 {
            let d_bit = (raw >> 22) & 1;
            let m_bit = (raw >> 5) & 1;
            let q_bit = (raw >> 6) & 1;
            let vd = ((raw >> 12) & 0xF) | (d_bit << 4);
            let vm = (raw & 0xF) | (m_bit << 4);
            let is_quad = q_bit != 0;
            let is_neg = (raw & 0x80) != 0;
            let op = if is_neg { NeonOp::Neg } else { NeonOp::Abs };
            return Some(ArmInst::new(
                Cond::AL,
                Op::NeonAlu {
                    op,
                    size: NeonSize::F32,
                    is_quad,
                    dst: vd as u8,
                    src1: vm as u8,
                    src2: vm as u8,
                },
                raw,
            ));
        }

        // NEON Data Processing (3-register same: 1111 001x ...)
        if (raw & 0xFE00_0000) == 0xF200_0000 {
            let d_bit = (raw >> 22) & 1;
            let n_bit = (raw >> 7) & 1;
            let m_bit = (raw >> 5) & 1;
            let q_bit = (raw >> 6) & 1;

            let vd = ((raw >> 12) & 0xF) | (d_bit << 4);
            let vn = ((raw >> 16) & 0xF) | (n_bit << 4);
            let vm = (raw & 0xF) | (m_bit << 4);

            let is_quad = q_bit != 0;
            let size_bits = (raw >> 20) & 0x3;
            let size = match size_bits {
                0b00 => NeonSize::I8,
                0b01 => NeonSize::I16,
                0b10 => NeonSize::I32,
                _ => NeonSize::F32,
            };

            let op_code = (raw >> 8) & 0xF;
            let bit24 = (raw >> 24) & 1;
            let bit4 = (raw >> 4) & 1;

            // Vector Float 3-register same: op_code == 0b1101
            if op_code == 0b1101 {
                if bit4 == 0 {
                    // VADD.F32 (size_bits == 0b00) / VSUB.F32 (size_bits == 0b10)
                    let op = if (raw & (1 << 21)) != 0 { NeonOp::Sub } else { NeonOp::Add };
                    return Some(ArmInst::new(
                        Cond::AL,
                        Op::NeonAlu {
                            op,
                            size: NeonSize::F32,
                            is_quad,
                            dst: vd as u8,
                            src1: vn as u8,
                            src2: vm as u8,
                        },
                        raw,
                    ));
                } else {
                    // VMLA.F32 (bit24 == 0, bit21 == 0), VMLS.F32 (bit24 == 0, bit21 == 1), VMUL.F32 (bit24 == 1, bit21 == 0)
                    let op = if bit24 != 0 {
                        NeonOp::Mul
                    } else if (raw & (1 << 21)) != 0 {
                        NeonOp::Mls
                    } else {
                        NeonOp::Mla
                    };
                    return Some(ArmInst::new(
                        Cond::AL,
                        Op::NeonAlu {
                            op,
                            size: NeonSize::F32,
                            is_quad,
                            dst: vd as u8,
                            src1: vn as u8,
                            src2: vm as u8,
                        },
                        raw,
                    ));
                }
            }

            // Vector Float Min/Max: op_code == 0b1111, bit4 == 0
            if op_code == 0b1111 && bit4 == 0 {
                let op = if (raw & (1 << 21)) != 0 { NeonOp::Min } else { NeonOp::Max };
                return Some(ArmInst::new(
                    Cond::AL,
                    Op::NeonAlu {
                        op,
                        size: NeonSize::F32,
                        is_quad,
                        dst: vd as u8,
                        src1: vn as u8,
                        src2: vm as u8,
                    },
                    raw,
                ));
            }

            // Integer VADD / VSUB: op_code == 0b1000, bit4 == 0
            if op_code == 0b1000 && bit4 == 0 {
                let is_sub = (raw & (1 << 9)) != 0;
                let op = if is_sub { NeonOp::Sub } else { NeonOp::Add };
                return Some(ArmInst::new(
                    Cond::AL,
                    Op::NeonAlu {
                        op,
                        size,
                        is_quad,
                        dst: vd as u8,
                        src1: vn as u8,
                        src2: vm as u8,
                    },
                    raw,
                ));
            }

            // Integer VMUL: op_code == 0b1001, bit4 == 1
            if op_code == 0b1001 && bit4 == 1 {
                return Some(ArmInst::new(
                    Cond::AL,
                    Op::NeonAlu {
                        op: NeonOp::Mul,
                        size,
                        is_quad,
                        dst: vd as u8,
                        src1: vn as u8,
                        src2: vm as u8,
                    },
                    raw,
                ));
            }

            // VAND / VORR / VEOR / VBIC: op_code == 0b0001 && bit4 == 1
            if op_code == 0b0001 && bit4 == 1 {
                let op = match (bit24, size_bits) {
                    (0, 0b00) => NeonOp::And,
                    (0, 0b01) => NeonOp::Bic,
                    (0, 0b10) => NeonOp::Orr,
                    (1, _) => NeonOp::Eor,
                    _ => NeonOp::Orr,
                };
                return Some(ArmInst::new(
                    Cond::AL,
                    Op::NeonAlu {
                        op,
                        size,
                        is_quad,
                        dst: vd as u8,
                        src1: vn as u8,
                        src2: vm as u8,
                    },
                    raw,
                ));
            }
        }

        // NEON Load/Store (VLD1 / VST1: 1111 0100 ...)
        if (raw & 0xFF10_0000) == 0xF400_0000 || (raw & 0xFF10_0000) == 0xF410_0000 {
            let is_load = (raw & (1 << 21)) != 0;
            let d_bit = (raw >> 22) & 1;
            let vd = ((raw >> 12) & 0xF) | (d_bit << 4);
            let rn = Reg::from_u8(((raw >> 16) & 0xF) as u8).unwrap_or(Reg::R0);
            let is_quad = ((raw >> 8) & 0xF) == 0xA;
            return Some(ArmInst::new(
                Cond::AL,
                Op::NeonLoadStore {
                    is_load,
                    is_quad,
                    reg: vd as u8,
                    rn,
                },
                raw,
            ));
        }

        None
    }

    fn decode_conditional(raw: u32) -> Op {
        // SDIV / UDIV (ARMv7-A virtualization extension / ARMv7-R):
        // cond 0111 00x1 Rd 1111 Rm 0001 Rn
        if (raw & 0x0FD0_F0F0) == 0x0710_F010 {
            let signed = (raw & 0x0020_0000) == 0;
            let rd = Reg::from_u8(((raw >> 16) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8(((raw >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let rn = Reg::from_u8((raw & 0xF) as u8).unwrap_or(Reg::R0);
            return Op::Div { signed, rd, rn, rm };
        }

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
        let bit25 = (raw >> 25) & 1;

        if bit25 == 0 {
            let bit4 = (raw >> 4) & 1;
            let bit7 = (raw >> 7) & 1;

            // Multiply or Halfword Transfer or Synchronization Primitives
            if bit4 == 1 && bit7 == 1 {
                let bits_7_4 = (raw >> 4) & 0xF;
                if bits_7_4 == 0b1001 {
                    // Check for synchronization primitives (LDREX / STREX)
                    if (raw & 0x0FF0_0FFF) == 0x0190_0F9F {
                        let rn = Reg::from_u8(((raw >> 16) & 0xF) as u8).unwrap_or(Reg::R0);
                        let rd = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
                        return Op::AtomicLoadEx { rd, rn };
                    }
                    if (raw & 0x0FF0_0FF0) == 0x0180_0F90 {
                        let rn = Reg::from_u8(((raw >> 16) & 0xF) as u8).unwrap_or(Reg::R0);
                        let rd = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
                        let rm = Reg::from_u8((raw & 0xF) as u8).unwrap_or(Reg::R0);
                        return Op::AtomicStoreEx { rd, rm, rn };
                    }
                    // Multiply / Multiply Long
                    return Self::decode_multiply(raw);
                } else {
                    // Halfword / Signed Data Transfer (LDRH, STRH, LDRSB, LDRSH)
                    return Self::decode_halfword_transfer(raw);
                }
            }

            // Miscellaneous: Branch Exchange (BX, BLX), CLZ, BKPT, MRS, MSR
            let bits_24_20 = (raw >> 20) & 0x1F;
            let bits_7_4 = (raw >> 4) & 0xF;

            // BX: 0001 0010 ... 0001
            if bits_24_20 == 0b10010
                && bits_7_4 == 0b0001
                && let Some(rm) = Reg::from_u8((raw & 0xF) as u8)
            {
                return Op::BranchExchange { link: false, rm };
            }

            // BLX register: 0001 0010 ... 0011
            if bits_24_20 == 0b10010
                && bits_7_4 == 0b0011
                && let Some(rm) = Reg::from_u8((raw & 0xF) as u8)
            {
                return Op::BranchExchange { link: true, rm };
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

        let (size, signed, is_load) = match op_bits {
            0b01 => (MemSize::Halfword, false, is_load), // LDRH / STRH
            0b10 => {
                if is_load {
                    (MemSize::Byte, true, true)          // LDRSB
                } else {
                    (MemSize::Doubleword, false, true)   // LDRD (load dual)
                }
            }
            0b11 => {
                if is_load {
                    (MemSize::Halfword, true, true)      // LDRSH
                } else {
                    (MemSize::Doubleword, false, false)  // STRD (store dual)
                }
            }
            _ => (MemSize::Word, false, is_load),
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

        if cp == 15 {
            let is_mrc = ((raw >> 20) & 1) != 0;
            let opc1 = ((raw >> 21) & 0x7) as u8;
            let crn = ((raw >> 16) & 0xF) as u8;
            let rd = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            let opc2 = ((raw >> 5) & 0x7) as u8;
            let crm = (raw & 0xF) as u8;
            return Op::Cp15Move {
                is_mrc,
                rd,
                crn,
                opc1,
                crm,
                opc2,
            };
        }

        Op::Unknown(raw)
    }

    /// Decodes VFPv3 (F32 and F64) instructions
    fn decode_vfp(raw: u32, is_double: bool) -> Op {
        let size = if is_double { VfpSize::F64 } else { VfpSize::F32 };

        // VMRS <Rt>, FPSCR: (0x_EF1_0A10)
        // If Rt == 15 (0xF), Rt is APSR_nzcv (CPSR flags); otherwise Rt is core register
        if (raw & 0x0FFF_0FFF) == 0x0EF1_0A10 {
            let rt_raw = ((raw >> 12) & 0xF) as u8;
            let rt = if rt_raw == 15 {
                None
            } else {
                Some(Reg::from_u8(rt_raw).unwrap_or(Reg::R0))
            };
            return Op::VfpMrsFpscr { rt };
        }

        // VMSR FPSCR, <Rt>: (0x_EE1_0A10)
        if (raw & 0x0FFF_0FFF) == 0x0EE1_0A10 {
            let rt_raw = ((raw >> 12) & 0xF) as u8;
            let rt = Reg::from_u8(rt_raw).unwrap_or(Reg::R0);
            return Op::VfpMsrFpscr { rt };
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

        // VFP 1-register extension / VCMP: bits [23:20] == 0b1011, bits [11:9] == 0b101
        if ((raw >> 20) & 0xF) == 0b1011 && ((raw >> 9) & 0x7) == 0b101 {
            let opc2 = (raw >> 16) & 0xF;
            if opc2 == 0b0100 || opc2 == 0b0101 {
                let with_zero = opc2 == 0b0101;
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
            } else if opc2 == 0b0001 {
                return Op::VfpAlu {
                    op: VfpOp::Sqrt,
                    size,
                    dst,
                    src1: src2,
                    src2,
                };
            } else if opc2 == 0b0000 {
                let bit6 = (raw >> 6) & 1;
                let bit7 = (raw >> 7) & 1;
                if bit6 == 1 {
                    let op = if bit7 == 1 { VfpOp::Abs } else { VfpOp::Neg };
                    return Op::VfpAlu {
                        op,
                        size,
                        dst,
                        src1: src2,
                        src2,
                    };
                }
            }
        }

        // VADD: 0x0E30_0A00 (bits [23:20] == 0b0011, bit 6 == 0)
        // VSUB: 0x0E30_0A40 (bits [23:20] == 0b0011, bit 6 == 1)
        // VMUL: 0x0E20_0A00 (bits [23:20] == 0b0010, bit 6 == 0)
        // VDIV: 0x0E80_0A00 (bits [23:20] == 0b1000, bit 6 == 0)
        // VFMA: 0x0EA0_0A00 (bits [23:20] == 0b1010, bit 6 == 0)
        // VFMS: 0x0EA0_0A40 (bits [23:20] == 0b1010, bit 6 == 1)
        let op_code = (raw >> 20) & 0xF;
        let bit6 = (raw >> 6) & 1;

        let vfp_op = match (op_code, bit6) {
            (0b0011, 0) => VfpOp::Add,
            (0b0011, 1) => VfpOp::Sub,
            (0b0010, 0) => VfpOp::Mul,
            (0b1000, 0) => VfpOp::Div,
            (0b1010, 0) => VfpOp::Fma,
            (0b1010, 1) => VfpOp::Fms,
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
        assert_eq!(inst.op, Op::VfpMrsFpscr { rt: None });

        // VMRS r1, FPSCR -> 0xEEF11A10
        let inst_mrs = ArmDecoder::decode(0xEEF1_1A10);
        assert_eq!(inst_mrs.op, Op::VfpMrsFpscr { rt: Some(Reg::R1) });

        // VMSR FPSCR, r2 -> 0xEEE12A10
        let inst_msr = ArmDecoder::decode(0xEEE1_2A10);
        assert_eq!(inst_msr.op, Op::VfpMsrFpscr { rt: Reg::R2 });

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

        // VFMA.F32 s0, s1, s2 -> 0xEEA00A81
        let inst_fma = ArmDecoder::decode(0xEEA0_0A81);
        match inst_fma.op {
            Op::VfpAlu { op, size, .. } => {
                assert_eq!(op, VfpOp::Fma);
                assert_eq!(size, VfpSize::F32);
            }
            _ => panic!("Expected VFMA"),
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

    #[test]
    fn test_decode_mov_imm_with_high_bits() {
        // MOV r7, #240 -> 0xE3A070F0 (has bits 4 and 7 set in immediate)
        let inst = ArmDecoder::decode(0xE3A0_70F0);
        assert_eq!(
            inst.op,
            Op::Alu {
                op: AluOp::Mov,
                rd: Reg::R7,
                rn: Reg::R0,
                op2: Operand2::Imm(240),
                set_flags: false
            }
        );
    }

    #[test]
    fn test_arm_neon_vector_decode() {
        // VADD.F32 Q0, Q0, Q0
        let inst = ArmDecoder::decode(0xF200_0D40);
        assert_eq!(
            inst.op,
            Op::NeonAlu {
                op: NeonOp::Add,
                size: NeonSize::F32,
                is_quad: true,
                dst: 0,
                src1: 0,
                src2: 0,
            }
        );

        // VSUB.F32 Q0, Q0, Q0
        let inst = ArmDecoder::decode(0xF220_0D40);
        assert_eq!(
            inst.op,
            Op::NeonAlu {
                op: NeonOp::Sub,
                size: NeonSize::F32,
                is_quad: true,
                dst: 0,
                src1: 0,
                src2: 0,
            }
        );

        // VMUL.F32 Q0, Q0, Q0
        let inst = ArmDecoder::decode(0xF300_0D50);
        assert_eq!(
            inst.op,
            Op::NeonAlu {
                op: NeonOp::Mul,
                size: NeonSize::F32,
                is_quad: true,
                dst: 0,
                src1: 0,
                src2: 0,
            }
        );

        // VMLA.F32 Q0, Q0, Q0
        let inst = ArmDecoder::decode(0xF200_0D50);
        assert_eq!(
            inst.op,
            Op::NeonAlu {
                op: NeonOp::Mla,
                size: NeonSize::F32,
                is_quad: true,
                dst: 0,
                src1: 0,
                src2: 0,
            }
        );

        // VMLS.F32 Q0, Q0, Q0
        let inst = ArmDecoder::decode(0xF220_0D50);
        assert_eq!(
            inst.op,
            Op::NeonAlu {
                op: NeonOp::Mls,
                size: NeonSize::F32,
                is_quad: true,
                dst: 0,
                src1: 0,
                src2: 0,
            }
        );

        // VMAX.F32 Q0, Q0, Q0
        let inst = ArmDecoder::decode(0xF200_0F40);
        assert_eq!(
            inst.op,
            Op::NeonAlu {
                op: NeonOp::Max,
                size: NeonSize::F32,
                is_quad: true,
                dst: 0,
                src1: 0,
                src2: 0,
            }
        );

        // VMIN.F32 Q0, Q0, Q0
        let inst = ArmDecoder::decode(0xF220_0F40);
        assert_eq!(
            inst.op,
            Op::NeonAlu {
                op: NeonOp::Min,
                size: NeonSize::F32,
                is_quad: true,
                dst: 0,
                src1: 0,
                src2: 0,
            }
        );

        // VABS.F32 Q1, Q2
        let inst = ArmDecoder::decode(0xF3B9_2744);
        assert_eq!(
            inst.op,
            Op::NeonAlu {
                op: NeonOp::Abs,
                size: NeonSize::F32,
                is_quad: true,
                dst: 2,
                src1: 4,
                src2: 4,
            }
        );

        // VNEG.F32 Q3, Q4
        let inst = ArmDecoder::decode(0xF3B9_67C8);
        assert_eq!(
            inst.op,
            Op::NeonAlu {
                op: NeonOp::Neg,
                size: NeonSize::F32,
                is_quad: true,
                dst: 6,
                src1: 8,
                src2: 8,
            }
        );

        // VBIC Q0, Q0, Q0
        let inst = ArmDecoder::decode(0xF210_0150);
        assert_eq!(
            inst.op,
            Op::NeonAlu {
                op: NeonOp::Bic,
                size: NeonSize::I16,
                is_quad: true,
                dst: 0,
                src1: 0,
                src2: 0,
            }
        );

        // VLD1.8 {d0, d1}, [r0] (Quadword 128-bit)
        let inst = ArmDecoder::decode(0xF420_0A00);
        assert_eq!(
            inst.op,
            Op::NeonLoadStore {
                is_load: true,
                is_quad: true,
                reg: 0,
                rn: Reg::R0,
            }
        );

        // VST1.8 {d0, d1}, [r0] (Quadword 128-bit)
        let inst = ArmDecoder::decode(0xF400_0A00);
        assert_eq!(
            inst.op,
            Op::NeonLoadStore {
                is_load: false,
                is_quad: true,
                reg: 0,
                rn: Reg::R0,
            }
        );
    }
}
