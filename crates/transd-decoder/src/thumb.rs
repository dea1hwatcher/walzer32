use transd_core::{Cond, Reg};
use crate::arm::ArmDecoder;
use crate::types::*;

pub struct ThumbDecoder;

impl ThumbDecoder {
    /// Decodes either a 16-bit Thumb or 32-bit Thumb-2 instruction
    /// Returns the decoded instruction and the number of bytes consumed (2 or 4).
    pub fn decode(hw1: u16, hw2: Option<u16>) -> (ArmInst, usize) {
        // Check if this is the prefix of a 32-bit Thumb-2 instruction
        let prefix = (hw1 >> 11) & 0x1F;
        if prefix == 0b11101 || prefix == 0b11110 || prefix == 0b11111 {
            let hw2_val = hw2.unwrap_or(0);
            let raw32 = ((hw1 as u32) << 16) | (hw2_val as u32);
            (Self::decode_thumb32(hw1, hw2_val, raw32), 4)
        } else {
            (Self::decode_thumb16(hw1), 2)
        }
    }

    /// Decodes 16-bit Thumb instructions
    fn decode_thumb16(hw: u16) -> ArmInst {
        let raw = hw as u32;
        let op_top = (hw >> 12) & 0xF;

        match op_top {
            // Shift (imm), Add, Subtract, Move/Compare/Add/Sub imm
            0b0000 | 0b0001 => Self::decode_t16_shift_add_sub(hw, raw),
            0b0010 | 0b0011 => Self::decode_t16_imm_ops(hw, raw),

            // ALU, High registers, PC-relative LDR
            0b0100 => Self::decode_t16_alu_hireg_ldr(hw, raw),

            // Load/Store register offset, sign-extended byte/halfword
            0b0101 => Self::decode_t16_load_store_reg(hw, raw),

            // Load/Store word/byte immediate offset
            0b0110 | 0b0111 => Self::decode_t16_load_store_imm(hw, raw),

            // Load/Store halfword immediate offset
            0b1000 => Self::decode_t16_load_store_halfword(hw, raw),

            // SP-relative Load/Store
            0b1001 => Self::decode_t16_sp_relative(hw, raw),

            // Load address (PC/SP + imm)
            0b1010 => Self::decode_t16_add_pc_sp(hw, raw),

            // Misc 16-bit (PUSH, POP, adjust SP, CBZ/CBNZ, NOP, BKPT)
            0b1011 => Self::decode_t16_misc(hw, raw),

            // Multiple Load/Store (LDMIA, STMIA)
            0b1100 => Self::decode_t16_ldm_stm(hw, raw),

            // Conditional Branch, SVC
            0b1101 => Self::decode_t16_cond_branch_svc(hw, raw),

            // Unconditional Branch (B)
            0b1110 => Self::decode_t16_uncond_branch(hw, raw),

            _ => ArmInst::new(Cond::AL, Op::Unknown(raw), raw),
        }
    }

    fn decode_t16_shift_add_sub(hw: u16, raw: u32) -> ArmInst {
        let op = (hw >> 11) & 0x3;
        let rd = Reg::from_u8((hw & 0x7) as u8).unwrap_or(Reg::R0);
        let rn = Reg::from_u8(((hw >> 3) & 0x7) as u8).unwrap_or(Reg::R0);

        match op {
            0b00 => {
                // LSL Rd, Rm, #imm5
                let imm5 = ((hw >> 6) & 0x1F) as u8;
                let rm = rn;
                ArmInst::new(
                    Cond::AL,
                    Op::Alu {
                        op: AluOp::Mov,
                        set_flags: true,
                        rd,
                        rn: Reg::R0,
                        op2: Operand2::Reg {
                            rm,
                            shift: Shift {
                                shift_type: ShiftType::Lsl,
                                amount: ShiftAmount::Imm(imm5),
                            },
                        },
                    },
                    raw,
                )
            }
            0b01 => {
                // LSR Rd, Rm, #imm5
                let imm5 = ((hw >> 6) & 0x1F) as u8;
                let rm = rn;
                ArmInst::new(
                    Cond::AL,
                    Op::Alu {
                        op: AluOp::Mov,
                        set_flags: true,
                        rd,
                        rn: Reg::R0,
                        op2: Operand2::Reg {
                            rm,
                            shift: Shift {
                                shift_type: ShiftType::Lsr,
                                amount: ShiftAmount::Imm(imm5),
                            },
                        },
                    },
                    raw,
                )
            }
            0b10 => {
                // ASR Rd, Rm, #imm5
                let imm5 = ((hw >> 6) & 0x1F) as u8;
                let rm = rn;
                ArmInst::new(
                    Cond::AL,
                    Op::Alu {
                        op: AluOp::Mov,
                        set_flags: true,
                        rd,
                        rn: Reg::R0,
                        op2: Operand2::Reg {
                            rm,
                            shift: Shift {
                                shift_type: ShiftType::Asr,
                                amount: ShiftAmount::Imm(imm5),
                            },
                        },
                    },
                    raw,
                )
            }
            0b11 => {
                // Add / Subtract (3-register or 3-bit immediate)
                let is_sub = ((hw >> 9) & 1) != 0;
                let is_imm = ((hw >> 10) & 1) != 0;
                let op2_val = ((hw >> 6) & 0x7) as u8;

                let op2 = if is_imm {
                    Operand2::Imm(op2_val as u32)
                } else {
                    let rm = Reg::from_u8(op2_val).unwrap_or(Reg::R0);
                    Operand2::Reg {
                        rm,
                        shift: Shift {
                            shift_type: ShiftType::Lsl,
                            amount: ShiftAmount::Imm(0),
                        },
                    }
                };

                let alu_op = if is_sub { AluOp::Sub } else { AluOp::Add };
                ArmInst::new(
                    Cond::AL,
                    Op::Alu {
                        op: alu_op,
                        set_flags: true,
                        rd,
                        rn,
                        op2,
                    },
                    raw,
                )
            }
            _ => unreachable!(),
        }
    }

    fn decode_t16_imm_ops(hw: u16, raw: u32) -> ArmInst {
        let op = (hw >> 11) & 0x3;
        let rd = Reg::from_u8(((hw >> 8) & 0x7) as u8).unwrap_or(Reg::R0);
        let imm8 = (hw & 0xFF) as u32;

        let (alu_op, rn) = match op {
            0b00 => (AluOp::Mov, Reg::R0), // MOV Rd, #imm8
            0b01 => (AluOp::Cmp, rd),      // CMP Rd, #imm8
            0b10 => (AluOp::Add, rd),      // ADD Rd, #imm8
            0b11 => (AluOp::Sub, rd),      // SUB Rd, #imm8
            _ => unreachable!(),
        };

        ArmInst::new(
            Cond::AL,
            Op::Alu {
                op: alu_op,
                set_flags: true,
                rd,
                rn,
                op2: Operand2::Imm(imm8),
            },
            raw,
        )
    }

    fn decode_t16_alu_hireg_ldr(hw: u16, raw: u32) -> ArmInst {
        let sub_op = (hw >> 10) & 0x3;
        match sub_op {
            0b00 => {
                // ALU operation (AND, EOR, LSL, LSR, ASR, ADC, SBC, ROR, TST, RSB/NEG, CMP, CMN, ORR, MUL, BIC, MVN)
                let opcode = ((hw >> 6) & 0xF) as u8;
                let rd = Reg::from_u8((hw & 0x7) as u8).unwrap_or(Reg::R0);
                let rm = Reg::from_u8(((hw >> 3) & 0x7) as u8).unwrap_or(Reg::R0);

                let alu_op = match opcode {
                    0x0 => AluOp::And,
                    0x1 => AluOp::Eor,
                    0x5 => AluOp::Adc,
                    0x6 => AluOp::Sbc,
                    0x8 => AluOp::Tst,
                    0x9 => AluOp::Rsb, // NEG Rd, Rm -> RSB Rd, Rm, #0
                    0xA => AluOp::Cmp,
                    0xB => AluOp::Cmn,
                    0xC => AluOp::Orr,
                    0xD => {
                        // MUL Rd, Rm, Rd
                        return ArmInst::new(
                            Cond::AL,
                            Op::Mul {
                                op: MulOp::Mul,
                                set_flags: true,
                                rd,
                                rn: Reg::R0,
                                rm,
                                rs: rd,
                            },
                            raw,
                        );
                    }
                    0xE => AluOp::Bic,
                    0xF => AluOp::Mvn,
                    _ => AluOp::Mov,
                };

                let rn = if alu_op == AluOp::Rsb {
                    Reg::R0 // NEG is 0 - Rm
                } else {
                    rd
                };

                ArmInst::new(
                    Cond::AL,
                    Op::Alu {
                        op: alu_op,
                        set_flags: true,
                        rd,
                        rn,
                        op2: Operand2::Reg {
                            rm,
                            shift: Shift {
                                shift_type: ShiftType::Lsl,
                                amount: ShiftAmount::Imm(0),
                            },
                        },
                    },
                    raw,
                )
            }
            0b01 => {
                // High register operations / BX / BLX
                let op = ((hw >> 8) & 0x3) as u8;
                let h1 = ((hw >> 7) & 1) as u8;
                let h2 = ((hw >> 6) & 1) as u8;
                let rd_idx = (h1 << 3) | ((hw & 0x7) as u8);
                let rm_idx = (h2 << 3) | (((hw >> 3) & 0x7) as u8);

                let rd = Reg::from_u8(rd_idx).unwrap_or(Reg::R0);
                let rm = Reg::from_u8(rm_idx).unwrap_or(Reg::R0);

                match op {
                    0b00 => {
                        // ADD Rd, Rm
                        ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Add,
                                set_flags: false,
                                rd,
                                rn: rd,
                                op2: Operand2::Reg {
                                    rm,
                                    shift: Shift {
                                        shift_type: ShiftType::Lsl,
                                        amount: ShiftAmount::Imm(0),
                                    },
                                },
                            },
                            raw,
                        )
                    }
                    0b01 => {
                        // CMP Rd, Rm
                        ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Cmp,
                                set_flags: true,
                                rd,
                                rn: rd,
                                op2: Operand2::Reg {
                                    rm,
                                    shift: Shift {
                                        shift_type: ShiftType::Lsl,
                                        amount: ShiftAmount::Imm(0),
                                    },
                                },
                            },
                            raw,
                        )
                    }
                    0b10 => {
                        // MOV Rd, Rm
                        if rd == Reg::R8 && rm == Reg::R8 {
                            // NOP in Thumb! (MOV r8, r8)
                            ArmInst::new(Cond::AL, Op::Nop, raw)
                        } else {
                            ArmInst::new(
                                Cond::AL,
                                Op::Alu {
                                    op: AluOp::Mov,
                                    set_flags: false,
                                    rd,
                                    rn: Reg::R0,
                                    op2: Operand2::Reg {
                                        rm,
                                        shift: Shift {
                                            shift_type: ShiftType::Lsl,
                                            amount: ShiftAmount::Imm(0),
                                        },
                                    },
                                },
                                raw,
                            )
                        }
                    }
                    0b11 => {
                        // BX / BLX
                        let is_link = ((hw >> 7) & 1) != 0;
                        ArmInst::new(Cond::AL, Op::BranchExchange { link: is_link, rm }, raw)
                    }
                    _ => unreachable!(),
                }
            }
            0b10 | 0b11 => {
                // LDR Rd, [PC, #imm8 * 4]
                let rd = Reg::from_u8(((hw >> 8) & 0x7) as u8).unwrap_or(Reg::R0);
                let imm8 = ((hw & 0xFF) as u32) * 4;
                ArmInst::new(
                    Cond::AL,
                    Op::LoadStore {
                        is_load: true,
                        size: MemSize::Word,
                        signed: false,
                        rd,
                        rn: Reg::PC,
                        addr_mode: AddrMode::Offset {
                            offset: AddrOffset::Imm(imm8),
                            add: true,
                        },
                    },
                    raw,
                )
            }
            _ => unreachable!(),
        }
    }

    fn decode_t16_load_store_reg(hw: u16, raw: u32) -> ArmInst {
        let opcode = (hw >> 9) & 0x7;
        let rm = Reg::from_u8(((hw >> 6) & 0x7) as u8).unwrap_or(Reg::R0);
        let rn = Reg::from_u8(((hw >> 3) & 0x7) as u8).unwrap_or(Reg::R0);
        let rd = Reg::from_u8((hw & 0x7) as u8).unwrap_or(Reg::R0);

        let (is_load, size, signed) = match opcode {
            0b000 => (false, MemSize::Word, false),     // STR
            0b001 => (false, MemSize::Halfword, false), // STRH
            0b010 => (false, MemSize::Byte, false),     // STRB
            0b011 => (true, MemSize::Byte, true),       // LDRSB
            0b100 => (true, MemSize::Word, false),      // LDR
            0b101 => (true, MemSize::Halfword, false),  // LDRH
            0b110 => (true, MemSize::Byte, false),      // LDRB
            0b111 => (true, MemSize::Halfword, true),   // LDRSH
            _ => unreachable!(),
        };

        ArmInst::new(
            Cond::AL,
            Op::LoadStore {
                is_load,
                size,
                signed,
                rd,
                rn,
                addr_mode: AddrMode::Offset {
                    offset: AddrOffset::Reg {
                        rm,
                        shift_type: ShiftType::Lsl,
                        shift_imm: 0,
                    },
                    add: true,
                },
            },
            raw,
        )
    }

    fn decode_t16_load_store_imm(hw: u16, raw: u32) -> ArmInst {
        let is_byte = ((hw >> 12) & 1) != 0;
        let is_load = ((hw >> 11) & 1) != 0;
        let imm5 = ((hw >> 6) & 0x1F) as u32;
        let rn = Reg::from_u8(((hw >> 3) & 0x7) as u8).unwrap_or(Reg::R0);
        let rd = Reg::from_u8((hw & 0x7) as u8).unwrap_or(Reg::R0);

        let (size, offset_val) = if is_byte {
            (MemSize::Byte, imm5)
        } else {
            (MemSize::Word, imm5 * 4)
        };

        ArmInst::new(
            Cond::AL,
            Op::LoadStore {
                is_load,
                size,
                signed: false,
                rd,
                rn,
                addr_mode: AddrMode::Offset {
                    offset: AddrOffset::Imm(offset_val),
                    add: true,
                },
            },
            raw,
        )
    }

    fn decode_t16_load_store_halfword(hw: u16, raw: u32) -> ArmInst {
        let is_load = ((hw >> 11) & 1) != 0;
        let imm5 = ((hw >> 6) & 0x1F) as u32;
        let rn = Reg::from_u8(((hw >> 3) & 0x7) as u8).unwrap_or(Reg::R0);
        let rd = Reg::from_u8((hw & 0x7) as u8).unwrap_or(Reg::R0);

        ArmInst::new(
            Cond::AL,
            Op::LoadStore {
                is_load,
                size: MemSize::Halfword,
                signed: false,
                rd,
                rn,
                addr_mode: AddrMode::Offset {
                    offset: AddrOffset::Imm(imm5 * 2),
                    add: true,
                },
            },
            raw,
        )
    }

    fn decode_t16_sp_relative(hw: u16, raw: u32) -> ArmInst {
        let is_load = ((hw >> 11) & 1) != 0;
        let rd = Reg::from_u8(((hw >> 8) & 0x7) as u8).unwrap_or(Reg::R0);
        let imm8 = ((hw & 0xFF) as u32) * 4;

        ArmInst::new(
            Cond::AL,
            Op::LoadStore {
                is_load,
                size: MemSize::Word,
                signed: false,
                rd,
                rn: Reg::SP,
                addr_mode: AddrMode::Offset {
                    offset: AddrOffset::Imm(imm8),
                    add: true,
                },
            },
            raw,
        )
    }

    fn decode_t16_add_pc_sp(hw: u16, raw: u32) -> ArmInst {
        let is_sp = ((hw >> 11) & 1) != 0;
        let rd = Reg::from_u8(((hw >> 8) & 0x7) as u8).unwrap_or(Reg::R0);
        let imm8 = ((hw & 0xFF) as u32) * 4;
        let rn = if is_sp { Reg::SP } else { Reg::PC };

        ArmInst::new(
            Cond::AL,
            Op::Alu {
                op: AluOp::Add,
                set_flags: false,
                rd,
                rn,
                op2: Operand2::Imm(imm8),
            },
            raw,
        )
    }

    fn decode_t16_misc(hw: u16, raw: u32) -> ArmInst {
        let sub = (hw >> 8) & 0xF;

        match sub {
            // Adjust SP: ADD/SUB SP, #imm7 * 4
            0b0000 => {
                let is_sub = ((hw >> 7) & 1) != 0;
                let imm7 = ((hw & 0x7F) as u32) * 4;
                let op = if is_sub { AluOp::Sub } else { AluOp::Add };
                ArmInst::new(
                    Cond::AL,
                    Op::Alu {
                        op,
                        set_flags: false,
                        rd: Reg::SP,
                        rn: Reg::SP,
                        op2: Operand2::Imm(imm7),
                    },
                    raw,
                )
            }
            // PUSH {regs, LR}
            0b0100 | 0b0101 => {
                let r_bit = ((hw >> 8) & 1) != 0;
                let mut reg_list = hw & 0xFF;
                if r_bit {
                    reg_list |= 1 << Reg::LR.index();
                }
                ArmInst::new(
                    Cond::AL,
                    Op::LoadStoreMultiple {
                        is_load: false,
                        rn: Reg::SP,
                        mode: BlockAddrMode::Db, // Decrement Before
                        writeback: true,
                        reg_list,
                    },
                    raw,
                )
            }
            // SXTH, SXTB, UXTH, UXTB: 0b0010
            0b0010 => {
                let op_bits = (hw >> 6) & 0x3;
                let rm = Reg::from_u8(((hw >> 3) & 0x7) as u8).unwrap_or(Reg::R0);
                let rd = Reg::from_u8((hw & 0x7) as u8).unwrap_or(Reg::R0);
                let op = match op_bits {
                    0b00 => ExtendOp::Sxth,
                    0b01 => ExtendOp::Sxtb,
                    0b10 => ExtendOp::Uxth,
                    0b11 => ExtendOp::Uxtb,
                    _ => unreachable!(),
                };
                ArmInst::new(
                    Cond::AL,
                    Op::SimdExtend {
                        op,
                        rd,
                        rn: None,
                        rm,
                        rotation: 0,
                    },
                    raw,
                )
            }
            // REV, REV16, REVSH: 0b1010
            0b1010 => {
                let op_bits = (hw >> 6) & 0x3;
                let rm = Reg::from_u8(((hw >> 3) & 0x7) as u8).unwrap_or(Reg::R0);
                let rd = Reg::from_u8((hw & 0x7) as u8).unwrap_or(Reg::R0);
                let op = match op_bits {
                    0b00 => ByteRevOp::Rev,
                    0b01 => ByteRevOp::Rev16,
                    0b11 => ByteRevOp::Revsh,
                    _ => return ArmInst::new(Cond::AL, Op::Unknown(raw), raw),
                };
                ArmInst::new(Cond::AL, Op::ByteRev { op, rd, rm }, raw)
            }
            // POP {regs, PC}
            0b1100 | 0b1101 => {
                let r_bit = ((hw >> 8) & 1) != 0;
                let mut reg_list = hw & 0xFF;
                if r_bit {
                    reg_list |= 1 << Reg::PC.index();
                }
                ArmInst::new(
                    Cond::AL,
                    Op::LoadStoreMultiple {
                        is_load: true,
                        rn: Reg::SP,
                        mode: BlockAddrMode::Ia, // Increment After
                        writeback: true,
                        reg_list,
                    },
                    raw,
                )
            }
            // BKPT
            0b1110 => {
                let imm8 = hw & 0xFF;
                ArmInst::new(Cond::AL, Op::Bkpt { imm: imm8 }, raw)
            }
            // If-Then (IT) and hints (NOP, YIELD, etc.)
            0b1111 => {
                let mask = (hw & 0xF) as u8;
                if mask != 0 {
                    let firstcond = Cond::from_u8(((hw >> 4) & 0xF) as u8);
                    ArmInst::new(Cond::AL, Op::It { firstcond, mask }, raw)
                } else {
                    ArmInst::new(Cond::AL, Op::Nop, raw)
                }
            }
            _ => ArmInst::new(Cond::AL, Op::Unknown(raw), raw),
        }
    }

    fn decode_t16_ldm_stm(hw: u16, raw: u32) -> ArmInst {
        let is_load = ((hw >> 11) & 1) != 0;
        let rn = Reg::from_u8(((hw >> 8) & 0x7) as u8).unwrap_or(Reg::R0);
        let reg_list = hw & 0xFF;

        ArmInst::new(
            Cond::AL,
            Op::LoadStoreMultiple {
                is_load,
                rn,
                mode: BlockAddrMode::Ia,
                writeback: true,
                reg_list,
            },
            raw,
        )
    }

    fn decode_t16_cond_branch_svc(hw: u16, raw: u32) -> ArmInst {
        let cond_bits = ((hw >> 8) & 0xF) as u8;

        if cond_bits == 0b1111 {
            // SVC #imm8
            let imm8 = (hw & 0xFF) as u32;
            ArmInst::new(Cond::AL, Op::Svc { imm: imm8 }, raw)
        } else {
            // Conditional branch B<cond>
            let cond = Cond::from_u8(cond_bits);
            let imm8 = (hw & 0xFF) as i8;
            // Target is PC + 4 + imm8 * 2
            let offset = (imm8 as i32) * 2;
            ArmInst::new(
                cond,
                Op::Branch {
                    link: false,
                    target: BranchTarget::Imm(offset),
                },
                raw,
            )
        }
    }

    fn decode_t16_uncond_branch(hw: u16, raw: u32) -> ArmInst {
        let imm11 = (hw & 0x7FF) as i16;
        // Sign extend 11-bit offset and multiply by 2
        let offset = ((imm11 << 5) >> 5) * 2;
        ArmInst::new(
            Cond::AL,
            Op::Branch {
                link: false,
                target: BranchTarget::Imm(offset as i32),
            },
            raw,
        )
    }

    /// Decodes 32-bit Thumb-2 instructions
    fn decode_thumb32(hw1: u16, hw2: u16, raw: u32) -> ArmInst {
        let _op1 = (hw1 >> 11) & 0x3;
        let _op2 = (hw1 >> 4) & 0x7F;

        // Branch and Link (BL / BLX immediate): hw1 prefix is 1111 0... (0xF000..0xF7FF)
        if (hw1 & 0xF800) == 0xF000 && ((hw2 >> 14) & 0x3) == 0b11 {
            let s = ((hw1 >> 10) & 1) as u32;
            let j1 = ((hw2 >> 13) & 1) as u32;
            let j2 = ((hw2 >> 11) & 1) as u32;
            let imm10 = (hw1 & 0x3FF) as u32;
            let imm11 = (hw2 & 0x7FF) as u32;

            let i1 = !(j1 ^ s) & 1;
            let i2 = !(j2 ^ s) & 1;

            let mut imm25 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
            // Sign-extend from bit 24
            if s != 0 {
                imm25 |= 0xFE00_0000;
            }

            return ArmInst::new(
                Cond::AL,
                Op::Branch {
                    link: true,
                    target: BranchTarget::Imm(imm25 as i32),
                },
                raw,
            );
        }

        // NOP.W hint (0xF3AF 8000)
        if hw1 == 0xF3AF && (hw2 & 0xFF00) == 0x8000 {
            return ArmInst::new(Cond::AL, Op::Nop, raw);
        }

        // Thumb-2 LDRD / STRD (immediate): 1110 100P U1W0 Rn ...
        if (hw1 & 0xFE40) == 0xE840 {
            let p = ((hw1 >> 8) & 1) != 0;
            let u = ((hw1 >> 7) & 1) != 0;
            let w = ((hw1 >> 5) & 1) != 0;
            let is_load = ((hw1 >> 4) & 1) != 0;
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((hw2 >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            let imm8 = ((hw2 & 0xFF) as u32) * 4;
            let offset = AddrOffset::Imm(imm8);
            let addr_mode = if p {
                if w {
                    AddrMode::PreIndex { offset, add: u }
                } else {
                    AddrMode::Offset { offset, add: u }
                }
            } else {
                AddrMode::PostIndex { offset, add: u }
            };
            return ArmInst::new(
                Cond::AL,
                Op::LoadStore {
                    is_load,
                    size: MemSize::Doubleword,
                    signed: false,
                    rd,
                    rn,
                    addr_mode,
                },
                raw,
            );
        }

        // Thumb-2 NEON 3-same and 2-register misc (0xEF.. / 0xFF..)
        if (hw1 & 0xEF00) == 0xEF00 {
            let u = ((hw1 >> 12) & 1) as u32;
            let arm_raw = 0xF200_0000 | (u << 24) | (((hw1 & 0x00FF) as u32) << 16) | (hw2 as u32);
            if let Some(inst) = ArmDecoder::decode_neon(arm_raw) {
                return ArmInst::new(Cond::AL, inst.op, raw);
            }
        }

        // Thumb-2 NEON Load/Store (VLD1..4 / VST1..4: 0xF900..)
        if (hw1 & 0xFF00) == 0xF900 {
            let arm_raw = 0xF400_0000 | (((hw1 & 0x00FF) as u32) << 16) | (hw2 as u32);
            if let Some(inst) = ArmDecoder::decode_neon(arm_raw) {
                return ArmInst::new(Cond::AL, inst.op, raw);
            }
        }

        // Thumb-2 SDIV / UDIV: 0xFB9n_Fdm / 0xFBBn_Fdm
        if ((hw1 & 0xFFD0) == 0xFB90) && ((hw2 & 0xF0F0) == 0xF0F0) {
            let signed = (hw1 & 0x0020) == 0;
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((hw2 & 0xF) as u8).unwrap_or(Reg::R0);
            return ArmInst::new(Cond::AL, Op::Div { signed, rd, rn, rm }, raw);
        }

        // Thumb-32 UBFX: 1111 0011 1100 Rn
        if (hw1 & 0xFFF0) == 0xF3C0 {
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let lsb = ((((hw2 >> 12) & 0x7) << 2) | ((hw2 >> 6) & 0x3)) as u8;
            let width = ((hw2 & 0x1F) as u8) + 1;
            return ArmInst::new(Cond::AL, Op::BitField { op: BitFieldOp::Ubfx, rd, rn, lsb, width }, raw);
        }

        // Thumb-32 SBFX: 1111 0011 0100 Rn
        if (hw1 & 0xFFF0) == 0xF340 {
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let lsb = ((((hw2 >> 12) & 0x7) << 2) | ((hw2 >> 6) & 0x3)) as u8;
            let width = ((hw2 & 0x1F) as u8) + 1;
            return ArmInst::new(Cond::AL, Op::BitField { op: BitFieldOp::Sbfx, rd, rn, lsb, width }, raw);
        }

        // Thumb-32 BFI / BFC: 1111 0011 0110 Rn
        if (hw1 & 0xFFF0) == 0xF360 {
            let rn_raw = (hw1 & 0xF) as u8;
            let rn = Reg::from_u8(rn_raw).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let lsb = ((((hw2 >> 12) & 0x7) << 2) | ((hw2 >> 6) & 0x3)) as u8;
            let msb = (hw2 & 0x1F) as u8;
            let width = if msb >= lsb { msb - lsb + 1 } else { 0 };
            let op = if rn_raw == 15 { BitFieldOp::Bfc } else { BitFieldOp::Bfi };
            return ArmInst::new(Cond::AL, Op::BitField { op, rd, rn, lsb, width }, raw);
        }

        // Thumb-32 RBIT, REV.W, REV16.W, REVSH.W: 0xFA9n_F0xm
        if (hw1 & 0xFFF0) == 0xFA90 {
            let rm = Reg::from_u8((hw2 & 0xF) as u8).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let op_nibble = (hw2 >> 4) & 0xF;
            let op = match op_nibble {
                0x8 => Some(ByteRevOp::Rev),
                0x9 => Some(ByteRevOp::Rev16),
                0xA => Some(ByteRevOp::Rbit),
                0xB => Some(ByteRevOp::Revsh),
                _ => None,
            };
            if let Some(op) = op {
                return ArmInst::new(Cond::AL, Op::ByteRev { op, rd, rm }, raw);
            }
        }

        // Thumb-32 SEL: 0xFAA0_F080
        if (hw1 & 0xFFF0) == 0xFAA0 && (hw2 & 0xF0F0) == 0xF080 {
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((hw2 & 0xF) as u8).unwrap_or(Reg::R0);
            return ArmInst::new(Cond::AL, Op::SimdSel { rd, rn, rm }, raw);
        }

        // Thumb-32 Parallel Arithmetic (SADD8, SSUB8, SADD16, SSUB16, SASX, SSAX, U..., Q..., SH..., UH...)
        if (hw1 & 0xFF00) == 0xFA00 && (hw1 & 0x0080) != 0 && (hw2 & 0xF080) == 0xF000 {
            let op1 = ((hw1 >> 4) & 0xF) as u8;
            let op2 = ((hw2 >> 4) & 0x7) as u8;
            let op = match (op1, op2) {
                // Add8 (0x8)
                (0x8, 0) => Some(SimdParallelOp::Sadd8),
                (0x8, 1) => Some(SimdParallelOp::Qadd8),
                (0x8, 2) => Some(SimdParallelOp::Shadd8),
                (0x8, 4) => Some(SimdParallelOp::Uadd8),
                (0x8, 5) => Some(SimdParallelOp::Uqadd8),
                (0x8, 6) => Some(SimdParallelOp::Uhadd8),
                // Add16 (0x9)
                (0x9, 0) => Some(SimdParallelOp::Sadd16),
                (0x9, 1) => Some(SimdParallelOp::Qadd16),
                (0x9, 2) => Some(SimdParallelOp::Shadd16),
                (0x9, 4) => Some(SimdParallelOp::Uadd16),
                (0x9, 5) => Some(SimdParallelOp::Uqadd16),
                (0x9, 6) => Some(SimdParallelOp::Uhadd16),
                // Asx (0xA)
                (0xA, 0) => Some(SimdParallelOp::Sasx),
                (0xA, 1) => Some(SimdParallelOp::Qasx),
                (0xA, 2) => Some(SimdParallelOp::Shasx),
                (0xA, 4) => Some(SimdParallelOp::Uasx),
                (0xA, 5) => Some(SimdParallelOp::Uqasx),
                (0xA, 6) => Some(SimdParallelOp::Uhasx),
                // Sub8 (0xC)
                (0xC, 0) => Some(SimdParallelOp::Ssub8),
                (0xC, 1) => Some(SimdParallelOp::Qsub8),
                (0xC, 2) => Some(SimdParallelOp::Shsub8),
                (0xC, 4) => Some(SimdParallelOp::Usub8),
                (0xC, 5) => Some(SimdParallelOp::Uqsub8),
                (0xC, 6) => Some(SimdParallelOp::Uhsub8),
                // Sub16 (0xD)
                (0xD, 0) => Some(SimdParallelOp::Ssub16),
                (0xD, 1) => Some(SimdParallelOp::Qsub16),
                (0xD, 2) => Some(SimdParallelOp::Shsub16),
                (0xD, 4) => Some(SimdParallelOp::Usub16),
                (0xD, 5) => Some(SimdParallelOp::Uqsub16),
                (0xD, 6) => Some(SimdParallelOp::Uhsub16),
                // Sax (0xE)
                (0xE, 0) => Some(SimdParallelOp::Ssax),
                (0xE, 1) => Some(SimdParallelOp::Qsax),
                (0xE, 2) => Some(SimdParallelOp::Shsax),
                (0xE, 4) => Some(SimdParallelOp::Usax),
                (0xE, 5) => Some(SimdParallelOp::Uqsax),
                (0xE, 6) => Some(SimdParallelOp::Uhsax),
                _ => None,
            };
            if let Some(op) = op {
                let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
                let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
                let rm = Reg::from_u8((hw2 & 0xF) as u8).unwrap_or(Reg::R0);
                return ArmInst::new(Cond::AL, Op::SimdParallel { op, rd, rn, rm }, raw);
            }
        }

        // Thumb-32 PKHBT / PKHTB: 0xEAC0
        if (hw1 & 0xFFF0) == 0xEAC0 && (hw2 & 0x8010) == 0 {
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((hw2 & 0xF) as u8).unwrap_or(Reg::R0);
            let tb = ((hw2 >> 5) & 1) != 0;
            let imm3 = ((hw2 >> 12) & 7) as u8;
            let imm2 = ((hw2 >> 6) & 3) as u8;
            let shift = (imm3 << 2) | imm2;
            let op = if tb { PkhOp::Pkhtb } else { PkhOp::Pkhbt };
            return ArmInst::new(Cond::AL, Op::SimdPkh { op, rd, rn, rm, shift }, raw);
        }

        // Thumb-32 Extend and Extend & Add (SXTAH, UXTAH, SXTAB16, UXTAB16, SXTAB, UXTAB, SXTH.W, UXTH.W, ...)
        if (hw1 & 0xFF80) == 0xFA00 && (hw1 & 0x0080) == 0 && (hw2 & 0xF0C0) == 0xF080 {
            let op_bits = (hw1 >> 4) & 7;
            let op = match op_bits {
                0 => Some(ExtendOp::Sxth),
                1 => Some(ExtendOp::Uxth),
                2 => Some(ExtendOp::Sxtb16),
                3 => Some(ExtendOp::Uxtb16),
                4 => Some(ExtendOp::Sxtb),
                5 => Some(ExtendOp::Uxtb),
                _ => None,
            };
            if let Some(op) = op {
                let rn_raw = (hw1 & 0xF) as u8;
                let rn = if rn_raw == 15 { None } else { Reg::from_u8(rn_raw) };
                let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
                let rm = Reg::from_u8((hw2 & 0xF) as u8).unwrap_or(Reg::R0);
                let rotation = (((hw2 >> 4) & 3) as u8) * 8;
                return ArmInst::new(Cond::AL, Op::SimdExtend { op, rd, rn, rm, rotation }, raw);
            }
        }

        // Thumb-2 VMOV 2 core registers <-> 1 double or 2 singles
        if (hw1 & 0xFFE0) == 0xEC40 && ((hw2 & 0x0FD0) == 0x0B10 || (hw2 & 0x0FD0) == 0x0A10) {
            let to_core = ((hw1 >> 4) & 1) != 0;
            let is_double = ((hw2 >> 8) & 0xF) == 0xB;
            let rt2 = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let rt = Reg::from_u8(((hw2 >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            let m_bit = ((hw2 >> 5) & 1) as u8;
            let vm = (hw2 & 0xF) as u8;
            let vfp_reg = if is_double {
                let d_idx = (m_bit << 4) | vm;
                VfpReg::D(d_idx)
            } else {
                let s_idx = (vm << 1) | m_bit;
                VfpReg::S(s_idx)
            };
            return ArmInst::new(
                Cond::AL,
                Op::VfpMovTwoCore {
                    to_core,
                    is_double,
                    rt,
                    rt2,
                    vfp_reg,
                },
                raw,
            );
        }

        // Thumb-32 UMAAL: 0xFBE0
        if (hw1 & 0xFFF0) == 0xFBE0 && (hw2 & 0x00F0) == 0x0060 {
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let rd_lo = Reg::from_u8(((hw2 >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            let rd_hi = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((hw2 & 0xF) as u8).unwrap_or(Reg::R0);
            return ArmInst::new(Cond::AL, Op::Umaal { rd_lo, rd_hi, rn, rm }, raw);
        }

        // Thumb-32 SMULxy / SMLAxy: 0xFB10
        if (hw1 & 0xFFF0) == 0xFB10 {
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let ra_raw = ((hw2 >> 12) & 0xF) as u8;
            let ra = Reg::from_u8(ra_raw).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((hw2 & 0xF) as u8).unwrap_or(Reg::R0);
            let y_top = ((hw2 >> 5) & 1) != 0;
            let x_top = ((hw2 >> 4) & 1) != 0;
            let op = if ra_raw == 15 {
                DspMulOp::Smul { x_top, y_top }
            } else {
                DspMulOp::Smla { x_top, y_top }
            };
            return ArmInst::new(Cond::AL, Op::DspMul { op, rd, rn: ra, rm, rs: rn }, raw);
        }

        // Thumb-32 SMUAD / SMLAD: 0xFB20
        if (hw1 & 0xFFF0) == 0xFB20 {
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let ra_raw = ((hw2 >> 12) & 0xF) as u8;
            let ra = Reg::from_u8(ra_raw).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((hw2 & 0xF) as u8).unwrap_or(Reg::R0);
            let swap = ((hw2 >> 4) & 1) != 0;
            let op = if ra_raw == 15 {
                DspMulOp::Smuad { swap }
            } else {
                DspMulOp::Smlad { swap }
            };
            return ArmInst::new(Cond::AL, Op::DspMul { op, rd, rn: ra, rm, rs: rn }, raw);
        }

        // Thumb-32 SMULWy / SMLAWy: 0xFB30
        if (hw1 & 0xFFF0) == 0xFB30 {
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let ra_raw = ((hw2 >> 12) & 0xF) as u8;
            let ra = Reg::from_u8(ra_raw).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((hw2 & 0xF) as u8).unwrap_or(Reg::R0);
            let y_top = ((hw2 >> 4) & 1) != 0;
            let op = if ra_raw == 15 {
                DspMulOp::Smulw { y_top }
            } else {
                DspMulOp::Smlaw { y_top }
            };
            return ArmInst::new(Cond::AL, Op::DspMul { op, rd, rn: ra, rm, rs: rn }, raw);
        }

        // Thumb-32 SMUSD / SMLSD: 0xFB40
        if (hw1 & 0xFFF0) == 0xFB40 {
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let ra_raw = ((hw2 >> 12) & 0xF) as u8;
            let ra = Reg::from_u8(ra_raw).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((hw2 & 0xF) as u8).unwrap_or(Reg::R0);
            let swap = ((hw2 >> 4) & 1) != 0;
            let op = if ra_raw == 15 {
                DspMulOp::Smusd { swap }
            } else {
                DspMulOp::Smlsd { swap }
            };
            return ArmInst::new(Cond::AL, Op::DspMul { op, rd, rn: ra, rm, rs: rn }, raw);
        }

        // Thumb-2 VMRS <Rt>, FPSCR (0xEEF1, 0x<Rt>A10)
        if hw1 == 0xEEF1 && (hw2 & 0x0FFF) == 0x0A10 {
            let rt_raw = ((hw2 >> 12) & 0xF) as u8;
            let rt = if rt_raw == 15 {
                None
            } else {
                Some(Reg::from_u8(rt_raw).unwrap_or(Reg::R0))
            };
            return ArmInst::new(Cond::AL, Op::VfpMrsFpscr { rt }, raw);
        }

        // Thumb-2 VMSR FPSCR, <Rt> (0xEEE1, 0x<Rt>A10)
        if hw1 == 0xEEE1 && (hw2 & 0x0FFF) == 0x0A10 {
            let rt_raw = ((hw2 >> 12) & 0xF) as u8;
            let rt = Reg::from_u8(rt_raw).unwrap_or(Reg::R0);
            return ArmInst::new(Cond::AL, Op::VfpMsrFpscr { rt }, raw);
        }

        // Thumb-2 VDUP (ARM core register): 0xEE80..
        if (hw1 & 0xFF90) == 0xEE80 && (hw2 & 0x0F5F) == 0x0B10 {
            let arm_raw = ((hw1 as u32) << 16) | (hw2 as u32);
            let inst = ArmDecoder::decode(arm_raw);
            return ArmInst::new(Cond::AL, inst.op, raw);
        }

        // Thumb-2 VFP instructions (Load/Store Single & Multiple, VPUSH/VPOP, ALU, Conversions)
        if (hw1 & 0xEC00) == 0xEC00 && (hw2 & 0x0E00) == 0x0A00 {
            let arm_raw = 0xE000_0000 | (((hw1 & 0x0FFF) as u32) << 16) | (hw2 as u32);
            let inst = ArmDecoder::decode(arm_raw);
            if !matches!(inst.op, Op::Unknown(_)) {
                return ArmInst::new(Cond::AL, inst.op, raw);
            }
        }

        ArmInst::new(Cond::AL, Op::Unknown(raw), raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thumb_push_pop() {
        // PUSH {r4, lr} -> 0xB510
        let (inst, size) = ThumbDecoder::decode(0xB510, None);
        assert_eq!(size, 2);
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

        // POP {r4, pc} -> 0xBD10
        let (inst, size) = ThumbDecoder::decode(0xBD10, None);
        assert_eq!(size, 2);
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
    fn test_thumb_mov_add_imm() {
        // MOV r1, #42 -> 0x212A
        let (inst, size) = ThumbDecoder::decode(0x212A, None);
        assert_eq!(size, 2);
        match inst.op {
            Op::Alu {
                op,
                rd,
                op2: Operand2::Imm(imm),
                ..
            } => {
                assert_eq!(op, AluOp::Mov);
                assert_eq!(rd, Reg::R1);
                assert_eq!(imm, 42);
            }
            _ => panic!("Expected MOV imm"),
        }

        // ADD r1, #5 -> 0x3105
        let (inst, size) = ThumbDecoder::decode(0x3105, None);
        assert_eq!(size, 2);
        match inst.op {
            Op::Alu {
                op,
                rd,
                op2: Operand2::Imm(imm),
                ..
            } => {
                assert_eq!(op, AluOp::Add);
                assert_eq!(rd, Reg::R1);
                assert_eq!(imm, 5);
            }
            _ => panic!("Expected ADD imm"),
        }
    }

    #[test]
    fn test_thumb_svc() {
        // SVC 0 -> 0xDF00
        let (inst, size) = ThumbDecoder::decode(0xDF00, None);
        assert_eq!(size, 2);
        assert_eq!(inst.op, Op::Svc { imm: 0 });
    }

    #[test]
    fn test_thumb_bx_lr() {
        // BX lr -> 0x4770
        let (inst, size) = ThumbDecoder::decode(0x4770, None);
        assert_eq!(size, 2);
        assert_eq!(
            inst.op,
            Op::BranchExchange {
                link: false,
                rm: Reg::LR
            }
        );
    }

    #[test]
    fn test_thumb_neon_decode() {
        // VADD.F32 Q0, Q0, Q0 -> hi=0xEF00, lo=0x0D40
        let (inst, size) = ThumbDecoder::decode(0xEF00, Some(0x0D40));
        assert_eq!(size, 4);
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

        // VMUL.F32 Q0, Q0, Q0 -> hi=0xFF00, lo=0x0D50
        let (inst, size) = ThumbDecoder::decode(0xFF00, Some(0x0D50));
        assert_eq!(size, 4);
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

        // VABS.F32 Q1, Q2 -> hi=0xFFB9, lo=0x2744
        let (inst, size) = ThumbDecoder::decode(0xFFB9, Some(0x2744));
        assert_eq!(size, 4);
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

        // VLD1.8 {d0, d1}, [r0] -> hi=0xF920, lo=0x0A0F
        let (inst, size) = ThumbDecoder::decode(0xF920, Some(0x0A0F));
        assert_eq!(size, 4);
        assert_eq!(
            inst.op,
            Op::NeonLoadStore {
                is_load: true,
                structure_elements: 1,
                reg_count: 2,
                stride: 1,
                size: NeonSize::I8,
                first_reg: 0,
                rn: Reg::R0,
                writeback: NeonWriteback::None,
            }
        );

        // VLD2.8 {d0, d1}, [r0]! -> hi=0xF920, lo=0x080D
        let (inst_vld2, size_vld2) = ThumbDecoder::decode(0xF920, Some(0x080D));
        assert_eq!(size_vld2, 4);
        assert_eq!(
            inst_vld2.op,
            Op::NeonLoadStore {
                is_load: true,
                structure_elements: 2,
                reg_count: 2,
                stride: 1,
                size: NeonSize::I8,
                first_reg: 0,
                rn: Reg::R0,
                writeback: NeonWriteback::PostInc,
            }
        );

        // Thumb-2 VMRS APSR_nzcv, FPSCR -> hi=0xEEF1, lo=0xFA10
        let (inst_vmrs, size) = ThumbDecoder::decode(0xEEF1, Some(0xFA10));
        assert_eq!(size, 4);
        assert_eq!(inst_vmrs.op, Op::VfpMrsFpscr { rt: None });

        // Thumb-2 VMSR FPSCR, r3 -> hi=0xEEE1, lo=0x3A10
        let (inst_vmsr, size) = ThumbDecoder::decode(0xEEE1, Some(0x3A10));
        assert_eq!(size, 4);
        assert_eq!(inst_vmsr.op, Op::VfpMsrFpscr { rt: Reg::R3 });

        // Thumb-2 VTRN.32 d0, d1 -> hi=0xFFBA, lo=0x0081
        let (inst_vtrn, size) = ThumbDecoder::decode(0xFFBA, Some(0x0081));
        assert_eq!(size, 4);
        assert_eq!(
            inst_vtrn.op,
            Op::NeonPermute {
                op: NeonPermuteOp::Trn,
                size: NeonSize::I32,
                is_quad: false,
                vd: 0,
                vm: 1,
            }
        );

        // Thumb-2 VMULL.P8 q0, d0, d1 -> hi=0xEF80, lo=0x0E01
        let (inst_vmull, size) = ThumbDecoder::decode(0xEF80, Some(0x0E01));
        assert_eq!(size, 4);
        assert_eq!(
            inst_vmull.op,
            Op::NeonPolyMul {
                vd: 0,
                vn: 0,
                vm: 1,
            }
        );

        // Thumb-2 VPADD.F32 d0, d1, d2 -> hi=0xFF01, lo=0x0D02
        let (inst_vpadd, size) = ThumbDecoder::decode(0xFF01, Some(0x0D02));
        assert_eq!(size, 4);
        assert_eq!(
            inst_vpadd.op,
            Op::NeonAlu {
                op: NeonOp::Padd,
                size: NeonSize::F32,
                is_quad: false,
                dst: 0,
                src1: 1,
                src2: 2,
            }
        );

        // Thumb-2 VEXT.8 d0, d1, d2, #3 -> hi=0xEFB1, lo=0x0302
        let (inst_vext, size) = ThumbDecoder::decode(0xEFB1, Some(0x0302));
        assert_eq!(size, 4);
        assert_eq!(
            inst_vext.op,
            Op::NeonExtract {
                is_quad: false,
                imm: 3,
                vd: 0,
                vn: 1,
                vm: 2,
            }
        );

        // Thumb-2 VREV64.32 q0, q1 -> hi=0xFFB8, lo=0x0042
        let (inst_vrev, size) = ThumbDecoder::decode(0xFFB8, Some(0x0042));
        assert_eq!(size, 4);
        assert_eq!(
            inst_vrev.op,
            Op::NeonRev {
                op: NeonRevOp::Rev64,
                size: NeonSize::I32,
                is_quad: true,
                vd: 0,
                vm: 2,
            }
        );

        // Thumb-2 VDUP.32 q0, d2[1] -> hi=0xFFBC, lo=0x0C42
        let (inst_vdup_sc, size) = ThumbDecoder::decode(0xFFBC, Some(0x0C42));
        assert_eq!(size, 4);
        assert_eq!(
            inst_vdup_sc.op,
            Op::NeonDupScalar {
                size: NeonSize::I32,
                index: 1,
                is_quad: true,
                vd: 0,
                vm: 2,
            }
        );

        // Thumb-2 VDUP.32 q0, r3 -> hi=0xEEA0, lo=0x3B10
        let (inst_vdup_core, size) = ThumbDecoder::decode(0xEEA0, Some(0x3B10));
        assert_eq!(size, 4);
        assert_eq!(
            inst_vdup_core.op,
            Op::NeonDupCore {
                size: NeonSize::I32,
                is_quad: true,
                vd: 0,
                rt: Reg::R3,
            }
        );

        // Thumb-2 VMOVN.I16 d0, q1 -> hi=0xFFB2, lo=0x0202
        let (inst_vmovn, size) = ThumbDecoder::decode(0xFFB2, Some(0x0202));
        assert_eq!(size, 4);
        assert_eq!(
            inst_vmovn.op,
            Op::NeonShiftNarrow {
                signed: false,
                dest_unsigned: false,
                saturate: false,
                src_size: NeonSize::I16,
                shift: 0,
                vd: 0,
                vm: 2,
            }
        );

        // Thumb-2 VMOVL.S8 q0, d2 -> hi=0xEF88, lo=0x0A12
        let (inst_vmovl, size) = ThumbDecoder::decode(0xEF88, Some(0x0A12));
        assert_eq!(size, 4);
        assert_eq!(
            inst_vmovl.op,
            Op::NeonShiftWiden {
                signed: true,
                src_size: NeonSize::I8,
                shift: 0,
                vd: 0,
                vm: 2,
            }
        );

        // Thumb-2 VCVT.F32.S32 q0, q1 -> hi=0xFFBB, lo=0x0642
        let (inst_vcvt1, size) = ThumbDecoder::decode(0xFFBB, Some(0x0642));
        assert_eq!(size, 4);
        assert_eq!(
            inst_vcvt1.op,
            Op::NeonCvt {
                op: NeonCvtOp::F32FromS32,
                is_quad: true,
                vd: 0,
                vm: 2,
            }
        );

        // Thumb-2 VCVT.S32.F32 d0, d2 -> hi=0xFFBB, lo=0x0702
        let (inst_vcvt2, size) = ThumbDecoder::decode(0xFFBB, Some(0x0702));
        assert_eq!(size, 4);
        assert_eq!(
            inst_vcvt2.op,
            Op::NeonCvt {
                op: NeonCvtOp::S32FromF32,
                is_quad: false,
                vd: 0,
                vm: 2,
            }
        );

        // Thumb-2 VPUSH {d8-d15} -> hi=0xED2D, lo=0x8B10
        let (inst_vpush, size) = ThumbDecoder::decode(0xED2D, Some(0x8B10));
        assert_eq!(size, 4);
        assert_eq!(
            inst_vpush.op,
            Op::VfpLoadStoreMultiple {
                is_load: false,
                is_double: true,
                writeback: true,
                is_add: false,
                rn: Reg::SP,
                start_reg: 8,
                count: 8,
            }
        );

        // Thumb-2 VPOP {d8-d15} -> hi=0xECBD, lo=0x8B10
        let (inst_vpop, size) = ThumbDecoder::decode(0xECBD, Some(0x8B10));
        assert_eq!(size, 4);
        assert_eq!(
            inst_vpop.op,
            Op::VfpLoadStoreMultiple {
                is_load: true,
                is_double: true,
                writeback: true,
                is_add: true,
                rn: Reg::SP,
                start_reg: 8,
                count: 8,
            }
        );

        // Thumb-2 VCVT.F64.F32 d0, s0 -> hi=0xEEB7, lo=0x0AC0
        let (inst_vcvt_sc, size) = ThumbDecoder::decode(0xEEB7, Some(0x0AC0));
        assert_eq!(size, 4);
        assert_eq!(
            inst_vcvt_sc.op,
            Op::VfpCvt {
                op: VfpCvtOp::F64FromF32,
                dst: VfpReg::D(0),
                src: VfpReg::S(0),
            }
        );
    }

    #[test]
    fn test_thumb_bitfield_and_byte_rev() {
        // Thumb-16 REV r0, r1 -> 0xBA08
        let (inst_rev, size) = ThumbDecoder::decode(0xBA08, None);
        assert_eq!(size, 2);
        assert_eq!(inst_rev.op, Op::ByteRev { op: ByteRevOp::Rev, rd: Reg::R0, rm: Reg::R1 });

        // Thumb-16 REV16 r0, r1 -> 0xBA48
        let (inst_rev16, size) = ThumbDecoder::decode(0xBA48, None);
        assert_eq!(size, 2);
        assert_eq!(inst_rev16.op, Op::ByteRev { op: ByteRevOp::Rev16, rd: Reg::R0, rm: Reg::R1 });

        // Thumb-16 REVSH r0, r1 -> 0xBAC8
        let (inst_revsh, size) = ThumbDecoder::decode(0xBAC8, None);
        assert_eq!(size, 2);
        assert_eq!(inst_revsh.op, Op::ByteRev { op: ByteRevOp::Revsh, rd: Reg::R0, rm: Reg::R1 });

        // Thumb-32 RBIT r0, r1 -> hi=0xFA91, lo=0xF0A1
        let (inst_rbit, size) = ThumbDecoder::decode(0xFA91, Some(0xF0A1));
        assert_eq!(size, 4);
        assert_eq!(inst_rbit.op, Op::ByteRev { op: ByteRevOp::Rbit, rd: Reg::R0, rm: Reg::R1 });

        // Thumb-32 UBFX r0, r1, #1, #8 -> hi=0xF3C1, lo=0x0047
        let (inst_ubfx, size) = ThumbDecoder::decode(0xF3C1, Some(0x0047));
        assert_eq!(size, 4);
        assert_eq!(
            inst_ubfx.op,
            Op::BitField {
                op: BitFieldOp::Ubfx,
                rd: Reg::R0,
                rn: Reg::R1,
                lsb: 1,
                width: 8,
            }
        );

        // Thumb-32 SBFX r0, r1, #1, #8 -> hi=0xF341, lo=0x0047
        let (inst_sbfx, size) = ThumbDecoder::decode(0xF341, Some(0x0047));
        assert_eq!(size, 4);
        assert_eq!(
            inst_sbfx.op,
            Op::BitField {
                op: BitFieldOp::Sbfx,
                rd: Reg::R0,
                rn: Reg::R1,
                lsb: 1,
                width: 8,
            }
        );

        // Thumb-32 BFI r0, r1, #1, #11 -> hi=0xF361, lo=0x004B
        let (inst_bfi, size) = ThumbDecoder::decode(0xF361, Some(0x004B));
        assert_eq!(size, 4);
        assert_eq!(
            inst_bfi.op,
            Op::BitField {
                op: BitFieldOp::Bfi,
                rd: Reg::R0,
                rn: Reg::R1,
                lsb: 1,
                width: 11,
            }
        );

        // Thumb-32 BFC r0, #1, #11 -> hi=0xF36F, lo=0x004B
        let (inst_bfc, size) = ThumbDecoder::decode(0xF36F, Some(0x004B));
        assert_eq!(size, 4);
        assert_eq!(
            inst_bfc.op,
            Op::BitField {
                op: BitFieldOp::Bfc,
                rd: Reg::R0,
                rn: Reg::from_u8(15).unwrap(),
                lsb: 1,
                width: 11,
            }
        );
    }

    #[test]
    fn test_thumb_simd_media_parallel() {
        // Thumb-16 SXTH r0, r2 -> 0xB210
        let (inst, sz) = ThumbDecoder::decode(0xB210, None);
        assert_eq!(sz, 2);
        assert_eq!(
            inst.op,
            Op::SimdExtend {
                op: ExtendOp::Sxth,
                rd: Reg::R0,
                rn: None,
                rm: Reg::R2,
                rotation: 0,
            }
        );

        // Thumb-16 UXTB r0, r2 -> 0xB2D0
        let (inst, sz) = ThumbDecoder::decode(0xB2D0, None);
        assert_eq!(sz, 2);
        assert_eq!(
            inst.op,
            Op::SimdExtend {
                op: ExtendOp::Uxtb,
                rd: Reg::R0,
                rn: None,
                rm: Reg::R2,
                rotation: 0,
            }
        );

        // Thumb-32 SADD8 r0, r1, r2 -> hi=0xFA81, lo=0xF002
        let (inst, sz) = ThumbDecoder::decode(0xFA81, Some(0xF002));
        assert_eq!(sz, 4);
        assert_eq!(
            inst.op,
            Op::SimdParallel {
                op: SimdParallelOp::Sadd8,
                rd: Reg::R0,
                rn: Reg::R1,
                rm: Reg::R2,
            }
        );

        // Thumb-32 UADD8 r0, r1, r2 -> hi=0xFA81, lo=0xF042
        let (inst, sz) = ThumbDecoder::decode(0xFA81, Some(0xF042));
        assert_eq!(sz, 4);
        assert_eq!(
            inst.op,
            Op::SimdParallel {
                op: SimdParallelOp::Uadd8,
                rd: Reg::R0,
                rn: Reg::R1,
                rm: Reg::R2,
            }
        );

        // Thumb-32 SEL r0, r1, r2 -> hi=0xFAA1, lo=0xF082
        let (inst, sz) = ThumbDecoder::decode(0xFAA1, Some(0xF082));
        assert_eq!(sz, 4);
        assert_eq!(
            inst.op,
            Op::SimdSel {
                rd: Reg::R0,
                rn: Reg::R1,
                rm: Reg::R2,
            }
        );

        // Thumb-32 PKHBT r0, r1, r2, LSL #1 -> hi=0xEAC1, lo=0x0042
        let (inst, sz) = ThumbDecoder::decode(0xEAC1, Some(0x0042));
        assert_eq!(sz, 4);
        assert_eq!(
            inst.op,
            Op::SimdPkh {
                op: PkhOp::Pkhbt,
                rd: Reg::R0,
                rn: Reg::R1,
                rm: Reg::R2,
                shift: 1,
            }
        );

        // Thumb-32 SXTAB r0, r1, r2 -> hi=0xFA41, lo=0xF082
        let (inst, sz) = ThumbDecoder::decode(0xFA41, Some(0xF082));
        assert_eq!(sz, 4);
        assert_eq!(
            inst.op,
            Op::SimdExtend {
                op: ExtendOp::Sxtb,
                rd: Reg::R0,
                rn: Some(Reg::R1),
                rm: Reg::R2,
                rotation: 0,
            }
        );
    }
}
