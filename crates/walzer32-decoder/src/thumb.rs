use walzer32_core::{Cond, Reg};
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

                if matches!(opcode, 0x2 | 0x3 | 0x4 | 0x7) {
                    let shift_type = match opcode {
                        0x2 => ShiftType::Lsl,
                        0x3 => ShiftType::Lsr,
                        0x4 => ShiftType::Asr,
                        0x7 => ShiftType::Ror,
                        _ => unreachable!(),
                    };
                    return ArmInst::new(
                        Cond::AL,
                        Op::Alu {
                            op: AluOp::Mov,
                            set_flags: true,
                            rd,
                            rn: Reg::R0,
                            op2: Operand2::Reg {
                                rm: rd,
                                shift: Shift {
                                    shift_type,
                                    amount: ShiftAmount::Reg(rm),
                                },
                            },
                        },
                        raw,
                    );
                }

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

                if alu_op == AluOp::Rsb {
                    // Thumb-1 NEG Rd, Rm is an alias for RSBS Rd, Rm, #0 (0 - Rm)
                    return ArmInst::new(
                        Cond::AL,
                        Op::Alu {
                            op: AluOp::Rsb,
                            set_flags: true,
                            rd,
                            rn: rm,
                            op2: Operand2::Imm(0),
                        },
                        raw,
                    );
                }

                let rn = rd;

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
        // CBZ / CBNZ: 1011 00i1 1 imm5 Rn / 1011 10i1 1 imm5 Rn
        if (hw & 0xF500) == 0xB100 {
            let is_nonzero = (hw & 0x0800) != 0;
            let rn = Reg::from_u8((hw & 0x7) as u8).unwrap_or(Reg::R0);
            let imm5 = ((hw >> 3) & 0x1F) as u32;
            let i = ((hw >> 9) & 1) as u32;
            let offset = (i << 6) | (imm5 << 1);
            return ArmInst::new(Cond::AL, Op::CompareBranch { is_nonzero, rn, offset }, raw);
        }

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
                    exchange: false,
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
                exchange: false,
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

            let exchange = ((hw2 >> 12) & 1) == 0;
            if exchange {
                imm25 &= !3;
            }

            return ArmInst::new(
                Cond::AL,
                Op::Branch {
                    link: true,
                    exchange,
                    target: BranchTarget::Imm(imm25 as i32),
                },
                raw,
            );
        }

        // Branch (B<c>.W / B.W immediate): hw1 prefix 1111 0... (0xF000..0xF7FF) with hw2 bits [15:14] == 0b10
        if (hw1 & 0xF800) == 0xF000 && ((hw2 >> 14) & 0x3) == 0b10 {
            let s = ((hw1 >> 10) & 1) as u32;
            let j1 = ((hw2 >> 13) & 1) as u32;
            let j2 = ((hw2 >> 11) & 1) as u32;
            let imm11 = (hw2 & 0x7FF) as u32;
            let is_uncond = ((hw2 >> 12) & 1) != 0;

            if is_uncond {
                // B.W Encoding T4
                let imm10 = (hw1 & 0x3FF) as u32;
                let i1 = !(j1 ^ s) & 1;
                let i2 = !(j2 ^ s) & 1;
                let mut imm25 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
                if s != 0 {
                    imm25 |= 0xFE00_0000;
                }
                return ArmInst::new(
                    Cond::AL,
                    Op::Branch {
                        link: false,
                        exchange: false,
                        target: BranchTarget::Imm(imm25 as i32),
                    },
                    raw,
                );
            } else {
                // B<c>.W Encoding T3
                let cond_bits = ((hw1 >> 6) & 0xF) as u8;
                if cond_bits < 0b1110 {
                    let cond = Cond::from_u8(cond_bits);
                    let imm6 = (hw1 & 0x3F) as u32;
                    let mut imm21 = (s << 20) | (j2 << 19) | (j1 << 18) | (imm6 << 12) | (imm11 << 1);
                    if s != 0 {
                        imm21 |= 0xFFE0_0000;
                    }
                    return ArmInst::new(
                        cond,
                        Op::Branch {
                            link: false,
                            exchange: false,
                            target: BranchTarget::Imm(imm21 as i32),
                        },
                        raw,
                    );
                }
            }
        }

        // NOP.W hint (0xF3AF 8000)
        if hw1 == 0xF3AF && (hw2 & 0xFF00) == 0x8000 {
            return ArmInst::new(Cond::AL, Op::Nop, raw);
        }

        // Thumb-32 Data-processing (modified immediate): 1111 0 i 0 op S Rn | 0 imm3 Rd imm8
        if (hw1 & 0xF800) == 0xF000 && (hw1 & 0x0200) == 0 && (hw2 & 0x8000) == 0 {
            let i = ((hw1 >> 10) & 1) as u32;
            let op_bits = (hw1 >> 5) & 0xF;
            let set_flags = (hw1 & 0x10) != 0;
            let rn_raw = (hw1 & 0xF) as u8;
            let rn = Reg::from_u8(rn_raw).unwrap_or(Reg::R0);
            let imm3 = ((hw2 >> 12) & 7) as u32;
            let rd_raw = ((hw2 >> 8) & 0xF) as u8;
            let rd = Reg::from_u8(rd_raw).unwrap_or(Reg::R0);
            let imm8 = (hw2 & 0xFF) as u32;
            let imm32 = Self::thumb_expand_imm(i, imm3, imm8);

            match op_bits {
                0b0000 => {
                    // AND / TST
                    if set_flags && rd_raw == 15 {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Tst,
                                set_flags: true,
                                rd: Reg::R0,
                                rn,
                                op2: Operand2::Imm(imm32),
                            },
                            raw,
                        );
                    } else {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::And,
                                set_flags,
                                rd,
                                rn,
                                op2: Operand2::Imm(imm32),
                            },
                            raw,
                        );
                    }
                }
                0b0001 => {
                    // BIC
                    return ArmInst::new(
                        Cond::AL,
                        Op::Alu {
                            op: AluOp::Bic,
                            set_flags,
                            rd,
                            rn,
                            op2: Operand2::Imm(imm32),
                        },
                        raw,
                    );
                }
                0b0010 => {
                    // ORR / MOV
                    if rn_raw == 15 {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Mov,
                                set_flags,
                                rd,
                                rn: Reg::R0,
                                op2: Operand2::Imm(imm32),
                            },
                            raw,
                        );
                    } else {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Orr,
                                set_flags,
                                rd,
                                rn,
                                op2: Operand2::Imm(imm32),
                            },
                            raw,
                        );
                    }
                }
                0b0011 => {
                    // ORN / MVN
                    if rn_raw == 15 {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Mvn,
                                set_flags,
                                rd,
                                rn: Reg::R0,
                                op2: Operand2::Imm(imm32),
                            },
                            raw,
                        );
                    } else {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Orr,
                                set_flags,
                                rd,
                                rn,
                                op2: Operand2::Imm(!imm32),
                            },
                            raw,
                        );
                    }
                }
                0b0100 => {
                    // EOR / TEQ
                    if set_flags && rd_raw == 15 {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Teq,
                                set_flags: true,
                                rd: Reg::R0,
                                rn,
                                op2: Operand2::Imm(imm32),
                            },
                            raw,
                        );
                    } else {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Eor,
                                set_flags,
                                rd,
                                rn,
                                op2: Operand2::Imm(imm32),
                            },
                            raw,
                        );
                    }
                }
                0b1000 => {
                    // ADD / CMN
                    if set_flags && rd_raw == 15 {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Cmn,
                                set_flags: true,
                                rd: Reg::R0,
                                rn,
                                op2: Operand2::Imm(imm32),
                            },
                            raw,
                        );
                    } else {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Add,
                                set_flags,
                                rd,
                                rn,
                                op2: Operand2::Imm(imm32),
                            },
                            raw,
                        );
                    }
                }
                0b1010 => {
                    // ADC
                    return ArmInst::new(
                        Cond::AL,
                        Op::Alu {
                            op: AluOp::Adc,
                            set_flags,
                            rd,
                            rn,
                            op2: Operand2::Imm(imm32),
                        },
                        raw,
                    );
                }
                0b1011 => {
                    // SBC
                    return ArmInst::new(
                        Cond::AL,
                        Op::Alu {
                            op: AluOp::Sbc,
                            set_flags,
                            rd,
                            rn,
                            op2: Operand2::Imm(imm32),
                        },
                        raw,
                    );
                }
                0b1101 => {
                    // SUB / CMP
                    if set_flags && rd_raw == 15 {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Cmp,
                                set_flags: true,
                                rd: Reg::R0,
                                rn,
                                op2: Operand2::Imm(imm32),
                            },
                            raw,
                        );
                    } else {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Sub,
                                set_flags,
                                rd,
                                rn,
                                op2: Operand2::Imm(imm32),
                            },
                            raw,
                        );
                    }
                }
                0b1110 => {
                    // RSB
                    return ArmInst::new(
                        Cond::AL,
                        Op::Alu {
                            op: AluOp::Rsb,
                            set_flags,
                            rd,
                            rn,
                            op2: Operand2::Imm(imm32),
                        },
                        raw,
                    );
                }
                _ => {}
            }
        }

        // Thumb-32 ADDW: 1111 0 i 1 0 0 0 0 0 Rn | 0 imm3 Rd imm8
        if (hw1 & 0xFBE0) == 0xF200 && (hw2 & 0x8000) == 0 {
            let i = ((hw1 >> 10) & 1) as u32;
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let imm3 = ((hw2 >> 12) & 7) as u32;
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let imm8 = (hw2 & 0xFF) as u32;
            let imm12 = (i << 11) | (imm3 << 8) | imm8;
            return ArmInst::new(
                Cond::AL,
                Op::Alu {
                    op: AluOp::Add,
                    set_flags: false,
                    rd,
                    rn,
                    op2: Operand2::Imm(imm12),
                },
                raw,
            );
        }

        // Thumb-32 SUBW: 1111 0 i 1 0 1 0 1 0 Rn | 0 imm3 Rd imm8
        if (hw1 & 0xFBE0) == 0xF2A0 && (hw2 & 0x8000) == 0 {
            let i = ((hw1 >> 10) & 1) as u32;
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let imm3 = ((hw2 >> 12) & 7) as u32;
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let imm8 = (hw2 & 0xFF) as u32;
            let imm12 = (i << 11) | (imm3 << 8) | imm8;
            return ArmInst::new(
                Cond::AL,
                Op::Alu {
                    op: AluOp::Sub,
                    set_flags: false,
                    rd,
                    rn,
                    op2: Operand2::Imm(imm12),
                },
                raw,
            );
        }

        // Thumb-32 MOVW: 1111 0 i 10 0 1 0 0 imm4 | 0 imm3 Rd imm8
        // Thumb-32 MOVT: 1111 0 i 10 1 1 0 0 imm4 | 0 imm3 Rd imm8
        if ((hw1 & 0xFBF0) == 0xF240 || (hw1 & 0xFBF0) == 0xF2C0) && (hw2 & 0x8000) == 0 {
            let is_top = (hw1 & 0x0080) != 0;
            let i = (hw1 >> 10) & 1;
            let imm4 = hw1 & 0xF;
            let imm3 = (hw2 >> 12) & 7;
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let imm8 = hw2 & 0xFF;
            let imm16 = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8;
            if is_top {
                return ArmInst::new(Cond::AL, Op::Movt { rd, imm: imm16 }, raw);
            } else {
                return ArmInst::new(Cond::AL, Op::Movw { rd, imm: imm16 }, raw);
            }
        }

        // Thumb-32 DMB / DSB / ISB / CLREX: 1111 0011 1011 1111 1000 1111 <op:4> <opt:4>
        if hw1 == 0xF3BF {
            match hw2 & 0xFFF0 {
                0x8F20 => return ArmInst::new(Cond::AL, Op::Clrex, raw),
                0x8F40 => return ArmInst::new(Cond::AL, Op::MemoryBarrier { is_data: true }, raw), // DSB
                0x8F50 => return ArmInst::new(Cond::AL, Op::MemoryBarrier { is_data: true }, raw), // DMB
                0x8F60 => return ArmInst::new(Cond::AL, Op::MemoryBarrier { is_data: false }, raw), // ISB
                _ => {}
            }
        }

        // Thumb-32 TBB / TBH: 1110 1000 1101 Rn | 1111 0000 000H Rm
        if (hw1 & 0xFFF0) == 0xE8D0 && (hw2 & 0xFFE0) == 0xF000 {
            let is_halfword = ((hw2 >> 4) & 1) != 0;
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((hw2 & 0xF) as u8).unwrap_or(Reg::R0);
            return ArmInst::new(Cond::AL, Op::TableBranch { is_halfword, rn, rm }, raw);
        }

        // Thumb-32 LDREX: 1110 1000 0101 Rn | Rt 1111 imm8
        if (hw1 & 0xFFF0) == 0xE850 && (hw2 & 0x0F00) == 0x0F00 {
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((hw2 >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            return ArmInst::new(Cond::AL, Op::AtomicLoadEx { rd, rn }, raw);
        }

        // Thumb-32 STREX: 1110 1000 0100 Rn | Rt Rd 0000 0000
        if (hw1 & 0xFFF0) == 0xE840 && (hw2 & 0x00FF) == 0x0000 {
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8(((hw2 >> 12) & 0xF) as u8).unwrap_or(Reg::R0); // Rt: data to store
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);  // Rd: destination status
            return ArmInst::new(Cond::AL, Op::AtomicStoreEx { rd, rm, rn }, raw);
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

        // Thumb-32 Load / Store Multiple (LDM, LDMIA, LDMDB, POP.W, STM, STMIA, STMDB, PUSH.W)
        // 1110 100x x0xx xxxx (0xE800..0xE9FF with bit 6 == 0)
        if (hw1 & 0xFE40) == 0xE800 {
            let is_db = (hw1 & 0x0100) != 0;
            let mode = if is_db {
                BlockAddrMode::Db
            } else {
                BlockAddrMode::Ia
            };
            let writeback = (hw1 & 0x0020) != 0;
            let is_load = (hw1 & 0x0010) != 0;
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::SP);

            let mut reg_list = hw2 & 0x1FFF;
            if (hw2 & 0x4000) != 0 {
                reg_list |= 1 << 14; // LR
            }
            if (hw2 & 0x8000) != 0 && is_load {
                reg_list |= 1 << 15; // PC
            }

            return ArmInst::new(
                Cond::AL,
                Op::LoadStoreMultiple {
                    is_load,
                    rn,
                    mode,
                    writeback,
                    reg_list,
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

        // Thumb-32 Load / Store Single Data Item: 1111 100 op1 1 op2 Rn (0xF800..0xF9FF)
        if (hw1 & 0xFE00) == 0xF800 {
            let b8 = (hw1 >> 8) & 1;
            let b7 = (hw1 >> 7) & 1;
            let b6 = (hw1 >> 6) & 1;
            let b5 = (hw1 >> 5) & 1;
            let b4 = (hw1 >> 4) & 1;

            if !(b8 == 1 && b4 == 0) {
                let signed = b8 == 1;
                let size = if b6 == 1 {
                    MemSize::Word
                } else if b5 == 1 {
                    MemSize::Halfword
                } else {
                    MemSize::Byte
                };

                let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
                let rd = Reg::from_u8(((hw2 >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
                let is_load = if rn == Reg::PC { true } else { b4 == 1 };

                let addr_mode = if rn == Reg::PC {
                    // ARM ARM A6.3.9 Load/store literal:
                    // When Rn == 15 (PC), b7 is the U bit (1 = add, 0 = subtract)
                    // Offset is always a 12-bit unsigned immediate (imm12)
                    let imm12 = (hw2 & 0xFFF) as u32;
                    AddrMode::Offset {
                        offset: AddrOffset::Imm(imm12),
                        add: b7 == 1,
                    }
                } else if b7 == 1 {
                    let imm12 = (hw2 & 0xFFF) as u32;
                    AddrMode::Offset {
                        offset: AddrOffset::Imm(imm12),
                        add: true,
                    }
                } else if ((hw2 >> 11) & 1) == 0 {
                    let rm = Reg::from_u8((hw2 & 0xF) as u8).unwrap_or(Reg::R0);
                    let shift_imm = ((hw2 >> 4) & 3) as u8;
                    AddrMode::Offset {
                        offset: AddrOffset::Reg {
                            rm,
                            shift_type: ShiftType::Lsl,
                            shift_imm,
                        },
                        add: true,
                    }
                } else {
                    let p = ((hw2 >> 10) & 1) != 0;
                    let u = ((hw2 >> 9) & 1) != 0;
                    let w = ((hw2 >> 8) & 1) != 0;
                    let imm8 = (hw2 & 0xFF) as u32;
                    let offset = AddrOffset::Imm(imm8);
                    if p {
                        if w {
                            AddrMode::PreIndex { offset, add: u }
                        } else {
                            AddrMode::Offset { offset, add: u }
                        }
                    } else {
                        AddrMode::PostIndex { offset, add: u }
                    }
                };

                return ArmInst::new(
                    Cond::AL,
                    Op::LoadStore {
                        is_load,
                        size,
                        signed,
                        rd,
                        rn,
                        addr_mode,
                    },
                    raw,
                );
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

        // Thumb-32 SSAT16 / USAT16: 1111 0011 0010 Rn / 1111 0011 1010 Rn
        if ((hw1 & 0xFFF0) == 0xF320 || (hw1 & 0xFFF0) == 0xF3A0) && (hw2 & 0x70F0) == 0 {
            let is_unsigned = (hw1 & 0x0080) != 0;
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let sat4 = (hw2 & 0xF) as u8;
            let op = if is_unsigned {
                BitSatOp::Usat16 { sat_imm: sat4 }
            } else {
                BitSatOp::Ssat16 { sat_imm: sat4 + 1 }
            };
            return ArmInst::new(Cond::AL, Op::BitSat { op, rd, rn }, raw);
        }

        // Thumb-32 SSAT / USAT: 1111 0011 00sh 0 Rn / 1111 0011 10sh 0 Rn
        if ((hw1 & 0xFFD0) == 0xF300 || (hw1 & 0xFFD0) == 0xF380) && (hw2 & 0x8020) == 0 {
            let is_unsigned = (hw1 & 0x0080) != 0;
            let sh = (hw1 & 0x0020) != 0;
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let imm5 = ((((hw2 >> 12) & 0x7) << 2) | ((hw2 >> 6) & 0x3)) as u8;
            let sat5 = (hw2 & 0x1F) as u8;
            let shift_type = if sh { ShiftType::Asr } else { ShiftType::Lsl };
            let op = if is_unsigned {
                BitSatOp::Usat { sat_imm: sat5, shift_type, shift_imm: imm5 }
            } else {
                BitSatOp::Ssat { sat_imm: sat5 + 1, shift_type, shift_imm: imm5 }
            };
            return ArmInst::new(Cond::AL, Op::BitSat { op, rd, rn }, raw);
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

        // Thumb-32 CLZ: 0xFABm_F08m
        if (hw1 & 0xFFF0) == 0xFAB0 && (hw2 & 0xF0F0) == 0xF080 && (hw1 & 0xF) == (hw2 & 0xF) {
            let rm = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            return ArmInst::new(Cond::AL, Op::Clz { rd, rm }, raw);
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

        // Thumb-32 Data-processing (shifted register): 1110 101 0 op S Rn | 0 imm3 Rd imm2 type Rm
        if (hw1 & 0xFE00) == 0xEA00 && (hw2 & 0x8000) == 0 {
            let op_bits = (hw1 >> 5) & 0xF;
            let set_flags = (hw1 & 0x10) != 0;
            let rn_raw = (hw1 & 0xF) as u8;
            let rn = Reg::from_u8(rn_raw).unwrap_or(Reg::R0);

            let imm3 = ((hw2 >> 12) & 7) as u8;
            let rd_raw = ((hw2 >> 8) & 0xF) as u8;
            let rd = Reg::from_u8(rd_raw).unwrap_or(Reg::R0);
            let imm2 = ((hw2 >> 6) & 3) as u8;
            let type_bits = (hw2 >> 4) & 3;
            let rm = Reg::from_u8((hw2 & 0xF) as u8).unwrap_or(Reg::R0);

            let shift_imm = (imm3 << 2) | imm2;
            let shift_type = match type_bits {
                0 => ShiftType::Lsl,
                1 => ShiftType::Lsr,
                2 => ShiftType::Asr,
                3 => ShiftType::Ror,
                _ => unreachable!(),
            };

            let op2 = Operand2::Reg {
                rm,
                shift: Shift {
                    shift_type,
                    amount: ShiftAmount::Imm(shift_imm),
                },
            };

            match op_bits {
                0b0000 => {
                    if set_flags && rd_raw == 15 {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Tst,
                                set_flags: true,
                                rd: Reg::R0,
                                rn,
                                op2,
                            },
                            raw,
                        );
                    } else {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::And,
                                set_flags,
                                rd,
                                rn,
                                op2,
                            },
                            raw,
                        );
                    }
                }
                0b0001 => {
                    return ArmInst::new(
                        Cond::AL,
                        Op::Alu {
                            op: AluOp::Bic,
                            set_flags,
                            rd,
                            rn,
                            op2,
                        },
                        raw,
                    );
                }
                0b0010 => {
                    if rn_raw == 15 {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Mov,
                                set_flags,
                                rd,
                                rn: Reg::R0,
                                op2,
                            },
                            raw,
                        );
                    } else {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Orr,
                                set_flags,
                                rd,
                                rn,
                                op2,
                            },
                            raw,
                        );
                    }
                }
                0b0011 => {
                    if rn_raw == 15 {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Mvn,
                                set_flags,
                                rd,
                                rn: Reg::R0,
                                op2,
                            },
                            raw,
                        );
                    }
                }
                0b0100 => {
                    if set_flags && rd_raw == 15 {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Teq,
                                set_flags: true,
                                rd: Reg::R0,
                                rn,
                                op2,
                            },
                            raw,
                        );
                    } else {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Eor,
                                set_flags,
                                rd,
                                rn,
                                op2,
                            },
                            raw,
                        );
                    }
                }
                0b1000 => {
                    if set_flags && rd_raw == 15 {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Cmn,
                                set_flags: true,
                                rd: Reg::R0,
                                rn,
                                op2,
                            },
                            raw,
                        );
                    } else {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Add,
                                set_flags,
                                rd,
                                rn,
                                op2,
                            },
                            raw,
                        );
                    }
                }
                0b1010 => {
                    return ArmInst::new(
                        Cond::AL,
                        Op::Alu {
                            op: AluOp::Adc,
                            set_flags,
                            rd,
                            rn,
                            op2,
                        },
                        raw,
                    );
                }
                0b1011 => {
                    return ArmInst::new(
                        Cond::AL,
                        Op::Alu {
                            op: AluOp::Sbc,
                            set_flags,
                            rd,
                            rn,
                            op2,
                        },
                        raw,
                    );
                }
                0b1101 => {
                    if set_flags && rd_raw == 15 {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Cmp,
                                set_flags: true,
                                rd: Reg::R0,
                                rn,
                                op2,
                            },
                            raw,
                        );
                    } else {
                        return ArmInst::new(
                            Cond::AL,
                            Op::Alu {
                                op: AluOp::Sub,
                                set_flags,
                                rd,
                                rn,
                                op2,
                            },
                            raw,
                        );
                    }
                }
                0b1110 => {
                    return ArmInst::new(
                        Cond::AL,
                        Op::Alu {
                            op: AluOp::Rsb,
                            set_flags,
                            rd,
                            rn,
                            op2,
                        },
                        raw,
                    );
                }
                _ => {}
            }
        }

        // Thumb-32 Data-processing (shifted register) - LSL, LSR, ASR, ROR (register): 0xFA00..0xFA7F
        // hw1: 1111 1010 00op S Rn
        // hw2: 1111 Rd   0000 Rm
        if (hw1 & 0xFF80) == 0xFA00 && (hw1 & 0x0080) == 0 && (hw2 & 0xF0F0) == 0xF000 {
            let op_code = (hw1 >> 5) & 0x3;
            let shift_type = match op_code {
                0 => ShiftType::Lsl,
                1 => ShiftType::Lsr,
                2 => ShiftType::Asr,
                3 => ShiftType::Ror,
                _ => unreachable!(),
            };
            let set_flags = (hw1 & 0x10) != 0;
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((hw2 & 0xF) as u8).unwrap_or(Reg::R0);

            return ArmInst::new(
                Cond::AL,
                Op::Alu {
                    op: AluOp::Mov,
                    set_flags,
                    rd,
                    rn: Reg::R0,
                    op2: Operand2::Reg {
                        rm: rn,
                        shift: Shift {
                            shift_type,
                            amount: ShiftAmount::Reg(rm),
                        },
                    },
                },
                raw,
            );
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

        // Thumb-32 QADD / QDADD / QSUB / QDSUB
        if (hw1 & 0xFFF0) == 0xFA80 && (hw2 & 0xF0C0) == 0xF080 {
            let op_code = (hw2 >> 4) & 0x3;
            let op = match op_code {
                0 => CoreSatOp::Qadd,
                1 => CoreSatOp::Qdadd,
                2 => CoreSatOp::Qsub,
                3 => CoreSatOp::Qdsub,
                _ => unreachable!(),
            };
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((hw2 & 0xF) as u8).unwrap_or(Reg::R0);
            return ArmInst::new(Cond::AL, Op::CoreSat { op, rd, rm, rn }, raw);
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

        // Thumb-32 MUL / MLA / MLS: 0xFB00
        if (hw1 & 0xFFF0) == 0xFB00 {
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let ra_raw = ((hw2 >> 12) & 0xF) as u8;
            let ra = Reg::from_u8(ra_raw).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let op1 = (hw2 >> 4) & 0xF;
            let rm = Reg::from_u8((hw2 & 0xF) as u8).unwrap_or(Reg::R0);

            if op1 == 0 {
                let op = if ra_raw == 15 {
                    MulOp::Mul
                } else {
                    MulOp::Mla
                };
                return ArmInst::new(
                    Cond::AL,
                    Op::Mul {
                        op,
                        set_flags: false,
                        rd,
                        rn: ra,
                        rm,
                        rs: rn,
                    },
                    raw,
                );
            } else if op1 == 1 {
                return ArmInst::new(
                    Cond::AL,
                    Op::Mul {
                        op: MulOp::Mls,
                        set_flags: false,
                        rd,
                        rn: ra,
                        rm,
                        rs: rn,
                    },
                    raw,
                );
            }
        }

        // Thumb-32 SMULL / UMULL / SMLAL / UMLAL: 0xFB80, 0xFBA0, 0xFBC0, 0xFBE0
        if (hw1 & 0xFF90) == 0xFB80 && (hw2 & 0x00F0) == 0x0000 {
            let signed = (hw1 & 0x0020) == 0;
            let accumulate = (hw1 & 0x0040) != 0;
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let rd_lo = Reg::from_u8(((hw2 >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            let rd_hi = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((hw2 & 0xF) as u8).unwrap_or(Reg::R0);
            return ArmInst::new(
                Cond::AL,
                Op::MulLong {
                    signed,
                    accumulate,
                    set_flags: false,
                    rd_hi,
                    rd_lo,
                    rm,
                    rs: rn,
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

        // Thumb-32 SMMUL / SMMLA / SMMLS: 0xFB50 / 0xFB60
        if ((hw1 & 0xFFF0) == 0xFB50 || (hw1 & 0xFFF0) == 0xFB60) && (hw2 & 0x00E0) == 0x0000 {
            let is_sub = (hw1 & 0x00F0) == 0x0060;
            let rn = Reg::from_u8((hw1 & 0xF) as u8).unwrap_or(Reg::R0);
            let ra_raw = ((hw2 >> 12) & 0xF) as u8;
            let rd = Reg::from_u8(((hw2 >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let round = ((hw2 >> 4) & 1) != 0;
            let rm = Reg::from_u8((hw2 & 0xF) as u8).unwrap_or(Reg::R0);

            let op = if is_sub {
                HighMulOp::Smmls { round }
            } else if ra_raw == 15 {
                HighMulOp::Smmul { round }
            } else {
                HighMulOp::Smmla { round }
            };
            let ra = if is_sub || ra_raw != 15 {
                Some(Reg::from_u8(ra_raw).unwrap_or(Reg::R0))
            } else {
                None
            };
            return ArmInst::new(Cond::AL, Op::HighMul { op, rd, rn, rm, ra }, raw);
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

        // Thumb-2 CP15 coprocessor instructions (MCR, MRC: cp=15)
        if (hw1 & 0xEF00) == 0xEE00 && (hw2 & 0x0F00) == 0x0F00 {
            let arm_raw = 0xE000_0000 | (((hw1 & 0x0FFF) as u32) << 16) | (hw2 as u32);
            let inst = ArmDecoder::decode(arm_raw);
            if !matches!(inst.op, Op::Unknown(_)) {
                return ArmInst::new(Cond::AL, inst.op, raw);
            }
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

    #[inline]
    pub fn thumb_expand_imm(i: u32, imm3: u32, imm8: u32) -> u32 {
        let imm12 = (i << 11) | (imm3 << 8) | imm8;
        let top4 = imm12 >> 8;
        match top4 {
            0 => imm8,
            1 => imm8 | (imm8 << 16),
            2 => (imm8 << 8) | (imm8 << 24),
            3 => imm8 | (imm8 << 8) | (imm8 << 16) | (imm8 << 24),
            _ => {
                let unrotated = 0x80 | (imm12 & 0x7F);
                let rot = (imm12 >> 7) & 0x1F;
                unrotated.rotate_right(rot)
            }
        }
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

        // PUSH.W {r4-r8, lr} -> 0xE92D 0x41F0
        let (inst32, size32) = ThumbDecoder::decode(0xE92D, Some(0x41F0));
        assert_eq!(size32, 4);
        assert_eq!(
            inst32.op,
            Op::LoadStoreMultiple {
                is_load: false,
                rn: Reg::SP,
                mode: BlockAddrMode::Db,
                writeback: true,
                reg_list: 0x41F0,
            }
        );

        // POP.W {r4-r8, pc} -> 0xE8BD 0x81F0
        let (inst_pop32, size_pop32) = ThumbDecoder::decode(0xE8BD, Some(0x81F0));
        assert_eq!(size_pop32, 4);
        assert_eq!(
            inst_pop32.op,
            Op::LoadStoreMultiple {
                is_load: true,
                rn: Reg::SP,
                mode: BlockAddrMode::Ia,
                writeback: true,
                reg_list: 0x81F0,
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
    #[test]
    fn test_thumb_core_saturation_and_smmul() {
        // Thumb-32 QADD r1, r2, r3 -> hw1=0xFA83, hw2=0xF182
        let (inst, size) = ThumbDecoder::decode(0xFA83, Some(0xF182));
        assert_eq!(size, 4);
        assert_eq!(inst.op, Op::CoreSat { op: CoreSatOp::Qadd, rd: Reg::R1, rm: Reg::R2, rn: Reg::R3 });

        // Thumb-32 QDADD r1, r2, r3 -> hw1=0xFA83, hw2=0xF192
        let (inst, size) = ThumbDecoder::decode(0xFA83, Some(0xF192));
        assert_eq!(size, 4);
        assert_eq!(inst.op, Op::CoreSat { op: CoreSatOp::Qdadd, rd: Reg::R1, rm: Reg::R2, rn: Reg::R3 });

        // Thumb-32 QSUB r1, r2, r3 -> hw1=0xFA83, hw2=0xF1A2
        let (inst, size) = ThumbDecoder::decode(0xFA83, Some(0xF1A2));
        assert_eq!(size, 4);
        assert_eq!(inst.op, Op::CoreSat { op: CoreSatOp::Qsub, rd: Reg::R1, rm: Reg::R2, rn: Reg::R3 });

        // Thumb-32 QDSUB r1, r2, r3 -> hw1=0xFA83, hw2=0xF1B2
        let (inst, size) = ThumbDecoder::decode(0xFA83, Some(0xF1B2));
        assert_eq!(size, 4);
        assert_eq!(inst.op, Op::CoreSat { op: CoreSatOp::Qdsub, rd: Reg::R1, rm: Reg::R2, rn: Reg::R3 });

        // Thumb-32 SSAT r1, #16, r2, lsl #2 -> hw1=0xF302, hw2=0x018F
        let (inst, size) = ThumbDecoder::decode(0xF302, Some(0x018F));
        assert_eq!(size, 4);
        assert_eq!(inst.op, Op::BitSat {
            op: BitSatOp::Ssat { sat_imm: 16, shift_type: ShiftType::Lsl, shift_imm: 2 },
            rd: Reg::R1,
            rn: Reg::R2,
        });

        // Thumb-32 USAT r1, #15, r2, asr #2 -> hw1=0xF3A2, hw2=0x018F
        let (inst, size) = ThumbDecoder::decode(0xF3A2, Some(0x018F));
        assert_eq!(size, 4);
        assert_eq!(inst.op, Op::BitSat {
            op: BitSatOp::Usat { sat_imm: 15, shift_type: ShiftType::Asr, shift_imm: 2 },
            rd: Reg::R1,
            rn: Reg::R2,
        });

        // Thumb-32 SSAT16 r1, #8, r2 -> hw1=0xF322, hw2=0x0107
        let (inst, size) = ThumbDecoder::decode(0xF322, Some(0x0107));
        assert_eq!(size, 4);
        assert_eq!(inst.op, Op::BitSat {
            op: BitSatOp::Ssat16 { sat_imm: 8 },
            rd: Reg::R1,
            rn: Reg::R2,
        });

        // Thumb-32 USAT16 r1, #8, r2 -> hw1=0xF3A2, hw2=0x0108
        let (inst, size) = ThumbDecoder::decode(0xF3A2, Some(0x0108));
        assert_eq!(size, 4);
        assert_eq!(inst.op, Op::BitSat {
            op: BitSatOp::Usat16 { sat_imm: 8 },
            rd: Reg::R1,
            rn: Reg::R2,
        });

        // Thumb-32 SMMUL r1, r2, r3 -> hw1=0xFB52, hw2=0xF103
        let (inst, size) = ThumbDecoder::decode(0xFB52, Some(0xF103));
        assert_eq!(size, 4);
        assert_eq!(inst.op, Op::HighMul {
            op: HighMulOp::Smmul { round: false },
            rd: Reg::R1,
            rn: Reg::R2,
            rm: Reg::R3,
            ra: None,
        });

        // Thumb-32 SMMULR r1, r2, r3 -> hw1=0xFB52, hw2=0xF113
        let (inst, size) = ThumbDecoder::decode(0xFB52, Some(0xF113));
        assert_eq!(size, 4);
        assert_eq!(inst.op, Op::HighMul {
            op: HighMulOp::Smmul { round: true },
            rd: Reg::R1,
            rn: Reg::R2,
            rm: Reg::R3,
            ra: None,
        });

        // Thumb-32 SMMLA r1, r2, r3, r4 -> hw1=0xFB52, hw2=0x4103
        let (inst, size) = ThumbDecoder::decode(0xFB52, Some(0x4103));
        assert_eq!(size, 4);
        assert_eq!(inst.op, Op::HighMul {
            op: HighMulOp::Smmla { round: false },
            rd: Reg::R1,
            rn: Reg::R2,
            rm: Reg::R3,
            ra: Some(Reg::R4),
        });

        // Thumb-32 SMMLS r1, r2, r3, r4 -> hw1=0xFB62, hw2=0x4103
        let (inst, size) = ThumbDecoder::decode(0xFB62, Some(0x4103));
        assert_eq!(size, 4);
        assert_eq!(inst.op, Op::HighMul {
            op: HighMulOp::Smmls { round: false },
            rd: Reg::R1,
            rn: Reg::R2,
            rm: Reg::R3,
            ra: Some(Reg::R4),
        });
    }

    #[test]
    fn test_thumb_movw_movt_cbz_and_table_branch() {
        // CBZ r0, #4 -> 0xB110
        let (inst, size) = ThumbDecoder::decode(0xB110, None);
        assert_eq!(size, 2);
        assert_eq!(inst.op, Op::CompareBranch { is_nonzero: false, rn: Reg::R0, offset: 4 });

        // CBNZ r3, #12 -> 0xB933
        let (inst, size) = ThumbDecoder::decode(0xB933, None);
        assert_eq!(size, 2);
        assert_eq!(inst.op, Op::CompareBranch { is_nonzero: true, rn: Reg::R3, offset: 12 });

        // MOVW r1, #0x1234 -> hw1=0xF241, hw2=0x2134
        let (inst, size) = ThumbDecoder::decode(0xF241, Some(0x2134));
        assert_eq!(size, 4);
        assert_eq!(inst.op, Op::Movw { rd: Reg::R1, imm: 0x1234 });

        // MOVT r1, #0x5678 -> hw1=0xF2C5, hw2=0x6178
        let (inst, size) = ThumbDecoder::decode(0xF2C5, Some(0x6178));
        assert_eq!(size, 4);
        assert_eq!(inst.op, Op::Movt { rd: Reg::R1, imm: 0x5678 });

        // TBB [pc, r0] -> hw1=0xE8DF, hw2=0xF000
        let (inst, size) = ThumbDecoder::decode(0xE8DF, Some(0xF000));
        assert_eq!(size, 4);
        assert_eq!(inst.op, Op::TableBranch { is_halfword: false, rn: Reg::PC, rm: Reg::R0 });

        // TBH [r1, r2, lsl #1] -> hw1=0xE8D1, hw2=0xF012
        let (inst, size) = ThumbDecoder::decode(0xE8D1, Some(0xF012));
        assert_eq!(size, 4);
        assert_eq!(inst.op, Op::TableBranch { is_halfword: true, rn: Reg::R1, rm: Reg::R2 });

        // LDREX r2, [r1] -> hw1=0xE851, hw2=0x2F00 (Rt=R2 at bits 15..12, 1111 at bits 11..8)
        let (inst, size) = ThumbDecoder::decode(0xE851, Some(0x2F00));
        assert_eq!(size, 4);
        assert_eq!(inst.op, Op::AtomicLoadEx { rd: Reg::R2, rn: Reg::R1 });

        // STREX r0, r2, [r1] -> hw1=0xE841, hw2=0x2000 (Rt=R2 at bits 15..12, Rd=R0 at bits 11..8)
        let (inst, size) = ThumbDecoder::decode(0xE841, Some(0x2000));
        assert_eq!(size, 4);
        assert_eq!(inst.op, Op::AtomicStoreEx { rd: Reg::R0, rm: Reg::R2, rn: Reg::R1 });

        // CLREX -> hw1=0xF3BF, hw2=0x8F2F
        let (inst, size) = ThumbDecoder::decode(0xF3BF, Some(0x8F2F));
        assert_eq!(size, 4);
        assert_eq!(inst.op, Op::Clrex);
    }

    #[test]
    fn test_thumb_register_shifts() {
        // Thumb-32 LSR.W R9, R0, R7 -> hw1=0xFA20, hw2=0xF907
        let (inst, sz) = ThumbDecoder::decode(0xFA20, Some(0xF907));
        assert_eq!(sz, 4);
        assert_eq!(
            inst.op,
            Op::Alu {
                op: AluOp::Mov,
                set_flags: false,
                rd: Reg::R9,
                rn: Reg::R0,
                op2: Operand2::Reg {
                    rm: Reg::R0,
                    shift: Shift {
                        shift_type: ShiftType::Lsr,
                        amount: ShiftAmount::Reg(Reg::R7),
                    },
                },
            }
        );

        // 16-bit Thumb LSRS R1, R2 -> opcode=3 (010000 0011 010 001 = 0x40D1)
        let (inst16, sz16) = ThumbDecoder::decode(0x40D1, None);
        assert_eq!(sz16, 2);
        assert_eq!(
            inst16.op,
            Op::Alu {
                op: AluOp::Mov,
                set_flags: true,
                rd: Reg::R1,
                rn: Reg::R0,
                op2: Operand2::Reg {
                    rm: Reg::R1,
                    shift: Shift {
                        shift_type: ShiftType::Lsr,
                        amount: ShiftAmount::Reg(Reg::R2),
                    },
                },
            }
        );
    }

    #[test]
    fn test_thumb_data_proc_imm() {
        // MOV.W R0, #0x100 -> hw1=0xF44F, hw2=0x7080
        let (inst, sz) = ThumbDecoder::decode(0xF44F, Some(0x7080));
        assert_eq!(sz, 4);
        assert_eq!(
            inst.op,
            Op::Alu {
                op: AluOp::Mov,
                set_flags: false,
                rd: Reg::R0,
                rn: Reg::R0,
                op2: Operand2::Imm(0x100),
            }
        );

        // ADDW R0, R1, #0x842 -> hw1=0xF601, hw2=0x0042
        let (addw, sz_addw) = ThumbDecoder::decode(0xF601, Some(0x0042));
        assert_eq!(sz_addw, 4);
        assert_eq!(
            addw.op,
            Op::Alu {
                op: AluOp::Add,
                set_flags: false,
                rd: Reg::R0,
                rn: Reg::R1,
                op2: Operand2::Imm(0x842),
            }
        );
    }

    #[test]
    fn test_thumb_load_store_single() {
        // STR.W R1, [R0, R5, LSL #2] -> hw1=0xF840, hw2=0x1025
        let (inst, sz) = ThumbDecoder::decode(0xF840, Some(0x1025));
        assert_eq!(sz, 4);
        assert_eq!(
            inst.op,
            Op::LoadStore {
                is_load: false,
                size: MemSize::Word,
                signed: false,
                rd: Reg::R1,
                rn: Reg::R0,
                addr_mode: AddrMode::Offset {
                    offset: AddrOffset::Reg {
                        rm: Reg::R5,
                        shift_type: ShiftType::Lsl,
                        shift_imm: 2,
                    },
                    add: true,
                },
            }
        );

        // LDR.W R1, [R0, #0x42] -> hw1=0xF8D0, hw2=0x1042
        let (ldr, sz_ldr) = ThumbDecoder::decode(0xF8D0, Some(0x1042));
        assert_eq!(sz_ldr, 4);
        assert_eq!(
            ldr.op,
            Op::LoadStore {
                is_load: true,
                size: MemSize::Word,
                signed: false,
                rd: Reg::R1,
                rn: Reg::R0,
                addr_mode: AddrMode::Offset {
                    offset: AddrOffset::Imm(0x42),
                    add: true,
                },
            }
        );
    }

    #[test]
    fn test_thumb_data_proc_shifted_reg() {
        // ADD.W R6, R6, R0, LSL #1 -> hw1=0xEB06, hw2=0x0640
        let (inst, sz) = ThumbDecoder::decode(0xEB06, Some(0x0640));
        assert_eq!(sz, 4);
        assert_eq!(
            inst.op,
            Op::Alu {
                op: AluOp::Add,
                set_flags: false,
                rd: Reg::R6,
                rn: Reg::R6,
                op2: Operand2::Reg {
                    rm: Reg::R0,
                    shift: Shift {
                        shift_type: ShiftType::Lsl,
                        amount: ShiftAmount::Imm(1),
                    },
                },
            }
        );
    }

    #[test]
    fn test_thumb_bc_w_and_b_w() {
        // BEQ.W -> hw1=0xF000, hw2=0x817F
        let (inst, sz) = ThumbDecoder::decode(0xF000, Some(0x817F));
        assert_eq!(sz, 4);
        assert_eq!(inst.cond, Cond::EQ);
        assert_eq!(
            inst.op,
            Op::Branch {
                link: false,
                exchange: false,
                target: BranchTarget::Imm(766),
            }
        );
    }

    #[test]
    fn test_thumb_clz() {
        // CLZ R0, R0 -> hw1=0xFAB0, hw2=0xF080
        let (inst, sz) = ThumbDecoder::decode(0xFAB0, Some(0xF080));
        assert_eq!(sz, 4);
        assert_eq!(inst.cond, Cond::AL);
        assert_eq!(inst.op, Op::Clz { rd: Reg::R0, rm: Reg::R0 });

        // CLZ R3, R5 -> hw1=0xFAB5, hw2=0xF385
        let (inst, sz) = ThumbDecoder::decode(0xFAB5, Some(0xF385));
        assert_eq!(sz, 4);
        assert_eq!(inst.cond, Cond::AL);
        assert_eq!(inst.op, Op::Clz { rd: Reg::R3, rm: Reg::R5 });
    }

    #[test]
    fn test_thumb_literal_load_negative() {
        // LDR.W SB, [PC, #-0x44] -> hw1=0xF85F, hw2=0x9044
        let (inst, sz) = ThumbDecoder::decode(0xF85F, Some(0x9044));
        assert_eq!(sz, 4);
        assert_eq!(inst.cond, Cond::AL);
        assert_eq!(
            inst.op,
            Op::LoadStore {
                is_load: true,
                size: MemSize::Word,
                signed: false,
                rd: Reg::R9,
                rn: Reg::PC,
                addr_mode: AddrMode::Offset {
                    offset: AddrOffset::Imm(0x44),
                    add: false,
                },
            }
        );
    }

    #[test]
    fn test_thumb_neg_rsb() {
        // RSBS r2, r5, #0 (NEG r2, r5) -> 0x426A
        let (inst, sz) = ThumbDecoder::decode(0x426A, None);
        assert_eq!(sz, 2);
        assert_eq!(inst.cond, Cond::AL);
        assert_eq!(
            inst.op,
            Op::Alu {
                op: AluOp::Rsb,
                set_flags: true,
                rd: Reg::R2,
                rn: Reg::R5,
                op2: Operand2::Imm(0),
            }
        );
    }
}
