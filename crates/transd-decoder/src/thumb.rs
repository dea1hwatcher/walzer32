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
        let op1 = (hw1 >> 11) & 0x3;
        let _op2 = (hw1 >> 4) & 0x7F;

        // Branch and Link (BL / BLX immediate)
        if op1 == 0b11 && ((hw2 >> 14) & 0x3) == 0b11 {
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

        // Thumb-2 NEON Load/Store (VLD1 / VST1: 0xF900.. / 0xF910..)
        if (hw1 & 0xFF10) == 0xF900 || (hw1 & 0xFF10) == 0xF910 {
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

        // VLD1.8 {d0, d1}, [r0] -> hi=0xF920, lo=0x0A00
        let (inst, size) = ThumbDecoder::decode(0xF920, Some(0x0A00));
        assert_eq!(size, 4);
        assert_eq!(
            inst.op,
            Op::NeonLoadStore {
                is_load: true,
                is_quad: true,
                reg: 0,
                rn: Reg::R0,
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
    }
}
