use thiserror::Error;
use transd_core::{CpuState, Cpsr, GuestAddr, Memory, MemoryError, Reg};
use transd_decoder::*;

#[derive(Error, Debug)]
pub enum InterpError {
    #[error("Memory fault: {0}")]
    Memory(#[from] MemoryError),
    #[error("Unknown instruction: 0x{0:08x}")]
    UnknownInstruction(u32),
    #[error("Breakpoint hit at {0}")]
    Breakpoint(GuestAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepResult {
    /// Normal execution, advanced to next instruction
    Continue,
    /// Branch occurred
    Branch { target: GuestAddr },
    /// Supervisor Call (Syscall)
    Svc { imm: u32 },
    /// Breakpoint instruction
    Bkpt { imm: u16 },
}

pub struct Interpreter;

impl Interpreter {
    /// Executes a single instruction at current CPU PC and advances state
    pub fn step(cpu: &mut CpuState, mem: &mut impl Memory) -> Result<StepResult, InterpError> {
        let pc = cpu.pc();
        let is_thumb = cpu.is_thumb();

        // 1. Fetch & Decode
        let (inst, inst_len) = decode_next(mem, pc, is_thumb)?;
        let next_pc = pc.add(inst_len as u32);

        // 2. Evaluate Condition
        if !cpu.check_cond(inst.cond) {
            cpu.set_pc(next_pc);
            return Ok(StepResult::Continue);
        }

        // 3. Execute Operation
        match inst.op {
            Op::Nop => {
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::Alu {
                op,
                set_flags,
                rd,
                rn,
                op2,
            } => {
                let op2_val = Self::eval_op2(cpu, op2);
                let rn_val = if rn.is_pc() {
                    // ARM PC-relative reads: PC + 8 in ARM, PC + 4 in Thumb
                    let pc_offset = if is_thumb { 4 } else { 8 };
                    pc.add(pc_offset).as_u32()
                } else {
                    cpu.reg(rn)
                };

                let mut res = 0u32;
                match op {
                    AluOp::And => {
                        res = rn_val & op2_val;
                        if set_flags {
                            cpu.update_nz(res);
                        }
                    }
                    AluOp::Eor => {
                        res = rn_val ^ op2_val;
                        if set_flags {
                            cpu.update_nz(res);
                        }
                    }
                    AluOp::Sub => {
                        res = if set_flags {
                            cpu.update_sub_flags(rn_val, op2_val, false)
                        } else {
                            rn_val.wrapping_sub(op2_val)
                        };
                    }
                    AluOp::Rsb => {
                        res = if set_flags {
                            cpu.update_sub_flags(op2_val, rn_val, false)
                        } else {
                            op2_val.wrapping_sub(rn_val)
                        };
                    }
                    AluOp::Add => {
                        res = if set_flags {
                            cpu.update_add_flags(rn_val, op2_val, false)
                        } else {
                            rn_val.wrapping_add(op2_val)
                        };
                    }
                    AluOp::Adc => {
                        let c = cpu.cpsr.contains(Cpsr::C);
                        res = if set_flags {
                            cpu.update_add_flags(rn_val, op2_val, c)
                        } else {
                            rn_val.wrapping_add(op2_val).wrapping_add(if c { 1 } else { 0 })
                        };
                    }
                    AluOp::Sbc => {
                        let not_c = !cpu.cpsr.contains(Cpsr::C);
                        res = if set_flags {
                            cpu.update_sub_flags(rn_val, op2_val, not_c)
                        } else {
                            rn_val.wrapping_sub(op2_val).wrapping_sub(if not_c { 1 } else { 0 })
                        };
                    }
                    AluOp::Rsc => {
                        let not_c = !cpu.cpsr.contains(Cpsr::C);
                        res = if set_flags {
                            cpu.update_sub_flags(op2_val, rn_val, not_c)
                        } else {
                            op2_val.wrapping_sub(rn_val).wrapping_sub(if not_c { 1 } else { 0 })
                        };
                    }
                    AluOp::Tst => {
                        cpu.update_nz(rn_val & op2_val);
                    }
                    AluOp::Teq => {
                        cpu.update_nz(rn_val ^ op2_val);
                    }
                    AluOp::Cmp => {
                        cpu.update_sub_flags(rn_val, op2_val, false);
                    }
                    AluOp::Cmn => {
                        cpu.update_add_flags(rn_val, op2_val, false);
                    }
                    AluOp::Orr => {
                        res = rn_val | op2_val;
                        if set_flags {
                            cpu.update_nz(res);
                        }
                    }
                    AluOp::Mov => {
                        res = op2_val;
                        if set_flags {
                            cpu.update_nz(res);
                        }
                    }
                    AluOp::Bic => {
                        res = rn_val & !op2_val;
                        if set_flags {
                            cpu.update_nz(res);
                        }
                    }
                    AluOp::Mvn => {
                        res = !op2_val;
                        if set_flags {
                            cpu.update_nz(res);
                        }
                    }
                }

                if !op.is_test() {
                    if rd.is_pc() {
                        let target = GuestAddr::new(res & !1);
                        cpu.set_pc(target);
                        if (res & 1) != 0 {
                            cpu.set_thumb(true);
                        }
                        return Ok(StepResult::Branch { target });
                    } else {
                        cpu.set_reg(rd, res);
                    }
                }

                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::Mul {
                op,
                set_flags,
                rd,
                rn,
                rm,
                rs,
            } => {
                let rm_val = cpu.reg(rm);
                let rs_val = cpu.reg(rs);
                let rn_val = cpu.reg(rn);

                let res = match op {
                    MulOp::Mul => rm_val.wrapping_mul(rs_val),
                    MulOp::Mla => rm_val.wrapping_mul(rs_val).wrapping_add(rn_val),
                    MulOp::Mls => rn_val.wrapping_sub(rm_val.wrapping_mul(rs_val)),
                };

                cpu.set_reg(rd, res);
                if set_flags {
                    cpu.update_nz(res);
                }

                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::Branch { link, target } => {
                let target_addr = match target {
                    BranchTarget::Imm(offset) => {
                        // Offset is relative to PC + 8 in ARM, PC + 4 in Thumb
                        let pc_base = if is_thumb { 4 } else { 8 };
                        pc.add(pc_base).offset(offset)
                    }
                    BranchTarget::Reg(r) => GuestAddr::new(cpu.reg(r)),
                };

                if link {
                    // Set LR to return address
                    let ret_addr = if is_thumb {
                        next_pc.as_u32() | 1 // Set bit 0 for Thumb return
                    } else {
                        next_pc.as_u32()
                    };
                    cpu.set_lr(ret_addr);
                }

                cpu.set_pc(target_addr);
                Ok(StepResult::Branch { target: target_addr })
            }
            Op::BranchExchange { link, rm } => {
                let target_raw = cpu.reg(rm);
                let thumb_target = (target_raw & 1) != 0;
                let target_addr = GuestAddr::new(target_raw & !1);

                if link {
                    let ret_addr = if is_thumb {
                        next_pc.as_u32() | 1
                    } else {
                        next_pc.as_u32()
                    };
                    cpu.set_lr(ret_addr);
                }

                cpu.set_thumb(thumb_target);
                cpu.set_pc(target_addr);
                Ok(StepResult::Branch { target: target_addr })
            }
            Op::LoadStore {
                is_load,
                size,
                signed,
                rd,
                rn,
                addr_mode,
            } => {
                let rn_val = if rn.is_pc() {
                    let pc_offset = if is_thumb { 4 } else { 8 };
                    (pc.as_u32() + pc_offset) & !3 // PC-relative loads often mask bit 1
                } else {
                    cpu.reg(rn)
                };

                let (eff_addr, wb_val) = Self::eval_addr_mode(cpu, rn_val, addr_mode);

                if let Some(new_rn) = wb_val {
                    cpu.set_reg(rn, new_rn);
                }

                if is_load {
                    let val = match (size, signed) {
                        (MemSize::Byte, false) => mem.read_u8(GuestAddr::new(eff_addr))? as u32,
                        (MemSize::Byte, true) => mem.read_u8(GuestAddr::new(eff_addr))? as i8 as i32 as u32,
                        (MemSize::Halfword, false) => mem.read_u16(GuestAddr::new(eff_addr))? as u32,
                        (MemSize::Halfword, true) => mem.read_u16(GuestAddr::new(eff_addr))? as i16 as i32 as u32,
                        (MemSize::Word, _) => mem.read_u32(GuestAddr::new(eff_addr))?,
                        _ => 0,
                    };

                    if rd.is_pc() {
                        let target = GuestAddr::new(val & !1);
                        cpu.set_pc(target);
                        if (val & 1) != 0 {
                            cpu.set_thumb(true);
                        }
                        return Ok(StepResult::Branch { target });
                    } else {
                        cpu.set_reg(rd, val);
                    }
                } else {
                    let val = cpu.reg(rd);
                    match size {
                        MemSize::Byte => mem.write_u8(GuestAddr::new(eff_addr), val as u8)?,
                        MemSize::Halfword => mem.write_u16(GuestAddr::new(eff_addr), val as u16)?,
                        MemSize::Word => mem.write_u32(GuestAddr::new(eff_addr), val)?,
                        _ => {}
                    }
                }

                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::LoadStoreMultiple {
                is_load,
                rn,
                mode,
                writeback,
                reg_list,
            } => {
                let base = cpu.reg(rn);
                let reg_count = reg_list.count_ones();
                let total_bytes = reg_count * 4;

                let start_addr = match mode {
                    BlockAddrMode::Ia => base,
                    BlockAddrMode::Ib => base.wrapping_add(4),
                    BlockAddrMode::Da => base.wrapping_sub(total_bytes).wrapping_add(4),
                    BlockAddrMode::Db => base.wrapping_sub(total_bytes),
                };

                let mut cur = start_addr;
                let mut pc_loaded = false;
                let mut pc_val = 0u32;

                for i in 0..16 {
                    if (reg_list & (1 << i)) != 0 {
                        let reg = Reg::from_u8(i as u8).unwrap();
                        let addr = GuestAddr::new(cur);
                        if is_load {
                            let val = mem.read_u32(addr)?;
                            if reg.is_pc() {
                                pc_loaded = true;
                                pc_val = val;
                            } else {
                                cpu.set_reg(reg, val);
                            }
                        } else {
                            let val = cpu.reg(reg);
                            mem.write_u32(addr, val)?;
                        }
                        cur = cur.wrapping_add(4);
                    }
                }

                if writeback {
                    let final_base = match mode {
                        BlockAddrMode::Ia | BlockAddrMode::Ib => base.wrapping_add(total_bytes),
                        BlockAddrMode::Da | BlockAddrMode::Db => base.wrapping_sub(total_bytes),
                    };
                    cpu.set_reg(rn, final_base);
                }

                if pc_loaded {
                    let target = GuestAddr::new(pc_val & !1);
                    cpu.set_pc(target);
                    if (pc_val & 1) != 0 {
                        cpu.set_thumb(true);
                    }
                    return Ok(StepResult::Branch { target });
                }

                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::Svc { imm } => {
                cpu.set_pc(next_pc);
                Ok(StepResult::Svc { imm })
            }
            Op::Bkpt { imm } => Ok(StepResult::Bkpt { imm }),
            Op::Clz { rd, rm } => {
                let val = cpu.reg(rm);
                cpu.set_reg(rd, val.leading_zeros());
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::Unknown(raw) => Err(InterpError::UnknownInstruction(raw)),
            _ => {
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
        }
    }

    fn eval_op2(cpu: &CpuState, op2: Operand2) -> u32 {
        match op2 {
            Operand2::Imm(val) => val,
            Operand2::Reg { rm, shift } => {
                let val = cpu.reg(rm);
                let amt = match shift.amount {
                    ShiftAmount::Imm(imm) => imm as u32,
                    ShiftAmount::Reg(r) => cpu.reg(r) & 0xFF,
                };

                match shift.shift_type {
                    ShiftType::Lsl => {
                        if amt >= 32 {
                            0
                        } else {
                            val << amt
                        }
                    }
                    ShiftType::Lsr => {
                        if amt >= 32 {
                            0
                        } else {
                            val >> amt
                        }
                    }
                    ShiftType::Asr => {
                        let signed = val as i32;
                        if amt >= 32 {
                            if signed < 0 {
                                0xFFFF_FFFF
                            } else {
                                0
                            }
                        } else {
                            (signed >> amt) as u32
                        }
                    }
                    ShiftType::Ror => val.rotate_right(amt & 31),
                    ShiftType::Rrx => {
                        let c = if cpu.cpsr.contains(Cpsr::C) { 1 } else { 0 };
                        (val >> 1) | (c << 31)
                    }
                }
            }
        }
    }

    fn eval_addr_mode(
        cpu: &CpuState,
        rn_val: u32,
        addr_mode: AddrMode,
    ) -> (u32, Option<u32>) {
        match addr_mode {
            AddrMode::Offset { offset, add } => {
                let off = Self::eval_offset(cpu, offset);
                let addr = if add {
                    rn_val.wrapping_add(off)
                } else {
                    rn_val.wrapping_sub(off)
                };
                (addr, None)
            }
            AddrMode::PreIndex { offset, add } => {
                let off = Self::eval_offset(cpu, offset);
                let addr = if add {
                    rn_val.wrapping_add(off)
                } else {
                    rn_val.wrapping_sub(off)
                };
                (addr, Some(addr))
            }
            AddrMode::PostIndex { offset, add } => {
                let off = Self::eval_offset(cpu, offset);
                let new_rn = if add {
                    rn_val.wrapping_add(off)
                } else {
                    rn_val.wrapping_sub(off)
                };
                (rn_val, Some(new_rn))
            }
        }
    }

    fn eval_offset(cpu: &CpuState, offset: AddrOffset) -> u32 {
        match offset {
            AddrOffset::Imm(val) => val,
            AddrOffset::Reg {
                rm,
                shift_type,
                shift_imm,
            } => {
                let val = cpu.reg(rm);
                match shift_type {
                    ShiftType::Lsl => val << shift_imm,
                    ShiftType::Lsr => val >> shift_imm,
                    ShiftType::Asr => ((val as i32) >> shift_imm) as u32,
                    ShiftType::Ror => val.rotate_right(shift_imm as u32),
                    ShiftType::Rrx => val >> 1,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transd_core::FlatMemory;

    #[test]
    fn test_interp_basic_arm_addition() {
        let mut cpu = CpuState::new();
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x1000);

        // 0x1000: MOV r1, #10     (0xE3A0100A)
        // 0x1004: ADD r0, r1, #32 (0xE2810020)
        // 0x1008: SVC 0           (0xEF000000)
        mem.write_u32(GuestAddr::new(0x1000), 0xE3A0_100A).unwrap();
        mem.write_u32(GuestAddr::new(0x1004), 0xE281_0020).unwrap();
        mem.write_u32(GuestAddr::new(0x1008), 0xEF00_0000).unwrap();

        cpu.set_pc(GuestAddr::new(0x1000));

        let r1 = Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_eq!(r1, StepResult::Continue);
        assert_eq!(cpu.reg(Reg::R1), 10);
        assert_eq!(cpu.pc(), GuestAddr::new(0x1004));

        let r2 = Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_eq!(r2, StepResult::Continue);
        assert_eq!(cpu.reg(Reg::R0), 42);
        assert_eq!(cpu.pc(), GuestAddr::new(0x1008));

        let r3 = Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_eq!(r3, StepResult::Svc { imm: 0 });
    }

    #[test]
    fn test_interp_arm_loop_countdown() {
        let mut cpu = CpuState::new();
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x1000);

        // 0x1000: MOV r0, #5       (0xE3A00005)
        // loop:
        // 0x1004: SUBS r0, r0, #1  (0xE2500001)
        // 0x1008: BNE loop (-8)    (0x1AFFFFFD)
        // 0x100C: SVC 0            (0xEF000000)
        mem.write_u32(GuestAddr::new(0x1000), 0xE3A0_0005).unwrap();
        mem.write_u32(GuestAddr::new(0x1004), 0xE250_0001).unwrap();
        mem.write_u32(GuestAddr::new(0x1008), 0x1AFF_FFFD).unwrap();
        mem.write_u32(GuestAddr::new(0x100C), 0xEF00_0000).unwrap();

        cpu.set_pc(GuestAddr::new(0x1000));

        // Step through loop until SVC
        let mut steps = 0;
        loop {
            let res = Interpreter::step(&mut cpu, &mut mem).unwrap();
            steps += 1;
            if let StepResult::Svc { .. } = res {
                break;
            }
            assert!(steps < 50, "Infinite loop detected");
        }

        assert_eq!(cpu.reg(Reg::R0), 0);
        assert!(cpu.cpsr.contains(Cpsr::Z));
    }

    #[test]
    fn test_interp_thumb_push_pop_call() {
        let mut cpu = CpuState::new();
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);

        cpu.set_thumb(true);
        cpu.set_sp(0x2800); // Stack pointer at high address

        // Function at 0x1000:
        // PUSH {r4, lr}  -> 0xB510
        // MOV r0, #42    -> 0x202A
        // POP {r4, pc}   -> 0xBD10
        mem.write_u16(GuestAddr::new(0x1000), 0xB510).unwrap();
        mem.write_u16(GuestAddr::new(0x1002), 0x202A).unwrap();
        mem.write_u16(GuestAddr::new(0x1004), 0xBD10).unwrap();

        // Caller setup: LR points to return address 0x1051 (bit 0 = 1 for Thumb)
        cpu.set_lr(0x1051);
        cpu.set_pc(GuestAddr::new(0x1000));
        cpu.set_reg(Reg::R4, 0x1234);

        // 1. PUSH {r4, lr}
        Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.sp(), 0x2800 - 8);

        // 2. MOV r0, #42
        Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.reg(Reg::R0), 42);

        // 3. POP {r4, pc}
        let res = Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.sp(), 0x2800);
        assert_eq!(cpu.reg(Reg::R4), 0x1234);
        assert_eq!(cpu.pc(), GuestAddr::new(0x1050));
        assert!(cpu.is_thumb());
        assert_eq!(res, StepResult::Branch { target: GuestAddr::new(0x1050) });
    }
}
