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

fn get_lane_u64(val: u64, lane: usize, elem_bytes: usize) -> u32 {
    let shift = lane * elem_bytes * 8;
    let mask = match elem_bytes {
        1 => 0xFFu64,
        2 => 0xFFFFu64,
        _ => 0xFFFF_FFFFu64,
    };
    ((val >> shift) & mask) as u32
}

fn set_lane_u64(val: u64, lane: usize, elem_bytes: usize, elem: u32) -> u64 {
    let shift = lane * elem_bytes * 8;
    let mask = match elem_bytes {
        1 => 0xFFu64,
        2 => 0xFFFFu64,
        _ => 0xFFFF_FFFFu64,
    } << shift;
    let elem_masked = (elem as u64) & match elem_bytes {
        1 => 0xFF,
        2 => 0xFFFF,
        _ => 0xFFFF_FFFF,
    };
    (val & !mask) | (elem_masked << shift)
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
        let mut cond = inst.cond;
        let in_it_block = is_thumb && cpu.cpsr.itstate() != 0;
        if is_thumb && !matches!(inst.op, Op::It { .. }) {
            if let Some(it_cond) = cpu.cpsr.advance_itstate() {
                cond = it_cond;
            }
        }

        if !cpu.check_cond(cond) {
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
                mut set_flags,
                rd,
                rn,
                op2,
            } => {
                if in_it_block && !op.is_test() {
                    set_flags = false;
                }
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
                        (MemSize::Doubleword, _) => {
                            let v0 = mem.read_u32(GuestAddr::new(eff_addr))?;
                            let v1 = mem.read_u32(GuestAddr::new(eff_addr.wrapping_add(4)))?;
                            cpu.set_reg(rd, v0);
                            if let Some(rd2) = Reg::from_u8(rd.index() as u8 + 1) {
                                cpu.set_reg(rd2, v1);
                            }
                            v0
                        }
                    };

                    if size != MemSize::Doubleword {
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
                    }
                } else {
                    let val = cpu.reg(rd);
                    match size {
                        MemSize::Byte => mem.write_u8(GuestAddr::new(eff_addr), val as u8)?,
                        MemSize::Halfword => mem.write_u16(GuestAddr::new(eff_addr), val as u16)?,
                        MemSize::Word => mem.write_u32(GuestAddr::new(eff_addr), val)?,
                        MemSize::Doubleword => {
                            let v0 = val;
                            let v1 = if let Some(rd2) = Reg::from_u8(rd.index() as u8 + 1) {
                                cpu.reg(rd2)
                            } else {
                                0
                            };
                            mem.write_u32(GuestAddr::new(eff_addr), v0)?;
                            mem.write_u32(GuestAddr::new(eff_addr.wrapping_add(4)), v1)?;
                        }
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
            Op::Div {
                signed,
                rd,
                rn,
                rm,
            } => {
                let n = cpu.reg(rn);
                let d = cpu.reg(rm);
                let res = if d == 0 {
                    0
                } else if signed {
                    let sn = n as i32;
                    let sd = d as i32;
                    sn.wrapping_div(sd) as u32
                } else {
                    n / d
                };
                cpu.set_reg(rd, res);
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::BitField {
                op,
                rd,
                rn,
                lsb,
                width,
            } => {
                let mask = if width >= 32 {
                    0xFFFF_FFFFu32
                } else {
                    ((1u64 << width) - 1) as u32
                };
                let res = match op {
                    BitFieldOp::Ubfx => {
                        let n = cpu.reg(rn);
                        (n.wrapping_shr(lsb as u32)) & mask
                    }
                    BitFieldOp::Sbfx => {
                        let n = cpu.reg(rn);
                        let extracted = (n.wrapping_shr(lsb as u32)) & mask;
                        let sign_bit = 1u32.wrapping_shl((width - 1) as u32);
                        if (extracted & sign_bit) != 0 {
                            extracted | !mask
                        } else {
                            extracted
                        }
                    }
                    BitFieldOp::Bfi => {
                        let d = cpu.reg(rd);
                        let n = cpu.reg(rn);
                        let insert_val = (n & mask).wrapping_shl(lsb as u32);
                        let clear_mask = !(mask.wrapping_shl(lsb as u32));
                        (d & clear_mask) | insert_val
                    }
                    BitFieldOp::Bfc => {
                        let d = cpu.reg(rd);
                        let clear_mask = !(mask.wrapping_shl(lsb as u32));
                        d & clear_mask
                    }
                };
                cpu.set_reg(rd, res);
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::ByteRev { op, rd, rm } => {
                let m = cpu.reg(rm);
                let res = match op {
                    ByteRevOp::Rev => m.swap_bytes(),
                    ByteRevOp::Rev16 => ((m & 0x00FF_00FF) << 8) | ((m & 0xFF00_FF00) >> 8),
                    ByteRevOp::Revsh => {
                        let lo = (m & 0xFFFF) as u16;
                        (lo.swap_bytes() as i16) as i32 as u32
                    }
                    ByteRevOp::Rbit => m.reverse_bits(),
                };
                cpu.set_reg(rd, res);
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::SimdParallel { op, rd, rn, rm } => {
                let n = cpu.reg(rn);
                let m = cpu.reg(rm);

                let n_b = [
                    (n & 0xFF) as u8,
                    ((n >> 8) & 0xFF) as u8,
                    ((n >> 16) & 0xFF) as u8,
                    ((n >> 24) & 0xFF) as u8,
                ];
                let m_b = [
                    (m & 0xFF) as u8,
                    ((m >> 8) & 0xFF) as u8,
                    ((m >> 16) & 0xFF) as u8,
                    ((m >> 24) & 0xFF) as u8,
                ];
                let n_h = [(n & 0xFFFF) as u16, ((n >> 16) & 0xFFFF) as u16];
                let m_h = [(m & 0xFFFF) as u16, ((m >> 16) & 0xFFFF) as u16];

                let res = match op {
                    // Normal signed (sets GE flags)
                    SimdParallelOp::Sadd8 => {
                        let mut ge = 0u8;
                        let mut res = 0u32;
                        for i in 0..4 {
                            let sum = (n_b[i] as i8 as i16) + (m_b[i] as i8 as i16);
                            if sum >= 0 {
                                ge |= 1 << i;
                            }
                            res |= ((sum as u8) as u32) << (i * 8);
                        }
                        cpu.cpsr.set_ge_bits(ge);
                        res
                    }
                    SimdParallelOp::Ssub8 => {
                        let mut ge = 0u8;
                        let mut res = 0u32;
                        for i in 0..4 {
                            let diff = (n_b[i] as i8 as i16) - (m_b[i] as i8 as i16);
                            if diff >= 0 {
                                ge |= 1 << i;
                            }
                            res |= ((diff as u8) as u32) << (i * 8);
                        }
                        cpu.cpsr.set_ge_bits(ge);
                        res
                    }
                    SimdParallelOp::Sadd16 => {
                        let mut ge = 0u8;
                        let mut res = 0u32;
                        for i in 0..2 {
                            let sum = (n_h[i] as i16 as i32) + (m_h[i] as i16 as i32);
                            if sum >= 0 {
                                ge |= 0b11 << (i * 2);
                            }
                            res |= ((sum as u16) as u32) << (i * 16);
                        }
                        cpu.cpsr.set_ge_bits(ge);
                        res
                    }
                    SimdParallelOp::Ssub16 => {
                        let mut ge = 0u8;
                        let mut res = 0u32;
                        for i in 0..2 {
                            let diff = (n_h[i] as i16 as i32) - (m_h[i] as i16 as i32);
                            if diff >= 0 {
                                ge |= 0b11 << (i * 2);
                            }
                            res |= ((diff as u16) as u32) << (i * 16);
                        }
                        cpu.cpsr.set_ge_bits(ge);
                        res
                    }
                    SimdParallelOp::Sasx => {
                        let mut ge = 0u8;
                        let diff_lo = (n_h[0] as i16 as i32) - (m_h[1] as i16 as i32);
                        let sum_hi = (n_h[1] as i16 as i32) + (m_h[0] as i16 as i32);
                        if diff_lo >= 0 {
                            ge |= 0b0011;
                        }
                        if sum_hi >= 0 {
                            ge |= 0b1100;
                        }
                        cpu.cpsr.set_ge_bits(ge);
                        ((sum_hi as u16 as u32) << 16) | (diff_lo as u16 as u32)
                    }
                    SimdParallelOp::Ssax => {
                        let mut ge = 0u8;
                        let sum_lo = (n_h[0] as i16 as i32) + (m_h[1] as i16 as i32);
                        let diff_hi = (n_h[1] as i16 as i32) - (m_h[0] as i16 as i32);
                        if sum_lo >= 0 {
                            ge |= 0b0011;
                        }
                        if diff_hi >= 0 {
                            ge |= 0b1100;
                        }
                        cpu.cpsr.set_ge_bits(ge);
                        ((diff_hi as u16 as u32) << 16) | (sum_lo as u16 as u32)
                    }

                    // Normal unsigned (sets GE flags)
                    SimdParallelOp::Uadd8 => {
                        let mut ge = 0u8;
                        let mut res = 0u32;
                        for i in 0..4 {
                            let sum = (n_b[i] as u16) + (m_b[i] as u16);
                            if sum >= 0x100 {
                                ge |= 1 << i;
                            }
                            res |= ((sum as u8) as u32) << (i * 8);
                        }
                        cpu.cpsr.set_ge_bits(ge);
                        res
                    }
                    SimdParallelOp::Usub8 => {
                        let mut ge = 0u8;
                        let mut res = 0u32;
                        for i in 0..4 {
                            let diff = (n_b[i] as i16) - (m_b[i] as i16);
                            if diff >= 0 {
                                ge |= 1 << i;
                            }
                            res |= ((diff as u8) as u32) << (i * 8);
                        }
                        cpu.cpsr.set_ge_bits(ge);
                        res
                    }
                    SimdParallelOp::Uadd16 => {
                        let mut ge = 0u8;
                        let mut res = 0u32;
                        for i in 0..2 {
                            let sum = (n_h[i] as u32) + (m_h[i] as u32);
                            if sum >= 0x10000 {
                                ge |= 0b11 << (i * 2);
                            }
                            res |= ((sum as u16) as u32) << (i * 16);
                        }
                        cpu.cpsr.set_ge_bits(ge);
                        res
                    }
                    SimdParallelOp::Usub16 => {
                        let mut ge = 0u8;
                        let mut res = 0u32;
                        for i in 0..2 {
                            let diff = (n_h[i] as i32) - (m_h[i] as i32);
                            if diff >= 0 {
                                ge |= 0b11 << (i * 2);
                            }
                            res |= ((diff as u16) as u32) << (i * 16);
                        }
                        cpu.cpsr.set_ge_bits(ge);
                        res
                    }
                    SimdParallelOp::Uasx => {
                        let mut ge = 0u8;
                        let diff_lo = (n_h[0] as i32) - (m_h[1] as i32);
                        let sum_hi = (n_h[1] as u32) + (m_h[0] as u32);
                        if diff_lo >= 0 {
                            ge |= 0b0011;
                        }
                        if sum_hi >= 0x10000 {
                            ge |= 0b1100;
                        }
                        cpu.cpsr.set_ge_bits(ge);
                        ((sum_hi as u16 as u32) << 16) | (diff_lo as u16 as u32)
                    }
                    SimdParallelOp::Usax => {
                        let mut ge = 0u8;
                        let sum_lo = (n_h[0] as u32) + (m_h[1] as u32);
                        let diff_hi = (n_h[1] as i32) - (m_h[0] as i32);
                        if sum_lo >= 0x10000 {
                            ge |= 0b0011;
                        }
                        if diff_hi >= 0 {
                            ge |= 0b1100;
                        }
                        cpu.cpsr.set_ge_bits(ge);
                        ((diff_hi as u16 as u32) << 16) | (sum_lo as u16 as u32)
                    }

                    // Saturating signed
                    SimdParallelOp::Qadd8 => {
                        let mut res = 0u32;
                        for i in 0..4 {
                            let sum = ((n_b[i] as i8 as i16) + (m_b[i] as i8 as i16)).clamp(-128, 127);
                            res |= ((sum as i8 as u8) as u32) << (i * 8);
                        }
                        res
                    }
                    SimdParallelOp::Qsub8 => {
                        let mut res = 0u32;
                        for i in 0..4 {
                            let diff = ((n_b[i] as i8 as i16) - (m_b[i] as i8 as i16)).clamp(-128, 127);
                            res |= ((diff as i8 as u8) as u32) << (i * 8);
                        }
                        res
                    }
                    SimdParallelOp::Qadd16 => {
                        let mut res = 0u32;
                        for i in 0..2 {
                            let sum = ((n_h[i] as i16 as i32) + (m_h[i] as i16 as i32)).clamp(-32768, 32767);
                            res |= ((sum as i16 as u16) as u32) << (i * 16);
                        }
                        res
                    }
                    SimdParallelOp::Qsub16 => {
                        let mut res = 0u32;
                        for i in 0..2 {
                            let diff = ((n_h[i] as i16 as i32) - (m_h[i] as i16 as i32)).clamp(-32768, 32767);
                            res |= ((diff as i16 as u16) as u32) << (i * 16);
                        }
                        res
                    }
                    SimdParallelOp::Qasx => {
                        let diff_lo = ((n_h[0] as i16 as i32) - (m_h[1] as i16 as i32)).clamp(-32768, 32767);
                        let sum_hi = ((n_h[1] as i16 as i32) + (m_h[0] as i16 as i32)).clamp(-32768, 32767);
                        ((sum_hi as i16 as u16 as u32) << 16) | (diff_lo as i16 as u16 as u32)
                    }
                    SimdParallelOp::Qsax => {
                        let sum_lo = ((n_h[0] as i16 as i32) + (m_h[1] as i16 as i32)).clamp(-32768, 32767);
                        let diff_hi = ((n_h[1] as i16 as i32) - (m_h[0] as i16 as i32)).clamp(-32768, 32767);
                        ((diff_hi as i16 as u16 as u32) << 16) | (sum_lo as i16 as u16 as u32)
                    }

                    // Saturating unsigned
                    SimdParallelOp::Uqadd8 => {
                        let mut res = 0u32;
                        for i in 0..4 {
                            let sum = ((n_b[i] as u16) + (m_b[i] as u16)).min(255);
                            res |= (sum as u32) << (i * 8);
                        }
                        res
                    }
                    SimdParallelOp::Uqsub8 => {
                        let mut res = 0u32;
                        for i in 0..4 {
                            let diff = ((n_b[i] as i16) - (m_b[i] as i16)).max(0);
                            res |= (diff as u32) << (i * 8);
                        }
                        res
                    }
                    SimdParallelOp::Uqadd16 => {
                        let mut res = 0u32;
                        for i in 0..2 {
                            let sum = ((n_h[i] as u32) + (m_h[i] as u32)).min(65535);
                            res |= sum << (i * 16);
                        }
                        res
                    }
                    SimdParallelOp::Uqsub16 => {
                        let mut res = 0u32;
                        for i in 0..2 {
                            let diff = ((n_h[i] as i32) - (m_h[i] as i32)).max(0);
                            res |= (diff as u32) << (i * 16);
                        }
                        res
                    }
                    SimdParallelOp::Uqasx => {
                        let diff_lo = ((n_h[0] as i32) - (m_h[1] as i32)).max(0) as u32;
                        let sum_hi = ((n_h[1] as u32) + (m_h[0] as u32)).min(65535);
                        (sum_hi << 16) | diff_lo
                    }
                    SimdParallelOp::Uqsax => {
                        let sum_lo = ((n_h[0] as u32) + (m_h[1] as u32)).min(65535);
                        let diff_hi = ((n_h[1] as i32) - (m_h[0] as i32)).max(0) as u32;
                        (diff_hi << 16) | sum_lo
                    }

                    // Halving signed (average)
                    SimdParallelOp::Shadd8 => {
                        let mut res = 0u32;
                        for i in 0..4 {
                            let sum = ((n_b[i] as i8 as i16) + (m_b[i] as i8 as i16)) >> 1;
                            res |= ((sum as u8) as u32) << (i * 8);
                        }
                        res
                    }
                    SimdParallelOp::Shsub8 => {
                        let mut res = 0u32;
                        for i in 0..4 {
                            let diff = ((n_b[i] as i8 as i16) - (m_b[i] as i8 as i16)) >> 1;
                            res |= ((diff as u8) as u32) << (i * 8);
                        }
                        res
                    }
                    SimdParallelOp::Shadd16 => {
                        let mut res = 0u32;
                        for i in 0..2 {
                            let sum = ((n_h[i] as i16 as i32) + (m_h[i] as i16 as i32)) >> 1;
                            res |= ((sum as u16) as u32) << (i * 16);
                        }
                        res
                    }
                    SimdParallelOp::Shsub16 => {
                        let mut res = 0u32;
                        for i in 0..2 {
                            let diff = ((n_h[i] as i16 as i32) - (m_h[i] as i16 as i32)) >> 1;
                            res |= ((diff as u16) as u32) << (i * 16);
                        }
                        res
                    }
                    SimdParallelOp::Shasx => {
                        let diff_lo = (((n_h[0] as i16 as i32) - (m_h[1] as i16 as i32)) >> 1) as u16;
                        let sum_hi = (((n_h[1] as i16 as i32) + (m_h[0] as i16 as i32)) >> 1) as u16;
                        ((sum_hi as u32) << 16) | (diff_lo as u32)
                    }
                    SimdParallelOp::Shsax => {
                        let sum_lo = (((n_h[0] as i16 as i32) + (m_h[1] as i16 as i32)) >> 1) as u16;
                        let diff_hi = (((n_h[1] as i16 as i32) - (m_h[0] as i16 as i32)) >> 1) as u16;
                        ((diff_hi as u32) << 16) | (sum_lo as u32)
                    }

                    // Halving unsigned (average)
                    SimdParallelOp::Uhadd8 => {
                        let mut res = 0u32;
                        for i in 0..4 {
                            let sum = ((n_b[i] as u16) + (m_b[i] as u16)) >> 1;
                            res |= ((sum as u8) as u32) << (i * 8);
                        }
                        res
                    }
                    SimdParallelOp::Uhsub8 => {
                        let mut res = 0u32;
                        for i in 0..4 {
                            let diff = ((n_b[i] as i16) - (m_b[i] as i16)) >> 1;
                            res |= ((diff as u8) as u32) << (i * 8);
                        }
                        res
                    }
                    SimdParallelOp::Uhadd16 => {
                        let mut res = 0u32;
                        for i in 0..2 {
                            let sum = ((n_h[i] as u32) + (m_h[i] as u32)) >> 1;
                            res |= (sum & 0xFFFF) << (i * 16);
                        }
                        res
                    }
                    SimdParallelOp::Uhsub16 => {
                        let mut res = 0u32;
                        for i in 0..2 {
                            let diff = ((n_h[i] as i32) - (m_h[i] as i32)) >> 1;
                            res |= ((diff as u16) as u32) << (i * 16);
                        }
                        res
                    }
                    SimdParallelOp::Uhasx => {
                        let diff_lo = (((n_h[0] as i32) - (m_h[1] as i32)) >> 1) as u16;
                        let sum_hi = (((n_h[1] as u32) + (m_h[0] as u32)) >> 1) as u16;
                        ((sum_hi as u32) << 16) | (diff_lo as u32)
                    }
                    SimdParallelOp::Uhsax => {
                        let sum_lo = (((n_h[0] as u32) + (m_h[1] as u32)) >> 1) as u16;
                        let diff_hi = (((n_h[1] as i32) - (m_h[0] as i32)) >> 1) as u16;
                        ((diff_hi as u32) << 16) | (sum_lo as u32)
                    }
                };

                cpu.set_reg(rd, res);
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::SimdSel { rd, rn, rm } => {
                let n = cpu.reg(rn);
                let m = cpu.reg(rm);
                let ge = cpu.cpsr.ge_bits();
                let mut res = 0u32;
                for i in 0..4 {
                    let byte = if (ge & (1 << i)) != 0 {
                        (n >> (i * 8)) & 0xFF
                    } else {
                        (m >> (i * 8)) & 0xFF
                    };
                    res |= byte << (i * 8);
                }
                cpu.set_reg(rd, res);
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::SimdPkh { op, rd, rn, rm, shift } => {
                let n = cpu.reg(rn);
                let m = cpu.reg(rm);
                let res = match op {
                    PkhOp::Pkhbt => {
                        let m_shifted = m.wrapping_shl(shift as u32);
                        (n & 0x0000_FFFF) | (m_shifted & 0xFFFF_0000)
                    }
                    PkhOp::Pkhtb => {
                        let effective_shift = if shift == 0 { 32 } else { shift as u32 };
                        let m_shifted = ((m as i32) >> effective_shift) as u32;
                        (m_shifted & 0x0000_FFFF) | (n & 0xFFFF_0000)
                    }
                };
                cpu.set_reg(rd, res);
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::SimdExtend { op, rd, rn, rm, rotation } => {
                let m = cpu.reg(rm);
                let rotated = if rotation == 0 {
                    m
                } else {
                    m.rotate_right(rotation as u32)
                };
                let n_val = rn.map(|r| cpu.reg(r));
                let res = match op {
                    ExtendOp::Sxtb => {
                        let ext = (rotated as i8 as i32) as u32;
                        n_val.map_or(ext, |n| n.wrapping_add(ext))
                    }
                    ExtendOp::Uxtb => {
                        let ext = (rotated & 0xFF) as u32;
                        n_val.map_or(ext, |n| n.wrapping_add(ext))
                    }
                    ExtendOp::Sxth => {
                        let ext = (rotated as i16 as i32) as u32;
                        n_val.map_or(ext, |n| n.wrapping_add(ext))
                    }
                    ExtendOp::Uxth => {
                        let ext = (rotated & 0xFFFF) as u32;
                        n_val.map_or(ext, |n| n.wrapping_add(ext))
                    }
                    ExtendOp::Sxtb16 => {
                        let ext_lo = ((rotated as i8 as i16) as u16) as u32;
                        let ext_hi = (((rotated >> 16) as i8 as i16) as u16) as u32;
                        let ext = (ext_hi << 16) | ext_lo;
                        match n_val {
                            Some(n) => {
                                let sum_lo = (n & 0xFFFF).wrapping_add(ext_lo) & 0xFFFF;
                                let sum_hi = ((n >> 16) & 0xFFFF).wrapping_add(ext_hi) & 0xFFFF;
                                (sum_hi << 16) | sum_lo
                            }
                            None => ext,
                        }
                    }
                    ExtendOp::Uxtb16 => {
                        let ext_lo = (rotated & 0xFF) as u32;
                        let ext_hi = ((rotated >> 16) & 0xFF) as u32;
                        let ext = (ext_hi << 16) | ext_lo;
                        match n_val {
                            Some(n) => {
                                let sum_lo = (n & 0xFFFF).wrapping_add(ext_lo) & 0xFFFF;
                                let sum_hi = ((n >> 16) & 0xFFFF).wrapping_add(ext_hi) & 0xFFFF;
                                (sum_hi << 16) | sum_lo
                            }
                            None => ext,
                        }
                    }
                };
                cpu.set_reg(rd, res);
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::DspMul { op, rd, rn, rm, rs } => {
                let m = cpu.reg(rm);
                let s = cpu.reg(rs);
                let acc = cpu.reg(rn);

                let res = match op {
                    DspMulOp::Smul { x_top, y_top } => {
                        let m_half = if x_top { (m >> 16) as i16 } else { (m & 0xFFFF) as i16 };
                        let s_half = if y_top { (s >> 16) as i16 } else { (s & 0xFFFF) as i16 };
                        (m_half as i32).wrapping_mul(s_half as i32) as u32
                    }
                    DspMulOp::Smla { x_top, y_top } => {
                        let m_half = if x_top { (m >> 16) as i16 } else { (m & 0xFFFF) as i16 };
                        let s_half = if y_top { (s >> 16) as i16 } else { (s & 0xFFFF) as i16 };
                        let prod = (m_half as i32).wrapping_mul(s_half as i32);
                        prod.wrapping_add(acc as i32) as u32
                    }
                    DspMulOp::Smulw { y_top } => {
                        let s_half = if y_top { (s >> 16) as i16 } else { (s & 0xFFFF) as i16 };
                        let prod = (m as i32 as i64).wrapping_mul(s_half as i32 as i64);
                        (prod >> 16) as i32 as u32
                    }
                    DspMulOp::Smlaw { y_top } => {
                        let s_half = if y_top { (s >> 16) as i16 } else { (s & 0xFFFF) as i16 };
                        let prod = (m as i32 as i64).wrapping_mul(s_half as i32 as i64);
                        ((prod >> 16) as i32).wrapping_add(acc as i32) as u32
                    }
                    DspMulOp::Smuad { swap } => {
                        let s_lo = if swap { (s >> 16) as i16 } else { (s & 0xFFFF) as i16 };
                        let s_hi = if swap { (s & 0xFFFF) as i16 } else { (s >> 16) as i16 };
                        let m_lo = (m & 0xFFFF) as i16;
                        let m_hi = (m >> 16) as i16;
                        let p1 = (m_lo as i32).wrapping_mul(s_lo as i32);
                        let p2 = (m_hi as i32).wrapping_mul(s_hi as i32);
                        p1.wrapping_add(p2) as u32
                    }
                    DspMulOp::Smusd { swap } => {
                        let s_lo = if swap { (s >> 16) as i16 } else { (s & 0xFFFF) as i16 };
                        let s_hi = if swap { (s & 0xFFFF) as i16 } else { (s >> 16) as i16 };
                        let m_lo = (m & 0xFFFF) as i16;
                        let m_hi = (m >> 16) as i16;
                        let p1 = (m_lo as i32).wrapping_mul(s_lo as i32);
                        let p2 = (m_hi as i32).wrapping_mul(s_hi as i32);
                        p1.wrapping_sub(p2) as u32
                    }
                    DspMulOp::Smlad { swap } => {
                        let s_lo = if swap { (s >> 16) as i16 } else { (s & 0xFFFF) as i16 };
                        let s_hi = if swap { (s & 0xFFFF) as i16 } else { (s >> 16) as i16 };
                        let m_lo = (m & 0xFFFF) as i16;
                        let m_hi = (m >> 16) as i16;
                        let p1 = (m_lo as i32).wrapping_mul(s_lo as i32);
                        let p2 = (m_hi as i32).wrapping_mul(s_hi as i32);
                        p1.wrapping_add(p2).wrapping_add(acc as i32) as u32
                    }
                    DspMulOp::Smlsd { swap } => {
                        let s_lo = if swap { (s >> 16) as i16 } else { (s & 0xFFFF) as i16 };
                        let s_hi = if swap { (s & 0xFFFF) as i16 } else { (s >> 16) as i16 };
                        let m_lo = (m & 0xFFFF) as i16;
                        let m_hi = (m >> 16) as i16;
                        let p1 = (m_lo as i32).wrapping_mul(s_lo as i32);
                        let p2 = (m_hi as i32).wrapping_mul(s_hi as i32);
                        p1.wrapping_sub(p2).wrapping_add(acc as i32) as u32
                    }
                };

                cpu.set_reg(rd, res);
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::Umaal { rd_lo, rd_hi, rn, rm } => {
                let n = cpu.reg(rn) as u64;
                let m = cpu.reg(rm) as u64;
                let lo_orig = cpu.reg(rd_lo) as u64;
                let hi_orig = cpu.reg(rd_hi) as u64;
                let res = (n * m).wrapping_add(lo_orig).wrapping_add(hi_orig);
                cpu.set_reg(rd_lo, (res & 0xFFFF_FFFF) as u32);
                cpu.set_reg(rd_hi, (res >> 32) as u32);
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::CoreSat { op, rd, rm, rn } => {
                let m = cpu.reg(rm) as i32;
                let n = cpu.reg(rn) as i32;
                let res = match op {
                    CoreSatOp::Qadd => {
                        let (sum, of) = m.overflowing_add(n);
                        if of {
                            cpu.cpsr.insert(transd_core::Cpsr::Q);
                            m.saturating_add(n)
                        } else {
                            sum
                        }
                    }
                    CoreSatOp::Qsub => {
                        let (diff, of) = m.overflowing_sub(n);
                        if of {
                            cpu.cpsr.insert(transd_core::Cpsr::Q);
                            m.saturating_sub(n)
                        } else {
                            diff
                        }
                    }
                    CoreSatOp::Qdadd => {
                        let (n2, of1) = n.overflowing_add(n);
                        let n2_sat = if of1 {
                            cpu.cpsr.insert(transd_core::Cpsr::Q);
                            n.saturating_add(n)
                        } else {
                            n2
                        };
                        let (sum, of2) = m.overflowing_add(n2_sat);
                        if of2 {
                            cpu.cpsr.insert(transd_core::Cpsr::Q);
                            m.saturating_add(n2_sat)
                        } else {
                            sum
                        }
                    }
                    CoreSatOp::Qdsub => {
                        let (n2, of1) = n.overflowing_add(n);
                        let n2_sat = if of1 {
                            cpu.cpsr.insert(transd_core::Cpsr::Q);
                            n.saturating_add(n)
                        } else {
                            n2
                        };
                        let (diff, of2) = m.overflowing_sub(n2_sat);
                        if of2 {
                            cpu.cpsr.insert(transd_core::Cpsr::Q);
                            m.saturating_sub(n2_sat)
                        } else {
                            diff
                        }
                    }
                };
                cpu.set_reg(rd, res as u32);
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::BitSat { op, rd, rn } => {
                let n_val = cpu.reg(rn);
                let res = match op {
                    BitSatOp::Ssat { sat_imm, shift_type, shift_imm } => {
                        let shifted = match shift_type {
                            ShiftType::Lsl => (n_val as i32) << shift_imm,
                            ShiftType::Asr => (n_val as i32) >> shift_imm,
                            _ => n_val as i32,
                        };
                        let sat = sat_imm as u32;
                        let max_val = if sat >= 32 { i32::MAX as i64 } else { (1i64 << (sat - 1)) - 1 };
                        let min_val = if sat >= 32 { i32::MIN as i64 } else { -(1i64 << (sat - 1)) };
                        let val_i64 = shifted as i64;
                        if val_i64 > max_val {
                            cpu.cpsr.insert(transd_core::Cpsr::Q);
                            max_val as u32
                        } else if val_i64 < min_val {
                            cpu.cpsr.insert(transd_core::Cpsr::Q);
                            min_val as u32
                        } else {
                            shifted as u32
                        }
                    }
                    BitSatOp::Usat { sat_imm, shift_type, shift_imm } => {
                        let shifted = match shift_type {
                            ShiftType::Lsl => (n_val as i32) << shift_imm,
                            ShiftType::Asr => (n_val as i32) >> shift_imm,
                            _ => n_val as i32,
                        };
                        let sat = sat_imm as u32;
                        let max_val = if sat >= 32 { u32::MAX as i64 } else { (1i64 << sat) - 1 };
                        let val_i64 = shifted as i64;
                        if val_i64 > max_val {
                            cpu.cpsr.insert(transd_core::Cpsr::Q);
                            max_val as u32
                        } else if val_i64 < 0 {
                            cpu.cpsr.insert(transd_core::Cpsr::Q);
                            0
                        } else {
                            shifted as u32
                        }
                    }
                    BitSatOp::Ssat16 { sat_imm } => {
                        let sat = sat_imm as i32;
                        let max_val = (1i32 << (sat - 1)) - 1;
                        let min_val = -(1i32 << (sat - 1));

                        let v_lo = n_val as i16 as i32;
                        let v_hi = (n_val >> 16) as i16 as i32;

                        let lo = if v_lo > max_val {
                            cpu.cpsr.insert(transd_core::Cpsr::Q);
                            max_val as u16
                        } else if v_lo < min_val {
                            cpu.cpsr.insert(transd_core::Cpsr::Q);
                            min_val as u16
                        } else {
                            v_lo as u16
                        };

                        let hi = if v_hi > max_val {
                            cpu.cpsr.insert(transd_core::Cpsr::Q);
                            max_val as u16
                        } else if v_hi < min_val {
                            cpu.cpsr.insert(transd_core::Cpsr::Q);
                            min_val as u16
                        } else {
                            v_hi as u16
                        };

                        ((hi as u32) << 16) | (lo as u32)
                    }
                    BitSatOp::Usat16 { sat_imm } => {
                        let sat = sat_imm as i32;
                        let max_val = if sat >= 16 { 0xFFFF } else { (1i32 << sat) - 1 };

                        let v_lo = n_val as i16 as i32;
                        let v_hi = (n_val >> 16) as i16 as i32;

                        let lo = if v_lo > max_val {
                            cpu.cpsr.insert(transd_core::Cpsr::Q);
                            max_val as u16
                        } else if v_lo < 0 {
                            cpu.cpsr.insert(transd_core::Cpsr::Q);
                            0
                        } else {
                            v_lo as u16
                        };

                        let hi = if v_hi > max_val {
                            cpu.cpsr.insert(transd_core::Cpsr::Q);
                            max_val as u16
                        } else if v_hi < 0 {
                            cpu.cpsr.insert(transd_core::Cpsr::Q);
                            0
                        } else {
                            v_hi as u16
                        };

                        ((hi as u32) << 16) | (lo as u32)
                    }
                };
                cpu.set_reg(rd, res);
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::HighMul { op, rd, rn, rm, ra } => {
                let n = cpu.reg(rn) as i32 as i64;
                let m = cpu.reg(rm) as i32 as i64;
                let round_offset = match op {
                    HighMulOp::Smmul { round } | HighMulOp::Smmla { round } | HighMulOp::Smmls { round } => {
                        if round { 0x8000_0000i64 } else { 0i64 }
                    }
                };
                let prod = (n * m).wrapping_add(round_offset);
                let high_word = (prod >> 32) as i32;
                let res = match op {
                    HighMulOp::Smmul { .. } => high_word as u32,
                    HighMulOp::Smmla { .. } => {
                        let a = ra.map(|r| cpu.reg(r) as i32).unwrap_or(0);
                        a.wrapping_add(high_word) as u32
                    }
                    HighMulOp::Smmls { .. } => {
                        let a = ra.map(|r| cpu.reg(r) as i32).unwrap_or(0);
                        a.wrapping_sub(high_word) as u32
                    }
                };
                cpu.set_reg(rd, res);
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::Movw { rd, imm } => {
                cpu.set_reg(rd, imm as u32);
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::Movt { rd, imm } => {
                let cur = cpu.reg(rd);
                let new_val = (cur & 0x0000_FFFF) | ((imm as u32) << 16);
                cpu.set_reg(rd, new_val);
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::CompareBranch { is_nonzero, rn, offset } => {
                let val = cpu.reg(rn);
                let take = if is_nonzero { val != 0 } else { val == 0 };
                if take {
                    let target_addr = pc.add(4).offset(offset as i32);
                    cpu.set_pc(target_addr);
                } else {
                    cpu.set_pc(next_pc);
                }
                Ok(StepResult::Continue)
            }
            Op::TableBranch { is_halfword, rn, rm } => {
                let base = if rn == Reg::PC {
                    let pc_val = pc.add(4).as_u32();
                    GuestAddr::new(pc_val & !3)
                } else {
                    GuestAddr::new(cpu.reg(rn))
                };
                let idx = cpu.reg(rm);
                let table_offset = if is_halfword {
                    let addr = base.add(idx * 2);
                    let h = mem.read_u16(addr)?;
                    (h as u32) * 2
                } else {
                    let addr = base.add(idx);
                    let b = mem.read_u8(addr)?;
                    (b as u32) * 2
                };
                let target = pc.add(4).add(table_offset);
                cpu.set_pc(target);
                Ok(StepResult::Continue)
            }
            Op::VfpAlu {
                op,
                size,
                dst,
                src1,
                src2,
            } => {
                match size {
                    VfpSize::F32 => {
                        let raw_s1 = match src1 {
                            VfpReg::S(idx) => cpu.s_reg(idx),
                            _ => 0.0,
                        };
                        let raw_s2 = match src2 {
                            VfpReg::S(idx) => cpu.s_reg(idx),
                            _ => 0.0,
                        };

                        let s1 = cpu.sanitize_f32(raw_s1, true);
                        let s2 = cpu.sanitize_f32(raw_s2, true);

                        let mut res = 0.0f32;
                        match op {
                            VfpOp::Add => res = s1 + s2,
                            VfpOp::Sub => res = s1 - s2,
                            VfpOp::Mul => res = s1 * s2,
                            VfpOp::Div => res = s1 / s2,
                            VfpOp::Abs => res = s1.abs(),
                            VfpOp::Neg => res = -s1,
                            VfpOp::Sqrt => res = s1.sqrt(),
                            VfpOp::Fma => {
                                let dst_val = match dst {
                                    VfpReg::S(idx) => cpu.s_reg(idx),
                                    _ => 0.0,
                                };
                                res = s1.mul_add(s2, dst_val);
                            }
                            VfpOp::Fms => {
                                let dst_val = match dst {
                                    VfpReg::S(idx) => cpu.s_reg(idx),
                                    _ => 0.0,
                                };
                                res = (-s1).mul_add(s2, dst_val);
                            }
                            VfpOp::Cmp | VfpOp::CmpZero => {
                                let comp_val = if op == VfpOp::CmpZero { 0.0 } else { s2 };
                                let (n, z, c, v) = if s1.is_nan() || comp_val.is_nan() {
                                    (false, false, true, true)
                                } else if s1 == comp_val {
                                    (false, true, true, false)
                                } else if s1 < comp_val {
                                    (true, false, false, false)
                                } else {
                                    (false, false, true, false)
                                };

                                let mut flags = 0u32;
                                if n { flags |= 1 << 31; }
                                if z { flags |= 1 << 30; }
                                if c { flags |= 1 << 29; }
                                if v { flags |= 1 << 28; }
                                cpu.fpscr = (cpu.fpscr & 0x0FFF_FFFF) | flags;
                            }
                        }

                        if !matches!(op, VfpOp::Cmp | VfpOp::CmpZero) {
                            let sanitized_res = cpu.sanitize_f32(res, false);
                            if let VfpReg::S(dst_idx) = dst {
                                cpu.set_s_reg(dst_idx, sanitized_res);
                            }
                        }
                    }
                    VfpSize::F64 => {
                        let raw_d1 = match src1 {
                            VfpReg::D(idx) => cpu.d_reg(idx),
                            _ => 0.0,
                        };
                        let raw_d2 = match src2 {
                            VfpReg::D(idx) => cpu.d_reg(idx),
                            _ => 0.0,
                        };

                        let d1 = cpu.sanitize_f64(raw_d1, true);
                        let d2 = cpu.sanitize_f64(raw_d2, true);

                        let mut res = 0.0f64;
                        match op {
                            VfpOp::Add => res = d1 + d2,
                            VfpOp::Sub => res = d1 - d2,
                            VfpOp::Mul => res = d1 * d2,
                            VfpOp::Div => res = d1 / d2,
                            VfpOp::Abs => res = d1.abs(),
                            VfpOp::Neg => res = -d1,
                            VfpOp::Sqrt => res = d1.sqrt(),
                            VfpOp::Fma => {
                                let dst_val = match dst {
                                    VfpReg::D(idx) => cpu.d_reg(idx),
                                    _ => 0.0,
                                };
                                res = d1.mul_add(d2, dst_val);
                            }
                            VfpOp::Fms => {
                                let dst_val = match dst {
                                    VfpReg::D(idx) => cpu.d_reg(idx),
                                    _ => 0.0,
                                };
                                res = (-d1).mul_add(d2, dst_val);
                            }
                            VfpOp::Cmp | VfpOp::CmpZero => {
                                let comp_val = if op == VfpOp::CmpZero { 0.0 } else { d2 };
                                let (n, z, c, v) = if d1.is_nan() || comp_val.is_nan() {
                                    (false, false, true, true)
                                } else if d1 == comp_val {
                                    (false, true, true, false)
                                } else if d1 < comp_val {
                                    (true, false, false, false)
                                } else {
                                    (false, false, true, false)
                                };

                                let mut flags = 0u32;
                                if n { flags |= 1 << 31; }
                                if z { flags |= 1 << 30; }
                                if c { flags |= 1 << 29; }
                                if v { flags |= 1 << 28; }
                                cpu.fpscr = (cpu.fpscr & 0x0FFF_FFFF) | flags;
                            }
                        }

                        if !matches!(op, VfpOp::Cmp | VfpOp::CmpZero) {
                            let sanitized_res = cpu.sanitize_f64(res, false);
                            if let VfpReg::D(dst_idx) = dst {
                                cpu.set_d_reg(dst_idx, sanitized_res);
                            }
                        }
                    }
                }
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::VfpMov { size, dst, src } => {
                match size {
                    VfpSize::F32 => {
                        let val = match src {
                            VfpReg::S(idx) => cpu.s_reg(idx),
                            _ => 0.0,
                        };
                        let sanitized = cpu.sanitize_f32(val, false);
                        if let VfpReg::S(dst_idx) = dst {
                            cpu.set_s_reg(dst_idx, sanitized);
                        }
                    }
                    VfpSize::F64 => {
                        let val = match src {
                            VfpReg::D(idx) => cpu.d_reg(idx),
                            _ => 0.0,
                        };
                        let sanitized = cpu.sanitize_f64(val, false);
                        if let VfpReg::D(dst_idx) = dst {
                            cpu.set_d_reg(dst_idx, sanitized);
                        }
                    }
                }
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::VfpMovCore {
                to_core,
                core_reg,
                vfp_reg,
            } => {
                if to_core {
                    let val = match vfp_reg {
                        VfpReg::S(idx) => cpu.s_reg(idx).to_bits(),
                        _ => 0,
                    };
                    cpu.set_reg(core_reg, val);
                } else {
                    let val = cpu.reg(core_reg);
                    if let VfpReg::S(idx) = vfp_reg {
                        cpu.set_s_reg(idx, f32::from_bits(val));
                    }
                }
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::VfpMovTwoCore {
                to_core,
                is_double,
                rt,
                rt2,
                vfp_reg,
            } => {
                if to_core {
                    if is_double {
                        let d_idx = match vfp_reg {
                            VfpReg::D(idx) => idx,
                            _ => 0,
                        };
                        let bits = cpu.d_reg_u64(d_idx);
                        cpu.set_reg(rt, (bits & 0xFFFF_FFFF) as u32);
                        cpu.set_reg(rt2, (bits >> 32) as u32);
                    } else {
                        let s_idx = match vfp_reg {
                            VfpReg::S(idx) => idx,
                            _ => 0,
                        };
                        cpu.set_reg(rt, cpu.s_reg_u32(s_idx));
                        cpu.set_reg(rt2, cpu.s_reg_u32(s_idx + 1));
                    }
                } else {
                    if is_double {
                        let d_idx = match vfp_reg {
                            VfpReg::D(idx) => idx,
                            _ => 0,
                        };
                        let lo = cpu.reg(rt) as u64;
                        let hi = (cpu.reg(rt2) as u64) << 32;
                        cpu.set_d_reg_u64(d_idx, hi | lo);
                    } else {
                        let s_idx = match vfp_reg {
                            VfpReg::S(idx) => idx,
                            _ => 0,
                        };
                        cpu.set_s_reg_u32(s_idx, cpu.reg(rt));
                        cpu.set_s_reg_u32(s_idx + 1, cpu.reg(rt2));
                    }
                }
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::VfpMrsFpscr { rt } => {
                match rt {
                    None => {
                        let n = (cpu.fpscr & (1 << 31)) != 0;
                        let z = (cpu.fpscr & (1 << 30)) != 0;
                        let c = (cpu.fpscr & (1 << 29)) != 0;
                        let v = (cpu.fpscr & (1 << 28)) != 0;
                        cpu.cpsr.set(Cpsr::N, n);
                        cpu.cpsr.set(Cpsr::Z, z);
                        cpu.cpsr.set(Cpsr::C, c);
                        cpu.cpsr.set(Cpsr::V, v);
                    }
                    Some(r) => {
                        cpu.set_reg(r, cpu.fpscr);
                    }
                }
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::VfpMsrFpscr { rt } => {
                let val = cpu.reg(rt);
                cpu.fpscr = val;
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::VfpLoadStore {
                is_load,
                size,
                vfp_reg,
                rn,
                offset,
            } => {
                let addr = GuestAddr::new(cpu.reg(rn).wrapping_add(offset as u32));
                if is_load {
                    match (size, vfp_reg) {
                        (VfpSize::F32, VfpReg::S(idx)) => {
                            let bits = mem.read_u32(addr)?;
                            cpu.set_s_reg(idx, f32::from_bits(bits));
                        }
                        (VfpSize::F64, VfpReg::D(idx)) => {
                            let bits = mem.read_u64(addr)?;
                            cpu.set_d_reg(idx, f64::from_bits(bits));
                        }
                        _ => {}
                    }
                } else {
                    match (size, vfp_reg) {
                        (VfpSize::F32, VfpReg::S(idx)) => {
                            let bits = cpu.s_reg(idx).to_bits();
                            mem.write_u32(addr, bits)?;
                        }
                        (VfpSize::F64, VfpReg::D(idx)) => {
                            let bits = cpu.d_reg(idx).to_bits();
                            mem.write_u64(addr, bits)?;
                        }
                        _ => {}
                    }
                }
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::VfpLoadStoreMultiple {
                is_load,
                is_double,
                writeback,
                is_add,
                rn,
                start_reg,
                count,
            } => {
                let base = cpu.reg(rn);
                let elem_size: u32 = if is_double { 8 } else { 4 };
                let total_bytes = (count as u32) * elem_size;

                let start_addr = if is_add {
                    base
                } else {
                    base.wrapping_sub(total_bytes)
                };

                let mut current_addr = start_addr;
                for i in 0..(count as usize) {
                    let reg_idx = (start_reg as usize + i) as u8;
                    let addr = GuestAddr::new(current_addr);
                    if is_double {
                        let d_idx = reg_idx % 32;
                        if is_load {
                            let val = mem.read_u64(addr)?;
                            cpu.vfp[d_idx as usize] = val;
                        } else {
                            let val = cpu.vfp[d_idx as usize];
                            mem.write_u64(addr, val)?;
                        }
                    } else {
                        let s_idx = reg_idx % 32;
                        if is_load {
                            let val = mem.read_u32(addr)?;
                            cpu.set_s_reg_u32(s_idx, val);
                        } else {
                            let val = cpu.s_reg_u32(s_idx);
                            mem.write_u32(addr, val)?;
                        }
                    }
                    current_addr = current_addr.wrapping_add(elem_size);
                }

                if writeback {
                    let new_base = if is_add {
                        base.wrapping_add(total_bytes)
                    } else {
                        base.wrapping_sub(total_bytes)
                    };
                    cpu.set_reg(rn, new_base);
                }

                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::VfpCvt { op, dst, src } => {
                match op {
                    VfpCvtOp::F64FromF32 => {
                        let s_idx = match src { VfpReg::S(idx) => idx, _ => 0 };
                        let d_idx = match dst { VfpReg::D(idx) => idx, _ => 0 };
                        let f = cpu.s_reg(s_idx);
                        cpu.set_d_reg(d_idx, f as f64);
                    }
                    VfpCvtOp::F32FromF64 => {
                        let d_idx = match src { VfpReg::D(idx) => idx, _ => 0 };
                        let s_idx = match dst { VfpReg::S(idx) => idx, _ => 0 };
                        let d = cpu.d_reg(d_idx);
                        cpu.set_s_reg(s_idx, d as f32);
                    }
                    VfpCvtOp::F32FromS32 => {
                        let s_src = match src { VfpReg::S(idx) => idx, _ => 0 };
                        let s_dst = match dst { VfpReg::S(idx) => idx, _ => 0 };
                        let int_val = cpu.s_reg_u32(s_src) as i32;
                        cpu.set_s_reg(s_dst, int_val as f32);
                    }
                    VfpCvtOp::F32FromU32 => {
                        let s_src = match src { VfpReg::S(idx) => idx, _ => 0 };
                        let s_dst = match dst { VfpReg::S(idx) => idx, _ => 0 };
                        let uint_val = cpu.s_reg_u32(s_src);
                        cpu.set_s_reg(s_dst, uint_val as f32);
                    }
                    VfpCvtOp::S32FromF32 => {
                        let s_src = match src { VfpReg::S(idx) => idx, _ => 0 };
                        let s_dst = match dst { VfpReg::S(idx) => idx, _ => 0 };
                        let f = cpu.s_reg(s_src);
                        let res = if f.is_nan() {
                            0
                        } else if f >= i32::MAX as f32 {
                            i32::MAX as u32
                        } else if f <= i32::MIN as f32 {
                            i32::MIN as u32
                        } else {
                            (f as i32) as u32
                        };
                        cpu.set_s_reg_u32(s_dst, res);
                    }
                    VfpCvtOp::U32FromF32 => {
                        let s_src = match src { VfpReg::S(idx) => idx, _ => 0 };
                        let s_dst = match dst { VfpReg::S(idx) => idx, _ => 0 };
                        let f = cpu.s_reg(s_src);
                        let res = if f.is_nan() || f <= 0.0 {
                            0
                        } else if f >= u32::MAX as f32 {
                            u32::MAX
                        } else {
                            f as u32
                        };
                        cpu.set_s_reg_u32(s_dst, res);
                    }
                    VfpCvtOp::F64FromS32 => {
                        let s_src = match src { VfpReg::S(idx) => idx, _ => 0 };
                        let d_dst = match dst { VfpReg::D(idx) => idx, _ => 0 };
                        let int_val = cpu.s_reg_u32(s_src) as i32;
                        cpu.set_d_reg(d_dst, int_val as f64);
                    }
                    VfpCvtOp::F64FromU32 => {
                        let s_src = match src { VfpReg::S(idx) => idx, _ => 0 };
                        let d_dst = match dst { VfpReg::D(idx) => idx, _ => 0 };
                        let uint_val = cpu.s_reg_u32(s_src);
                        cpu.set_d_reg(d_dst, uint_val as f64);
                    }
                    VfpCvtOp::S32FromF64 => {
                        let d_src = match src { VfpReg::D(idx) => idx, _ => 0 };
                        let s_dst = match dst { VfpReg::S(idx) => idx, _ => 0 };
                        let d = cpu.d_reg(d_src);
                        let res = if d.is_nan() {
                            0
                        } else if d >= i32::MAX as f64 {
                            i32::MAX as u32
                        } else if d <= i32::MIN as f64 {
                            i32::MIN as u32
                        } else {
                            (d as i32) as u32
                        };
                        cpu.set_s_reg_u32(s_dst, res);
                    }
                    VfpCvtOp::U32FromF64 => {
                        let d_src = match src { VfpReg::D(idx) => idx, _ => 0 };
                        let s_dst = match dst { VfpReg::S(idx) => idx, _ => 0 };
                        let d = cpu.d_reg(d_src);
                        let res = if d.is_nan() || d <= 0.0 {
                            0
                        } else if d >= u32::MAX as f64 {
                            u32::MAX
                        } else {
                            d as u32
                        };
                        cpu.set_s_reg_u32(s_dst, res);
                    }
                }

                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::AtomicLoadEx { rd, rn } => {
                let addr = GuestAddr::new(cpu.reg(rn));
                let val = mem.read_u32(addr)?;
                cpu.exclusive_addr = addr.as_u32();
                cpu.set_reg(rd, val);
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::AtomicStoreEx { rd, rm, rn } => {
                let addr = cpu.reg(rn);
                if cpu.exclusive_addr == addr {
                    let val = cpu.reg(rm);
                    mem.write_u32(GuestAddr::new(addr), val)?;
                    cpu.set_reg(rd, 0); // 0 indicates success in ARM STREX
                    cpu.exclusive_addr = 0xFFFF_FFFF;
                } else {
                    cpu.set_reg(rd, 1); // 1 indicates exclusive reservation failed
                }
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::Clrex => {
                cpu.exclusive_addr = 0xFFFF_FFFF;
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::MemoryBarrier { .. } => {
                std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::Cp15Move {
                is_mrc,
                rd,
                crn,
                crm,
                opc2,
                ..
            } => {
                // CP15 c13, c0, 3: TPIDRURW (User Read/Write Thread ID Register)
                // CP15 c13, c0, 2: TPIDRURO (User Read-Only Thread ID Register)
                if crn == 13 && crm == 0 && (opc2 == 3 || opc2 == 2) {
                    if is_mrc {
                        cpu.set_reg(rd, cpu.tls_ptr);
                    } else {
                        cpu.tls_ptr = cpu.reg(rd);
                    }
                }
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::It { firstcond, mask } => {
                let itstate = ((firstcond as u8) << 4) | (mask & 0xF);
                cpu.cpsr.set_itstate(itstate);
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::NeonAlu {
                op,
                size,
                is_quad,
                dst,
                src1,
                src2,
            } => {
                let count = if is_quad { 2 } else { 1 };
                for i in 0..count {
                    let d_idx = (dst as usize) + i;
                    let s1_idx = (src1 as usize) + i;
                    let s2_idx = (src2 as usize) + i;
                    if d_idx < 32 && s1_idx < 32 && s2_idx < 32 {
                        let a = cpu.vfp[s1_idx];
                        let b = cpu.vfp[s2_idx];
                        let acc = cpu.vfp[d_idx];
                        let res = match (op, size) {
                            (NeonOp::And, _) => a & b,
                            (NeonOp::Orr, _) => a | b,
                            (NeonOp::Eor, _) => a ^ b,
                            (NeonOp::Bic, _) => a & !b,
                            (NeonOp::Add, NeonSize::F32) => {
                                let a0 = f32::from_bits((a & 0xFFFF_FFFF) as u32);
                                let a1 = f32::from_bits((a >> 32) as u32);
                                let b0 = f32::from_bits((b & 0xFFFF_FFFF) as u32);
                                let b1 = f32::from_bits((b >> 32) as u32);
                                let r0 = (a0 + b0).to_bits() as u64;
                                let r1 = ((a1 + b1).to_bits() as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Sub, NeonSize::F32) => {
                                let a0 = f32::from_bits((a & 0xFFFF_FFFF) as u32);
                                let a1 = f32::from_bits((a >> 32) as u32);
                                let b0 = f32::from_bits((b & 0xFFFF_FFFF) as u32);
                                let b1 = f32::from_bits((b >> 32) as u32);
                                let r0 = (a0 - b0).to_bits() as u64;
                                let r1 = ((a1 - b1).to_bits() as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Mul, NeonSize::F32) => {
                                let a0 = f32::from_bits((a & 0xFFFF_FFFF) as u32);
                                let a1 = f32::from_bits((a >> 32) as u32);
                                let b0 = f32::from_bits((b & 0xFFFF_FFFF) as u32);
                                let b1 = f32::from_bits((b >> 32) as u32);
                                let r0 = (a0 * b0).to_bits() as u64;
                                let r1 = ((a1 * b1).to_bits() as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Mla, NeonSize::F32) => {
                                let a0 = f32::from_bits((a & 0xFFFF_FFFF) as u32);
                                let a1 = f32::from_bits((a >> 32) as u32);
                                let b0 = f32::from_bits((b & 0xFFFF_FFFF) as u32);
                                let b1 = f32::from_bits((b >> 32) as u32);
                                let acc0 = f32::from_bits((acc & 0xFFFF_FFFF) as u32);
                                let acc1 = f32::from_bits((acc >> 32) as u32);
                                let r0 = (acc0 + (a0 * b0)).to_bits() as u64;
                                let r1 = ((acc1 + (a1 * b1)).to_bits() as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Mls, NeonSize::F32) => {
                                let a0 = f32::from_bits((a & 0xFFFF_FFFF) as u32);
                                let a1 = f32::from_bits((a >> 32) as u32);
                                let b0 = f32::from_bits((b & 0xFFFF_FFFF) as u32);
                                let b1 = f32::from_bits((b >> 32) as u32);
                                let acc0 = f32::from_bits((acc & 0xFFFF_FFFF) as u32);
                                let acc1 = f32::from_bits((acc >> 32) as u32);
                                let r0 = (acc0 - (a0 * b0)).to_bits() as u64;
                                let r1 = ((acc1 - (a1 * b1)).to_bits() as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Min, NeonSize::F32) => {
                                let a0 = f32::from_bits((a & 0xFFFF_FFFF) as u32);
                                let a1 = f32::from_bits((a >> 32) as u32);
                                let b0 = f32::from_bits((b & 0xFFFF_FFFF) as u32);
                                let b1 = f32::from_bits((b >> 32) as u32);
                                let r0 = a0.min(b0).to_bits() as u64;
                                let r1 = (a1.min(b1).to_bits() as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Max, NeonSize::F32) => {
                                let a0 = f32::from_bits((a & 0xFFFF_FFFF) as u32);
                                let a1 = f32::from_bits((a >> 32) as u32);
                                let b0 = f32::from_bits((b & 0xFFFF_FFFF) as u32);
                                let b1 = f32::from_bits((b >> 32) as u32);
                                let r0 = a0.max(b0).to_bits() as u64;
                                let r1 = (a1.max(b1).to_bits() as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Abs, NeonSize::F32) => {
                                let b0 = f32::from_bits((b & 0xFFFF_FFFF) as u32);
                                let b1 = f32::from_bits((b >> 32) as u32);
                                let r0 = b0.abs().to_bits() as u64;
                                let r1 = (b1.abs().to_bits() as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Neg, NeonSize::F32) => {
                                let b0 = f32::from_bits((b & 0xFFFF_FFFF) as u32);
                                let b1 = f32::from_bits((b >> 32) as u32);
                                let r0 = (-b0).to_bits() as u64;
                                let r1 = ((-b1).to_bits() as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Add, NeonSize::I32) => {
                                let a0 = (a & 0xFFFF_FFFF) as u32;
                                let a1 = (a >> 32) as u32;
                                let b0 = (b & 0xFFFF_FFFF) as u32;
                                let b1 = (b >> 32) as u32;
                                let r0 = a0.wrapping_add(b0) as u64;
                                let r1 = (a1.wrapping_add(b1) as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Sub, NeonSize::I32) => {
                                let a0 = (a & 0xFFFF_FFFF) as u32;
                                let a1 = (a >> 32) as u32;
                                let b0 = (b & 0xFFFF_FFFF) as u32;
                                let b1 = (b >> 32) as u32;
                                let r0 = a0.wrapping_sub(b0) as u64;
                                let r1 = (a1.wrapping_sub(b1) as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Mul, NeonSize::I32) => {
                                let a0 = (a & 0xFFFF_FFFF) as u32;
                                let a1 = (a >> 32) as u32;
                                let b0 = (b & 0xFFFF_FFFF) as u32;
                                let b1 = (b >> 32) as u32;
                                let r0 = a0.wrapping_mul(b0) as u64;
                                let r1 = (a1.wrapping_mul(b1) as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Add, NeonSize::I16) => {
                                let mut r = 0u64;
                                for k in 0..4 {
                                    let ak = ((a >> (k * 16)) & 0xFFFF) as u16;
                                    let bk = ((b >> (k * 16)) & 0xFFFF) as u16;
                                    let rk = (ak.wrapping_add(bk) as u64) << (k * 16);
                                    r |= rk;
                                }
                                r
                            }
                            (NeonOp::Sub, NeonSize::I16) => {
                                let mut r = 0u64;
                                for k in 0..4 {
                                    let ak = ((a >> (k * 16)) & 0xFFFF) as u16;
                                    let bk = ((b >> (k * 16)) & 0xFFFF) as u16;
                                    let rk = (ak.wrapping_sub(bk) as u64) << (k * 16);
                                    r |= rk;
                                }
                                r
                            }
                            (NeonOp::Mul, NeonSize::I16) => {
                                let mut r = 0u64;
                                for k in 0..4 {
                                    let ak = ((a >> (k * 16)) & 0xFFFF) as u16;
                                    let bk = ((b >> (k * 16)) & 0xFFFF) as u16;
                                    let rk = (ak.wrapping_mul(bk) as u64) << (k * 16);
                                    r |= rk;
                                }
                                r
                            }
                            (NeonOp::Add, NeonSize::I8) => {
                                let mut r = 0u64;
                                for byte_idx in 0..8 {
                                    let ab = ((a >> (byte_idx * 8)) & 0xFF) as u8;
                                    let bb = ((b >> (byte_idx * 8)) & 0xFF) as u8;
                                    let rb = (ab.wrapping_add(bb) as u64) << (byte_idx * 8);
                                    r |= rb;
                                }
                                r
                            }
                            (NeonOp::Sub, NeonSize::I8) => {
                                let mut r = 0u64;
                                for byte_idx in 0..8 {
                                    let ab = ((a >> (byte_idx * 8)) & 0xFF) as u8;
                                    let bb = ((b >> (byte_idx * 8)) & 0xFF) as u8;
                                    let rb = (ab.wrapping_sub(bb) as u64) << (byte_idx * 8);
                                    r |= rb;
                                }
                                r
                            }
                            (NeonOp::Mul, NeonSize::I8) => {
                                let mut r = 0u64;
                                for byte_idx in 0..8 {
                                    let ab = ((a >> (byte_idx * 8)) & 0xFF) as u8;
                                    let bb = ((b >> (byte_idx * 8)) & 0xFF) as u8;
                                    let rb = (ab.wrapping_mul(bb) as u64) << (byte_idx * 8);
                                    r |= rb;
                                }
                                r
                            }
                            (NeonOp::Sqadd, NeonSize::I32) => {
                                let a0 = ((a as u32) as i32).saturating_add((b as u32) as i32) as u32 as u64;
                                let a1 = (((a >> 32) as i32).saturating_add((b >> 32) as i32) as u32 as u64) << 32;
                                a0 | a1
                            }
                            (NeonOp::Sqadd, NeonSize::I16) => {
                                let mut r = 0u64;
                                for k in 0..4 {
                                    let ak = (a >> (k * 16)) as i16;
                                    let bk = (b >> (k * 16)) as i16;
                                    let rk = (ak.saturating_add(bk) as u16 as u64) << (k * 16);
                                    r |= rk;
                                }
                                r
                            }
                            (NeonOp::Sqadd, NeonSize::I8) => {
                                let mut r = 0u64;
                                for k in 0..8 {
                                    let ak = (a >> (k * 8)) as i8;
                                    let bk = (b >> (k * 8)) as i8;
                                    let rk = (ak.saturating_add(bk) as u8 as u64) << (k * 8);
                                    r |= rk;
                                }
                                r
                            }
                            (NeonOp::Uqadd, NeonSize::I32) => {
                                let a0 = (a as u32).saturating_add(b as u32) as u64;
                                let a1 = (((a >> 32) as u32).saturating_add((b >> 32) as u32) as u64) << 32;
                                a0 | a1
                            }
                            (NeonOp::Uqadd, NeonSize::I16) => {
                                let mut r = 0u64;
                                for k in 0..4 {
                                    let ak = (a >> (k * 16)) as u16;
                                    let bk = (b >> (k * 16)) as u16;
                                    let rk = (ak.saturating_add(bk) as u64) << (k * 16);
                                    r |= rk;
                                }
                                r
                            }
                            (NeonOp::Uqadd, NeonSize::I8) => {
                                let mut r = 0u64;
                                for k in 0..8 {
                                    let ak = (a >> (k * 8)) as u8;
                                    let bk = (b >> (k * 8)) as u8;
                                    let rk = (ak.saturating_add(bk) as u64) << (k * 8);
                                    r |= rk;
                                }
                                r
                            }
                            (NeonOp::Sqsub, NeonSize::I32) => {
                                let a0 = ((a as u32) as i32).saturating_sub((b as u32) as i32) as u32 as u64;
                                let a1 = (((a >> 32) as i32).saturating_sub((b >> 32) as i32) as u32 as u64) << 32;
                                a0 | a1
                            }
                            (NeonOp::Sqsub, NeonSize::I16) => {
                                let mut r = 0u64;
                                for k in 0..4 {
                                    let ak = (a >> (k * 16)) as i16;
                                    let bk = (b >> (k * 16)) as i16;
                                    let rk = (ak.saturating_sub(bk) as u16 as u64) << (k * 16);
                                    r |= rk;
                                }
                                r
                            }
                            (NeonOp::Sqsub, NeonSize::I8) => {
                                let mut r = 0u64;
                                for k in 0..8 {
                                    let ak = (a >> (k * 8)) as i8;
                                    let bk = (b >> (k * 8)) as i8;
                                    let rk = (ak.saturating_sub(bk) as u8 as u64) << (k * 8);
                                    r |= rk;
                                }
                                r
                            }
                            (NeonOp::Uqsub, NeonSize::I32) => {
                                let a0 = (a as u32).saturating_sub(b as u32) as u64;
                                let a1 = (((a >> 32) as u32).saturating_sub((b >> 32) as u32) as u64) << 32;
                                a0 | a1
                            }
                            (NeonOp::Uqsub, NeonSize::I16) => {
                                let mut r = 0u64;
                                for k in 0..4 {
                                    let ak = (a >> (k * 16)) as u16;
                                    let bk = (b >> (k * 16)) as u16;
                                    let rk = (ak.saturating_sub(bk) as u64) << (k * 16);
                                    r |= rk;
                                }
                                r
                            }
                            (NeonOp::Uqsub, NeonSize::I8) => {
                                let mut r = 0u64;
                                for k in 0..8 {
                                    let ak = (a >> (k * 8)) as u8;
                                    let bk = (b >> (k * 8)) as u8;
                                    let rk = (ak.saturating_sub(bk) as u64) << (k * 8);
                                    r |= rk;
                                }
                                r
                            }
                            (NeonOp::Sqshl, NeonSize::I32) => {
                                let mut r = 0u64;
                                for k in 0..2 {
                                    let val = (a >> (k * 32)) as i32;
                                    let shift = (b >> (k * 32)) as i8;
                                    let res = if shift >= 32 {
                                        if val < 0 { i32::MIN } else if val > 0 { i32::MAX } else { 0 }
                                    } else if shift >= 0 {
                                        let shifted = (val as i64) << shift;
                                        shifted.clamp(i32::MIN as i64, i32::MAX as i64) as i32
                                    } else {
                                        val >> ((-shift).min(31))
                                    };
                                    r |= (res as u32 as u64) << (k * 32);
                                }
                                r
                            }
                            (NeonOp::Sqshl, NeonSize::I16) => {
                                let mut r = 0u64;
                                for k in 0..4 {
                                    let val = (a >> (k * 16)) as i16;
                                    let shift = (b >> (k * 16)) as i8;
                                    let res = if shift >= 16 {
                                        if val < 0 { i16::MIN } else if val > 0 { i16::MAX } else { 0 }
                                    } else if shift >= 0 {
                                        let shifted = (val as i32) << shift;
                                        shifted.clamp(i16::MIN as i32, i16::MAX as i32) as i16
                                    } else {
                                        val >> ((-shift).min(15))
                                    };
                                    r |= (res as u16 as u64) << (k * 16);
                                }
                                r
                            }
                            (NeonOp::Sqshl, NeonSize::I8) => {
                                let mut r = 0u64;
                                for k in 0..8 {
                                    let val = (a >> (k * 8)) as i8;
                                    let shift = (b >> (k * 8)) as i8;
                                    let res = if shift >= 8 {
                                        if val < 0 { i8::MIN } else if val > 0 { i8::MAX } else { 0 }
                                    } else if shift >= 0 {
                                        let shifted = (val as i16) << shift;
                                        shifted.clamp(i8::MIN as i16, i8::MAX as i16) as i8
                                    } else {
                                        val >> ((-shift).min(7))
                                    };
                                    r |= (res as u8 as u64) << (k * 8);
                                }
                                r
                            }
                            (NeonOp::Uqshl, NeonSize::I32) => {
                                let mut r = 0u64;
                                for k in 0..2 {
                                    let val = (a >> (k * 32)) as u32;
                                    let shift = (b >> (k * 32)) as i8;
                                    let res = if shift >= 32 {
                                        if val > 0 { u32::MAX } else { 0 }
                                    } else if shift >= 0 {
                                        let shifted = (val as u64) << shift;
                                        shifted.min(u32::MAX as u64) as u32
                                    } else {
                                        val >> ((-shift).min(31))
                                    };
                                    r |= (res as u64) << (k * 32);
                                }
                                r
                            }
                            (NeonOp::Uqshl, NeonSize::I16) => {
                                let mut r = 0u64;
                                for k in 0..4 {
                                    let val = (a >> (k * 16)) as u16;
                                    let shift = (b >> (k * 16)) as i8;
                                    let res = if shift >= 16 {
                                        if val > 0 { u16::MAX } else { 0 }
                                    } else if shift >= 0 {
                                        let shifted = (val as u32) << shift;
                                        shifted.min(u16::MAX as u32) as u16
                                    } else {
                                        val >> ((-shift).min(15))
                                    };
                                    r |= (res as u64) << (k * 16);
                                }
                                r
                            }
                            (NeonOp::Uqshl, NeonSize::I8) => {
                                let mut r = 0u64;
                                for k in 0..8 {
                                    let val = (a >> (k * 8)) as u8;
                                    let shift = (b >> (k * 8)) as i8;
                                    let res = if shift >= 8 {
                                        if val > 0 { u8::MAX } else { 0 }
                                    } else if shift >= 0 {
                                        let shifted = (val as u16) << shift;
                                        shifted.min(u8::MAX as u16) as u8
                                    } else {
                                        val >> ((-shift).min(7))
                                    };
                                    r |= (res as u64) << (k * 8);
                                }
                                r
                            }
                            // Pairwise reductions (Stage 45)
                            (NeonOp::Padd, NeonSize::F32) => {
                                let a0 = f32::from_bits((a & 0xFFFF_FFFF) as u32);
                                let a1 = f32::from_bits((a >> 32) as u32);
                                let b0 = f32::from_bits((b & 0xFFFF_FFFF) as u32);
                                let b1 = f32::from_bits((b >> 32) as u32);
                                let r0 = (a0 + a1).to_bits() as u64;
                                let r1 = ((b0 + b1).to_bits() as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Pmax, NeonSize::F32) => {
                                let a0 = f32::from_bits((a & 0xFFFF_FFFF) as u32);
                                let a1 = f32::from_bits((a >> 32) as u32);
                                let b0 = f32::from_bits((b & 0xFFFF_FFFF) as u32);
                                let b1 = f32::from_bits((b >> 32) as u32);
                                let r0 = a0.max(a1).to_bits() as u64;
                                let r1 = (b0.max(b1).to_bits() as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Pmin, NeonSize::F32) => {
                                let a0 = f32::from_bits((a & 0xFFFF_FFFF) as u32);
                                let a1 = f32::from_bits((a >> 32) as u32);
                                let b0 = f32::from_bits((b & 0xFFFF_FFFF) as u32);
                                let b1 = f32::from_bits((b >> 32) as u32);
                                let r0 = a0.min(a1).to_bits() as u64;
                                let r1 = (b0.min(b1).to_bits() as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Padd, NeonSize::I32) => {
                                let a0 = (a & 0xFFFF_FFFF) as u32;
                                let a1 = (a >> 32) as u32;
                                let b0 = (b & 0xFFFF_FFFF) as u32;
                                let b1 = (b >> 32) as u32;
                                let r0 = a0.wrapping_add(a1) as u64;
                                let r1 = (b0.wrapping_add(b1) as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Padd, NeonSize::I16) => {
                                let a0 = (a & 0xFFFF) as u16;
                                let a1 = ((a >> 16) & 0xFFFF) as u16;
                                let a2 = ((a >> 32) & 0xFFFF) as u16;
                                let a3 = ((a >> 48) & 0xFFFF) as u16;
                                let b0 = (b & 0xFFFF) as u16;
                                let b1 = ((b >> 16) & 0xFFFF) as u16;
                                let b2 = ((b >> 32) & 0xFFFF) as u16;
                                let b3 = ((b >> 48) & 0xFFFF) as u16;
                                let r0 = a0.wrapping_add(a1) as u64;
                                let r1 = (a2.wrapping_add(a3) as u64) << 16;
                                let r2 = (b0.wrapping_add(b1) as u64) << 32;
                                let r3 = (b2.wrapping_add(b3) as u64) << 48;
                                r0 | r1 | r2 | r3
                            }
                            (NeonOp::Padd, NeonSize::I8) => {
                                let mut r = 0u64;
                                for k in 0..4 {
                                    let ak0 = ((a >> (2 * k * 8)) & 0xFF) as u8;
                                    let ak1 = ((a >> ((2 * k + 1) * 8)) & 0xFF) as u8;
                                    r |= (ak0.wrapping_add(ak1) as u64) << (k * 8);
                                }
                                for k in 0..4 {
                                    let bk0 = ((b >> (2 * k * 8)) & 0xFF) as u8;
                                    let bk1 = ((b >> ((2 * k + 1) * 8)) & 0xFF) as u8;
                                    r |= (bk0.wrapping_add(bk1) as u64) << ((4 + k) * 8);
                                }
                                r
                            }
                            (NeonOp::Pmax, NeonSize::I32) => {
                                let a0 = (a & 0xFFFF_FFFF) as u32 as i32;
                                let a1 = (a >> 32) as u32 as i32;
                                let b0 = (b & 0xFFFF_FFFF) as u32 as i32;
                                let b1 = (b >> 32) as u32 as i32;
                                let r0 = (a0.max(a1) as u32) as u64;
                                let r1 = ((b0.max(b1) as u32) as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Pmax, NeonSize::I16) => {
                                let a0 = (a as i16).max((a >> 16) as i16) as u16 as u64;
                                let a1 = ((a >> 32) as i16).max((a >> 48) as i16) as u16 as u64;
                                let b0 = (b as i16).max((b >> 16) as i16) as u16 as u64;
                                let b1 = ((b >> 32) as i16).max((b >> 48) as i16) as u16 as u64;
                                a0 | (a1 << 16) | (b0 << 32) | (b1 << 48)
                            }
                            (NeonOp::Pmax, NeonSize::I8) => {
                                let mut r = 0u64;
                                for k in 0..4 {
                                    let ak0 = (a >> (2 * k * 8)) as i8;
                                    let ak1 = (a >> ((2 * k + 1) * 8)) as i8;
                                    r |= (ak0.max(ak1) as u8 as u64) << (k * 8);
                                }
                                for k in 0..4 {
                                    let bk0 = (b >> (2 * k * 8)) as i8;
                                    let bk1 = (b >> ((2 * k + 1) * 8)) as i8;
                                    r |= (bk0.max(bk1) as u8 as u64) << ((4 + k) * 8);
                                }
                                r
                            }
                            (NeonOp::Pmin, NeonSize::I32) => {
                                let a0 = (a & 0xFFFF_FFFF) as u32 as i32;
                                let a1 = (a >> 32) as u32 as i32;
                                let b0 = (b & 0xFFFF_FFFF) as u32 as i32;
                                let b1 = (b >> 32) as u32 as i32;
                                let r0 = (a0.min(a1) as u32) as u64;
                                let r1 = ((b0.min(b1) as u32) as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Pmin, NeonSize::I16) => {
                                let a0 = (a as i16).min((a >> 16) as i16) as u16 as u64;
                                let a1 = ((a >> 32) as i16).min((a >> 48) as i16) as u16 as u64;
                                let b0 = (b as i16).min((b >> 16) as i16) as u16 as u64;
                                let b1 = ((b >> 32) as i16).min((b >> 48) as i16) as u16 as u64;
                                a0 | (a1 << 16) | (b0 << 32) | (b1 << 48)
                            }
                            (NeonOp::Pmin, NeonSize::I8) => {
                                let mut r = 0u64;
                                for k in 0..4 {
                                    let ak0 = (a >> (2 * k * 8)) as i8;
                                    let ak1 = (a >> ((2 * k + 1) * 8)) as i8;
                                    r |= (ak0.min(ak1) as u8 as u64) << (k * 8);
                                }
                                for k in 0..4 {
                                    let bk0 = (b >> (2 * k * 8)) as i8;
                                    let bk1 = (b >> ((2 * k + 1) * 8)) as i8;
                                    r |= (bk0.min(bk1) as u8 as u64) << ((4 + k) * 8);
                                }
                                r
                            }
                            (NeonOp::Upmax, NeonSize::I32) => {
                                let a0 = (a & 0xFFFF_FFFF) as u32;
                                let a1 = (a >> 32) as u32;
                                let b0 = (b & 0xFFFF_FFFF) as u32;
                                let b1 = (b >> 32) as u32;
                                let r0 = a0.max(a1) as u64;
                                let r1 = (b0.max(b1) as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Upmax, NeonSize::I16) => {
                                let a0 = (a as u16).max((a >> 16) as u16) as u64;
                                let a1 = ((a >> 32) as u16).max((a >> 48) as u16) as u64;
                                let b0 = (b as u16).max((b >> 16) as u16) as u64;
                                let b1 = ((b >> 32) as u16).max((b >> 48) as u16) as u64;
                                a0 | (a1 << 16) | (b0 << 32) | (b1 << 48)
                            }
                            (NeonOp::Upmax, NeonSize::I8) => {
                                let mut r = 0u64;
                                for k in 0..4 {
                                    let ak0 = ((a >> (2 * k * 8)) & 0xFF) as u8;
                                    let ak1 = ((a >> ((2 * k + 1) * 8)) & 0xFF) as u8;
                                    r |= (ak0.max(ak1) as u64) << (k * 8);
                                }
                                for k in 0..4 {
                                    let bk0 = ((b >> (2 * k * 8)) & 0xFF) as u8;
                                    let bk1 = ((b >> ((2 * k + 1) * 8)) & 0xFF) as u8;
                                    r |= (bk0.max(bk1) as u64) << ((4 + k) * 8);
                                }
                                r
                            }
                            (NeonOp::Upmin, NeonSize::I32) => {
                                let a0 = (a & 0xFFFF_FFFF) as u32;
                                let a1 = (a >> 32) as u32;
                                let b0 = (b & 0xFFFF_FFFF) as u32;
                                let b1 = (b >> 32) as u32;
                                let r0 = a0.min(a1) as u64;
                                let r1 = (b0.min(b1) as u64) << 32;
                                r0 | r1
                            }
                            (NeonOp::Upmin, NeonSize::I16) => {
                                let a0 = (a as u16).min((a >> 16) as u16) as u64;
                                let a1 = ((a >> 32) as u16).min((a >> 48) as u16) as u64;
                                let b0 = (b as u16).min((b >> 16) as u16) as u64;
                                let b1 = ((b >> 32) as u16).min((b >> 48) as u16) as u64;
                                a0 | (a1 << 16) | (b0 << 32) | (b1 << 48)
                            }
                            (NeonOp::Upmin, NeonSize::I8) => {
                                let mut r = 0u64;
                                for k in 0..4 {
                                    let ak0 = ((a >> (2 * k * 8)) & 0xFF) as u8;
                                    let ak1 = ((a >> ((2 * k + 1) * 8)) & 0xFF) as u8;
                                    r |= (ak0.min(ak1) as u64) << (k * 8);
                                }
                                for k in 0..4 {
                                    let bk0 = ((b >> (2 * k * 8)) & 0xFF) as u8;
                                    let bk1 = ((b >> ((2 * k + 1) * 8)) & 0xFF) as u8;
                                    r |= (bk0.min(bk1) as u64) << ((4 + k) * 8);
                                }
                                r
                            }
                            _ => a,
                        };
                        cpu.vfp[d_idx] = res;
                    }
                }
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::NeonLoadStore {
                is_load,
                structure_elements,
                reg_count,
                stride,
                size,
                first_reg,
                rn,
                writeback,
            } => {
                let elem_bytes = match size {
                    NeonSize::I8 => 1,
                    NeonSize::I16 => 2,
                    _ => 4,
                };
                let base_addr = cpu.reg(rn);

                if structure_elements == 1 {
                    // Sequential transfer without interleaving (VLD1 / VST1)
                    for i in 0..(reg_count as usize) {
                        let d_idx = (first_reg as usize) + i * (stride as usize);
                        let addr = GuestAddr::new(base_addr.wrapping_add((i * 8) as u32));
                        if d_idx < 32 {
                            if is_load {
                                let lo = mem.read_u32(addr)? as u64;
                                let hi = (mem.read_u32(addr.add(4))? as u64) << 32;
                                cpu.vfp[d_idx] = lo | hi;
                            } else {
                                let val = cpu.vfp[d_idx];
                                mem.write_u32(addr, val as u32)?;
                                mem.write_u32(addr.add(4), (val >> 32) as u32)?;
                            }
                        }
                    }
                } else if structure_elements == 2 && reg_count == 4 {
                    // Two 128-bit vectors (2 Quadwords): Vector 0 = (first_reg, first_reg+1), Vector 1 = (first_reg+2, first_reg+3)
                    let num_structures = 16 / elem_bytes;
                    let elements_per_d = 8 / elem_bytes;
                    for s in 0..num_structures {
                        let offset0 = ((2 * s) * elem_bytes) as u32;
                        let offset1 = ((2 * s + 1) * elem_bytes) as u32;
                        let addr0 = GuestAddr::new(base_addr.wrapping_add(offset0));
                        let addr1 = GuestAddr::new(base_addr.wrapping_add(offset1));

                        let (d0_idx, l0) = if s < elements_per_d {
                            (first_reg as usize, s)
                        } else {
                            ((first_reg + 1) as usize, s - elements_per_d)
                        };
                        let (d1_idx, l1) = if s < elements_per_d {
                            ((first_reg + 2) as usize, s)
                        } else {
                            ((first_reg + 3) as usize, s - elements_per_d)
                        };

                        if is_load {
                            let e0 = match elem_bytes {
                                1 => mem.read_u8(addr0)? as u32,
                                2 => mem.read_u16(addr0)? as u32,
                                _ => mem.read_u32(addr0)?,
                            };
                            let e1 = match elem_bytes {
                                1 => mem.read_u8(addr1)? as u32,
                                2 => mem.read_u16(addr1)? as u32,
                                _ => mem.read_u32(addr1)?,
                            };
                            if d0_idx < 32 {
                                cpu.vfp[d0_idx] = set_lane_u64(cpu.vfp[d0_idx], l0, elem_bytes, e0);
                            }
                            if d1_idx < 32 {
                                cpu.vfp[d1_idx] = set_lane_u64(cpu.vfp[d1_idx], l1, elem_bytes, e1);
                            }
                        } else {
                            if d0_idx < 32 {
                                let e0 = get_lane_u64(cpu.vfp[d0_idx], l0, elem_bytes);
                                match elem_bytes {
                                    1 => mem.write_u8(addr0, e0 as u8)?,
                                    2 => mem.write_u16(addr0, e0 as u16)?,
                                    _ => mem.write_u32(addr0, e0)?,
                                }
                            }
                            if d1_idx < 32 {
                                let e1 = get_lane_u64(cpu.vfp[d1_idx], l1, elem_bytes);
                                match elem_bytes {
                                    1 => mem.write_u8(addr1, e1 as u8)?,
                                    2 => mem.write_u16(addr1, e1 as u16)?,
                                    _ => mem.write_u32(addr1, e1)?,
                                }
                            }
                        }
                    }
                } else {
                    // Standard 2, 3, or 4 D registers interleaved
                    let num_structures = 8 / elem_bytes;
                    let se = structure_elements as usize;
                    for s in 0..num_structures {
                        for e in 0..se {
                            let mem_offset = ((s * se + e) * elem_bytes) as u32;
                            let addr = GuestAddr::new(base_addr.wrapping_add(mem_offset));
                            let d_idx = (first_reg as usize) + e * (stride as usize);

                            if is_load {
                                let val = match elem_bytes {
                                    1 => mem.read_u8(addr)? as u32,
                                    2 => mem.read_u16(addr)? as u32,
                                    _ => mem.read_u32(addr)?,
                                };
                                if d_idx < 32 {
                                    cpu.vfp[d_idx] = set_lane_u64(cpu.vfp[d_idx], s, elem_bytes, val);
                                }
                            } else {
                                if d_idx < 32 {
                                    let val = get_lane_u64(cpu.vfp[d_idx], s, elem_bytes);
                                    match elem_bytes {
                                        1 => mem.write_u8(addr, val as u8)?,
                                        2 => mem.write_u16(addr, val as u16)?,
                                        _ => mem.write_u32(addr, val)?,
                                    }
                                }
                            }
                        }
                    }
                }

                // Writeback
                match writeback {
                    NeonWriteback::None => {},
                    NeonWriteback::PostInc => {
                        let total_bytes = (reg_count as u32) * 8;
                        cpu.set_reg(rn, cpu.reg(rn).wrapping_add(total_bytes));
                    }
                    NeonWriteback::Reg(rm) => {
                        cpu.set_reg(rn, cpu.reg(rn).wrapping_add(cpu.reg(rm)));
                    }
                }

                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::NeonLoadStoreLane {
                is_load,
                structure_elements,
                all_lanes,
                lane,
                size,
                first_reg,
                stride,
                rn,
                writeback,
            } => {
                let elem_bytes = match size {
                    NeonSize::I8 => 1,
                    NeonSize::I16 => 2,
                    _ => 4,
                };
                let base_addr = cpu.reg(rn);
                let se = structure_elements as usize;

                if all_lanes {
                    // Broadcast / replicate to all lanes
                    let num_lanes = 8 / elem_bytes;
                    for e in 0..se {
                        let addr = GuestAddr::new(base_addr.wrapping_add((e * elem_bytes) as u32));
                        let val = match elem_bytes {
                            1 => mem.read_u8(addr)? as u32,
                            2 => mem.read_u16(addr)? as u32,
                            _ => mem.read_u32(addr)?,
                        };
                        let d_idx = (first_reg as usize) + e * (stride as usize);
                        if d_idx < 32 {
                            let mut reg_val = 0u64;
                            for l in 0..num_lanes {
                                reg_val = set_lane_u64(reg_val, l, elem_bytes, val);
                            }
                            cpu.vfp[d_idx] = reg_val;
                        }
                    }
                } else {
                    // Single lane transfer
                    for e in 0..se {
                        let addr = GuestAddr::new(base_addr.wrapping_add((e * elem_bytes) as u32));
                        let d_idx = (first_reg as usize) + e * (stride as usize);
                        if is_load {
                            let val = match elem_bytes {
                                1 => mem.read_u8(addr)? as u32,
                                2 => mem.read_u16(addr)? as u32,
                                _ => mem.read_u32(addr)?,
                            };
                            if d_idx < 32 {
                                cpu.vfp[d_idx] = set_lane_u64(cpu.vfp[d_idx], lane as usize, elem_bytes, val);
                            }
                        } else {
                            if d_idx < 32 {
                                let val = get_lane_u64(cpu.vfp[d_idx], lane as usize, elem_bytes);
                                match elem_bytes {
                                    1 => mem.write_u8(addr, val as u8)?,
                                    2 => mem.write_u16(addr, val as u16)?,
                                    _ => mem.write_u32(addr, val)?,
                                }
                            }
                        }
                    }
                }

                // Writeback
                let transferred = (se * elem_bytes) as u32;
                match writeback {
                    NeonWriteback::None => {},
                    NeonWriteback::PostInc => {
                        cpu.set_reg(rn, cpu.reg(rn).wrapping_add(transferred));
                    }
                    NeonWriteback::Reg(rm) => {
                        cpu.set_reg(rn, cpu.reg(rn).wrapping_add(cpu.reg(rm)));
                    }
                }

                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::NeonPermute {
                op,
                size,
                is_quad,
                vd,
                vm,
            } => {
                let count = if is_quad { 2 } else { 1 };
                let elem_bytes = match size {
                    NeonSize::I8 => 1,
                    NeonSize::I16 => 2,
                    _ => 4,
                };
                let total_bytes = count * 8;
                let num_elems = total_bytes / elem_bytes;
                let half = num_elems / 2;

                // Read input vectors a and b
                let mut bytes_a = [0u8; 16];
                let mut bytes_b = [0u8; 16];
                for i in 0..count {
                    let d_idx = (vd as usize) + i;
                    let m_idx = (vm as usize) + i;
                    if d_idx < 32 {
                        bytes_a[i * 8..(i + 1) * 8].copy_from_slice(&cpu.vfp[d_idx].to_le_bytes());
                    }
                    if m_idx < 32 {
                        bytes_b[i * 8..(i + 1) * 8].copy_from_slice(&cpu.vfp[m_idx].to_le_bytes());
                    }
                }

                let get_elem = |buf: &[u8; 16], idx: usize| -> u32 {
                    match elem_bytes {
                        1 => buf[idx] as u32,
                        2 => u16::from_le_bytes([buf[idx * 2], buf[idx * 2 + 1]]) as u32,
                        _ => u32::from_le_bytes([
                            buf[idx * 4],
                            buf[idx * 4 + 1],
                            buf[idx * 4 + 2],
                            buf[idx * 4 + 3],
                        ]),
                    }
                };

                let mut out_a = [0u8; 16];
                let mut out_b = [0u8; 16];

                let set_elem = |buf: &mut [u8; 16], idx: usize, val: u32| {
                    match elem_bytes {
                        1 => buf[idx] = val as u8,
                        2 => {
                            let le = (val as u16).to_le_bytes();
                            buf[idx * 2..idx * 2 + 2].copy_from_slice(&le);
                        }
                        _ => {
                            let le = val.to_le_bytes();
                            buf[idx * 4..idx * 4 + 4].copy_from_slice(&le);
                        }
                    }
                };

                match op {
                    NeonPermuteOp::Trn => {
                        for i in 0..half {
                            set_elem(&mut out_a, 2 * i, get_elem(&bytes_a, 2 * i));
                            set_elem(&mut out_a, 2 * i + 1, get_elem(&bytes_b, 2 * i));
                            set_elem(&mut out_b, 2 * i, get_elem(&bytes_a, 2 * i + 1));
                            set_elem(&mut out_b, 2 * i + 1, get_elem(&bytes_b, 2 * i + 1));
                        }
                    }
                    NeonPermuteOp::Zip => {
                        for i in 0..half {
                            set_elem(&mut out_a, 2 * i, get_elem(&bytes_a, i));
                            set_elem(&mut out_a, 2 * i + 1, get_elem(&bytes_b, i));
                            set_elem(&mut out_b, 2 * i, get_elem(&bytes_a, half + i));
                            set_elem(&mut out_b, 2 * i + 1, get_elem(&bytes_b, half + i));
                        }
                    }
                    NeonPermuteOp::Uzp => {
                        for i in 0..half {
                            set_elem(&mut out_a, i, get_elem(&bytes_a, 2 * i));
                            set_elem(&mut out_a, half + i, get_elem(&bytes_b, 2 * i));
                            set_elem(&mut out_b, i, get_elem(&bytes_a, 2 * i + 1));
                            set_elem(&mut out_b, half + i, get_elem(&bytes_b, 2 * i + 1));
                        }
                    }
                }

                // Write results back
                for i in 0..count {
                    let d_idx = (vd as usize) + i;
                    let m_idx = (vm as usize) + i;
                    let val_a = u64::from_le_bytes(out_a[i * 8..(i + 1) * 8].try_into().unwrap());
                    let val_b = u64::from_le_bytes(out_b[i * 8..(i + 1) * 8].try_into().unwrap());
                    if d_idx < 32 {
                        cpu.vfp[d_idx] = val_a;
                    }
                    if m_idx < 32 {
                        cpu.vfp[m_idx] = val_b;
                    }
                }

                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::NeonTbl {
                is_tbx,
                vd,
                vn,
                len,
                vm,
            } => {
                let mut table = [0u8; 32];
                let num_regs = (len as usize).min(4);
                for k in 0..num_regs {
                    let reg_idx = ((vn as usize) + k) % 32;
                    let bytes = cpu.vfp[reg_idx].to_le_bytes();
                    table[k * 8..(k + 1) * 8].copy_from_slice(&bytes);
                }

                let idx_reg = (vm as usize) % 32;
                let idx_bytes = cpu.vfp[idx_reg].to_le_bytes();
                let dst_reg = (vd as usize) % 32;
                let mut dst_bytes = cpu.vfp[dst_reg].to_le_bytes();

                for i in 0..8 {
                    let index = idx_bytes[i] as usize;
                    if index < num_regs * 8 {
                        dst_bytes[i] = table[index];
                    } else if !is_tbx {
                        dst_bytes[i] = 0;
                    }
                }

                cpu.vfp[dst_reg] = u64::from_le_bytes(dst_bytes);
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::NeonShiftImm {
                signed,
                saturate,
                size,
                is_quad,
                shift,
                vd,
                vm,
            } => {
                let count = if is_quad { 2 } else { 1 };
                for i in 0..count {
                    let d_idx = (vd as usize) + i;
                    let m_idx = (vm as usize) + i;
                    if d_idx < 32 && m_idx < 32 {
                        let a = cpu.vfp[m_idx];
                        let res = match (signed, size) {
                            (true, NeonSize::I32) => {
                                let mut r = 0u64;
                                for k in 0..2 {
                                    let val = (a >> (k * 32)) as i32;
                                    let shifted = if saturate {
                                        let s = (val as i64) << shift;
                                        s.clamp(i32::MIN as i64, i32::MAX as i64) as i32
                                    } else {
                                        val << shift
                                    };
                                    r |= (shifted as u32 as u64) << (k * 32);
                                }
                                r
                            }
                            (true, NeonSize::I16) => {
                                let mut r = 0u64;
                                for k in 0..4 {
                                    let val = (a >> (k * 16)) as i16;
                                    let shifted = if saturate {
                                        let s = (val as i32) << shift;
                                        s.clamp(i16::MIN as i32, i16::MAX as i32) as i16
                                    } else {
                                        val << shift
                                    };
                                    r |= (shifted as u16 as u64) << (k * 16);
                                }
                                r
                            }
                            (true, NeonSize::I8) => {
                                let mut r = 0u64;
                                for k in 0..8 {
                                    let val = (a >> (k * 8)) as i8;
                                    let shifted = if saturate {
                                        let s = (val as i16) << shift;
                                        s.clamp(i8::MIN as i16, i8::MAX as i16) as i8
                                    } else {
                                        val << shift
                                    };
                                    r |= (shifted as u8 as u64) << (k * 8);
                                }
                                r
                            }
                            (false, NeonSize::I32) => {
                                let mut r = 0u64;
                                for k in 0..2 {
                                    let val = (a >> (k * 32)) as u32;
                                    let shifted = if saturate {
                                        let s = (val as u64) << shift;
                                        s.min(u32::MAX as u64) as u32
                                    } else {
                                        val << shift
                                    };
                                    r |= (shifted as u64) << (k * 32);
                                }
                                r
                            }
                            (false, NeonSize::I16) => {
                                let mut r = 0u64;
                                for k in 0..4 {
                                    let val = (a >> (k * 16)) as u16;
                                    let shifted = if saturate {
                                        let s = (val as u32) << shift;
                                        s.min(u16::MAX as u32) as u16
                                    } else {
                                        val << shift
                                    };
                                    r |= (shifted as u64) << (k * 16);
                                }
                                r
                            }
                            (false, NeonSize::I8) => {
                                let mut r = 0u64;
                                for k in 0..8 {
                                    let val = (a >> (k * 8)) as u8;
                                    let shifted = if saturate {
                                        let s = (val as u16) << shift;
                                        s.min(u8::MAX as u16) as u8
                                    } else {
                                        val << shift
                                    };
                                    r |= (shifted as u64) << (k * 8);
                                }
                                r
                            }
                            _ => a,
                        };
                        cpu.vfp[d_idx] = res;
                    }
                }
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::NeonShiftNarrow {
                signed,
                dest_unsigned,
                saturate,
                src_size,
                shift,
                vd,
                vm,
            } => {
                let m0 = (vm as usize) % 32;
                let m1 = (vm as usize + 1) % 32;
                let d_idx = (vd as usize) % 32;

                let val0 = cpu.vfp[m0];
                let val1 = cpu.vfp[m1];

                let mut out = 0u64;
                match src_size {
                    NeonSize::I16 => {
                        // 16-bit to 8-bit (8 elements from Q to D)
                        for k in 0..8 {
                            let src_u64 = if k < 4 { val0 } else { val1 };
                            let sub_idx = k % 4;
                            let elem = (src_u64 >> (sub_idx * 16)) as u16;
                            let res_byte = if signed {
                                let val = (elem as i16) >> shift;
                                if saturate {
                                    if dest_unsigned {
                                        val.clamp(0, 255) as u8
                                    } else {
                                        val.clamp(-128, 127) as i8 as u8
                                    }
                                } else {
                                    val as u8
                                }
                            } else {
                                let val = elem >> shift;
                                if saturate {
                                    val.min(255) as u8
                                } else {
                                    val as u8
                                }
                            };
                            out |= (res_byte as u64) << (k * 8);
                        }
                    }
                    NeonSize::I32 => {
                        // 32-bit to 16-bit (4 elements from Q to D)
                        for k in 0..4 {
                            let src_u64 = if k < 2 { val0 } else { val1 };
                            let sub_idx = k % 2;
                            let elem = (src_u64 >> (sub_idx * 32)) as u32;
                            let res_h = if signed {
                                let val = (elem as i32) >> shift;
                                if saturate {
                                    if dest_unsigned {
                                        val.clamp(0, 65535) as u16
                                    } else {
                                        val.clamp(-32768, 32767) as i16 as u16
                                    }
                                } else {
                                    val as u16
                                }
                            } else {
                                let val = elem >> shift;
                                if saturate {
                                    val.min(65535) as u16
                                } else {
                                    val as u16
                                }
                            };
                            out |= (res_h as u64) << (k * 16);
                        }
                    }
                    _ => {
                        // 64-bit to 32-bit (2 elements from Q to D)
                        for k in 0..2 {
                            let src_u64 = if k == 0 { val0 } else { val1 };
                            let res_w = if signed {
                                let val = (src_u64 as i64) >> shift;
                                if saturate {
                                    if dest_unsigned {
                                        val.clamp(0, u32::MAX as i64) as u32
                                    } else {
                                        val.clamp(i32::MIN as i64, i32::MAX as i64) as i32 as u32
                                    }
                                } else {
                                    val as u32
                                }
                            } else {
                                let val = src_u64 >> shift;
                                if saturate {
                                    val.min(u32::MAX as u64) as u32
                                } else {
                                    val as u32
                                }
                            };
                            out |= (res_w as u64) << (k * 32);
                        }
                    }
                }

                cpu.vfp[d_idx] = out;
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::NeonPolyMul { vd, vn, vm } => {
                let n_idx = (vn as usize) % 32;
                let m_idx = (vm as usize) % 32;
                let d0_idx = (vd as usize) % 32;
                let d1_idx = (vd as usize + 1) % 32;

                let bytes_n = cpu.vfp[n_idx].to_le_bytes();
                let bytes_m = cpu.vfp[m_idx].to_le_bytes();

                let mut out_lo = 0u64;
                let mut out_hi = 0u64;

                for i in 0..8 {
                    let a = bytes_n[i] as u16;
                    let b = bytes_m[i] as u16;
                    let mut poly_res = 0u16;
                    for bit in 0..8 {
                        if (b & (1 << bit)) != 0 {
                            poly_res ^= a << bit;
                        }
                    }
                    if i < 4 {
                        out_lo |= (poly_res as u64) << (i * 16);
                    } else {
                        out_hi |= (poly_res as u64) << ((i - 4) * 16);
                    }
                }

                cpu.vfp[d0_idx] = out_lo;
                cpu.vfp[d1_idx] = out_hi;
                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::NeonExtract {
                is_quad,
                imm,
                vd,
                vn,
                vm,
            } => {
                if is_quad {
                    let n0 = (vn as usize) % 32;
                    let n1 = (vn as usize + 1) % 32;
                    let m0 = (vm as usize) % 32;
                    let m1 = (vm as usize + 1) % 32;
                    let d0 = (vd as usize) % 32;
                    let d1 = (vd as usize + 1) % 32;

                    let mut concat = [0u8; 32];
                    concat[0..8].copy_from_slice(&cpu.vfp[n0].to_le_bytes());
                    concat[8..16].copy_from_slice(&cpu.vfp[n1].to_le_bytes());
                    concat[16..24].copy_from_slice(&cpu.vfp[m0].to_le_bytes());
                    concat[24..32].copy_from_slice(&cpu.vfp[m1].to_le_bytes());

                    let offset = (imm as usize).min(16);
                    let r0 = u64::from_le_bytes(concat[offset..offset + 8].try_into().unwrap());
                    let r1 = u64::from_le_bytes(concat[offset + 8..offset + 16].try_into().unwrap());

                    cpu.vfp[d0] = r0;
                    cpu.vfp[d1] = r1;
                } else {
                    let n = (vn as usize) % 32;
                    let m = (vm as usize) % 32;
                    let d = (vd as usize) % 32;

                    let mut concat = [0u8; 16];
                    concat[0..8].copy_from_slice(&cpu.vfp[n].to_le_bytes());
                    concat[8..16].copy_from_slice(&cpu.vfp[m].to_le_bytes());

                    let offset = (imm as usize).min(8);
                    let r = u64::from_le_bytes(concat[offset..offset + 8].try_into().unwrap());

                    cpu.vfp[d] = r;
                }

                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::NeonRev {
                op,
                size,
                is_quad,
                vd,
                vm,
            } => {
                let count = if is_quad { 2 } else { 1 };
                let mut src = [0u8; 16];
                for i in 0..count {
                    let m = (vm as usize + i) % 32;
                    src[i * 8..(i + 1) * 8].copy_from_slice(&cpu.vfp[m].to_le_bytes());
                }

                let block_bytes = match op {
                    NeonRevOp::Rev64 => 8,
                    NeonRevOp::Rev32 => 4,
                    NeonRevOp::Rev16 => 2,
                };
                let elem_bytes = match size {
                    NeonSize::I8 => 1,
                    NeonSize::I16 => 2,
                    _ => 4,
                };
                let total_bytes = count * 8;
                let num_blocks = total_bytes / block_bytes;
                let elems_per_block = block_bytes / elem_bytes;
                let mut dst = [0u8; 16];

                for b in 0..num_blocks {
                    let block_start = b * block_bytes;
                    for i in 0..elems_per_block {
                        let src_off = block_start + i * elem_bytes;
                        let dst_off = block_start + (elems_per_block - 1 - i) * elem_bytes;
                        dst[dst_off..dst_off + elem_bytes].copy_from_slice(&src[src_off..src_off + elem_bytes]);
                    }
                }

                for i in 0..count {
                    let d = (vd as usize + i) % 32;
                    cpu.vfp[d] = u64::from_le_bytes(dst[i * 8..(i + 1) * 8].try_into().unwrap());
                }

                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::NeonDupScalar {
                size,
                index,
                is_quad,
                vd,
                vm,
            } => {
                let src_bytes = cpu.vfp[(vm as usize) % 32].to_le_bytes();
                let val64 = match size {
                    NeonSize::I8 => {
                        let b = src_bytes[(index as usize) % 8];
                        u64::from_le_bytes([b; 8])
                    }
                    NeonSize::I16 => {
                        let idx = ((index as usize) % 4) * 2;
                        let b0 = src_bytes[idx];
                        let b1 = src_bytes[idx + 1];
                        u64::from_le_bytes([b0, b1, b0, b1, b0, b1, b0, b1])
                    }
                    _ => {
                        let idx = ((index as usize) % 2) * 4;
                        let w = u32::from_le_bytes(src_bytes[idx..idx + 4].try_into().unwrap());
                        (w as u64) | ((w as u64) << 32)
                    }
                };

                let count = if is_quad { 2 } else { 1 };
                for i in 0..count {
                    let d = (vd as usize + i) % 32;
                    cpu.vfp[d] = val64;
                }

                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::NeonDupCore {
                size,
                is_quad,
                vd,
                rt,
            } => {
                let val = cpu.reg(rt);
                let val64 = match size {
                    NeonSize::I8 => {
                        let b = (val & 0xFF) as u8;
                        u64::from_le_bytes([b; 8])
                    }
                    NeonSize::I16 => {
                        let h = (val & 0xFFFF) as u16;
                        let [b0, b1] = h.to_le_bytes();
                        u64::from_le_bytes([b0, b1, b0, b1, b0, b1, b0, b1])
                    }
                    _ => (val as u64) | ((val as u64) << 32),
                };

                let count = if is_quad { 2 } else { 1 };
                for i in 0..count {
                    let d = (vd as usize + i) % 32;
                    cpu.vfp[d] = val64;
                }

                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::NeonShiftWiden {
                signed,
                src_size,
                shift,
                vd,
                vm,
            } => {
                let m = (vm as usize) % 32;
                let d0 = (vd as usize) % 32;
                let d1 = (vd as usize + 1) % 32;
                let src_val = cpu.vfp[m];

                match src_size {
                    NeonSize::I8 => {
                        let mut lo64 = 0u64;
                        let mut hi64 = 0u64;
                        for k in 0..8 {
                            let b = (src_val >> (k * 8)) as u8;
                            let widened = if signed {
                                ((b as i8 as i16) << shift) as u16
                            } else {
                                (b as u16) << shift
                            };
                            if k < 4 {
                                lo64 |= (widened as u64) << (k * 16);
                            } else {
                                hi64 |= (widened as u64) << ((k - 4) * 16);
                            }
                        }
                        cpu.vfp[d0] = lo64;
                        cpu.vfp[d1] = hi64;
                    }
                    NeonSize::I16 => {
                        let mut lo64 = 0u64;
                        let mut hi64 = 0u64;
                        for k in 0..4 {
                            let h = (src_val >> (k * 16)) as u16;
                            let widened = if signed {
                                ((h as i16 as i32) << shift) as u32
                            } else {
                                (h as u32) << shift
                            };
                            if k < 2 {
                                lo64 |= (widened as u64) << (k * 32);
                            } else {
                                hi64 |= (widened as u64) << ((k - 2) * 32);
                            }
                        }
                        cpu.vfp[d0] = lo64;
                        cpu.vfp[d1] = hi64;
                    }
                    _ => {
                        let w0 = src_val as u32;
                        let w1 = (src_val >> 32) as u32;
                        let res0 = if signed {
                            ((w0 as i32 as i64) << shift) as u64
                        } else {
                            (w0 as u64) << shift
                        };
                        let res1 = if signed {
                            ((w1 as i32 as i64) << shift) as u64
                        } else {
                            (w1 as u64) << shift
                        };
                        cpu.vfp[d0] = res0;
                        cpu.vfp[d1] = res1;
                    }
                }

                cpu.set_pc(next_pc);
                Ok(StepResult::Continue)
            }
            Op::NeonCvt {
                op,
                is_quad,
                vd,
                vm,
            } => {
                let regs = if is_quad { 2 } else { 1 };
                for r in 0..regs {
                    let m = (vm as usize + r) % 32;
                    let d = (vd as usize + r) % 32;
                    let src_val = cpu.vfp[m];

                    let mut out = 0u64;
                    for lane in 0..2 {
                        let word = (src_val >> (lane * 32)) as u32;
                        let res_u32 = match op {
                            NeonCvtOp::F32FromS32 => (word as i32 as f32).to_bits(),
                            NeonCvtOp::F32FromU32 => (word as f32).to_bits(),
                            NeonCvtOp::S32FromF32 => {
                                let f = f32::from_bits(word);
                                if f.is_nan() {
                                    0
                                } else if f >= i32::MAX as f32 {
                                    i32::MAX as u32
                                } else if f <= i32::MIN as f32 {
                                    i32::MIN as u32
                                } else {
                                    (f as i32) as u32
                                }
                            }
                            NeonCvtOp::U32FromF32 => {
                                let f = f32::from_bits(word);
                                if f.is_nan() || f <= 0.0 {
                                    0
                                } else if f >= u32::MAX as f32 {
                                    u32::MAX
                                } else {
                                    f as u32
                                }
                            }
                        };
                        out |= (res_u32 as u64) << (lane * 32);
                    }
                    cpu.vfp[d] = out;
                }

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
    fn test_interp_vfp_arithmetic_and_comparison() {
        let mut cpu = CpuState::new();
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x1000);

        // Set s1 = 1.5, s2 = 2.5
        cpu.set_s_reg(1, 1.5);
        cpu.set_s_reg(2, 2.5);

        // 0x1000: VADD.F32 s0, s1, s2 -> s0 should be 4.0 (0xEE300A81)
        // 0x1004: VCMP.F32 s0, s1     -> s0 (4.0) > s1 (1.5) (0xEEB40A60)
        // 0x1008: VMRS APSR_nzcv, FPSCR -> (0xEEF1FA10)
        // 0x100C: SVC 0
        mem.write_u32(GuestAddr::new(0x1000), 0xEE30_0A81).unwrap();
        mem.write_u32(GuestAddr::new(0x1004), 0xEEB4_0A60).unwrap();
        mem.write_u32(GuestAddr::new(0x1008), 0xEEF1_FA10).unwrap();
        mem.write_u32(GuestAddr::new(0x100C), 0xEF00_0000).unwrap();

        cpu.set_pc(GuestAddr::new(0x1000));

        // Step 1: VADD.F32
        Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.s_reg(0), 4.0);

        // Step 2: VCMP.F32
        Interpreter::step(&mut cpu, &mut mem).unwrap();

        // Step 3: VMRS APSR_nzcv, FPSCR
        Interpreter::step(&mut cpu, &mut mem).unwrap();

        // Condition C=1, Z=0 means greater than!
        assert!(cpu.cpsr.contains(Cpsr::C));
        assert!(!cpu.cpsr.contains(Cpsr::Z));
        assert!(cpu.check_cond(transd_core::Cond::GT));
    }

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

    #[test]
    fn test_interp_thumb_it_block() {
        let mut cpu = CpuState::new();
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);

        cpu.set_thumb(true);

        // Sequence at 0x1000:
        // 0x1000: CMP r0, #0      -> 0x2800 (CMP r0, #0)
        // 0x1002: ITE EQ          -> 0xBF0C (firstcond=EQ, mask=1100 for ITE)
        // 0x1004: MOV r1, #10     -> 0x210A (executed if EQ)
        // 0x1006: MOV r1, #20     -> 0x2114 (executed if NE)
        // 0x1008: SVC 0           -> 0xDF00
        mem.write_u16(GuestAddr::new(0x1000), 0x2800).unwrap();
        mem.write_u16(GuestAddr::new(0x1002), 0xBF0C).unwrap();
        mem.write_u16(GuestAddr::new(0x1004), 0x210A).unwrap();
        mem.write_u16(GuestAddr::new(0x1006), 0x2114).unwrap();
        mem.write_u16(GuestAddr::new(0x1008), 0xDF00).unwrap();

        // Case A: r0 = 0 -> condition EQ holds -> r1 becomes 10
        cpu.set_reg(Reg::R0, 0);
        cpu.set_pc(GuestAddr::new(0x1000));

        // 1. CMP
        Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert!(cpu.cpsr.contains(Cpsr::Z));

        // 2. ITE EQ
        Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_ne!(cpu.cpsr.itstate(), 0);

        // 3. MOV r1, #10 (Then - should execute!)
        Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.reg(Reg::R1), 10);

        // 4. MOV r1, #20 (Else - should be SKIPPED!)
        Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.reg(Reg::R1), 10); // Still 10!
        assert_eq!(cpu.cpsr.itstate(), 0); // IT block finished

        // Case B: r0 = 5 -> condition EQ does NOT hold -> r1 becomes 20
        cpu.set_reg(Reg::R0, 5);
        cpu.set_reg(Reg::R1, 0);
        cpu.set_pc(GuestAddr::new(0x1000));

        // CMP
        Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert!(!cpu.cpsr.contains(Cpsr::Z));

        // ITE EQ
        Interpreter::step(&mut cpu, &mut mem).unwrap();

        // MOV r1, #10 (Then - skipped)
        Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.reg(Reg::R1), 0);

        // MOV r1, #20 (Else - executed!)
        Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.reg(Reg::R1), 20);
        assert_eq!(cpu.cpsr.itstate(), 0);
    }

    #[test]
    fn test_interp_ldrd_strd() {
        let mut cpu = CpuState::new();
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);

        // Base memory address in r0 = 0x1500
        cpu.set_reg(Reg::R0, 0x1500);
        // Values in r2, r3
        cpu.set_reg(Reg::R2, 0x1122_3344);
        cpu.set_reg(Reg::R3, 0x5566_7788);

        // 0x1000: STRD r2, [r0, #8] (0xE1C020F8)
        // 0x1004: LDRD r4, [r0, #8] (0xE1C040D8)
        // 0x1008: SVC 0
        mem.write_u32(GuestAddr::new(0x1000), 0xE1C0_20F8).unwrap();
        mem.write_u32(GuestAddr::new(0x1004), 0xE1C0_40D8).unwrap();
        mem.write_u32(GuestAddr::new(0x1008), 0xEF00_0000).unwrap();

        cpu.set_pc(GuestAddr::new(0x1000));

        // 1. STRD
        Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_eq!(mem.read_u32(GuestAddr::new(0x1508)).unwrap(), 0x1122_3344);
        assert_eq!(mem.read_u32(GuestAddr::new(0x150C)).unwrap(), 0x5566_7788);

        // 2. LDRD into r4, r5
        Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.reg(Reg::R4), 0x1122_3344);
        assert_eq!(cpu.reg(Reg::R5), 0x5566_7788);
    }

    #[test]
    fn test_interp_neon_alu_and_load_store() {
        let mut cpu = CpuState::new();
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);

        // Write two 32-bit ints [100, 200] at 0x1500
        mem.write_u32(GuestAddr::new(0x1500), 100).unwrap();
        mem.write_u32(GuestAddr::new(0x1504), 200).unwrap();

        cpu.set_reg(Reg::R0, 0x1500); // load ptr
        cpu.set_reg(Reg::R1, 0x1600); // store ptr

        // Preset d1 with [300, 400]
        cpu.vfp[1] = 300 | ((400 as u64) << 32);

        // 0x1000: VLD1.32 {d0}, [r0] (0xF4200700)
        // 0x1004: VADD.I32 d2, d0, d1 (0xF2202801) -> [400, 600]
        // 0x1008: VST1.32 {d2}, [r1] (0xF4012700)
        mem.write_u32(GuestAddr::new(0x1000), 0xF420_0700).unwrap();
        mem.write_u32(GuestAddr::new(0x1004), 0xF220_2801).unwrap();
        mem.write_u32(GuestAddr::new(0x1008), 0xF401_2700).unwrap();

        cpu.set_pc(GuestAddr::new(0x1000));

        // 1. VLD1
        Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.vfp[0] & 0xFFFF_FFFF, 100);
        assert_eq!(cpu.vfp[0] >> 32, 200);

        // 2. VADD.I32
        Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.vfp[2] & 0xFFFF_FFFF, 400); // 100 + 300
        assert_eq!(cpu.vfp[2] >> 32, 600);        // 200 + 400

        // 3. VST1
        Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_eq!(mem.read_u32(GuestAddr::new(0x1600)).unwrap(), 400);
        assert_eq!(mem.read_u32(GuestAddr::new(0x1604)).unwrap(), 600);
    }

    #[test]
    fn test_interp_neon_f32x4_vector_pipeline() {
        let mut cpu = CpuState::new();
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);

        // Input vector in memory at 0x1500: [1.0, 2.0, 3.0, 4.0]
        let input_a = [1.0f32, 2.0f32, 3.0f32, 4.0f32];
        for (i, val) in input_a.iter().enumerate() {
            mem.write_u32(GuestAddr::new(0x1500 + (i as u32) * 4), val.to_bits()).unwrap();
        }

        cpu.set_reg(Reg::R0, 0x1500); // source pointer
        cpu.set_reg(Reg::R1, 0x1600); // destination pointer

        // Q1 (d2, d3) preset with [10.0, 20.0, 30.0, 40.0]
        cpu.set_q_reg_f32x4(1, [10.0, 20.0, 30.0, 40.0]);

        // Instructions:
        // 0x1000: VLD1.8 {d0, d1}, [r0] (Quadword 128-bit load -> Q0) -> 0xF4200A00
        // 0x1004: VMUL.F32 Q2, Q0, Q1 (0xF3004D52) -> Q2 = [10.0, 40.0, 90.0, 160.0]
        // 0x1008: VMLA.F32 Q2, Q0, Q1 (0xF2004D52) -> Q2 += [10.0, 40.0, 90.0, 160.0] => [20.0, 80.0, 180.0, 320.0]
        // 0x100C: VST1.8 {d4, d5}, [r1] (Quadword 128-bit store from Q2 -> d4, d5) -> 0xF4014A00
        mem.write_u32(GuestAddr::new(0x1000), 0xF420_0A00).unwrap();
        mem.write_u32(GuestAddr::new(0x1004), 0xF300_4D52).unwrap();
        mem.write_u32(GuestAddr::new(0x1008), 0xF200_4D52).unwrap();
        mem.write_u32(GuestAddr::new(0x100C), 0xF401_4A00).unwrap();

        cpu.set_pc(GuestAddr::new(0x1000));

        // 1. VLD1 Q0
        Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.q_reg_f32x4(0), [1.0, 2.0, 3.0, 4.0]);

        // 2. VMUL.F32 Q2 = Q0 * Q1
        Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.q_reg_f32x4(2), [10.0, 40.0, 90.0, 160.0]);

        // 3. VMLA.F32 Q2 += Q0 * Q1
        Interpreter::step(&mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.q_reg_f32x4(2), [20.0, 80.0, 180.0, 320.0]);

        // 4. VST1 Q2
        Interpreter::step(&mut cpu, &mut mem).unwrap();
        let mut out = [0.0f32; 4];
        for (i, slot) in out.iter_mut().enumerate() {
            let bits = mem.read_u32(GuestAddr::new(0x1600 + (i as u32) * 4)).unwrap();
            *slot = f32::from_bits(bits);
        }
        assert_eq!(out, [20.0, 80.0, 180.0, 320.0]);
    }
}
