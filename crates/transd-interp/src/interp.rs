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
            Op::VfpAlu {
                op,
                size,
                dst,
                src1,
                src2,
            } => {
                match size {
                    VfpSize::F32 => {
                        let s1 = match src1 {
                            VfpReg::S(idx) => cpu.s_reg(idx),
                            _ => 0.0,
                        };
                        let s2 = match src2 {
                            VfpReg::S(idx) => cpu.s_reg(idx),
                            _ => 0.0,
                        };

                        let mut res = 0.0f32;
                        match op {
                            VfpOp::Add => res = s1 + s2,
                            VfpOp::Sub => res = s1 - s2,
                            VfpOp::Mul => res = s1 * s2,
                            VfpOp::Div => res = s1 / s2,
                            VfpOp::Abs => res = s1.abs(),
                            VfpOp::Neg => res = -s1,
                            VfpOp::Sqrt => res = s1.sqrt(),
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
                            if let VfpReg::S(dst_idx) = dst {
                                cpu.set_s_reg(dst_idx, res);
                            }
                        }
                    }
                    VfpSize::F64 => {
                        let d1 = match src1 {
                            VfpReg::D(idx) => cpu.d_reg(idx),
                            _ => 0.0,
                        };
                        let d2 = match src2 {
                            VfpReg::D(idx) => cpu.d_reg(idx),
                            _ => 0.0,
                        };

                        let mut res = 0.0f64;
                        match op {
                            VfpOp::Add => res = d1 + d2,
                            VfpOp::Sub => res = d1 - d2,
                            VfpOp::Mul => res = d1 * d2,
                            VfpOp::Div => res = d1 / d2,
                            VfpOp::Abs => res = d1.abs(),
                            VfpOp::Neg => res = -d1,
                            VfpOp::Sqrt => res = d1.sqrt(),
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
                            if let VfpReg::D(dst_idx) = dst {
                                cpu.set_d_reg(dst_idx, res);
                            }
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
            Op::VfpMrsFpscr => {
                let n = (cpu.fpscr & (1 << 31)) != 0;
                let z = (cpu.fpscr & (1 << 30)) != 0;
                let c = (cpu.fpscr & (1 << 29)) != 0;
                let v = (cpu.fpscr & (1 << 28)) != 0;
                cpu.cpsr.set(Cpsr::N, n);
                cpu.cpsr.set(Cpsr::Z, z);
                cpu.cpsr.set(Cpsr::C, c);
                cpu.cpsr.set(Cpsr::V, v);

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
                is_quad,
                reg,
                rn,
            } => {
                let base_addr = cpu.reg(rn);
                let count = if is_quad { 2 } else { 1 };
                for i in 0..count {
                    let d_idx = (reg as usize) + i;
                    let addr = GuestAddr::new(base_addr.wrapping_add((i * 8) as u32));
                    if d_idx < 32 {
                        if is_load {
                            let lo = mem.read_u32(addr)? as u64;
                            let hi = (mem.read_u32(addr.add(4))? as u64) << 32;
                            cpu.vfp[d_idx] = lo | hi;
                        } else {
                            let val = cpu.vfp[d_idx];
                            mem.write_u32(addr, (val & 0xFFFF_FFFF) as u32)?;
                            mem.write_u32(addr.add(4), (val >> 32) as u32)?;
                        }
                    }
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
