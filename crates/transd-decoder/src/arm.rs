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

        // NEON Permute (VTRN, VUZP, VZIP: 2-register misc with opc2 == 0b10)
        if (raw & 0xFFB3_0810) == 0xF3B2_0000 {
            let op_code = (raw >> 7) & 0xF;
            let op = match op_code {
                0b0001 => Some(NeonPermuteOp::Trn),
                0b0010 => Some(NeonPermuteOp::Uzp),
                0b0011 => Some(NeonPermuteOp::Zip),
                _ => None,
            };
            if let Some(op) = op {
                let size_bits = (raw >> 18) & 0x3;
                let size = match size_bits {
                    0 => NeonSize::I8,
                    1 => NeonSize::I16,
                    _ => NeonSize::I32,
                };
                let d_bit = (raw >> 22) & 1;
                let m_bit = (raw >> 5) & 1;
                let q_bit = (raw >> 6) & 1;
                let vd = ((raw >> 12) & 0xF) | (d_bit << 4);
                let vm = (raw & 0xF) | (m_bit << 4);
                let is_quad = q_bit != 0;
                return Some(ArmInst::new(
                    Cond::AL,
                    Op::NeonPermute {
                        op,
                        size,
                        is_quad,
                        vd: vd as u8,
                        vm: vm as u8,
                    },
                    raw,
                ));
            }
        }

        // NEON Element Reverse (VREV64, VREV32, VREV16: 2-register misc with opc2 == 0b00)
        // 1111 0011 1 D 11 size 00 Vd 0 op:2 00 Q M 0 Vm
        if (raw & 0xFFB3_0990) == 0xF3B0_0000 {
            let op_bits = (raw >> 9) & 0x3;
            let op = match op_bits {
                0b00 => Some(NeonRevOp::Rev64),
                0b01 => Some(NeonRevOp::Rev32),
                0b10 => Some(NeonRevOp::Rev16),
                _ => None,
            };
            if let Some(op) = op {
                let size_bits = (raw >> 18) & 0x3;
                let size = match size_bits {
                    0b00 => Some(NeonSize::I8),
                    0b01 if op != NeonRevOp::Rev16 => Some(NeonSize::I16),
                    0b10 if op == NeonRevOp::Rev64 => Some(NeonSize::I32),
                    _ => None,
                };
                if let Some(size) = size {
                    let d_bit = (raw >> 22) & 1;
                    let m_bit = (raw >> 5) & 1;
                    let q_bit = (raw >> 6) & 1;
                    let vd = ((raw >> 12) & 0xF) | (d_bit << 4);
                    let vm = (raw & 0xF) | (m_bit << 4);
                    let is_quad = q_bit != 0;
                    return Some(ArmInst::new(
                        Cond::AL,
                        Op::NeonRev {
                            op,
                            size,
                            is_quad,
                            vd: vd as u8,
                            vm: vm as u8,
                        },
                        raw,
                    ));
                }
            }
        }

        // NEON Duplicate scalar (VDUP: 1111 0011 1 D 11 imm4 Vd 1100 0 Q M 0 Vm)
        if (raw & 0xFFB0_0F90) == 0xF3B0_0C00 {
            let imm4 = (raw >> 16) & 0xF;
            let size_idx = if (imm4 & 1) != 0 {
                Some((NeonSize::I8, (imm4 >> 1) as u8))
            } else if (imm4 & 2) != 0 {
                Some((NeonSize::I16, (imm4 >> 2) as u8))
            } else if (imm4 & 4) != 0 {
                Some((NeonSize::I32, (imm4 >> 3) as u8))
            } else {
                None
            };
            if let Some((size, index)) = size_idx {
                let d_bit = (raw >> 22) & 1;
                let m_bit = (raw >> 5) & 1;
                let q_bit = (raw >> 6) & 1;
                let vd = ((raw >> 12) & 0xF) | (d_bit << 4);
                let vm = (raw & 0xF) | (m_bit << 4);
                let is_quad = q_bit != 0;
                return Some(ArmInst::new(
                    Cond::AL,
                    Op::NeonDupScalar {
                        size,
                        index,
                        is_quad,
                        vd: vd as u8,
                        vm: vm as u8,
                    },
                    raw,
                ));
            }
        }

        // NEON Table Lookup (VTBL, VTBX: 1111 0011 1 D 11 Vn Vd 10 len N op M 0 Vm)
        if (raw & 0xFFB0_0C10) == 0xF3B0_0800 {
            let d_bit = (raw >> 22) & 1;
            let n_bit = (raw >> 7) & 1;
            let m_bit = (raw >> 5) & 1;
            let vd = ((raw >> 12) & 0xF) | (d_bit << 4);
            let vn = ((raw >> 16) & 0xF) | (n_bit << 4);
            let vm = (raw & 0xF) | (m_bit << 4);
            let len = (((raw >> 8) & 0x3) + 1) as u8;
            let is_tbx = ((raw >> 6) & 1) != 0;
            return Some(ArmInst::new(
                Cond::AL,
                Op::NeonTbl {
                    is_tbx,
                    vd: vd as u8,
                    vn: vn as u8,
                    len,
                    vm: vm as u8,
                },
                raw,
            ));
        }

        // NEON Polynomial Multiply (VMULL.P8: 1111 0010 1 D 00 Vn Vd 1110 N 0 M 0 Vm)
        if (raw & 0xFF80_0F00) == 0xF280_0E00 {
            let d_bit = (raw >> 22) & 1;
            let n_bit = (raw >> 7) & 1;
            let m_bit = (raw >> 5) & 1;
            let vd = ((raw >> 12) & 0xF) | (d_bit << 4);
            let vn = ((raw >> 16) & 0xF) | (n_bit << 4);
            let vm = (raw & 0xF) | (m_bit << 4);
            return Some(ArmInst::new(
                Cond::AL,
                Op::NeonPolyMul {
                    vd: vd as u8,
                    vn: vn as u8,
                    vm: vm as u8,
                },
                raw,
            ));
        }

        // NEON Shift Left Saturating by immediate (VQSHL: 1111 001x 1 D 11 imm6 Vd 0111 L Q M 1 Vm)
        if (raw & 0xFE80_0F90) == 0xF280_0710 {
            let u = (raw >> 24) & 1;
            let d_bit = (raw >> 22) & 1;
            let imm6 = (raw >> 16) & 0x3F;
            let vd = ((raw >> 12) & 0xF) | (d_bit << 4);
            let q_bit = (raw >> 6) & 1;
            let m_bit = (raw >> 5) & 1;
            let vm = (raw & 0xF) | (m_bit << 4);
            let (size, shift) = if (imm6 & 0b100000) != 0 {
                (NeonSize::I32, (imm6 - 32) as u8)
            } else if (imm6 & 0b010000) != 0 {
                (NeonSize::I16, (imm6 - 16) as u8)
            } else if (imm6 & 0b001000) != 0 {
                (NeonSize::I8, (imm6 - 8) as u8)
            } else {
                (NeonSize::I8, 0)
            };
            return Some(ArmInst::new(
                Cond::AL,
                Op::NeonShiftImm {
                    signed: u == 0,
                    saturate: true,
                    size,
                    is_quad: q_bit != 0,
                    shift,
                    vd: vd as u8,
                    vm: vm as u8,
                },
                raw,
            ));
        }

        // NEON Shift Right Narrow by immediate (VSHRN / VQSHRN / VQSHRUN)
        if (raw & 0xFF80_0F90) == 0xF280_0810
            || (raw & 0xFE80_0F90) == 0xF280_0910
            || (raw & 0xFF80_0F90) == 0xF380_0810
        {
            let is_vshrn = (raw & 0xFF80_0F90) == 0xF280_0810;
            let is_vqshrun = (raw & 0xFF80_0F90) == 0xF380_0810;
            let u = (raw >> 24) & 1;
            let d_bit = (raw >> 22) & 1;
            let imm6 = (raw >> 16) & 0x3F;
            let vd = ((raw >> 12) & 0xF) | (d_bit << 4);
            let m_bit = (raw >> 5) & 1;
            let vm = (raw & 0xF) | (m_bit << 4);
            let (src_size, shift) = if (imm6 & 0b100000) != 0 {
                (NeonSize::F32, (64 - imm6) as u8)
            } else if (imm6 & 0b010000) != 0 {
                (NeonSize::I32, (32 - imm6) as u8)
            } else if (imm6 & 0b001000) != 0 {
                (NeonSize::I16, (16 - imm6) as u8)
            } else {
                (NeonSize::I16, 0)
            };
            let (saturate, signed, dest_unsigned) = if is_vshrn {
                (false, false, false)
            } else if is_vqshrun {
                (true, true, true)
            } else if u != 0 {
                (true, false, true)
            } else {
                (true, true, false)
            };
            return Some(ArmInst::new(
                Cond::AL,
                Op::NeonShiftNarrow {
                    signed,
                    dest_unsigned,
                    saturate,
                    src_size,
                    shift,
                    vd: vd as u8,
                    vm: vm as u8,
                },
                raw,
            ));
        }

        // NEON Move Narrowing (VMOVN, VQMOVUN, VQMOVN: 2-register misc)
        // 1111 0011 1 D 11 size 10 Vd 0010 op:2 0 M 0 Vm
        if (raw & 0xFFB3_0F10) == 0xF3B2_0200 {
            let size_bits = (raw >> 18) & 0x3;
            let src_size = match size_bits {
                0 => NeonSize::I16,
                1 => NeonSize::I32,
                _ => NeonSize::F32,
            };
            let op_bits = (raw >> 6) & 0x3;
            let (saturate, signed, dest_unsigned) = match op_bits {
                0 => (false, false, false), // VMOVN
                1 => (true, true, true),    // VQMOVUN
                2 => (true, true, false),   // VQMOVN.S
                _ => (true, false, true),   // VQMOVN.U
            };
            let d_bit = (raw >> 22) & 1;
            let m_bit = (raw >> 5) & 1;
            let vd = ((raw >> 12) & 0xF) | (d_bit << 4);
            let vm = (raw & 0xF) | (m_bit << 4);
            return Some(ArmInst::new(
                Cond::AL,
                Op::NeonShiftNarrow {
                    signed,
                    dest_unsigned,
                    saturate,
                    src_size,
                    shift: 0,
                    vd: vd as u8,
                    vm: vm as u8,
                },
                raw,
            ));
        }

        // NEON Shift Left Widening / Move Long (VMOVL, VSHLL)
        // 1111 001U 1 D imm6 Vd 1010 0 0 M 1 Vm
        if (raw & 0xFE80_0F90) == 0xF280_0A10 {
            let u = (raw >> 24) & 1;
            let signed = u == 0;
            let d_bit = (raw >> 22) & 1;
            let m_bit = (raw >> 5) & 1;
            let imm6 = (raw >> 16) & 0x3F;
            let vd = ((raw >> 12) & 0xF) | (d_bit << 4);
            let vm = (raw & 0xF) | (m_bit << 4);
            let (src_size, shift) = if (imm6 & 0b100000) != 0 {
                (NeonSize::I32, (imm6 - 32) as u8)
            } else if (imm6 & 0b010000) != 0 {
                (NeonSize::I16, (imm6 - 16) as u8)
            } else if (imm6 & 0b001000) != 0 {
                (NeonSize::I8, (imm6 - 8) as u8)
            } else {
                (NeonSize::I8, 0)
            };
            return Some(ArmInst::new(
                Cond::AL,
                Op::NeonShiftWiden {
                    signed,
                    src_size,
                    shift,
                    vd: vd as u8,
                    vm: vm as u8,
                },
                raw,
            ));
        }

        // NEON VSHLL with shift = size (2-register misc: 1111 0011 1 D 11 size 10 Vd 0011 00 0 M 0 Vm)
        if (raw & 0xFFB3_0F10) == 0xF3B2_0300 {
            let size_bits = (raw >> 18) & 0x3;
            let (src_size, shift) = match size_bits {
                0 => (NeonSize::I8, 8),
                1 => (NeonSize::I16, 16),
                _ => (NeonSize::I32, 32),
            };
            let d_bit = (raw >> 22) & 1;
            let m_bit = (raw >> 5) & 1;
            let vd = ((raw >> 12) & 0xF) | (d_bit << 4);
            let vm = (raw & 0xF) | (m_bit << 4);
            return Some(ArmInst::new(
                Cond::AL,
                Op::NeonShiftWiden {
                    signed: false,
                    src_size,
                    shift,
                    vd: vd as u8,
                    vm: vm as u8,
                },
                raw,
            ));
        }

        // NEON Vector Convert between Floating-Point and Integer (VCVT)
        // 1111 0011 1 D 11 10 11 Vd 011 op:3 Q M 0 Vm (0xF3BB_0600)
        if (raw & 0xFFBF_0610) == 0xF3BB_0600 {
            let d_bit = (raw >> 22) & 1;
            let m_bit = (raw >> 5) & 1;
            let q_bit = (raw >> 6) & 1;
            let vd = ((raw >> 12) & 0xF) | (d_bit << 4);
            let vm = (raw & 0xF) | (m_bit << 4);
            let is_quad = q_bit != 0;
            let to_int = (raw & 0x100) != 0;
            let unsigned = (raw & 0x80) != 0;
            let op = match (to_int, unsigned) {
                (false, false) => NeonCvtOp::F32FromS32,
                (false, true) => NeonCvtOp::F32FromU32,
                (true, false) => NeonCvtOp::S32FromF32,
                (true, true) => NeonCvtOp::U32FromF32,
            };
            return Some(ArmInst::new(
                Cond::AL,
                Op::NeonCvt {
                    op,
                    is_quad,
                    vd: vd as u8,
                    vm: vm as u8,
                },
                raw,
            ));
        }

        // NEON Extract (VEXT: 1111 0010 1 D 11 Vn Vd imm4 N Q M 0 Vm)
        if (raw & 0xFFB0_0010) == 0xF2B0_0000 {
            let d_bit = (raw >> 22) & 1;
            let n_bit = (raw >> 7) & 1;
            let m_bit = (raw >> 5) & 1;
            let q_bit = (raw >> 6) & 1;
            let vd = ((raw >> 12) & 0xF) | (d_bit << 4);
            let vn = ((raw >> 16) & 0xF) | (n_bit << 4);
            let vm = (raw & 0xF) | (m_bit << 4);
            let imm4 = ((raw >> 8) & 0xF) as u8;
            let is_quad = q_bit != 0;
            return Some(ArmInst::new(
                Cond::AL,
                Op::NeonExtract {
                    is_quad,
                    imm: imm4,
                    vd: vd as u8,
                    vn: vn as u8,
                    vm: vm as u8,
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
                    // VPADD.F32 (bit24 == 1, Q == 0, bit 21 == 0)
                    if bit24 != 0 && !is_quad && (raw & (1 << 21)) == 0 {
                        return Some(ArmInst::new(
                            Cond::AL,
                            Op::NeonAlu {
                                op: NeonOp::Padd,
                                size: NeonSize::F32,
                                is_quad: false,
                                dst: vd as u8,
                                src1: vn as u8,
                                src2: vm as u8,
                            },
                            raw,
                        ));
                    }
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
                let is_min = (raw & (1 << 21)) != 0;
                if bit24 != 0 && !is_quad {
                    // Pairwise VPMAX.F32 / VPMIN.F32
                    let op = if is_min { NeonOp::Pmin } else { NeonOp::Pmax };
                    return Some(ArmInst::new(
                        Cond::AL,
                        Op::NeonAlu {
                            op,
                            size: NeonSize::F32,
                            is_quad: false,
                            dst: vd as u8,
                            src1: vn as u8,
                            src2: vm as u8,
                        },
                        raw,
                    ));
                }
                let op = if is_min { NeonOp::Min } else { NeonOp::Max };
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

            // Saturating VQADD: op_code == 0b0000, bit4 == 1
            if op_code == 0b0000 && bit4 == 1 {
                let op = if bit24 != 0 { NeonOp::Uqadd } else { NeonOp::Sqadd };
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

            // Saturating VQSUB: op_code == 0b0010, bit4 == 1
            if op_code == 0b0010 && bit4 == 1 {
                let op = if bit24 != 0 { NeonOp::Uqsub } else { NeonOp::Sqsub };
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

            // Saturating VQSHL (register): op_code == 0b0100, bit4 == 1
            if op_code == 0b0100 && bit4 == 1 {
                let op = if bit24 != 0 { NeonOp::Uqshl } else { NeonOp::Sqshl };
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

            // Pairwise integer VPADD: op_code == 0b1011, bit4 == 1, bit24 == 0, Q == 0
            if op_code == 0b1011 && bit4 == 1 && bit24 == 0 && !is_quad && size_bits < 3 {
                return Some(ArmInst::new(
                    Cond::AL,
                    Op::NeonAlu {
                        op: NeonOp::Padd,
                        size,
                        is_quad: false,
                        dst: vd as u8,
                        src1: vn as u8,
                        src2: vm as u8,
                    },
                    raw,
                ));
            }

            // Pairwise integer VPMAX / VPMIN: op_code == 0b1010, Q == 0
            if op_code == 0b1010 && !is_quad && size_bits < 3 {
                let op = match (bit24 != 0, bit4 != 0) {
                    (false, false) => NeonOp::Pmax,
                    (true, false) => NeonOp::Upmax,
                    (false, true) => NeonOp::Pmin,
                    (true, true) => NeonOp::Upmin,
                };
                return Some(ArmInst::new(
                    Cond::AL,
                    Op::NeonAlu {
                        op,
                        size,
                        is_quad: false,
                        dst: vd as u8,
                        src1: vn as u8,
                        src2: vm as u8,
                    },
                    raw,
                ));
            }
        }

        // NEON Element and Structure Load/Store (VLD1..4, VST1..4: 1111 0100 ...)
        if (raw & 0xFF00_0000) == 0xF400_0000 {
            let is_load = (raw & (1 << 21)) != 0;
            let d_bit = (raw >> 22) & 1;
            let first_reg = (((raw >> 12) & 0xF) | (d_bit << 4)) as u8;
            let rn = Reg::from_u8(((raw >> 16) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm_bits = (raw & 0xF) as u8;
            let writeback = match rm_bits {
                0b1111 => NeonWriteback::None,
                0b1101 => NeonWriteback::PostInc,
                other => NeonWriteback::Reg(Reg::from_u8(other).unwrap_or(Reg::R0)),
            };

            if (raw & (1 << 23)) == 0 {
                // Multiple structures
                let itype = ((raw >> 8) & 0xF) as u8;
                let (structure_elements, reg_count, stride) = match itype {
                    0b0000 => (4, 4, 1),
                    0b0001 => (4, 4, 2),
                    0b0010 => (1, 4, 1),
                    0b0011 => (2, 4, 1),
                    0b0100 => (3, 3, 1),
                    0b0101 => (3, 3, 2),
                    0b0110 => (1, 3, 1),
                    0b0111 => (1, 1, 1),
                    0b1000 => (2, 2, 1),
                    0b1001 => (2, 2, 2),
                    0b1010 => (1, 2, 1),
                    _ => return None,
                };
                let size_bits = (raw >> 6) & 0x3;
                let size = match size_bits {
                    0b00 => NeonSize::I8,
                    0b01 => NeonSize::I16,
                    0b10 => NeonSize::I32,
                    0b11 => NeonSize::I32,
                    _ => unreachable!(),
                };
                return Some(ArmInst::new(
                    Cond::AL,
                    Op::NeonLoadStore {
                        is_load,
                        structure_elements,
                        reg_count,
                        stride,
                        size,
                        first_reg,
                        rn,
                        writeback,
                    },
                    raw,
                ));
            } else {
                // Single element / all lanes
                let b11_10 = (raw >> 10) & 0x3;
                if b11_10 == 0b11 {
                    // All lanes (broadcast/replicate)
                    let se_bits = (raw >> 8) & 0x3;
                    let structure_elements = se_bits as u8 + 1;
                    let size_bits = (raw >> 6) & 0x3;
                    let size = match size_bits {
                        0b00 => NeonSize::I8,
                        0b01 => NeonSize::I16,
                        0b10 => NeonSize::I32,
                        _ => NeonSize::I32,
                    };
                    return Some(ArmInst::new(
                        Cond::AL,
                        Op::NeonLoadStoreLane {
                            is_load,
                            structure_elements,
                            all_lanes: true,
                            lane: 0,
                            size,
                            first_reg,
                            stride: 1,
                            rn,
                            writeback,
                        },
                        raw,
                    ));
                } else {
                    // Single lane
                    let se_bits = (raw >> 8) & 0x3;
                    let structure_elements = se_bits as u8 + 1;
                    let (size, lane) = match b11_10 {
                        0b00 => (NeonSize::I8, ((raw >> 5) & 0x7) as u8),
                        0b01 => (NeonSize::I16, ((raw >> 6) & 0x3) as u8),
                        0b10 => (NeonSize::I32, ((raw >> 7) & 0x1) as u8),
                        _ => unreachable!(),
                    };
                    return Some(ArmInst::new(
                        Cond::AL,
                        Op::NeonLoadStoreLane {
                            is_load,
                            structure_elements,
                            all_lanes: false,
                            lane,
                            size,
                            first_reg,
                            stride: 1,
                            rn,
                            writeback,
                        },
                        raw,
                    ));
                }
            }
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

            // 16-bit DSP Multiplies (SMULxy, SMLAxy, SMULWy, SMLAWy)
            // cond 0001 0xx0 Rd Rn Rs 1xx0 Rm
            if (raw & 0x0F90_0090) == 0x0100_0080 {
                let op_bits = (raw >> 21) & 0x3;
                let rd = Reg::from_u8(((raw >> 16) & 0xF) as u8).unwrap_or(Reg::R0);
                let rn = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
                let rs = Reg::from_u8(((raw >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
                let rm = Reg::from_u8((raw & 0xF) as u8).unwrap_or(Reg::R0);
                let x_top = ((raw >> 5) & 1) != 0;
                let y_top = ((raw >> 6) & 1) != 0;

                let op = match op_bits {
                    0b00 => Some(DspMulOp::Smla { x_top, y_top }),
                    0b01 => {
                        if x_top {
                            Some(DspMulOp::Smulw { y_top })
                        } else {
                            Some(DspMulOp::Smlaw { y_top })
                        }
                    }
                    0b11 => Some(DspMulOp::Smul { x_top, y_top }),
                    _ => None,
                };
                if let Some(op) = op {
                    return Op::DspMul { op, rd, rn, rm, rs };
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
        // UMAAL: cond 0000 0100 RdHi RdLo Rs 1001 Rm
        if (raw & 0x0FF0_00F0) == 0x0040_0090 {
            let rd_hi = Reg::from_u8(((raw >> 16) & 0xF) as u8).unwrap_or(Reg::R0);
            let rd_lo = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            let rs = Reg::from_u8(((raw >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((raw & 0xF) as u8).unwrap_or(Reg::R0);
            return Op::Umaal { rd_lo, rd_hi, rn: rs, rm };
        }

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

    /// Category 1: Single Data Transfer (LDR, STR, LDRB, STRB) and Media Bitfield/ByteRev
    fn decode_cat1(raw: u32) -> Op {
        // Bitfield Instructions (UBFX, SBFX, BFI, BFC)
        if (raw & 0x0FE0_0070) == 0x07E0_0050 {
            let rd = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            let rn = Reg::from_u8((raw & 0xF) as u8).unwrap_or(Reg::R0);
            let lsb = ((raw >> 7) & 0x1F) as u8;
            let width = (((raw >> 16) & 0x1F) as u8) + 1;
            return Op::BitField { op: BitFieldOp::Ubfx, rd, rn, lsb, width };
        }
        if (raw & 0x0FE0_0070) == 0x07A0_0050 {
            let rd = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            let rn = Reg::from_u8((raw & 0xF) as u8).unwrap_or(Reg::R0);
            let lsb = ((raw >> 7) & 0x1F) as u8;
            let width = (((raw >> 16) & 0x1F) as u8) + 1;
            return Op::BitField { op: BitFieldOp::Sbfx, rd, rn, lsb, width };
        }
        if (raw & 0x0FE0_0070) == 0x07C0_0010 {
            let rd = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            let rn_raw = (raw & 0xF) as u8;
            let rn = Reg::from_u8(rn_raw).unwrap_or(Reg::R0);
            let lsb = ((raw >> 7) & 0x1F) as u8;
            let msb = ((raw >> 16) & 0x1F) as u8;
            let width = if msb >= lsb { msb - lsb + 1 } else { 0 };
            let op = if rn_raw == 15 { BitFieldOp::Bfc } else { BitFieldOp::Bfi };
            return Op::BitField { op, rd, rn, lsb, width };
        }

        // Byte Reversal Instructions (REV, REV16, REVSH, RBIT)
        if (raw & 0x0FFF_0FF0) == 0x06BF_0F30 {
            let rd = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((raw & 0xF) as u8).unwrap_or(Reg::R0);
            return Op::ByteRev { op: ByteRevOp::Rev, rd, rm };
        }
        if (raw & 0x0FFF_0FF0) == 0x06BF_0FB0 {
            let rd = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((raw & 0xF) as u8).unwrap_or(Reg::R0);
            return Op::ByteRev { op: ByteRevOp::Rev16, rd, rm };
        }
        if (raw & 0x0FFF_0FF0) == 0x06FF_0F30 {
            let rd = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((raw & 0xF) as u8).unwrap_or(Reg::R0);
            return Op::ByteRev { op: ByteRevOp::Rbit, rd, rm };
        }
        if (raw & 0x0FFF_0FF0) == 0x06FF_0FB0 {
            let rd = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((raw & 0xF) as u8).unwrap_or(Reg::R0);
            return Op::ByteRev { op: ByteRevOp::Revsh, rd, rm };
        }

        // Parallel Addition and Subtraction (SADD8, SSUB8, SADD16, SSUB16, SASX, SSAX, U..., Q..., SH..., UH...)
        // cond 0110 0 op1:3 Rn Rd 1111 op2:3 1 Rm
        if (raw & 0x0F80_0F10) == 0x0600_0F10 {
            let op1 = ((raw >> 20) & 0x7) as u8;
            let op2 = ((raw >> 5) & 0x7) as u8;
            let op = match (op1, op2) {
                // S (Signed)
                (1, 4) => Some(SimdParallelOp::Sadd8),
                (1, 7) => Some(SimdParallelOp::Ssub8),
                (1, 0) => Some(SimdParallelOp::Sadd16),
                (1, 3) => Some(SimdParallelOp::Ssub16),
                (1, 1) => Some(SimdParallelOp::Sasx),
                (1, 2) => Some(SimdParallelOp::Ssax),
                // Q (Signed Saturating)
                (2, 4) => Some(SimdParallelOp::Qadd8),
                (2, 7) => Some(SimdParallelOp::Qsub8),
                (2, 0) => Some(SimdParallelOp::Qadd16),
                (2, 3) => Some(SimdParallelOp::Qsub16),
                (2, 1) => Some(SimdParallelOp::Qasx),
                (2, 2) => Some(SimdParallelOp::Qsax),
                // SH (Signed Halving)
                (3, 4) => Some(SimdParallelOp::Shadd8),
                (3, 7) => Some(SimdParallelOp::Shsub8),
                (3, 0) => Some(SimdParallelOp::Shadd16),
                (3, 3) => Some(SimdParallelOp::Shsub16),
                (3, 1) => Some(SimdParallelOp::Shasx),
                (3, 2) => Some(SimdParallelOp::Shsax),
                // U (Unsigned)
                (5, 4) => Some(SimdParallelOp::Uadd8),
                (5, 7) => Some(SimdParallelOp::Usub8),
                (5, 0) => Some(SimdParallelOp::Uadd16),
                (5, 3) => Some(SimdParallelOp::Usub16),
                (5, 1) => Some(SimdParallelOp::Uasx),
                (5, 2) => Some(SimdParallelOp::Usax),
                // UQ (Unsigned Saturating)
                (6, 4) => Some(SimdParallelOp::Uqadd8),
                (6, 7) => Some(SimdParallelOp::Uqsub8),
                (6, 0) => Some(SimdParallelOp::Uqadd16),
                (6, 3) => Some(SimdParallelOp::Uqsub16),
                (6, 1) => Some(SimdParallelOp::Uqasx),
                (6, 2) => Some(SimdParallelOp::Uqsax),
                // UH (Unsigned Halving)
                (7, 4) => Some(SimdParallelOp::Uhadd8),
                (7, 7) => Some(SimdParallelOp::Uhsub8),
                (7, 0) => Some(SimdParallelOp::Uhadd16),
                (7, 3) => Some(SimdParallelOp::Uhsub16),
                (7, 1) => Some(SimdParallelOp::Uhasx),
                (7, 2) => Some(SimdParallelOp::Uhsax),
                _ => None,
            };
            if let Some(op) = op {
                let rn = Reg::from_u8(((raw >> 16) & 0xF) as u8).unwrap_or(Reg::R0);
                let rd = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
                let rm = Reg::from_u8((raw & 0xF) as u8).unwrap_or(Reg::R0);
                return Op::SimdParallel { op, rd, rn, rm };
            }
        }

        // SEL (Select bytes according to APSR GE flags): cond 0110 1000 Rn Rd 1111 1011 Rm
        if (raw & 0x0FF0_0FF0) == 0x0680_0FB0 {
            let rn = Reg::from_u8(((raw >> 16) & 0xF) as u8).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((raw & 0xF) as u8).unwrap_or(Reg::R0);
            return Op::SimdSel { rd, rn, rm };
        }

        // PKHBT and PKHTB (Pack Halfword): cond 0110 1000 Rn Rd imm5 tb 01 Rm
        if (raw & 0x0FF0_0030) == 0x0680_0010 {
            let rn = Reg::from_u8(((raw >> 16) & 0xF) as u8).unwrap_or(Reg::R0);
            let rd = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((raw & 0xF) as u8).unwrap_or(Reg::R0);
            let tb = ((raw >> 6) & 1) != 0;
            let shift = ((raw >> 7) & 0x1F) as u8;
            let op = if tb { PkhOp::Pkhtb } else { PkhOp::Pkhbt };
            return Op::SimdPkh { op, rd, rn, rm, shift };
        }

        // Extend and Extend & Add (SXTB, UXTB, SXTH, UXTH, SXTAB, UXTAB, SXTAH, UXTAH, SXTAB16, UXTAB16)
        // cond 0110 1xxx Rn Rd rot:2 00 0111 Rm
        if (raw & 0x0F80_03F0) == 0x0680_0070 {
            let op_bits = (raw >> 20) & 0x7;
            let op = match op_bits {
                0 => Some(ExtendOp::Sxtb16),
                2 => Some(ExtendOp::Sxtb),
                3 => Some(ExtendOp::Sxth),
                4 => Some(ExtendOp::Uxtb16),
                6 => Some(ExtendOp::Uxtb),
                7 => Some(ExtendOp::Uxth),
                _ => None,
            };
            if let Some(op) = op {
                let rn_raw = ((raw >> 16) & 0xF) as u8;
                let rn = if rn_raw == 15 { None } else { Reg::from_u8(rn_raw) };
                let rd = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
                let rm = Reg::from_u8((raw & 0xF) as u8).unwrap_or(Reg::R0);
                let rotation = (((raw >> 10) & 0x3) as u8) * 8;
                return Op::SimdExtend { op, rd, rn, rm, rotation };
            }
        }

        // Dual 16-bit Multiplies (SMUAD, SMUSD, SMLAD, SMLSD)
        // cond 0111 0000 Rd Rn Rs 0xx1 Rm
        if (raw & 0x0FF0_0090) == 0x0700_0010 {
            let rd = Reg::from_u8(((raw >> 16) & 0xF) as u8).unwrap_or(Reg::R0);
            let rn = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            let rs = Reg::from_u8(((raw >> 8) & 0xF) as u8).unwrap_or(Reg::R0);
            let rm = Reg::from_u8((raw & 0xF) as u8).unwrap_or(Reg::R0);
            let swap = ((raw >> 5) & 1) != 0;
            let is_sub = ((raw >> 6) & 1) != 0;
            let is_accumulate = ((raw >> 12) & 0xF) != 15;

            let op = match (is_accumulate, is_sub) {
                (false, false) => DspMulOp::Smuad { swap },
                (false, true) => DspMulOp::Smusd { swap },
                (true, false) => DspMulOp::Smlad { swap },
                (true, true) => DspMulOp::Smlsd { swap },
            };
            return Op::DspMul { op, rd, rn, rm, rs };
        }

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

        // VDUP (ARM core register): 1110 1110 1 B Q 0 Vd:4 Rt:4 1011 D 0 E 1 0000
        if (raw & 0x0F90_0F5F) == 0x0E80_0B10 {
            let b = ((raw >> 22) & 1) != 0;
            let q = ((raw >> 21) & 1) != 0;
            let e = ((raw >> 5) & 1) != 0;
            let d = (raw >> 7) & 1;
            let vd = (((raw >> 16) & 0xF) | (d << 4)) as u8;
            let rt = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            let size = match (b, e) {
                (false, false) => Some(NeonSize::I32),
                (false, true) => Some(NeonSize::I16),
                (true, false) => Some(NeonSize::I8),
                _ => None,
            };
            if let Some(size) = size {
                return Op::NeonDupCore {
                    size,
                    is_quad: q,
                    vd,
                    rt,
                };
            }
        }

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

        // VMOV 2 core registers <-> 1 double or 2 singles
        // VMOV <Rt>, <Rt2>, <Dm> (0x_C50_0B10) / VMOV <Dm>, <Rt>, <Rt2> (0x_C40_0B10)
        // VMOV <Rt>, <Rt2>, <Sm>, <Sm1> (0x_C50_0A10) / VMOV <Sm>, <Sm1>, <Rt>, <Rt2> (0x_C40_0A10)
        if (raw & 0x0FE0_0FD0) == 0x0C40_0B10 || (raw & 0x0FE0_0FD0) == 0x0C40_0A10 {
            let to_core = ((raw >> 20) & 1) != 0;
            let is_double = ((raw >> 8) & 0xF) == 0xB;
            let rt2 = Reg::from_u8(((raw >> 16) & 0xF) as u8).unwrap_or(Reg::R0);
            let rt = Reg::from_u8(((raw >> 12) & 0xF) as u8).unwrap_or(Reg::R0);
            let m_bit = ((raw >> 5) & 1) as u8;
            let vm = (raw & 0xF) as u8;
            let vfp_reg = if is_double {
                let d_idx = (m_bit << 4) | vm;
                VfpReg::D(d_idx)
            } else {
                let s_idx = (vm << 1) | m_bit;
                VfpReg::S(s_idx)
            };
            return Op::VfpMovTwoCore {
                to_core,
                is_double,
                rt,
                rt2,
                vfp_reg,
            };
        }

        // VLDR / VSTR / VLDM / VSTM / VPUSH / VPOP: bits [27:25] == 0b110
        if ((raw >> 25) & 0x7) == 0b110 {
            let p = ((raw >> 24) & 1) != 0;
            let u = ((raw >> 23) & 1) != 0;
            let d = ((raw >> 22) & 1) as u8;
            let w = ((raw >> 21) & 1) != 0;
            let is_load = ((raw >> 20) & 1) != 0;
            let rn = Reg::from_u8(((raw >> 16) & 0xF) as u8).unwrap_or(Reg::R0);
            let vd = ((raw >> 12) & 0xF) as u8;
            let imm8 = (raw & 0xFF) as u8;

            if p && !w {
                // Single VLDR / VSTR
                let offset = if u { (imm8 as i32) * 4 } else { -((imm8 as i32) * 4) };
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
            } else {
                // VLDM / VSTM / VPUSH / VPOP (Multiple transfer)
                let (start_reg, count) = if is_double {
                    let d_idx = (d << 4) | vd;
                    (d_idx, imm8 / 2)
                } else {
                    let s_idx = (vd << 1) | d;
                    (s_idx, imm8)
                };
                return Op::VfpLoadStoreMultiple {
                    is_load,
                    is_double,
                    writeback: w,
                    is_add: u,
                    rn,
                    start_reg,
                    count,
                };
            }
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

        // VFP 1-register extension / VCMP: bits [23:20] == 0b1D11, bits [11:9] == 0b101
        if ((raw >> 20) & 0b1011) == 0b1011 && ((raw >> 9) & 0x7) == 0b101 {
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
            } else if opc2 == 0b0111 {
                // VCVT between Single and Double precision
                let (op, dst, src) = if is_double {
                    (
                        VfpCvtOp::F32FromF64,
                        VfpReg::S((vd << 1) | d),
                        VfpReg::D((m << 4) | vm),
                    )
                } else {
                    (
                        VfpCvtOp::F64FromF32,
                        VfpReg::D((d << 4) | vd),
                        VfpReg::S((vm << 1) | m),
                    )
                };
                return Op::VfpCvt { op, dst, src };
            } else if opc2 == 0b1000 {
                // VCVT from integer to floating-point
                let signed = ((raw >> 7) & 1) != 0;
                let src = VfpReg::S((vm << 1) | m);
                let (op, dst) = if is_double {
                    let op = if signed { VfpCvtOp::F64FromS32 } else { VfpCvtOp::F64FromU32 };
                    (op, VfpReg::D((d << 4) | vd))
                } else {
                    let op = if signed { VfpCvtOp::F32FromS32 } else { VfpCvtOp::F32FromU32 };
                    (op, VfpReg::S((vd << 1) | d))
                };
                return Op::VfpCvt { op, dst, src };
            } else if opc2 == 0b1100 {
                // VCVT from floating-point to unsigned 32-bit integer (round towards zero)
                let dst = VfpReg::S((vd << 1) | d);
                let (op, src) = if is_double {
                    (VfpCvtOp::U32FromF64, VfpReg::D((m << 4) | vm))
                } else {
                    (VfpCvtOp::U32FromF32, VfpReg::S((vm << 1) | m))
                };
                return Op::VfpCvt { op, dst, src };
            } else if opc2 == 0b1101 {
                // VCVT from floating-point to signed 32-bit integer (round towards zero)
                let dst = VfpReg::S((vd << 1) | d);
                let (op, src) = if is_double {
                    (VfpCvtOp::S32FromF64, VfpReg::D((m << 4) | vm))
                } else {
                    (VfpCvtOp::S32FromF32, VfpReg::S((vm << 1) | m))
                };
                return Op::VfpCvt { op, dst, src };
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

        // VLD1.8 {d0, d1}, [r0] (2 D registers)
        let inst = ArmDecoder::decode(0xF420_0A0F);
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

        // VST1.8 {d0, d1}, [r0] (2 D registers)
        let inst = ArmDecoder::decode(0xF400_0A0F);
        assert_eq!(
            inst.op,
            Op::NeonLoadStore {
                is_load: false,
                structure_elements: 1,
                reg_count: 2,
                stride: 1,
                size: NeonSize::I8,
                first_reg: 0,
                rn: Reg::R0,
                writeback: NeonWriteback::None,
            }
        );

        // VLD2.8 {d0, d1}, [r0]! (2 D registers with post-inc)
        let inst_vld2 = ArmDecoder::decode(0xF420_080D);
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

        // VLD3.8 {d0, d1, d2}, [r0]
        let inst_vld3 = ArmDecoder::decode(0xF420_040F);
        assert_eq!(
            inst_vld3.op,
            Op::NeonLoadStore {
                is_load: true,
                structure_elements: 3,
                reg_count: 3,
                stride: 1,
                size: NeonSize::I8,
                first_reg: 0,
                rn: Reg::R0,
                writeback: NeonWriteback::None,
            }
        );

        // VLD4.8 {d0, d1, d2, d3}, [r0]
        let inst_vld4 = ArmDecoder::decode(0xF420_000F);
        assert_eq!(
            inst_vld4.op,
            Op::NeonLoadStore {
                is_load: true,
                structure_elements: 4,
                reg_count: 4,
                stride: 1,
                size: NeonSize::I8,
                first_reg: 0,
                rn: Reg::R0,
                writeback: NeonWriteback::None,
            }
        );

        // VLD1.8 {d0[]}, [r0] (all lanes broadcast)
        let inst_vld1_all = ArmDecoder::decode(0xF4A0_0C0F);
        assert_eq!(
            inst_vld1_all.op,
            Op::NeonLoadStoreLane {
                is_load: true,
                structure_elements: 1,
                all_lanes: true,
                lane: 0,
                size: NeonSize::I8,
                first_reg: 0,
                stride: 1,
                rn: Reg::R0,
                writeback: NeonWriteback::None,
            }
        );

        // VTRN.32 d0, d1
        let inst = ArmDecoder::decode(0xF3BA_0081);
        assert_eq!(
            inst.op,
            Op::NeonPermute {
                op: NeonPermuteOp::Trn,
                size: NeonSize::I32,
                is_quad: false,
                vd: 0,
                vm: 1,
            }
        );

        // VZIP.16 q0, q1 (vd=0, vm=2, is_quad=true)
        let inst = ArmDecoder::decode(0xF3B6_01C2);
        assert_eq!(
            inst.op,
            Op::NeonPermute {
                op: NeonPermuteOp::Zip,
                size: NeonSize::I16,
                is_quad: true,
                vd: 0,
                vm: 2,
            }
        );

        // VTBL.8 d5, {d8, d9}, d3
        let inst = ArmDecoder::decode(0xF3B8_5903);
        assert_eq!(
            inst.op,
            Op::NeonTbl {
                is_tbx: false,
                vd: 5,
                vn: 8,
                len: 2,
                vm: 3,
            }
        );

        // VQADD.S32 q0, q1, q2
        let inst = ArmDecoder::decode(0xF222_0054);
        assert_eq!(
            inst.op,
            Op::NeonAlu {
                op: NeonOp::Sqadd,
                size: NeonSize::I32,
                is_quad: true,
                dst: 0,
                src1: 2,
                src2: 4,
            }
        );

        // VMULL.P8 q0, d0, d1
        let inst = ArmDecoder::decode(0xF280_0E01);
        assert_eq!(
            inst.op,
            Op::NeonPolyMul {
                vd: 0,
                vn: 0,
                vm: 1,
            }
        );

        // VPADD.F32 d0, d1, d2
        let inst = ArmDecoder::decode(0xF301_0D02);
        assert_eq!(
            inst.op,
            Op::NeonAlu {
                op: NeonOp::Padd,
                size: NeonSize::F32,
                is_quad: false,
                dst: 0,
                src1: 1,
                src2: 2,
            }
        );

        // VPADD.I32 d0, d1, d2
        let inst = ArmDecoder::decode(0xF221_0B12);
        assert_eq!(
            inst.op,
            Op::NeonAlu {
                op: NeonOp::Padd,
                size: NeonSize::I32,
                is_quad: false,
                dst: 0,
                src1: 1,
                src2: 2,
            }
        );

        // VPMAX.F32 d0, d1, d2
        let inst = ArmDecoder::decode(0xF301_0F02);
        assert_eq!(
            inst.op,
            Op::NeonAlu {
                op: NeonOp::Pmax,
                size: NeonSize::F32,
                is_quad: false,
                dst: 0,
                src1: 1,
                src2: 2,
            }
        );

        // VPMIN.F32 d0, d1, d2
        let inst = ArmDecoder::decode(0xF321_0F02);
        assert_eq!(
            inst.op,
            Op::NeonAlu {
                op: NeonOp::Pmin,
                size: NeonSize::F32,
                is_quad: false,
                dst: 0,
                src1: 1,
                src2: 2,
            }
        );

        // VPMAX.S32 d0, d1, d2
        let inst = ArmDecoder::decode(0xF221_0A02);
        assert_eq!(
            inst.op,
            Op::NeonAlu {
                op: NeonOp::Pmax,
                size: NeonSize::I32,
                is_quad: false,
                dst: 0,
                src1: 1,
                src2: 2,
            }
        );

        // VPMIN.U16 d0, d1, d2
        let inst = ArmDecoder::decode(0xF311_0A12);
        assert_eq!(
            inst.op,
            Op::NeonAlu {
                op: NeonOp::Upmin,
                size: NeonSize::I16,
                is_quad: false,
                dst: 0,
                src1: 1,
                src2: 2,
            }
        );

        // VEXT.8 d0, d1, d2, #3
        let inst = ArmDecoder::decode(0xF2B1_0302);
        assert_eq!(
            inst.op,
            Op::NeonExtract {
                is_quad: false,
                imm: 3,
                vd: 0,
                vn: 1,
                vm: 2,
            }
        );

        // VEXT.8 q0, q1, q2, #5
        let inst = ArmDecoder::decode(0xF2B2_0544);
        assert_eq!(
            inst.op,
            Op::NeonExtract {
                is_quad: true,
                imm: 5,
                vd: 0,
                vn: 2,
                vm: 4,
            }
        );

        // VREV64.32 q0, q1
        let inst = ArmDecoder::decode(0xF3B8_0042);
        assert_eq!(
            inst.op,
            Op::NeonRev {
                op: NeonRevOp::Rev64,
                size: NeonSize::I32,
                is_quad: true,
                vd: 0,
                vm: 2,
            }
        );

        // VREV32.16 d0, d1
        let inst = ArmDecoder::decode(0xF3B4_0201);
        assert_eq!(
            inst.op,
            Op::NeonRev {
                op: NeonRevOp::Rev32,
                size: NeonSize::I16,
                is_quad: false,
                vd: 0,
                vm: 1,
            }
        );

        // VREV16.8 d0, d1
        let inst = ArmDecoder::decode(0xF3B0_0401);
        assert_eq!(
            inst.op,
            Op::NeonRev {
                op: NeonRevOp::Rev16,
                size: NeonSize::I8,
                is_quad: false,
                vd: 0,
                vm: 1,
            }
        );

        // VDUP.32 q0, d2[1]
        let inst = ArmDecoder::decode(0xF3BC_0C42);
        assert_eq!(
            inst.op,
            Op::NeonDupScalar {
                size: NeonSize::I32,
                index: 1,
                is_quad: true,
                vd: 0,
                vm: 2,
            }
        );

        // VDUP.32 q0, r3
        let inst = ArmDecoder::decode(0xEEA0_3B10);
        assert_eq!(
            inst.op,
            Op::NeonDupCore {
                size: NeonSize::I32,
                is_quad: true,
                vd: 0,
                rt: Reg::R3,
            }
        );

        // VMOVN.I16 d0, q1 (0xF3B2_0202)
        let inst = ArmDecoder::decode(0xF3B2_0202);
        assert_eq!(
            inst.op,
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

        // VMOVN.I32 d0, q1 (0xF3B6_0202)
        let inst = ArmDecoder::decode(0xF3B6_0202);
        assert_eq!(
            inst.op,
            Op::NeonShiftNarrow {
                signed: false,
                dest_unsigned: false,
                saturate: false,
                src_size: NeonSize::I32,
                shift: 0,
                vd: 0,
                vm: 2,
            }
        );

        // VMOVL.S8 q0, d2 (0xF288_0A12)
        let inst = ArmDecoder::decode(0xF288_0A12);
        assert_eq!(
            inst.op,
            Op::NeonShiftWiden {
                signed: true,
                src_size: NeonSize::I8,
                shift: 0,
                vd: 0,
                vm: 2,
            }
        );

        // VMOVL.U8 q0, d2 (0xF388_0A12)
        let inst = ArmDecoder::decode(0xF388_0A12);
        assert_eq!(
            inst.op,
            Op::NeonShiftWiden {
                signed: false,
                src_size: NeonSize::I8,
                shift: 0,
                vd: 0,
                vm: 2,
            }
        );

        // VSHLL.S16 q0, d2, #4 (0xF294_0A12)
        let inst = ArmDecoder::decode(0xF294_0A12);
        assert_eq!(
            inst.op,
            Op::NeonShiftWiden {
                signed: true,
                src_size: NeonSize::I16,
                shift: 4,
                vd: 0,
                vm: 2,
            }
        );

        // VCVT.F32.S32 q0, q1 (0xF3BB_0642)
        let inst = ArmDecoder::decode(0xF3BB_0642);
        assert_eq!(
            inst.op,
            Op::NeonCvt {
                op: NeonCvtOp::F32FromS32,
                is_quad: true,
                vd: 0,
                vm: 2,
            }
        );

        // VCVT.S32.F32 d0, d2 (0xF3BB_0702)
        let inst = ArmDecoder::decode(0xF3BB_0702);
        assert_eq!(
            inst.op,
            Op::NeonCvt {
                op: NeonCvtOp::S32FromF32,
                is_quad: false,
                vd: 0,
                vm: 2,
            }
        );

        // VCVT.U32.F32 q0, q1 (0xF3BB_07C2)
        let inst = ArmDecoder::decode(0xF3BB_07C2);
        assert_eq!(
            inst.op,
            Op::NeonCvt {
                op: NeonCvtOp::U32FromF32,
                is_quad: true,
                vd: 0,
                vm: 2,
            }
        );

        // VPUSH {d8-d15} (0xED2D_8B10)
        let inst = ArmDecoder::decode(0xED2D_8B10);
        assert_eq!(
            inst.op,
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

        // VPOP {d8-d15} (0xECBD_8B10)
        let inst = ArmDecoder::decode(0xECBD_8B10);
        assert_eq!(
            inst.op,
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

        // VCVT.F64.F32 d0, s0 (0xEEB7_0AC0)
        let inst = ArmDecoder::decode(0xEEB7_0AC0);
        assert_eq!(
            inst.op,
            Op::VfpCvt {
                op: VfpCvtOp::F64FromF32,
                dst: VfpReg::D(0),
                src: VfpReg::S(0),
            }
        );

        // VCVT.F32.F64 s0, d0 (0xEEB7_0BC0)
        let inst = ArmDecoder::decode(0xEEB7_0BC0);
        assert_eq!(
            inst.op,
            Op::VfpCvt {
                op: VfpCvtOp::F32FromF64,
                dst: VfpReg::S(0),
                src: VfpReg::D(0),
            }
        );

        // VCVT.F32.S32 s0, s0 (0xEEB8_0AC0)
        let inst = ArmDecoder::decode(0xEEB8_0AC0);
        assert_eq!(
            inst.op,
            Op::VfpCvt {
                op: VfpCvtOp::F32FromS32,
                dst: VfpReg::S(0),
                src: VfpReg::S(0),
            }
        );

        // VCVT.S32.F32 s0, s0 (0xEEBD_0AC0)
        let inst = ArmDecoder::decode(0xEEBD_0AC0);
        assert_eq!(
            inst.op,
            Op::VfpCvt {
                op: VfpCvtOp::S32FromF32,
                dst: VfpReg::S(0),
                src: VfpReg::S(0),
            }
        );
    }

    #[test]
    fn test_decode_bitfield_and_byte_rev() {
        // UBFX r0, r1, #4, #8
        let inst = ArmDecoder::decode(0xE7E7_0251);
        assert_eq!(
            inst.op,
            Op::BitField {
                op: BitFieldOp::Ubfx,
                rd: Reg::R0,
                rn: Reg::R1,
                lsb: 4,
                width: 8,
            }
        );

        // SBFX r0, r1, #4, #8
        let inst = ArmDecoder::decode(0xE7A7_0251);
        assert_eq!(
            inst.op,
            Op::BitField {
                op: BitFieldOp::Sbfx,
                rd: Reg::R0,
                rn: Reg::R1,
                lsb: 4,
                width: 8,
            }
        );

        // BFI r0, r1, #4, #8 (msb = 11 -> 0xB)
        let inst = ArmDecoder::decode(0xE7CB_0211);
        assert_eq!(
            inst.op,
            Op::BitField {
                op: BitFieldOp::Bfi,
                rd: Reg::R0,
                rn: Reg::R1,
                lsb: 4,
                width: 8,
            }
        );

        // BFC r0, #4, #8 (Rn = 15)
        let inst = ArmDecoder::decode(0xE7CB_021F);
        assert_eq!(
            inst.op,
            Op::BitField {
                op: BitFieldOp::Bfc,
                rd: Reg::R0,
                rn: Reg::from_u8(15).unwrap(),
                lsb: 4,
                width: 8,
            }
        );

        // REV r0, r1
        let inst = ArmDecoder::decode(0xE6BF_0F31);
        assert_eq!(inst.op, Op::ByteRev { op: ByteRevOp::Rev, rd: Reg::R0, rm: Reg::R1 });

        // REV16 r0, r1
        let inst = ArmDecoder::decode(0xE6BF_0FB1);
        assert_eq!(inst.op, Op::ByteRev { op: ByteRevOp::Rev16, rd: Reg::R0, rm: Reg::R1 });

        // RBIT r0, r1
        let inst = ArmDecoder::decode(0xE6FF_0F31);
        assert_eq!(inst.op, Op::ByteRev { op: ByteRevOp::Rbit, rd: Reg::R0, rm: Reg::R1 });

        // REVSH r0, r1
        let inst = ArmDecoder::decode(0xE6FF_0FB1);
        assert_eq!(inst.op, Op::ByteRev { op: ByteRevOp::Revsh, rd: Reg::R0, rm: Reg::R1 });
    }

    #[test]
    fn test_decode_arm_simd_media_parallel() {
        // SADD8 r0, r1, r2 -> 0xE611_0F92
        let inst = ArmDecoder::decode(0xE611_0F92);
        assert_eq!(
            inst.op,
            Op::SimdParallel {
                op: SimdParallelOp::Sadd8,
                rd: Reg::R0,
                rn: Reg::R1,
                rm: Reg::R2,
            }
        );

        // SSUB8 r0, r1, r2 -> 0xE611_0FF2
        let inst = ArmDecoder::decode(0xE611_0FF2);
        assert_eq!(
            inst.op,
            Op::SimdParallel {
                op: SimdParallelOp::Ssub8,
                rd: Reg::R0,
                rn: Reg::R1,
                rm: Reg::R2,
            }
        );

        // UADD8 r0, r1, r2 -> 0xE651_0F92
        let inst = ArmDecoder::decode(0xE651_0F92);
        assert_eq!(
            inst.op,
            Op::SimdParallel {
                op: SimdParallelOp::Uadd8,
                rd: Reg::R0,
                rn: Reg::R1,
                rm: Reg::R2,
            }
        );

        // SEL r0, r1, r2 -> 0xE681_0FB2
        let inst = ArmDecoder::decode(0xE681_0FB2);
        assert_eq!(
            inst.op,
            Op::SimdSel {
                rd: Reg::R0,
                rn: Reg::R1,
                rm: Reg::R2,
            }
        );

        // PKHBT r0, r1, r2, LSL #2 -> 0xE681_0112
        let inst = ArmDecoder::decode(0xE681_0112);
        assert_eq!(
            inst.op,
            Op::SimdPkh {
                op: PkhOp::Pkhbt,
                rd: Reg::R0,
                rn: Reg::R1,
                rm: Reg::R2,
                shift: 2,
            }
        );

        // PKHTB r0, r1, r2, ASR #2 -> 0xE681_0152
        let inst = ArmDecoder::decode(0xE681_0152);
        assert_eq!(
            inst.op,
            Op::SimdPkh {
                op: PkhOp::Pkhtb,
                rd: Reg::R0,
                rn: Reg::R1,
                rm: Reg::R2,
                shift: 2,
            }
        );

        // SXTB r0, r2 -> 0xE6AF_0072 (Rn = 15)
        let inst = ArmDecoder::decode(0xE6AF_0072);
        assert_eq!(
            inst.op,
            Op::SimdExtend {
                op: ExtendOp::Sxtb,
                rd: Reg::R0,
                rn: None,
                rm: Reg::R2,
                rotation: 0,
            }
        );

        // SXTAB r0, r1, r2 -> 0xE6A1_0072
        let inst = ArmDecoder::decode(0xE6A1_0072);
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

        // UXTH r0, r2, ROR #8 -> 0xE6FF_0472 (rot: 1 -> 8)
        let inst = ArmDecoder::decode(0xE6FF_0472);
        assert_eq!(
            inst.op,
            Op::SimdExtend {
                op: ExtendOp::Uxth,
                rd: Reg::R0,
                rn: None,
                rm: Reg::R2,
                rotation: 8,
            }
        );
    }
}
