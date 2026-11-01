use crate::addr::GuestAddr;
use crate::cpsr::{Cond, Cpsr};
use crate::reg::Reg;

/// ARMv7 Floating-point Status and Control Register (FPSCR) bit definitions
pub mod fpscr {
    pub const N: u32 = 1 << 31; // Negative condition flag
    pub const Z: u32 = 1 << 30; // Zero condition flag
    pub const C: u32 = 1 << 29; // Carry condition flag
    pub const V: u32 = 1 << 28; // Overflow condition flag
    pub const QC: u32 = 1 << 27; // Cumulative saturation bit (NEON)
    pub const AHP: u32 = 1 << 26; // Alternative half-precision control
    pub const DN: u32 = 1 << 25; // Default NaN mode (1 = Default NaN, 0 = NaN propagation)
    pub const FZ: u32 = 1 << 24; // Flush-to-zero mode (FTZ) (1 = flush denormals, 0 = IEEE-754)
    pub const RMODE_MASK: u32 = 3 << 22; // Rounding Mode mask
    pub const RMODE_RN: u32 = 0 << 22; // Round to Nearest (RN)
    pub const RMODE_RP: u32 = 1 << 22; // Round towards Plus Infinity (RP)
    pub const RMODE_RM: u32 = 2 << 22; // Round towards Minus Infinity (RM)
    pub const RMODE_RZ: u32 = 3 << 22; // Round towards Zero (RZ)
    pub const STRIDE_MASK: u32 = 3 << 20;
    pub const LEN_MASK: u32 = 7 << 16;
    pub const IDC: u32 = 1 << 7; // Input Denormal cumulative exception
    pub const IXC: u32 = 1 << 4; // Inexact cumulative exception
    pub const UFC: u32 = 1 << 3; // Underflow cumulative exception
    pub const OFC: u32 = 1 << 2; // Overflow cumulative exception
    pub const DZC: u32 = 1 << 1; // Division by Zero cumulative exception
    pub const IOC: u32 = 1 << 0; // Invalid Operation cumulative exception

    /// RunFast mode enabled by default on Android NDK (FZ=1, DN=1)
    pub const RUNFAST_MODE: u32 = DN | FZ;
}

/// Fixed byte offsets for JIT assembly trampolines accessing CpuState
pub const OFFSET_R0: usize = 0;
pub const OFFSET_SP: usize = 13 * 4; // 52
pub const OFFSET_LR: usize = 14 * 4; // 56
pub const OFFSET_PC: usize = 15 * 4; // 60
pub const OFFSET_CPSR: usize = 64;   // 64
pub const OFFSET_FPSCR: usize = 68;  // 68
pub const OFFSET_VFP: usize = 72;    // 72 (8-byte aligned)
pub const OFFSET_TLS: usize = 72 + 32 * 8; // 328
pub const OFFSET_EXCLUSIVE: usize = 332;   // 332
pub const CPU_STATE_SIZE: usize = 336;     // 336 bytes

/// Complete state of the ARM32 Guest CPU
#[repr(C)]
#[derive(Debug, Clone, PartialEq)]
pub struct CpuState {
    /// General Purpose Registers r0 - r15
    pub regs: [u32; 16],
    /// Current Program Status Register (CPSR / APSR)
    pub cpsr: Cpsr,
    /// Floating-point Status and Control Register
    pub fpscr: u32,
    /// 32 VFP / NEON 64-bit registers (d0 - d31)
    pub vfp: [u64; 32],
    /// Thread-Local Storage pointer (CP15 c13, c0, 3)
    pub tls_ptr: u32,
    /// Exclusive monitor reservation address (for LDREX/STREX)
    /// 0xFFFF_FFFF if no reservation active
    pub exclusive_addr: u32,
}

impl Default for CpuState {
    fn default() -> Self {
        Self {
            regs: [0; 16],
            cpsr: Cpsr::empty(),
            fpscr: 0,
            vfp: [0; 32],
            tls_ptr: 0,
            exclusive_addr: 0xFFFF_FFFF,
        }
    }
}

impl CpuState {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline(always)]
    pub fn reg(&self, r: Reg) -> u32 {
        self.regs[r.index()]
    }

    #[inline(always)]
    pub fn set_reg(&mut self, r: Reg, val: u32) {
        self.regs[r.index()] = val;
    }

    #[inline(always)]
    pub fn sp(&self) -> u32 {
        self.regs[Reg::SP.index()]
    }

    #[inline(always)]
    pub fn set_sp(&mut self, val: u32) {
        self.regs[Reg::SP.index()] = val;
    }

    #[inline(always)]
    pub fn lr(&self) -> u32 {
        self.regs[Reg::LR.index()]
    }

    #[inline(always)]
    pub fn set_lr(&mut self, val: u32) {
        self.regs[Reg::LR.index()] = val;
    }

    #[inline(always)]
    pub fn pc(&self) -> GuestAddr {
        GuestAddr::new(self.regs[Reg::PC.index()])
    }

    #[inline(always)]
    pub fn set_pc(&mut self, addr: GuestAddr) {
        self.regs[Reg::PC.index()] = addr.as_u32();
    }

    #[inline(always)]
    pub fn is_thumb(&self) -> bool {
        self.cpsr.contains(Cpsr::T)
    }

    #[inline(always)]
    pub fn set_thumb(&mut self, thumb: bool) {
        self.cpsr.set(Cpsr::T, thumb);
    }

    #[inline(always)]
    pub fn check_cond(&self, cond: Cond) -> bool {
        cond.is_satisfied(self.cpsr)
    }

    // --- VFP / NEON Accessors ---

    /// Reads single-precision float register s0 - s31
    pub fn s_reg(&self, idx: u8) -> f32 {
        assert!(idx < 32);
        let d_idx = (idx / 2) as usize;
        let d_val = self.vfp[d_idx];
        let bits = if idx.is_multiple_of(2) {
            d_val as u32
        } else {
            (d_val >> 32) as u32
        };
        f32::from_bits(bits)
    }

    /// Writes single-precision float register s0 - s31
    pub fn set_s_reg(&mut self, idx: u8, val: f32) {
        assert!(idx < 32);
        let d_idx = (idx / 2) as usize;
        let bits = val.to_bits() as u64;
        if idx.is_multiple_of(2) {
            self.vfp[d_idx] = (self.vfp[d_idx] & 0xFFFF_FFFF_0000_0000) | bits;
        } else {
            self.vfp[d_idx] = (self.vfp[d_idx] & 0x0000_0000_FFFF_FFFF) | (bits << 32);
        }
    }

    /// Reads double-precision float register d0 - d31
    pub fn d_reg(&self, idx: u8) -> f64 {
        assert!(idx < 32);
        f64::from_bits(self.vfp[idx as usize])
    }

    /// Writes double-precision float register d0 - d31
    pub fn set_d_reg(&mut self, idx: u8, val: f64) {
        assert!(idx < 32);
        self.vfp[idx as usize] = val.to_bits();
    }

    /// Reads 128-bit quadword register Q0 - Q15 (composed of d[2*idx], d[2*idx+1])
    pub fn q_reg(&self, idx: u8) -> [u64; 2] {
        assert!(idx < 16);
        let base = (idx * 2) as usize;
        [self.vfp[base], self.vfp[base + 1]]
    }

    /// Writes 128-bit quadword register Q0 - Q15
    pub fn set_q_reg(&mut self, idx: u8, val: [u64; 2]) {
        assert!(idx < 16);
        let base = (idx * 2) as usize;
        self.vfp[base] = val[0];
        self.vfp[base + 1] = val[1];
    }

    /// Reads Q0 - Q15 as four 32-bit floats
    pub fn q_reg_f32x4(&self, idx: u8) -> [f32; 4] {
        assert!(idx < 16);
        let base = (idx * 2) as usize;
        let d0 = self.vfp[base];
        let d1 = self.vfp[base + 1];
        [
            f32::from_bits(d0 as u32),
            f32::from_bits((d0 >> 32) as u32),
            f32::from_bits(d1 as u32),
            f32::from_bits((d1 >> 32) as u32),
        ]
    }

    /// Writes Q0 - Q15 from four 32-bit floats
    pub fn set_q_reg_f32x4(&mut self, idx: u8, val: [f32; 4]) {
        assert!(idx < 16);
        let base = (idx * 2) as usize;
        let d0 = (val[0].to_bits() as u64) | ((val[1].to_bits() as u64) << 32);
        let d1 = (val[2].to_bits() as u64) | ((val[3].to_bits() as u64) << 32);
        self.vfp[base] = d0;
        self.vfp[base + 1] = d1;
    }

    /// Reads Q0 - Q15 as four 32-bit integers
    pub fn q_reg_u32x4(&self, idx: u8) -> [u32; 4] {
        assert!(idx < 16);
        let base = (idx * 2) as usize;
        let d0 = self.vfp[base];
        let d1 = self.vfp[base + 1];
        [
            d0 as u32,
            (d0 >> 32) as u32,
            d1 as u32,
            (d1 >> 32) as u32,
        ]
    }

    /// Writes Q0 - Q15 from four 32-bit integers
    pub fn set_q_reg_u32x4(&mut self, idx: u8, val: [u32; 4]) {
        assert!(idx < 16);
        let base = (idx * 2) as usize;
        let d0 = (val[0] as u64) | ((val[1] as u64) << 32);
        let d1 = (val[2] as u64) | ((val[3] as u64) << 32);
        self.vfp[base] = d0;
        self.vfp[base + 1] = d1;
    }

    /// Reads D0 - D31 as two 32-bit floats
    pub fn d_reg_f32x2(&self, idx: u8) -> [f32; 2] {
        assert!(idx < 32);
        let d = self.vfp[idx as usize];
        [
            f32::from_bits(d as u32),
            f32::from_bits((d >> 32) as u32),
        ]
    }

    /// Writes D0 - D31 from two 32-bit floats
    pub fn set_d_reg_f32x2(&mut self, idx: u8, val: [f32; 2]) {
        assert!(idx < 32);
        let d = (val[0].to_bits() as u64) | ((val[1].to_bits() as u64) << 32);
        self.vfp[idx as usize] = d;
    }

    // --- FPSCR Floating-Point Mode Helpers ---

    #[inline(always)]
    pub fn fpscr_ftz(&self) -> bool {
        (self.fpscr & fpscr::FZ) != 0
    }

    #[inline(always)]
    pub fn fpscr_default_nan(&self) -> bool {
        (self.fpscr & fpscr::DN) != 0
    }

    #[inline(always)]
    pub fn fpscr_rmode(&self) -> u32 {
        (self.fpscr & fpscr::RMODE_MASK) >> 22
    }

    /// Sanitizes an input operand or operation result according to FPSCR FZ (Flush-To-Zero)
    /// and DN (Default NaN) settings.
    pub fn sanitize_f32(&mut self, val: f32, is_input: bool) -> f32 {
        let mut res = val;
        if self.fpscr_ftz() && res.is_subnormal() {
            res = if res.is_sign_negative() { -0.0f32 } else { 0.0f32 };
            self.fpscr |= if is_input { fpscr::IDC } else { fpscr::UFC };
        }
        if self.fpscr_default_nan() && res.is_nan() {
            res = f32::from_bits(0x7FC0_0000);
            if !val.is_nan() {
                self.fpscr |= fpscr::IOC;
            }
        }
        res
    }

    /// Sanitizes an f64 input operand or result according to FPSCR FZ and DN.
    pub fn sanitize_f64(&mut self, val: f64, is_input: bool) -> f64 {
        let mut res = val;
        if self.fpscr_ftz() && res.is_subnormal() {
            res = if res.is_sign_negative() { -0.0f64 } else { 0.0f64 };
            self.fpscr |= if is_input { fpscr::IDC } else { fpscr::UFC };
        }
        if self.fpscr_default_nan() && res.is_nan() {
            res = f64::from_bits(0x7FF8_0000_0000_0000);
            if !val.is_nan() {
                self.fpscr |= fpscr::IOC;
            }
        }
        res
    }

    // --- Flag helpers ---

    /// Sets N and Z flags based on 32-bit result
    #[inline(always)]
    pub fn update_nz(&mut self, val: u32) {
        self.cpsr.set(Cpsr::N, (val as i32) < 0);
        self.cpsr.set(Cpsr::Z, val == 0);
    }

    /// Sets N, Z, C, V flags for Addition: a + b (+ carry_in)
    #[inline(always)]
    pub fn update_add_flags(&mut self, a: u32, b: u32, carry_in: bool) -> u32 {
        let carry_val = if carry_in { 1u64 } else { 0u64 };
        let sum64 = (a as u64) + (b as u64) + carry_val;
        let res = sum64 as u32;

        self.update_nz(res);
        self.cpsr.set(Cpsr::C, sum64 > 0xFFFF_FFFF);

        // Signed overflow occurs if signs of a and b are identical, but sign of result is different
        let signed_v = (!(a ^ b) & (a ^ res) & 0x8000_0000) != 0;
        self.cpsr.set(Cpsr::V, signed_v);

        res
    }

    /// Sets N, Z, C, V flags for Subtraction: a - b (- borrow_in)
    /// Note: In ARM, Carry is inverted borrow (C=1 means NO borrow!)
    #[inline(always)]
    pub fn update_sub_flags(&mut self, a: u32, b: u32, borrow_in: bool) -> u32 {
        let not_b = !b;
        let carry_in = !borrow_in;
        self.update_add_flags(a, not_b, carry_in)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_state_layout() {
        assert_eq!(std::mem::size_of::<CpuState>(), CPU_STATE_SIZE);
        assert_eq!(std::mem::offset_of!(CpuState, regs), OFFSET_R0);
        assert_eq!(std::mem::offset_of!(CpuState, cpsr), OFFSET_CPSR);
        assert_eq!(std::mem::offset_of!(CpuState, fpscr), OFFSET_FPSCR);
        assert_eq!(std::mem::offset_of!(CpuState, vfp), OFFSET_VFP);
        assert_eq!(std::mem::offset_of!(CpuState, tls_ptr), OFFSET_TLS);
        assert_eq!(std::mem::offset_of!(CpuState, exclusive_addr), OFFSET_EXCLUSIVE);
    }

    #[test]
    fn test_add_sub_flags() {
        let mut cpu = CpuState::new();

        // 5 + 3 = 8
        let res = cpu.update_add_flags(5, 3, false);
        assert_eq!(res, 8);
        assert!(!cpu.cpsr.contains(Cpsr::N));
        assert!(!cpu.cpsr.contains(Cpsr::Z));
        assert!(!cpu.cpsr.contains(Cpsr::C));
        assert!(!cpu.cpsr.contains(Cpsr::V));

        // 5 - 5 = 0
        let res = cpu.update_sub_flags(5, 5, false);
        assert_eq!(res, 0);
        assert!(cpu.cpsr.contains(Cpsr::Z));
        assert!(cpu.cpsr.contains(Cpsr::C)); // ARM: No borrow -> Carry is 1
        assert!(!cpu.cpsr.contains(Cpsr::V));

        // 0 - 1 = -1 (underflow)
        let res = cpu.update_sub_flags(0, 1, false);
        assert_eq!(res, 0xFFFF_FFFF);
        assert!(cpu.cpsr.contains(Cpsr::N));
        assert!(!cpu.cpsr.contains(Cpsr::Z));
        assert!(!cpu.cpsr.contains(Cpsr::C)); // Borrow occurred -> Carry is 0
    }
}
