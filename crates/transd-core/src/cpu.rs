use crate::addr::GuestAddr;
use crate::cpsr::{Cond, Cpsr};
use crate::reg::Reg;

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
