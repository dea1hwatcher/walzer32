use crate::reg::A64Reg;
use transd_core::Cond;

/// Low-level AArch64 Machine Code Assembler
#[derive(Debug, Default)]
pub struct A64Assembler {
    pub code: Vec<u32>,
}

impl A64Assembler {
    pub fn new() -> Self {
        Self { code: Vec::new() }
    }

    #[inline(always)]
    pub fn emit(&mut self, inst: u32) {
        self.code.push(inst);
    }

    #[inline(always)]
    pub fn cursor(&self) -> usize {
        self.code.len()
    }

    #[inline(always)]
    pub fn patch(&mut self, index: usize, inst: u32) {
        self.code[index] = inst;
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.code.len() * 4);
        for &inst in &self.code {
            bytes.extend_from_slice(&inst.to_le_bytes());
        }
        bytes
    }

    // --- Data Processing (Immediate) ---

    /// MOVZ Wd, #imm16, LSL #hw
    pub fn movz_w(&mut self, rd: A64Reg, imm16: u16, hw: u8) {
        assert!(hw == 0 || hw == 16);
        let hw_field = (hw / 16) as u32;
        let inst = 0x5280_0000 | (hw_field << 21) | ((imm16 as u32) << 5) | rd.index();
        self.emit(inst);
    }

    /// MOVK Wd, #imm16, LSL #hw
    pub fn movk_w(&mut self, rd: A64Reg, imm16: u16, hw: u8) {
        assert!(hw == 0 || hw == 16);
        let hw_field = (hw / 16) as u32;
        let inst = 0x7280_0000 | (hw_field << 21) | ((imm16 as u32) << 5) | rd.index();
        self.emit(inst);
    }

    /// Loads arbitrary 32-bit immediate into Wd using at most 2 instructions (MOVZ + optional MOVK)
    pub fn mov_imm32(&mut self, rd: A64Reg, val: u32) {
        let low = (val & 0xFFFF) as u16;
        let high = ((val >> 16) & 0xFFFF) as u16;

        self.movz_w(rd, low, 0);
        if high != 0 {
            self.movk_w(rd, high, 16);
        }
    }

    /// ADD Wd, Wn, #imm12
    pub fn add_w_imm(&mut self, rd: A64Reg, rn: A64Reg, imm12: u16) {
        assert!(imm12 <= 0xFFF);
        let inst = 0x1100_0000 | ((imm12 as u32) << 10) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// ADDS Wd, Wn, #imm12 (sets flags)
    pub fn adds_w_imm(&mut self, rd: A64Reg, rn: A64Reg, imm12: u16) {
        assert!(imm12 <= 0xFFF);
        let inst = 0x3100_0000 | ((imm12 as u32) << 10) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// SUB Wd, Wn, #imm12
    pub fn sub_w_imm(&mut self, rd: A64Reg, rn: A64Reg, imm12: u16) {
        assert!(imm12 <= 0xFFF);
        let inst = 0x5100_0000 | ((imm12 as u32) << 10) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// SUBS Wd, Wn, #imm12 (sets flags)
    pub fn subs_w_imm(&mut self, rd: A64Reg, rn: A64Reg, imm12: u16) {
        assert!(imm12 <= 0xFFF);
        let inst = 0x7100_0000 | ((imm12 as u32) << 10) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// CMP Wn, #imm12 -> SUBS WZR, Wn, #imm12
    pub fn cmp_w_imm(&mut self, rn: A64Reg, imm12: u16) {
        self.subs_w_imm(A64Reg::SP, rn, imm12);
    }

    // --- Data Processing (Shifted Register) ---

    /// ADD Wd, Wn, Wm
    pub fn add_w_reg(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x0B00_0000 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// ADDS Wd, Wn, Wm (sets flags)
    pub fn adds_w_reg(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x2B00_0000 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// SUB Wd, Wn, Wm
    pub fn sub_w_reg(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x4B00_0000 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// SUBS Wd, Wn, Wm (sets flags)
    pub fn subs_w_reg(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x6B00_0000 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// CMP Wn, Wm -> SUBS WZR, Wn, Wm
    pub fn cmp_w_reg(&mut self, rn: A64Reg, rm: A64Reg) {
        self.subs_w_reg(A64Reg::SP, rn, rm);
    }

    /// AND Wd, Wn, Wm
    pub fn and_w_reg(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x0A00_0000 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// ORR Wd, Wn, Wm
    pub fn orr_w_reg(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x2A00_0000 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// MOV Wd, Wm -> ORR Wd, WZR, Wm
    pub fn mov_w_reg(&mut self, rd: A64Reg, rm: A64Reg) {
        self.orr_w_reg(rd, A64Reg::SP, rm);
    }

    /// EOR Wd, Wn, Wm
    pub fn eor_w_reg(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x4A00_0000 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// BIC Wd, Wn, Wm
    pub fn bic_w_reg(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x0A20_0000 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// CSEL Wd, Wn, Wm, cond
    pub fn csel_w(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg, cond: Cond) {
        let cond_field = (cond as u32) & 0xF;
        let inst = 0x1A80_0000 | (rm.index() << 16) | (cond_field << 12) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    // --- Load / Store (Memory) ---

    /// LDR Wt, [Xn, #offset] (32-bit load, offset must be multiple of 4, up to 16380)
    pub fn ldr_w_imm(&mut self, rt: A64Reg, rn: A64Reg, offset: u32) {
        assert_eq!(offset % 4, 0);
        let imm12 = offset / 4;
        assert!(imm12 <= 0xFFF);
        let inst = 0xB940_0000 | (imm12 << 10) | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    /// STR Wt, [Xn, #offset] (32-bit store, offset must be multiple of 4)
    pub fn str_w_imm(&mut self, rt: A64Reg, rn: A64Reg, offset: u32) {
        assert_eq!(offset % 4, 0);
        let imm12 = offset / 4;
        assert!(imm12 <= 0xFFF);
        let inst = 0xB900_0000 | (imm12 << 10) | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    /// LDR Xt, [Xn, #offset] (64-bit load, offset must be multiple of 8, up to 32760)
    pub fn ldr_x_imm(&mut self, rt: A64Reg, rn: A64Reg, offset: u32) {
        assert_eq!(offset % 8, 0);
        let imm12 = offset / 8;
        assert!(imm12 <= 0xFFF);
        let inst = 0xF940_0000 | (imm12 << 10) | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    /// STR Xt, [Xn, #offset] (64-bit store, offset must be multiple of 8)
    pub fn str_x_imm(&mut self, rt: A64Reg, rn: A64Reg, offset: u32) {
        assert_eq!(offset % 8, 0);
        let imm12 = offset / 8;
        assert!(imm12 <= 0xFFF);
        let inst = 0xF900_0000 | (imm12 << 10) | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    // --- Control Flow ---

    /// B #offset_words (unconditional branch, offset in 32-bit words)
    pub fn b(&mut self, offset_words: i32) {
        let imm26 = (offset_words as u32) & 0x03FF_FFFF;
        let inst = 0x1400_0000 | imm26;
        self.emit(inst);
    }

    /// B.cond #offset_words (conditional branch)
    pub fn b_cond(&mut self, cond: Cond, offset_words: i32) {
        let imm19 = (offset_words as u32) & 0x7FFFF;
        let cond_field = (cond as u32) & 0xF;
        let inst = 0x5400_0000 | (imm19 << 5) | cond_field;
        self.emit(inst);
    }

    /// BR Xn (branch to register)
    pub fn br(&mut self, rn: A64Reg) {
        let inst = 0xD61F_0000 | (rn.index() << 5);
        self.emit(inst);
    }

    /// BLR Xn (branch with link to register)
    pub fn blr(&mut self, rn: A64Reg) {
        let inst = 0xD63F_0000 | (rn.index() << 5);
        self.emit(inst);
    }

    /// RET [Xn] (default to X30 / LR)
    pub fn ret(&mut self, rn: Option<A64Reg>) {
        let reg = rn.unwrap_or(A64Reg::X30);
        let inst = 0xD65F_0000 | (reg.index() << 5);
        self.emit(inst);
    }

    /// NOP
    pub fn nop(&mut self) {
        self.emit(0xD503_201F);
    }

    /// SVC #imm16
    pub fn svc(&mut self, imm16: u16) {
        let inst = 0xD400_0001 | ((imm16 as u32) << 5);
        self.emit(inst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asm_nop() {
        let mut asm = A64Assembler::new();
        asm.nop();
        assert_eq!(asm.code, vec![0xD503_201F]);
    }

    #[test]
    fn test_asm_ret() {
        let mut asm = A64Assembler::new();
        asm.ret(None);
        // RET (defaults to x30) -> 0xD65F03C0
        assert_eq!(asm.code, vec![0xD65F_03C0]);
    }

    #[test]
    fn test_asm_mov_imm32() {
        let mut asm = A64Assembler::new();
        // MOVZ w0, #42 -> 0x52800540
        asm.mov_imm32(A64Reg::X0, 42);
        assert_eq!(asm.code, vec![0x5280_0540]);

        // 0x12345678 -> MOVZ w1, #0x5678, LSL #0; MOVK w1, #0x1234, LSL #16
        let mut asm2 = A64Assembler::new();
        asm2.mov_imm32(A64Reg::X1, 0x1234_5678);
        assert_eq!(asm2.code.len(), 2);
    }

    #[test]
    fn test_asm_add_sub() {
        let mut asm = A64Assembler::new();
        // ADD w0, w1, #5
        asm.add_w_imm(A64Reg::X0, A64Reg::X1, 5);
        // SUB w2, w0, w1
        asm.sub_w_reg(A64Reg::X2, A64Reg::X0, A64Reg::X1);
        assert_eq!(asm.code.len(), 2);
    }
}
