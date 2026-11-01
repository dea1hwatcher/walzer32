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

    /// MOVZ Xd, #imm16, LSL #hw (hw in 0, 16, 32, 48)
    pub fn movz_x(&mut self, rd: A64Reg, imm16: u16, hw: u8) {
        assert!(hw == 0 || hw == 16 || hw == 32 || hw == 48);
        let hw_field = (hw / 16) as u32;
        let inst = 0xD280_0000 | (hw_field << 21) | ((imm16 as u32) << 5) | rd.index();
        self.emit(inst);
    }

    /// MOVK Xd, #imm16, LSL #hw (hw in 0, 16, 32, 48)
    pub fn movk_x(&mut self, rd: A64Reg, imm16: u16, hw: u8) {
        assert!(hw == 0 || hw == 16 || hw == 32 || hw == 48);
        let hw_field = (hw / 16) as u32;
        let inst = 0xF280_0000 | (hw_field << 21) | ((imm16 as u32) << 5) | rd.index();
        self.emit(inst);
    }

    /// Loads arbitrary 64-bit immediate into Xd using MOVZ + up to 3 MOVK instructions
    pub fn mov_imm64(&mut self, rd: A64Reg, val: u64) {
        let c0 = (val & 0xFFFF) as u16;
        let c1 = ((val >> 16) & 0xFFFF) as u16;
        let c2 = ((val >> 32) & 0xFFFF) as u16;
        let c3 = ((val >> 48) & 0xFFFF) as u16;

        self.movz_x(rd, c0, 0);
        if c1 != 0 {
            self.movk_x(rd, c1, 16);
        }
        if c2 != 0 {
            self.movk_x(rd, c2, 32);
        }
        if c3 != 0 {
            self.movk_x(rd, c3, 48);
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

    /// MOV Xd, Xm -> ORR Xd, XZR, Xm
    pub fn mov_x_reg(&mut self, rd: A64Reg, rm: A64Reg) {
        let inst = 0xAA00_03E0 | (rm.index() << 16) | rd.index();
        self.emit(inst);
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

    // --- Load / Store Pair (Stack & Context Spill / Fill) ---

    /// STP Xt1, Xt2, [Xn, #imm]! (Pre-index 64-bit pair store with writeback)
    pub fn stp_x_pre(&mut self, rt1: A64Reg, rt2: A64Reg, rn: A64Reg, imm_bytes: i32) {
        assert_eq!(imm_bytes % 8, 0);
        let imm7 = (imm_bytes / 8) as u32 & 0x7F;
        let inst = 0xA980_0000 | (imm7 << 15) | (rt2.index() << 10) | (rn.index() << 5) | rt1.index();
        self.emit(inst);
    }

    /// LDP Xt1, Xt2, [Xn], #imm (Post-index 64-bit pair load with writeback)
    pub fn ldp_x_post(&mut self, rt1: A64Reg, rt2: A64Reg, rn: A64Reg, imm_bytes: i32) {
        assert_eq!(imm_bytes % 8, 0);
        let imm7 = (imm_bytes / 8) as u32 & 0x7F;
        let inst = 0xA8C0_0000 | (imm7 << 15) | (rt2.index() << 10) | (rn.index() << 5) | rt1.index();
        self.emit(inst);
    }

    /// STP Xt1, Xt2, [Xn, #imm] (Signed offset 64-bit pair store)
    pub fn stp_x_offset(&mut self, rt1: A64Reg, rt2: A64Reg, rn: A64Reg, imm_bytes: i32) {
        assert_eq!(imm_bytes % 8, 0);
        let imm7 = (imm_bytes / 8) as u32 & 0x7F;
        let inst = 0xA900_0000 | (imm7 << 15) | (rt2.index() << 10) | (rn.index() << 5) | rt1.index();
        self.emit(inst);
    }

    /// LDP Xt1, Xt2, [Xn, #imm] (Signed offset 64-bit pair load)
    pub fn ldp_x_offset(&mut self, rt1: A64Reg, rt2: A64Reg, rn: A64Reg, imm_bytes: i32) {
        assert_eq!(imm_bytes % 8, 0);
        let imm7 = (imm_bytes / 8) as u32 & 0x7F;
        let inst = 0xA940_0000 | (imm7 << 15) | (rt2.index() << 10) | (rn.index() << 5) | rt1.index();
        self.emit(inst);
    }

    /// STP Wt1, Wt2, [Xn, #imm] (Signed offset 32-bit pair store)
    pub fn stp_w_offset(&mut self, rt1: A64Reg, rt2: A64Reg, rn: A64Reg, imm_bytes: i32) {
        assert_eq!(imm_bytes % 4, 0);
        let imm7 = (imm_bytes / 4) as u32 & 0x7F;
        let inst = 0x2900_0000 | (imm7 << 15) | (rt2.index() << 10) | (rn.index() << 5) | rt1.index();
        self.emit(inst);
    }

    /// LDP Wt1, Wt2, [Xn, #imm] (Signed offset 32-bit pair load)
    pub fn ldp_w_offset(&mut self, rt1: A64Reg, rt2: A64Reg, rn: A64Reg, imm_bytes: i32) {
        assert_eq!(imm_bytes % 4, 0);
        let imm7 = (imm_bytes / 4) as u32 & 0x7F;
        let inst = 0x2940_0000 | (imm7 << 15) | (rt2.index() << 10) | (rn.index() << 5) | rt1.index();
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

    // --- 64-bit Extended & Pointer Arithmetic ---

    /// ADD Xd, Xn, Wm, UXTW (Unsigned extend 32-bit Wm to 64-bit and add to Xn)
    pub fn add_x_uxtw(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x8B20_4000 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// ADD Xd, Xn, Xm (64-bit register addition)
    pub fn add_x_reg(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x8B00_0000 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// SUB Xd, Xn, Xm (64-bit register subtraction)
    pub fn sub_x_reg(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0xCB00_0000 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// ADD Xd, Xn, #imm12 (64-bit immediate addition)
    pub fn add_x_imm(&mut self, rd: A64Reg, rn: A64Reg, imm12: u16) {
        assert!(imm12 <= 0xFFF);
        let inst = 0x9100_0000 | ((imm12 as u32) << 10) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// SUB Xd, Xn, #imm12 (64-bit immediate subtraction)
    pub fn sub_x_imm(&mut self, rd: A64Reg, rn: A64Reg, imm12: u16) {
        assert!(imm12 <= 0xFFF);
        let inst = 0xD100_0000 | ((imm12 as u32) << 10) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    // --- Byte & Halfword Load / Store (Memory) ---

    /// LDRB Wt, [Xn, #offset] (Unsigned byte load, offset 0..4095)
    pub fn ldrb_w_imm(&mut self, rt: A64Reg, rn: A64Reg, offset: u32) {
        assert!(offset <= 0xFFF);
        let inst = 0x3940_0000 | (offset << 10) | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    /// LDRSB Wt, [Xn, #offset] (Signed byte load into 32-bit register, offset 0..4095)
    pub fn ldrsb_w_imm(&mut self, rt: A64Reg, rn: A64Reg, offset: u32) {
        assert!(offset <= 0xFFF);
        let inst = 0x39C0_0000 | (offset << 10) | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    /// STRB Wt, [Xn, #offset] (Byte store, offset 0..4095)
    pub fn strb_w_imm(&mut self, rt: A64Reg, rn: A64Reg, offset: u32) {
        assert!(offset <= 0xFFF);
        let inst = 0x3900_0000 | (offset << 10) | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    /// LDRH Wt, [Xn, #offset] (Unsigned halfword load, offset multiple of 2, up to 8190)
    pub fn ldrh_w_imm(&mut self, rt: A64Reg, rn: A64Reg, offset: u32) {
        assert_eq!(offset % 2, 0);
        let imm12 = offset / 2;
        assert!(imm12 <= 0xFFF);
        let inst = 0x7940_0000 | (imm12 << 10) | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    /// LDRSH Wt, [Xn, #offset] (Signed halfword load into 32-bit register, offset multiple of 2)
    pub fn ldrsh_w_imm(&mut self, rt: A64Reg, rn: A64Reg, offset: u32) {
        assert_eq!(offset % 2, 0);
        let imm12 = offset / 2;
        assert!(imm12 <= 0xFFF);
        let inst = 0x79C0_0000 | (imm12 << 10) | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    /// STRH Wt, [Xn, #offset] (Halfword store, offset multiple of 2, up to 8190)
    pub fn strh_w_imm(&mut self, rt: A64Reg, rn: A64Reg, offset: u32) {
        assert_eq!(offset % 2, 0);
        let imm12 = offset / 2;
        assert!(imm12 <= 0xFFF);
        let inst = 0x7900_0000 | (imm12 << 10) | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    // --- Register Offset Load / Store (Zero-Overhead 4GB Guest Arena Addressing) ---

    /// LDR Wt, [Xn, Wm, UXTW] (32-bit load indexed by zero-extended 32-bit guest address)
    pub fn ldr_w_uxtw(&mut self, rt: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0xB860_4800 | (rm.index() << 16) | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    /// STR Wt, [Xn, Wm, UXTW] (32-bit store indexed by zero-extended 32-bit guest address)
    pub fn str_w_uxtw(&mut self, rt: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0xB820_4800 | (rm.index() << 16) | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    /// LDRB Wt, [Xn, Wm, UXTW] (Byte load indexed by zero-extended 32-bit guest address)
    pub fn ldrb_w_uxtw(&mut self, rt: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x3860_4800 | (rm.index() << 16) | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    /// STRB Wt, [Xn, Wm, UXTW] (Byte store indexed by zero-extended 32-bit guest address)
    pub fn strb_w_uxtw(&mut self, rt: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x3820_4800 | (rm.index() << 16) | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    /// LDRH Wt, [Xn, Wm, UXTW] (Halfword load indexed by zero-extended 32-bit guest address)
    pub fn ldrh_w_uxtw(&mut self, rt: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x7860_4800 | (rm.index() << 16) | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    /// STRH Wt, [Xn, Wm, UXTW] (Halfword store indexed by zero-extended 32-bit guest address)
    pub fn strh_w_uxtw(&mut self, rt: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x7820_4800 | (rm.index() << 16) | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    /// LDRSB Wt, [Xn, Wm, UXTW] (Signed byte load indexed by zero-extended 32-bit guest address)
    pub fn ldrsb_w_uxtw(&mut self, rt: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x38E0_4800 | (rm.index() << 16) | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    /// LDRSH Wt, [Xn, Wm, UXTW] (Signed halfword load indexed by zero-extended 32-bit guest address)
    pub fn ldrsh_w_uxtw(&mut self, rt: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x78E0_4800 | (rm.index() << 16) | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    // --- Multiply, Divide & Bit Manipulation ---

    /// MUL Wd, Wn, Wm (Rd = Rn * Rm)
    pub fn mul_w_reg(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x1B00_7C00 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// MADD Wd, Wn, Wm, Wa (Rd = Wa + Rn * Rm)
    pub fn madd_w_reg(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg, ra: A64Reg) {
        let inst = 0x1B00_0000 | (rm.index() << 16) | (ra.index() << 10) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// MSUB Wd, Wn, Wm, Wa (Rd = Wa - Rn * Rm)
    pub fn msub_w_reg(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg, ra: A64Reg) {
        let inst = 0x1B00_8000 | (rm.index() << 16) | (ra.index() << 10) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// SMULL Xd, Wn, Wm (Signed 32x32 -> 64-bit multiply: SMADDL Xd, Wn, Wm, XZR)
    pub fn smull_x(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x9B20_7C00 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// UMULL Xd, Wn, Wm (Unsigned 32x32 -> 64-bit multiply: UMADDL Xd, Wn, Wm, XZR)
    pub fn umull_x(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x9BA0_7C00 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// SMADDL Xd, Wn, Wm, Xa (Signed 32x32 -> 64-bit multiply-accumulate: Xd = Xa + Wn * Wm)
    pub fn smaddl_x(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg, ra: A64Reg) {
        let inst = 0x9B20_0000 | (rm.index() << 16) | (ra.index() << 10) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// UMADDL Xd, Wn, Wm, Xa (Unsigned 32x32 -> 64-bit multiply-accumulate: Xd = Xa + Wn * Wm)
    pub fn umaddl_x(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg, ra: A64Reg) {
        let inst = 0x9BA0_0000 | (rm.index() << 16) | (ra.index() << 10) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// SDIV Wd, Wn, Wm (Signed 32-bit division)
    pub fn sdiv_w_reg(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x1AC0_0C00 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// UDIV Wd, Wn, Wm (Unsigned 32-bit division)
    pub fn udiv_w_reg(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x1AC0_0800 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// CLZ Wd, Wn (Count leading zeros)
    pub fn clz_w_reg(&mut self, rd: A64Reg, rn: A64Reg) {
        let inst = 0x5AC0_1000 | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// RBIT Wd, Wn (Reverse bit order)
    pub fn rbit_w_reg(&mut self, rd: A64Reg, rn: A64Reg) {
        let inst = 0x5AC0_0000 | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// REV Wd, Wn (Reverse byte order in 32-bit word)
    pub fn rev_w_reg(&mut self, rd: A64Reg, rn: A64Reg) {
        let inst = 0x5AC0_0800 | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    // --- Shifts & Auxiliary Operations ---

    /// LSL Wd, Wn, #shift (0..31)
    pub fn lsl_w_imm(&mut self, rd: A64Reg, rn: A64Reg, shift: u8) {
        let shift = shift & 31;
        let immr = (32 - shift) & 31;
        let imms = 31 - shift;
        let inst = 0x5300_0000 | ((immr as u32) << 16) | ((imms as u32) << 10) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// LSR Wd, Wn, #shift (0..31)
    pub fn lsr_w_imm(&mut self, rd: A64Reg, rn: A64Reg, shift: u8) {
        let shift = (shift & 31) as u32;
        let inst = 0x5300_7C00 | (shift << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// ASR Wd, Wn, #shift (0..31)
    pub fn asr_w_imm(&mut self, rd: A64Reg, rn: A64Reg, shift: u8) {
        let shift = (shift & 31) as u32;
        let inst = 0x1300_7C00 | (shift << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// LSLV Wd, Wn, Wm (Logical shift left variable)
    pub fn lsl_w_reg(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x1AC0_2000 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// LSRV Wd, Wn, Wm (Logical shift right variable)
    pub fn lsr_w_reg(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x1AC0_2400 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// ASRV Wd, Wn, Wm (Arithmetic shift right variable)
    pub fn asr_w_reg(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x1AC0_2800 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// RORV Wd, Wn, Wm (Rotate right variable)
    pub fn ror_w_reg(&mut self, rd: A64Reg, rn: A64Reg, rm: A64Reg) {
        let inst = 0x1AC0_2C00 | (rm.index() << 16) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// MVN Wd, Wm (Rd = ~Rm -> ORN Wd, WZR, Wm)
    pub fn mvn_w_reg(&mut self, rd: A64Reg, rm: A64Reg) {
        let inst = 0x2A20_03E0 | (rm.index() << 16) | rd.index();
        self.emit(inst);
    }

    /// TST Wn, Wm (Wn & Wm, sets flags -> ANDS WZR, Wn, Wm)
    pub fn tst_w_reg(&mut self, rn: A64Reg, rm: A64Reg) {
        let inst = 0x6A00_001F | (rm.index() << 16) | (rn.index() << 5);
        self.emit(inst);
    }

    /// UBFX Wd, Wn, #lsb, #width (Unsigned bitfield extract: UBFM Wd, Wn, #lsb, #(lsb+width-1))
    pub fn ubfx_w(&mut self, rd: A64Reg, rn: A64Reg, lsb: u8, width: u8) {
        assert!(width >= 1 && width <= 32);
        let lsb = (lsb & 31) as u32;
        let imms = ((lsb + (width as u32) - 1) & 31) as u32;
        let inst = 0x5300_0000 | (lsb << 16) | (imms << 10) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// SBFX Wd, Wn, #lsb, #width (Signed bitfield extract: SBFM Wd, Wn, #lsb, #(lsb+width-1))
    pub fn sbfx_w(&mut self, rd: A64Reg, rn: A64Reg, lsb: u8, width: u8) {
        assert!(width >= 1 && width <= 32);
        let lsb = (lsb & 31) as u32;
        let imms = ((lsb + (width as u32) - 1) & 31) as u32;
        let inst = 0x1300_0000 | (lsb << 16) | (imms << 10) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// BFI Wd, Wn, #lsb, #width (Bitfield insert: BFM Wd, Wn, #((-lsb) & 31), #(width-1))
    pub fn bfi_w(&mut self, rd: A64Reg, rn: A64Reg, lsb: u8, width: u8) {
        assert!(width >= 1 && width <= 32);
        let immr = ((-(lsb as i32)) & 31) as u32;
        let imms = ((width as u32) - 1) & 31;
        let inst = 0x3300_0000 | (immr << 16) | (imms << 10) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// BFI Xd, Xn, #lsb, #width (64-bit Bitfield insert)
    pub fn bfi_x(&mut self, rd: A64Reg, rn: A64Reg, lsb: u8, width: u8) {
        assert!(width >= 1 && width <= 64 && lsb < 64 && (lsb + width) <= 64);
        let immr = ((-(lsb as i32)) & 63) as u32;
        let imms = ((width as u32) - 1) & 63;
        let inst = 0xB340_0000 | (immr << 16) | (imms << 10) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// LSR Xd, Xn, #shift (0..63)
    pub fn lsr_x_imm(&mut self, rd: A64Reg, rn: A64Reg, shift: u8) {
        assert!(shift < 64);
        let inst = 0xD340_0000 | ((shift as u32) << 16) | (0x3F << 10) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// LSL Xd, Xn, #shift (0..63)
    pub fn lsl_x_imm(&mut self, rd: A64Reg, rn: A64Reg, shift: u8) {
        assert!(shift < 64);
        let immr = (64 - (shift as u32)) & 63;
        let imms = 63 - (shift as u32);
        let inst = 0xD340_0000 | (immr << 16) | (imms << 10) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// ASR Xd, Xn, #shift (0..63)
    pub fn asr_x_imm(&mut self, rd: A64Reg, rn: A64Reg, shift: u8) {
        assert!(shift < 64);
        let inst = 0x9340_0000 | ((shift as u32) << 16) | (0x3F << 10) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// RBIT Wd, Wn (Reverse bits in 32-bit register)
    pub fn rbit_w(&mut self, rd: A64Reg, rn: A64Reg) {
        let inst = 0x5AC0_0000 | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// REV Wd, Wn (Reverse bytes in 32-bit register)
    pub fn rev_w(&mut self, rd: A64Reg, rn: A64Reg) {
        let inst = 0x5AC0_0800 | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// REV16 Wd, Wn (Reverse bytes in each 16-bit halfword)
    pub fn rev16_w(&mut self, rd: A64Reg, rn: A64Reg) {
        let inst = 0x5AC0_0400 | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// SXTB Wd, Wn (Signed extend byte: SBFM Wd, Wn, #0, #7)
    pub fn sxtb_w(&mut self, rd: A64Reg, rn: A64Reg) {
        let inst = 0x1300_1C00 | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// SXTH Wd, Wn (Signed extend halfword: SBFM Wd, Wn, #0, #15)
    pub fn sxth_w(&mut self, rd: A64Reg, rn: A64Reg) {
        let inst = 0x1300_3C00 | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// UXTB Wd, Wn (Unsigned extend byte: UBFM Wd, Wn, #0, #7)
    pub fn uxtb_w(&mut self, rd: A64Reg, rn: A64Reg) {
        let inst = 0x5300_1C00 | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// UXTH Wd, Wn (Unsigned extend halfword: UBFM Wd, Wn, #0, #15)
    pub fn uxth_w(&mut self, rd: A64Reg, rn: A64Reg) {
        let inst = 0x5300_3C00 | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// SXTW Xd, Wn (Signed extend 32-bit register to 64-bit: SBFM Xd, Xn, #0, #31)
    pub fn sxtw_x(&mut self, rd: A64Reg, rn: A64Reg) {
        let inst = 0x9340_7C00 | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    /// ROR Wd, Wn, #shift (Rotate right 32-bit register: EXTR Wd, Wn, Wn, #shift)
    pub fn ror_w(&mut self, rd: A64Reg, rn: A64Reg, shift: u8) {
        let imm = (shift & 31) as u32;
        let inst = 0x1380_0000 | (rn.index() << 16) | (imm << 10) | (rn.index() << 5) | rd.index();
        self.emit(inst);
    }

    // --- VFPv3 Floating Point Operations ---

    /// FADD Sd, Sn, Sm (Single-precision FP addition)
    pub fn fadd_s(&mut self, rd: u8, rn: u8, rm: u8) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let inst = 0x1E20_2800 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FADD Dd, Dn, Dm (Double-precision FP addition)
    pub fn fadd_d(&mut self, rd: u8, rn: u8, rm: u8) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let inst = 0x1E60_2800 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FSUB Sd, Sn, Sm (Single-precision FP subtraction)
    pub fn fsub_s(&mut self, rd: u8, rn: u8, rm: u8) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let inst = 0x1E20_3800 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FSUB Dd, Dn, Dm (Double-precision FP subtraction)
    pub fn fsub_d(&mut self, rd: u8, rn: u8, rm: u8) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let inst = 0x1E60_3800 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FMUL Sd, Sn, Sm (Single-precision FP multiplication)
    pub fn fmul_s(&mut self, rd: u8, rn: u8, rm: u8) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let inst = 0x1E20_0800 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FMUL Dd, Dn, Dm (Double-precision FP multiplication)
    pub fn fmul_d(&mut self, rd: u8, rn: u8, rm: u8) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let inst = 0x1E60_0800 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FDIV Sd, Sn, Sm (Single-precision FP division)
    pub fn fdiv_s(&mut self, rd: u8, rn: u8, rm: u8) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let inst = 0x1E20_1800 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FDIV Dd, Dn, Dm (Double-precision FP division)
    pub fn fdiv_d(&mut self, rd: u8, rn: u8, rm: u8) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let inst = 0x1E60_1800 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FCMP Sn, Sm (Single-precision FP comparison)
    pub fn fcmp_s(&mut self, rn: u8, rm: u8) {
        assert!(rn < 32 && rm < 32);
        let inst = 0x1E20_2000 | ((rm as u32) << 16) | ((rn as u32) << 5);
        self.emit(inst);
    }

    /// FCMP Dn, Dm (Double-precision FP comparison)
    pub fn fcmp_d(&mut self, rn: u8, rm: u8) {
        assert!(rn < 32 && rm < 32);
        let inst = 0x1E60_2000 | ((rm as u32) << 16) | ((rn as u32) << 5);
        self.emit(inst);
    }

    /// FCMP Sn, #0.0 (Single-precision FP compare with zero)
    pub fn fcmp_zero_s(&mut self, rn: u8) {
        assert!(rn < 32);
        let inst = 0x1E20_2008 | ((rn as u32) << 5);
        self.emit(inst);
    }

    /// FCMP Dn, #0.0 (Double-precision FP compare with zero)
    pub fn fcmp_zero_d(&mut self, rn: u8) {
        assert!(rn < 32);
        let inst = 0x1E60_2008 | ((rn as u32) << 5);
        self.emit(inst);
    }

    /// FABS Sd, Sn
    pub fn fabs_s(&mut self, rd: u8, rn: u8) {
        assert!(rd < 32 && rn < 32);
        let inst = 0x1E20_C000 | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FABS Dd, Dn
    pub fn fabs_d(&mut self, rd: u8, rn: u8) {
        assert!(rd < 32 && rn < 32);
        let inst = 0x1E60_C000 | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FNEG Sd, Sn
    pub fn fneg_s(&mut self, rd: u8, rn: u8) {
        assert!(rd < 32 && rn < 32);
        let inst = 0x1E21_4000 | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FNEG Dd, Dn
    pub fn fneg_d(&mut self, rd: u8, rn: u8) {
        assert!(rd < 32 && rn < 32);
        let inst = 0x1E61_4000 | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FSQRT Sd, Sn
    pub fn fsqrt_s(&mut self, rd: u8, rn: u8) {
        assert!(rd < 32 && rn < 32);
        let inst = 0x1E21_C000 | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FSQRT Dd, Dn
    pub fn fsqrt_d(&mut self, rd: u8, rn: u8) {
        assert!(rd < 32 && rn < 32);
        let inst = 0x1E61_C000 | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FMADD Sd, Sn, Sm, Sa (Fused Multiply-Add: Sd = Sa + Sn * Sm)
    pub fn fmadd_s(&mut self, rd: u8, rn: u8, rm: u8, ra: u8) {
        assert!(rd < 32 && rn < 32 && rm < 32 && ra < 32);
        let inst = 0x1F00_0000 | ((rm as u32) << 16) | ((ra as u32) << 10) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FMSUB Sd, Sn, Sm, Sa (Fused Multiply-Subtract: Sd = Sa - Sn * Sm)
    pub fn fmsub_s(&mut self, rd: u8, rn: u8, rm: u8, ra: u8) {
        assert!(rd < 32 && rn < 32 && rm < 32 && ra < 32);
        let inst = 0x1F00_8000 | ((rm as u32) << 16) | ((ra as u32) << 10) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FMADD Dd, Dn, Dm, Da (Fused Multiply-Add: Dd = Da + Dn * Dm)
    pub fn fmadd_d(&mut self, rd: u8, rn: u8, rm: u8, ra: u8) {
        assert!(rd < 32 && rn < 32 && rm < 32 && ra < 32);
        let inst = 0x1F40_0000 | ((rm as u32) << 16) | ((ra as u32) << 10) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FMSUB Dd, Dn, Dm, Da (Fused Multiply-Subtract: Dd = Da - Dn * Dm)
    pub fn fmsub_d(&mut self, rd: u8, rn: u8, rm: u8, ra: u8) {
        assert!(rd < 32 && rn < 32 && rm < 32 && ra < 32);
        let inst = 0x1F40_8000 | ((rm as u32) << 16) | ((ra as u32) << 10) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// MRS Xt, FPCR (Read Floating-Point Control Register)
    pub fn mrs_fpcr(&mut self, rt: A64Reg) {
        let inst = 0xD53B_4400 | (rt.index() as u32);
        self.emit(inst);
    }

    /// MSR FPCR, Xt (Write Floating-Point Control Register)
    pub fn msr_fpcr(&mut self, rt: A64Reg) {
        let inst = 0xD51B_4400 | (rt.index() as u32);
        self.emit(inst);
    }

    /// FMOV Sd, Sn (Move single-precision register)
    pub fn fmov_s(&mut self, rd: u8, rn: u8) {
        assert!(rd < 32 && rn < 32);
        let inst = 0x1E20_4000 | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FMOV Dd, Dn (Move double-precision register)
    pub fn fmov_d(&mut self, rd: u8, rn: u8) {
        assert!(rd < 32 && rn < 32);
        let inst = 0x1E60_4000 | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FMOV Wd, Sn (Move float register to 32-bit core register)
    pub fn fmov_w_from_s(&mut self, rd: A64Reg, rn_s: u8) {
        assert!(rn_s < 32);
        let inst = 0x1E26_0000 | ((rn_s as u32) << 5) | rd.index();
        self.emit(inst);
    }

    /// FMOV Sd, Wn (Move 32-bit core register to float register)
    pub fn fmov_s_from_w(&mut self, rd_s: u8, rn: A64Reg) {
        assert!(rd_s < 32);
        let inst = 0x1E27_0000 | (rn.index() << 5) | (rd_s as u32);
        self.emit(inst);
    }

    /// FMOV Xd, Dn (Move double-precision float register to 64-bit core register)
    pub fn fmov_x_from_d(&mut self, rd: A64Reg, rn_d: u8) {
        assert!(rn_d < 32);
        let inst = 0x9E66_0000 | ((rn_d as u32) << 5) | rd.index();
        self.emit(inst);
    }

    /// FMOV Dd, Xn (Move 64-bit core register to double-precision float register)
    pub fn fmov_d_from_x(&mut self, rd_d: u8, rn: A64Reg) {
        assert!(rd_d < 32);
        let inst = 0x9E67_0000 | (rn.index() << 5) | (rd_d as u32);
        self.emit(inst);
    }

    /// FCVT Dd, Sn (Convert single-precision to double-precision)
    pub fn fcvt_d_s(&mut self, rd: u8, rn: u8) {
        assert!(rd < 32 && rn < 32);
        let inst = 0x1E22_C000 | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FCVT Sd, Dn (Convert double-precision to single-precision)
    pub fn fcvt_s_d(&mut self, rd: u8, rn: u8) {
        assert!(rd < 32 && rn < 32);
        let inst = 0x1E62_4000 | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// SCVTF Sd, Sn (Scalar signed 32-bit int to single float)
    pub fn scvtf_s_s(&mut self, rd: u8, rn: u8) {
        assert!(rd < 32 && rn < 32);
        let inst = 0x5E21_D800 | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// UCVTF Sd, Sn (Scalar unsigned 32-bit int to single float)
    pub fn ucvtf_s_s(&mut self, rd: u8, rn: u8) {
        assert!(rd < 32 && rn < 32);
        let inst = 0x7E21_D800 | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FCVTZS Sd, Sn (Scalar single float to signed 32-bit int)
    pub fn fcvtzs_s_s(&mut self, rd: u8, rn: u8) {
        assert!(rd < 32 && rn < 32);
        let inst = 0x5EA1_B800 | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FCVTZU Sd, Sn (Scalar single float to unsigned 32-bit int)
    pub fn fcvtzu_s_s(&mut self, rd: u8, rn: u8) {
        assert!(rd < 32 && rn < 32);
        let inst = 0x7EA1_B800 | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// SCVTF Dd, Wn (Convert signed 32-bit core register to double float)
    pub fn scvtf_d_w(&mut self, rd: u8, rn: A64Reg) {
        assert!(rd < 32);
        let inst = 0x1E62_0000 | (rn.index() << 5) | (rd as u32);
        self.emit(inst);
    }

    /// UCVTF Dd, Wn (Convert unsigned 32-bit core register to double float)
    pub fn ucvtf_d_w(&mut self, rd: u8, rn: A64Reg) {
        assert!(rd < 32);
        let inst = 0x1E63_0000 | (rn.index() << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FCVTZS Wd, Dn (Convert double float to signed 32-bit core register)
    pub fn fcvtzs_w_d(&mut self, rd: A64Reg, rn: u8) {
        assert!(rn < 32);
        let inst = 0x1E78_0000 | ((rn as u32) << 5) | rd.index();
        self.emit(inst);
    }

    /// FCVTZU Wd, Dn (Convert double float to unsigned 32-bit core register)
    pub fn fcvtzu_w_d(&mut self, rd: A64Reg, rn: u8) {
        assert!(rn < 32);
        let inst = 0x1E79_0000 | ((rn as u32) << 5) | rd.index();
        self.emit(inst);
    }

    /// LDR St, [Xn, #offset] (Single-precision float load, offset multiple of 4, up to 16380)
    pub fn ldr_s_imm(&mut self, rt: u8, rn: A64Reg, offset: u32) {
        assert!(rt < 32);
        assert_eq!(offset % 4, 0);
        let imm12 = offset / 4;
        assert!(imm12 <= 0xFFF);
        let inst = 0xBD40_0000 | (imm12 << 10) | (rn.index() << 5) | (rt as u32);
        self.emit(inst);
    }

    /// STR St, [Xn, #offset] (Single-precision float store, offset multiple of 4)
    pub fn str_s_imm(&mut self, rt: u8, rn: A64Reg, offset: u32) {
        assert!(rt < 32);
        assert_eq!(offset % 4, 0);
        let imm12 = offset / 4;
        assert!(imm12 <= 0xFFF);
        let inst = 0xBD00_0000 | (imm12 << 10) | (rn.index() << 5) | (rt as u32);
        self.emit(inst);
    }

    /// LDR Dt, [Xn, #offset] (Double-precision float load, offset multiple of 8, up to 32760)
    pub fn ldr_d_imm(&mut self, rt: u8, rn: A64Reg, offset: u32) {
        assert!(rt < 32);
        assert_eq!(offset % 8, 0);
        let imm12 = offset / 8;
        assert!(imm12 <= 0xFFF);
        let inst = 0xFD40_0000 | (imm12 << 10) | (rn.index() << 5) | (rt as u32);
        self.emit(inst);
    }

    /// STR Dt, [Xn, #offset] (Double-precision float store, offset multiple of 8)
    pub fn str_d_imm(&mut self, rt: u8, rn: A64Reg, offset: u32) {
        assert!(rt < 32);
        assert_eq!(offset % 8, 0);
        let imm12 = offset / 8;
        assert!(imm12 <= 0xFFF);
        let inst = 0xFD00_0000 | (imm12 << 10) | (rn.index() << 5) | (rt as u32);
        self.emit(inst);
    }

    /// LDR Qt, [Xn, #offset] (128-bit vector load, offset multiple of 16)
    pub fn ldr_q_imm(&mut self, rt: u8, rn: A64Reg, offset: u32) {
        assert!(rt < 32);
        assert_eq!(offset % 16, 0);
        let imm12 = offset / 16;
        assert!(imm12 <= 0xFFF);
        let inst = 0x3DC0_0000 | (imm12 << 10) | (rn.index() << 5) | (rt as u32);
        self.emit(inst);
    }

    /// STR Qt, [Xn, #offset] (128-bit vector store, offset multiple of 16)
    pub fn str_q_imm(&mut self, rt: u8, rn: A64Reg, offset: u32) {
        assert!(rt < 32);
        assert_eq!(offset % 16, 0);
        let imm12 = offset / 16;
        assert!(imm12 <= 0xFFF);
        let inst = 0x3D80_0000 | (imm12 << 10) | (rn.index() << 5) | (rt as u32);
        self.emit(inst);
    }

    // --- NEON Advanced SIMD Operations ---

    /// ADD Vd.4S / Vd.2S, Vn, Vm (Vector 32-bit integer add)
    pub fn neon_add_int(&mut self, rd: u8, rn: u8, rm: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0EA0_8400 | q | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// SUB Vd.4S / Vd.2S, Vn, Vm (Vector 32-bit integer sub)
    pub fn neon_sub_int(&mut self, rd: u8, rn: u8, rm: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x2EA0_8400 | q | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// MUL Vd.4S / Vd.2S, Vn, Vm (Vector 32-bit integer mul)
    pub fn neon_mul_int(&mut self, rd: u8, rn: u8, rm: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0EA0_9C00 | q | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    pub fn neon_add_4s(&mut self, rd: u8, rn: u8, rm: u8) {
        self.neon_add_int(rd, rn, rm, true);
    }

    pub fn neon_sub_4s(&mut self, rd: u8, rn: u8, rm: u8) {
        self.neon_sub_int(rd, rn, rm, true);
    }

    pub fn neon_mul_4s(&mut self, rd: u8, rn: u8, rm: u8) {
        self.neon_mul_int(rd, rn, rm, true);
    }

    /// AND Vd.16B / Vd.8B
    pub fn neon_and(&mut self, rd: u8, rn: u8, rm: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E20_1C00 | q | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// ORR Vd.16B / Vd.8B
    pub fn neon_orr(&mut self, rd: u8, rn: u8, rm: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0EA0_1C00 | q | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// EOR Vd.16B / Vd.8B
    pub fn neon_eor(&mut self, rd: u8, rn: u8, rm: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x2E20_1C00 | q | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// BIC Vd.16B / Vd.8B
    pub fn neon_bic(&mut self, rd: u8, rn: u8, rm: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E60_1C00 | q | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    pub fn neon_and_16b(&mut self, rd: u8, rn: u8, rm: u8) {
        self.neon_and(rd, rn, rm, true);
    }

    pub fn neon_orr_16b(&mut self, rd: u8, rn: u8, rm: u8) {
        self.neon_orr(rd, rn, rm, true);
    }

    pub fn neon_eor_16b(&mut self, rd: u8, rn: u8, rm: u8) {
        self.neon_eor(rd, rn, rm, true);
    }

    pub fn neon_bic_16b(&mut self, rd: u8, rn: u8, rm: u8) {
        self.neon_bic(rd, rn, rm, true);
    }

    // --- Vector Single-Precision Float Operations ---

    /// FADD Vd.4S / Vd.2S, Vn, Vm
    pub fn neon_fadd(&mut self, rd: u8, rn: u8, rm: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E20_D400 | q | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FSUB Vd.4S / Vd.2S, Vn, Vm
    pub fn neon_fsub(&mut self, rd: u8, rn: u8, rm: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0EA0_D400 | q | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FMUL Vd.4S / Vd.2S, Vn, Vm
    pub fn neon_fmul(&mut self, rd: u8, rn: u8, rm: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x2E20_DC00 | q | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FMLA Vd.4S / Vd.2S, Vn, Vm (Vector floating-point multiply-accumulate: Vd += Vn * Vm)
    pub fn neon_fmla(&mut self, rd: u8, rn: u8, rm: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E20_CC00 | q | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FMLS Vd.4S / Vd.2S, Vn, Vm (Vector floating-point multiply-subtract: Vd -= Vn * Vm)
    pub fn neon_fmls(&mut self, rd: u8, rn: u8, rm: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0EA0_CC00 | q | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FMAX Vd.4S / Vd.2S, Vn, Vm
    pub fn neon_fmax(&mut self, rd: u8, rn: u8, rm: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E20_F400 | q | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FMIN Vd.4S / Vd.2S, Vn, Vm
    pub fn neon_fmin(&mut self, rd: u8, rn: u8, rm: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0EA0_F400 | q | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FABS Vd.4S / Vd.2S, Vn
    pub fn neon_fabs(&mut self, rd: u8, rn: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0EA0_F800 | q | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FNEG Vd.4S / Vd.2S, Vn
    pub fn neon_fneg(&mut self, rd: u8, rn: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x2EA0_F800 | q | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// SQADD Vd, Vn, Vm (Signed saturating add)
    pub fn neon_sqadd(&mut self, rd: u8, rn: u8, rm: u8, size: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32 && size < 4);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E20_0C00 | q | ((size as u32) << 22) | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// UQADD Vd, Vn, Vm (Unsigned saturating add)
    pub fn neon_uqadd(&mut self, rd: u8, rn: u8, rm: u8, size: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32 && size < 4);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x2E20_0C00 | q | ((size as u32) << 22) | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// SQSUB Vd, Vn, Vm (Signed saturating sub)
    pub fn neon_sqsub(&mut self, rd: u8, rn: u8, rm: u8, size: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32 && size < 4);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E20_2C00 | q | ((size as u32) << 22) | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// UQSUB Vd, Vn, Vm (Unsigned saturating sub)
    pub fn neon_uqsub(&mut self, rd: u8, rn: u8, rm: u8, size: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32 && size < 4);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x2E20_2C00 | q | ((size as u32) << 22) | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// SQSHL Vd, Vn, Vm (Signed saturating shift left by vector register)
    pub fn neon_sqshl(&mut self, rd: u8, rn: u8, rm: u8, size: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32 && size < 4);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E20_4C00 | q | ((size as u32) << 22) | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// UQSHL Vd, Vn, Vm (Unsigned saturating shift left by vector register)
    pub fn neon_uqshl(&mut self, rd: u8, rn: u8, rm: u8, size: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32 && size < 4);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x2E20_4C00 | q | ((size as u32) << 22) | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// TRN1 Vd, Vn, Vm (Transpose primary)
    pub fn neon_trn1(&mut self, rd: u8, rn: u8, rm: u8, size: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32 && size < 4);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E00_2800 | q | ((size as u32) << 22) | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// TRN2 Vd, Vn, Vm (Transpose secondary)
    pub fn neon_trn2(&mut self, rd: u8, rn: u8, rm: u8, size: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32 && size < 4);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E00_6800 | q | ((size as u32) << 22) | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// ZIP1 Vd, Vn, Vm (Zip primary)
    pub fn neon_zip1(&mut self, rd: u8, rn: u8, rm: u8, size: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32 && size < 4);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E00_3800 | q | ((size as u32) << 22) | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// ZIP2 Vd, Vn, Vm (Zip secondary)
    pub fn neon_zip2(&mut self, rd: u8, rn: u8, rm: u8, size: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32 && size < 4);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E00_7800 | q | ((size as u32) << 22) | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// UZP1 Vd, Vn, Vm (Unzip primary)
    pub fn neon_uzp1(&mut self, rd: u8, rn: u8, rm: u8, size: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32 && size < 4);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E00_1800 | q | ((size as u32) << 22) | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// UZP2 Vd, Vn, Vm (Unzip secondary)
    pub fn neon_uzp2(&mut self, rd: u8, rn: u8, rm: u8, size: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32 && size < 4);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E00_5800 | q | ((size as u32) << 22) | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// PMULL Vd.8H, Vn.8B, Vm.8B (Polynomial Multiply Long: GF(2) carry-less multiply)
    pub fn neon_pmull(&mut self, rd: u8, rn: u8, rm: u8) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let inst = 0x0E20_E000 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// ADDP Vd, Vn, Vm (Pairwise integer add)
    pub fn neon_addp(&mut self, rd: u8, rn: u8, rm: u8, size: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32 && size < 4);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E20_BC00 | q | ((size as u32) << 22) | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FADDP Vd, Vn, Vm (Pairwise floating-point add)
    pub fn neon_faddp(&mut self, rd: u8, rn: u8, rm: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x2E20_D400 | q | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FMAXP Vd, Vn, Vm (Pairwise floating-point max)
    pub fn neon_fmaxp(&mut self, rd: u8, rn: u8, rm: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x2E20_F400 | q | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FMINP Vd, Vn, Vm (Pairwise floating-point min)
    pub fn neon_fminp(&mut self, rd: u8, rn: u8, rm: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x2EA0_F400 | q | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// SMAXP Vd, Vn, Vm (Pairwise signed integer max)
    pub fn neon_smaxp(&mut self, rd: u8, rn: u8, rm: u8, size: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32 && size < 4);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E20_A400 | q | ((size as u32) << 22) | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// SMINP Vd, Vn, Vm (Pairwise signed integer min)
    pub fn neon_sminp(&mut self, rd: u8, rn: u8, rm: u8, size: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32 && size < 4);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E20_AC00 | q | ((size as u32) << 22) | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// UMAXP Vd, Vn, Vm (Pairwise unsigned integer max)
    pub fn neon_umaxp(&mut self, rd: u8, rn: u8, rm: u8, size: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32 && size < 4);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x2E20_A400 | q | ((size as u32) << 22) | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// UMINP Vd, Vn, Vm (Pairwise unsigned integer min)
    pub fn neon_uminp(&mut self, rd: u8, rn: u8, rm: u8, size: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32 && size < 4);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x2E20_AC00 | q | ((size as u32) << 22) | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// EXT Vd, Vn, Vm, #imm (Vector extract)
    pub fn neon_ext(&mut self, rd: u8, rn: u8, rm: u8, imm4: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let imm_mask = if is_quad { 15 } else { 7 };
        let inst = 0x2E00_0000 | q | ((rm as u32) << 16) | (((imm4 & imm_mask) as u32) << 11) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// REV64 Vd, Vn (Reverse elements within 64-bit words)
    pub fn neon_rev64(&mut self, rd: u8, rn: u8, size: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && size < 4);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E20_0800 | q | ((size as u32) << 22) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// REV32 Vd, Vn (Reverse elements within 32-bit words)
    pub fn neon_rev32(&mut self, rd: u8, rn: u8, size: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && size < 2);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x2E20_0800 | q | ((size as u32) << 22) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// REV16 Vd, Vn (Reverse elements within 16-bit words)
    pub fn neon_rev16(&mut self, rd: u8, rn: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E20_1800 | q | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// DUP Vd, Vn[index] (Duplicate vector element to all lanes)
    pub fn neon_dup_element(&mut self, rd: u8, rn: u8, imm5: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32 && imm5 < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E00_0400 | q | ((imm5 as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// DUP Vd, Rn (Duplicate general-purpose core register to all vector lanes)
    pub fn neon_dup_core(&mut self, rd: u8, rn: A64Reg, imm5: u8, is_quad: bool) {
        assert!(rd < 32 && imm5 < 32);
        let q = if is_quad { 1 << 30 } else { 0 };
        let inst = 0x0E00_0C00 | q | ((imm5 as u32) << 16) | (rn.index() << 5) | (rd as u32);
        self.emit(inst);
    }

    /// LDP Dt1, Dt2, [Xn, #offset] (Load pair of 64-bit vector registers)
    pub fn ldp_d_offset(&mut self, rt1: u8, rt2: u8, rn: A64Reg, offset_bytes: i32) {
        assert!(rt1 < 32 && rt2 < 32);
        assert_eq!(offset_bytes % 8, 0);
        let imm7 = ((offset_bytes / 8) as u32) & 0x7F;
        let inst = 0x6C40_0000 | (imm7 << 15) | ((rt2 as u32) << 10) | (rn.index() << 5) | (rt1 as u32);
        self.emit(inst);
    }

    /// STP Dt1, Dt2, [Xn, #offset] (Store pair of 64-bit vector registers)
    pub fn stp_d_offset(&mut self, rt1: u8, rt2: u8, rn: A64Reg, offset_bytes: i32) {
        assert!(rt1 < 32 && rt2 < 32);
        assert_eq!(offset_bytes % 8, 0);
        let imm7 = ((offset_bytes / 8) as u32) & 0x7F;
        let inst = 0x6C00_0000 | (imm7 << 15) | ((rt2 as u32) << 10) | (rn.index() << 5) | (rt1 as u32);
        self.emit(inst);
    }

    /// LDP Qt1, Qt2, [Xn, #offset] (Load pair of 128-bit vector registers)
    pub fn ldp_q_offset(&mut self, rt1: u8, rt2: u8, rn: A64Reg, offset_bytes: i32) {
        assert!(rt1 < 32 && rt2 < 32);
        assert_eq!(offset_bytes % 16, 0);
        let imm7 = ((offset_bytes / 16) as u32) & 0x7F;
        let inst = 0xAC40_0000 | (imm7 << 15) | ((rt2 as u32) << 10) | (rn.index() << 5) | (rt1 as u32);
        self.emit(inst);
    }

    /// STP Qt1, Qt2, [Xn, #offset] (Store pair of 128-bit vector registers)
    pub fn stp_q_offset(&mut self, rt1: u8, rt2: u8, rn: A64Reg, offset_bytes: i32) {
        assert!(rt1 < 32 && rt2 < 32);
        assert_eq!(offset_bytes % 16, 0);
        let imm7 = ((offset_bytes / 16) as u32) & 0x7F;
        let inst = 0xAC00_0000 | (imm7 << 15) | ((rt2 as u32) << 10) | (rn.index() << 5) | (rt1 as u32);
        self.emit(inst);
    }

    /// XTN Vd, Vn (Extract narrow: 16b->8b, 32b->16b, 64b->32b)
    pub fn neon_xtn(&mut self, rd: u8, rn: u8, size: u8) {
        assert!(rd < 32 && rn < 32 && size < 3);
        let inst = 0x0E21_2800 | ((size as u32) << 22) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// SQXTN Vd, Vn (Signed saturating extract narrow)
    pub fn neon_sqxtn(&mut self, rd: u8, rn: u8, size: u8) {
        assert!(rd < 32 && rn < 32 && size < 3);
        let inst = 0x0E21_4800 | ((size as u32) << 22) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// SQXTUN Vd, Vn (Signed saturating extract unsigned narrow)
    pub fn neon_sqxtun(&mut self, rd: u8, rn: u8, size: u8) {
        assert!(rd < 32 && rn < 32 && size < 3);
        let inst = 0x2E21_2800 | ((size as u32) << 22) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// UQXTN Vd, Vn (Unsigned saturating extract narrow)
    pub fn neon_uqxtn(&mut self, rd: u8, rn: u8, size: u8) {
        assert!(rd < 32 && rn < 32 && size < 3);
        let inst = 0x2E21_4800 | ((size as u32) << 22) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// SHRN Vd, Vn, #shift (Shift right narrow by immediate)
    pub fn neon_shrn(&mut self, rd: u8, rn: u8, size: u8, shift: u8) {
        assert!(rd < 32 && rn < 32 && size < 3);
        let bits = match size { 0 => 16, 1 => 32, _ => 64 };
        assert!(shift > 0 && shift <= bits);
        let immb = (1 << (size + 3)) | (bits - shift);
        let inst = 0x0F00_8400 | ((immb as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// SQSHRUN Vd, Vn, #shift (Signed saturating shift right unsigned narrow)
    pub fn neon_sqshrun(&mut self, rd: u8, rn: u8, size: u8, shift: u8) {
        assert!(rd < 32 && rn < 32 && size < 3);
        let bits = match size { 0 => 16, 1 => 32, _ => 64 };
        assert!(shift > 0 && shift <= bits);
        let immb = (1 << (size + 3)) | (bits - shift);
        let inst = 0x2F00_8400 | ((immb as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// SQSHRN Vd, Vn, #shift (Signed saturating shift right narrow)
    pub fn neon_sqshrn(&mut self, rd: u8, rn: u8, size: u8, shift: u8) {
        assert!(rd < 32 && rn < 32 && size < 3);
        let bits = match size { 0 => 16, 1 => 32, _ => 64 };
        assert!(shift > 0 && shift <= bits);
        let immb = (1 << (size + 3)) | (bits - shift);
        let inst = 0x0F00_9400 | ((immb as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// UQSHRN Vd, Vn, #shift (Unsigned saturating shift right narrow)
    pub fn neon_uqshrn(&mut self, rd: u8, rn: u8, size: u8, shift: u8) {
        assert!(rd < 32 && rn < 32 && size < 3);
        let bits = match size { 0 => 16, 1 => 32, _ => 64 };
        assert!(shift > 0 && shift <= bits);
        let immb = (1 << (size + 3)) | (bits - shift);
        let inst = 0x2F00_9400 | ((immb as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// SSHLL Vd, Vn, #shift (Signed shift left long / widen: 8b->8h, 16b->4s, 32b->2d)
    pub fn neon_sshll(&mut self, rd: u8, rn: u8, size_shift: u8, shift: u8) {
        assert!(rd < 32 && rn < 32 && (3..=5).contains(&size_shift));
        let imm = (1 << size_shift) | (shift & ((1 << size_shift) - 1));
        let inst = 0x0F00_A400 | ((imm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// USHLL Vd, Vn, #shift (Unsigned shift left long / widen: 8b->8h, 16b->4s, 32b->2d)
    pub fn neon_ushll(&mut self, rd: u8, rn: u8, size_shift: u8, shift: u8) {
        assert!(rd < 32 && rn < 32 && (3..=5).contains(&size_shift));
        let imm = (1 << size_shift) | (shift & ((1 << size_shift) - 1));
        let inst = 0x2F00_A400 | ((imm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// SCVTF Vd, Vn (Signed 32-bit int to float vector conversion: 2S or 4S)
    pub fn neon_scvtf(&mut self, rd: u8, rn: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32);
        let q = if is_quad { 0x4E21_D800 } else { 0x0E21_D800 };
        let inst = q | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// UCVTF Vd, Vn (Unsigned 32-bit int to float vector conversion: 2S or 4S)
    pub fn neon_ucvtf(&mut self, rd: u8, rn: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32);
        let q = if is_quad { 0x6E21_D800 } else { 0x2E21_D800 };
        let inst = q | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FCVTZS Vd, Vn (Float to signed 32-bit int vector conversion round-to-zero: 2S or 4S)
    pub fn neon_fcvtzs(&mut self, rd: u8, rn: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32);
        let q = if is_quad { 0x4EA1_B800 } else { 0x0EA1_B800 };
        let inst = q | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// FCVTZU Vd, Vn (Float to unsigned 32-bit int vector conversion round-to-zero: 2S or 4S)
    pub fn neon_fcvtzu(&mut self, rd: u8, rn: u8, is_quad: bool) {
        assert!(rd < 32 && rn < 32);
        let q = if is_quad { 0x6EA1_B800 } else { 0x2EA1_B800 };
        let inst = q | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// LD1 {Vt.8B..}, [Xn] (Multiple 1-element structures load: 1 to 4 registers)
    pub fn neon_ld1_mult(&mut self, q: u8, opcode: u8, size: u8, rn: A64Reg, rt: u8) {
        assert!(rt < 32);
        let inst = ((q as u32) << 30)
            | (0b001100 << 24)
            | (1 << 22)
            | (((opcode as u32) & 0xF) << 12)
            | (((size as u32) & 0x3) << 10)
            | (rn.index() << 5)
            | (rt as u32);
        self.emit(inst);
    }

    /// ST1 {Vt.8B..}, [Xn] (Multiple 1-element structures store: 1 to 4 registers)
    pub fn neon_st1_mult(&mut self, q: u8, opcode: u8, size: u8, rn: A64Reg, rt: u8) {
        assert!(rt < 32);
        let inst = ((q as u32) << 30)
            | (0b001100 << 24)
            | (0 << 22)
            | (((opcode as u32) & 0xF) << 12)
            | (((size as u32) & 0x3) << 10)
            | (rn.index() << 5)
            | (rt as u32);
        self.emit(inst);
    }

    /// LD2 {Vt, Vt+1}, [Xn] (2-element structures load: 8B/16B/4H/8H/2S/4S)
    pub fn neon_ld2(&mut self, q: u8, size: u8, rn: A64Reg, rt: u8) {
        self.neon_ld1_mult(q, 0b1000, size, rn, rt);
    }

    /// ST2 {Vt, Vt+1}, [Xn] (2-element structures store)
    pub fn neon_st2(&mut self, q: u8, size: u8, rn: A64Reg, rt: u8) {
        self.neon_st1_mult(q, 0b1000, size, rn, rt);
    }

    /// LD3 {Vt, Vt+1, Vt+2}, [Xn] (3-element structures load)
    pub fn neon_ld3(&mut self, q: u8, size: u8, rn: A64Reg, rt: u8) {
        self.neon_ld1_mult(q, 0b0100, size, rn, rt);
    }

    /// ST3 {Vt, Vt+1, Vt+2}, [Xn] (3-element structures store)
    pub fn neon_st3(&mut self, q: u8, size: u8, rn: A64Reg, rt: u8) {
        self.neon_st1_mult(q, 0b0100, size, rn, rt);
    }

    /// LD4 {Vt, Vt+1, Vt+2, Vt+3}, [Xn] (4-element structures load)
    pub fn neon_ld4(&mut self, q: u8, size: u8, rn: A64Reg, rt: u8) {
        self.neon_ld1_mult(q, 0b0000, size, rn, rt);
    }

    /// ST4 {Vt, Vt+1, Vt+2, Vt+3}, [Xn] (4-element structures store)
    pub fn neon_st4(&mut self, q: u8, size: u8, rn: A64Reg, rt: u8) {
        self.neon_st1_mult(q, 0b0000, size, rn, rt);
    }

    /// LD1R {Vt}, [Xn] (Load 1 element and replicate to all lanes of 1 vector)
    pub fn neon_ld1r(&mut self, q: u8, size: u8, rn: A64Reg, rt: u8) {
        assert!(rt < 32);
        let inst = ((q as u32) << 30)
            | (0b001101 << 24)
            | (1 << 22)
            | (0b01100 << 12)
            | (((size as u32) & 0x3) << 10)
            | (rn.index() << 5)
            | (rt as u32);
        self.emit(inst);
    }

    /// LD2R {Vt, Vt+1}, [Xn] (Load 2 elements and replicate to all lanes of 2 vectors)
    pub fn neon_ld2r(&mut self, q: u8, size: u8, rn: A64Reg, rt: u8) {
        assert!(rt < 32);
        let inst = ((q as u32) << 30)
            | (0b001101 << 24)
            | (1 << 22)
            | (1 << 21)
            | (0b01100 << 12)
            | (((size as u32) & 0x3) << 10)
            | (rn.index() << 5)
            | (rt as u32);
        self.emit(inst);
    }

    /// LD3R {Vt, Vt+1, Vt+2}, [Xn] (Load 3 elements and replicate to all lanes of 3 vectors)
    pub fn neon_ld3r(&mut self, q: u8, size: u8, rn: A64Reg, rt: u8) {
        assert!(rt < 32);
        let inst = ((q as u32) << 30)
            | (0b001101 << 24)
            | (1 << 22)
            | (0b01110 << 12)
            | (((size as u32) & 0x3) << 10)
            | (rn.index() << 5)
            | (rt as u32);
        self.emit(inst);
    }

    /// LD4R {Vt, Vt+1, Vt+2, Vt+3}, [Xn] (Load 4 elements and replicate to all lanes of 4 vectors)
    pub fn neon_ld4r(&mut self, q: u8, size: u8, rn: A64Reg, rt: u8) {
        assert!(rt < 32);
        let inst = ((q as u32) << 30)
            | (0b001101 << 24)
            | (1 << 22)
            | (1 << 21)
            | (0b01110 << 12)
            | (((size as u32) & 0x3) << 10)
            | (rn.index() << 5)
            | (rt as u32);
        self.emit(inst);
    }

    /// LDXR Wt, [Xn] (Load exclusive 32-bit register)
    pub fn ldxr_w(&mut self, rt: A64Reg, rn: A64Reg) {
        let inst = 0x885F_7C00 | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    /// STXR Ws, Wt, [Xn] (Store exclusive 32-bit register)
    pub fn stxr_w(&mut self, rs: A64Reg, rt: A64Reg, rn: A64Reg) {
        let inst = 0x8800_7C00 | (rs.index() << 16) | (rn.index() << 5) | rt.index();
        self.emit(inst);
    }

    /// CLREX (Clear exclusive monitor reservation)
    pub fn clrex(&mut self) {
        self.emit(0xD503_3F5F);
    }

    /// DMB ISH (Data Memory Barrier, Inner Shareable)
    pub fn dmb_ish(&mut self) {
        self.emit(0xD503_3BBF);
    }

    /// DSB ISH (Data Synchronization Barrier, Inner Shareable)
    pub fn dsb_ish(&mut self) {
        self.emit(0xD503_39BF);
    }

    /// ISB (Instruction Synchronization Barrier)
    pub fn isb(&mut self) {
        self.emit(0xD503_3FDF);
    }

    /// MRS Xt, TPIDR_EL0 (Read Thread ID Register)
    pub fn mrs_tpidr_el0(&mut self, rt: A64Reg) {
        let inst = 0xD53B_D040 | rt.index();
        self.emit(inst);
    }

    /// MSR TPIDR_EL0, Xt (Write Thread ID Register)
    pub fn msr_tpidr_el0(&mut self, rt: A64Reg) {
        let inst = 0xD51B_D040 | rt.index();
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

    #[test]
    fn test_asm_atomics_and_barriers() {
        let mut asm = A64Assembler::new();
        asm.ldxr_w(A64Reg::X0, A64Reg::X1);
        asm.stxr_w(A64Reg::X2, A64Reg::X0, A64Reg::X1);
        asm.clrex();
        asm.dmb_ish();
        asm.dsb_ish();
        asm.isb();
        asm.mrs_tpidr_el0(A64Reg::X0);
        asm.msr_tpidr_el0(A64Reg::X0);

        assert_eq!(asm.code.len(), 8);
        assert_eq!(asm.code[0], 0x885F_7C20); // LDXR W0, [X1]
        assert_eq!(asm.code[1], 0x8802_7C20); // STXR W2, W0, [X1]
        assert_eq!(asm.code[2], 0xD503_3F5F); // CLREX
        assert_eq!(asm.code[3], 0xD503_3BBF); // DMB ISH
        assert_eq!(asm.code[4], 0xD503_39BF); // DSB ISH
        assert_eq!(asm.code[5], 0xD503_3FDF); // ISB
        assert_eq!(asm.code[6], 0xD53B_D040); // MRS X0, TPIDR_EL0
        assert_eq!(asm.code[7], 0xD51B_D040); // MSR TPIDR_EL0, X0
    }

    #[test]
    fn test_asm_extended_and_mem() {
        let mut asm = A64Assembler::new();
        // ADD X10, X1, W9, UXTW
        asm.add_x_uxtw(A64Reg::X10, A64Reg::X1, A64Reg::X9);
        // LDRB W11, [X10, #4]
        asm.ldrb_w_imm(A64Reg::X11, A64Reg::X10, 4);
        // STRB W11, [X10, #4]
        asm.strb_w_imm(A64Reg::X11, A64Reg::X10, 4);
        // LDRH W12, [X10, #6]
        asm.ldrh_w_imm(A64Reg::X12, A64Reg::X10, 6);
        // STRH W12, [X10, #6]
        asm.strh_w_imm(A64Reg::X12, A64Reg::X10, 6);

        assert_eq!(asm.code.len(), 5);
        assert_eq!(asm.code[0], 0x8B29_402A); // ADD X10, X1, W9, UXTW
        assert_eq!(asm.code[1], 0x3940_114B); // LDRB W11, [X10, #4]
        assert_eq!(asm.code[2], 0x3900_114B); // STRB W11, [X10, #4]
        assert_eq!(asm.code[3], 0x7940_0D4C); // LDRH W12, [X10, #6]
        assert_eq!(asm.code[4], 0x7900_0D4C); // STRH W12, [X10, #6]
    }

    #[test]
    fn test_asm_register_offset_uxtw() {
        let mut asm = A64Assembler::new();
        // LDR W11, [X1, W12, UXTW]
        asm.ldr_w_uxtw(A64Reg::X11, A64Reg::X1, A64Reg::X12);
        // STR W11, [X1, W12, UXTW]
        asm.str_w_uxtw(A64Reg::X11, A64Reg::X1, A64Reg::X12);
        // LDRB W11, [X1, W12, UXTW]
        asm.ldrb_w_uxtw(A64Reg::X11, A64Reg::X1, A64Reg::X12);
        // STRB W11, [X1, W12, UXTW]
        asm.strb_w_uxtw(A64Reg::X11, A64Reg::X1, A64Reg::X12);
        // LDRH W11, [X1, W12, UXTW]
        asm.ldrh_w_uxtw(A64Reg::X11, A64Reg::X1, A64Reg::X12);
        // STRH W11, [X1, W12, UXTW]
        asm.strh_w_uxtw(A64Reg::X11, A64Reg::X1, A64Reg::X12);
        // LDRSB W11, [X1, W12, UXTW]
        asm.ldrsb_w_uxtw(A64Reg::X11, A64Reg::X1, A64Reg::X12);
        // LDRSH W11, [X1, W12, UXTW]
        asm.ldrsh_w_uxtw(A64Reg::X11, A64Reg::X1, A64Reg::X12);

        assert_eq!(asm.code.len(), 8);
        assert_eq!(asm.code[0], 0xB86C_482B); // LDR W11, [X1, W12, UXTW]
        assert_eq!(asm.code[1], 0xB82C_482B); // STR W11, [X1, W12, UXTW]
        assert_eq!(asm.code[2], 0x386C_482B); // LDRB W11, [X1, W12, UXTW]
        assert_eq!(asm.code[3], 0x382C_482B); // STRB W11, [X1, W12, UXTW]
        assert_eq!(asm.code[4], 0x786C_482B); // LDRH W11, [X1, W12, UXTW]
        assert_eq!(asm.code[5], 0x782C_482B); // STRH W11, [X1, W12, UXTW]
        assert_eq!(asm.code[6], 0x38EC_482B); // LDRSB W11, [X1, W12, UXTW]
        assert_eq!(asm.code[7], 0x78EC_482B); // LDRSH W11, [X1, W12, UXTW]
    }

    #[test]
    fn test_asm_multiply_and_shifts() {
        let mut asm = A64Assembler::new();
        asm.mul_w_reg(A64Reg::X0, A64Reg::X1, A64Reg::X2);
        asm.madd_w_reg(A64Reg::X0, A64Reg::X1, A64Reg::X2, A64Reg::X3);
        asm.msub_w_reg(A64Reg::X0, A64Reg::X1, A64Reg::X2, A64Reg::X3);
        asm.sdiv_w_reg(A64Reg::X0, A64Reg::X1, A64Reg::X2);
        asm.udiv_w_reg(A64Reg::X0, A64Reg::X1, A64Reg::X2);
        asm.clz_w_reg(A64Reg::X0, A64Reg::X1);
        asm.lsl_w_imm(A64Reg::X0, A64Reg::X1, 2);
        asm.lsr_w_imm(A64Reg::X0, A64Reg::X1, 2);
        asm.asr_w_imm(A64Reg::X0, A64Reg::X1, 2);
        asm.mvn_w_reg(A64Reg::X0, A64Reg::X1);
        asm.tst_w_reg(A64Reg::X0, A64Reg::X1);

        assert_eq!(asm.code.len(), 11);
    }

    #[test]
    fn test_asm_bitfield_and_byte_rev() {
        let mut asm = A64Assembler::new();
        // UBFX W0, W1, #4, #8 -> 0x5304_2C20
        asm.ubfx_w(A64Reg::X0, A64Reg::X1, 4, 8);
        // SBFX W0, W1, #4, #8 -> 0x1304_2C20
        asm.sbfx_w(A64Reg::X0, A64Reg::X1, 4, 8);
        // BFI W0, W1, #4, #8 -> 0x331C_1C20
        asm.bfi_w(A64Reg::X0, A64Reg::X1, 4, 8);
        // RBIT W0, W1 -> 0x5AC0_0020
        asm.rbit_w(A64Reg::X0, A64Reg::X1);
        // REV W0, W1 -> 0x5AC0_0820
        asm.rev_w(A64Reg::X0, A64Reg::X1);
        // REV16 W0, W1 -> 0x5AC0_0420
        asm.rev16_w(A64Reg::X0, A64Reg::X1);
        // SXTH W0, W1 -> 0x1300_3C20
        asm.sxth_w(A64Reg::X0, A64Reg::X1);
        // SXTB W0, W1 -> 0x1300_1C20
        asm.sxtb_w(A64Reg::X0, A64Reg::X1);
        // UXTB W0, W1 -> 0x5300_1C20
        asm.uxtb_w(A64Reg::X0, A64Reg::X1);
        // UXTH W0, W1 -> 0x5300_3C20
        asm.uxth_w(A64Reg::X0, A64Reg::X1);
        // ROR W0, W1, #8 -> 0x1381_2020
        asm.ror_w(A64Reg::X0, A64Reg::X1, 8);

        assert_eq!(asm.code.len(), 11);
        assert_eq!(asm.code[0], 0x5304_2C20);
        assert_eq!(asm.code[1], 0x1304_2C20);
        assert_eq!(asm.code[2], 0x331C_1C20);
        assert_eq!(asm.code[3], 0x5AC0_0020);
        assert_eq!(asm.code[4], 0x5AC0_0820);
        assert_eq!(asm.code[5], 0x5AC0_0420);
        assert_eq!(asm.code[6], 0x1300_3C20);
        assert_eq!(asm.code[7], 0x1300_1C20);
        assert_eq!(asm.code[8], 0x5300_1C20);
        assert_eq!(asm.code[9], 0x5300_3C20);
        assert_eq!(asm.code[10], 0x1381_2020);
    }

    #[test]
    fn test_asm_neon_interleaved_multi_load_store() {
        let mut asm = A64Assembler::new();
        // LD2 {V0.8B, V1.8B}, [X10] -> 0x0C40_8140
        asm.neon_ld2(0, 0, A64Reg::X10, 0);
        // ST2 {V0.8B, V1.8B}, [X10] -> 0x0C00_8140
        asm.neon_st2(0, 0, A64Reg::X10, 0);
        // LD3 {V0.8B, V1.8B, V2.8B}, [X10] -> 0x0C40_4140
        asm.neon_ld3(0, 0, A64Reg::X10, 0);
        // ST3 {V0.8B, V1.8B, V2.8B}, [X10] -> 0x0C00_4140
        asm.neon_st3(0, 0, A64Reg::X10, 0);
        // LD4 {V0.8B, V1.8B, V2.8B, V3.8B}, [X10] -> 0x0C40_0140
        asm.neon_ld4(0, 0, A64Reg::X10, 0);
        // ST4 {V0.8B, V1.8B, V2.8B, V3.8B}, [X10] -> 0x0C00_0140
        asm.neon_st4(0, 0, A64Reg::X10, 0);
        // LD2 {V0.16B, V1.16B}, [X10] -> 0x4C40_8140
        asm.neon_ld2(1, 0, A64Reg::X10, 0);
        // LD1R {V0.8B}, [X10] -> 0x0D40_C140
        asm.neon_ld1r(0, 0, A64Reg::X10, 0);

        assert_eq!(asm.code.len(), 8);
        assert_eq!(asm.code[0], 0x0C40_8140);
        assert_eq!(asm.code[1], 0x0C00_8140);
        assert_eq!(asm.code[2], 0x0C40_4140);
        assert_eq!(asm.code[3], 0x0C00_4140);
        assert_eq!(asm.code[4], 0x0C40_0140);
        assert_eq!(asm.code[5], 0x0C00_0140);
        assert_eq!(asm.code[6], 0x4C40_8140);
        assert_eq!(asm.code[7], 0x0D40_C140);
    }

    #[test]
    fn test_asm_vfp_and_neon() {
        let mut asm = A64Assembler::new();
        // FADD S0, S1, S2
        asm.fadd_s(0, 1, 2);
        // FSUB D0, D1, D2
        asm.fsub_d(0, 1, 2);
        // FMUL S3, S4, S5
        asm.fmul_s(3, 4, 5);
        // FDIV D6, D7, D8
        asm.fdiv_d(6, 7, 8);
        // FCMP S0, S1
        asm.fcmp_s(0, 1);
        // LDR S0, [X0, #16]
        asm.ldr_s_imm(0, A64Reg::X0, 16);
        // STR D1, [X0, #32]
        asm.str_d_imm(1, A64Reg::X0, 32);
        // NEON ADD V0.4S, V1.4S, V2.4S
        asm.neon_add_4s(0, 1, 2);
        // NEON AND V3.16B, V4.16B, V5.16B
        asm.neon_and_16b(3, 4, 5);

        assert_eq!(asm.code.len(), 9);
        assert_eq!(asm.code[0], 0x1E22_2820); // FADD S0, S1, S2
        assert_eq!(asm.code[1], 0x1E62_3820); // FSUB D0, D1, D2
    }

    #[test]
    fn test_asm_pair_load_store_and_mov64() {
        let mut asm = A64Assembler::new();
        // STP X19, X20, [SP, #-64]!
        asm.stp_x_pre(A64Reg::X19, A64Reg::X20, A64Reg::SP, -64);
        // LDP X19, X20, [SP], #64
        asm.ldp_x_post(A64Reg::X19, A64Reg::X20, A64Reg::SP, 64);
        // STP W19, W20, [X0, #0]
        asm.stp_w_offset(A64Reg::X19, A64Reg::X20, A64Reg::X0, 0);
        // LDP W19, W20, [X0, #0]
        asm.ldp_w_offset(A64Reg::X19, A64Reg::X20, A64Reg::X0, 0);
        // MOV X0, X9
        asm.mov_x_reg(A64Reg::X0, A64Reg::X9);
        // MOV_IMM64
        asm.mov_imm64(A64Reg::X9, 0x1234_5678_9ABC_DEF0);

        assert_eq!(asm.code[0] & 0xFFC0_0000, 0xA980_0000); // STP X pre
        assert_eq!(asm.code[1] & 0xFFC0_0000, 0xA8C0_0000); // LDP X post
        assert_eq!(asm.code[2] & 0xFFC0_0000, 0x2900_0000); // STP W
        assert_eq!(asm.code[3] & 0xFFC0_0000, 0x2940_0000); // LDP W
        assert_eq!(asm.code[4], 0xAA09_03E0);               // MOV X0, X9
        assert_eq!(asm.code.len(), 9); // 5 + 4 for 64-bit mov
    }

    #[test]
    fn test_asm_neon_vector_fp_and_quad_mem() {
        let mut asm = A64Assembler::new();
        asm.neon_fadd(0, 1, 2, true);
        asm.neon_fsub(0, 1, 2, true);
        asm.neon_fmul(0, 1, 2, true);
        asm.neon_fmla(0, 1, 2, true);
        asm.neon_fmls(0, 1, 2, true);
        asm.neon_fmax(0, 1, 2, true);
        asm.neon_fmin(0, 1, 2, true);
        asm.neon_fabs(0, 1, true);
        asm.neon_fneg(0, 1, true);
        asm.ldr_q_imm(1, A64Reg::X0, 160);
        asm.str_q_imm(1, A64Reg::X0, 160);

        assert_eq!(asm.code[0], 0x4E20_D400 | (2 << 16) | (1 << 5) | 0);
        assert_eq!(asm.code[1], 0x4EA0_D400 | (2 << 16) | (1 << 5) | 0);
        assert_eq!(asm.code[2], 0x6E20_DC00 | (2 << 16) | (1 << 5) | 0);
        assert_eq!(asm.code[3], 0x4E20_CC00 | (2 << 16) | (1 << 5) | 0);
        assert_eq!(asm.code[4], 0x4EA0_CC00 | (2 << 16) | (1 << 5) | 0);
        assert_eq!(asm.code[5], 0x4E20_F400 | (2 << 16) | (1 << 5) | 0);
        assert_eq!(asm.code[6], 0x4EA0_F400 | (2 << 16) | (1 << 5) | 0);
        assert_eq!(asm.code[7], 0x4EA0_F800 | (1 << 5) | 0);
        assert_eq!(asm.code[8], 0x6EA0_F800 | (1 << 5) | 0);
        assert_eq!(asm.code[9], 0x3DC0_0000 | (10 << 10) | (0 << 5) | 1);
        assert_eq!(asm.code[10], 0x3D80_0000 | (10 << 10) | (0 << 5) | 1);
    }

    #[test]
    fn test_asm_neon_narrow_widen_cvt() {
        let mut asm = A64Assembler::new();
        asm.neon_xtn(0, 1, 0);
        asm.neon_sqxtn(0, 1, 1);
        asm.neon_sqxtun(0, 1, 2);
        asm.neon_uqxtn(0, 1, 0);
        asm.neon_shrn(0, 1, 0, 3);
        asm.neon_sshll(0, 1, 3, 0);
        asm.neon_ushll(0, 1, 4, 5);
        asm.neon_scvtf(0, 1, false);
        asm.neon_scvtf(0, 1, true);
        asm.neon_ucvtf(0, 1, false);
        asm.neon_fcvtzs(0, 1, false);
        asm.neon_fcvtzs(0, 1, true);
        asm.neon_fcvtzu(0, 1, true);

        assert_eq!(asm.code[0], 0x0E21_2820);
        assert_eq!(asm.code[1], 0x0E61_4820);
        assert_eq!(asm.code[2], 0x2EA1_2820);
        assert_eq!(asm.code[3], 0x2E21_4820);
        assert_eq!(asm.code[4], 0x0F0D_8420);
        assert_eq!(asm.code[5], 0x0F08_A420);
        assert_eq!(asm.code[6], 0x2F15_A420);
        assert_eq!(asm.code[7], 0x0E21_D820);
        assert_eq!(asm.code[8], 0x4E21_D820);
        assert_eq!(asm.code[9], 0x2E21_D820);
        assert_eq!(asm.code[10], 0x0EA1_B820);
        assert_eq!(asm.code[11], 0x4EA1_B820);
        assert_eq!(asm.code[12], 0x6EA1_B820);
    }

    #[test]
    fn test_asm_scalar_vcvt_and_fmov() {
        let mut asm = A64Assembler::new();
        asm.fmov_w_from_s(A64Reg::X0, 1);
        asm.fmov_s_from_w(0, A64Reg::X1);
        asm.fcvt_d_s(0, 1);
        asm.fcvt_s_d(0, 1);
        asm.scvtf_s_s(0, 1);
        asm.ucvtf_s_s(0, 1);
        asm.fcvtzs_s_s(0, 1);
        asm.fcvtzu_s_s(0, 1);
        asm.scvtf_d_w(0, A64Reg::X1);
        asm.ucvtf_d_w(0, A64Reg::X1);
        asm.fcvtzs_w_d(A64Reg::X0, 1);
        asm.fcvtzu_w_d(A64Reg::X0, 1);

        assert_eq!(asm.code[0], 0x1E26_0020);
        assert_eq!(asm.code[1], 0x1E27_0020);
        assert_eq!(asm.code[2], 0x1E22_C020);
        assert_eq!(asm.code[3], 0x1E62_4020);
        assert_eq!(asm.code[4], 0x5E21_D820);
        assert_eq!(asm.code[5], 0x7E21_D820);
        assert_eq!(asm.code[6], 0x5EA1_B820);
        assert_eq!(asm.code[7], 0x7EA1_B820);
        assert_eq!(asm.code[8], 0x1E62_0020);
        assert_eq!(asm.code[9], 0x1E63_0020);
        assert_eq!(asm.code[10], 0x1E78_0020);
        assert_eq!(asm.code[11], 0x1E79_0020);
    }

    #[test]
    fn test_asm_stage52_multiplies_and_fmov_d() {
        let mut asm = A64Assembler::new();
        asm.smull_x(A64Reg::X0, A64Reg::X1, A64Reg::X2);
        asm.umull_x(A64Reg::X0, A64Reg::X1, A64Reg::X2);
        asm.smaddl_x(A64Reg::X0, A64Reg::X1, A64Reg::X2, A64Reg::X3);
        asm.umaddl_x(A64Reg::X0, A64Reg::X1, A64Reg::X2, A64Reg::X3);
        asm.bfi_x(A64Reg::X0, A64Reg::X1, 32, 32);
        asm.lsr_x_imm(A64Reg::X0, A64Reg::X1, 32);
        asm.lsl_x_imm(A64Reg::X0, A64Reg::X1, 32);
        asm.asr_x_imm(A64Reg::X0, A64Reg::X1, 16);
        asm.fmov_x_from_d(A64Reg::X0, 1);
        asm.fmov_d_from_x(0, A64Reg::X1);

        assert_eq!(asm.code[0], 0x9B22_7C20);
        assert_eq!(asm.code[1], 0x9BA2_7C20);
        assert_eq!(asm.code[2], 0x9B22_0C20);
        assert_eq!(asm.code[3], 0x9BA2_0C20);
        assert_eq!(asm.code[4], 0xB360_7C20);
        assert_eq!(asm.code[5], 0xD360_FC20);
        assert_eq!(asm.code[6], 0xD360_7C20);
        assert_eq!(asm.code[7], 0x9350_FC20);
        assert_eq!(asm.code[8], 0x9E66_0020);
        assert_eq!(asm.code[9], 0x9E67_0020);
    }
}
