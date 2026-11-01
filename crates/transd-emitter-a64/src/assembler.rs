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

    // --- NEON Advanced SIMD Operations ---

    /// ADD Vd.4S, Vn.4S, Vm.4S (Vector 4 x 32-bit integer/float add)
    pub fn neon_add_4s(&mut self, rd: u8, rn: u8, rm: u8) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let inst = 0x4E20_8400 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// SUB Vd.4S, Vn.4S, Vm.4S (Vector 4 x 32-bit sub)
    pub fn neon_sub_4s(&mut self, rd: u8, rn: u8, rm: u8) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let inst = 0x4E60_8400 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// MUL Vd.4S, Vn.4S, Vm.4S (Vector 4 x 32-bit multiply)
    pub fn neon_mul_4s(&mut self, rd: u8, rn: u8, rm: u8) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let inst = 0x4E20_9C00 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// AND Vd.16B, Vn.16B, Vm.16B (Vector bitwise AND 128-bit)
    pub fn neon_and_16b(&mut self, rd: u8, rn: u8, rm: u8) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let inst = 0x4E20_1C00 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// ORR Vd.16B, Vn.16B, Vm.16B (Vector bitwise OR 128-bit)
    pub fn neon_orr_16b(&mut self, rd: u8, rn: u8, rm: u8) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let inst = 0x4EA0_1C00 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
        self.emit(inst);
    }

    /// EOR Vd.16B, Vn.16B, Vm.16B (Vector bitwise EOR 128-bit)
    pub fn neon_eor_16b(&mut self, rd: u8, rn: u8, rm: u8) {
        assert!(rd < 32 && rn < 32 && rm < 32);
        let inst = 0x6E20_1C00 | ((rm as u32) << 16) | ((rn as u32) << 5) | (rd as u32);
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
}
