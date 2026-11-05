use walzer32_core::{ArenaMemory, GuestAddr, Memory, Reg};
use walzer32_rt::DbtEngine;

#[test]
fn test_arm_sadd8_uadd8_and_sel() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Initial register setup:
    // r1 = 0x8080_8080
    // r2 = 0x8000_8000
    // r8 = 0x1122_3344 (SEL source A)
    // r9 = 0xAABB_CCDD (SEL source B)
    engine.cpu.set_reg(Reg::R1, 0x8080_8080);
    engine.cpu.set_reg(Reg::R2, 0x8000_8000);
    engine.cpu.set_reg(Reg::R8, 0x1122_3344);
    engine.cpu.set_reg(Reg::R9, 0xAABB_CCDD);

    // Program:
    // 0x20000: UADD8 r3, r1, r2  -> 0xE651_3F92
    //          Byte 3: 0x80+0x80 = 0x100 >= 0x100 -> GE3 = 1
    //          Byte 2: 0x80+0x00 = 0x80 < 0x100   -> GE2 = 0
    //          Byte 1: 0x80+0x80 = 0x100 >= 0x100 -> GE1 = 1
    //          Byte 0: 0x80+0x00 = 0x80 < 0x100   -> GE0 = 0
    //          GE[3:0] = 0b1010
    //          Result r3 = 0x0080_0080
    // 0x20004: SEL r5, r8, r9    -> 0xE688_5FB9
    //          For GE[3]=1 -> byte 3 from r8 = 0x11
    //          For GE[2]=0 -> byte 2 from r9 = 0xBB
    //          For GE[1]=1 -> byte 1 from r8 = 0x33
    //          For GE[0]=0 -> byte 0 from r9 = 0xDD
    //          Result r5 = 0x11BB_33DD
    // 0x20008: MOV r7, #1        -> 0xE3A0_7001
    // 0x2000C: MOV r0, #0        -> 0xE3A0_0000
    // 0x20010: SVC 0             -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xE651_3F92).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xE688_5FB9).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // Verify UADD8 result:
    assert_eq!(engine.cpu.reg(Reg::R3), 0x0080_0080);
    // Verify GE bits in CPSR:
    assert_eq!(engine.cpu.cpsr.ge_bits(), 0b1010);
    // Verify SEL result:
    assert_eq!(engine.cpu.reg(Reg::R5), 0x11BB_33DD);
}

#[test]
fn test_arm_pkhbt_and_pkhtb() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    engine.cpu.set_reg(Reg::R1, 0x1234_5678);
    engine.cpu.set_reg(Reg::R2, 0xABCD_EF01);

    // Program:
    // 0x20000: PKHBT r3, r1, r2, LSL #4 -> 0xE681_3212
    //          r1[15:0] = 0x5678
    //          (r2 << 4) = 0xBCDE_F010 -> [31:16] = 0xBCDE
    //          Result r3 = 0xBCDE_5678
    // 0x20004: PKHTB r4, r1, r2, ASR #4 -> 0xE681_4252
    //          r1[31:16] = 0x1234
    //          (r2 asr 4) = 0xFABC_DEF0 -> [15:0] = 0xDEF0
    //          Result r4 = 0x1234_DEF0
    // 0x20008: MOV r7, #1               -> 0xE3A0_7001
    // 0x2000C: MOV r0, #0               -> 0xE3A0_0000
    // 0x20010: SVC 0                    -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xE681_3212).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xE681_4252).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    assert_eq!(engine.cpu.reg(Reg::R3), 0xBCDE_5678);
    assert_eq!(engine.cpu.reg(Reg::R4), 0x1234_DEF0);
}

#[test]
fn test_arm_sxtb_uxtb_sxth_uxth_sxtab() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    engine.cpu.set_reg(Reg::R1, 0x1000_0000);
    engine.cpu.set_reg(Reg::R2, 0x0000_8585);

    // Program:
    // 0x20000: SXTB r3, r2              -> 0xE6AF_3072 (sign extend 0x85 -> 0xFFFF_FF85)
    // 0x20004: UXTB r4, r2              -> 0xE6EF_4072 (zero extend 0x85 -> 0x0000_0085)
    // 0x20008: SXTH r5, r2              -> 0xE6BF_5072 (sign extend 0x8585 -> 0xFFFF_8585)
    // 0x2000C: UXTH r6, r2              -> 0xE6FF_6072 (zero extend 0x8585 -> 0x0000_8585)
    // 0x20010: SXTAB r8, r1, r2, ROR #8 -> 0xE6A1_8472 (0x1000_0000 + 0xFFFF_FF85 = 0x0FFF_FF85)
    // 0x20014: MOV r7, #1               -> 0xE3A0_7001
    // 0x20018: MOV r0, #0               -> 0xE3A0_0000
    // 0x2001C: SVC 0                    -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xE6AF_3072).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xE6EF_4072).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE6BF_5072).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE6FF_6072).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xE6A1_8472).unwrap();
    engine.mem.write_u32(code_base.add(20), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(24), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(28), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(30).unwrap();
    assert_eq!(exit_code, 0);

    assert_eq!(engine.cpu.reg(Reg::R3), 0xFFFF_FF85);
    assert_eq!(engine.cpu.reg(Reg::R4), 0x0000_0085);
    assert_eq!(engine.cpu.reg(Reg::R5), 0xFFFF_8585);
    assert_eq!(engine.cpu.reg(Reg::R6), 0x0000_8585);
    assert_eq!(engine.cpu.reg(Reg::R8), 0x0FFF_FF85);
}

#[test]
fn test_thumb_simd_media_parallel() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    engine.cpu.set_reg(Reg::R1, 0x8080_8080);
    engine.cpu.set_reg(Reg::R2, 0x8000_8000);
    engine.cpu.set_reg(Reg::R8, 0x1122_3344);
    engine.cpu.set_reg(Reg::R9, 0xAABB_CCDD);

    // Thumb instructions:
    // 0x20000: sxth r4, r2                 -> 0xB214 (Thumb-16: 0x8000 sign extended -> 0xFFFF_8000)
    // 0x20002: uxtb r5, r2                 -> 0xB2D5 (Thumb-16: 0x00 zero extended -> 0x0000_0000)
    // 0x20004: uadd8 r0, r1, r2            -> 0xFA81 0xF042 (Thumb-32: GE = 0b1010)
    // 0x20008: sel r6, r8, r9              -> 0xFAA8 0xF689 (Thumb-32: 0x11BB_33DD)
    // 0x2000C: pkhbt r3, r8, r9, lsl #4    -> 0xEAC8 0x1309 (Thumb-32)
    // 0x20010: movs r7, #1                 -> 0x2701 (Thumb-16)
    // 0x20012: movs r0, #0                 -> 0x2000 (Thumb-16)
    // 0x20014: svc 0                       -> 0xDF00 (Thumb-16)
    engine.mem.write_u16(code_base, 0xB214).unwrap();
    engine.mem.write_u16(code_base.add(2), 0xB2D5).unwrap();

    // UADD8 r0, r1, r2
    engine.mem.write_u16(code_base.add(4), 0xFA81).unwrap();
    engine.mem.write_u16(code_base.add(6), 0xF042).unwrap();

    // SEL r6, r8, r9
    engine.mem.write_u16(code_base.add(8), 0xFAA8).unwrap();
    engine.mem.write_u16(code_base.add(10), 0xF689).unwrap();

    // PKHBT r3, r8, r9, lsl #4 (imm3=1, imm2=0 -> 0x1309)
    engine.mem.write_u16(code_base.add(12), 0xEAC8).unwrap();
    engine.mem.write_u16(code_base.add(14), 0x1309).unwrap();

    engine.mem.write_u16(code_base.add(16), 0x2701).unwrap();
    engine.mem.write_u16(code_base.add(18), 0x2000).unwrap();
    engine.mem.write_u16(code_base.add(20), 0xDF00).unwrap();

    engine.cpu.set_thumb(true);
    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(30).unwrap();
    assert_eq!(exit_code, 0);

    // Verify:
    assert_eq!(engine.cpu.reg(Reg::R4), 0xFFFF_8000);
    assert_eq!(engine.cpu.reg(Reg::R5), 0x0000_0000);
    assert_eq!(engine.cpu.cpsr.ge_bits(), 0b1010);
    assert_eq!(engine.cpu.reg(Reg::R6), 0x11BB_33DD);

    // PKHBT r3, r8, r9, lsl #4:
    // r8[15:0] = 0x3344
    // (r9 << 4) = 0xABB_CCDD0 -> [31:16] = 0xABBC
    // Result = 0xABBC_3344
    assert_eq!(engine.cpu.reg(Reg::R3), 0xABBC_3344);
}
