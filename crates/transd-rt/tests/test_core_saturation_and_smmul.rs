use transd_core::{ArenaMemory, Cpsr, GuestAddr, Memory, Reg};
use transd_rt::DbtEngine;

#[test]
fn test_arm_core_saturation_qadd_qsub() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Initial register setup:
    // r1 = 0x7000_0000
    // r2 = 0x2000_0000
    engine.cpu.set_reg(Reg::R1, 0x7000_0000);
    engine.cpu.set_reg(Reg::R2, 0x2000_0000);

    // Program:
    // 0x20000: QADD r3, r1, r2    -> 0xE102_3051  (0x7000_0000 + 0x2000_0000 -> clamps to 0x7FFF_FFFF, sets Q)
    // 0x20004: QSUB r4, r1, r2    -> 0xE122_4051  (0x7000_0000 - 0x2000_0000 -> 0x5000_0000, no sat)
    // 0x20008: QDADD r5, r1, r2   -> 0xE142_5051  (2*r2 = 0x4000_0000, r1 + 0x4000_0000 -> clamps to 0x7FFF_FFFF)
    // 0x2000C: QDSUB r6, r1, r2   -> 0xE162_6051  (2*r2 = 0x4000_0000, r1 - 0x4000_0000 -> 0x3000_0000)
    // 0x20010: MOV r7, #1         -> 0xE3A0_7001
    // 0x20014: MOV r0, #0         -> 0xE3A0_0000
    // 0x20018: SVC 0              -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xE102_3051).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xE122_4051).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE142_5051).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE162_6051).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(20), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(24), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    assert_eq!(engine.cpu.reg(Reg::R3), 0x7FFF_FFFF);
    assert_eq!(engine.cpu.reg(Reg::R4), 0x5000_0000);
    assert_eq!(engine.cpu.reg(Reg::R5), 0x7FFF_FFFF);
    assert_eq!(engine.cpu.reg(Reg::R6), 0x3000_0000);
    assert!(engine.cpu.cpsr.contains(Cpsr::Q));
}

#[test]
fn test_arm_bitsat_ssat_usat() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Initial register setup:
    // r1 = 0x0005_0000 (327680)
    // r3 = 0xFFFF_63C0 (-40000)
    // r5 = 0xFFFF_FF9C (-100)
    // r7 = 300
    // r9 = 0x7FFF_8000 (hi = 32767, lo = -32768)
    // r11 = 0xFFFE_0120 (hi = -2, lo = 288)
    engine.cpu.set_reg(Reg::R1, 0x0005_0000);
    engine.cpu.set_reg(Reg::R3, 0xFFFF_63C0);
    engine.cpu.set_reg(Reg::R5, 0xFFFF_FF9C);
    engine.cpu.set_reg(Reg::R7, 300);
    engine.cpu.set_reg(Reg::R9, 0x7FFF_8000);
    engine.cpu.set_reg(Reg::R11, 0xFFFE_0120);

    // Program:
    // 0x20000: SSAT r2, #16, r1    -> 0xE6AF_2011  (327680 -> clamps to 32767 = 0x7FFF)
    // 0x20004: SSAT r4, #16, r3    -> 0xE6AF_4013  (-40000 -> clamps to -32768 = 0xFFFF_8000)
    // 0x20008: USAT r6, #8, r5     -> 0xE6E8_6015  (-100 -> clamps to 0)
    // 0x2000C: USAT r8, #8, r7     -> 0xE6E8_8017  (300 -> clamps to 255 = 0xFF)
    // 0x20010: SSAT16 r10, #8, r9  -> 0xE6A7_AF39  (32767 -> 127, -32768 -> -128 = 0x007F_FF80)
    // 0x20014: USAT16 r12, #8, r11 -> 0xE6E8_CF3B  (-2 -> 0, 288 -> 255 = 0x0000_00FF)
    // 0x20018: MOV r7, #1          -> 0xE3A0_7001
    // 0x2001C: MOV r0, #0          -> 0xE3A0_0000
    // 0x20020: SVC 0               -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xE6AF_2011).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xE6AF_4013).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE6E8_6015).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE6E8_8017).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xE6A7_AF39).unwrap();
    engine.mem.write_u32(code_base.add(20), 0xE6E8_CF3B).unwrap();
    engine.mem.write_u32(code_base.add(24), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(28), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(32), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    assert_eq!(engine.cpu.reg(Reg::R2), 0x0000_7FFF);
    assert_eq!(engine.cpu.reg(Reg::R4), 0xFFFF_8000);
    assert_eq!(engine.cpu.reg(Reg::R6), 0);
    assert_eq!(engine.cpu.reg(Reg::R8), 255);
    assert_eq!(engine.cpu.reg(Reg::R10), 0x007F_FF80);
    assert_eq!(engine.cpu.reg(Reg::R12), 0x0000_00FF);
    assert!(engine.cpu.cpsr.contains(Cpsr::Q));
}

#[test]
fn test_arm_smmul_smmla_smmls() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Initial register setup:
    // r1 = 0x3000_0000
    // r2 = 0x4000_0000
    // r4 = 10
    // r8 = 0x1000_0000
    engine.cpu.set_reg(Reg::R1, 0x3000_0000);
    engine.cpu.set_reg(Reg::R2, 0x4000_0000);
    engine.cpu.set_reg(Reg::R4, 10);
    engine.cpu.set_reg(Reg::R8, 0x1000_0000);

    // Program:
    // 0x20000: SMMUL r3, r1, r2      -> 0xE753_F211  ((r1 * r2) >> 32 = 0x0C00_0000)
    // 0x20004: SMMLA r5, r1, r2, r4  -> 0xE755_4211  (10 + 0x0C00_0000 = 0x0C00_000A)
    // 0x20008: SMMLS r6, r1, r2, r8  -> 0xE756_82D1  (0x1000_0000 - 0x0C00_0000 = 0x0400_0000)
    // 0x2000C: MOV r7, #1            -> 0xE3A0_7001
    // 0x20010: MOV r0, #0            -> 0xE3A0_0000
    // 0x20014: SVC 0                 -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xE753_F211).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xE755_4211).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE756_82D1).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(20), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    assert_eq!(engine.cpu.reg(Reg::R3), 0x0C00_0000);
    assert_eq!(engine.cpu.reg(Reg::R5), 0x0C00_000A);
    assert_eq!(engine.cpu.reg(Reg::R6), 0x0400_0000);
}

#[test]
fn test_thumb_core_saturation_and_smmul() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    engine.cpu.set_reg(Reg::R1, 0x7000_0000);
    engine.cpu.set_reg(Reg::R2, 0x2000_0000);
    engine.cpu.set_reg(Reg::R8, 0xFFFE_0120);
    engine.cpu.set_thumb(true);

    // Thumb-32 instructions:
    // 0x20000: QADD r3, r1, r2       -> hw1=0xFA82, hw2=0xF381 (0x7FFF_FFFF)
    // 0x20004: SSAT r4, #16, r1      -> hw1=0xF301, hw2=0x040F (0x7FFF)
    // 0x20008: USAT16 r6, #8, r8     -> hw1=0xF3A8, hw2=0x0608 (0x0000_00FF)
    // 0x2000C: SMMUL r5, r1, r2      -> hw1=0xFB51, hw2=0xF502 (0x0E00_0000)
    //          0x7000_0000 * 0x2000_0000 = 0x0E00_0000_0000_0000 >> 32 = 0x0E00_0000
    // 0x20010: MOVS r7, #1           -> 0x2701 (Thumb-16)
    // 0x20012: MOVS r0, #0           -> 0x2000 (Thumb-16)
    // 0x20014: SVC 0                 -> 0xDF00 (Thumb-16)

    engine.mem.write_u16(code_base, 0xFA82).unwrap();
    engine.mem.write_u16(code_base.add(2), 0xF381).unwrap();

    engine.mem.write_u16(code_base.add(4), 0xF301).unwrap();
    engine.mem.write_u16(code_base.add(6), 0x040F).unwrap();

    engine.mem.write_u16(code_base.add(8), 0xF3A8).unwrap();
    engine.mem.write_u16(code_base.add(10), 0x0608).unwrap();

    engine.mem.write_u16(code_base.add(12), 0xFB51).unwrap();
    engine.mem.write_u16(code_base.add(14), 0xF502).unwrap();

    engine.mem.write_u16(code_base.add(16), 0x2701).unwrap();
    engine.mem.write_u16(code_base.add(18), 0x2000).unwrap();
    engine.mem.write_u16(code_base.add(20), 0xDF00).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    assert_eq!(engine.cpu.reg(Reg::R3), 0x7FFF_FFFF);
    assert_eq!(engine.cpu.reg(Reg::R4), 0x0000_7FFF);
    assert_eq!(engine.cpu.reg(Reg::R6), 0x0000_00FF);
    assert_eq!(engine.cpu.reg(Reg::R5), 0x0E00_0000);
    assert!(engine.cpu.cpsr.contains(Cpsr::Q));
}
