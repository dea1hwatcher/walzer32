use transd_core::{ArenaMemory, GuestAddr, Memory, Reg};
use transd_rt::DbtEngine;

#[test]
fn test_arm_vmov_two_core_double() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Initial register setup:
    // r1 = 0x1122_3344, r2 = 0x5566_7788
    engine.cpu.set_reg(Reg::R1, 0x1122_3344);
    engine.cpu.set_reg(Reg::R2, 0x5566_7788);

    // Program:
    // 0x20000: VMOV D1, R1, R2  -> 0xEC42_1B11
    // 0x20004: VMOV R3, R4, D1  -> 0xEC54_3B11
    // 0x20008: MOV R7, #1       -> 0xE3A0_7001
    // 0x2000C: MOV R0, #0       -> 0xE3A0_0000
    // 0x20010: SVC 0            -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xEC42_1B11).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xEC54_3B11).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // Verify VFP D1 and core registers R3, R4
    assert_eq!(engine.cpu.d_reg_u64(1), 0x5566_7788_1122_3344);
    assert_eq!(engine.cpu.reg(Reg::R3), 0x1122_3344);
    assert_eq!(engine.cpu.reg(Reg::R4), 0x5566_7788);
}

#[test]
fn test_arm_vmov_two_core_singles() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Initial register setup:
    // r1 = 0xAABB_CCDD, r2 = 0x1234_5678
    engine.cpu.set_reg(Reg::R1, 0xAABB_CCDD);
    engine.cpu.set_reg(Reg::R2, 0x1234_5678);

    // Program:
    // 0x20000: VMOV S4, S5, R1, R2 -> 0xEC42_1A12
    // 0x20004: VMOV R5, R6, S4, S5 -> 0xEC56_5A12
    // 0x20008: MOV R7, #1          -> 0xE3A0_7001
    // 0x2000C: MOV R0, #0          -> 0xE3A0_0000
    // 0x20010: SVC 0               -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xEC42_1A12).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xEC56_5A12).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // Verify VFP S4, S5 and core registers R5, R6
    assert_eq!(engine.cpu.s_reg_u32(4), 0xAABB_CCDD);
    assert_eq!(engine.cpu.s_reg_u32(5), 0x1234_5678);
    assert_eq!(engine.cpu.reg(Reg::R5), 0xAABB_CCDD);
    assert_eq!(engine.cpu.reg(Reg::R6), 0x1234_5678);
}

#[test]
fn test_arm_umaal() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Initial register setup:
    // r1 = 0x1234_5678, r2 = 0x10
    // r3 = 0x1000, r4 = 0x2
    engine.cpu.set_reg(Reg::R1, 0x1234_5678);
    engine.cpu.set_reg(Reg::R2, 0x10);
    engine.cpu.set_reg(Reg::R3, 0x1000);
    engine.cpu.set_reg(Reg::R4, 0x2);

    // Program:
    // 0x20000: UMAAL R3, R4, R1, R2 -> 0xE044_3291
    // 0x20004: MOV R7, #1           -> 0xE3A0_7001
    // 0x20008: MOV R0, #0           -> 0xE3A0_0000
    // 0x2000C: SVC 0                -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xE044_3291).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // UMAAL computes: (Rn * Rm) + RdLo + RdHi
    // 0x1234_5678 * 16 + 0x1000 + 2 = 0x1_2345_6780 + 0x1002 = 0x1_2345_7782
    assert_eq!(engine.cpu.reg(Reg::R3), 0x2345_7782);
    assert_eq!(engine.cpu.reg(Reg::R4), 0x0000_0001);
}

#[test]
fn test_arm_dsp_multiplies() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Initial register setup:
    // r1 = 0x7FFF_0003 (high = 32767, low = 3)
    // r2 = 0x0004_FFFE (high = 4, low = -2)
    // r4 = 100
    engine.cpu.set_reg(Reg::R1, 0x7FFF_0003);
    engine.cpu.set_reg(Reg::R2, 0x0004_FFFE);
    engine.cpu.set_reg(Reg::R4, 100);

    // Program:
    // 0x20000: SMULBB R3, R1, R2      -> 0xE163_0281  (3 * -2 = -6)
    // 0x20004: SMULTT R5, R1, R2      -> 0xE165_02E1  (32767 * 4 = 131068)
    // 0x20008: SMLABB R6, R1, R2, R4  -> 0xE106_4281  (-6 + 100 = 94)
    // 0x2000C: SMULWB R8, R1, R2      -> 0xE128_02A1  ((R1 * -2) >> 16 = -65535)
    // 0x20010: SMLAWB R14, R1, R2, R4 -> 0xE12E_4281  (-65535 + 100 = -65435)
    // 0x20014: SMUAD R9, R1, R2       -> 0xE709_F211  (3*-2 + 32767*4 = 131062)
    // 0x20018: SMUSD R10, R1, R2      -> 0xE70A_F251  (3*-2 - 32767*4 = -131074)
    // 0x2001C: SMLAD R11, R1, R2, R4  -> 0xE70B_4211  (131062 + 100 = 131162)
    // 0x20020: SMLSD R12, R1, R2, R4  -> 0xE70C_4251  (-131074 + 100 = -130974)
    // 0x20024: MOV R7, #1             -> 0xE3A0_7001
    // 0x20028: MOV R0, #0             -> 0xE3A0_0000
    // 0x2002C: SVC 0                  -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xE163_0281).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xE165_02E1).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE106_4281).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE128_02A1).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xE12E_4281).unwrap();
    engine.mem.write_u32(code_base.add(20), 0xE709_F211).unwrap();
    engine.mem.write_u32(code_base.add(24), 0xE70A_F251).unwrap();
    engine.mem.write_u32(code_base.add(28), 0xE70B_4211).unwrap();
    engine.mem.write_u32(code_base.add(32), 0xE70C_4251).unwrap();
    engine.mem.write_u32(code_base.add(36), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(40), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(44), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(25).unwrap();
    assert_eq!(exit_code, 0);

    assert_eq!(engine.cpu.reg(Reg::R3), (-6i32) as u32);
    assert_eq!(engine.cpu.reg(Reg::R5), 131068);
    assert_eq!(engine.cpu.reg(Reg::R6), 94);
    assert_eq!(engine.cpu.reg(Reg::R8), (-65535i32) as u32);
    assert_eq!(engine.cpu.reg(Reg::LR), (-65435i32) as u32);
    assert_eq!(engine.cpu.reg(Reg::R9), 131062);
    assert_eq!(engine.cpu.reg(Reg::R10), (-131074i32) as u32);
    assert_eq!(engine.cpu.reg(Reg::R11), 131162);
    assert_eq!(engine.cpu.reg(Reg::R12), (-130974i32) as u32);
}

#[test]
fn test_thumb_vmov_two_core_and_dsp_mul() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    engine.cpu.set_reg(Reg::R1, 0x1122_3344);
    engine.cpu.set_reg(Reg::R2, 0x5566_7788);
    engine.cpu.set_thumb(true);

    // 0x20000: VMOV D2, R1, R2 (hw1=0xEC42, hw2=0x1B12)
    // 0x20004: VMOV R3, R4, D2 (hw1=0xEC54, hw2=0x3B12)
    // 0x20008: UMAAL R1, R2, R3, R4 (hw1=0xFBE3, hw2=0x1264)
    //          r1 = 0x1122_3344, r2 = 0x5566_7788, r3 = 0x1122_3344, r4 = 0x5566_7788
    // 0x2000C: MOVS R7, #1     -> 0x2701 (Thumb-16)
    // 0x2000E: MOVS R0, #0     -> 0x2000 (Thumb-16)
    // 0x20010: SVC 0           -> 0xDF00 (Thumb-16)

    // Write Thumb instructions (little-endian 16-bit halfwords)
    engine.mem.write_u16(code_base, 0xEC42).unwrap();
    engine.mem.write_u16(code_base.add(2), 0x1B12).unwrap();

    engine.mem.write_u16(code_base.add(4), 0xEC54).unwrap();
    engine.mem.write_u16(code_base.add(6), 0x3B12).unwrap();

    engine.mem.write_u16(code_base.add(8), 0xFBE3).unwrap();
    engine.mem.write_u16(code_base.add(10), 0x1264).unwrap();

    engine.mem.write_u16(code_base.add(12), 0x2701).unwrap();
    engine.mem.write_u16(code_base.add(14), 0x2000).unwrap();
    engine.mem.write_u16(code_base.add(16), 0xDF00).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // Verify D2 was written
    assert_eq!(engine.cpu.d_reg_u64(2), 0x5566_7788_1122_3344);
    assert_eq!(engine.cpu.reg(Reg::R3), 0x1122_3344);
    assert_eq!(engine.cpu.reg(Reg::R4), 0x5566_7788);

    // Verify UMAAL:
    // rn = r3 = 0x1122_3344, rm = r4 = 0x5566_7788
    // acc_lo = r1 = 0x1122_3344, acc_hi = r2 = 0x5566_7788
    let prod = (0x1122_3344u64) * (0x5566_7788u64);
    let total = prod + 0x1122_3344u64 + 0x5566_7788u64;
    assert_eq!(engine.cpu.reg(Reg::R1), (total & 0xFFFF_FFFF) as u32);
    assert_eq!(engine.cpu.reg(Reg::R2), (total >> 32) as u32);
}
