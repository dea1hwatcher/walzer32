use walzer32_core::{ArenaMemory, GuestAddr, Memory, Reg};
use walzer32_rt::DbtEngine;

#[test]
fn test_vpush_vpop_callee_saved_registers() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    let stack_base = GuestAddr::new(0x30000);
    arena.commit_range(code_base, 0x10000).unwrap();
    arena.commit_range(stack_base.sub(0x10000), 0x20000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Initial SP = 0x30000
    engine.cpu.set_reg(Reg::SP, stack_base.as_u32());

    // Setup callee-saved registers d8..d15 with distinct values
    let original_d: [u64; 8] = [
        0x1122_3344_5566_7788,
        0x2233_4455_6677_8899,
        0x3344_5566_7788_99AA,
        0x4455_6677_8899_AABB,
        0x5566_7788_99AA_BBCC,
        0x6677_8899_AABB_CCDD,
        0x7788_99AA_BBCC_DDEE,
        0x8899_AABB_CCDD_EEFF,
    ];
    for (i, &val) in original_d.iter().enumerate() {
        engine.cpu.vfp[8 + i] = val;
    }

    // Program:
    // 0x20000: VPUSH {d8-d15}  -> 0xED2D_8B10
    // 0x20004: MOV r7, #1      -> 0xE3A0_7001
    // 0x20008: MOV r0, #0      -> 0xE3A0_0000
    // 0x2000C: SVC 0           -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xED2D_8B10).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // Verify SP decremented by 8 * 8 = 64 bytes
    assert_eq!(engine.cpu.reg(Reg::SP), 0x30000 - 64);

    // Verify memory was written at [0x30000 - 64]
    for (i, &expected) in original_d.iter().enumerate() {
        let addr = GuestAddr::new(0x30000 - 64 + (i as u32) * 8);
        let val = engine.mem.read_u64(addr).unwrap();
        assert_eq!(val, expected, "Mismatch at d{}", 8 + i);
    }

    // Corrupt registers d8..d15
    for i in 0..8 {
        engine.cpu.vfp[8 + i] = 0xDEAD_BEEF_CAFE_BABE;
    }

    // Second Program: VPOP {d8-d15}
    // 0x20010: VPOP {d8-d15}   -> 0xECBD_8B10
    // 0x20014: MOV r7, #1      -> 0xE3A0_7001
    // 0x20018: MOV r0, #0      -> 0xE3A0_0000
    // 0x2001C: SVC 0           -> 0xEF00_0000
    let pop_base = code_base.add(16);
    engine.mem.write_u32(pop_base, 0xECBD_8B10).unwrap();
    engine.mem.write_u32(pop_base.add(4), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(pop_base.add(8), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(pop_base.add(12), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(pop_base);
    let exit_code2 = engine.run(20).unwrap();
    assert_eq!(exit_code2, 0);

    // Verify SP restored
    assert_eq!(engine.cpu.reg(Reg::SP), 0x30000);

    // Verify d8..d15 restored
    for (i, &expected) in original_d.iter().enumerate() {
        assert_eq!(engine.cpu.vfp[8 + i], expected, "Restored mismatch at d{}", 8 + i);
    }
}

#[test]
fn test_scalar_vcvt_single_double() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x21000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // S0 = PI
    engine.cpu.set_s_reg(0, std::f32::consts::PI);
    // D2 = E
    engine.cpu.set_d_reg(2, std::f64::consts::E);

    // Program:
    // 0x21000: VCVT.F64.F32 d1, s0 -> 0xEEB7_1AC0
    // 0x21004: VCVT.F32.F64 s6, d2 -> 0xEEB7_3BC2 (dst s6: d_bit=0, vd=3; src d2: vm=2)
    // 0x21008: MOV r7, #1          -> 0xE3A0_7001
    // 0x2100C: MOV r0, #0          -> 0xE3A0_0000
    // 0x21010: SVC 0               -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xEEB7_1AC0).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xEEB7_3BC2).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    let d1 = engine.cpu.d_reg(1);
    let diff1 = (d1 - std::f64::consts::PI).abs();
    assert!(diff1 < 1e-6, "d1 was {d1}");

    let s6 = engine.cpu.s_reg(6);
    let diff2 = (s6 - (std::f64::consts::E as f32)).abs();
    assert!(diff2 < 1e-5, "s6 was {s6}");
}

#[test]
fn test_scalar_vcvt_int_float() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x22000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // S0 = -42 (as raw bits)
    engine.cpu.set_s_reg_u32(0, -42i32 as u32);
    // S1 = 1000 (as raw bits)
    engine.cpu.set_s_reg_u32(1, 1000u32);
    // S4 = 99.8f32
    engine.cpu.set_s_reg(4, 99.8f32);
    // S5 = -15.9f32
    engine.cpu.set_s_reg(5, -15.9f32);
    // D4 = 12345.678f64
    engine.cpu.set_d_reg(4, 12345.678f64);

    // Program:
    // 0x22000: VCVT.F32.S32 s2, s0 -> 0xEEB8_1AC0
    // 0x22004: VCVT.F32.U32 s3, s1 -> 0xEEF8_1A60 (d_bit=1, vd=1 -> s3; m_bit=1, vm=0 -> s1)
    // 0x22008: VCVT.S32.F32 s6, s4 -> 0xEEBD_3AC2 (dst s6: d_bit=0, vd=3; src s4: m_bit=0, vm=2)
    // 0x2200C: VCVT.S32.F32 s7, s5 -> 0xEEFD_3AE2 (dst s7: d_bit=1, vd=3; src s5: m_bit=1, vm=2)
    // 0x22010: VCVT.S32.F64 s8, d4 -> 0xEEBD_4BC4 (dst s8: d_bit=0, vd=4; src d4: m_bit=0, vm=4)
    // 0x22014: MOV r7, #1          -> 0xE3A0_7001
    // 0x22018: MOV r0, #0          -> 0xE3A0_0000
    // 0x2201C: SVC 0               -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xEEB8_1AC0).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xEEF8_1A60).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xEEBD_3AC2).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xEEFD_3AE2).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xEEBD_4BC4).unwrap();
    engine.mem.write_u32(code_base.add(20), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(24), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(28), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    assert_eq!(engine.cpu.s_reg(2), -42.0f32);
    assert_eq!(engine.cpu.s_reg(3), 1000.0f32);
    assert_eq!(engine.cpu.s_reg_u32(6) as i32, 99);
    assert_eq!(engine.cpu.s_reg_u32(7) as i32, -15);
    assert_eq!(engine.cpu.s_reg_u32(8) as i32, 12345);
}

#[test]
fn test_thumb2_vpush_vpop_and_vcvt() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x23000);
    let stack_base = GuestAddr::new(0x40000);
    arena.commit_range(code_base, 0x10000).unwrap();
    arena.commit_range(stack_base.sub(0x10000), 0x20000).unwrap();

    let mut engine = DbtEngine::new(arena);
    engine.cpu.set_thumb(true);
    engine.cpu.set_reg(Reg::SP, stack_base.as_u32());

    // Setup D8..D10
    engine.cpu.vfp[8] = 0xAAAA_BBBB_CCCC_DDDD;
    engine.cpu.vfp[9] = 0x1111_2222_3333_4444;
    engine.cpu.vfp[10] = 0x5555_6666_7777_8888;

    // S0 = 123.456f32
    engine.cpu.set_s_reg(0, 123.456f32);

    // Thumb-2 instructions:
    // 0x23000: VPUSH {d8-d10}       -> hi=0xED2D, lo=0x8B06 (count 3 D-regs = 6)
    // 0x23004: VCVT.F64.F32 d0, s0   -> hi=0xEEB7, lo=0x0AC0
    // 0x23008: MOVS r7, #1          -> 0x2701 (16-bit Thumb)
    // 0x2300A: MOVS r0, #0          -> 0x2000 (16-bit Thumb)
    // 0x2300C: SVC 0                -> 0xDF00 (16-bit Thumb)
    let p_vpush = (0x8B06u32 << 16) | 0xED2Du32;
    let p_vcvt = (0x0AC0u32 << 16) | 0xEEB7u32;
    engine.mem.write_u32(code_base, p_vpush).unwrap();
    engine.mem.write_u32(code_base.add(4), p_vcvt).unwrap();
    engine.mem.write_u16(code_base.add(8), 0x2701).unwrap();
    engine.mem.write_u16(code_base.add(10), 0x2000).unwrap();
    engine.mem.write_u16(code_base.add(12), 0xDF00).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // SP decremented by 3 * 8 = 24 bytes
    assert_eq!(engine.cpu.reg(Reg::SP), 0x40000 - 24);

    // D0 holds converted double
    let d0 = engine.cpu.d_reg(0);
    assert!((d0 - 123.456f64).abs() < 1e-4);
}
