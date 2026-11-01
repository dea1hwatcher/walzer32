use transd_core::{ArenaMemory, Cpsr, GuestAddr, Memory};
use transd_rt::DbtEngine;

#[test]
fn test_neon_matrix_vector_dot_product() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x1000);
    let data_base = GuestAddr::new(0x2000);

    arena.commit_range(code_base, 0x10000).unwrap();

    // Setup input vectors at 0x2000 and 0x2010:
    // Vec A: [1.5, 2.5, 3.5, 4.5]
    let vec_a = [1.5f32, 2.5, 3.5, 4.5];
    for (i, val) in vec_a.iter().enumerate() {
        arena.write_u32(data_base.add(i as u32 * 4), val.to_bits()).unwrap();
    }
    // Vec B: [2.0, 4.0, 6.0, 8.0]
    let vec_b = [2.0f32, 4.0, 6.0, 8.0];
    for (i, val) in vec_b.iter().enumerate() {
        arena.write_u32(data_base.add(16 + i as u32 * 4), val.to_bits()).unwrap();
    }

    // Program at 0x1000:
    // 0x1000: MOV r0, #0x2000          (0xE3A0_0C20)
    // 0x1004: VLD1.8 {d0, d1}, [r0]    (0xF420_0A00) -> Q0
    // 0x1008: MOV r1, #0x2010          (0xE3A0_1C20 | 0x10) -> (0xE3A0_1C20 then ADD r1, #16 -> 0xE281_1010)
    // 0x100C: VLD1.8 {d2, d3}, [r1]    (0xF421_2A00) -> Q1
    // 0x1010: VMUL.F32 Q2, Q0, Q1      (0xF300_4D52) -> Q2 = [3.0, 10.0, 21.0, 36.0]
    // 0x1014: VMLA.F32 Q2, Q0, Q1      (0xF200_4D52) -> Q2 += [3.0, 10.0, 21.0, 36.0] => [6.0, 20.0, 42.0, 72.0]
    // 0x1018: MOV r2, #0x2020          (0xE3A0_2C20 then ADD r2, #32 -> 0xE282_2020)
    // 0x101C: VST1.8 {d4, d5}, [r2]    (0xF402_4A00) -> Store Q2
    // 0x1020: MOV r7, #1               (0xE3A0_7001)
    // 0x1024: MOV r0, #0               (0xE3A0_0000)
    // 0x1028: SVC 0                    (0xEF00_0000)
    arena.write_u32(code_base, 0xE3A0_0C20).unwrap();
    arena.write_u32(code_base.add(4), 0xF420_0A00).unwrap();
    arena.write_u32(code_base.add(8), 0xE3A0_1C20).unwrap();
    arena.write_u32(code_base.add(12), 0xE281_1010).unwrap();
    arena.write_u32(code_base.add(16), 0xF421_2A00).unwrap();
    arena.write_u32(code_base.add(20), 0xF300_4D52).unwrap();
    arena.write_u32(code_base.add(24), 0xF200_4D52).unwrap();
    arena.write_u32(code_base.add(28), 0xE3A0_2C20).unwrap();
    arena.write_u32(code_base.add(32), 0xE282_2020).unwrap();
    arena.write_u32(code_base.add(36), 0xF402_4A00).unwrap();
    arena.write_u32(code_base.add(40), 0xE3A0_7001).unwrap();
    arena.write_u32(code_base.add(44), 0xE3A0_0000).unwrap();
    arena.write_u32(code_base.add(48), 0xEF00_0000).unwrap();

    let mut engine = DbtEngine::new(arena);
    engine.cpu.set_pc(code_base);

    let exit_code = engine.run(50).unwrap();
    assert_eq!(exit_code, 0);

    // Verify Q0, Q1, Q2 in CPU state
    assert_eq!(engine.cpu.q_reg_f32x4(0), [1.5, 2.5, 3.5, 4.5]);
    assert_eq!(engine.cpu.q_reg_f32x4(1), [2.0, 4.0, 6.0, 8.0]);
    assert_eq!(engine.cpu.q_reg_f32x4(2), [6.0, 20.0, 42.0, 72.0]);

    // Verify memory output at 0x2020
    let mut out = [0.0f32; 4];
    for (i, slot) in out.iter_mut().enumerate() {
        let bits = engine.mem.read_u32(data_base.add(32 + i as u32 * 4)).unwrap();
        *slot = f32::from_bits(bits);
    }
    assert_eq!(out, [6.0, 20.0, 42.0, 72.0]);
}

#[test]
fn test_neon_min_max_and_abs_neg() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x3000);
    arena.commit_range(code_base, 0x10000).unwrap();

    // Preset Q0 and Q1 directly
    // Q0 = [-5.0, 12.0, -0.5, 100.0]
    // Q1 = [3.0, -15.0, 0.5, 50.0]
    let mut engine = DbtEngine::new(arena);
    engine.cpu.set_q_reg_f32x4(0, [-5.0, 12.0, -0.5, 100.0]);
    engine.cpu.set_q_reg_f32x4(1, [3.0, -15.0, 0.5, 50.0]);

    // Program at 0x3000:
    // 0x3000: VMAX.F32 Q2, Q0, Q1 -> 0xF200_4F42 (Q2 = [3.0, 12.0, 0.5, 100.0])
    // 0x3004: VMIN.F32 Q3, Q0, Q1 -> 0xF220_6F42 (Q3 = [-5.0, -15.0, -0.5, 50.0])
    // 0x3008: VABS.F32 Q4, Q3     -> 0xF3B9_8746 (Q4 = [5.0, 15.0, 0.5, 50.0])
    // 0x300C: VNEG.F32 Q5, Q2     -> 0xF3B9_A7C4 (Q5 = [-3.0, -12.0, -0.5, -100.0])
    // 0x3010: MOV r7, #1          -> 0xE3A0_7001
    // 0x3014: MOV r0, #42         -> 0xE3A0_002A
    // 0x3018: SVC 0               -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xF200_4F42).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xF220_6F42).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xF3B9_8746).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xF3B9_A7C4).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(20), 0xE3A0_002A).unwrap();
    engine.mem.write_u32(code_base.add(24), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(30).unwrap();
    assert_eq!(exit_code, 42);

    assert_eq!(engine.cpu.q_reg_f32x4(2), [3.0, 12.0, 0.5, 100.0]);
    assert_eq!(engine.cpu.q_reg_f32x4(3), [-5.0, -15.0, -0.5, 50.0]);
    assert_eq!(engine.cpu.q_reg_f32x4(4), [5.0, 15.0, 0.5, 50.0]);
    assert_eq!(engine.cpu.q_reg_f32x4(5), [-3.0, -12.0, -0.5, -100.0]);
}

#[test]
fn test_neon_thumb2_vector_math() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x5000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);
    engine.cpu.set_q_reg_f32x4(0, [2.0, 3.0, 4.0, 5.0]);
    engine.cpu.set_q_reg_f32x4(1, [10.0, 20.0, 30.0, 40.0]);

    // Thumb-2 instructions at 0x5000:
    // 0x5000: VADD.F32 Q2, Q0, Q1 (hi=0xEF00, lo=0x4D42) -> [12.0, 23.0, 34.0, 45.0]
    // 0x5004: VSUB.F32 Q3, Q1, Q0 (hi=0xEF22, lo=0x6D40) -> [8.0, 17.0, 26.0, 35.0]
    // 0x5008: MOVS r7, #1         (0x2701, 16-bit Thumb)
    // 0x500A: MOVS r0, #0         (0x2000, 16-bit Thumb)
    // 0x500C: SVC 0               (0xDF00, 16-bit Thumb)
    engine.mem.write_u16(code_base, 0xEF00).unwrap();
    engine.mem.write_u16(code_base.add(2), 0x4D42).unwrap();
    engine.mem.write_u16(code_base.add(4), 0xEF22).unwrap();
    engine.mem.write_u16(code_base.add(6), 0x6D40).unwrap();
    engine.mem.write_u16(code_base.add(8), 0x2701).unwrap();
    engine.mem.write_u16(code_base.add(10), 0x2000).unwrap();
    engine.mem.write_u16(code_base.add(12), 0xDF00).unwrap();

    // Set CPSR Thumb bit and PC
    engine.cpu.cpsr.insert(Cpsr::T);
    engine.cpu.set_pc(code_base);

    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    assert_eq!(engine.cpu.q_reg_f32x4(2), [12.0, 23.0, 34.0, 45.0]);
    assert_eq!(engine.cpu.q_reg_f32x4(3), [8.0, 17.0, 26.0, 35.0]);
}

#[test]
fn test_neon_vtrn_vzip_vuzp_matrix_transpose() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x6000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Q0 = [1, 2, 3, 4], Q1 = [10, 20, 30, 40]
    engine.cpu.set_q_reg_u32x4(0, [1, 2, 3, 4]);
    engine.cpu.set_q_reg_u32x4(1, [10, 20, 30, 40]);

    // Q2 = [1, 2, 3, 4], Q3 = [10, 20, 30, 40]
    engine.cpu.set_q_reg_u32x4(2, [1, 2, 3, 4]);
    engine.cpu.set_q_reg_u32x4(3, [10, 20, 30, 40]);

    // Q4 = [1, 2, 3, 4], Q5 = [10, 20, 30, 40]
    engine.cpu.set_q_reg_u32x4(4, [1, 2, 3, 4]);
    engine.cpu.set_q_reg_u32x4(5, [10, 20, 30, 40]);

    // Program at 0x6000:
    // 0x6000: VTRN.32 q0, q1 -> 0xF3BA00C2
    // 0x6004: VZIP.32 q2, q3 -> 0xF3BA41C6
    // 0x6008: VUZP.32 q4, q5 -> 0xF3BA814A
    // 0x600C: MOV r7, #1     -> 0xE3A07001
    // 0x6010: MOV r0, #0     -> 0xE3A00000
    // 0x6014: SVC 0          -> 0xEF000000
    engine.mem.write_u32(code_base, 0xF3BA_00C2).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xF3BA_41C6).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xF3BA_814A).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(20), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // VTRN.32: Transpose 2x2 blocks
    assert_eq!(engine.cpu.q_reg_u32x4(0), [1, 10, 3, 30]);
    assert_eq!(engine.cpu.q_reg_u32x4(1), [2, 20, 4, 40]);

    // VZIP.32: Interleave lower and upper halves
    assert_eq!(engine.cpu.q_reg_u32x4(2), [1, 10, 2, 20]);
    assert_eq!(engine.cpu.q_reg_u32x4(3), [3, 30, 4, 40]);

    // VUZP.32: De-interleave even and odd elements
    assert_eq!(engine.cpu.q_reg_u32x4(4), [1, 3, 10, 30]);
    assert_eq!(engine.cpu.q_reg_u32x4(5), [2, 4, 20, 40]);
}

#[test]
fn test_neon_vtbl_and_vtbx_table_lookup() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x7000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Setup table in D2 and D3:
    // D2 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]
    // D3 = [0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00]
    let d2_bytes: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
    let d3_bytes: [u8; 8] = [0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00];
    engine.cpu.vfp[2] = u64::from_le_bytes(d2_bytes);
    engine.cpu.vfp[3] = u64::from_le_bytes(d3_bytes);

    // Index vector in D1: [1, 0, 7, 15, 8, 20, 2, 255]
    let d1_bytes: [u8; 8] = [1, 0, 7, 15, 8, 20, 2, 255];
    engine.cpu.vfp[1] = u64::from_le_bytes(d1_bytes);

    // Second index vector in D4 for VTBX: [0, 20, 20, 20, 20, 20, 20, 3]
    let d4_bytes: [u8; 8] = [0, 20, 20, 20, 20, 20, 20, 3];
    engine.cpu.vfp[4] = u64::from_le_bytes(d4_bytes);

    // Program at 0x7000:
    // 0x7000: VTBL.8 d0, {d2, d3}, d1 -> 0xF3B20901
    // 0x7004: VTBX.8 d0, {d2, d3}, d4 -> 0xF3B20944
    // 0x7008: MOV r7, #1             -> 0xE3A07001
    // 0x700C: MOV r0, #0             -> 0xE3A00000
    // 0x7010: SVC 0                  -> 0xEF000000
    engine.mem.write_u32(code_base, 0xF3B2_0901).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xF3B2_0944).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // After VTBL:
    // [0xBB, 0xAA, 0x22, 0x00, 0x33, 0x00, 0xCC, 0x00]
    // After VTBX with [0, 20, 20, 20, 20, 20, 20, 3]:
    // slot 0 gets table[0] = 0xAA
    // slots 1..6 had index 20 (OOB) so they retain VTBL output: [0xAA, 0x22, 0x00, 0x33, 0x00, 0xCC]
    // slot 7 gets table[3] = 0xDD
    let expected_d0: [u8; 8] = [0xAA, 0xAA, 0x22, 0x00, 0x33, 0x00, 0xCC, 0xDD];
    assert_eq!(engine.cpu.vfp[0].to_le_bytes(), expected_d0);
}

#[test]
fn test_neon_saturating_math_and_shifts() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x8000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Q0 = [i32::MAX - 5, -100, 50, 0]
    // Q1 = [10, -50, -200, i32::MIN]
    let q0_u32: [u32; 4] = [
        (i32::MAX - 5) as u32,
        (-100i32) as u32,
        50u32,
        0u32,
    ];
    let q1_u32: [u32; 4] = [
        10u32,
        (-50i32) as u32,
        (-200i32) as u32,
        i32::MIN as u32,
    ];
    engine.cpu.set_q_reg_u32x4(0, q0_u32);
    engine.cpu.set_q_reg_u32x4(1, q1_u32);

    // Program at 0x8000:
    // 0x8000: VQADD.S32 q2, q0, q1   -> 0xF2204052
    // 0x8004: VQSUB.U32 q3, q0, q1   -> 0xF3206252
    // 0x8008: VQSHL.S32 q4, q0, #2   -> 0xF2A28750
    // 0x800C: VQSHRN.S32 d10, q0, #8 -> 0xF298A910
    // 0x8010: MOV r7, #1             -> 0xE3A07001
    // 0x8014: MOV r0, #0             -> 0xE3A00000
    // 0x8018: SVC 0                  -> 0xEF000000
    engine.mem.write_u32(code_base, 0xF220_4052).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xF320_6252).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xF2A2_8750).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xF298_A910).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(20), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(24), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // Verify VQADD.S32:
    assert_eq!(
        engine.cpu.q_reg_u32x4(2),
        [i32::MAX as u32, (-150i32) as u32, (-150i32) as u32, i32::MIN as u32]
    );

    // Verify VQSUB.U32:
    assert_eq!(
        engine.cpu.q_reg_u32x4(3),
        [0x7FFF_FFF0, 0, 0, 0]
    );

    // Verify VQSHL.S32 #2:
    assert_eq!(
        engine.cpu.q_reg_u32x4(4),
        [i32::MAX as u32, (-400i32) as u32, 200, 0]
    );

    // Verify VQSHRN.S32 #8 into D10:
    assert_eq!(engine.cpu.vfp[10], 0xFFFF_7FFF);
}

#[test]
fn test_neon_polynomial_multiply_pmull() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x9000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Setup input vectors D0 and D1:
    let d0_bytes: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let d1_bytes: [u8; 8] = [2, 3, 4, 5, 6, 7, 8, 9];
    engine.cpu.vfp[0] = u64::from_le_bytes(d0_bytes);
    engine.cpu.vfp[1] = u64::from_le_bytes(d1_bytes);

    // Program at 0x9000:
    // 0x9000: VMULL.P8 q5, d0, d1 -> 0xF280AE01
    // 0x9004: MOV r7, #1          -> 0xE3A07001
    // 0x9008: MOV r0, #0          -> 0xE3A00000
    // 0x900C: SVC 0               -> 0xEF000000
    engine.mem.write_u32(code_base, 0xF280_AE01).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // Q5 consists of D10 and D11:
    // Expected: [0x14000c00060002, 0x4800380012001e]
    assert_eq!(engine.cpu.vfp[10], 0x0014_000C_0006_0002);
    assert_eq!(engine.cpu.vfp[11], 0x0048_0038_0012_001E);
}
