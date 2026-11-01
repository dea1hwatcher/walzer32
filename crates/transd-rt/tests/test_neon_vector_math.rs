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

#[test]
fn test_neon_pairwise_reductions() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0xA000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Setup D0 and D1 (F32):
    // D0 = [10.0, 20.0], D1 = [30.0, 40.0]
    let d0_f: [f32; 2] = [10.0, 20.0];
    let d1_f: [f32; 2] = [30.0, 40.0];
    engine.cpu.vfp[0] = (d0_f[0].to_bits() as u64) | ((d0_f[1].to_bits() as u64) << 32);
    engine.cpu.vfp[1] = (d1_f[0].to_bits() as u64) | ((d1_f[1].to_bits() as u64) << 32);

    // Setup D5 and D6 (I32):
    // D5 = [100, -50], D6 = [200, 300]
    engine.cpu.vfp[5] = (100u32 as u64) | (((-50i32 as u32) as u64) << 32);
    engine.cpu.vfp[6] = (200u32 as u64) | ((300u32 as u64) << 32);

    // Setup D12 and D13 (I16):
    // D12 = [10, 20, 30, 40], D13 = [50, 60, 70, 80]
    let d12_h = [10u16, 20, 30, 40];
    let d13_h = [50u16, 60, 70, 80];
    let mut d12_val = 0u64;
    let mut d13_val = 0u64;
    for (i, (&h12, &h13)) in d12_h.iter().zip(d13_h.iter()).enumerate() {
        d12_val |= (h12 as u64) << (i * 16);
        d13_val |= (h13 as u64) << (i * 16);
    }
    engine.cpu.vfp[12] = d12_val;
    engine.cpu.vfp[13] = d13_val;

    // Setup D15 and D16 (I8):
    let d15_bytes: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let d16_bytes: [u8; 8] = [9, 10, 11, 12, 13, 14, 15, 16];
    engine.cpu.vfp[15] = u64::from_le_bytes(d15_bytes);
    engine.cpu.vfp[16] = u64::from_le_bytes(d16_bytes);

    // Program at 0xA000:
    // 0xA000: VPADD.F32 d2, d0, d1 -> 0xF3002D01
    // 0xA004: VPMAX.F32 d3, d0, d1 -> 0xF3003F01
    // 0xA008: VPMIN.F32 d4, d0, d1 -> 0xF3204F01
    // 0xA00C: VPADD.I32 d7, d5, d6 -> 0xF2257B16
    // 0xA010: VPMAX.S32 d8, d5, d6 -> 0xF2258A06
    // 0xA014: VPMIN.S32 d9, d5, d6 -> 0xF2259A16
    // 0xA018: VPADD.I16 d14, d12, d13 -> 0xF21CEB1D
    // 0xA01C: VPADD.I8 d17, d15, d16  -> 0xF24F1B30
    // 0xA020: MOV r7, #1          -> 0xE3A07001
    // 0xA024: MOV r0, #0          -> 0xE3A00000
    // 0xA028: SVC 0               -> 0xEF000000
    engine.mem.write_u32(code_base, 0xF300_2D01).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xF300_3F01).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xF320_4F01).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xF225_7B16).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xF225_8A06).unwrap();
    engine.mem.write_u32(code_base.add(20), 0xF225_9A16).unwrap();
    engine.mem.write_u32(code_base.add(24), 0xF21C_EB1D).unwrap();
    engine.mem.write_u32(code_base.add(28), 0xF24F_1B30).unwrap();
    engine.mem.write_u32(code_base.add(32), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(36), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(40), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(30).unwrap();
    assert_eq!(exit_code, 0);

    // Verify VPADD.F32 d2: [30.0, 70.0]
    let d2_0 = f32::from_bits((engine.cpu.vfp[2] & 0xFFFF_FFFF) as u32);
    let d2_1 = f32::from_bits((engine.cpu.vfp[2] >> 32) as u32);
    assert_eq!([d2_0, d2_1], [30.0, 70.0]);

    // Verify VPMAX.F32 d3: [20.0, 40.0]
    let d3_0 = f32::from_bits((engine.cpu.vfp[3] & 0xFFFF_FFFF) as u32);
    let d3_1 = f32::from_bits((engine.cpu.vfp[3] >> 32) as u32);
    assert_eq!([d3_0, d3_1], [20.0, 40.0]);

    // Verify VPMIN.F32 d4: [10.0, 30.0]
    let d4_0 = f32::from_bits((engine.cpu.vfp[4] & 0xFFFF_FFFF) as u32);
    let d4_1 = f32::from_bits((engine.cpu.vfp[4] >> 32) as u32);
    assert_eq!([d4_0, d4_1], [10.0, 30.0]);

    // Verify VPADD.I32 d7: [50, 500]
    let d7_0 = (engine.cpu.vfp[7] & 0xFFFF_FFFF) as u32 as i32;
    let d7_1 = (engine.cpu.vfp[7] >> 32) as u32 as i32;
    assert_eq!([d7_0, d7_1], [50, 500]);

    // Verify VPMAX.S32 d8: [100, 300]
    let d8_0 = (engine.cpu.vfp[8] & 0xFFFF_FFFF) as u32 as i32;
    let d8_1 = (engine.cpu.vfp[8] >> 32) as u32 as i32;
    assert_eq!([d8_0, d8_1], [100, 300]);

    // Verify VPMIN.S32 d9: [-50, 200]
    let d9_0 = (engine.cpu.vfp[9] & 0xFFFF_FFFF) as u32 as i32;
    let d9_1 = (engine.cpu.vfp[9] >> 32) as u32 as i32;
    assert_eq!([d9_0, d9_1], [-50, 200]);

    // Verify VPADD.I16 d14: [30, 70, 110, 150]
    let d14 = [
        (engine.cpu.vfp[14] & 0xFFFF) as u16,
        ((engine.cpu.vfp[14] >> 16) & 0xFFFF) as u16,
        ((engine.cpu.vfp[14] >> 32) & 0xFFFF) as u16,
        ((engine.cpu.vfp[14] >> 48) & 0xFFFF) as u16,
    ];
    assert_eq!(d14, [30, 70, 110, 150]);

    // Verify VPADD.I8 d17: [3, 7, 11, 15, 19, 23, 27, 31]
    let d17_bytes = engine.cpu.vfp[17].to_le_bytes();
    assert_eq!(d17_bytes, [3, 7, 11, 15, 19, 23, 27, 31]);
}

#[test]
fn test_neon_vext_extract() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0xB000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Setup D0 and D1:
    // D0 = [1, 2, 3, 4, 5, 6, 7, 8]
    // D1 = [9, 10, 11, 12, 13, 14, 15, 16]
    let d0_bytes: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let d1_bytes: [u8; 8] = [9, 10, 11, 12, 13, 14, 15, 16];
    engine.cpu.vfp[0] = u64::from_le_bytes(d0_bytes);
    engine.cpu.vfp[1] = u64::from_le_bytes(d1_bytes);

    // Setup Q2 (D4, D5) = bytes 0..15:
    let q2_lo: [u8; 8] = [10, 11, 12, 13, 14, 15, 16, 17];
    let q2_hi: [u8; 8] = [18, 19, 20, 21, 22, 23, 24, 25];
    engine.cpu.vfp[4] = u64::from_le_bytes(q2_lo);
    engine.cpu.vfp[5] = u64::from_le_bytes(q2_hi);

    // Setup Q3 (D6, D7) = bytes 16..31:
    let q3_lo: [u8; 8] = [26, 27, 28, 29, 30, 31, 32, 33];
    let q3_hi: [u8; 8] = [34, 35, 36, 37, 38, 39, 40, 41];
    engine.cpu.vfp[6] = u64::from_le_bytes(q3_lo);
    engine.cpu.vfp[7] = u64::from_le_bytes(q3_hi);

    // Program at 0xB000:
    // 0xB000: VEXT.8 d2, d0, d1, #3 -> 0xF2B02301
    // 0xB004: VEXT.8 q4, q2, q3, #6 -> 0xF2B48646 (dest Q4 = D8, D9)
    // 0xB008: MOV r7, #1          -> 0xE3A07001
    // 0xB00C: MOV r0, #0          -> 0xE3A00000
    // 0xB010: SVC 0               -> 0xEF000000
    engine.mem.write_u32(code_base, 0xF2B0_2301).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xF2B4_8646).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // Verify VEXT.8 d2, d0, d1, #3:
    // D0 = [1, 2, 3, 4, 5, 6, 7, 8], D1 = [9, 10, 11, 12, 13, 14, 15, 16]
    // Extracting at offset 3 gives: [4, 5, 6, 7, 8, 9, 10, 11]
    assert_eq!(engine.cpu.vfp[2].to_le_bytes(), [4, 5, 6, 7, 8, 9, 10, 11]);

    // Verify VEXT.8 q4, q2, q3, #6:
    // Q2 = [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]
    // Q3 = [26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41]
    // Extracting at offset 6 gives 16 bytes:
    // [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]
    assert_eq!(engine.cpu.vfp[8].to_le_bytes(), [16, 17, 18, 19, 20, 21, 22, 23]);
    assert_eq!(engine.cpu.vfp[9].to_le_bytes(), [24, 25, 26, 27, 28, 29, 30, 31]);
}

#[test]
fn test_neon_vrev_element_reversal() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0xC000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Setup Q1 (D2, D3) = [10, 20, 30, 40]
    engine.cpu.set_q_reg_u32x4(1, [10, 20, 30, 40]);

    // Setup D5 = [1, 2, 3, 4] as 16-bit
    let d5_h = [1u16, 2, 3, 4];
    let mut d5_val = 0u64;
    for (i, &h) in d5_h.iter().enumerate() {
        d5_val |= (h as u64) << (i * 16);
    }
    engine.cpu.vfp[5] = d5_val;

    // Setup D7 = [1, 2, 3, 4, 5, 6, 7, 8] as 8-bit
    let d7_bytes: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    engine.cpu.vfp[7] = u64::from_le_bytes(d7_bytes);

    // Program at 0xC000:
    // 0xC000: VREV64.32 q0, q1 -> 0xF3B8_0042 (reverses 32-bit within 64-bit words)
    // 0xC004: VREV32.16 d4, d5 -> 0xF3B4_4205 (reverses 16-bit within 32-bit words)
    // 0xC008: VREV16.8 d6, d7  -> 0xF3B0_6407 (reverses 8-bit within 16-bit words)
    // 0xC00C: MOV r7, #1       -> 0xE3A0_7001
    // 0xC010: MOV r0, #0       -> 0xE3A0_0000
    // 0xC014: SVC 0            -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xF3B8_0042).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xF3B4_4205).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xF3B0_6407).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(20), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // Verify VREV64.32 q0:
    // Input Q1 = [10, 20, 30, 40]
    // Word 0 reversed: [20, 10], Word 1 reversed: [40, 30]
    assert_eq!(engine.cpu.q_reg_u32x4(0), [20, 10, 40, 30]);

    // Verify VREV32.16 d4:
    // Input D5 = [1, 2, 3, 4]
    // Word 0 reversed: [2, 1], Word 1 reversed: [4, 3]
    let d4 = [
        (engine.cpu.vfp[4] & 0xFFFF) as u16,
        ((engine.cpu.vfp[4] >> 16) & 0xFFFF) as u16,
        ((engine.cpu.vfp[4] >> 32) & 0xFFFF) as u16,
        ((engine.cpu.vfp[4] >> 48) & 0xFFFF) as u16,
    ];
    assert_eq!(d4, [2, 1, 4, 3]);

    // Verify VREV16.8 d6:
    // Input D7 = [1, 2, 3, 4, 5, 6, 7, 8]
    // Pairs reversed: [2, 1, 4, 3, 6, 5, 8, 7]
    assert_eq!(engine.cpu.vfp[6].to_le_bytes(), [2, 1, 4, 3, 6, 5, 8, 7]);
}

#[test]
fn test_neon_vdup_lane_and_core_broadcast() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0xD000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Setup D2 = [0x1111_1111, 0x2222_2222]
    engine.cpu.vfp[2] = 0x2222_2222_1111_1111;

    // Setup R4 = 0xCAFEBABE, R5 = 0x42
    engine.cpu.set_reg(transd_core::Reg::R4, 0xCAFEBABE);
    engine.cpu.set_reg(transd_core::Reg::R5, 0x42);

    // Program at 0xD000:
    // 0xD000: VDUP.32 q0, d2[1] -> 0xF3BC_0C42
    // 0xD004: VDUP.16 d4, d2[0] -> 0xF3B2_4C02
    // 0xD008: VDUP.32 q3, r4    -> 0xEEA6_4B10
    // 0xD00C: VDUP.8 d8, r5     -> 0xEEC8_5B10
    // 0xD010: MOV r7, #1        -> 0xE3A0_7001
    // 0xD014: MOV r0, #0        -> 0xE3A0_0000
    // 0xD018: SVC 0             -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xF3BC_0C42).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xF3B2_4C02).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xEEA6_4B10).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xEEC8_5B10).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(20), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(24), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // Verify VDUP.32 q0, d2[1]:
    assert_eq!(
        engine.cpu.q_reg_u32x4(0),
        [0x2222_2222, 0x2222_2222, 0x2222_2222, 0x2222_2222]
    );

    // Verify VDUP.16 d4, d2[0]:
    let d4 = [
        (engine.cpu.vfp[4] & 0xFFFF) as u16,
        ((engine.cpu.vfp[4] >> 16) & 0xFFFF) as u16,
        ((engine.cpu.vfp[4] >> 32) & 0xFFFF) as u16,
        ((engine.cpu.vfp[4] >> 48) & 0xFFFF) as u16,
    ];
    assert_eq!(d4, [0x1111, 0x1111, 0x1111, 0x1111]);

    // Verify VDUP.32 q3, r4:
    assert_eq!(
        engine.cpu.q_reg_u32x4(3),
        [0xCAFEBABE, 0xCAFEBABE, 0xCAFEBABE, 0xCAFEBABE]
    );

    // Verify VDUP.8 d8, r5:
    assert_eq!(engine.cpu.vfp[8].to_le_bytes(), [0x42; 8]);
}

#[test]
fn test_neon_vmovn_narrowing() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0xE000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Setup Q1 (D2, D3) with 16-bit values:
    let q1_h: [u16; 8] = [0x0110, 0x0220, 0x0330, 0x0440, 0x0550, 0x0660, 0x0770, 0x0880];
    let mut d2_val = 0u64;
    let mut d3_val = 0u64;
    for (i, &h) in q1_h.iter().enumerate() {
        if i < 4 {
            d2_val |= (h as u64) << (i * 16);
        } else {
            d3_val |= (h as u64) << ((i - 4) * 16);
        }
    }
    engine.cpu.vfp[2] = d2_val;
    engine.cpu.vfp[3] = d3_val;

    // Setup Q2 (D4, D5) with 32-bit values:
    engine.cpu.set_q_reg_u32x4(2, [0x1234_5678, 0x9ABC_DEF0, 0x0FED_CBA9, 0x8765_4321]);

    // Program at 0xE000:
    // 0xE000: VMOVN.I16 d0, q1 -> 0xF3B2_0202
    // 0xE004: VMOVN.I32 d1, q2 -> 0xF3B6_1204
    // 0xE008: MOV r7, #1       -> 0xE3A0_7001
    // 0xE00C: MOV r0, #0       -> 0xE3A0_0000
    // 0xE010: SVC 0            -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xF3B2_0202).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xF3B6_1204).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // Verify VMOVN.I16 d0, q1:
    // Narrow 8x16-bit to 8x8-bit
    assert_eq!(
        engine.cpu.vfp[0].to_le_bytes(),
        [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]
    );

    // Verify VMOVN.I32 d1, q2:
    // Narrow 4x32-bit to 4x16-bit
    let d1 = [
        (engine.cpu.vfp[1] & 0xFFFF) as u16,
        ((engine.cpu.vfp[1] >> 16) & 0xFFFF) as u16,
        ((engine.cpu.vfp[1] >> 32) & 0xFFFF) as u16,
        ((engine.cpu.vfp[1] >> 48) & 0xFFFF) as u16,
    ];
    assert_eq!(d1, [0x5678, 0xDEF0, 0xCBA9, 0x4321]);
}

#[test]
fn test_neon_vmovl_and_vshll_widening() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0xF000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Setup D2 = [-10i8, 20i8, -30i8, 40i8, -50i8, 60i8, -70i8, 80i8]
    let d2_bytes = [-10i8 as u8, 20, -30i8 as u8, 40, -50i8 as u8, 60, -70i8 as u8, 80];
    engine.cpu.vfp[2] = u64::from_le_bytes(d2_bytes);

    // Setup D3 = [10u8, 20, 30, 40, 50, 60, 70, 80]
    let d3_bytes = [10u8, 20, 30, 40, 50, 60, 70, 80];
    engine.cpu.vfp[3] = u64::from_le_bytes(d3_bytes);

    // Setup D4 = [100i16, 200, 300, 400]
    let d4_h: [u16; 4] = [100, 200, 300, 400];
    let mut d4_val = 0u64;
    for (i, &h) in d4_h.iter().enumerate() {
        d4_val |= (h as u64) << (i * 16);
    }
    engine.cpu.vfp[4] = d4_val;

    // Program at 0xF000:
    // 0xF000: VMOVL.S8 q0, d2       -> 0xF288_0A12 (Q0 = D0, D1)
    // 0xF004: VMOVL.U8 q3, d3       -> 0xF388_6A13 (Q3 = D6, D7)
    // 0xF008: VSHLL.S16 q4, d4, #4  -> 0xF294_8A14 (Q4 = D8, D9)
    // 0xF00C: MOV r7, #1            -> 0xE3A0_7001
    // 0xF010: MOV r0, #0            -> 0xE3A0_0000
    // 0xF014: SVC 0                 -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xF288_0A12).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xF388_6A13).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xF294_8A14).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(20), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // Verify VMOVL.S8 q0, d2:
    let q0_h = [
        (engine.cpu.vfp[0] & 0xFFFF) as u16 as i16,
        ((engine.cpu.vfp[0] >> 16) & 0xFFFF) as u16 as i16,
        ((engine.cpu.vfp[0] >> 32) & 0xFFFF) as u16 as i16,
        ((engine.cpu.vfp[0] >> 48) & 0xFFFF) as u16 as i16,
        (engine.cpu.vfp[1] & 0xFFFF) as u16 as i16,
        ((engine.cpu.vfp[1] >> 16) & 0xFFFF) as u16 as i16,
        ((engine.cpu.vfp[1] >> 32) & 0xFFFF) as u16 as i16,
        ((engine.cpu.vfp[1] >> 48) & 0xFFFF) as u16 as i16,
    ];
    assert_eq!(q0_h, [-10, 20, -30, 40, -50, 60, -70, 80]);

    // Verify VMOVL.U8 q3, d3:
    let q3_h = [
        (engine.cpu.vfp[6] & 0xFFFF) as u16,
        ((engine.cpu.vfp[6] >> 16) & 0xFFFF) as u16,
        ((engine.cpu.vfp[6] >> 32) & 0xFFFF) as u16,
        ((engine.cpu.vfp[6] >> 48) & 0xFFFF) as u16,
        (engine.cpu.vfp[7] & 0xFFFF) as u16,
        ((engine.cpu.vfp[7] >> 16) & 0xFFFF) as u16,
        ((engine.cpu.vfp[7] >> 32) & 0xFFFF) as u16,
        ((engine.cpu.vfp[7] >> 48) & 0xFFFF) as u16,
    ];
    assert_eq!(q3_h, [10, 20, 30, 40, 50, 60, 70, 80]);

    // Verify VSHLL.S16 q4, d4, #4:
    // Inputs [100, 200, 300, 400] shifted left by 4 = [1600, 3200, 4800, 6400]
    assert_eq!(engine.cpu.q_reg_u32x4(4), [1600, 3200, 4800, 6400]);
}

#[test]
fn test_neon_vcvt_vector_int_float_conversions() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x10000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Setup Q1 (D2, D3) = [-10i32, 20i32, -500i32, 1000i32]
    engine.cpu.set_q_reg_u32x4(
        1,
        [
            -10i32 as u32,
            20i32 as u32,
            -500i32 as u32,
            1000i32 as u32,
        ],
    );

    // Setup D4 = [100u32, 50000u32]
    engine.cpu.vfp[4] = (100u64) | ((50000u64) << 32);

    // Setup Q3 (D6, D7) = [12.75f32, -45.5f32, 100.2f32, -0.9f32]
    engine.cpu.set_q_reg_u32x4(
        3,
        [
            (12.75f32).to_bits(),
            (-45.5f32).to_bits(),
            (100.2f32).to_bits(),
            (-0.9f32).to_bits(),
        ],
    );

    // Program at 0x10000:
    // 0x10000: VCVT.F32.S32 q0, q1 -> 0xF3BB_0642 (dest Q0 = D0, D1)
    // 0x10004: VCVT.F32.U32 d5, d4 -> 0xF3BB_5684 (dest D5)
    // 0x10008: VCVT.S32.F32 q4, q3 -> 0xF3BB_8746 (dest Q4 = D8, D9)
    // 0x1000C: MOV r7, #1          -> 0xE3A0_7001
    // 0x10010: MOV r0, #0          -> 0xE3A0_0000
    // 0x10014: SVC 0               -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xF3BB_0642).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xF3BB_5684).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xF3BB_8746).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(20), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // Verify VCVT.F32.S32 q0:
    let q0_words = engine.cpu.q_reg_u32x4(0);
    let q0_floats: Vec<f32> = q0_words.iter().map(|&w| f32::from_bits(w)).collect();
    assert_eq!(q0_floats, vec![-10.0, 20.0, -500.0, 1000.0]);

    // Verify VCVT.F32.U32 d5:
    let d5_0 = f32::from_bits((engine.cpu.vfp[5] & 0xFFFF_FFFF) as u32);
    let d5_1 = f32::from_bits((engine.cpu.vfp[5] >> 32) as u32);
    assert_eq!([d5_0, d5_1], [100.0, 50000.0]);

    // Verify VCVT.S32.F32 q4:
    // [12.75, -45.5, 100.2, -0.9] rounded towards zero = [12, -45, 100, 0]
    let q4_words = engine.cpu.q_reg_u32x4(4);
    let q4_ints: Vec<i32> = q4_words.iter().map(|&w| w as i32).collect();
    assert_eq!(q4_ints, vec![12, -45, 100, 0]);
}
