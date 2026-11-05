use walzer32_core::{ArenaMemory, GuestAddr, Memory, Reg};
use walzer32_rt::DbtEngine;

#[test]
fn test_neon_vld2_vst2_interleaved_pairs() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    let in_data = GuestAddr::new(0x30000);
    let out_data = GuestAddr::new(0x31000);

    arena.commit_range(code_base, 0x10000).unwrap();
    arena.commit_range(in_data, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Prepare 16 bytes of interleaved pairs: (0x10, 0x20), (0x11, 0x21), ..., (0x17, 0x27)
    let original: [u8; 16] = [
        0x10, 0x20, 0x11, 0x21, 0x12, 0x22, 0x13, 0x23,
        0x14, 0x24, 0x15, 0x25, 0x16, 0x26, 0x17, 0x27,
    ];
    for (i, &b) in original.iter().enumerate() {
        engine.mem.write_u8(in_data.add(i as u32), b).unwrap();
    }

    engine.cpu.set_reg(Reg::R0, in_data.as_u32());
    engine.cpu.set_reg(Reg::R1, out_data.as_u32());

    // Instructions:
    // 0x20000: VLD2.8 {d0, d1}, [r0]!  -> 0xF420_080D
    // 0x20004: VST2.8 {d0, d1}, [r1]!  -> 0xF401_080D
    // 0x20008: MOV r7, #1              -> 0xE3A0_7001
    // 0x2000C: MOV r0, #0              -> 0xE3A0_0000
    // 0x20010: SVC 0                   -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xF420_080D).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xF401_080D).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // Verify registers:
    // d0 should hold all 8 element 0s: 0x10..0x17 -> in little endian: 0x1716_1514_1312_1110
    // d1 should hold all 8 element 1s: 0x20..0x27 -> in little endian: 0x2726_2524_2322_2120
    assert_eq!(engine.cpu.vfp[0], 0x1716_1514_1312_1110);
    assert_eq!(engine.cpu.vfp[1], 0x2726_2524_2322_2120);

    // Verify post-increment writeback on r1 (transferred 16 bytes)
    assert_eq!(engine.cpu.reg(Reg::R1), out_data.as_u32() + 16);

    // Verify interleaved data written to out_data
    for i in 0..16 {
        let val = engine.mem.read_u8(out_data.add(i as u32)).unwrap();
        assert_eq!(val, original[i], "Mismatch at byte {}", i);
    }
}

#[test]
fn test_neon_vld3_vst3_rgb_channels() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    let in_data = GuestAddr::new(0x40000);
    let out_data = GuestAddr::new(0x41000);

    arena.commit_range(code_base, 0x10000).unwrap();
    arena.commit_range(in_data, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // 24 bytes of 8 RGB triples
    let mut rgb_original = [0u8; 24];
    for i in 0..8 {
        rgb_original[i * 3] = (0x10 + i) as u8;     // R
        rgb_original[i * 3 + 1] = (0x50 + i) as u8; // G
        rgb_original[i * 3 + 2] = (0x90 + i) as u8; // B
    }
    for (i, &b) in rgb_original.iter().enumerate() {
        engine.mem.write_u8(in_data.add(i as u32), b).unwrap();
    }

    engine.cpu.set_reg(Reg::R0, in_data.as_u32());
    engine.cpu.set_reg(Reg::R1, out_data.as_u32());

    // 0x20000: VLD3.8 {d0, d1, d2}, [r0]! -> 0xF420_040D
    // 0x20004: VST3.8 {d0, d1, d2}, [r1]! -> 0xF401_040D
    // 0x20008: MOV r7, #1                 -> 0xE3A0_7001
    // 0x2000C: MOV r0, #0                 -> 0xE3A0_0000
    // 0x20010: SVC 0                      -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xF420_040D).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xF401_040D).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // Verify de-interleaving into d0 (R), d1 (G), d2 (B)
    assert_eq!(engine.cpu.vfp[0], 0x1716_1514_1312_1110);
    assert_eq!(engine.cpu.vfp[1], 0x5756_5554_5352_5150);
    assert_eq!(engine.cpu.vfp[2], 0x9796_9594_9392_9190);

    // Verify out_data contains exact reconstructed RGB stream
    for i in 0..24 {
        let val = engine.mem.read_u8(out_data.add(i as u32)).unwrap();
        assert_eq!(val, rgb_original[i], "Mismatch at RGB byte {}", i);
    }
}

#[test]
fn test_neon_vld4_vst4_rgba_and_16bit() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    let in_rgba = GuestAddr::new(0x50000);
    let out_rgba = GuestAddr::new(0x51000);
    let in_audio = GuestAddr::new(0x52000);

    arena.commit_range(code_base, 0x10000).unwrap();
    arena.commit_range(in_rgba, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // 32 bytes of RGBA (8 pixels)
    let mut rgba_original = [0u8; 32];
    for i in 0..8 {
        rgba_original[i * 4] = 0xAA;     // R
        rgba_original[i * 4 + 1] = 0xBB; // G
        rgba_original[i * 4 + 2] = 0xCC; // B
        rgba_original[i * 4 + 3] = 0xFF; // A
    }
    for (i, &b) in rgba_original.iter().enumerate() {
        engine.mem.write_u8(in_rgba.add(i as u32), b).unwrap();
    }

    // 16 bytes of 4 16-bit stereo samples: (0x1001, 0x2001), (0x1002, 0x2002), ...
    for i in 0..4 {
        let left: u16 = 0x1000 + i + 1;
        let right: u16 = 0x2000 + i + 1;
        engine.mem.write_u16(in_audio.add((i * 4) as u32), left).unwrap();
        engine.mem.write_u16(in_audio.add((i * 4 + 2) as u32), right).unwrap();
    }

    engine.cpu.set_reg(Reg::R0, in_rgba.as_u32());
    engine.cpu.set_reg(Reg::R1, out_rgba.as_u32());
    engine.cpu.set_reg(Reg::R2, in_audio.as_u32());

    // 0x20000: VLD4.8 {d0, d1, d2, d3}, [r0]! -> 0xF420_000D
    // 0x20004: VST4.8 {d0, d1, d2, d3}, [r1]  -> 0xF401_000F
    // 0x20008: VLD2.16 {d4, d5}, [r2]!        -> 0xF422_484D
    // 0x2000C: MOV r7, #1                     -> 0xE3A0_7001
    // 0x20010: MOV r0, #0                     -> 0xE3A0_0000
    // 0x20014: SVC 0                          -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xF420_000D).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xF401_000F).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xF422_484D).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(20), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // Verify RGBA registers:
    assert_eq!(engine.cpu.vfp[0], 0xAAAA_AAAA_AAAA_AAAA);
    assert_eq!(engine.cpu.vfp[1], 0xBBBB_BBBB_BBBB_BBBB);
    assert_eq!(engine.cpu.vfp[2], 0xCCCC_CCCC_CCCC_CCCC);
    assert_eq!(engine.cpu.vfp[3], 0xFFFF_FFFF_FFFF_FFFF);

    // Verify out_rgba matches rgba_original
    for i in 0..32 {
        let val = engine.mem.read_u8(out_rgba.add(i as u32)).unwrap();
        assert_eq!(val, rgba_original[i], "Mismatch at RGBA byte {}", i);
    }

    // Verify 16-bit stereo de-interleaving:
    // d4 has 4 left samples (0x1004, 0x1003, 0x1002, 0x1001)
    // d5 has 4 right samples (0x2004, 0x2003, 0x2002, 0x2001)
    assert_eq!(engine.cpu.vfp[4], 0x1004_1003_1002_1001);
    assert_eq!(engine.cpu.vfp[5], 0x2004_2003_2002_2001);
}

#[test]
fn test_neon_vld1_all_lanes_broadcast() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    let data_base = GuestAddr::new(0x60000);

    arena.commit_range(code_base, 0x10000).unwrap();
    arena.commit_range(data_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Store scalar byte 0x42 at 0x60000
    engine.mem.write_u8(data_base, 0x42).unwrap();
    // Store scalar u32 0xCAFE_BABE at 0x60004
    engine.mem.write_u32(data_base.add(4), 0xCAFE_BABE).unwrap();

    engine.cpu.set_reg(Reg::R0, data_base.as_u32());
    engine.cpu.set_reg(Reg::R1, data_base.add(4).as_u32());

    // 0x20000: VLD1.8 {d0[]}, [r0]   -> 0xF4A0_0C0F
    // 0x20004: VLD1.32 {d1[]}, [r1]  -> 0xF4A1_1C8F
    // 0x20008: MOV r7, #1            -> 0xE3A0_7001
    // 0x2000C: MOV r0, #0            -> 0xE3A0_0000
    // 0x20010: SVC 0                 -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xF4A0_0C0F).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xF4A1_1C8F).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    // All 8 lanes of d0 should be 0x42
    assert_eq!(engine.cpu.vfp[0], 0x4242_4242_4242_4242);
    // Both 32-bit lanes of d1 should be 0xCAFE_BABE
    assert_eq!(engine.cpu.vfp[1], 0xCAFE_BABE_CAFE_BABE);
}

#[test]
fn test_thumb2_neon_vld2_and_vld4() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    let in_data = GuestAddr::new(0x70000);
    let out_data = GuestAddr::new(0x71000);
    let in_rgba = GuestAddr::new(0x72000);
    let broadcast_scalar = GuestAddr::new(0x73000);

    arena.commit_range(code_base, 0x10000).unwrap();
    arena.commit_range(in_data, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Interleaved pairs: 16 bytes
    let original: [u8; 16] = [
        1, 10, 2, 20, 3, 30, 4, 40,
        5, 50, 6, 60, 7, 70, 8, 80,
    ];
    for (i, &b) in original.iter().enumerate() {
        engine.mem.write_u8(in_data.add(i as u32), b).unwrap();
    }

    // RGBA: 32 bytes (all Rs = 0x11, Gs = 0x22, Bs = 0x33, As = 0x44)
    for i in 0..8 {
        engine.mem.write_u8(in_rgba.add((i * 4) as u32), 0x11).unwrap();
        engine.mem.write_u8(in_rgba.add((i * 4 + 1) as u32), 0x22).unwrap();
        engine.mem.write_u8(in_rgba.add((i * 4 + 2) as u32), 0x33).unwrap();
        engine.mem.write_u8(in_rgba.add((i * 4 + 3) as u32), 0x44).unwrap();
    }

    // Scalar byte 0x99 for broadcast
    engine.mem.write_u8(broadcast_scalar, 0x99).unwrap();

    engine.cpu.set_reg(Reg::R0, in_data.as_u32());
    engine.cpu.set_reg(Reg::R1, out_data.as_u32());
    engine.cpu.set_reg(Reg::R2, in_rgba.as_u32());
    engine.cpu.set_reg(Reg::R3, broadcast_scalar.as_u32());

    // Thumb-2 instructions (16-bit halfwords):
    // 0x20000: vld2.8 {d0, d1}, [r0]!         -> hw1=0xF920, hw2=0x080D
    // 0x20004: vst2.8 {d0, d1}, [r1]!         -> hw1=0xF901, hw2=0x080D
    // 0x20008: vld4.8 {d2, d3, d4, d5}, [r2]! -> hw1=0xF922, hw2=0x200D
    // 0x2000C: vld1.8 {d6[]}, [r3]            -> hw1=0xF9A3, hw2=0x6C0F
    // 0x20010: movs r7, #1                    -> 0x2701 (Thumb-16)
    // 0x20012: movs r0, #0                    -> 0x2000 (Thumb-16)
    // 0x20014: svc 0                          -> 0xDF00 (Thumb-16)
    engine.mem.write_u16(code_base, 0xF920).unwrap();
    engine.mem.write_u16(code_base.add(2), 0x080D).unwrap();

    engine.mem.write_u16(code_base.add(4), 0xF901).unwrap();
    engine.mem.write_u16(code_base.add(6), 0x080D).unwrap();

    engine.mem.write_u16(code_base.add(8), 0xF922).unwrap();
    engine.mem.write_u16(code_base.add(10), 0x200D).unwrap();

    engine.mem.write_u16(code_base.add(12), 0xF9A3).unwrap();
    engine.mem.write_u16(code_base.add(14), 0x6C0F).unwrap();

    engine.mem.write_u16(code_base.add(16), 0x2701).unwrap();
    engine.mem.write_u16(code_base.add(18), 0x2000).unwrap();
    engine.mem.write_u16(code_base.add(20), 0xDF00).unwrap();

    engine.cpu.set_thumb(true);
    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(30).unwrap();
    assert_eq!(exit_code, 0);

    // Verify vld2 de-interleave
    assert_eq!(engine.cpu.vfp[0], 0x0807_0605_0403_0201);
    assert_eq!(engine.cpu.vfp[1], 0x5046_3C32_281E_140A);

    // Verify vst2 roundtrip in memory
    for i in 0..16 {
        let val = engine.mem.read_u8(out_data.add(i as u32)).unwrap();
        assert_eq!(val, original[i]);
    }

    // Verify vld4 RGBA de-interleave:
    assert_eq!(engine.cpu.vfp[2], 0x1111_1111_1111_1111);
    assert_eq!(engine.cpu.vfp[3], 0x2222_2222_2222_2222);
    assert_eq!(engine.cpu.vfp[4], 0x3333_3333_3333_3333);
    assert_eq!(engine.cpu.vfp[5], 0x4444_4444_4444_4444);

    // Verify broadcast into d6:
    assert_eq!(engine.cpu.vfp[6], 0x9999_9999_9999_9999);
}
