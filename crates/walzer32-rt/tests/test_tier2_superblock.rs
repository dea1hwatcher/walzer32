use walzer32_core::{ArenaMemory, GuestAddr, Memory, Reg};
use walzer32_rt::DbtEngine;

#[test]
fn test_sdiv_udiv_execution() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x1000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Test program at 0x1000:
    // 0x1000: SDIV r0, r1, r2  (0xE710_F211: r0 = r1 / r2 signed)
    // 0x1004: UDIV r3, r4, r5  (0xE733_F514: r3 = r4 / r5 unsigned)
    // 0x1008: SDIV r6, r1, r7  (0xE716_F711: r6 = r1 / r7 where r7=0 -> div-by-zero => 0)
    // 0x100C: MOV r7, #1       (0xE3A0_7001)
    // 0x1010: SVC 0            (0xEF00_0000)
    engine.mem.write_u32(code_base, 0xE710_F211).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xE733_F514).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE716_F711).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xEF00_0000).unwrap();

    // r1 = -100, r2 = 5 -> r0 should be -20
    engine.cpu.set_reg(Reg::R1, (-100i32) as u32);
    engine.cpu.set_reg(Reg::R2, 5);

    // r4 = 1000, r5 = 8 -> r3 should be 125
    engine.cpu.set_reg(Reg::R4, 1000);
    engine.cpu.set_reg(Reg::R5, 8);

    // r7 = 0 for divide by zero test
    engine.cpu.set_reg(Reg::R7, 0);

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, -20i32 as u32);

    assert_eq!(engine.cpu.reg(Reg::R0) as i32, -20);
    assert_eq!(engine.cpu.reg(Reg::R3), 125);
    assert_eq!(engine.cpu.reg(Reg::R6), 0); // Div by zero returns 0 without trap
}

#[test]
fn test_tier2_hot_loop_superblock_promotion() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x2000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Loop at 0x2000:
    // 0x2000: SUBS r0, r0, #1 (0xE250_0001)
    // 0x2004: BNE 0x2000      (0x1AFF_FFFD)
    // 0x2008: MOV r7, #1      (0xE3A0_7001)
    // 0x200C: SVC 0           (0xEF00_0000)
    engine.mem.write_u32(code_base, 0xE250_0001).unwrap();
    engine.mem.write_u32(code_base.add(4), 0x1AFF_FFFD).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xEF00_0000).unwrap();

    // Start with 50 iterations (above HOT_THRESHOLD = 20)
    engine.cpu.set_reg(Reg::R0, 50);
    engine.cpu.set_pc(code_base);

    let exit_code = engine.run(200).unwrap();
    assert_eq!(exit_code, 0);

    // Verify CPU finished loop
    assert_eq!(engine.cpu.reg(Reg::R0), 0);

    // Verify Tier-2 Superblock promotion occurred!
    assert!(engine.cache.has_superblock(code_base));
    assert!(engine.telemetry.tier2_superblocks_compiled >= 1);
}

#[test]
fn test_multi_block_superblock_with_side_exit() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x4000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Program:
    // Block 1 at 0x4000:
    // 0x4000: ADD r0, r0, #1  (0xE280_0001)
    // 0x4004: CMP r0, #5      (0xE350_0005)
    // 0x4008: BEQ 0x4018      (offset = (0x4018 - 0x4008 - 8) / 4 = 2 -> 0x0A00_0002)
    // Block 2 at 0x400C (fallthrough):
    // 0x400C: ADD r1, r1, #10 (0xE281_100A)
    // 0x4010: B 0x4000        (offset = (0x4000 - 0x4010 - 8) / 4 = -6 -> 0xEAFF_FFFA)
    // Exit Block at 0x4018 (side exit target):
    // 0x4018: MOV r7, #1      (0xE3A0_7001)
    // 0x401C: SVC 0           (0xEF00_0000)
    engine.mem.write_u32(code_base, 0xE280_0001).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xE350_0005).unwrap();
    engine.mem.write_u32(code_base.add(8), 0x0A00_0002).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE281_100A).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xEAFF_FFFA).unwrap();
    engine.mem.write_u32(code_base.add(24), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(28), 0xEF00_0000).unwrap();

    engine.cpu.set_reg(Reg::R0, 0);
    engine.cpu.set_reg(Reg::R1, 0);
    engine.cpu.set_pc(code_base);

    // Trace runs until r0 reaches 5 (5 iterations)
    // r1 increases by 10 each time r0 < 5: 4 times -> r1 = 40!
    let exit_code = engine.run(100).unwrap();
    assert_eq!(exit_code, 5); // r0 is returned in r0 as exit code

    assert_eq!(engine.cpu.reg(Reg::R0), 5);
    assert_eq!(engine.cpu.reg(Reg::R1), 40);
}
