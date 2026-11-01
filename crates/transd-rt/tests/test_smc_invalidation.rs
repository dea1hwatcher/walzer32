use transd_core::{FlatMemory, GuestAddr, Memory};
use transd_rt::DbtEngine;

#[test]
fn test_smc_write_guest_u32_invalidates_and_recompiles() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);

    // Initial program at 0x1000:
    // 0x1000: MOV r0, #10  (0xE3A0_000A)
    // 0x1004: MOV r7, #1   (exit) (0xE3A0_7001)
    // 0x1008: SVC 0        (0xEF00_0000)
    mem.write_u32(GuestAddr::new(0x1000), 0xE3A0_000A).unwrap();
    mem.write_u32(GuestAddr::new(0x1004), 0xE3A0_7001).unwrap();
    mem.write_u32(GuestAddr::new(0x1008), 0xEF00_0000).unwrap();

    let mut engine = DbtEngine::new(mem);
    engine.cpu.set_pc(GuestAddr::new(0x1000));

    // First run -> executes 0x1000 with r0 = 10
    let exit_code = engine.run(10).unwrap();
    assert_eq!(exit_code, 10);
    assert!(engine.cache.lookup(GuestAddr::new(0x1000)).is_some());

    // Self-Modifying Code (SMC): Overwrite instruction at 0x1000 with MOV r0, #99 (0xE3A0_0063)
    engine
        .write_guest_u32(GuestAddr::new(0x1000), 0xE3A0_0063)
        .unwrap();

    // Cache must have invalidated the block
    assert!(engine.cache.lookup(GuestAddr::new(0x1000)).is_none());

    // Second run at 0x1000 -> re-lifts, re-compiles, and executes with r0 = 99
    engine.cpu.set_pc(GuestAddr::new(0x1000));
    let new_exit_code = engine.run(10).unwrap();
    assert_eq!(new_exit_code, 99);
}

#[test]
fn test_smc_cacheflush_syscall_invalidates_range() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x2000), 0x2000);

    // 0x2000: MOV r0, #40
    // 0x2004: MOV r7, #1 (exit)
    // 0x2008: SVC 0
    mem.write_u32(GuestAddr::new(0x2000), 0xE3A0_0028).unwrap();
    mem.write_u32(GuestAddr::new(0x2004), 0xE3A0_7001).unwrap();
    mem.write_u32(GuestAddr::new(0x2008), 0xEF00_0000).unwrap();

    let mut engine = DbtEngine::new(mem);
    engine.cpu.set_pc(GuestAddr::new(0x2000));
    let exit_code = engine.run(10).unwrap();
    assert_eq!(exit_code, 40);
    assert!(engine.cache.lookup(GuestAddr::new(0x2000)).is_some());

    // Guest overwrites 0x2000 directly in memory (raw write without write_guest_u32)
    engine
        .mem
        .write_u32(GuestAddr::new(0x2000), 0xE3A0_0032)
        .unwrap(); // MOV r0, #50

    // Now guest executes __ARM_NR_cacheflush (0xF0002):
    // r0 = 0x2000 (start)
    // r1 = 0x2010 (end)
    // r2 = 0 (flags)
    // r7 = 0xF0002 (SYS_cacheflush)
    // SVC 0
    // MOV r7, #1 (exit)
    // SVC 0
    let flush_pc = GuestAddr::new(0x2100);
    engine
        .mem
        .write_u32(flush_pc, 0xE3A0_0C20)
        .unwrap(); // r0 = 0x2000
    engine
        .mem
        .write_u32(flush_pc.add(4), 0xE3A0_1C20)
        .unwrap(); // r1 = 0x2000 (base)
    engine
        .mem
        .write_u32(flush_pc.add(8), 0xE281_1010)
        .unwrap(); // r1 = r1 + 16 (0x2010)
    engine
        .mem
        .write_u32(flush_pc.add(12), 0xE3A0_2000)
        .unwrap(); // r2 = 0
    engine
        .mem
        .write_u32(flush_pc.add(16), 0xE3A0_7002)
        .unwrap(); // r7 = 2
    engine
        .mem
        .write_u32(flush_pc.add(20), 0xE387_780F)
        .unwrap(); // ORR r7, r7, #0x000F0000 -> r7 = 0xF0002
    engine
        .mem
        .write_u32(flush_pc.add(24), 0xEF00_0000)
        .unwrap(); // SVC 0 (cacheflush!)
    engine
        .mem
        .write_u32(flush_pc.add(28), 0xE3A0_7001)
        .unwrap(); // MOV r7, #1 (exit)
    engine
        .mem
        .write_u32(flush_pc.add(32), 0xEF00_0000)
        .unwrap(); // SVC 0

    engine.cpu.set_pc(flush_pc);
    let _ = engine.run(15).unwrap();

    // The cacheflush syscall must have invalidated 0x2000!
    assert!(engine.cache.lookup(GuestAddr::new(0x2000)).is_none());

    // Running at 0x2000 now produces the new value 50!
    engine.cpu.set_pc(GuestAddr::new(0x2000));
    let new_exit_code = engine.run(10).unwrap();
    assert_eq!(new_exit_code, 50);
}

#[test]
fn test_unchaining_on_target_invalidation() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x3000), 0x2000);

    // Block 1 at 0x3000:
    // B 0x3020 (direct branch to Block 2)
    // 0xEA000006 (offset +6 words = +24 bytes + 8 = +32 bytes -> 0x3020)
    mem.write_u32(GuestAddr::new(0x3000), 0xEA00_0006).unwrap();

    // Block 2 at 0x3020:
    // MOV r0, #77
    // MOV r7, #1 (exit)
    // SVC 0
    mem.write_u32(GuestAddr::new(0x3020), 0xE3A0_004D).unwrap();
    mem.write_u32(GuestAddr::new(0x3024), 0xE3A0_7001).unwrap();
    mem.write_u32(GuestAddr::new(0x3028), 0xEF00_0000).unwrap();

    let mut engine = DbtEngine::new(mem);
    engine.cpu.set_pc(GuestAddr::new(0x3000));

    // Lift both blocks into cache
    let _ = engine.step().unwrap(); // lifts 0x3000
    let _ = engine.step().unwrap(); // jumps to 0x3020 and lifts it

    assert!(engine.cache.lookup(GuestAddr::new(0x3000)).is_some());
    assert!(engine.cache.lookup(GuestAddr::new(0x3020)).is_some());

    // Chain 0x3000 -> 0x3020
    let chained = engine.chain_blocks(GuestAddr::new(0x3000), GuestAddr::new(0x3020));
    assert!(chained);

    // Verify incoming and outgoing edge tracking
    assert!(engine.cache.outgoing_edges.get(&GuestAddr::new(0x3000)).unwrap().contains(&GuestAddr::new(0x3020)));
    assert!(engine.cache.incoming_edges.get(&GuestAddr::new(0x3020)).unwrap().contains(&GuestAddr::new(0x3000)));

    // Invalidate Block 2 at 0x3020
    let invalidated = engine.invalidate_range(GuestAddr::new(0x3020), 16);
    assert_eq!(invalidated, 1);
    assert!(engine.cache.lookup(GuestAddr::new(0x3020)).is_none());

    // Verify Block 1 was cleanly unchained: incoming edges gone, outgoing edge removed
    assert!(engine.cache.incoming_edges.get(&GuestAddr::new(0x3020)).is_none());
    assert!(engine.cache.outgoing_edges.get(&GuestAddr::new(0x3000)).unwrap().is_empty());
}
