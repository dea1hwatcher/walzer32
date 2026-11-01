use std::thread;
use transd_core::{ArenaMemory, GuestAddr, Memory, SharedArenaMemory};
use transd_rt::DbtEngine;

#[test]
fn test_dbt_execution_on_4gb_arena_memory() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x1000);
    let data_base = GuestAddr::new(0x2000);

    // Commit 64KB for code and data
    arena.commit_range(code_base, 0x10000).unwrap();

    // Program:
    // 0x1000: MOV r0, #0x2000  (data_base: 0xE3A0_0C20)
    // 0x1004: MOV r1, #77      (0xE3A0_104D)
    // 0x1008: STR r1, [r0]     (0xE580_1000)
    // 0x100C: LDR r2, [r0]     (0xE590_2000)
    // 0x1010: MOV r0, r2       (0xE1A0_0002)
    // 0x1014: MOV r7, #1       (exit: 0xE3A0_7001)
    // 0x1018: SVC 0            (0xEF00_0000)
    arena.write_u32(code_base, 0xE3A0_0C20).unwrap();
    arena.write_u32(code_base.add(4), 0xE3A0_104D).unwrap();
    arena.write_u32(code_base.add(8), 0xE580_1000).unwrap();
    arena.write_u32(code_base.add(12), 0xE590_2000).unwrap();
    arena.write_u32(code_base.add(16), 0xE1A0_0002).unwrap();
    arena.write_u32(code_base.add(20), 0xE3A0_7001).unwrap();
    arena.write_u32(code_base.add(24), 0xEF00_0000).unwrap();

    let mut engine = DbtEngine::new(arena);
    engine.cpu.set_pc(code_base);

    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 77);

    // Verify data in 4GB arena
    let val = engine.mem.read_u32(data_base).unwrap();
    assert_eq!(val, 77);
}

#[test]
fn test_shared_arena_multithreaded_execution() {
    let shared = SharedArenaMemory::new().unwrap();
    let thread_mem_base = GuestAddr::new(0x4000_0000);
    shared.commit_range(thread_mem_base, 0x20000).unwrap();

    // Code at 0x4000_0000:
    // r0 = arg
    // ADD r0, r0, #10
    // MOV r7, #1
    // SVC 0
    {
        use transd_core::Memory;
        let mut init_mem = shared.clone();
        init_mem.write_u32(thread_mem_base, 0xE280_000A).unwrap(); // ADD r0, r0, #10
        init_mem.write_u32(thread_mem_base.add(4), 0xE3A0_7001).unwrap(); // MOV r7, #1
        init_mem.write_u32(thread_mem_base.add(8), 0xEF00_0000).unwrap(); // SVC 0
    }

    let t1_mem = shared.clone();
    let t1 = thread::spawn(move || {
        let mut engine = DbtEngine::new(t1_mem);
        engine.cpu.set_pc(thread_mem_base);
        engine.cpu.set_reg(transd_core::Reg::R0, 15);
        let res = engine.run(10).unwrap();
        assert_eq!(res, 25);
    });

    let t2_mem = shared.clone();
    let t2 = thread::spawn(move || {
        let mut engine = DbtEngine::new(t2_mem);
        engine.cpu.set_pc(thread_mem_base);
        engine.cpu.set_reg(transd_core::Reg::R0, 40);
        let res = engine.run(10).unwrap();
        assert_eq!(res, 50);
    });

    t1.join().unwrap();
    t2.join().unwrap();
}
