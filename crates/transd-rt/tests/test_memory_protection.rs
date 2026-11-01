use transd_core::{
    ArenaMemory, FlatMemory, GuestAddr, Memory, MemoryError, PROT_EXEC, PROT_NONE, PROT_READ,
    PROT_WRITE,
};
use transd_rt::DbtEngine;

#[test]
fn test_flat_memory_mprotect_permissions() {
    let base = GuestAddr::new(0x1000);
    let mut mem = FlatMemory::new(base, 0x4000);

    // Initial write before protection
    mem.write_u32(GuestAddr::new(0x1000), 0x1122_3344).unwrap();
    assert_eq!(mem.read_u32(GuestAddr::new(0x1000)).unwrap(), 0x1122_3344);

    // 1. Mark page as PROT_READ only
    mem.mprotect(GuestAddr::new(0x1000), 4096, PROT_READ).unwrap();
    assert_eq!(mem.get_protection(GuestAddr::new(0x1000)), PROT_READ);

    // Read must succeed
    assert_eq!(mem.read_u32(GuestAddr::new(0x1000)).unwrap(), 0x1122_3344);

    // Write must fail with PermissionDenied (write = true)
    let err = mem.write_u32(GuestAddr::new(0x1000), 0x5566_7788).unwrap_err();
    assert_eq!(
        err,
        MemoryError::PermissionDenied {
            addr: GuestAddr::new(0x1000),
            write: true
        }
    );

    // 2. Mark page as PROT_NONE
    mem.mprotect(GuestAddr::new(0x1000), 4096, PROT_NONE).unwrap();
    let err_read = mem.read_u32(GuestAddr::new(0x1000)).unwrap_err();
    assert_eq!(
        err_read,
        MemoryError::PermissionDenied {
            addr: GuestAddr::new(0x1000),
            write: false
        }
    );

    // 3. Restore PROT_READ | PROT_WRITE
    mem.mprotect(GuestAddr::new(0x1000), 4096, PROT_READ | PROT_WRITE).unwrap();
    mem.write_u32(GuestAddr::new(0x1000), 0x9988_7766).unwrap();
    assert_eq!(mem.read_u32(GuestAddr::new(0x1000)).unwrap(), 0x9988_7766);
}

#[test]
fn test_arena_memory_mprotect_permissions() {
    let mut arena = ArenaMemory::new().expect("Failed to allocate 4GB virtual arena");
    let base = GuestAddr::new(0x2000_0000);
    arena.commit_range(base, 0x10000).unwrap();

    arena.write_u32(base, 0xCAFE_BABE).unwrap();
    assert_eq!(arena.read_u32(base).unwrap(), 0xCAFE_BABE);

    // Write-protect page with PROT_READ
    arena.mprotect(base, 4096, PROT_READ).unwrap();
    assert_eq!(arena.get_protection(base), PROT_READ);

    // Read succeeds
    assert_eq!(arena.read_u32(base).unwrap(), 0xCAFE_BABE);

    // Write fails with PermissionDenied
    let err = arena.write_u32(base, 0xDEAD_BEEF).unwrap_err();
    assert_eq!(
        err,
        MemoryError::PermissionDenied {
            addr: base,
            write: true
        }
    );

    // Restore write permissions
    arena.mprotect(base, 4096, PROT_READ | PROT_WRITE | PROT_EXEC).unwrap();
    arena.write_u32(base, 0xDEAD_BEEF).unwrap();
    assert_eq!(arena.read_u32(base).unwrap(), 0xDEAD_BEEF);
}

#[test]
fn test_sys_mprotect_syscall_execution() {
    let mut arena = ArenaMemory::new().expect("Failed to allocate 4GB virtual arena");
    let code_base = GuestAddr::new(0x1000);
    let target_page = GuestAddr::new(0x5000);
    arena.commit_range(code_base, 0x10000).unwrap();

    // Write initial value to target page
    arena.write_u32(target_page, 0x1234_5678).unwrap();

    // Program at 0x1000:
    // 0x1000: MOV r0, #0x5000  (0xE3A0_0A05 -> 5 rot 20 = 0x5000)
    // 0x1004: MOV r1, #0x1000  (0xE3A0_1A01 -> 1 rot 20 = 0x1000 = 4096 bytes)
    // 0x1008: MOV r2, #1       (0xE3A0_2001 -> PROT_READ)
    // 0x100C: MOV r7, #125     (0xE3A0_707D -> __NR_mprotect = 125)
    // 0x1010: SVC 0            (0xEF00_0000)
    // 0x1014: MOV r7, #1       (0xE3A0_7001 -> sys_exit, r0 from mprotect returned as exit code)
    // 0x1018: SVC 0            (0xEF00_0000)
    arena.write_u32(code_base, 0xE3A0_0A05).unwrap();
    arena.write_u32(code_base.add(4), 0xE3A0_1A01).unwrap();
    arena.write_u32(code_base.add(8), 0xE3A0_2001).unwrap();
    arena.write_u32(code_base.add(12), 0xE3A0_707D).unwrap();
    arena.write_u32(code_base.add(16), 0xEF00_0000).unwrap();
    arena.write_u32(code_base.add(20), 0xE3A0_7001).unwrap();
    arena.write_u32(code_base.add(24), 0xEF00_0000).unwrap();

    let mut engine = DbtEngine::new(arena);
    engine.cpu.set_pc(code_base);

    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0); // sys_mprotect succeeded (returns 0)

    // Verify target page is now PROT_READ
    assert_eq!(engine.mem.get_protection(target_page), PROT_READ);

    // Attempting to write to target_page must now fail!
    assert!(engine.mem.write_u32(target_page, 0x9999).is_err());
}

#[test]
fn test_smc_guard_page_write_fault_recovery() {
    let mut arena = ArenaMemory::new().expect("Failed to allocate 4GB virtual arena");
    let code_page = GuestAddr::new(0x2000);
    arena.commit_range(code_page, 0x10000).unwrap();

    // Block at 0x2000:
    // 0x2000: MOV r0, #42  (0xE3A0_002A)
    // 0x2004: MOV r7, #1   (0xE3A0_7001) -> sys_exit
    // 0x2008: SVC 0        (0xEF00_0000)
    arena.write_u32(code_page, 0xE3A0_002A).unwrap();
    arena.write_u32(code_page.add(4), 0xE3A0_7001).unwrap();
    arena.write_u32(code_page.add(8), 0xEF00_0000).unwrap();

    let mut engine = DbtEngine::new(arena);
    // Enable hardware/memory SMC guard page write-protection!
    engine.enable_smc_guard_pages(true);
    engine.cpu.set_pc(code_page);

    // First execution: compiles block and write-protects page 0x2000
    let exit_code = engine.run(10).unwrap();
    assert_eq!(exit_code, 42);

    // Verify page is now write-protected by DBT guard pages
    assert_eq!(engine.mem.get_protection(code_page), PROT_READ | PROT_EXEC);
    assert!(engine.cache.is_code_page(code_page.as_u32() >> 12));

    // Now guest performs self-modifying code (SMC):
    // Write 0xE3A0_0063 (MOV r0, #99) to 0x2000 via write_guest_u32!
    // Since the page was protected PROT_READ | PROT_EXEC, this triggers a write fault,
    // which handle_write_fault catches, unprotects, and invalidates!
    engine.write_guest_u32(code_page, 0xE3A0_0063).unwrap();

    // Verify that SMC write trap was captured and recorded in telemetry
    assert!(engine.telemetry.smc_write_traps >= 1);
    // Verify that the old compiled block at 0x2000 was invalidated
    assert!(engine.cache.lookup(code_page).is_none());
    // Verify page was unprotected to allow writes
    assert_eq!(
        engine.mem.get_protection(code_page),
        PROT_READ | PROT_WRITE | PROT_EXEC
    );

    // Re-run the modified code: it should re-compile and return 99!
    engine.cpu.set_pc(code_page);
    let exit_code2 = engine.run(10).unwrap();
    assert_eq!(exit_code2, 99);
}

#[test]
fn test_smc_guard_page_interpreter_store_instruction_recovery() {
    let mut arena = ArenaMemory::new().expect("Failed to allocate 4GB virtual arena");
    let code_page = GuestAddr::new(0x4000);
    let patcher_page = GuestAddr::new(0x6000);
    arena.commit_range(code_page, 0x10000).unwrap();

    // Function at 0x4000:
    // 0x4000: MOV r0, #10  (0xE3A0_000A)
    // 0x4004: MOV r7, #1   (0xE3A0_7001)
    // 0x4008: SVC 0        (0xEF00_0000)
    arena.write_u32(code_page, 0xE3A0_000A).unwrap();
    arena.write_u32(code_page.add(4), 0xE3A0_7001).unwrap();
    arena.write_u32(code_page.add(8), 0xEF00_0000).unwrap();

    let mut engine = DbtEngine::new(arena);
    engine.enable_smc_guard_pages(true);

    // Execute function at 0x4000 first time to compile it and protect page 0x4000
    engine.cpu.set_pc(code_page);
    let res1 = engine.run(10).unwrap();
    assert_eq!(res1, 10);
    assert_eq!(engine.mem.get_protection(code_page), PROT_READ | PROT_EXEC);

    // Now write a runtime JIT patcher at 0x6000 that writes directly into 0x4000:
    // 0x6000: MOV r1, #0x4000  (0xE3A0_1901 -> 1 rot 18 = 0x4000)
    // 0x6004: MOV r2, #0x77    (0xE3A0_2077 -> imm 119)
    // 0x6008: STR r2, [r1]     (0xE581_2000 -> store into 0x4000!)
    // 0x600C: MOV r0, #0       (0xE3A0_0000)
    // 0x6010: MOV r7, #1       (0xE3A0_7001)
    // 0x6014: SVC 0            (0xEF00_0000)
    engine.mem.write_u32(patcher_page, 0xE3A0_1901).unwrap();
    engine.mem.write_u32(patcher_page.add(4), 0xE3A0_2077).unwrap();
    engine.mem.write_u32(patcher_page.add(8), 0xE581_2000).unwrap();
    engine.mem.write_u32(patcher_page.add(12), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(patcher_page.add(16), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(patcher_page.add(20), 0xEF00_0000).unwrap();

    // Execute patcher: the STR at 0x6008 stores into the protected 0x4000 page!
    // The DBT engine's step() catches the write fault, unprotects page 0x4000,
    // invalidates the block, and finishes the store instruction cleanly!
    engine.cpu.set_pc(patcher_page);
    let patch_res = engine.run(20).unwrap();
    assert_eq!(patch_res, 0);

    // Verify SMC trap was caught and handled
    assert!(engine.telemetry.smc_write_traps >= 1);
    assert_eq!(engine.mem.read_u32(code_page).unwrap(), 0x77);
}
