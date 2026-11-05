use walzer32_core::{FlatMemory, GuestAddr, Memory, SharedMemory};
use walzer32_elf::SymbolResolver;
use walzer32_rt::DbtEngine;
use walzer32_bridge::{
    invoke_guest, BionicBridge, JniBridge,
};

#[test]
fn test_atomic_ldrex_strex_success() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let mut bionic = BionicBridge::new(GuestAddr::new(0x7000_0000), GuestAddr::new(0x7010_0000), 0x100_000);
    bionic.install_stubs(&mut mem).unwrap();
    let mut jni = JniBridge::new(GuestAddr::new(0x7005_0000));
    jni.install(&mut mem).unwrap();
    let mut engine = DbtEngine::new(mem);

    // Target memory word to atomically increment: at 0x7003_0000, initial value = 42
    let target_addr = GuestAddr::new(0x7003_0000);
    engine.mem.write_u32(target_addr, 42).unwrap();

    // Assembly routine:
    // PUSH {lr}
    // LDR r1, =target_addr
    // LDREX r0, [r1]        ; r0 = 42, sets exclusive reservation
    // ADD r0, r0, #1        ; r0 = 43
    // STREX r2, r0, [r1]    ; stores 43 to [r1], r2 = 0 on success
    // MOV r0, r2            ; return status in r0
    // POP {lr}
    // BX lr
    let code_addr = GuestAddr::new(0x7002_0000);
    let insts = [
        0xE52DE004, // STR lr, [sp, #-4]!
        0xE59F1014, // LDR r1, [pc, #20] -> target_addr (0x04 + 8 + 20 = 0x20)
        0xE1910F9F, // LDREX r0, [r1]
        0xE2800001, // ADD r0, r0, #1
        0xE1812F90, // STREX r2, r0, [r1]
        0xE1A00002, // MOV r0, r2
        0xE49DE004, // LDR lr, [sp], #4
        0xE12FFF1E, // BX lr
        // Literal pool:
        target_addr.as_u32(),
    ];

    for (i, &word) in insts.iter().enumerate() {
        engine.mem.write_u32(code_addr.add((i * 4) as u32), word).unwrap();
    }
    engine.cpu.set_sp(0x701F_F000);

    let status = invoke_guest(&mut engine, &mut bionic, &mut jni, code_addr, &[]).unwrap();
    assert_eq!(status, 0); // 0 indicates success in STREX
    let val_in_mem = engine.mem.read_u32(target_addr).unwrap();
    assert_eq!(val_in_mem, 43); // Successfully updated 42 -> 43
}

#[test]
fn test_atomic_strex_fails_after_clrex() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let mut bionic = BionicBridge::new(GuestAddr::new(0x7000_0000), GuestAddr::new(0x7010_0000), 0x100_000);
    bionic.install_stubs(&mut mem).unwrap();
    let mut jni = JniBridge::new(GuestAddr::new(0x7005_0000));
    jni.install(&mut mem).unwrap();
    let mut engine = DbtEngine::new(mem);

    let target_addr = GuestAddr::new(0x7003_0000);
    engine.mem.write_u32(target_addr, 100).unwrap();

    // Assembly routine:
    // PUSH {lr}
    // LDR r1, =target_addr
    // LDREX r0, [r1]        ; r0 = 100, sets exclusive reservation
    // CLREX                 ; Clears reservation!
    // ADD r0, r0, #5        ; r0 = 105
    // STREX r2, r0, [r1]    ; Should FAIL! r2 = 1, memory NOT updated
    // MOV r0, r2            ; return status in r0
    // POP {lr}
    // BX lr
    let code_addr = GuestAddr::new(0x7002_0000);
    let insts = [
        0xE52DE004, // STR lr, [sp, #-4]!
        0xE59F1018, // LDR r1, [pc, #24] -> target_addr (0x04 + 8 + 24 = 0x24)
        0xE1910F9F, // LDREX r0, [r1]
        0xF57FF01F, // CLREX
        0xE2800005, // ADD r0, r0, #5
        0xE1812F90, // STREX r2, r0, [r1]
        0xE1A00002, // MOV r0, r2
        0xE49DE004, // LDR lr, [sp], #4
        0xE12FFF1E, // BX lr
        // Literal pool:
        target_addr.as_u32(),
    ];

    for (i, &word) in insts.iter().enumerate() {
        engine.mem.write_u32(code_addr.add((i * 4) as u32), word).unwrap();
    }
    engine.cpu.set_sp(0x701F_F000);

    let status = invoke_guest(&mut engine, &mut bionic, &mut jni, code_addr, &[]).unwrap();
    assert_eq!(status, 1); // 1 indicates STREX failure because of CLREX
    let val_in_mem = engine.mem.read_u32(target_addr).unwrap();
    assert_eq!(val_in_mem, 100); // Value was preserved (unmodified)
}

#[test]
fn test_tls_mrc_mcr_tpidrurw() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let mut bionic = BionicBridge::new(GuestAddr::new(0x7000_0000), GuestAddr::new(0x7010_0000), 0x100_000);
    bionic.install_stubs(&mut mem).unwrap();
    let mut jni = JniBridge::new(GuestAddr::new(0x7005_0000));
    jni.install(&mut mem).unwrap();
    let mut engine = DbtEngine::new(mem);

    // Initial TLS pointer set in CPU state
    engine.cpu.tls_ptr = 0x7012_3450;

    // Assembly routine:
    // PUSH {lr}
    // MRC p15, 0, r0, c13, c0, 3  ; read TPIDRURW into r0
    // ADD r1, r0, #0x100          ; new TLS pointer
    // MCR p15, 0, r1, c13, c0, 3  ; write new TPIDRURW from r1
    // MRC p15, 0, r2, c13, c0, 3  ; read back to verify
    // MOV r0, r2                  ; return in r0
    // POP {lr}
    // BX lr
    let code_addr = GuestAddr::new(0x7002_0000);
    let insts = [
        0xE52DE004, // STR lr, [sp, #-4]!
        0xEE1D0F70, // MRC p15, 0, r0, c13, c0, 3
        0xE2801C01, // ADD r1, r0, #0x100
        0xEE0D1F70, // MCR p15, 0, r1, c13, c0, 3
        0xEE1D2F70, // MRC p15, 0, r2, c13, c0, 3
        0xE1A00002, // MOV r0, r2
        0xE49DE004, // LDR lr, [sp], #4
        0xE12FFF1E, // BX lr
    ];

    for (i, &word) in insts.iter().enumerate() {
        engine.mem.write_u32(code_addr.add((i * 4) as u32), word).unwrap();
    }
    engine.cpu.set_sp(0x701F_F000);

    let res = invoke_guest(&mut engine, &mut bionic, &mut jni, code_addr, &[]).unwrap();
    assert_eq!(res, 0x7012_3550);
    assert_eq!(engine.cpu.tls_ptr, 0x7012_3550);
}

#[test]
fn test_bionic_pthread_create_and_mutex() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let mut bionic = BionicBridge::new(GuestAddr::new(0x7000_0000), GuestAddr::new(0x7010_0000), 0x100_000);
    bionic.install_stubs(&mut mem).unwrap();
    let mut jni = JniBridge::new(GuestAddr::new(0x7005_0000));
    jni.install(&mut mem).unwrap();
    let mut engine = DbtEngine::new(mem);

    let pthread_create_addr = bionic.stub_base.add((walzer32_bridge::BionicFuncId::PthreadCreate as u32) * 8);
    let mutex_init_addr = bionic.stub_base.add((walzer32_bridge::BionicFuncId::PthreadMutexInit as u32) * 8);
    let mutex_lock_addr = bionic.stub_base.add((walzer32_bridge::BionicFuncId::PthreadMutexLock as u32) * 8);
    let mutex_unlock_addr = bionic.stub_base.add((walzer32_bridge::BionicFuncId::PthreadMutexUnlock as u32) * 8);

    let tid_out_addr = GuestAddr::new(0x7003_0000);
    let mutex_addr = GuestAddr::new(0x7003_0010);
    let thread_func_addr = GuestAddr::new(0x7002_0500);

    // Assembly routine:
    // PUSH {lr}
    // 1. pthread_create(&tid, NULL, thread_func, 1234)
    // LDR r0, =tid_out_addr
    // MOV r1, #0
    // LDR r2, =thread_func_addr
    // LDR r3, =1234
    // LDR r4, =pthread_create_addr
    // BLX r4
    //
    // 2. pthread_mutex_init(&mutex, NULL)
    // LDR r0, =mutex_addr
    // MOV r1, #0
    // LDR r4, =mutex_init_addr
    // BLX r4
    //
    // 3. pthread_mutex_lock(&mutex)
    // LDR r0, =mutex_addr
    // LDR r4, =mutex_lock_addr
    // BLX r4
    //
    // 4. pthread_mutex_unlock(&mutex)
    // LDR r0, =mutex_addr
    // LDR r4, =mutex_unlock_addr
    // BLX r4
    //
    // POP {lr}
    // BX lr
    let code_addr = GuestAddr::new(0x7002_0000);
    let insts = [
        0xE52DE004, // STR lr, [sp, #-4]!
        // 1. pthread_create
        0xE59F0040, // LDR r0, [pc, #64] -> tid_out_addr
        0xE3A01000, // MOV r1, #0
        0xE59F203C, // LDR r2, [pc, #60] -> thread_func_addr
        0xE59F303C, // LDR r3, [pc, #60] -> 1234
        0xE59F403C, // LDR r4, [pc, #60] -> pthread_create_addr
        0xE12FFF34, // BLX r4
        // 2. pthread_mutex_init
        0xE59F0038, // LDR r0, [pc, #56] -> mutex_addr
        0xE3A01000, // MOV r1, #0
        0xE59F4034, // LDR r4, [pc, #52] -> mutex_init_addr
        0xE12FFF34, // BLX r4
        // 3. pthread_mutex_lock
        0xE59F0028, // LDR r0, [pc, #40] -> mutex_addr
        0xE59F402C, // LDR r4, [pc, #44] -> mutex_lock_addr
        0xE12FFF34, // BLX r4
        // 4. pthread_mutex_unlock
        0xE59F001C, // LDR r0, [pc, #28] -> mutex_addr
        0xE59F4024, // LDR r4, [pc, #36] -> mutex_unlock_addr
        0xE12FFF34, // BLX r4
        // Return
        0xE49DE004, // LDR lr, [sp], #4
        0xE12FFF1E, // BX lr
        // Literal pool:
        tid_out_addr.as_u32(),
        thread_func_addr.as_u32(),
        1234,
        pthread_create_addr.as_u32(),
        mutex_addr.as_u32(),
        mutex_init_addr.as_u32(),
        mutex_lock_addr.as_u32(),
        mutex_unlock_addr.as_u32(),
    ];

    for (i, &word) in insts.iter().enumerate() {
        engine.mem.write_u32(code_addr.add((i * 4) as u32), word).unwrap();
    }
    engine.cpu.set_sp(0x701F_F000);

    let res = invoke_guest(&mut engine, &mut bionic, &mut jni, code_addr, &[]).unwrap();
    assert_eq!(res, 0);

    // Verify thread creation was registered
    let tid = engine.mem.read_u32(tid_out_addr).unwrap();
    assert_eq!(tid, 1);
    assert_eq!(bionic.threads.len(), 1);
    let desc = bionic.threads.get(&1).unwrap();
    assert_eq!(desc.id, 1);
    assert_eq!(desc.start_routine, thread_func_addr);
    assert_eq!(desc.arg, 1234);
    assert_ne!(desc.stack_top.as_u32(), 0);
    assert_ne!(desc.tls_ptr.as_u32(), 0);
}

#[test]
fn test_shared_memory_concurrent_access() {
    let base = GuestAddr::new(0x7000_0000);
    let mut mem = SharedMemory::new(base, 0x100_000);

    let addr = GuestAddr::new(0x7000_1000);
    mem.write_u32(addr, 0x1234_5678).unwrap();

    let mut mem2 = mem.clone();
    let val = mem2.read_u32(addr).unwrap();
    assert_eq!(val, 0x1234_5678);

    // Test atomic CAS
    let old = mem2.atomic_cmpxchg_u32(addr, 0x1234_5678, 0x9999_8888).unwrap();
    assert_eq!(old, 0x1234_5678);

    let updated = mem.read_u32(addr).unwrap();
    assert_eq!(updated, 0x9999_8888);
}

#[test]
fn test_aeabi_read_tp() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let mut bionic = BionicBridge::new(GuestAddr::new(0x7000_0000), GuestAddr::new(0x7010_0000), 0x100_000);
    bionic.install_stubs(&mut mem).unwrap();
    let mut jni = JniBridge::new(GuestAddr::new(0x7005_0000));
    jni.install(&mut mem).unwrap();
    let mut engine = DbtEngine::new(mem);

    // Set thread pointer in CPU
    let expected_tp = 0x7015_8000;
    engine.cpu.tls_ptr = expected_tp;

    // Resolve __aeabi_read_tp address
    let read_tp_addr = bionic.resolve("__aeabi_read_tp").expect("__aeabi_read_tp must be defined");

    // Guest code calling __aeabi_read_tp:
    // PUSH {lr}
    // BLX r1
    // POP {lr}
    // BX lr
    let code_addr = GuestAddr::new(0x7002_0000);
    let insts = [
        0xE52DE004, // STR lr, [sp, #-4]!
        0xE12FFF31, // BLX r1
        0xE49DE004, // LDR lr, [sp], #4
        0xE12FFF1E, // BX lr
    ];
    for (i, &word) in insts.iter().enumerate() {
        engine.mem.write_u32(code_addr.add((i * 4) as u32), word).unwrap();
    }
    engine.cpu.set_reg(walzer32_core::Reg::R1, read_tp_addr.as_u32());
    engine.cpu.set_sp(0x701F_F000);

    let res = invoke_guest(&mut engine, &mut bionic, &mut jni, code_addr, &[]).unwrap();
    assert_eq!(res, expected_tp);
    assert_eq!(engine.cpu.reg(walzer32_core::Reg::R0), expected_tp);
}


#[test]
fn test_cp15_memory_barriers_do_not_corrupt_tls() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let mut bionic = BionicBridge::new(GuestAddr::new(0x7000_0000), GuestAddr::new(0x7010_0000), 0x100_000);
    bionic.install_stubs(&mut mem).unwrap();
    let mut jni = JniBridge::new(GuestAddr::new(0x7005_0000));
    jni.install(&mut mem).unwrap();
    let mut engine = DbtEngine::new(mem);

    // Initial TLS pointer set in CPU state
    const SENTINEL_TLS: u32 = 0xDEAD_BEE0;
    engine.cpu.tls_ptr = SENTINEL_TLS;

    // ARM Assembly routine:
    // PUSH {lr}
    // MOV r0, #0x42                ; r0 is NOT the TLS pointer
    // MCR p15, 0, r0, c7, c10, 5   ; DMB barrier (used by Unity Mono / Boehm GC)
    // MCR p15, 0, r0, c7, c10, 4   ; DSB barrier
    // MCR p15, 0, r0, c7, c5, 4    ; ISB barrier
    // MRC p15, 0, r1, c13, c0, 3   ; read TPIDRURW into r1
    // MOV r0, r1                   ; return in r0
    // POP {lr}
    // BX lr
    let code_addr = GuestAddr::new(0x7002_0000);
    let insts = [
        0xE52DE004, // STR lr, [sp, #-4]!
        0xE3A00042, // MOV r0, #0x42
        0xEE070F9A, // MCR p15, 0, r0, c7, c10, 5 (DMB)
        0xEE070F8A, // MCR p15, 0, r0, c7, c10, 4 (DSB)
        0xEE070F95, // MCR p15, 0, r0, c7, c5, 4  (ISB)
        0xEE1D1F70, // MRC p15, 0, r1, c13, c0, 3 (read TLS)
        0xE1A00001, // MOV r0, r1
        0xE49DE004, // LDR lr, [sp], #4
        0xE12FFF1E, // BX lr
    ];

    for (i, &word) in insts.iter().enumerate() {
        engine.mem.write_u32(code_addr.add((i * 4) as u32), word).unwrap();
    }
    engine.cpu.set_sp(0x701F_F000);

    let res = invoke_guest(&mut engine, &mut bionic, &mut jni, code_addr, &[]).unwrap();
    assert_eq!(res, SENTINEL_TLS, "TLS was corrupted by CP15 memory barriers!");
    assert_eq!(engine.cpu.tls_ptr, SENTINEL_TLS, "cpu.tls_ptr was corrupted!");
}
