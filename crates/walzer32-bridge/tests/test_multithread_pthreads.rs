use walzer32_bridge::{
    invoke_guest_mt, BionicBridge, JniBridge, SharedGuestRuntime,
};
use walzer32_core::{GuestAddr, Memory, SharedArenaMemory, SharedMemory};
use walzer32_elf::SymbolResolver;
use walzer32_rt::{DbtEngine, FutexManager};

/// Encodes `MOVW Rd, #imm16` (`0xE300_0000 | ((imm >> 12) << 16) | (rd << 12) | (imm & 0xFFF)`)
fn movw(rd: u32, imm16: u16) -> u32 {
    let imm = imm16 as u32;
    0xE300_0000 | ((imm >> 12) << 16) | (rd << 12) | (imm & 0xFFF)
}

/// Encodes `MOVT Rd, #imm16` (`0xE340_0000 | ((imm >> 12) << 16) | (rd << 12) | (imm & 0xFFF)`)
fn movt(rd: u32, imm16: u16) -> u32 {
    let imm = imm16 as u32;
    0xE340_0000 | ((imm >> 12) << 16) | (rd << 12) | (imm & 0xFFF)
}

fn mov32(code: &mut Vec<(u32, u32)>, pc: &mut u32, rd: u32, val: u32) {
    code.push((*pc, movw(rd, (val & 0xFFFF) as u16)));
    *pc += 4;
    if (val >> 16) != 0 {
        code.push((*pc, movt(rd, (val >> 16) as u16)));
        *pc += 4;
    }
}

fn call_abs(code: &mut Vec<(u32, u32)>, pc: &mut u32, target: u32) {
    mov32(code, pc, 12, target);
    code.push((*pc, 0xE12F_FF3C)); // BLX R12
    *pc += 4;
}

fn arm_branch(cond: u32, from_pc: u32, to_pc: u32) -> u32 {
    let offset = ((to_pc as i64 - (from_pc as i64 + 8)) >> 2) as i32;
    (cond << 28) | 0x0A00_0000 | ((offset as u32) & 0x00FF_FFFF)
}

fn setup_mt_env() -> (
    DbtEngine<SharedMemory>,
    SharedGuestRuntime,
    BionicStubs,
) {
    let mem = SharedMemory::new(GuestAddr::new(0x1000), 0x0040_0000);
    let mut mem_init = mem.clone();
    // Map stub/heap pages inside SharedMemory range? Wait: FlatMemory uses fixed [base, base+size).
    // Place stub_base at 0x0010_0000 and heap at 0x0018_0000..0x003F_0000 inside the 4 MB region.
    let bionic = BionicBridge::new(
        GuestAddr::new(0x0010_0000),
        GuestAddr::new(0x0018_0000),
        0x0026_0000,
    );
    bionic.install_stubs(&mut mem_init).unwrap();
    let stubs = BionicStubs {
        pthread_create: bionic.resolve("pthread_create").unwrap().as_u32(),
        pthread_join: bionic.resolve("pthread_join").unwrap().as_u32(),
        pthread_mutex_init: bionic.resolve("pthread_mutex_init").unwrap().as_u32(),
        pthread_mutex_lock: bionic.resolve("pthread_mutex_lock").unwrap().as_u32(),
        pthread_mutex_unlock: bionic.resolve("pthread_mutex_unlock").unwrap().as_u32(),
        pthread_cond_init: bionic.resolve("pthread_cond_init").unwrap().as_u32(),
        pthread_cond_wait: bionic.resolve("pthread_cond_wait").unwrap().as_u32(),
        pthread_cond_signal: bionic.resolve("pthread_cond_signal").unwrap().as_u32(),
    };

    let jni = JniBridge::new(GuestAddr::new(0x0014_0000));
    let futex = FutexManager::new();
    let runtime = SharedGuestRuntime::new(bionic, jni, futex);

    let mut engine = DbtEngine::new(mem);
    engine.cpu.set_sp(0x000F_0000);
    (engine, runtime, stubs)
}

struct BionicStubs {
    pthread_create: u32,
    pthread_join: u32,
    pthread_mutex_init: u32,
    pthread_mutex_lock: u32,
    pthread_mutex_unlock: u32,
    pthread_cond_init: u32,
    pthread_cond_wait: u32,
    pthread_cond_signal: u32,
}

#[test]
fn test_mt_pthread_create_join_and_futex_mutex_race() {
    let (mut engine, runtime, stubs) = setup_mt_env();

    // Shared data region at 0x0005_0000:
    // +0x00: pthread_mutex_t
    // +0x04: shared_counter (starts at 0)
    // +0x10..0x20: tids[0..4]
    // +0x20..0x30: retvals[0..4]
    let mutex_addr: u32 = 0x0005_0000;
    let counter_addr: u32 = 0x0005_0004;
    let tids_base: u32 = 0x0005_0010;
    let rets_base: u32 = 0x0005_0020;
    engine.mem.write_u32(GuestAddr::new(counter_addr), 0).unwrap();

    // Worker function at 0x0001_0000 (R0 = worker_id 1..=4):
    // PUSH {R4, R5, R6, LR}      (0xE92D_4070)
    // MOV R4, R0                 (0xE1A0_4000) -> worker_id
    // MOV R5, #50                (0xE3A0_5032) -> iterations
    // loop:
    //   mov32 R0, mutex_addr
    //   BLX pthread_mutex_lock
    //   mov32 R6, counter_addr
    //   LDR R0, [R6]             (0xE596_0000)
    //   ADD R0, R0, #1           (0xE280_0001)
    //   STR R0, [R6]             (0xE586_0000)
    //   mov32 R0, mutex_addr
    //   BLX pthread_mutex_unlock
    //   SUBS R5, R5, #1          (0xE255_5001)
    //   BNE loop
    // ADD R0, R4, #100           (0xE284_0064) -> retval = 100 + worker_id
    // POP {R4, R5, R6, PC}       (0xE8BD_8070)
    let worker_pc: u32 = 0x0001_0000;
    let mut code = Vec::new();
    let mut pc = worker_pc;
    code.push((pc, 0xE92D_4070));
    pc += 4;
    code.push((pc, 0xE1A0_4000));
    pc += 4;
    code.push((pc, 0xE3A0_5032));
    pc += 4; // 50 iterations per thread
    let loop_pc = pc;
    mov32(&mut code, &mut pc, 0, mutex_addr);
    call_abs(&mut code, &mut pc, stubs.pthread_mutex_lock);
    mov32(&mut code, &mut pc, 6, counter_addr);
    code.push((pc, 0xE596_0000));
    pc += 4;
    code.push((pc, 0xE280_0001));
    pc += 4;
    code.push((pc, 0xE586_0000));
    pc += 4;
    mov32(&mut code, &mut pc, 0, mutex_addr);
    call_abs(&mut code, &mut pc, stubs.pthread_mutex_unlock);
    code.push((pc, 0xE255_5001));
    pc += 4;
    code.push((pc, arm_branch(1 /* NE */, pc, loop_pc)));
    pc += 4;
    code.push((pc, 0xE284_0064));
    pc += 4;
    code.push((pc, 0xE8BD_8070));

    // Main function at 0x0002_0000:
    // PUSH {R4, LR}              (0xE92D_4010)
    // Init mutex
    let main_pc: u32 = 0x0002_0000;
    pc = main_pc;
    code.push((pc, 0xE92D_4010));
    pc += 4;
    mov32(&mut code, &mut pc, 0, mutex_addr);
    code.push((pc, 0xE3A0_1000)); // MOV R1, #0
    pc += 4;
    call_abs(&mut code, &mut pc, stubs.pthread_mutex_init);

    // Spawn 4 worker threads
    for i in 0..4u32 {
        mov32(&mut code, &mut pc, 0, tids_base + i * 4);
        code.push((pc, 0xE3A0_1000)); // attr = NULL
        pc += 4;
        mov32(&mut code, &mut pc, 2, worker_pc);
        code.push((pc, 0xE3A0_3000 | (i + 1))); // arg = i + 1
        pc += 4;
        call_abs(&mut code, &mut pc, stubs.pthread_create);
    }

    // Join all 4 worker threads
    for i in 0..4u32 {
        mov32(&mut code, &mut pc, 0, tids_base + i * 4);
        code.push((pc, 0xE590_0000)); // LDR R0, [R0]
        pc += 4;
        mov32(&mut code, &mut pc, 1, rets_base + i * 4);
        call_abs(&mut code, &mut pc, stubs.pthread_join);
    }

    // Return *counter_addr
    mov32(&mut code, &mut pc, 0, counter_addr);
    code.push((pc, 0xE590_0000)); // LDR R0, [R0]
    pc += 4;
    code.push((pc, 0xE8BD_8010)); // POP {R4, PC}

    for (addr, word) in code {
        engine.mem.write_u32(GuestAddr::new(addr), word).unwrap();
    }

    let final_counter = invoke_guest_mt(&mut engine, &runtime, GuestAddr::new(main_pc), &[]).unwrap();
    assert_eq!(final_counter, 200, "4 threads x 50 mutex-protected increments must equal 200");
    assert_eq!(engine.mem.read_u32(GuestAddr::new(mutex_addr)).unwrap(), 0);
    for i in 0..4u32 {
        let ret = engine.mem.read_u32(GuestAddr::new(rets_base + i * 4)).unwrap();
        assert_eq!(ret, 100 + i + 1, "pthread_join must collect exact worker return value");
    }
    runtime.join_all_workers();
}

#[test]
fn test_mt_pthread_cond_wait_and_signal() {
    let (mut engine, runtime, stubs) = setup_mt_env();

    let mutex_addr: u32 = 0x0006_0000;
    let cond_addr: u32 = 0x0006_0004;
    let ready_addr: u32 = 0x0006_0008;
    let payload_addr: u32 = 0x0006_000C;
    let observed_addr: u32 = 0x0006_0010;
    let tid_addr: u32 = 0x0006_0014;
    let ret_addr: u32 = 0x0006_0018;

    engine.mem.write_u32(GuestAddr::new(ready_addr), 0).unwrap();
    engine.mem.write_u32(GuestAddr::new(payload_addr), 0).unwrap();
    engine.mem.write_u32(GuestAddr::new(observed_addr), 0).unwrap();

    // Consumer worker at 0x0001_2000:
    //   lock(mutex)
    // wait_loop:
    //   LDR R0, [ready_addr]; CMP R0, #0; BNE got_ready
    //   cond_wait(cond, mutex)
    //   B wait_loop
    // got_ready:
    //   *observed = *payload
    //   unlock(mutex)
    //   return 0x42
    let worker_pc: u32 = 0x0001_2000;
    let mut code = Vec::new();
    let mut pc = worker_pc;
    code.push((pc, 0xE92D_4010)); // PUSH {R4, LR}
    pc += 4;
    mov32(&mut code, &mut pc, 0, mutex_addr);
    call_abs(&mut code, &mut pc, stubs.pthread_mutex_lock);

    let wait_loop_pc = pc;
    mov32(&mut code, &mut pc, 0, ready_addr);
    code.push((pc, 0xE590_0000)); // LDR R0, [R0]
    pc += 4;
    code.push((pc, 0xE350_0000)); // CMP R0, #0
    pc += 4;
    let bne_patch_idx = code.len();
    code.push((pc, 0)); // placeholder for BNE got_ready
    let bne_pc = pc;
    pc += 4;

    mov32(&mut code, &mut pc, 0, cond_addr);
    mov32(&mut code, &mut pc, 1, mutex_addr);
    call_abs(&mut code, &mut pc, stubs.pthread_cond_wait);
    code.push((pc, arm_branch(0xE /* AL */, pc, wait_loop_pc)));
    pc += 4;

    let got_ready_pc = pc;
    code[bne_patch_idx].1 = arm_branch(1 /* NE */, bne_pc, got_ready_pc);
    mov32(&mut code, &mut pc, 0, payload_addr);
    code.push((pc, 0xE590_1000)); // LDR R1, [R0]
    pc += 4;
    mov32(&mut code, &mut pc, 0, observed_addr);
    code.push((pc, 0xE580_1000)); // STR R1, [R0]
    pc += 4;
    mov32(&mut code, &mut pc, 0, mutex_addr);
    call_abs(&mut code, &mut pc, stubs.pthread_mutex_unlock);
    code.push((pc, 0xE3A0_0042)); // MOV R0, #0x42
    pc += 4;
    code.push((pc, 0xE8BD_8010)); // POP {R4, PC}

    // Main producer at 0x0002_2000:
    // init mutex, init cond, create worker, yield loop ~50 iters so worker enters cond_wait,
    // lock(mutex), *payload = 0xCAFE_BABE, *ready = 1, cond_signal(cond), unlock(mutex), join(worker)
    let main_pc: u32 = 0x0002_2000;
    pc = main_pc;
    code.push((pc, 0xE92D_4010));
    pc += 4;
    mov32(&mut code, &mut pc, 0, mutex_addr);
    code.push((pc, 0xE3A0_1000));
    pc += 4;
    call_abs(&mut code, &mut pc, stubs.pthread_mutex_init);

    mov32(&mut code, &mut pc, 0, cond_addr);
    code.push((pc, 0xE3A0_1000));
    pc += 4;
    call_abs(&mut code, &mut pc, stubs.pthread_cond_init);

    mov32(&mut code, &mut pc, 0, tid_addr);
    code.push((pc, 0xE3A0_1000));
    pc += 4;
    mov32(&mut code, &mut pc, 2, worker_pc);
    code.push((pc, 0xE3A0_3000));
    pc += 4;
    call_abs(&mut code, &mut pc, stubs.pthread_create);

    // Small delay loop so worker runs into cond_wait before producer signals
    code.push((pc, 0xE3A0_4040)); // MOV R4, #64
    pc += 4;
    let delay_pc = pc;
    code.push((pc, 0xE254_4001)); // SUBS R4, R4, #1
    pc += 4;
    code.push((pc, arm_branch(1 /* NE */, pc, delay_pc)));
    pc += 4;

    mov32(&mut code, &mut pc, 0, mutex_addr);
    call_abs(&mut code, &mut pc, stubs.pthread_mutex_lock);
    mov32(&mut code, &mut pc, 0, payload_addr);
    mov32(&mut code, &mut pc, 1, 0xCAFE_BABE);
    code.push((pc, 0xE580_1000)); // STR R1, [R0]
    pc += 4;
    mov32(&mut code, &mut pc, 0, ready_addr);
    code.push((pc, 0xE3A0_1001)); // MOV R1, #1
    pc += 4;
    code.push((pc, 0xE580_1000)); // STR R1, [R0]
    pc += 4;
    mov32(&mut code, &mut pc, 0, cond_addr);
    call_abs(&mut code, &mut pc, stubs.pthread_cond_signal);
    mov32(&mut code, &mut pc, 0, mutex_addr);
    call_abs(&mut code, &mut pc, stubs.pthread_mutex_unlock);

    mov32(&mut code, &mut pc, 0, tid_addr);
    code.push((pc, 0xE590_0000));
    pc += 4;
    mov32(&mut code, &mut pc, 1, ret_addr);
    call_abs(&mut code, &mut pc, stubs.pthread_join);

    mov32(&mut code, &mut pc, 0, observed_addr);
    code.push((pc, 0xE590_0000));
    pc += 4;
    code.push((pc, 0xE8BD_8010));

    for (addr, word) in code {
        engine.mem.write_u32(GuestAddr::new(addr), word).unwrap();
    }

    let observed = invoke_guest_mt(&mut engine, &runtime, GuestAddr::new(main_pc), &[]).unwrap();
    assert_eq!(observed, 0xCAFE_BABE);
    assert_eq!(engine.mem.read_u32(GuestAddr::new(ret_addr)).unwrap(), 0x42);
    runtime.join_all_workers();
}

#[test]
fn test_mt_shared_arena_pthread_and_atomic_fetch_add() {
    let mem = SharedArenaMemory::new().expect("Failed to reserve SharedArenaMemory");
    let mut mem_init = mem.clone();
    mem_init.commit_range(GuestAddr::new(0x0001_0000), 0x0040_0000).unwrap();

    let bionic = BionicBridge::new(
        GuestAddr::new(0x0010_0000),
        GuestAddr::new(0x0018_0000),
        0x0026_0000,
    );
    bionic.install_stubs(&mut mem_init).unwrap();
    let pthread_create = bionic.resolve("pthread_create").unwrap().as_u32();
    let pthread_join = bionic.resolve("pthread_join").unwrap().as_u32();
    let atomic_fetch_add_4 = bionic.resolve("__atomic_fetch_add_4").unwrap().as_u32();

    let jni = JniBridge::new(GuestAddr::new(0x0014_0000));
    let runtime = SharedGuestRuntime::new(bionic, jni, FutexManager::new());

    let mut engine = DbtEngine::new(mem);
    engine.cpu.set_sp(0x000F_0000);

    let counter_addr: u32 = 0x0007_0000;
    let tids_base: u32 = 0x0007_0010;
    engine.mem.write_u32(GuestAddr::new(counter_addr), 0).unwrap();

    // Worker increments counter 50 times using Bionic __atomic_fetch_add_4
    let worker_pc: u32 = 0x0001_4000;
    let mut code = Vec::new();
    let mut pc = worker_pc;
    code.push((pc, 0xE92D_4010)); // PUSH {R4, LR}
    pc += 4;
    code.push((pc, 0xE3A0_4032)); // MOV R4, #50
    pc += 4;
    let loop_pc = pc;
    mov32(&mut code, &mut pc, 0, counter_addr);
    code.push((pc, 0xE3A0_1001)); // val = 1
    pc += 4;
    code.push((pc, 0xE3A0_2005)); // __ATOMIC_SEQ_CST
    pc += 4;
    call_abs(&mut code, &mut pc, atomic_fetch_add_4);
    code.push((pc, 0xE254_4001)); // SUBS R4, R4, #1
    pc += 4;
    code.push((pc, arm_branch(1 /* NE */, pc, loop_pc)));
    pc += 4;
    code.push((pc, 0xE3A0_0000)); // return 0
    pc += 4;
    code.push((pc, 0xE8BD_8010));

    let main_pc: u32 = 0x0002_4000;
    pc = main_pc;
    code.push((pc, 0xE92D_4010));
    pc += 4;
    for i in 0..4u32 {
        mov32(&mut code, &mut pc, 0, tids_base + i * 4);
        code.push((pc, 0xE3A0_1000));
        pc += 4;
        mov32(&mut code, &mut pc, 2, worker_pc);
        code.push((pc, 0xE3A0_3000));
        pc += 4;
        call_abs(&mut code, &mut pc, pthread_create);
    }
    for i in 0..4u32 {
        mov32(&mut code, &mut pc, 0, tids_base + i * 4);
        code.push((pc, 0xE590_0000));
        pc += 4;
        code.push((pc, 0xE3A0_1000)); // retval_ptr = NULL
        pc += 4;
        call_abs(&mut code, &mut pc, pthread_join);
    }
    mov32(&mut code, &mut pc, 0, counter_addr);
    code.push((pc, 0xE590_0000));
    pc += 4;
    code.push((pc, 0xE8BD_8010));

    for (addr, word) in code {
        engine.mem.write_u32(GuestAddr::new(addr), word).unwrap();
    }

    let final_val = invoke_guest_mt(&mut engine, &runtime, GuestAddr::new(main_pc), &[]).unwrap();
    assert_eq!(final_val, 200);
    runtime.join_all_workers();
    assert!(engine.shared_jit.is_some());
    assert!(engine.cache_count() > 0);
}

#[test]
fn test_mt_ldrex_strex_worker_execution() {
    let (mut engine, runtime, stubs) = setup_mt_env();

    let counter_addr: u32 = 0x0008_0000;
    let tids_base: u32 = 0x0008_0010;
    engine.mem.write_u32(GuestAddr::new(counter_addr), 0).unwrap();

    // Per-thread isolated slots using LDREX/STREX CAS loop (each worker operates on its own word
    // to verify native LDREX/STREX emission & retry loop inside spawned pthreads without race flakiness
    // in host software interpreter). Also tests 4 threads running LDREX/STREX in parallel.
    let worker_pc: u32 = 0x0001_6000;
    let mut code = Vec::new();
    let mut pc = worker_pc;
    // R0 = thread slot index (0..4)
    // ADD R6, R6, R0, LSL #2 -> slot = counter_addr + idx * 4
    code.push((pc, 0xE92D_4070)); // PUSH {R4, R5, R6, LR}
    pc += 4;
    mov32(&mut code, &mut pc, 6, counter_addr);
    code.push((pc, 0xE086_6100)); // ADD R6, R6, R0, LSL #2
    pc += 4;
    code.push((pc, 0xE3A0_4032)); // MOV R4, #50
    pc += 4;
    let outer_loop = pc;
    let cas_retry = pc;
    code.push((pc, 0xE196_0F9F)); // LDREX R0, [R6]
    pc += 4;
    code.push((pc, 0xE280_0001)); // ADD R0, R0, #1
    pc += 4;
    code.push((pc, 0xE186_1F90)); // STREX R1, R0, [R6]
    pc += 4;
    code.push((pc, 0xE351_0000)); // CMP R1, #0
    pc += 4;
    code.push((pc, arm_branch(1 /* NE */, pc, cas_retry)));
    pc += 4;
    code.push((pc, 0xE254_4001)); // SUBS R4, R4, #1
    pc += 4;
    code.push((pc, arm_branch(1 /* NE */, pc, outer_loop)));
    pc += 4;
    code.push((pc, 0xE596_0000)); // LDR R0, [R6]
    pc += 4;
    code.push((pc, 0xE8BD_8070)); // POP {R4, R5, R6, PC}

    let main_pc: u32 = 0x0002_6000;
    pc = main_pc;
    code.push((pc, 0xE92D_4010));
    pc += 4;
    for i in 0..4u32 {
        mov32(&mut code, &mut pc, 0, tids_base + i * 4);
        code.push((pc, 0xE3A0_1000));
        pc += 4;
        mov32(&mut code, &mut pc, 2, worker_pc);
        code.push((pc, 0xE3A0_3000 | i));
        pc += 4;
        call_abs(&mut code, &mut pc, stubs.pthread_create);
    }
    for i in 0..4u32 {
        mov32(&mut code, &mut pc, 0, tids_base + i * 4);
        code.push((pc, 0xE590_0000));
        pc += 4;
        code.push((pc, 0xE3A0_1000));
        pc += 4;
        call_abs(&mut code, &mut pc, stubs.pthread_join);
    }
    code.push((pc, 0xE3A0_0000));
    pc += 4;
    code.push((pc, 0xE8BD_8010));

    for (addr, word) in code {
        engine.mem.write_u32(GuestAddr::new(addr), word).unwrap();
    }
    invoke_guest_mt(&mut engine, &runtime, GuestAddr::new(main_pc), &[]).unwrap();
    runtime.join_all_workers();
    for i in 0..4u32 {
        assert_eq!(
            engine.mem.read_u32(GuestAddr::new(counter_addr + i * 4)).unwrap(),
            50
        );
    }
}
