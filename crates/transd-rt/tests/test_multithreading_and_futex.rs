use std::sync::Arc;
use std::thread;
use std::time::Duration;
use transd_core::{FlatMemory, GuestAddr, Memory, Reg, SharedMemory};
use transd_rt::{
    ConcurrentJitCache, DbtEngine, DefaultSyscallHandler, FutexManager, ThreadManager,
    DEFAULT_THREAD_STACK_SIZE,
};

#[test]
fn test_guest_futex_syscall_wait_wake() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);
    let futex_addr = GuestAddr::new(0x1500);
    // Initial futex word is 0
    mem.write_u32(futex_addr, 0).unwrap();

    let futex_mgr = FutexManager::new();

    // 1. Thread 1: executes FUTEX_WAIT on 0x1500 expecting 0
    // r0 = 0x1500 (uaddr)
    // r1 = 0 (FUTEX_WAIT)
    // r2 = 0 (val = 0)
    // r7 = 240 (SYS_futex)
    // SVC 0
    // MOV r0, #42 (after waking up)
    // MOV r7, #1  (exit)
    // SVC 0
    mem.write_u32(GuestAddr::new(0x1000), 0xE3A0_0C15).unwrap(); // r0 = 0x1500
    mem.write_u32(GuestAddr::new(0x1004), 0xE3A0_1000).unwrap(); // r1 = 0 (FUTEX_WAIT)
    mem.write_u32(GuestAddr::new(0x1008), 0xE3A0_2000).unwrap(); // r2 = 0 (val = 0)
    mem.write_u32(GuestAddr::new(0x100C), 0xE3A0_70F0).unwrap(); // r7 = 240 (FUTEX)
    mem.write_u32(GuestAddr::new(0x1010), 0xEF00_0000).unwrap(); // SVC 0
    mem.write_u32(GuestAddr::new(0x1014), 0xE3A0_002A).unwrap(); // r0 = 42
    mem.write_u32(GuestAddr::new(0x1018), 0xE3A0_7001).unwrap(); // r7 = 1 (exit)
    mem.write_u32(GuestAddr::new(0x101C), 0xEF00_0000).unwrap(); // SVC 0

    let shared_mem = SharedMemory::from_flat(mem);
    let shared_mem_child = shared_mem.clone();
    let futex_clone = futex_mgr.clone();

    let child = thread::spawn(move || {
        let mut engine = DbtEngine::new(shared_mem_child);
        engine.syscall_handler = Box::new(DefaultSyscallHandler::with_futex(futex_clone, 1001));
        engine.cpu.set_pc(GuestAddr::new(0x1000));
        let exit_code = engine.run(20).unwrap();
        assert_eq!(exit_code, 42);
    });

    // Wait until child thread has entered the futex wait queue
    for _ in 0..200 {
        if futex_mgr.waiters_count(futex_addr) > 0 {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let woken = futex_mgr.wake(futex_addr, 1);
    assert_eq!(woken, 1);

    child.join().unwrap();
}

#[test]
fn test_multi_threaded_dbt_execution_and_tls_isolation() {
    let memory_base = GuestAddr::new(0x2000_0000);
    let memory_size = 16 * 1024 * 1024; // 16 MB
    let shared_mem = SharedMemory::new(memory_base, memory_size);

    // Thread program at 0x2000_1000:
    // r0 = thread arg (value)
    // 0x2000_1000: MOV r1, #10
    // 0x2000_1004: ADD r0, r0, r1
    // 0x2000_1008: MOV r7, #1      (exit)
    // 0x2000_100C: SVC 0
    {
        use transd_core::Memory;
        let mut mem_init = shared_mem.clone();
        mem_init.write_u32(GuestAddr::new(0x2000_1000), 0xE3A0_100A).unwrap(); // MOV r1, #10
        mem_init.write_u32(GuestAddr::new(0x2000_1004), 0xE080_0001).unwrap(); // ADD r0, r0, r1
        mem_init.write_u32(GuestAddr::new(0x2000_1008), 0xE3A0_7001).unwrap(); // MOV r7, #1
        mem_init.write_u32(GuestAddr::new(0x2000_100C), 0xEF00_0000).unwrap(); // SVC 0
    }

    let mut thread_mgr = ThreadManager::new(GuestAddr::new(0x2080_0000));
    let futex_mgr = FutexManager::new();
    let shared_cache = Arc::new(ConcurrentJitCache::new());

    let mut handles = Vec::new();
    let thread_count = 4;

    for i in 0..thread_count {
        let tid = thread_mgr.next_tid();
        let stack = thread_mgr.alloc_stack(DEFAULT_THREAD_STACK_SIZE);
        let tls = 0x3000_0000 + i * 0x1000;
        let thread_arg = i * 100; // Expected exit code: i * 100 + 10

        let mem_clone = shared_mem.clone();
        let futex_clone = futex_mgr.clone();
        let cache_clone = shared_cache.clone();

        let handle = thread::spawn(move || {
            let mut engine = DbtEngine::new(mem_clone);
            engine.syscall_handler = Box::new(DefaultSyscallHandler::with_futex(futex_clone, tid));

            // Set thread-local context
            engine.cpu.set_pc(GuestAddr::new(0x2000_1000));
            engine.cpu.set_reg(Reg::R0, thread_arg);
            engine.cpu.set_sp(stack.as_u32());
            engine.cpu.tls_ptr = tls;

            // Check if block already in concurrent JIT cache
            if let Some(cached) = cache_clone.lookup(GuestAddr::new(0x2000_1000)) {
                engine.cache.insert(GuestAddr::new(0x2000_1000), cached);
            }

            let exit_code = engine.run(20).unwrap();
            assert_eq!(exit_code, thread_arg + 10);
            assert_eq!(engine.cpu.tls_ptr, tls);

            // Populate shared concurrent cache for other threads
            if let Some(b) = engine.cache.lookup(GuestAddr::new(0x2000_1000)) {
                cache_clone.insert(GuestAddr::new(0x2000_1000), b.clone());
            }
        });

        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }
}
