use std::time::Duration;
use walzer32_core::{ArenaMemory, FlatMemory, GuestAddr, Memory, Reg};
use walzer32_rt::{
    AsyncJit, AsyncJitConfig, CodeSnapshot, CompilationJob, CompilationQueue, DbtEngine,
};

#[test]
fn test_code_snapshot_capture_and_memory() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);
    mem.write_u32(GuestAddr::new(0x1000), 0x1234_5678).unwrap();
    mem.write_u32(GuestAddr::new(0x1004), 0x9ABC_DEF0).unwrap();

    let snap = CodeSnapshot::capture(&mem, GuestAddr::new(0x1000), 512).unwrap();
    assert_eq!(snap.read_u32(GuestAddr::new(0x1000)).unwrap(), 0x1234_5678);
    assert_eq!(snap.read_u32(GuestAddr::new(0x1004)).unwrap(), 0x9ABC_DEF0);
    assert_eq!(snap.read_u8(GuestAddr::new(0x1000)).unwrap(), 0x78);

    let mut buf = [0u8; 8];
    snap.read_bytes(GuestAddr::new(0x1000), &mut buf).unwrap();
    assert_eq!(&buf[0..4], &0x1234_5678u32.to_le_bytes());

    // Writes must return PermissionDenied
    let mut snap_mut = snap.clone();
    assert!(snap_mut.write_u32(GuestAddr::new(0x1000), 0).is_err());
}

#[test]
fn test_compilation_queue_dedup_and_capacity() {
    let queue = CompilationQueue::new();
    let mem = FlatMemory::new(GuestAddr::new(0x1000), 0x1000);
    let snap = CodeSnapshot::capture(&mem, GuestAddr::new(0x1000), 256).unwrap();

    let job1 = CompilationJob {
        entry: GuestAddr::new(0x1000),
        is_thumb: false,
        code: snap.clone(),
    };

    // First enqueue succeeds
    assert!(queue.enqueue(job1.clone(), 10));
    assert_eq!(queue.in_flight_count(), 1);

    // Duplicate enqueue with same entry address is filtered out!
    let job_dup = CompilationJob {
        entry: GuestAddr::new(0x1000),
        is_thumb: false,
        code: snap.clone(),
    };
    assert!(!queue.enqueue(job_dup, 10));
    assert_eq!(queue.in_flight_count(), 1);

    // Capacity test: max depth 2
    let job2 = CompilationJob {
        entry: GuestAddr::new(0x1020),
        is_thumb: false,
        code: snap.clone(),
    };
    assert!(queue.enqueue(job2, 2));

    let job3 = CompilationJob {
        entry: GuestAddr::new(0x1040),
        is_thumb: false,
        code: snap,
    };
    // Should be dropped because queue already has 2 items
    assert!(!queue.enqueue(job3, 2));
}

#[test]
fn test_async_jit_worker_trace_compilation() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x2000), 0x2000);

    // ARM32 Loop:
    // 0x2000: SUBS r0, r0, #1 (0xE250_0001)
    // 0x2004: BNE 0x2000      (0x1AFF_FFFD)
    // 0x2008: MOV r7, #1      (0xE3A0_7001)
    // 0x200C: SVC 0           (0xEF00_0000)
    mem.write_u32(GuestAddr::new(0x2000), 0xE250_0001).unwrap();
    mem.write_u32(GuestAddr::new(0x2004), 0x1AFF_FFFD).unwrap();
    mem.write_u32(GuestAddr::new(0x2008), 0xE3A0_7001).unwrap();
    mem.write_u32(GuestAddr::new(0x200C), 0xEF00_0000).unwrap();

    let snap = CodeSnapshot::capture(&mem, GuestAddr::new(0x2000), 512).unwrap();

    let mut jit = AsyncJit::new(AsyncJitConfig {
        worker_threads: 2,
        max_queue_depth: 32,
        code_window_size: 512,
        max_trace_blocks: 8,
        max_trace_insts: 128,
    });

    let enqueued = jit.enqueue(GuestAddr::new(0x2000), false, snap);
    assert!(enqueued);

    // Wait for worker pool to complete compilation
    assert!(jit.wait_for_idle(Duration::from_secs(2)));

    let results = jit.drain_results();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].entry, GuestAddr::new(0x2000));
    assert!(results[0].compiled.code_bytes.len() >= 16);
    assert!(results[0].compile_duration_us > 0);

    let stats = jit.stats();
    assert_eq!(stats.jobs_enqueued, 1);
    assert_eq!(stats.jobs_completed, 1);
    assert_eq!(stats.jobs_dropped, 0);
    assert_eq!(stats.dedup_filtered, 0);
    assert_eq!(stats.in_flight, 0);
}

#[test]
fn test_engine_async_jit_zero_jank_loop() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x2000);
    arena.commit_range(code_base, 0x10000).unwrap();

    // Loop at 0x2000:
    // 0x2000: SUBS r0, r0, #1 (0xE250_0001)
    // 0x2004: BNE 0x2000      (0x1AFF_FFFD)
    // 0x2008: MOV r7, #1      (0xE3A0_7001)
    // 0x200C: SVC 0           (0xEF00_0000)
    arena.write_u32(code_base, 0xE250_0001).unwrap();
    arena.write_u32(code_base.add(4), 0x1AFF_FFFD).unwrap();
    arena.write_u32(code_base.add(8), 0xE3A0_7001).unwrap();
    arena.write_u32(code_base.add(12), 0xEF00_0000).unwrap();

    let mut engine = DbtEngine::with_async_jit(
        arena,
        AsyncJitConfig {
            worker_threads: 2,
            max_queue_depth: 32,
            code_window_size: 1024,
            max_trace_blocks: 8,
            max_trace_insts: 128,
        },
    );

    // Run 60 iterations (exceeds HOT_THRESHOLD = 20)
    engine.cpu.set_reg(Reg::R0, 60);
    engine.cpu.set_pc(code_base);

    let exit_code = engine.run(300).unwrap();
    assert_eq!(exit_code, 0);
    assert_eq!(engine.cpu.reg(Reg::R0), 0);

    // Flush any pending background compilations
    let promoted = engine.flush_async_jit(Duration::from_secs(2));
    assert!(promoted >= 1 || engine.cache.has_superblock(code_base));

    // Verify superblock is now committed and cached
    assert!(engine.cache.has_superblock(code_base));
    assert!(engine.telemetry.tier2_superblocks_compiled >= 1);

    // Verify async JIT telemetry
    let stats = engine.async_jit_stats().unwrap();
    assert!(stats.jobs_enqueued >= 1);
    assert!(stats.jobs_completed >= 1);
    assert_eq!(stats.worker_count, 2);
}

#[test]
fn test_async_jit_multi_worker_concurrency() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x10000);

    // Set up 4 distinct loops at 0x1000, 0x2000, 0x3000, 0x4000
    for i in 0..4 {
        let base = GuestAddr::new(0x1000 + i * 0x1000);
        mem.write_u32(base, 0xE250_0001).unwrap(); // SUBS r0, r0, #1
        mem.write_u32(base.add(4), 0x1AFF_FFFD).unwrap(); // BNE base
        mem.write_u32(base.add(8), 0xE3A0_7001).unwrap(); // MOV r7, #1
        mem.write_u32(base.add(12), 0xEF00_0000).unwrap(); // SVC 0
    }

    let mut jit = AsyncJit::new(AsyncJitConfig {
        worker_threads: 4,
        max_queue_depth: 64,
        code_window_size: 512,
        max_trace_blocks: 8,
        max_trace_insts: 128,
    });

    for i in 0..4 {
        let base = GuestAddr::new(0x1000 + i * 0x1000);
        let snap = CodeSnapshot::capture(&mem, base, 512).unwrap();
        assert!(jit.enqueue(base, false, snap));
    }

    assert!(jit.wait_for_idle(Duration::from_secs(3)));

    let results = jit.drain_results();
    assert_eq!(results.len(), 4);

    let stats = jit.stats();
    assert_eq!(stats.jobs_completed, 4);
    assert_eq!(stats.in_flight, 0);
    assert_eq!(stats.worker_count, 4);
}

#[test]
fn test_async_jit_smc_invalidation_safety() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x3000);
    arena.commit_range(code_base, 0x10000).unwrap();

    arena.write_u32(code_base, 0xE250_0001).unwrap();
    arena.write_u32(code_base.add(4), 0x1AFF_FFFD).unwrap();
    arena.write_u32(code_base.add(8), 0xE3A0_7001).unwrap();
    arena.write_u32(code_base.add(12), 0xEF00_0000).unwrap();

    let mut engine = DbtEngine::with_async_jit(
        arena,
        AsyncJitConfig {
            worker_threads: 1,
            max_queue_depth: 16,
            code_window_size: 512,
            max_trace_blocks: 8,
            max_trace_insts: 128,
        },
    );

    // Run 25 steps to populate Tier-1 block and trigger async enqueue
    for _ in 0..25 {
        let _ = engine.step();
    }

    // Now simulate SMC invalidation of that block before background job promotes!
    engine.invalidate_range(code_base, 16);
    assert!(engine.cache.lookup(code_base).is_none());

    // Flush async JIT: the background compilation finished, BUT poll_background_jit
    // must discard it because the Tier-1 block was invalidated!
    let _ = engine.async_jit.as_ref().unwrap().wait_for_idle(Duration::from_secs(2));
    let promoted = engine.poll_background_jit();

    // Promoted must be 0, and cache must NOT contain the invalidated block!
    assert_eq!(promoted, 0);
    assert!(engine.cache.lookup(code_base).is_none());
    assert!(!engine.cache.has_superblock(code_base));
}
