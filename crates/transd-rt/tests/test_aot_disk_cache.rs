use std::fs;
use transd_core::{FlatMemory, GuestAddr, Memory, Reg};
use transd_emitter_a64::CompiledBlock;
use transd_ir::BlockExit;
use transd_rt::{calculate_sha256, AotCacheError, AotDiskCache, DbtEngine};

#[test]
fn test_aot_disk_cache_file_roundtrip_and_crc() {
    let temp_dir = std::env::temp_dir();
    let cache_path = temp_dir.join("test_roundtrip.transd_cache");

    let binary_bytes = b"sample_arm_shared_library_bytes";
    let hash = calculate_sha256(binary_bytes);
    let build_id = [0x55u8; 20];

    let mut cache = AotDiskCache::new(hash, build_id);

    let block1 = CompiledBlock {
        guest_entry: GuestAddr::new(0x1000),
        is_thumb: false,
        code_bytes: vec![0x10, 0x00, 0x80, 0x52], // MOV W16, #0
        inst_count: 1,
        guest_byte_size: 4,
        patch_sites: vec![],
        exit: BlockExit::Direct(GuestAddr::new(0x1004)),
    };

    let block2 = CompiledBlock {
        guest_entry: GuestAddr::new(0x1004),
        is_thumb: false,
        code_bytes: vec![0xC0, 0x03, 0x5F, 0xD6], // RET
        inst_count: 1,
        guest_byte_size: 4,
        patch_sites: vec![],
        exit: BlockExit::Indirect(Reg::LR),
    };

    cache.add_block(&block1, false);
    cache.add_block(&block2, false);

    // Save to disk
    cache.save_to_file(&cache_path).unwrap();
    assert!(cache_path.exists());

    // Load from disk
    let loaded = AotDiskCache::load_from_file(&cache_path).unwrap();
    assert_eq!(loaded.header.binary_hash, hash);
    assert_eq!(loaded.header.build_id, build_id);
    assert_eq!(loaded.records.len(), 2);
    assert_eq!(loaded.records[0].guest_entry, GuestAddr::new(0x1000));
    assert_eq!(loaded.records[1].guest_entry, GuestAddr::new(0x1004));

    // Test CRC corruption detection: tamper with a byte in the file
    let mut file_bytes = fs::read(&cache_path).unwrap();
    file_bytes[10] ^= 0xFF; // Corrupt header target arch
    let res = AotDiskCache::deserialize(&file_bytes);
    assert!(matches!(res, Err(AotCacheError::HeaderCrcMismatch { .. })));

    let _ = fs::remove_file(cache_path);
}

#[test]
fn test_aot_zero_cold_start_execution() {
    let temp_dir = std::env::temp_dir();
    let cache_path = temp_dir.join("test_cold_start.transd_cache");

    let entry = GuestAddr::new(0x2000);

    let binary_bytes = b"test_cold_start_lib";
    let hash = calculate_sha256(binary_bytes);

    // --- Engine 1: JIT compile and export AOT cache ---
    {
        let mut mem1 = FlatMemory::new(GuestAddr::new(0x1000), 0x10000);
        // 0x2000: MOV R0, #42        (0xE3A0002A)
        // 0x2004: BX LR              (0xE12FFF1E)
        mem1.write_u32(entry, 0xE3A0_002A).unwrap();
        mem1.write_u32(entry.add(4), 0xE12F_FF1E).unwrap();

        let mut engine1 = DbtEngine::new(mem1);
        engine1.cpu.set_pc(entry);
        engine1.cpu.set_lr(0xDEAD_BEE0);

        // Step to trigger JIT compilation of block at 0x2000
        let _ = engine1.step().unwrap();
        assert_eq!(engine1.cache.blocks.len(), 1);
        assert_eq!(engine1.cache.misses, 1);

        // Save AOT cache file
        engine1.save_aot_cache_file(&cache_path, hash, [0u8; 20]).unwrap();
    }

    // --- Engine 2: Fresh engine with 0 initial compiled blocks ---
    {
        let mut mem2 = FlatMemory::new(GuestAddr::new(0x1000), 0x10000);
        mem2.write_u32(entry, 0xE3A0_002A).unwrap();
        mem2.write_u32(entry.add(4), 0xE12F_FF1E).unwrap();

        let mut engine2 = DbtEngine::new(mem2);
        assert_eq!(engine2.cache.blocks.len(), 0);

        // Pre-load from AOT disk cache
        let preloaded = engine2.load_aot_cache_file(&cache_path, Some(&hash)).unwrap();
        assert_eq!(preloaded, 1);
        assert_eq!(engine2.cache.blocks.len(), 1);

        engine2.cpu.set_pc(entry);
        engine2.cpu.set_lr(0xDEAD_BEE0);

        // Execute step: must be a 100% cache HIT on the very first instruction!
        let _ = engine2.step().unwrap();
        assert_eq!(engine2.cache.hits, 1);
        assert_eq!(engine2.cache.misses, 0); // ZERO cache misses! Zero cold-start latency!
        assert_eq!(engine2.cpu.reg(Reg::R0), 42);
    }

    let _ = fs::remove_file(cache_path);
}

#[test]
fn test_aot_reachability_scanner() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x10000);

    // Construct multi-block control flow graph in memory:
    // Block A (0x3000):
    //   ADD r0, r0, #1
    //   B 0x3010
    // Block B (0x3010):
    //   CMP r0, #10
    //   BEQ 0x3020 (taken: Block C)
    //   (fallthrough: Block D at 0x3018)
    // Block D (0x3018):
    //   BX lr
    // Block C (0x3020):
    //   MOV r1, #99
    //   BX lr

    // Block A (0x3000):
    mem.write_u32(GuestAddr::new(0x3000), 0xE280_0001).unwrap(); // ADD r0, r0, #1
    mem.write_u32(GuestAddr::new(0x3004), 0xEA00_0001).unwrap(); // B 0x3010

    // Block B (0x3010):
    mem.write_u32(GuestAddr::new(0x3010), 0xE350_000A).unwrap(); // CMP r0, #10
    mem.write_u32(GuestAddr::new(0x3014), 0x0A00_0001).unwrap(); // BEQ 0x3020

    // Block D (0x3018):
    mem.write_u32(GuestAddr::new(0x3018), 0xE12F_FF1E).unwrap(); // BX lr

    // Block C (0x3020):
    mem.write_u32(GuestAddr::new(0x3020), 0xE3A0_1063).unwrap(); // MOV r1, #99
    mem.write_u32(GuestAddr::new(0x3024), 0xE12F_FF1E).unwrap(); // BX lr

    let mut engine = DbtEngine::new(mem);
    assert_eq!(engine.cache.blocks.len(), 0);

    // Run AOT scanner starting strictly from entry point 0x3000
    let compiled = engine.precompile_aot(&[GuestAddr::new(0x3000)], 50);

    // Scanner must automatically discover:
    // - Block A (0x3000)
    // - Block B (0x3010)
    // - Block D (0x3018 - fallthrough)
    // - Block C (0x3020 - branch target)
    assert!(compiled >= 4);
    assert!(engine.cache.blocks.contains_key(&GuestAddr::new(0x3000)));
    assert!(engine.cache.blocks.contains_key(&GuestAddr::new(0x3010)));
    assert!(engine.cache.blocks.contains_key(&GuestAddr::new(0x3018)));
    assert!(engine.cache.blocks.contains_key(&GuestAddr::new(0x3020)));
}
