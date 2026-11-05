use walzer32_core::{CpuState, FlatMemory, GuestAddr, Memory, Reg};
use walzer32_rt::telemetry::TelemetryManager;
use walzer32_rt::tombstone::{LibraryInfo, TombstoneReport, TombstoneSignal};
use walzer32_rt::DbtEngine;

#[test]
fn test_telemetry_metrics_and_hud() {
    let mut telem = TelemetryManager::new();

    // 1. Initial State
    assert_eq!(telem.cache_hit_rate(), 100.0);
    assert_eq!(telem.avg_compilation_latency_us(), 0.0);

    // 2. Record JIT and Execution metrics
    telem.record_instructions(1_000_000);
    telem.record_compilation(50);
    telem.record_compilation(70);
    assert_eq!(telem.total_blocks_compiled, 2);
    assert_eq!(telem.avg_compilation_latency_us(), 60.0);

    // 10 hits, 2 misses -> 10 / 12 = 83.33%
    for _ in 0..10 {
        telem.record_cache_hit();
    }
    for _ in 0..2 {
        telem.record_cache_miss();
    }
    let hit_rate = telem.cache_hit_rate();
    assert!((hit_rate - 83.33).abs() < 0.1);

    telem.record_chained_jump();
    telem.record_chained_jump();
    assert_eq!(telem.jit_chained_jumps, 2);

    // 3. Record Frame times
    telem.record_frame(16.6);
    telem.record_frame(16.6);
    assert_eq!(telem.total_frames_rendered, 2);
    assert!((telem.current_fps() - 60.0).abs() < 1.0);

    // 4. Update MIPS and Memory
    telem.update_mips(1_000_000, 0.01); // 1M insts in 10ms = 100 MIPS
    assert!((telem.current_mips() - 100.0).abs() < 0.1);
    telem.update_memory_usage(32 * 1024 * 1024, 512 * 1024);

    // 5. Render ASCII HUD Overlay
    let hud = telem.render_hud_overlay();
    assert!(hud.contains("WALZER32 DBT ENGINE TELEMETRY HUD"));
    assert!(hud.contains("FPS:"));
    assert!(hud.contains("MIPS: 100.00"));
    assert!(hud.contains("83.3% Hit"));
    assert!(hud.contains("Chained Fast Jumps:         2"));
    assert!(hud.contains("Total Insts:     1000000"));
    assert!(hud.contains("Arena Memory:  32.0 MB"));

    // 6. Render JSON
    let json = telem.render_json();
    assert!(json.contains("\"total_instructions\": 1000000"));
    assert!(json.contains("\"total_blocks_compiled\": 2"));
    assert!(json.contains("\"jit_chained_jumps\": 2"));
}

#[test]
fn test_tombstone_crash_report_generation() {
    let memory_base = GuestAddr::new(0x2000_0000);
    let mut mem = FlatMemory::new(memory_base, 0x100_000);

    // Setup dummy code around 0x2000_1000:
    // 0x2000_0FF0: NOP (0xE1A00000)
    // 0x2000_0FF4: NOP (0xE1A00000)
    // 0x2000_0FF8: ADD r1, r1, #4 (0xE2811004)
    // 0x2000_0FFC: MOV r0, #0     (0xE3A00000)
    // 0x2000_1000: LDR r2, [r0]   (0xE5902000) <-- FAULTING PC (Null pointer dereference)
    // 0x2000_1004: BX lr          (0xE12FFF1E)
    mem.write_u32(GuestAddr::new(0x2000_0FF0), 0xE1A0_0000).unwrap();
    mem.write_u32(GuestAddr::new(0x2000_0FF4), 0xE1A0_0000).unwrap();
    mem.write_u32(GuestAddr::new(0x2000_0FF8), 0xE281_1004).unwrap();
    mem.write_u32(GuestAddr::new(0x2000_0FFC), 0xE3A0_0000).unwrap();
    mem.write_u32(GuestAddr::new(0x2000_1000), 0xE590_2000).unwrap();
    mem.write_u32(GuestAddr::new(0x2000_1004), 0xE12F_FF1E).unwrap();

    // Setup stack words at SP = 0x2001_0000
    let sp_addr = GuestAddr::new(0x2001_0000);
    mem.write_u32(sp_addr, 0x0000_0042).unwrap();
    mem.write_u32(sp_addr.add(4), 0x2000_1004).unwrap(); // caller return address
    mem.write_u32(sp_addr.add(8), 0x2000_1050).unwrap(); // outer caller return address

    // Configure CPU state
    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::R0, 0x0000_0000); // null pointer
    cpu.set_reg(Reg::R1, 0x1234_5678);
    cpu.set_reg(Reg::R2, 0xCAFE_BABE);
    cpu.set_sp(sp_addr.as_u32());
    cpu.set_lr(0x2000_1004);
    cpu.set_pc(GuestAddr::new(0x2000_1000));
    cpu.vfp[0] = 0x3FF0_0000_0000_0000; // 1.0 in IEEE-754 double

    // Configure loaded libraries
    let mut lib_game = LibraryInfo::new("/data/app/lib/armeabi-v7a/libgame.so", GuestAddr::new(0x2000_0000), 0x10000);
    lib_game.add_symbol("Java_com_example_Game_step", GuestAddr::new(0x2000_0FC0));
    lib_game.add_symbol("GameEngine_Update", GuestAddr::new(0x2000_1040));

    let report = TombstoneReport::capture(
        &cpu,
        &mem,
        TombstoneSignal::SigSegv {
            code: 1, // SEGV_MAPERR
            fault_addr: GuestAddr::new(0x0000_0000),
        },
        &[lib_game],
        "render_thread",
        1234,
        5678,
        Some("Null pointer dereference in game update loop"),
    );

    // Verify Tombstone fields
    assert_eq!(report.pid, 1234);
    assert_eq!(report.tid, 5678);
    assert_eq!(report.thread_name, "render_thread");
    assert_eq!(report.signal.name(), "SIGSEGV");
    assert_eq!(report.signal.number(), 11);
    assert_eq!(report.signal.fault_addr(), Some(GuestAddr::new(0)));

    // Verify Backtrace
    assert!(report.backtrace.len() >= 2);
    assert_eq!(report.backtrace[0].frame_idx, 0);
    assert_eq!(report.backtrace[0].pc, GuestAddr::new(0x2000_1000));
    assert_eq!(report.backtrace[0].lib_name, "/data/app/lib/armeabi-v7a/libgame.so");
    assert_eq!(report.backtrace[0].relative_pc, 0x1000);
    assert!(report.backtrace[0].symbol.is_some());
    let (sym_name, offset) = report.backtrace[0].symbol.as_ref().unwrap();
    assert_eq!(sym_name, "Java_com_example_Game_step");
    assert_eq!(*offset, 0x2000_1000 - 0x2000_0FC0); // 0x40

    // Verify Code Dump around PC
    assert!(!report.code_dump.is_empty());
    let pc_line = report.code_dump.iter().find(|l| l.is_pc).expect("PC line not marked");
    assert_eq!(pc_line.addr, GuestAddr::new(0x2000_1000));
    assert_eq!(pc_line.hex_bytes, "e5902000");

    // Verify Stack Dump
    assert!(!report.stack_dump.is_empty());
    assert_eq!(report.stack_dump[0].addr, sp_addr);
    assert_eq!(report.stack_dump[0].words[0], 0x0000_0042);
    assert_eq!(report.stack_dump[0].words[1], 0x2000_1004);

    // Format Tombstone and verify layout
    let tombstone_text = report.format_tombstone();
    assert!(tombstone_text.contains("*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***"));
    assert!(tombstone_text.contains("signal 11 (SIGSEGV), code 1 (SEGV_MAPERR (Address not mapped to object)), fault addr 0x00000000"));
    assert!(tombstone_text.contains("Abort message: 'Null pointer dereference in game update loop'"));
    assert!(tombstone_text.contains("r0  00000000  r1  12345678  r2  cafebabe"));
    assert!(tombstone_text.contains("d00  3ff0000000000000"));
    assert!(tombstone_text.contains("#00 pc 00001000  /data/app/lib/armeabi-v7a/libgame.so (Java_com_example_Game_step+0x40)"));
    assert!(tombstone_text.contains("----> 20001000  e5902000"));
    assert!(tombstone_text.contains("stack around sp (20010000):"));
    assert!(tombstone_text.contains("20000000-20010000 r-xp        64 KB  /data/app/lib/armeabi-v7a/libgame.so"));

    // Test writing to file
    let temp_file = std::env::temp_dir().join("tombstone_test_00.txt");
    report.write_to_file(&temp_file).expect("Failed to write tombstone file");
    assert!(temp_file.exists());
    let read_back = std::fs::read_to_string(&temp_file).expect("Failed to read tombstone file");
    assert_eq!(read_back, tombstone_text);
    let _ = std::fs::remove_file(temp_file);
}

#[test]
fn test_engine_integration_tombstone_and_telemetry() {
    let memory_base = GuestAddr::new(0x1000_0000);
    let mut mem = FlatMemory::new(memory_base, 0x100_000);

    // Code:
    // 0x1000_0000: MOV r0, #42 (0xE3A0002A)
    // 0x1000_0004: BX lr       (0xE12FFF1E)
    mem.write_u32(GuestAddr::new(0x1000_0000), 0xE3A0_002A).unwrap();
    mem.write_u32(GuestAddr::new(0x1000_0004), 0xE12F_FF1E).unwrap();

    let mut engine = DbtEngine::new(mem);
    engine.cpu.set_pc(GuestAddr::new(0x1000_0000));
    engine.cpu.set_lr(0x0000_0000);

    // Step execution
    let res = engine.step().expect("Step failed");
    assert_eq!(res, walzer32_rt::EngineStepResult::Continue);
    assert_eq!(engine.cpu.reg(Reg::R0), 42);
    assert_eq!(engine.telemetry.total_instructions, 1);

    // Render HUD
    let hud = engine.render_telemetry_hud();
    assert!(hud.contains("WALZER32 DBT ENGINE TELEMETRY HUD"));

    // Capture Tombstone
    let tombstone = engine.capture_tombstone(
        TombstoneSignal::Trap { message: "Breakpoint trap".into() },
        &[],
        "worker",
        999,
        999,
        None,
    );
    assert_eq!(tombstone.signal.name(), "SIGTRAP");
    assert_eq!(tombstone.thread_name, "worker");
}
