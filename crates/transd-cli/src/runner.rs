use transd_bridge::{
    invoke_guest_full, invoke_jni_onload, BionicBridge, GlesBridge, JniBridge,
};
use transd_core::{FlatMemory, GuestAddr};
use transd_elf::{CompositeResolver, ElfLoader};
use transd_rt::DbtEngine;

pub fn execute_so(
    path: &str,
    data: &[u8],
    target_func: Option<&str>,
    args: &[u32],
    show_hud: bool,
) -> Result<u32, Box<dyn std::error::Error>> {
    println!("=== Transd Execution Runner: {} ===", path);

    // 1. Memory Arena Setup (128 MB space from 0x2000_0000 to 0x2800_0000)
    let memory_base = GuestAddr::new(0x2000_0000);
    let memory_size = 128 * 1024 * 1024; // 128 MB
    let mut mem = FlatMemory::new(memory_base, memory_size);

    // 2. Initialize Bionic C bridge, JNI bridge, and GLES passthrough bridge
    let bionic_base = GuestAddr::new(0x2700_0000);
    let heap_base = GuestAddr::new(0x2710_0000);
    let mut bionic = BionicBridge::new(bionic_base, heap_base, 8 * 1024 * 1024);
    bionic.install_stubs(&mut mem)?;

    let jni_base = GuestAddr::new(0x2705_0000);
    let mut jni = JniBridge::new(jni_base);
    jni.install(&mut mem)?;

    let gles_base = GuestAddr::new(0x2708_0000);
    let gles_heap = GuestAddr::new(0x2709_0000);
    let mut gles = GlesBridge::new(gles_base, gles_heap);
    gles.install_stubs(&mut mem)?;

    let resolver = CompositeResolver::new().with(&bionic).with(&gles);

    // 3. Load 32-bit ELF library at load_base
    let load_base = GuestAddr::new(0x2000_0000);
    let lib = ElfLoader::load(data, load_base, &mut mem, &resolver)?;

    println!("Loaded library: {:?}", lib.soname.as_deref().unwrap_or("unnamed"));
    println!("Load Base:      {}", lib.load_base);
    println!("Virtual Size:   {:.2} KB", lib.total_size as f64 / 1024.0);
    println!("Exported syms:  {} symbols", lib.symbols.len());

    // 4. Initialize DBT Engine with asynchronous background JIT compilation
    let mut engine = DbtEngine::new(mem);
    engine.enable_async_jit(transd_rt::AsyncJitConfig::default());

    // Set initial stack pointer at top of guest memory space (8-byte aligned)
    engine.cpu.set_sp(0x27FF_F000);

    // If a persistent AOT translation cache exists, pre-load all blocks for zero cold-start latency
    let default_cache_path = format!("{path}.transd_cache");
    if std::path::Path::new(&default_cache_path).exists() {
        let hash = transd_rt::calculate_sha256(data);
        match engine.load_aot_cache_file(&default_cache_path, Some(&hash)) {
            Ok(count) => println!("Preloaded {} AOT blocks from disk cache ({})", count, default_cache_path),
            Err(e) => eprintln!("Warning: failed to load AOT cache: {}", e),
        }
    }

    // 5. Run static constructors (init_func & init_array)
    let mut constructors = Vec::new();
    if let Some(init) = lib.init_func {
        constructors.push(init);
    }
    constructors.extend_from_slice(&lib.init_array);

    if !constructors.is_empty() {
        println!("\n[Executing {} Constructors]", constructors.len());
        for (idx, &ctor) in constructors.iter().enumerate() {
            println!("  [{}] Invoking ctor at {}", idx, ctor);
            invoke_guest_full(&mut engine, &mut bionic, &mut jni, Some(&mut gles), ctor, &[])?;
        }
    }

    // 6. Resolve Target Function
    let func_name = match target_func {
        Some(name) => name,
        None => {
            // Default: check if JNI_OnLoad exists
            if lib.find_symbol("JNI_OnLoad").is_some() {
                "JNI_OnLoad"
            } else {
                println!("\nAvailable exported symbols:");
                let mut sym_names: Vec<_> = lib.symbols.keys().collect();
                sym_names.sort();
                for name in sym_names.iter().take(20) {
                    println!("  - {}", name);
                }
                if sym_names.len() > 20 {
                    println!("  ... and {} more", sym_names.len() - 20);
                }
                return Err("No function specified with --func <name>".into());
            }
        }
    };

    let func_addr = lib
        .find_symbol(func_name)
        .ok_or_else(|| format!("Function '{}' not found in exported symbols", func_name))?;

    println!("\n[Invoking Target Function]");
    println!("  Function:  {}", func_name);
    println!("  Address:   {}", func_addr);
    println!("  Arguments: {:?}", args);

    let start_time = std::time::Instant::now();

    let res = if func_name == "JNI_OnLoad" {
        invoke_jni_onload(&mut engine, &mut bionic, &mut jni, func_addr)
    } else {
        invoke_guest_full(&mut engine, &mut bionic, &mut jni, Some(&mut gles), func_addr, args)
    };

    let elapsed = start_time.elapsed();

    match res {
        Ok(result) => {
            println!("\n=== Execution Completed ===");
            println!("Return value: {} (0x{:08x})", result, result);
            println!("Execution time: {:.3} ms", elapsed.as_secs_f64() * 1000.0);
            println!("Insts executed: {}", engine.total_insts_executed);
            println!(
                "JIT Cache:    {} blocks cached (hits: {}, misses: {})",
                engine.cache.count(),
                engine.cache.hits,
                engine.cache.misses
            );

            if let Some(stats) = engine.async_jit_stats() {
                println!(
                    "Async JIT:    {} superblocks compiled ({} enqueued, {} deduped, {} workers)",
                    stats.jobs_completed,
                    stats.jobs_enqueued,
                    stats.dedup_filtered,
                    stats.worker_count
                );
            }

            if !gles.draw_calls.is_empty() || gles.swap_count > 0 {
                println!("\n[Graphics (EGL/GLES) Passthrough Stats]");
                println!("  Total draw calls: {}", gles.draw_calls.len());
                println!("  Buffer swaps:     {}", gles.swap_count);
                println!("  Active program:   {}", gles.active_program);
                println!("  Viewport:         {:?}", gles.viewport);
                println!("  Clear color:      {:?}", gles.clear_color);
            }

            if !bionic.logs.is_empty() {
                println!("\n[Captured Android Logs (Logcat)]");
                for log in &bionic.logs {
                    let prio_char = match log.priority {
                        2 => 'V',
                        3 => 'D',
                        4 => 'I',
                        5 => 'W',
                        6 => 'E',
                        7 => 'F',
                        _ => '?',
                    };
                    println!("  [{}/{}] {}", prio_char, log.tag, log.text);
                }
            }

            if !jni.registered_natives.is_empty() {
                println!("\n[Dynamically Registered JNI Methods]");
                for m in &jni.registered_natives {
                    println!("  -> {} {} at {}", m.name, m.signature, m.fn_ptr);
                }
            }

            if show_hud {
                engine
                    .telemetry
                    .update_memory_usage(lib.total_size, engine.pool.allocated_bytes());
                engine
                    .telemetry
                    .update_mips(engine.total_insts_executed, elapsed.as_secs_f64());
                println!("\n{}", engine.render_telemetry_hud());
            }

            Ok(result)
        }
        Err(e) => {
            eprintln!("\nExecution Trapped with Error: {}", e);
            let lib_name = lib.soname.as_deref().unwrap_or(path);
            let mut info =
                transd_rt::tombstone::LibraryInfo::new(lib_name, lib.load_base, lib.total_size);
            for (sym, &addr) in &lib.symbols {
                info.add_symbol(sym, addr);
            }
            let tombstone = engine.capture_tombstone(
                transd_rt::tombstone::TombstoneSignal::Trap {
                    message: e.to_string(),
                },
                &[info],
                "main",
                std::process::id(),
                std::process::id(),
                Some(&e.to_string()),
            );
            println!("\n[Android Tombstone Crash Report]");
            println!("{}", tombstone.format_tombstone());
            Err(e.into())
        }
    }
}
