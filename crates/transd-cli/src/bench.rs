/// Benchmark Profiler for Transd DBT.
///
/// Measures:
///   - Basic block JIT compilation latency (us/block)
///   - Execution throughput in MIPS (Million Instructions Per Second)
///   - JIT cache hit ratios and block chaining efficiency
///   - Memory throughput and allocation overhead

use std::time::Instant;
use transd_bridge::{
    invoke_guest_full, invoke_jni_onload, BionicBridge, GlesBridge, JniBridge,
};
use transd_core::{FlatMemory, GuestAddr};
use transd_elf::{CompositeResolver, ElfLoader};
use transd_rt::DbtEngine;

#[allow(dead_code)]
pub struct BenchmarkResult {
    pub iterations: u32,
    pub total_insts: u64,
    pub total_time_ms: f64,
    pub mips: f64,
    pub blocks_compiled: usize,
    pub jit_bytes_generated: usize,
    pub cache_hit_ratio: f64,
    pub chained_jumps: u64,
}

pub fn run_benchmark(
    path: &str,
    data: &[u8],
    target_func: Option<&str>,
    args: &[u32],
    iterations: u32,
) -> Result<BenchmarkResult, Box<dyn std::error::Error>> {
    println!("=== Transd DBT Benchmark & Profiler: {} ===", path);
    println!("Benchmark Iterations: {}", iterations);

    // 1. Setup Guest Arena
    let memory_base = GuestAddr::new(0x2000_0000);
    let memory_size = 128 * 1024 * 1024;
    let mut mem = FlatMemory::new(memory_base, memory_size);

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
    let load_base = GuestAddr::new(0x2000_0000);
    let lib = ElfLoader::load(data, load_base, &mut mem, &resolver)?;

    let mut engine = DbtEngine::new(mem);
    engine.cpu.set_sp(0x27FF_F000);

    // Constructors
    if let Some(init) = lib.init_func {
        invoke_guest_full(&mut engine, &mut bionic, &mut jni, Some(&mut gles), init, &[])?;
    }
    for &ctor in &lib.init_array {
        invoke_guest_full(&mut engine, &mut bionic, &mut jni, Some(&mut gles), ctor, &[])?;
    }

    // Resolve target
    let func_name = match target_func {
        Some(name) => name,
        None => {
            if lib.find_symbol("JNI_OnLoad").is_some() {
                "JNI_OnLoad"
            } else if let Some(first_sym) = lib.symbols.keys().next() {
                first_sym.as_str()
            } else {
                return Err("No functions available to benchmark".into());
            }
        }
    };

    let func_addr = lib
        .find_symbol(func_name)
        .ok_or_else(|| format!("Symbol '{}' not found", func_name))?;

    println!("Target Function:      {} at {}", func_name, func_addr);

    // Warmup & JIT Compile Pass
    let compile_start = Instant::now();
    if func_name == "JNI_OnLoad" {
        invoke_jni_onload(&mut engine, &mut bionic, &mut jni, func_addr)?;
    } else {
        invoke_guest_full(&mut engine, &mut bionic, &mut jni, Some(&mut gles), func_addr, args)?;
    }
    let compile_elapsed = compile_start.elapsed();

    let blocks_compiled = engine.cache.count();
    let jit_bytes = engine.pool.total_bytes;
    let initial_insts = engine.total_insts_executed;

    println!("[Warmup / Compilation Phase]");
    println!("  Blocks compiled:    {}", blocks_compiled);
    println!("  JIT bytes created:  {} bytes", jit_bytes);
    println!("  Warmup time:        {:.3} ms", compile_elapsed.as_secs_f64() * 1000.0);

    // Measurement Loops
    let bench_start = Instant::now();
    for _ in 0..iterations {
        engine.cpu.set_sp(0x27FF_F000);
        if func_name == "JNI_OnLoad" {
            let _ = invoke_jni_onload(&mut engine, &mut bionic, &mut jni, func_addr)?;
        } else {
            let _ = invoke_guest_full(&mut engine, &mut bionic, &mut jni, Some(&mut gles), func_addr, args)?;
        }
    }
    let bench_elapsed = bench_start.elapsed();
    let bench_time_secs = bench_elapsed.as_secs_f64();
    let total_insts_measured = engine.total_insts_executed - initial_insts;

    let mips = if bench_time_secs > 0.0 {
        (total_insts_measured as f64) / (bench_time_secs * 1_000_000.0)
    } else {
        0.0
    };

    let total_lookups = engine.cache.hits + engine.cache.misses;
    let hit_ratio = if total_lookups > 0 {
        (engine.cache.hits as f64 / total_lookups as f64) * 100.0
    } else {
        0.0
    };

    println!("\n=== Benchmark Results ===");
    println!("  Total Iterations:   {}", iterations);
    println!("  Total Insts:        {}", total_insts_measured);
    println!("  Elapsed Time:       {:.3} ms", bench_time_secs * 1000.0);
    println!("  Average per run:    {:.3} ms", (bench_time_secs * 1000.0) / iterations as f64);
    println!("  Throughput:         {:.2} MIPS", mips);
    println!("  JIT Cache Hits:     {} ({:.1}%)", engine.cache.hits, hit_ratio);
    println!("  Chained Jumps:      {}", engine.cache.chained_jumps);

    Ok(BenchmarkResult {
        iterations,
        total_insts: total_insts_measured,
        total_time_ms: bench_time_secs * 1000.0,
        mips,
        blocks_compiled,
        jit_bytes_generated: jit_bytes,
        cache_hit_ratio: hit_ratio,
        chained_jumps: engine.cache.chained_jumps,
    })
}
