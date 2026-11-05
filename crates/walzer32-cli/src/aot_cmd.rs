use std::fs;
use std::path::Path;
use walzer32_bridge::{BionicBridge, GlesBridge, JniBridge};
use walzer32_core::{FlatMemory, GuestAddr};
use walzer32_elf::{CompositeResolver, ElfLoader};
use walzer32_rt::{calculate_sha256, DbtEngine};

pub fn compile_aot(
    so_path: &str,
    output_path: Option<&str>,
    max_blocks: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Walzer32 AOT Pre-Compiler: {} ===", so_path);

    let data = fs::read(so_path)?;
    let hash = calculate_sha256(&data);
    let hash_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    println!("Binary SHA-256: {}", hash_hex);

    let default_output = format!("{so_path}.walzer32_cache");
    let out_file = output_path.unwrap_or(&default_output);

    // 1. Setup arena memory and bridges
    let memory_base = GuestAddr::new(0x2000_0000);
    let memory_size = 128 * 1024 * 1024;
    let mut mem = FlatMemory::new(memory_base, memory_size);

    let bionic_base = GuestAddr::new(0x2700_0000);
    let heap_base = GuestAddr::new(0x2710_0000);
    let bionic = BionicBridge::new(bionic_base, heap_base, 8 * 1024 * 1024);
    bionic.install_stubs(&mut mem)?;

    let jni_base = GuestAddr::new(0x2705_0000);
    let jni = JniBridge::new(jni_base);
    jni.install(&mut mem)?;

    let gles_base = GuestAddr::new(0x2708_0000);
    let gles_heap = GuestAddr::new(0x2709_0000);
    let gles = GlesBridge::new(gles_base, gles_heap);
    gles.install_stubs(&mut mem)?;

    let resolver = CompositeResolver::new().with(&bionic).with(&gles);

    // 2. Load ELF
    let load_base = GuestAddr::new(0x2000_0000);
    let lib = ElfLoader::load(&data, load_base, &mut mem, &resolver)?;

    println!("Loaded library: {:?}", lib.soname.as_deref().unwrap_or("unnamed"));
    println!("Load Base:      {}", lib.load_base);
    println!("Exported syms:  {} symbols", lib.symbols.len());

    // 3. Initialize DBT Engine
    let mut engine = DbtEngine::new(mem);
    engine.cpu.set_sp(0x27FF_F000);

    // 4. Gather entry points
    let mut entry_points = Vec::new();
    if let Some(init) = lib.init_func {
        entry_points.push(init);
    }
    entry_points.extend_from_slice(&lib.init_array);
    if lib.entry_point.as_u32() != 0 {
        entry_points.push(lib.entry_point);
    }
    for &sym_addr in lib.symbols.values() {
        entry_points.push(sym_addr);
    }

    println!("Compiling reachable code paths (max {} blocks)...", max_blocks);
    let start_t = std::time::Instant::now();
    let compiled = engine.precompile_aot(&entry_points, max_blocks);
    let elapsed = start_t.elapsed();

    let disk_cache = engine.export_aot_cache(hash, [0u8; 20]);
    disk_cache.save_to_file(Path::new(out_file))?;

    let file_size = fs::metadata(out_file)?.len();

    println!("=== AOT Compilation Successful ===");
    println!("Blocks compiled:      {}", compiled);
    println!("Superblocks:          {}", disk_cache.header.superblock_count);
    println!("Emitted code bytes:   {} bytes", disk_cache.header.total_code_bytes);
    println!("Cache file size:      {} bytes ({:.2} KB)", file_size, file_size as f64 / 1024.0);
    println!("Compilation time:     {:.2?}", elapsed);
    println!("Output cache path:    {}", out_file);

    Ok(())
}
