use std::process::Command;
use byteorder::{ByteOrder, LittleEndian};
use transd_elf::{
    ELFCLASS32, ELFDATA2LSB, ELF_MAGIC, EM_ARM, ET_DYN, EV_CURRENT, PF_R, PF_W, PF_X,
    PT_DYNAMIC, PT_LOAD, STB_GLOBAL, STT_FUNC,
};

fn generate_test_so(path: &std::path::Path) {
    let mut elf = vec![0u8; 1024];

    // 1. ELF Header (52 bytes)
    elf[0..4].copy_from_slice(&ELF_MAGIC);
    elf[4] = ELFCLASS32;
    elf[5] = ELFDATA2LSB;
    elf[6] = EV_CURRENT;
    LittleEndian::write_u16(&mut elf[16..18], ET_DYN);
    LittleEndian::write_u16(&mut elf[18..20], EM_ARM);
    LittleEndian::write_u32(&mut elf[20..24], EV_CURRENT as u32);
    LittleEndian::write_u32(&mut elf[24..28], 0);      // e_entry
    LittleEndian::write_u32(&mut elf[28..32], 52);     // e_phoff
    LittleEndian::write_u16(&mut elf[40..42], 52);     // e_ehsize
    LittleEndian::write_u16(&mut elf[42..44], 32);     // e_phentsize
    LittleEndian::write_u16(&mut elf[44..46], 2);      // e_phnum (PT_LOAD, PT_DYNAMIC)

    // 2. Phdr #0: PT_LOAD (offset 52)
    LittleEndian::write_u32(&mut elf[52..56], PT_LOAD);
    LittleEndian::write_u32(&mut elf[56..60], 0);       // p_offset
    LittleEndian::write_u32(&mut elf[60..64], 0);       // p_vaddr
    LittleEndian::write_u32(&mut elf[64..68], 0);       // p_paddr
    LittleEndian::write_u32(&mut elf[68..72], 1024);    // p_filesz
    LittleEndian::write_u32(&mut elf[72..76], 1024);    // p_memsz
    LittleEndian::write_u32(&mut elf[76..80], PF_R | PF_W | PF_X);
    LittleEndian::write_u32(&mut elf[80..84], 4096);    // p_align

    // 3. Phdr #1: PT_DYNAMIC (offset 84)
    LittleEndian::write_u32(&mut elf[84..88], PT_DYNAMIC);
    LittleEndian::write_u32(&mut elf[88..92], 200);     // p_offset
    LittleEndian::write_u32(&mut elf[92..96], 200);     // p_vaddr
    LittleEndian::write_u32(&mut elf[96..100], 200);    // p_paddr
    LittleEndian::write_u32(&mut elf[100..104], 64);    // p_filesz
    LittleEndian::write_u32(&mut elf[104..108], 64);    // p_memsz
    LittleEndian::write_u32(&mut elf[108..112], PF_R | PF_W);
    LittleEndian::write_u32(&mut elf[112..116], 4);     // p_align

    // 4. Code of function add_and_square at offset 0x80 (128 bytes):
    // 0x80: ADD r0, r0, r1 (0xE0800001)
    // 0x84: MUL r2, r0, r0 (0xE0020090)
    // 0x88: MOV r0, r2     (0xE1A00002)
    // 0x8C: BX lr          (0xE12FFF1E)
    LittleEndian::write_u32(&mut elf[0x80..0x84], 0xE080_0001);
    LittleEndian::write_u32(&mut elf[0x84..0x88], 0xE002_0090);
    LittleEndian::write_u32(&mut elf[0x88..0x8C], 0xE1A0_0002);
    LittleEndian::write_u32(&mut elf[0x8C..0x90], 0xE12F_FF1E);

    // 5. Strtab at offset 400: "\0libtest.so\0add_and_square\0"
    let strtab = b"\0libtest.so\0add_and_square\0";
    elf[400..400 + strtab.len()].copy_from_slice(strtab);

    // 6. Symtab at offset 500:
    // Sym #0: undefined dummy (16 bytes)
    // Sym #1: add_and_square (st_name = 12, st_value = 0x80, STT_FUNC)
    LittleEndian::write_u32(&mut elf[500 + 16..500 + 20], 12);  // st_name -> "add_and_square"
    LittleEndian::write_u32(&mut elf[500 + 20..500 + 24], 0x80); // st_value = 0x80
    elf[500 + 28] = (STB_GLOBAL << 4) | STT_FUNC;
    LittleEndian::write_u16(&mut elf[500 + 30..500 + 32], 1);   // st_shndx = 1

    // 7. Dynamic Table at offset 200:
    // Entry 0: DT_STRTAB = 400
    LittleEndian::write_u32(&mut elf[200..204], transd_elf::DT_STRTAB);
    LittleEndian::write_u32(&mut elf[204..208], 400);
    // Entry 1: DT_STRSZ = strtab.len()
    LittleEndian::write_u32(&mut elf[208..212], transd_elf::DT_STRSZ);
    LittleEndian::write_u32(&mut elf[212..216], strtab.len() as u32);
    // Entry 2: DT_SONAME = 1 ("libtest.so")
    LittleEndian::write_u32(&mut elf[216..220], transd_elf::DT_SONAME);
    LittleEndian::write_u32(&mut elf[220..224], 1);
    // Entry 3: DT_SYMTAB = 500
    LittleEndian::write_u32(&mut elf[224..228], transd_elf::DT_SYMTAB);
    LittleEndian::write_u32(&mut elf[228..232], 500);
    // Entry 4: DT_NULL
    LittleEndian::write_u32(&mut elf[232..236], transd_elf::DT_NULL);
    LittleEndian::write_u32(&mut elf[236..240], 0);

    std::fs::write(path, elf).unwrap();
}

#[test]
fn test_cli_info_and_run_e2e() {
    let temp_dir = std::env::temp_dir();
    let test_so_path = temp_dir.join("libcli_test.so");
    generate_test_so(&test_so_path);

    let cli_exe = env!("CARGO_BIN_EXE_transd-cli");

    // 1. Test `transd-cli info <file.so>`
    let info_output = Command::new(cli_exe)
        .arg("info")
        .arg(&test_so_path)
        .output()
        .expect("Failed to execute transd-cli info");

    assert!(info_output.status.success());
    let stdout = String::from_utf8_lossy(&info_output.stdout);
    assert!(stdout.contains("ARMv7-A (32-bit Little-Endian"));
    assert!(stdout.contains("SONAME: libtest.so"));

    // 2. Test `transd-cli run <file.so> --func add_and_square --args 5,6 --hud`
    // (5 + 6)^2 = 11^2 = 121
    let run_output = Command::new(cli_exe)
        .arg("run")
        .arg(&test_so_path)
        .arg("--func")
        .arg("add_and_square")
        .arg("--args")
        .arg("5,6")
        .arg("--hud")
        .output()
        .expect("Failed to execute transd-cli run");

    // Exit code is 121
    assert_eq!(run_output.status.code(), Some(121));
    let stdout = String::from_utf8_lossy(&run_output.stdout);
    assert!(stdout.contains("Return value: 121 (0x00000079)"));
    assert!(stdout.contains("=== Execution Completed ==="));
    assert!(stdout.contains("TRANSD DBT ENGINE TELEMETRY HUD"));
    assert!(stdout.contains("FPS:"));
    assert!(stdout.contains("MIPS:"));
    assert!(stdout.contains("JIT Cache:"));
    assert!(stdout.contains("Arena Memory:"));

    // 3. Test `transd-cli bench <file.so> --func add_and_square --args 5,6 --iter 25`
    let bench_output = Command::new(cli_exe)
        .arg("bench")
        .arg(&test_so_path)
        .arg("--func")
        .arg("add_and_square")
        .arg("--args")
        .arg("5,6")
        .arg("--iter")
        .arg("25")
        .output()
        .expect("Failed to execute transd-cli bench");

    assert!(bench_output.status.success());
    let bench_stdout = String::from_utf8_lossy(&bench_output.stdout);
    assert!(bench_stdout.contains("Transd DBT Benchmark & Profiler"));
    assert!(bench_stdout.contains("Benchmark Iterations: 25"));
    assert!(bench_stdout.contains("Throughput:"));
    assert!(bench_stdout.contains("MIPS"));
    assert!(bench_stdout.contains("=== Benchmark Results ==="));

    // Cleanup
    let _ = std::fs::remove_file(test_so_path);
}

/// Helper to build a minimal valid ZIP/APK in memory
fn build_test_apk(so_bytes: &[u8]) -> Vec<u8> {
    let files = [
        ("lib/armeabi-v7a/libtest.so", so_bytes),
        ("AndroidManifest.xml", b"dummy_manifest"),
    ];

    let mut data = Vec::new();
    let mut cd_offsets = Vec::new();

    for (name, content) in &files {
        let lfh_offset = data.len();
        cd_offsets.push(lfh_offset);

        let mut lfh = vec![0u8; 30];
        LittleEndian::write_u32(&mut lfh[0..4], 0x04034B50);
        LittleEndian::write_u16(&mut lfh[4..6], 20);
        LittleEndian::write_u32(&mut lfh[18..22], content.len() as u32);
        LittleEndian::write_u32(&mut lfh[22..26], content.len() as u32);
        LittleEndian::write_u16(&mut lfh[26..28], name.len() as u16);

        data.extend_from_slice(&lfh);
        data.extend_from_slice(name.as_bytes());
        data.extend_from_slice(content);
    }

    let cd_start = data.len();
    for (i, (name, content)) in files.iter().enumerate() {
        let mut cdh = vec![0u8; 46];
        LittleEndian::write_u32(&mut cdh[0..4], 0x02014B50);
        LittleEndian::write_u16(&mut cdh[4..6], 20);
        LittleEndian::write_u16(&mut cdh[6..8], 20);
        LittleEndian::write_u32(&mut cdh[20..24], content.len() as u32);
        LittleEndian::write_u32(&mut cdh[24..28], content.len() as u32);
        LittleEndian::write_u16(&mut cdh[28..30], name.len() as u16);
        LittleEndian::write_u32(&mut cdh[42..46], cd_offsets[i] as u32);

        data.extend_from_slice(&cdh);
        data.extend_from_slice(name.as_bytes());
    }

    let cd_size = data.len() - cd_start;
    let mut eocd = vec![0u8; 22];
    LittleEndian::write_u32(&mut eocd[0..4], 0x06054B50);
    LittleEndian::write_u16(&mut eocd[8..10], files.len() as u16);
    LittleEndian::write_u16(&mut eocd[10..12], files.len() as u16);
    LittleEndian::write_u32(&mut eocd[12..16], cd_size as u32);
    LittleEndian::write_u32(&mut eocd[16..20], cd_start as u32);
    data.extend_from_slice(&eocd);

    data
}

#[test]
fn test_cli_apk_and_devices_e2e() {
    let temp_dir = std::env::temp_dir();
    let test_so_path = temp_dir.join("libapk_test.so");
    generate_test_so(&test_so_path);
    let so_bytes = std::fs::read(&test_so_path).unwrap();
    let _ = std::fs::remove_file(test_so_path);

    let apk_bytes = build_test_apk(&so_bytes);
    let test_apk_path = temp_dir.join("test_game.apk");
    std::fs::write(&test_apk_path, apk_bytes).unwrap();

    let cli_exe = env!("CARGO_BIN_EXE_transd-cli");

    // 1. Inspect APK: transd-cli apk <test_game.apk>
    let info_output = Command::new(cli_exe)
        .arg("apk")
        .arg(&test_apk_path)
        .output()
        .expect("Failed to execute transd-cli apk");

    assert!(info_output.status.success());
    let stdout = String::from_utf8_lossy(&info_output.stdout);
    assert!(stdout.contains("Transd APK Inspector"));
    assert!(stdout.contains("32-bit ARM Only: YES (Requires Transd DBT on ARMv9+)"));
    assert!(stdout.contains("lib/armeabi-v7a/libtest.so"));

    // 2. Execute APK: transd-cli apk <test_game.apk> --run --func add_and_square --args 3,4
    // (3 + 4)^2 = 7^2 = 49
    let run_output = Command::new(cli_exe)
        .arg("apk")
        .arg(&test_apk_path)
        .arg("--run")
        .arg("--func")
        .arg("add_and_square")
        .arg("--args")
        .arg("3,4")
        .output()
        .expect("Failed to execute transd-cli apk --run");

    assert_eq!(run_output.status.code(), Some(49));
    let stdout = String::from_utf8_lossy(&run_output.stdout);
    assert!(stdout.contains("Extracting & Running 32-bit Native Library: libtest.so"));
    assert!(stdout.contains("Return value: 49 (0x00000031)"));

    // 3. Test `transd-cli devices`
    let dev_output = Command::new(cli_exe)
        .arg("devices")
        .output()
        .expect("Failed to execute transd-cli devices");

    assert!(dev_output.status.success());
    let stdout = String::from_utf8_lossy(&dev_output.stdout);
    assert!(stdout.contains("Transd Android ADB Device Inspector"));

    // Cleanup
    let _ = std::fs::remove_file(test_apk_path);
}

#[test]
fn test_cli_subcommands_run_apk_aot_compile_repackage() {
    let temp_dir = std::env::temp_dir();
    let test_so_path = temp_dir.join("libcli_subcmd_test.so");
    generate_test_so(&test_so_path);
    let so_bytes = std::fs::read(&test_so_path).unwrap();

    let test_apk_path = temp_dir.join("cli_subcmd_test.apk");
    let apk_bytes = build_test_apk(&so_bytes);
    std::fs::write(&test_apk_path, apk_bytes).unwrap();

    let cli_exe = env!("CARGO_BIN_EXE_transd-cli");

    // 1. Test `transd-cli run <apk>` directly (without needing `apk --run`)
    let run_apk_out = Command::new(cli_exe)
        .arg("run")
        .arg(&test_apk_path)
        .arg("--func")
        .arg("add_and_square")
        .arg("--args")
        .arg("6,7")
        .output()
        .expect("Failed to execute transd-cli run <apk>");

    // (6 + 7)^2 = 13^2 = 169
    assert_eq!(run_apk_out.status.code(), Some(169));
    let run_stdout = String::from_utf8_lossy(&run_apk_out.stdout);
    assert!(run_stdout.contains("Extracting & Running 32-bit Native Library: libtest.so"));
    assert!(run_stdout.contains("Return value: 169 (0x000000a9)"));

    // 2. Test `transd-cli aot-compile <so> -o <cache>`
    let cache_path = temp_dir.join("libcli_subcmd_test.so.transd_cache");
    let aot_out = Command::new(cli_exe)
        .arg("aot-compile")
        .arg(&test_so_path)
        .arg("-o")
        .arg(&cache_path)
        .output()
        .expect("Failed to execute transd-cli aot-compile");

    assert!(aot_out.status.success());
    let aot_stdout = String::from_utf8_lossy(&aot_out.stdout);
    assert!(aot_stdout.contains("Transd AOT Pre-Compiler"));
    assert!(cache_path.exists());

    // 3. Test `transd-cli repackage <in.apk> -o <out.apk>`
    let out_apk_path = temp_dir.join("repackaged_subcmd_out.apk");
    let repkg_out = Command::new(cli_exe)
        .arg("repackage")
        .arg(&test_apk_path)
        .arg("-o")
        .arg(&out_apk_path)
        .output()
        .expect("Failed to execute transd-cli repackage");

    assert!(repkg_out.status.success());
    let repkg_stdout = String::from_utf8_lossy(&repkg_out.stdout);
    assert!(repkg_stdout.contains("Repackaging Successful!"));
    assert!(out_apk_path.exists());

    // Cleanup
    let _ = std::fs::remove_file(test_so_path);
    let _ = std::fs::remove_file(test_apk_path);
    let _ = std::fs::remove_file(cache_path);
    let _ = std::fs::remove_file(out_apk_path);
}
