use byteorder::{ByteOrder, LittleEndian};
use std::fs;
use walzer32_android::session::Walzer32Session;
use walzer32_core::GuestAddr;
use walzer32_elf::{
    DT_STRSZ, DT_STRTAB, DT_SYMENT, DT_SYMTAB, ELFCLASS32, ELFDATA2LSB, ELF_MAGIC, EM_ARM,
    ET_DYN, EV_CURRENT, PF_R, PF_W, PF_X, PT_DYNAMIC, PT_LOAD, STB_GLOBAL, STT_FUNC,
};
use walzer32_rt::calculate_sha256;

fn build_arm32_test_library() -> Vec<u8> {
    let mut elf = vec![0u8; 1024];

    // ELF Header
    elf[0..4].copy_from_slice(&ELF_MAGIC);
    elf[4] = ELFCLASS32;
    elf[5] = ELFDATA2LSB;
    elf[6] = EV_CURRENT;
    LittleEndian::write_u16(&mut elf[16..18], ET_DYN);
    LittleEndian::write_u16(&mut elf[18..20], EM_ARM);
    LittleEndian::write_u32(&mut elf[20..24], EV_CURRENT as u32);
    LittleEndian::write_u32(&mut elf[28..32], 52); // e_phoff
    LittleEndian::write_u16(&mut elf[40..42], 52); // e_ehsize
    LittleEndian::write_u16(&mut elf[42..44], 32); // e_phentsize
    LittleEndian::write_u16(&mut elf[44..46], 2);  // e_phnum

    // Phdr #0: PT_LOAD
    LittleEndian::write_u32(&mut elf[52..56], PT_LOAD);
    LittleEndian::write_u32(&mut elf[68..72], 1024); // p_filesz
    LittleEndian::write_u32(&mut elf[72..76], 1024); // p_memsz
    LittleEndian::write_u32(&mut elf[76..80], PF_R | PF_W | PF_X);
    LittleEndian::write_u32(&mut elf[80..84], 4096);

    // Phdr #1: PT_DYNAMIC
    LittleEndian::write_u32(&mut elf[84..88], PT_DYNAMIC);
    LittleEndian::write_u32(&mut elf[88..92], 200);  // p_offset
    LittleEndian::write_u32(&mut elf[92..96], 200);  // p_vaddr
    LittleEndian::write_u32(&mut elf[100..104], 64); // p_filesz
    LittleEndian::write_u32(&mut elf[104..108], 64); // p_memsz
    LittleEndian::write_u32(&mut elf[108..112], PF_R | PF_W);
    LittleEndian::write_u32(&mut elf[112..116], 4);

    // Code of function `compute_val` at offset 0x80:
    // 0x80: ADD r0, r0, r1 (0xE0800001)
    // 0x84: BX lr          (0xE12FFF1E)
    LittleEndian::write_u32(&mut elf[0x80..0x84], 0xE080_0001);
    LittleEndian::write_u32(&mut elf[0x84..0x88], 0xE12F_FF1E);

    // Strtab at offset 400
    let strtab = b"\0libaottest.so\0compute_val\0";
    elf[400..400 + strtab.len()].copy_from_slice(strtab);

    // Symtab at offset 500
    LittleEndian::write_u32(&mut elf[500 + 16..500 + 20], 15);   // st_name -> "compute_val"
    LittleEndian::write_u32(&mut elf[500 + 20..500 + 24], 0x80); // st_value = 0x80
    elf[500 + 28] = (STB_GLOBAL << 4) | STT_FUNC;
    LittleEndian::write_u16(&mut elf[500 + 30..500 + 32], 1);

    // Dynamic Table at offset 200
    LittleEndian::write_u32(&mut elf[200..204], DT_STRTAB);
    LittleEndian::write_u32(&mut elf[204..208], 400);

    LittleEndian::write_u32(&mut elf[208..212], DT_STRSZ);
    LittleEndian::write_u32(&mut elf[212..216], strtab.len() as u32);

    LittleEndian::write_u32(&mut elf[216..220], DT_SYMTAB);
    LittleEndian::write_u32(&mut elf[220..224], 500);

    LittleEndian::write_u32(&mut elf[224..228], DT_SYMENT);
    LittleEndian::write_u32(&mut elf[228..232], 16);

    elf
}

#[test]
fn test_session_aot_persistence_and_cold_start() {
    let elf_data = build_arm32_test_library();
    let temp_dir = std::env::temp_dir().join("walzer32_aot_test_dir");
    let _ = fs::create_dir_all(&temp_dir);

    let cache_file = temp_dir.join("libaottest.so.walzer32_cache");
    let _ = fs::remove_file(&cache_file);

    // --- Session 1: First launch without cache ---
    {
        let mut session1 = Walzer32Session::new(GuestAddr::new(0x7000_0000), 0x800_0000).unwrap();
        session1.set_aot_cache_dir(&temp_dir);

        let lib1 = session1.load_library_bytes("libaottest.so", &elf_data).unwrap();
        let sym_addr = lib1.find_symbol("compute_val").unwrap();

        // Calling native function should execute and return 10 + 20 = 30
        let res = session1.call_native(sym_addr, &[10, 20]).unwrap();
        assert_eq!(res, 30);

        // AOT cache file must now exist on disk!
        assert!(cache_file.exists());
    }

    // --- Session 2: Second launch with precompiled AOT cache ---
    {
        let mut session2 = Walzer32Session::new(GuestAddr::new(0x7000_0000), 0x800_0000).unwrap();
        session2.set_aot_cache_dir(&temp_dir);

        // Loading library should pre-load precompiled blocks directly from disk
        let lib2 = session2.load_library_bytes("libaottest.so", &elf_data).unwrap();
        assert!(session2.engine.cache.blocks.len() > 0);

        let sym_addr = lib2.find_symbol("compute_val").unwrap();

        // Must execute directly with 0 cache misses
        let initial_misses = session2.engine.cache.misses;
        let res = session2.call_native(sym_addr, &[15, 25]).unwrap();
        assert_eq!(res, 40);
        assert_eq!(session2.engine.cache.misses, initial_misses);
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_session_aot_export_import() {
    let elf_data = build_arm32_test_library();
    let hash = calculate_sha256(&elf_data);

    let mut session = Walzer32Session::new(GuestAddr::new(0x7000_0000), 0x800_0000).unwrap();
    let lib = session.load_library_bytes("libaottest.so", &elf_data).unwrap();

    // Precompile library
    let precompiled = session.precompile_library("libaottest.so", 100);
    assert!(precompiled > 0);

    // Export cache
    let disk_cache = session.export_aot_cache(hash, [0u8; 20]);
    assert_eq!(disk_cache.header.binary_hash, hash);
    assert!(disk_cache.records.len() > 0);

    // Fresh session imports cache
    let mut session_fresh = Walzer32Session::new(GuestAddr::new(0x7000_0000), 0x800_0000).unwrap();
    let imported = session_fresh.import_aot_cache(&disk_cache).unwrap();
    assert_eq!(imported, disk_cache.records.len());
    assert_eq!(session_fresh.engine.cache.blocks.len(), disk_cache.records.len());

    let sym_addr = lib.find_symbol("compute_val").unwrap();
    assert!(session_fresh.engine.cache.lookup(sym_addr).is_some());
}
