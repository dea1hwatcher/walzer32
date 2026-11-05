use byteorder::{ByteOrder, LittleEndian};
use walzer32_elf::fixups::sanitize_elf_headers;
use walzer32_elf::header::*;

#[test]
fn test_sanitize_elf_headers_textrel_and_needed() {
    let mut elf = vec![0u8; 1024];

    // 1. ELF Header (Elf32_Ehdr)
    elf[0..4].copy_from_slice(&ELF_MAGIC);
    elf[4] = ELFCLASS32;
    elf[5] = ELFDATA2LSB;
    elf[6] = EV_CURRENT;
    LittleEndian::write_u16(&mut elf[16..18], ET_DYN);
    LittleEndian::write_u16(&mut elf[18..20], EM_ARM);
    LittleEndian::write_u32(&mut elf[20..24], EV_CURRENT as u32);

    // e_phoff = 52, e_phentsize = 32, e_phnum = 2
    LittleEndian::write_u32(&mut elf[28..32], 52);
    LittleEndian::write_u16(&mut elf[42..44], 32);
    LittleEndian::write_u16(&mut elf[44..46], 2);

    // 2. Program Headers
    // PHDR 0: PT_LOAD covering entire file (vaddr = 0x10000, offset = 0, filesz = 1024)
    let ph0 = 52;
    LittleEndian::write_u32(&mut elf[ph0..ph0 + 4], PT_LOAD);
    LittleEndian::write_u32(&mut elf[ph0 + 4..ph0 + 8], 0);       // p_offset
    LittleEndian::write_u32(&mut elf[ph0 + 8..ph0 + 12], 0x10000); // p_vaddr
    LittleEndian::write_u32(&mut elf[ph0 + 16..ph0 + 20], 1024);  // p_filesz
    LittleEndian::write_u32(&mut elf[ph0 + 24..ph0 + 28], 4);     // p_flags = R

    // PHDR 1: PT_DYNAMIC at offset 200, vaddr 0x100c8, filesz = 80
    let ph1 = 52 + 32;
    let dyn_offset = 200;
    let dyn_vaddr = 0x10000 + dyn_offset as u32;
    LittleEndian::write_u32(&mut elf[ph1..ph1 + 4], PT_DYNAMIC);
    LittleEndian::write_u32(&mut elf[ph1 + 4..ph1 + 8], dyn_offset as u32);
    LittleEndian::write_u32(&mut elf[ph1 + 8..ph1 + 12], dyn_vaddr);
    LittleEndian::write_u32(&mut elf[ph1 + 16..ph1 + 20], 80);
    LittleEndian::write_u32(&mut elf[ph1 + 24..ph1 + 28], 6); // p_flags = RW

    // 3. String Table (.dynstr) at offset 400 (vaddr = 0x10190)
    let strtab_offset = 400;
    let strtab_vaddr = 0x10000 + strtab_offset as u32;
    let strtab_bytes = b"\0/system/lib/libc.so\0libm.so\0/data/data/com.foo/libfoo.so\0";
    elf[strtab_offset..strtab_offset + strtab_bytes.len()].copy_from_slice(strtab_bytes);

    // 4. Dynamic table entries (8 entries * 8 bytes = 64 bytes)
    // Entry 0: DT_STRTAB
    let mut cur = dyn_offset;
    LittleEndian::write_u32(&mut elf[cur..cur + 4], DT_STRTAB);
    LittleEndian::write_u32(&mut elf[cur + 4..cur + 8], strtab_vaddr);
    cur += 8;

    // Entry 1: DT_STRSZ
    LittleEndian::write_u32(&mut elf[cur..cur + 4], DT_STRSZ);
    LittleEndian::write_u32(&mut elf[cur + 4..cur + 8], strtab_bytes.len() as u32);
    cur += 8;

    // Entry 2: DT_TEXTREL (tag 22, val 0)
    LittleEndian::write_u32(&mut elf[cur..cur + 4], DT_TEXTREL);
    LittleEndian::write_u32(&mut elf[cur + 4..cur + 8], 0);
    cur += 8;

    // Entry 3: DT_FLAGS with DF_TEXTREL (tag 30, val 0x0000_0005: DF_ORIGIN | DF_TEXTREL)
    LittleEndian::write_u32(&mut elf[cur..cur + 4], DT_FLAGS);
    LittleEndian::write_u32(&mut elf[cur + 4..cur + 8], 0x0000_0005);
    cur += 8;

    // Entry 4: DT_NEEDED = 1 ("/system/lib/libc.so")
    LittleEndian::write_u32(&mut elf[cur..cur + 4], DT_NEEDED);
    LittleEndian::write_u32(&mut elf[cur + 4..cur + 8], 1);
    cur += 8;

    // Entry 5: DT_NEEDED = 21 ("libm.so")
    LittleEndian::write_u32(&mut elf[cur..cur + 4], DT_NEEDED);
    LittleEndian::write_u32(&mut elf[cur + 4..cur + 8], 21);
    cur += 8;

    // Entry 6: DT_NEEDED = 29 ("/data/data/com.foo/libfoo.so")
    LittleEndian::write_u32(&mut elf[cur..cur + 4], DT_NEEDED);
    LittleEndian::write_u32(&mut elf[cur + 4..cur + 8], 29);
    cur += 8;

    // Entry 7: DT_NULL
    LittleEndian::write_u32(&mut elf[cur..cur + 4], DT_NULL);
    LittleEndian::write_u32(&mut elf[cur + 4..cur + 8], 0);

    // Run sanitize_elf_headers
    let report = sanitize_elf_headers(&mut elf).expect("Sanitization failed");

    // Verify report
    assert!(report.textrel_cleared, "DT_TEXTREL should have been cleared");
    assert!(report.df_textrel_cleared, "DF_TEXTREL bit should have been cleared");
    assert_eq!(report.sanitized_needed.len(), 2);
    assert_eq!(report.sanitized_needed[0], ("/system/lib/libc.so".to_string(), "libc.so".to_string()));
    assert_eq!(report.sanitized_needed[1], ("/data/data/com.foo/libfoo.so".to_string(), "libfoo.so".to_string()));

    // Verify mutated binary
    // Entry 2 (DT_TEXTREL) should now be DT_DEBUG (21)
    let tag2 = LittleEndian::read_u32(&elf[dyn_offset + 16..dyn_offset + 20]);
    assert_eq!(tag2, DT_DEBUG);

    // Entry 3 (DT_FLAGS) should now be 0x0000_0001 (DF_ORIGIN, without DF_TEXTREL)
    let val3 = LittleEndian::read_u32(&elf[dyn_offset + 28..dyn_offset + 32]);
    assert_eq!(val3, 0x0000_0001);

    // Entry 4 (DT_NEEDED) should now point to "libc.so" (1 + 12 = 13)
    let val4 = LittleEndian::read_u32(&elf[dyn_offset + 36..dyn_offset + 40]);
    let name4 = std::str::from_utf8(&elf[strtab_offset + val4 as usize..strtab_offset + val4 as usize + 7]).unwrap();
    assert_eq!(name4, "libc.so");

    // Entry 5 (DT_NEEDED) should still point to "libm.so" (21)
    let val5 = LittleEndian::read_u32(&elf[dyn_offset + 44..dyn_offset + 48]);
    assert_eq!(val5, 21);

    // Entry 6 (DT_NEEDED) should now point to "libfoo.so" (29 + 23 = 52)
    let val6 = LittleEndian::read_u32(&elf[dyn_offset + 52..dyn_offset + 56]);
    let name6 = std::str::from_utf8(&elf[strtab_offset + val6 as usize..strtab_offset + val6 as usize + 9]).unwrap();
    assert_eq!(name6, "libfoo.so");
}
