use byteorder::{ByteOrder, LittleEndian};
use transd_core::{FlatMemory, GuestAddr, Memory};
use transd_elf::{
    ElfLoader, NullResolver, ELFDATA2LSB, ELFCLASS32, ELF_MAGIC, EM_ARM, ET_DYN, EV_CURRENT,
    PF_R, PF_W, PT_DYNAMIC, PT_LOAD, PT_TLS, R_ARM_TLS_DTPMOD32, R_ARM_TLS_DTPOFF32,
    R_ARM_TLS_IE32, R_ARM_TLS_LE32, R_ARM_TLS_TPOFF32, STB_GLOBAL, STT_OBJECT, DT_NULL,
    DT_REL, DT_RELSZ, DT_STRSZ, DT_STRTAB, DT_SYMTAB,
};

fn create_test_tls_elf() -> Vec<u8> {
    let mut elf = vec![0u8; 1024];

    // 1. Ehdr (52 bytes)
    elf[0..4].copy_from_slice(&ELF_MAGIC);
    elf[4] = ELFCLASS32;
    elf[5] = ELFDATA2LSB;
    elf[6] = EV_CURRENT;
    LittleEndian::write_u16(&mut elf[16..18], ET_DYN);
    LittleEndian::write_u16(&mut elf[18..20], EM_ARM);
    LittleEndian::write_u32(&mut elf[20..24], EV_CURRENT as u32);
    LittleEndian::write_u32(&mut elf[24..28], 0x1000); // e_entry
    LittleEndian::write_u32(&mut elf[28..32], 52);     // e_phoff
    LittleEndian::write_u16(&mut elf[40..42], 52);     // e_ehsize
    LittleEndian::write_u16(&mut elf[42..44], 32);     // e_phentsize
    LittleEndian::write_u16(&mut elf[44..46], 3);      // e_phnum (1 PT_LOAD, 1 PT_TLS, 1 PT_DYNAMIC)

    // 2. Phdr #0: PT_LOAD (offset 52)
    LittleEndian::write_u32(&mut elf[52..56], PT_LOAD);
    LittleEndian::write_u32(&mut elf[56..60], 0);      // p_offset
    LittleEndian::write_u32(&mut elf[60..64], 0);      // p_vaddr
    LittleEndian::write_u32(&mut elf[64..68], 0);      // p_paddr
    LittleEndian::write_u32(&mut elf[68..72], 1024);   // p_filesz
    LittleEndian::write_u32(&mut elf[72..76], 1024);   // p_memsz
    LittleEndian::write_u32(&mut elf[76..80], PF_R | PF_W);
    LittleEndian::write_u32(&mut elf[80..84], 4096);   // p_align

    // 3. Phdr #1: PT_TLS (offset 84)
    // TLS template data at offset 0x180, filesz = 8, memsz = 16 (8 bytes initialized, 8 bytes BSS)
    LittleEndian::write_u32(&mut elf[84..88], PT_TLS);
    LittleEndian::write_u32(&mut elf[88..92], 0x180);  // p_offset
    LittleEndian::write_u32(&mut elf[92..96], 0x180);  // p_vaddr
    LittleEndian::write_u32(&mut elf[96..100], 0x180); // p_paddr
    LittleEndian::write_u32(&mut elf[100..104], 8);    // p_filesz
    LittleEndian::write_u32(&mut elf[104..108], 16);   // p_memsz
    LittleEndian::write_u32(&mut elf[108..112], PF_R);
    LittleEndian::write_u32(&mut elf[112..116], 4);    // p_align

    // Template data at offset 0x180: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    elf[0x180..0x188].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

    // 4. Phdr #2: PT_DYNAMIC (offset 116)
    LittleEndian::write_u32(&mut elf[116..120], PT_DYNAMIC);
    LittleEndian::write_u32(&mut elf[120..124], 700);  // p_offset
    LittleEndian::write_u32(&mut elf[124..128], 700);  // p_vaddr
    LittleEndian::write_u32(&mut elf[128..132], 700);  // p_paddr
    LittleEndian::write_u32(&mut elf[132..136], 128);  // p_filesz
    LittleEndian::write_u32(&mut elf[136..140], 128);  // p_memsz
    LittleEndian::write_u32(&mut elf[140..144], PF_R | PF_W);
    LittleEndian::write_u32(&mut elf[144..148], 4);    // p_align

    // 5. Strtab at offset 450: "\0my_tls_var\0"
    let strtab = b"\0my_tls_var\0";
    elf[450..450 + strtab.len()].copy_from_slice(strtab);

    // 6. Symtab at offset 500:
    // Sym #0: undefined dummy (16 bytes)
    // Sym #1: my_tls_var (st_name = 1, st_value = 4 (offset in TLS block), st_size = 4, st_info = STT_OBJECT)
    LittleEndian::write_u32(&mut elf[500 + 16..500 + 20], 1); // st_name
    LittleEndian::write_u32(&mut elf[500 + 20..500 + 24], 4); // st_value = 4
    LittleEndian::write_u32(&mut elf[500 + 24..500 + 28], 4); // st_size = 4
    elf[500 + 28] = (STB_GLOBAL << 4) | STT_OBJECT;
    LittleEndian::write_u16(&mut elf[500 + 30..500 + 32], 1); // st_shndx

    // 7. Relocations at offset 600 (5 relocations * 8 bytes = 40 bytes)
    // Rel #0: R_ARM_TLS_DTPMOD32 at offset 0x100
    LittleEndian::write_u32(&mut elf[600..604], 0x100);
    LittleEndian::write_u32(&mut elf[604..608], (1 << 8) | (R_ARM_TLS_DTPMOD32 as u32));

    // Rel #1: R_ARM_TLS_DTPOFF32 at offset 0x104
    LittleEndian::write_u32(&mut elf[608..612], 0x104);
    LittleEndian::write_u32(&mut elf[612..616], (1 << 8) | (R_ARM_TLS_DTPOFF32 as u32));

    // Rel #2: R_ARM_TLS_TPOFF32 at offset 0x108
    LittleEndian::write_u32(&mut elf[616..620], 0x108);
    LittleEndian::write_u32(&mut elf[620..624], (1 << 8) | (R_ARM_TLS_TPOFF32 as u32));

    // Rel #3: R_ARM_TLS_IE32 at offset 0x10C
    LittleEndian::write_u32(&mut elf[624..628], 0x10C);
    LittleEndian::write_u32(&mut elf[628..632], (1 << 8) | (R_ARM_TLS_IE32 as u32));

    // Rel #4: R_ARM_TLS_LE32 at offset 0x110 (with addend = 8 in memory)
    LittleEndian::write_u32(&mut elf[0x110..0x114], 8);
    LittleEndian::write_u32(&mut elf[632..636], 0x110);
    LittleEndian::write_u32(&mut elf[636..640], (1 << 8) | (R_ARM_TLS_LE32 as u32));

    // 8. Dynamic table at offset 700
    LittleEndian::write_u32(&mut elf[700..704], DT_STRTAB);
    LittleEndian::write_u32(&mut elf[704..708], 450);
    LittleEndian::write_u32(&mut elf[708..712], DT_STRSZ);
    LittleEndian::write_u32(&mut elf[712..716], strtab.len() as u32);
    LittleEndian::write_u32(&mut elf[716..720], DT_SYMTAB);
    LittleEndian::write_u32(&mut elf[720..724], 500);
    LittleEndian::write_u32(&mut elf[724..728], DT_REL);
    LittleEndian::write_u32(&mut elf[728..732], 600);
    LittleEndian::write_u32(&mut elf[732..736], DT_RELSZ);
    LittleEndian::write_u32(&mut elf[736..740], 40);
    LittleEndian::write_u32(&mut elf[740..744], DT_NULL);
    LittleEndian::write_u32(&mut elf[744..748], 0);

    elf
}

#[test]
fn test_elf_tls_template_and_instantiation() {
    let elf_bytes = create_test_tls_elf();
    let mut mem = FlatMemory::new(GuestAddr::new(0x4000_0000), 0x20_000);

    let lib = ElfLoader::load(
        &elf_bytes,
        GuestAddr::new(0x4000_0000),
        &mut mem,
        &NullResolver,
    )
    .unwrap();

    // 1. Verify PT_TLS was detected and parsed
    let tls = lib.tls_template.as_ref().expect("TLS template must be present");
    assert_eq!(tls.filesz, 8);
    assert_eq!(tls.memsz, 16);
    assert_eq!(tls.template_addr, GuestAddr::new(0x4000_0180));

    // 2. Instantiate thread TLS block in guest memory
    let thread_tls_addr = GuestAddr::new(0x4000_5000);
    let instantiated_len = lib.instantiate_tls(thread_tls_addr, &mut mem).unwrap();
    assert_eq!(instantiated_len, 16);

    // Initialized 8 bytes must match template
    let mut init_buf = [0u8; 8];
    mem.read_bytes(thread_tls_addr, &mut init_buf).unwrap();
    assert_eq!(init_buf, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

    // Remaining 8 bytes must be zeroed (TLS BSS)
    let mut bss_buf = [0u8; 8];
    mem.read_bytes(thread_tls_addr.add(8), &mut bss_buf).unwrap();
    assert_eq!(bss_buf, [0; 8]);
}

#[test]
fn test_elf_tls_relocations() {
    let elf_bytes = create_test_tls_elf();
    let mut mem = FlatMemory::new(GuestAddr::new(0x4000_0000), 0x20_000);

    let _lib = ElfLoader::load(
        &elf_bytes,
        GuestAddr::new(0x4000_0000),
        &mut mem,
        &NullResolver,
    )
    .unwrap();

    // 1. Rel #0: R_ARM_TLS_DTPMOD32 at 0x4000_0100 -> Module ID = 1
    let dtpmod = mem.read_u32(GuestAddr::new(0x4000_0100)).unwrap();
    assert_eq!(dtpmod, 1);

    // 2. Rel #1: R_ARM_TLS_DTPOFF32 at 0x4000_0104 -> st_value = 4
    let dtpoff = mem.read_u32(GuestAddr::new(0x4000_0104)).unwrap();
    assert_eq!(dtpoff, 4);

    // 3. Rel #2: R_ARM_TLS_TPOFF32 at 0x4000_0108 -> st_value = 4
    let tpoff = mem.read_u32(GuestAddr::new(0x4000_0108)).unwrap();
    assert_eq!(tpoff, 4);

    // 4. Rel #3: R_ARM_TLS_IE32 at 0x4000_010C -> st_value = 4
    let ie_val = mem.read_u32(GuestAddr::new(0x4000_010C)).unwrap();
    assert_eq!(ie_val, 4);

    // 5. Rel #4: R_ARM_TLS_LE32 at 0x4000_0110 -> st_value (4) + addend (8) = 12
    let le_val = mem.read_u32(GuestAddr::new(0x4000_0110)).unwrap();
    assert_eq!(le_val, 12);
}
