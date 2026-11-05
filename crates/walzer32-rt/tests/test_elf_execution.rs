use byteorder::{ByteOrder, LittleEndian};
use walzer32_core::{FlatMemory, GuestAddr, Reg};
use walzer32_elf::{
    ElfLoader, NullResolver, ELFCLASS32, ELFDATA2LSB, ELF_MAGIC, EM_ARM, ET_DYN, EV_CURRENT,
    PF_R, PF_W, PF_X, PT_DYNAMIC, PT_LOAD, STB_GLOBAL, STT_FUNC,
};
use walzer32_rt::DbtEngine;

fn build_arm32_calculator_so() -> Vec<u8> {
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

    // 5. Strtab at offset 400: "\0libcalc.so\0add_and_square\0"
    let strtab = b"\0libcalc.so\0add_and_square\0";
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
    LittleEndian::write_u32(&mut elf[200..204], walzer32_elf::DT_STRTAB);
    LittleEndian::write_u32(&mut elf[204..208], 400);
    // Entry 1: DT_STRSZ = strtab.len()
    LittleEndian::write_u32(&mut elf[208..212], walzer32_elf::DT_STRSZ);
    LittleEndian::write_u32(&mut elf[212..216], strtab.len() as u32);
    // Entry 2: DT_SONAME = 1 ("libcalc.so")
    LittleEndian::write_u32(&mut elf[216..220], walzer32_elf::DT_SONAME);
    LittleEndian::write_u32(&mut elf[220..224], 1);
    // Entry 3: DT_SYMTAB = 500
    LittleEndian::write_u32(&mut elf[224..228], walzer32_elf::DT_SYMTAB);
    LittleEndian::write_u32(&mut elf[228..232], 500);
    // Entry 4: DT_NULL
    LittleEndian::write_u32(&mut elf[232..236], walzer32_elf::DT_NULL);
    LittleEndian::write_u32(&mut elf[236..240], 0);

    elf
}

#[test]
fn test_load_so_and_execute_native_function() {
    let elf_data = build_arm32_calculator_so();
    let mut mem = FlatMemory::new(GuestAddr::new(0x2000_0000), 0x20_000);

    // 1. Load the shared library at guest address 0x2000_0000
    let lib = ElfLoader::load(
        &elf_data,
        GuestAddr::new(0x2000_0000),
        &mut mem,
        &NullResolver,
    )
    .unwrap();

    assert_eq!(lib.soname.as_deref(), Some("libcalc.so"));

    // 2. Locate the exported function `add_and_square`
    let func_addr = lib.find_symbol("add_and_square").expect("Symbol not found");
    assert_eq!(func_addr, GuestAddr::new(0x2000_0080));

    // 3. Initialize DBT Engine
    let mut engine = DbtEngine::new(mem);

    // 4. Set up parameters:
    // Calling add_and_square(a = 3, b = 4)
    engine.cpu.set_reg(Reg::R0, 3);
    engine.cpu.set_reg(Reg::R1, 4);
    engine.cpu.set_sp(0x2001_F000);

    // Sentinel return address: 0xDEAD_BEE0
    let sentinel_lr = 0xDEAD_BEE0;
    engine.cpu.set_lr(sentinel_lr);
    engine.cpu.set_pc(func_addr);

    // 5. Execute steps until returning to the sentinel address in LR
    let mut step_count = 0;
    while engine.cpu.pc() != GuestAddr::new(sentinel_lr) {
        let (inst, _len) = walzer32_decoder::decode_next(&engine.mem, engine.cpu.pc(), engine.cpu.is_thumb()).unwrap();
        println!("Step {}: PC = {}, raw = 0x{:08x}, inst = {:?}, R0 = {}, R1 = {}, R2 = {}, LR = 0x{:x}", 
            step_count, engine.cpu.pc(), inst.raw, inst.op, engine.cpu.reg(Reg::R0), engine.cpu.reg(Reg::R1), engine.cpu.reg(Reg::R2), engine.cpu.lr());
        engine.step().unwrap();
        step_count += 1;
        assert!(step_count < 20, "Execution took too many steps or looped");
    }

    // 6. Verify result: (3 + 4)^2 = 7^2 = 49
    let result = engine.cpu.reg(Reg::R0);
    assert_eq!(result, 49);
    assert_eq!(step_count, 4); // Exact 4 instructions executed!
}
