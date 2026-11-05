use walzer32_elf::{ElfParser, PT_DYNAMIC, PT_LOAD};

pub fn print_elf_info(path: &str, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Walzer32 ELF Inspector: {} ===", path);
    println!("File size: {} bytes ({:.2} KB)", data.len(), data.len() as f64 / 1024.0);

    let parser = ElfParser::parse(data)?;

    println!("\n[ELF Header]");
    println!("  Machine:       ARMv7-A (32-bit Little-Endian, EM_ARM={})", parser.header.e_machine);
    println!("  Type:          {}", if parser.header.e_type == 3 { "Shared Object (ET_DYN / .so)" } else { "Executable (ET_EXEC)" });
    println!("  Entry point:   0x{:08x}", parser.header.e_entry);
    println!("  Program hdrs:  {} entries (offset 0x{:x})", parser.header.e_phnum, parser.header.e_phoff);

    println!("\n[Program Headers / Segments]");
    for (i, ph) in parser.program_headers.iter().enumerate() {
        let type_str = match ph.p_type {
            PT_LOAD => "PT_LOAD",
            PT_DYNAMIC => "PT_DYNAMIC",
            walzer32_elf::PT_INTERP => "PT_INTERP",
            walzer32_elf::PT_NOTE => "PT_NOTE",
            walzer32_elf::PT_PHDR => "PT_PHDR",
            walzer32_elf::PT_TLS => "PT_TLS",
            walzer32_elf::PT_GNU_RELRO => "PT_GNU_RELRO",
            walzer32_elf::PT_ARM_EXIDX => "PT_ARM_EXIDX",
            _ => "OTHER",
        };

        let mut flags = String::new();
        if ph.p_flags & walzer32_elf::PF_R != 0 { flags.push('R'); }
        if ph.p_flags & walzer32_elf::PF_W != 0 { flags.push('W'); }
        if ph.p_flags & walzer32_elf::PF_X != 0 { flags.push('X'); }

        println!("  [{:>2}] {:<12} vaddr: 0x{:08x}..0x{:08x}  filesz: {:>6}  memsz: {:>6}  flags: [{:<3}]",
            i, type_str, ph.p_vaddr, ph.p_vaddr + ph.p_memsz, ph.p_filesz, ph.p_memsz, flags);
    }

    // Dynamic Tags
    let dyn_entries = parser.parse_dynamic_table()?;
    if !dyn_entries.is_empty() {
        println!("\n[Dynamic Section ({} entries)]", dyn_entries.len());

        let mut strtab_vaddr = None;
        let mut strsz = 0;
        let mut needed_offsets = Vec::new();
        let mut soname_offset = None;
        let mut init_vaddr = None;
        let mut init_array_vaddr = None;
        let mut init_arraysz = 0;

        for d in &dyn_entries {
            match d.d_tag {
                walzer32_elf::DT_STRTAB => strtab_vaddr = Some(d.d_val),
                walzer32_elf::DT_STRSZ => strsz = d.d_val as usize,
                walzer32_elf::DT_NEEDED => needed_offsets.push(d.d_val as usize),
                walzer32_elf::DT_SONAME => soname_offset = Some(d.d_val as usize),
                walzer32_elf::DT_INIT => init_vaddr = Some(d.d_val),
                walzer32_elf::DT_INIT_ARRAY => init_array_vaddr = Some(d.d_val),
                walzer32_elf::DT_INIT_ARRAYSZ => init_arraysz = d.d_val,
                _ => {}
            }
        }

        let strtab_offset = strtab_vaddr.and_then(|va| parser.vaddr_to_offset(va)).unwrap_or(0);

        if let Some(off) = soname_offset {
            if off < strsz {
                if let Ok(name) = parser.read_string_at(strtab_offset + off) {
                    println!("  SONAME: {}", name);
                }
            }
        }

        if !needed_offsets.is_empty() {
            println!("  Dependencies (DT_NEEDED):");
            for off in needed_offsets {
                if off < strsz {
                    if let Ok(dep) = parser.read_string_at(strtab_offset + off) {
                        println!("    -> {}", dep);
                    }
                }
            }
        }

        if let Some(va) = init_vaddr {
            println!("  DT_INIT constructor: 0x{:08x}", va);
        }
        if let Some(va) = init_array_vaddr {
            println!("  DT_INIT_ARRAY: 0x{:08x} ({} functions)", va, init_arraysz / 4);
        }
    }

    Ok(())
}
