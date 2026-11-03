use byteorder::{ByteOrder, LittleEndian};
use crate::header::*;

/// Report detailing ELF header sanitization and fixups
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ElfFixupReport {
    /// Whether a DT_TEXTREL entry was neutralized
    pub textrel_cleared: bool,
    /// Whether the DF_TEXTREL bit was stripped from DT_FLAGS
    pub df_textrel_cleared: bool,
    /// List of DT_NEEDED dependencies sanitized from absolute paths to basenames (original, basename)
    pub sanitized_needed: Vec<(String, String)>,
}

/// In-place sanitization of 32-bit ELF binaries:
/// 1. Clears `DT_TEXTREL` (tag 22) -> replaces tag with `DT_DEBUG` (21) and val with 0
/// 2. Clears `DF_TEXTREL` (0x0000_0004) in `DT_FLAGS` (tag 30)
/// 3. Normalizes `DT_NEEDED` (tag 1): if string has slashes (e.g. `/system/lib/libc.so`),
///    shifts `d_val` offset to point to basename (`libc.so`) in-place.
pub fn sanitize_elf_headers(elf: &mut [u8]) -> Result<ElfFixupReport, &'static str> {
    if elf.len() < 52 {
        return Err("ELF buffer too small for Ehdr");
    }
    if elf[0..4] != ELF_MAGIC {
        return Err("Invalid ELF magic");
    }
    if elf[4] != ELFCLASS32 || elf[5] != ELFDATA2LSB {
        return Err("Only 32-bit little-endian ELF is supported for fixups");
    }

    let phoff = LittleEndian::read_u32(&elf[28..32]) as usize;
    let phentsize = LittleEndian::read_u16(&elf[42..44]) as usize;
    let phnum = LittleEndian::read_u16(&elf[44..46]) as usize;

    if phoff == 0 || phentsize < 32 || phnum == 0 {
        return Err("Invalid program header table");
    }

    // Step 1: Collect PT_LOAD segments to translate vaddr -> file offset
    let mut pt_loads = Vec::new();
    let mut dynamic_offset = None;
    let mut dynamic_size = None;

    for i in 0..phnum {
        let entry_offset = phoff + i * phentsize;
        if entry_offset + 32 > elf.len() {
            return Err("Program header exceeds ELF size");
        }
        let p_type = LittleEndian::read_u32(&elf[entry_offset..entry_offset + 4]);
        let p_offset = LittleEndian::read_u32(&elf[entry_offset + 4..entry_offset + 8]) as usize;
        let p_vaddr = LittleEndian::read_u32(&elf[entry_offset + 8..entry_offset + 12]);
        let p_filesz = LittleEndian::read_u32(&elf[entry_offset + 16..entry_offset + 20]) as usize;

        if p_type == PT_LOAD {
            pt_loads.push((p_vaddr, p_offset, p_filesz));
        } else if p_type == PT_DYNAMIC {
            dynamic_offset = Some(p_offset);
            dynamic_size = Some(p_filesz);
        }
    }

    let (dyn_offset, dyn_size) = match (dynamic_offset, dynamic_size) {
        (Some(o), Some(s)) => (o, s),
        _ => return Ok(ElfFixupReport::default()), // No dynamic table, nothing to fixup
    };

    if dyn_offset + dyn_size > elf.len() {
        return Err("Dynamic table exceeds ELF size");
    }

    let vaddr_to_offset = |vaddr: u32| -> Option<usize> {
        for &(p_vaddr, p_offset, p_filesz) in &pt_loads {
            if vaddr >= p_vaddr && (vaddr as usize) < (p_vaddr as usize + p_filesz) {
                return Some(p_offset + (vaddr - p_vaddr) as usize);
            }
        }
        None
    };

    // Step 2: First pass on PT_DYNAMIC to find DT_STRTAB
    let mut strtab_offset = None;
    let mut strsz = None;

    let num_dyn = dyn_size / 8;
    for i in 0..num_dyn {
        let entry_pos = dyn_offset + i * 8;
        let d_tag = LittleEndian::read_u32(&elf[entry_pos..entry_pos + 4]);
        let d_val = LittleEndian::read_u32(&elf[entry_pos + 4..entry_pos + 8]);

        if d_tag == DT_NULL {
            break;
        } else if d_tag == DT_STRTAB {
            strtab_offset = vaddr_to_offset(d_val);
        } else if d_tag == DT_STRSZ {
            strsz = Some(d_val as usize);
        }
    }

    let mut report = ElfFixupReport::default();

    // Step 3: Second pass on PT_DYNAMIC to fix DT_TEXTREL, DT_FLAGS, and DT_NEEDED
    for i in 0..num_dyn {
        let entry_pos = dyn_offset + i * 8;
        let d_tag = LittleEndian::read_u32(&elf[entry_pos..entry_pos + 4]);
        let d_val = LittleEndian::read_u32(&elf[entry_pos + 4..entry_pos + 8]);

        if d_tag == DT_NULL {
            break;
        } else if d_tag == DT_TEXTREL {
            // Neutralize DT_TEXTREL: change tag to harmless DT_DEBUG and val to 0
            LittleEndian::write_u32(&mut elf[entry_pos..entry_pos + 4], DT_DEBUG);
            LittleEndian::write_u32(&mut elf[entry_pos + 4..entry_pos + 8], 0);
            report.textrel_cleared = true;
        } else if d_tag == DT_FLAGS {
            if (d_val & DF_TEXTREL) != 0 {
                let new_flags = d_val & !DF_TEXTREL;
                LittleEndian::write_u32(&mut elf[entry_pos + 4..entry_pos + 8], new_flags);
                report.df_textrel_cleared = true;
            }
        } else if d_tag == DT_NEEDED && strtab_offset.is_some() {
            let strtab_off = strtab_offset.unwrap();
            let name_off = strtab_off + d_val as usize;
            let max_len = strsz.map(|s| strtab_off + s - name_off).unwrap_or(256);
            let actual_max = max_len.min(elf.len().saturating_sub(name_off));

            let mut str_bytes = Vec::new();
            for &b in &elf[name_off..name_off + actual_max] {
                if b == 0 {
                    break;
                }
                str_bytes.push(b);
            }

            if let Some(slash_idx) = std::str::from_utf8(&str_bytes).ok().and_then(|s| s.rfind('/')) {
                let name_str = std::str::from_utf8(&str_bytes).unwrap();
                let original = name_str.to_string();
                let basename = name_str[slash_idx + 1..].to_string();
                // Advance d_val offset to point directly past the last slash
                let new_d_val = d_val + (slash_idx as u32 + 1);
                LittleEndian::write_u32(&mut elf[entry_pos + 4..entry_pos + 8], new_d_val);
                report.sanitized_needed.push((original, basename));
            }
        }
    }

    Ok(report)
}
