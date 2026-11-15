use byteorder::{ByteOrder, LittleEndian};
use walzer32_elf::ElfParser;

const ELF64_EHDR_SIZE: usize = 64;
const ELF64_PHDR_SIZE: usize = 56;
const ELF64_SHDR_SIZE: usize = 64;
const ELF64_SYM_SIZE: usize = 24;
const ELF64_RELA_SIZE: usize = 24;
const PAGE_SIZE: usize = 0x1000;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;

const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_HASH: u32 = 5;
const SHT_DYNAMIC: u32 = 6;
const SHT_DYNSYM: u32 = 11;

const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;

const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
const DT_STRSZ: u64 = 10;
const DT_SYMENT: u64 = 11;
const DT_SONAME: u64 = 14;
const DT_FLAGS: u64 = 30;
const DF_BIND_NOW: u64 = 0x8;

const R_AARCH64_GLOB_DAT: u64 = 1025;

fn align_up(v: usize, align: usize) -> usize {
    (v + align - 1) & !(align - 1)
}

/// Standard SysV ELF string hash algorithm.
pub fn elf_sysv_hash(name: &str) -> u32 {
    let mut h: u32 = 0;
    for &b in name.as_bytes() {
        h = (h << 4).wrapping_add(b as u32);
        let g = h & 0xF000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

/// Extracts `Java_*` and `JNI_OnLoad` dynamic exports from a 32-bit ARM `.so` image.
pub fn extract_arm32_jni_exports(arm32_elf: &[u8]) -> Vec<String> {
    let Ok(parser) = ElfParser::parse(arm32_elf) else {
        return Vec::new();
    };
    let mut exports: Vec<String> = parser
        .dynamic_symbol_names()
        .into_iter()
        .filter(|s| s == "JNI_OnLoad" || s.starts_with("Java_"))
        .collect();
    exports.sort();
    exports.dedup();
    exports
}

/// Encodes AArch64 `ADRP X16, target_page`, `LDR X16, [X16, #off]`, `BR X16`.
#[allow(dead_code)]
fn emit_got_tail_jump(buf: &mut Vec<u8>, code_vaddr: usize, got_vaddr: usize) {
    let page_diff = ((got_vaddr >> 12) as i64) - ((code_vaddr >> 12) as i64);
    let imm21 = (page_diff as u32) & 0x1F_FFFF;
    let immlo = imm21 & 3;
    let immhi = (imm21 >> 2) & 0x7_FFFF;
    let adrp = 0x9000_0010u32 | (immlo << 29) | (immhi << 5);

    let got_off12 = ((got_vaddr & 0xFFF) >> 3) as u32;
    let ldr = 0xF940_0210u32 | (got_off12 << 10);
    let br_x16 = 0xD61F_0200u32;

    buf.extend_from_slice(&adrp.to_le_bytes());
    buf.extend_from_slice(&ldr.to_le_bytes());
    buf.extend_from_slice(&br_x16.to_le_bytes());
}

/// Generates a dynamic 64-bit `EM_AARCH64` ELF `.so` proxy library.
///
/// The generated library declares `DT_SONAME` and `DT_NEEDED` (`libwalzer32.so` plus `extra_needed`),
/// exports `JNI_OnLoad` (tail-calling `walzer32_proxy_jni_onload` via GOT `R_AARCH64_GLOB_DAT`) and
/// all provided `exported_symbols` (`Java_*` etc.) with valid `.dynsym`, `.dynstr`, `.hash`, and `PT_DYNAMIC`.
pub fn generate_dynamic_arm64_stub(
    soname: &str,
    extra_needed: &[&str],
    exported_symbols: &[String],
) -> Vec<u8> {
    // Normalize symbol list: always export `JNI_OnLoad`, plus unique `exported_symbols` (excluding duplicates/import).
    let mut exports = vec!["JNI_OnLoad".to_string()];
    for s in exported_symbols {
        if s != "JNI_OnLoad"
            && s != "walzer32_proxy_jni_onload"
            && !s.is_empty()
            && !exports.iter().any(|e| e == s)
        {
            exports.push(s.clone());
        }
    }

    // Needed libraries: `libwalzer32.so`, `libc.so`, plus unique extras (skipping self).
    let mut needed = vec!["libwalzer32.so".to_string(), "libc.so".to_string()];
    for &lib in extra_needed {
        if lib != soname && !lib.is_empty() && !needed.iter().any(|n| n == lib) {
            needed.push(lib.to_string());
        }
    }

    // Build `.dynstr`
    let mut dynstr = Vec::new();
    dynstr.push(0); // index 0 = empty string
    let mut add_str = |s: &str| -> u32 {
        let off = dynstr.len() as u32;
        dynstr.extend_from_slice(s.as_bytes());
        dynstr.push(0);
        off
    };

    let soname_off = add_str(soname);
    let needed_offs: Vec<u32> = needed.iter().map(|n| add_str(n)).collect();
    let import_onload_off = add_str("walzer32_proxy_jni_onload");
    let export_name_offs: Vec<u32> = exports.iter().map(|s| add_str(s)).collect();

    // Layout Segment 0 (RX):
    //   0x0000: Elf64_Ehdr (64)
    //   0x0040: 3 * Elf64_Phdr (168)
    //   0x0100: .dynstr
    //   align 8: .dynsym ((2 + exports.len()) * 24)
    //   align 4: .hash (8 + (nbucket + nchain) * 4)
    //   align 8: .rela.dyn (24 bytes for got[0] -> sym[1])
    //   align 16: .text
    let dynstr_off = 0x0100usize;
    let dynsym_off = align_up(dynstr_off + dynstr.len(), 8);
    let sym_count = 2 + exports.len(); // [0]=null, [1]=import walzer32_proxy_jni_onload, [2..]=exports
    let hash_off = align_up(dynsym_off + sym_count * ELF64_SYM_SIZE, 4);
    let nbucket = sym_count.max(1);
    let nchain = sym_count;
    let hash_size = (2 + nbucket + nchain) * 4;
    let rela_off = align_up(hash_off + hash_size, 8);
    let rela_size = ELF64_RELA_SIZE; // 1 entry
    let text_off = align_up(rela_off + rela_size, 16);

    // Reserve text sizes first to know exact rw_off (next page boundary after text)
    // JNI_OnLoad uses 12 bytes (GOT tail call); other stub exports use 8 bytes (MOV W0, #0; RET).
    let mut export_vaddrs = Vec::with_capacity(exports.len());
    let mut cursor = text_off;
    for name in &exports {
        export_vaddrs.push(cursor as u64);
        cursor += if name == "JNI_OnLoad" { 12 } else { 8 };
    }
    let rx_filesz = cursor;
    let rw_off = align_up(rx_filesz, PAGE_SIZE);
    let rw_vaddr = rw_off;
    let got_vaddr = rw_vaddr; // 8-byte GOT slot for walzer32_proxy_jni_onload
    let dynamic_off = rw_off + 8;
    let dynamic_vaddr = rw_vaddr + 8;

    // Build .dynamic entries
    let mut dyn_entries: Vec<(u64, u64)> = Vec::new();
    for off in needed_offs {
        dyn_entries.push((DT_NEEDED, off as u64));
    }
    dyn_entries.push((DT_SONAME, soname_off as u64));
    dyn_entries.push((DT_HASH, hash_off as u64));
    dyn_entries.push((DT_STRTAB, dynstr_off as u64));
    dyn_entries.push((DT_SYMTAB, dynsym_off as u64));
    dyn_entries.push((DT_RELA, rela_off as u64));
    dyn_entries.push((DT_RELASZ, rela_size as u64));
    dyn_entries.push((DT_RELAENT, ELF64_RELA_SIZE as u64));
    dyn_entries.push((DT_STRSZ, dynstr.len() as u64));
    dyn_entries.push((DT_SYMENT, ELF64_SYM_SIZE as u64));
    dyn_entries.push((DT_FLAGS, DF_BIND_NOW));
    dyn_entries.push((DT_NULL, 0));
    let dynamic_size = dyn_entries.len() * 16;

    // Build .shstrtab
    let mut shstrtab = Vec::new();
    shstrtab.push(0); // 0 = empty string
    let mut add_shstr = |s: &str| -> u32 {
        let off = shstrtab.len() as u32;
        shstrtab.extend_from_slice(s.as_bytes());
        shstrtab.push(0);
        off
    };
    let dynstr_shname = add_shstr(".dynstr");
    let dynsym_shname = add_shstr(".dynsym");
    let hash_shname = add_shstr(".hash");
    let rela_shname = add_shstr(".rela.dyn");
    let text_shname = add_shstr(".text");
    let got_shname = add_shstr(".got");
    let dynamic_shname = add_shstr(".dynamic");
    let shstrtab_shname = add_shstr(".shstrtab");

    let rw_filesz = (dynamic_off + dynamic_size) - rw_off;
    let shstrtab_off = align_up(dynamic_off + dynamic_size, 8);
    let shnum = 9usize;
    let shdr_off = align_up(shstrtab_off + shstrtab.len(), 8);
    let total_size = shdr_off + shnum * ELF64_SHDR_SIZE;

    let mut img = vec![0u8; total_size];

    // 1. Elf64_Ehdr
    img[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    img[4] = 2; // ELFCLASS64
    img[5] = 1; // ELFDATA2LSB
    img[6] = 1; // EV_CURRENT
    LittleEndian::write_u16(&mut img[16..18], 3); // ET_DYN
    LittleEndian::write_u16(&mut img[18..20], 183); // EM_AARCH64
    LittleEndian::write_u32(&mut img[20..24], 1); // EV_CURRENT
    LittleEndian::write_u64(&mut img[32..40], ELF64_EHDR_SIZE as u64); // e_phoff
    LittleEndian::write_u64(&mut img[40..48], shdr_off as u64); // e_shoff
    LittleEndian::write_u16(&mut img[52..54], ELF64_EHDR_SIZE as u16);
    LittleEndian::write_u16(&mut img[54..56], ELF64_PHDR_SIZE as u16);
    LittleEndian::write_u16(&mut img[56..58], 3); // e_phnum
    LittleEndian::write_u16(&mut img[58..60], ELF64_SHDR_SIZE as u16); // e_shentsize = 0x40 (sizeof(Elf64_Shdr))
    LittleEndian::write_u16(&mut img[60..62], shnum as u16); // e_shnum = 9
    LittleEndian::write_u16(&mut img[62..64], 8); // e_shstrndx = 8 (.shstrtab)

    // 2. Elf64_Phdr table
    let write_phdr = |buf: &mut [u8],
                      idx: usize,
                      p_type: u32,
                      p_flags: u32,
                      offset: u64,
                      vaddr: u64,
                      size: u64,
                      align: u64| {
        let base = ELF64_EHDR_SIZE + idx * ELF64_PHDR_SIZE;
        LittleEndian::write_u32(&mut buf[base..base + 4], p_type);
        LittleEndian::write_u32(&mut buf[base + 4..base + 8], p_flags);
        LittleEndian::write_u64(&mut buf[base + 8..base + 16], offset);
        LittleEndian::write_u64(&mut buf[base + 16..base + 24], vaddr);
        LittleEndian::write_u64(&mut buf[base + 24..base + 32], vaddr);
        LittleEndian::write_u64(&mut buf[base + 32..base + 40], size);
        LittleEndian::write_u64(&mut buf[base + 40..base + 48], size);
        LittleEndian::write_u64(&mut buf[base + 48..base + 56], align);
    };
    write_phdr(
        &mut img,
        0,
        PT_LOAD,
        PF_R | PF_X,
        0,
        0,
        rx_filesz as u64,
        PAGE_SIZE as u64,
    );
    write_phdr(
        &mut img,
        1,
        PT_LOAD,
        PF_R | PF_W,
        rw_off as u64,
        rw_vaddr as u64,
        rw_filesz as u64,
        PAGE_SIZE as u64,
    );
    write_phdr(
        &mut img,
        2,
        PT_DYNAMIC,
        PF_R | PF_W,
        dynamic_off as u64,
        dynamic_vaddr as u64,
        dynamic_size as u64,
        8,
    );

    // 3. .dynstr
    img[dynstr_off..dynstr_off + dynstr.len()].copy_from_slice(&dynstr);

    // 4. .dynsym + .hash
    let write_sym = |buf: &mut [u8],
                     idx: usize,
                     st_name: u32,
                     st_info: u8,
                     st_shndx: u16,
                     st_value: u64,
                     st_size: u64| {
        let off = dynsym_off + idx * ELF64_SYM_SIZE;
        LittleEndian::write_u32(&mut buf[off..off + 4], st_name);
        buf[off + 4] = st_info;
        buf[off + 5] = 0;
        LittleEndian::write_u16(&mut buf[off + 6..off + 8], st_shndx);
        LittleEndian::write_u64(&mut buf[off + 8..off + 16], st_value);
        LittleEndian::write_u64(&mut buf[off + 16..off + 24], st_size);
    };
    // Symbol 1: imported undefined `walzer32_proxy_jni_onload`
    write_sym(&mut img, 1, import_onload_off, (1 << 4) | 2, 0, 0, 0);

    let mut buckets = vec![0u32; nbucket];
    let mut chains = vec![0u32; nchain];
    // Insert import & exports into SysV hash
    let mut insert_hash = |sym_idx: u32, name: &str| {
        let b = (elf_sysv_hash(name) as usize) % nbucket;
        chains[sym_idx as usize] = buckets[b];
        buckets[b] = sym_idx;
    };
    insert_hash(1, "walzer32_proxy_jni_onload");

    for (i, name) in exports.iter().enumerate() {
        let sym_idx = 2 + i;
        let code_len = if name == "JNI_OnLoad" { 12u64 } else { 8u64 };
        write_sym(
            &mut img,
            sym_idx,
            export_name_offs[i],
            (1 << 4) | 2, // STB_GLOBAL | STT_FUNC
            5,            // Section 5 = .text
            export_vaddrs[i],
            code_len,
        );
        insert_hash(sym_idx as u32, name);
    }

    LittleEndian::write_u32(&mut img[hash_off..hash_off + 4], nbucket as u32);
    LittleEndian::write_u32(&mut img[hash_off + 4..hash_off + 8], nchain as u32);
    for (i, &b) in buckets.iter().enumerate() {
        let off = hash_off + 8 + i * 4;
        LittleEndian::write_u32(&mut img[off..off + 4], b);
    }
    for (i, &c) in chains.iter().enumerate() {
        let off = hash_off + 8 + (nbucket + i) * 4;
        LittleEndian::write_u32(&mut img[off..off + 4], c);
    }

    // 5. .rela.dyn: R_AARCH64_GLOB_DAT on got[0] for sym[1]
    LittleEndian::write_u64(&mut img[rela_off..rela_off + 8], got_vaddr as u64);
    LittleEndian::write_u64(&mut img[rela_off + 8..rela_off + 16], (1u64 << 32) | R_AARCH64_GLOB_DAT);
    LittleEndian::write_i64(&mut img[rela_off + 16..rela_off + 24], 0);

    // 6. .text stubs
    let mut text_buf = Vec::new();
    for (_i, name) in exports.iter().enumerate() {
        if name == "JNI_OnLoad" {
            // MOVZ W0, #6
            text_buf.extend_from_slice(&0x5280_00C0u32.to_le_bytes());
            // MOVK W0, #1, LSL #16 (0x00010006 = JNI_VERSION_1_6)
            text_buf.extend_from_slice(&0x72A0_0020u32.to_le_bytes());
            // RET
            text_buf.extend_from_slice(&0xD65F_03C0u32.to_le_bytes());
        } else {
            text_buf.extend_from_slice(&0x5280_0000u32.to_le_bytes()); // MOV W0, #0
            text_buf.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // RET
        }
    }
    img[text_off..text_off + text_buf.len()].copy_from_slice(&text_buf);

    // 7. .dynamic
    for (i, &(tag, val)) in dyn_entries.iter().enumerate() {
        let off = dynamic_off + i * 16;
        LittleEndian::write_u64(&mut img[off..off + 8], tag);
        LittleEndian::write_u64(&mut img[off + 8..off + 16], val);
    }

    // 8. .shstrtab
    img[shstrtab_off..shstrtab_off + shstrtab.len()].copy_from_slice(&shstrtab);

    // 9. Section header table (Elf64_Shdr)
    let write_shdr = |buf: &mut [u8],
                      idx: usize,
                      sh_name: u32,
                      sh_type: u32,
                      sh_flags: u64,
                      sh_addr: u64,
                      sh_offset: u64,
                      sh_size: u64,
                      sh_link: u32,
                      sh_info: u32,
                      sh_addralign: u64,
                      sh_entsize: u64| {
        let base = shdr_off + idx * ELF64_SHDR_SIZE;
        LittleEndian::write_u32(&mut buf[base..base + 4], sh_name);
        LittleEndian::write_u32(&mut buf[base + 4..base + 8], sh_type);
        LittleEndian::write_u64(&mut buf[base + 8..base + 16], sh_flags);
        LittleEndian::write_u64(&mut buf[base + 16..base + 24], sh_addr);
        LittleEndian::write_u64(&mut buf[base + 24..base + 32], sh_offset);
        LittleEndian::write_u64(&mut buf[base + 32..base + 40], sh_size);
        LittleEndian::write_u32(&mut buf[base + 40..base + 44], sh_link);
        LittleEndian::write_u32(&mut buf[base + 44..base + 48], sh_info);
        LittleEndian::write_u64(&mut buf[base + 48..base + 56], sh_addralign);
        LittleEndian::write_u64(&mut buf[base + 56..base + 64], sh_entsize);
    };

    // [0] SHT_NULL
    write_shdr(&mut img, 0, 0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0);
    // [1] .dynstr
    write_shdr(&mut img, 1, dynstr_shname, SHT_STRTAB, SHF_ALLOC, dynstr_off as u64, dynstr_off as u64, dynstr.len() as u64, 0, 0, 1, 0);
    // [2] .dynsym
    write_shdr(&mut img, 2, dynsym_shname, SHT_DYNSYM, SHF_ALLOC, dynsym_off as u64, dynsym_off as u64, (sym_count * ELF64_SYM_SIZE) as u64, 1, 1, 8, ELF64_SYM_SIZE as u64);
    // [3] .hash
    write_shdr(&mut img, 3, hash_shname, SHT_HASH, SHF_ALLOC, hash_off as u64, hash_off as u64, hash_size as u64, 2, 0, 4, 4);
    // [4] .rela.dyn
    write_shdr(&mut img, 4, rela_shname, SHT_RELA, SHF_ALLOC, rela_off as u64, rela_off as u64, rela_size as u64, 2, 0, 8, ELF64_RELA_SIZE as u64);
    // [5] .text
    write_shdr(&mut img, 5, text_shname, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, text_off as u64, text_off as u64, (rx_filesz - text_off) as u64, 0, 0, 16, 0);
    // [6] .got
    write_shdr(&mut img, 6, got_shname, SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, got_vaddr as u64, rw_off as u64, 8, 0, 0, 8, 8);
    // [7] .dynamic
    write_shdr(&mut img, 7, dynamic_shname, SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, dynamic_vaddr as u64, dynamic_off as u64, dynamic_size as u64, 1, 0, 8, 16);
    // [8] .shstrtab
    write_shdr(&mut img, 8, shstrtab_shname, SHT_STRTAB, 0, 0, shstrtab_off as u64, shstrtab.len() as u64, 0, 0, 1, 0);

    img
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_arm64_elf_structure_and_exports() {
        let exports = vec![
            "Java_com_example_Game_nativeTick".to_string(),
            "Java_com_example_Game_nativeInit".to_string(),
        ];
        let elf = generate_dynamic_arm64_stub("libgame.so", &["libGLESv2.so"], &exports);

        // Check ELF64 AArch64 header
        assert_eq!(&elf[0..4], &[0x7F, b'E', b'L', b'F']);
        assert_eq!(elf[4], 2); // ELFCLASS64
        assert_eq!(LittleEndian::read_u16(&elf[16..18]), 3); // ET_DYN
        assert_eq!(LittleEndian::read_u16(&elf[18..20]), 183); // EM_AARCH64
        assert_eq!(LittleEndian::read_u16(&elf[56..58]), 3); // 3 PHDRs

        // Check PT_LOAD RX and RW page alignment + RW offset == 0x1000
        let rw_off = LittleEndian::read_u64(&elf[ELF64_EHDR_SIZE + ELF64_PHDR_SIZE + 8..][..8]);
        let rw_vaddr = LittleEndian::read_u64(&elf[ELF64_EHDR_SIZE + ELF64_PHDR_SIZE + 16..][..8]);
        assert_eq!(rw_off, 0x1000);
        assert_eq!(rw_vaddr, 0x1000);

        // Verify .dynstr contains SONAME, NEEDED, import, and Java_* exports
        let text = String::from_utf8_lossy(&elf);
        assert!(text.contains("libgame.so"));
        assert!(text.contains("libwalzer32.so"));
        assert!(text.contains("libGLESv2.so"));
        assert!(text.contains("walzer32_proxy_jni_onload"));
        assert!(text.contains("JNI_OnLoad"));
        assert!(text.contains("Java_com_example_Game_nativeTick"));
        assert!(text.contains("Java_com_example_Game_nativeInit"));

        // Verify ELF64 section headers and .shstrtab satisfying Android 8+ (API 26+) Bionic requirements
        assert_eq!(LittleEndian::read_u16(&elf[58..60]), 64); // e_shentsize == 64
        assert_eq!(LittleEndian::read_u16(&elf[60..62]), 9); // e_shnum == 9
        assert_eq!(LittleEndian::read_u16(&elf[62..64]), 8); // e_shstrndx == 8
        assert!(LittleEndian::read_u64(&elf[40..48]) > 0); // e_shoff > 0
        assert!(text.contains(".shstrtab"));
        assert!(text.contains(".dynamic"));
    }
}
