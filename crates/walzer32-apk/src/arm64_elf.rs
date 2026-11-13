use byteorder::{ByteOrder, LittleEndian};
use walzer32_elf::ElfParser;

const ELF64_EHDR_SIZE: usize = 64;
const ELF64_PHDR_SIZE: usize = 56;
const ELF64_SYM_SIZE: usize = 24;
const ELF64_RELA_SIZE: usize = 24;
const PAGE_SIZE: usize = 0x1000;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;

const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

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
    let total_size = dynamic_off + dynamic_size;

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
    LittleEndian::write_u16(&mut img[52..54], ELF64_EHDR_SIZE as u16);
    LittleEndian::write_u16(&mut img[54..56], ELF64_PHDR_SIZE as u16);
    LittleEndian::write_u16(&mut img[56..58], 3); // e_phnum

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
        (total_size - rw_off) as u64,
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
            1,
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
    for (i, name) in exports.iter().enumerate() {
        if name == "JNI_OnLoad" {
            emit_got_tail_jump(&mut text_buf, export_vaddrs[i] as usize, got_vaddr);
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
    }
}
