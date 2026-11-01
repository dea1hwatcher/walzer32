use byteorder::{ByteOrder, LittleEndian};
use std::ptr;
use transd_android::*;
use transd_elf::{
    ELFCLASS32, ELFDATA2LSB, ELF_MAGIC, EM_ARM, ET_DYN, EV_CURRENT, PF_R, PF_W, PF_X,
    PT_DYNAMIC, PT_LOAD, STB_GLOBAL, STT_FUNC,
};

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
    // Entry 0: STN_UNDEF (16 bytes zeros)
    // Entry 1: add_and_square (offset 12 in strtab)
    let sym1 = 500 + 16;
    LittleEndian::write_u32(&mut elf[sym1..sym1 + 4], 12); // st_name -> "add_and_square"
    LittleEndian::write_u32(&mut elf[sym1 + 4..sym1 + 8], 0x80); // st_value -> 0x80
    LittleEndian::write_u32(&mut elf[sym1 + 8..sym1 + 12], 16);  // st_size
    elf[sym1 + 12] = (STB_GLOBAL << 4) | (STT_FUNC & 0xF); // st_info
    elf[sym1 + 13] = 0; // st_other
    LittleEndian::write_u16(&mut elf[sym1 + 14..sym1 + 16], 1);  // st_shndx (1 = defined)

    // 7. Dynamic Table entries at offset 200:
    // DT_STRTAB (5) -> 400
    // DT_SYMTAB (6) -> 500
    // DT_STRSZ  (10) -> strtab.len()
    // DT_SYMENT (11) -> 16
    // DT_NULL   (0)  -> 0
    let mut cur = 200;
    let dyn_tags: &[(u32, u32)] = &[
        (5, 400),
        (6, 500),
        (10, strtab.len() as u32),
        (11, 16),
        (0, 0),
    ];
    for &(tag, val) in dyn_tags {
        LittleEndian::write_u32(&mut elf[cur..cur + 4], tag);
        LittleEndian::write_u32(&mut elf[cur + 4..cur + 8], val);
        cur += 8;
    }

    elf
}

#[test]
fn test_android_session_and_jni_exports() {
    unsafe {
        // 1. Reset any previous state
        Java_com_transd_loader_TransdEngine_nativeReset(ptr::null_mut(), ptr::null_mut());

        // 2. Initialize engine
        let init_res = Java_com_transd_loader_TransdEngine_nativeInit(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_eq!(init_res, JNI_OK);

        // 3. Status should report 0 loaded libraries initially
        let status = Java_com_transd_loader_TransdEngine_nativeGetStatus(
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_eq!(status, 0);

        // 4. Load the 32-bit calculator .so
        let elf_bytes = build_arm32_calculator_so();
        let lib_name = b"libcalc.so";
        let load_res = Java_com_transd_loader_TransdEngine_nativeLoadLibraryBytes(
            ptr::null_mut(),
            ptr::null_mut(),
            lib_name.as_ptr(),
            lib_name.len(),
            elf_bytes.as_ptr(),
            elf_bytes.len(),
        );
        assert_eq!(load_res, JNI_OK);

        // 5. Status should now be 1
        let status2 = Java_com_transd_loader_TransdEngine_nativeGetStatus(
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_eq!(status2, 1);

        // 6. Find function address and invoke it through nativeCallMethod:
        // (3 + 4)^2 = 49
        let guard = get_or_init_session().unwrap();
        let session = guard.as_ref().unwrap();
        let lib = session.loaded_libraries.get("libcalc.so").unwrap();
        let fn_addr = lib.find_symbol("add_and_square").unwrap();
        drop(guard);

        let calc_res = Java_com_transd_loader_TransdEngine_nativeCallMethod(
            ptr::null_mut(),
            ptr::null_mut(),
            fn_addr.as_u32() as i64,
            3,
            4,
            0,
            0,
        );
        assert_eq!(calc_res, 49);

        // Clean up
        Java_com_transd_loader_TransdEngine_nativeReset(ptr::null_mut(), ptr::null_mut());
    }
}
