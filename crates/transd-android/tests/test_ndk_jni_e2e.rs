use byteorder::{ByteOrder, LittleEndian};
use std::ptr;
use transd_android::*;
use transd_bridge::{BionicFuncId, BIONIC_SVC_MAGIC};
use transd_core::{CpuState, Reg};
use transd_elf::{
    ELFCLASS32, ELFDATA2LSB, ELF_MAGIC, EM_ARM, ET_DYN, EV_CURRENT, PF_R, PF_W, PF_X,
    PT_ARM_EXIDX, PT_DYNAMIC, PT_LOAD, STB_GLOBAL, STT_FUNC,
};

fn build_arm32_ndk_so() -> Vec<u8> {
    let mut elf = vec![0u8; 2048];

    // 1. ELF Header (52 bytes)
    elf[0..4].copy_from_slice(&ELF_MAGIC);
    elf[4] = ELFCLASS32;
    elf[5] = ELFDATA2LSB;
    elf[6] = EV_CURRENT;
    LittleEndian::write_u16(&mut elf[16..18], ET_DYN);
    LittleEndian::write_u16(&mut elf[18..20], EM_ARM);
    LittleEndian::write_u32(&mut elf[20..24], EV_CURRENT as u32);
    LittleEndian::write_u32(&mut elf[24..28], 0); // e_entry
    LittleEndian::write_u32(&mut elf[28..32], 52); // e_phoff
    LittleEndian::write_u16(&mut elf[40..42], 52); // e_ehsize
    LittleEndian::write_u16(&mut elf[42..44], 32); // e_phentsize
    LittleEndian::write_u16(&mut elf[44..46], 3); // e_phnum (PT_LOAD, PT_DYNAMIC, PT_ARM_EXIDX)

    // 2. Phdr #0: PT_LOAD (offset 52)
    LittleEndian::write_u32(&mut elf[52..56], PT_LOAD);
    LittleEndian::write_u32(&mut elf[56..60], 0); // p_offset
    LittleEndian::write_u32(&mut elf[60..64], 0); // p_vaddr
    LittleEndian::write_u32(&mut elf[64..68], 0); // p_paddr
    LittleEndian::write_u32(&mut elf[68..72], 2048); // p_filesz
    LittleEndian::write_u32(&mut elf[72..76], 2048); // p_memsz
    LittleEndian::write_u32(&mut elf[76..80], PF_R | PF_W | PF_X);
    LittleEndian::write_u32(&mut elf[80..84], 4096); // p_align

    // 3. Phdr #1: PT_DYNAMIC (offset 84)
    LittleEndian::write_u32(&mut elf[84..88], PT_DYNAMIC);
    LittleEndian::write_u32(&mut elf[88..92], 0x200); // p_offset
    LittleEndian::write_u32(&mut elf[92..96], 0x200); // p_vaddr
    LittleEndian::write_u32(&mut elf[96..100], 0x200); // p_paddr
    LittleEndian::write_u32(&mut elf[100..104], 64); // p_filesz
    LittleEndian::write_u32(&mut elf[104..108], 64); // p_memsz
    LittleEndian::write_u32(&mut elf[108..112], PF_R | PF_W);
    LittleEndian::write_u32(&mut elf[112..116], 4); // p_align

    // 4. Phdr #2: PT_ARM_EXIDX (offset 116)
    LittleEndian::write_u32(&mut elf[116..120], PT_ARM_EXIDX);
    LittleEndian::write_u32(&mut elf[120..124], 0x300); // p_offset
    LittleEndian::write_u32(&mut elf[124..128], 0x300); // p_vaddr
    LittleEndian::write_u32(&mut elf[128..132], 0x300); // p_paddr
    LittleEndian::write_u32(&mut elf[132..136], 64); // p_filesz: 64 bytes = 8 entries
    LittleEndian::write_u32(&mut elf[136..140], 64); // p_memsz: 64 bytes = 8 entries
    LittleEndian::write_u32(&mut elf[140..144], PF_R);
    LittleEndian::write_u32(&mut elf[144..148], 4); // p_align

    // 5. Code Section at offset 0x80:
    // Function 1: Java_com_example_ndk_NativeLib_computeSaturated(env, obj, a, b)
    // r0=env, r1=obj, r2=a, r3=b
    // QADD r0, r3, r2  (0xE102_0053: r0 = sat_i32(r2 + r3))
    // BX lr            (0xE12F_FF1E)
    LittleEndian::write_u32(&mut elf[0x80..0x84], 0xE102_0053);
    LittleEndian::write_u32(&mut elf[0x84..0x88], 0xE12F_FF1E);

    // Function 2: Java_com_example_ndk_NativeLib_bitSaturate(env, obj, val)
    // r0=env, r1=obj, r2=val
    // SSAT r0, #8, r2  (0xE6A7_0012: clamps r2 to signed 8-bit [-128, 127])
    // BX lr            (0xE12F_FF1E)
    LittleEndian::write_u32(&mut elf[0x90..0x94], 0xE6A7_0012);
    LittleEndian::write_u32(&mut elf[0x94..0x98], 0xE12F_FF1E);

    // 6. Strtab at offset 0x400:
    let strtab = b"\0libndk_game.so\0Java_com_example_ndk_NativeLib_computeSaturated\0Java_com_example_ndk_NativeLib_bitSaturate\0";
    elf[0x400..0x400 + strtab.len()].copy_from_slice(strtab);

    let offset_sym1 = 16; // "Java_com_example_ndk_NativeLib_computeSaturated"
    let offset_sym2 = 16 + "Java_com_example_ndk_NativeLib_computeSaturated\0".len() as u32;

    // 7. Symtab at offset 0x500:
    // Entry 0: STN_UNDEF (16 bytes)
    // Entry 1: computeSaturated
    let sym1 = 0x500 + 16;
    LittleEndian::write_u32(&mut elf[sym1..sym1 + 4], offset_sym1);
    LittleEndian::write_u32(&mut elf[sym1 + 4..sym1 + 8], 0x80);
    LittleEndian::write_u32(&mut elf[sym1 + 8..sym1 + 12], 8);
    elf[sym1 + 12] = (STB_GLOBAL << 4) | (STT_FUNC & 0xF);
    elf[sym1 + 13] = 0;
    LittleEndian::write_u16(&mut elf[sym1 + 14..sym1 + 16], 1);

    // Entry 2: bitSaturate
    let sym2 = 0x500 + 32;
    LittleEndian::write_u32(&mut elf[sym2..sym2 + 4], offset_sym2);
    LittleEndian::write_u32(&mut elf[sym2 + 4..sym2 + 8], 0x90);
    LittleEndian::write_u32(&mut elf[sym2 + 8..sym2 + 12], 8);
    elf[sym2 + 12] = (STB_GLOBAL << 4) | (STT_FUNC & 0xF);
    elf[sym2 + 13] = 0;
    LittleEndian::write_u16(&mut elf[sym2 + 14..sym2 + 16], 1);

    // 8. Dynamic Table at offset 0x200:
    let mut cur = 0x200;
    let dyn_tags: &[(u32, u32)] = &[
        (5, 0x400),                 // DT_STRTAB
        (6, 0x500),                 // DT_SYMTAB
        (10, strtab.len() as u32),  // DT_STRSZ
        (11, 16),                   // DT_SYMENT
        (0, 0),                     // DT_NULL
    ];
    for &(tag, val) in dyn_tags {
        LittleEndian::write_u32(&mut elf[cur..cur + 4], tag);
        LittleEndian::write_u32(&mut elf[cur + 4..cur + 8], val);
        cur += 8;
    }

    elf
}

#[test]
fn test_ndk_jni_e2e_full_lifecycle() {
    unsafe {
        // 1. Reset state
        Java_com_transd_loader_TransdEngine_nativeReset(ptr::null_mut(), ptr::null_mut());

        // 2. Initialize engine
        let init_res = Java_com_transd_loader_TransdEngine_nativeInit(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_eq!(init_res, JNI_OK);

        // 3. Load synthetic NDK shared library with PT_ARM_EXIDX
        let elf_bytes = build_arm32_ndk_so();
        let lib_name = b"libndk_game.so";
        let load_res = Java_com_transd_loader_TransdEngine_nativeLoadLibraryBytes(
            ptr::null_mut(),
            ptr::null_mut(),
            lib_name.as_ptr(),
            lib_name.len(),
            elf_bytes.as_ptr(),
            elf_bytes.len(),
        );
        assert_eq!(load_res, JNI_OK);

        let status = Java_com_transd_loader_TransdEngine_nativeGetStatus(
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_eq!(status, 1);

        // 4. Verify LoadedLibrary fields
        let guard = get_or_init_session().unwrap();
        let session = guard.as_ref().unwrap();
        let lib = session.loaded_libraries.get("libndk_game.so").unwrap();

        assert_eq!(lib.exidx_addr, Some(lib.load_base.add(0x300)));
        assert_eq!(lib.exidx_count, 8);
        assert_eq!(lib.phnum, 3);
        assert_eq!(lib.phdr_addr, lib.load_base.add(52));

        let fn_sat_addr = lib
            .find_symbol("Java_com_example_ndk_NativeLib_computeSaturated")
            .expect("Symbol computeSaturated must exist");
        let fn_bit_addr = lib
            .find_symbol("Java_com_example_ndk_NativeLib_bitSaturate")
            .expect("Symbol bitSaturate must exist");
        let load_base = lib.load_base;

        // 5. Verify Unwind find_exidx via Bionic registry
        let found_lib = session
            .bionic
            .dso_registry
            .find_by_pc(lib.load_base.add(0x80));
        assert!(found_lib.is_some());
        assert_eq!(
            found_lib.unwrap().exidx_addr,
            Some(lib.load_base.add(0x300))
        );
        assert_eq!(found_lib.unwrap().exidx_count, 8);
        drop(guard);

        // 6. Execute computeSaturated via nativeCallMethod:
        // Test normal addition: 15 + 25 = 40
        let res_normal = Java_com_transd_loader_TransdEngine_nativeCallMethod(
            ptr::null_mut(),
            ptr::null_mut(),
            fn_sat_addr.as_u32() as i64,
            0,
            0,
            15,
            25,
        );
        assert_eq!(res_normal, 40);

        // Test saturation: 0x7000_0000 + 0x2000_0000 -> 0x7FFF_FFFF (2147483647)
        let res_sat = Java_com_transd_loader_TransdEngine_nativeCallMethod(
            ptr::null_mut(),
            ptr::null_mut(),
            fn_sat_addr.as_u32() as i64,
            0,
            0,
            0x7000_0000,
            0x2000_0000,
        );
        assert_eq!(res_sat, 0x7FFF_FFFF);

        // 7. Execute bitSaturate via nativeCallMethod:
        // Test in-range: 42 -> 42
        let res_bit_in = Java_com_transd_loader_TransdEngine_nativeCallMethod(
            ptr::null_mut(),
            ptr::null_mut(),
            fn_bit_addr.as_u32() as i64,
            0,
            0,
            42,
            0,
        );
        assert_eq!(res_bit_in, 42);

        // Test positive clamp: 500 -> 127
        let res_bit_high = Java_com_transd_loader_TransdEngine_nativeCallMethod(
            ptr::null_mut(),
            ptr::null_mut(),
            fn_bit_addr.as_u32() as i64,
            0,
            0,
            500,
            0,
        );
        assert_eq!(res_bit_high, 127);

        // Test negative clamp: -300 -> -128
        let res_bit_low = Java_com_transd_loader_TransdEngine_nativeCallMethod(
            ptr::null_mut(),
            ptr::null_mut(),
            fn_bit_addr.as_u32() as i64,
            0,
            0,
            -300,
            0,
        );
        assert_eq!(res_bit_low as i32, -128);

        // 8. Invoke Bionic __gnu_Unwind_Find_exidx stub directly through session engine
        let mut guard = get_or_init_session().unwrap();
        let session = guard.as_mut().unwrap();
        let mut cpu = CpuState::new();
        let pcount_addr = load_base.add(0x380);

        cpu.set_reg(Reg::R0, load_base.add(0x84).as_u32());
        cpu.set_reg(Reg::R1, pcount_addr.as_u32());
        let _ = session
            .bionic
            .handle_svc(
                BIONIC_SVC_MAGIC | (BionicFuncId::GnuUnwindFindExidx as u32),
                &mut cpu,
                &mut session.engine.mem,
            )
            .unwrap();

        assert_eq!(cpu.reg(Reg::R0), load_base.add(0x300).as_u32());
        assert_eq!(
            transd_core::Memory::read_u32(&session.engine.mem, pcount_addr).unwrap(),
            8
        );
        drop(guard);

        // 9. Clean up
        Java_com_transd_loader_TransdEngine_nativeReset(ptr::null_mut(), ptr::null_mut());
    }
}
