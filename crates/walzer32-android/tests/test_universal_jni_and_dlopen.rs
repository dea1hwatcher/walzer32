use walzer32_android::{
    get_or_init_session, reset_session, walzer32_universal_jni_dispatcher, Walzer32Session,
};
use walzer32_bridge::HostJniCallFrame;
use walzer32_core::{GuestAddr, Memory};
use walzer32_elf::SymbolResolver;

fn movw(rd: u32, imm16: u16) -> u32 {
    let imm = imm16 as u32;
    0xE300_0000 | ((imm >> 12) << 16) | (rd << 12) | (imm & 0xFFF)
}

fn movt(rd: u32, imm16: u16) -> u32 {
    let imm = imm16 as u32;
    0xE340_0000 | ((imm >> 12) << 16) | (rd << 12) | (imm & 0xFFF)
}

fn mov32(code: &mut Vec<(u32, u32)>, pc: &mut u32, rd: u32, val: u32) {
    code.push((*pc, movw(rd, (val & 0xFFFF) as u16)));
    *pc += 4;
    if (val >> 16) != 0 {
        code.push((*pc, movt(rd, (val >> 16) as u16)));
        *pc += 4;
    }
}

fn call_abs(code: &mut Vec<(u32, u32)>, pc: &mut u32, target: u32) {
    mov32(code, pc, 12, target);
    code.push((*pc, 0xE12F_FF3C)); // BLX R12
    *pc += 4;
}

/// Builds a minimal valid ET_DYN ARM32 ELF `.so` exporting a single function `plugin_calc` (`return arg0 + 77;`).
fn build_minimal_arm32_plugin_so() -> Vec<u8> {
    let mut img = vec![0u8; 0x3000];

    // ELF Header (52 bytes at 0x0000)
    img[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    img[4] = 1; // EI_CLASS = ELFCLASS32
    img[5] = 1; // EI_DATA = ELFDATA2LSB
    img[6] = 1; // EI_VERSION = EV_CURRENT
    img[16..18].copy_from_slice(&3u16.to_le_bytes()); // e_type = ET_DYN
    img[18..20].copy_from_slice(&40u16.to_le_bytes()); // e_machine = EM_ARM
    img[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    img[28..32].copy_from_slice(&52u32.to_le_bytes()); // e_phoff = 52
    img[40..42].copy_from_slice(&52u16.to_le_bytes()); // e_ehsize
    img[42..44].copy_from_slice(&32u16.to_le_bytes()); // e_phentsize
    img[44..46].copy_from_slice(&2u16.to_le_bytes()); // e_phnum = 2

    // PHDR 0: PT_LOAD (offset 52) covering 0x0000..0x3000
    let p0 = 52;
    img[p0..p0 + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    img[p0 + 4..p0 + 8].copy_from_slice(&0u32.to_le_bytes()); // p_offset
    img[p0 + 8..p0 + 12].copy_from_slice(&0u32.to_le_bytes()); // p_vaddr
    img[p0 + 12..p0 + 16].copy_from_slice(&0u32.to_le_bytes()); // p_paddr
    img[p0 + 16..p0 + 20].copy_from_slice(&0x3000u32.to_le_bytes()); // p_filesz
    img[p0 + 20..p0 + 24].copy_from_slice(&0x3000u32.to_le_bytes()); // p_memsz
    img[p0 + 24..p0 + 28].copy_from_slice(&7u32.to_le_bytes()); // RWX
    img[p0 + 28..p0 + 32].copy_from_slice(&0x1000u32.to_le_bytes());

    // PHDR 1: PT_DYNAMIC at 0x0200 (len 64 bytes)
    let p1 = 52 + 32;
    img[p1..p1 + 4].copy_from_slice(&2u32.to_le_bytes()); // PT_DYNAMIC
    img[p1 + 4..p1 + 8].copy_from_slice(&0x0200u32.to_le_bytes());
    img[p1 + 8..p1 + 12].copy_from_slice(&0x0200u32.to_le_bytes());
    img[p1 + 12..p1 + 16].copy_from_slice(&0x0200u32.to_le_bytes());
    img[p1 + 16..p1 + 20].copy_from_slice(&80u32.to_le_bytes());
    img[p1 + 20..p1 + 24].copy_from_slice(&80u32.to_le_bytes());
    img[p1 + 24..p1 + 28].copy_from_slice(&6u32.to_le_bytes());
    img[p1 + 28..p1 + 32].copy_from_slice(&4u32.to_le_bytes());

    // .dynstr at 0x0300: "\0plugin_calc\0libplugin_dyn.so\0"
    let strtab_off = 0x0300usize;
    let s1 = b"\0plugin_calc\0libplugin_dyn.so\0";
    img[strtab_off..strtab_off + s1.len()].copy_from_slice(s1);

    // .dynsym at 0x0400 (2 entries * 16 bytes): [0]=null, [1]=plugin_calc @ 0x1000
    let symtab_off = 0x0400usize;
    let sym1 = symtab_off + 16;
    img[sym1..sym1 + 4].copy_from_slice(&1u32.to_le_bytes()); // st_name = "plugin_calc"
    img[sym1 + 4..sym1 + 8].copy_from_slice(&0x1000u32.to_le_bytes()); // st_value = 0x1000
    img[sym1 + 8..sym1 + 12].copy_from_slice(&8u32.to_le_bytes()); // st_size
    img[sym1 + 12] = (1 << 4) | 2; // STB_GLOBAL | STT_FUNC
    img[sym1 + 14..sym1 + 16].copy_from_slice(&1u16.to_le_bytes()); // shndx = 1

    // .hash at 0x0500: nbucket=1, nchain=2
    let hash_off = 0x0500usize;
    img[hash_off..hash_off + 4].copy_from_slice(&1u32.to_le_bytes());
    img[hash_off + 4..hash_off + 8].copy_from_slice(&2u32.to_le_bytes());
    img[hash_off + 8..hash_off + 12].copy_from_slice(&1u32.to_le_bytes()); // bucket[0] = 1
    img[hash_off + 12..hash_off + 16].copy_from_slice(&0u32.to_le_bytes()); // chain[0] = 0
    img[hash_off + 16..hash_off + 20].copy_from_slice(&0u32.to_le_bytes()); // chain[1] = 0

    // .dynamic at 0x0200: DT_HASH(4), DT_STRTAB(5), DT_SYMTAB(6), DT_STRSZ(10), DT_SYMENT(11), DT_NULL(0)
    let dyn_entries: [(u32, u32); 6] = [
        (4, hash_off as u32),
        (5, strtab_off as u32),
        (6, symtab_off as u32),
        (10, s1.len() as u32),
        (11, 16),
        (0, 0),
    ];
    for (i, (tag, val)) in dyn_entries.iter().enumerate() {
        let off = 0x0200 + i * 8;
        img[off..off + 4].copy_from_slice(&tag.to_le_bytes());
        img[off + 4..off + 8].copy_from_slice(&val.to_le_bytes());
    }

    // ARM32 function `plugin_calc` at 0x1000: ADD R0, R0, #77 ; BX LR
    img[0x1000..0x1004].copy_from_slice(&0xE280_004Du32.to_le_bytes());
    img[0x1004..0x1008].copy_from_slice(&0xE12F_FF1Eu32.to_le_bytes());
    img
}

#[test]
fn test_runtime_dlopen_vfs_and_dlsym_execution() {
    let mut session = Walzer32Session::new(GuestAddr::new(0x7000_0000), 0x0200_0000).unwrap();
    let plugin_elf = build_minimal_arm32_plugin_so();
    session.register_vfs_file("/lib/armeabi-v7a/libplugin_dyn.so", plugin_elf);

    let dlopen_addr = session.bionic.resolve("dlopen").unwrap().as_u32();
    let dlsym_addr = session.bionic.resolve("dlsym").unwrap().as_u32();

    // Place caller code and string literals in the mmap heap area (0x70C8_0000),
    // away from the dynamic library load arena (0x7100_0000+).
    let caller_pc = 0x70C8_0000u32;
    let name_addr = 0x70C8_1000u32;
    let sym_addr = 0x70C8_1040u32;
    session
        .engine
        .mem
        .write_bytes(GuestAddr::new(name_addr), b"libplugin_dyn.so\0")
        .unwrap();
    session
        .engine
        .mem
        .write_bytes(GuestAddr::new(sym_addr), b"plugin_calc\0")
        .unwrap();

    // Caller code:
    //   r4 = dlopen("libplugin_dyn.so", 2)
    //   r0 = dlsym(r4, "plugin_calc")
    //   blx r0 with arg r0 = 100  -> returns 177
    let mut code = Vec::new();
    let mut pc = caller_pc;
    code.push((pc, 0xE92D_4010)); // PUSH {R4, LR}
    pc += 4;
    mov32(&mut code, &mut pc, 0, name_addr);
    code.push((pc, 0xE3A0_1002)); // MOV R1, #2
    pc += 4;
    call_abs(&mut code, &mut pc, dlopen_addr);
    code.push((pc, 0xE1A0_4000)); // MOV R4, R0 (handle)
    pc += 4;
    code.push((pc, 0xE1A0_0004)); // MOV R0, R4
    pc += 4;
    mov32(&mut code, &mut pc, 1, sym_addr);
    call_abs(&mut code, &mut pc, dlsym_addr);
    code.push((pc, 0xE1A0_C000)); // MOV R12, R0 (fn_ptr)
    pc += 4;
    code.push((pc, 0xE3A0_0064)); // MOV R0, #100
    pc += 4;
    code.push((pc, 0xE12F_FF3C)); // BLX R12
    pc += 4;
    code.push((pc, 0xE8BD_8010)); // POP {R4, PC}
    for (addr, insn) in code {
        session.engine.mem.write_u32(GuestAddr::new(addr), insn).unwrap();
    }

    let ret = session.call_native(GuestAddr::new(caller_pc), &[]).unwrap();
    assert_eq!(ret, 177);
    assert!(session.loaded_libraries.contains_key("libplugin_dyn.so"));
}

#[test]
fn test_universal_jni_thunk_register_natives_and_dispatch() {
    reset_session();
    {
        let mut guard = get_or_init_session().unwrap();
        let session = guard.as_mut().unwrap();

        // Guest 32-bit JNI native method: jlong compute(JNIEnv*, jobject, jint a, jlong b)
        // AAPCS32 softfp layout: r0=env, r1=thiz, r2=a, r3=pad, [sp+0]=b_lo, [sp+4]=b_hi
        // Computes 64-bit: (r2 as u64) + b -> returns R0=lo, R1=hi
        let fn_pc = 0x7101_0000u32;
        let insns = [
            0xE59D_3000u32, // LDR R3, [SP, #0]  (b_lo)
            0xE59D_1004u32, // LDR R1, [SP, #4]  (b_hi)
            0xE092_0003u32, // ADDS R0, R2, R3
            0xE2A1_1000u32, // ADC R1, R1, #0
            0xE12F_FF1Eu32, // BX LR
        ];
        for (i, insn) in insns.iter().enumerate() {
            session
                .engine
                .mem
                .write_u32(GuestAddr::new(fn_pc + (i as u32) * 4), *insn)
                .unwrap();
        }

        // Execute real guest ARM32 calling (*env)->FindClass + (*env)->RegisterNatives:
        let reg_cls_str = 0x7102_1000u32;
        let reg_m_name = 0x7102_1040u32;
        let reg_m_sig = 0x7102_1080u32;
        let reg_methods_arr = 0x7102_10C0u32;
        session
            .engine
            .mem
            .write_bytes(GuestAddr::new(reg_cls_str), b"com/example/GameEngine\0")
            .unwrap();
        session
            .engine
            .mem
            .write_bytes(GuestAddr::new(reg_m_name), b"nativeAdd64\0")
            .unwrap();
        session
            .engine
            .mem
            .write_bytes(GuestAddr::new(reg_m_sig), b"(IJ)J\0")
            .unwrap();
        session
            .engine
            .mem
            .write_u32(GuestAddr::new(reg_methods_arr), reg_m_name)
            .unwrap();
        session
            .engine
            .mem
            .write_u32(GuestAddr::new(reg_methods_arr + 4), reg_m_sig)
            .unwrap();
        session
            .engine
            .mem
            .write_u32(GuestAddr::new(reg_methods_arr + 8), fn_pc)
            .unwrap();

        let env_ptr = session.jni.env_ptr.as_u32();
        let onload_pc = 0x7101_0200u32;
        let mut reg_code = Vec::new();
        let mut pc = onload_pc;
        reg_code.push((pc, 0xE92D_4070)); // PUSH {R4, R5, R6, LR}
        pc += 4;
        mov32(&mut reg_code, &mut pc, 6, env_ptr);
        reg_code.push((pc, 0xE596_4000)); // LDR R4, [R6] (JNIEnv* vtable)
        pc += 4;
        reg_code.push((pc, 0xE1A0_0006)); // MOV R0, R6
        pc += 4;
        mov32(&mut reg_code, &mut pc, 1, reg_cls_str);
        reg_code.push((pc, 0xE594_C018)); // LDR R12, [R4, #24] (FindClass index 6)
        pc += 4;
        reg_code.push((pc, 0xE12F_FF3C)); // BLX R12
        pc += 4;
        reg_code.push((pc, 0xE1A0_1000)); // MOV R1, R0 (jclass)
        pc += 4;
        reg_code.push((pc, 0xE1A0_0006)); // MOV R0, R6 (env)
        pc += 4;
        mov32(&mut reg_code, &mut pc, 2, reg_methods_arr);
        reg_code.push((pc, 0xE3A0_3001)); // MOV R3, #1
        pc += 4;
        mov32(&mut reg_code, &mut pc, 5, 215 * 4);
        reg_code.push((pc, 0xE794_C005)); // LDR R12, [R4, R5] (RegisterNatives index 215)
        pc += 4;
        reg_code.push((pc, 0xE12F_FF3C)); // BLX R12
        pc += 4;
        reg_code.push((pc, 0xE8BD_8070)); // POP {R4, R5, R6, PC}
        for (addr, insn) in reg_code {
            session.engine.mem.write_u32(GuestAddr::new(addr), insn).unwrap();
        }
        let reg_ret = session.call_native(GuestAddr::new(onload_pc), &[]).unwrap();
        assert_eq!(reg_ret, 0); // JNI_OK

        let key = (
            "com/example/GameEngine".to_string(),
            "nativeAdd64".to_string(),
            "(IJ)J".to_string(),
        );
        let thunk = session
            .compiled_jni_thunks
            .get(&key)
            .expect("thunk compiled")
            .clone();
        assert_ne!(thunk.host_fn_ptr, 0);

        let mut frame = HostJniCallFrame::default();
        frame.host_env = 0x1000;
        frame.host_thiz = 0x2000;
        frame.gprs[0] = 0x1000;
        frame.gprs[1] = 0x2000;
        frame.gprs[2] = 100; // jint a
        frame.gprs[3] = 0x0000_0001_FFFF_FFE0; // jlong b (crosses 32-bit carry!)

        // Release GLOBAL_SESSION before entering universal dispatcher (mirrors host ART call)
        drop(guard);

        let result = unsafe { walzer32_universal_jni_dispatcher(thunk.descriptor_ptr, &mut frame) };
        assert_eq!(result, 0x0000_0001_FFFF_FFE0u64 + 100);
    }
    reset_session();
}

#[test]
fn test_native_activity_save_state_and_content_rect_callbacks() {
    let mut session = Walzer32Session::new(GuestAddr::new(0x7000_0000), 0x0200_0000).unwrap();
    let act_ptr = session
        .bionic
        .alloc_guest_memory(40, 8, &mut session.engine.mem);
    let cb_ptr = session
        .bionic
        .alloc_guest_memory(64, 8, &mut session.engine.mem);
    session.guest_native_activity_ptr = act_ptr.as_u32();
    session.guest_native_callbacks_ptr = cb_ptr.as_u32();

    // Guest payload returned by onSaveInstanceState: 8 bytes [0xDE, 0xAD, ...]
    let saved_payload_addr = 0x7102_0500u32;
    let payload = [0xDEu8, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4];
    session
        .engine
        .mem
        .write_bytes(GuestAddr::new(saved_payload_addr), &payload)
        .unwrap();

    // Slot 2: void* onSaveInstanceState(ANativeActivity*, size_t* outSize)
    // Writes 8 to *R1, returns saved_payload_addr in R0
    let save_fn_pc = 0x7101_1000u32;
    let mut code = Vec::new();
    let mut pc = save_fn_pc;
    code.push((pc, 0xE3A0_2008)); // MOV R2, #8
    pc += 4;
    code.push((pc, 0xE581_2000)); // STR R2, [R1]
    pc += 4;
    mov32(&mut code, &mut pc, 0, saved_payload_addr);
    code.push((pc, 0xE12F_FF1E)); // BX LR
    for (addr, insn) in code {
        session.engine.mem.write_u32(GuestAddr::new(addr), insn).unwrap();
    }
    session
        .engine
        .mem
        .write_u32(cb_ptr.add(2 * 4), save_fn_pc)
        .unwrap();

    // Slot 13: void onContentRectChanged(ANativeActivity*, const ARect* rect)
    // Copies rect[0..4] (left, top, right, bottom) to scratch addr 0x7102_0600
    let rect_sink = 0x7102_0600u32;
    let rect_fn_pc = 0x7101_2000u32;
    let mut code2 = Vec::new();
    let mut pc2 = rect_fn_pc;
    mov32(&mut code2, &mut pc2, 2, rect_sink);
    code2.push((pc2, 0xE591_3000)); // LDR R3, [R1, #0]
    pc2 += 4;
    code2.push((pc2, 0xE582_3000)); // STR R3, [R2, #0]
    pc2 += 4;
    code2.push((pc2, 0xE591_300C)); // LDR R3, [R1, #12] (bottom)
    pc2 += 4;
    code2.push((pc2, 0xE582_3004)); // STR R3, [R2, #4]
    pc2 += 4;
    code2.push((pc2, 0xE12F_FF1E)); // BX LR
    for (addr, insn) in code2 {
        session.engine.mem.write_u32(GuestAddr::new(addr), insn).unwrap();
    }
    session
        .engine
        .mem
        .write_u32(cb_ptr.add(13 * 4), rect_fn_pc)
        .unwrap();

    let saved = session
        .invoke_native_activity_save_state()
        .unwrap()
        .expect("saved bytes");
    assert_eq!(saved.as_slice(), &payload);

    assert!(session.invoke_native_activity_content_rect(10, 20, 1080, 2400).unwrap());
    assert_eq!(session.engine.mem.read_u32(GuestAddr::new(rect_sink)).unwrap(), 10);
    assert_eq!(session.engine.mem.read_u32(GuestAddr::new(rect_sink + 4)).unwrap(), 2400);
}
