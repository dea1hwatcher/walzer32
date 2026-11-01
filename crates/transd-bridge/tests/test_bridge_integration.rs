use transd_core::{FlatMemory, GuestAddr, Memory};
use transd_rt::DbtEngine;
use transd_bridge::{
    invoke_guest, invoke_jni_onload, BionicBridge, JniBridge, JNI_VERSION_1_6,
};

#[test]
fn test_bionic_log_and_malloc() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);

    let mut bionic = BionicBridge::new(
        GuestAddr::new(0x7000_0000),
        GuestAddr::new(0x7010_0000),
        0x100_000,
    );
    bionic.install_stubs(&mut mem).unwrap();

    let mut jni = JniBridge::new(GuestAddr::new(0x7005_0000));
    jni.install(&mut mem).unwrap();

    let mut engine = DbtEngine::new(mem);

    // Write a test ARM32 function at 0x7002_0000:
    // Calls __android_log_print(ANDROID_LOG_INFO = 4, tag = "TransdTag", msg = "Hello from DBT Bionic!")
    //
    // Tag string at 0x7002_0100: "TransdTag\0"
    // Msg string at 0x7002_0120: "Hello from DBT Bionic!\0"
    let code_addr = GuestAddr::new(0x7002_0000);
    let tag_addr = GuestAddr::new(0x7002_0100);
    let msg_addr = GuestAddr::new(0x7002_0120);

    engine.mem.write_bytes(tag_addr, b"TransdTag\0").unwrap();
    engine.mem.write_bytes(msg_addr, b"Hello from DBT Bionic!\0").unwrap();

    let log_func_addr = bionic.stub_base.add((transd_bridge::BionicFuncId::AndroidLogPrint as u32) * 8);

    // Assembly code at 0x7002_0000:
    // PUSH {lr}
    // MOV r0, #4 (prio)
    // LDR r1, =tag_addr
    // LDR r2, =msg_addr
    // LDR r3, =log_func_addr
    // BLX r3
    // POP {lr}
    // BX lr
    let insts = [
        0xE52DE004, // STR lr, [sp, #-4]! (PUSH {lr})
        0xE3A00004, // MOV r0, #4
        0xE59F1010, // LDR r1, [pc, #16] -> tag_addr (0x08 + 8 + 16 = 0x20)
        0xE59F2010, // LDR r2, [pc, #16] -> msg_addr (0x0C + 8 + 16 = 0x24)
        0xE59F3010, // LDR r3, [pc, #16] -> log_func_addr (0x10 + 8 + 16 = 0x28)
        0xE12FFF33, // BLX r3
        0xE49DE004, // LDR lr, [sp], #4  (POP {lr})
        0xE12FFF1E, // BX lr
        // Literals at pc+8:
        tag_addr.as_u32(),
        msg_addr.as_u32(),
        log_func_addr.as_u32(),
    ];

    for (i, &word) in insts.iter().enumerate() {
        engine.mem.write_u32(code_addr.add((i * 4) as u32), word).unwrap();
    }

    engine.cpu.set_sp(0x701F_F000);

    let res = invoke_guest(&mut engine, &mut bionic, &mut jni, code_addr, &[]).unwrap();
    assert_eq!(res, 1); // log_print returns 1

    // Verify log message was captured!
    assert_eq!(bionic.logs.len(), 1);
    assert_eq!(bionic.logs[0].priority, 4);
    assert_eq!(bionic.logs[0].tag, "TransdTag");
    assert_eq!(bionic.logs[0].text, "Hello from DBT Bionic!");
}

#[test]
fn test_jni_get_version_and_new_string() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);

    let mut bionic = BionicBridge::new(
        GuestAddr::new(0x7000_0000),
        GuestAddr::new(0x7010_0000),
        0x100_000,
    );
    bionic.install_stubs(&mut mem).unwrap();

    let mut jni = JniBridge::new(GuestAddr::new(0x7005_0000));
    jni.install(&mut mem).unwrap();

    let mut engine = DbtEngine::new(mem);

    // 1. Test GetVersion:
    // Calls (*env)->GetVersion(env)
    // Code at 0x7002_0000:
    let code_addr = GuestAddr::new(0x7002_0000);
    let insts = [
        0xE52DE004, // STR lr, [sp, #-4]!
        0xE5901000, // LDR r1, [r0]
        0xE5911010, // LDR r1, [r1, #16]
        0xE12FFF31, // BLX r1
        0xE49DE004, // LDR lr, [sp], #4
        0xE12FFF1E, // BX lr
    ];

    for (i, &word) in insts.iter().enumerate() {
        engine.mem.write_u32(code_addr.add((i * 4) as u32), word).unwrap();
    }

    engine.cpu.set_sp(0x701F_F000);

    let env_val = jni.env_ptr.as_u32();
    let version = invoke_guest(
        &mut engine,
        &mut bionic,
        &mut jni,
        code_addr,
        &[env_val],
    )
    .unwrap();

    assert_eq!(version, JNI_VERSION_1_6);

    // 2. Test NewStringUTF:
    // Text at 0x7002_0200: "Hello Android ARM32!\0"
    let text_addr = GuestAddr::new(0x7002_0200);
    engine.mem.write_bytes(text_addr, b"Hello Android ARM32!\0").unwrap();

    // Code at 0x7002_0030:
    let code2_addr = GuestAddr::new(0x7002_0030);
    let insts2 = [
        0xE52DE004, // STR lr, [sp, #-4]!
        0xE59F1010, // LDR r1, [pc, #16] -> text_addr (0x34 + 8 + 16 = 0x4C)
        0xE5902000, // LDR r2, [r0]
        0xE5922298, // LDR r2, [r2, #664]
        0xE12FFF32, // BLX r2
        0xE49DE004, // LDR lr, [sp], #4
        0xE12FFF1E, // BX lr
        // Literal at 0x4C:
        text_addr.as_u32(),
    ];

    for (i, &word) in insts2.iter().enumerate() {
        engine.mem.write_u32(code2_addr.add((i * 4) as u32), word).unwrap();
    }

    let env_val = jni.env_ptr.as_u32();
    let string_handle = invoke_guest(
        &mut engine,
        &mut bionic,
        &mut jni,
        code2_addr,
        &[env_val],
    )
    .unwrap();

    assert!(string_handle >= 100);
    assert_eq!(
        jni.strings.get(&string_handle).map(|s| s.as_str()),
        Some("Hello Android ARM32!")
    );
}

#[test]
fn test_jni_onload_lifecycle() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);

    let mut bionic = BionicBridge::new(
        GuestAddr::new(0x7000_0000),
        GuestAddr::new(0x7010_0000),
        0x100_000,
    );
    bionic.install_stubs(&mut mem).unwrap();

    let mut jni = JniBridge::new(GuestAddr::new(0x7005_0000));
    jni.install(&mut mem).unwrap();

    let mut engine = DbtEngine::new(mem);

    // Code simulating JNI_OnLoad(JavaVM *vm, void *reserved):
    // 0x7002_0000:
    // PUSH {r4, lr}
    // MOV r4, r0             ; r4 = vm
    // SUB sp, sp, #8         ; stack allocation for void *env
    // MOV r1, sp             ; r1 = &env
    // MOV r2, #0x00010006    ; r2 = JNI_VERSION_1_6
    // LDR r3, [r4]           ; r3 = *vm
    // LDR r3, [r3, #24]      ; r3 = (*vm)->GetEnv (index 6 * 4 = 24)
    // BLX r3                 ; call GetEnv(vm, &env, JNI_VERSION_1_6)
    // MOV r0, #0x00010006    ; return JNI_VERSION_1_6
    // ADD sp, sp, #8
    // POP {r4, lr}
    // BX lr
    let onload_addr = GuestAddr::new(0x7002_0000);
    let insts = [
        0xE92D4010, // PUSH {r4, lr}
        0xE1A04000, // MOV r4, r0
        0xE24DD008, // SUB sp, sp, #8
        0xE1A0100D, // MOV r1, sp
        0xE59F2018, // LDR r2, [pc, #24] -> JNI_VERSION_1_6
        0xE5943000, // LDR r3, [r4]
        0xE5933018, // LDR r3, [r3, #24]
        0xE12FFF33, // BLX r3
        0xE59F000C, // LDR r0, [pc, #12] -> JNI_VERSION_1_6
        0xE28DD008, // ADD sp, sp, #8
        0xE8BD4010, // POP {r4, lr}
        0xE12FFF1E, // BX lr
        // Literals:
        JNI_VERSION_1_6,
        JNI_VERSION_1_6,
    ];

    for (i, &word) in insts.iter().enumerate() {
        engine.mem.write_u32(onload_addr.add((i * 4) as u32), word).unwrap();
    }

    engine.cpu.set_sp(0x701F_F000);

    let ver = invoke_jni_onload(&mut engine, &mut bionic, &mut jni, onload_addr).unwrap();
    assert_eq!(ver, JNI_VERSION_1_6);
}

#[test]
fn test_jni_extended_bridge_apis() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);

    let bionic = BionicBridge::new(
        GuestAddr::new(0x7000_0000),
        GuestAddr::new(0x7010_0000),
        0x100_000,
    );
    bionic.install_stubs(&mut mem).unwrap();

    let mut jni = JniBridge::new(GuestAddr::new(0x7005_0000));
    jni.install(&mut mem).unwrap();

    let mut engine = DbtEngine::new(mem);

    // 1. Direct unit test of Exception lifecycle
    let mut cpu = transd_core::CpuState::new();
    assert_eq!(jni.pending_exception, 0);

    // ExceptionCheck when no exception -> 0
    let check_imm = transd_bridge::JNI_SVC_MAGIC | transd_bridge::jni_idx::EXCEPTION_CHECK;
    jni.handle_svc(check_imm, &mut cpu, &mut engine.mem).unwrap();
    assert_eq!(cpu.reg(transd_core::Reg::R0), 0);

    // ThrowNew -> pending_exception becomes non-zero
    let throw_imm = transd_bridge::JNI_SVC_MAGIC | transd_bridge::jni_idx::THROW_NEW;
    jni.handle_svc(throw_imm, &mut cpu, &mut engine.mem).unwrap();
    assert_ne!(jni.pending_exception, 0);

    // ExceptionCheck when exception pending -> 1
    jni.handle_svc(check_imm, &mut cpu, &mut engine.mem).unwrap();
    assert_eq!(cpu.reg(transd_core::Reg::R0), 1);

    // ExceptionClear -> pending_exception becomes 0
    let clear_imm = transd_bridge::JNI_SVC_MAGIC | transd_bridge::jni_idx::EXCEPTION_CLEAR;
    jni.handle_svc(clear_imm, &mut cpu, &mut engine.mem).unwrap();
    assert_eq!(jni.pending_exception, 0);

    // 2. Test GlobalRef lifecycle
    let global_imm = transd_bridge::JNI_SVC_MAGIC | transd_bridge::jni_idx::NEW_GLOBAL_REF;
    cpu.set_reg(transd_core::Reg::R1, 105); // obj handle 105
    jni.handle_svc(global_imm, &mut cpu, &mut engine.mem).unwrap();
    assert_eq!(cpu.reg(transd_core::Reg::R0), 105);
    assert_eq!(jni.global_refs.get(&105), Some(&105));

    let del_global_imm = transd_bridge::JNI_SVC_MAGIC | transd_bridge::jni_idx::DELETE_GLOBAL_REF;
    cpu.set_reg(transd_core::Reg::R1, 105);
    jni.handle_svc(del_global_imm, &mut cpu, &mut engine.mem).unwrap();
    assert!(jni.global_refs.get(&105).is_none());

    // 3. Test ByteArray lifecycle
    let new_arr_imm = transd_bridge::JNI_SVC_MAGIC | transd_bridge::jni_idx::NEW_BYTE_ARRAY;
    cpu.set_reg(transd_core::Reg::R1, 256); // len 256
    jni.handle_svc(new_arr_imm, &mut cpu, &mut engine.mem).unwrap();
    let arr_handle = cpu.reg(transd_core::Reg::R0);
    assert!(arr_handle >= 100);

    let get_len_imm = transd_bridge::JNI_SVC_MAGIC | transd_bridge::jni_idx::GET_ARRAY_LENGTH;
    cpu.set_reg(transd_core::Reg::R1, arr_handle);
    jni.handle_svc(get_len_imm, &mut cpu, &mut engine.mem).unwrap();
    assert_eq!(cpu.reg(transd_core::Reg::R0), 256);
}
