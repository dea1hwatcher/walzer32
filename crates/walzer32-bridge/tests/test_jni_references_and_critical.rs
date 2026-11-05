use walzer32_bridge::{
    jni_idx, vm_idx, JniBridge, JNI_FALSE, JNI_OK, JNI_SVC_MAGIC, JNI_TRUE,
};
use walzer32_core::{CpuState, FlatMemory, GuestAddr, Memory, Reg};

#[test]
fn test_jni_local_frames_push_pop() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x20_000);
    let mut jni = JniBridge::new(GuestAddr::new(0x7000_0000));
    jni.install(&mut mem).unwrap();

    let mut cpu = CpuState::new();

    assert_eq!(jni.local_frames.len(), 1);

    // 1. PushLocalFrame(16)
    cpu.set_reg(Reg::R1, 16);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::PUSH_LOCAL_FRAME, &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), JNI_OK);
    assert_eq!(jni.local_frames.len(), 2);

    // 2. Allocate two objects in child frame
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::ALLOC_OBJECT, &mut cpu, &mut mem)
        .unwrap();
    let _obj1 = cpu.reg(Reg::R0);

    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::ALLOC_OBJECT, &mut cpu, &mut mem)
        .unwrap();
    let obj2 = cpu.reg(Reg::R0);

    assert_eq!(jni.local_frames[1].len(), 2);

    // 3. PopLocalFrame returning obj2
    cpu.set_reg(Reg::R1, obj2);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::POP_LOCAL_FRAME, &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), obj2);
    assert_eq!(jni.local_frames.len(), 1);

    // obj2 was promoted to the parent frame
    assert_eq!(jni.local_frames[0], vec![obj2]);
}

#[test]
fn test_jni_weak_global_refs_and_is_same_object() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x20_000);
    let mut jni = JniBridge::new(GuestAddr::new(0x7000_0000));
    jni.install(&mut mem).unwrap();

    let mut cpu = CpuState::new();

    // 1. Create object
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::ALLOC_OBJECT, &mut cpu, &mut mem)
        .unwrap();
    let obj = cpu.reg(Reg::R0);

    // 2. NewWeakGlobalRef(obj)
    cpu.set_reg(Reg::R1, obj);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::NEW_WEAK_GLOBAL_REF, &mut cpu, &mut mem)
        .unwrap();
    let weak_ref = cpu.reg(Reg::R0);
    assert_ne!(weak_ref, 0);
    assert_ne!(weak_ref, obj);

    // 3. IsSameObject(weak_ref, obj) -> JNI_TRUE (1)
    cpu.set_reg(Reg::R1, weak_ref);
    cpu.set_reg(Reg::R2, obj);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::IS_SAME_OBJECT, &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), JNI_TRUE as u32);

    // 4. DeleteWeakGlobalRef(weak_ref)
    cpu.set_reg(Reg::R1, weak_ref);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::DELETE_WEAK_GLOBAL_REF, &mut cpu, &mut mem)
        .unwrap();

    // 5. IsSameObject(weak_ref, 0) -> JNI_TRUE (now dead weak ref behaves as NULL)
    cpu.set_reg(Reg::R1, weak_ref);
    cpu.set_reg(Reg::R2, 0);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::IS_SAME_OBJECT, &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), JNI_TRUE as u32);
}

#[test]
fn test_jni_critical_pinning() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x20_000);
    let mut jni = JniBridge::new(GuestAddr::new(0x7000_0000));
    jni.install(&mut mem).unwrap();

    let mut cpu = CpuState::new();

    // 1. Test GetStringCritical
    let str_handle = jni.intern_string("FastPinnedString".to_string());
    let is_copy_addr = GuestAddr::new(0x7000_5000);

    cpu.set_reg(Reg::R1, str_handle);
    cpu.set_reg(Reg::R2, is_copy_addr.as_u32());
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::GET_STRING_CRITICAL, &mut cpu, &mut mem)
        .unwrap();
    let str_ptr = cpu.reg(Reg::R0);
    assert_ne!(str_ptr, 0);
    assert_eq!(mem.read_u8(is_copy_addr).unwrap(), JNI_FALSE);

    // ReleaseStringCritical
    cpu.set_reg(Reg::R1, str_handle);
    cpu.set_reg(Reg::R2, str_ptr);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::RELEASE_STRING_CRITICAL, &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 2. Test GetPrimitiveArrayCritical with byte array
    let arr_data_addr = GuestAddr::new(0x7000_6000);
    mem.write_bytes(arr_data_addr, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    let arr_handle = jni.next_handle;
    jni.next_handle += 1;
    jni.arrays.insert(arr_handle, (arr_data_addr, 8, 1));

    cpu.set_reg(Reg::R1, arr_handle);
    cpu.set_reg(Reg::R2, is_copy_addr.as_u32());
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::GET_PRIMITIVE_ARRAY_CRITICAL, &mut cpu, &mut mem)
        .unwrap();
    let arr_ptr = cpu.reg(Reg::R0);
    assert_eq!(arr_ptr, arr_data_addr.as_u32());
    assert_eq!(mem.read_u8(is_copy_addr).unwrap(), JNI_FALSE);

    // ReleasePrimitiveArrayCritical
    cpu.set_reg(Reg::R1, arr_handle);
    cpu.set_reg(Reg::R2, arr_ptr);
    cpu.set_reg(Reg::R3, 0); // JNI_COMMIT
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::RELEASE_PRIMITIVE_ARRAY_CRITICAL, &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_javavm_attach_current_thread() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x20_000);
    let mut jni = JniBridge::new(GuestAddr::new(0x7000_0000));
    jni.install(&mut mem).unwrap();

    let mut cpu = CpuState::new();

    // Call JavaVM::AttachCurrentThread(vm, &env, NULL)
    let penv_addr = GuestAddr::new(0x7000_8000);
    mem.write_u32(penv_addr, 0).unwrap(); // initially NULL

    cpu.set_reg(Reg::R0, jni.vm_ptr.as_u32());
    cpu.set_reg(Reg::R1, penv_addr.as_u32());
    cpu.set_reg(Reg::R2, 0);

    // JavaVM calls have 0x8000 flag in svc_imm
    let vm_imm = JNI_SVC_MAGIC | 0x8000 | vm_idx::ATTACH_CURRENT_THREAD;
    jni.handle_svc(vm_imm, &mut cpu, &mut mem).unwrap();

    assert_eq!(cpu.reg(Reg::R0), JNI_OK);

    // *penv must now contain the valid JNIEnv* address!
    let env_ptr = mem.read_u32(penv_addr).unwrap();
    assert_eq!(env_ptr, jni.env_ptr.as_u32());
}
