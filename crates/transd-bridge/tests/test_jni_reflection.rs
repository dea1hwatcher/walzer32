use transd_core::{CpuState, FlatMemory, GuestAddr, Memory, Reg};
use transd_bridge::{
    jni_idx, JniBridge, JNI_SVC_MAGIC,
};

fn setup_bridge_and_cpu() -> (FlatMemory, CpuState, JniBridge) {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let jni = JniBridge::new(GuestAddr::new(0x7005_0000));
    jni.install(&mut mem).unwrap();

    let mut cpu = CpuState::new();
    cpu.set_sp(0x701F_F000);
    (mem, cpu, jni)
}

#[test]
fn test_jni_reflection_fields() {
    let (mut mem, mut cpu, mut jni) = setup_bridge_and_cpu();

    // 1. FindClass "com/transd/test/Player\0"
    let class_str_addr = GuestAddr::new(0x7001_0000);
    mem.write_bytes(class_str_addr, b"com/transd/test/Player\0").unwrap();

    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, class_str_addr.as_u32());
    let handled = jni.handle_svc(JNI_SVC_MAGIC | jni_idx::FIND_CLASS, &mut cpu, &mut mem).unwrap();
    assert!(handled);
    let class_handle = cpu.reg(Reg::R0);
    assert_ne!(class_handle, 0);

    // 2. GetFieldID for int field "health" "I"
    let field_health_addr = GuestAddr::new(0x7001_0050);
    let sig_int_addr = GuestAddr::new(0x7001_0060);
    mem.write_bytes(field_health_addr, b"health\0").unwrap();
    mem.write_bytes(sig_int_addr, b"I\0").unwrap();

    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, class_handle);
    cpu.set_reg(Reg::R2, field_health_addr.as_u32());
    cpu.set_reg(Reg::R3, sig_int_addr.as_u32());
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::GET_FIELD_ID, &mut cpu, &mut mem).unwrap();
    let health_field_id = cpu.reg(Reg::R0);
    assert_ne!(health_field_id, 0);

    // 3. AllocObject / NewObject for Player instance
    let obj_handle = 200u32;

    // 4. SetIntField(env, obj, health_field_id, 100)
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, obj_handle);
    cpu.set_reg(Reg::R2, health_field_id);
    cpu.set_reg(Reg::R3, 100);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::SET_INT_FIELD, &mut cpu, &mut mem).unwrap();

    // 5. GetIntField(env, obj, health_field_id) -> returns 100
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, obj_handle);
    cpu.set_reg(Reg::R2, health_field_id);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::GET_INT_FIELD, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 100);

    // 6. GetFieldID for boolean field "isAlive" "Z"
    let field_alive_addr = GuestAddr::new(0x7001_0070);
    let sig_bool_addr = GuestAddr::new(0x7001_0080);
    mem.write_bytes(field_alive_addr, b"isAlive\0").unwrap();
    mem.write_bytes(sig_bool_addr, b"Z\0").unwrap();

    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, class_handle);
    cpu.set_reg(Reg::R2, field_alive_addr.as_u32());
    cpu.set_reg(Reg::R3, sig_bool_addr.as_u32());
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::GET_FIELD_ID, &mut cpu, &mut mem).unwrap();
    let alive_field_id = cpu.reg(Reg::R0);

    // SetBooleanField to true (1)
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, obj_handle);
    cpu.set_reg(Reg::R2, alive_field_id);
    cpu.set_reg(Reg::R3, 1);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::SET_BOOLEAN_FIELD, &mut cpu, &mut mem).unwrap();

    // GetBooleanField -> returns 1
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, obj_handle);
    cpu.set_reg(Reg::R2, alive_field_id);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::GET_BOOLEAN_FIELD, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    // 7. Static field: GetStaticFieldID for "MAX_PLAYERS" "I"
    let field_max_addr = GuestAddr::new(0x7001_0090);
    mem.write_bytes(field_max_addr, b"MAX_PLAYERS\0").unwrap();

    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, class_handle);
    cpu.set_reg(Reg::R2, field_max_addr.as_u32());
    cpu.set_reg(Reg::R3, sig_int_addr.as_u32());
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::GET_STATIC_FIELD_ID, &mut cpu, &mut mem).unwrap();
    let max_field_id = cpu.reg(Reg::R0);

    // SetStaticIntField(env, class_handle, max_field_id, 64)
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, class_handle);
    cpu.set_reg(Reg::R2, max_field_id);
    cpu.set_reg(Reg::R3, 64);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::SET_STATIC_INT_FIELD, &mut cpu, &mut mem).unwrap();

    // GetStaticIntField(env, class_handle, max_field_id) -> returns 64
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, class_handle);
    cpu.set_reg(Reg::R2, max_field_id);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::GET_STATIC_INT_FIELD, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 64);
}

#[test]
fn test_jni_reflection_method_invocation_thunks() {
    let (mut mem, mut cpu, mut jni) = setup_bridge_and_cpu();

    // Context / Activity class
    let class_str_addr = GuestAddr::new(0x7001_0000);
    mem.write_bytes(class_str_addr, b"android/content/Context\0").unwrap();

    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, class_str_addr.as_u32());
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::FIND_CLASS, &mut cpu, &mut mem).unwrap();
    let context_class = cpu.reg(Reg::R0);

    // 1. GetMethodID for getPackageName() -> String
    let meth_pkg_addr = GuestAddr::new(0x7001_0030);
    let sig_pkg_addr = GuestAddr::new(0x7001_0050);
    mem.write_bytes(meth_pkg_addr, b"getPackageName\0").unwrap();
    mem.write_bytes(sig_pkg_addr, b"()Ljava/lang/String;\0").unwrap();

    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, context_class);
    cpu.set_reg(Reg::R2, meth_pkg_addr.as_u32());
    cpu.set_reg(Reg::R3, sig_pkg_addr.as_u32());
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::GET_METHOD_ID, &mut cpu, &mut mem).unwrap();
    let get_pkg_method = cpu.reg(Reg::R0);

    // CallObjectMethod(env, context_obj, get_pkg_method)
    let context_obj = 300u32;
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, context_obj);
    cpu.set_reg(Reg::R2, get_pkg_method);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::CALL_OBJECT_METHOD, &mut cpu, &mut mem).unwrap();
    let string_handle = cpu.reg(Reg::R0);
    assert_ne!(string_handle, 0);

    // GetStringUTFChars to inspect package name
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, string_handle);
    cpu.set_reg(Reg::R2, 0); // isCopy = NULL
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::GET_STRING_UTF_CHARS, &mut cpu, &mut mem).unwrap();
    let cstr_ptr = GuestAddr::new(cpu.reg(Reg::R0));

    let mut buf = vec![0u8; 15];
    mem.read_bytes(cstr_ptr, &mut buf).unwrap();
    assert_eq!(std::str::from_utf8(&buf).unwrap(), "com.transd.app\0");

    // 2. GetMethodID for getAbsolutePath() -> String
    let meth_path_addr = GuestAddr::new(0x7001_0080);
    mem.write_bytes(meth_path_addr, b"getAbsolutePath\0").unwrap();

    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, context_class);
    cpu.set_reg(Reg::R2, meth_path_addr.as_u32());
    cpu.set_reg(Reg::R3, sig_pkg_addr.as_u32());
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::GET_METHOD_ID, &mut cpu, &mut mem).unwrap();
    let get_path_method = cpu.reg(Reg::R0);

    // CallObjectMethod
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, context_obj);
    cpu.set_reg(Reg::R2, get_path_method);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::CALL_OBJECT_METHOD, &mut cpu, &mut mem).unwrap();
    let path_handle = cpu.reg(Reg::R0);

    // GetStringUTFLength
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, path_handle);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::GET_STRING_UTF_LENGTH, &mut cpu, &mut mem).unwrap();
    let path_len = cpu.reg(Reg::R0);
    assert_eq!(path_len, "/data/data/com.transd.app/files".len() as u32);

    // 3. CallBooleanMethod returns JNI_TRUE (1)
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, context_obj);
    cpu.set_reg(Reg::R2, 999);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::CALL_BOOLEAN_METHOD, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    // 4. CallIntMethod returns 0
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, context_obj);
    cpu.set_reg(Reg::R2, 999);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::CALL_INT_METHOD, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_jni_direct_byte_buffer() {
    let (mut mem, mut cpu, mut jni) = setup_bridge_and_cpu();

    let raw_buf_addr = GuestAddr::new(0x7003_0000);
    let cap = 4096u32;
    mem.write_bytes(raw_buf_addr, b"TRANSD_DIRECT_BUFFER_PAYLOAD").unwrap();

    // 1. NewDirectByteBuffer(env, address = 0x7003_0000, capacity = 4096)
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, raw_buf_addr.as_u32());
    cpu.set_reg(Reg::R2, cap);
    cpu.set_reg(Reg::R3, 0); // High 32 bits of jlong capacity
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::NEW_DIRECT_BYTE_BUFFER, &mut cpu, &mut mem).unwrap();
    let buf_handle = cpu.reg(Reg::R0);
    assert_ne!(buf_handle, 0);

    // 2. GetDirectBufferAddress(env, buf_handle)
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, buf_handle);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::GET_DIRECT_BUFFER_ADDRESS, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), raw_buf_addr.as_u32());

    // 3. GetDirectBufferCapacity(env, buf_handle)
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, buf_handle);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::GET_DIRECT_BUFFER_CAPACITY, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), cap);
    assert_eq!(cpu.reg(Reg::R1), 0);
}

#[test]
fn test_jni_primitive_array_regions_and_exceptions() {
    let (mut mem, mut cpu, mut jni) = setup_bridge_and_cpu();

    // 1. NewByteArray(env, length = 16)
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, 16);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::NEW_BYTE_ARRAY, &mut cpu, &mut mem).unwrap();
    let arr_handle = cpu.reg(Reg::R0);
    assert_ne!(arr_handle, 0);

    // GetArrayLength
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, arr_handle);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::GET_ARRAY_LENGTH, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 16);

    // 2. SetByteArrayRegion(env, arr, start = 2, len = 4, buf)
    let src_buf_addr = GuestAddr::new(0x7004_0000);
    let sp_addr = GuestAddr::new(cpu.sp());
    mem.write_bytes(src_buf_addr, &[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
    // 5th argument passed on stack:
    mem.write_u32(sp_addr, src_buf_addr.as_u32()).unwrap();

    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, arr_handle);
    cpu.set_reg(Reg::R2, 2);
    cpu.set_reg(Reg::R3, 4);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::SET_BYTE_ARRAY_REGION, &mut cpu, &mut mem).unwrap();

    // 3. GetByteArrayRegion(env, arr, start = 2, len = 4, dest_buf)
    let dst_buf_addr = GuestAddr::new(0x7004_0100);
    mem.write_u32(sp_addr, dst_buf_addr.as_u32()).unwrap();

    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, arr_handle);
    cpu.set_reg(Reg::R2, 2);
    cpu.set_reg(Reg::R3, 4);
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::GET_BYTE_ARRAY_REGION, &mut cpu, &mut mem).unwrap();

    let mut read_back = vec![0u8; 4];
    mem.read_bytes(dst_buf_addr, &mut read_back).unwrap();
    assert_eq!(read_back, vec![0xAA, 0xBB, 0xCC, 0xDD]);

    // 4. ExceptionCheck, ThrowNew, ExceptionOccurred, ExceptionClear
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::EXCEPTION_CHECK, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // ThrowNew
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    cpu.set_reg(Reg::R1, 1); // clazz
    cpu.set_reg(Reg::R2, 0); // message
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::THROW_NEW, &mut cpu, &mut mem).unwrap();

    // ExceptionCheck -> returns 1
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::EXCEPTION_CHECK, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    // ExceptionClear -> resets exception
    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::EXCEPTION_CLEAR, &mut cpu, &mut mem).unwrap();

    cpu.set_reg(Reg::R0, jni.env_ptr.as_u32());
    jni.handle_svc(JNI_SVC_MAGIC | jni_idx::EXCEPTION_CHECK, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}
