use walzer32_core::GuestAddr;
use walzer32_android::session::Walzer32Session;
use walzer32_android::jni_exports::{
    Java_com_walzer32_loader_Walzer32Engine_nativeSetSystemProperty,
};

#[test]
fn test_android_session_properties_and_vfs_sync() {
    let mut session = Walzer32Session::new(GuestAddr::new(0x7000_0000), 0x200_0000).unwrap();

    // 1. Verify default properties
    assert_eq!(
        session.get_system_property("ro.product.cpu.abi"),
        Some("armeabi-v7a".to_string())
    );
    assert_eq!(
        session.get_system_property("ro.build.version.sdk"),
        Some("28".to_string())
    );

    // 2. Set custom property
    session.set_system_property("debug.walzer32.custom_flag", "enabled_1");
    assert_eq!(
        session.get_system_property("debug.walzer32.custom_flag"),
        Some("enabled_1".to_string())
    );

    // 3. Verify VFS /system/build.prop was updated
    let vfs = session.engine.syscall_handler.vfs().unwrap();
    let file = vfs.virtual_files.get("/system/build.prop").expect("build.prop must exist");
    let content = String::from_utf8_lossy(file);
    assert!(content.contains("debug.walzer32.custom_flag=enabled_1"));
    assert!(content.contains("ro.product.cpu.abi=armeabi-v7a"));
}

#[test]
fn test_jni_native_set_system_property() {
    let key = "persist.walzer32.mode";
    let val = "performance";

    let res = unsafe {
        Java_com_walzer32_loader_Walzer32Engine_nativeSetSystemProperty(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            key.as_ptr(),
            key.len(),
            val.as_ptr(),
            val.len(),
        )
    };
    assert_eq!(res, 0);

    let guard = walzer32_android::session::get_or_init_session().unwrap();
    let session = guard.as_ref().unwrap();
    assert_eq!(
        session.get_system_property("persist.walzer32.mode"),
        Some("performance".to_string())
    );
}
