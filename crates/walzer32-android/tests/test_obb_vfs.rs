use walzer32_android::session::{get_or_init_session, reset_session, Walzer32Session};
use walzer32_android::jni_exports::{
    Java_com_walzer32_loader_Walzer32Engine_nativeMountAppDataDir,
    Java_com_walzer32_loader_Walzer32Engine_nativeMountObb,
    Java_com_walzer32_loader_Walzer32Engine_nativeMountPatchObb,
    JNI_OK,
};
use walzer32_apk::ZipBuilder;
use walzer32_core::GuestAddr;

#[test]
fn test_session_obb_vfs_mount() {
    let mut session = Walzer32Session::new(GuestAddr::new(0x7000_0000), 0x200_0000).unwrap();

    let obb_payload = b"OBB Main Expansion Pack Data Content v100".to_vec();
    session.mount_obb("com.walzer32.game", 100, obb_payload.clone());

    let patch_payload = b"OBB Patch Expansion Pack Data Content v100".to_vec();
    session.mount_patch_obb("com.walzer32.game", 100, patch_payload.clone());

    session.mount_app_data_dir("com.walzer32.game");

    let vfs = session.engine.vfs().unwrap();

    // Verify main OBB access across different standard paths
    let main_sdcard = vfs.get_file("/sdcard/Android/obb/com.walzer32.game/main.100.com.walzer32.game.obb");
    let main_storage = vfs.get_file("/storage/emulated/0/Android/obb/com.walzer32.game/main.100.com.walzer32.game.obb");
    let main_data = vfs.get_file("/data/media/0/Android/obb/com.walzer32.game/main.100.com.walzer32.game.obb");

    assert!(main_sdcard.is_some());
    assert!(main_storage.is_some());
    assert!(main_data.is_some());

    assert_eq!(main_sdcard.unwrap().as_ref(), &obb_payload[..]);
    assert_eq!(main_storage.unwrap().as_ref(), &obb_payload[..]);
    assert_eq!(main_data.unwrap().as_ref(), &obb_payload[..]);

    // Verify patch OBB access
    let patch_sdcard = vfs.get_file("/sdcard/Android/obb/com.walzer32.game/patch.100.com.walzer32.game.obb");
    assert!(patch_sdcard.is_some());
    assert_eq!(patch_sdcard.unwrap().as_ref(), &patch_payload[..]);

    // Verify app data directory redirection rule
    let redirected = vfs.resolve_path("/data/user/0/com.walzer32.game/files/save.dat");
    assert_eq!(redirected, "/data/data/com.walzer32.game/files/save.dat");
}

#[test]
fn test_session_apk_asset_streaming() {
    let mut session = Walzer32Session::new(GuestAddr::new(0x7000_0000), 0x200_0000).unwrap();

    let mut builder = ZipBuilder::new();
    builder.add_file("assets/levels/world1.bin", b"World 1 Binary Map Data");
    builder.add_file("assets/ui/theme.json", b"{\"theme\": \"cyberpunk\"}");
    let apk_bytes = builder.build();

    // Attaching APK automatically extracts and registers assets in AssetBridge
    session.attach_apk(apk_bytes);

    assert!(session.asset.assets_map.contains_key("levels/world1.bin"));
    assert!(session.asset.assets_map.contains_key("ui/theme.json"));

    let world_data = session.asset.assets_map.get("levels/world1.bin").unwrap();
    assert_eq!(world_data.as_ref(), b"World 1 Binary Map Data");
}

#[test]
fn test_jni_exports_obb_mount() {
    reset_session();
    drop(get_or_init_session().unwrap());

    let pkg = b"com.walzer32.shooter";
    let obb_data = b"JNI OBB Test Payload 123456";

    unsafe {
        let res = Java_com_walzer32_loader_Walzer32Engine_nativeMountObb(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            pkg.as_ptr(),
            pkg.len(),
            42,
            obb_data.as_ptr(),
            obb_data.len(),
        );
        assert_eq!(res, JNI_OK);

        let patch_res = Java_com_walzer32_loader_Walzer32Engine_nativeMountPatchObb(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            pkg.as_ptr(),
            pkg.len(),
            42,
            obb_data.as_ptr(),
            obb_data.len(),
        );
        assert_eq!(patch_res, JNI_OK);

        let data_res = Java_com_walzer32_loader_Walzer32Engine_nativeMountAppDataDir(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            pkg.as_ptr(),
            pkg.len(),
        );
        assert_eq!(data_res, JNI_OK);
    }

    let guard = get_or_init_session().unwrap();
    let session = guard.as_ref().unwrap();
    let vfs = session.engine.vfs().unwrap();

    let obb_path = "/sdcard/Android/obb/com.walzer32.shooter/main.42.com.walzer32.shooter.obb";
    let resolved = vfs.get_file(obb_path);
    assert!(resolved.is_some());
    assert_eq!(resolved.unwrap().as_ref(), obb_data);

    let patch_path = "/sdcard/Android/obb/com.walzer32.shooter/patch.42.com.walzer32.shooter.obb";
    let patch_resolved = vfs.get_file(patch_path);
    assert!(patch_resolved.is_some());
    assert_eq!(patch_resolved.unwrap().as_ref(), obb_data);
}
