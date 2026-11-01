use std::ptr;
use transd_android::{
    get_or_init_session, reset_session,
    Java_com_transd_loader_TransdEngine_nativeGenerateTombstone,
    Java_com_transd_loader_TransdEngine_nativeGetTelemetryHud,
    Java_com_transd_loader_TransdEngine_nativeGetTelemetryJson,
    TombstoneSignal,
};

#[test]
fn test_session_telemetry_and_tombstone() {
    reset_session();
    let mut guard = get_or_init_session().unwrap();
    let session = guard.as_mut().unwrap();

    // 1. Initial Telemetry
    let hud = session.get_telemetry_hud();
    assert!(hud.contains("TRANSD DBT ENGINE TELEMETRY HUD"));

    let json = session.get_telemetry_json();
    assert!(json.contains("\"fps\":"));
    assert!(json.contains("\"total_instructions\":"));

    // 2. Draw Frame updates FPS and telemetry
    session.on_draw_frame().unwrap();
    session.on_draw_frame().unwrap();
    assert_eq!(session.engine.telemetry.total_frames_rendered, 2);

    // 3. Generate Tombstone Report
    let tombstone = session.generate_tombstone(
        TombstoneSignal::SigAbrt,
        Some("Assertion failed in native game engine"),
    );
    assert_eq!(tombstone.signal.name(), "SIGABRT");
    let text = tombstone.format_tombstone();
    assert!(text.contains("*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***"));
    assert!(text.contains("signal 6 (SIGABRT)"));
    assert!(text.contains("Abort message: 'Assertion failed in native game engine'"));
}

#[test]
fn test_jni_telemetry_and_tombstone_exports() {
    reset_session();
    // Initialize session
    drop(get_or_init_session().unwrap());

    unsafe {
        // 1. Query required buffer size for Telemetry HUD
        let hud_len = Java_com_transd_loader_TransdEngine_nativeGetTelemetryHud(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
        );
        assert!(hud_len > 100);

        // Fetch HUD string into buffer
        let mut buf = vec![0u8; hud_len as usize + 16];
        let written = Java_com_transd_loader_TransdEngine_nativeGetTelemetryHud(
            ptr::null_mut(),
            ptr::null_mut(),
            buf.as_mut_ptr(),
            buf.len(),
        );
        assert_eq!(written, hud_len);
        let hud_str = String::from_utf8_lossy(&buf[..written as usize]);
        assert!(hud_str.contains("TRANSD DBT ENGINE TELEMETRY HUD"));

        // 2. Query JSON Telemetry metrics
        let json_len = Java_com_transd_loader_TransdEngine_nativeGetTelemetryJson(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
        );
        assert!(json_len > 50);

        let mut json_buf = vec![0u8; json_len as usize + 16];
        let json_written = Java_com_transd_loader_TransdEngine_nativeGetTelemetryJson(
            ptr::null_mut(),
            ptr::null_mut(),
            json_buf.as_mut_ptr(),
            json_buf.len(),
        );
        assert_eq!(json_written, json_len);
        let json_str = String::from_utf8_lossy(&json_buf[..json_written as usize]);
        assert!(json_str.contains("\"cache_hit_rate\":"));

        // 3. Query Tombstone crash report
        let tomb_len = Java_com_transd_loader_TransdEngine_nativeGenerateTombstone(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
        );
        assert!(tomb_len > 200);

        let mut tomb_buf = vec![0u8; tomb_len as usize + 16];
        let tomb_written = Java_com_transd_loader_TransdEngine_nativeGenerateTombstone(
            ptr::null_mut(),
            ptr::null_mut(),
            tomb_buf.as_mut_ptr(),
            tomb_buf.len(),
        );
        assert_eq!(tomb_written, tomb_len);
        let tomb_str = String::from_utf8_lossy(&tomb_buf[..tomb_written as usize]);
        assert!(tomb_str.contains("*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***"));
        assert!(tomb_str.contains("signal 5 (SIGTRAP)"));
    }
}
