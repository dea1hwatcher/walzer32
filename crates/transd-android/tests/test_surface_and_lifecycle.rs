use std::ffi::c_void;
use std::sync::Mutex;
use transd_android::{
    get_or_init_session, reset_session,
    Java_com_transd_loader_TransdEngine_nativeDrawFrame,
    Java_com_transd_loader_TransdEngine_nativeKeyEvent,
    Java_com_transd_loader_TransdEngine_nativeSurfaceChanged,
    Java_com_transd_loader_TransdEngine_nativeSurfaceCreated,
    Java_com_transd_loader_TransdEngine_nativeSurfaceDestroyed,
    Java_com_transd_loader_TransdEngine_nativeTouchEvent, JNI_OK,
};
use transd_bridge::{TouchEvent, GUEST_SURFACE_HANDLE};
use transd_core::{GuestAddr, Memory};

static TEST_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_surface_lifecycle_and_window_mapping() {
    let _lock = TEST_MUTEX.lock().unwrap();
    reset_session();

    let env = std::ptr::null_mut();
    let clazz = std::ptr::null_mut();
    let mock_surface_ptr = 0xAAAA_BBBB_CCCC_DDDD_usize as *mut c_void;

    unsafe {
        // 1. Surface Created
        let res = Java_com_transd_loader_TransdEngine_nativeSurfaceCreated(
            env,
            clazz,
            mock_surface_ptr,
            1920,
            1080,
        );
        assert_eq!(res, JNI_OK);

        {
            let guard = get_or_init_session().unwrap();
            let session = guard.as_ref().unwrap();
            assert!(session.surface.is_active);
            assert_eq!(session.surface.host_window_ptr, mock_surface_ptr as usize);
            assert_eq!(session.surface.guest_handle, GUEST_SURFACE_HANDLE);
            assert_eq!(session.surface.width, 1920);
            assert_eq!(session.surface.height, 1080);
        }

        // 2. Surface Changed (resize / rotation)
        let res_change = Java_com_transd_loader_TransdEngine_nativeSurfaceChanged(
            env,
            clazz,
            2560,
            1440,
        );
        assert_eq!(res_change, JNI_OK);

        {
            let guard = get_or_init_session().unwrap();
            let session = guard.as_ref().unwrap();
            assert_eq!(session.surface.width, 2560);
            assert_eq!(session.surface.height, 1440);
        }

        // 3. Surface Destroyed
        let res_destroy = Java_com_transd_loader_TransdEngine_nativeSurfaceDestroyed(env, clazz);
        assert_eq!(res_destroy, JNI_OK);

        {
            let guard = get_or_init_session().unwrap();
            let session = guard.as_ref().unwrap();
            assert!(!session.surface.is_active);
            assert_eq!(session.surface.host_window_ptr, 0);
        }
    }
}

#[test]
fn test_touch_and_key_event_forwarding() {
    let _lock = TEST_MUTEX.lock().unwrap();
    reset_session();

    let env = std::ptr::null_mut();
    let clazz = std::ptr::null_mut();

    unsafe {
        // Forward touch down: (120.5, 340.25)
        let res1 = Java_com_transd_loader_TransdEngine_nativeTouchEvent(
            env,
            clazz,
            0, // ACTION_DOWN
            120.5,
            340.25,
            1, // pointerId
        );
        assert_eq!(res1, JNI_OK);

        // Forward touch up: (150.0, 340.25)
        let res2 = Java_com_transd_loader_TransdEngine_nativeTouchEvent(
            env,
            clazz,
            1, // ACTION_UP
            150.0,
            340.25,
            1,
        );
        assert_eq!(res2, JNI_OK);

        // Forward key down: Back key (4)
        let res3 = Java_com_transd_loader_TransdEngine_nativeKeyEvent(
            env,
            clazz,
            0, // ACTION_DOWN
            4, // KEYCODE_BACK
        );
        assert_eq!(res3, JNI_OK);

        // Verify queues inside session
        let mut guard = get_or_init_session().unwrap();
        let session = guard.as_mut().unwrap();

        let ev1 = session.surface.pop_touch_event().unwrap();
        assert_eq!(
            ev1,
            TouchEvent {
                action: 0,
                x: 120.5,
                y: 340.25,
                pointer_id: 1,
            }
        );

        let ev2 = session.surface.pop_touch_event().unwrap();
        assert_eq!(
            ev2,
            TouchEvent {
                action: 1,
                x: 150.0,
                y: 340.25,
                pointer_id: 1,
            }
        );
        assert!(session.surface.pop_touch_event().is_none());

        let key_ev = session.surface.pop_key_event().unwrap();
        assert_eq!(key_ev.action, 0);
        assert_eq!(key_ev.key_code, 4);
        assert!(session.surface.pop_key_event().is_none());
    }
}

#[test]
fn test_draw_frame_invokes_guest() {
    let _lock = TEST_MUTEX.lock().unwrap();
    reset_session();

    let render_pc = GuestAddr::new(0x7000_1000);
    let counter_addr = GuestAddr::new(0x7000_2000);

    // Write simple guest render function at 0x7000_1000:
    // loads counter at 0x7000_2000, increments by 1, stores back, returns via BX LR
    // 0x7000_1000: LDR r0, =0x7000_2000 (0xE3A0_0470 -> r0 = 0x70000000; 0xE280_0C20 -> r0 = 0x70002000)
    // 0x7000_1008: LDR r1, [r0]
    // 0x7000_100C: ADD r1, r1, #1
    // 0x7000_1010: STR r1, [r0]
    // 0x7000_1014: BX lr (0xE12F_FF1E)
    {
        let mut guard = get_or_init_session().unwrap();
        let session = guard.as_mut().unwrap();

        session.engine.mem.write_u32(counter_addr, 0).unwrap();
        session.engine.mem.write_u32(render_pc, 0xE3A0_0470).unwrap(); // r0 = 0x7000_0000
        session.engine.mem.write_u32(render_pc.add(4), 0xE280_0C20).unwrap(); // r0 = 0x7000_2000
        session.engine.mem.write_u32(render_pc.add(8), 0xE590_1000).unwrap(); // LDR r1, [r0]
        session.engine.mem.write_u32(render_pc.add(12), 0xE281_1001).unwrap(); // ADD r1, r1, #1
        session.engine.mem.write_u32(render_pc.add(16), 0xE580_1000).unwrap(); // STR r1, [r0]
        session.engine.mem.write_u32(render_pc.add(20), 0xE12F_FF1E).unwrap(); // BX lr

        session.surface.register_draw_frame_fn(render_pc);
    }

    let env = std::ptr::null_mut();
    let clazz = std::ptr::null_mut();

    unsafe {
        // Trigger frame 1
        let res1 = Java_com_transd_loader_TransdEngine_nativeDrawFrame(env, clazz);
        assert_eq!(res1, JNI_OK);

        // Trigger frame 2
        let res2 = Java_com_transd_loader_TransdEngine_nativeDrawFrame(env, clazz);
        assert_eq!(res2, JNI_OK);

        // Verify counter incremented to 2
        let guard = get_or_init_session().unwrap();
        let session = guard.as_ref().unwrap();
        let count = session.engine.mem.read_u32(counter_addr).unwrap();
        assert_eq!(count, 2);
    }
}
