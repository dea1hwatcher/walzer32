use std::ffi::c_void;
use transd_core::GuestAddr;
use crate::session::{get_or_init_session, reset_session};

// Standard JNI 64-bit primitive types matching Android NDK
pub type JNIEnv = *mut c_void;
pub type JClass = *mut c_void;
pub type JString = *mut c_void;
pub type JObject = *mut c_void;
pub type JInt = i32;
pub type JLong = i64;
pub type JFloat = f32;

/// JNI Return codes
pub const JNI_OK: JInt = 0;
pub const JNI_ERR_GENERIC: JInt = -1;
pub const JNI_ERR_NOT_FOUND: JInt = -2;
pub const JNI_ERR_LOAD_FAIL: JInt = -3;

/// Standard JNI lifecycle entrypoint
#[unsafe(no_mangle)]
pub unsafe extern "C" fn JNI_OnLoad(_vm: *mut c_void, _reserved: *mut c_void) -> JInt {
    log_i!("Transd: JNI_OnLoad called by ART");
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            let _ = session.ensure_bundled_apk_loaded();
        }
    }
    0x0001_0006 // JNI_VERSION_1_6
}

/// JNI Export: Initialize Transd DBT Engine from Android Application
///
/// Java Signature:
///   public static native int nativeInit(String apkPath);
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeInit(
    _env: JNIEnv,
    _clazz: JClass,
    _apk_path: JString,
) -> JInt {
    log_i!("Transd: TransdEngine.nativeInit called");
    match get_or_init_session() {
        Ok(mut guard) => {
            if let Some(session) = guard.as_mut() {
                let _ = session.ensure_bundled_apk_loaded();
            }
            JNI_OK
        }
        Err(e) => {
            log_e!("Transd: get_or_init_session failed: {:?}", e);
            JNI_ERR_GENERIC
        }
    }
}

/// JNI Export: Load a 32-bit ELF shared library by raw bytes or name
///
/// Java Signature:
///   public static native int nativeLoadLibraryBytes(String name, byte[] elfBytes);
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeLoadLibraryBytes(
    _env: JNIEnv,
    _clazz: JClass,
    name_str: *const u8,
    name_len: usize,
    bytes_ptr: *const u8,
    bytes_len: usize,
) -> JInt {
    if name_str.is_null() || bytes_ptr.is_null() || bytes_len == 0 {
        return JNI_ERR_GENERIC;
    }

    let name = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(name_str, name_len) }) {
        Ok(s) => s,
        Err(_) => return JNI_ERR_GENERIC,
    };

    let elf_slice = unsafe { std::slice::from_raw_parts(bytes_ptr, bytes_len) };

    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };

    let session = match guard.as_mut() {
        Some(s) => s,
        None => return JNI_ERR_GENERIC,
    };

    match session.load_library_bytes(name, elf_slice) {
        Ok(_) => JNI_OK,
        Err(_) => JNI_ERR_LOAD_FAIL,
    }
}

/// JNI Export: Call a 32-bit native guest function by virtual address
///
/// Java Signature:
///   public static native int nativeCallMethod(long fnAddr, int arg0, int arg1, int arg2, int arg3);
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeCallMethod(
    _env: JNIEnv,
    _clazz: JClass,
    fn_addr: JLong,
    arg0: JInt,
    arg1: JInt,
    arg2: JInt,
    arg3: JInt,
) -> JInt {
    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };

    let session = match guard.as_mut() {
        Some(s) => s,
        None => return JNI_ERR_GENERIC,
    };

    let args = [arg0 as u32, arg1 as u32, arg2 as u32, arg3 as u32];
    match session.call_native(GuestAddr::new(fn_addr as u32), &args) {
        Ok(ret) => ret as JInt,
        Err(_) => JNI_ERR_GENERIC,
    }
}

/// JNI Export: Query loaded library count and registered natives
///
/// Java Signature:
///   public static native int nativeGetStatus();
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeGetStatus(
    _env: JNIEnv,
    _clazz: JClass,
) -> JInt {
    let guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };

    match guard.as_ref() {
        Some(s) => s.loaded_libraries.len() as JInt,
        None => 0,
    }
}

/// JNI Export: Reset and clean up session
///
/// Java Signature:
///   public static native void nativeReset();
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeReset(
    _env: JNIEnv,
    _clazz: JClass,
) {
    reset_session();
}

/// JNI Export: SurfaceView created - establishes native window and assigns 32-bit guest handle
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeSurfaceCreated(
    _env: JNIEnv,
    _clazz: JClass,
    surface: JObject,
    width: JInt,
    height: JInt,
) -> JInt {
    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };
    if let Some(session) = guard.as_mut() {
        session.on_surface_created(surface as usize, width as u32, height as u32);
        JNI_OK
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: SurfaceView changed - updates viewport dimensions
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeSurfaceChanged(
    _env: JNIEnv,
    _clazz: JClass,
    width: JInt,
    height: JInt,
) -> JInt {
    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };
    if let Some(session) = guard.as_mut() {
        session.on_surface_changed(width as u32, height as u32);
        JNI_OK
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: SurfaceView destroyed
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeSurfaceDestroyed(
    _env: JNIEnv,
    _clazz: JClass,
) -> JInt {
    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };
    if let Some(session) = guard.as_mut() {
        session.on_surface_destroyed();
        JNI_OK
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: Triggers frame render in guest DBT
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeDrawFrame(
    _env: JNIEnv,
    _clazz: JClass,
) -> JInt {
    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };
    if let Some(session) = guard.as_mut() {
        match session.on_draw_frame() {
            Ok(()) => JNI_OK,
            Err(_) => JNI_ERR_GENERIC,
        }
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: Forwards touch event to guest touch queue
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeTouchEvent(
    _env: JNIEnv,
    _clazz: JClass,
    action: JInt,
    x: JFloat,
    y: JFloat,
    pointer_id: JInt,
) -> JInt {
    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };
    if let Some(session) = guard.as_mut() {
        session.on_touch_event(action as u32, x, y, pointer_id as u32);
        JNI_OK
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: Forwards key event to guest key queue
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeKeyEvent(
    _env: JNIEnv,
    _clazz: JClass,
    action: JInt,
    key_code: JInt,
) -> JInt {
    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };
    if let Some(session) = guard.as_mut() {
        session.on_key_event(action as u32, key_code as u32);
        JNI_OK
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: Query ASCII Telemetry HUD overlay
/// Returns bytes written into out_buf (or total required buffer length if out_buf is null)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeGetTelemetryHud(
    _env: JNIEnv,
    _clazz: JClass,
    out_buf: *mut u8,
    max_len: usize,
) -> JInt {
    let guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };
    if let Some(session) = guard.as_ref() {
        let text = session.get_telemetry_hud();
        let bytes = text.as_bytes();
        if out_buf.is_null() || max_len == 0 {
            return bytes.len() as JInt;
        }
        let copy_len = bytes.len().min(max_len);
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, copy_len);
        }
        copy_len as JInt
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: Query JSON Telemetry metrics
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeGetTelemetryJson(
    _env: JNIEnv,
    _clazz: JClass,
    out_buf: *mut u8,
    max_len: usize,
) -> JInt {
    let guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };
    if let Some(session) = guard.as_ref() {
        let text = session.get_telemetry_json();
        let bytes = text.as_bytes();
        if out_buf.is_null() || max_len == 0 {
            return bytes.len() as JInt;
        }
        let copy_len = bytes.len().min(max_len);
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, copy_len);
        }
        copy_len as JInt
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: Captures Android Tombstone crash report
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeGenerateTombstone(
    _env: JNIEnv,
    _clazz: JClass,
    out_buf: *mut u8,
    max_len: usize,
) -> JInt {
    let guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };
    if let Some(session) = guard.as_ref() {
        let tombstone = session.generate_tombstone(
            transd_rt::tombstone::TombstoneSignal::Trap {
                message: "Native tombstone requested via JNI".into(),
            },
            Some("JNI Diagnostic Dump"),
        );
        let text = tombstone.format_tombstone();
        let bytes = text.as_bytes();
        if out_buf.is_null() || max_len == 0 {
            return bytes.len() as JInt;
        }
        let copy_len = bytes.len().min(max_len);
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, copy_len);
        }
        copy_len as JInt
    } else {
        JNI_ERR_GENERIC
    }
}


/// JNI Export: Render Host Audio PCM Frames from Lock-Free Ring Buffer
/// Fills `out_buf` with 48 kHz stereo 16-bit PCM samples [L0, R0, L1, R1, ...]
/// Returns the number of frames rendered (frames = samples / 2)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeRenderAudioPcm(
    _env: JNIEnv,
    _clazz: JClass,
    out_buf: *mut i16,
    max_samples: usize,
) -> JInt {
    if out_buf.is_null() || max_samples == 0 {
        return 0;
    }

    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };

    if let Some(session) = guard.as_mut() {
        let slice = unsafe { std::slice::from_raw_parts_mut(out_buf, max_samples) };
        session.read_audio_frames(slice) as JInt
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: Set Audio Volume Level in millibels (-9600 = mute, 0 = max)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeSetAudioVolume(
    _env: JNIEnv,
    _clazz: JClass,
    millibels: JInt,
) -> JInt {
    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };

    if let Some(session) = guard.as_mut() {
        session.set_audio_volume(millibels);
        JNI_OK
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: Get Audio Buffer Underrun Count
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeGetAudioUnderruns(
    _env: JNIEnv,
    _clazz: JClass,
) -> JLong {
    let guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return 0,
    };

    if let Some(session) = guard.as_ref() {
        session.get_audio_underruns() as JLong
    } else {
        0
    }
}

/// JNI Export: Get Audio Buffer Overrun Count
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeGetAudioOverruns(
    _env: JNIEnv,
    _clazz: JClass,
) -> JLong {
    let guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return 0,
    };

    if let Some(session) = guard.as_ref() {
        session.get_audio_overruns() as JLong
    } else {
        0
    }
}

/// JNI Export: Get Current Audio Latency in milliseconds
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeGetAudioLatencyMs(
    _env: JNIEnv,
    _clazz: JClass,
) -> f32 {
    let guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return 0.0,
    };

    if let Some(session) = guard.as_ref() {
        session.get_audio_latency_ms()
    } else {
        0.0
    }
}

/// JNI Export: Set Target Audio Latency in milliseconds
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeSetTargetAudioLatencyMs(
    _env: JNIEnv,
    _clazz: JClass,
    latency_ms: f32,
) -> JInt {
    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };

    if let Some(session) = guard.as_mut() {
        session.set_target_audio_latency_ms(latency_ms);
        JNI_OK
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: Get Audio Ring Buffer Watermark Ratio (0.0 .. 1.0)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeGetAudioWatermarkRatio(
    _env: JNIEnv,
    _clazz: JClass,
) -> f32 {
    let guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return 0.0,
    };

    if let Some(session) = guard.as_ref() {
        session.get_audio_watermark_ratio()
    } else {
        0.0
    }
}


/// JNI Export: Set AOT Cache Directory
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeSetAotCacheDir(
    _env: JNIEnv,
    _clazz: JClass,
    path_ptr: *const u8,
    path_len: usize,
) -> JInt {
    if path_ptr.is_null() || path_len == 0 {
        return JNI_ERR_GENERIC;
    }
    let path_str = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(path_ptr, path_len) }) {
        Ok(s) => s,
        Err(_) => return JNI_ERR_GENERIC,
    };
    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };
    if let Some(session) = guard.as_mut() {
        session.set_aot_cache_dir(path_str);
        JNI_OK
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: Precompile Library Ahead-Of-Time
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativePrecompileLibrary(
    _env: JNIEnv,
    _clazz: JClass,
    name_ptr: *const u8,
    name_len: usize,
    max_blocks: JInt,
) -> JInt {
    if name_ptr.is_null() || name_len == 0 {
        return JNI_ERR_GENERIC;
    }
    let name_str = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(name_ptr, name_len) }) {
        Ok(s) => s,
        Err(_) => return JNI_ERR_GENERIC,
    };
    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };
    if let Some(session) = guard.as_mut() {
        session.precompile_library(name_str, (max_blocks.max(1)) as usize) as JInt
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: Enable multi-core background asynchronous JIT compilation
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeEnableAsyncJit(
    _env: JNIEnv,
    _clazz: JClass,
    worker_threads: JInt,
) -> JInt {
    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };
    if let Some(session) = guard.as_mut() {
        session.enable_async_jit(worker_threads.max(0) as usize);
        JNI_OK
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: Disable background asynchronous JIT compilation
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeDisableAsyncJit(
    _env: JNIEnv,
    _clazz: JClass,
) -> JInt {
    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };
    if let Some(session) = guard.as_mut() {
        session.disable_async_jit();
        JNI_OK
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: Flush all pending background JIT compilations
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeFlushAsyncJit(
    _env: JNIEnv,
    _clazz: JClass,
    timeout_ms: JInt,
) -> JInt {
    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };
    if let Some(session) = guard.as_mut() {
        let promoted = session.flush_async_jit(std::time::Duration::from_millis(timeout_ms.max(1) as u64));
        promoted as JInt
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: Mount an OBB expansion pack into the guest VFS
///
/// Java Signature:
///   public static native int nativeMountObb(String packageName, int version, byte[] obbBytes);
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeMountObb(
    _env: JNIEnv,
    _clazz: JClass,
    pkg_str: *const u8,
    pkg_len: usize,
    version: JInt,
    obb_ptr: *const u8,
    obb_len: usize,
) -> JInt {
    if pkg_str.is_null() || obb_ptr.is_null() || obb_len == 0 {
        return JNI_ERR_GENERIC;
    }

    let pkg = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(pkg_str, pkg_len) }) {
        Ok(s) => s,
        Err(_) => return JNI_ERR_GENERIC,
    };

    let obb_slice = unsafe { std::slice::from_raw_parts(obb_ptr, obb_len) };

    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };

    if let Some(session) = guard.as_mut() {
        session.mount_obb(pkg, version as u32, obb_slice.to_vec());
        JNI_OK
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: Mount a patch OBB expansion pack into the guest VFS
///
/// Java Signature:
///   public static native int nativeMountPatchObb(String packageName, int version, byte[] obbBytes);
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeMountPatchObb(
    _env: JNIEnv,
    _clazz: JClass,
    pkg_str: *const u8,
    pkg_len: usize,
    version: JInt,
    obb_ptr: *const u8,
    obb_len: usize,
) -> JInt {
    if pkg_str.is_null() || obb_ptr.is_null() || obb_len == 0 {
        return JNI_ERR_GENERIC;
    }

    let pkg = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(pkg_str, pkg_len) }) {
        Ok(s) => s,
        Err(_) => return JNI_ERR_GENERIC,
    };

    let obb_slice = unsafe { std::slice::from_raw_parts(obb_ptr, obb_len) };

    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };

    if let Some(session) = guard.as_mut() {
        session.mount_patch_obb(pkg, version as u32, obb_slice.to_vec());
        JNI_OK
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: Mount an application's private data directory
///
/// Java Signature:
///   public static native int nativeMountAppDataDir(String packageName);
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeMountAppDataDir(
    _env: JNIEnv,
    _clazz: JClass,
    pkg_str: *const u8,
    pkg_len: usize,
) -> JInt {
    if pkg_str.is_null() {
        return JNI_ERR_GENERIC;
    }

    let pkg = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(pkg_str, pkg_len) }) {
        Ok(s) => s,
        Err(_) => return JNI_ERR_GENERIC,
    };

    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };

    if let Some(session) = guard.as_mut() {
        session.mount_app_data_dir(pkg);
        JNI_OK
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: Set or override an Android system property
///
/// Java Signature:
///   public static native int nativeSetSystemProperty(String name, String value);
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_transd_loader_TransdEngine_nativeSetSystemProperty(
    _env: JNIEnv,
    _clazz: JClass,
    name_str: *const u8,
    name_len: usize,
    val_str: *const u8,
    val_len: usize,
) -> JInt {
    if name_str.is_null() || val_str.is_null() {
        return JNI_ERR_GENERIC;
    }

    let name = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(name_str, name_len) }) {
        Ok(s) => s,
        Err(_) => return JNI_ERR_GENERIC,
    };

    let val = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(val_str, val_len) }) {
        Ok(s) => s,
        Err(_) => return JNI_ERR_GENERIC,
    };

    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(_) => return JNI_ERR_GENERIC,
    };

    if let Some(session) = guard.as_mut() {
        session.set_system_property(name, val);
        JNI_OK
    } else {
        JNI_ERR_GENERIC
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Game-Specific JNI Bindings (Zombie Road Trip / Cocos2d-x / Apportable)
// ─────────────────────────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_noodlecake_noodlenews_NoodlecakeGameActivity_getPlatform(
    _env: JNIEnv,
    _clazz: JClass,
) -> JInt {
    0 // Android platform
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_noodlecake_noodlenews_NoodlecakeGameActivity_getVersion(
    _env: JNIEnv,
    _clazz: JClass,
) -> JInt {
    30 // Version 30
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_noodlecake_iapv3_PurchaseWrapperV3_handleMessage(
    _env: JNIEnv,
    _clazz: JClass,
    _msg: JString,
    _code: JInt,
) {
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_noodlecake_lib_font_NoodleBitmap_nativeInitBitmapDC(
    _env: JNIEnv,
    _clazz: JClass,
    _width: JInt,
    _height: JInt,
    _pixels: JObject,
) {
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_noodlecake_lib_uikit_UIAccelerometer_onSensorChanged(
    _env: JNIEnv,
    _clazz: JClass,
    x: JFloat,
    y: JFloat,
    z: JFloat,
    timestamp: JLong,
) {
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            let env_ptr = session.jni.env_ptr.as_u32();
            if let Some(info) = session.jni_registry.find_by_symbol("Java_com_noodlecake_lib_uikit_UIAccelerometer_onSensorChanged") {
                let fn_ptr = info.fn_ptr;
                let _ = session.call_native(fn_ptr, &[env_ptr, 1, x.to_bits(), y.to_bits(), z.to_bits(), timestamp as u32, (timestamp >> 32) as u32]);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_noodlecake_lib_uikit_UIAlertView_returnAlertView(
    _env: JNIEnv,
    _clazz: JClass,
    alert_id: JInt,
    button_idx: JInt,
    _text: JString,
) {
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            let env_ptr = session.jni.env_ptr.as_u32();
            if let Some(info) = session.jni_registry.find_by_symbol("Java_com_noodlecake_lib_uikit_UIAlertView_returnAlertView") {
                let fn_ptr = info.fn_ptr;
                let _ = session.call_native(fn_ptr, &[env_ptr, 1, alert_id as u32, button_idx as u32, 0]);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_noodlecake_lib_uikit_UIApplication_appDidBecomeActive(
    _env: JNIEnv,
    _clazz: JClass,
) {
    log_i!("Transd: appDidBecomeActive called");
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            let env_ptr = session.jni.env_ptr.as_u32();
            if let Some(info) = session.jni_registry.find_by_symbol("Java_com_noodlecake_lib_uikit_UIApplication_appDidBecomeActive") {
                let fn_ptr = info.fn_ptr;
                let _ = session.call_native(fn_ptr, &[env_ptr, 1]);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_noodlecake_lib_uikit_UIApplication_appDidEnterBackground(
    _env: JNIEnv,
    _clazz: JClass,
) {
    log_i!("Transd: appDidEnterBackground called");
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            let env_ptr = session.jni.env_ptr.as_u32();
            if let Some(info) = session.jni_registry.find_by_symbol("Java_com_noodlecake_lib_uikit_UIApplication_appDidEnterBackground") {
                let fn_ptr = info.fn_ptr;
                let _ = session.call_native(fn_ptr, &[env_ptr, 1]);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_noodlecake_lib_uikit_UIApplication_appDidReceiveMemoryWarning(
    _env: JNIEnv,
    _clazz: JClass,
) {
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            let env_ptr = session.jni.env_ptr.as_u32();
            if let Some(info) = session.jni_registry.find_by_symbol("Java_com_noodlecake_lib_uikit_UIApplication_appDidReceiveMemoryWarning") {
                let fn_ptr = info.fn_ptr;
                let _ = session.call_native(fn_ptr, &[env_ptr, 1]);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_noodlecake_lib_uikit_UIApplication_appWillEnterForeground(
    _env: JNIEnv,
    _clazz: JClass,
) {
    log_i!("Transd: appWillEnterForeground called");
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            let env_ptr = session.jni.env_ptr.as_u32();
            if let Some(info) = session.jni_registry.find_by_symbol("Java_com_noodlecake_lib_uikit_UIApplication_appWillEnterForeground") {
                let fn_ptr = info.fn_ptr;
                let _ = session.call_native(fn_ptr, &[env_ptr, 1]);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_noodlecake_lib_uikit_UIApplication_appWillResignActive(
    _env: JNIEnv,
    _clazz: JClass,
) {
    log_i!("Transd: appWillResignActive called");
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            let env_ptr = session.jni.env_ptr.as_u32();
            if let Some(info) = session.jni_registry.find_by_symbol("Java_com_noodlecake_lib_uikit_UIApplication_appWillResignActive") {
                let fn_ptr = info.fn_ptr;
                let _ = session.call_native(fn_ptr, &[env_ptr, 1]);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_noodlecake_lib_uikit_UIApplication_appWillTerminate(
    _env: JNIEnv,
    _clazz: JClass,
) {
    log_i!("Transd: appWillTerminate called");
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            let env_ptr = session.jni.env_ptr.as_u32();
            if let Some(info) = session.jni_registry.find_by_symbol("Java_com_noodlecake_lib_uikit_UIApplication_appWillTerminate") {
                let fn_ptr = info.fn_ptr;
                let _ = session.call_native(fn_ptr, &[env_ptr, 1]);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_org_cocos2dx_lib_Cocos2dxBitmap_nativeInitBitmapDC(
    _env: JNIEnv,
    _clazz: JClass,
    _width: JInt,
    _height: JInt,
    _pixels: JObject,
) {
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeDeleteBackward(
    _env: JNIEnv,
    _clazz: JClass,
) {
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            let env_ptr = session.jni.env_ptr.as_u32();
            if let Some(info) = session.jni_registry.find_by_symbol("Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeDeleteBackward") {
                let fn_ptr = info.fn_ptr;
                let _ = session.call_native(fn_ptr, &[env_ptr, 1]);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeGetContentText(
    _env: JNIEnv,
    _clazz: JClass,
) -> JString {
    std::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeInit(
    _env: JNIEnv,
    _clazz: JClass,
    width: JInt,
    height: JInt,
) {
    log_i!("Transd: Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeInit({}, {}) called", width, height);
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            session.on_surface_created(0, width as u32, height as u32);
            let env_ptr = session.jni.env_ptr.as_u32();
            if let Some(info) = session.jni_registry.find_by_symbol("Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeInit") {
                let fn_ptr = info.fn_ptr;
                log_i!("Transd: Invoking guest nativeInit at 0x{:08x}...", fn_ptr.as_u32());
                match session.call_native(fn_ptr, &[env_ptr, 1, width as u32, height as u32]) {
                    Ok(res) => log_i!("Transd: guest nativeInit finished with 0x{:08x}", res),
                    Err(e) => log_e!("Transd: guest nativeInit error: {:?}", e),
                }
            } else {
                log_i!("Transd: Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeInit not found in guest libs");
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeInsertText(
    _env: JNIEnv,
    _clazz: JClass,
    _text: JString,
) {
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeKeyDown(
    _env: JNIEnv,
    _clazz: JClass,
    key_code: JInt,
) -> JInt {
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            let env_ptr = session.jni.env_ptr.as_u32();
            if let Some(info) = session.jni_registry.find_by_symbol("Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeKeyDown") {
                let fn_ptr = info.fn_ptr;
                match session.call_native(fn_ptr, &[env_ptr, 1, key_code as u32]) {
                    Ok(r) => return r as JInt,
                    Err(_) => return 0,
                }
            }
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeRender(
    _env: JNIEnv,
    _clazz: JClass,
) {
    static FRAME_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let f = FRAME_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if f == 0 || f.is_multiple_of(300) {
        log_i!("Transd: nativeRender frame {}", f);
    }
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            let _ = session.on_draw_frame();
            let env_ptr = session.jni.env_ptr.as_u32();
            if let Some(info) = session.jni_registry.find_by_symbol("Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeRender") {
                let fn_ptr = info.fn_ptr;
                match session.call_native(fn_ptr, &[env_ptr, 1]) {
                    Ok(_) => {}
                    Err(e) => {
                        if f.is_multiple_of(300) {
                            log_e!("Transd: guest nativeRender error: {:?}", e);
                        }
                    }
                }
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeSurfaceChanged(
    _env: JNIEnv,
    _clazz: JClass,
    width: JInt,
    height: JInt,
) {
    log_i!("Transd: Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeSurfaceChanged({}, {}) called", width, height);
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            session.on_surface_changed(width as u32, height as u32);
            let env_ptr = session.jni.env_ptr.as_u32();
            if let Some(info) = session.jni_registry.find_by_symbol("Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeSurfaceChanged") {
                let fn_ptr = info.fn_ptr;
                let _ = session.call_native(fn_ptr, &[env_ptr, 1, width as u32, height as u32]);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeTouchesBegin(
    _env: JNIEnv,
    _clazz: JClass,
    id: JInt,
    x: JFloat,
    y: JFloat,
    timestamp: JLong,
) {
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            session.on_touch_event(0, x, y, id as u32);
            let env_ptr = session.jni.env_ptr.as_u32();
            if let Some(info) = session.jni_registry.find_by_symbol("Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeTouchesBegin") {
                let fn_ptr = info.fn_ptr;
                let _ = session.call_native(fn_ptr, &[env_ptr, 1, id as u32, x.to_bits(), y.to_bits(), timestamp as u32, (timestamp >> 32) as u32]);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeTouchesEnd(
    _env: JNIEnv,
    _clazz: JClass,
    id: JInt,
    x: JFloat,
    y: JFloat,
    timestamp: JLong,
) {
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            session.on_touch_event(1, x, y, id as u32);
            let env_ptr = session.jni.env_ptr.as_u32();
            if let Some(info) = session.jni_registry.find_by_symbol("Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeTouchesEnd") {
                let fn_ptr = info.fn_ptr;
                let _ = session.call_native(fn_ptr, &[env_ptr, 1, id as u32, x.to_bits(), y.to_bits(), timestamp as u32, (timestamp >> 32) as u32]);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeTouchesMove(
    _env: JNIEnv,
    _clazz: JClass,
    _ids: JObject,
    _xs: JObject,
    _ys: JObject,
    _timestamp: JLong,
) {
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeTouchesCancel(
    _env: JNIEnv,
    _clazz: JClass,
    _ids: JObject,
    _xs: JObject,
    _ys: JObject,
    _timestamp: JLong,
) {
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_noodlecake_ads_InterstitialController_IncentivizedAdComplete(
    _env: JNIEnv,
    _clazz: JClass,
) {
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_noodlecake_ads_PlayHaven_nativeUnlockReward(
    _env: JNIEnv,
    _clazz: JClass,
    _reward: JString,
) {
}


/// Android NDK NativeActivity Entry Point:
/// Invoked by Android OS NativeActivity framework when creating a pure native C/C++ or Unity/Unreal activity.
/// Safely handles out-of-order startup (when ANativeActivity_onCreate is invoked before JNI_OnLoad).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ANativeActivity_onCreate(
    _activity: *mut c_void,
    _saved_state: *mut c_void,
    _saved_state_size: usize,
) {
    drop(get_or_init_session());
}
