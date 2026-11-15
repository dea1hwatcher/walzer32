use std::ffi::c_void;
use walzer32_bridge::{KeyEvent, TouchEvent};
use walzer32_core::{GuestAddr, Memory};
use crate::session::{
    fast_channels, get_or_init_session, reset_session, try_get_or_init_session,
};

unsafe fn write_utf8_out(text: &str, out_buf: *mut u8, max_len: usize) -> JInt {
    let bytes = text.as_bytes();
    if out_buf.is_null() || max_len == 0 {
        return bytes.len() as JInt;
    }
    let copy_len = bytes.len().min(max_len);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, copy_len);
    }
    copy_len as JInt
}

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
pub unsafe extern "C" fn JNI_OnLoad(vm: *mut c_void, _reserved: *mut c_void) -> JInt {
    log_i!("Walzer32: JNI_OnLoad called by ART");
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            session.host_java_vm = vm as usize;
            #[cfg(target_os = "android")]
            if !vm.is_null() {
                let vm_table = unsafe { *(vm as *const *const usize) };
                if !vm_table.is_null() {
                    let get_env: unsafe extern "C" fn(
                        *mut c_void,
                        *mut *mut c_void,
                        JInt,
                    ) -> JInt = unsafe { std::mem::transmute(*vm_table.add(6)) };
                    let mut env_out: *mut c_void = std::ptr::null_mut();
                    if unsafe { get_env(vm, &mut env_out, 0x0001_0006) } == 0
                        && !env_out.is_null()
                    {
                        session.host_jni_env = env_out as usize;
                    }
                }
            }
            let _ = session.ensure_bundled_apk_loaded();
            let _ = session.flush_pending_jni_registrations();
        }
    }
    0x0001_0006 // JNI_VERSION_1_6
}

/// Entrypoint invoked by synthesized ARM64 proxy `.so` `JNI_OnLoad` stubs (`DT_NEEDED: libwalzer32.so`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn walzer32_proxy_jni_onload(vm: *mut c_void, reserved: *mut c_void) -> JInt {
    unsafe { JNI_OnLoad(vm, reserved) }
}

/// Automatic ELF .init_array constructor called by Bionic when libwalzer32.so is loaded as DT_NEEDED
#[cfg(target_os = "android")]
#[used]
#[unsafe(link_section = ".init_array")]
static WALZER32_INIT_ARRAY: unsafe extern "C" fn() = {
    unsafe extern "C" fn init() {
        log_i!("Walzer32: .init_array constructor invoked by Bionic Linker");
        if let Ok(mut guard) = get_or_init_session() {
            if let Some(session) = guard.as_mut() {
                let _ = session.ensure_bundled_apk_loaded();
            }
        }
    }
    init
};

/// JNI Export: Initialize Walzer32 DBT Engine from Android Application
///
/// Java Signature:
///   public static native int nativeInit(String apkPath);
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeInit(
    env: JNIEnv,
    _clazz: JClass,
    _apk_path: JString,
) -> JInt {
    log_i!("Walzer32: Walzer32Engine.nativeInit called");
    match get_or_init_session() {
        Ok(mut guard) => {
            if let Some(session) = guard.as_mut() {
                session.host_jni_env = env as usize;
                let _ = session.ensure_bundled_apk_loaded();
                let _ = session.flush_pending_jni_registrations();
            }
            JNI_OK
        }
        Err(e) => {
            log_e!("Walzer32: get_or_init_session failed: {:?}", e);
            JNI_ERR_GENERIC
        }
    }
}

/// JNI Export: Load a 32-bit ELF shared library by raw bytes or name
///
/// Java Signature:
///   public static native int nativeLoadLibraryBytes(String name, byte[] elfBytes);
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeLoadLibraryBytes(
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
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeCallMethod(
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
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeGetStatus(
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
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeReset(
    _env: JNIEnv,
    _clazz: JClass,
) {
    reset_session();
}

/// JNI Export: SurfaceView created - establishes native window and assigns 32-bit guest handle
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeSurfaceCreated(
    env: JNIEnv,
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
        #[cfg(target_os = "android")]
        let (window_ptr, owns_window) = if !env.is_null() && !surface.is_null() {
            if let Some(fp) = session.gles.resolve_host_symbol("ANativeWindow_fromSurface") {
                let from_surface: unsafe extern "C" fn(JNIEnv, JObject) -> *mut c_void =
                    unsafe { std::mem::transmute(fp) };
                let win = unsafe { from_surface(env, surface) };
                if !win.is_null() {
                    (win as usize, true)
                } else {
                    (surface as usize, false)
                }
            } else {
                (surface as usize, false)
            }
        } else {
            (surface as usize, false)
        };
        #[cfg(not(target_os = "android"))]
        let (window_ptr, owns_window) = {
            let _ = env;
            (surface as usize, false)
        };

        #[allow(unused_mut)]
        let mut final_w = width as u32;
        #[allow(unused_mut)]
        let mut final_h = height as u32;
        #[cfg(target_os = "android")]
        if owns_window && window_ptr != 0 && (final_w == 0 || final_h == 0) {
            if let Some(fp) = session.gles.resolve_host_symbol("ANativeWindow_getWidth") {
                let get_w: unsafe extern "C" fn(*mut c_void) -> i32 =
                    unsafe { std::mem::transmute(fp) };
                let w = unsafe { get_w(window_ptr as *mut c_void) };
                if w > 0 {
                    final_w = w as u32;
                }
            }
            if let Some(fp) = session.gles.resolve_host_symbol("ANativeWindow_getHeight") {
                let get_h: unsafe extern "C" fn(*mut c_void) -> i32 =
                    unsafe { std::mem::transmute(fp) };
                let h = unsafe { get_h(window_ptr as *mut c_void) };
                if h > 0 {
                    final_h = h as u32;
                }
            }
        }

        session.on_surface_created(window_ptr, final_w, final_h);
        session.owns_host_window = owns_window;
        JNI_OK
    } else {
        JNI_ERR_GENERIC
    }
}

/// JNI Export: SurfaceView changed - updates viewport dimensions
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeSurfaceChanged(
    _env: JNIEnv,
    _clazz: JClass,
    width: JInt,
    height: JInt,
) -> JInt {
    match try_get_or_init_session() {
        Some(Ok(mut guard)) => {
            if let Some(session) = guard.as_mut() {
                session.on_surface_changed(width as u32, height as u32);
                JNI_OK
            } else {
                JNI_ERR_GENERIC
            }
        }
        Some(Err(_)) => JNI_ERR_GENERIC,
        None => {
            fast_channels().set_pending_resize(width as u32, height as u32);
            JNI_OK
        }
    }
}

/// JNI Export: SurfaceView destroyed
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeSurfaceDestroyed(
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
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeDrawFrame(
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
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeTouchEvent(
    _env: JNIEnv,
    _clazz: JClass,
    action: JInt,
    x: JFloat,
    y: JFloat,
    pointer_id: JInt,
) -> JInt {
    match try_get_or_init_session() {
        Some(Ok(mut guard)) => {
            if let Some(session) = guard.as_mut() {
                session.on_touch_event(action as u32, x, y, pointer_id as u32);
                JNI_OK
            } else {
                JNI_ERR_GENERIC
            }
        }
        Some(Err(_)) => JNI_ERR_GENERIC,
        None => {
            fast_channels().push_touch(TouchEvent {
                action: action as u32,
                x,
                y,
                pointer_id: pointer_id as u32,
            });
            JNI_OK
        }
    }
}

/// JNI Export: Forwards key event to guest key queue
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeKeyEvent(
    _env: JNIEnv,
    _clazz: JClass,
    action: JInt,
    key_code: JInt,
) -> JInt {
    match try_get_or_init_session() {
        Some(Ok(mut guard)) => {
            if let Some(session) = guard.as_mut() {
                session.on_key_event(action as u32, key_code as u32);
                JNI_OK
            } else {
                JNI_ERR_GENERIC
            }
        }
        Some(Err(_)) => JNI_ERR_GENERIC,
        None => {
            fast_channels().push_key(KeyEvent {
                action: action as u32,
                key_code: key_code as u32,
            });
            JNI_OK
        }
    }
}

/// JNI Export: Query ASCII Telemetry HUD overlay
/// Returns bytes written into out_buf (or total required buffer length if out_buf is null)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeGetTelemetryHud(
    _env: JNIEnv,
    _clazz: JClass,
    out_buf: *mut u8,
    max_len: usize,
) -> JInt {
    let text = match try_get_or_init_session() {
        Some(Ok(guard)) => match guard.as_ref() {
            Some(session) => session.get_telemetry_hud(),
            None => return JNI_ERR_GENERIC,
        },
        Some(Err(_)) => return JNI_ERR_GENERIC,
        None => fast_channels().telemetry_hud_snapshot(),
    };
    unsafe { write_utf8_out(&text, out_buf, max_len) }
}

/// JNI Export: Query JSON Telemetry metrics
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeGetTelemetryJson(
    _env: JNIEnv,
    _clazz: JClass,
    out_buf: *mut u8,
    max_len: usize,
) -> JInt {
    let text = match try_get_or_init_session() {
        Some(Ok(guard)) => match guard.as_ref() {
            Some(session) => session.get_telemetry_json(),
            None => return JNI_ERR_GENERIC,
        },
        Some(Err(_)) => return JNI_ERR_GENERIC,
        None => fast_channels().telemetry_json_snapshot(),
    };
    unsafe { write_utf8_out(&text, out_buf, max_len) }
}

/// JNI Export: Captures Android Tombstone crash report
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeGenerateTombstone(
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
            walzer32_rt::tombstone::TombstoneSignal::Trap {
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
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeRenderAudioPcm(
    _env: JNIEnv,
    _clazz: JClass,
    out_buf: *mut i16,
    max_samples: usize,
) -> JInt {
    if out_buf.is_null() || max_samples == 0 {
        return 0;
    }

    let slice = unsafe { std::slice::from_raw_parts_mut(out_buf, max_samples) };
    match try_get_or_init_session() {
        Some(Ok(mut guard)) => {
            if let Some(session) = guard.as_mut() {
                session.read_audio_frames(slice) as JInt
            } else {
                JNI_ERR_GENERIC
            }
        }
        Some(Err(_)) => JNI_ERR_GENERIC,
        None => fast_channels().read_audio_frames(slice) as JInt,
    }
}

/// JNI Export: Set Audio Volume Level in millibels (-9600 = mute, 0 = max)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeSetAudioVolume(
    _env: JNIEnv,
    _clazz: JClass,
    millibels: JInt,
) -> JInt {
    match try_get_or_init_session() {
        Some(Ok(mut guard)) => {
            if let Some(session) = guard.as_mut() {
                session.set_audio_volume(millibels);
                JNI_OK
            } else {
                JNI_ERR_GENERIC
            }
        }
        Some(Err(_)) => JNI_ERR_GENERIC,
        None => {
            fast_channels().set_volume_millibels(millibels);
            JNI_OK
        }
    }
}

/// JNI Export: Get Audio Buffer Underrun Count
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeGetAudioUnderruns(
    _env: JNIEnv,
    _clazz: JClass,
) -> JLong {
    match try_get_or_init_session() {
        Some(Ok(guard)) => guard
            .as_ref()
            .map(|s| s.get_audio_underruns() as JLong)
            .unwrap_or(0),
        Some(Err(_)) => 0,
        None => fast_channels().audio_underruns() as JLong,
    }
}

/// JNI Export: Get Audio Buffer Overrun Count
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeGetAudioOverruns(
    _env: JNIEnv,
    _clazz: JClass,
) -> JLong {
    match try_get_or_init_session() {
        Some(Ok(guard)) => guard
            .as_ref()
            .map(|s| s.get_audio_overruns() as JLong)
            .unwrap_or(0),
        Some(Err(_)) => 0,
        None => fast_channels().audio_overruns() as JLong,
    }
}

/// JNI Export: Get Current Audio Latency in milliseconds
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeGetAudioLatencyMs(
    _env: JNIEnv,
    _clazz: JClass,
) -> f32 {
    match try_get_or_init_session() {
        Some(Ok(guard)) => guard
            .as_ref()
            .map(|s| s.get_audio_latency_ms())
            .unwrap_or(0.0),
        Some(Err(_)) => 0.0,
        None => fast_channels().audio_latency_ms(),
    }
}

/// JNI Export: Set Target Audio Latency in milliseconds
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeSetTargetAudioLatencyMs(
    _env: JNIEnv,
    _clazz: JClass,
    latency_ms: f32,
) -> JInt {
    match try_get_or_init_session() {
        Some(Ok(mut guard)) => {
            if let Some(session) = guard.as_mut() {
                session.set_target_audio_latency_ms(latency_ms);
                JNI_OK
            } else {
                JNI_ERR_GENERIC
            }
        }
        Some(Err(_)) => JNI_ERR_GENERIC,
        None => {
            fast_channels().set_target_latency_ms(latency_ms);
            JNI_OK
        }
    }
}

/// JNI Export: Get Audio Ring Buffer Watermark Ratio (0.0 .. 1.0)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeGetAudioWatermarkRatio(
    _env: JNIEnv,
    _clazz: JClass,
) -> f32 {
    match try_get_or_init_session() {
        Some(Ok(guard)) => guard
            .as_ref()
            .map(|s| s.get_audio_watermark_ratio())
            .unwrap_or(0.0),
        Some(Err(_)) => 0.0,
        None => fast_channels().audio_watermark_ratio(),
    }
}


/// JNI Export: Set AOT Cache Directory
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeSetAotCacheDir(
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
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativePrecompileLibrary(
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
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeEnableAsyncJit(
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
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeDisableAsyncJit(
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
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeFlushAsyncJit(
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
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeMountObb(
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
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeMountPatchObb(
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
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeMountAppDataDir(
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
pub unsafe extern "C" fn Java_com_walzer32_loader_Walzer32Engine_nativeSetSystemProperty(
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
    log_i!("Walzer32: appDidBecomeActive called");
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
    log_i!("Walzer32: appDidEnterBackground called");
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
    log_i!("Walzer32: appWillEnterForeground called");
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
    log_i!("Walzer32: appWillResignActive called");
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
    log_i!("Walzer32: appWillTerminate called");
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

fn objc_get_sel(session: &mut crate::session::Walzer32Session, sel_reg: GuestAddr, name: &[u8]) -> Option<u32> {
    let addr = session.alloc_guest_bytes(name).ok()?;
    session.call_native(sel_reg, &[addr]).ok()
}

fn objc_get_cls(session: &mut crate::session::Walzer32Session, lookup_cls: GuestAddr, name: &[u8]) -> Option<u32> {
    let addr = session.alloc_guest_bytes(name).ok()?;
    session.call_native(lookup_cls, &[addr]).ok()
}

static CACHED_DIRECTOR: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static CACHED_DRAW_SCENE_IMP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static CACHED_RUN_WITH_SCENE_IMP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static CACHED_PUSH_SCENE_IMP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static CACHED_SET_NEXT_SCENE_IMP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static CACHED_SCENE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static CACHED_VISIT_IMP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static CACHED_LAYER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static CACHED_LAYER_DRAW_IMP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn objc_send_msg0(session: &mut crate::session::Walzer32Session, msg_lkp: GuestAddr, recv: u32, sel: u32) -> Option<u32> {
    if recv == 0 || sel == 0 { return None; }
    let imp = session.call_native(msg_lkp, &[recv, sel]).ok()?;
    session.call_native(GuestAddr(imp), &[recv, sel]).ok()
}

fn objc_send_msg1(session: &mut crate::session::Walzer32Session, msg_lkp: GuestAddr, recv: u32, sel: u32, arg1: u32) -> Option<u32> {
    if recv == 0 || sel == 0 { return None; }
    let imp = session.call_native(msg_lkp, &[recv, sel]).ok()?;
    session.call_native(GuestAddr(imp), &[recv, sel, arg1]).ok()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeInit(
    _env: JNIEnv,
    _clazz: JClass,
    width: JInt,
    height: JInt,
) {
    log_i!("Walzer32: Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeInit({}, {}) called", width, height);
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            session.on_surface_created(0, width as u32, height as u32);
            let env_ptr = session.jni.env_ptr.as_u32();
            if let Some(info) = session.jni_registry.find_by_symbol("Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeInit") {
                let fn_ptr = info.fn_ptr;
                log_i!("Walzer32: Invoking guest nativeInit at 0x{:08x}...", fn_ptr.as_u32());
                match session.call_native(fn_ptr, &[env_ptr, 1, width as u32, height as u32]) {
                    Ok(res) => log_i!("Walzer32: guest nativeInit finished with 0x{:08x}", res),
                    Err(e) => log_e!("Walzer32: guest nativeInit error: {:?}", e),
                }
            } else {
                log_i!("Walzer32: Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeInit not found in guest libs");
            }

            // Hook Cocos2D mainLoop into libuikit's nativeRender loop
            let main_loop_sym = session.find_loaded_symbol("mainLoop");
            let set_hook_sym = session.find_loaded_symbol("setMainLoopHook");
            log_i!("Walzer32: mainLoop at {:?}, setMainLoopHook at {:?}", main_loop_sym, set_hook_sym);

            if let (Some(ml), Some(sh)) = (main_loop_sym, set_hook_sym) {
                match session.call_native(sh, &[ml.as_u32()]) {
                    Ok(res) => log_i!("Walzer32: Successfully registered mainLoop (0x{:08x}) via setMainLoopHook (res 0x{:08x})", ml.as_u32(), res),
                    Err(e) => log_e!("Walzer32: setMainLoopHook error: {:?}", e),
                }
            }

            if let Some(gh) = session.find_loaded_symbol("getMainLoopHook") {
                match session.call_native(gh, &[]) {
                    Ok(hook_val) => log_i!("Walzer32: Verified getMainLoopHook() = 0x{:08x}", hook_val),
                    Err(e) => log_e!("Walzer32: getMainLoopHook error: {:?}", e),
                }
            }

            // Look up direct function pointers in libcocos2d.so
            let cocos_base = session.loaded_libraries.get("libcocos2d.so").map(|l| l.load_base.as_u32()).unwrap_or(0);
            log_i!("Walzer32: libcocos2d.so load_base = 0x{:08x}", cocos_base);
            if cocos_base != 0 {
                // Direct thumb entry points in libcocos2d.so:
                let draw_scene_imp = cocos_base + 0x119745; // -[CCDirectorAndroid drawScene]
                let run_with_scene_imp = cocos_base + 0x10d5fd; // -[CCDirector runWithScene:]
                let push_scene_imp = cocos_base + 0x10d6e5; // -[CCDirector pushScene:]
                let set_next_scene_imp = cocos_base + 0x10da89; // -[CCDirector setNextScene]
                let visit_imp = cocos_base + 0x000c28cd; // -[CCNode visit]

                CACHED_DRAW_SCENE_IMP.store(draw_scene_imp, std::sync::atomic::Ordering::Relaxed);
                CACHED_RUN_WITH_SCENE_IMP.store(run_with_scene_imp, std::sync::atomic::Ordering::Relaxed);
                CACHED_PUSH_SCENE_IMP.store(push_scene_imp, std::sync::atomic::Ordering::Relaxed);
                CACHED_SET_NEXT_SCENE_IMP.store(set_next_scene_imp, std::sync::atomic::Ordering::Relaxed);
                CACHED_VISIT_IMP.store(visit_imp, std::sync::atomic::Ordering::Relaxed);
                log_i!("Walzer32: Cached cocos2d IMPs: drawScene=0x{:08x}, runWithScene=0x{:08x}, pushScene=0x{:08x}, setNextScene=0x{:08x}, visit=0x{:08x}",
                    draw_scene_imp, run_with_scene_imp, push_scene_imp, set_next_scene_imp, visit_imp);
            }

            // Inspect and verify Objective-C runtime state (CCDirector, UIApplication, Scene)
            let lookup_class_sym = session.find_loaded_symbol("objc_lookup_class");
            let sel_register_name_sym = session.find_loaded_symbol("sel_registerName");
            let msg_lookup_sym = session.find_loaded_symbol("objc_msg_lookup");

            log_i!("Walzer32: objc_lookup_class: {:?}, sel_registerName: {:?}, objc_msg_lookup: {:?}",
                lookup_class_sym, sel_register_name_sym, msg_lookup_sym);

            if let (Some(lookup_cls), Some(sel_reg), Some(msg_lkp)) = (lookup_class_sym, sel_register_name_sym, msg_lookup_sym) {
                if let Some(cls_director) = objc_get_cls(session, lookup_cls, b"CCDirector\0") {
                    let sel_shared_dir = objc_get_sel(session, sel_reg, b"sharedDirector\0").unwrap_or(0);
                    let director = objc_send_msg0(session, msg_lkp, cls_director, sel_shared_dir).unwrap_or(0);
                    if director != 0 {
                        CACHED_DIRECTOR.store(director, std::sync::atomic::Ordering::Relaxed);
                        log_i!("Walzer32: Cached [CCDirector sharedDirector]=0x{:08x}", director);

                        // Setup director dimensions and clean flags
                        let w_f32 = width as f32;
                        let h_f32 = height as f32;
                        let _ = session.engine.mem.write_u32(GuestAddr::new(director + 0x7c), w_f32.to_bits());
                        let _ = session.engine.mem.write_u32(GuestAddr::new(director + 0x80), h_f32.to_bits());
                        let _ = session.engine.mem.write_u32(GuestAddr::new(director + 0x84), w_f32.to_bits());
                        let _ = session.engine.mem.write_u32(GuestAddr::new(director + 0x88), h_f32.to_bits());
                        let _ = session.engine.mem.write_u32(GuestAddr::new(director + 0x44), 0); // isPaused_ = false
                        let _ = session.engine.mem.write_u32(GuestAddr::new(director + 0x14), 0); // drawWhiteBackground_ = false
                    }

                    // Attempt app delegate launch first to allow game setup
                    let cls_app = objc_get_cls(session, lookup_cls, b"UIApplication\0").unwrap_or(0);
                    let sel_shared_app = objc_get_sel(session, sel_reg, b"sharedApplication\0").unwrap_or(0);
                    let sel_delegate = objc_get_sel(session, sel_reg, b"delegate\0").unwrap_or(0);
                    let sel_set_delegate = objc_get_sel(session, sel_reg, b"setDelegate:\0").unwrap_or(0);
                    let app = objc_send_msg0(session, msg_lkp, cls_app, sel_shared_app).unwrap_or(0);
                    let mut delegate = objc_send_msg0(session, msg_lkp, app, sel_delegate).unwrap_or(0);

                    if delegate == 0 {
                        log_i!("Walzer32: Delegate is nil, instantiating BigAirAppDelegate...");
                        if let Some(cls_delegate) = objc_get_cls(session, lookup_cls, b"BigAirAppDelegate\0") {
                            let sel_alloc = objc_get_sel(session, sel_reg, b"alloc\0").unwrap_or(0);
                            let sel_init = objc_get_sel(session, sel_reg, b"init\0").unwrap_or(0);
                            let raw_del = objc_send_msg0(session, msg_lkp, cls_delegate, sel_alloc).unwrap_or(0);
                            delegate = objc_send_msg0(session, msg_lkp, raw_del, sel_init).unwrap_or(0);
                            log_i!("Walzer32: Instantiated BigAirAppDelegate = 0x{:08x}", delegate);
                            if delegate != 0 && app != 0 {
                                let _ = objc_send_msg1(session, msg_lkp, app, sel_set_delegate, delegate);
                            }
                        }
                    }

                    if delegate != 0 {
                        let sel_launch = objc_get_sel(session, sel_reg, b"applicationDidFinishLaunching:\0").unwrap_or(0);
                        let launch_res = objc_send_msg1(session, msg_lkp, delegate, sel_launch, app);
                        log_i!("Walzer32: applicationDidFinishLaunching returned {:?}", launch_res);
                    }

                    // Check if director has runningScene_ or nextScene_
                    let mut running_scene = session.engine.mem.read_u32(GuestAddr::new(director + 0x48)).unwrap_or(0);
                    let mut next_scene = session.engine.mem.read_u32(GuestAddr::new(director + 0x50)).unwrap_or(0);
                    log_i!("Walzer32: Post-delegate director runningScene_=0x{:08x}, nextScene_=0x{:08x}", running_scene, next_scene);

                    // If neither exists, instantiate MenuScene (or NoodleIntroScene fallback)
                    if running_scene == 0 && next_scene == 0 {
                        let sel_node = objc_get_sel(session, sel_reg, b"node\0").unwrap_or(0);
                        let mut target_scene = 0;
                        if let Some(cls_menu) = objc_get_cls(session, lookup_cls, b"MenuScene\0") {
                            if sel_node != 0 {
                                target_scene = objc_send_msg0(session, msg_lkp, cls_menu, sel_node).unwrap_or(0);
                                log_i!("Walzer32: [MenuScene node] = 0x{:08x}", target_scene);
                            }
                        }
                        if target_scene == 0 {
                            if let Some(cls_intro) = objc_get_cls(session, lookup_cls, b"NoodleIntroScene\0") {
                                if sel_node != 0 {
                                    target_scene = objc_send_msg0(session, msg_lkp, cls_intro, sel_node).unwrap_or(0);
                                    log_i!("Walzer32: [NoodleIntroScene node] = 0x{:08x}", target_scene);
                                }
                            }
                        }
                        if target_scene == 0 {
                            if let Some(cls_scene) = objc_get_cls(session, lookup_cls, b"CCScene\0") {
                                if sel_node != 0 {
                                    target_scene = objc_send_msg0(session, msg_lkp, cls_scene, sel_node).unwrap_or(0);
                                    log_i!("Walzer32: [CCScene node] = 0x{:08x}", target_scene);
                                }
                            }
                        }

                        if target_scene != 0 {
                            running_scene = target_scene;
                            next_scene = target_scene;
                        }
                    }

                    let active_scene = if running_scene != 0 { running_scene } else { next_scene };
                    if active_scene != 0 && director != 0 {
                        let w_f32 = width as f32;
                        let h_f32 = height as f32;

                        // Guarantee CCNode invariants on active_scene:
                        // visible_ at 0x24 = 1, isRunning_ at 0xdc = 1, isTransformDirty_ at 0xe4 = 1
                        let _ = session.engine.mem.write_u8(GuestAddr::new(active_scene + 0x24), 1);
                        let _ = session.engine.mem.write_u8(GuestAddr::new(active_scene + 0xdc), 1);
                        let _ = session.engine.mem.write_u8(GuestAddr::new(active_scene + 0xe4), 1);
                        let _ = session.engine.mem.write_u32(GuestAddr::new(active_scene + 0x3c), w_f32.to_bits());
                        let _ = session.engine.mem.write_u32(GuestAddr::new(active_scene + 0x40), h_f32.to_bits());
                        let _ = session.engine.mem.write_u32(GuestAddr::new(active_scene + 0x44), w_f32.to_bits());
                        let _ = session.engine.mem.write_u32(GuestAddr::new(active_scene + 0x48), h_f32.to_bits());

                        // Also ensure children of active_scene are visible_ = 1
                        let children_obj = session.engine.mem.read_u32(GuestAddr::new(active_scene + 0xcc)).unwrap_or(0);
                        if children_obj != 0 {
                            let data_ptr = session.engine.mem.read_u32(GuestAddr::new(children_obj)).unwrap_or(0);
                            if data_ptr != 0 {
                                let num_children = session.engine.mem.read_u32(GuestAddr::new(data_ptr)).unwrap_or(0);
                                let arr_ptr = session.engine.mem.read_u32(GuestAddr::new(data_ptr + 8)).unwrap_or(0);
                                log_i!("Walzer32: active_scene children: count={}, arr=0x{:08x}", num_children, arr_ptr);
                                for i in 0..num_children.min(32) {
                                    if let Ok(ch) = session.engine.mem.read_u32(GuestAddr::new(arr_ptr + i * 4)) {
                                        if ch != 0 {
                                            let _ = session.engine.mem.write_u8(GuestAddr::new(ch + 0x24), 1);
                                            let _ = session.engine.mem.write_u8(GuestAddr::new(ch + 0xdc), 1);
                                        }
                                    }
                                }
                            }
                        }

                        // Write to director: runningScene_ = active_scene, nextScene_ = 0
                        let _ = session.engine.mem.write_u32(GuestAddr::new(director + 0x48), active_scene);
                        let _ = session.engine.mem.write_u32(GuestAddr::new(director + 0x50), 0);
                        let _ = session.engine.mem.write_u32(GuestAddr::new(director + 0x44), 0);
                        let _ = session.engine.mem.write_u32(GuestAddr::new(director + 0x14), 0);

                        // Trigger onEnter and onEnterTransitionDidFinish
                        let sel_on_enter = objc_get_sel(session, sel_reg, b"onEnter\0").unwrap_or(0);
                        if sel_on_enter != 0 {
                            let _ = objc_send_msg0(session, msg_lkp, active_scene, sel_on_enter);
                        }
                        let sel_enter_done = objc_get_sel(session, sel_reg, b"onEnterTransitionDidFinish\0").unwrap_or(0);
                        if sel_enter_done != 0 {
                            let _ = objc_send_msg0(session, msg_lkp, active_scene, sel_enter_done);
                        }

                        CACHED_SCENE.store(active_scene, std::sync::atomic::Ordering::Relaxed);
                        log_i!("Walzer32: Configured active scene 0x{:08x} on director 0x{:08x}", active_scene, director);

                        // Instantiate CCLayerColor and attach to active_scene
                        if cocos_base != 0 {
                            let layer_with_color_imp = cocos_base + 0x10e931; // +[CCLayerColor layerWithColor:]
                            let layer_draw_imp = cocos_base + 0x10ed95; // -[CCLayerColor draw]
                            let node_add_child_imp = cocos_base + 0x000c2281; // -[CCNode addChild:]
                            CACHED_LAYER_DRAW_IMP.store(layer_draw_imp, std::sync::atomic::Ordering::Relaxed);

                            let cls_layer_color = objc_get_cls(session, lookup_cls, b"CCLayerColor\0")
                                .unwrap_or(cocos_base + 0x18d9a0);
                            log_i!("Walzer32: CCLayerColor class = 0x{:08x}", cls_layer_color);

                            // Color: 0xFFFF5533 (vibrant orange/red ccColor4B)
                            let color_val: u32 = 0xFFFF5533;
                            if let Ok(layer) = session.call_native(GuestAddr(layer_with_color_imp), &[cls_layer_color, 0, color_val]) {
                                if layer != 0 {
                                    log_i!("Walzer32: Successfully created CCLayerColor = 0x{:08x}", layer);
                                    let _ = session.engine.mem.write_u8(GuestAddr::new(layer + 0x24), 1); // visible_ = 1
                                    let _ = session.engine.mem.write_u8(GuestAddr::new(layer + 0xdc), 1); // isRunning_ = 1
                                    let _ = session.engine.mem.write_u32(GuestAddr::new(layer + 0x3c), w_f32.to_bits());
                                    let _ = session.engine.mem.write_u32(GuestAddr::new(layer + 0x40), h_f32.to_bits());
                                    let _ = session.engine.mem.write_u32(GuestAddr::new(layer + 0x44), w_f32.to_bits());
                                    let _ = session.engine.mem.write_u32(GuestAddr::new(layer + 0x48), h_f32.to_bits());

                                    let sel_add_child = objc_get_sel(session, sel_reg, b"addChild:\0").unwrap_or(0);
                                    let add_direct_res = session.call_native(GuestAddr(node_add_child_imp), &[active_scene, sel_add_child, layer]);
                                    log_i!("Walzer32: Direct -[CCNode addChild:] returned {:?}", add_direct_res);

                                    CACHED_LAYER.store(layer, std::sync::atomic::Ordering::Relaxed);
                                } else {
                                    log_e!("Walzer32: CCLayerColor layerWithColor returned 0");
                                }
                            } else {
                                log_e!("Walzer32: CCLayerColor layerWithColor call failed");
                            }
                        }
                    }
                }
            }

            // Also ensure UIApplication appDidBecomeActive is called to transition app state
            if let Some(app_active) = session.jni_registry.find_by_symbol("Java_com_noodlecake_lib_uikit_UIApplication_appDidBecomeActive") {
                log_i!("Walzer32: Triggering appDidBecomeActive at 0x{:08x}...", app_active.fn_ptr.as_u32());
                let _ = session.call_native(app_active.fn_ptr, &[env_ptr, 1]);
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
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            if f == 0 || f.is_multiple_of(300) {
                log_i!("Walzer32: nativeRender frame {}, total_draw_calls {}, swap_count {}", f, session.gles_total_draw_calls(), session.gles_swap_count());
            }
            let _ = session.on_draw_frame();
            let env_ptr = session.jni.env_ptr.as_u32();
            if let Some(info) = session.jni_registry.find_by_symbol("Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeRender") {
                let fn_ptr = info.fn_ptr;
                match session.call_native(fn_ptr, &[env_ptr, 1]) {
                    Ok(_) => {}
                    Err(e) => {
                        if f.is_multiple_of(300) {
                            log_e!("Walzer32: guest nativeRender error: {:?}", e);
                        }
                    }
                }
            }

            // 1. Direct CCDirectorAndroid drawScene call via cached IMP
            let director = CACHED_DIRECTOR.load(std::sync::atomic::Ordering::Relaxed);
            let draw_imp = CACHED_DRAW_SCENE_IMP.load(std::sync::atomic::Ordering::Relaxed);
            if director != 0 && draw_imp != 0 {
                // Ensure director flags: isPaused_ = false, drawWhiteBackground_ = false
                let _ = session.engine.mem.write_u32(GuestAddr::new(director + 0x44), 0);
                let _ = session.engine.mem.write_u32(GuestAddr::new(director + 0x14), 0);
                let res = session.call_native(GuestAddr(draw_imp), &[director, 0]);
                if f == 0 || f.is_multiple_of(60) {
                    log_i!("Walzer32: Frame {} -[CCDirectorAndroid drawScene] res: {:?}, total_draw_calls: {}", f, res, session.gles_total_draw_calls());
                }
            }

            // 2. Direct [scene visit] call via cached IMP
            let scene = CACHED_SCENE.load(std::sync::atomic::Ordering::Relaxed);
            let visit_imp = CACHED_VISIT_IMP.load(std::sync::atomic::Ordering::Relaxed);
            if scene != 0 && visit_imp != 0 {
                // Ensure scene visible_ is 1
                let _ = session.engine.mem.write_u8(GuestAddr::new(scene + 0x24), 1);
                let vres = session.call_native(GuestAddr(visit_imp), &[scene, 0]);
                if f == 0 || f.is_multiple_of(60) {
                    log_i!("Walzer32: Frame {} direct [scene visit] res: {:?}, total_draw_calls: {}", f, vres, session.gles_total_draw_calls());
                }
            }

            // 3. Direct [CCLayerColor draw] call via cached IMP
            let layer = CACHED_LAYER.load(std::sync::atomic::Ordering::Relaxed);
            let layer_draw_imp = CACHED_LAYER_DRAW_IMP.load(std::sync::atomic::Ordering::Relaxed);
            if layer != 0 && layer_draw_imp != 0 {
                if let Some(fp) = session.gles.resolve_host_symbol("glEnableClientState") {
                    let enable_cs: extern "C" fn(u32) = unsafe { std::mem::transmute(fp) };
                    enable_cs(0x8074); // GL_VERTEX_ARRAY
                    enable_cs(0x8076); // GL_COLOR_ARRAY
                }
                if let Some(fp_matrix) = session.gles.resolve_host_symbol("glMatrixMode") {
                    let matrix_fn: extern "C" fn(u32) = unsafe { std::mem::transmute(fp_matrix) };
                    if let Some(fp_ident) = session.gles.resolve_host_symbol("glLoadIdentity") {
                        let ident_fn: extern "C" fn() = unsafe { std::mem::transmute(fp_ident) };
                        if let Some(fp_ortho) = session.gles.resolve_host_symbol("glOrthof") {
                            let ortho_fn: extern "C" fn(f32, f32, f32, f32, f32, f32) = unsafe { std::mem::transmute(fp_ortho) };
                            matrix_fn(0x1701); // GL_PROJECTION
                            ident_fn();
                            ortho_fn(0.0, 2520.0, 0.0, 1080.0, -1000.0, 1000.0);
                            matrix_fn(0x1700); // GL_MODELVIEW
                            ident_fn();
                        }
                    }
                }
                let lres = session.call_native(GuestAddr(layer_draw_imp), &[layer, 0]);
                if f == 0 || f.is_multiple_of(60) {
                    log_i!("Walzer32: Frame {} direct [CCLayerColor draw] res: {:?}, total_draw_calls: {}", f, lres, session.gles_total_draw_calls());
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
    log_i!("Walzer32: Java_org_cocos2dx_lib_Cocos2dxRenderer_nativeSurfaceChanged({}, {}) called", width, height);
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


#[repr(C)]
#[allow(dead_code)]
struct HostANativeActivityCallbacks {
    on_start: Option<unsafe extern "C" fn(*mut c_void)>,
    on_resume: Option<unsafe extern "C" fn(*mut c_void)>,
    on_save_instance_state: Option<unsafe extern "C" fn(*mut c_void, *mut usize) -> *mut c_void>,
    on_pause: Option<unsafe extern "C" fn(*mut c_void)>,
    on_stop: Option<unsafe extern "C" fn(*mut c_void)>,
    on_destroy: Option<unsafe extern "C" fn(*mut c_void)>,
    on_window_focus_changed: Option<unsafe extern "C" fn(*mut c_void, i32)>,
    on_native_window_created: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    on_native_window_resized: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    on_native_window_redraw_needed: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    on_native_window_destroyed: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    on_input_queue_created: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    on_input_queue_destroyed: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    on_content_rect_changed: Option<unsafe extern "C" fn(*mut c_void, *const c_void)>,
    on_configuration_changed: Option<unsafe extern "C" fn(*mut c_void)>,
    on_low_memory: Option<unsafe extern "C" fn(*mut c_void)>,
}

#[repr(C)]
#[allow(dead_code)]
struct HostANativeActivity {
    callbacks: *mut HostANativeActivityCallbacks,
    vm: *mut c_void,
    env: *mut c_void,
    clazz: *mut c_void,
    internal_data_path: *const std::ffi::c_char,
    external_data_path: *const std::ffi::c_char,
    sdk_version: i32,
    instance: *mut c_void,
    asset_manager: *mut c_void,
    obb_path: *const std::ffi::c_char,
}

fn dispatch_guest_activity_cb(slot_index: usize, extra_arg: Option<u32>) {
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            let _ = session.invoke_native_activity_callback(slot_index, extra_arg);
        }
    }
}

unsafe extern "C" fn host_cb_on_start(_act: *mut c_void) {
    dispatch_guest_activity_cb(0, None);
}
unsafe extern "C" fn host_cb_on_resume(_act: *mut c_void) {
    dispatch_guest_activity_cb(1, None);
}
#[cfg(target_os = "android")]
unsafe extern "C" fn host_cb_on_save_instance_state(
    _act: *mut c_void,
    out_size: *mut usize,
) -> *mut c_void {
    unsafe extern "C" {
        fn malloc(size: usize) -> *mut c_void;
    }
    if !out_size.is_null() {
        unsafe { *out_size = 0 };
    }
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            if let Ok(Some(bytes)) = session.invoke_native_activity_save_state() {
                let ptr = unsafe { malloc(bytes.len()) };
                if !ptr.is_null() {
                    unsafe {
                        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, bytes.len());
                    }
                    if !out_size.is_null() {
                        unsafe { *out_size = bytes.len() };
                    }
                    return ptr;
                }
            }
        }
    }
    std::ptr::null_mut()
}
#[cfg(not(target_os = "android"))]
unsafe extern "C" fn host_cb_on_save_instance_state(
    _act: *mut c_void,
    out_size: *mut usize,
) -> *mut c_void {
    if !out_size.is_null() {
        unsafe { *out_size = 0 };
    }
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            let _ = session.invoke_native_activity_save_state();
        }
    }
    std::ptr::null_mut()
}
unsafe extern "C" fn host_cb_on_pause(_act: *mut c_void) {
    dispatch_guest_activity_cb(3, None);
}
unsafe extern "C" fn host_cb_on_stop(_act: *mut c_void) {
    dispatch_guest_activity_cb(4, None);
}
unsafe extern "C" fn host_cb_on_destroy(_act: *mut c_void) {
    dispatch_guest_activity_cb(5, None);
}
unsafe extern "C" fn host_cb_on_window_focus_changed(_act: *mut c_void, has_focus: i32) {
    dispatch_guest_activity_cb(6, Some(has_focus as u32));
}
unsafe extern "C" fn host_cb_on_native_window_created(_act: *mut c_void, window: *mut c_void) {
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            let w = 0u32;
            let h = 0u32;
            session.on_surface_created(window as usize, w, h);
            let _ = session.invoke_native_activity_callback(
                7,
                Some(walzer32_bridge::GUEST_SURFACE_HANDLE),
            );
        }
    }
}
unsafe extern "C" fn host_cb_on_native_window_resized(_act: *mut c_void, _window: *mut c_void) {
    dispatch_guest_activity_cb(8, Some(walzer32_bridge::GUEST_SURFACE_HANDLE));
}
unsafe extern "C" fn host_cb_on_native_window_redraw_needed(_act: *mut c_void, _window: *mut c_void) {
    dispatch_guest_activity_cb(9, Some(walzer32_bridge::GUEST_SURFACE_HANDLE));
}
unsafe extern "C" fn host_cb_on_native_window_destroyed(_act: *mut c_void, _window: *mut c_void) {
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            let _ = session.invoke_native_activity_callback(
                10,
                Some(walzer32_bridge::GUEST_SURFACE_HANDLE),
            );
            session.on_surface_destroyed();
        }
    }
}
unsafe extern "C" fn host_cb_on_input_queue_created(_act: *mut c_void, _queue: *mut c_void) {
    dispatch_guest_activity_cb(11, Some(0x3200_0001));
}
unsafe extern "C" fn host_cb_on_input_queue_destroyed(_act: *mut c_void, _queue: *mut c_void) {
    dispatch_guest_activity_cb(12, Some(0x3200_0001));
}
unsafe extern "C" fn host_cb_on_content_rect_changed(_act: *mut c_void, rect: *const c_void) {
    if rect.is_null() {
        return;
    }
    let vals = unsafe { std::slice::from_raw_parts(rect as *const i32, 4) };
    if let Ok(mut guard) = get_or_init_session() {
        if let Some(session) = guard.as_mut() {
            let _ = session.invoke_native_activity_content_rect(vals[0], vals[1], vals[2], vals[3]);
        }
    }
}
unsafe extern "C" fn host_cb_on_configuration_changed(_act: *mut c_void) {
    dispatch_guest_activity_cb(14, None);
}
unsafe extern "C" fn host_cb_on_low_memory(_act: *mut c_void) {
    dispatch_guest_activity_cb(15, None);
}

unsafe fn read_host_cstr(ptr: *const std::ffi::c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        unsafe { std::ffi::CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }
}

/// Android NDK NativeActivity Entry Point:
/// Invoked by Android OS NativeActivity framework when creating a pure native C/C++ or Unity/Unreal activity.
/// Marshals a 32-bit ANativeActivity struct + callback table and executes guest ANativeActivity_onCreate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ANativeActivity_onCreate(
    activity: *mut c_void,
    saved_state: *mut c_void,
    saved_state_size: usize,
) {
    log_i!("Walzer32: ANativeActivity_onCreate invoked");
    let mut guard = match get_or_init_session() {
        Ok(g) => g,
        Err(e) => {
            log_e!("Walzer32: ANativeActivity_onCreate session init error: {:?}", e);
            return;
        }
    };
    let Some(session) = guard.as_mut() else {
        return;
    };
    let _ = session.ensure_bundled_apk_loaded();

    let (internal_path, external_path, obb_path, sdk_version, host_cb_ptr) = if !activity.is_null() {
        let host_act = unsafe { &*(activity as *const HostANativeActivity) };
        (
            unsafe { read_host_cstr(host_act.internal_data_path) },
            unsafe { read_host_cstr(host_act.external_data_path) },
            unsafe { read_host_cstr(host_act.obb_path) },
            host_act.sdk_version,
            host_act.callbacks,
        )
    } else {
        (
            "/data/data/com.walzer32.loader/files".to_string(),
            "/sdcard/Android/data/com.walzer32.loader/files".to_string(),
            "/sdcard/Android/obb/com.walzer32.loader".to_string(),
            29,
            std::ptr::null_mut(),
        )
    };

    let saved_slice = if !saved_state.is_null() && saved_state_size > 0 {
        unsafe { std::slice::from_raw_parts(saved_state as *const u8, saved_state_size) }
    } else {
        &[]
    };

    if !host_cb_ptr.is_null() {
        let host_cbs = unsafe { &mut *host_cb_ptr };
        host_cbs.on_start = Some(host_cb_on_start);
        host_cbs.on_resume = Some(host_cb_on_resume);
        host_cbs.on_save_instance_state = Some(host_cb_on_save_instance_state);
        host_cbs.on_pause = Some(host_cb_on_pause);
        host_cbs.on_stop = Some(host_cb_on_stop);
        host_cbs.on_destroy = Some(host_cb_on_destroy);
        host_cbs.on_window_focus_changed = Some(host_cb_on_window_focus_changed);
        host_cbs.on_native_window_created = Some(host_cb_on_native_window_created);
        host_cbs.on_native_window_resized = Some(host_cb_on_native_window_resized);
        host_cbs.on_native_window_redraw_needed = Some(host_cb_on_native_window_redraw_needed);
        host_cbs.on_native_window_destroyed = Some(host_cb_on_native_window_destroyed);
        host_cbs.on_input_queue_created = Some(host_cb_on_input_queue_created);
        host_cbs.on_input_queue_destroyed = Some(host_cb_on_input_queue_destroyed);
        host_cbs.on_content_rect_changed = Some(host_cb_on_content_rect_changed);
        host_cbs.on_configuration_changed = Some(host_cb_on_configuration_changed);
        host_cbs.on_low_memory = Some(host_cb_on_low_memory);
    }

    match session.setup_native_activity32(
        &internal_path,
        &external_path,
        &obb_path,
        sdk_version,
        saved_slice,
    ) {
        Ok(true) => log_i!("Walzer32: Guest ANativeActivity_onCreate completed"),
        Ok(false) => log_i!("Walzer32: No guest ANativeActivity_onCreate symbol found"),
        Err(e) => log_e!("Walzer32: Guest ANativeActivity_onCreate error: {:?}", e),
    }
}
