use std::ptr;
use walzer32_android::jni_exports::*;
use walzer32_android::session::{reset_session, Walzer32Session};
use walzer32_bridge::{AudioFormat, SL_PLAYSTATE_PLAYING};
use walzer32_core::GuestAddr;

#[test]
fn test_android_session_audio_streaming() {
    let mut session = Walzer32Session::new(GuestAddr::new(0x7000_0000), 0x800_0000).unwrap();

    // Configure audio format to 44.1 kHz stereo
    session.audio.set_format(AudioFormat {
        channels: 2,
        sample_rate_hz: 44100,
        bits_per_sample: 16,
    });
    session.audio.set_play_state(SL_PLAYSTATE_PLAYING);

    // Enqueue 441 stereo frames (882 samples) of 16-bit PCM
    let mut samples = Vec::with_capacity(882);
    for _ in 0..441 {
        samples.push(800i16);
        samples.push(-800i16);
    }
    let enqueued = session.audio.enqueue_pcm_samples(&samples);
    assert!(enqueued > 0);

    // Read back through session
    let mut out = [0i16; 128];
    let frames_read = session.read_audio_frames(&mut out);
    assert_eq!(frames_read, 64);
    assert_eq!(out[0], 800);
    assert_eq!(out[1], -800);

    // Volume adjustment
    session.set_audio_volume(-2000);
    assert_eq!(session.audio.volume_millibels, -2000);

    // Underruns & overruns
    assert_eq!(session.get_audio_underruns(), 0);
    assert_eq!(session.get_audio_overruns(), 0);
}

#[test]
fn test_android_jni_audio_exports() {
    reset_session();

    let env = ptr::null_mut();
    let clazz = ptr::null_mut();

    // 1. Initialize engine
    let res = unsafe { Java_com_walzer32_loader_Walzer32Engine_nativeInit(env, clazz, ptr::null_mut()) };
    assert_eq!(res, JNI_OK);

    // 2. Set volume via JNI (-1500 mB)
    let vol_res = unsafe { Java_com_walzer32_loader_Walzer32Engine_nativeSetAudioVolume(env, clazz, -1500) };
    assert_eq!(vol_res, JNI_OK);

    // 3. Render PCM audio via JNI (initially empty buffer -> underrun with silence fill)
    let mut pcm_out = [1234i16; 64];
    let rendered = unsafe {
        Java_com_walzer32_loader_Walzer32Engine_nativeRenderAudioPcm(
            env,
            clazz,
            pcm_out.as_mut_ptr(),
            pcm_out.len(),
        )
    };
    assert_eq!(rendered, 0); // 0 valid frames available
    for &sample in &pcm_out {
        assert_eq!(sample, 0); // filled with silence
    }

    // 4. Query underruns and overruns via JNI
    let underruns = unsafe { Java_com_walzer32_loader_Walzer32Engine_nativeGetAudioUnderruns(env, clazz) };
    assert_eq!(underruns, 1);

    let overruns = unsafe { Java_com_walzer32_loader_Walzer32Engine_nativeGetAudioOverruns(env, clazz) };
    assert_eq!(overruns, 0);

    // 5. Query and set audio latency metrics via JNI
    let initial_lat = unsafe { Java_com_walzer32_loader_Walzer32Engine_nativeGetAudioLatencyMs(env, clazz) };
    assert_eq!(initial_lat, 0.0);

    let set_target_res = unsafe { Java_com_walzer32_loader_Walzer32Engine_nativeSetTargetAudioLatencyMs(env, clazz, 8.0) };
    assert_eq!(set_target_res, JNI_OK);

    let wm = unsafe { Java_com_walzer32_loader_Walzer32Engine_nativeGetAudioWatermarkRatio(env, clazz) };
    assert_eq!(wm, 0.0);
}
