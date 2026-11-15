use std::sync::{mpsc, Mutex};
use std::time::Duration;

static TEST_MUTEX: Mutex<()> = Mutex::new(());
use walzer32_android::{
    get_or_init_session, reset_session, Walzer32Session,
    Java_com_walzer32_loader_Walzer32Engine_nativeGetAudioLatencyMs,
    Java_com_walzer32_loader_Walzer32Engine_nativeGetAudioWatermarkRatio,
    Java_com_walzer32_loader_Walzer32Engine_nativeGetTelemetryHud,
    Java_com_walzer32_loader_Walzer32Engine_nativeGetTelemetryJson,
    Java_com_walzer32_loader_Walzer32Engine_nativeKeyEvent,
    Java_com_walzer32_loader_Walzer32Engine_nativeRenderAudioPcm,
    Java_com_walzer32_loader_Walzer32Engine_nativeSetAudioVolume,
    Java_com_walzer32_loader_Walzer32Engine_nativeSetTargetAudioLatencyMs,
    Java_com_walzer32_loader_Walzer32Engine_nativeSurfaceChanged,
    Java_com_walzer32_loader_Walzer32Engine_nativeTouchEvent, JNI_OK,
};
use walzer32_core::{GuestAddr, Memory};
use walzer32_elf::SymbolResolver;

fn movw(rd: u32, imm16: u16) -> u32 {
    let imm = imm16 as u32;
    0xE300_0000 | ((imm >> 12) << 16) | (rd << 12) | (imm & 0xFFF)
}

fn movt(rd: u32, imm16: u16) -> u32 {
    let imm = imm16 as u32;
    0xE340_0000 | ((imm >> 12) << 16) | (rd << 12) | (imm & 0xFFF)
}

fn mov32(code: &mut Vec<(u32, u32)>, pc: &mut u32, rd: u32, val: u32) {
    code.push((*pc, movw(rd, (val & 0xFFFF) as u16)));
    *pc += 4;
    if (val >> 16) != 0 {
        code.push((*pc, movt(rd, (val >> 16) as u16)));
        *pc += 4;
    }
}

fn call_abs(code: &mut Vec<(u32, u32)>, pc: &mut u32, target: u32) {
    mov32(code, pc, 12, target);
    code.push((*pc, 0xE12F_FF3C)); // BLX R12
    *pc += 4;
}

fn arm_branch(cond: u32, from_pc: u32, to_pc: u32) -> u32 {
    let offset = ((to_pc as i64 - (from_pc as i64 + 8)) >> 2) as i32;
    (cond << 28) | 0x0A00_0000 | ((offset as u32) & 0x00FF_FFFF)
}

#[test]
fn test_session_lazy_multithread_pthread_create_join() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let mut session = Walzer32Session::new(GuestAddr::new(0x7000_0000), 0x0200_0000).unwrap();

    let pthread_create = session.bionic.resolve("pthread_create").unwrap().as_u32();
    let pthread_join = session.bionic.resolve("pthread_join").unwrap().as_u32();
    let pthread_mutex_init = session.bionic.resolve("pthread_mutex_init").unwrap().as_u32();
    let pthread_mutex_lock = session.bionic.resolve("pthread_mutex_lock").unwrap().as_u32();
    let pthread_mutex_unlock = session.bionic.resolve("pthread_mutex_unlock").unwrap().as_u32();

    let mutex_addr: u32 = 0x7102_0000;
    let counter_addr: u32 = 0x7102_0004;
    let tids_base: u32 = 0x7102_0010;
    let rets_base: u32 = 0x7102_0020;
    session.engine.mem.write_u32(GuestAddr::new(counter_addr), 0).unwrap();

    let worker_pc: u32 = 0x7100_0000;
    let mut code = Vec::new();
    let mut pc = worker_pc;
    code.push((pc, 0xE92D_4070)); // PUSH {R4, R5, R6, LR}
    pc += 4;
    code.push((pc, 0xE1A0_4000)); // MOV R4, R0
    pc += 4;
    code.push((pc, 0xE3A0_5032)); // MOV R5, #50
    pc += 4;
    let loop_pc = pc;
    mov32(&mut code, &mut pc, 0, mutex_addr);
    call_abs(&mut code, &mut pc, pthread_mutex_lock);
    mov32(&mut code, &mut pc, 6, counter_addr);
    code.push((pc, 0xE596_0000)); // LDR R0, [R6]
    pc += 4;
    code.push((pc, 0xE280_0001)); // ADD R0, R0, #1
    pc += 4;
    code.push((pc, 0xE586_0000)); // STR R0, [R6]
    pc += 4;
    mov32(&mut code, &mut pc, 0, mutex_addr);
    call_abs(&mut code, &mut pc, pthread_mutex_unlock);
    code.push((pc, 0xE255_5001)); // SUBS R5, R5, #1
    pc += 4;
    code.push((pc, arm_branch(1 /* NE */, pc, loop_pc)));
    pc += 4;
    code.push((pc, 0xE284_0064)); // ADD R0, R4, #100
    pc += 4;
    code.push((pc, 0xE8BD_8070)); // POP {R4, R5, R6, PC}

    let main_pc: u32 = 0x7100_1000;
    pc = main_pc;
    code.push((pc, 0xE92D_4010)); // PUSH {R4, LR}
    pc += 4;
    mov32(&mut code, &mut pc, 0, mutex_addr);
    code.push((pc, 0xE3A0_1000)); // MOV R1, #0
    pc += 4;
    call_abs(&mut code, &mut pc, pthread_mutex_init);

    for i in 0..4u32 {
        mov32(&mut code, &mut pc, 0, tids_base + i * 4);
        code.push((pc, 0xE3A0_1000)); // attr = NULL
        pc += 4;
        mov32(&mut code, &mut pc, 2, worker_pc);
        code.push((pc, 0xE3A0_3000 | (i + 1))); // arg = i + 1
        pc += 4;
        call_abs(&mut code, &mut pc, pthread_create);
    }

    for i in 0..4u32 {
        mov32(&mut code, &mut pc, 0, tids_base + i * 4);
        code.push((pc, 0xE590_0000)); // LDR R0, [R0]
        pc += 4;
        mov32(&mut code, &mut pc, 1, rets_base + i * 4);
        call_abs(&mut code, &mut pc, pthread_join);
    }

    mov32(&mut code, &mut pc, 6, counter_addr);
    code.push((pc, 0xE596_0000)); // LDR R0, [R6]
    pc += 4;
    code.push((pc, 0xE8BD_8010)); // POP {R4, PC}

    for (addr, insn) in code {
        session.engine.mem.write_u32(GuestAddr::new(addr), insn).unwrap();
    }

    let ret = session.call_native(GuestAddr::new(main_pc), &[]).unwrap();
    assert_eq!(ret, 200);
    assert_eq!(
        session.engine.mem.read_u32(GuestAddr::new(counter_addr)).unwrap(),
        200
    );
    for i in 0..4u32 {
        assert_eq!(
            session.engine.mem.read_u32(GuestAddr::new(rets_base + i * 4)).unwrap(),
            101 + i
        );
    }
    // All workers joined cleanly -> runtime bridges automatically reclaimed into Walzer32Session.
    assert!(session.active_mt_runtime.is_none());
}

#[test]
fn test_jni_nonblocking_while_session_locked() {
    let _lock = TEST_MUTEX.lock().unwrap();
    reset_session();

    let mut guard = get_or_init_session().unwrap();
    {
        let session = guard.as_mut().unwrap();
        // Push 8 stereo frames (16 samples) into the lock-free audio ring while holding session lock
        let samples: Vec<i16> = (1..=16).map(|i| i * 100).collect();
        session.audio.ring_buffer.push_slice(&samples);
        session.sync_fast_channels();
    }

    let (tx, rx) = mpsc::channel();
    let handle = std::thread::spawn(move || unsafe {
        let env = std::ptr::null_mut();
        let clazz = std::ptr::null_mut();

        assert_eq!(
            Java_com_walzer32_loader_Walzer32Engine_nativeTouchEvent(env, clazz, 0, 120.5, 240.5, 1),
            JNI_OK
        );
        assert_eq!(
            Java_com_walzer32_loader_Walzer32Engine_nativeKeyEvent(env, clazz, 0, 66),
            JNI_OK
        );
        assert_eq!(
            Java_com_walzer32_loader_Walzer32Engine_nativeSurfaceChanged(env, clazz, 1440, 900),
            JNI_OK
        );
        assert_eq!(
            Java_com_walzer32_loader_Walzer32Engine_nativeSetAudioVolume(env, clazz, -600),
            JNI_OK
        );
        assert_eq!(
            Java_com_walzer32_loader_Walzer32Engine_nativeSetTargetAudioLatencyMs(env, clazz, 12.5),
            JNI_OK
        );

        let mut pcm = vec![0i16; 16];
        let frames = Java_com_walzer32_loader_Walzer32Engine_nativeRenderAudioPcm(
            env,
            clazz,
            pcm.as_mut_ptr(),
            pcm.len(),
        );
        let lat = Java_com_walzer32_loader_Walzer32Engine_nativeGetAudioLatencyMs(env, clazz);
        let wm = Java_com_walzer32_loader_Walzer32Engine_nativeGetAudioWatermarkRatio(env, clazz);

        let mut hud_buf = vec![0u8; 512];
        let hud_len = Java_com_walzer32_loader_Walzer32Engine_nativeGetTelemetryHud(
            env,
            clazz,
            hud_buf.as_mut_ptr(),
            hud_buf.len(),
        );
        let mut json_buf = vec![0u8; 512];
        let json_len = Java_com_walzer32_loader_Walzer32Engine_nativeGetTelemetryJson(
            env,
            clazz,
            json_buf.as_mut_ptr(),
            json_buf.len(),
        );

        tx.send((frames, pcm, lat, wm, hud_len, json_len)).unwrap();
    });

    // Must complete almost instantaneously EVEN WHILE `guard` holds GLOBAL_SESSION!
    let (frames, pcm, lat, wm, hud_len, json_len) = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("UI/Audio/Telemetry JNI calls deadlocked or blocked on GLOBAL_SESSION!");
    handle.join().unwrap();

    assert_eq!(frames, 8);
    assert_eq!(pcm[0], 100);
    assert_eq!(pcm[15], 1600);
    assert!(lat >= 0.0);
    assert!(wm >= 0.0);
    assert!(hud_len > 0);
    assert!(json_len > 0);

    // Release GLOBAL_SESSION lock, then pump a frame and verify queued fast inputs were drained
    drop(guard);

    let mut guard2 = get_or_init_session().unwrap();
    let session = guard2.as_mut().unwrap();
    session.on_draw_frame().unwrap();

    assert_eq!(session.surface.touch_queue.len(), 1);
    assert_eq!(session.surface.touch_queue[0].x, 120.5);
    assert_eq!(session.surface.touch_queue[0].y, 240.5);
    assert_eq!(session.surface.key_queue.len(), 1);
    assert_eq!(session.surface.key_queue[0].key_code, 66);
    assert_eq!(session.surface.width, 1440);
    assert_eq!(session.surface.height, 900);
    assert_eq!(session.audio.volume_millibels(), -600);
    assert_eq!(session.audio.target_latency_ms, 12.5);
}
