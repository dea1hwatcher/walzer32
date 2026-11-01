use transd_bridge::{
    AudioBridge, AudioFormat, AudioFuncId, AUDIO_SVC_MAGIC,
    SL_PLAYSTATE_PLAYING, SL_PLAYSTATE_STOPPED, SL_RESULT_SUCCESS,
};
use transd_core::{CpuState, FlatMemory, GuestAddr, Memory, Reg};

#[test]
fn test_audio_opensles_full_pipeline() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x20000);
    let stub_base = GuestAddr::new(0x2000);
    let mut audio = AudioBridge::with_stub_base(stub_base);
    audio.install_stubs(&mut mem).unwrap();

    let mut cpu = CpuState::new();

    // 1. slCreateEngine(&engine)
    let p_engine = GuestAddr::new(0x8000);
    cpu.set_reg(Reg::R0, p_engine.as_u32());
    let handled = audio
        .handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::SlCreateEngine as u32), &mut cpu, &mut mem)
        .unwrap();
    assert!(handled);
    assert_eq!(cpu.reg(Reg::R0), SL_RESULT_SUCCESS);
    let engine_obj = mem.read_u32(p_engine).unwrap();
    assert_eq!(engine_obj, stub_base.add(0x1000).as_u32());

    // 2. (*engine)->CreateAudioPlayer(engine, &player, ...)
    let p_player = GuestAddr::new(0x8004);
    cpu.set_reg(Reg::R0, engine_obj);
    cpu.set_reg(Reg::R1, p_player.as_u32());
    audio
        .handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::SlEngineCreateAudioPlayer as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), SL_RESULT_SUCCESS);
    let player_obj = mem.read_u32(p_player).unwrap();
    assert_eq!(player_obj, stub_base.add(0x1100).as_u32());

    // 3. (*player)->GetInterface(player, SL_IID_PLAY, &playItf)
    let p_play_itf = GuestAddr::new(0x8008);
    cpu.set_reg(Reg::R0, player_obj);
    cpu.set_reg(Reg::R1, stub_base.add(0x610).as_u32()); // SL_IID_PLAY
    cpu.set_reg(Reg::R2, p_play_itf.as_u32());
    audio
        .handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::SlObjectGetInterface as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), SL_RESULT_SUCCESS);
    let play_itf = mem.read_u32(p_play_itf).unwrap();
    assert_eq!(play_itf, stub_base.add(0x1150).as_u32());

    // 4. (*player)->GetInterface(player, SL_IID_ANDROIDSIMPLEBUFFERQUEUE, &bqItf)
    let p_bq_itf = GuestAddr::new(0x800C);
    cpu.set_reg(Reg::R0, player_obj);
    cpu.set_reg(Reg::R1, stub_base.add(0x620).as_u32()); // SL_IID_ANDROIDSIMPLEBUFFERQUEUE
    cpu.set_reg(Reg::R2, p_bq_itf.as_u32());
    audio
        .handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::SlObjectGetInterface as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), SL_RESULT_SUCCESS);
    let bq_itf = mem.read_u32(p_bq_itf).unwrap();
    assert_eq!(bq_itf, stub_base.add(0x1200).as_u32());

    // 5. (*player)->GetInterface(player, SL_IID_VOLUME, &volumeItf)
    let p_vol_itf = GuestAddr::new(0x8010);
    cpu.set_reg(Reg::R0, player_obj);
    cpu.set_reg(Reg::R1, stub_base.add(0x640).as_u32()); // SL_IID_VOLUME
    cpu.set_reg(Reg::R2, p_vol_itf.as_u32());
    audio
        .handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::SlObjectGetInterface as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), SL_RESULT_SUCCESS);
    let vol_itf = mem.read_u32(p_vol_itf).unwrap();
    assert_eq!(vol_itf, stub_base.add(0x1300).as_u32());

    // 6. Set play state to PLAYING
    cpu.set_reg(Reg::R0, play_itf);
    cpu.set_reg(Reg::R1, SL_PLAYSTATE_PLAYING);
    audio
        .handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::SlPlaySetPlayState as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(audio.play_state, SL_PLAYSTATE_PLAYING);

    // 7. Register BufferQueue callback
    let cb_addr = GuestAddr::new(0x9000);
    let cb_ctx = GuestAddr::new(0xAAAA_BBBB);
    cpu.set_reg(Reg::R0, bq_itf);
    cpu.set_reg(Reg::R1, cb_addr.as_u32());
    cpu.set_reg(Reg::R2, cb_ctx.as_u32());
    audio
        .handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::SlBqRegisterCallback as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(audio.callback_fn, cb_addr);
    assert_eq!(audio.callback_context, cb_ctx);
    assert!(audio.has_callback());

    // 8. Set volume to -1000 mB (-10 dB, gain ~0.316)
    cpu.set_reg(Reg::R0, vol_itf);
    cpu.set_reg(Reg::R1, (-1000i16) as u32);
    audio
        .handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::SlVolumeSetVolumeLevel as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(audio.volume_millibels, -1000);
    let mult = audio.volume_multiplier();
    assert!((mult - 0.3162).abs() < 0.01);

    // 9. Prepare 44.1 kHz stereo PCM in guest memory: 441 frames (882 samples = 1764 bytes)
    audio.set_format(AudioFormat {
        channels: 2,
        sample_rate_hz: 44100,
        bits_per_sample: 16,
    });

    let pcm_addr = GuestAddr::new(0xA000);
    let mut raw_bytes = Vec::with_capacity(1764);
    for _ in 0..441 {
        let left: i16 = 1000;
        let right: i16 = -1000;
        raw_bytes.extend_from_slice(&left.to_le_bytes());
        raw_bytes.extend_from_slice(&right.to_le_bytes());
    }
    mem.write_bytes(pcm_addr, &raw_bytes).unwrap();

    // 10. Enqueue buffer via OpenSL ES SVC
    cpu.set_reg(Reg::R0, bq_itf);
    cpu.set_reg(Reg::R1, pcm_addr.as_u32());
    cpu.set_reg(Reg::R2, raw_bytes.len() as u32);
    audio
        .handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::SlBqEnqueue as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), SL_RESULT_SUCCESS);
    assert_eq!(audio.queued_count(), 1);

    // 11. Verify ring buffer has ~480 resampled stereo frames at 48 kHz
    let avail = audio.available_frames();
    assert!((avail as i32 - 480).abs() <= 2);

    // 12. Read host frames and verify volume attenuation
    let mut host_out = vec![0i16; avail * 2];
    let frames_read = audio.read_host_frames(&mut host_out);
    assert_eq!(frames_read, avail);

    // 1000 * 0.3162 = ~316
    let first_left = host_out[0];
    let first_right = host_out[1];
    assert!((first_left - 316).abs() <= 10);
    assert!((first_right - (-316)).abs() <= 10);
}

#[test]
fn test_audio_aaudio_pipeline() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x20000);
    let stub_base = GuestAddr::new(0x2000);
    let mut audio = AudioBridge::with_stub_base(stub_base);
    audio.install_stubs(&mut mem).unwrap();

    let mut cpu = CpuState::new();

    // 1. AAudio_createStreamBuilder()
    audio
        .handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::AAudioCreateStreamBuilder as u32), &mut cpu, &mut mem)
        .unwrap();
    let builder = cpu.reg(Reg::R0);
    assert_eq!(builder, 1);

    // 2. Set sample rate to 22050 Hz
    cpu.set_reg(Reg::R0, builder);
    cpu.set_reg(Reg::R1, 22050);
    audio
        .handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::AAudioStreamBuilderSetSampleRate as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(audio.format.sample_rate_hz, 22050);

    // 3. Set channel count to 1 (mono)
    cpu.set_reg(Reg::R0, builder);
    cpu.set_reg(Reg::R1, 1);
    audio
        .handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::AAudioStreamBuilderSetChannelCount as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(audio.format.channels, 1);

    // 4. Open stream
    let p_stream = GuestAddr::new(0x5000);
    cpu.set_reg(Reg::R0, builder);
    cpu.set_reg(Reg::R1, p_stream.as_u32());
    audio
        .handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::AAudioStreamBuilderOpenStream as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    let stream_handle = mem.read_u32(p_stream).unwrap();
    assert_eq!(stream_handle, 1);

    // 5. Start stream
    cpu.set_reg(Reg::R0, stream_handle);
    audio
        .handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::AAudioStreamRequestStart as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(audio.play_state, SL_PLAYSTATE_PLAYING);

    // 6. Write 220 frames of mono 22.05 kHz PCM (220 samples = 440 bytes)
    let pcm_addr = GuestAddr::new(0x6000);
    let mut raw_bytes = Vec::with_capacity(440);
    for _ in 0..220 {
        let sample: i16 = 500;
        raw_bytes.extend_from_slice(&sample.to_le_bytes());
    }
    mem.write_bytes(pcm_addr, &raw_bytes).unwrap();

    cpu.set_reg(Reg::R0, stream_handle);
    cpu.set_reg(Reg::R1, pcm_addr.as_u32());
    cpu.set_reg(Reg::R2, 220); // 220 frames
    cpu.set_reg(Reg::R3, 0);   // timeout
    audio
        .handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::AAudioStreamWrite as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), 220);

    // Resampled to 48 kHz stereo: 220 * (48000 / 22050) = ~478 frames
    let avail = audio.available_frames();
    assert!((avail as i32 - 478).abs() <= 4);

    let mut host_out = vec![0i16; avail * 2];
    audio.read_host_frames(&mut host_out);

    // Both left and right channels should be ~500 (mono duplicated to stereo)
    assert!((host_out[0] - 500).abs() <= 5);
    assert!((host_out[1] - 500).abs() <= 5);

    // 7. Stop stream
    cpu.set_reg(Reg::R0, stream_handle);
    audio
        .handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::AAudioStreamRequestStop as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(audio.play_state, SL_PLAYSTATE_STOPPED);
}

#[test]
fn test_audio_underrun_and_silence_fill() {
    let mut audio = AudioBridge::new();
    assert_eq!(audio.available_frames(), 0);

    let mut out = [999i16; 32];
    let frames_read = audio.read_host_frames(&mut out);

    // 0 samples in buffer -> 0 frames read
    assert_eq!(frames_read, 0);
    // Entire output filled with silence (0)
    for &sample in &out {
        assert_eq!(sample, 0);
    }
    // Underrun counter incremented
    assert_eq!(audio.underrun_count(), 1);
}
