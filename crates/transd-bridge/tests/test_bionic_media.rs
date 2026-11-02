//! Stage 100 integration tests: Android Media NDK Subsystem (libmediandk.so)
//! Tests: AMediaFormat (new/delete/set/get/toString),
//!        AMediaCodec (create/delete/configure/start/stop/flush/buffers)

use transd_bridge::bionic::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use transd_core::{ArenaMemory, CpuState, GuestAddr, Memory, MemoryError, Reg};
use transd_elf::loader::SymbolResolver;

const STUB_BASE: u32 = 0x0001_0000;
const HEAP_START: u32 = 0x0002_0000;

fn call_bionic(
    bridge: &mut BionicBridge,
    func_id: BionicFuncId,
    cpu: &mut CpuState,
    mem: &mut impl Memory,
) -> Result<bool, MemoryError> {
    bridge.handle_svc(BIONIC_SVC_MAGIC | (func_id as u32), cpu, mem)
}

fn setup() -> (BionicBridge, ArenaMemory, CpuState) {
    let mut mem = ArenaMemory::new().expect("arena");
    let stub_base = GuestAddr::new(STUB_BASE);
    let heap_start = GuestAddr::new(HEAP_START);

    mem.commit_range(stub_base, 0x0008_0000).expect("commit stub");
    mem.commit_range(heap_start, 0x0030_0000).expect("commit heap");

    let bridge = BionicBridge::new(stub_base, heap_start, 0x0030_0000);
    bridge.install_stubs(&mut mem).expect("stubs");

    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::SP, HEAP_START + 0x0028_0000);

    (bridge, mem, cpu)
}

#[test]
fn test_media_symbols() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "AMediaFormat_new",
        "AMediaFormat_delete",
        "AMediaFormat_setString",
        "AMediaFormat_getString",
        "AMediaFormat_setInt32",
        "AMediaFormat_getInt32",
        "AMediaFormat_setInt64",
        "AMediaFormat_getInt64",
        "AMediaFormat_setFloat",
        "AMediaFormat_getFloat",
        "AMediaFormat_toString",
        "AMediaCodec_createDecoderByType",
        "AMediaCodec_createEncoderByType",
        "AMediaCodec_createCodecByName",
        "AMediaCodec_delete",
        "AMediaCodec_configure",
        "AMediaCodec_start",
        "AMediaCodec_stop",
        "AMediaCodec_flush",
        "AMediaCodec_dequeueInputBuffer",
        "AMediaCodec_getInputBuffer",
        "AMediaCodec_queueInputBuffer",
        "AMediaCodec_dequeueOutputBuffer",
        "AMediaCodec_getOutputBuffer",
        "AMediaCodec_releaseOutputBuffer",
        "AMediaCodec_getOutputFormat",
    ];

    for sym in symbols {
        assert!(
            bridge.resolve(sym).is_some(),
            "Symbol {} not resolved by BionicBridge",
            sym
        );
    }
}

#[test]
fn test_media_format_get_set() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. AMediaFormat_new()
    call_bionic(&mut bridge, BionicFuncId::AMediaFormatNew, &mut cpu, &mut mem).unwrap();
    let fmt = cpu.reg(Reg::R0);
    assert_ne!(fmt, 0);

    // 2. setString("mime", "video/avc")
    let key_mime = GuestAddr::new(HEAP_START + 0x0100);
    let val_mime = GuestAddr::new(HEAP_START + 0x0150);
    mem.write_bytes(key_mime, b"mime\0").unwrap();
    mem.write_bytes(val_mime, b"video/avc\0").unwrap();

    cpu.set_reg(Reg::R0, fmt);
    cpu.set_reg(Reg::R1, key_mime.as_u32());
    cpu.set_reg(Reg::R2, val_mime.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AMediaFormatSetString, &mut cpu, &mut mem).unwrap();

    // getString("mime", &out_str)
    let out_str_ptr = GuestAddr::new(HEAP_START + 0x0200);
    cpu.set_reg(Reg::R0, fmt);
    cpu.set_reg(Reg::R1, key_mime.as_u32());
    cpu.set_reg(Reg::R2, out_str_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AMediaFormatGetString, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1); // found = true

    let resolved_str_addr = GuestAddr::new(mem.read_u32(out_str_ptr).unwrap());
    let mut resolved_str = [0u8; 9];
    mem.read_bytes(resolved_str_addr, &mut resolved_str).unwrap();
    assert_eq!(&resolved_str, b"video/avc");

    // 3. setInt32 / getInt32 ("width" -> 1920)
    let key_width = GuestAddr::new(HEAP_START + 0x0250);
    mem.write_bytes(key_width, b"width\0").unwrap();
    cpu.set_reg(Reg::R0, fmt);
    cpu.set_reg(Reg::R1, key_width.as_u32());
    cpu.set_reg(Reg::R2, 1920);
    call_bionic(&mut bridge, BionicFuncId::AMediaFormatSetInt32, &mut cpu, &mut mem).unwrap();

    let out_i32 = GuestAddr::new(HEAP_START + 0x0300);
    cpu.set_reg(Reg::R0, fmt);
    cpu.set_reg(Reg::R1, key_width.as_u32());
    cpu.set_reg(Reg::R2, out_i32.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AMediaFormatGetInt32, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);
    assert_eq!(mem.read_u32(out_i32).unwrap(), 1920);

    // 4. setInt64 / getInt64 ("durationUs" -> 5_000_000_000)
    let key_dur = GuestAddr::new(HEAP_START + 0x0350);
    mem.write_bytes(key_dur, b"durationUs\0").unwrap();

    let dur_val: i64 = 5_000_000_000;
    let sp_addr = GuestAddr::new(HEAP_START + 0x0028_0000);
    mem.write_u32(sp_addr, dur_val as u32).unwrap();
    mem.write_u32(sp_addr.add(4), (dur_val >> 32) as u32).unwrap();
    cpu.set_reg(Reg::SP, sp_addr.as_u32());

    cpu.set_reg(Reg::R0, fmt);
    cpu.set_reg(Reg::R1, key_dur.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AMediaFormatSetInt64, &mut cpu, &mut mem).unwrap();

    let out_i64 = GuestAddr::new(HEAP_START + 0x0400);
    cpu.set_reg(Reg::R0, fmt);
    cpu.set_reg(Reg::R1, key_dur.as_u32());
    cpu.set_reg(Reg::R2, out_i64.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AMediaFormatGetInt64, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);
    let low = mem.read_u32(out_i64).unwrap() as u64;
    let high = mem.read_u32(out_i64.add(4)).unwrap() as u64;
    assert_eq!((low | (high << 32)) as i64, 5_000_000_000);

    // 5. setFloat / getFloat ("frame-rate" -> 60.0)
    let key_fps = GuestAddr::new(HEAP_START + 0x0450);
    mem.write_bytes(key_fps, b"frame-rate\0").unwrap();
    cpu.set_reg(Reg::R0, fmt);
    cpu.set_reg(Reg::R1, key_fps.as_u32());
    cpu.set_s_reg(0, 60.0);
    call_bionic(&mut bridge, BionicFuncId::AMediaFormatSetFloat, &mut cpu, &mut mem).unwrap();

    let out_f32 = GuestAddr::new(HEAP_START + 0x0500);
    cpu.set_reg(Reg::R0, fmt);
    cpu.set_reg(Reg::R1, key_fps.as_u32());
    cpu.set_reg(Reg::R2, out_f32.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AMediaFormatGetFloat, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);
    let read_fps = f32::from_bits(mem.read_u32(out_f32).unwrap());
    assert!((read_fps - 60.0).abs() < 1e-6);

    // 6. AMediaFormat_toString(fmt)
    cpu.set_reg(Reg::R0, fmt);
    call_bionic(&mut bridge, BionicFuncId::AMediaFormatToString, &mut cpu, &mut mem).unwrap();
    let debug_ptr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(debug_ptr.as_u32(), 0);

    // 7. AMediaFormat_delete(fmt)
    cpu.set_reg(Reg::R0, fmt);
    call_bionic(&mut bridge, BionicFuncId::AMediaFormatDelete, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert!(bridge.media_formats.get(&fmt).is_none());
}

#[test]
fn test_media_codec_lifecycle_and_buffers() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. Create decoder for "video/avc"
    let mime_addr = GuestAddr::new(HEAP_START + 0x0100);
    mem.write_bytes(mime_addr, b"video/avc\0").unwrap();
    cpu.set_reg(Reg::R0, mime_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AMediaCodecCreateDecoderByType, &mut cpu, &mut mem).unwrap();
    let codec = cpu.reg(Reg::R0);
    assert_ne!(codec, 0);

    // 2. Create and configure format
    call_bionic(&mut bridge, BionicFuncId::AMediaFormatNew, &mut cpu, &mut mem).unwrap();
    let fmt = cpu.reg(Reg::R0);

    cpu.set_reg(Reg::R0, codec);
    cpu.set_reg(Reg::R1, fmt);
    cpu.set_reg(Reg::R2, 0); // surface
    cpu.set_reg(Reg::R3, 0); // crypto
    call_bionic(&mut bridge, BionicFuncId::AMediaCodecConfigure, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0); // AMEDIA_OK

    // 3. Start codec
    cpu.set_reg(Reg::R0, codec);
    call_bionic(&mut bridge, BionicFuncId::AMediaCodecStart, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert!(bridge.media_codecs.get(&codec).unwrap().is_started);

    // 4. Dequeue input buffer
    cpu.set_reg(Reg::R0, codec);
    cpu.set_reg(Reg::R1, 0); // timeoutUs
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::AMediaCodecDequeueInputBuffer, &mut cpu, &mut mem).unwrap();
    let in_idx = cpu.reg(Reg::R0);
    assert_eq!(in_idx, 0);

    // 5. Get input buffer pointer
    let out_size_ptr = GuestAddr::new(HEAP_START + 0x0200);
    cpu.set_reg(Reg::R0, codec);
    cpu.set_reg(Reg::R1, in_idx);
    cpu.set_reg(Reg::R2, out_size_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AMediaCodecGetInputBuffer, &mut cpu, &mut mem).unwrap();
    let in_buf = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(in_buf.as_u32(), 0);
    assert_eq!(mem.read_u32(out_size_ptr).unwrap(), 65536);

    // Write mock NAL unit [0x00, 0x00, 0x00, 0x01, 0x67, ...]
    let mock_nal: [u8; 8] = [0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1E];
    mem.write_bytes(in_buf, &mock_nal).unwrap();

    // 6. Queue input buffer with presentation time 33333 us (first frame of 30fps)
    let sp_addr = GuestAddr::new(HEAP_START + 0x0028_0000);
    let pts: i64 = 33333;
    mem.write_u32(sp_addr, pts as u32).unwrap();
    mem.write_u32(sp_addr.add(4), 0).unwrap();
    mem.write_u32(sp_addr.add(8), 1).unwrap(); // flags = 1 (BUFFER_FLAG_KEY_FRAME)
    cpu.set_reg(Reg::SP, sp_addr.as_u32());

    cpu.set_reg(Reg::R0, codec);
    cpu.set_reg(Reg::R1, in_idx);
    cpu.set_reg(Reg::R2, 0); // offset
    cpu.set_reg(Reg::R3, 8); // size
    call_bionic(&mut bridge, BionicFuncId::AMediaCodecQueueInputBuffer, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 7. Dequeue output buffer
    let info_ptr = GuestAddr::new(HEAP_START + 0x0300);
    cpu.set_reg(Reg::R0, codec);
    cpu.set_reg(Reg::R1, info_ptr.as_u32());
    cpu.set_reg(Reg::R2, 0); // timeoutUs
    call_bionic(&mut bridge, BionicFuncId::AMediaCodecDequeueOutputBuffer, &mut cpu, &mut mem).unwrap();
    let out_idx = cpu.reg(Reg::R0);
    assert_eq!(out_idx, 0);

    // Verify AMediaCodecBufferInfo
    assert_eq!(mem.read_u32(info_ptr).unwrap(), 0); // offset
    assert_eq!(mem.read_u32(info_ptr.add(4)).unwrap(), 8); // size
    assert_eq!(mem.read_u32(info_ptr.add(8)).unwrap(), 33333); // time low
    assert_eq!(mem.read_u32(info_ptr.add(16)).unwrap(), 1); // flags

    // 8. Get output buffer
    cpu.set_reg(Reg::R0, codec);
    cpu.set_reg(Reg::R1, out_idx);
    cpu.set_reg(Reg::R2, out_size_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AMediaCodecGetOutputBuffer, &mut cpu, &mut mem).unwrap();
    let out_buf = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(out_buf.as_u32(), 0);

    // 9. Release output buffer
    cpu.set_reg(Reg::R0, codec);
    cpu.set_reg(Reg::R1, out_idx);
    cpu.set_reg(Reg::R2, 1); // render = true
    call_bionic(&mut bridge, BionicFuncId::AMediaCodecReleaseOutputBuffer, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 10. Stop and delete codec
    cpu.set_reg(Reg::R0, codec);
    call_bionic(&mut bridge, BionicFuncId::AMediaCodecStop, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, codec);
    call_bionic(&mut bridge, BionicFuncId::AMediaCodecDelete, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert!(bridge.media_codecs.get(&codec).is_none());
}
