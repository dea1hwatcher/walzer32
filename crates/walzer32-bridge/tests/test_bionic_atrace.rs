//! Stage 76 integration tests: System Event Tracing & Android Trace
//! Tests: atrace_init, atrace_set_tracing_enabled, atrace_get_enabled_tags,
//!        atrace_begin_body, atrace_end_body, atrace_async_begin_body,
//!        atrace_async_end_body, atrace_int_body, atrace_int64_body,
//!        ATrace_beginSection, ATrace_endSection, ATrace_setCounter, ATrace_isEnabled

use walzer32_bridge::bionic::{AtraceEvent, BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use walzer32_core::{ArenaMemory, CpuState, GuestAddr, Memory, MemoryError, Reg};
use walzer32_elf::loader::SymbolResolver;

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
    mem.commit_range(heap_start, 0x0010_0000).expect("commit heap");

    let bridge = BionicBridge::new(stub_base, heap_start, 0x0010_0000);
    bridge.install_stubs(&mut mem).expect("stubs");

    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::SP, HEAP_START + 0x0008_0000);

    (bridge, mem, cpu)
}

fn write_str(mem: &mut impl Memory, addr: GuestAddr, s: &str) {
    let bytes = s.as_bytes();
    mem.write_bytes(addr, bytes).unwrap();
    mem.write_u8(addr.add(bytes.len() as u32), 0).unwrap();
}

#[test]
fn test_atrace_lifecycle_and_disabled_state() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // Init tracing
    call_bionic(&mut bridge, BionicFuncId::AtraceInit, &mut cpu, &mut mem).unwrap();
    assert!(!bridge.atrace_enabled);

    // When disabled, get_enabled_tags returns 0
    call_bionic(&mut bridge, BionicFuncId::AtraceGetEnabledTags, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(cpu.reg(Reg::R1), 0);

    // Call begin_body while disabled
    let str_addr = GuestAddr::new(HEAP_START + 0x1000);
    write_str(&mut mem, str_addr, "inactive_section");
    cpu.set_reg(Reg::R0, str_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AtraceBeginBody, &mut cpu, &mut mem).unwrap();
    call_bionic(&mut bridge, BionicFuncId::AtraceEndBody, &mut cpu, &mut mem).unwrap();

    // No events should be recorded
    assert!(bridge.atrace_events.is_empty());
}

#[test]
fn test_atrace_events_recording() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // Enable tracing
    cpu.set_reg(Reg::R0, 1);
    call_bionic(&mut bridge, BionicFuncId::AtraceSetTracingEnabled, &mut cpu, &mut mem).unwrap();
    assert!(bridge.atrace_enabled);

    // Enabled tags should now return 64-bit mask
    call_bionic(&mut bridge, BionicFuncId::AtraceGetEnabledTags, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0xFFFF_FFFF);
    assert_eq!(cpu.reg(Reg::R1), 0xFFFF_FFFF);

    let sec_addr = GuestAddr::new(HEAP_START + 0x2000);
    let async_addr = GuestAddr::new(HEAP_START + 0x2040);
    let fps_addr = GuestAddr::new(HEAP_START + 0x2080);
    let frame_ns_addr = GuestAddr::new(HEAP_START + 0x20C0);

    write_str(&mut mem, sec_addr, "render_frame");
    write_str(&mut mem, async_addr, "upload_texture");
    write_str(&mut mem, fps_addr, "fps");
    write_str(&mut mem, frame_ns_addr, "frame_time_ns");

    // 1. atrace_begin_body
    cpu.set_reg(Reg::R0, sec_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AtraceBeginBody, &mut cpu, &mut mem).unwrap();

    // 2. atrace_async_begin_body(name, 101)
    cpu.set_reg(Reg::R0, async_addr.as_u32());
    cpu.set_reg(Reg::R1, 101);
    call_bionic(&mut bridge, BionicFuncId::AtraceAsyncBeginBody, &mut cpu, &mut mem).unwrap();

    // 3. atrace_int_body(name, 60)
    cpu.set_reg(Reg::R0, fps_addr.as_u32());
    cpu.set_reg(Reg::R1, 60);
    call_bionic(&mut bridge, BionicFuncId::AtraceIntBody, &mut cpu, &mut mem).unwrap();

    // 4. atrace_int64_body(name, 16_666_666i64)
    let val_64: i64 = 16_666_666;
    let low = (val_64 as u64) as u32;
    let high = ((val_64 as u64) >> 32) as u32;
    cpu.set_reg(Reg::R0, frame_ns_addr.as_u32());
    cpu.set_reg(Reg::R1, 0); // padding
    cpu.set_reg(Reg::R2, low);
    cpu.set_reg(Reg::R3, high);
    call_bionic(&mut bridge, BionicFuncId::AtraceInt64Body, &mut cpu, &mut mem).unwrap();

    // 5. atrace_async_end_body(name, 101)
    cpu.set_reg(Reg::R0, async_addr.as_u32());
    cpu.set_reg(Reg::R1, 101);
    call_bionic(&mut bridge, BionicFuncId::AtraceAsyncEndBody, &mut cpu, &mut mem).unwrap();

    // 6. atrace_end_body
    call_bionic(&mut bridge, BionicFuncId::AtraceEndBody, &mut cpu, &mut mem).unwrap();

    // Verify events sequence
    assert_eq!(bridge.atrace_events.len(), 6);
    assert_eq!(bridge.atrace_events[0], AtraceEvent::Begin("render_frame".to_string()));
    assert_eq!(bridge.atrace_events[1], AtraceEvent::AsyncBegin("upload_texture".to_string(), 101));
    assert_eq!(bridge.atrace_events[2], AtraceEvent::Counter("fps".to_string(), 60));
    assert_eq!(bridge.atrace_events[3], AtraceEvent::Counter("frame_time_ns".to_string(), 16_666_666));
    assert_eq!(bridge.atrace_events[4], AtraceEvent::AsyncEnd("upload_texture".to_string(), 101));
    assert_eq!(bridge.atrace_events[5], AtraceEvent::End);

    // Disable tracing and check that no further events are recorded
    cpu.set_reg(Reg::R0, 0);
    call_bionic(&mut bridge, BionicFuncId::AtraceSetTracingEnabled, &mut cpu, &mut mem).unwrap();
    assert!(!bridge.atrace_enabled);

    cpu.set_reg(Reg::R0, sec_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AtraceBeginBody, &mut cpu, &mut mem).unwrap();
    assert_eq!(bridge.atrace_events.len(), 6);
}

#[test]
fn test_atrace_symbol_resolution() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "atrace_begin_body",
        "atrace_end_body",
        "atrace_async_begin_body",
        "atrace_async_end_body",
        "atrace_set_tracing_enabled",
        "atrace_init",
        "atrace_int_body",
        "atrace_int64_body",
        "atrace_get_enabled_tags",
        "ATrace_beginSection",
        "ATrace_endSection",
        "ATrace_setCounter",
        "ATrace_isEnabled",
    ];

    for sym in symbols {
        let addr = bridge.resolve(sym);
        assert!(addr.is_some(), "Symbol {} must be resolved", sym);
        assert_ne!(addr.unwrap().as_u32(), 0);
    }
}
