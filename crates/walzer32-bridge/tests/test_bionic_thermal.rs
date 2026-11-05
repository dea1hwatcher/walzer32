//! Stage 93 integration tests: Android Thermal & Performance NDK APIs (ADPF)
//! Tests: AThermal_acquireManager, AThermal_releaseManager, AThermal_getCurrentThermalStatus,
//!        AThermal_registerThermalStatusListener, AThermal_unregisterThermalStatusListener,
//!        AThermal_getThermalHeadroom, APerformanceHint_getManager, APerformanceHint_createSession,
//!        APerformanceHint_updateTargetWorkDuration, APerformanceHint_reportActualWorkDuration,
//!        APerformanceHint_closeSession

use walzer32_bridge::bionic::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
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

#[test]
fn test_thermal_and_perf_symbols() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "AThermal_acquireManager",
        "AThermal_releaseManager",
        "AThermal_getCurrentThermalStatus",
        "AThermal_registerThermalStatusListener",
        "AThermal_unregisterThermalStatusListener",
        "AThermal_getThermalHeadroom",
        "APerformanceHint_getManager",
        "APerformanceHint_createSession",
        "APerformanceHint_updateTargetWorkDuration",
        "APerformanceHint_reportActualWorkDuration",
        "APerformanceHint_closeSession",
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
fn test_thermal_manager_lifecycle_and_status() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. Status before acquire -> returns ATHERMAL_STATUS_ERROR (-1)
    cpu.set_reg(Reg::R0, 0x7000_1000);
    call_bionic(&mut bridge, BionicFuncId::AThermalGetCurrentThermalStatus, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, -1);

    // 2. AThermal_acquireManager()
    call_bionic(&mut bridge, BionicFuncId::AThermalAcquireManager, &mut cpu, &mut mem).unwrap();
    let mgr = cpu.reg(Reg::R0);
    assert_ne!(mgr, 0);

    // 3. Default status is 0 (ATHERMAL_STATUS_NONE)
    cpu.set_reg(Reg::R0, mgr);
    call_bionic(&mut bridge, BionicFuncId::AThermalGetCurrentThermalStatus, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 4. Update status on bridge to 3 (ATHERMAL_STATUS_SEVERE)
    bridge.set_thermal_status(3);
    cpu.set_reg(Reg::R0, mgr);
    call_bionic(&mut bridge, BionicFuncId::AThermalGetCurrentThermalStatus, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 3);

    // 5. AThermal_releaseManager(mgr)
    cpu.set_reg(Reg::R0, mgr);
    call_bionic(&mut bridge, BionicFuncId::AThermalReleaseManager, &mut cpu, &mut mem).unwrap();

    // After release, manager is no longer active -> returns -1
    cpu.set_reg(Reg::R0, mgr);
    call_bionic(&mut bridge, BionicFuncId::AThermalGetCurrentThermalStatus, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, -1);
}

#[test]
fn test_thermal_listeners_and_headroom() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // Acquire manager
    call_bionic(&mut bridge, BionicFuncId::AThermalAcquireManager, &mut cpu, &mut mem).unwrap();
    let mgr = cpu.reg(Reg::R0);

    // Register callback
    let cb_addr = 0x0002_5000;
    let data_addr = 0x0002_6000;
    cpu.set_reg(Reg::R0, mgr);
    cpu.set_reg(Reg::R1, cb_addr);
    cpu.set_reg(Reg::R2, data_addr);
    call_bionic(&mut bridge, BionicFuncId::AThermalRegisterThermalStatusListener, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(bridge.thermal_listeners.len(), 1);

    // Duplicate registration should be idempotent
    cpu.set_reg(Reg::R0, mgr);
    cpu.set_reg(Reg::R1, cb_addr);
    cpu.set_reg(Reg::R2, data_addr);
    call_bionic(&mut bridge, BionicFuncId::AThermalRegisterThermalStatusListener, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(bridge.thermal_listeners.len(), 1);

    // Unregister callback
    cpu.set_reg(Reg::R0, mgr);
    cpu.set_reg(Reg::R1, cb_addr);
    cpu.set_reg(Reg::R2, data_addr);
    call_bionic(&mut bridge, BionicFuncId::AThermalUnregisterThermalStatusListener, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(bridge.thermal_listeners.len(), 0);

    // Unregister nonexistent -> returns -22 (-EINVAL)
    cpu.set_reg(Reg::R0, mgr);
    cpu.set_reg(Reg::R1, cb_addr);
    cpu.set_reg(Reg::R2, data_addr);
    call_bionic(&mut bridge, BionicFuncId::AThermalUnregisterThermalStatusListener, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, -22);

    // Headroom test: valid forecast seconds 0..60
    bridge.set_thermal_headroom(0.75);
    cpu.set_reg(Reg::R0, mgr);
    cpu.set_reg(Reg::R1, 10); // forecast 10s
    call_bionic(&mut bridge, BionicFuncId::AThermalGetThermalHeadroom, &mut cpu, &mut mem).unwrap();
    let headroom = f32::from_bits(cpu.reg(Reg::R0));
    assert!((headroom - 0.75).abs() < 1e-6);
    assert!((cpu.s_reg(0) - 0.75).abs() < 1e-6);

    // Invalid forecast seconds (> 60) -> returns NaN
    cpu.set_reg(Reg::R0, mgr);
    cpu.set_reg(Reg::R1, 65);
    call_bionic(&mut bridge, BionicFuncId::AThermalGetThermalHeadroom, &mut cpu, &mut mem).unwrap();
    let nan_val = f32::from_bits(cpu.reg(Reg::R0));
    assert!(nan_val.is_nan());
}

#[test]
fn test_performance_hint_session_lifecycle() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. APerformanceHint_getManager()
    call_bionic(&mut bridge, BionicFuncId::APerformanceHintGetManager, &mut cpu, &mut mem).unwrap();
    let mgr = cpu.reg(Reg::R0);
    assert_ne!(mgr, 0);

    // 2. Prepare thread IDs [201, 202] in guest memory
    let tids_addr = GuestAddr::new(HEAP_START + 0x0100);
    mem.write_u32(tids_addr, 201).unwrap();
    mem.write_u32(tids_addr.add(4), 202).unwrap();

    // Setup stack for 64-bit target duration = 16_666_666 ns (~16.6ms for 60fps)
    let sp_addr = GuestAddr::new(HEAP_START + 0x0008_0000);
    let target_ns: i64 = 16_666_666;
    mem.write_u32(sp_addr, target_ns as u32).unwrap();
    mem.write_u32(sp_addr.add(4), (target_ns >> 32) as u32).unwrap();
    cpu.set_reg(Reg::SP, sp_addr.as_u32());

    // 3. APerformanceHint_createSession(mgr, tids, size=2, target_duration)
    cpu.set_reg(Reg::R0, mgr);
    cpu.set_reg(Reg::R1, tids_addr.as_u32());
    cpu.set_reg(Reg::R2, 2);
    call_bionic(&mut bridge, BionicFuncId::APerformanceHintCreateSession, &mut cpu, &mut mem).unwrap();
    let session = cpu.reg(Reg::R0);
    assert_ne!(session, 0);

    let session_data = bridge.perf_sessions.get(&session).expect("session exists");
    assert_eq!(session_data.thread_ids, vec![201, 202]);
    assert_eq!(session_data.target_duration_ns, 16_666_666);

    // 4. APerformanceHint_updateTargetWorkDuration(session, target=8_333_333 ns for 120fps)
    // AAPCS: R0 = session, R1 = padding, R2 = low 32, R3 = high 32
    let new_target_ns: i64 = 8_333_333;
    cpu.set_reg(Reg::R0, session);
    cpu.set_reg(Reg::R1, 0); // padding
    cpu.set_reg(Reg::R2, new_target_ns as u32);
    cpu.set_reg(Reg::R3, (new_target_ns >> 32) as u32);
    call_bionic(&mut bridge, BionicFuncId::APerformanceHintUpdateTargetWorkDuration, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(bridge.perf_sessions.get(&session).unwrap().target_duration_ns, 8_333_333);

    // 5. APerformanceHint_reportActualWorkDuration(session, actual=8_100_000 ns)
    let actual_ns: i64 = 8_100_000;
    cpu.set_reg(Reg::R0, session);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, actual_ns as u32);
    cpu.set_reg(Reg::R3, (actual_ns >> 32) as u32);
    call_bionic(&mut bridge, BionicFuncId::APerformanceHintReportActualWorkDuration, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(bridge.perf_sessions.get(&session).unwrap().actual_duration_ns, 8_100_000);

    // 6. APerformanceHint_closeSession(session)
    cpu.set_reg(Reg::R0, session);
    call_bionic(&mut bridge, BionicFuncId::APerformanceHintCloseSession, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert!(bridge.perf_sessions.get(&session).is_none());

    // Calling update on closed session -> returns -22 (-EINVAL)
    cpu.set_reg(Reg::R0, session);
    cpu.set_reg(Reg::R2, 1000);
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::APerformanceHintUpdateTargetWorkDuration, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, -22);
}
