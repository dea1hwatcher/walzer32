//! Stage 94 integration tests: Android Looper & Choreographer NDK APIs
//! Tests: ALooper_forThread, ALooper_prepare, ALooper_acquire, ALooper_release,
//!        ALooper_pollOnce, ALooper_pollAll, ALooper_wake, ALooper_addFd, ALooper_removeFd,
//!        AChoreographer_getInstance, AChoreographer_postFrameCallback,
//!        AChoreographer_postFrameCallbackDelayed, AChoreographer_postFrameCallback64,
//!        AChoreographer_postFrameCallbackDelayed64, AChoreographer_registerRefreshRateCallback,
//!        AChoreographer_unregisterRefreshRateCallback

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
    mem.commit_range(heap_start, 0x0010_0000).expect("commit heap");

    let bridge = BionicBridge::new(stub_base, heap_start, 0x0010_0000);
    bridge.install_stubs(&mut mem).expect("stubs");

    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::SP, HEAP_START + 0x0008_0000);

    (bridge, mem, cpu)
}

#[test]
fn test_looper_and_choreographer_symbols() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "ALooper_forThread",
        "ALooper_prepare",
        "ALooper_acquire",
        "ALooper_release",
        "ALooper_pollOnce",
        "ALooper_pollAll",
        "ALooper_wake",
        "ALooper_addFd",
        "ALooper_removeFd",
        "AChoreographer_getInstance",
        "AChoreographer_postFrameCallback",
        "AChoreographer_postFrameCallbackDelayed",
        "AChoreographer_postFrameCallback64",
        "AChoreographer_postFrameCallbackDelayed64",
        "AChoreographer_registerRefreshRateCallback",
        "AChoreographer_unregisterRefreshRateCallback",
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
fn test_looper_lifecycle_and_wake() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. ALooper_forThread() before prepare -> returns 0 (NULL)
    call_bionic(&mut bridge, BionicFuncId::ALooperForThread, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 2. ALooper_prepare(opts=1) -> returns valid looper handle
    cpu.set_reg(Reg::R0, 1); // ALOOPER_PREPARE_ALLOW_NON_CALLBACKS
    call_bionic(&mut bridge, BionicFuncId::ALooperPrepare, &mut cpu, &mut mem).unwrap();
    let looper = cpu.reg(Reg::R0);
    assert_ne!(looper, 0);

    // 3. ALooper_forThread() now returns the same handle
    call_bionic(&mut bridge, BionicFuncId::ALooperForThread, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), looper);

    // 4. ALooper_pollOnce(timeout=0) with no events -> ALOOPER_POLL_TIMEOUT (-3)
    cpu.set_reg(Reg::R0, 0); // timeout 0
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 0);
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::ALooperPollOnce, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, -3);

    // 5. ALooper_wake(looper)
    cpu.set_reg(Reg::R0, looper);
    call_bionic(&mut bridge, BionicFuncId::ALooperWake, &mut cpu, &mut mem).unwrap();

    // 6. ALooper_pollOnce(timeout=1000) -> ALOOPER_POLL_WAKE (-1)
    cpu.set_reg(Reg::R0, 1000);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 0);
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::ALooperPollOnce, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, -1);

    // Subsequent poll -> woken cleared, returns timeout
    cpu.set_reg(Reg::R0, 0);
    call_bionic(&mut bridge, BionicFuncId::ALooperPollOnce, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, -3);

    // 7. ALooper_acquire and ALooper_release
    cpu.set_reg(Reg::R0, looper);
    call_bionic(&mut bridge, BionicFuncId::ALooperAcquire, &mut cpu, &mut mem).unwrap();
    assert_eq!(bridge.loopers.get(&1).unwrap().refcount, 2);

    cpu.set_reg(Reg::R0, looper);
    call_bionic(&mut bridge, BionicFuncId::ALooperRelease, &mut cpu, &mut mem).unwrap();
    assert_eq!(bridge.loopers.get(&1).unwrap().refcount, 1);

    cpu.set_reg(Reg::R0, looper);
    call_bionic(&mut bridge, BionicFuncId::ALooperRelease, &mut cpu, &mut mem).unwrap();
    assert!(bridge.loopers.get(&1).is_none());

    // After release refcount 0 -> looper destroyed
    call_bionic(&mut bridge, BionicFuncId::ALooperForThread, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_looper_fd_registration_and_poll() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // Prepare looper
    cpu.set_reg(Reg::R0, 1);
    call_bionic(&mut bridge, BionicFuncId::ALooperPrepare, &mut cpu, &mut mem).unwrap();
    let looper = cpu.reg(Reg::R0);

    // Setup stack for 5th (callback) and 6th (data) arguments
    let sp_addr = GuestAddr::new(HEAP_START + 0x0008_0000);
    mem.write_u32(sp_addr, 0).unwrap(); // callback = 0 (ident returned by poll)
    mem.write_u32(sp_addr.add(4), 0xCAFE_BABE).unwrap(); // data
    cpu.set_reg(Reg::SP, sp_addr.as_u32());

    // ALooper_addFd(looper, fd=10, ident=99, events=1, callback=NULL, data=0xCAFEBABE)
    cpu.set_reg(Reg::R0, looper);
    cpu.set_reg(Reg::R1, 10); // fd
    cpu.set_reg(Reg::R2, 99); // ident
    cpu.set_reg(Reg::R3, 1);  // ALOOPER_EVENT_INPUT
    call_bionic(&mut bridge, BionicFuncId::ALooperAddFd, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    // Memory for out parameters
    let out_fd = GuestAddr::new(HEAP_START + 0x0100);
    let out_events = GuestAddr::new(HEAP_START + 0x0104);
    let out_data = GuestAddr::new(HEAP_START + 0x0108);

    // ALooper_pollOnce(timeout=100, outFd, outEvents, outData)
    cpu.set_reg(Reg::R0, 100);
    cpu.set_reg(Reg::R1, out_fd.as_u32());
    cpu.set_reg(Reg::R2, out_events.as_u32());
    cpu.set_reg(Reg::R3, out_data.as_u32());
    call_bionic(&mut bridge, BionicFuncId::ALooperPollOnce, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, 99); // ident returned

    assert_eq!(mem.read_u32(out_fd).unwrap(), 10);
    assert_eq!(mem.read_u32(out_events).unwrap(), 1);
    assert_eq!(mem.read_u32(out_data).unwrap(), 0xCAFE_BABE);

    // ALooper_removeFd(looper, fd=10)
    cpu.set_reg(Reg::R0, looper);
    cpu.set_reg(Reg::R1, 10);
    call_bionic(&mut bridge, BionicFuncId::ALooperRemoveFd, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    // Second remove -> returns 0
    cpu.set_reg(Reg::R0, looper);
    cpu.set_reg(Reg::R1, 10);
    call_bionic(&mut bridge, BionicFuncId::ALooperRemoveFd, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_choreographer_lifecycle_and_callbacks() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. AChoreographer_getInstance()
    call_bionic(&mut bridge, BionicFuncId::AChoreographerGetInstance, &mut cpu, &mut mem).unwrap();
    let choreo = cpu.reg(Reg::R0);
    assert_ne!(choreo, 0);

    // 2. AChoreographer_postFrameCallback
    cpu.set_reg(Reg::R0, choreo);
    cpu.set_reg(Reg::R1, 0x1000); // callback
    cpu.set_reg(Reg::R2, 0x2000); // data
    call_bionic(&mut bridge, BionicFuncId::AChoreographerPostFrameCallback, &mut cpu, &mut mem).unwrap();

    // 3. AChoreographer_postFrameCallbackDelayed
    cpu.set_reg(Reg::R0, choreo);
    cpu.set_reg(Reg::R1, 0x1004);
    cpu.set_reg(Reg::R2, 0x2004);
    cpu.set_reg(Reg::R3, 16); // delayMillis
    call_bionic(&mut bridge, BionicFuncId::AChoreographerPostFrameCallbackDelayed, &mut cpu, &mut mem).unwrap();

    // 4. AChoreographer_postFrameCallback64
    cpu.set_reg(Reg::R0, choreo);
    cpu.set_reg(Reg::R1, 0x1008);
    cpu.set_reg(Reg::R2, 0x2008);
    call_bionic(&mut bridge, BionicFuncId::AChoreographerPostFrameCallback64, &mut cpu, &mut mem).unwrap();

    // 5. AChoreographer_postFrameCallbackDelayed64
    cpu.set_reg(Reg::R0, choreo);
    cpu.set_reg(Reg::R1, 0x100C);
    cpu.set_reg(Reg::R2, 0x200C);
    cpu.set_reg(Reg::R3, 33);
    call_bionic(&mut bridge, BionicFuncId::AChoreographerPostFrameCallbackDelayed64, &mut cpu, &mut mem).unwrap();

    assert_eq!(bridge.choreo_callbacks.len(), 4);

    let drained = bridge.drain_choreographer_callbacks();
    assert_eq!(drained.len(), 4);
    assert_eq!(bridge.choreo_callbacks.len(), 0);

    assert_eq!(drained[0].callback, 0x1000);
    assert_eq!(drained[0].data, 0x2000);
    assert!(!drained[0].is_64);
    assert_eq!(drained[0].delay_ms, 0);

    assert_eq!(drained[1].callback, 0x1004);
    assert_eq!(drained[1].data, 0x2004);
    assert!(!drained[1].is_64);
    assert_eq!(drained[1].delay_ms, 16);

    assert_eq!(drained[2].callback, 0x1008);
    assert_eq!(drained[2].data, 0x2008);
    assert!(drained[2].is_64);
    assert_eq!(drained[2].delay_ms, 0);

    assert_eq!(drained[3].callback, 0x100C);
    assert_eq!(drained[3].data, 0x200C);
    assert!(drained[3].is_64);
    assert_eq!(drained[3].delay_ms, 33);

    // 6. Refresh rate callbacks
    cpu.set_reg(Reg::R0, choreo);
    cpu.set_reg(Reg::R1, 0x3000);
    cpu.set_reg(Reg::R2, 0x4000);
    call_bionic(&mut bridge, BionicFuncId::AChoreographerRegisterRefreshRateCallback, &mut cpu, &mut mem).unwrap();
    assert_eq!(bridge.choreo_refresh_callbacks.len(), 1);

    // Duplicate is idempotent
    call_bionic(&mut bridge, BionicFuncId::AChoreographerRegisterRefreshRateCallback, &mut cpu, &mut mem).unwrap();
    assert_eq!(bridge.choreo_refresh_callbacks.len(), 1);

    // Unregister
    call_bionic(&mut bridge, BionicFuncId::AChoreographerUnregisterRefreshRateCallback, &mut cpu, &mut mem).unwrap();
    assert_eq!(bridge.choreo_refresh_callbacks.len(), 0);
}
