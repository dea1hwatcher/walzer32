//! Stage 85 integration tests: Android Native Window (ANativeWindow) NDK APIs
//! Tests: ANativeWindow_acquire, ANativeWindow_release, ANativeWindow_getWidth,
//!        ANativeWindow_getHeight, ANativeWindow_getFormat,
//!        ANativeWindow_setBuffersGeometry, ANativeWindow_lock, ANativeWindow_unlockAndPost

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
fn test_anativewindow_dimensions_and_format() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // Default dimensions: 1920x1080, format: 1 (RGBA_8888)
    cpu.set_reg(Reg::R0, 0x3000_0001); // dummy window pointer
    call_bionic(&mut bridge, BionicFuncId::ANativeWindowGetWidth, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1920);

    cpu.set_reg(Reg::R0, 0x3000_0001);
    call_bionic(&mut bridge, BionicFuncId::ANativeWindowGetHeight, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1080);

    cpu.set_reg(Reg::R0, 0x3000_0001);
    call_bionic(&mut bridge, BionicFuncId::ANativeWindowGetFormat, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    // setBuffersGeometry(window, 1280, 720, 4)
    cpu.set_reg(Reg::R0, 0x3000_0001);
    cpu.set_reg(Reg::R1, 1280);
    cpu.set_reg(Reg::R2, 720);
    cpu.set_reg(Reg::R3, 4); // WINDOW_FORMAT_RGBX_8888
    call_bionic(&mut bridge, BionicFuncId::ANativeWindowSetBuffersGeometry, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Verify updated dimensions
    cpu.set_reg(Reg::R0, 0x3000_0001);
    call_bionic(&mut bridge, BionicFuncId::ANativeWindowGetWidth, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1280);

    cpu.set_reg(Reg::R0, 0x3000_0001);
    call_bionic(&mut bridge, BionicFuncId::ANativeWindowGetHeight, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 720);

    cpu.set_reg(Reg::R0, 0x3000_0001);
    call_bionic(&mut bridge, BionicFuncId::ANativeWindowGetFormat, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 4);
}

#[test]
fn test_anativewindow_lock_unlock() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let buf_addr = GuestAddr::new(HEAP_START + 0x1000);

    // acquire & release
    cpu.set_reg(Reg::R0, 0x3000_0001);
    call_bionic(&mut bridge, BionicFuncId::ANativeWindowAcquire, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 0x3000_0001);
    call_bionic(&mut bridge, BionicFuncId::ANativeWindowRelease, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // lock window
    cpu.set_reg(Reg::R0, 0x3000_0001);
    cpu.set_reg(Reg::R1, buf_addr.as_u32());
    cpu.set_reg(Reg::R2, 0); // bounds = NULL
    call_bionic(&mut bridge, BionicFuncId::ANativeWindowLock, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Verify ANativeWindow_Buffer fields
    let width = mem.read_u32(buf_addr).unwrap();
    let height = mem.read_u32(buf_addr.add(4)).unwrap();
    let stride = mem.read_u32(buf_addr.add(8)).unwrap();
    let format = mem.read_u32(buf_addr.add(12)).unwrap();
    let bits = mem.read_u32(buf_addr.add(16)).unwrap();

    assert_eq!(width, 1920);
    assert_eq!(height, 1080);
    assert_eq!(stride, 1920);
    assert_eq!(format, 1);
    assert_eq!(bits, 0x7200_0000);

    // unlockAndPost
    cpu.set_reg(Reg::R0, 0x3000_0001);
    call_bionic(&mut bridge, BionicFuncId::ANativeWindowUnlockAndPost, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_symbol_resolution() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "ANativeWindow_acquire",
        "ANativeWindow_release",
        "ANativeWindow_getWidth",
        "ANativeWindow_getHeight",
        "ANativeWindow_getFormat",
        "ANativeWindow_setBuffersGeometry",
        "ANativeWindow_lock",
        "ANativeWindow_unlockAndPost",
    ];

    for sym in symbols {
        let addr = bridge.resolve(sym);
        assert!(addr.is_some(), "Symbol {} must be resolved", sym);
        assert_ne!(addr.unwrap().as_u32(), 0);
    }
}
