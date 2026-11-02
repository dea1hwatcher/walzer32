//! Stage 99 integration tests: Android Native Hardware Buffer NDK APIs
//! Tests: AHardwareBuffer_allocate, AHardwareBuffer_acquire, AHardwareBuffer_release,
//!        AHardwareBuffer_describe, AHardwareBuffer_lock, AHardwareBuffer_unlock,
//!        AHardwareBuffer_isSupported, AHardwareBuffer_lockPlanes

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
    mem.commit_range(heap_start, 0x0020_0000).expect("commit heap");

    let bridge = BionicBridge::new(stub_base, heap_start, 0x0020_0000);
    bridge.install_stubs(&mut mem).expect("stubs");

    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::SP, HEAP_START + 0x0018_0000);

    (bridge, mem, cpu)
}

#[test]
fn test_hardware_buffer_symbols() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "AHardwareBuffer_allocate",
        "AHardwareBuffer_acquire",
        "AHardwareBuffer_release",
        "AHardwareBuffer_describe",
        "AHardwareBuffer_lock",
        "AHardwareBuffer_unlock",
        "AHardwareBuffer_isSupported",
        "AHardwareBuffer_lockPlanes",
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
fn test_hardware_buffer_is_supported() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let desc_addr = GuestAddr::new(HEAP_START + 0x0100);
    // 1920x1080, layers=1, format=1 (RGBA_8888)
    mem.write_u32(desc_addr, 1920).unwrap();
    mem.write_u32(desc_addr.add(4), 1080).unwrap();
    mem.write_u32(desc_addr.add(8), 1).unwrap();
    mem.write_u32(desc_addr.add(12), 1).unwrap();

    cpu.set_reg(Reg::R0, desc_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AHardwareBufferIsSupported, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    // Invalid: 0 width
    mem.write_u32(desc_addr, 0).unwrap();
    cpu.set_reg(Reg::R0, desc_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AHardwareBufferIsSupported, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_hardware_buffer_allocate_describe_release() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. Prepare AHardwareBuffer_Desc in guest memory
    let desc_addr = GuestAddr::new(HEAP_START + 0x0100);
    mem.write_u32(desc_addr, 800).unwrap(); // width
    mem.write_u32(desc_addr.add(4), 600).unwrap(); // height
    mem.write_u32(desc_addr.add(8), 1).unwrap(); // layers
    mem.write_u32(desc_addr.add(12), 1).unwrap(); // format: RGBA_8888
    mem.write_u32(desc_addr.add(16), 0x33).unwrap(); // usage low
    mem.write_u32(desc_addr.add(20), 0).unwrap(); // usage high

    let out_buf_ptr = GuestAddr::new(HEAP_START + 0x0200);

    // 2. AHardwareBuffer_allocate(desc, &out_buf)
    cpu.set_reg(Reg::R0, desc_addr.as_u32());
    cpu.set_reg(Reg::R1, out_buf_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AHardwareBufferAllocate, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let handle = mem.read_u32(out_buf_ptr).unwrap();
    assert_ne!(handle, 0);
    assert_eq!(bridge.hw_buffers.get(&handle).unwrap().refcount, 1);

    // 3. AHardwareBuffer_describe(handle, &out_desc)
    let out_desc = GuestAddr::new(HEAP_START + 0x0300);
    cpu.set_reg(Reg::R0, handle);
    cpu.set_reg(Reg::R1, out_desc.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AHardwareBufferDescribe, &mut cpu, &mut mem).unwrap();

    assert_eq!(mem.read_u32(out_desc).unwrap(), 800);
    assert_eq!(mem.read_u32(out_desc.add(4)).unwrap(), 600);
    assert_eq!(mem.read_u32(out_desc.add(8)).unwrap(), 1);
    assert_eq!(mem.read_u32(out_desc.add(12)).unwrap(), 1);
    assert_eq!(mem.read_u32(out_desc.add(16)).unwrap(), 0x33);
    assert_eq!(mem.read_u32(out_desc.add(24)).unwrap(), 800); // stride

    // 4. AHardwareBuffer_acquire and release
    cpu.set_reg(Reg::R0, handle);
    call_bionic(&mut bridge, BionicFuncId::AHardwareBufferAcquire, &mut cpu, &mut mem).unwrap();
    assert_eq!(bridge.hw_buffers.get(&handle).unwrap().refcount, 2);

    cpu.set_reg(Reg::R0, handle);
    call_bionic(&mut bridge, BionicFuncId::AHardwareBufferRelease, &mut cpu, &mut mem).unwrap();
    assert_eq!(bridge.hw_buffers.get(&handle).unwrap().refcount, 1);

    cpu.set_reg(Reg::R0, handle);
    call_bionic(&mut bridge, BionicFuncId::AHardwareBufferRelease, &mut cpu, &mut mem).unwrap();
    assert!(bridge.hw_buffers.get(&handle).is_none());
}

#[test]
fn test_hardware_buffer_lock_unlock_and_pixel_write() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. Allocate 16x16 buffer
    let desc_addr = GuestAddr::new(HEAP_START + 0x0100);
    mem.write_u32(desc_addr, 16).unwrap();
    mem.write_u32(desc_addr.add(4), 16).unwrap();
    mem.write_u32(desc_addr.add(8), 1).unwrap();
    mem.write_u32(desc_addr.add(12), 1).unwrap(); // RGBA_8888
    mem.write_u32(desc_addr.add(16), 3).unwrap();
    mem.write_u32(desc_addr.add(20), 0).unwrap();

    let out_buf_ptr = GuestAddr::new(HEAP_START + 0x0200);
    cpu.set_reg(Reg::R0, desc_addr.as_u32());
    cpu.set_reg(Reg::R1, out_buf_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AHardwareBufferAllocate, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    let handle = mem.read_u32(out_buf_ptr).unwrap();

    // 2. AHardwareBuffer_lock(buffer, usage, fence, rect, &outVirtualAddress)
    // AAPCS: R0=buffer, R1=pad, R2:R3=usage(64), [SP]=fence, [SP+4]=rect, [SP+8]=&vaddr
    let out_vaddr_ptr = GuestAddr::new(HEAP_START + 0x0300);
    let sp_addr = GuestAddr::new(HEAP_START + 0x0018_0000);
    mem.write_u32(sp_addr, (-1i32) as u32).unwrap(); // fence = -1
    mem.write_u32(sp_addr.add(4), 0).unwrap(); // rect = NULL
    mem.write_u32(sp_addr.add(8), out_vaddr_ptr.as_u32()).unwrap(); // outVirtualAddress
    cpu.set_reg(Reg::SP, sp_addr.as_u32());

    cpu.set_reg(Reg::R0, handle);
    cpu.set_reg(Reg::R1, 0); // padding
    cpu.set_reg(Reg::R2, 3); // usage low
    cpu.set_reg(Reg::R3, 0); // usage high
    call_bionic(&mut bridge, BionicFuncId::AHardwareBufferLock, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let vaddr = GuestAddr::new(mem.read_u32(out_vaddr_ptr).unwrap());
    assert_ne!(vaddr.as_u32(), 0);
    assert!(bridge.hw_buffers.get(&handle).unwrap().is_locked);

    // 3. Write red RGBA pixel [255, 0, 0, 255]
    let red_pixel: [u8; 4] = [255, 0, 0, 255];
    mem.write_bytes(vaddr, &red_pixel).unwrap();

    let mut read_pixel = [0u8; 4];
    mem.read_bytes(vaddr, &mut read_pixel).unwrap();
    assert_eq!(read_pixel, red_pixel);

    // 4. AHardwareBuffer_unlock(buffer, &fence)
    let fence_out = GuestAddr::new(HEAP_START + 0x0400);
    cpu.set_reg(Reg::R0, handle);
    cpu.set_reg(Reg::R1, fence_out.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AHardwareBufferUnlock, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert!(!bridge.hw_buffers.get(&handle).unwrap().is_locked);
    assert_eq!(mem.read_u32(fence_out).unwrap(), (-1i32) as u32);
}

#[test]
fn test_hardware_buffer_lock_planes() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // Allocate 32x32 RGB_888 buffer (format 3, 3 bytes per pixel)
    let desc_addr = GuestAddr::new(HEAP_START + 0x0100);
    mem.write_u32(desc_addr, 32).unwrap();
    mem.write_u32(desc_addr.add(4), 32).unwrap();
    mem.write_u32(desc_addr.add(8), 1).unwrap();
    mem.write_u32(desc_addr.add(12), 3).unwrap(); // RGB_888
    mem.write_u32(desc_addr.add(16), 3).unwrap();
    mem.write_u32(desc_addr.add(20), 0).unwrap();

    let out_buf_ptr = GuestAddr::new(HEAP_START + 0x0200);
    cpu.set_reg(Reg::R0, desc_addr.as_u32());
    cpu.set_reg(Reg::R1, out_buf_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AHardwareBufferAllocate, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    let handle = mem.read_u32(out_buf_ptr).unwrap();

    // AHardwareBuffer_lockPlanes(handle, usage, fence, rect, &outPlanes)
    let out_planes = GuestAddr::new(HEAP_START + 0x0300);
    let sp_addr = GuestAddr::new(HEAP_START + 0x0018_0000);
    mem.write_u32(sp_addr, (-1i32) as u32).unwrap();
    mem.write_u32(sp_addr.add(4), 0).unwrap();
    mem.write_u32(sp_addr.add(8), out_planes.as_u32()).unwrap();
    cpu.set_reg(Reg::SP, sp_addr.as_u32());

    cpu.set_reg(Reg::R0, handle);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 3);
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::AHardwareBufferLockPlanes, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Verify outPlanes
    let plane_count = mem.read_u32(out_planes).unwrap();
    let data_ptr = mem.read_u32(out_planes.add(4)).unwrap();
    let pixel_stride = mem.read_u32(out_planes.add(8)).unwrap();
    let row_stride = mem.read_u32(out_planes.add(12)).unwrap();

    assert_eq!(plane_count, 1);
    assert_ne!(data_ptr, 0);
    assert_eq!(pixel_stride, 3);
    assert_eq!(row_stride, 32 * 3); // 96 bytes per row

    // Unlock
    cpu.set_reg(Reg::R0, handle);
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::AHardwareBufferUnlock, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}
