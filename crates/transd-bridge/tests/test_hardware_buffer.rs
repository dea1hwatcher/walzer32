use transd_core::{CpuState, FlatMemory, GuestAddr, Memory, Reg};
use transd_elf::SymbolResolver;
use transd_bridge::{
    HardwareBufferBridge, HardwareBufferFuncId, HARDWARE_BUFFER_SVC_MAGIC,
    AHARDWAREBUFFER_FORMAT_RGBA_8888, AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN,
    AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN,
};

#[test]
fn test_hardware_buffer_symbols_resolution() {
    let bridge = HardwareBufferBridge::with_stub_base(GuestAddr::new(0x7000_0000));

    let symbols = [
        "AHardwareBuffer_allocate",
        "AHardwareBuffer_acquire",
        "AHardwareBuffer_release",
        "AHardwareBuffer_describe",
        "AHardwareBuffer_lock",
        "AHardwareBuffer_unlock",
        "AHardwareBuffer_getId",
    ];

    for sym in symbols {
        let addr = bridge.resolve(sym);
        assert!(addr.is_some(), "Symbol {sym} must resolve");
        assert!(addr.unwrap().as_u32() >= 0x7000_0000);
    }
}

#[test]
fn test_hardware_buffer_allocate_describe_lock_unlock() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let mut bridge = HardwareBufferBridge::new(
        GuestAddr::new(0x7000_0000),
        GuestAddr::new(0x7005_0000),
        0x50_000,
    );
    bridge.install_stubs(&mut mem).unwrap();

    let mut cpu = CpuState::default();

    // 1. Write AHardwareBuffer_Desc at 0x7001_0000:
    // width = 128, height = 64, layers = 1, format = RGBA_8888 (1)
    // usage = CPU_READ_OFTEN | CPU_WRITE_OFTEN (0x33)
    let desc_addr = GuestAddr::new(0x7001_0000);
    mem.write_u32(desc_addr, 128).unwrap();        // width
    mem.write_u32(desc_addr.add(4), 64).unwrap();   // height
    mem.write_u32(desc_addr.add(8), 1).unwrap();    // layers
    mem.write_u32(desc_addr.add(12), AHARDWAREBUFFER_FORMAT_RGBA_8888).unwrap(); // format
    mem.write_u32(desc_addr.add(16), (AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN | AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN) as u32).unwrap(); // usage_lo
    mem.write_u32(desc_addr.add(20), 0).unwrap();   // usage_hi
    mem.write_u32(desc_addr.add(24), 0).unwrap();   // stride
    mem.write_u32(desc_addr.add(28), 0).unwrap();   // rfu0
    mem.write_u32(desc_addr.add(32), 0).unwrap();   // rfu1

    let out_buf_ptr = GuestAddr::new(0x7001_0050);

    // Call AHardwareBuffer_allocate(desc_ptr, out_buf_ptr)
    cpu.set_reg(Reg::R0, desc_addr.as_u32());
    cpu.set_reg(Reg::R1, out_buf_ptr.as_u32());
    let handled = bridge.handle_svc(
        HARDWARE_BUFFER_SVC_MAGIC | (HardwareBufferFuncId::Allocate as u32),
        &mut cpu,
        &mut mem,
    ).unwrap();
    assert!(handled);
    assert_eq!(cpu.reg(Reg::R0), 0, "Allocate must return 0 (ANDROID_SUCCESS)");

    let handle = mem.read_u32(out_buf_ptr).unwrap();
    assert_ne!(handle, 0);

    // 2. Call AHardwareBuffer_describe(handle, out_desc_ptr)
    let out_desc_addr = GuestAddr::new(0x7001_0100);
    cpu.set_reg(Reg::R0, handle);
    cpu.set_reg(Reg::R1, out_desc_addr.as_u32());
    bridge.handle_svc(
        HARDWARE_BUFFER_SVC_MAGIC | (HardwareBufferFuncId::Describe as u32),
        &mut cpu,
        &mut mem,
    ).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    assert_eq!(mem.read_u32(out_desc_addr).unwrap(), 128);      // width
    assert_eq!(mem.read_u32(out_desc_addr.add(4)).unwrap(), 64); // height
    assert_eq!(mem.read_u32(out_desc_addr.add(8)).unwrap(), 1);  // layers
    assert_eq!(mem.read_u32(out_desc_addr.add(12)).unwrap(), AHARDWAREBUFFER_FORMAT_RGBA_8888);
    assert_eq!(mem.read_u32(out_desc_addr.add(24)).unwrap(), 128); // stride (aligned)

    // 3. Call AHardwareBuffer_lock(handle, usage, fence, rect=NULL, &out_virt_addr)
    let sp = GuestAddr::new(0x7002_0000);
    cpu.set_sp(sp.as_u32());
    let out_virt_ptr = GuestAddr::new(0x7001_0200);
    mem.write_u32(sp, 0).unwrap(); // rect = NULL
    mem.write_u32(sp.add(4), out_virt_ptr.as_u32()).unwrap(); // outVirtualAddress

    cpu.set_reg(Reg::R0, handle);
    cpu.set_reg(Reg::R1, 0x33); // usage_lo
    cpu.set_reg(Reg::R2, 0);    // usage_hi
    cpu.set_reg(Reg::R3, (-1i32) as u32); // fence
    bridge.handle_svc(
        HARDWARE_BUFFER_SVC_MAGIC | (HardwareBufferFuncId::Lock as u32),
        &mut cpu,
        &mut mem,
    ).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "Lock must return 0");

    let virt_addr = GuestAddr::new(mem.read_u32(out_virt_ptr).unwrap());
    assert!(virt_addr.as_u32() >= 0x7005_0000);

    // 4. Write pixels to locked buffer memory
    let pixel_pattern = [0xAA, 0xBB, 0xCC, 0xFF];
    mem.write_bytes(virt_addr, &pixel_pattern).unwrap();

    let mut readback = [0u8; 4];
    mem.read_bytes(virt_addr, &mut readback).unwrap();
    assert_eq!(readback, pixel_pattern);

    // 5. Call AHardwareBuffer_unlock(handle, &fence)
    let fence_out = GuestAddr::new(0x7001_0300);
    cpu.set_reg(Reg::R0, handle);
    cpu.set_reg(Reg::R1, fence_out.as_u32());
    bridge.handle_svc(
        HARDWARE_BUFFER_SVC_MAGIC | (HardwareBufferFuncId::Unlock as u32),
        &mut cpu,
        &mut mem,
    ).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 6. Call AHardwareBuffer_getId(handle, &out_id)
    let id_out = GuestAddr::new(0x7001_0400);
    cpu.set_reg(Reg::R0, handle);
    cpu.set_reg(Reg::R1, id_out.as_u32());
    bridge.handle_svc(
        HARDWARE_BUFFER_SVC_MAGIC | (HardwareBufferFuncId::GetId as u32),
        &mut cpu,
        &mut mem,
    ).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(id_out).unwrap(), handle);

    // 7. Acquire & Release
    cpu.set_reg(Reg::R0, handle);
    bridge.handle_svc(
        HARDWARE_BUFFER_SVC_MAGIC | (HardwareBufferFuncId::Acquire as u32),
        &mut cpu,
        &mut mem,
    ).unwrap();
    assert_eq!(bridge.buffers.get(&handle).unwrap().ref_count, 2);

    cpu.set_reg(Reg::R0, handle);
    bridge.handle_svc(
        HARDWARE_BUFFER_SVC_MAGIC | (HardwareBufferFuncId::Release as u32),
        &mut cpu,
        &mut mem,
    ).unwrap();
    assert_eq!(bridge.buffers.get(&handle).unwrap().ref_count, 1);

    cpu.set_reg(Reg::R0, handle);
    bridge.handle_svc(
        HARDWARE_BUFFER_SVC_MAGIC | (HardwareBufferFuncId::Release as u32),
        &mut cpu,
        &mut mem,
    ).unwrap();
    assert!(!bridge.buffers.contains_key(&handle), "Buffer should be deleted when ref_count reaches 0");
}
