use transd_core::{CpuState, FlatMemory, GuestAddr, Memory, Reg};
use transd_bridge::{BionicBridge, BionicFuncId};

fn call_bionic(
    bridge: &mut BionicBridge,
    func_id: BionicFuncId,
    cpu: &mut CpuState,
    mem: &mut FlatMemory,
) -> Result<bool, String> {
    let svc_imm = transd_bridge::BIONIC_SVC_MAGIC | (func_id as u32);
    bridge
        .handle_svc(svc_imm, cpu, mem)
        .map_err(|e| format!("{:?}", e))
}

#[test]
fn test_ainputqueue_looper_attachment_and_native_activity_stubs() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let mut bridge = BionicBridge::new(
        GuestAddr::new(0x7000_0000),
        GuestAddr::new(0x7010_0000),
        0x100_000,
    );
    bridge.install_stubs(&mut mem).unwrap();

    let mut cpu = CpuState::new();
    cpu.set_sp(0x701F_F000);

    // 1. Prepare ALooper for thread
    cpu.set_reg(Reg::R0, 1); // ALOOPER_PREPARE_ALLOW_NON_CALLBACKS
    call_bionic(&mut bridge, BionicFuncId::ALooperPrepare, &mut cpu, &mut mem).unwrap();
    let looper_handle = cpu.reg(Reg::R0);
    assert_ne!(looper_handle, 0);

    // 2. Attach AInputQueue to Looper
    // AInputQueue_attachLooper(queue=0x5001, looper=looper_handle, ident=77, callback=0, data=0xCAFE_BABE)
    let queue_handle = 0x5001u32;
    let ident = 77i32;
    let data_word = 0xCAFE_BABEu32;
    mem.write_u32(GuestAddr::new(cpu.sp()), data_word).unwrap();

    cpu.set_reg(Reg::R0, queue_handle);
    cpu.set_reg(Reg::R1, looper_handle);
    cpu.set_reg(Reg::R2, ident as u32);
    cpu.set_reg(Reg::R3, 0); // callback = NULL
    call_bionic(&mut bridge, BionicFuncId::AInputQueueAttachLooper, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 3. Verify ALooper_pollOnce triggers the attached input queue and returns its ident!
    let out_fd = GuestAddr::new(0x7005_0000);
    let out_events = GuestAddr::new(0x7005_0004);
    let out_data = GuestAddr::new(0x7005_0008);

    cpu.set_reg(Reg::R0, 100); // timeout_millis = 100
    cpu.set_reg(Reg::R1, out_fd.as_u32());
    cpu.set_reg(Reg::R2, out_events.as_u32());
    cpu.set_reg(Reg::R3, out_data.as_u32());
    call_bionic(&mut bridge, BionicFuncId::ALooperPollOnce, &mut cpu, &mut mem).unwrap();

    assert_eq!(cpu.reg(Reg::R0) as i32, ident, "ALooper_pollOnce must return attached input queue ident!");
    assert_eq!(mem.read_u32(out_fd).unwrap(), 0x1000 + queue_handle);
    assert_eq!(mem.read_u32(out_events).unwrap(), 1); // ALOOPER_EVENT_INPUT
    assert_eq!(mem.read_u32(out_data).unwrap(), data_word);

    // 4. Test AInputQueue_hasEvents & AInputQueue_getEvent
    cpu.set_reg(Reg::R0, queue_handle);
    call_bionic(&mut bridge, BionicFuncId::AInputQueueHasEvents, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "Initially no pending events");

    let out_event = GuestAddr::new(0x7005_0010);
    cpu.set_reg(Reg::R0, queue_handle);
    cpu.set_reg(Reg::R1, out_event.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AInputQueueGetEvent, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, -11, "EAGAIN when queue is empty");

    // 5. Detach AInputQueue from Looper
    cpu.set_reg(Reg::R0, queue_handle);
    call_bionic(&mut bridge, BionicFuncId::AInputQueueDetachLooper, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 6. After detach, ALooper_pollOnce should return TIMEOUT (-3)
    cpu.set_reg(Reg::R0, 0); // timeout = 0
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 0);
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::ALooperPollOnce, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, -3); // ALOOPER_POLL_TIMEOUT

    // 7. Verify ANativeActivity stubs
    call_bionic(&mut bridge, BionicFuncId::ANativeActivityFinish, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    call_bionic(&mut bridge, BionicFuncId::ANativeActivitySetWindowFormat, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    call_bionic(&mut bridge, BionicFuncId::ANativeActivitySetWindowFlags, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    call_bionic(&mut bridge, BionicFuncId::ANativeActivityShowSoftInput, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    call_bionic(&mut bridge, BionicFuncId::ANativeActivityHideSoftInput, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}
