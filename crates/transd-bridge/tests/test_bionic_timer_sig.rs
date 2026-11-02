//! Stage 72 integration tests: High-Resolution Timers & POSIX Signals Extensions
//! Tests: timer_create, timer_settime, timer_gettime, timer_getoverrun, timer_delete,
//!        sigpending, sigsuspend, sigwait, sigtimedwait, sigwaitinfo

use transd_bridge::bionic::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use transd_core::{ArenaMemory, CpuState, GuestAddr, Memory, MemoryError, Reg};

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

    mem.commit_range(stub_base, 0x0001_0000).unwrap();
    mem.commit_range(heap_start, 0x0010_0000).unwrap();

    let bridge = BionicBridge::new(stub_base, heap_start, 512 * 1024);
    bridge.install_stubs(&mut mem).unwrap();
    let cpu = CpuState::new();
    (bridge, mem, cpu)
}

fn scratch(offset: u32) -> GuestAddr {
    GuestAddr::new(HEAP_START + 0x8000 + offset)
}

// ── POSIX Timers: create, settime, gettime, overrun, delete ───────────────────

#[test]
fn test_timer_lifecycle() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let timerid_ptr = scratch(0x100);

    // 1. timer_create(CLOCK_MONOTONIC = 1, NULL, &timerid)
    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, 0); // sevp = NULL
    cpu.set_reg(Reg::R2, timerid_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::TimerCreate, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let timerid = mem.read_u32(timerid_ptr).unwrap();
    assert_ne!(timerid, 0);
    assert!(bridge.timers.contains_key(&timerid));

    // 2. timer_settime(timerid, flags = 0, &new_val, &old_val)
    let new_val = scratch(0x130);
    let old_val = scratch(0x150);

    // new_val: it_interval = (1 sec, 500_000_000 nsec), it_value = (2 sec, 0 nsec)
    mem.write_u32(new_val, 1).unwrap();
    mem.write_u32(new_val.add(4), 500_000_000).unwrap();
    mem.write_u32(new_val.add(8), 2).unwrap();
    mem.write_u32(new_val.add(12), 0).unwrap();

    cpu.set_reg(Reg::R0, timerid);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, new_val.as_u32());
    cpu.set_reg(Reg::R3, old_val.as_u32());
    call_bionic(&mut bridge, BionicFuncId::TimerSettime, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 3. timer_gettime(timerid, &curr_val)
    let curr_val = scratch(0x180);
    cpu.set_reg(Reg::R0, timerid);
    cpu.set_reg(Reg::R1, curr_val.as_u32());
    call_bionic(&mut bridge, BionicFuncId::TimerGettime, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    assert_eq!(mem.read_u32(curr_val).unwrap(), 1);
    assert_eq!(mem.read_u32(curr_val.add(4)).unwrap(), 500_000_000);
    assert_eq!(mem.read_u32(curr_val.add(8)).unwrap(), 2);
    assert_eq!(mem.read_u32(curr_val.add(12)).unwrap(), 0);

    // 4. timer_settime again -> verify old_val receives previous values
    let new_val2 = scratch(0x1A0);
    let old_val2 = scratch(0x1C0);
    mem.write_u32(new_val2, 0).unwrap();
    mem.write_u32(new_val2.add(4), 0).unwrap();
    mem.write_u32(new_val2.add(8), 5).unwrap();
    mem.write_u32(new_val2.add(12), 0).unwrap();

    cpu.set_reg(Reg::R0, timerid);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, new_val2.as_u32());
    cpu.set_reg(Reg::R3, old_val2.as_u32());
    call_bionic(&mut bridge, BionicFuncId::TimerSettime, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    assert_eq!(mem.read_u32(old_val2).unwrap(), 1);
    assert_eq!(mem.read_u32(old_val2.add(4)).unwrap(), 500_000_000);
    assert_eq!(mem.read_u32(old_val2.add(8)).unwrap(), 2);

    // 5. timer_getoverrun(timerid) -> 0
    cpu.set_reg(Reg::R0, timerid);
    call_bionic(&mut bridge, BionicFuncId::TimerGetoverrun, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 6. timer_delete(timerid)
    cpu.set_reg(Reg::R0, timerid);
    call_bionic(&mut bridge, BionicFuncId::TimerDelete, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert!(!bridge.timers.contains_key(&timerid));

    // 7. timer_gettime on deleted timer returns -1
    cpu.set_reg(Reg::R0, timerid);
    cpu.set_reg(Reg::R1, curr_val.as_u32());
    call_bionic(&mut bridge, BionicFuncId::TimerGettime, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0xFFFF_FFFF);
}

// ── POSIX Signals Extensions ──────────────────────────────────────────────────

#[test]
fn test_sigpending_and_sigsuspend() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. Set pending signal: SIGALRM = 14 -> bit 13
    bridge.signal_state.pending_mask = 1 << 13;

    let set_buf = scratch(0x200);
    cpu.set_reg(Reg::R0, set_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Sigpending, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let low = mem.read_u32(set_buf).unwrap();
    assert_eq!(low, 1 << 13);

    // 2. sigsuspend returns -1
    cpu.set_reg(Reg::R0, set_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Sigsuspend, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0xFFFF_FFFF);
}

#[test]
fn test_sigwait_and_sigwaitinfo_and_sigtimedwait() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // Mask for SIGUSR1 (signal 10 -> bit 9)
    let set_buf = scratch(0x300);
    mem.write_u32(set_buf, 1 << 9).unwrap();
    mem.write_u32(set_buf.add(4), 0).unwrap();

    // 1. sigwait(&set, &sig) -> sig = 10, returns 0
    let sig_out = scratch(0x330);
    cpu.set_reg(Reg::R0, set_buf.as_u32());
    cpu.set_reg(Reg::R1, sig_out.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Sigwait, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(sig_out).unwrap(), 10);

    // 2. sigwaitinfo(&set, &info) -> returns 10, info.si_signo = 10
    let info_buf = scratch(0x350);
    cpu.set_reg(Reg::R0, set_buf.as_u32());
    cpu.set_reg(Reg::R1, info_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Sigwaitinfo, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 10);
    assert_eq!(mem.read_u32(info_buf).unwrap(), 10);

    // 3. sigtimedwait(&set, &info, timeout = NULL) -> returns 10
    let info_buf2 = scratch(0x380);
    cpu.set_reg(Reg::R0, set_buf.as_u32());
    cpu.set_reg(Reg::R1, info_buf2.as_u32());
    cpu.set_reg(Reg::R2, 0); // timeout = NULL
    call_bionic(&mut bridge, BionicFuncId::Sigtimedwait, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 10);
    assert_eq!(mem.read_u32(info_buf2).unwrap(), 10);
}
