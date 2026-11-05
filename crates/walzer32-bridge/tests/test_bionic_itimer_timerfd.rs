//! Stage 90 integration tests: POSIX Interval Timers, Timer File Descriptors & Alarms
//! Tests: getitimer, setitimer, alarm, ualarm, timerfd_create, timerfd_settime, timerfd_gettime, profil

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
fn test_itimer_get_set() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let new_val_addr = GuestAddr::new(HEAP_START + 0x0100);
    let old_val_addr = GuestAddr::new(HEAP_START + 0x0200);
    let curr_val_addr = GuestAddr::new(HEAP_START + 0x0300);

    // new_val: it_interval = { 1 sec, 500000 usec }, it_value = { 2 sec, 250000 usec }
    mem.write_u32(new_val_addr, 1).unwrap();
    mem.write_u32(new_val_addr.add(4), 500_000).unwrap();
    mem.write_u32(new_val_addr.add(8), 2).unwrap();
    mem.write_u32(new_val_addr.add(12), 250_000).unwrap();

    // 1. setitimer(ITIMER_REAL=0, new_val, NULL)
    cpu.set_reg(Reg::R0, 0); // ITIMER_REAL
    cpu.set_reg(Reg::R1, new_val_addr.as_u32());
    cpu.set_reg(Reg::R2, 0); // old_val = NULL
    call_bionic(&mut bridge, BionicFuncId::Setitimer, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 2. getitimer(ITIMER_REAL=0, curr_val)
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, curr_val_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Getitimer, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    assert_eq!(mem.read_u32(curr_val_addr).unwrap(), 1);
    assert_eq!(mem.read_u32(curr_val_addr.add(4)).unwrap(), 500_000);
    assert_eq!(mem.read_u32(curr_val_addr.add(8)).unwrap(), 2);
    assert_eq!(mem.read_u32(curr_val_addr.add(12)).unwrap(), 250_000);

    // 3. setitimer with old_val capture
    let new_val2 = GuestAddr::new(HEAP_START + 0x0400);
    mem.write_u32(new_val2, 5).unwrap();
    mem.write_u32(new_val2.add(4), 0).unwrap();
    mem.write_u32(new_val2.add(8), 10).unwrap();
    mem.write_u32(new_val2.add(12), 0).unwrap();

    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, new_val2.as_u32());
    cpu.set_reg(Reg::R2, old_val_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Setitimer, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Old val should have previous settings
    assert_eq!(mem.read_u32(old_val_addr).unwrap(), 1);
    assert_eq!(mem.read_u32(old_val_addr.add(4)).unwrap(), 500_000);
}

#[test]
fn test_alarm_and_ualarm() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // alarm(10) -> returns 0 (no previous alarm)
    cpu.set_reg(Reg::R0, 10);
    call_bionic(&mut bridge, BionicFuncId::Alarm, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // alarm(5) -> returns 10 (previous alarm seconds)
    cpu.set_reg(Reg::R0, 5);
    call_bionic(&mut bridge, BionicFuncId::Alarm, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 10);

    // ualarm(100000, 50000)
    cpu.set_reg(Reg::R0, 100_000);
    cpu.set_reg(Reg::R1, 50_000);
    call_bionic(&mut bridge, BionicFuncId::Ualarm, &mut cpu, &mut mem).unwrap();
}

#[test]
fn test_timerfd_lifecycle_and_read() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. timerfd_create(CLOCK_MONOTONIC=1, 0)
    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::TimerfdCreate, &mut cpu, &mut mem).unwrap();
    let fd = cpu.reg(Reg::R0);
    assert!(fd >= 350);

    // 2. timerfd_settime(fd, 0, new_val, NULL)
    let spec_addr = GuestAddr::new(HEAP_START + 0x0100);
    mem.write_u32(spec_addr, 1).unwrap(); // interval sec
    mem.write_u32(spec_addr.add(4), 200_000_000).unwrap(); // interval nsec
    mem.write_u32(spec_addr.add(8), 3).unwrap(); // value sec
    mem.write_u32(spec_addr.add(12), 400_000_000).unwrap(); // value nsec

    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, 0); // flags
    cpu.set_reg(Reg::R2, spec_addr.as_u32());
    cpu.set_reg(Reg::R3, 0); // old_val = NULL
    call_bionic(&mut bridge, BionicFuncId::TimerfdSettime, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 3. timerfd_gettime(fd, curr_val)
    let curr_addr = GuestAddr::new(HEAP_START + 0x0200);
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, curr_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::TimerfdGettime, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    assert_eq!(mem.read_u32(curr_addr).unwrap(), 1);
    assert_eq!(mem.read_u32(curr_addr.add(4)).unwrap(), 200_000_000);
    assert_eq!(mem.read_u32(curr_addr.add(8)).unwrap(), 3);
    assert_eq!(mem.read_u32(curr_addr.add(12)).unwrap(), 400_000_000);

    // 4. POSIX read(fd, &uint64, 8)
    let read_buf = GuestAddr::new(HEAP_START + 0x0300);
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, read_buf.as_u32());
    cpu.set_reg(Reg::R2, 8);
    call_bionic(&mut bridge, BionicFuncId::Read, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 8);

    let exp_low = mem.read_u32(read_buf).unwrap();
    let exp_high = mem.read_u32(read_buf.add(4)).unwrap();
    let exp = (exp_high as u64) << 32 | (exp_low as u64);
    assert_eq!(exp, 1);

    // 5. Close(fd)
    cpu.set_reg(Reg::R0, fd);
    call_bionic(&mut bridge, BionicFuncId::SocketClose, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_symbol_resolution() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "getitimer",
        "setitimer",
        "alarm",
        "ualarm",
        "timerfd_create",
        "timerfd_settime",
        "timerfd_gettime",
        "profil",
    ];

    for sym in symbols {
        let addr = bridge.resolve(sym);
        assert!(addr.is_some(), "Symbol {} must be resolved", sym);
        assert_ne!(addr.unwrap().as_u32(), 0);
    }
}
