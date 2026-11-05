//! Stage 79 integration tests: Advanced CPU Affinity & Multi-core Thread Scheduling APIs
//! Tests: sched_setaffinity, sched_getaffinity, sched_getcpu,
//!        sched_setscheduler, sched_getscheduler, sched_setparam,
//!        sched_getparam, sched_get_priority_min, sched_get_priority_max,
//!        sched_rr_get_interval

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
fn test_sched_affinity_and_cpu() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let mask_addr = GuestAddr::new(HEAP_START + 0x1000);

    // sched_setaffinity: returns 0
    cpu.set_reg(Reg::R0, 0); // pid = 0 (calling thread)
    cpu.set_reg(Reg::R1, 128); // cpusetsize = 128 bytes
    cpu.set_reg(Reg::R2, mask_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::SchedSetaffinity, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // sched_getaffinity: returns 0 and populates bitmask
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 128);
    cpu.set_reg(Reg::R2, mask_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::SchedGetaffinity, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let mask = mem.read_u32(mask_addr).unwrap();
    assert!(mask > 0, "CPU mask must have at least one CPU core set");

    // sched_getcpu: returns 0
    call_bionic(&mut bridge, BionicFuncId::SchedGetcpu, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_sched_policy_and_params() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let param_addr = GuestAddr::new(HEAP_START + 0x2000);

    // sched_getscheduler: returns 0 (SCHED_OTHER)
    cpu.set_reg(Reg::R0, 0);
    call_bionic(&mut bridge, BionicFuncId::SchedGetscheduler, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // sched_setscheduler: returns 0
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0); // SCHED_OTHER
    cpu.set_reg(Reg::R2, param_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::SchedSetscheduler, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // sched_getparam: writes priority 0
    mem.write_u32(param_addr, 999).unwrap();
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, param_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::SchedGetparam, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(param_addr).unwrap(), 0);

    // sched_setparam: returns 0
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, param_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::SchedSetparam, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_sched_priority_min_max_and_rr() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let ts_addr = GuestAddr::new(HEAP_START + 0x3000);

    // SCHED_OTHER (0): min=0, max=0
    cpu.set_reg(Reg::R0, 0);
    call_bionic(&mut bridge, BionicFuncId::SchedGetPriorityMin, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 0);
    call_bionic(&mut bridge, BionicFuncId::SchedGetPriorityMax, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // SCHED_FIFO (1): min=1, max=99
    cpu.set_reg(Reg::R0, 1);
    call_bionic(&mut bridge, BionicFuncId::SchedGetPriorityMin, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    cpu.set_reg(Reg::R0, 1);
    call_bionic(&mut bridge, BionicFuncId::SchedGetPriorityMax, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 99);

    // SCHED_RR (2): min=1, max=99
    cpu.set_reg(Reg::R0, 2);
    call_bionic(&mut bridge, BionicFuncId::SchedGetPriorityMin, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    cpu.set_reg(Reg::R0, 2);
    call_bionic(&mut bridge, BionicFuncId::SchedGetPriorityMax, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 99);

    // sched_rr_get_interval: writes 10ms (10_000_000 ns)
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, ts_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::SchedRrGetInterval, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(ts_addr).unwrap(), 0); // tv_sec
    assert_eq!(mem.read_u32(ts_addr.add(4)).unwrap(), 10_000_000); // tv_nsec
}

#[test]
fn test_symbol_resolution() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "sched_setaffinity", "sched_getaffinity", "sched_getcpu",
        "sched_setscheduler", "sched_getscheduler", "sched_setparam",
        "sched_getparam", "sched_get_priority_min", "sched_get_priority_max",
        "sched_rr_get_interval",
    ];

    for sym in symbols {
        let addr = bridge.resolve(sym);
        assert!(addr.is_some(), "Symbol {} must be resolved", sym);
        assert_ne!(addr.unwrap().as_u32(), 0);
    }
}
