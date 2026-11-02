//! Stage 73 integration tests: Process Resource Limits & System Info
//! Tests: getrlimit, getrlimit64, setrlimit, setrlimit64, prlimit, prlimit64,
//!        sysinfo, getpagesize, get_nprocs, get_nprocs_conf, sysconf

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

// ── getpagesize & get_nprocs & sysconf ────────────────────────────────────────

#[test]
fn test_getpagesize_and_nprocs() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. getpagesize() -> 4096
    call_bionic(&mut bridge, BionicFuncId::Getpagesize, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 4096);

    // 2. get_nprocs() -> >= 1
    call_bionic(&mut bridge, BionicFuncId::GetNprocs, &mut cpu, &mut mem).unwrap();
    let nprocs = cpu.reg(Reg::R0);
    assert!(nprocs >= 1);

    // 3. get_nprocs_conf() -> >= 1
    call_bionic(&mut bridge, BionicFuncId::GetNprocsConf, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), nprocs);
}

#[test]
fn test_sysconf_keys() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // _SC_PAGESIZE = 39 -> 4096
    cpu.set_reg(Reg::R0, 39);
    call_bionic(&mut bridge, BionicFuncId::Sysconf, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 4096);

    // _SC_PAGE_SIZE = 40 -> 4096
    cpu.set_reg(Reg::R0, 40);
    call_bionic(&mut bridge, BionicFuncId::Sysconf, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 4096);

    // _SC_PHYS_PAGES = 85 -> 1048576 (4GB / 4KB)
    cpu.set_reg(Reg::R0, 85);
    call_bionic(&mut bridge, BionicFuncId::Sysconf, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1048576);

    // _SC_OPEN_MAX = 4 -> 1024
    cpu.set_reg(Reg::R0, 4);
    call_bionic(&mut bridge, BionicFuncId::Sysconf, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1024);

    // _SC_CLK_TCK = 6 -> 100
    cpu.set_reg(Reg::R0, 6);
    call_bionic(&mut bridge, BionicFuncId::Sysconf, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 100);

    // Unknown key -> -1 (0xFFFF_FFFF)
    cpu.set_reg(Reg::R0, 9999);
    call_bionic(&mut bridge, BionicFuncId::Sysconf, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0xFFFF_FFFF);
}

// ── sysinfo ───────────────────────────────────────────────────────────────────

#[test]
fn test_sysinfo() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let info_buf = scratch(0x100);

    cpu.set_reg(Reg::R0, info_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Sysinfo, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let uptime = mem.read_u32(info_buf).unwrap();
    let load0 = mem.read_u32(info_buf.add(4)).unwrap();
    let totalram = mem.read_u32(info_buf.add(16)).unwrap();
    let freeram = mem.read_u32(info_buf.add(20)).unwrap();
    let procs = mem.read_u16(info_buf.add(40)).unwrap();
    let mem_unit = mem.read_u32(info_buf.add(52)).unwrap();

    assert_eq!(uptime, 3600);
    assert_eq!(load0, 65536);
    assert_eq!(totalram, 0x8000_0000); // 2 GB
    assert_eq!(freeram, 0x4000_0000);  // 1 GB
    assert_eq!(procs, 42);
    assert_eq!(mem_unit, 1);
}

// ── getrlimit & setrlimit ─────────────────────────────────────────────────────

#[test]
fn test_getrlimit_and_setrlimit() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let rl_buf = scratch(0x200);

    // 1. getrlimit(RLIMIT_STACK = 3, &rl) -> initial 8 MB
    cpu.set_reg(Reg::R0, 3);
    cpu.set_reg(Reg::R1, rl_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Getrlimit, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let cur = mem.read_u32(rl_buf).unwrap();
    let max = mem.read_u32(rl_buf.add(4)).unwrap();
    assert_eq!(cur, 8 * 1024 * 1024);
    assert_eq!(max, 8 * 1024 * 1024);

    // 2. setrlimit(RLIMIT_STACK = 3, &new_rl) -> set to 16 MB
    let new_rl = scratch(0x230);
    mem.write_u32(new_rl, 16 * 1024 * 1024).unwrap();
    mem.write_u32(new_rl.add(4), 32 * 1024 * 1024).unwrap();

    cpu.set_reg(Reg::R0, 3);
    cpu.set_reg(Reg::R1, new_rl.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Setrlimit, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 3. getrlimit again to verify updated values
    cpu.set_reg(Reg::R0, 3);
    cpu.set_reg(Reg::R1, rl_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Getrlimit, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    assert_eq!(mem.read_u32(rl_buf).unwrap(), 16 * 1024 * 1024);
    assert_eq!(mem.read_u32(rl_buf.add(4)).unwrap(), 32 * 1024 * 1024);
}

// ── getrlimit64 & setrlimit64 & prlimit64 ─────────────────────────────────────

#[test]
fn test_getrlimit64_and_setrlimit64_and_prlimit64() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let rl64_buf = scratch(0x300);

    // 1. getrlimit64(RLIMIT_NOFILE = 7, &rl64)
    cpu.set_reg(Reg::R0, 7);
    cpu.set_reg(Reg::R1, rl64_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Getrlimit64, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let cur_low = mem.read_u32(rl64_buf).unwrap();
    let cur_high = mem.read_u32(rl64_buf.add(4)).unwrap();
    let max_low = mem.read_u32(rl64_buf.add(8)).unwrap();
    let max_high = mem.read_u32(rl64_buf.add(12)).unwrap();

    assert_eq!(cur_low, 1024);
    assert_eq!(cur_high, 0);
    assert_eq!(max_low, 4096);
    assert_eq!(max_high, 0);

    // 2. prlimit64(pid = 0, RLIMIT_NOFILE = 7, &new_lim, &old_lim)
    let new_lim = scratch(0x350);
    let old_lim = scratch(0x380);

    // set cur = 2048, max = 8192
    mem.write_u32(new_lim, 2048).unwrap();
    mem.write_u32(new_lim.add(4), 0).unwrap();
    mem.write_u32(new_lim.add(8), 8192).unwrap();
    mem.write_u32(new_lim.add(12), 0).unwrap();

    cpu.set_reg(Reg::R0, 0); // pid
    cpu.set_reg(Reg::R1, 7); // resource
    cpu.set_reg(Reg::R2, new_lim.as_u32());
    cpu.set_reg(Reg::R3, old_lim.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Prlimit64, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Verify old_lim received (1024, 4096)
    assert_eq!(mem.read_u32(old_lim).unwrap(), 1024);
    assert_eq!(mem.read_u32(old_lim.add(8)).unwrap(), 4096);

    // Verify getrlimit64 now returns (2048, 8192)
    cpu.set_reg(Reg::R0, 7);
    cpu.set_reg(Reg::R1, rl64_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Getrlimit64, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(rl64_buf).unwrap(), 2048);
    assert_eq!(mem.read_u32(rl64_buf.add(8)).unwrap(), 8192);
}
