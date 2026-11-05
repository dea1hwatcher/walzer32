//! Stage 78 integration tests: POSIX Extended Capabilities & Credentials
//! Tests: capget, capset, getgroups, setgroups, getresuid, getresgid,
//!        setresuid, setresgid, setreuid, setregid

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
fn test_capget_and_capset() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let hdr_addr = GuestAddr::new(HEAP_START + 0x1000);
    let data_addr = GuestAddr::new(HEAP_START + 0x1020);

    // capget: hdrp in R0, datap in R1
    cpu.set_reg(Reg::R0, hdr_addr.as_u32());
    cpu.set_reg(Reg::R1, data_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Capget, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let version = mem.read_u32(hdr_addr).unwrap();
    assert_eq!(version, 0x2008_0522); // _LINUX_CAPABILITY_VERSION_3

    // capset: returns 0
    cpu.set_reg(Reg::R0, hdr_addr.as_u32());
    cpu.set_reg(Reg::R1, data_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Capset, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_getgroups_and_setgroups() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let list_addr = GuestAddr::new(HEAP_START + 0x2000);

    // getgroups with size=0 returns count of groups (1)
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::Getgroups, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    // getgroups with size=1 writes group ID (10000 = AID_APP_START)
    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, list_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Getgroups, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);
    assert_eq!(mem.read_u32(list_addr).unwrap(), 10000);

    // setgroups returns 0
    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, list_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Setgroups, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_resuid_and_resgid() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let r_addr = GuestAddr::new(HEAP_START + 0x3000);
    let e_addr = GuestAddr::new(HEAP_START + 0x3004);
    let s_addr = GuestAddr::new(HEAP_START + 0x3008);

    // getresuid
    cpu.set_reg(Reg::R0, r_addr.as_u32());
    cpu.set_reg(Reg::R1, e_addr.as_u32());
    cpu.set_reg(Reg::R2, s_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Getresuid, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(r_addr).unwrap(), 10000);
    assert_eq!(mem.read_u32(e_addr).unwrap(), 10000);
    assert_eq!(mem.read_u32(s_addr).unwrap(), 10000);

    // getresgid
    cpu.set_reg(Reg::R0, r_addr.as_u32());
    cpu.set_reg(Reg::R1, e_addr.as_u32());
    cpu.set_reg(Reg::R2, s_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Getresgid, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(r_addr).unwrap(), 10000);
    assert_eq!(mem.read_u32(e_addr).unwrap(), 10000);
    assert_eq!(mem.read_u32(s_addr).unwrap(), 10000);

    // setresuid, setresgid, setreuid, setregid
    cpu.set_reg(Reg::R0, 10000);
    cpu.set_reg(Reg::R1, 10000);
    cpu.set_reg(Reg::R2, 10000);
    call_bionic(&mut bridge, BionicFuncId::Setresuid, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 10000);
    cpu.set_reg(Reg::R1, 10000);
    cpu.set_reg(Reg::R2, 10000);
    call_bionic(&mut bridge, BionicFuncId::Setresgid, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 10000);
    cpu.set_reg(Reg::R1, 10000);
    call_bionic(&mut bridge, BionicFuncId::Setreuid, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 10000);
    cpu.set_reg(Reg::R1, 10000);
    call_bionic(&mut bridge, BionicFuncId::Setregid, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_symbol_resolution() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "capget", "capset", "getgroups", "setgroups",
        "getresuid", "getresgid", "setresuid", "setresgid",
        "setreuid", "setregid",
    ];

    for sym in symbols {
        let addr = bridge.resolve(sym);
        assert!(addr.is_some(), "Symbol {} must be resolved", sym);
        assert_ne!(addr.unwrap().as_u32(), 0);
    }
}
