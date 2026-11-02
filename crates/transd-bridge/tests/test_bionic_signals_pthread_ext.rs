//! Stage 81 integration tests: Advanced Signal Masking & Extended Pthread APIs
//! Tests: pthread_sigmask, sigqueue, pthread_kill, pthread_setname_np,
//!        pthread_getname_np, pthread_equal, pthread_getattr_np

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

fn write_str(mem: &mut impl Memory, addr: GuestAddr, s: &str) {
    let bytes = s.as_bytes();
    mem.write_bytes(addr, bytes).unwrap();
    mem.write_u8(addr.add(bytes.len() as u32), 0).unwrap();
}

fn read_c_str(mem: &impl Memory, mut addr: GuestAddr) -> String {
    let mut bytes = Vec::new();
    loop {
        let b = mem.read_u8(addr).unwrap();
        if b == 0 {
            break;
        }
        bytes.push(b);
        addr = addr.add(1);
    }
    String::from_utf8_lossy(&bytes).to_string()
}

#[test]
fn test_pthread_sigmask_and_sigqueue() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let set_addr = GuestAddr::new(HEAP_START + 0x1000);
    let old_set_addr = GuestAddr::new(HEAP_START + 0x1020);

    // Block signal 2 (SIGINT)
    mem.write_u32(set_addr, 1 << 1).unwrap();
    mem.write_u32(set_addr.add(4), 0).unwrap();

    cpu.set_reg(Reg::R0, 0); // SIG_BLOCK = 0 (in transd signal_state)
    cpu.set_reg(Reg::R1, set_addr.as_u32());
    cpu.set_reg(Reg::R2, old_set_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::PthreadSigmask, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(bridge.signal_state.blocked_mask & (1 << 1), 1 << 1);

    // sigqueue & pthread_kill
    cpu.set_reg(Reg::R0, 100);
    cpu.set_reg(Reg::R1, 9);
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::Sigqueue, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, 9);
    call_bionic(&mut bridge, BionicFuncId::PthreadKill, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_pthread_name_np() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let name_addr = GuestAddr::new(HEAP_START + 0x2000);
    let buf_addr = GuestAddr::new(HEAP_START + 0x2040);

    // Default thread 1 name is "main"
    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, buf_addr.as_u32());
    cpu.set_reg(Reg::R2, 64);
    call_bionic(&mut bridge, BionicFuncId::PthreadGetnameNp, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(read_c_str(&mem, buf_addr), "main");

    // Set name to "WorkerThread"
    write_str(&mut mem, name_addr, "WorkerThread");
    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, name_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::PthreadSetnameNp, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Get name again
    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, buf_addr.as_u32());
    cpu.set_reg(Reg::R2, 64);
    call_bionic(&mut bridge, BionicFuncId::PthreadGetnameNp, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(read_c_str(&mem, buf_addr), "WorkerThread");

    // ERANGE when buffer too small
    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, buf_addr.as_u32());
    cpu.set_reg(Reg::R2, 5);
    call_bionic(&mut bridge, BionicFuncId::PthreadGetnameNp, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 34); // ERANGE
}

#[test]
fn test_pthread_equal_and_getattr() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let attr_addr = GuestAddr::new(HEAP_START + 0x3000);

    // pthread_equal: matching IDs -> 1, different -> 0
    cpu.set_reg(Reg::R0, 42);
    cpu.set_reg(Reg::R1, 42);
    call_bionic(&mut bridge, BionicFuncId::PthreadEqual, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    cpu.set_reg(Reg::R0, 42);
    cpu.set_reg(Reg::R1, 43);
    call_bionic(&mut bridge, BionicFuncId::PthreadEqual, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // pthread_getattr_np
    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, attr_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::PthreadGetattrNp, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let stackaddr = mem.read_u32(attr_addr.add(4)).unwrap();
    let stacksize = mem.read_u32(attr_addr.add(8)).unwrap();
    assert_eq!(stackaddr, 0x7000_0000);
    assert_eq!(stacksize, 0x0010_0000); // 1MB
}

#[test]
fn test_symbol_resolution() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "pthread_sigmask", "sigqueue", "pthread_kill",
        "pthread_setname_np", "pthread_getname_np",
        "pthread_equal", "pthread_getattr_np",
    ];

    for sym in symbols {
        let addr = bridge.resolve(sym);
        assert!(addr.is_some(), "Symbol {} must be resolved", sym);
        assert_ne!(addr.unwrap().as_u32(), 0);
    }
}
