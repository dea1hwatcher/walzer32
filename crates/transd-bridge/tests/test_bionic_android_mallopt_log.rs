//! Stage 82 integration tests: Android Memory Management & Security Log Extensions
//! Tests: android_mallopt, malloc_info, mallinfo,
//!        __android_log_bwrite, __android_log_security_bwrite, __android_log_btwrite

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
fn test_android_mallopt_and_mallinfo() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let mallinfo_addr = GuestAddr::new(HEAP_START + 0x1000);

    // android_mallopt returns 1 (true)
    cpu.set_reg(Reg::R0, 0); // M_PURGE
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::AndroidMallopt, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    // malloc_info returns 0
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::MallocInfo, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // mallinfo: buffer passed in R0 per AAPCS large struct return
    cpu.set_reg(Reg::R0, mallinfo_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Mallinfo, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), mallinfo_addr.as_u32());

    let ordblks = mem.read_u32(mallinfo_addr.add(4)).unwrap();
    let fordblks = mem.read_u32(mallinfo_addr.add(28)).unwrap();
    assert_eq!(ordblks, 1);
    assert!(fordblks > 0);
}

#[test]
fn test_android_log_bwrite() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let payload_addr = GuestAddr::new(HEAP_START + 0x2000);

    // __android_log_bwrite(tag, payload, len) -> returns len
    cpu.set_reg(Reg::R0, 1001);
    cpu.set_reg(Reg::R1, payload_addr.as_u32());
    cpu.set_reg(Reg::R2, 16);
    call_bionic(&mut bridge, BionicFuncId::AndroidLogBwrite, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 16);

    // __android_log_security_bwrite(tag, payload, len) -> returns len
    cpu.set_reg(Reg::R0, 2001);
    cpu.set_reg(Reg::R1, payload_addr.as_u32());
    cpu.set_reg(Reg::R2, 32);
    call_bionic(&mut bridge, BionicFuncId::AndroidLogSecurityBwrite, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 32);

    // __android_log_btwrite(tag, type, payload, len) -> returns len
    cpu.set_reg(Reg::R0, 3001);
    cpu.set_reg(Reg::R1, 1);
    cpu.set_reg(Reg::R2, payload_addr.as_u32());
    cpu.set_reg(Reg::R3, 64);
    call_bionic(&mut bridge, BionicFuncId::AndroidLogBtwrite, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 64);
}

#[test]
fn test_symbol_resolution() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "android_mallopt", "malloc_info", "mallinfo",
        "__android_log_bwrite", "__android_log_security_bwrite",
        "__android_log_btwrite",
    ];

    for sym in symbols {
        let addr = bridge.resolve(sym);
        assert!(addr.is_some(), "Symbol {} must be resolved", sym);
        assert_ne!(addr.unwrap().as_u32(), 0);
    }
}
