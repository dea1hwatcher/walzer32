//! Stage 84 integration tests: Extended Network Interface Discovery
//! Tests: if_nametoindex, if_indextoname, if_nameindex, if_freenameindex

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
fn test_if_nametoindex_and_indextoname() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let name_addr = GuestAddr::new(HEAP_START + 0x1000);
    let buf_addr = GuestAddr::new(HEAP_START + 0x1040);

    // if_nametoindex: "lo" -> 1
    write_str(&mut mem, name_addr, "lo");
    cpu.set_reg(Reg::R0, name_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::IfNametoindex, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    // "wlan0" -> 2
    write_str(&mut mem, name_addr, "wlan0");
    cpu.set_reg(Reg::R0, name_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::IfNametoindex, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 2);

    // "rmnet0" -> 3
    write_str(&mut mem, name_addr, "rmnet0");
    cpu.set_reg(Reg::R0, name_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::IfNametoindex, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 3);

    // "eth0" -> 4
    write_str(&mut mem, name_addr, "eth0");
    cpu.set_reg(Reg::R0, name_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::IfNametoindex, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 4);

    // "nonexistent" -> 0
    write_str(&mut mem, name_addr, "unknown_if");
    cpu.set_reg(Reg::R0, name_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::IfNametoindex, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // if_indextoname: 1 -> "lo"
    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, buf_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::IfIndextoname, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), buf_addr.as_u32());
    assert_eq!(read_c_str(&mem, buf_addr), "lo");

    // if_indextoname: 2 -> "wlan0"
    cpu.set_reg(Reg::R0, 2);
    cpu.set_reg(Reg::R1, buf_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::IfIndextoname, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), buf_addr.as_u32());
    assert_eq!(read_c_str(&mem, buf_addr), "wlan0");

    // if_indextoname: 99 -> NULL (0)
    cpu.set_reg(Reg::R0, 99);
    cpu.set_reg(Reg::R1, buf_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::IfIndextoname, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_if_nameindex_and_free() {
    let (mut bridge, mut mem, mut cpu) = setup();

    call_bionic(&mut bridge, BionicFuncId::IfNameindex, &mut cpu, &mut mem).unwrap();
    let base_addr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(base_addr.as_u32(), 0);

    // Entry 0: 1, "lo"
    let idx0 = mem.read_u32(base_addr).unwrap();
    let name_ptr0 = GuestAddr::new(mem.read_u32(base_addr.add(4)).unwrap());
    assert_eq!(idx0, 1);
    assert_eq!(read_c_str(&mem, name_ptr0), "lo");

    // Entry 1: 2, "wlan0"
    let idx1 = mem.read_u32(base_addr.add(8)).unwrap();
    let name_ptr1 = GuestAddr::new(mem.read_u32(base_addr.add(12)).unwrap());
    assert_eq!(idx1, 2);
    assert_eq!(read_c_str(&mem, name_ptr1), "wlan0");

    // Entry 2: 3, "rmnet0"
    let idx2 = mem.read_u32(base_addr.add(16)).unwrap();
    let name_ptr2 = GuestAddr::new(mem.read_u32(base_addr.add(20)).unwrap());
    assert_eq!(idx2, 3);
    assert_eq!(read_c_str(&mem, name_ptr2), "rmnet0");

    // Terminator: 0, 0
    let term_idx = mem.read_u32(base_addr.add(24)).unwrap();
    let term_ptr = mem.read_u32(base_addr.add(28)).unwrap();
    assert_eq!(term_idx, 0);
    assert_eq!(term_ptr, 0);

    // if_freenameindex: returns 0
    cpu.set_reg(Reg::R0, base_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::IfFreenameindex, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_symbol_resolution() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "if_nametoindex", "if_indextoname", "if_nameindex", "if_freenameindex",
    ];

    for sym in symbols {
        let addr = bridge.resolve(sym);
        assert!(addr.is_some(), "Symbol {} must be resolved", sym);
        assert_ne!(addr.unwrap().as_u32(), 0);
    }
}
