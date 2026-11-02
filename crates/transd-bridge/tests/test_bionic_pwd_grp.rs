//! Stage 89 integration tests: System User & Group Database Emulation
//! Tests: getpwnam, getpwuid, getpwnam_r, getpwuid_r, getgrnam, getgrgid,
//!        getgrnam_r, getgrgid_r, setpwent, endpwent, getpwent, setgrent, endgrent, getgrent

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

fn read_string_at(mem: &impl Memory, addr: GuestAddr) -> String {
    let mut bytes = Vec::new();
    let mut cur = addr;
    loop {
        let b = mem.read_u8(cur).unwrap();
        if b == 0 {
            break;
        }
        bytes.push(b);
        cur = cur.add(1);
    }
    String::from_utf8(bytes).unwrap()
}

#[test]
fn test_getpwuid_and_getpwnam() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. getpwuid(0) -> root
    cpu.set_reg(Reg::R0, 0);
    call_bionic(&mut bridge, BionicFuncId::Getpwuid, &mut cpu, &mut mem).unwrap();
    let pwd_addr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(pwd_addr.as_u32(), 0);

    let name_addr = GuestAddr::new(mem.read_u32(pwd_addr).unwrap());
    let uid = mem.read_u32(pwd_addr.add(8)).unwrap();
    let gid = mem.read_u32(pwd_addr.add(12)).unwrap();
    let dir_addr = GuestAddr::new(mem.read_u32(pwd_addr.add(20)).unwrap());
    let shell_addr = GuestAddr::new(mem.read_u32(pwd_addr.add(24)).unwrap());

    assert_eq!(read_string_at(&mem, name_addr), "root");
    assert_eq!(uid, 0);
    assert_eq!(gid, 0);
    assert_eq!(read_string_at(&mem, dir_addr), "/");
    assert_eq!(read_string_at(&mem, shell_addr), "/system/bin/sh");

    // 2. getpwnam("shell") -> uid 2000
    let str_addr = GuestAddr::new(HEAP_START + 0x0100);
    mem.write_bytes(str_addr, b"shell\0").unwrap();

    cpu.set_reg(Reg::R0, str_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Getpwnam, &mut cpu, &mut mem).unwrap();
    let pwd_shell = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(pwd_shell.as_u32(), 0);
    assert_eq!(mem.read_u32(pwd_shell.add(8)).unwrap(), 2000);

    // 3. getpwnam("u0_a123") -> uid 10123
    mem.write_bytes(str_addr, b"u0_a123\0").unwrap();
    cpu.set_reg(Reg::R0, str_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Getpwnam, &mut cpu, &mut mem).unwrap();
    let pwd_app = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(pwd_app.as_u32(), 0);
    assert_eq!(mem.read_u32(pwd_app.add(8)).unwrap(), 10123);
    assert_eq!(mem.read_u32(pwd_app.add(12)).unwrap(), 10123);
}

#[test]
fn test_getpwuid_r_and_getpwnam_r() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let pwd_struct = GuestAddr::new(HEAP_START + 0x0100);
    let buf_addr = GuestAddr::new(HEAP_START + 0x0200);
    let result_slot = GuestAddr::new(HEAP_START + 0x0500);

    // 1. getpwuid_r(10050, pwd, buf, 256, &result)
    let sp = GuestAddr::new(cpu.sp());
    mem.write_u32(sp, result_slot.as_u32()).unwrap(); // 5th arg on stack

    cpu.set_reg(Reg::R0, 10050);
    cpu.set_reg(Reg::R1, pwd_struct.as_u32());
    cpu.set_reg(Reg::R2, buf_addr.as_u32());
    cpu.set_reg(Reg::R3, 256);
    call_bionic(&mut bridge, BionicFuncId::GetpwuidR, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0); // success

    assert_eq!(mem.read_u32(result_slot).unwrap(), pwd_struct.as_u32());
    let name_addr = GuestAddr::new(mem.read_u32(pwd_struct).unwrap());
    assert_eq!(read_string_at(&mem, name_addr), "u0_a50");
    assert_eq!(mem.read_u32(pwd_struct.add(8)).unwrap(), 10050);

    // 2. Buffer too small => ERANGE (34)
    cpu.set_reg(Reg::R0, 10050);
    cpu.set_reg(Reg::R1, pwd_struct.as_u32());
    cpu.set_reg(Reg::R2, buf_addr.as_u32());
    cpu.set_reg(Reg::R3, 4); // too small
    call_bionic(&mut bridge, BionicFuncId::GetpwuidR, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 34); // ERANGE
    assert_eq!(mem.read_u32(result_slot).unwrap(), 0);
}

#[test]
fn test_getgrgid_and_getgrnam() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. getgrgid(3003) -> inet
    cpu.set_reg(Reg::R0, 3003);
    call_bionic(&mut bridge, BionicFuncId::Getgrgid, &mut cpu, &mut mem).unwrap();
    let grp_addr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(grp_addr.as_u32(), 0);

    let name_addr = GuestAddr::new(mem.read_u32(grp_addr).unwrap());
    let gid = mem.read_u32(grp_addr.add(8)).unwrap();
    assert_eq!(read_string_at(&mem, name_addr), "inet");
    assert_eq!(gid, 3003);

    // 2. getgrnam("net_raw") -> 3004
    let str_addr = GuestAddr::new(HEAP_START + 0x0100);
    mem.write_bytes(str_addr, b"net_raw\0").unwrap();

    cpu.set_reg(Reg::R0, str_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Getgrnam, &mut cpu, &mut mem).unwrap();
    let grp_raw = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(grp_raw.as_u32(), 0);
    assert_eq!(mem.read_u32(grp_raw.add(8)).unwrap(), 3004);
}

#[test]
fn test_pwent_and_grent_iteration() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. setpwent & iterate getpwent
    call_bionic(&mut bridge, BionicFuncId::Setpwent, &mut cpu, &mut mem).unwrap();

    let mut users = Vec::new();
    loop {
        call_bionic(&mut bridge, BionicFuncId::Getpwent, &mut cpu, &mut mem).unwrap();
        let ptr = cpu.reg(Reg::R0);
        if ptr == 0 {
            break;
        }
        let pwd_addr = GuestAddr::new(ptr);
        let name_addr = GuestAddr::new(mem.read_u32(pwd_addr).unwrap());
        users.push(read_string_at(&mem, name_addr));
    }
    assert_eq!(users, vec!["root", "system", "shell", "u0_a100"]);

    // endpwent resets
    call_bionic(&mut bridge, BionicFuncId::Endpwent, &mut cpu, &mut mem).unwrap();

    // 2. setgrent & iterate getgrent
    call_bionic(&mut bridge, BionicFuncId::Setgrent, &mut cpu, &mut mem).unwrap();

    let mut groups = Vec::new();
    loop {
        call_bionic(&mut bridge, BionicFuncId::Getgrent, &mut cpu, &mut mem).unwrap();
        let ptr = cpu.reg(Reg::R0);
        if ptr == 0 {
            break;
        }
        let grp_addr = GuestAddr::new(ptr);
        let name_addr = GuestAddr::new(mem.read_u32(grp_addr).unwrap());
        groups.push(read_string_at(&mem, name_addr));
    }
    assert_eq!(groups, vec!["root", "system", "shell", "inet", "net_raw", "u0_a100"]);
}

#[test]
fn test_symbol_resolution() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "getpwnam",
        "getpwuid",
        "getpwnam_r",
        "getpwuid_r",
        "getgrnam",
        "getgrgid",
        "getgrnam_r",
        "getgrgid_r",
        "setpwent",
        "endpwent",
        "getpwent",
        "setgrent",
        "endgrent",
        "getgrent",
    ];

    for sym in symbols {
        let addr = bridge.resolve(sym);
        assert!(addr.is_some(), "Symbol {} must be resolved", sym);
        assert_ne!(addr.unwrap().as_u32(), 0);
    }
}
