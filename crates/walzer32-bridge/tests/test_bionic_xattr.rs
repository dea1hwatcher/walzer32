//! Stage 98 integration tests: Linux POSIX Extended Attributes (xattr) Subsystem
//! Tests: getxattr, lgetxattr, fgetxattr, setxattr, lsetxattr, fsetxattr,
//!        listxattr, llistxattr, flistxattr, removexattr, lremovexattr, fremovexattr

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
fn test_xattr_symbols() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "getxattr",
        "lgetxattr",
        "fgetxattr",
        "setxattr",
        "lsetxattr",
        "fsetxattr",
        "listxattr",
        "llistxattr",
        "flistxattr",
        "removexattr",
        "lremovexattr",
        "fremovexattr",
    ];

    for sym in symbols {
        assert!(
            bridge.resolve(sym).is_some(),
            "Symbol {} not resolved by BionicBridge",
            sym
        );
    }
}

#[test]
fn test_getxattr_default_selinux() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let path_addr = GuestAddr::new(HEAP_START + 0x0100);
    let name_addr = GuestAddr::new(HEAP_START + 0x0150);
    mem.write_bytes(path_addr, b"/data/app/test_file\0").unwrap();
    mem.write_bytes(name_addr, b"security.selinux\0").unwrap();

    // 1. Size probe: getxattr(path, name, NULL, size=0)
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, name_addr.as_u32());
    cpu.set_reg(Reg::R2, 0); // NULL val
    cpu.set_reg(Reg::R3, 0); // size 0
    call_bionic(&mut bridge, BionicFuncId::Getxattr, &mut cpu, &mut mem).unwrap();
    let needed = cpu.reg(Reg::R0) as usize;
    assert_eq!(needed, b"u:object_r:app_data_file:s0\0".len());

    // 2. Read context: getxattr(path, name, buf, size=needed)
    let val_addr = GuestAddr::new(HEAP_START + 0x0200);
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, name_addr.as_u32());
    cpu.set_reg(Reg::R2, val_addr.as_u32());
    cpu.set_reg(Reg::R3, needed as u32);
    call_bionic(&mut bridge, BionicFuncId::Getxattr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as usize, needed);

    let mut out = vec![0u8; needed];
    mem.read_bytes(val_addr, &mut out).unwrap();
    assert_eq!(&out, b"u:object_r:app_data_file:s0\0");
}

#[test]
fn test_setxattr_getxattr_and_flags() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let path_addr = GuestAddr::new(HEAP_START + 0x0100);
    let name_addr = GuestAddr::new(HEAP_START + 0x0150);
    let val_addr = GuestAddr::new(HEAP_START + 0x0200);

    mem.write_bytes(path_addr, b"/data/test\0").unwrap();
    mem.write_bytes(name_addr, b"user.checksum\0").unwrap();
    mem.write_bytes(val_addr, b"123456").unwrap();

    // 1. setxattr(path, name, "123456", 6, flags=0)
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, name_addr.as_u32());
    cpu.set_reg(Reg::R2, val_addr.as_u32());
    cpu.set_reg(Reg::R3, 6);
    call_bionic(&mut bridge, BionicFuncId::Setxattr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 2. getxattr(path, name, out_buf, 6)
    let out_addr = GuestAddr::new(HEAP_START + 0x0300);
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, name_addr.as_u32());
    cpu.set_reg(Reg::R2, out_addr.as_u32());
    cpu.set_reg(Reg::R3, 6);
    call_bionic(&mut bridge, BionicFuncId::Getxattr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 6);
    let mut out = [0u8; 6];
    mem.read_bytes(out_addr, &mut out).unwrap();
    assert_eq!(&out, b"123456");

    // 3. setxattr with XATTR_CREATE=1 on existing attribute -> fails (-1)
    let sp_addr = GuestAddr::new(HEAP_START + 0x0008_0000);
    mem.write_u32(sp_addr, 1).unwrap(); // flags = XATTR_CREATE
    cpu.set_reg(Reg::SP, sp_addr.as_u32());
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, name_addr.as_u32());
    cpu.set_reg(Reg::R2, val_addr.as_u32());
    cpu.set_reg(Reg::R3, 6);
    call_bionic(&mut bridge, BionicFuncId::Setxattr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), u32::MAX);

    // 4. setxattr with XATTR_REPLACE=2 on existing attribute -> succeeds
    mem.write_u32(sp_addr, 2).unwrap(); // flags = XATTR_REPLACE
    mem.write_bytes(val_addr, b"654321").unwrap();
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, name_addr.as_u32());
    cpu.set_reg(Reg::R2, val_addr.as_u32());
    cpu.set_reg(Reg::R3, 6);
    call_bionic(&mut bridge, BionicFuncId::Setxattr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Verify updated value
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, name_addr.as_u32());
    cpu.set_reg(Reg::R2, out_addr.as_u32());
    cpu.set_reg(Reg::R3, 6);
    call_bionic(&mut bridge, BionicFuncId::Getxattr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 6);
    mem.read_bytes(out_addr, &mut out).unwrap();
    assert_eq!(&out, b"654321");
}

#[test]
fn test_listxattr_and_removexattr() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let path_addr = GuestAddr::new(HEAP_START + 0x0100);
    let name_addr = GuestAddr::new(HEAP_START + 0x0150);
    let val_addr = GuestAddr::new(HEAP_START + 0x0200);

    mem.write_bytes(path_addr, b"/data/test_list\0").unwrap();
    mem.write_bytes(name_addr, b"user.tag\0").unwrap();
    mem.write_bytes(val_addr, b"android").unwrap();

    // Set custom attribute
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, name_addr.as_u32());
    cpu.set_reg(Reg::R2, val_addr.as_u32());
    cpu.set_reg(Reg::R3, 7);
    call_bionic(&mut bridge, BionicFuncId::Setxattr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // listxattr size probe
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::Listxattr, &mut cpu, &mut mem).unwrap();
    let list_size = cpu.reg(Reg::R0) as usize;
    assert!(list_size >= b"security.selinux\0user.tag\0".len());

    // listxattr read list
    let list_buf = GuestAddr::new(HEAP_START + 0x0300);
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, list_buf.as_u32());
    cpu.set_reg(Reg::R2, list_size as u32);
    call_bionic(&mut bridge, BionicFuncId::Listxattr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as usize, list_size);

    let mut list_bytes = vec![0u8; list_size];
    mem.read_bytes(list_buf, &mut list_bytes).unwrap();
    let list_str = String::from_utf8_lossy(&list_bytes);
    assert!(list_str.contains("security.selinux"));
    assert!(list_str.contains("user.tag"));

    // removexattr(path, name)
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, name_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Removexattr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // second removexattr -> fails (-1)
    call_bionic(&mut bridge, BionicFuncId::Removexattr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), u32::MAX);
}

#[test]
fn test_fgetxattr_fsetxattr_flistxattr_fremovexattr() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // Register a virtual file
    bridge.vfs.register_file("/data/fd_test.txt", vec![0u8; 16]);

    // Open file
    let path_addr = GuestAddr::new(HEAP_START + 0x0100);
    mem.write_bytes(path_addr, b"/data/fd_test.txt\0").unwrap();
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, 2);
    call_bionic(&mut bridge, BionicFuncId::Open, &mut cpu, &mut mem).unwrap();
    let fd = cpu.reg(Reg::R0);
    assert_ne!(fd, u32::MAX);

    // 1. fsetxattr(fd, "user.author", "walzer32", 8, 0)
    let name_addr = GuestAddr::new(HEAP_START + 0x0150);
    let val_addr = GuestAddr::new(HEAP_START + 0x0200);
    mem.write_bytes(name_addr, b"user.author\0").unwrap();
    mem.write_bytes(val_addr, b"walzer32").unwrap();

    let sp_addr = GuestAddr::new(HEAP_START + 0x0008_0000);
    mem.write_u32(sp_addr, 0).unwrap();
    cpu.set_reg(Reg::SP, sp_addr.as_u32());

    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, name_addr.as_u32());
    cpu.set_reg(Reg::R2, val_addr.as_u32());
    cpu.set_reg(Reg::R3, 8);
    call_bionic(&mut bridge, BionicFuncId::Fsetxattr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 2. fgetxattr(fd, "user.author", out_buf, 8)
    let out_addr = GuestAddr::new(HEAP_START + 0x0300);
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, name_addr.as_u32());
    cpu.set_reg(Reg::R2, out_addr.as_u32());
    cpu.set_reg(Reg::R3, 8);
    call_bionic(&mut bridge, BionicFuncId::Fgetxattr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 8);
    let mut out = [0u8; 8];
    mem.read_bytes(out_addr, &mut out).unwrap();
    assert_eq!(&out, b"walzer32");

    // 3. flistxattr(fd, out_buf, 64)
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, out_addr.as_u32());
    cpu.set_reg(Reg::R2, 64);
    call_bionic(&mut bridge, BionicFuncId::Flistxattr, &mut cpu, &mut mem).unwrap();
    let flen = cpu.reg(Reg::R0) as usize;
    assert!(flen > 0);

    // 4. fremovexattr(fd, "user.author")
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, name_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Fremovexattr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Check removed
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, name_addr.as_u32());
    cpu.set_reg(Reg::R2, out_addr.as_u32());
    cpu.set_reg(Reg::R3, 6);
    call_bionic(&mut bridge, BionicFuncId::Fgetxattr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), u32::MAX);
}
