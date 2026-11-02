//! Stage 80 integration tests: POSIX Shared Memory, Anonymous Files & Android Ashmem
//! Tests: shm_open, shm_unlink, memfd_create, ashmem_create_region,
//!        ashmem_set_prot_region, ashmem_get_prot_region, ashmem_get_size_region,
//!        ashmem_pin_region, ashmem_unpin_region

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

#[test]
fn test_ashmem_lifecycle() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let name_addr = GuestAddr::new(HEAP_START + 0x1000);
    write_str(&mut mem, name_addr, "my_ashmem_region");

    // ashmem_create_region(name, size=4096)
    cpu.set_reg(Reg::R0, name_addr.as_u32());
    cpu.set_reg(Reg::R1, 4096);
    call_bionic(&mut bridge, BionicFuncId::AshmemCreateRegion, &mut cpu, &mut mem).unwrap();
    let fd = cpu.reg(Reg::R0);
    assert_ne!(fd, 0xFFFF_FFFF);

    // ashmem_get_size_region
    cpu.set_reg(Reg::R0, fd);
    call_bionic(&mut bridge, BionicFuncId::AshmemGetSizeRegion, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 4096);

    // ashmem_get_prot_region: default prot is 0x7
    cpu.set_reg(Reg::R0, fd);
    call_bionic(&mut bridge, BionicFuncId::AshmemGetProtRegion, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0x7);

    // ashmem_set_prot_region to 0x3 (PROT_READ | PROT_WRITE)
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, 0x3);
    call_bionic(&mut bridge, BionicFuncId::AshmemSetProtRegion, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // ashmem_get_prot_region should now be 0x3
    cpu.set_reg(Reg::R0, fd);
    call_bionic(&mut bridge, BionicFuncId::AshmemGetProtRegion, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0x3);

    // ashmem_pin_region and ashmem_unpin_region
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 4096);
    call_bionic(&mut bridge, BionicFuncId::AshmemPinRegion, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 4096);
    call_bionic(&mut bridge, BionicFuncId::AshmemUnpinRegion, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_ashmem_mmap_and_rw() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let name_addr = GuestAddr::new(HEAP_START + 0x2000);
    let data_addr = GuestAddr::new(HEAP_START + 0x2040);
    write_str(&mut mem, name_addr, "rw_ashmem");

    // Create ashmem region size 4096
    cpu.set_reg(Reg::R0, name_addr.as_u32());
    cpu.set_reg(Reg::R1, 4096);
    call_bionic(&mut bridge, BionicFuncId::AshmemCreateRegion, &mut cpu, &mut mem).unwrap();
    let fd = cpu.reg(Reg::R0);

    // Write "hello ashmem" (12 bytes) via POSIX write
    mem.write_bytes(data_addr, b"hello ashmem").unwrap();
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, data_addr.as_u32());
    cpu.set_reg(Reg::R2, 12);
    call_bionic(&mut bridge, BionicFuncId::Write, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 12);

    // Mmap ashmem fd: mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 4096);
    cpu.set_reg(Reg::R2, 3); // PROT_READ | PROT_WRITE
    cpu.set_reg(Reg::R3, 1); // MAP_SHARED
    // 5th arg (fd) is on stack in ARM AAPCS
    let sp = cpu.reg(Reg::SP);
    mem.write_u32(GuestAddr::new(sp), fd).unwrap();
    mem.write_u32(GuestAddr::new(sp + 4), 0).unwrap(); // offset = 0
    call_bionic(&mut bridge, BionicFuncId::Mmap, &mut cpu, &mut mem).unwrap();
    let mapped_addr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(mapped_addr.as_u32(), 0xFFFF_FFFF);

    // Read 12 bytes from mapped memory -> should match "hello ashmem"
    let mut read_buf = [0u8; 12];
    mem.read_bytes(mapped_addr, &mut read_buf).unwrap();
    assert_eq!(&read_buf, b"hello ashmem");

    // Close descriptor
    cpu.set_reg(Reg::R0, fd);
    call_bionic(&mut bridge, BionicFuncId::SocketClose, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_shm_and_memfd() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let shm_name_addr = GuestAddr::new(HEAP_START + 0x3000);
    let memfd_name_addr = GuestAddr::new(HEAP_START + 0x3040);
    write_str(&mut mem, shm_name_addr, "/test_shm");
    write_str(&mut mem, memfd_name_addr, "test_memfd");

    // shm_open
    cpu.set_reg(Reg::R0, shm_name_addr.as_u32());
    cpu.set_reg(Reg::R1, 2); // O_RDWR
    cpu.set_reg(Reg::R2, 0o666);
    call_bionic(&mut bridge, BionicFuncId::ShmOpen, &mut cpu, &mut mem).unwrap();
    let shm_fd = cpu.reg(Reg::R0);
    assert_ne!(shm_fd, 0xFFFF_FFFF);

    // ftruncate to 8192
    cpu.set_reg(Reg::R0, shm_fd);
    cpu.set_reg(Reg::R1, 8192);
    call_bionic(&mut bridge, BionicFuncId::Ftruncate, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // ashmem_get_size_region on shm_fd returns 8192
    cpu.set_reg(Reg::R0, shm_fd);
    call_bionic(&mut bridge, BionicFuncId::AshmemGetSizeRegion, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 8192);

    // shm_unlink returns 0
    cpu.set_reg(Reg::R0, shm_name_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::ShmUnlink, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // memfd_create
    cpu.set_reg(Reg::R0, memfd_name_addr.as_u32());
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::MemfdCreate, &mut cpu, &mut mem).unwrap();
    let memfd = cpu.reg(Reg::R0);
    assert_ne!(memfd, 0xFFFF_FFFF);

    // ftruncate to 2048
    cpu.set_reg(Reg::R0, memfd);
    cpu.set_reg(Reg::R1, 2048);
    call_bionic(&mut bridge, BionicFuncId::Ftruncate, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, memfd);
    call_bionic(&mut bridge, BionicFuncId::AshmemGetSizeRegion, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 2048);
}

#[test]
fn test_symbol_resolution() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "shm_open", "shm_unlink", "memfd_create",
        "ashmem_create_region", "ashmem_set_prot_region",
        "ashmem_get_prot_region", "ashmem_get_size_region",
        "ashmem_pin_region", "ashmem_unpin_region",
    ];

    for sym in symbols {
        let addr = bridge.resolve(sym);
        assert!(addr.is_some(), "Symbol {} must be resolved", sym);
        assert_ne!(addr.unwrap().as_u32(), 0);
    }
}
