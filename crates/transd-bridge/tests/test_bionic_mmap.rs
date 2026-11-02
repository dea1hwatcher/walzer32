//! Stage 67 integration tests: Memory-Mapped I/O APIs
//! Tests: mmap, mmap64, munmap, madvise, msync, mremap, mlock, munlock, mlockall, munlockall, mincore

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

// ── mmap & munmap ────────────────────────────────────────────────────────────

#[test]
fn test_mmap_anonymous_and_munmap() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // mmap(NULL, 8192, PROT_READ|PROT_WRITE=3, MAP_ANON=0x20, -1, 0)
    cpu.set_reg(Reg::R0, 0); // addr = 0 (let kernel choose)
    cpu.set_reg(Reg::R1, 8192); // len
    cpu.set_reg(Reg::R2, 3); // prot
    cpu.set_reg(Reg::R3, 0x20); // flags
    call_bionic(&mut bridge, BionicFuncId::Mmap, &mut cpu, &mut mem).unwrap();

    let mapped_addr = cpu.reg(Reg::R0);
    assert_ne!(mapped_addr, u32::MAX, "mmap should not return MAP_FAILED");
    assert_eq!(mapped_addr & 0xFFF, 0, "mmap should be 4KB page aligned");
    assert!(bridge.mmap_regions.contains_key(&mapped_addr));

    // Verify we can write and read from the mapped memory
    let gaddr = GuestAddr::new(mapped_addr);
    mem.write_u32(gaddr, 0xDEAD_BEEF).unwrap();
    assert_eq!(mem.read_u32(gaddr).unwrap(), 0xDEAD_BEEF);

    // munmap(mapped_addr, 8192)
    cpu.set_reg(Reg::R0, mapped_addr);
    cpu.set_reg(Reg::R1, 8192);
    call_bionic(&mut bridge, BionicFuncId::Munmap, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert!(!bridge.mmap_regions.contains_key(&mapped_addr));
}

#[test]
fn test_mmap64_separate_allocations() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // First mmap64
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 4096);
    cpu.set_reg(Reg::R2, 3);
    cpu.set_reg(Reg::R3, 0x20);
    call_bionic(&mut bridge, BionicFuncId::Mmap64, &mut cpu, &mut mem).unwrap();
    let addr1 = cpu.reg(Reg::R0);

    // Second mmap64
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 4096);
    cpu.set_reg(Reg::R2, 3);
    cpu.set_reg(Reg::R3, 0x20);
    call_bionic(&mut bridge, BionicFuncId::Mmap64, &mut cpu, &mut mem).unwrap();
    let addr2 = cpu.reg(Reg::R0);

    assert_ne!(addr1, addr2, "two mmap calls must return distinct addresses");
    assert!(addr2 >= addr1 + 4096);
}

// ── mremap ───────────────────────────────────────────────────────────────────

#[test]
fn test_mremap_grow() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // Map 4096 bytes initially
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 4096);
    cpu.set_reg(Reg::R2, 3);
    cpu.set_reg(Reg::R3, 0x20);
    call_bionic(&mut bridge, BionicFuncId::Mmap, &mut cpu, &mut mem).unwrap();
    let old_addr = cpu.reg(Reg::R0);

    // Write a test marker
    mem.write_u32(GuestAddr::new(old_addr), 0x1234_5678).unwrap();

    // mremap(old_addr, 4096, 16384, MREMAP_MAYMOVE=1)
    cpu.set_reg(Reg::R0, old_addr);
    cpu.set_reg(Reg::R1, 4096);
    cpu.set_reg(Reg::R2, 16384);
    cpu.set_reg(Reg::R3, 1);
    call_bionic(&mut bridge, BionicFuncId::Mremap, &mut cpu, &mut mem).unwrap();
    let new_addr = cpu.reg(Reg::R0);

    assert_ne!(new_addr, u32::MAX);
    // Verify old contents were preserved in the new buffer
    assert_eq!(mem.read_u32(GuestAddr::new(new_addr)).unwrap(), 0x1234_5678);
}

// ── madvise, msync, mlock stubs ──────────────────────────────────────────────

#[test]
fn test_madvise_and_msync() {
    let (mut bridge, mut mem, mut cpu) = setup();

    cpu.set_reg(Reg::R0, 0x7100_0000);
    cpu.set_reg(Reg::R1, 4096);
    cpu.set_reg(Reg::R2, 0); // MADV_NORMAL
    call_bionic(&mut bridge, BionicFuncId::Madvise, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 0x7100_0000);
    cpu.set_reg(Reg::R1, 4096);
    cpu.set_reg(Reg::R2, 1); // MS_ASYNC
    call_bionic(&mut bridge, BionicFuncId::Msync, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_lock_apis() {
    let (mut bridge, mut mem, mut cpu) = setup();

    call_bionic(&mut bridge, BionicFuncId::Mlock, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    call_bionic(&mut bridge, BionicFuncId::Munlock, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    call_bionic(&mut bridge, BionicFuncId::Mlockall, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    call_bionic(&mut bridge, BionicFuncId::Munlockall, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

// ── mincore ──────────────────────────────────────────────────────────────────

#[test]
fn test_mincore() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let vec_buf = scratch(0);

    // mincore(0x7100_0000, 8192, vec_buf) -> 2 pages
    cpu.set_reg(Reg::R0, 0x7100_0000);
    cpu.set_reg(Reg::R1, 8192);
    cpu.set_reg(Reg::R2, vec_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Mincore, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Both pages should be marked resident (1)
    assert_eq!(mem.read_u8(vec_buf).unwrap(), 1);
    assert_eq!(mem.read_u8(vec_buf.add(1)).unwrap(), 1);
}
