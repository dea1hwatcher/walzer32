//! Stage 63 integration tests: Directory enumeration APIs
//! Tests: opendir, closedir, readdir, readdir64, rewinddir, telldir, seekdir, fdopendir, dirfd

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

fn write_str(mem: &mut impl Memory, addr: GuestAddr, s: &str) {
    let bytes = s.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        mem.write_u8(addr.add(i as u32), *b).unwrap();
    }
    mem.write_u8(addr.add(bytes.len() as u32), 0).unwrap();
}

fn read_dirent_name(mem: &impl Memory, dirent_ptr: u32) -> String {
    // ARM32 dirent64 layout: ino(8) + off(8) + reclen(2) + type(1) + name[256]
    // name starts at offset 19
    let name_addr = GuestAddr::new(dirent_ptr + 19);
    let mut bytes = Vec::new();
    for i in 0..255u32 {
        let b = mem.read_u8(name_addr.add(i)).unwrap_or(0);
        if b == 0 {
            break;
        }
        bytes.push(b);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

// ── opendir ──────────────────────────────────────────────────────────────────

#[test]
fn test_opendir_proc_succeeds() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let path_ptr = scratch(0);
    write_str(&mut mem, path_ptr, "/proc");
    cpu.set_reg(Reg::R0, path_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Opendir, &mut cpu, &mut mem).unwrap();
    let handle = cpu.reg(Reg::R0);
    assert_ne!(handle, 0, "opendir(/proc) should succeed");
    assert!(bridge.dir_handles.contains_key(&handle));
}

#[test]
fn test_opendir_missing_path_returns_null() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let path_ptr = scratch(0);
    write_str(&mut mem, path_ptr, "/nonexistent/path/xyz");
    cpu.set_reg(Reg::R0, path_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Opendir, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "opendir on missing path should return NULL");
}

#[test]
fn test_opendir_slash_root() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let path_ptr = scratch(0);
    write_str(&mut mem, path_ptr, "/");
    cpu.set_reg(Reg::R0, path_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Opendir, &mut cpu, &mut mem).unwrap();
    // "/" is a special-cased valid prefix
    let handle = cpu.reg(Reg::R0);
    assert_ne!(handle, 0, "opendir('/') should succeed");
}

// ── readdir ───────────────────────────────────────────────────────────────────

#[test]
fn test_readdir_returns_entry() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let path_ptr = scratch(0);
    write_str(&mut mem, path_ptr, "/proc");
    cpu.set_reg(Reg::R0, path_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Opendir, &mut cpu, &mut mem).unwrap();
    let handle = cpu.reg(Reg::R0);
    assert_ne!(handle, 0);

    cpu.set_reg(Reg::R0, handle);
    call_bionic(&mut bridge, BionicFuncId::Readdir, &mut cpu, &mut mem).unwrap();
    let dirent_ptr = cpu.reg(Reg::R0);
    assert_ne!(dirent_ptr, 0, "first readdir should return non-NULL");

    let name = read_dirent_name(&mem, dirent_ptr);
    assert!(!name.is_empty(), "dirent name should not be empty");
    // VFS has /proc/cpuinfo and /proc/version → children are "cpuinfo" and "version"
    assert!(
        name == "cpuinfo" || name == "version" || name == "self",
        "unexpected name: {name}"
    );
}

#[test]
fn test_readdir_end_of_dir_returns_null() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let path_ptr = scratch(0);
    write_str(&mut mem, path_ptr, "/proc");
    cpu.set_reg(Reg::R0, path_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Opendir, &mut cpu, &mut mem).unwrap();
    let handle = cpu.reg(Reg::R0);
    assert_ne!(handle, 0);

    let mut count = 0;
    loop {
        cpu.set_reg(Reg::R0, handle);
        call_bionic(&mut bridge, BionicFuncId::Readdir, &mut cpu, &mut mem).unwrap();
        if cpu.reg(Reg::R0) == 0 {
            break;
        }
        count += 1;
        assert!(count < 100, "readdir loop: too many entries");
    }
    assert!(count > 0, "expected at least one entry under /proc");
}

#[test]
fn test_readdir64_same_semantics() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let path_ptr = scratch(0);
    write_str(&mut mem, path_ptr, "/proc");
    cpu.set_reg(Reg::R0, path_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Opendir, &mut cpu, &mut mem).unwrap();
    let handle = cpu.reg(Reg::R0);

    cpu.set_reg(Reg::R0, handle);
    call_bionic(&mut bridge, BionicFuncId::Readdir64, &mut cpu, &mut mem).unwrap();
    assert_ne!(cpu.reg(Reg::R0), 0, "readdir64 first call should return non-NULL");
}

// ── closedir ──────────────────────────────────────────────────────────────────

#[test]
fn test_closedir_valid() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let path_ptr = scratch(0);
    write_str(&mut mem, path_ptr, "/proc");
    cpu.set_reg(Reg::R0, path_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Opendir, &mut cpu, &mut mem).unwrap();
    let handle = cpu.reg(Reg::R0);

    cpu.set_reg(Reg::R0, handle);
    call_bionic(&mut bridge, BionicFuncId::Closedir, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "closedir should return 0");
    assert!(!bridge.dir_handles.contains_key(&handle));
}

#[test]
fn test_closedir_invalid_returns_minus_one() {
    let (mut bridge, mut mem, mut cpu) = setup();
    cpu.set_reg(Reg::R0, 9999);
    call_bionic(&mut bridge, BionicFuncId::Closedir, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), u32::MAX, "closedir(invalid) should return -1");
}

// ── rewinddir ─────────────────────────────────────────────────────────────────

#[test]
fn test_rewinddir_resets_index() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let path_ptr = scratch(0);
    write_str(&mut mem, path_ptr, "/proc");
    cpu.set_reg(Reg::R0, path_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Opendir, &mut cpu, &mut mem).unwrap();
    let handle = cpu.reg(Reg::R0);

    // Advance one entry
    cpu.set_reg(Reg::R0, handle);
    call_bionic(&mut bridge, BionicFuncId::Readdir, &mut cpu, &mut mem).unwrap();
    assert_eq!(bridge.dir_handles[&handle].1, 1);

    // Rewind
    cpu.set_reg(Reg::R0, handle);
    call_bionic(&mut bridge, BionicFuncId::Rewinddir, &mut cpu, &mut mem).unwrap();
    assert_eq!(bridge.dir_handles[&handle].1, 0, "index should be 0 after rewinddir");

    // First entry is available again
    cpu.set_reg(Reg::R0, handle);
    call_bionic(&mut bridge, BionicFuncId::Readdir, &mut cpu, &mut mem).unwrap();
    assert_ne!(cpu.reg(Reg::R0), 0, "readdir after rewinddir should succeed");
}

// ── telldir / seekdir ──────────────────────────────────────────────────────────

#[test]
fn test_telldir_tracks_position() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let path_ptr = scratch(0);
    write_str(&mut mem, path_ptr, "/proc");
    cpu.set_reg(Reg::R0, path_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Opendir, &mut cpu, &mut mem).unwrap();
    let handle = cpu.reg(Reg::R0);

    // Initial position = 0
    cpu.set_reg(Reg::R0, handle);
    call_bionic(&mut bridge, BionicFuncId::Telldir, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Read one entry → position = 1
    cpu.set_reg(Reg::R0, handle);
    call_bionic(&mut bridge, BionicFuncId::Readdir, &mut cpu, &mut mem).unwrap();

    cpu.set_reg(Reg::R0, handle);
    call_bionic(&mut bridge, BionicFuncId::Telldir, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);
}

#[test]
fn test_seekdir_sets_position() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let path_ptr = scratch(0);
    write_str(&mut mem, path_ptr, "/proc");
    cpu.set_reg(Reg::R0, path_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Opendir, &mut cpu, &mut mem).unwrap();
    let handle = cpu.reg(Reg::R0);

    cpu.set_reg(Reg::R0, handle);
    cpu.set_reg(Reg::R1, 2);
    call_bionic(&mut bridge, BionicFuncId::Seekdir, &mut cpu, &mut mem).unwrap();
    assert_eq!(bridge.dir_handles[&handle].1, 2);
}

// ── dirfd ─────────────────────────────────────────────────────────────────────

#[test]
fn test_dirfd_returns_minus_one() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let path_ptr = scratch(0);
    write_str(&mut mem, path_ptr, "/proc");
    cpu.set_reg(Reg::R0, path_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Opendir, &mut cpu, &mut mem).unwrap();
    let handle = cpu.reg(Reg::R0);

    cpu.set_reg(Reg::R0, handle);
    call_bionic(&mut bridge, BionicFuncId::Dirfd, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), u32::MAX, "dirfd should return -1");
}

// ── two independent handles ────────────────────────────────────────────────────

#[test]
fn test_two_independent_handles() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let path_ptr = scratch(0);
    write_str(&mut mem, path_ptr, "/proc");

    cpu.set_reg(Reg::R0, path_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Opendir, &mut cpu, &mut mem).unwrap();
    let h1 = cpu.reg(Reg::R0);

    cpu.set_reg(Reg::R0, path_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Opendir, &mut cpu, &mut mem).unwrap();
    let h2 = cpu.reg(Reg::R0);

    assert_ne!(h1, 0);
    assert_ne!(h2, 0);
    assert_ne!(h1, h2, "two opendir calls must yield distinct handles");

    // Advance h1 only
    cpu.set_reg(Reg::R0, h1);
    call_bionic(&mut bridge, BionicFuncId::Readdir, &mut cpu, &mut mem).unwrap();

    assert_eq!(bridge.dir_handles[&h2].1, 0, "h2 index must remain 0");

    // Clean up
    cpu.set_reg(Reg::R0, h1);
    call_bionic(&mut bridge, BionicFuncId::Closedir, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, h2);
    call_bionic(&mut bridge, BionicFuncId::Closedir, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}
