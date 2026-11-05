//! Stage 74 integration tests: Extended Filesystem & Path APIs
//! Tests: symlink, symlinkat, link, linkat, chmod, fchmod, fchmodat,
//!        chown, fchown, lchown, fchownat, mknod, mknodat,
//!        sync, fsync, fdatasync, pipe2, dup3, statfs, statfs64,
//!        fstatfs, fstatfs64, statvfs, fstatvfs

use walzer32_bridge::bionic::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use walzer32_core::{ArenaMemory, CpuState, GuestAddr, Memory, MemoryError, Reg};

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

// ── pipe2 & dup3 ─────────────────────────────────────────────────────────────

#[test]
fn test_pipe2_and_dup3() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let pipefd_buf = scratch(0x100);

    // 1. pipe2(pipefds, flags = 0x80000)
    cpu.set_reg(Reg::R0, pipefd_buf.as_u32());
    cpu.set_reg(Reg::R1, 0x80000); // O_CLOEXEC
    call_bionic(&mut bridge, BionicFuncId::Pipe2, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let rfd = mem.read_u32(pipefd_buf).unwrap();
    let wfd = mem.read_u32(pipefd_buf.add(4)).unwrap();

    assert_ne!(rfd, wfd);
    assert!(bridge.pipe_fds.contains_key(&rfd));

    // 2. dup3 with oldfd == newfd returns -1 (EINVAL per POSIX)
    cpu.set_reg(Reg::R0, rfd);
    cpu.set_reg(Reg::R1, rfd);
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::Dup3, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0xFFFF_FFFF);

    // 3. dup3 with newfd != oldfd returns newfd
    cpu.set_reg(Reg::R0, rfd);
    cpu.set_reg(Reg::R1, 77);
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::Dup3, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 77);
}

// ── statfs & statvfs ──────────────────────────────────────────────────────────

#[test]
fn test_statfs_and_statvfs() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let path_str = scratch(0x200);
    mem.write_bytes(path_str, b"/data\0").unwrap();

    let buf = scratch(0x230);

    // 1. statfs("/data", &buf)
    cpu.set_reg(Reg::R0, path_str.as_u32());
    cpu.set_reg(Reg::R1, buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Statfs, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let f_type = mem.read_u32(buf).unwrap();
    let f_bsize = mem.read_u32(buf.add(4)).unwrap();
    let f_blocks = mem.read_u32(buf.add(8)).unwrap();
    let f_bfree = mem.read_u32(buf.add(12)).unwrap();
    let f_namelen = mem.read_u32(buf.add(36)).unwrap();

    assert_eq!(f_type, 0xEF53); // ext4 magic
    assert_eq!(f_bsize, 4096);
    assert_eq!(f_blocks, 10_485_760);
    assert_eq!(f_bfree, 5_242_880);
    assert_eq!(f_namelen, 255);

    // 2. fstatfs(fd = 1, &buf)
    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Fstatfs, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 3. statvfs("/data", &buf)
    cpu.set_reg(Reg::R0, path_str.as_u32());
    cpu.set_reg(Reg::R1, buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Statvfs, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 4. fstatvfs(fd = 1, &buf)
    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Fstatvfs, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

// ── symlink, link, chmod, chown, mknod, sync ──────────────────────────────────

#[test]
fn test_symlink_link_chmod_chown_mknod_sync() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let target = scratch(0x300);
    let linkpath = scratch(0x330);
    mem.write_bytes(target, b"target.txt\0").unwrap();
    mem.write_bytes(linkpath, b"link.txt\0").unwrap();

    // symlink & symlinkat
    cpu.set_reg(Reg::R0, target.as_u32());
    cpu.set_reg(Reg::R1, linkpath.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Symlink, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, target.as_u32());
    cpu.set_reg(Reg::R1, 0xFFFF_FF9C); // AT_FDCWD (-100)
    cpu.set_reg(Reg::R2, linkpath.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Symlinkat, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // link & linkat
    cpu.set_reg(Reg::R0, target.as_u32());
    cpu.set_reg(Reg::R1, linkpath.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Link, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 0xFFFF_FF9C);
    cpu.set_reg(Reg::R1, target.as_u32());
    cpu.set_reg(Reg::R2, 0xFFFF_FF9C);
    cpu.set_reg(Reg::R3, linkpath.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Linkat, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // chmod, fchmod, fchmodat
    cpu.set_reg(Reg::R0, target.as_u32());
    cpu.set_reg(Reg::R1, 0o644);
    call_bionic(&mut bridge, BionicFuncId::Chmod, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, 0o644);
    call_bionic(&mut bridge, BionicFuncId::Fchmod, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 0xFFFF_FF9C);
    cpu.set_reg(Reg::R1, target.as_u32());
    cpu.set_reg(Reg::R2, 0o644);
    call_bionic(&mut bridge, BionicFuncId::Fchmodat, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // chown, fchown, lchown, fchownat
    cpu.set_reg(Reg::R0, target.as_u32());
    cpu.set_reg(Reg::R1, 1000);
    cpu.set_reg(Reg::R2, 1000);
    call_bionic(&mut bridge, BionicFuncId::Chown, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, 1000);
    cpu.set_reg(Reg::R2, 1000);
    call_bionic(&mut bridge, BionicFuncId::Fchown, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, target.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Lchown, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 0xFFFF_FF9C);
    cpu.set_reg(Reg::R1, target.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Fchownat, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // mknod & mknodat
    cpu.set_reg(Reg::R0, target.as_u32());
    cpu.set_reg(Reg::R1, 0o10644);
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::Mknod, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 0xFFFF_FF9C);
    cpu.set_reg(Reg::R1, target.as_u32());
    cpu.set_reg(Reg::R2, 0o10644);
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::Mknodat, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // sync, fsync, fdatasync
    call_bionic(&mut bridge, BionicFuncId::Sync, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 1);
    call_bionic(&mut bridge, BionicFuncId::Fsync, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 1);
    call_bionic(&mut bridge, BionicFuncId::Fdatasync, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}
