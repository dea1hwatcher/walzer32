// Stage 61 integration tests: POSIX File System & Directory APIs
// open, openat, lseek, lseek64, stat, stat64, fstat, fstat64, access, faccessat,
// getcwd, chdir, readlink, mkdir, unlink, rename.

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
    let stub_base  = GuestAddr::new(STUB_BASE);
    let heap_start = GuestAddr::new(HEAP_START);

    mem.commit_range(stub_base,  0x0001_0000).unwrap();
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

fn read_str(mem: &impl Memory, addr: GuestAddr) -> String {
    let mut bytes = Vec::new();
    let mut i = 0u32;
    loop {
        let b = mem.read_u8(addr.add(i)).unwrap();
        if b == 0 { break; }
        bytes.push(b);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

// ─── Open, Read, Close ─────────────────────────────────────────────────────

#[test]
fn test_open_read_close() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let path_addr = scratch(0x00);
    let buf_addr  = scratch(0x100);

    write_str(&mut mem, path_addr, "/proc/cpuinfo");

    // open("/proc/cpuinfo", O_RDONLY=0)
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::Open, &mut cpu, &mut mem).unwrap();
    let fd = cpu.reg(Reg::R0);
    assert!(fd >= 3, "open should return fd >= 3, got {}", fd);

    // read(fd, buf, 64)
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, buf_addr.as_u32());
    cpu.set_reg(Reg::R2, 64);
    call_bionic(&mut bridge, BionicFuncId::Read, &mut cpu, &mut mem).unwrap();
    let n = cpu.reg(Reg::R0);
    assert_eq!(n, 64);

    let mut data = vec![0u8; n as usize];
    for i in 0..n {
        data[i as usize] = mem.read_u8(buf_addr.add(i)).unwrap();
    }
    let text = String::from_utf8_lossy(&data);
    assert!(text.contains("processor"), "expected processor info, got {}", text);

    // close(fd) -> 0
    cpu.set_reg(Reg::R0, fd);
    call_bionic(&mut bridge, BionicFuncId::SocketClose, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // close(fd) again -> -1 (EBADF)
    cpu.set_reg(Reg::R0, fd);
    call_bionic(&mut bridge, BionicFuncId::SocketClose, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), u32::MAX);
}

// ─── Lseek ─────────────────────────────────────────────────────────────────

#[test]
fn test_lseek() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let path_addr = scratch(0x00);
    let buf_addr  = scratch(0x100);

    write_str(&mut mem, path_addr, "/proc/version");

    // open("/proc/version", 0)
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::Open, &mut cpu, &mut mem).unwrap();
    let fd = cpu.reg(Reg::R0);

    // lseek(fd, 6, SEEK_SET=0)
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, 6);
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::Lseek, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 6);

    // read 7 bytes ("version")
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, buf_addr.as_u32());
    cpu.set_reg(Reg::R2, 7);
    call_bionic(&mut bridge, BionicFuncId::Read, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 7);

    let mut data = vec![0u8; 7];
    for i in 0..7u32 {
        data[i as usize] = mem.read_u8(buf_addr.add(i)).unwrap();
    }
    assert_eq!(std::str::from_utf8(&data).unwrap(), "version");

    // close
    cpu.set_reg(Reg::R0, fd);
    call_bionic(&mut bridge, BionicFuncId::SocketClose, &mut cpu, &mut mem).unwrap();
}

// ─── Stat and Fstat ────────────────────────────────────────────────────────

#[test]
fn test_stat64_and_fstat64() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let path_addr = scratch(0x00);
    let stat_buf  = scratch(0x200);

    write_str(&mut mem, path_addr, "/system/build.prop");

    // stat64("/system/build.prop", &stat_buf) -> 0
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, stat_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Stat64, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Read st_size from stat_buf: offset 44 (8 bytes i64)
    let size_lo = mem.read_u32(stat_buf.add(44)).unwrap() as u64;
    let size_hi = mem.read_u32(stat_buf.add(48)).unwrap() as u64;
    let st_size = (size_lo | (size_hi << 32)) as i64;
    assert!(st_size > 50, "expected build.prop size > 50, got {}", st_size);

    // open and fstat64
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::Open, &mut cpu, &mut mem).unwrap();
    let fd = cpu.reg(Reg::R0);

    let fstat_buf = scratch(0x300);
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, fstat_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Fstat64, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let fsize_lo = mem.read_u32(fstat_buf.add(44)).unwrap() as u64;
    let fsize_hi = mem.read_u32(fstat_buf.add(48)).unwrap() as u64;
    let fst_size = (fsize_lo | (fsize_hi << 32)) as i64;
    assert_eq!(st_size, fst_size);

    cpu.set_reg(Reg::R0, fd);
    call_bionic(&mut bridge, BionicFuncId::SocketClose, &mut cpu, &mut mem).unwrap();
}

// ─── Access ────────────────────────────────────────────────────────────────

#[test]
fn test_access() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let path_ok = scratch(0x00);
    let path_err = scratch(0x100);

    write_str(&mut mem, path_ok, "/proc/cpuinfo");
    write_str(&mut mem, path_err, "/nonexistent/path/file");

    // access("/proc/cpuinfo", 0) -> 0
    cpu.set_reg(Reg::R0, path_ok.as_u32());
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::Access, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // access("/nonexistent/path/file", 0) -> -1
    cpu.set_reg(Reg::R0, path_err.as_u32());
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::Access, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), u32::MAX);
}

// ─── Getcwd & Chdir ────────────────────────────────────────────────────────

#[test]
fn test_getcwd_and_chdir() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let buf_addr  = scratch(0x00);
    let path_addr = scratch(0x200);

    // getcwd(buf, 256) -> buf
    cpu.set_reg(Reg::R0, buf_addr.as_u32());
    cpu.set_reg(Reg::R1, 256);
    call_bionic(&mut bridge, BionicFuncId::Getcwd, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), buf_addr.as_u32());
    let s = read_str(&mem, buf_addr);
    assert_eq!(s, "/data/data/com.transd.app");

    // chdir("/data/local/tmp")
    write_str(&mut mem, path_addr, "/data/local/tmp");
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Chdir, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // getcwd(buf, 256) -> "/data/local/tmp"
    cpu.set_reg(Reg::R0, buf_addr.as_u32());
    cpu.set_reg(Reg::R1, 256);
    call_bionic(&mut bridge, BionicFuncId::Getcwd, &mut cpu, &mut mem).unwrap();
    let s2 = read_str(&mem, buf_addr);
    assert_eq!(s2, "/data/local/tmp");
}

// ─── Readlink ──────────────────────────────────────────────────────────────

#[test]
fn test_readlink_proc_self_exe() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let path_addr = scratch(0x00);
    let buf_addr  = scratch(0x100);

    write_str(&mut mem, path_addr, "/proc/self/exe");

    // readlink("/proc/self/exe", buf, 64) -> count
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, buf_addr.as_u32());
    cpu.set_reg(Reg::R2, 64);
    call_bionic(&mut bridge, BionicFuncId::Readlink, &mut cpu, &mut mem).unwrap();
    let len = cpu.reg(Reg::R0);
    assert_eq!(len, 25);

    let mut bytes = vec![0u8; len as usize];
    for i in 0..len {
        bytes[i as usize] = mem.read_u8(buf_addr.add(i)).unwrap();
    }
    assert_eq!(std::str::from_utf8(&bytes).unwrap(), "/system/bin/app_process32");
}

// ─── Stubs (mkdir, unlink, rename) ─────────────────────────────────────────

#[test]
fn test_directory_stubs() {
    let (mut bridge, mut mem, mut cpu) = setup();

    call_bionic(&mut bridge, BionicFuncId::Mkdir, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    call_bionic(&mut bridge, BionicFuncId::Unlink, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    call_bionic(&mut bridge, BionicFuncId::Rename, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}
