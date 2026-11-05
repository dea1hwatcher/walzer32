//! Stage 95 integration tests: POSIX Vector & Positional File I/O
//! Tests: readv, writev, pread, pwrite, pread64, pwrite64, preadv, pwritev,
//!        posix_fallocate, posix_fallocate64, fallocate

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
fn test_vector_and_positional_io_symbols() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "readv",
        "writev",
        "pread",
        "pwrite",
        "pread64",
        "pwrite64",
        "preadv",
        "pwritev",
        "posix_fallocate",
        "posix_fallocate64",
        "fallocate",
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
fn test_readv_writev_pipe() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. Create a pipe: int pipefd[2]
    let pipe_fds_addr = GuestAddr::new(HEAP_START + 0x0100);
    cpu.set_reg(Reg::R0, pipe_fds_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Pipe, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let read_fd = mem.read_u32(pipe_fds_addr).unwrap();
    let write_fd = mem.read_u32(pipe_fds_addr.add(4)).unwrap();

    // 2. Prepare 2 data buffers in guest memory: "Hello, " (7 bytes) and "World!" (6 bytes)
    let buf1 = GuestAddr::new(HEAP_START + 0x0200);
    let buf2 = GuestAddr::new(HEAP_START + 0x0300);
    mem.write_bytes(buf1, b"Hello, ").unwrap();
    mem.write_bytes(buf2, b"World!").unwrap();

    // 3. Prepare struct iovec array for writev: iov[0] = {buf1, 7}, iov[1] = {buf2, 6}
    let write_iov = GuestAddr::new(HEAP_START + 0x0400);
    mem.write_u32(write_iov, buf1.as_u32()).unwrap();
    mem.write_u32(write_iov.add(4), 7).unwrap();
    mem.write_u32(write_iov.add(8), buf2.as_u32()).unwrap();
    mem.write_u32(write_iov.add(12), 6).unwrap();

    // 4. writev(write_fd, write_iov, 2)
    cpu.set_reg(Reg::R0, write_fd);
    cpu.set_reg(Reg::R1, write_iov.as_u32());
    cpu.set_reg(Reg::R2, 2);
    call_bionic(&mut bridge, BionicFuncId::Writev, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 13); // 7 + 6 = 13 bytes written

    // 5. Prepare struct iovec array for readv: iov[0] = {recv1, 5}, iov[1] = {recv2, 8}
    let recv1 = GuestAddr::new(HEAP_START + 0x0500);
    let recv2 = GuestAddr::new(HEAP_START + 0x0600);
    let read_iov = GuestAddr::new(HEAP_START + 0x0700);
    mem.write_u32(read_iov, recv1.as_u32()).unwrap();
    mem.write_u32(read_iov.add(4), 5).unwrap();
    mem.write_u32(read_iov.add(8), recv2.as_u32()).unwrap();
    mem.write_u32(read_iov.add(12), 8).unwrap();

    // 6. readv(read_fd, read_iov, 2)
    cpu.set_reg(Reg::R0, read_fd);
    cpu.set_reg(Reg::R1, read_iov.as_u32());
    cpu.set_reg(Reg::R2, 2);
    call_bionic(&mut bridge, BionicFuncId::Readv, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 13);

    // Verify received data: "Hello" in recv1, ", World!" in recv2
    let mut out1 = [0u8; 5];
    let mut out2 = [0u8; 8];
    mem.read_bytes(recv1, &mut out1).unwrap();
    mem.read_bytes(recv2, &mut out2).unwrap();
    assert_eq!(&out1, b"Hello");
    assert_eq!(&out2, b", World!");
}

#[test]
fn test_pread_pwrite_file() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // Register a file "/data/test.bin" with 32 bytes of 'A'
    bridge.vfs.register_file("/data/test.bin", vec![b'A'; 32]);

    // Open file: open("/data/test.bin", O_RDWR=2)
    let path_addr = GuestAddr::new(HEAP_START + 0x0100);
    mem.write_bytes(path_addr, b"/data/test.bin\0").unwrap();
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, 2);
    call_bionic(&mut bridge, BionicFuncId::Open, &mut cpu, &mut mem).unwrap();
    let fd = cpu.reg(Reg::R0);
    assert_ne!(fd, u32::MAX);

    // 1. pwrite(fd, "XYZ", 3, offset=10)
    let write_buf = GuestAddr::new(HEAP_START + 0x0200);
    mem.write_bytes(write_buf, b"XYZ").unwrap();
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, write_buf.as_u32());
    cpu.set_reg(Reg::R2, 3);
    cpu.set_reg(Reg::R3, 10);
    call_bionic(&mut bridge, BionicFuncId::Pwrite, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 3);

    // 2. pread(fd, out_buf, 3, offset=10)
    let read_buf = GuestAddr::new(HEAP_START + 0x0300);
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, read_buf.as_u32());
    cpu.set_reg(Reg::R2, 3);
    cpu.set_reg(Reg::R3, 10);
    call_bionic(&mut bridge, BionicFuncId::Pread, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 3);

    let mut out = [0u8; 3];
    mem.read_bytes(read_buf, &mut out).unwrap();
    assert_eq!(&out, b"XYZ");

    // Verify current cursor is still at 0 by doing normal read
    let cur_buf = GuestAddr::new(HEAP_START + 0x0400);
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, cur_buf.as_u32());
    cpu.set_reg(Reg::R2, 4);
    call_bionic(&mut bridge, BionicFuncId::Read, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 4);
    let mut head = [0u8; 4];
    mem.read_bytes(cur_buf, &mut head).unwrap();
    assert_eq!(&head, b"AAAA"); // Cursor was untouched at 0!

    // 3. pread64(fd, out_buf, 3, offset=10)
    let sp_addr = GuestAddr::new(HEAP_START + 0x0008_0000);
    mem.write_u32(sp_addr, 10).unwrap(); // low 32 bits
    mem.write_u32(sp_addr.add(4), 0).unwrap(); // high 32 bits
    cpu.set_reg(Reg::SP, sp_addr.as_u32());

    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, read_buf.as_u32());
    cpu.set_reg(Reg::R2, 3);
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::Pread64, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 3);
    mem.read_bytes(read_buf, &mut out).unwrap();
    assert_eq!(&out, b"XYZ");
}

#[test]
fn test_preadv_pwritev_file() {
    let (mut bridge, mut mem, mut cpu) = setup();

    bridge.vfs.register_file("/data/vector.bin", vec![0u8; 64]);

    let path_addr = GuestAddr::new(HEAP_START + 0x0100);
    mem.write_bytes(path_addr, b"/data/vector.bin\0").unwrap();
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, 2);
    call_bionic(&mut bridge, BionicFuncId::Open, &mut cpu, &mut mem).unwrap();
    let fd = cpu.reg(Reg::R0);
    assert_ne!(fd, u32::MAX);

    // 1. pwritev at offset 24: iov[0] = "123", iov[1] = "4567"
    let w1 = GuestAddr::new(HEAP_START + 0x0200);
    let w2 = GuestAddr::new(HEAP_START + 0x0250);
    mem.write_bytes(w1, b"123").unwrap();
    mem.write_bytes(w2, b"4567").unwrap();

    let write_iov = GuestAddr::new(HEAP_START + 0x0300);
    mem.write_u32(write_iov, w1.as_u32()).unwrap();
    mem.write_u32(write_iov.add(4), 3).unwrap();
    mem.write_u32(write_iov.add(8), w2.as_u32()).unwrap();
    mem.write_u32(write_iov.add(12), 4).unwrap();

    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, write_iov.as_u32());
    cpu.set_reg(Reg::R2, 2);
    cpu.set_reg(Reg::R3, 24); // offset 24
    call_bionic(&mut bridge, BionicFuncId::Pwritev, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 7);

    // 2. preadv at offset 24: iov[0] = 4 bytes, iov[1] = 3 bytes
    let r1 = GuestAddr::new(HEAP_START + 0x0400);
    let r2 = GuestAddr::new(HEAP_START + 0x0450);
    let read_iov = GuestAddr::new(HEAP_START + 0x0500);
    mem.write_u32(read_iov, r1.as_u32()).unwrap();
    mem.write_u32(read_iov.add(4), 4).unwrap();
    mem.write_u32(read_iov.add(8), r2.as_u32()).unwrap();
    mem.write_u32(read_iov.add(12), 3).unwrap();

    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, read_iov.as_u32());
    cpu.set_reg(Reg::R2, 2);
    cpu.set_reg(Reg::R3, 24);
    call_bionic(&mut bridge, BionicFuncId::Preadv, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 7);

    let mut out1 = [0u8; 4];
    let mut out2 = [0u8; 3];
    mem.read_bytes(r1, &mut out1).unwrap();
    mem.read_bytes(r2, &mut out2).unwrap();
    assert_eq!(&out1, b"1234");
    assert_eq!(&out2, b"567");
}

#[test]
fn test_posix_fallocate_and_fallocate() {
    let (mut bridge, mut mem, mut cpu) = setup();

    bridge.vfs.register_file("/data/alloc.bin", vec![0u8; 16]);
    let path_addr = GuestAddr::new(HEAP_START + 0x0100);
    mem.write_bytes(path_addr, b"/data/alloc.bin\0").unwrap();
    cpu.set_reg(Reg::R0, path_addr.as_u32());
    cpu.set_reg(Reg::R1, 2);
    call_bionic(&mut bridge, BionicFuncId::Open, &mut cpu, &mut mem).unwrap();
    let fd = cpu.reg(Reg::R0);
    assert_ne!(fd, u32::MAX);

    // 1. posix_fallocate with negative offset -> 22 (EINVAL)
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, (-1i32) as u32);
    cpu.set_reg(Reg::R2, 100);
    call_bionic(&mut bridge, BionicFuncId::PosixFallocate, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 22);

    // 2. posix_fallocate with zero length -> 22 (EINVAL)
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::PosixFallocate, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 22);

    // 3. posix_fallocate with invalid fd -> 9 (EBADF)
    cpu.set_reg(Reg::R0, 9999);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 100);
    call_bionic(&mut bridge, BionicFuncId::PosixFallocate, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 9);

    // 4. posix_fallocate valid -> 0 (OK)
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 1024);
    call_bionic(&mut bridge, BionicFuncId::PosixFallocate, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 5. fallocate valid -> 0
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, 0); // mode
    cpu.set_reg(Reg::R2, 0); // offset
    cpu.set_reg(Reg::R3, 1024); // len
    call_bionic(&mut bridge, BionicFuncId::Fallocate, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 6. fallocate invalid fd -> -1
    cpu.set_reg(Reg::R0, 9999);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 0);
    cpu.set_reg(Reg::R3, 1024);
    call_bionic(&mut bridge, BionicFuncId::Fallocate, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), u32::MAX);
}
