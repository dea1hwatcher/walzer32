// Stage 58 integration tests: dl_iterate_phdr, Atomic builtins (__atomic_*/__sync_*),
// POSIX Socket API, inet helpers (htons/htonl/ntohs/ntohl/inet_aton/inet_ntoa).

use transd_bridge::bionic::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use transd_core::{ArenaMemory, CpuState, GuestAddr, Memory, MemoryError, Reg};

const HEAP_START: u32 = 0x0002_0000;

fn call_bionic(
    bridge: &mut BionicBridge,
    func_id: BionicFuncId,
    cpu: &mut CpuState,
    mem: &mut impl transd_core::Memory,
) -> Result<bool, MemoryError> {
    bridge.handle_svc(BIONIC_SVC_MAGIC | (func_id as u32), cpu, mem)
}

fn setup() -> (BionicBridge, ArenaMemory, CpuState) {
    let mut mem = ArenaMemory::new().expect("arena");
    let stub_base  = GuestAddr::new(0x0001_0000);
    let heap_start = GuestAddr::new(HEAP_START);

    mem.commit_range(stub_base,  0x0001_0000).unwrap(); // stub region
    mem.commit_range(heap_start, 0x0010_0000).unwrap(); // heap + scratch

    let bridge = BionicBridge::new(stub_base, heap_start, 1024 * 1024);
    bridge.install_stubs(&mut mem).unwrap();
    let cpu = CpuState::new();
    (bridge, mem, cpu)
}

/// Scratch page inside the committed heap region.
fn scratch(offset: u32) -> GuestAddr {
    GuestAddr::new(HEAP_START + 0x8000 + offset)
}

// ─── dl_iterate_phdr stub ──────────────────────────────────────────────────

#[test]
fn test_dl_iterate_phdr_returns_zero() {
    let (mut bridge, mut mem, mut cpu) = setup();
    cpu.set_reg(Reg::R0, scratch(0).as_u32()); // callback ptr (ignored)
    cpu.set_reg(Reg::R1, 0);                    // data ptr
    call_bionic(&mut bridge, BionicFuncId::DlIteratePhdr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "dl_iterate_phdr returns 0 (stub, no iteration)");
}

// ─── Atomic builtins ───────────────────────────────────────────────────────

#[test]
fn test_atomic_fetch_add4() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let addr = scratch(0x00);
    mem.write_u32(addr, 10).unwrap();

    // __atomic_fetch_add_4(ptr, val=5, order=0) -> returns old=10, stores 15
    cpu.set_reg(Reg::R0, addr.as_u32());
    cpu.set_reg(Reg::R1, 5);
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::AtomicFetchAdd4, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 10, "returns old value");
    assert_eq!(mem.read_u32(addr).unwrap(), 15, "stores new value");
}

#[test]
fn test_atomic_load4_store4() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let addr = scratch(0x10);
    mem.write_u32(addr, 42).unwrap();

    // __atomic_load_4(ptr, order)
    cpu.set_reg(Reg::R0, addr.as_u32());
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::AtomicLoad4, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 42, "load returns value");

    // __atomic_store_4(ptr, val=99, order)
    cpu.set_reg(Reg::R0, addr.as_u32());
    cpu.set_reg(Reg::R1, 99);
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::AtomicStore4, &mut cpu, &mut mem).unwrap();
    assert_eq!(mem.read_u32(addr).unwrap(), 99, "store writes value");
}

#[test]
fn test_atomic_compare_exchange4_success() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let addr     = scratch(0x20);
    let exp_addr = scratch(0x24);
    mem.write_u32(addr, 7).unwrap();
    mem.write_u32(exp_addr, 7).unwrap(); // expected == current → CAS succeeds

    cpu.set_reg(Reg::R0, addr.as_u32());
    cpu.set_reg(Reg::R1, exp_addr.as_u32());
    cpu.set_reg(Reg::R2, 100);
    cpu.set_reg(Reg::R3, 0);
    // R4 is not accessible via Reg enum directly; set via regs array
    cpu.regs[4] = 0; // fail order
    call_bionic(&mut bridge, BionicFuncId::AtomicCompareExchange4, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1, "CAS success → 1");
    assert_eq!(mem.read_u32(addr).unwrap(), 100, "value updated");
}

#[test]
fn test_atomic_compare_exchange4_failure() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let addr     = scratch(0x30);
    let exp_addr = scratch(0x34);
    mem.write_u32(addr, 7).unwrap();
    mem.write_u32(exp_addr, 99).unwrap(); // expected ≠ current → CAS fails

    cpu.set_reg(Reg::R0, addr.as_u32());
    cpu.set_reg(Reg::R1, exp_addr.as_u32());
    cpu.set_reg(Reg::R2, 100);
    cpu.set_reg(Reg::R3, 0);
    cpu.regs[4] = 0;
    call_bionic(&mut bridge, BionicFuncId::AtomicCompareExchange4, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "CAS failure → 0");
    assert_eq!(mem.read_u32(addr).unwrap(), 7, "value unchanged");
    assert_eq!(mem.read_u32(exp_addr).unwrap(), 7, "expected ptr updated to actual");
}

#[test]
fn test_atomic_exchange4() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let addr = scratch(0x40);
    mem.write_u32(addr, 55).unwrap();

    cpu.set_reg(Reg::R0, addr.as_u32());
    cpu.set_reg(Reg::R1, 200);
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::AtomicExchange4, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 55, "returns old value");
    assert_eq!(mem.read_u32(addr).unwrap(), 200, "stores new value");
}

// ─── __sync_* builtins ─────────────────────────────────────────────────────

#[test]
fn test_sync_val_compare_and_swap4() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let addr = scratch(0x50);
    mem.write_u32(addr, 10).unwrap();

    // __sync_val_compare_and_swap_4(ptr, old=10, new=20) → returns old=10, stores 20
    cpu.set_reg(Reg::R0, addr.as_u32());
    cpu.set_reg(Reg::R1, 10);
    cpu.set_reg(Reg::R2, 20);
    call_bionic(&mut bridge, BionicFuncId::SyncValCompareAndSwap4, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 10, "returns old");
    assert_eq!(mem.read_u32(addr).unwrap(), 20, "swapped");
}

#[test]
fn test_sync_bool_compare_and_swap4() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let addr = scratch(0x60);
    mem.write_u32(addr, 5).unwrap();

    // Success case
    cpu.set_reg(Reg::R0, addr.as_u32());
    cpu.set_reg(Reg::R1, 5);
    cpu.set_reg(Reg::R2, 50);
    call_bionic(&mut bridge, BionicFuncId::SyncBoolCompareAndSwap4, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1, "success → 1");

    // Failure case (wrong old)
    cpu.set_reg(Reg::R0, addr.as_u32());
    cpu.set_reg(Reg::R1, 0); // wrong
    cpu.set_reg(Reg::R2, 99);
    call_bionic(&mut bridge, BionicFuncId::SyncBoolCompareAndSwap4, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "failure → 0");
}

#[test]
fn test_sync_fetch_and_add4() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let addr = scratch(0x70);
    mem.write_u32(addr, 3).unwrap();

    cpu.set_reg(Reg::R0, addr.as_u32());
    cpu.set_reg(Reg::R1, 4);
    call_bionic(&mut bridge, BionicFuncId::SyncFetchAndAdd4, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 3, "returns old");
    assert_eq!(mem.read_u32(addr).unwrap(), 7, "added");
}

#[test]
fn test_sync_fetch_and_sub4() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let addr = scratch(0x80);
    mem.write_u32(addr, 10).unwrap();

    cpu.set_reg(Reg::R0, addr.as_u32());
    cpu.set_reg(Reg::R1, 3);
    call_bionic(&mut bridge, BionicFuncId::SyncFetchAndSub4, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 10, "returns old");
    assert_eq!(mem.read_u32(addr).unwrap(), 7, "subtracted");
}

// ─── POSIX socket stubs ────────────────────────────────────────────────────

#[test]
fn test_socket_returns_valid_fd() {
    let (mut bridge, mut mem, mut cpu) = setup();

    cpu.set_reg(Reg::R0, 2); // AF_INET
    cpu.set_reg(Reg::R1, 1); // SOCK_STREAM
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::Socket, &mut cpu, &mut mem).unwrap();
    let fd1 = cpu.reg(Reg::R0);
    assert!(fd1 >= 10, "fd >= 10, got {}", fd1);

    cpu.set_reg(Reg::R0, 2);
    cpu.set_reg(Reg::R1, 2); // SOCK_DGRAM
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::Socket, &mut cpu, &mut mem).unwrap();
    let fd2 = cpu.reg(Reg::R0);
    assert!(fd2 > fd1, "second fd is unique");
}

#[test]
fn test_connect_send_recv_close() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // socket()
    cpu.set_reg(Reg::R0, 2);
    cpu.set_reg(Reg::R1, 1);
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::Socket, &mut cpu, &mut mem).unwrap();
    let fd = cpu.reg(Reg::R0);

    // connect(fd, sockaddr, 16) → 0
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, scratch(0x200).as_u32());
    cpu.set_reg(Reg::R2, 16);
    call_bionic(&mut bridge, BionicFuncId::SocketConnect, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "connect ok");

    // send(fd, buf, 8, 0) → 8
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, scratch(0x210).as_u32());
    cpu.set_reg(Reg::R2, 8);
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::SocketSend, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 8, "send returns len");

    // recv(fd, buf, 8, 0) → 0 (stub EOF)
    cpu.set_reg(Reg::R0, fd);
    cpu.set_reg(Reg::R1, scratch(0x210).as_u32());
    cpu.set_reg(Reg::R2, 8);
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::SocketRecv, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "recv returns 0 (EOF)");

    // close(fd) → 0
    cpu.set_reg(Reg::R0, fd);
    call_bionic(&mut bridge, BionicFuncId::SocketClose, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "close ok");

    // close again → EBADF (0xFFFF_FFFF)
    cpu.set_reg(Reg::R0, fd);
    call_bionic(&mut bridge, BionicFuncId::SocketClose, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), u32::MAX, "double-close → EBADF");
}

// ─── Byte-order helpers ────────────────────────────────────────────────────

#[test]
fn test_htons_ntohs() {
    let (mut bridge, mut mem, mut cpu) = setup();

    cpu.set_reg(Reg::R0, 0x1234);
    call_bionic(&mut bridge, BionicFuncId::Htons, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as u16, 0x3412, "htons(0x1234)");

    cpu.set_reg(Reg::R0, 0x3412);
    call_bionic(&mut bridge, BionicFuncId::Ntohs, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as u16, 0x1234, "ntohs(0x3412)");
}

#[test]
fn test_htonl_ntohl() {
    let (mut bridge, mut mem, mut cpu) = setup();

    cpu.set_reg(Reg::R0, 0x1234_5678);
    call_bionic(&mut bridge, BionicFuncId::Htonl, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0x7856_3412, "htonl(0x12345678)");

    cpu.set_reg(Reg::R0, 0x7856_3412);
    call_bionic(&mut bridge, BionicFuncId::Ntohl, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0x1234_5678, "ntohl(0x78563412)");
}

// ─── inet_aton / inet_ntoa ──────────────────────────────────────────────────

#[test]
fn test_inet_aton_valid() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let str_addr = scratch(0x300);
    let out_addr = scratch(0x310);

    // write "127.0.0.1\0"
    for (i, b) in b"127.0.0.1\0".iter().enumerate() {
        mem.write_u8(str_addr.add(i as u32), *b).unwrap();
    }

    cpu.set_reg(Reg::R0, str_addr.as_u32());
    cpu.set_reg(Reg::R1, out_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::InetAton, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1, "inet_aton returns 1 on success");

    // inet_aton stores the u32 in network byte order (big-endian value = 0x7F000001).
    // mem.write_u32 writes LE on host, so read back and verify the u32 value directly.
    let stored = mem.read_u32(out_addr).unwrap();
    assert_eq!(stored, 0x7F00_0001u32, "127.0.0.1 stored as 0x7F000001, got 0x{:08X}", stored);
}

#[test]
fn test_inet_aton_invalid() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let str_addr = scratch(0x320);
    let out_addr = scratch(0x330);

    for (i, b) in b"not.an.ip\0".iter().enumerate() {
        mem.write_u8(str_addr.add(i as u32), *b).unwrap();
    }

    cpu.set_reg(Reg::R0, str_addr.as_u32());
    cpu.set_reg(Reg::R1, out_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::InetAton, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "inet_aton returns 0 on failure");
}

#[test]
fn test_inet_ntoa() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 127.0.0.1 as network-byte-order u32: from_be_bytes([127,0,0,1])
    let addr_ne = u32::from_be_bytes([127, 0, 0, 1]);
    cpu.set_reg(Reg::R0, addr_ne);
    call_bionic(&mut bridge, BionicFuncId::InetNtoa, &mut cpu, &mut mem).unwrap();

    let buf_ptr = GuestAddr::new(cpu.reg(Reg::R0));
    let mut result = Vec::new();
    for i in 0u32..16 {
        let b = mem.read_u8(buf_ptr.add(i)).unwrap();
        if b == 0 { break; }
        result.push(b);
    }
    let s = std::str::from_utf8(&result).unwrap();
    assert_eq!(s, "127.0.0.1", "inet_ntoa");
}
