// Stage 60 integration tests: dup/dup2, fcntl, select/poll,
// getaddrinfo/freeaddrinfo, getnameinfo, gethostbyname/gethostbyname_r,
// getifaddrs/freeifaddrs, setsid/getpgrp/setpgid.

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

// ─── dup & dup2 ────────────────────────────────────────────────────────────

#[test]
fn test_dup_socket() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // Create socket
    cpu.set_reg(Reg::R0, 2); // AF_INET
    cpu.set_reg(Reg::R1, 1); // SOCK_STREAM
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::Socket, &mut cpu, &mut mem).unwrap();
    let sock_fd = cpu.reg(Reg::R0);
    assert!(sock_fd >= 10);

    // dup(sock_fd)
    cpu.set_reg(Reg::R0, sock_fd);
    call_bionic(&mut bridge, BionicFuncId::Dup, &mut cpu, &mut mem).unwrap();
    let dup_fd = cpu.reg(Reg::R0);
    assert_ne!(sock_fd, dup_fd);
    assert!(bridge.socket_fds.contains_key(&dup_fd));
}

#[test]
fn test_dup_pipe_read() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let arr  = scratch(0x00);
    let wbuf = scratch(0x20);
    let rbuf = scratch(0x40);

    // pipe()
    cpu.set_reg(Reg::R0, arr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Pipe, &mut cpu, &mut mem).unwrap();
    let read_fd  = mem.read_u32(arr).unwrap();
    let write_fd = mem.read_u32(arr.add(4)).unwrap();

    // write payload into pipe
    let payload = b"CLONE";
    for (i, b) in payload.iter().enumerate() {
        mem.write_u8(wbuf.add(i as u32), *b).unwrap();
    }
    cpu.set_reg(Reg::R0, write_fd);
    cpu.set_reg(Reg::R1, wbuf.as_u32());
    cpu.set_reg(Reg::R2, 5);
    call_bionic(&mut bridge, BionicFuncId::Write, &mut cpu, &mut mem).unwrap();

    // dup(read_fd) -> dup_read_fd
    cpu.set_reg(Reg::R0, read_fd);
    call_bionic(&mut bridge, BionicFuncId::Dup, &mut cpu, &mut mem).unwrap();
    let dup_read_fd = cpu.reg(Reg::R0);
    assert_ne!(read_fd, dup_read_fd);

    // read from duplicated fd
    cpu.set_reg(Reg::R0, dup_read_fd);
    cpu.set_reg(Reg::R1, rbuf.as_u32());
    cpu.set_reg(Reg::R2, 5);
    call_bionic(&mut bridge, BionicFuncId::Read, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 5);

    let mut result = [0u8; 5];
    for i in 0..5u32 {
        result[i as usize] = mem.read_u8(rbuf.add(i)).unwrap();
    }
    assert_eq!(&result, payload);
}

#[test]
fn test_dup2() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // dup2(old_fd=1, new_fd=50) -> 50
    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, 50);
    call_bionic(&mut bridge, BionicFuncId::Dup2, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 50);
}

// ─── fcntl ─────────────────────────────────────────────────────────────────

#[test]
fn test_fcntl() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // F_GETFL (3) -> O_RDWR (2)
    cpu.set_reg(Reg::R0, 10);
    cpu.set_reg(Reg::R1, 3);
    call_bionic(&mut bridge, BionicFuncId::Fcntl, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 2);

    // F_SETFL (4) -> 0
    cpu.set_reg(Reg::R0, 10);
    cpu.set_reg(Reg::R1, 4);
    cpu.set_reg(Reg::R2, 0x800); // O_NONBLOCK
    call_bionic(&mut bridge, BionicFuncId::Fcntl, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // F_GETFD (1) -> 0
    cpu.set_reg(Reg::R0, 10);
    cpu.set_reg(Reg::R1, 1);
    call_bionic(&mut bridge, BionicFuncId::Fcntl, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // F_SETFD (2) -> 0
    cpu.set_reg(Reg::R0, 10);
    cpu.set_reg(Reg::R1, 2);
    cpu.set_reg(Reg::R2, 1); // FD_CLOEXEC
    call_bionic(&mut bridge, BionicFuncId::Fcntl, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

// ─── select & poll ─────────────────────────────────────────────────────────

#[test]
fn test_select_and_poll() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // select(0, NULL, NULL, NULL, NULL) -> 0
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 0);
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::Select, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // poll(NULL, 0, 0) -> 0
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::Poll, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

// ─── Name and Address resolution ───────────────────────────────────────────

#[test]
fn test_name_resolution() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let res_ptr = scratch(0x100);

    // getaddrinfo("localhost", NULL, NULL, &res) -> EAI_AGAIN (11)
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 0);
    cpu.set_reg(Reg::R3, res_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Getaddrinfo, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 11);

    // freeaddrinfo(NULL) -> void (0)
    cpu.set_reg(Reg::R0, 0);
    call_bionic(&mut bridge, BionicFuncId::Freeaddrinfo, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // getnameinfo(...) -> EAI_AGAIN (11)
    call_bionic(&mut bridge, BionicFuncId::Getnameinfo, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 11);

    // gethostbyname("localhost") -> NULL (0)
    cpu.set_reg(Reg::R0, 0);
    call_bionic(&mut bridge, BionicFuncId::Gethostbyname, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // gethostbyname_r(..., result_ptr, ...) -> ENOENT (2), *result_ptr = 0
    mem.write_u32(res_ptr, 0x1234_5678).unwrap();
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 0);
    cpu.set_reg(Reg::R3, res_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::GethostbynameR, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 2);
    assert_eq!(mem.read_u32(res_ptr).unwrap(), 0);
}

// ─── Network Interface Enumeration ─────────────────────────────────────────

#[test]
fn test_ifaddrs() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let ifap_ptr = scratch(0x200);

    mem.write_u32(ifap_ptr, 0xDEAD_BEEF).unwrap();
    cpu.set_reg(Reg::R0, ifap_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Getifaddrs, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), u32::MAX); // -1
    assert_eq!(mem.read_u32(ifap_ptr).unwrap(), 0); // *ifap = NULL

    cpu.set_reg(Reg::R0, 0);
    call_bionic(&mut bridge, BionicFuncId::Freeifaddrs, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

// ─── Process group & session ───────────────────────────────────────────────

#[test]
fn test_process_group_and_session() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // setsid() -> pid
    call_bionic(&mut bridge, BionicFuncId::Setsid, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), bridge.pid);

    // getpgrp() -> pid
    call_bionic(&mut bridge, BionicFuncId::Getpgrp, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), bridge.pid);

    // setpgid(0, 0) -> 0
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::Setpgid, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}
