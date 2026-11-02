//! Stage 71 integration tests: POSIX Network & Socket Extensions
//! Tests: inet_ntop, inet_pton, gai_strerror, getservbyname, getservbyport,
//!        getprotobyname, getprotobynumber, socketpair, epoll_create/1,
//!        epoll_ctl, epoll_wait/pwait, pselect, ppoll, getaddrinfo

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

// ── inet_pton & inet_ntop ─────────────────────────────────────────────────────

#[test]
fn test_inet_pton_and_inet_ntop() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let ip_str = scratch(0x100);
    let bin_out = scratch(0x130);
    let text_out = scratch(0x150);

    mem.write_bytes(ip_str, b"192.168.1.50\0").unwrap();

    // 1. inet_pton(AF_INET = 2, "192.168.1.50", &bin_out)
    cpu.set_reg(Reg::R0, 2);
    cpu.set_reg(Reg::R1, ip_str.as_u32());
    cpu.set_reg(Reg::R2, bin_out.as_u32());
    call_bionic(&mut bridge, BionicFuncId::InetPton, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    let mut parsed_bytes = [0u8; 4];
    mem.read_bytes(bin_out, &mut parsed_bytes).unwrap();
    assert_eq!(parsed_bytes, [192, 168, 1, 50]);

    // 2. inet_pton with invalid address returns 0
    let bad_ip = scratch(0x180);
    mem.write_bytes(bad_ip, b"999.168.1.50\0").unwrap();
    cpu.set_reg(Reg::R0, 2);
    cpu.set_reg(Reg::R1, bad_ip.as_u32());
    cpu.set_reg(Reg::R2, bin_out.as_u32());
    call_bionic(&mut bridge, BionicFuncId::InetPton, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 3. inet_ntop(AF_INET = 2, &bin_out, text_out, size = 16)
    cpu.set_reg(Reg::R0, 2);
    cpu.set_reg(Reg::R1, bin_out.as_u32());
    cpu.set_reg(Reg::R2, text_out.as_u32());
    cpu.set_reg(Reg::R3, 16);
    call_bionic(&mut bridge, BionicFuncId::InetNtop, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), text_out.as_u32());

    let mut buf = [0u8; 13];
    mem.read_bytes(text_out, &mut buf).unwrap();
    assert_eq!(&buf[..12], b"192.168.1.50");

    // 4. inet_ntop with buffer too small returns 0
    cpu.set_reg(Reg::R0, 2);
    cpu.set_reg(Reg::R1, bin_out.as_u32());
    cpu.set_reg(Reg::R2, text_out.as_u32());
    cpu.set_reg(Reg::R3, 5); // too small for "192.168.1.50"
    call_bionic(&mut bridge, BionicFuncId::InetNtop, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

// ── gai_strerror ──────────────────────────────────────────────────────────────

#[test]
fn test_gai_strerror() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // gai_strerror(0) -> "Success"
    cpu.set_reg(Reg::R0, 0);
    call_bionic(&mut bridge, BionicFuncId::GaiStrerror, &mut cpu, &mut mem).unwrap();
    let ptr = GuestAddr::new(cpu.reg(Reg::R0));
    let mut buf = [0u8; 8];
    mem.read_bytes(ptr, &mut buf).unwrap();
    assert_eq!(&buf[..7], b"Success");

    // gai_strerror(2) -> "Temporary failure in name resolution"
    cpu.set_reg(Reg::R0, 2);
    call_bionic(&mut bridge, BionicFuncId::GaiStrerror, &mut cpu, &mut mem).unwrap();
    let ptr2 = GuestAddr::new(cpu.reg(Reg::R0));
    let mut buf2 = [0u8; 9];
    mem.read_bytes(ptr2, &mut buf2).unwrap();
    assert_eq!(&buf2[..9], b"Temporary");
}

// ── getservbyname & getservbyport ─────────────────────────────────────────────

#[test]
fn test_getservbyname_and_getservbyport() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let srv_name = scratch(0x200);
    mem.write_bytes(srv_name, b"http\0").unwrap();

    // 1. getservbyname("http", "tcp")
    cpu.set_reg(Reg::R0, srv_name.as_u32());
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::Getservbyname, &mut cpu, &mut mem).unwrap();
    let s_ptr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(s_ptr.as_u32(), 0);

    let s_port_raw = mem.read_u32(s_ptr.add(8)).unwrap() as u16;
    assert_eq!(u16::from_be(s_port_raw), 80);

    // 2. getservbyport(htons(443), "tcp")
    let port_443_be = 443u16.to_be();
    cpu.set_reg(Reg::R0, port_443_be as u32);
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::Getservbyport, &mut cpu, &mut mem).unwrap();
    let s_ptr2 = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(s_ptr2.as_u32(), 0);

    let name_ptr = GuestAddr::new(mem.read_u32(s_ptr2).unwrap());
    let mut nbuf = [0u8; 6];
    mem.read_bytes(name_ptr, &mut nbuf).unwrap();
    assert_eq!(&nbuf[..5], b"https");

    // 3. getservbyname for unknown service returns 0
    let unknown_srv = scratch(0x230);
    mem.write_bytes(unknown_srv, b"unknown_svc\0").unwrap();
    cpu.set_reg(Reg::R0, unknown_srv.as_u32());
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::Getservbyname, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

// ── getprotobyname & getprotobynumber ─────────────────────────────────────────

#[test]
fn test_getprotobyname_and_getprotobynumber() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let proto_name = scratch(0x250);
    mem.write_bytes(proto_name, b"tcp\0").unwrap();

    // 1. getprotobyname("tcp") -> proto 6
    cpu.set_reg(Reg::R0, proto_name.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Getprotobyname, &mut cpu, &mut mem).unwrap();
    let p_ptr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(p_ptr.as_u32(), 0);

    let proto_num = mem.read_u32(p_ptr.add(8)).unwrap();
    assert_eq!(proto_num, 6);

    // 2. getprotobynumber(17) -> "udp"
    cpu.set_reg(Reg::R0, 17);
    call_bionic(&mut bridge, BionicFuncId::Getprotobynumber, &mut cpu, &mut mem).unwrap();
    let p_ptr2 = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(p_ptr2.as_u32(), 0);

    let name_ptr = GuestAddr::new(mem.read_u32(p_ptr2).unwrap());
    let mut nbuf = [0u8; 4];
    mem.read_bytes(name_ptr, &mut nbuf).unwrap();
    assert_eq!(&nbuf[..3], b"udp");
}

// ── socketpair ────────────────────────────────────────────────────────────────

#[test]
fn test_socketpair_lifecycle() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let sv_buf = scratch(0x300);

    // socketpair(AF_UNIX = 1, SOCK_STREAM = 1, 0, sv)
    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, 1);
    cpu.set_reg(Reg::R2, 0);
    cpu.set_reg(Reg::R3, sv_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Socketpair, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let fd0 = mem.read_u32(sv_buf).unwrap();
    let fd1 = mem.read_u32(sv_buf.add(4)).unwrap();

    assert_ne!(fd0, fd1);
    assert!(bridge.socket_fds.contains_key(&fd0));
    assert!(bridge.socket_fds.contains_key(&fd1));

    // Close both sockets
    cpu.set_reg(Reg::R0, fd0);
    call_bionic(&mut bridge, BionicFuncId::SocketClose, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert!(!bridge.socket_fds.contains_key(&fd0));

    cpu.set_reg(Reg::R0, fd1);
    call_bionic(&mut bridge, BionicFuncId::SocketClose, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert!(!bridge.socket_fds.contains_key(&fd1));
}

// ── epoll (create, ctl, wait, close) ──────────────────────────────────────────

#[test]
fn test_epoll_full_lifecycle() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. epoll_create1(0) -> epfd
    cpu.set_reg(Reg::R0, 0);
    call_bionic(&mut bridge, BionicFuncId::EpollCreate1, &mut cpu, &mut mem).unwrap();
    let epfd = cpu.reg(Reg::R0);
    assert_ne!(epfd, 0);
    assert!(bridge.epoll_fds.contains_key(&epfd));

    // 2. epoll_ctl(epfd, EPOLL_CTL_ADD = 1, fd = 55, event)
    let ev_in = scratch(0x400);
    mem.write_u32(ev_in, 1).unwrap(); // EPOLLIN = 1
    mem.write_u32(ev_in.add(4), 0x9ABC_DEF0).unwrap(); // data low
    mem.write_u32(ev_in.add(8), 0x1234_5678).unwrap(); // data high

    cpu.set_reg(Reg::R0, epfd);
    cpu.set_reg(Reg::R1, 1); // ADD
    cpu.set_reg(Reg::R2, 55); // target fd
    cpu.set_reg(Reg::R3, ev_in.as_u32());
    call_bionic(&mut bridge, BionicFuncId::EpollCtl, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 3. epoll_wait(epfd, events_out, maxevents = 4, timeout = 0)
    let ev_out = scratch(0x450);
    cpu.set_reg(Reg::R0, epfd);
    cpu.set_reg(Reg::R1, ev_out.as_u32());
    cpu.set_reg(Reg::R2, 4);
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::EpollWait, &mut cpu, &mut mem).unwrap();
    let count = cpu.reg(Reg::R0);
    assert_eq!(count, 1);

    let out_ev = mem.read_u32(ev_out).unwrap();
    let out_data_low = mem.read_u32(ev_out.add(4)).unwrap();
    let out_data_high = mem.read_u32(ev_out.add(8)).unwrap();

    assert_eq!(out_ev, 1);
    assert_eq!(out_data_low, 0x9ABC_DEF0);
    assert_eq!(out_data_high, 0x1234_5678);

    // 4. epoll_ctl(epfd, EPOLL_CTL_DEL = 2, fd = 55, NULL)
    cpu.set_reg(Reg::R0, epfd);
    cpu.set_reg(Reg::R1, 2); // DEL
    cpu.set_reg(Reg::R2, 55);
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::EpollCtl, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 5. epoll_wait returns 0 when no fds monitored
    cpu.set_reg(Reg::R0, epfd);
    cpu.set_reg(Reg::R1, ev_out.as_u32());
    cpu.set_reg(Reg::R2, 4);
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::EpollWait, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 6. close(epfd)
    cpu.set_reg(Reg::R0, epfd);
    call_bionic(&mut bridge, BionicFuncId::SocketClose, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert!(!bridge.epoll_fds.contains_key(&epfd));
}

// ── getaddrinfo & pselect / ppoll ─────────────────────────────────────────────

#[test]
fn test_getaddrinfo_and_multiplexers() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let node_str = scratch(0x500);
    let serv_str = scratch(0x530);
    let hints_buf = scratch(0x550);
    let res_ptr = scratch(0x580);

    mem.write_bytes(node_str, b"192.168.0.1\0").unwrap();
    mem.write_bytes(serv_str, b"8080\0").unwrap();

    // hints: ai_socktype = SOCK_STREAM (1) at offset 8
    mem.write_u32(hints_buf.add(8), 1).unwrap();

    // getaddrinfo("192.168.0.1", "8080", hints, &res)
    cpu.set_reg(Reg::R0, node_str.as_u32());
    cpu.set_reg(Reg::R1, serv_str.as_u32());
    cpu.set_reg(Reg::R2, hints_buf.as_u32());
    cpu.set_reg(Reg::R3, res_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Getaddrinfo, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0); // EAI_SUCCESS

    let ai_addr = GuestAddr::new(mem.read_u32(res_ptr).unwrap());
    assert_ne!(ai_addr.as_u32(), 0);

    let family = mem.read_u32(ai_addr.add(4)).unwrap();
    let socktype = mem.read_u32(ai_addr.add(8)).unwrap();
    let addrlen = mem.read_u32(ai_addr.add(16)).unwrap();
    let sockaddr_ptr = GuestAddr::new(mem.read_u32(ai_addr.add(20)).unwrap());

    assert_eq!(family, 2); // AF_INET
    assert_eq!(socktype, 1); // SOCK_STREAM
    assert_eq!(addrlen, 16); // sizeof(sockaddr_in)

    // Inspect sockaddr_in
    let sin_family = mem.read_u16(sockaddr_ptr).unwrap();
    let sin_port = mem.read_u16(sockaddr_ptr.add(2)).unwrap();
    let mut sin_addr = [0u8; 4];
    mem.read_bytes(sockaddr_ptr.add(4), &mut sin_addr).unwrap();

    assert_eq!(sin_family, 2);
    assert_eq!(u16::from_be(sin_port), 8080);
    assert_eq!(sin_addr, [192, 168, 0, 1]);

    // freeaddrinfo
    cpu.set_reg(Reg::R0, ai_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Freeaddrinfo, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // pselect & ppoll return 0
    call_bionic(&mut bridge, BionicFuncId::Pselect, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    call_bionic(&mut bridge, BionicFuncId::Ppoll, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}
