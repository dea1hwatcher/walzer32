//! Stage 83 integration tests: POSIX Message Queues (mqueue)
//! Tests: mq_open, mq_close, mq_unlink, mq_send, mq_receive,
//!        mq_timedsend, mq_timedreceive, mq_getattr, mq_setattr

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

fn write_str(mem: &mut impl Memory, addr: GuestAddr, s: &str) {
    let bytes = s.as_bytes();
    mem.write_bytes(addr, bytes).unwrap();
    mem.write_u8(addr.add(bytes.len() as u32), 0).unwrap();
}

#[test]
fn test_mq_lifecycle_and_rw() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let name_addr = GuestAddr::new(HEAP_START + 0x1000);
    let msg1_addr = GuestAddr::new(HEAP_START + 0x1040);
    let msg2_addr = GuestAddr::new(HEAP_START + 0x1060);
    let recv_addr = GuestAddr::new(HEAP_START + 0x1080);
    let prio_addr = GuestAddr::new(HEAP_START + 0x10C0);
    let attr_addr = GuestAddr::new(HEAP_START + 0x10E0);

    write_str(&mut mem, name_addr, "/test_queue");
    mem.write_bytes(msg1_addr, b"msg1").unwrap();
    mem.write_bytes(msg2_addr, b"msg2_longer").unwrap();

    // mq_open
    cpu.set_reg(Reg::R0, name_addr.as_u32());
    cpu.set_reg(Reg::R1, 0o102); // O_CREAT | O_RDWR
    call_bionic(&mut bridge, BionicFuncId::MqOpen, &mut cpu, &mut mem).unwrap();
    let mqdes = cpu.reg(Reg::R0);
    assert!(mqdes >= 400);

    // mq_getattr: curmsgs = 0
    cpu.set_reg(Reg::R0, mqdes);
    cpu.set_reg(Reg::R1, attr_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::MqGetattr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(attr_addr.add(12)).unwrap(), 0); // curmsgs

    // mq_send msg1 with priority 10
    cpu.set_reg(Reg::R0, mqdes);
    cpu.set_reg(Reg::R1, msg1_addr.as_u32());
    cpu.set_reg(Reg::R2, 4);
    cpu.set_reg(Reg::R3, 10);
    call_bionic(&mut bridge, BionicFuncId::MqSend, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // mq_send msg2 with priority 20
    cpu.set_reg(Reg::R0, mqdes);
    cpu.set_reg(Reg::R1, msg2_addr.as_u32());
    cpu.set_reg(Reg::R2, 11);
    cpu.set_reg(Reg::R3, 20);
    call_bionic(&mut bridge, BionicFuncId::MqSend, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // mq_getattr: curmsgs = 2
    cpu.set_reg(Reg::R0, mqdes);
    cpu.set_reg(Reg::R1, attr_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::MqGetattr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(attr_addr.add(12)).unwrap(), 2);

    // mq_receive msg1
    cpu.set_reg(Reg::R0, mqdes);
    cpu.set_reg(Reg::R1, recv_addr.as_u32());
    cpu.set_reg(Reg::R2, 64);
    cpu.set_reg(Reg::R3, prio_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::MqReceive, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 4);
    let mut b1 = [0u8; 4];
    mem.read_bytes(recv_addr, &mut b1).unwrap();
    assert_eq!(&b1, b"msg1");
    assert_eq!(mem.read_u32(prio_addr).unwrap(), 10);

    // mq_receive msg2
    cpu.set_reg(Reg::R0, mqdes);
    cpu.set_reg(Reg::R1, recv_addr.as_u32());
    cpu.set_reg(Reg::R2, 64);
    cpu.set_reg(Reg::R3, prio_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::MqReceive, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 11);
    let mut b2 = [0u8; 11];
    mem.read_bytes(recv_addr, &mut b2).unwrap();
    assert_eq!(&b2, b"msg2_longer");
    assert_eq!(mem.read_u32(prio_addr).unwrap(), 20);

    // mq_receive empty queue returns 0
    cpu.set_reg(Reg::R0, mqdes);
    cpu.set_reg(Reg::R1, recv_addr.as_u32());
    cpu.set_reg(Reg::R2, 64);
    cpu.set_reg(Reg::R3, prio_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::MqReceive, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // mq_close
    cpu.set_reg(Reg::R0, mqdes);
    call_bionic(&mut bridge, BionicFuncId::MqClose, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // mq_unlink
    cpu.set_reg(Reg::R0, name_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::MqUnlink, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Operations on closed mqdes return -1 (0xFFFF_FFFF)
    cpu.set_reg(Reg::R0, mqdes);
    cpu.set_reg(Reg::R1, msg1_addr.as_u32());
    cpu.set_reg(Reg::R2, 4);
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::MqSend, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0xFFFF_FFFF);
}

#[test]
fn test_mq_timed_variants_and_setattr() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let name_addr = GuestAddr::new(HEAP_START + 0x2000);
    let msg_addr = GuestAddr::new(HEAP_START + 0x2040);
    let recv_addr = GuestAddr::new(HEAP_START + 0x2060);
    let attr_addr = GuestAddr::new(HEAP_START + 0x2080);

    write_str(&mut mem, name_addr, "/timed_queue");
    mem.write_bytes(msg_addr, b"timed_msg").unwrap();

    // mq_open
    cpu.set_reg(Reg::R0, name_addr.as_u32());
    cpu.set_reg(Reg::R1, 0o102);
    call_bionic(&mut bridge, BionicFuncId::MqOpen, &mut cpu, &mut mem).unwrap();
    let mqdes = cpu.reg(Reg::R0);

    // mq_timedsend
    cpu.set_reg(Reg::R0, mqdes);
    cpu.set_reg(Reg::R1, msg_addr.as_u32());
    cpu.set_reg(Reg::R2, 9);
    cpu.set_reg(Reg::R3, 5);
    call_bionic(&mut bridge, BionicFuncId::MqTimedsend, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // mq_setattr
    cpu.set_reg(Reg::R0, mqdes);
    cpu.set_reg(Reg::R1, attr_addr.as_u32());
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::MqSetattr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // mq_timedreceive
    cpu.set_reg(Reg::R0, mqdes);
    cpu.set_reg(Reg::R1, recv_addr.as_u32());
    cpu.set_reg(Reg::R2, 64);
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::MqTimedreceive, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 9);
    let mut b = [0u8; 9];
    mem.read_bytes(recv_addr, &mut b).unwrap();
    assert_eq!(&b, b"timed_msg");
}

#[test]
fn test_symbol_resolution() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "mq_open", "mq_close", "mq_unlink",
        "mq_send", "mq_receive", "mq_timedsend",
        "mq_timedreceive", "mq_getattr", "mq_setattr",
    ];

    for sym in symbols {
        let addr = bridge.resolve(sym);
        assert!(addr.is_some(), "Symbol {} must be resolved", sym);
        assert_ne!(addr.unwrap().as_u32(), 0);
    }
}
