//! Stage 77 integration tests: EventFD & POSIX Asynchronous I/O APIs
//! Tests: eventfd, eventfd_read, eventfd_write, aio_read, aio_write,
//!        aio_error, aio_return, aio_suspend, aio_cancel

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
fn test_eventfd_counter_mode() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let val_addr = GuestAddr::new(HEAP_START + 0x1000);

    // Create eventfd with initval = 10
    cpu.set_reg(Reg::R0, 10);
    cpu.set_reg(Reg::R1, 0); // flags = 0 (counter mode)
    call_bionic(&mut bridge, BionicFuncId::Eventfd, &mut cpu, &mut mem).unwrap();
    let efd = cpu.reg(Reg::R0);
    assert!(efd >= 300);

    // Read initial value
    cpu.set_reg(Reg::R0, efd);
    cpu.set_reg(Reg::R1, val_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::EventfdRead, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    let low = mem.read_u32(val_addr).unwrap() as u64;
    let high = mem.read_u32(val_addr.add(4)).unwrap() as u64;
    let val = (high << 32) | low;
    assert_eq!(val, 10);

    // Second read should return 0 (reset in counter mode)
    cpu.set_reg(Reg::R0, efd);
    cpu.set_reg(Reg::R1, val_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::EventfdRead, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    let low = mem.read_u32(val_addr).unwrap() as u64;
    let high = mem.read_u32(val_addr.add(4)).unwrap() as u64;
    assert_eq!((high << 32) | low, 0);

    // Write 5 to eventfd (AAPCS: R0=fd, R2:R3=value)
    cpu.set_reg(Reg::R0, efd);
    cpu.set_reg(Reg::R1, 0); // padding
    cpu.set_reg(Reg::R2, 5);
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::EventfdWrite, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Write 15 to eventfd
    cpu.set_reg(Reg::R0, efd);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 15);
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::EventfdWrite, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Read accumulated 20
    cpu.set_reg(Reg::R0, efd);
    cpu.set_reg(Reg::R1, val_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::EventfdRead, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    let low = mem.read_u32(val_addr).unwrap() as u64;
    let high = mem.read_u32(val_addr.add(4)).unwrap() as u64;
    assert_eq!((high << 32) | low, 20);
}

#[test]
fn test_eventfd_semaphore_mode() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let val_addr = GuestAddr::new(HEAP_START + 0x2000);

    // Create eventfd with initval = 2, flags = 1 (EFD_SEMAPHORE)
    cpu.set_reg(Reg::R0, 2);
    cpu.set_reg(Reg::R1, 1);
    call_bionic(&mut bridge, BionicFuncId::Eventfd, &mut cpu, &mut mem).unwrap();
    let efd = cpu.reg(Reg::R0);

    // First read -> 1
    cpu.set_reg(Reg::R0, efd);
    cpu.set_reg(Reg::R1, val_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::EventfdRead, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    let low = mem.read_u32(val_addr).unwrap() as u64;
    let high = mem.read_u32(val_addr.add(4)).unwrap() as u64;
    assert_eq!((high << 32) | low, 1);

    // Second read -> 1
    cpu.set_reg(Reg::R0, efd);
    cpu.set_reg(Reg::R1, val_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::EventfdRead, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    let low = mem.read_u32(val_addr).unwrap() as u64;
    let high = mem.read_u32(val_addr.add(4)).unwrap() as u64;
    assert_eq!((high << 32) | low, 1);

    // Third read -> 0
    cpu.set_reg(Reg::R0, efd);
    cpu.set_reg(Reg::R1, val_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::EventfdRead, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    let low = mem.read_u32(val_addr).unwrap() as u64;
    let high = mem.read_u32(val_addr.add(4)).unwrap() as u64;
    assert_eq!((high << 32) | low, 0);
}

#[test]
fn test_eventfd_posix_read_write_and_close() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let buf_addr = GuestAddr::new(HEAP_START + 0x3000);

    // Create eventfd
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::Eventfd, &mut cpu, &mut mem).unwrap();
    let efd = cpu.reg(Reg::R0);

    // Write 42 via POSIX write(fd, buf, 8)
    mem.write_u32(buf_addr, 42).unwrap();
    mem.write_u32(buf_addr.add(4), 0).unwrap();
    cpu.set_reg(Reg::R0, efd);
    cpu.set_reg(Reg::R1, buf_addr.as_u32());
    cpu.set_reg(Reg::R2, 8);
    call_bionic(&mut bridge, BionicFuncId::Write, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 8);

    // Read via POSIX read(fd, buf, 8)
    let read_buf = GuestAddr::new(HEAP_START + 0x3020);
    cpu.set_reg(Reg::R0, efd);
    cpu.set_reg(Reg::R1, read_buf.as_u32());
    cpu.set_reg(Reg::R2, 8);
    call_bionic(&mut bridge, BionicFuncId::Read, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 8);
    let low = mem.read_u32(read_buf).unwrap() as u64;
    let high = mem.read_u32(read_buf.add(4)).unwrap() as u64;
    assert_eq!((high << 32) | low, 42);

    // Close descriptor
    cpu.set_reg(Reg::R0, efd);
    call_bionic(&mut bridge, BionicFuncId::SocketClose, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Read on closed descriptor returns error -1 (0xFFFF_FFFF)
    cpu.set_reg(Reg::R0, efd);
    cpu.set_reg(Reg::R1, read_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::EventfdRead, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0xFFFF_FFFF);
}

#[test]
fn test_aio_operations() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let aiocb_addr = GuestAddr::new(HEAP_START + 0x4000);

    // aio_read & aio_write return 0
    cpu.set_reg(Reg::R0, aiocb_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AioRead, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, aiocb_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AioWrite, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // aio_error returns 0 (operation completed)
    cpu.set_reg(Reg::R0, aiocb_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AioError, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // aio_return returns aio_nbytes (offset 20)
    mem.write_u32(aiocb_addr.add(20), 256).unwrap();
    cpu.set_reg(Reg::R0, aiocb_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AioReturn, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 256);

    // aio_suspend returns 0
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::AioSuspend, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // aio_cancel returns 2 (AIO_ALLDONE)
    cpu.set_reg(Reg::R0, 10);
    cpu.set_reg(Reg::R1, aiocb_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AioCancel, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 2);
}

#[test]
fn test_symbol_resolution() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "eventfd", "eventfd_read", "eventfd_write",
        "aio_read", "aio_write", "aio_error", "aio_return",
        "aio_suspend", "aio_cancel",
    ];

    for sym in symbols {
        let addr = bridge.resolve(sym);
        assert!(addr.is_some(), "Symbol {} must be resolved", sym);
        assert_ne!(addr.unwrap().as_u32(), 0);
    }
}
