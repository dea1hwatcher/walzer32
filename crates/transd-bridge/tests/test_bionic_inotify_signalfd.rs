//! Stage 96 integration tests: Linux Inotify, Signalfd & Eventfd2 Subsystems
//! Tests: inotify_init, inotify_init1, inotify_add_watch, inotify_rm_watch,
//!        signalfd, signalfd4, eventfd2

use transd_bridge::bionic::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use transd_core::{ArenaMemory, CpuState, GuestAddr, Memory, MemoryError, Reg};
use transd_elf::loader::SymbolResolver;

const STUB_BASE: u32 = 0x0001_0000;
const HEAP_START: u32 = 0x0002_0000;

const IN_MODIFY: u32 = 0x0000_0002;
const IN_CREATE: u32 = 0x0000_0100;
const IN_DELETE: u32 = 0x0000_0200;

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
fn test_inotify_and_signalfd_symbols() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "inotify_init",
        "inotify_init1",
        "inotify_add_watch",
        "inotify_rm_watch",
        "signalfd",
        "signalfd4",
        "eventfd2",
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
fn test_inotify_watch_and_events() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. inotify_init1(flags = 0)
    cpu.set_reg(Reg::R0, 0);
    call_bionic(&mut bridge, BionicFuncId::InotifyInit1, &mut cpu, &mut mem).unwrap();
    let ifd = cpu.reg(Reg::R0);
    assert_ne!(ifd, u32::MAX);

    // 2. inotify_add_watch(ifd, "/data/app", mask=IN_CREATE | IN_MODIFY)
    let path1 = GuestAddr::new(HEAP_START + 0x0100);
    mem.write_bytes(path1, b"/data/app\0").unwrap();
    cpu.set_reg(Reg::R0, ifd);
    cpu.set_reg(Reg::R1, path1.as_u32());
    cpu.set_reg(Reg::R2, IN_CREATE | IN_MODIFY);
    call_bionic(&mut bridge, BionicFuncId::InotifyAddWatch, &mut cpu, &mut mem).unwrap();
    let wd1 = cpu.reg(Reg::R0) as i32;
    assert_eq!(wd1, 1);

    // 3. inotify_add_watch(ifd, "/data/logs", mask=IN_DELETE) -> wd 2
    let path2 = GuestAddr::new(HEAP_START + 0x0200);
    mem.write_bytes(path2, b"/data/logs\0").unwrap();
    cpu.set_reg(Reg::R0, ifd);
    cpu.set_reg(Reg::R1, path2.as_u32());
    cpu.set_reg(Reg::R2, IN_DELETE);
    call_bionic(&mut bridge, BionicFuncId::InotifyAddWatch, &mut cpu, &mut mem).unwrap();
    let wd2 = cpu.reg(Reg::R0) as i32;
    assert_eq!(wd2, 2);

    // 4. Update watch on existing path "/data/app" -> returns same wd 1
    cpu.set_reg(Reg::R0, ifd);
    cpu.set_reg(Reg::R1, path1.as_u32());
    cpu.set_reg(Reg::R2, IN_MODIFY);
    call_bionic(&mut bridge, BionicFuncId::InotifyAddWatch, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, 1);

    // 5. inotify_rm_watch(ifd, wd=2) -> returns 0
    cpu.set_reg(Reg::R0, ifd);
    cpu.set_reg(Reg::R1, wd2 as u32);
    call_bionic(&mut bridge, BionicFuncId::InotifyRmWatch, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // rm_watch nonexistent -> returns -1
    cpu.set_reg(Reg::R0, ifd);
    cpu.set_reg(Reg::R1, 999);
    call_bionic(&mut bridge, BionicFuncId::InotifyRmWatch, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), u32::MAX);

    // 6. Trigger inotify event on "/data/app"
    let triggered = bridge.trigger_inotify_event("/data/app", IN_MODIFY, 0x1122_3344, "config.json");
    assert_eq!(triggered, 1);

    // 7. read(ifd, buf, 64) -> reads struct inotify_event
    let read_buf = GuestAddr::new(HEAP_START + 0x0300);
    cpu.set_reg(Reg::R0, ifd);
    cpu.set_reg(Reg::R1, read_buf.as_u32());
    cpu.set_reg(Reg::R2, 64);
    call_bionic(&mut bridge, BionicFuncId::Read, &mut cpu, &mut mem).unwrap();
    let bytes_read = cpu.reg(Reg::R0) as usize;
    assert!(bytes_read >= 16);

    let ev_wd = mem.read_u32(read_buf).unwrap() as i32;
    let ev_mask = mem.read_u32(read_buf.add(4)).unwrap();
    let ev_cookie = mem.read_u32(read_buf.add(8)).unwrap();
    let ev_len = mem.read_u32(read_buf.add(12)).unwrap() as usize;

    assert_eq!(ev_wd, 1);
    assert_eq!(ev_mask, IN_MODIFY);
    assert_eq!(ev_cookie, 0x1122_3344);
    assert!(ev_len > 0);

    let mut name_bytes = vec![0u8; ev_len];
    mem.read_bytes(read_buf.add(16), &mut name_bytes).unwrap();
    let name_str = String::from_utf8_lossy(&name_bytes).trim_end_matches('\0').to_string();
    assert_eq!(name_str, "config.json");

    // 8. Close inotify fd
    cpu.set_reg(Reg::R0, ifd);
    call_bionic(&mut bridge, BionicFuncId::SocketClose, &mut cpu, &mut mem).unwrap();
    assert!(bridge.inotify_instances.get(&ifd).is_none());
}

#[test]
fn test_signalfd_lifecycle_and_read() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. Prepare sigmask in memory: set bits for SIGINT (2) and SIGTERM (15)
    let mask_addr = GuestAddr::new(HEAP_START + 0x0100);
    let mask: u64 = (1 << 2) | (1 << 15);
    mem.write_u32(mask_addr, mask as u32).unwrap();
    mem.write_u32(mask_addr.add(4), (mask >> 32) as u32).unwrap();

    // 2. signalfd(fd=-1, &mask, flags=0)
    cpu.set_reg(Reg::R0, u32::MAX);
    cpu.set_reg(Reg::R1, mask_addr.as_u32());
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::Signalfd, &mut cpu, &mut mem).unwrap();
    let sfd = cpu.reg(Reg::R0);
    assert_ne!(sfd, u32::MAX);
    assert_eq!(bridge.signalfd_table.get(&sfd).cloned(), Some(mask));

    // 3. read(sfd, buf, 128) -> returns 128 bytes
    let siginfo_buf = GuestAddr::new(HEAP_START + 0x0200);
    cpu.set_reg(Reg::R0, sfd);
    cpu.set_reg(Reg::R1, siginfo_buf.as_u32());
    cpu.set_reg(Reg::R2, 128);
    call_bionic(&mut bridge, BionicFuncId::Read, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 128);

    // 4. Update signalfd mask: signalfd(sfd, &new_mask, 0)
    let new_mask: u64 = 1 << 9; // SIGKILL
    mem.write_u32(mask_addr, new_mask as u32).unwrap();
    mem.write_u32(mask_addr.add(4), 0).unwrap();

    cpu.set_reg(Reg::R0, sfd);
    cpu.set_reg(Reg::R1, mask_addr.as_u32());
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::Signalfd, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), sfd);
    assert_eq!(bridge.signalfd_table.get(&sfd).cloned(), Some(new_mask));

    // 5. Close signalfd
    cpu.set_reg(Reg::R0, sfd);
    call_bionic(&mut bridge, BionicFuncId::SocketClose, &mut cpu, &mut mem).unwrap();
    assert!(bridge.signalfd_table.get(&sfd).is_none());
}

#[test]
fn test_eventfd2_operations() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. eventfd2(initval=42, flags=0)
    cpu.set_reg(Reg::R0, 42);
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::Eventfd2, &mut cpu, &mut mem).unwrap();
    let efd = cpu.reg(Reg::R0);
    assert_ne!(efd, u32::MAX);

    // 2. read(efd, buf, 8) -> returns 8 bytes, value 42
    let buf = GuestAddr::new(HEAP_START + 0x0100);
    cpu.set_reg(Reg::R0, efd);
    cpu.set_reg(Reg::R1, buf.as_u32());
    cpu.set_reg(Reg::R2, 8);
    call_bionic(&mut bridge, BionicFuncId::Read, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 8);
    let val_low = mem.read_u32(buf).unwrap() as u64;
    let val_high = mem.read_u32(buf.add(4)).unwrap() as u64;
    assert_eq!(val_low | (val_high << 32), 42);

    // 3. write(efd, buf, 8) with value 10
    mem.write_u32(buf, 10).unwrap();
    mem.write_u32(buf.add(4), 0).unwrap();
    cpu.set_reg(Reg::R0, efd);
    cpu.set_reg(Reg::R1, buf.as_u32());
    cpu.set_reg(Reg::R2, 8);
    call_bionic(&mut bridge, BionicFuncId::Write, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 8);

    // 4. read again -> returns 10
    cpu.set_reg(Reg::R0, efd);
    cpu.set_reg(Reg::R1, buf.as_u32());
    cpu.set_reg(Reg::R2, 8);
    call_bionic(&mut bridge, BionicFuncId::Read, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 8);
    let val_low = mem.read_u32(buf).unwrap() as u64;
    let val_high = mem.read_u32(buf.add(4)).unwrap() as u64;
    assert_eq!(val_low | (val_high << 32), 10);

    // 5. Close eventfd
    cpu.set_reg(Reg::R0, efd);
    call_bionic(&mut bridge, BionicFuncId::SocketClose, &mut cpu, &mut mem).unwrap();
    assert!(bridge.eventfd_table.get(&efd).is_none());
}
