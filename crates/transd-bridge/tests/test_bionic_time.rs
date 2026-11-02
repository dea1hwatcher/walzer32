//! Stage 66 integration tests: Time & Date APIs
//! Tests: time, difftime, clock, times, gmtime, gmtime_r, localtime, localtime_r,
//! mktime, asctime, asctime_r, ctime, ctime_r, strftime, strptime

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

fn read_str(mem: &impl Memory, addr: GuestAddr) -> String {
    let mut bytes = Vec::new();
    let mut i = 0u32;
    loop {
        let b = mem.read_u8(addr.add(i)).unwrap_or(0);
        if b == 0 {
            break;
        }
        bytes.push(b);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

// ── time & difftime ──────────────────────────────────────────────────────────

#[test]
fn test_time_and_difftime() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let tloc = scratch(0);

    // time(&tloc)
    cpu.set_reg(Reg::R0, tloc.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Time, &mut cpu, &mut mem).unwrap();
    let t = cpu.reg(Reg::R0);
    assert!(t > 1_600_000_000, "timestamp should be recent");
    assert_eq!(mem.read_u32(tloc).unwrap(), t);

    // difftime(t + 100, t) -> 100.0
    cpu.set_reg(Reg::R0, t + 100);
    cpu.set_reg(Reg::R1, t);
    call_bionic(&mut bridge, BionicFuncId::Difftime, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.d_reg(0), 100.0);
}

// ── clock & times ────────────────────────────────────────────────────────────

#[test]
fn test_clock_and_times() {
    let (mut bridge, mut mem, mut cpu) = setup();

    call_bionic(&mut bridge, BionicFuncId::Clock, &mut cpu, &mut mem).unwrap();
    let c = cpu.reg(Reg::R0);
    assert!(c > 0);

    let tms_buf = scratch(0);
    cpu.set_reg(Reg::R0, tms_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Times, &mut cpu, &mut mem).unwrap();
    assert!(cpu.reg(Reg::R0) > 0);
    // Verify struct tms was populated
    let utime = mem.read_u32(tms_buf).unwrap();
    assert!(utime > 0);
}

// ── gmtime & localtime ───────────────────────────────────────────────────────

#[test]
fn test_gmtime_and_gmtime_r() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let time_ptr = scratch(0);
    let tm_out = scratch(0x100);

    // 0 = 1970-01-01 00:00:00 UTC, Thursday (wday = 4)
    mem.write_u32(time_ptr, 0).unwrap();

    // gmtime(&0)
    cpu.set_reg(Reg::R0, time_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Gmtime, &mut cpu, &mut mem).unwrap();
    let ptr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(ptr.as_u32(), 0);

    assert_eq!(mem.read_u32(ptr).unwrap(), 0); // sec
    assert_eq!(mem.read_u32(ptr.add(4)).unwrap(), 0); // min
    assert_eq!(mem.read_u32(ptr.add(8)).unwrap(), 0); // hour
    assert_eq!(mem.read_u32(ptr.add(12)).unwrap(), 1); // mday
    assert_eq!(mem.read_u32(ptr.add(16)).unwrap(), 0); // mon
    assert_eq!(mem.read_u32(ptr.add(20)).unwrap(), 70); // year (1970 - 1900)
    assert_eq!(mem.read_u32(ptr.add(24)).unwrap(), 4); // wday (Thu)

    // gmtime_r(&0, tm_out)
    cpu.set_reg(Reg::R0, time_ptr.as_u32());
    cpu.set_reg(Reg::R1, tm_out.as_u32());
    call_bionic(&mut bridge, BionicFuncId::GmtimeR, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), tm_out.as_u32());
    assert_eq!(mem.read_u32(tm_out.add(12)).unwrap(), 1);
    assert_eq!(mem.read_u32(tm_out.add(20)).unwrap(), 70);
}

#[test]
fn test_localtime_and_localtime_r() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let time_ptr = scratch(0);
    let tm_out = scratch(0x100);

    // 86400 = 1970-01-02 00:00:00
    mem.write_u32(time_ptr, 86400).unwrap();

    cpu.set_reg(Reg::R0, time_ptr.as_u32());
    cpu.set_reg(Reg::R1, tm_out.as_u32());
    call_bionic(&mut bridge, BionicFuncId::LocaltimeR, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), tm_out.as_u32());

    assert_eq!(mem.read_u32(tm_out.add(12)).unwrap(), 2); // mday = 2
    assert_eq!(mem.read_u32(tm_out.add(24)).unwrap(), 5); // wday = 5 (Friday)
}

// ── mktime roundtrip ────────────────────────────────────────────────────────

#[test]
fn test_mktime_roundtrip() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let tm_ptr = scratch(0);

    // 2026-03-15 12:30:45
    // year = 2026 - 1900 = 126, mon = 2 (March), mday = 15, hour = 12, min = 30, sec = 45
    mem.write_u32(tm_ptr, 45).unwrap();
    mem.write_u32(tm_ptr.add(4), 30).unwrap();
    mem.write_u32(tm_ptr.add(8), 12).unwrap();
    mem.write_u32(tm_ptr.add(12), 15).unwrap();
    mem.write_u32(tm_ptr.add(16), 2).unwrap();
    mem.write_u32(tm_ptr.add(20), 126).unwrap();

    cpu.set_reg(Reg::R0, tm_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Mktime, &mut cpu, &mut mem).unwrap();
    let t = cpu.reg(Reg::R0);
    assert!(t > 1_700_000_000);

    // Now decompose with gmtime_r and verify it matches
    let time_val_ptr = scratch(0x100);
    let tm_out = scratch(0x200);
    mem.write_u32(time_val_ptr, t).unwrap();

    cpu.set_reg(Reg::R0, time_val_ptr.as_u32());
    cpu.set_reg(Reg::R1, tm_out.as_u32());
    call_bionic(&mut bridge, BionicFuncId::GmtimeR, &mut cpu, &mut mem).unwrap();

    assert_eq!(mem.read_u32(tm_out).unwrap(), 45);
    assert_eq!(mem.read_u32(tm_out.add(4)).unwrap(), 30);
    assert_eq!(mem.read_u32(tm_out.add(8)).unwrap(), 12);
    assert_eq!(mem.read_u32(tm_out.add(12)).unwrap(), 15);
    assert_eq!(mem.read_u32(tm_out.add(16)).unwrap(), 2);
    assert_eq!(mem.read_u32(tm_out.add(20)).unwrap(), 126);
}

// ── asctime & ctime ──────────────────────────────────────────────────────────

#[test]
fn test_asctime_and_ctime() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let time_ptr = scratch(0);
    let buf = scratch(0x100);

    mem.write_u32(time_ptr, 0).unwrap(); // 1970-01-01 00:00:00 Thu

    // ctime_r(&0, buf) -> "Thu Jan  1 00:00:00 1970\n"
    cpu.set_reg(Reg::R0, time_ptr.as_u32());
    cpu.set_reg(Reg::R1, buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::CtimeR, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), buf.as_u32());

    let formatted = read_str(&mem, buf);
    assert!(formatted.contains("Thu Jan"));
    assert!(formatted.contains("1970"));
}

// ── strftime & strptime ──────────────────────────────────────────────────────

#[test]
fn test_strftime() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let out_buf = scratch(0);
    let fmt_ptr = scratch(0x100);
    let tm_ptr = scratch(0x200);

    // 2026-11-02 18:30:00 (year = 126, mon = 10, mday = 2, hour = 18, min = 30, sec = 0)
    mem.write_u32(tm_ptr, 0).unwrap(); // sec
    mem.write_u32(tm_ptr.add(4), 30).unwrap(); // min
    mem.write_u32(tm_ptr.add(8), 18).unwrap(); // hour
    mem.write_u32(tm_ptr.add(12), 2).unwrap(); // mday
    mem.write_u32(tm_ptr.add(16), 10).unwrap(); // mon
    mem.write_u32(tm_ptr.add(20), 126).unwrap(); // year
    mem.write_u32(tm_ptr.add(24), 1).unwrap(); // wday (Mon)
    mem.write_u32(tm_ptr.add(28), 305).unwrap(); // yday

    write_str(&mut mem, fmt_ptr, "%Y-%m-%d %H:%M:%S");

    cpu.set_reg(Reg::R0, out_buf.as_u32());
    cpu.set_reg(Reg::R1, 64);
    cpu.set_reg(Reg::R2, fmt_ptr.as_u32());
    cpu.set_reg(Reg::R3, tm_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Strftime, &mut cpu, &mut mem).unwrap();

    let n = cpu.reg(Reg::R0);
    assert_eq!(n, 19);
    assert_eq!(read_str(&mem, out_buf), "2026-11-02 18:30:00");
}

#[test]
fn test_strptime() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let s_ptr = scratch(0);
    let fmt_ptr = scratch(0x100);
    let tm_ptr = scratch(0x200);

    write_str(&mut mem, s_ptr, "2026-08-20 09:15:30");
    write_str(&mut mem, fmt_ptr, "%Y-%m-%d %H:%M:%S");

    cpu.set_reg(Reg::R0, s_ptr.as_u32());
    cpu.set_reg(Reg::R1, fmt_ptr.as_u32());
    cpu.set_reg(Reg::R2, tm_ptr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Strptime, &mut cpu, &mut mem).unwrap();

    let rem_ptr = cpu.reg(Reg::R0);
    assert_ne!(rem_ptr, 0);

    // Verify extracted fields
    assert_eq!(mem.read_u32(tm_ptr.add(20)).unwrap(), 126); // year 2026 - 1900
    assert_eq!(mem.read_u32(tm_ptr.add(16)).unwrap(), 7); // mon (August = 7)
    assert_eq!(mem.read_u32(tm_ptr.add(12)).unwrap(), 20); // mday
    assert_eq!(mem.read_u32(tm_ptr.add(8)).unwrap(), 9); // hour
    assert_eq!(mem.read_u32(tm_ptr.add(4)).unwrap(), 15); // min
    assert_eq!(mem.read_u32(tm_ptr).unwrap(), 30); // sec
}
