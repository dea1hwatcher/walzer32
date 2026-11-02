//! Stage 68 integration tests: Dynamic Linker & Android Log Extensions
//! Tests: android_dlopen_ext, dladdr, dladdr1, __android_log_assert,
//!        __android_log_buf_print, __android_log_buf_write, __android_log_vprint,
//!        __android_log_is_loggable, __assert, __assert2

use transd_bridge::bionic::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC, RTLD_DEFAULT};
use transd_core::{ArenaMemory, CpuState, GuestAddr, Memory, MemoryError, Reg};
use transd_elf::LoadedLibrary;

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

// ── android_dlopen_ext ─────────────────────────────────────────────────────────

#[test]
fn test_android_dlopen_ext_system_and_null() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. filename = NULL -> returns RTLD_DEFAULT
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::AndroidDlopenExt, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), RTLD_DEFAULT);

    // 2. filename = "libc.so" -> returns 0xB100_0001
    let libc_str = scratch(0x100);
    mem.write_bytes(libc_str, b"libc.so\0").unwrap();
    cpu.set_reg(Reg::R0, libc_str.as_u32());
    cpu.set_reg(Reg::R1, 2); // RTLD_NOW
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::AndroidDlopenExt, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0xB100_0001);

    // 3. filename = "liblog.so" -> returns 0xB100_0001
    let liblog_str = scratch(0x120);
    mem.write_bytes(liblog_str, b"/system/lib/liblog.so\0").unwrap();
    cpu.set_reg(Reg::R0, liblog_str.as_u32());
    cpu.set_reg(Reg::R1, 2);
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::AndroidDlopenExt, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0xB100_0001);

    // 4. nonexistent library -> returns 0 and sets last_dlerror
    let missing_str = scratch(0x150);
    mem.write_bytes(missing_str, b"libmissing.so\0").unwrap();
    cpu.set_reg(Reg::R0, missing_str.as_u32());
    cpu.set_reg(Reg::R1, 2);
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::AndroidDlopenExt, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert!(bridge.last_dlerror.as_ref().unwrap().contains("libmissing.so"));
}

#[test]
fn test_android_dlopen_ext_registered_dso() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let mut lib = LoadedLibrary::default();
    lib.load_base = GuestAddr::new(0x4000_0000);
    lib.total_size = 0x4000;
    lib.soname = Some("libgame_native.so".to_string());
    let handle = bridge.register_library(lib);

    let name_str = scratch(0x200);
    mem.write_bytes(name_str, b"libgame_native.so\0").unwrap();
    cpu.set_reg(Reg::R0, name_str.as_u32());
    cpu.set_reg(Reg::R1, 2);
    cpu.set_reg(Reg::R2, 0);
    call_bionic(&mut bridge, BionicFuncId::AndroidDlopenExt, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), handle);
}

// ── dladdr & dladdr1 ──────────────────────────────────────────────────────────

#[test]
fn test_dladdr_and_dladdr1_dso() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let mut lib = LoadedLibrary::default();
    lib.load_base = GuestAddr::new(0x5000_0000);
    lib.total_size = 0x1000;
    lib.soname = Some("libengine.so".to_string());
    lib.symbols.insert("calculate".to_string(), GuestAddr::new(0x5000_0100));
    lib.symbols.insert("render".to_string(), GuestAddr::new(0x5000_0400));
    bridge.register_library(lib);

    let info_buf = scratch(0x300);

    // 1. dladdr for address 0x5000_0150 (inside calculate function)
    cpu.set_reg(Reg::R0, 0x5000_0150);
    cpu.set_reg(Reg::R1, info_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Dladdr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    let fname_ptr = GuestAddr::new(mem.read_u32(info_buf).unwrap());
    let fbase = mem.read_u32(info_buf.add(4)).unwrap();
    let sname_ptr = GuestAddr::new(mem.read_u32(info_buf.add(8)).unwrap());
    let saddr = mem.read_u32(info_buf.add(12)).unwrap();

    let mut fname_buf = [0u8; 12];
    mem.read_bytes(fname_ptr, &mut fname_buf).unwrap();
    assert_eq!(&fname_buf[..12], b"libengine.so");
    assert_eq!(fbase, 0x5000_0000);

    let mut sname_buf = [0u8; 9];
    mem.read_bytes(sname_ptr, &mut sname_buf).unwrap();
    assert_eq!(&sname_buf[..9], b"calculate");
    assert_eq!(saddr, 0x5000_0100);

    // 2. dladdr1 for address 0x5000_0400 with extra_info
    let extra_buf = scratch(0x350);
    mem.write_u32(extra_buf, 0x1234_5678).unwrap();
    cpu.set_reg(Reg::R0, 0x5000_0400);
    cpu.set_reg(Reg::R1, info_buf.as_u32());
    cpu.set_reg(Reg::R2, extra_buf.as_u32());
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::Dladdr1, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);
    assert_eq!(mem.read_u32(extra_buf).unwrap(), 0);

    let sname_ptr2 = GuestAddr::new(mem.read_u32(info_buf.add(8)).unwrap());
    let mut sname_buf2 = [0u8; 6];
    mem.read_bytes(sname_ptr2, &mut sname_buf2).unwrap();
    assert_eq!(&sname_buf2[..6], b"render");

    // 3. dladdr for unmapped address -> returns 0
    cpu.set_reg(Reg::R0, 0x9000_0000);
    cpu.set_reg(Reg::R1, info_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Dladdr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_dladdr_synthetic_stubs() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let malloc_addr = bridge.symbol_table.get("malloc").copied().unwrap();
    let info_buf = scratch(0x400);

    cpu.set_reg(Reg::R0, malloc_addr.as_u32());
    cpu.set_reg(Reg::R1, info_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Dladdr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    let fname_ptr = GuestAddr::new(mem.read_u32(info_buf).unwrap());
    let fbase = mem.read_u32(info_buf.add(4)).unwrap();
    let sname_ptr = GuestAddr::new(mem.read_u32(info_buf.add(8)).unwrap());
    let saddr = mem.read_u32(info_buf.add(12)).unwrap();

    let mut fname_buf = [0u8; 7];
    mem.read_bytes(fname_ptr, &mut fname_buf).unwrap();
    assert_eq!(&fname_buf[..7], b"libc.so");
    assert_eq!(fbase, STUB_BASE);

    let mut sname_buf = [0u8; 6];
    mem.read_bytes(sname_ptr, &mut sname_buf).unwrap();
    assert_eq!(&sname_buf[..6], b"malloc");
    assert_eq!(saddr, malloc_addr.as_u32());
}

// ── Android Log Extensions ───────────────────────────────────────────────────

#[test]
fn test_android_log_assert() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let cond_str = scratch(0x500);
    let tag_str  = scratch(0x530);
    let fmt_str  = scratch(0x550);

    mem.write_bytes(cond_str, b"ptr != NULL\0").unwrap();
    mem.write_bytes(tag_str,  b"MySubsystem\0").unwrap();
    mem.write_bytes(fmt_str,  b"null pointer in setup()\0").unwrap();

    cpu.set_reg(Reg::R0, cond_str.as_u32());
    cpu.set_reg(Reg::R1, tag_str.as_u32());
    cpu.set_reg(Reg::R2, fmt_str.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AndroidLogAssert, &mut cpu, &mut mem).unwrap();

    let last_log = bridge.logs.last().expect("log entry");
    assert_eq!(last_log.priority, 7); // ANDROID_LOG_FATAL
    assert_eq!(last_log.tag, "MySubsystem");
    assert_eq!(last_log.text, "ptr != NULL: null pointer in setup()");
}

#[test]
fn test_android_log_buf_print_and_buf_write() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let tag_str = scratch(0x600);
    let msg_str = scratch(0x620);

    mem.write_bytes(tag_str, b"AudioEngine\0").unwrap();
    mem.write_bytes(msg_str, b"Buffer initialized at 48kHz\0").unwrap();

    // __android_log_buf_print(buf_id = 0, priority = 4 (INFO), tag, fmt)
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 4); // ANDROID_LOG_INFO
    cpu.set_reg(Reg::R2, tag_str.as_u32());
    cpu.set_reg(Reg::R3, msg_str.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AndroidLogBufPrint, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    assert_eq!(bridge.logs.len(), 1);
    assert_eq!(bridge.logs[0].priority, 4);
    assert_eq!(bridge.logs[0].tag, "AudioEngine");
    assert_eq!(bridge.logs[0].text, "Buffer initialized at 48kHz");

    // __android_log_buf_write(buf_id = 4, priority = 6 (ERROR), tag, text)
    let err_str = scratch(0x660);
    mem.write_bytes(err_str, b"Underrun occurred in track 2\0").unwrap();
    cpu.set_reg(Reg::R0, 4);
    cpu.set_reg(Reg::R1, 6); // ANDROID_LOG_ERROR
    cpu.set_reg(Reg::R2, tag_str.as_u32());
    cpu.set_reg(Reg::R3, err_str.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AndroidLogBufWrite, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    assert_eq!(bridge.logs.len(), 2);
    assert_eq!(bridge.logs[1].priority, 6);
    assert_eq!(bridge.logs[1].tag, "AudioEngine");
    assert_eq!(bridge.logs[1].text, "Underrun occurred in track 2");
}

#[test]
fn test_android_log_vprint_and_is_loggable() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let tag_str = scratch(0x700);
    let fmt_str = scratch(0x720);

    mem.write_bytes(tag_str, b"VTag\0").unwrap();
    mem.write_bytes(fmt_str, b"Sample vprint log\0").unwrap();

    // __android_log_vprint(prio = 3 (DEBUG), tag, fmt, va_list = 0)
    cpu.set_reg(Reg::R0, 3);
    cpu.set_reg(Reg::R1, tag_str.as_u32());
    cpu.set_reg(Reg::R2, fmt_str.as_u32());
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::AndroidLogVprint, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    assert_eq!(bridge.logs.len(), 1);
    assert_eq!(bridge.logs[0].priority, 3);
    assert_eq!(bridge.logs[0].tag, "VTag");
    assert_eq!(bridge.logs[0].text, "Sample vprint log");

    // __android_log_is_loggable(prio = 4, tag, def_prio = 3) -> 1
    cpu.set_reg(Reg::R0, 4);
    cpu.set_reg(Reg::R1, tag_str.as_u32());
    cpu.set_reg(Reg::R2, 3);
    call_bionic(&mut bridge, BionicFuncId::AndroidLogIsLoggable, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    // __android_log_is_loggable(prio = 2, tag, def_prio = 4) -> 0
    cpu.set_reg(Reg::R0, 2);
    cpu.set_reg(Reg::R1, tag_str.as_u32());
    cpu.set_reg(Reg::R2, 4);
    call_bionic(&mut bridge, BionicFuncId::AndroidLogIsLoggable, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

// ── __assert & __assert2 ──────────────────────────────────────────────────────

#[test]
fn test_assert_and_assert2() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let file_str = scratch(0x800);
    let func_str = scratch(0x830);
    let msg_str  = scratch(0x860);

    mem.write_bytes(file_str, b"physics.c\0").unwrap();
    mem.write_bytes(func_str, b"step_simulation\0").unwrap();
    mem.write_bytes(msg_str,  b"dt > 0.0f\0").unwrap();

    // __assert(file, line = 42, msg)
    cpu.set_reg(Reg::R0, file_str.as_u32());
    cpu.set_reg(Reg::R1, 42);
    cpu.set_reg(Reg::R2, msg_str.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Assert, &mut cpu, &mut mem).unwrap();

    assert_eq!(bridge.logs.len(), 1);
    assert_eq!(bridge.logs[0].priority, 7);
    assert_eq!(bridge.logs[0].tag, "assert");
    assert_eq!(bridge.logs[0].text, "physics.c:42: assertion failed: dt > 0.0f");

    // __assert2(file, line = 105, func, msg)
    cpu.set_reg(Reg::R0, file_str.as_u32());
    cpu.set_reg(Reg::R1, 105);
    cpu.set_reg(Reg::R2, func_str.as_u32());
    cpu.set_reg(Reg::R3, msg_str.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Assert2, &mut cpu, &mut mem).unwrap();

    assert_eq!(bridge.logs.len(), 2);
    assert_eq!(bridge.logs[1].priority, 7);
    assert_eq!(bridge.logs[1].tag, "assert");
    assert_eq!(bridge.logs[1].text, "physics.c:105: step_simulation: assertion failed: dt > 0.0f");
}
