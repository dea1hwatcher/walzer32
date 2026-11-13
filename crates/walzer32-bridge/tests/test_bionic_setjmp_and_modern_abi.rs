//! Stage 102 integration tests: setjmp/longjmp, getrandom, prctl, statx, clock_gettime64.

use walzer32_bridge::bionic::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use walzer32_core::{ArenaMemory, CpuState, GuestAddr, Memory, MemoryError, Reg};
use walzer32_elf::SymbolResolver;

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

#[test]
fn test_setjmp_and_longjmp_lifecycle() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let jmp_buf = scratch(0);

    // Setup callee-saved registers before setjmp
    cpu.set_reg(Reg::R4, 0x1111_1111);
    cpu.set_reg(Reg::R5, 0x2222_2222);
    cpu.set_reg(Reg::R6, 0x3333_3333);
    cpu.set_reg(Reg::R7, 0x4444_4444);
    cpu.set_reg(Reg::R8, 0x5555_5555);
    cpu.set_reg(Reg::R9, 0x6666_6666);
    cpu.set_reg(Reg::R10, 0x7777_7777);
    cpu.set_reg(Reg::R11, 0x8888_8888);
    cpu.set_sp(0x000A_0000);
    cpu.set_reg(Reg::LR, 0x0004_1234); // return address
    cpu.set_d_reg_u64(8, 0xCAFE_BABE_0000_0001);
    cpu.set_d_reg_u64(15, 0xDEAD_BEEF_0000_0002);

    // 1. Call setjmp(&jmp_buf)
    cpu.set_reg(Reg::R0, jmp_buf.as_u32());
    let handled = call_bionic(&mut bridge, BionicFuncId::Setjmp, &mut cpu, &mut mem).unwrap();
    assert!(handled);
    assert_eq!(cpu.reg(Reg::R0), 0, "setjmp direct return must be 0");

    // 2. Corrupt/change registers as if other functions were called
    cpu.set_reg(Reg::R4, 0xAAAA_AAAA);
    cpu.set_reg(Reg::R5, 0xBBBB_BBBB);
    cpu.set_reg(Reg::R6, 0xCCCC_CCCC);
    cpu.set_reg(Reg::R7, 0xDDDD_DDDD);
    cpu.set_sp(0x0009_0000);
    cpu.set_reg(Reg::LR, 0x0001_0000);
    cpu.set_d_reg_u64(8, 0);
    cpu.set_d_reg_u64(15, 0);

    // 3. Call longjmp(&jmp_buf, 42)
    cpu.set_reg(Reg::R0, jmp_buf.as_u32());
    cpu.set_reg(Reg::R1, 42);
    let handled2 = call_bionic(&mut bridge, BionicFuncId::Longjmp, &mut cpu, &mut mem).unwrap();
    assert!(handled2);

    // Verify registers were completely restored
    assert_eq!(cpu.reg(Reg::R4), 0x1111_1111);
    assert_eq!(cpu.reg(Reg::R5), 0x2222_2222);
    assert_eq!(cpu.reg(Reg::R6), 0x3333_3333);
    assert_eq!(cpu.reg(Reg::R7), 0x4444_4444);
    assert_eq!(cpu.reg(Reg::R8), 0x5555_5555);
    assert_eq!(cpu.reg(Reg::R9), 0x6666_6666);
    assert_eq!(cpu.reg(Reg::R10), 0x7777_7777);
    assert_eq!(cpu.reg(Reg::R11), 0x8888_8888);
    assert_eq!(cpu.sp(), 0x000A_0000);
    assert_eq!(cpu.reg(Reg::LR), 0x0004_1234);
    assert_eq!(cpu.d_reg_u64(8), 0xCAFE_BABE_0000_0001);
    assert_eq!(cpu.d_reg_u64(15), 0xDEAD_BEEF_0000_0002);

    // Return value in R0 must be 42
    assert_eq!(cpu.reg(Reg::R0), 42);
}

#[test]
fn test_longjmp_zero_value_returns_one() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let jmp_buf = scratch(0);
    cpu.set_sp(0x000A_0000);
    cpu.set_reg(Reg::LR, 0x0004_5678);

    cpu.set_reg(Reg::R0, jmp_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Setjmp, &mut cpu, &mut mem).unwrap();

    // Call longjmp with val = 0 (POSIX requires longjmp returning 0 to yield 1)
    cpu.set_reg(Reg::R0, jmp_buf.as_u32());
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::Longjmp, &mut cpu, &mut mem).unwrap();

    assert_eq!(cpu.reg(Reg::R0), 1, "POSIX longjmp with 0 must yield 1");
}

#[test]
fn test_getrandom_fills_buffer() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let buf_addr = scratch(0);
    let len = 32u32;

    cpu.set_reg(Reg::R0, buf_addr.as_u32());
    cpu.set_reg(Reg::R1, len);
    cpu.set_reg(Reg::R2, 0);

    let handled = call_bionic(&mut bridge, BionicFuncId::Getrandom, &mut cpu, &mut mem).unwrap();
    assert!(handled);
    assert_eq!(cpu.reg(Reg::R0), len);

    let mut data = [0u8; 32];
    mem.read_bytes(buf_addr, &mut data).unwrap();
    // At least one non-zero byte
    assert!(data.iter().any(|&b| b != 0), "getrandom must produce non-zero random bytes");
}

#[test]
fn test_prctl_set_and_get_name() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // PR_SET_NAME (15)
    cpu.set_reg(Reg::R0, 15);
    cpu.set_reg(Reg::R1, scratch(0).as_u32());
    mem.write_bytes(scratch(0), b"MainThread\0").unwrap();

    let handled = call_bionic(&mut bridge, BionicFuncId::Prctl, &mut cpu, &mut mem).unwrap();
    assert!(handled);
    assert_eq!(cpu.reg(Reg::R0), 0);

    // PR_GET_NAME (16)
    cpu.set_reg(Reg::R0, 16);
    cpu.set_reg(Reg::R1, scratch(64).as_u32());

    let handled2 = call_bionic(&mut bridge, BionicFuncId::Prctl, &mut cpu, &mut mem).unwrap();
    assert!(handled2);
    assert_eq!(cpu.reg(Reg::R0), 0);

    let mut name = [0u8; 16];
    mem.read_bytes(scratch(64), &mut name).unwrap();
    assert!(name.starts_with(b"walzer32"));
}

#[test]
fn test_clock_gettime64_resolution() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let tp = scratch(0);
    cpu.set_reg(Reg::R0, 0); // CLOCK_REALTIME
    cpu.set_reg(Reg::R1, tp.as_u32());

    let handled = call_bionic(&mut bridge, BionicFuncId::ClockGettime64, &mut cpu, &mut mem).unwrap();
    assert!(handled);
    assert_eq!(cpu.reg(Reg::R0), 0);

    let sec_low = mem.read_u32(tp).unwrap() as u64;
    let sec_high = mem.read_u32(tp.add(4)).unwrap() as u64;
    let sec = (sec_high << 32) | sec_low;

    // Time must be after year 2024 (~1_700_000_000)
    assert!(sec > 1_700_000_000, "clock_gettime64 seconds must be valid epoch");
}

#[test]
fn test_statx_stub() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let statx_buf = scratch(0);
    cpu.set_sp(scratch(0x100).as_u32());
    mem.write_u32(scratch(0x100), statx_buf.as_u32()).unwrap();

    cpu.set_reg(Reg::R0, 0); // AT_FDCWD
    cpu.set_reg(Reg::R1, scratch(0x200).as_u32()); // path
    cpu.set_reg(Reg::R2, 0); // flags
    cpu.set_reg(Reg::R3, 0x7FF); // mask

    let handled = call_bionic(&mut bridge, BionicFuncId::Statx, &mut cpu, &mut mem).unwrap();
    assert!(handled);
    assert_eq!(cpu.reg(Reg::R0), 0);

    let mut buf = [0u8; 256];
    mem.read_bytes(statx_buf, &mut buf).unwrap();
    // Mode should be non-zero
    let mode = u16::from_le_bytes([buf[0x1C], buf[0x1D]]);
    assert_ne!(mode, 0);
}

#[test]
fn test_symbol_resolution_new_apis() {
    let (bridge, _mem, _cpu) = setup();

    for sym in ["setjmp", "longjmp", "_setjmp", "_longjmp", "sigsetjmp", "siglongjmp", "getrandom", "prctl", "statx", "clock_gettime64"] {
        assert!(bridge.resolve(sym).is_some(), "symbol '{}' must resolve in BionicBridge", sym);
    }
}
