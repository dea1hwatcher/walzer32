//! Stage 70 integration tests: Exception Handling & Unwinding
//! Tests: _Unwind_RaiseException, _Unwind_ForcedUnwind, _Unwind_DeleteException,
//!        _Unwind_Resume, _Unwind_GetGR, _Unwind_SetGR, _Unwind_GetIP, _Unwind_SetIP,
//!        __aeabi_unwind_cpp_pr0, __aeabi_unwind_cpp_pr1, __aeabi_unwind_cpp_pr2,
//!        __cxa_begin_cleanup, __cxa_end_cleanup, _Unwind_Backtrace, _Unwind_Complete

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

// ── Raise, ForcedUnwind, Backtrace ───────────────────────────────────────────

#[test]
fn test_unwind_raise_and_forced_unwind_and_backtrace() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let exc = scratch(0x100);

    // 1. _Unwind_RaiseException -> returns _URC_END_OF_STACK (5)
    cpu.set_reg(Reg::R0, exc.as_u32());
    call_bionic(&mut bridge, BionicFuncId::UnwindRaiseException, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 5);

    // 2. _Unwind_ForcedUnwind -> returns _URC_END_OF_STACK (5)
    cpu.set_reg(Reg::R0, exc.as_u32());
    cpu.set_reg(Reg::R1, 0); // stop_fn = NULL
    cpu.set_reg(Reg::R2, 0); // stop_arg = NULL
    call_bionic(&mut bridge, BionicFuncId::UnwindForcedUnwind, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 5);

    // 3. _Unwind_Backtrace -> returns _URC_END_OF_STACK (5)
    cpu.set_reg(Reg::R0, 0); // trace_fn = NULL
    cpu.set_reg(Reg::R1, 0); // trace_arg = NULL
    call_bionic(&mut bridge, BionicFuncId::UnwindBacktrace, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 5);
}

// ── Delete, Resume, Complete ──────────────────────────────────────────────────

#[test]
fn test_unwind_delete_and_resume_and_complete() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let exc = scratch(0x200);

    // struct _Unwind_Exception { uint64_t class; _Unwind_Exception_Cleanup_Fn cleanup; ... }
    mem.write_u32(exc, 0x474E_5543).unwrap(); // class low ("GNUC")
    mem.write_u32(exc.add(4), 0).unwrap();    // class high
    mem.write_u32(exc.add(8), 0x1234_5678).unwrap(); // cleanup fn pointer

    // 1. _Unwind_DeleteException clears cleanup callback and returns 0
    cpu.set_reg(Reg::R0, exc.as_u32());
    call_bionic(&mut bridge, BionicFuncId::UnwindDeleteException, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(exc.add(8)).unwrap(), 0);

    // 2. _Unwind_Resume returns 0
    cpu.set_reg(Reg::R0, exc.as_u32());
    call_bionic(&mut bridge, BionicFuncId::UnwindResume, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 3. _Unwind_Complete returns 0
    cpu.set_reg(Reg::R0, exc.as_u32());
    call_bionic(&mut bridge, BionicFuncId::UnwindComplete, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

// ── Context Registers: GetGR, SetGR, GetIP, SetIP ────────────────────────────

#[test]
fn test_unwind_context_registers_and_ip() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let ctx = scratch(0x300);

    // Populate mock register context (R0..R15)
    mem.write_u32(ctx, 0x1111_1111).unwrap(); // R0
    mem.write_u32(ctx.add(4), 0x2222_2222).unwrap(); // R1
    mem.write_u32(ctx.add(13 * 4), 0x001F_F000).unwrap(); // R13 (SP)
    mem.write_u32(ctx.add(15 * 4), 0x0001_2345).unwrap(); // R15 (PC with Thumb bit set)

    // 1. _Unwind_GetGR
    cpu.set_reg(Reg::R0, ctx.as_u32());
    cpu.set_reg(Reg::R1, 0); // index = R0
    call_bionic(&mut bridge, BionicFuncId::UnwindGetGR, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0x1111_1111);

    cpu.set_reg(Reg::R0, ctx.as_u32());
    cpu.set_reg(Reg::R1, 13); // index = SP
    call_bionic(&mut bridge, BionicFuncId::UnwindGetGR, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0x001F_F000);

    // 2. _Unwind_SetGR
    cpu.set_reg(Reg::R0, ctx.as_u32());
    cpu.set_reg(Reg::R1, 1); // index = R1
    cpu.set_reg(Reg::R2, 0xCAFE_BABE);
    call_bionic(&mut bridge, BionicFuncId::UnwindSetGR, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(ctx.add(4)).unwrap(), 0xCAFE_BABE);

    // Verify GetGR reads the updated value
    cpu.set_reg(Reg::R0, ctx.as_u32());
    cpu.set_reg(Reg::R1, 1);
    call_bionic(&mut bridge, BionicFuncId::UnwindGetGR, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0xCAFE_BABE);

    // 3. _Unwind_GetIP clears Thumb bit (!1)
    cpu.set_reg(Reg::R0, ctx.as_u32());
    call_bionic(&mut bridge, BionicFuncId::UnwindGetIP, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0x0001_2344);

    // 4. _Unwind_SetIP updates PC
    cpu.set_reg(Reg::R0, ctx.as_u32());
    cpu.set_reg(Reg::R1, 0x0004_5678);
    call_bionic(&mut bridge, BionicFuncId::UnwindSetIP, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(ctx.add(15 * 4)).unwrap(), 0x0004_5678);

    cpu.set_reg(Reg::R0, ctx.as_u32());
    call_bionic(&mut bridge, BionicFuncId::UnwindGetIP, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0x0004_5678);
}

// ── Personality Routines & C++ ABI Cleanup ────────────────────────────────────

#[test]
fn test_aeabi_unwind_cpp_personalities_and_cxa_cleanup() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // __aeabi_unwind_cpp_pr0/1/2 return _URC_CONTINUE_UNWIND (8)
    call_bionic(&mut bridge, BionicFuncId::AeabiUnwindCppPr0, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 8);

    call_bionic(&mut bridge, BionicFuncId::AeabiUnwindCppPr1, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 8);

    call_bionic(&mut bridge, BionicFuncId::AeabiUnwindCppPr2, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 8);

    // __cxa_begin_cleanup and __cxa_end_cleanup return 0
    cpu.set_reg(Reg::R0, 0x1234);
    call_bionic(&mut bridge, BionicFuncId::CxaBeginCleanup, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    call_bionic(&mut bridge, BionicFuncId::CxaEndCleanup, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}
