// Stage 59 integration tests: pipe/read/write, memalign/posix_memalign/malloc_usable_size,
// pthread_barrier_*, clock_nanosleep.

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
    mem.commit_range(heap_start, 0x0010_0000).unwrap(); // 1 MiB heap + scratch

    let bridge = BionicBridge::new(stub_base, heap_start, 512 * 1024);
    bridge.install_stubs(&mut mem).unwrap();
    let cpu = CpuState::new();
    (bridge, mem, cpu)
}

/// Scratch area above the heap allocation zone.
fn scratch(offset: u32) -> GuestAddr {
    GuestAddr::new(HEAP_START + 0x8000 + offset)
}

// ─── pipe / read / write ───────────────────────────────────────────────────

#[test]
fn test_pipe_creates_unique_fds() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let arr = scratch(0x00);

    cpu.set_reg(Reg::R0, arr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Pipe, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "pipe() returns 0");

    let read_fd  = mem.read_u32(arr).unwrap();
    let write_fd = mem.read_u32(arr.add(4)).unwrap();
    assert!(read_fd >= 100, "read_fd >= 100, got {}", read_fd);
    assert_eq!(write_fd, read_fd + 1, "write_fd == read_fd + 1");
}

#[test]
fn test_pipe_write_then_read() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let arr    = scratch(0x10);
    let wbuf   = scratch(0x20);
    let rbuf   = scratch(0x40);

    // Open pipe
    cpu.set_reg(Reg::R0, arr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Pipe, &mut cpu, &mut mem).unwrap();
    let read_fd  = mem.read_u32(arr).unwrap();
    let write_fd = mem.read_u32(arr.add(4)).unwrap();

    // Write 5 bytes through write_fd
    let payload = b"HELLO";
    for (i, b) in payload.iter().enumerate() {
        mem.write_u8(wbuf.add(i as u32), *b).unwrap();
    }
    cpu.set_reg(Reg::R0, write_fd);
    cpu.set_reg(Reg::R1, wbuf.as_u32());
    cpu.set_reg(Reg::R2, 5);
    call_bionic(&mut bridge, BionicFuncId::Write, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 5, "write returns count");

    // Read 5 bytes from read_fd
    cpu.set_reg(Reg::R0, read_fd);
    cpu.set_reg(Reg::R1, rbuf.as_u32());
    cpu.set_reg(Reg::R2, 5);
    call_bionic(&mut bridge, BionicFuncId::Read, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 5, "read returns count");

    let mut result = [0u8; 5];
    for i in 0..5u32 {
        result[i as usize] = mem.read_u8(rbuf.add(i)).unwrap();
    }
    assert_eq!(&result, payload, "pipe round-trip data matches");
}

#[test]
fn test_pipe_read_eof_on_empty() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let arr  = scratch(0x60);
    let rbuf = scratch(0x70);

    cpu.set_reg(Reg::R0, arr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Pipe, &mut cpu, &mut mem).unwrap();
    let read_fd = mem.read_u32(arr).unwrap();

    // Read with empty pipe → EOF (0)
    cpu.set_reg(Reg::R0, read_fd);
    cpu.set_reg(Reg::R1, rbuf.as_u32());
    cpu.set_reg(Reg::R2, 8);
    call_bionic(&mut bridge, BionicFuncId::Read, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "empty pipe read returns 0 (EOF)");
}

#[test]
fn test_write_non_pipe_fd_succeeds() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let buf = scratch(0x80);

    // Write to stdout (fd=1) — stub should silently consume
    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, buf.as_u32());
    cpu.set_reg(Reg::R2, 10);
    call_bionic(&mut bridge, BionicFuncId::Write, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 10, "write to non-pipe fd returns count");
}

// ─── Extended allocator ────────────────────────────────────────────────────

#[test]
fn test_malloc_usable_size_returns_zero() {
    let (mut bridge, mut mem, mut cpu) = setup();
    cpu.set_reg(Reg::R0, scratch(0).as_u32());
    call_bionic(&mut bridge, BionicFuncId::MallocUsableSize, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "malloc_usable_size returns 0 (conservative stub)");
}

#[test]
fn test_memalign_alignment_16() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // memalign(16, 64) -> aligned ptr
    cpu.set_reg(Reg::R0, 16);  // alignment
    cpu.set_reg(Reg::R1, 64);  // size
    call_bionic(&mut bridge, BionicFuncId::Memalign, &mut cpu, &mut mem).unwrap();
    let ptr = cpu.reg(Reg::R0);
    assert_ne!(ptr, 0, "memalign returns non-null");
    assert_eq!(ptr % 16, 0, "pointer is 16-byte aligned, got 0x{:X}", ptr);

    // Second call returns a different (higher) pointer
    cpu.set_reg(Reg::R0, 16);
    cpu.set_reg(Reg::R1, 64);
    call_bionic(&mut bridge, BionicFuncId::Memalign, &mut cpu, &mut mem).unwrap();
    let ptr2 = cpu.reg(Reg::R0);
    assert!(ptr2 > ptr, "second allocation is at higher address");
    assert_eq!(ptr2 % 16, 0, "second pointer also 16-byte aligned");
}

#[test]
fn test_memalign_alignment_4096() {
    let (mut bridge, mut mem, mut cpu) = setup();

    cpu.set_reg(Reg::R0, 4096); // page-aligned
    cpu.set_reg(Reg::R1, 128);
    call_bionic(&mut bridge, BionicFuncId::Memalign, &mut cpu, &mut mem).unwrap();
    let ptr = cpu.reg(Reg::R0);
    assert_ne!(ptr, 0, "page-aligned alloc non-null");
    assert_eq!(ptr % 4096, 0, "pointer is page-aligned, got 0x{:X}", ptr);
}

#[test]
fn test_posix_memalign_success() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let memptr_slot = scratch(0x100);

    // posix_memalign(&ptr, 32, 128) -> 0; *memptr != 0 and % 32 == 0
    cpu.set_reg(Reg::R0, memptr_slot.as_u32());
    cpu.set_reg(Reg::R1, 32);   // alignment
    cpu.set_reg(Reg::R2, 128);  // size
    call_bionic(&mut bridge, BionicFuncId::PosixMemalign, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "posix_memalign returns 0");

    let ptr = mem.read_u32(memptr_slot).unwrap();
    assert_ne!(ptr, 0, "stored pointer is non-null");
    assert_eq!(ptr % 32, 0, "stored pointer is 32-byte aligned, got 0x{:X}", ptr);
}

// ─── pthread_barrier_* ─────────────────────────────────────────────────────

#[test]
fn test_pthread_barrier_init_and_destroy() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let barrier = scratch(0x200);

    // init(barrier, NULL, count=3)
    cpu.set_reg(Reg::R0, barrier.as_u32());
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 3);
    call_bionic(&mut bridge, BionicFuncId::PthreadBarrierInit, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "barrier_init returns 0");

    let count   = mem.read_u32(barrier).unwrap();
    let current = mem.read_u32(barrier.add(4)).unwrap();
    assert_eq!(count, 3, "count stored correctly");
    assert_eq!(current, 3, "current == count on fresh barrier");

    // destroy -> 0
    cpu.set_reg(Reg::R0, barrier.as_u32());
    call_bionic(&mut bridge, BionicFuncId::PthreadBarrierDestroy, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "barrier_destroy returns 0");
}

#[test]
fn test_pthread_barrier_wait_count_1() {
    // A barrier with count=1: first wait immediately returns SERIAL
    let (mut bridge, mut mem, mut cpu) = setup();
    let barrier = scratch(0x210);

    cpu.set_reg(Reg::R0, barrier.as_u32());
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 1);
    call_bionic(&mut bridge, BionicFuncId::PthreadBarrierInit, &mut cpu, &mut mem).unwrap();

    cpu.set_reg(Reg::R0, barrier.as_u32());
    call_bionic(&mut bridge, BionicFuncId::PthreadBarrierWait, &mut cpu, &mut mem).unwrap();
    // PTHREAD_BARRIER_SERIAL_THREAD = -1 as u32 = 0xFFFF_FFFF
    assert_eq!(cpu.reg(Reg::R0), u32::MAX, "count=1 wait returns SERIAL_THREAD");

    // After reset, count is restored
    let current = mem.read_u32(barrier.add(4)).unwrap();
    assert_eq!(current, 1, "barrier reset after trigger");
}

#[test]
fn test_pthread_barrier_wait_count_3() {
    // count=3: first two waits return 0, third returns SERIAL and resets
    let (mut bridge, mut mem, mut cpu) = setup();
    let barrier = scratch(0x220);

    cpu.set_reg(Reg::R0, barrier.as_u32());
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, 3);
    call_bionic(&mut bridge, BionicFuncId::PthreadBarrierInit, &mut cpu, &mut mem).unwrap();

    // Wait 1 -> 0
    cpu.set_reg(Reg::R0, barrier.as_u32());
    call_bionic(&mut bridge, BionicFuncId::PthreadBarrierWait, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "wait 1 returns 0");

    // Wait 2 -> 0
    cpu.set_reg(Reg::R0, barrier.as_u32());
    call_bionic(&mut bridge, BionicFuncId::PthreadBarrierWait, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "wait 2 returns 0");

    // Wait 3 -> SERIAL + reset
    cpu.set_reg(Reg::R0, barrier.as_u32());
    call_bionic(&mut bridge, BionicFuncId::PthreadBarrierWait, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), u32::MAX, "wait 3 returns SERIAL_THREAD");
    assert_eq!(mem.read_u32(barrier.add(4)).unwrap(), 3, "barrier reset to 3");
}

// ─── clock_nanosleep ───────────────────────────────────────────────────────

#[test]
fn test_clock_nanosleep_returns_zero() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let ts = scratch(0x300);
    mem.write_u32(ts, 0).unwrap();       // tv_sec
    mem.write_u32(ts.add(4), 1000).unwrap(); // tv_nsec

    // clock_nanosleep(CLOCK_MONOTONIC=1, 0, &ts, NULL)
    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, ts.as_u32());
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::ClockNanosleep, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0, "clock_nanosleep returns 0 (stub)");
}

#[test]
fn test_segregated_free_list_recycles_chunks() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // Malloc 64 bytes
    cpu.set_reg(Reg::R0, 64);
    call_bionic(&mut bridge, BionicFuncId::Malloc, &mut cpu, &mut mem).unwrap();
    let ptr1 = cpu.reg(Reg::R0);
    assert_ne!(ptr1, 0);

    // Free the chunk
    cpu.set_reg(Reg::R0, ptr1);
    call_bionic(&mut bridge, BionicFuncId::Free, &mut cpu, &mut mem).unwrap();

    // Malloc 64 bytes again: MUST recycle ptr1 from free bucket
    cpu.set_reg(Reg::R0, 64);
    call_bionic(&mut bridge, BionicFuncId::Malloc, &mut cpu, &mut mem).unwrap();
    let ptr2 = cpu.reg(Reg::R0);
    assert_eq!(ptr1, ptr2, "Free list must recycle previously freed chunk");

    // Realloc growth and in-place reuse
    cpu.set_reg(Reg::R0, ptr2);
    cpu.set_reg(Reg::R1, 48); // smaller than 64: should reuse in-place
    call_bionic(&mut bridge, BionicFuncId::Realloc, &mut cpu, &mut mem).unwrap();
    let ptr3 = cpu.reg(Reg::R0);
    assert_eq!(ptr2, ptr3, "Realloc shrink must reuse in-place without moving");
}
