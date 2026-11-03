use transd_core::{CpuState, FlatMemory, GuestAddr, Memory, Reg};
use transd_interp::Interpreter;

#[test]
fn test_exclusive_monitor_multithreaded_contention() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);

    // Lock variable at 0x2000 initialized to 0 (unlocked)
    mem.write_u32(GuestAddr::new(0x2000), 0).unwrap();

    // Program:
    // 0x1000: LDREX r0, [r1]   (0xE1910F9F)
    // 0x1004: STREX r2, r3, [r1] (0xE1812F93) -> r2 = 0 if success, 1 if failed
    // 0x1008: SVC 0
    mem.write_u32(GuestAddr::new(0x1000), 0xE191_0F9F).unwrap();
    mem.write_u32(GuestAddr::new(0x1004), 0xE181_2F93).unwrap();
    mem.write_u32(GuestAddr::new(0x1008), 0xEF00_0000).unwrap();

    // Thread 0
    let mut cpu0 = CpuState::new();
    cpu0.thread_id = 0;
    cpu0.set_pc(GuestAddr::new(0x1000));
    cpu0.set_reg(Reg::R1, 0x2000);
    cpu0.set_reg(Reg::R3, 1); // Value to store

    // Thread 1
    let mut cpu1 = CpuState::new();
    cpu1.thread_id = 1;
    assert_eq!(cpu1.thread_id, 1);

    // Step 1: Thread 0 executes LDREX
    Interpreter::step(&mut cpu0, &mut mem).unwrap();
    assert_eq!(cpu0.reg(Reg::R0), 0);
    assert_eq!(cpu0.pc(), GuestAddr::new(0x1004));

    // Step 2: Thread 1 writes to 0x2014 (within same 64-byte granule 0x2000..0x203F)
    mem.write_u32(GuestAddr::new(0x2014), 999).unwrap();

    // Step 3: Thread 0 attempts STREX — it must FAIL because thread 1 wrote to that granule!
    Interpreter::step(&mut cpu0, &mut mem).unwrap();
    assert_eq!(cpu0.reg(Reg::R2), 1, "STREX must fail (R2=1) when another thread wrote to the 64-byte granule");

    // Step 4: Retry sequence without interruption:
    cpu0.set_pc(GuestAddr::new(0x1000));
    Interpreter::step(&mut cpu0, &mut mem).unwrap(); // LDREX
    Interpreter::step(&mut cpu0, &mut mem).unwrap(); // STREX
    assert_eq!(cpu0.reg(Reg::R2), 0, "STREX must succeed (R2=0) when no conflicting writes occurred");
    assert_eq!(mem.read_u32(GuestAddr::new(0x2000)).unwrap(), 1, "Memory at lock address must be updated");
}
