use transd_core::Memory;
use transd_core::{GuestAddr, Reg};
use transd_core::ArenaMemory;
use transd_rt::DbtEngine;

#[test]
fn test_arm_movw_and_movt() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Initial register setup:
    engine.cpu.set_reg(Reg::R1, 0);
    engine.cpu.set_reg(Reg::R8, 0);

    // Program:
    // 0x20000: MOVW r1, #0x1234      -> 0xE301_1234
    // 0x20004: MOVT r1, #0x5678      -> 0xE345_1678
    // 0x20008: MOVW r8, #0xDEAD      -> 0xE30D_8EAD
    // 0x2000C: MOVT r8, #0xBEEF      -> 0xE34B_8EEF
    // 0x20010: MOV r7, #1            -> 0xE3A0_7001
    // 0x20014: MOV r0, #0            -> 0xE3A0_0000
    // 0x20018: SVC 0                 -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xE301_1234).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xE345_1678).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE30D_8EAD).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE34B_8EEF).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(20), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(24), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    assert_eq!(engine.cpu.reg(Reg::R1), 0x5678_1234);
    assert_eq!(engine.cpu.reg(Reg::R8), 0xBEEF_DEAD);
}

#[test]
fn test_thumb_movw_and_movt() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);
    engine.cpu.set_reg(Reg::R2, 0);
    engine.cpu.set_reg(Reg::R9, 0);
    engine.cpu.set_thumb(true);

    // Thumb-32 instructions:
    // 0x20000: MOVW r2, #0xCAFE      -> hw1=0xF64C, hw2=0x22FE
    // 0x20004: MOVT r2, #0xBABE      -> hw1=0xF6CB, hw2=0x22BE
    // 0x20008: MOVW r9, #0x1234      -> hw1=0xF241, hw2=0x2934
    // 0x2000C: MOVT r9, #0x5678      -> hw1=0xF2C5, hw2=0x6978
    // 0x20010: MOVS r7, #1           -> 0x2701 (Thumb-16)
    // 0x20012: MOVS r0, #0           -> 0x2000 (Thumb-16)
    // 0x20014: SVC 0                 -> 0xDF00 (Thumb-16)
    engine.mem.write_u16(code_base, 0xF64C).unwrap();
    engine.mem.write_u16(code_base.add(2), 0x22FE).unwrap();

    engine.mem.write_u16(code_base.add(4), 0xF6CB).unwrap();
    engine.mem.write_u16(code_base.add(6), 0x22BE).unwrap();

    engine.mem.write_u16(code_base.add(8), 0xF241).unwrap();
    engine.mem.write_u16(code_base.add(10), 0x2934).unwrap();

    engine.mem.write_u16(code_base.add(12), 0xF2C5).unwrap();
    engine.mem.write_u16(code_base.add(14), 0x6978).unwrap();

    engine.mem.write_u16(code_base.add(16), 0x2701).unwrap();
    engine.mem.write_u16(code_base.add(18), 0x2000).unwrap();
    engine.mem.write_u16(code_base.add(20), 0xDF00).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    assert_eq!(engine.cpu.reg(Reg::R2), 0xBABE_CAFE);
    assert_eq!(engine.cpu.reg(Reg::R9), 0x5678_1234);
}

#[test]
fn test_thumb_cbz_and_cbnz() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);
    engine.cpu.set_reg(Reg::R0, 0);
    engine.cpu.set_reg(Reg::R1, 5);
    engine.cpu.set_reg(Reg::R2, 0);
    engine.cpu.set_reg(Reg::R3, 0);
    engine.cpu.set_thumb(true);

    // Program:
    // 0x20000: CBZ r0, #4 (target = 0x20000 + 4 + 4 = 0x20008) -> 0xB110
    // 0x20002: MOVS r2, #99                                    -> 0x2263 (skipped!)
    // 0x20004: NOP                                             -> 0xBF00
    // 0x20006: NOP                                             -> 0xBF00
    // 0x20008: CBNZ r1, #4 (target = 0x20008 + 4 + 4 = 0x20010) -> 0xB911
    // 0x2000A: MOVS r3, #99                                    -> 0x2363 (skipped!)
    // 0x2000C: NOP                                             -> 0xBF00
    // 0x2000E: NOP                                             -> 0xBF00
    // 0x20010: MOVS r7, #1                                     -> 0x2701
    // 0x20012: MOVS r0, #0                                     -> 0x2000
    // 0x20014: SVC 0                                           -> 0xDF00
    engine.mem.write_u16(code_base, 0xB110).unwrap();
    engine.mem.write_u16(code_base.add(2), 0x2263).unwrap();
    engine.mem.write_u16(code_base.add(4), 0xBF00).unwrap();
    engine.mem.write_u16(code_base.add(6), 0xBF00).unwrap();

    engine.mem.write_u16(code_base.add(8), 0xB911).unwrap();
    engine.mem.write_u16(code_base.add(10), 0x2363).unwrap();
    engine.mem.write_u16(code_base.add(12), 0xBF00).unwrap();
    engine.mem.write_u16(code_base.add(14), 0xBF00).unwrap();

    engine.mem.write_u16(code_base.add(16), 0x2701).unwrap();
    engine.mem.write_u16(code_base.add(18), 0x2000).unwrap();
    engine.mem.write_u16(code_base.add(20), 0xDF00).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    assert_eq!(engine.cpu.reg(Reg::R2), 0);
    assert_eq!(engine.cpu.reg(Reg::R3), 0);
}

#[test]
fn test_thumb_table_branch_byte() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);
    engine.cpu.set_reg(Reg::R1, 2); // Select Case 2
    engine.cpu.set_reg(Reg::R4, 0);
    engine.cpu.set_thumb(true);

    // Jump Table Switch:
    // 0x20000: TBB [pc, r1]           -> hw1=0xE8DF, hw2=0xF000
    // 0x20004: Table (4 bytes):
    //          case 0 offset: 6  (target = 0x20004 + 6*2  = 0x20010)
    //          case 1 offset: 8  (target = 0x20004 + 8*2  = 0x20014)
    //          case 2 offset: 10 (target = 0x20004 + 10*2 = 0x20018)
    //          case 3 offset: 12 (target = 0x20004 + 12*2 = 0x2001C)
    // 0x20008: NOP (0xBF00)
    // 0x2000A: NOP (0xBF00)
    // 0x2000C: NOP (0xBF00)
    // 0x2000E: NOP (0xBF00)
    // 0x20010: MOVS r4, #10; B 0x20020 (hw1=0x240A, hw2=0xE006)
    // 0x20014: MOVS r4, #20; B 0x20020 (hw1=0x2414, hw2=0xE004)
    // 0x20018: MOVS r4, #30; B 0x20020 (hw1=0x241E, hw2=0xE002)
    // 0x2001C: MOVS r4, #40; B 0x20020 (hw1=0x2428, hw2=0xE000)
    // 0x20020: MOVS r7, #1
    // 0x20022: MOVS r0, #0
    // 0x20024: SVC 0
    engine.mem.write_u16(code_base, 0xE8DF).unwrap();
    engine.mem.write_u16(code_base.add(2), 0xF001).unwrap();

    // Table entries at 0x20004..0x20007:
    engine.mem.write_u8(code_base.add(4), 6).unwrap();
    engine.mem.write_u8(code_base.add(5), 8).unwrap();
    engine.mem.write_u8(code_base.add(6), 10).unwrap();
    engine.mem.write_u8(code_base.add(7), 12).unwrap();

    // NOP padding
    engine.mem.write_u16(code_base.add(8), 0xBF00).unwrap();
    engine.mem.write_u16(code_base.add(10), 0xBF00).unwrap();
    engine.mem.write_u16(code_base.add(12), 0xBF00).unwrap();
    engine.mem.write_u16(code_base.add(14), 0xBF00).unwrap();

    // Case 0: 0x20010
    engine.mem.write_u16(code_base.add(16), 0x240A).unwrap();
    engine.mem.write_u16(code_base.add(18), 0xE005).unwrap();

    // Case 1: 0x20014
    engine.mem.write_u16(code_base.add(20), 0x2414).unwrap();
    engine.mem.write_u16(code_base.add(22), 0xE003).unwrap();

    // Case 2: 0x20018
    engine.mem.write_u16(code_base.add(24), 0x241E).unwrap();
    engine.mem.write_u16(code_base.add(26), 0xE001).unwrap();

    // Case 3: 0x2001C
    engine.mem.write_u16(code_base.add(28), 0x2428).unwrap();
    engine.mem.write_u16(code_base.add(30), 0xBF00).unwrap();

    // Exit: 0x20020
    engine.mem.write_u16(code_base.add(32), 0x2701).unwrap();
    engine.mem.write_u16(code_base.add(34), 0x2000).unwrap();
    engine.mem.write_u16(code_base.add(36), 0xDF00).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(50).unwrap();
    assert_eq!(exit_code, 0);

    assert_eq!(engine.cpu.reg(Reg::R4), 30);
}

#[test]
fn test_thumb_atomic_ldrex_strex_clrex() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    let data_base = GuestAddr::new(0x30000);
    arena.commit_range(code_base, 0x10000).unwrap();
    arena.commit_range(data_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);
    engine.mem.write_u32(data_base, 100).unwrap();

    engine.cpu.set_reg(Reg::R1, data_base.as_u32());
    engine.cpu.set_thumb(true);

    // 0x20000: LDREX r2, [r1]        -> hw1=0xE851, hw2=0xF200
    // 0x20004: ADDS r2, r2, #1       -> 0x3201
    // 0x20006: STREX r0, r2, [r1]    -> hw1=0xE841, hw2=0x0200
    // 0x2000A: CLREX                 -> hw1=0xF3BF, hw2=0x8F2F
    // 0x2000E: STREX r3, r2, [r1]    -> hw1=0xE841, hw2=0x3200 (fails -> r3 = 1)
    // 0x20012: MOVS r7, #1           -> 0x2701
    // 0x20014: MOVS r0, #0           -> 0x2000
    // 0x20016: SVC 0                 -> 0xDF00
    engine.mem.write_u16(code_base, 0xE851).unwrap();
    engine.mem.write_u16(code_base.add(2), 0xF200).unwrap();

    engine.mem.write_u16(code_base.add(4), 0x3201).unwrap();

    engine.mem.write_u16(code_base.add(6), 0xE841).unwrap();
    engine.mem.write_u16(code_base.add(8), 0x0200).unwrap();

    engine.mem.write_u16(code_base.add(10), 0xF3BF).unwrap();
    engine.mem.write_u16(code_base.add(12), 0x8F2F).unwrap();

    engine.mem.write_u16(code_base.add(14), 0xE841).unwrap();
    engine.mem.write_u16(code_base.add(16), 0x3200).unwrap();

    engine.mem.write_u16(code_base.add(18), 0x2701).unwrap();
    engine.mem.write_u16(code_base.add(20), 0x2000).unwrap();
    engine.mem.write_u16(code_base.add(22), 0xDF00).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    assert_eq!(engine.cpu.reg(Reg::R2), 101);
    assert_eq!(engine.cpu.reg(Reg::R3), 1); // STREX failed after CLREX
    assert_eq!(engine.mem.read_u32(data_base).unwrap(), 101);
}


#[test]
fn test_thumb_table_branch_halfword() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);
    engine.cpu.set_reg(Reg::R1, 1); // Select Case 1
    engine.cpu.set_reg(Reg::R4, 0);
    engine.cpu.set_thumb(true);

    // Jump Table Switch (Halfwords):
    // 0x20000: TBH [pc, r1, lsl #1]   -> hw1=0xE8DF, hw2=0xF011
    // 0x20004: Table (3 halfwords):
    //          case 0 offset: 8  (target = 0x20004 + 8*2  = 0x20014)
    //          case 1 offset: 10 (target = 0x20004 + 10*2 = 0x20018)
    //          case 2 offset: 12 (target = 0x20004 + 12*2 = 0x2001C)
    // 0x2000A..0x20013: NOP padding
    // 0x20014: MOVS r4, #50;  B 0x20020
    // 0x20018: MOVS r4, #200; B 0x20020
    // 0x2001C: MOVS r4, #250; B 0x20020
    // 0x20020: MOVS r7, #1
    // 0x20022: MOVS r0, #0
    // 0x20024: SVC 0
    engine.mem.write_u16(code_base, 0xE8DF).unwrap();
    engine.mem.write_u16(code_base.add(2), 0xF011).unwrap();

    // Table halfwords at 0x20004..0x20009
    engine.mem.write_u16(code_base.add(4), 8).unwrap();
    engine.mem.write_u16(code_base.add(6), 10).unwrap();
    engine.mem.write_u16(code_base.add(8), 12).unwrap();

    // NOP padding
    engine.mem.write_u16(code_base.add(10), 0xBF00).unwrap();
    engine.mem.write_u16(code_base.add(12), 0xBF00).unwrap();

    // Case 0: 0x20014
    engine.mem.write_u16(code_base.add(20), 0x2432).unwrap(); // MOVS r4, #50
    engine.mem.write_u16(code_base.add(22), 0xE003).unwrap(); // B 0x20020

    // Case 1: 0x20018
    engine.mem.write_u16(code_base.add(24), 0x24C8).unwrap(); // MOVS r4, #200
    engine.mem.write_u16(code_base.add(26), 0xE001).unwrap(); // B 0x20020

    // Case 2: 0x2001C
    engine.mem.write_u16(code_base.add(28), 0x24FA).unwrap(); // MOVS r4, #250
    engine.mem.write_u16(code_base.add(30), 0xBF00).unwrap();

    // Exit: 0x20020
    engine.mem.write_u16(code_base.add(32), 0x2701).unwrap();
    engine.mem.write_u16(code_base.add(34), 0x2000).unwrap();
    engine.mem.write_u16(code_base.add(36), 0xDF00).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(50).unwrap();
    assert_eq!(exit_code, 0);

    assert_eq!(engine.cpu.reg(Reg::R4), 200);
}
