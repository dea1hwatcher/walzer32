use transd_core::{ArenaMemory, GuestAddr, Memory, Reg};
use transd_rt::DbtEngine;

#[test]
fn test_arm_ubfx_and_sbfx() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Initial values:
    // r1 = 0x8000_F0E0
    // r2 = 0x8000_F8E0
    engine.cpu.set_reg(Reg::R1, 0x8000_F0E0);
    engine.cpu.set_reg(Reg::R2, 0x8000_F8E0);

    // Program:
    // 0x20000: UBFX r0, r1, #4, #8  -> 0xE7E7_0251 (extracts bits [11:4] = 0x0E zero-extended)
    // 0x20004: SBFX r3, r2, #4, #8  -> 0xE7A7_3252 (extracts bits [11:4] = 0x8E sign-extended)
    // 0x20008: MOV r7, #1           -> 0xE3A0_7001
    // 0x2000C: SVC 0                -> 0xEF00_0000 (exit code = r0 = 0x0E)
    engine.mem.write_u32(code_base, 0xE7E7_0251).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xE7A7_3252).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0x0E);

    // Verify:
    // r0 = 0x0000_000E
    assert_eq!(engine.cpu.reg(Reg::R0), 0x0000_000E);
    // r3 = 0xFFFF_FF8E
    assert_eq!(engine.cpu.reg(Reg::R3), 0xFFFF_FF8E);
}

#[test]
fn test_arm_bfi_and_bfc() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // r0 = 0x1234_5678
    // r1 = 0xABCD_EF42
    engine.cpu.set_reg(Reg::R0, 0x1234_5678);
    engine.cpu.set_reg(Reg::R1, 0xABCD_EF42);

    // Program:
    // 0x20000: BFI r0, r1, #8, #8  -> 0xE7CF_0411 (insert lowest 8 bits of r1 = 0x42 into r0 at bit 8)
    // 0x20004: BFC r0, #4, #8      -> 0xE7CB_021F (clear bits [11:4] in r0)
    // 0x20008: MOV r7, #1          -> 0xE3A0_7001
    // 0x2000C: SVC 0               -> 0xEF00_0000 (exit code = r0)
    engine.mem.write_u32(code_base, 0xE7CF_0411).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xE7CB_021F).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();

    // After BFI: 0x1234_5678 with 0x42 inserted at bit 8 -> 0x1234_4278
    // After BFC: bits [11:4] cleared: 0x1234_4278 & ~0xFF0 = 0x1234_4008
    assert_eq!(exit_code, 0x1234_4008);
    assert_eq!(engine.cpu.reg(Reg::R0), 0x1234_4008);
}

#[test]
fn test_arm_rev_rev16_revsh_rbit() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    engine.cpu.set_reg(Reg::R1, 0x1234_5678);
    engine.cpu.set_reg(Reg::R3, 0x0000_0080);
    engine.cpu.set_reg(Reg::R6, 0x1234_5678);

    // Program:
    // 0x20000: REV r8, r1    -> 0xE6BF_8F31 (0x1234_5678 -> 0x7856_3412)
    // 0x20004: REV16 r2, r1  -> 0xE6BF_2FB1 (0x1234_5678 -> 0x3412_7856)
    // 0x20008: REVSH r4, r3  -> 0xE6FF_4FB3 (0x0000_0080 -> 0xFFFF_8000)
    // 0x2000C: RBIT r5, r6   -> 0xE6FF_5F36 (0x1234_5678 -> 0x1E6A_2C48)
    // 0x20010: MOV r7, #1    -> 0xE3A0_7001
    // 0x20014: MOV r0, #0    -> 0xE3A0_0000
    // 0x20018: SVC 0         -> 0xEF00_0000
    engine.mem.write_u32(code_base, 0xE6BF_8F31).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xE6BF_2FB1).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE6FF_4FB3).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE6FF_5F36).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(20), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(24), 0xEF00_0000).unwrap();

    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(20).unwrap();
    assert_eq!(exit_code, 0);

    assert_eq!(engine.cpu.reg(Reg::R8), 0x7856_3412);
    assert_eq!(engine.cpu.reg(Reg::R2), 0x3412_7856);
    assert_eq!(engine.cpu.reg(Reg::R4), 0xFFFF_8000);
    assert_eq!(engine.cpu.reg(Reg::R5), 0x1E6A_2C48);
}

#[test]
fn test_thumb_bitfield_and_byte_rev() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x20000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    engine.cpu.set_reg(Reg::R1, 0x1234_5678);
    engine.cpu.set_reg(Reg::R2, 0x8000_F8E0);
    engine.cpu.set_reg(Reg::R3, 0x0000_0080);

    // Thumb instructions:
    // 0x20000: rev r4, r1               -> 0xBA0C (Thumb-16: Rd=4, Rm=1)
    // 0x20002: rev16 r5, r1             -> 0xBA4D (Thumb-16: Rd=5, Rm=1)
    // 0x20004: revsh r6, r3             -> 0xBADE (Thumb-16: Rd=6, Rm=3)
    // 0x20006: rbit r0, r1              -> hw1=0xFA91, hw2=0xF0A1 (Thumb-32: Rd=0, Rm=1)
    // 0x2000A: ubfx r8, r1, #4, #8      -> hw1=0xF3C1, hw2=0x1807 (Thumb-32: Rd=8, Rn=1)
    // 0x2000E: sbfx r9, r2, #4, #8      -> hw1=0xF342, hw2=0x1907 (Thumb-32: Rd=9, Rn=2)
    // 0x20012: movs r7, #1              -> 0x2701 (Thumb-16)
    // 0x20014: movs r0, #0              -> 0x2000 (Thumb-16)
    // 0x20016: svc 0                    -> 0xDF00 (Thumb-16)
    engine.mem.write_u16(code_base, 0xBA0C).unwrap();
    engine.mem.write_u16(code_base.add(2), 0xBA4D).unwrap();
    engine.mem.write_u16(code_base.add(4), 0xBADE).unwrap();

    // RBIT r0, r1: hw1 = 0xFA91, hw2 = 0xF0A1
    engine.mem.write_u16(code_base.add(6), 0xFA91).unwrap();
    engine.mem.write_u16(code_base.add(8), 0xF0A1).unwrap();

    // UBFX r8, r1, #4, #8: hw1 = 0xF3C1, hw2 = 0x1807
    engine.mem.write_u16(code_base.add(10), 0xF3C1).unwrap();
    engine.mem.write_u16(code_base.add(12), 0x1807).unwrap();

    // SBFX r9, r2, #4, #8: hw1 = 0xF342, hw2 = 0x1907
    engine.mem.write_u16(code_base.add(14), 0xF342).unwrap();
    engine.mem.write_u16(code_base.add(16), 0x1907).unwrap();

    engine.mem.write_u16(code_base.add(18), 0x2701).unwrap();
    engine.mem.write_u16(code_base.add(20), 0x2000).unwrap();
    engine.mem.write_u16(code_base.add(22), 0xDF00).unwrap();

    engine.cpu.set_thumb(true);
    engine.cpu.set_pc(code_base);
    let exit_code = engine.run(30).unwrap();
    assert_eq!(exit_code, 0);

    // Verify byte reversals:
    assert_eq!(engine.cpu.reg(Reg::R4), 0x7856_3412); // rev
    assert_eq!(engine.cpu.reg(Reg::R5), 0x3412_7856); // rev16
    assert_eq!(engine.cpu.reg(Reg::R6), 0xFFFF_8000); // revsh

    // Verify bitfield extracts:
    assert_eq!(engine.cpu.reg(Reg::R8), 0x0000_0067); // ubfx (bits [11:4] of 0x1234_5678)
    assert_eq!(engine.cpu.reg(Reg::R9), 0xFFFF_FF8E); // sbfx
}
