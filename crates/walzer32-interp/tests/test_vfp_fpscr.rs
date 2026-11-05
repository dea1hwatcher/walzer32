use walzer32_core::{fpscr, CpuState, FlatMemory, GuestAddr, Memory, Reg};
use walzer32_interp::Interpreter;

#[test]
fn test_vfp_vmrs_vmsr_fpscr() {
    let mut cpu = CpuState::new();
    let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);

    // 1. VMSR FPSCR, r1 (write 0x0300_0000: RUNFAST_MODE to FPSCR)
    // 0xEEE11A10
    mem.write_u32(GuestAddr::new(0x1000), 0xEEE1_1A10).unwrap();
    // 2. VMRS r2, FPSCR (read FPSCR into r2)
    // 0xEEF12A10
    mem.write_u32(GuestAddr::new(0x1004), 0xEEF1_2A10).unwrap();
    // 3. VMRS APSR_nzcv, FPSCR (transfer flags)
    // 0xEEF1FA10
    mem.write_u32(GuestAddr::new(0x1008), 0xEEF1_FA10).unwrap();

    cpu.set_reg(Reg::R1, fpscr::RUNFAST_MODE | fpscr::N | fpscr::Z);
    cpu.set_pc(GuestAddr::new(0x1000));

    // Step 1: VMSR
    Interpreter::step(&mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.fpscr, fpscr::RUNFAST_MODE | fpscr::N | fpscr::Z);
    assert!(cpu.fpscr_ftz());
    assert!(cpu.fpscr_default_nan());

    // Step 2: VMRS r2
    Interpreter::step(&mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R2), fpscr::RUNFAST_MODE | fpscr::N | fpscr::Z);

    // Step 3: VMRS APSR_nzcv
    Interpreter::step(&mut cpu, &mut mem).unwrap();
    assert!(cpu.cpsr.contains(walzer32_core::Cpsr::N));
    assert!(cpu.cpsr.contains(walzer32_core::Cpsr::Z));
    assert!(!cpu.cpsr.contains(walzer32_core::Cpsr::C));
    assert!(!cpu.cpsr.contains(walzer32_core::Cpsr::V));
}

#[test]
fn test_vfp_runfast_ftz_flush_to_zero() {
    let mut cpu = CpuState::new();
    let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);

    // VADD.F32 s0, s1, s2 -> 0xEE300A81
    mem.write_u32(GuestAddr::new(0x1000), 0xEE30_0A81).unwrap();

    // 1. Without FTZ (FZ = 0): subnormals are preserved
    cpu.fpscr = 0;
    let subnormal_f32 = f32::from_bits(0x0000_0001); // smallest subnormal
    cpu.set_s_reg(1, subnormal_f32);
    cpu.set_s_reg(2, 0.0);
    cpu.set_pc(GuestAddr::new(0x1000));

    Interpreter::step(&mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.s_reg(0).to_bits(), 0x0000_0001);

    // 2. With FTZ (FZ = 1): subnormal input is flushed to 0.0, IDC flag is set
    cpu.fpscr = fpscr::FZ;
    cpu.set_s_reg(1, subnormal_f32);
    cpu.set_s_reg(2, 0.0);
    cpu.set_pc(GuestAddr::new(0x1000));

    Interpreter::step(&mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.s_reg(0), 0.0);
    assert_ne!(cpu.fpscr & fpscr::IDC, 0); // Input Denormal flag set
}

#[test]
fn test_vfp_default_nan_mode() {
    let mut cpu = CpuState::new();
    let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);

    // VDIV.F32 s0, s1, s2 (0.0 / 0.0 -> NaN) -> 0xEE800A81
    mem.write_u32(GuestAddr::new(0x1000), 0xEE80_0A81).unwrap();

    // With DN = 1: NaN is normalized to Default NaN (0x7FC0_0000)
    cpu.fpscr = fpscr::DN;
    cpu.set_s_reg(1, 0.0);
    cpu.set_s_reg(2, 0.0);
    cpu.set_pc(GuestAddr::new(0x1000));

    Interpreter::step(&mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.s_reg(0).to_bits(), 0x7FC0_0000);
}

#[test]
fn test_vfp_vfma_vfms_fused_multiply_add() {
    let mut cpu = CpuState::new();
    let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);

    // 1. VFMA.F32 s0, s1, s2 (s0 = s0 + s1 * s2) -> 0xEEA00A81
    mem.write_u32(GuestAddr::new(0x1000), 0xEEA0_0A81).unwrap();
    // 2. VFMS.F32 s0, s1, s2 (s0 = s0 - s1 * s2) -> 0xEEA00AC1
    mem.write_u32(GuestAddr::new(0x1004), 0xEEA0_0AC1).unwrap();

    cpu.set_s_reg(0, 10.0);
    cpu.set_s_reg(1, 3.0);
    cpu.set_s_reg(2, 4.0);
    cpu.set_pc(GuestAddr::new(0x1000));

    // Step 1: VFMA: 10.0 + (3.0 * 4.0) = 22.0
    Interpreter::step(&mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.s_reg(0), 22.0);

    // Step 2: VFMS: 22.0 - (3.0 * 4.0) = 10.0
    Interpreter::step(&mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.s_reg(0), 10.0);
}
