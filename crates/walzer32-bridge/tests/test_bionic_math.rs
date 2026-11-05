use walzer32_core::{CpuState, FlatMemory, GuestAddr, Reg};
use walzer32_bridge::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};

#[test]
fn test_bionic_libm_math_intrinsics() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x100_000);
    let mut bionic = BionicBridge::new(
        GuestAddr::new(0x7000_0000),
        GuestAddr::new(0x7005_0000),
        0x50_000,
    );
    bionic.install_stubs(&mut mem).unwrap();

    let mut cpu = CpuState::new();

    // 1. Test sinf(PI / 2) -> 1.0
    let pi_over_2 = std::f32::consts::FRAC_PI_2;
    cpu.set_reg(Reg::R0, pi_over_2.to_bits());
    bionic.handle_svc(BIONIC_SVC_MAGIC | (BionicFuncId::Sinf as u32), &mut cpu, &mut mem).unwrap();
    let sin_res = f32::from_bits(cpu.reg(Reg::R0));
    assert!((sin_res - 1.0).abs() < 1e-6);
    assert_eq!(cpu.s_reg(0), sin_res);

    // 2. Test cosf(0.0) -> 1.0
    cpu.set_reg(Reg::R0, 0.0f32.to_bits());
    bionic.handle_svc(BIONIC_SVC_MAGIC | (BionicFuncId::Cosf as u32), &mut cpu, &mut mem).unwrap();
    assert_eq!(f32::from_bits(cpu.reg(Reg::R0)), 1.0);

    // 3. Test sqrtf(16.0) -> 4.0
    cpu.set_reg(Reg::R0, 16.0f32.to_bits());
    bionic.handle_svc(BIONIC_SVC_MAGIC | (BionicFuncId::Sqrtf as u32), &mut cpu, &mut mem).unwrap();
    assert_eq!(f32::from_bits(cpu.reg(Reg::R0)), 4.0);

    // 4. Test powf(2.0, 8.0) -> 256.0
    cpu.set_reg(Reg::R0, 2.0f32.to_bits());
    cpu.set_reg(Reg::R1, 8.0f32.to_bits());
    bionic.handle_svc(BIONIC_SVC_MAGIC | (BionicFuncId::Powf as u32), &mut cpu, &mut mem).unwrap();
    assert_eq!(f32::from_bits(cpu.reg(Reg::R0)), 256.0);

    // 5. Test atan2f(1.0, 1.0) -> PI / 4
    cpu.set_reg(Reg::R0, 1.0f32.to_bits());
    cpu.set_reg(Reg::R1, 1.0f32.to_bits());
    bionic.handle_svc(BIONIC_SVC_MAGIC | (BionicFuncId::Atan2f as u32), &mut cpu, &mut mem).unwrap();
    let atan_res = f32::from_bits(cpu.reg(Reg::R0));
    assert!((atan_res - std::f32::consts::FRAC_PI_4).abs() < 1e-6);

    // 6. Test floorf(3.7) -> 3.0
    cpu.set_reg(Reg::R0, 3.7f32.to_bits());
    bionic.handle_svc(BIONIC_SVC_MAGIC | (BionicFuncId::Floorf as u32), &mut cpu, &mut mem).unwrap();
    assert_eq!(f32::from_bits(cpu.reg(Reg::R0)), 3.0);

    // 7. Test double precision sqrt(144.0) -> 12.0
    let d144_bits = 144.0f64.to_bits();
    cpu.set_reg(Reg::R0, d144_bits as u32);
    cpu.set_reg(Reg::R1, (d144_bits >> 32) as u32);
    bionic.handle_svc(BIONIC_SVC_MAGIC | (BionicFuncId::Sqrt as u32), &mut cpu, &mut mem).unwrap();
    let d_res_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
    assert_eq!(f64::from_bits(d_res_bits), 12.0);
    assert_eq!(cpu.d_reg(0), 12.0);

    // 8. Test double precision pow(3.0, 3.0) -> 27.0
    let d3_bits = 3.0f64.to_bits();
    cpu.set_reg(Reg::R0, d3_bits as u32);
    cpu.set_reg(Reg::R1, (d3_bits >> 32) as u32);
    cpu.set_reg(Reg::R2, d3_bits as u32);
    cpu.set_reg(Reg::R3, (d3_bits >> 32) as u32);
    bionic.handle_svc(BIONIC_SVC_MAGIC | (BionicFuncId::Pow as u32), &mut cpu, &mut mem).unwrap();
    let pow_res_bits = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
    assert_eq!(f64::from_bits(pow_res_bits), 27.0);
    assert_eq!(cpu.d_reg(0), 27.0);
}
