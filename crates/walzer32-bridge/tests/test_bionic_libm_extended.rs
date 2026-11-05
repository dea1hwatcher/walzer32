// Stage 62 integration tests: Extended libm Math Intrinsics (f32 & f64)
// atan, asin, acos, sinh, cosh, tanh, log10, log2, exp2, fmod, round, trunc, hypot, copysign, cbrt, ldexp

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
    mem.commit_range(heap_start, 0x0010_0000).unwrap();

    let bridge = BionicBridge::new(stub_base, heap_start, 512 * 1024);
    bridge.install_stubs(&mut mem).unwrap();
    let cpu = CpuState::new();
    (bridge, mem, cpu)
}

fn set_f32(cpu: &mut CpuState, val: f32) {
    cpu.set_reg(Reg::R0, val.to_bits());
    cpu.set_s_reg(0, val);
}

fn get_f32(cpu: &CpuState) -> f32 {
    f32::from_bits(cpu.reg(Reg::R0))
}

fn set_f64(cpu: &mut CpuState, val: f64) {
    let bits = val.to_bits();
    cpu.set_reg(Reg::R0, bits as u32);
    cpu.set_reg(Reg::R1, (bits >> 32) as u32);
    cpu.set_d_reg(0, val);
}

fn get_f64(cpu: &CpuState) -> f64 {
    let lo = cpu.reg(Reg::R0) as u64;
    let hi = cpu.reg(Reg::R1) as u64;
    f64::from_bits(lo | (hi << 32))
}

// ─── Single-Precision (f32) Tests ──────────────────────────────────────────

#[test]
fn test_trig_and_hyp_f32() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // atanf(1.0) -> pi/4 (~0.785398)
    set_f32(&mut cpu, 1.0);
    call_bionic(&mut bridge, BionicFuncId::Atanf, &mut cpu, &mut mem).unwrap();
    let res = get_f32(&cpu);
    assert!((res - std::f32::consts::FRAC_PI_4).abs() < 1e-5);
    assert_eq!(cpu.s_reg(0), res);

    // asinf(0.5) -> pi/6 (~0.523598)
    set_f32(&mut cpu, 0.5);
    call_bionic(&mut bridge, BionicFuncId::Asinf, &mut cpu, &mut mem).unwrap();
    let res = get_f32(&cpu);
    assert!((res - std::f32::consts::FRAC_PI_6).abs() < 1e-5);

    // acosf(0.5) -> pi/3 (~1.047197)
    set_f32(&mut cpu, 0.5);
    call_bionic(&mut bridge, BionicFuncId::Acosf, &mut cpu, &mut mem).unwrap();
    let res = get_f32(&cpu);
    assert!((res - std::f32::consts::FRAC_PI_3).abs() < 1e-5);

    // sinhf(0.0) -> 0.0, coshf(0.0) -> 1.0, tanhf(0.0) -> 0.0
    set_f32(&mut cpu, 0.0);
    call_bionic(&mut bridge, BionicFuncId::Sinhf, &mut cpu, &mut mem).unwrap();
    assert_eq!(get_f32(&cpu), 0.0);

    set_f32(&mut cpu, 0.0);
    call_bionic(&mut bridge, BionicFuncId::Coshf, &mut cpu, &mut mem).unwrap();
    assert_eq!(get_f32(&cpu), 1.0);

    set_f32(&mut cpu, 0.0);
    call_bionic(&mut bridge, BionicFuncId::Tanhf, &mut cpu, &mut mem).unwrap();
    assert_eq!(get_f32(&cpu), 0.0);
}

#[test]
fn test_exp_log_pow_f32() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // log10f(100.0) -> 2.0
    set_f32(&mut cpu, 100.0);
    call_bionic(&mut bridge, BionicFuncId::Log10f, &mut cpu, &mut mem).unwrap();
    assert!((get_f32(&cpu) - 2.0).abs() < 1e-5);

    // log2f(8.0) -> 3.0
    set_f32(&mut cpu, 8.0);
    call_bionic(&mut bridge, BionicFuncId::Log2f, &mut cpu, &mut mem).unwrap();
    assert!((get_f32(&cpu) - 3.0).abs() < 1e-5);

    // exp2f(3.0) -> 8.0
    set_f32(&mut cpu, 3.0);
    call_bionic(&mut bridge, BionicFuncId::Exp2f, &mut cpu, &mut mem).unwrap();
    assert!((get_f32(&cpu) - 8.0).abs() < 1e-5);

    // cbrtf(27.0) -> 3.0
    set_f32(&mut cpu, 27.0);
    call_bionic(&mut bridge, BionicFuncId::Cbrtf, &mut cpu, &mut mem).unwrap();
    assert!((get_f32(&cpu) - 3.0).abs() < 1e-5);

    // ldexpf(1.5, 3) -> 12.0
    set_f32(&mut cpu, 1.5);
    cpu.set_reg(Reg::R1, 3);
    call_bionic(&mut bridge, BionicFuncId::Ldexpf, &mut cpu, &mut mem).unwrap();
    assert!((get_f32(&cpu) - 12.0).abs() < 1e-5);
}

#[test]
fn test_ops_f32() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // fmodf(5.5, 2.0) -> 1.5
    set_f32(&mut cpu, 5.5);
    cpu.set_reg(Reg::R1, 2.0_f32.to_bits());
    call_bionic(&mut bridge, BionicFuncId::Fmodf, &mut cpu, &mut mem).unwrap();
    assert!((get_f32(&cpu) - 1.5).abs() < 1e-5);

    // roundf(2.6) -> 3.0, roundf(-2.6) -> -3.0
    set_f32(&mut cpu, 2.6);
    call_bionic(&mut bridge, BionicFuncId::Roundf, &mut cpu, &mut mem).unwrap();
    assert_eq!(get_f32(&cpu), 3.0);

    set_f32(&mut cpu, -2.6);
    call_bionic(&mut bridge, BionicFuncId::Roundf, &mut cpu, &mut mem).unwrap();
    assert_eq!(get_f32(&cpu), -3.0);

    // truncf(2.9) -> 2.0, truncf(-2.9) -> -2.0
    set_f32(&mut cpu, 2.9);
    call_bionic(&mut bridge, BionicFuncId::Truncf, &mut cpu, &mut mem).unwrap();
    assert_eq!(get_f32(&cpu), 2.0);

    set_f32(&mut cpu, -2.9);
    call_bionic(&mut bridge, BionicFuncId::Truncf, &mut cpu, &mut mem).unwrap();
    assert_eq!(get_f32(&cpu), -2.0);

    // hypotf(3.0, 4.0) -> 5.0
    set_f32(&mut cpu, 3.0);
    cpu.set_reg(Reg::R1, 4.0_f32.to_bits());
    call_bionic(&mut bridge, BionicFuncId::Hypotf, &mut cpu, &mut mem).unwrap();
    assert!((get_f32(&cpu) - 5.0).abs() < 1e-5);

    // copysignf(5.0, -1.0) -> -5.0
    set_f32(&mut cpu, 5.0);
    cpu.set_reg(Reg::R1, (-1.0_f32).to_bits());
    call_bionic(&mut bridge, BionicFuncId::Copysignf, &mut cpu, &mut mem).unwrap();
    assert_eq!(get_f32(&cpu), -5.0);
}

// ─── Double-Precision (f64) Tests ──────────────────────────────────────────

#[test]
fn test_trig_and_hyp_f64() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // atan(1.0) -> pi/4
    set_f64(&mut cpu, 1.0);
    call_bionic(&mut bridge, BionicFuncId::Atan, &mut cpu, &mut mem).unwrap();
    let res = get_f64(&cpu);
    assert!((res - std::f64::consts::FRAC_PI_4).abs() < 1e-10);
    assert_eq!(cpu.d_reg(0), res);

    // asin(0.5) -> pi/6
    set_f64(&mut cpu, 0.5);
    call_bionic(&mut bridge, BionicFuncId::Asin, &mut cpu, &mut mem).unwrap();
    let res = get_f64(&cpu);
    assert!((res - std::f64::consts::FRAC_PI_6).abs() < 1e-10);

    // acos(0.5) -> pi/3
    set_f64(&mut cpu, 0.5);
    call_bionic(&mut bridge, BionicFuncId::Acos, &mut cpu, &mut mem).unwrap();
    let res = get_f64(&cpu);
    assert!((res - std::f64::consts::FRAC_PI_3).abs() < 1e-10);

    // sinh(0.0) -> 0.0, cosh(0.0) -> 1.0, tanh(0.0) -> 0.0
    set_f64(&mut cpu, 0.0);
    call_bionic(&mut bridge, BionicFuncId::Sinh, &mut cpu, &mut mem).unwrap();
    assert_eq!(get_f64(&cpu), 0.0);

    set_f64(&mut cpu, 0.0);
    call_bionic(&mut bridge, BionicFuncId::Cosh, &mut cpu, &mut mem).unwrap();
    assert_eq!(get_f64(&cpu), 1.0);

    set_f64(&mut cpu, 0.0);
    call_bionic(&mut bridge, BionicFuncId::Tanh, &mut cpu, &mut mem).unwrap();
    assert_eq!(get_f64(&cpu), 0.0);
}

#[test]
fn test_exp_log_pow_f64() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // log10(1000.0) -> 3.0
    set_f64(&mut cpu, 1000.0);
    call_bionic(&mut bridge, BionicFuncId::Log10, &mut cpu, &mut mem).unwrap();
    assert!((get_f64(&cpu) - 3.0).abs() < 1e-10);

    // log2(16.0) -> 4.0
    set_f64(&mut cpu, 16.0);
    call_bionic(&mut bridge, BionicFuncId::Log2, &mut cpu, &mut mem).unwrap();
    assert!((get_f64(&cpu) - 4.0).abs() < 1e-10);

    // exp2(4.0) -> 16.0
    set_f64(&mut cpu, 4.0);
    call_bionic(&mut bridge, BionicFuncId::Exp2, &mut cpu, &mut mem).unwrap();
    assert!((get_f64(&cpu) - 16.0).abs() < 1e-10);

    // cbrt(64.0) -> 4.0
    set_f64(&mut cpu, 64.0);
    call_bionic(&mut bridge, BionicFuncId::Cbrt, &mut cpu, &mut mem).unwrap();
    assert!((get_f64(&cpu) - 4.0).abs() < 1e-10);

    // ldexp(2.5, 2) -> 10.0
    set_f64(&mut cpu, 2.5);
    cpu.set_reg(Reg::R2, 2);
    call_bionic(&mut bridge, BionicFuncId::Ldexp, &mut cpu, &mut mem).unwrap();
    assert!((get_f64(&cpu) - 10.0).abs() < 1e-10);
}

#[test]
fn test_ops_f64() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // fmod(7.5, 2.0) -> 1.5
    set_f64(&mut cpu, 7.5);
    let y_bits = 2.0_f64.to_bits();
    cpu.set_reg(Reg::R2, y_bits as u32);
    cpu.set_reg(Reg::R3, (y_bits >> 32) as u32);
    call_bionic(&mut bridge, BionicFuncId::Fmod, &mut cpu, &mut mem).unwrap();
    assert!((get_f64(&cpu) - 1.5).abs() < 1e-10);

    // round(3.7) -> 4.0
    set_f64(&mut cpu, 3.7);
    call_bionic(&mut bridge, BionicFuncId::Round, &mut cpu, &mut mem).unwrap();
    assert_eq!(get_f64(&cpu), 4.0);

    // trunc(3.7) -> 3.0
    set_f64(&mut cpu, 3.7);
    call_bionic(&mut bridge, BionicFuncId::Trunc, &mut cpu, &mut mem).unwrap();
    assert_eq!(get_f64(&cpu), 3.0);

    // hypot(5.0, 12.0) -> 13.0
    set_f64(&mut cpu, 5.0);
    let y_bits = 12.0_f64.to_bits();
    cpu.set_reg(Reg::R2, y_bits as u32);
    cpu.set_reg(Reg::R3, (y_bits >> 32) as u32);
    call_bionic(&mut bridge, BionicFuncId::Hypot, &mut cpu, &mut mem).unwrap();
    assert!((get_f64(&cpu) - 13.0).abs() < 1e-10);

    // copysign(4.0, -2.0) -> -4.0
    set_f64(&mut cpu, 4.0);
    let y_bits = (-2.0_f64).to_bits();
    cpu.set_reg(Reg::R2, y_bits as u32);
    cpu.set_reg(Reg::R3, (y_bits >> 32) as u32);
    call_bionic(&mut bridge, BionicFuncId::Copysign, &mut cpu, &mut mem).unwrap();
    assert_eq!(get_f64(&cpu), -4.0);
}
