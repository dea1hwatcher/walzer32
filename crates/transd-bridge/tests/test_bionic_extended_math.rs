//! Stage 91 integration tests: Extended Math & Floating Point Functions
//! Tests: fma, fmaf, remquo, remquof, nextafter, nextafterf, nan, nanf,
//!        fdim, fdimf, ilogb, ilogbf, logb, logbf, scalbn, scalbnf, scalbln, scalblnf

use transd_bridge::bionic::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use transd_core::{ArenaMemory, CpuState, GuestAddr, Memory, MemoryError, Reg};
use transd_elf::loader::SymbolResolver;

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

    mem.commit_range(stub_base, 0x0008_0000).expect("commit stub");
    mem.commit_range(heap_start, 0x0010_0000).expect("commit heap");

    let bridge = BionicBridge::new(stub_base, heap_start, 0x0010_0000);
    bridge.install_stubs(&mut mem).expect("stubs");

    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::SP, HEAP_START + 0x0008_0000);

    (bridge, mem, cpu)
}

#[test]
fn test_fma_and_fmaf() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. fmaf(2.0, 3.0, 4.0) => 10.0
    cpu.set_reg(Reg::R0, 2.0f32.to_bits());
    cpu.set_reg(Reg::R1, 3.0f32.to_bits());
    cpu.set_reg(Reg::R2, 4.0f32.to_bits());
    call_bionic(&mut bridge, BionicFuncId::Fmaf, &mut cpu, &mut mem).unwrap();
    let res_f32 = f32::from_bits(cpu.reg(Reg::R0));
    assert_eq!(res_f32, 10.0f32);

    // 2. fma(2.5, 4.0, 5.5) => 15.5
    let x_bits = 2.5f64.to_bits();
    let y_bits = 4.0f64.to_bits();
    let z_bits = 5.5f64.to_bits();

    cpu.set_reg(Reg::R0, (x_bits & 0xFFFF_FFFF) as u32);
    cpu.set_reg(Reg::R1, (x_bits >> 32) as u32);
    cpu.set_reg(Reg::R2, (y_bits & 0xFFFF_FFFF) as u32);
    cpu.set_reg(Reg::R3, (y_bits >> 32) as u32);

    let sp = GuestAddr::new(cpu.sp());
    mem.write_u32(sp, (z_bits & 0xFFFF_FFFF) as u32).unwrap();
    mem.write_u32(sp.add(4), (z_bits >> 32) as u32).unwrap();

    call_bionic(&mut bridge, BionicFuncId::Fma, &mut cpu, &mut mem).unwrap();
    let res_u64 = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
    let res_f64 = f64::from_bits(res_u64);
    assert_eq!(res_f64, 15.5f64);
}

#[test]
fn test_remquo_and_remquof() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let quo_addr = GuestAddr::new(HEAP_START + 0x0100);

    // 1. remquof(10.0, 3.0, &quo)
    cpu.set_reg(Reg::R0, 10.0f32.to_bits());
    cpu.set_reg(Reg::R1, 3.0f32.to_bits());
    cpu.set_reg(Reg::R2, quo_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Remquof, &mut cpu, &mut mem).unwrap();

    let rem_f32 = f32::from_bits(cpu.reg(Reg::R0));
    let quo = mem.read_u32(quo_addr).unwrap() as i32;
    assert_eq!(quo, 3);
    assert!((rem_f32 - 1.0f32).abs() < 1e-5);

    // 2. remquo(14.0, 4.0, &quo)
    let x_bits = 14.0f64.to_bits();
    let y_bits = 4.0f64.to_bits();

    cpu.set_reg(Reg::R0, (x_bits & 0xFFFF_FFFF) as u32);
    cpu.set_reg(Reg::R1, (x_bits >> 32) as u32);
    cpu.set_reg(Reg::R2, (y_bits & 0xFFFF_FFFF) as u32);
    cpu.set_reg(Reg::R3, (y_bits >> 32) as u32);

    let sp = GuestAddr::new(cpu.sp());
    mem.write_u32(sp, quo_addr.as_u32()).unwrap();

    call_bionic(&mut bridge, BionicFuncId::Remquo, &mut cpu, &mut mem).unwrap();
    let res_u64 = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
    let rem_f64 = f64::from_bits(res_u64);
    let quo64 = mem.read_u32(quo_addr).unwrap() as i32;

    assert_eq!(quo64, 4); // round(14/4) = 4 (or 3.5 rounds to 4)
    assert!((rem_f64 - (-2.0f64)).abs() < 1e-5);
}

#[test]
fn test_nextafter_and_nan() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. nextafterf(1.0, 2.0)
    cpu.set_reg(Reg::R0, 1.0f32.to_bits());
    cpu.set_reg(Reg::R1, 2.0f32.to_bits());
    call_bionic(&mut bridge, BionicFuncId::Nextafterf, &mut cpu, &mut mem).unwrap();
    let res_f32 = f32::from_bits(cpu.reg(Reg::R0));
    assert!(res_f32 > 1.0f32);

    // 2. nanf
    call_bionic(&mut bridge, BionicFuncId::Nanf, &mut cpu, &mut mem).unwrap();
    let nan_f32 = f32::from_bits(cpu.reg(Reg::R0));
    assert!(nan_f32.is_nan());

    // 3. nan
    call_bionic(&mut bridge, BionicFuncId::Nan, &mut cpu, &mut mem).unwrap();
    let nan_u64 = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
    let nan_f64 = f64::from_bits(nan_u64);
    assert!(nan_f64.is_nan());
}

#[test]
fn test_fdim_ilogb_scalbn() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. fdimf(5.0, 2.0) => 3.0
    cpu.set_reg(Reg::R0, 5.0f32.to_bits());
    cpu.set_reg(Reg::R1, 2.0f32.to_bits());
    call_bionic(&mut bridge, BionicFuncId::Fdimf, &mut cpu, &mut mem).unwrap();
    assert_eq!(f32::from_bits(cpu.reg(Reg::R0)), 3.0f32);

    // fdimf(2.0, 5.0) => 0.0
    cpu.set_reg(Reg::R0, 2.0f32.to_bits());
    cpu.set_reg(Reg::R1, 5.0f32.to_bits());
    call_bionic(&mut bridge, BionicFuncId::Fdimf, &mut cpu, &mut mem).unwrap();
    assert_eq!(f32::from_bits(cpu.reg(Reg::R0)), 0.0f32);

    // 2. ilogbf(16.0) => 4
    cpu.set_reg(Reg::R0, 16.0f32.to_bits());
    call_bionic(&mut bridge, BionicFuncId::Ilogbf, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0) as i32, 4);

    // 3. scalbnf(3.0, 3) => 24.0 (3 * 2^3)
    cpu.set_reg(Reg::R0, 3.0f32.to_bits());
    cpu.set_reg(Reg::R1, 3);
    call_bionic(&mut bridge, BionicFuncId::Scalbnf, &mut cpu, &mut mem).unwrap();
    assert_eq!(f32::from_bits(cpu.reg(Reg::R0)), 24.0f32);

    // 4. scalbn(1.5, 4) => 24.0 (1.5 * 2^4)
    let x_bits = 1.5f64.to_bits();
    cpu.set_reg(Reg::R0, (x_bits & 0xFFFF_FFFF) as u32);
    cpu.set_reg(Reg::R1, (x_bits >> 32) as u32);
    cpu.set_reg(Reg::R2, 4);
    call_bionic(&mut bridge, BionicFuncId::Scalbn, &mut cpu, &mut mem).unwrap();
    let res_u64 = (cpu.reg(Reg::R0) as u64) | ((cpu.reg(Reg::R1) as u64) << 32);
    assert_eq!(f64::from_bits(res_u64), 24.0f64);
}

#[test]
fn test_symbol_resolution() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "fmaf",
        "fma",
        "remquof",
        "remquo",
        "nextafterf",
        "nextafter",
        "nanf",
        "nan",
        "fdimf",
        "fdim",
        "ilogbf",
        "ilogb",
        "logbf",
        "logb",
        "scalbnf",
        "scalbn",
        "scalblnf",
        "scalbln",
    ];

    for sym in symbols {
        let addr = bridge.resolve(sym);
        assert!(addr.is_some(), "Symbol {} must be resolved", sym);
        assert_ne!(addr.unwrap().as_u32(), 0);
    }
}
