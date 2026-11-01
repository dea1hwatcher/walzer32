use transd_core::{ArenaMemory, Cond, Cpsr, GuestAddr, Memory, Reg};
use transd_decoder::{ArmInst, BitSatOp, CoreSatOp, Op, ShiftType};
use transd_emitter_a64::A64Compiler;
use transd_ir::{BlockExit, IrBlock, Lifter};
use transd_rt::DbtEngine;

#[test]
fn test_jit_compile_coresat_and_bitsat_blocks() {
    let mut block = IrBlock::new(GuestAddr::new(0x1000), false);

    // QADD r0, r1, r2
    block.insts.push(ArmInst::new(
        Cond::AL,
        Op::CoreSat {
            op: CoreSatOp::Qadd,
            rd: Reg::R0,
            rm: Reg::R1,
            rn: Reg::R2,
        },
        0xE102_0051,
    ));

    // QSUB r3, r4, r5
    block.insts.push(ArmInst::new(
        Cond::AL,
        Op::CoreSat {
            op: CoreSatOp::Qsub,
            rd: Reg::R3,
            rm: Reg::R4,
            rn: Reg::R5,
        },
        0xE125_3054,
    ));

    // QDADD r6, r7, r8
    block.insts.push(ArmInst::new(
        Cond::AL,
        Op::CoreSat {
            op: CoreSatOp::Qdadd,
            rd: Reg::R6,
            rm: Reg::R7,
            rn: Reg::R8,
        },
        0xE148_6057,
    ));

    // QDSUB r9, r10, r11
    block.insts.push(ArmInst::new(
        Cond::AL,
        Op::CoreSat {
            op: CoreSatOp::Qdsub,
            rd: Reg::R9,
            rm: Reg::R10,
            rn: Reg::R11,
        },
        0xE16B_905A,
    ));

    // SSAT r0, #16, r1, LSL #2
    block.insts.push(ArmInst::new(
        Cond::AL,
        Op::BitSat {
            op: BitSatOp::Ssat {
                sat_imm: 16,
                shift_type: ShiftType::Lsl,
                shift_imm: 2,
            },
            rd: Reg::R0,
            rn: Reg::R1,
        },
        0xE6A0_0111,
    ));

    // USAT r2, #8, r3, ASR #4
    block.insts.push(ArmInst::new(
        Cond::AL,
        Op::BitSat {
            op: BitSatOp::Usat {
                sat_imm: 8,
                shift_type: ShiftType::Asr,
                shift_imm: 4,
            },
            rd: Reg::R2,
            rn: Reg::R3,
        },
        0xE6E0_2253,
    ));

    // SSAT16 r4, #12, r5
    block.insts.push(ArmInst::new(
        Cond::AL,
        Op::BitSat {
            op: BitSatOp::Ssat16 { sat_imm: 12 },
            rd: Reg::R4,
            rn: Reg::R5,
        },
        0xE6A0_4F35,
    ));

    // USAT16 r6, #8, r7
    block.insts.push(ArmInst::new(
        Cond::AL,
        Op::BitSat {
            op: BitSatOp::Usat16 { sat_imm: 8 },
            rd: Reg::R6,
            rn: Reg::R7,
        },
        0xE6E0_6F37,
    ));

    block.exit = BlockExit::Direct(GuestAddr::new(0x1020));

    let compiled = A64Compiler::compile(&block);
    assert_eq!(compiled.inst_count, 8);
    assert!(compiled.code_bytes.len() > 100);
    assert_eq!(compiled.patch_sites.len(), 1);
}

#[test]
fn test_engine_jit_coresat_execution() {
    let mut arena = ArenaMemory::new().expect("Failed to reserve 4GB virtual arena");
    let code_base = GuestAddr::new(0x30000);
    arena.commit_range(code_base, 0x10000).unwrap();

    let mut engine = DbtEngine::new(arena);

    // Initial setup
    engine.cpu.set_reg(Reg::R1, 0x6000_0000);
    engine.cpu.set_reg(Reg::R2, 0x3000_0000); // 0x6000_0000 + 0x3000_0000 = 0x9000_0000 -> saturated to 0x7FFF_FFFF
    engine.cpu.set_reg(Reg::R4, 0x8000_0000); // -2147483648
    engine.cpu.set_reg(Reg::R5, 0x0000_0001); // -2147483648 - 1 -> saturated to -2147483648 (0x8000_0000)

    // Program:
    // 0x30000: QADD r0, r1, r2    (0xE102_0051)
    // 0x30004: QSUB r3, r4, r5    (0xE125_3054)
    // 0x30008: MOV r7, #1         (0xE3A0_7001)
    // 0x3000C: MOV r0, #0         (0xE3A0_0000)
    // 0x30010: SVC 0              (0xEF00_0000)
    engine.mem.write_u32(code_base, 0xE102_0051).unwrap();
    engine.mem.write_u32(code_base.add(4), 0xE125_3054).unwrap();
    engine.mem.write_u32(code_base.add(8), 0xE3A0_7001).unwrap();
    engine.mem.write_u32(code_base.add(12), 0xE3A0_0000).unwrap();
    engine.mem.write_u32(code_base.add(16), 0xEF00_0000).unwrap();

    // Verify lifting produces correct basic block
    let block = Lifter::lift_block(&engine.mem, code_base, false).unwrap();
    assert_eq!(block.insts.len(), 5);

    let compiled = A64Compiler::compile(&block);
    assert_eq!(compiled.inst_count, 5);

    engine.cpu.set_pc(code_base);
    let exit = engine.run(10).unwrap();
    assert_eq!(exit, 0);

    assert_eq!(engine.cpu.reg(Reg::R3), 0x8000_0000);
    assert!(engine.cpu.cpsr.contains(Cpsr::Q));
}
