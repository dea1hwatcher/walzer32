use transd_core::{CpuState, FlatMemory, GuestAddr, Memory, Reg};
use transd_rt::{
    signals::{sa_flags, sig_actions, sig_stack, sigprocmask_how, signal_nr, GuestSigaction, GuestStackT},
    DbtEngine,
};
use transd_bridge::{
    invoke_guest, BionicBridge, BionicFuncId, JniBridge,
};

#[test]
fn test_bionic_sigaction_and_procmask_and_altstack() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let mut bionic = BionicBridge::new(GuestAddr::new(0x7000_0000), GuestAddr::new(0x7010_0000), 0x100_000);
    bionic.install_stubs(&mut mem).unwrap();

    let mut cpu = CpuState::new();

    // 1. Configure sigaction in guest memory
    let act_addr = GuestAddr::new(0x7003_0000);
    let old_act_addr = GuestAddr::new(0x7003_0040);
    let act = GuestSigaction {
        sa_handler: 0x7002_0500,
        sa_flags: sa_flags::SA_SIGINFO | sa_flags::SA_ONSTACK,
        sa_restorer: 0x7000_02A0,
        sa_mask: (1 << (signal_nr::SIGBUS - 1)) | (1 << (signal_nr::SIGFPE - 1)),
    };
    act.write_to_mem(&mut mem, act_addr, 8).unwrap();

    // Call sigaction(SIGSEGV, &act, &old_act)
    cpu.set_reg(Reg::R0, signal_nr::SIGSEGV);
    cpu.set_reg(Reg::R1, act_addr.as_u32());
    cpu.set_reg(Reg::R2, old_act_addr.as_u32());
    bionic
        .handle_svc(transd_bridge::BIONIC_SVC_MAGIC | (BionicFuncId::Sigaction as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0); // Success

    // Verify action in BionicBridge
    let cur_act = bionic.signal_state.get_action(signal_nr::SIGSEGV).unwrap();
    assert_eq!(cur_act.sa_handler, 0x7002_0500);
    assert_eq!(cur_act.sa_flags, sa_flags::SA_SIGINFO | sa_flags::SA_ONSTACK);

    // Verify old action was written (initially SIG_DFL)
    let old_act = GuestSigaction::read_from_mem(&mem, old_act_addr, 8).unwrap();
    assert_eq!(old_act.sa_handler, sig_actions::SIG_DFL);

    // 2. Test sigprocmask (SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK)
    let set_addr = GuestAddr::new(0x7003_0080);
    let old_set_addr = GuestAddr::new(0x7003_0090);
    let block_mask: u64 = (1 << (signal_nr::SIGINT - 1)) | (1 << (signal_nr::SIGQUIT - 1));
    mem.write_u32(set_addr, block_mask as u32).unwrap();
    mem.write_u32(set_addr.add(4), (block_mask >> 32) as u32).unwrap();

    cpu.set_reg(Reg::R0, sigprocmask_how::SIG_BLOCK);
    cpu.set_reg(Reg::R1, set_addr.as_u32());
    cpu.set_reg(Reg::R2, old_set_addr.as_u32());
    bionic
        .handle_svc(transd_bridge::BIONIC_SVC_MAGIC | (BionicFuncId::Sigprocmask as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(bionic.signal_state.blocked_mask, block_mask);

    // 3. Test sigaltstack
    let ss_addr = GuestAddr::new(0x7003_00A0);
    let old_ss_addr = GuestAddr::new(0x7003_00C0);
    let new_ss = GuestStackT {
        ss_sp: 0x7008_0000,
        ss_flags: 0,
        ss_size: sig_stack::SIGSTKSZ,
    };
    new_ss.write_to_mem(&mut mem, ss_addr).unwrap();

    cpu.set_reg(Reg::R0, ss_addr.as_u32());
    cpu.set_reg(Reg::R1, old_ss_addr.as_u32());
    cpu.set_sp(0x701F_0000); // Executing on normal stack
    bionic
        .handle_svc(transd_bridge::BIONIC_SVC_MAGIC | (BionicFuncId::Sigaltstack as u32), &mut cpu, &mut mem)
        .unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert!(bionic.signal_state.alt_stack.is_enabled());
    assert_eq!(bionic.signal_state.alt_stack.ss_sp, 0x7008_0000);
}

#[test]
fn test_bionic_raise_invokes_guest_signal_handler() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let mut bionic = BionicBridge::new(GuestAddr::new(0x7000_0000), GuestAddr::new(0x7010_0000), 0x100_000);
    bionic.install_stubs(&mut mem).unwrap();
    let mut jni = JniBridge::new(GuestAddr::new(0x7005_0000));
    jni.install(&mut mem).unwrap();
    let mut engine = DbtEngine::new(mem);

    let raise_addr = bionic.stub_base.add((BionicFuncId::Raise as u32) * 8);
    let handler_addr = GuestAddr::new(0x7002_0500);
    let out_data_addr = GuestAddr::new(0x7003_0000);

    // 1. Register SIGUSR1 handler in bionic
    let act = GuestSigaction {
        sa_handler: handler_addr.as_u32(),
        sa_flags: sa_flags::SA_SIGINFO,
        sa_restorer: 0,
        sa_mask: 0,
    };
    bionic.signal_state.set_action(signal_nr::SIGUSR1, Some(act)).unwrap();

    // 2. Assemble Signal Handler routine at 0x7002_0500:
    // void handler(int sig, siginfo_t *info, void *ucontext)
    // On entry:
    // r0 = sig (10)
    // r1 = &siginfo
    // r2 = &ucontext
    // lr = return trampoline
    //
    // Routine:
    // LDR r3, =out_data_addr
    // STR r0, [r3]          ; write sig (10) into [0x7003_0000]
    // LDR r4, [r1]          ; read si_signo from siginfo
    // STR r4, [r3, #4]      ; write si_signo to [0x7003_0004]
    // BX lr                 ; return via rt_sigreturn
    let handler_insts = [
        0xE59F300C, // LDR r3, [pc, #12] -> out_data_addr (0x00 + 8 + 12 = 0x14)
        0xE5830000, // STR r0, [r3]
        0xE5914000, // LDR r4, [r1]
        0xE5834004, // STR r4, [r3, #4]
        0xE12FFF1E, // BX lr
        // Literal pool:
        out_data_addr.as_u32(),
    ];
    for (i, &word) in handler_insts.iter().enumerate() {
        engine.mem.write_u32(handler_addr.add((i * 4) as u32), word).unwrap();
    }

    // 3. Assemble Main routine at 0x7002_0000:
    // PUSH {lr}
    // LDR r0, =10           ; SIGUSR1
    // LDR r1, =raise_addr
    // BLX r1                ; invoke raise(SIGUSR1)
    // MOV r0, #42           ; normal return code after signal handler resumes
    // POP {lr}
    // BX lr
    let code_addr = GuestAddr::new(0x7002_0000);
    let main_insts = [
        0xE52DE004, // STR lr, [sp, #-4]!
        0xE3A0000A, // MOV r0, #10 (SIGUSR1)
        0xE59F1010, // LDR r1, [pc, #16] -> raise_addr (0x08 + 8 + 16 = 0x20)
        0xE12FFF31, // BLX r1
        0xE3A0002A, // MOV r0, #42
        0xE49DE004, // LDR lr, [sp], #4
        0xE12FFF1E, // BX lr
        // Literal pool:
        0,          // padding
        raise_addr.as_u32(),
    ];
    for (i, &word) in main_insts.iter().enumerate() {
        engine.mem.write_u32(code_addr.add((i * 4) as u32), word).unwrap();
    }

    engine.cpu.set_sp(0x701F_F000);

    // Execute
    let res = invoke_guest(&mut engine, &mut bionic, &mut jni, code_addr, &[]).unwrap();
    assert_eq!(res, 42); // Normal return after signal return!

    // Verify handler wrote the signal number and siginfo correctly
    let recorded_sig = engine.mem.read_u32(out_data_addr).unwrap();
    assert_eq!(recorded_sig, signal_nr::SIGUSR1);

    let recorded_info_sig = engine.mem.read_u32(out_data_addr.add(4)).unwrap();
    assert_eq!(recorded_info_sig, signal_nr::SIGUSR1);
}

#[test]
fn test_engine_fault_translation_and_recovery() {
    let mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let mut engine = DbtEngine::new(mem);

    // Initial CPU state
    engine.cpu.set_reg(Reg::R0, 100);
    engine.cpu.set_reg(Reg::R5, 555);
    engine.cpu.set_sp(0x7010_0000);
    let fault_pc = GuestAddr::new(0x7002_0100);
    engine.cpu.set_pc(fault_pc);

    // Register a SIGSEGV handler in engine's syscall handler
    let handler_addr = 0x7002_0800;
    let act = GuestSigaction {
        sa_handler: handler_addr,
        sa_flags: sa_flags::SA_SIGINFO,
        sa_restorer: 0,
        sa_mask: 0,
    };
    engine
        .syscall_handler
        .signal_state_mut()
        .unwrap()
        .set_action(signal_nr::SIGSEGV, Some(act))
        .unwrap();

    // Trigger guest fault (e.g. read from invalid address 0x0000_0008)
    let handled = engine.handle_guest_fault(signal_nr::SIGSEGV, Some(0x0000_0008)).unwrap();
    assert!(handled);

    // CPU should now be redirected to the signal handler
    assert_eq!(engine.cpu.pc(), GuestAddr::new(handler_addr));
    assert_eq!(engine.cpu.reg(Reg::R0), signal_nr::SIGSEGV);

    // Inspect the siginfo_t generated on the guest stack
    let siginfo_addr = GuestAddr::new(engine.cpu.reg(Reg::R1));
    let ucontext_addr = GuestAddr::new(engine.cpu.reg(Reg::R2));
    assert_eq!(engine.mem.read_u32(siginfo_addr).unwrap(), signal_nr::SIGSEGV);
    assert_eq!(engine.mem.read_u32(siginfo_addr.add(12)).unwrap(), 0x0000_0008); // si_addr

    // Read ucontext_t from guest memory and simulate handler recovery
    // (e.g. handler skips faulting instruction by advancing pc by 4)
    let mut ucontext = transd_rt::signals::GuestUContext::read_from_mem(&engine.mem, ucontext_addr).unwrap();
    assert_eq!(ucontext.uc_mcontext.arm_pc, fault_pc.as_u32());
    assert_eq!(ucontext.uc_mcontext.arm_r0, 100);
    assert_eq!(ucontext.uc_mcontext.arm_r5, 555);

    // Advance PC to skip faulting instruction and set R0 = 999
    ucontext.uc_mcontext.arm_pc += 4;
    ucontext.uc_mcontext.arm_r0 = 999;
    ucontext.write_to_mem(&mut engine.mem, ucontext_addr).unwrap();

    // Now execute rt_sigreturn
    engine
        .syscall_handler
        .signal_state_mut()
        .unwrap()
        .restore_sigreturn(&mut engine.cpu, &engine.mem)
        .unwrap();

    // Verification of restored and recovered state
    assert_eq!(engine.cpu.pc(), fault_pc.add(4)); // Advanced past faulting inst!
    assert_eq!(engine.cpu.reg(Reg::R0), 999);      // Recovered result!
    assert_eq!(engine.cpu.reg(Reg::R5), 555);      // Preserved register!
    assert_eq!(engine.cpu.sp(), 0x7010_0000);      // Restored SP!
}
