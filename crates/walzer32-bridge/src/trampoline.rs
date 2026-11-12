use walzer32_core::{GuestAddr, Memory, Reg};
use walzer32_rt::{DbtEngine, EngineError, EngineStepResult};
#[cfg(unix)]
use libc;
use crate::asset::AssetBridge;
use crate::audio::AudioBridge;
use crate::bionic::BionicBridge;
use crate::gles::GlesBridge;
use crate::hardware_buffer::HardwareBufferBridge;
use crate::jni::JniBridge;

pub const SENTINEL_RETURN_ADDR: u32 = 0xDEAD_BEE0;

/// Invokes a 32-bit guest function conforming to ARM AAPCS calling convention
pub fn invoke_guest<M: Memory>(
    engine: &mut DbtEngine<M>,
    bionic: &mut BionicBridge,
    jni: &mut JniBridge,
    func_addr: GuestAddr,
    args: &[u32],
) -> Result<u32, EngineError> {
    invoke_guest_extended(engine, bionic, jni, None, None, None, None, func_addr, args)
}

/// Invokes a 32-bit guest function with optional GLES passthrough support
pub fn invoke_guest_full<M: Memory>(
    engine: &mut DbtEngine<M>,
    bionic: &mut BionicBridge,
    jni: &mut JniBridge,
    gles: Option<&mut GlesBridge>,
    func_addr: GuestAddr,
    args: &[u32],
) -> Result<u32, EngineError> {
    invoke_guest_extended(engine, bionic, jni, gles, None, None, None, func_addr, args)
}

fn dispatch_bridge_svc<M: Memory>(
    imm: u32,
    engine: &mut DbtEngine<M>,
    bionic: &mut BionicBridge,
    jni: &mut JniBridge,
    gles: &mut Option<&mut GlesBridge>,
    audio: &mut Option<&mut AudioBridge>,
    asset: &mut Option<&mut AssetBridge>,
    hw_buffer: &mut Option<&mut HardwareBufferBridge>,
) -> Result<(), EngineError> {
    if bionic.handle_svc(imm, &mut engine.cpu, &mut engine.mem)? {
        engine.sync_signal_state(&bionic.signal_state);
        return Ok(());
    }
    if jni.handle_svc(imm, &mut engine.cpu, &mut engine.mem)? {
        return Ok(());
    }
    if let Some(g) = gles.as_deref_mut() {
        if g.handle_svc(imm, &mut engine.cpu, &mut engine.mem)? {
            return Ok(());
        }
    }
    if let Some(a) = audio.as_deref_mut() {
        if a.handle_svc(imm, &mut engine.cpu, &mut engine.mem)? {
            return Ok(());
        }
    }
    if let Some(ast) = asset.as_deref_mut() {
        if ast.handle_svc(imm, &mut engine.cpu, &mut engine.mem)? {
            return Ok(());
        }
    }
    if let Some(hb) = hw_buffer.as_deref_mut() {
        if hb.handle_svc(imm, &mut engine.cpu, &mut engine.mem)? {
            return Ok(());
        }
    }
    Ok(())
}

/// Invokes a 32-bit guest function with optional GLES, Audio, Asset, and HardwareBuffer passthrough support
pub fn invoke_guest_extended<M: Memory>(
    engine: &mut DbtEngine<M>,
    bionic: &mut BionicBridge,
    jni: &mut JniBridge,
    mut gles: Option<&mut GlesBridge>,
    mut audio: Option<&mut AudioBridge>,
    mut asset: Option<&mut AssetBridge>,
    mut hw_buffer: Option<&mut HardwareBufferBridge>,
    func_addr: GuestAddr,
    args: &[u32],
) -> Result<u32, EngineError> {
    // 1. Pass first 4 arguments in r0..r3
    if !args.is_empty() {
        engine.cpu.set_reg(Reg::R0, args[0]);
    }
    if args.len() > 1 {
        engine.cpu.set_reg(Reg::R1, args[1]);
    }
    if args.len() > 2 {
        engine.cpu.set_reg(Reg::R2, args[2]);
    }
    if args.len() > 3 {
        engine.cpu.set_reg(Reg::R3, args[3]);
    }

    // 2. Pass additional arguments on stack if > 4
    if args.len() > 4 {
        let mut sp = engine.cpu.sp();
        let stack_args = &args[4..];
        let stack_bytes = (stack_args.len() * 4) as u32;
        sp = (sp - stack_bytes) & !7; // 8-byte stack alignment
        engine.cpu.set_sp(sp);

        for (i, &val) in stack_args.iter().enumerate() {
            let addr = GuestAddr::new(sp + (i * 4) as u32);
            engine.mem.write_u32(addr, val)?;
        }
    }

    // 3. Set sentinel return address in LR
    engine.cpu.set_lr(SENTINEL_RETURN_ADDR);

    // 4. Set PC and Thumb state
    let is_thumb = func_addr.is_thumb();
    engine.cpu.set_thumb(is_thumb);
    engine.cpu.set_pc(func_addr.instruction_addr());

    // 5. Execution loop: handle Bionic, JNI, GLES & Audio SVC calls until returning to SENTINEL_RETURN_ADDR
    engine.sync_signal_state(&bionic.signal_state);

    #[cfg(test)]
    let mut steps: u64 = 0;

    while (engine.cpu.pc().as_u32() & !1) != (SENTINEL_RETURN_ADDR & !1) {
        // Check for pending Fastmem faults from hardware signal handler
        #[cfg(unix)]
        if let Some((sig, fault_addr)) = walzer32_rt::take_fastmem_fault() {
            let sig_nr = match sig as libc::c_int {
                libc::SIGSEGV => walzer32_rt::signals::signal_nr::SIGSEGV,
                libc::SIGBUS => walzer32_rt::signals::signal_nr::SIGBUS,
                libc::SIGILL => walzer32_rt::signals::signal_nr::SIGILL,
                _ => walzer32_rt::signals::signal_nr::SIGSEGV,
            };
            // Try SMC first (write to code page)
            if engine.handle_write_fault(walzer32_core::GuestAddr::new(fault_addr as u32)) {
                continue;
            }
            // Try guest signal delivery
            match engine.handle_guest_fault(sig_nr, Some(fault_addr as u32)) {
                Ok(true) => continue,
                _ => {
                    return Err(EngineError::Trap(format!(
                        "Unhandled guest signal {} at 0x{:08x}",
                        sig_nr, fault_addr
                    )));
                }
            }
        }

        match engine.step()? {
            EngineStepResult::Syscall(_) => {
                if let Some(imm) = engine.last_svc_imm() {
                    dispatch_bridge_svc(
                        imm,
                        engine,
                        bionic,
                        jni,
                        &mut gles,
                        &mut audio,
                        &mut asset,
                        &mut hw_buffer,
                    )?;
                }
            }
            EngineStepResult::Halted { exit_code } => {
                engine.cpu.set_reg(Reg::R0, exit_code as u32);
                break;
            }
            EngineStepResult::Continue | EngineStepResult::Breakpoint { .. } => {}
        }

        #[cfg(test)]
        {
            steps += 1;
            if steps > 10_000_000 {
                return Err(EngineError::Trap("Guest execution limit exceeded in test".into()));
            }
        }
    }

    if let Some(s) = engine.signal_state() {
        bionic.signal_state = s.clone();
    }

    Ok(engine.cpu.reg(Reg::R0))
}

/// Invokes standard JNI_OnLoad(JavaVM *vm, void *reserved)
pub fn invoke_jni_onload<M: Memory>(
    engine: &mut DbtEngine<M>,
    bionic: &mut BionicBridge,
    jni: &mut JniBridge,
    onload_addr: GuestAddr,
) -> Result<u32, EngineError> {
    invoke_guest(
        engine,
        bionic,
        jni,
        onload_addr,
        &[jni.vm_ptr.as_u32(), 0],
    )
}

/// Invokes an exported JNI method: native_func(JNIEnv *env, jobject thiz, ...args)
pub fn invoke_jni_method<M: Memory>(
    engine: &mut DbtEngine<M>,
    bionic: &mut BionicBridge,
    jni: &mut JniBridge,
    method_addr: GuestAddr,
    thiz: u32,
    args: &[u32],
) -> Result<u32, EngineError> {
    let mut full_args = Vec::with_capacity(2 + args.len());
    full_args.push(jni.env_ptr.as_u32());
    full_args.push(thiz);
    full_args.extend_from_slice(args);

    invoke_guest(engine, bionic, jni, method_addr, &full_args)
}
