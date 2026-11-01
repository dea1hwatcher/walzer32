use transd_core::{GuestAddr, Memory, Reg};
use transd_rt::{DbtEngine, EngineError};
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
    let mut steps = 0;
    while engine.cpu.pc() != GuestAddr::new(SENTINEL_RETURN_ADDR) {
        let pc = engine.cpu.pc();
        let thumb = engine.cpu.is_thumb();

        // Check if current instruction is an SVC (Bionic, JNI, GLES, or Audio stub)
        if let Ok((inst, _)) = transd_decoder::decode_next(&engine.mem, pc, thumb) {
            if let transd_decoder::Op::Svc { imm } = inst.op {
                // Try Bionic SVC
                if bionic.handle_svc(imm, &mut engine.cpu, &mut engine.mem)? {
                    let next_pc = pc.add(4);
                    engine.cpu.set_pc(next_pc);
                    continue;
                }
                // Try JNI SVC
                if jni.handle_svc(imm, &mut engine.cpu, &mut engine.mem)? {
                    let next_pc = pc.add(4);
                    engine.cpu.set_pc(next_pc);
                    continue;
                }
                // Try GLES SVC
                if let Some(ref mut g) = gles {
                    if g.handle_svc(imm, &mut engine.cpu, &mut engine.mem)? {
                        let next_pc = pc.add(4);
                        engine.cpu.set_pc(next_pc);
                        continue;
                    }
                }
                // Try Audio SVC
                if let Some(ref mut a) = audio {
                    if a.handle_svc(imm, &mut engine.cpu, &mut engine.mem)? {
                        let next_pc = pc.add(4);
                        engine.cpu.set_pc(next_pc);
                        continue;
                    }
                }
                // Try Asset SVC
                if let Some(ref mut ast) = asset {
                    if ast.handle_svc(imm, &mut engine.cpu, &mut engine.mem)? {
                        let next_pc = pc.add(4);
                        engine.cpu.set_pc(next_pc);
                        continue;
                    }
                }
                // Try HardwareBuffer SVC
                if let Some(ref mut hb) = hw_buffer {
                    if hb.handle_svc(imm, &mut engine.cpu, &mut engine.mem)? {
                        let next_pc = pc.add(4);
                        engine.cpu.set_pc(next_pc);
                        continue;
                    }
                }
            }
        }

        engine.step()?;
        steps += 1;
        if steps > 100_000 {
            return Err(EngineError::Trap("Guest execution limit exceeded (possible loop)".into()));
        }
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
