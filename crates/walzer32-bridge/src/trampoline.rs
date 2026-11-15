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
use crate::vulkan::VulkanBridge;

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

pub fn dispatch_bridge_svc<M: Memory>(
    imm: u32,
    engine: &mut DbtEngine<M>,
    bionic: &mut BionicBridge,
    jni: &mut JniBridge,
    gles: &mut Option<&mut GlesBridge>,
    audio: &mut Option<&mut AudioBridge>,
    asset: &mut Option<&mut AssetBridge>,
    hw_buffer: &mut Option<&mut HardwareBufferBridge>,
    vulkan: &mut Option<&mut VulkanBridge>,
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
    if let Some(vk) = vulkan.as_deref_mut() {
        if vk.handle_svc(imm, &mut engine.cpu, &mut engine.mem)? {
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
    gles: Option<&mut GlesBridge>,
    audio: Option<&mut AudioBridge>,
    asset: Option<&mut AssetBridge>,
    hw_buffer: Option<&mut HardwareBufferBridge>,
    func_addr: GuestAddr,
    args: &[u32],
) -> Result<u32, EngineError> {
    invoke_guest_all(
        engine, bionic, jni, gles, audio, asset, hw_buffer, None, func_addr, args,
    )
}

/// Prepares ARM32 AAPCS registers, stack arguments, LR sentinel, Thumb bit, and PC
/// for invoking a guest function.
pub fn prepare_guest_call<M: Memory>(
    engine: &mut DbtEngine<M>,
    func_addr: GuestAddr,
    args: &[u32],
) -> Result<(), EngineError> {
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

    engine.cpu.set_lr(SENTINEL_RETURN_ADDR);
    let is_thumb = func_addr.is_thumb();
    engine.cpu.set_thumb(is_thumb);
    engine.cpu.set_pc(func_addr.instruction_addr());
    Ok(())
}

/// Checks and services any pending Fastmem / SMC hardware fault on Unix hosts.
/// Returns `Ok(true)` if a fault was handled and guest execution should retry the step.
pub fn check_fastmem_fault<M: Memory>(_engine: &mut DbtEngine<M>) -> Result<bool, EngineError> {
    #[cfg(unix)]
    if let Some((sig, fault_addr)) = walzer32_rt::take_fastmem_fault() {
        let sig_nr = match sig as libc::c_int {
            libc::SIGSEGV => walzer32_rt::signals::signal_nr::SIGSEGV,
            libc::SIGBUS => walzer32_rt::signals::signal_nr::SIGBUS,
            libc::SIGILL => walzer32_rt::signals::signal_nr::SIGILL,
            _ => walzer32_rt::signals::signal_nr::SIGSEGV,
        };
        if _engine.handle_write_fault(GuestAddr::new(fault_addr as u32)) {
            return Ok(true);
        }
        return match _engine.handle_guest_fault(sig_nr, Some(fault_addr as u32)) {
            Ok(true) => Ok(true),
            _ => Err(EngineError::Trap(format!(
                "Unhandled guest signal {} at 0x{:08x}",
                sig_nr, fault_addr
            ))),
        };
    }
    Ok(false)
}

/// Invokes a 32-bit guest function with all bridges including Vulkan passthrough support
pub fn invoke_guest_all<M: Memory>(
    engine: &mut DbtEngine<M>,
    bionic: &mut BionicBridge,
    jni: &mut JniBridge,
    mut gles: Option<&mut GlesBridge>,
    mut audio: Option<&mut AudioBridge>,
    mut asset: Option<&mut AssetBridge>,
    mut hw_buffer: Option<&mut HardwareBufferBridge>,
    mut vulkan: Option<&mut VulkanBridge>,
    func_addr: GuestAddr,
    args: &[u32],
) -> Result<u32, EngineError> {
    prepare_guest_call(engine, func_addr, args)?;

    // 5. Execution loop: handle Bionic, JNI, GLES & Audio SVC calls until returning to SENTINEL_RETURN_ADDR
    engine.sync_signal_state(&bionic.signal_state);

    #[cfg(test)]
    let mut steps: u64 = 0;

    while (engine.cpu.pc().as_u32() & !1) != (SENTINEL_RETURN_ADDR & !1) {
        if check_fastmem_fault(engine)? {
            continue;
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
                        &mut vulkan,
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

use std::sync::{Arc, Mutex};
use walzer32_rt::FutexManager;
use crate::{
    ASSET_SVC_MAGIC, AUDIO_SVC_MAGIC, BIONIC_SVC_MAGIC, GLES_SVC_MAGIC,
    HARDWARE_BUFFER_SVC_MAGIC, JNI_SVC_MAGIC, VULKAN_SVC_MAGIC,
};
use crate::bionic::{
    futex_mutex_lock, futex_mutex_unlock, BlockingBionicOp, ThreadExitCoordinator,
};

/// Thread-safe shared bridge container for true multi-threaded guest execution (`invoke_guest_mt`).
#[derive(Clone)]
pub struct SharedGuestRuntime {
    pub bionic: Arc<Mutex<BionicBridge>>,
    pub jni: Arc<Mutex<JniBridge>>,
    pub gles: Option<Arc<Mutex<GlesBridge>>>,
    pub audio: Option<Arc<Mutex<AudioBridge>>>,
    pub asset: Option<Arc<Mutex<AssetBridge>>>,
    pub hw_buffer: Option<Arc<Mutex<HardwareBufferBridge>>>,
    pub vulkan: Option<Arc<Mutex<VulkanBridge>>>,
    pub futex: FutexManager,
    pub thread_coordinator: ThreadExitCoordinator,
    pub is_terminating: Arc<std::sync::atomic::AtomicBool>,
    worker_handles: Arc<Mutex<Vec<(u32, std::thread::JoinHandle<()>)>>>,
}

impl SharedGuestRuntime {
    pub fn new(bionic: BionicBridge, jni: JniBridge, futex: FutexManager) -> Self {
        let mut bionic = bionic;
        bionic.enable_multithreading(futex.clone());
        let thread_coordinator = bionic.thread_coordinator.clone();
        Self {
            bionic: Arc::new(Mutex::new(bionic)),
            jni: Arc::new(Mutex::new(jni)),
            gles: None,
            audio: None,
            asset: None,
            hw_buffer: None,
            vulkan: None,
            futex,
            thread_coordinator,
            is_terminating: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            worker_handles: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn from_shared(
        bionic: Arc<Mutex<BionicBridge>>,
        jni: Arc<Mutex<JniBridge>>,
        futex: FutexManager,
    ) -> Self {
        let thread_coordinator = {
            let mut b = bionic.lock().unwrap();
            b.enable_multithreading(futex.clone());
            b.thread_coordinator.clone()
        };
        Self {
            bionic,
            jni,
            gles: None,
            audio: None,
            asset: None,
            hw_buffer: None,
            vulkan: None,
            futex,
            thread_coordinator,
            is_terminating: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            worker_handles: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn with_gles(mut self, gles: Arc<Mutex<GlesBridge>>) -> Self {
        self.gles = Some(gles);
        self
    }

    pub fn with_audio(mut self, audio: Arc<Mutex<AudioBridge>>) -> Self {
        self.audio = Some(audio);
        self
    }

    pub fn with_asset(mut self, asset: Arc<Mutex<AssetBridge>>) -> Self {
        self.asset = Some(asset);
        self
    }

    pub fn with_hw_buffer(mut self, hw_buffer: Arc<Mutex<HardwareBufferBridge>>) -> Self {
        self.hw_buffer = Some(hw_buffer);
        self
    }

    pub fn with_vulkan(mut self, vulkan: Arc<Mutex<VulkanBridge>>) -> Self {
        self.vulkan = Some(vulkan);
        self
    }

    pub fn record_worker_handle(&self, tid: u32, handle: std::thread::JoinHandle<()>) {
        self.worker_handles.lock().unwrap().push((tid, handle));
    }

    pub fn join_worker(&self, tid: u32) {
        let mut handles = self.worker_handles.lock().unwrap();
        if let Some(pos) = handles.iter().position(|(t, _)| *t == tid) {
            let (_, handle) = handles.remove(pos);
            drop(handles);
            let _ = handle.join();
        }
    }

    pub fn active_worker_count(&self) -> usize {
        let mut handles = self.worker_handles.lock().unwrap();
        let mut i = 0;
        let mut finished = Vec::new();
        while i < handles.len() {
            if handles[i].1.is_finished() {
                finished.push(handles.remove(i).1);
            } else {
                i += 1;
            }
        }
        let remaining = handles.len();
        drop(handles);
        for h in finished {
            let _ = h.join();
        }
        remaining
    }

    pub fn join_all_workers(&self) {
        self.is_terminating.store(true, std::sync::atomic::Ordering::Release);
        self.futex.wake_all_queues();
        let handles = std::mem::take(&mut *self.worker_handles.lock().unwrap());
        for (_, handle) in handles {
            let _ = handle.join();
        }
    }
}

fn apply_mt_spawns_and_blocking<M: Memory + Clone + Send + Sync + 'static>(
    engine: &mut DbtEngine<M>,
    runtime: &SharedGuestRuntime,
    blocking: Option<BlockingBionicOp>,
    spawns: Vec<crate::bionic::PendingThreadSpawn>,
    tid: u32,
) -> Result<Option<u32>, EngineError> {
    for sp in spawns {
        let child = engine.fork_thread_at(
            sp.tid,
            sp.start_routine.as_u32(),
            sp.stack_top.as_u32(),
            sp.arg,
            SENTINEL_RETURN_ADDR,
            sp.tls_ptr.as_u32(),
        );
        spawn_worker_engine(child, runtime.clone(), sp.tid);
    }

    if let Some(op) = blocking {
        match op {
            BlockingBionicOp::MutexLock { mutex_ptr } => {
                futex_mutex_lock(&mut engine.mem, &runtime.futex, mutex_ptr, tid)?;
                engine.cpu.set_reg(Reg::R0, 0);
            }
            BlockingBionicOp::CondWait {
                cond_ptr,
                mutex_ptr,
                expected_seq,
                timeout,
                is_timedwait,
            } => {
                if mutex_ptr.as_u32() != 0 {
                    let _ = futex_mutex_unlock(&mut engine.mem, &runtime.futex, mutex_ptr, tid)?;
                }
                let timed_out = matches!(
                    runtime.futex.wait(&engine.mem, cond_ptr, expected_seq, timeout),
                    Err(walzer32_rt::FutexError::TimedOut)
                );
                if mutex_ptr.as_u32() != 0 {
                    futex_mutex_lock(&mut engine.mem, &runtime.futex, mutex_ptr, tid)?;
                }
                engine.cpu.set_reg(
                    Reg::R0,
                    if is_timedwait && timed_out { 110 } else { 0 },
                );
            }
            BlockingBionicOp::ThreadJoin { tid: target_tid, retval_ptr } => {
                let retval = runtime
                    .thread_coordinator
                    .wait_for(target_tid)
                    .unwrap_or(0);
                runtime.join_worker(target_tid);
                {
                    let mut b = runtime.bionic.lock().unwrap();
                    if let Some(desc) = b.threads.get_mut(&target_tid) {
                        desc.joined = true;
                        desc.retval = Some(retval);
                    }
                    b.pthread_specific.retain(|&(t, _), _| t != target_tid);
                }
                if retval_ptr.as_u32() != 0 {
                    engine.mem.write_u32(retval_ptr, retval)?;
                }
                engine.cpu.set_reg(Reg::R0, 0);
            }
            BlockingBionicOp::ExitThread { retval } => {
                engine.cpu.set_reg(Reg::R0, retval);
                return Ok(Some(retval));
            }
        }
    }
    Ok(None)
}

/// Flushes already-queued `PendingClone`, `PendingThreadSpawn`, and `BlockingBionicOp`
/// after promoting from single-threaded execution to `SharedGuestRuntime`.
pub fn flush_pending_mt_actions<M: Memory + Clone + Send + Sync + 'static>(
    engine: &mut DbtEngine<M>,
    runtime: &SharedGuestRuntime,
) -> Result<Option<u32>, EngineError> {
    if let Some(pending_clone) = engine.take_pending_clone() {
        let child_tid = pending_clone.child_tid;
        let child = engine.fork_for_thread(&pending_clone);
        spawn_worker_engine(child, runtime.clone(), child_tid);
    }
    let (blocking, spawns, tid) = {
        let mut bionic = runtime.bionic.lock().unwrap();
        (bionic.take_blocking_op(), bionic.drain_pending_spawns(), bionic.current_thread_id.max(1))
    };
    apply_mt_spawns_and_blocking(engine, runtime, blocking, spawns, tid)
}

/// Helper to invoke `dispatch_svc_mt`, spawn any newly created worker threads,
/// and run any blocking synchronization outside bridge mutexes.
pub fn handle_mt_syscall_and_spawns<M: Memory + Clone + Send + Sync + 'static>(
    engine: &mut DbtEngine<M>,
    runtime: &SharedGuestRuntime,
    tid: u32,
) -> Result<Option<u32>, EngineError> {
    if let Some(pending_clone) = engine.take_pending_clone() {
        let child_tid = pending_clone.child_tid;
        let child = engine.fork_for_thread(&pending_clone);
        spawn_worker_engine(child, runtime.clone(), child_tid);
    }

    if let Some(imm) = engine.last_svc_imm() {
        let (blocking, spawns) = dispatch_svc_mt(imm, tid, engine, runtime)?;
        return apply_mt_spawns_and_blocking(engine, runtime, blocking, spawns, tid);
    }
    Ok(None)
}

fn dispatch_svc_mt<M: Memory>(
    imm: u32,
    caller_tid: u32,
    engine: &mut DbtEngine<M>,
    runtime: &SharedGuestRuntime,
) -> Result<(Option<BlockingBionicOp>, Vec<crate::bionic::PendingThreadSpawn>), EngineError> {
    if (imm & 0xFFFF_0000) == BIONIC_SVC_MAGIC {
        let mut bionic = runtime.bionic.lock().unwrap();
        bionic.current_thread_id = caller_tid;
        let _ = bionic.handle_svc(imm, &mut engine.cpu, &mut engine.mem)?;
        let spawns = bionic.drain_pending_spawns();
        let blocking = bionic.take_blocking_op();
        return Ok((blocking, spawns));
    }

    // Lock only the target bridge for this SVC magic prefix so threads on different
    // subsystems never contend with each other or with blocking waits.
    match imm & 0xFFFF_0000 {
        JNI_SVC_MAGIC => {
            let mut jni = runtime.jni.lock().unwrap();
            let _ = jni.handle_svc(imm, &mut engine.cpu, &mut engine.mem)?;
        }
        GLES_SVC_MAGIC => {
            if let Some(g) = &runtime.gles {
                let mut gles = g.lock().unwrap();
                let _ = gles.handle_svc(imm, &mut engine.cpu, &mut engine.mem)?;
            }
        }
        AUDIO_SVC_MAGIC => {
            if let Some(a) = &runtime.audio {
                let mut audio = a.lock().unwrap();
                let _ = audio.handle_svc(imm, &mut engine.cpu, &mut engine.mem)?;
            }
        }
        ASSET_SVC_MAGIC => {
            if let Some(a) = &runtime.asset {
                let mut asset = a.lock().unwrap();
                let _ = asset.handle_svc(imm, &mut engine.cpu, &mut engine.mem)?;
            }
        }
        HARDWARE_BUFFER_SVC_MAGIC => {
            if let Some(h) = &runtime.hw_buffer {
                let mut hw = h.lock().unwrap();
                let _ = hw.handle_svc(imm, &mut engine.cpu, &mut engine.mem)?;
            }
        }
        VULKAN_SVC_MAGIC => {
            if let Some(v) = &runtime.vulkan {
                let mut vk = v.lock().unwrap();
                let _ = vk.handle_svc(imm, &mut engine.cpu, &mut engine.mem)?;
            }
        }
        _ => {}
    }
    Ok((None, Vec::new()))
}

pub fn spawn_worker_engine<M: Memory + Clone + Send + Sync + 'static>(
    mut child_engine: DbtEngine<M>,
    runtime: SharedGuestRuntime,
    tid: u32,
) {
    let coordinator = runtime.thread_coordinator.clone();
    coordinator.register(tid);
    let rt_handle = runtime.clone();
    let handle = std::thread::spawn(move || {
        let retval = run_guest_mt_loop(&mut child_engine, &rt_handle, tid).unwrap_or(0);
        coordinator.mark_finished(tid, retval);
    });
    runtime.record_worker_handle(tid, handle);
}

/// Core multi-threaded execution loop shared by main and spawned guest threads.
pub fn run_guest_mt_loop<M: Memory + Clone + Send + Sync + 'static>(
    engine: &mut DbtEngine<M>,
    runtime: &SharedGuestRuntime,
    tid: u32,
) -> Result<u32, EngineError> {
    loop {
        if runtime.is_terminating.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }

        if (engine.cpu.pc().as_u32() & !1) == (SENTINEL_RETURN_ADDR & !1) {
            break;
        }

        match engine.step()? {
            EngineStepResult::Syscall(_) => {
                if let Some(retval) = handle_mt_syscall_and_spawns(engine, runtime, tid)? {
                    return Ok(retval);
                }
            }
            EngineStepResult::Halted { exit_code } => {
                engine.cpu.set_reg(Reg::R0, exit_code);
                break;
            }
            EngineStepResult::Continue | EngineStepResult::Breakpoint { .. } => {}
        }

        #[cfg(test)]
        {
            steps += 1;
            if steps > 10_000_000 {
                return Err(EngineError::Trap(
                    "Guest execution limit exceeded in test".into(),
                ));
            }
        }
    }

    Ok(engine.cpu.reg(Reg::R0))
}

/// Multi-threaded guest invocation supporting real `pthread_create` / `SYS_clone` OS worker threads,
/// futex-backed mutexes/condvars, `pthread_join`, and lock-free shared JIT translation.
pub fn invoke_guest_mt<M: Memory + Clone + Send + Sync + 'static>(
    engine: &mut DbtEngine<M>,
    runtime: &SharedGuestRuntime,
    func_addr: GuestAddr,
    args: &[u32],
) -> Result<u32, EngineError> {
    engine.enable_shared_jit();
    engine.set_futex_manager(runtime.futex.clone());

    {
        let mut bionic = runtime.bionic.lock().unwrap();
        bionic.enable_multithreading(runtime.futex.clone());
    }

    prepare_guest_call(engine, func_addr, args)?;

    let res = run_guest_mt_loop(engine, runtime, 1000);

    if let Some(s) = engine.signal_state() {
        let mut bionic = runtime.bionic.lock().unwrap();
        bionic.signal_state = s.clone();
    }

    res
}
