use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use thiserror::Error;
use walzer32_apk::{ApkError, ApkPackage};
use walzer32_bridge::{
    check_fastmem_fault, dispatch_bridge_svc, flush_pending_mt_actions,
    marshal_host_jni_frame_to_aapcs32, prepare_guest_call, run_guest_mt_loop,
    unpack_guest_return_to_host_u64, AssetBridge, AudioBridge, AudioRingBuffer, BionicBridge,
    GlesBridge, HardwareBufferBridge, HostJniCallFrame, JniBridge, JniSignature,
    JniThunkGenerator, KeyEvent, RegisteredNativeMethod, SharedGuestRuntime, SurfaceBridge,
    TouchEvent, VulkanBridge, SENTINEL_RETURN_ADDR, SL_PLAYSTATE_PLAYING,
};
use walzer32_core::{GuestAddr, Memory, Reg};
#[cfg(not(target_os = "android"))]
use walzer32_core::SharedMemory;
#[cfg(target_os = "android")]
use walzer32_core::SharedArenaMemory;

// Memory type alias: SharedArenaMemory on Android (4GB thread-safe zero-overhead arena),
// SharedMemory on dev-host (Windows/Linux x86-64).
#[cfg(target_os = "android")]
type SessionMemory = SharedArenaMemory;
#[cfg(not(target_os = "android"))]
type SessionMemory = SharedMemory;
use walzer32_elf::{
    topological_sort_libs, CompositeResolver, ElfLoader, ElfParser, LoadedLibrary, LoaderError,
    SymbolResolver,
};
use walzer32_rt::{DbtEngine, EngineStepResult, JitPool};

#[derive(Debug, Clone)]
pub struct UniversalJniDescriptor {
    pub class_name: String,
    pub method_name: String,
    pub signature: String,
    pub guest_fn_ptr: GuestAddr,
    pub parsed_sig: JniSignature,
}

#[derive(Debug, Clone)]
pub struct CompiledJniThunk {
    pub class_name: String,
    pub method_name: String,
    pub signature: String,
    pub guest_fn_ptr: GuestAddr,
    pub host_fn_ptr: usize,
    pub descriptor_ptr: usize,
}

#[repr(C)]
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
struct HostJniNativeMethod {
    name: *const std::ffi::c_char,
    signature: *const std::ffi::c_char,
    fn_ptr: *const std::ffi::c_void,
}

/// Universal 64-bit->32-bit FFI trampoline invoked by generated AArch64 JNI thunks.
/// Marshals `HostJniCallFrame` arguments into AAPCS32 softfp and executes the guest 32-bit function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn walzer32_universal_jni_dispatcher(
    descriptor_ptr: usize,
    frame: *mut HostJniCallFrame,
) -> u64 {
    if descriptor_ptr == 0 || frame.is_null() {
        return 0;
    }
    let frame_copy = unsafe { *frame };
    let Ok(mut guard) = get_or_init_session() else {
        return 0;
    };
    let Some(session) = guard.as_mut() else {
        return 0;
    };
    let desc = unsafe { &*(descriptor_ptr as *const UniversalJniDescriptor) }.clone();
    let args32 =
        marshal_host_jni_frame_to_aapcs32(&desc.parsed_sig, &frame_copy, &mut session.jni);
    match session.call_native(desc.guest_fn_ptr, &args32) {
        Ok(r0) => {
            let r1 = session.engine.cpu.reg(Reg::R1);
            unpack_guest_return_to_host_u64(desc.parsed_sig.ret, r0, r1, &session.jni)
        }
        Err(e) => {
            log_e!(
                "Walzer32: Universal JNI dispatch failed for {}.{}{}: {:?}",
                desc.class_name,
                desc.method_name,
                desc.signature,
                e
            );
            0
        }
    }
}

#[cfg(target_os = "android")]
unsafe fn register_natives_on_host_env(
    host_jni_env: usize,
    class_name: &str,
    methods: &[(std::ffi::CString, std::ffi::CString, usize)],
) -> i32 {
    if host_jni_env == 0 || methods.is_empty() {
        return 0;
    }
    let env_ptr = host_jni_env as *mut std::ffi::c_void;
    let vtable = unsafe { *(host_jni_env as *const *const usize) };
    if vtable.is_null() {
        return -1;
    }
    // JNIEnv table indices: FindClass = 6, ExceptionClear = 17, RegisterNatives = 215, ExceptionCheck = 228
    let find_class: unsafe extern "C" fn(*mut std::ffi::c_void, *const std::ffi::c_char) -> *mut std::ffi::c_void =
        unsafe { std::mem::transmute(*vtable.add(6)) };
    let exception_clear: unsafe extern "C" fn(*mut std::ffi::c_void) =
        unsafe { std::mem::transmute(*vtable.add(17)) };
    let register_natives: unsafe extern "C" fn(
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        *const HostJniNativeMethod,
        i32,
    ) -> i32 = unsafe { std::mem::transmute(*vtable.add(215)) };
    let exception_check: unsafe extern "C" fn(*mut std::ffi::c_void) -> u8 =
        unsafe { std::mem::transmute(*vtable.add(228)) };

    let Ok(cls_cstr) = std::ffi::CString::new(class_name.replace('.', "/")) else {
        return -1;
    };
    let clazz = unsafe { find_class(env_ptr, cls_cstr.as_ptr()) };
    if clazz.is_null() || unsafe { exception_check(env_ptr) } != 0 {
        unsafe { exception_clear(env_ptr) };
        return -1;
    }

    let c_methods: Vec<HostJniNativeMethod> = methods
        .iter()
        .map(|(n, s, ptr)| HostJniNativeMethod {
            name: n.as_ptr(),
            signature: s.as_ptr(),
            fn_ptr: *ptr as *const std::ffi::c_void,
        })
        .collect();

    let rc = unsafe { register_natives(env_ptr, clazz, c_methods.as_ptr(), c_methods.len() as i32) };
    if unsafe { exception_check(env_ptr) } != 0 {
        unsafe { exception_clear(env_ptr) };
    }
    rc
}

#[cfg(not(target_os = "android"))]
unsafe fn register_natives_on_host_env(
    _host_jni_env: usize,
    _class_name: &str,
    _methods: &[(std::ffi::CString, std::ffi::CString, usize)],
) -> i32 {
    0
}

/// Lock-free / ultra-short-lock channels for UI, Audio, and Telemetry JNI calls so they never
/// block behind `GLOBAL_SESSION` while DBT execution or `nativeDrawFrame` holds the session mutex.
pub struct FastSessionChannels {
    pub audio_ring: Mutex<Option<Arc<AudioRingBuffer<i16>>>>,
    pub audio_volume_mb: AtomicI32,
    pub audio_volume_dirty: AtomicBool,
    pub audio_target_latency_bits: AtomicU32,
    pub audio_latency_dirty: AtomicBool,
    pub pending_touch: Mutex<Vec<TouchEvent>>,
    pub pending_key: Mutex<Vec<KeyEvent>>,
    pub pending_resize: Mutex<Option<(u32, u32)>>,
    pub telemetry_hud: Mutex<String>,
    pub telemetry_json: Mutex<String>,
}

impl FastSessionChannels {
    fn new() -> Self {
        Self {
            audio_ring: Mutex::new(None),
            audio_volume_mb: AtomicI32::new(0),
            audio_volume_dirty: AtomicBool::new(false),
            audio_target_latency_bits: AtomicU32::new(10.0f32.to_bits()),
            audio_latency_dirty: AtomicBool::new(false),
            pending_touch: Mutex::new(Vec::new()),
            pending_key: Mutex::new(Vec::new()),
            pending_resize: Mutex::new(None),
            telemetry_hud: Mutex::new(String::new()),
            telemetry_json: Mutex::new("{}".to_string()),
        }
    }

    pub fn push_touch(&self, ev: TouchEvent) {
        self.pending_touch.lock().unwrap_or_else(|e| e.into_inner()).push(ev);
    }

    pub fn push_key(&self, ev: KeyEvent) {
        self.pending_key.lock().unwrap_or_else(|e| e.into_inner()).push(ev);
    }

    pub fn set_pending_resize(&self, width: u32, height: u32) {
        *self.pending_resize.lock().unwrap_or_else(|e| e.into_inner()) = Some((width, height));
    }

    pub fn set_volume_millibels(&self, millibels: i32) {
        self.audio_volume_mb.store(millibels.clamp(-9600, 1000), Ordering::Release);
        self.audio_volume_dirty.store(true, Ordering::Release);
    }

    pub fn set_target_latency_ms(&self, ms: f32) {
        self.audio_target_latency_bits.store(ms.clamp(1.0, 100.0).to_bits(), Ordering::Release);
        self.audio_latency_dirty.store(true, Ordering::Release);
    }

    pub fn read_audio_frames(&self, out: &mut [i16]) -> usize {
        let ring = self
            .audio_ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(Arc::clone);
        if let Some(ring) = ring {
            ring.pop_slice_with_concealment(out) / 2
        } else {
            out.fill(0);
            0
        }
    }

    pub fn audio_underruns(&self) -> u64 {
        self.audio_ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|r| r.underrun_count())
            .unwrap_or(0)
    }

    pub fn audio_overruns(&self) -> u64 {
        self.audio_ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|r| r.overrun_count())
            .unwrap_or(0)
    }

    pub fn audio_latency_ms(&self) -> f32 {
        self.audio_ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|r| r.latency_ms(48000, 2))
            .unwrap_or(0.0)
    }

    pub fn audio_watermark_ratio(&self) -> f32 {
        self.audio_ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|r| r.watermark_fill_ratio())
            .unwrap_or(0.0)
    }

    pub fn telemetry_hud_snapshot(&self) -> String {
        self.telemetry_hud.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn telemetry_json_snapshot(&self) -> String {
        self.telemetry_json.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn clear(&self) {
        *self.audio_ring.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.audio_volume_mb.store(0, Ordering::Release);
        self.audio_volume_dirty.store(false, Ordering::Release);
        self.audio_target_latency_bits.store(10.0f32.to_bits(), Ordering::Release);
        self.audio_latency_dirty.store(false, Ordering::Release);
        self.pending_touch.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.pending_key.lock().unwrap_or_else(|e| e.into_inner()).clear();
        *self.pending_resize.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.telemetry_hud.lock().unwrap_or_else(|e| e.into_inner()).clear();
        *self.telemetry_json.lock().unwrap_or_else(|e| e.into_inner()) = "{}".to_string();
    }
}

static FAST_CHANNELS: OnceLock<FastSessionChannels> = OnceLock::new();

pub fn fast_channels() -> &'static FastSessionChannels {
    FAST_CHANNELS.get_or_init(FastSessionChannels::new)
}

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("Engine memory error: {0}")]
    Memory(#[from] walzer32_core::MemoryError),
    #[error("ELF loader error: {0}")]
    Loader(#[from] LoaderError),
    #[error("APK parsing error: {0}")]
    Apk(#[from] ApkError),
    #[error("Execution error: {0}")]
    Engine(#[from] walzer32_rt::EngineError),
    #[error("Session not initialized")]
    NotInitialized,
    #[error("Library not found: {0}")]
    LibraryNotFound(String),
    #[error("Symbol not found: {0}")]
    SymbolNotFound(String),
}

/// Global DBT Execution Session for Android Runtime
pub struct Walzer32Session {
    pub engine: DbtEngine<SessionMemory>,
    pub bionic: BionicBridge,
    pub gles: GlesBridge,
    pub jni: JniBridge,
    pub surface: SurfaceBridge,
    pub audio: AudioBridge,
    pub asset: AssetBridge,
    pub hardware_buffer: HardwareBufferBridge,
    pub vulkan: VulkanBridge,
    pub aot_cache_dir: Option<std::path::PathBuf>,
    pub apk_bytes: Option<Vec<u8>>,
    pub loaded_libraries: HashMap<String, LoadedLibrary>,
    pub next_load_addr: GuestAddr,
    pub jni_registry: crate::dynamic_jni::JniMethodRegistry,
    pub owns_host_window: bool,
    pub guest_native_activity_ptr: u32,
    pub guest_native_callbacks_ptr: u32,
    pub host_java_vm: usize,
    pub host_jni_env: usize,
    pub jni_thunk_pool: JitPool,
    pub jni_descriptors: Vec<Box<UniversalJniDescriptor>>,
    pub compiled_jni_thunks: HashMap<(String, String, String), CompiledJniThunk>,
    pub initialized: bool,
    pub active_mt_runtime: Option<SharedGuestRuntime>,
    pub main_stack_top: GuestAddr,
}

impl Walzer32Session {
    /// Initialize a new DBT session with a guest address space arena.
    ///
    /// On Android: `arena_base` is the fixed layout base (0x7000_0000); SharedArenaMemory
    /// reserves 4 GB and commits individual sections as needed across worker threads.
    /// On dev-host (Windows/Linux x86-64): SharedMemory with explicit base + size is used.
    pub fn new(arena_base: GuestAddr, arena_size: usize) -> Result<Self, SessionError> {
        // ── Memory allocation ────────────────────────────────────────────────
        #[cfg(target_os = "android")]
        let mut mem = SharedArenaMemory::new()?;

        #[cfg(not(target_os = "android"))]
        let mut mem = SharedMemory::new(arena_base, arena_size);

        // Layout inside arena:
        // arena_base + 0x0000_0000: Bionic stubs and TLS (0x100_000)
        // arena_base + 0x0010_0000: Bionic heap (0x400_000)
        // arena_base + 0x0050_0000: GLES stubs (0x100_000)
        // arena_base + 0x0060_0000: JNIEnv & JavaVM tables (0x100_000)
        // arena_base + 0x0070_0000: Audio stubs (0x100_000)
        // arena_base + 0x0080_0000: AssetManager stubs & heap (0x100_000)
        // arena_base + 0x0090_0000: HardwareBuffer stubs & heap (0x100_000)
        // arena_base + 0x00A0_0000: Stack region (0x100_000) -> SP top at +0x00B0_0000
        // arena_base + 0x00C0_0000: Anonymous mmap dynamic heap (0x400_000)
        // arena_base + 0x0100_0000: Dynamic library loading arena
        let bionic_stubs = arena_base;
        let bionic_heap = arena_base.add(0x100_000);
        let gles_stubs = arena_base.add(0x500_000);
        let gles_heap = arena_base.add(0x580_000);
        let jni_base = arena_base.add(0x600_000);
        let audio_stubs = arena_base.add(0x700_000);
        let asset_stubs = arena_base.add(0x800_000);
        let hw_buffer_stubs = arena_base.add(0x900_000);
        #[cfg(target_os = "android")]
        let mmap_base = GuestAddr::new(0x7800_0000);
        #[cfg(not(target_os = "android"))]
        let mmap_base = arena_base.add(0xC00_000);
        let lib_load_base = arena_base.add(0x100_0000);

        #[cfg(target_os = "android")]
        let (stack_region, stack_top, stack_size) = (
            GuestAddr::new(0x7F00_0000),
            GuestAddr::new(0x7F80_0000),
            0x80_0000usize, // 8 MB dedicated stack
        );

        #[cfg(not(target_os = "android"))]
        let (stack_region, stack_top, stack_size) = (
            arena_base.add(0xA00_000),
            arena_base.add(0xB00_000),
            0x10_0000usize,
        );

        // On Android commit pages for every fixed section up front.
        // ArenaMemory::commit_range(addr: GuestAddr, len: usize) -> Result<(), MemoryError>
        #[cfg(target_os = "android")]
        {
            mem.commit_range(bionic_stubs, 0x100_000)?;   // Bionic stubs + TLS
            mem.commit_range(bionic_heap,  0x400_000)?;   // Bionic heap
            mem.commit_range(gles_stubs,   0x180_000)?;   // GLES stubs + heap (up to jni_base)
            mem.commit_range(jni_base,     0x100_000)?;   // JNIEnv / JavaVM
            mem.commit_range(audio_stubs,  0x100_000)?;   // Audio stubs
            mem.commit_range(asset_stubs,  0x100_000)?;   // AssetManager stubs
            mem.commit_range(hw_buffer_stubs, 0x100_000)?;// HardwareBuffer stubs
            mem.commit_range(stack_region, stack_size)?;  // Stack region (8MB)
            mem.commit_range(mmap_base,    0x200_0000)?;  // mmap dynamic heap (32MB dedicated pool)
        }

        // Suppress unused-variable warning on targets where arena_size is not used directly
        let _ = arena_size;
        #[cfg(not(target_os = "android"))]
        let _ = (gles_heap, stack_region, stack_size);

        let mut bionic = BionicBridge::new(bionic_stubs, bionic_heap, 0x400_000);
        bionic.set_stack(stack_region, stack_size as u32);
        bionic.install_stubs(&mut mem)?;

        let gles = GlesBridge::new(gles_stubs, gles_heap);
        gles.install_stubs(&mut mem)?;

        let jni = JniBridge::new(jni_base);
        jni.install(&mut mem)?;

        let audio = AudioBridge::with_stub_base(audio_stubs);
        audio.install_stubs(&mut mem)?;

        let asset = AssetBridge::new(asset_stubs, asset_stubs.add(0x1000), 0xF_F000);
        asset.install_stubs(&mut mem)?;

        let hardware_buffer = HardwareBufferBridge::new(
            hw_buffer_stubs,
            hw_buffer_stubs.add(0x1000),
            0x7_F000,
        );
        hardware_buffer.install_stubs(&mut mem)?;

        let vulkan_stubs = arena_base.add(0x980_000);
        let vulkan = VulkanBridge::with_stub_base(vulkan_stubs);
        vulkan.install_stubs(&mut mem)?;

        let surface = SurfaceBridge::new();

        let mut engine = DbtEngine::new(mem);

        // Install host signal handlers for Fastmem/SMC on Android with actual host arena base
        #[cfg(target_os = "android")]
        {
            let host_base = engine.mem.as_mut_ptr() as usize;
            let mut sig_mgr = walzer32_rt::SignalManager::new(host_base, walzer32_core::ARENA_4GB_SIZE);
            if let Err(e) = sig_mgr.install_handlers() {
                log_e!("[walzer32] Warning: Failed to install signal handlers: {}", e);
            }
        }

        engine.cpu.set_sp(stack_top.as_u32() - 0x1000);
        bionic.set_mmap_current(mmap_base);
        engine.set_mmap_base(mmap_base);
        engine.sync_signal_state(&bionic.signal_state);
        if let Some(futex) = engine.futex_manager() {
            bionic.enable_multithreading(futex);
        }
        bionic.enable_deferred_dlopen();

        let session = Self {
            engine,
            bionic,
            gles,
            jni,
            surface,
            audio,
            asset,
            hardware_buffer,
            vulkan,
            aot_cache_dir: None,
            apk_bytes: None,
            loaded_libraries: HashMap::new(),
            next_load_addr: lib_load_base,
            jni_registry: crate::dynamic_jni::JniMethodRegistry::new(),
            owns_host_window: false,
            guest_native_activity_ptr: 0,
            guest_native_callbacks_ptr: 0,
            host_java_vm: 0,
            host_jni_env: 0,
            jni_thunk_pool: JitPool::new(),
            jni_descriptors: Vec::new(),
            compiled_jni_thunks: HashMap::new(),
            initialized: true,
            active_mt_runtime: None,
            main_stack_top: stack_top,
        };
        session.sync_fast_channels();
        Ok(session)
    }

    /// Attach an APK package by raw bytes and expose bundled 32-bit `.so` libraries in VFS for dynamic `dlopen`.
    pub fn attach_apk(&mut self, apk_bytes: Vec<u8>) {
        let _ = self.asset.load_apk(&apk_bytes);
        if let Ok(apk) = ApkPackage::open(&apk_bytes) {
            for lib in apk.arm32_libraries() {
                if let Ok(bytes) = apk.extract_library(&lib.filename) {
                    let arc = std::sync::Arc::new(bytes);
                    for path in [
                        format!("/lib/armeabi-v7a/{}", lib.filename),
                        format!("/data/app/lib/arm/{}", lib.filename),
                    ] {
                        self.bionic.vfs.register_file_arc(&path, std::sync::Arc::clone(&arc));
                        if let Some(vfs) = self.engine.vfs_mut() {
                            vfs.register_file_arc(&path, std::sync::Arc::clone(&arc));
                        }
                    }
                }
            }
        }
        self.apk_bytes = Some(apk_bytes);
    }

    /// Registers a custom in-memory file in the guest VFS
    pub fn register_vfs_file(&mut self, path: &str, content: Vec<u8>) {
        let arc = std::sync::Arc::new(content);
        self.bionic.vfs.register_file_arc(path, std::sync::Arc::clone(&arc));
        if let Some(vfs) = self.engine.vfs_mut() {
            vfs.register_file_arc(path, arc);
        }
    }

    /// Adds a path redirection rule in the guest VFS
    pub fn add_vfs_redirect(&mut self, from: &str, to: &str) {
        self.bionic.vfs.add_redirect(from, to);
        if let Some(vfs) = self.engine.vfs_mut() {
            vfs.add_redirect(from, to);
        }
    }

    /// Parse the attached APK package (borrows internal bytes)
    pub fn open_apk(&self) -> Result<Option<ApkPackage<'_>>, ApkError> {
        match &self.apk_bytes {
            Some(bytes) => ApkPackage::open(bytes).map(Some),
            None => Ok(None),
        }
    }

    /// Load a 32-bit ELF shared library by name from raw bytes (runs DT_INIT/DT_INIT_ARRAY and JNI_OnLoad).
    pub fn load_library_bytes(&mut self, name: &str, elf_bytes: &[u8]) -> Result<LoadedLibrary, SessionError> {
        self.load_library_bytes_opt(name, elf_bytes, true)
    }

    /// Load a 32-bit ELF shared library by name from raw bytes without invoking constructors.
    pub fn load_library_bytes_no_init(&mut self, name: &str, elf_bytes: &[u8]) -> Result<LoadedLibrary, SessionError> {
        self.load_library_bytes_opt(name, elf_bytes, false)
    }

    fn load_library_bytes_opt(&mut self, name: &str, elf_bytes: &[u8], run_init: bool) -> Result<LoadedLibrary, SessionError> {
        let basename = name.rsplit('/').next().unwrap_or(name);
        if let Some(existing) = self
            .loaded_libraries
            .get(name)
            .or_else(|| self.loaded_libraries.get(basename))
        {
            return Ok(existing.clone());
        }

        let load_addr = self.next_load_addr;

        // Specialized NDK bridges precede BionicBridge so dedicated handlers
        // (e.g., AssetBridge for AAssetManager_*) win over fallback stubs.
        let mut composite = CompositeResolver::new();
        composite.add(&self.gles);
        composite.add(&self.audio);
        composite.add(&self.asset);
        composite.add(&self.hardware_buffer);
        composite.add(&self.vulkan);
        composite.add(&self.bionic);

        struct LoadedMapResolver<'a>(&'a HashMap<String, LoadedLibrary>);
        impl<'a> SymbolResolver for LoadedMapResolver<'a> {
            fn resolve(&self, sym: &str) -> Option<GuestAddr> {
                for lib in self.0.values() {
                    if let Some(addr) = lib.find_symbol(sym) {
                        return Some(addr);
                    }
                }
                None
            }
        }
        let map_resolver = LoadedMapResolver(&self.loaded_libraries);
        composite.add(&map_resolver);

        let mut loaded = ElfLoader::load(elf_bytes, load_addr, &mut self.engine.mem, &composite)?;
        if loaded.soname.is_none() {
            loaded.soname = Some(basename.to_string());
        }

        // Align next load address to 64KB boundary
        let size_aligned = ((loaded.total_size + 0xFFFF) / 0x10000) * 0x10000;
        self.next_load_addr = load_addr.add(size_aligned as u32);

        self.loaded_libraries.insert(basename.to_string(), loaded.clone());
        let _ = self.bionic.register_library(loaded.clone());
        self.jni_registry.register_library(&loaded);

        // Automatic AOT translation cache loading & pre-compilation
        if let Some(ref dir) = self.aot_cache_dir {
            let hash = walzer32_rt::calculate_sha256(elf_bytes);
            let cache_filename = format!("{basename}.walzer32_cache");
            let cache_path = dir.join(cache_filename);

            if cache_path.exists() {
                let _ = self.engine.load_aot_cache_file(&cache_path, Some(&hash));
            } else {
                let mut entries = Vec::new();
                if let Some(init) = loaded.init_func {
                    entries.push(init);
                }
                for &init in &loaded.init_array {
                    entries.push(init);
                }
                if loaded.entry_point.as_u32() != 0 {
                    entries.push(loaded.entry_point);
                }
                for &addr in loaded.symbols.values() {
                    entries.push(addr);
                }

                self.engine.precompile_aot(&entries, 5000);
                let _ = self.engine.save_aot_cache_file(&cache_path, hash, [0u8; 20]);
            }
        }

        // Invoke DT_INIT and DT_INIT_ARRAY constructors within mapped module bounds
        let range_start = loaded.load_base.as_u32();
        let range_end = range_start.saturating_add(loaded.total_size as u32);
        let in_module = |addr: GuestAddr| {
            let raw = addr.as_u32() & !1;
            raw != 0 && raw != 0xFFFF_FFFE && raw >= range_start && raw < range_end
        };

        let mut init_fns = Vec::new();
        if let Some(init) = loaded.init_func {
            if in_module(init) {
                init_fns.push(init);
            }
        }
        for &init in &loaded.init_array {
            if in_module(init) {
                init_fns.push(init);
            }
        }

        let onload_opt = loaded.find_symbol("JNI_OnLoad").filter(|&a| in_module(a));
        if run_init && (!init_fns.is_empty() || onload_opt.is_some()) {
            let saved_cpu = self.engine.cpu.clone();
            for ctor in init_fns {
                if let Err(e) = self.call_native(ctor, &[0, 0, 0]) {
                    log_e!("Walzer32: constructor 0x{:08x} in {} error: {:?}", ctor.as_u32(), basename, e);
                }
            }
            if let Some(onload_addr) = onload_opt {
                let vm_ptr = self.jni.vm_ptr.as_u32();
                self.call_native(onload_addr, &[vm_ptr, 0])?;
            }
            self.engine.cpu = saved_cpu;
        }
        let _ = self.flush_pending_jni_registrations();

        Ok(loaded)
    }

    /// Compiles an executable AArch64 JNI thunk for `(class_name, method_name, signature)` -> `guest_fn_ptr`.
    pub fn compile_jni_thunk(
        &mut self,
        class_name: &str,
        method_name: &str,
        signature: &str,
        guest_fn_ptr: GuestAddr,
    ) -> Option<CompiledJniThunk> {
        let key = (
            class_name.to_string(),
            method_name.to_string(),
            signature.to_string(),
        );
        if let Some(existing) = self.compiled_jni_thunks.get(&key) {
            return Some(existing.clone());
        }
        let parsed_sig = JniSignature::parse(signature)?;
        let desc = Box::new(UniversalJniDescriptor {
            class_name: key.0.clone(),
            method_name: key.1.clone(),
            signature: key.2.clone(),
            guest_fn_ptr,
            parsed_sig,
        });
        let descriptor_ptr = desc.as_ref() as *const UniversalJniDescriptor as usize;
        self.jni_descriptors.push(desc);

        let thunk = JniThunkGenerator::generate_ffi_thunk(
            method_name,
            signature,
            guest_fn_ptr,
            descriptor_ptr,
            walzer32_universal_jni_dispatcher as *const () as usize,
        );
        let block = self.jni_thunk_pool.commit_block(&thunk.code_bytes).ok()?;
        let _ = self.jni_thunk_pool.flush_current();

        let compiled = CompiledJniThunk {
            class_name: key.0.clone(),
            method_name: key.1.clone(),
            signature: key.2.clone(),
            guest_fn_ptr,
            host_fn_ptr: block.code_ptr.0 as usize,
            descriptor_ptr,
        };
        self.compiled_jni_thunks.insert(key, compiled.clone());
        Some(compiled)
    }

    /// Compiles pending guest `RegisterNatives` calls into executable AArch64 thunks and
    /// registers them with host ART when `host_jni_env` is bound.
    pub fn flush_pending_jni_registrations(&mut self) -> usize {
        let pending = self.jni.take_pending_registrations();
        if pending.is_empty() {
            return 0;
        }
        let mut by_class: HashMap<String, Vec<(std::ffi::CString, std::ffi::CString, usize)>> =
            HashMap::new();
        let mut total = 0usize;
        for reg in pending {
            if let Some(compiled) = self.compile_jni_thunk(
                &reg.class_name,
                &reg.method.name,
                &reg.method.signature,
                reg.method.fn_ptr,
            ) {
                if let (Ok(c_name), Ok(c_sig)) = (
                    std::ffi::CString::new(reg.method.name.as_str()),
                    std::ffi::CString::new(reg.method.signature.as_str()),
                ) {
                    by_class
                        .entry(reg.class_name)
                        .or_default()
                        .push((c_name, c_sig, compiled.host_fn_ptr));
                }
                total += 1;
            }
        }
        if self.host_jni_env != 0 {
            for (class_name, host_methods) in by_class {
                if !host_methods.is_empty() {
                    let rc = unsafe {
                        register_natives_on_host_env(self.host_jni_env, &class_name, &host_methods)
                    };
                    log_i!(
                        "Walzer32: ART RegisterNatives({}) for {} method(s) -> {}",
                        class_name,
                        host_methods.len(),
                        rc
                    );
                }
            }
        }
        total
    }

    /// Synchronizes fast non-blocking UI/Audio/Telemetry channels with current session state.
    pub fn sync_fast_channels(&self) {
        let fc = fast_channels();
        let ring = if let Some(rt) = &self.active_mt_runtime {
            rt.audio
                .as_ref()
                .and_then(|a| a.lock().ok().map(|guard| Arc::clone(&guard.ring_buffer)))
        } else {
            Some(Arc::clone(&self.audio.ring_buffer))
        };
        if let Some(ring) = ring {
            *fc.audio_ring.lock().unwrap_or_else(|e| e.into_inner()) = Some(ring);
        }
        if !fc.audio_volume_dirty.load(Ordering::Acquire) {
            let vol = if let Some(rt) = &self.active_mt_runtime {
                rt.audio
                    .as_ref()
                    .and_then(|a| a.lock().ok().map(|g| g.volume_millibels()))
                    .unwrap_or_else(|| self.audio.volume_millibels())
            } else {
                self.audio.volume_millibels()
            };
            fc.audio_volume_mb.store(vol, Ordering::Release);
        }
        if !fc.audio_latency_dirty.load(Ordering::Acquire) {
            let lat = if let Some(rt) = &self.active_mt_runtime {
                rt.audio
                    .as_ref()
                    .and_then(|a| a.lock().ok().map(|g| g.target_latency_ms))
                    .unwrap_or(self.audio.target_latency_ms)
            } else {
                self.audio.target_latency_ms
            };
            fc.audio_target_latency_bits.store(lat.to_bits(), Ordering::Release);
        }
        *fc.telemetry_hud.lock().unwrap_or_else(|e| e.into_inner()) = self.get_telemetry_hud();
        *fc.telemetry_json.lock().unwrap_or_else(|e| e.into_inner()) = self.get_telemetry_json();
    }

    /// Drains queued touch, key, resize, and audio settings pushed via `FastSessionChannels`
    /// while `GLOBAL_SESSION` was locked by DBT execution.
    pub fn drain_pending_fast_inputs(&mut self) {
        let fc = fast_channels();
        let touches: Vec<TouchEvent> =
            std::mem::take(&mut *fc.pending_touch.lock().unwrap_or_else(|e| e.into_inner()));
        for ev in touches {
            self.surface.push_touch_event(ev);
        }

        let keys: Vec<KeyEvent> =
            std::mem::take(&mut *fc.pending_key.lock().unwrap_or_else(|e| e.into_inner()));
        for ev in keys {
            self.surface.push_key_event(ev);
        }

        if fc.audio_volume_dirty.swap(false, Ordering::AcqRel) {
            let vol = fc.audio_volume_mb.load(Ordering::Acquire);
            self.set_audio_volume(vol);
        }

        if fc.audio_latency_dirty.swap(false, Ordering::AcqRel) {
            let ms = f32::from_bits(fc.audio_target_latency_bits.load(Ordering::Acquire));
            self.set_target_audio_latency_ms(ms);
        }

        let resize = fc
            .pending_resize
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some((w, h)) = resize {
            self.on_surface_changed(w, h);
        }
    }

    fn promote_to_mt_runtime(&mut self) -> SharedGuestRuntime {
        let futex = self.engine.futex_manager().unwrap_or_default();
        self.engine.set_futex_manager(futex.clone());
        let bionic = std::mem::replace(
            &mut self.bionic,
            BionicBridge::new(GuestAddr::new(0), GuestAddr::new(0), 0),
        );
        let jni = std::mem::replace(&mut self.jni, JniBridge::new(GuestAddr::new(0)));
        let gles = std::mem::replace(
            &mut self.gles,
            GlesBridge::new(GuestAddr::new(0), GuestAddr::new(0)),
        );
        let audio = std::mem::replace(&mut self.audio, AudioBridge::with_stub_base(GuestAddr::new(0)));
        let asset = std::mem::replace(
            &mut self.asset,
            AssetBridge::new(GuestAddr::new(0), GuestAddr::new(0), 0),
        );
        let hw_buffer = std::mem::replace(
            &mut self.hardware_buffer,
            HardwareBufferBridge::new(GuestAddr::new(0), GuestAddr::new(0), 0),
        );
        let vulkan = std::mem::replace(
            &mut self.vulkan,
            VulkanBridge::with_stub_base(GuestAddr::new(0)),
        );

        SharedGuestRuntime::new(bionic, jni, futex)
            .with_gles(Arc::new(Mutex::new(gles)))
            .with_audio(Arc::new(Mutex::new(audio)))
            .with_asset(Arc::new(Mutex::new(asset)))
            .with_hw_buffer(Arc::new(Mutex::new(hw_buffer)))
            .with_vulkan(Arc::new(Mutex::new(vulkan)))
    }

    fn try_reclaim_mt_runtime(&mut self, rt: SharedGuestRuntime) -> Option<SharedGuestRuntime> {
        if rt.active_worker_count() > 0 || Arc::strong_count(&rt.bionic) > 1 {
            return Some(rt);
        }
        let SharedGuestRuntime {
            bionic,
            jni,
            gles,
            audio,
            asset,
            hw_buffer,
            vulkan,
            ..
        } = rt;
        if let Ok(m) = Arc::try_unwrap(bionic) {
            self.bionic = m.into_inner().unwrap_or_else(|e| e.into_inner());
        }
        if let Ok(m) = Arc::try_unwrap(jni) {
            self.jni = m.into_inner().unwrap_or_else(|e| e.into_inner());
        }
        if let Some(m) = gles.and_then(|a| Arc::try_unwrap(a).ok()) {
            self.gles = m.into_inner().unwrap_or_else(|e| e.into_inner());
        }
        if let Some(m) = audio.and_then(|a| Arc::try_unwrap(a).ok()) {
            self.audio = m.into_inner().unwrap_or_else(|e| e.into_inner());
        }
        if let Some(m) = asset.and_then(|a| Arc::try_unwrap(a).ok()) {
            self.asset = m.into_inner().unwrap_or_else(|e| e.into_inner());
        }
        if let Some(m) = hw_buffer.and_then(|a| Arc::try_unwrap(a).ok()) {
            self.hardware_buffer = m.into_inner().unwrap_or_else(|e| e.into_inner());
        }
        if let Some(m) = vulkan.and_then(|a| Arc::try_unwrap(a).ok()) {
            self.vulkan = m.into_inner().unwrap_or_else(|e| e.into_inner());
        }
        None
    }

    fn run_active_mt_loop(&mut self, rt: SharedGuestRuntime) -> Result<u32, SessionError> {
        let res = run_guest_mt_loop(&mut self.engine, &rt, 1);
        if let Some(s) = self.engine.signal_state() {
            if let Ok(mut b) = rt.bionic.lock() {
                b.signal_state = s.clone();
            }
        }
        self.active_mt_runtime = self.try_reclaim_mt_runtime(rt);
        self.sync_fast_channels();
        res.map_err(Into::into)
    }

    /// Call a 32-bit native function by guest address.
    /// Runs on a zero-lock single-thread fast path until the guest spawns a thread
    /// (`pthread_create` / `SYS_clone`), then lazily promotes execution to `SharedJit`
    /// and `SharedGuestRuntime` with real OS worker threads.
    pub fn call_native(&mut self, fn_addr: GuestAddr, args: &[u32]) -> Result<u32, SessionError> {
        let stack_top_u32 = self.main_stack_top.as_u32();
        let stack_bottom_u32 = stack_top_u32.saturating_sub(0x80_0000); // 8 MB stack
        let cur_sp = self.engine.cpu.sp();
        if cur_sp < stack_bottom_u32 || cur_sp > stack_top_u32 {
            self.engine.cpu.set_sp(stack_top_u32 - 0x1000);
        }
        let saved_sp = self.engine.cpu.sp();
        let res = self.call_native_inner(fn_addr, args);
        self.engine.cpu.set_sp(saved_sp);
        res
    }

    fn call_native_inner(&mut self, fn_addr: GuestAddr, args: &[u32]) -> Result<u32, SessionError> {
        if let Some(rt) = self.active_mt_runtime.take() {
            self.active_mt_runtime = self.try_reclaim_mt_runtime(rt);
        }

        if let Some(rt) = self.active_mt_runtime.take() {
            self.engine.enable_shared_jit();
            prepare_guest_call(&mut self.engine, fn_addr, args)?;
            if let Ok(b) = rt.bionic.lock() {
                self.engine.sync_signal_state(&b.signal_state);
            }
            return self.run_active_mt_loop(rt);
        }

        prepare_guest_call(&mut self.engine, fn_addr, args)?;
        self.engine.sync_signal_state(&self.bionic.signal_state);

        #[cfg(test)]
        let mut steps: u64 = 0;

        while (self.engine.cpu.pc().as_u32() & !1) != (SENTINEL_RETURN_ADDR & !1) {
            check_fastmem_fault(&mut self.engine)?;

            let debug_pc = self.engine.cpu.pc().as_u32() & !1;
            if (debug_pc & 0xfffff) == 0x5a710 {
                let sp = self.engine.cpu.reg(walzer32_core::Reg::SP);
                let r2 = self.engine.cpu.reg(walzer32_core::Reg::R2);
                let r3 = self.engine.cpu.reg(walzer32_core::Reg::R3);
                println!("=== DEBUG AT dictionaryWithObjectsAndKeys (pc=0x{:08x}, sp=0x{:08x}) ===", debug_pc, sp);
                println!("  Pair 0: Obj=0x{:08x}, Key=0x{:08x}", r2, r3);
                for i in 0..16 {
                    let obj = self.engine.mem.read_u32(walzer32_core::GuestAddr::new(sp + i * 8)).unwrap_or(0);
                    let key = self.engine.mem.read_u32(walzer32_core::GuestAddr::new(sp + i * 8 + 4)).unwrap_or(0);
                    println!("  Pair {:02}: Obj=0x{:08x}, Key=0x{:08x}", i + 1, obj, key);
                    if obj == 0 || key == 0 {
                        println!("  -> hit 0 at pair index {}", i + 1);
                        break;
                    }
                }
            }

            match self.engine.step()? {
                EngineStepResult::Syscall(_) => {
                    if let Some(imm) = self.engine.last_svc_imm() {
                        dispatch_bridge_svc(
                            imm,
                            &mut self.engine,
                            &mut self.bionic,
                            &mut self.jni,
                            &mut Some(&mut self.gles),
                            &mut Some(&mut self.audio),
                            &mut Some(&mut self.asset),
                            &mut Some(&mut self.hardware_buffer),
                            &mut Some(&mut self.vulkan),
                        )?;
                    }
                    let _ = self.flush_pending_jni_registrations();
                    if let Some(req) = self.bionic.take_pending_dlopen() {
                        let saved_cpu = self.engine.cpu.clone();
                        let handle = match self.load_library_bytes(&req.filename, &req.elf_bytes) {
                            Ok(_) => self
                                .bionic
                                .dso_registry
                                .find_by_soname(&req.filename)
                                .map(|(h, _)| h)
                                .unwrap_or(0),
                            Err(e) => {
                                self.bionic.last_dlerror = Some(format!(
                                    "dlopen failed loading \"{}\": {:?}",
                                    req.filename, e
                                ));
                                0
                            }
                        };
                        self.engine.cpu = saved_cpu;
                        self.engine.cpu.set_reg(Reg::R0, handle);
                    }
                    if !self.bionic.pending_spawns.is_empty()
                        || self.bionic.pending_blocking_op.is_some()
                        || self.engine.has_pending_clone()
                    {
                        self.engine.enable_shared_jit();
                        let rt = self.promote_to_mt_runtime();
                        if let Some(retval) =
                            flush_pending_mt_actions(&mut self.engine, &rt)?
                        {
                            self.active_mt_runtime = self.try_reclaim_mt_runtime(rt);
                            self.sync_fast_channels();
                            return Ok(retval);
                        }
                        return self.run_active_mt_loop(rt);
                    }
                }
                EngineStepResult::Halted { exit_code } => {
                    self.engine.cpu.set_reg(Reg::R0, exit_code);
                    break;
                }
                EngineStepResult::Breakpoint { imm } => {
                    let sp = self.engine.cpu.sp();
                    println!("=== HIT GUEST BREAKPOINT #{} (0x{:02x}) at pc=0x{:08x} ===", imm, imm, self.engine.cpu.pc().as_u32());
                    println!("  r0=0x{:08x} r1=0x{:08x} r2=0x{:08x} r3=0x{:08x}",
                        self.engine.cpu.reg(Reg::R0),
                        self.engine.cpu.reg(Reg::R1),
                        self.engine.cpu.reg(Reg::R2),
                        self.engine.cpu.reg(Reg::R3),
                    );
                    println!("  r4=0x{:08x} r5=0x{:08x} r6=0x{:08x} r7=0x{:08x} sp=0x{:08x} lr=0x{:08x}",
                        self.engine.cpu.reg(Reg::R4),
                        self.engine.cpu.reg(Reg::R5),
                        self.engine.cpu.reg(Reg::R6),
                        self.engine.cpu.reg(Reg::R7),
                        sp,
                        self.engine.cpu.lr(),
                    );
                    if imm == 0x44 || imm == 68 {
                        let count = self.engine.mem.read_u32(GuestAddr::new(sp)).unwrap_or(0);
                        let objs_ptr = self.engine.cpu.reg(Reg::R2);
                        let keys_ptr = self.engine.cpu.reg(Reg::R3);
                        println!("=== BREAKPOINT 44: dictionaryWithObjectsAndKeys count={} objs=0x{:08x} keys=0x{:08x} ===", count, objs_ptr, keys_ptr);
                        for i in 0..count.min(32) {
                            let obj = self.engine.mem.read_u32(GuestAddr::new(objs_ptr + i * 4)).unwrap_or(0);
                            let key = self.engine.mem.read_u32(GuestAddr::new(keys_ptr + i * 4)).unwrap_or(0);
                            let mut key_str = String::new();
                            let chars_ptr = self.engine.mem.read_u32(GuestAddr::new(key + 4)).unwrap_or(0);
                            for off in 0..32 {
                                if let Ok(b) = self.engine.mem.read_u8(GuestAddr::new(chars_ptr + off)) {
                                    if b == 0 { break; }
                                    key_str.push(b as char);
                                }
                            }
                            let isa = if obj >= 0x1000 {
                                self.engine.mem.read_u32(GuestAddr::new(obj)).unwrap_or(0)
                            } else {
                                0
                            };
                            println!("  Pair[{:02}]: obj=0x{:08x} (isa=0x{:08x}), key=0x{:08x} (\"{}\")", i, obj, isa, key, key_str);
                        }
                        println!("=== CALLER STACK AT SP=0x{:08x} (sp+0x240..0x2c0) ===", sp);
                        for off in (0x240..=0x2c0).step_by(4) {
                            let val = self.engine.mem.read_u32(GuestAddr::new(sp + off)).unwrap_or(0);
                            println!("  [sp+0x{:03x}] (0x{:08x}) = 0x{:08x}", off, sp + off, val);
                        }
                    } else if imm == 0x45 || imm == 69 {
                        println!("=== BREAKPOINT 45: after initWithObjects:count: returned r0=0x{:08x} ===", self.engine.cpu.reg(Reg::R0));
                    } else if imm == 0x46 || imm == 70 {
                        let sp = self.engine.cpu.sp();
                        println!("=== BREAKPOINT 46: BEFORE arrayWithObjects: at _unlocalizedDefaults ===");
                        println!("  receiver (r0): 0x{:08x}", self.engine.cpu.reg(Reg::R0));
                        println!("  selector (r1): 0x{:08x}", self.engine.cpu.reg(Reg::R1));
                        println!("  arg1 (r2): 0x{:08x}", self.engine.cpu.reg(Reg::R2));
                        println!("  arg2 (r3): 0x{:08x}", self.engine.cpu.reg(Reg::R3));
                        println!("  target (r5): 0x{:08x}", self.engine.cpu.reg(Reg::R5));
                        for i in 0..6 {
                            let val = self.engine.mem.read_u32(GuestAddr::new(sp + i * 4)).unwrap_or(0);
                            println!("  stack[sp+0x{:02x}]: 0x{:08x}", i * 4, val);
                        }
                    } else if imm == 0x47 || imm == 71 {
                        println!("=== BREAKPOINT 47: AFTER arrayWithObjects: at _unlocalizedDefaults ===");
                        println!("  r0: 0x{:08x}", self.engine.cpu.reg(Reg::R0));
                        println!("  r1: 0x{:08x}", self.engine.cpu.reg(Reg::R1));
                        println!("  r2: 0x{:08x}", self.engine.cpu.reg(Reg::R2));
                        println!("  r3: 0x{:08x}", self.engine.cpu.reg(Reg::R3));
                        println!("  r4: 0x{:08x}", self.engine.cpu.reg(Reg::R4));
                        println!("  r5: 0x{:08x}", self.engine.cpu.reg(Reg::R5));
                        println!("  r6: 0x{:08x}", self.engine.cpu.reg(Reg::R6));
                        println!("  sp: 0x{:08x}", self.engine.cpu.sp());
                        println!("  lr: 0x{:08x}", self.engine.cpu.lr());
                    } else if imm == 0x48 || imm == 72 {
                        let sp = self.engine.cpu.sp();
                        println!("=== BREAKPOINT 48: at 0x1e87aa (loading [sp, #0x78]) ===");
                        println!("  sp: 0x{:08x}", sp);
                        for offset in (0x50..=0x90).step_by(4) {
                            let val = self.engine.mem.read_u32(GuestAddr::new(sp + offset)).unwrap_or(0);
                            println!("  [sp+0x{:02x}] (0x{:08x}) = 0x{:08x}", offset, sp + offset, val);
                        }
                    } else {
                        println!("=== STACK DUMP AT SP=0x{:08x} ===", sp);
                        for i in 0..30 {
                            let addr = GuestAddr::new(sp + i * 4);
                            let val = self.engine.mem.read_u32(addr).unwrap_or(0);
                            println!("  [sp+0x{:02x}] (0x{:08x}) = 0x{:08x}", i * 4, addr.as_u32(), val);
                        }
                    }
                    return Err(SessionError::Engine(walzer32_rt::EngineError::Trap(format!(
                        "Hit guest breakpoint imm={} at pc=0x{:08x} r0=0x{:08x} r1=0x{:08x} r2=0x{:08x} r3=0x{:08x} r4=0x{:08x} r5=0x{:08x} r6=0x{:08x} r7=0x{:08x} sp=0x{:08x} lr=0x{:08x}",
                        imm,
                        self.engine.cpu.pc().as_u32(),
                        self.engine.cpu.reg(Reg::R0),
                        self.engine.cpu.reg(Reg::R1),
                        self.engine.cpu.reg(Reg::R2),
                        self.engine.cpu.reg(Reg::R3),
                        self.engine.cpu.reg(Reg::R4),
                        self.engine.cpu.reg(Reg::R5),
                        self.engine.cpu.reg(Reg::R6),
                        self.engine.cpu.reg(Reg::R7),
                        self.engine.cpu.sp(),
                        self.engine.cpu.lr(),
                    ))));
                }
                EngineStepResult::Continue => {}
            }

            #[cfg(test)]
            {
                steps += 1;
                if steps > 10_000_000 {
                    return Err(SessionError::Engine(walzer32_rt::EngineError::Trap(
                        "Guest execution limit exceeded in test".into(),
                    )));
                }
            }
        }

        if let Some(s) = self.engine.signal_state() {
            self.bionic.signal_state = s.clone();
        }
        let res = self.engine.cpu.reg(Reg::R0);
        self.sync_fast_channels();
        Ok(res)
    }

    /// Pumps queued OpenSL ES buffer callbacks while host hardware playback drains the ring buffer.
    pub fn pump_audio_callbacks(&mut self) {
        if self.audio.play_state != SL_PLAYSTATE_PLAYING || !self.audio.has_callback() {
            return;
        }
        let mut fired = 0;
        while fired < 4 && self.audio.queued_count() > 0 && self.audio.available_frames() < 2048 {
            if self.audio.consume_next_buffer().is_some() {
                let cb = self.audio.callback_fn;
                let bq_itf = self.audio.stub_base.add(0x1200).as_u32();
                let ctx = self.audio.callback_context.as_u32();
                if self.call_native(cb, &[bq_itf, ctx]).is_err() {
                    break;
                }
                fired += 1;
            } else {
                break;
            }
        }
    }

    /// Mounts an Android main OBB expansion pack into the guest VFS
    pub fn mount_obb(&mut self, package_name: &str, version: u32, obb_bytes: Vec<u8>) {
        let arc = std::sync::Arc::new(obb_bytes);
        self.bionic.vfs.mount_obb_arc(package_name, version, std::sync::Arc::clone(&arc));
        if let Some(vfs) = self.engine.vfs_mut() {
            vfs.mount_obb_arc(package_name, version, arc);
        }
    }

    /// Mounts an Android patch OBB expansion pack into the guest VFS
    pub fn mount_patch_obb(&mut self, package_name: &str, version: u32, obb_bytes: Vec<u8>) {
        let arc = std::sync::Arc::new(obb_bytes);
        self.bionic.vfs.mount_patch_obb_arc(package_name, version, std::sync::Arc::clone(&arc));
        if let Some(vfs) = self.engine.vfs_mut() {
            vfs.mount_patch_obb_arc(package_name, version, arc);
        }
    }

    /// Mounts a package's private app data directory in VFS (/data/data/{package_name}/)
    pub fn mount_app_data_dir(&mut self, package_name: &str) {
        self.bionic.vfs.mount_app_data_dir(package_name);
        if let Some(vfs) = self.engine.vfs_mut() {
            vfs.mount_app_data_dir(package_name);
        }
    }

    /// Reads host stereo PCM frames (48 kHz) from the lock-free audio ring buffer.
    /// `out` format: [L0, R0, L1, R1, ...]
    /// Returns the number of frames read (frames = samples / 2).
    pub fn read_audio_frames(&mut self, out: &mut [i16]) -> usize {
        let frames = self.audio.read_host_frames(out);
        if let Some(_completed) = self.audio.consume_next_buffer() {
            if self.audio.has_callback() {
                let cb = self.audio.callback_fn;
                let bq_itf = self.audio.stub_base.add(0x1200).as_u32();
                let ctx = self.audio.callback_context.as_u32();
                let _ = self.call_native(cb, &[bq_itf, ctx]);
            }
        }
        frames
    }

    /// Sets audio playback volume in millibels (-9600 to 0 mB)
    pub fn set_audio_volume(&mut self, millibels: i32) {
        if let Some(rt) = &self.active_mt_runtime {
            if let Some(a) = &rt.audio {
                if let Ok(mut guard) = a.lock() {
                    guard.set_volume_millibels(millibels);
                }
            }
        } else {
            self.audio.set_volume_millibels(millibels);
        }
        fast_channels()
            .audio_volume_mb
            .store(millibels.clamp(-9600, 1000), Ordering::Release);
        fast_channels().audio_volume_dirty.store(false, Ordering::Release);
    }

    /// Returns total number of audio underruns encountered
    pub fn get_audio_underruns(&self) -> u64 {
        self.audio.underrun_count()
    }

    /// Returns total number of audio overruns encountered
    pub fn get_audio_overruns(&self) -> u64 {
        self.audio.overrun_count()
    }

    /// Returns current audio playback latency in milliseconds at 48kHz stereo
    pub fn get_audio_latency_ms(&self) -> f32 {
        self.audio.current_latency_ms()
    }

    /// Sets target audio latency in milliseconds
    pub fn set_target_audio_latency_ms(&mut self, ms: f32) {
        if let Some(rt) = &self.active_mt_runtime {
            if let Some(a) = &rt.audio {
                if let Ok(mut guard) = a.lock() {
                    guard.set_target_latency_ms(ms);
                }
            }
        } else {
            self.audio.set_target_latency_ms(ms);
        }
        fast_channels()
            .audio_target_latency_bits
            .store(ms.clamp(1.0, 100.0).to_bits(), Ordering::Release);
        fast_channels().audio_latency_dirty.store(false, Ordering::Release);
    }

    /// Returns audio ring buffer fill ratio [0.0 .. 1.0]
    pub fn get_audio_watermark_ratio(&self) -> f32 {
        self.audio.buffer_watermark_ratio()
    }

    /// Sets directory for reading and writing persistent AOT translation caches
    pub fn set_aot_cache_dir(&mut self, dir: impl Into<std::path::PathBuf>) {
        self.aot_cache_dir = Some(dir.into());
    }

    /// Pre-compiles all reachable basic blocks and hot superblocks for a loaded library
    pub fn precompile_library(&mut self, name: &str, max_blocks: usize) -> usize {
        if let Some(loaded) = self.loaded_libraries.get(name) {
            let mut entries = Vec::new();
            if let Some(init) = loaded.init_func {
                entries.push(init);
            }
            for &init in &loaded.init_array {
                entries.push(init);
            }
            if loaded.entry_point.as_u32() != 0 {
                entries.push(loaded.entry_point);
            }
            for &addr in loaded.symbols.values() {
                entries.push(addr);
            }
            self.engine.precompile_aot(&entries, max_blocks)
        } else {
            0
        }
    }

    /// Exports AOT disk cache for current session state
    pub fn export_aot_cache(&self, binary_hash: [u8; 32], build_id: [u8; 20]) -> walzer32_rt::AotDiskCache {
        self.engine.export_aot_cache(binary_hash, build_id)
    }

    /// Imports an AOT disk cache into session
    pub fn import_aot_cache(&mut self, cache: &walzer32_rt::AotDiskCache) -> Result<usize, walzer32_rt::AotCacheError> {
        self.engine.import_aot_cache(cache)
    }

    /// Get list of native methods registered via JNI env->RegisterNatives
    pub fn registered_natives(&self) -> &[RegisteredNativeMethod] {
        &self.jni.registered_natives
    }

    /// Searches all loaded 32-bit ELF libraries for an exported guest symbol
    pub fn find_loaded_symbol(&self, name: &str) -> Option<GuestAddr> {
        for lib in self.loaded_libraries.values() {
            if let Some(addr) = lib.find_symbol(name) {
                return Some(addr);
            }
        }
        None
    }

    /// Allocates guest memory via Bionic heap/mmap and writes raw bytes
    pub fn alloc_guest_bytes(&mut self, bytes: &[u8]) -> Result<u32, SessionError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let ptr = self
            .bionic
            .alloc_guest_memory(bytes.len() as u32, 8, &mut self.engine.mem);
        if ptr.as_u32() != 0 {
            self.engine.mem.write_bytes(ptr, bytes)?;
        }
        Ok(ptr.as_u32())
    }

    /// Invokes a slot in guest ANativeActivityCallbacks32 if registered
    pub fn invoke_native_activity_callback(
        &mut self,
        slot_index: usize,
        extra_arg: Option<u32>,
    ) -> Result<bool, SessionError> {
        if self.guest_native_activity_ptr == 0 || self.guest_native_callbacks_ptr == 0 {
            return Ok(false);
        }
        let slot_addr = GuestAddr::new(self.guest_native_callbacks_ptr).add((slot_index * 4) as u32);
        let fn_ptr = self.engine.mem.read_u32(slot_addr)?;
        if fn_ptr == 0 {
            return Ok(false);
        }
        match extra_arg {
            Some(arg) => {
                let _ = self.call_native(GuestAddr::new(fn_ptr), &[self.guest_native_activity_ptr, arg])?;
            }
            None => {
                let _ = self.call_native(GuestAddr::new(fn_ptr), &[self.guest_native_activity_ptr])?;
            }
        }
        Ok(true)
    }

    /// Invokes guest ANativeActivityCallbacks32::onSaveInstanceState (slot 2) and reads saved bytes.
    pub fn invoke_native_activity_save_state(&mut self) -> Result<Option<Vec<u8>>, SessionError> {
        if self.guest_native_activity_ptr == 0 || self.guest_native_callbacks_ptr == 0 {
            return Ok(None);
        }
        let slot_addr = GuestAddr::new(self.guest_native_callbacks_ptr).add(2 * 4);
        let fn_ptr = self.engine.mem.read_u32(slot_addr)?;
        if fn_ptr == 0 {
            return Ok(None);
        }
        let out_size_ptr = self.alloc_guest_bytes(&[0u8; 4])?;
        if out_size_ptr == 0 {
            return Ok(None);
        }
        let data_ptr = self.call_native(
            GuestAddr::new(fn_ptr),
            &[self.guest_native_activity_ptr, out_size_ptr],
        )?;
        let out_size = self.engine.mem.read_u32(GuestAddr::new(out_size_ptr))?;
        if data_ptr == 0 || out_size == 0 || out_size > 16 * 1024 * 1024 {
            return Ok(None);
        }
        let mut buf = vec![0u8; out_size as usize];
        self.engine.mem.read_bytes(GuestAddr::new(data_ptr), &mut buf)?;
        Ok(Some(buf))
    }

    /// Invokes guest ANativeActivityCallbacks32::onContentRectChanged (slot 13) with a marshaled 32-bit ARect.
    pub fn invoke_native_activity_content_rect(
        &mut self,
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    ) -> Result<bool, SessionError> {
        if self.guest_native_activity_ptr == 0 || self.guest_native_callbacks_ptr == 0 {
            return Ok(false);
        }
        let mut rect_bytes = Vec::with_capacity(16);
        rect_bytes.extend_from_slice(&left.to_le_bytes());
        rect_bytes.extend_from_slice(&top.to_le_bytes());
        rect_bytes.extend_from_slice(&right.to_le_bytes());
        rect_bytes.extend_from_slice(&bottom.to_le_bytes());
        let rect_guest = self.alloc_guest_bytes(&rect_bytes)?;
        if rect_guest == 0 {
            return Ok(false);
        }
        self.invoke_native_activity_callback(13, Some(rect_guest))
    }

    /// Marshals a 32-bit ANativeActivity struct and executes guest ANativeActivity_onCreate
    pub fn setup_native_activity32(
        &mut self,
        internal_path: &str,
        external_path: &str,
        obb_path: &str,
        sdk_version: i32,
        saved_state: &[u8],
    ) -> Result<bool, SessionError> {
        let Some(on_create_addr) = self.find_loaded_symbol("ANativeActivity_onCreate") else {
            return Ok(false);
        };

        let callbacks_ptr = self
            .bionic
            .alloc_guest_memory(64, 8, &mut self.engine.mem);
        self.engine.mem.write_bytes(callbacks_ptr, &[0u8; 64])?;

        let activity_ptr = self
            .bionic
            .alloc_guest_memory(40, 8, &mut self.engine.mem);
        self.engine.mem.write_bytes(activity_ptr, &[0u8; 40])?;

        let mut internal_c = internal_path.as_bytes().to_vec();
        internal_c.push(0);
        let internal_guest = self.alloc_guest_bytes(&internal_c)?;

        let mut external_c = external_path.as_bytes().to_vec();
        external_c.push(0);
        let external_guest = self.alloc_guest_bytes(&external_c)?;

        let mut obb_c = obb_path.as_bytes().to_vec();
        obb_c.push(0);
        let obb_guest = self.alloc_guest_bytes(&obb_c)?;

        // Match NDK 32-bit ANativeActivity struct layout
        self.engine.mem.write_u32(activity_ptr, callbacks_ptr.as_u32())?;
        self.engine.mem.write_u32(activity_ptr.add(4), self.jni.vm_ptr.as_u32())?;
        self.engine.mem.write_u32(activity_ptr.add(8), self.jni.env_ptr.as_u32())?;
        self.engine.mem.write_u32(activity_ptr.add(12), 0x3000_0002)?; // clazz/activity jobject
        self.engine.mem.write_u32(activity_ptr.add(16), internal_guest)?;
        self.engine.mem.write_u32(activity_ptr.add(20), external_guest)?;
        self.engine.mem.write_u32(activity_ptr.add(24), sdk_version as u32)?;
        self.engine.mem.write_u32(activity_ptr.add(28), 0)?; // instance
        self.engine.mem.write_u32(activity_ptr.add(32), 0xA55E_0001)?; // AAssetManager*
        self.engine.mem.write_u32(activity_ptr.add(36), obb_guest)?;

        let saved_state_guest = if saved_state.is_empty() {
            0
        } else {
            self.alloc_guest_bytes(saved_state)?
        };

        self.guest_native_activity_ptr = activity_ptr.as_u32();
        self.guest_native_callbacks_ptr = callbacks_ptr.as_u32();

        let _ = self.call_native(
            on_create_addr,
            &[activity_ptr.as_u32(), saved_state_guest, saved_state.len() as u32],
        )?;
        Ok(true)
    }

    fn release_host_window(&mut self) {
        #[cfg(target_os = "android")]
        if self.owns_host_window && self.gles.host_window_ptr != 0 {
            if let Some(fp) = self.gles.resolve_host_symbol("ANativeWindow_release") {
                let release_fn: unsafe extern "C" fn(*mut std::ffi::c_void) =
                    unsafe { std::mem::transmute(fp) };
                unsafe { release_fn(self.gles.host_window_ptr as *mut std::ffi::c_void) };
            }
        }
        self.owns_host_window = false;
        self.gles.host_window_ptr = 0;
        self.vulkan.host_window_ptr = 0;
    }

    /// Handles SurfaceCreated lifecycle event from Android UI thread
    pub fn on_surface_created(&mut self, window_ptr: usize, width: u32, height: u32) {
        if self.gles.host_window_ptr != 0 && self.gles.host_window_ptr != window_ptr {
            self.release_host_window();
        }
        self.gles.host_window_ptr = window_ptr;
        self.vulkan.host_window_ptr = window_ptr;
        self.bionic.surface_width = width;
        self.bionic.surface_height = height;
        self.surface.on_surface_created(window_ptr, width, height);

        if self.surface.draw_frame_fn.is_none() {
            if let Some(draw_fn) = self.find_loaded_symbol("walzer32_guest_draw_frame") {
                self.surface.register_draw_frame_fn(draw_fn);
            }
        }
        if let Some(init_fn) = self.find_loaded_symbol("walzer32_guest_surface_created") {
            let guest_win = 0x3100_0001u32;
            match self.call_native(init_fn, &[guest_win, width, height]) {
                Ok(ret) => log_i!("Walzer32: walzer32_guest_surface_created({}, {}, {}) -> {}", guest_win, width, height, ret as i32),
                Err(e) => log_e!("Walzer32: walzer32_guest_surface_created failed: {:?}", e),
            }
        }
    }

    /// Handles SurfaceChanged viewport dimension update
    pub fn on_surface_changed(&mut self, width: u32, height: u32) {
        self.bionic.surface_width = width;
        self.bionic.surface_height = height;
        self.surface.on_surface_changed(width, height);
        if let Some(changed_fn) = self.find_loaded_symbol("walzer32_guest_surface_changed") {
            if let Err(e) = self.call_native(changed_fn, &[width, height]) {
                log_e!("Walzer32: walzer32_guest_surface_changed failed: {:?}", e);
            }
        }
    }

    /// Handles SurfaceDestroyed event
    pub fn on_surface_destroyed(&mut self) {
        if let Some(destroyed_fn) = self.find_loaded_symbol("walzer32_guest_surface_destroyed") {
            if let Err(e) = self.call_native(destroyed_fn, &[]) {
                log_e!("Walzer32: walzer32_guest_surface_destroyed failed: {:?}", e);
            }
        }
        self.release_host_window();
        self.surface.on_surface_destroyed();
    }

    /// Triggers frame render in guest DBT if a render callback is registered
    /// Triggers frame render in guest DBT
    pub fn on_draw_frame(&mut self) -> Result<(), SessionError> {
        self.drain_pending_fast_inputs();
        self.engine.telemetry.record_frame(16.6);
        if let Some(render_fn) = self.surface.draw_frame_fn {
            let _ = self.call_native(render_fn, &[])?;
        }
        self.pump_audio_callbacks();
        self.sync_fast_channels();
        Ok(())
    }

    /// Returns the ASCII telemetry HUD overlay from the DBT engine
    pub fn get_telemetry_hud(&self) -> String {
        self.engine.render_telemetry_hud()
    }

    /// Returns structured telemetry metrics in JSON format
    pub fn get_telemetry_json(&self) -> String {
        self.engine.telemetry.render_json()
    }

    /// Generates a comprehensive Android Tombstone crash dump from current session state
    pub fn generate_tombstone(
        &self,
        signal: walzer32_rt::tombstone::TombstoneSignal,
        abort_message: Option<&str>,
    ) -> walzer32_rt::tombstone::TombstoneReport {
        let mut libs = Vec::new();
        for (name, lib) in &self.loaded_libraries {
            let mut info = walzer32_rt::tombstone::LibraryInfo::new(name, lib.load_base, lib.total_size);
            for (sym, &addr) in &lib.symbols {
                info.add_symbol(sym, addr);
            }
            libs.push(info);
        }
        self.engine.capture_tombstone(signal, &libs, "main", 1000, 1000, abort_message)
    }

    /// Forwards touch input event into guest touch queue
    pub fn on_touch_event(&mut self, action: u32, x: f32, y: f32, pointer_id: u32) {
        self.surface.push_touch_event(TouchEvent {
            action,
            x,
            y,
            pointer_id,
        });
    }

    /// Forwards key input event into guest key queue
    pub fn on_key_event(&mut self, action: u32, key_code: u32) {
        self.surface.push_key_event(KeyEvent {
            action,
            key_code,
        });
    }

    /// Enables multi-core background asynchronous JIT compilation for zero-jank execution
    pub fn enable_async_jit(&mut self, worker_threads: usize) {
        let threads = if worker_threads == 0 {
            std::thread::available_parallelism().map(|p| p.get()).unwrap_or(2).min(4)
        } else {
            worker_threads
        };
        self.engine.enable_async_jit(walzer32_rt::AsyncJitConfig {
            worker_threads: threads,
            ..Default::default()
        });
    }

    /// Disables background asynchronous JIT compilation
    pub fn disable_async_jit(&mut self) {
        self.engine.disable_async_jit();
    }

    /// Flushes pending background JIT compilations
    pub fn flush_async_jit(&mut self, timeout: std::time::Duration) -> usize {
        self.engine.flush_async_jit(timeout)
    }

    /// Returns background JIT statistics if active
    pub fn async_jit_stats(&self) -> Option<walzer32_rt::AsyncJitStats> {
        self.engine.async_jit_stats()
    }

    /// Returns the value of an Android system property if present
    pub fn get_system_property(&self, name: &str) -> Option<String> {
        self.bionic.properties.get(name).map(|s| s.to_string())
    }

    /// Sets or overrides an Android system property and synchronizes /system/build.prop
    pub fn set_system_property(&mut self, name: &str, value: &str) {
        self.bionic.properties.set(name, value);
        let build_prop = self.bionic.properties.to_build_prop();
        self.register_vfs_file("/system/build.prop", build_prop.into_bytes());
    }

    /// Automatically detects if running inside a repackaged Android APK and loads bundled guest libraries
    pub fn ensure_bundled_apk_loaded(&mut self) -> Result<usize, SessionError> {
        if !self.loaded_libraries.is_empty() {
            return Ok(self.loaded_libraries.len());
        }

        let apk_path = match find_self_apk_path() {
            Some(p) => p,
            None => {
                log_i!("Walzer32: No self APK found in /proc/self/maps");
                return Ok(0);
            }
        };

        log_i!("Walzer32: Auto-discovered own APK at: {}", apk_path);

        let apk_bytes = match std::fs::read(&apk_path) {
            Ok(bytes) => bytes,
            Err(e) => {
                log_e!("Walzer32: Failed to read {}: {:?}", apk_path, e);
                return Ok(0);
            }
        };

        self.attach_apk(apk_bytes.clone());

        let apk = match ApkPackage::open(&apk_bytes) {
            Ok(a) => a,
            Err(e) => {
                log_e!("Walzer32: Failed to parse APK {}: {:?}", apk_path, e);
                return Ok(0);
            }
        };

        let mut primary_lib = None;
        if let Ok(config_bytes) = apk.archive().read_file("assets/walzer32_config.prop") {
            if let Ok(config_str) = std::str::from_utf8(&config_bytes) {
                for line in config_str.lines() {
                    let line = line.trim();
                    if let Some(val) = line.strip_prefix("walzer32.guest.primary_lib=") {
                        primary_lib = Some(val.to_string());
                    }
                }
            }
        }

        let arm32_libs = apk.arm32_libraries();
        if arm32_libs.is_empty() {
            log_i!("Walzer32: No 32-bit ARM libraries found in APK!");
            return Ok(0);
        }

        let mut extracted: Vec<(String, Vec<u8>, Vec<String>)> = Vec::with_capacity(arm32_libs.len());
        for lib in &arm32_libs {
            match apk.extract_library(&lib.filename) {
                Ok(data) => {
                    let needed = ElfParser::parse(&data)
                        .map(|p| p.needed_libraries())
                        .unwrap_or_default();
                    extracted.push((lib.filename.clone(), data, needed));
                }
                Err(e) => {
                    log_e!("Walzer32: Failed to extract {}: {:?}", lib.filename, e);
                }
            }
        }

        let lib_names: Vec<String> = extracted.iter().map(|(n, _, _)| n.clone()).collect();
        let topo_order = topological_sort_libs(
            &lib_names,
            |idx| extracted[idx].2.clone(),
            primary_lib.as_deref(),
        );

        let total_count = topo_order.len();
        log_i!(
            "Walzer32: Topologically loading {} bundled 32-bit libraries (primary: {:?})...",
            total_count,
            primary_lib
        );

        for idx in topo_order {
            let (ref filename, ref lib_data, ref needed) = extracted[idx];
            log_i!(
                "Walzer32: Loading {} ({} bytes, DT_NEEDED={:?})...",
                filename,
                lib_data.len(),
                needed
            );
            match self.load_library_bytes(filename, lib_data) {
                Ok(loaded) => {
                    log_i!(
                        "Walzer32: Successfully loaded {} at 0x{:08x} ({} symbols)",
                        filename,
                        loaded.load_base.as_u32(),
                        loaded.symbols.len()
                    );
                }
                Err(e) => {
                    log_e!("Walzer32: Failed to load {}: {:?}", filename, e);
                }
            }
        }

        log_i!(
            "Walzer32: Finished loading {} libraries. Total registered JNI methods: {}",
            self.loaded_libraries.len(),
            self.jni_registry.method_count()
        );

        Ok(self.loaded_libraries.len())
    }
}

pub fn find_self_apk_path() -> Option<String> {
    let pkg = std::fs::read_to_string("/proc/self/cmdline")
        .ok()
        .map(|s| s.trim_matches('\0').trim().to_string());

    let mut fallback = None;
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        for line in maps.lines() {
            if line.contains("base.apk") {
                if let Some(pos) = line.find('/') {
                    let path = line[pos..].trim();
                    if std::path::Path::new(path).exists() {
                        if let Some(ref p) = pkg {
                            if path.contains(p) {
                                return Some(path.to_string());
                            }
                        }
                        if fallback.is_none() {
                            fallback = Some(path.to_string());
                        }
                    }
                }
            }
        }
    }
    fallback
}


// Global static session protected by Mutex for JNI C ABI entry points
static GLOBAL_SESSION: Mutex<Option<Walzer32Session>> = Mutex::new(None);

fn create_default_session() -> Result<Walzer32Session, SessionError> {
    // Default 128MB arena starting at 0x7000_0000
    let mut session = Walzer32Session::new(GuestAddr::new(0x7000_0000), 0x800_0000)?;
    let _ = session.ensure_bundled_apk_loaded();
    session.sync_fast_channels();
    Ok(session)
}

pub fn get_or_init_session() -> Result<std::sync::MutexGuard<'static, Option<Walzer32Session>>, SessionError> {
    let mut guard = GLOBAL_SESSION.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(create_default_session()?);
    }
    Ok(guard)
}

/// Non-blocking attempt to acquire `GLOBAL_SESSION` (initializing it if currently `None`).
/// Returns `None` immediately when DBT execution or another thread holds `GLOBAL_SESSION`.
pub fn try_get_or_init_session(
) -> Option<Result<std::sync::MutexGuard<'static, Option<Walzer32Session>>, SessionError>> {
    let mut guard = GLOBAL_SESSION.try_lock().ok()?;
    if guard.is_none() {
        match create_default_session() {
            Ok(session) => *guard = Some(session),
            Err(e) => return Some(Err(e)),
        }
    }
    Some(Ok(guard))
}

pub fn reset_session() {
    let mut guard = GLOBAL_SESSION.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
    fast_channels().clear();
}

impl Drop for Walzer32Session {
    fn drop(&mut self) {
        if let Some(rt) = self.active_mt_runtime.take() {
            rt.join_all_workers();
        }
        self.release_host_window();
    }
}
