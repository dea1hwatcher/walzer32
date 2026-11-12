use std::collections::HashMap;
use std::sync::Mutex;
use thiserror::Error;
use walzer32_apk::{ApkError, ApkPackage};
use walzer32_bridge::{
    invoke_guest_all, invoke_jni_onload, AssetBridge, AudioBridge, BionicBridge, GlesBridge,
    HardwareBufferBridge, JniBridge, KeyEvent, RegisteredNativeMethod, SurfaceBridge, TouchEvent,
    VulkanBridge, SL_PLAYSTATE_PLAYING,
};
use walzer32_core::{GuestAddr, Memory};
#[cfg(not(target_os = "android"))]
use walzer32_core::FlatMemory;
#[cfg(target_os = "android")]
use walzer32_core::ArenaMemory;

// Memory type alias: ArenaMemory on Android (4GB zero-overhead arena),
// FlatMemory on dev-host (Windows/Linux x86-64).
#[cfg(target_os = "android")]
type SessionMemory = ArenaMemory;
#[cfg(not(target_os = "android"))]
type SessionMemory = FlatMemory;
use walzer32_elf::{CompositeResolver, ElfLoader, LoadedLibrary, LoaderError, SymbolResolver};
use walzer32_rt::DbtEngine;

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
    pub initialized: bool,
}

impl Walzer32Session {
    /// Initialize a new DBT session with a guest address space arena.
    ///
    /// On Android: `arena_base` is the fixed layout base (0x7000_0000); ArenaMemory
    /// reserves 4 GB and commits individual sections as needed.
    /// On dev-host (Windows/Linux x86-64): FlatMemory with explicit base + size is used.
    pub fn new(arena_base: GuestAddr, arena_size: usize) -> Result<Self, SessionError> {
        // ── Memory allocation ────────────────────────────────────────────────
        #[cfg(target_os = "android")]
        let mut mem = ArenaMemory::new()?;

        #[cfg(not(target_os = "android"))]
        let mut mem = FlatMemory::new(arena_base, arena_size);

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
        let stack_top = arena_base.add(0xB00_000);
        let mmap_base = arena_base.add(0xC00_000);
        let lib_load_base = arena_base.add(0x100_0000);

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
            mem.commit_range(arena_base.add(0xA00_000), 0x200_000)?; // Stack region
            mem.commit_range(mmap_base,    0x400_000)?;   // mmap dynamic heap
        }

        // Suppress unused-variable warning on targets where arena_size is not used directly
        let _ = arena_size;
        #[cfg(not(target_os = "android"))]
        let _ = gles_heap;

        let bionic = BionicBridge::new(bionic_stubs, bionic_heap, 0x400_000);
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
        engine.set_mmap_base(mmap_base);
        engine.sync_signal_state(&bionic.signal_state);

        Ok(Self {
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
            initialized: true,
        })
    }

    /// Attach an APK package by raw bytes
    pub fn attach_apk(&mut self, apk_bytes: Vec<u8>) {
        let _ = self.asset.load_apk(&apk_bytes);
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

    /// Load a 32-bit ELF shared library by name from raw bytes
    pub fn load_library_bytes(&mut self, name: &str, elf_bytes: &[u8]) -> Result<LoadedLibrary, SessionError> {
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

        let loaded = ElfLoader::load(elf_bytes, load_addr, &mut self.engine.mem, &composite)?;

        // Align next load address to 64KB boundary
        let size_aligned = ((loaded.total_size + 0xFFFF) / 0x10000) * 0x10000;
        self.next_load_addr = load_addr.add(size_aligned as u32);

        self.loaded_libraries.insert(name.to_string(), loaded.clone());
        let _ = self.bionic.register_library(loaded.clone());
        self.jni_registry.register_library(&loaded);

        // Automatic AOT translation cache loading & pre-compilation
        if let Some(ref dir) = self.aot_cache_dir {
            let hash = walzer32_rt::calculate_sha256(elf_bytes);
            let cache_filename = format!("{name}.walzer32_cache");
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

        // Call JNI_OnLoad if present
        if let Some(onload_addr) = loaded.find_symbol("JNI_OnLoad") {
            let _ = invoke_jni_onload(
                &mut self.engine,
                &mut self.bionic,
                &mut self.jni,
                onload_addr,
            )?;
        }

        Ok(loaded)
    }

    /// Call a 32-bit native function by guest address
    pub fn call_native(&mut self, fn_addr: GuestAddr, args: &[u32]) -> Result<u32, SessionError> {
        let res = invoke_guest_all(
            &mut self.engine,
            &mut self.bionic,
            &mut self.jni,
            Some(&mut self.gles),
            Some(&mut self.audio),
            Some(&mut self.asset),
            Some(&mut self.hardware_buffer),
            Some(&mut self.vulkan),
            fn_addr,
            args,
        )?;
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
        self.audio.set_volume_millibels(millibels);
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
        self.audio.set_target_latency_ms(ms);
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
    pub fn on_draw_frame(&mut self) -> Result<(), SessionError> {
        self.engine.telemetry.record_frame(16.6);
        if let Some(render_fn) = self.surface.draw_frame_fn {
            let _ = self.call_native(render_fn, &[])?;
        }
        self.pump_audio_callbacks();
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

        let mut arm32_libs = apk.arm32_libraries();
        if arm32_libs.is_empty() {
            log_i!("Walzer32: No 32-bit ARM libraries found in APK!");
            return Ok(0);
        }

        arm32_libs.sort_by_key(|lib| {
            let name = lib.filename.as_str();
            if name.contains("gnustl") || name.contains("c++_shared") {
                0
            } else if name.contains("objc") || name.contains("dispatch") {
                1
            } else if name.contains("ogg") || name.contains("vorbis") || name.contains("openal") {
                2
            } else if name.contains("foundation") || name.contains("coregraphics") {
                3
            } else if name.contains("quartzcore") || name.contains("uikit") {
                4
            } else if name.contains("cocos") || name.contains("noodle") || name.contains("box2d") {
                5
            } else if primary_lib.as_deref() == Some(name) {
                10
            } else {
                6
            }
        });

        let total_count = arm32_libs.len();
        log_i!("Walzer32: Loading {} bundled 32-bit libraries (primary: {:?})...", total_count, primary_lib);

        for lib in &arm32_libs {
            let lib_data = match apk.extract_library(&lib.filename) {
                Ok(data) => data,
                Err(e) => {
                    log_e!("Walzer32: Failed to extract {}: {:?}", lib.filename, e);
                    continue;
                }
            };
            log_i!("Walzer32: Loading {} ({} bytes)...", lib.filename, lib_data.len());
            match self.load_library_bytes(&lib.filename, &lib_data) {
                Ok(loaded) => {
                    log_i!(
                        "Walzer32: Successfully loaded {} at 0x{:08x} ({} symbols)",
                        lib.filename,
                        loaded.load_base.as_u32(),
                        loaded.symbols.len()
                    );
                    if let Some(onload_addr) = loaded.find_symbol("JNI_OnLoad") {
                        log_i!("Walzer32: Invoking JNI_OnLoad in {} at 0x{:08x}...", lib.filename, onload_addr.as_u32());
                        let vm_ptr = self.jni.vm_ptr.as_u32();
                        match self.call_native(onload_addr, &[vm_ptr, 0]) {
                            Ok(ret) => log_i!("Walzer32: JNI_OnLoad in {} returned 0x{:08x}", lib.filename, ret),
                            Err(e) => log_e!("Walzer32: JNI_OnLoad in {} error: {:?}", lib.filename, e),
                        }
                    }
                }
                Err(e) => {
                    log_e!("Walzer32: Failed to load {}: {:?}", lib.filename, e);
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

pub fn get_or_init_session() -> Result<std::sync::MutexGuard<'static, Option<Walzer32Session>>, SessionError> {
    let mut guard = GLOBAL_SESSION.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        // Default 128MB arena starting at 0x7000_0000
        let mut session = Walzer32Session::new(GuestAddr::new(0x7000_0000), 0x800_0000)?;
        let _ = session.ensure_bundled_apk_loaded();
        *guard = Some(session);
    }
    Ok(guard)
}

pub fn reset_session() {
    let mut guard = GLOBAL_SESSION.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

impl Drop for Walzer32Session {
    fn drop(&mut self) {
        self.release_host_window();
    }
}
