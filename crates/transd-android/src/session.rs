use std::collections::HashMap;
use std::sync::Mutex;
use thiserror::Error;
use transd_apk::{ApkError, ApkPackage};
use transd_bridge::{
    invoke_guest_extended, invoke_jni_onload, AudioBridge, BionicBridge, GlesBridge, JniBridge,
    KeyEvent, RegisteredNativeMethod, SurfaceBridge, TouchEvent,
};
use transd_core::{FlatMemory, GuestAddr};
use transd_elf::{CompositeResolver, ElfLoader, LoadedLibrary, LoaderError, SymbolResolver};
use transd_rt::DbtEngine;

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("Engine memory error: {0}")]
    Memory(#[from] transd_core::MemoryError),
    #[error("ELF loader error: {0}")]
    Loader(#[from] LoaderError),
    #[error("APK parsing error: {0}")]
    Apk(#[from] ApkError),
    #[error("Execution error: {0}")]
    Engine(#[from] transd_rt::EngineError),
    #[error("Session not initialized")]
    NotInitialized,
    #[error("Library not found: {0}")]
    LibraryNotFound(String),
    #[error("Symbol not found: {0}")]
    SymbolNotFound(String),
}

/// Global DBT Execution Session for Android Runtime
pub struct TransdSession {
    pub engine: DbtEngine<FlatMemory>,
    pub bionic: BionicBridge,
    pub gles: GlesBridge,
    pub jni: JniBridge,
    pub surface: SurfaceBridge,
    pub audio: AudioBridge,
    pub aot_cache_dir: Option<std::path::PathBuf>,
    pub apk_bytes: Option<Vec<u8>>,
    pub loaded_libraries: HashMap<String, LoadedLibrary>,
    pub next_load_addr: GuestAddr,
    pub initialized: bool,
}

impl TransdSession {
    /// Initialize a new DBT session with a guest address space arena
    pub fn new(arena_base: GuestAddr, arena_size: usize) -> Result<Self, SessionError> {
        let mut mem = FlatMemory::new(arena_base, arena_size);

        // Layout inside arena:
        // arena_base + 0x0000_0000: Bionic stubs and TLS (0x100_000)
        // arena_base + 0x0010_0000: Bionic heap (0x400_000)
        // arena_base + 0x0050_0000: GLES stubs (0x100_000)
        // arena_base + 0x0060_0000: JNIEnv & JavaVM tables (0x100_000)
        // arena_base + 0x0070_0000: Stack region (0x100_000) -> SP top at +0x0080_0000
        // arena_base + 0x0100_0000: Dynamic library loading arena
        let bionic_stubs = arena_base;
        let bionic_heap = arena_base.add(0x100_000);
        let gles_stubs = arena_base.add(0x500_000);
        let gles_heap = arena_base.add(0x580_000);
        let jni_base = arena_base.add(0x600_000);
        let audio_stubs = arena_base.add(0x700_000);
        let stack_top = arena_base.add(0x800_000);
        let lib_load_base = arena_base.add(0x100_0000);

        let bionic = BionicBridge::new(bionic_stubs, bionic_heap, 0x400_000);
        bionic.install_stubs(&mut mem)?;

        let gles = GlesBridge::new(gles_stubs, gles_heap);
        gles.install_stubs(&mut mem)?;

        let jni = JniBridge::new(jni_base);
        jni.install(&mut mem)?;

        let audio = AudioBridge::with_stub_base(audio_stubs);
        audio.install_stubs(&mut mem)?;

        let surface = SurfaceBridge::new();

        let mut engine = DbtEngine::new(mem);
        engine.cpu.set_sp(stack_top.as_u32() - 0x1000);

        Ok(Self {
            engine,
            bionic,
            gles,
            jni,
            surface,
            audio,
            aot_cache_dir: None,
            apk_bytes: None,
            loaded_libraries: HashMap::new(),
            next_load_addr: lib_load_base,
            initialized: true,
        })
    }

    /// Attach an APK package by raw bytes
    pub fn attach_apk(&mut self, apk_bytes: Vec<u8>) {
        self.apk_bytes = Some(apk_bytes);
    }

    /// Registers a custom in-memory file in the guest VFS
    pub fn register_vfs_file(&mut self, path: &str, content: Vec<u8>) {
        if let Some(vfs) = self.engine.vfs_mut() {
            vfs.register_file(path, content);
        }
    }

    /// Adds a path redirection rule in the guest VFS
    pub fn add_vfs_redirect(&mut self, from: &str, to: &str) {
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

        // Create composite resolver combining Bionic, GLES, Audio, and previously loaded libraries
        let mut composite = CompositeResolver::new();
        composite.add(&self.bionic);
        composite.add(&self.gles);
        composite.add(&self.audio);

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

        // Automatic AOT translation cache loading & pre-compilation
        if let Some(ref dir) = self.aot_cache_dir {
            let hash = transd_rt::calculate_sha256(elf_bytes);
            let cache_filename = format!("{name}.transd_cache");
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
        let res = invoke_guest_extended(
            &mut self.engine,
            &mut self.bionic,
            &mut self.jni,
            Some(&mut self.gles),
            Some(&mut self.audio),
            fn_addr,
            args,
        )?;
        Ok(res)
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
    pub fn export_aot_cache(&self, binary_hash: [u8; 32], build_id: [u8; 20]) -> transd_rt::AotDiskCache {
        self.engine.export_aot_cache(binary_hash, build_id)
    }

    /// Imports an AOT disk cache into session
    pub fn import_aot_cache(&mut self, cache: &transd_rt::AotDiskCache) -> Result<usize, transd_rt::AotCacheError> {
        self.engine.import_aot_cache(cache)
    }

    /// Get list of native methods registered via JNI env->RegisterNatives
    pub fn registered_natives(&self) -> &[RegisteredNativeMethod] {
        &self.jni.registered_natives
    }

    /// Handles SurfaceCreated lifecycle event from Android UI thread
    pub fn on_surface_created(&mut self, window_ptr: usize, width: u32, height: u32) {
        self.surface.on_surface_created(window_ptr, width, height);
    }

    /// Handles SurfaceChanged viewport dimension update
    pub fn on_surface_changed(&mut self, width: u32, height: u32) {
        self.surface.on_surface_changed(width, height);
    }

    /// Handles SurfaceDestroyed event
    pub fn on_surface_destroyed(&mut self) {
        self.surface.on_surface_destroyed();
    }

    /// Triggers frame render in guest DBT if a render callback is registered
    pub fn on_draw_frame(&mut self) -> Result<(), SessionError> {
        self.engine.telemetry.record_frame(16.6);
        if let Some(render_fn) = self.surface.draw_frame_fn {
            let _ = self.call_native(render_fn, &[])?;
        }
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
        signal: transd_rt::tombstone::TombstoneSignal,
        abort_message: Option<&str>,
    ) -> transd_rt::tombstone::TombstoneReport {
        let mut libs = Vec::new();
        for (name, lib) in &self.loaded_libraries {
            let mut info = transd_rt::tombstone::LibraryInfo::new(name, lib.load_base, lib.total_size);
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
}

// Global static session protected by Mutex for JNI C ABI entry points
static GLOBAL_SESSION: Mutex<Option<TransdSession>> = Mutex::new(None);

pub fn get_or_init_session() -> Result<std::sync::MutexGuard<'static, Option<TransdSession>>, SessionError> {
    let mut guard = GLOBAL_SESSION.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        // Default 128MB arena starting at 0x7000_0000
        let session = TransdSession::new(GuestAddr::new(0x7000_0000), 0x800_0000)?;
        *guard = Some(session);
    }
    Ok(guard)
}

pub fn reset_session() {
    let mut guard = GLOBAL_SESSION.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}
