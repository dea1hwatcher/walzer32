/// OpenSL ES / AAudio High-Performance Audio Passthrough Bridge for Walzer32 DBT.
///
/// Under Android NDK, games output audio through OpenSL ES (`libOpenSLES.so`)
/// or AAudio (`libaaudio.so`) using lock-free circular ring buffers.
///
/// `AudioBridge` provides:
///   1. Lock-free SPSC PCM audio streaming (`AudioRingBuffer<i16>`).
///   2. High-fidelity fractional sample rate conversion & mono-to-stereo expansion (`AudioResampler`).
///   3. Volume attenuation in millibels conforming to OpenSL ES specifications.
///   4. OpenSL ES & AAudio SVC stubs and interface vtables.
///   5. Buffer completion tracking and guest callback dispatching.

use std::collections::{HashMap, VecDeque};
#[cfg(target_os = "android")]
use std::ffi::c_void;
use std::sync::Arc;
#[cfg(target_os = "android")]
use std::sync::atomic::{AtomicBool, Ordering};
use walzer32_core::{CpuState, GuestAddr, Memory, MemoryError, Reg};
use walzer32_elf::SymbolResolver;

use crate::audio_resample::{downmix_to_stereo, AudioResampler};
use crate::audio_ring::AudioRingBuffer;
#[cfg(target_os = "android")]
use crate::host::{HostBridge, RawFnPtr};

pub const SL_RESULT_SUCCESS: u32 = 0;
pub const SL_RESULT_PARAMETER_INVALID: u32 = 2;

pub const SL_PLAYSTATE_STOPPED: u32 = 1;
pub const SL_PLAYSTATE_PAUSED: u32 = 2;
pub const SL_PLAYSTATE_PLAYING: u32 = 3;

pub const AUDIO_SVC_MAGIC: u32 = 0xAA0000;

/// Audio function identifiers for OpenSL ES and AAudio SVC stubs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AudioFuncId {
    SlCreateEngine = 1,
    SlObjectRealize = 2,
    SlObjectGetInterface = 3,
    SlObjectDestroy = 4,
    SlEngineCreateAudioPlayer = 5,
    SlEngineCreateOutputMix = 6,
    SlPlaySetPlayState = 7,
    SlPlayGetPlayState = 8,
    SlBqEnqueue = 9,
    SlBqClear = 10,
    SlBqGetState = 11,
    SlBqRegisterCallback = 12,
    SlVolumeSetVolumeLevel = 13,
    SlVolumeGetVolumeLevel = 14,
    AAudioCreateStreamBuilder = 20,
    AAudioStreamBuilderSetSampleRate = 21,
    AAudioStreamBuilderSetChannelCount = 22,
    AAudioStreamBuilderSetFormat = 23,
    AAudioStreamBuilderOpenStream = 24,
    AAudioStreamRequestStart = 25,
    AAudioStreamRequestPause = 26,
    AAudioStreamRequestStop = 27,
    AAudioStreamWrite = 28,
    AAudioStreamClose = 29,
    AAudioStreamBuilderDelete = 30,
}

impl AudioFuncId {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::SlCreateEngine),
            2 => Some(Self::SlObjectRealize),
            3 => Some(Self::SlObjectGetInterface),
            4 => Some(Self::SlObjectDestroy),
            5 => Some(Self::SlEngineCreateAudioPlayer),
            6 => Some(Self::SlEngineCreateOutputMix),
            7 => Some(Self::SlPlaySetPlayState),
            8 => Some(Self::SlPlayGetPlayState),
            9 => Some(Self::SlBqEnqueue),
            10 => Some(Self::SlBqClear),
            11 => Some(Self::SlBqGetState),
            12 => Some(Self::SlBqRegisterCallback),
            13 => Some(Self::SlVolumeSetVolumeLevel),
            14 => Some(Self::SlVolumeGetVolumeLevel),
            20 => Some(Self::AAudioCreateStreamBuilder),
            21 => Some(Self::AAudioStreamBuilderSetSampleRate),
            22 => Some(Self::AAudioStreamBuilderSetChannelCount),
            23 => Some(Self::AAudioStreamBuilderSetFormat),
            24 => Some(Self::AAudioStreamBuilderOpenStream),
            25 => Some(Self::AAudioStreamRequestStart),
            26 => Some(Self::AAudioStreamRequestPause),
            27 => Some(Self::AAudioStreamRequestStop),
            28 => Some(Self::AAudioStreamWrite),
            29 => Some(Self::AAudioStreamClose),
            30 => Some(Self::AAudioStreamBuilderDelete),
            _ => None,
        }
    }
}

/// Audio format specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioFormat {
    pub channels: u16,
    pub sample_rate_hz: u32,
    pub bits_per_sample: u16,
}

impl Default for AudioFormat {
    fn default() -> Self {
        Self {
            channels: 2,
            sample_rate_hz: 44100,
            bits_per_sample: 16,
        }
    }
}

/// PCM audio buffer queued by 32-bit guest application
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioBuffer {
    pub guest_addr: GuestAddr,
    pub size_bytes: usize,
    pub pcm_data: Vec<u8>,
}

#[cfg(target_os = "android")]
struct HostAudioCallbackState {
    ring: Arc<AudioRingBuffer<i16>>,
    paused: Arc<AtomicBool>,
}

#[cfg(target_os = "android")]
struct HostAudioStream {
    host: HostBridge,
    stream: *mut c_void,
    user_data: *mut HostAudioCallbackState,
    paused: Arc<AtomicBool>,
}

#[cfg(target_os = "android")]
unsafe impl Send for HostAudioStream {}
#[cfg(target_os = "android")]
unsafe impl Sync for HostAudioStream {}

#[cfg(target_os = "android")]
unsafe extern "C" fn host_aaudio_data_callback(
    _stream: *mut c_void,
    user_data: *mut c_void,
    audio_data: *mut c_void,
    num_frames: i32,
) -> i32 {
    if user_data.is_null() || audio_data.is_null() || num_frames <= 0 {
        return 0; // AAUDIO_CALLBACK_RESULT_CONTINUE
    }
    let state = unsafe { &*(user_data as *const HostAudioCallbackState) };
    let total_samples = (num_frames as usize) * 2;
    let out = unsafe { std::slice::from_raw_parts_mut(audio_data as *mut i16, total_samples) };
    if state.paused.load(Ordering::Acquire) {
        out.fill(0);
    } else {
        state.ring.pop_slice_with_concealment(out);
    }
    0 // AAUDIO_CALLBACK_RESULT_CONTINUE
}

#[cfg(target_os = "android")]
impl Drop for HostAudioStream {
    fn drop(&mut self) {
        self.paused.store(true, Ordering::Release);
        if !self.stream.is_null() {
            if let Some(fp) = self.host.resolve("AAudioStream_requestStop") {
                let stop_fn: unsafe extern "C" fn(*mut c_void) -> i32 = unsafe { std::mem::transmute(fp) };
                unsafe { stop_fn(self.stream) };
            }
            if let Some(fp) = self.host.resolve("AAudioStream_close") {
                let close_fn: unsafe extern "C" fn(*mut c_void) -> i32 = unsafe { std::mem::transmute(fp) };
                unsafe { close_fn(self.stream) };
            }
            self.stream = std::ptr::null_mut();
        }
        if !self.user_data.is_null() {
            unsafe { drop(Box::from_raw(self.user_data)) };
            self.user_data = std::ptr::null_mut();
        }
    }
}

/// OpenSL ES / AAudio passthrough bridge
pub struct AudioBridge {
    pub play_state: u32,
    pub callback_fn: GuestAddr,
    pub callback_context: GuestAddr,
    pub buffer_queue: VecDeque<AudioBuffer>,
    pub total_bytes_played: u64,
    pub total_buffers_enqueued: u64,
    pub format: AudioFormat,
    pub volume_millibels: i32,
    pub ring_buffer: Arc<AudioRingBuffer<i16>>,
    pub resampler: AudioResampler,
    pub target_latency_ms: f32,
    pub stub_base: GuestAddr,
    pub symbol_table: HashMap<String, GuestAddr>,
    #[cfg(target_os = "android")]
    host_stream: Option<HostAudioStream>,
}

impl AudioBridge {
    pub fn new() -> Self {
        Self::with_stub_base(GuestAddr::new(0))
    }

    pub fn with_stub_base(stub_base: GuestAddr) -> Self {
        let mut bridge = Self {
            play_state: SL_PLAYSTATE_STOPPED,
            callback_fn: GuestAddr::new(0),
            callback_context: GuestAddr::new(0),
            buffer_queue: VecDeque::new(),
            total_bytes_played: 0,
            total_buffers_enqueued: 0,
            format: AudioFormat::default(),
            volume_millibels: 0,
            ring_buffer: Arc::new(AudioRingBuffer::new(65536)),
            resampler: AudioResampler::new(44100, 48000),
            target_latency_ms: 10.0,
            stub_base,
            symbol_table: HashMap::new(),
            #[cfg(target_os = "android")]
            host_stream: None,
        };

        bridge.register_known_symbols();
        bridge
    }

    #[cfg(target_os = "android")]
    pub fn start_host_output_stream(&mut self) {
        if let Some(hs) = &mut self.host_stream {
            hs.paused.store(false, Ordering::Release);
            if !hs.stream.is_null() {
                if let Some(fp) = hs.host.resolve("AAudioStream_requestStart") {
                    let start_fn: unsafe extern "C" fn(*mut c_void) -> i32 = unsafe { std::mem::transmute(fp) };
                    unsafe { start_fn(hs.stream) };
                }
            }
            return;
        }

        let mut host = HostBridge::new();
        macro_rules! resolve_aa {
            ($sym:literal, $ty:ty) => {{
                let Some(fp) = host.resolve($sym) else {
                    return;
                };
                unsafe { std::mem::transmute::<RawFnPtr, $ty>(fp) }
            }};
        }

        let create_builder = resolve_aa!("AAudio_createStreamBuilder", unsafe extern "C" fn(*mut *mut c_void) -> i32);
        let set_direction = resolve_aa!("AAudioStreamBuilder_setDirection", unsafe extern "C" fn(*mut c_void, i32));
        let set_rate = resolve_aa!("AAudioStreamBuilder_setSampleRate", unsafe extern "C" fn(*mut c_void, i32));
        let set_ch = resolve_aa!("AAudioStreamBuilder_setChannelCount", unsafe extern "C" fn(*mut c_void, i32));
        let set_fmt = resolve_aa!("AAudioStreamBuilder_setFormat", unsafe extern "C" fn(*mut c_void, i32));
        let set_perf = resolve_aa!("AAudioStreamBuilder_setPerformanceMode", unsafe extern "C" fn(*mut c_void, i32));
        let set_cb = resolve_aa!(
            "AAudioStreamBuilder_setDataCallback",
            unsafe extern "C" fn(
                *mut c_void,
                unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, i32) -> i32,
                *mut c_void,
            )
        );
        let open_stream = resolve_aa!(
            "AAudioStreamBuilder_openStream",
            unsafe extern "C" fn(*mut c_void, *mut *mut c_void) -> i32
        );
        let delete_builder = resolve_aa!("AAudioStreamBuilder_delete", unsafe extern "C" fn(*mut c_void) -> i32);
        let request_start = resolve_aa!("AAudioStream_requestStart", unsafe extern "C" fn(*mut c_void) -> i32);

        let mut builder: *mut c_void = std::ptr::null_mut();
        if unsafe { create_builder(&mut builder) } != 0 || builder.is_null() {
            return;
        }

        let paused = Arc::new(AtomicBool::new(false));
        let state = Box::new(HostAudioCallbackState {
            ring: Arc::clone(&self.ring_buffer),
            paused: Arc::clone(&paused),
        });
        let user_data = Box::into_raw(state);

        unsafe {
            set_direction(builder, 0); // AAUDIO_DIRECTION_OUTPUT
            set_rate(builder, 48000);
            set_ch(builder, 2);
            set_fmt(builder, 1); // AAUDIO_FORMAT_PCM_I16
            set_perf(builder, 12); // AAUDIO_PERFORMANCE_MODE_LOW_LATENCY
            set_cb(builder, host_aaudio_data_callback, user_data as *mut c_void);
        }

        let mut stream: *mut c_void = std::ptr::null_mut();
        let open_res = unsafe { open_stream(builder, &mut stream) };
        unsafe { delete_builder(builder) };

        if open_res != 0 || stream.is_null() {
            unsafe { drop(Box::from_raw(user_data)) };
            return;
        }

        let start_res = unsafe { request_start(stream) };
        if start_res != 0 {
            let tmp = HostAudioStream {
                host,
                stream,
                user_data,
                paused,
            };
            drop(tmp);
            return;
        }

        self.host_stream = Some(HostAudioStream {
            host,
            stream,
            user_data,
            paused,
        });
    }

    #[cfg(target_os = "android")]
    pub fn stop_host_output_stream(&mut self) {
        self.host_stream = None;
    }

    /// Sets player state (STOPPED, PAUSED, PLAYING)
    pub fn set_play_state(&mut self, state: u32) -> u32 {
        self.play_state = state;
        #[cfg(target_os = "android")]
        match state {
            SL_PLAYSTATE_PLAYING => self.start_host_output_stream(),
            SL_PLAYSTATE_PAUSED => {
                if let Some(hs) = &mut self.host_stream {
                    hs.paused.store(true, Ordering::Release);
                    if !hs.stream.is_null() {
                        if let Some(fp) = hs.host.resolve("AAudioStream_requestPause") {
                            let pause_fn: unsafe extern "C" fn(*mut c_void) -> i32 =
                                unsafe { std::mem::transmute(fp) };
                            unsafe { pause_fn(hs.stream) };
                        }
                    }
                }
            }
            _ => self.stop_host_output_stream(),
        }
        SL_RESULT_SUCCESS
    }

    /// Registers the OpenSL ES BufferQueue callback function
    pub fn register_callback(&mut self, callback: GuestAddr, context: GuestAddr) -> u32 {
        self.callback_fn = callback;
        self.callback_context = context;
        SL_RESULT_SUCCESS
    }

    /// Checks if a guest callback is registered
    #[inline]
    pub fn has_callback(&self) -> bool {
        self.callback_fn.as_u32() != 0
    }

    /// Updates audio input format
    pub fn set_format(&mut self, format: AudioFormat) {
        self.format = format;
        self.resampler.set_rates(format.sample_rate_hz, 48000);
    }

    /// Sets playback volume in millibels (-9600 to 1000 mB, where 0 mB is unity gain)
    pub fn set_volume_millibels(&mut self, millibels: i32) {
        self.volume_millibels = millibels.clamp(-9600, 1000);
    }

    /// Gets current volume in millibels
    #[inline]
    pub fn volume_millibels(&self) -> i32 {
        self.volume_millibels
    }

    /// Calculates linear amplitude gain multiplier from volume in millibels
    pub fn volume_multiplier(&self) -> f32 {
        if self.volume_millibels <= -9600 {
            0.0
        } else if self.volume_millibels == 0 {
            1.0
        } else {
            10.0f32.powf(self.volume_millibels as f32 / 2000.0)
        }
    }

    /// Intercepts `(*bqItf)->Enqueue(bqItf, pBuffer, size)` from 32-bit guest
    pub fn enqueue_buffer(
        &mut self,
        mem: &impl Memory,
        buffer_addr: GuestAddr,
        size_bytes: usize,
    ) -> Result<u32, MemoryError> {
        if size_bytes == 0 || buffer_addr.as_u32() == 0 {
            return Ok(SL_RESULT_PARAMETER_INVALID);
        }

        let mut data = vec![0u8; size_bytes];
        mem.read_bytes(buffer_addr, &mut data)?;

        // Parse 16-bit PCM samples
        let sample_count = size_bytes / 2;
        let mut pcm_samples = Vec::with_capacity(sample_count);
        for i in 0..sample_count {
            let offset = i * 2;
            let sample = i16::from_le_bytes([data[offset], data[offset + 1]]);
            pcm_samples.push(sample);
        }

        // If format channels > 2 (e.g. Quad, 5.1, 7.1), downmix to stereo first
        let stereo_samples = if self.format.channels > 2 {
            let mut dm = Vec::with_capacity(pcm_samples.len() / (self.format.channels as usize) * 2);
            downmix_to_stereo(self.format.channels, &pcm_samples, &mut dm);
            dm
        } else {
            pcm_samples
        };

        // Resample / expand to 48 kHz stereo
        let mut resampled = Vec::new();
        if self.format.channels == 1 {
            self.resampler.resample_mono_to_stereo(&stereo_samples, &mut resampled);
        } else {
            self.resampler.resample_stereo(&stereo_samples, &mut resampled);
        }

        // Apply volume scaling if not unity
        let vol = self.volume_multiplier();
        if (vol - 1.0).abs() > 0.0001 {
            for s in resampled.iter_mut() {
                let scaled = (*s as f32 * vol).clamp(-32768.0, 32767.0);
                *s = scaled as i16;
            }
        }

        // Push into lock-free SPSC ring buffer for host hardware playback
        self.ring_buffer.push_slice(&resampled);

        if self.buffer_queue.len() >= 64 {
            self.buffer_queue.pop_front();
        }
        self.buffer_queue.push_back(AudioBuffer {
            guest_addr: buffer_addr,
            size_bytes,
            pcm_data: data,
        });

        self.total_buffers_enqueued += 1;
        Ok(SL_RESULT_SUCCESS)
    }

    /// Directly enqueues 16-bit PCM samples, performing resampling and volume scaling
    pub fn enqueue_pcm_samples(&mut self, samples: &[i16]) -> usize {
        if samples.is_empty() {
            return 0;
        }

        let stereo_samples = if self.format.channels > 2 {
            let mut dm = Vec::with_capacity(samples.len() / (self.format.channels as usize) * 2);
            downmix_to_stereo(self.format.channels, samples, &mut dm);
            dm
        } else {
            samples.to_vec()
        };

        let mut resampled = Vec::new();
        if self.format.channels == 1 {
            self.resampler.resample_mono_to_stereo(&stereo_samples, &mut resampled);
        } else {
            self.resampler.resample_stereo(&stereo_samples, &mut resampled);
        }

        let vol = self.volume_multiplier();
        if (vol - 1.0).abs() > 0.0001 {
            for s in resampled.iter_mut() {
                let scaled = (*s as f32 * vol).clamp(-32768.0, 32767.0);
                *s = scaled as i16;
            }
        }

        self.ring_buffer.push_slice(&resampled)
    }

    /// Reads host stereo frames (48 kHz) from the lock-free ring buffer into `out`.
    /// `out` format: [L0, R0, L1, R1, ...]
    /// Returns the number of frames actually read (frames = samples / 2).
    /// If fewer samples than requested are available, underrun concealment fade-out is applied.
    pub fn read_host_frames(&mut self, out: &mut [i16]) -> usize {
        let samples_read = self.ring_buffer.pop_slice_with_concealment(out);
        self.total_bytes_played += (samples_read * 2) as u64;
        samples_read / 2
    }

    /// Sets target audio playback latency in milliseconds
    pub fn set_target_latency_ms(&mut self, ms: f32) {
        self.target_latency_ms = ms.clamp(1.0, 100.0);
    }

    /// Current audio latency in milliseconds at host 48,000 Hz stereo output
    #[inline]
    pub fn current_latency_ms(&self) -> f32 {
        self.ring_buffer.latency_ms(48000, 2)
    }

    /// Ratio of buffer capacity currently occupied [0.0 .. 1.0]
    #[inline]
    pub fn buffer_watermark_ratio(&self) -> f32 {
        self.ring_buffer.watermark_fill_ratio()
    }


    /// Consumes the next buffer in queue (forwarding to host audio hardware)
    pub fn consume_next_buffer(&mut self) -> Option<AudioBuffer> {
        self.buffer_queue.pop_front()
    }

    /// Clears all queued buffers
    pub fn clear_queue(&mut self) {
        self.buffer_queue.clear();
    }

    /// Clears the ring buffer and resets resampler phase
    pub fn clear_ring_buffer(&mut self) {
        self.ring_buffer.clear();
        self.resampler.reset();
    }

    pub fn queued_count(&self) -> usize {
        self.buffer_queue.len()
    }

    /// Total number of buffer underruns encountered
    #[inline]
    pub fn underrun_count(&self) -> u64 {
        self.ring_buffer.underrun_count()
    }

    /// Total number of buffer overruns encountered
    #[inline]
    pub fn overrun_count(&self) -> u64 {
        self.ring_buffer.overrun_count()
    }


    /// Number of available stereo frames in ring buffer
    #[inline]
    pub fn available_frames(&self) -> usize {
        self.ring_buffer.available_read() / 2
    }

    /// Number of available samples in ring buffer
    #[inline]
    pub fn available_samples(&self) -> usize {
        self.ring_buffer.available_read()
    }

    fn register_known_symbols(&mut self) {
        if self.stub_base.as_u32() == 0 {
            return;
        }

        let symbols = [
            ("slCreateEngine", AudioFuncId::SlCreateEngine),
            ("AAudio_createStreamBuilder", AudioFuncId::AAudioCreateStreamBuilder),
            ("AAudioStreamBuilder_setSampleRate", AudioFuncId::AAudioStreamBuilderSetSampleRate),
            ("AAudioStreamBuilder_setChannelCount", AudioFuncId::AAudioStreamBuilderSetChannelCount),
            ("AAudioStreamBuilder_setFormat", AudioFuncId::AAudioStreamBuilderSetFormat),
            ("AAudioStreamBuilder_openStream", AudioFuncId::AAudioStreamBuilderOpenStream),
            ("AAudioStream_requestStart", AudioFuncId::AAudioStreamRequestStart),
            ("AAudioStream_requestPause", AudioFuncId::AAudioStreamRequestPause),
            ("AAudioStream_requestStop", AudioFuncId::AAudioStreamRequestStop),
            ("AAudioStream_write", AudioFuncId::AAudioStreamWrite),
            ("AAudioStream_close", AudioFuncId::AAudioStreamClose),
            ("AAudioStreamBuilder_delete", AudioFuncId::AAudioStreamBuilderDelete),
        ];

        for (name, id) in symbols {
            let addr = self.stub_base.add((id as u32) * 8);
            self.symbol_table.insert(name.to_string(), addr);
        }

        // OpenSL ES Interface GUID addresses
        self.symbol_table.insert("SL_IID_ENGINE".to_string(), self.stub_base.add(0x600));
        self.symbol_table.insert("SL_IID_PLAY".to_string(), self.stub_base.add(0x610));
        self.symbol_table.insert("SL_IID_ANDROIDSIMPLEBUFFERQUEUE".to_string(), self.stub_base.add(0x620));
        self.symbol_table.insert("SL_IID_BUFFERQUEUE".to_string(), self.stub_base.add(0x630));
        self.symbol_table.insert("SL_IID_VOLUME".to_string(), self.stub_base.add(0x640));
        self.symbol_table.insert("SL_IID_OUTPUTMIX".to_string(), self.stub_base.add(0x650));
    }

    /// Installs OpenSL ES and AAudio stubs and vtables into guest memory
    pub fn install_stubs(&self, mem: &mut impl Memory) -> Result<(), MemoryError> {
        if self.stub_base.as_u32() == 0 {
            return Ok(());
        }

        // 1. Install SVC stubs for each AudioFuncId
        for id_val in 1..=30 {
            if let Some(id) = AudioFuncId::from_u32(id_val) {
                let addr = self.stub_base.add((id as u32) * 8);
                let svc_code = 0xEF00_0000 | (AUDIO_SVC_MAGIC | (id as u32));
                let bx_lr = 0xE12F_FF1E;

                mem.write_u32(addr, svc_code)?;
                mem.write_u32(addr.add(4), bx_lr)?;
            }
        }

        // 2. OpenSL ES Object and Interface layout
        let addr_engine_obj = self.stub_base.add(0x1000);
        let addr_engine_obj_vtbl = self.stub_base.add(0x100);
        let addr_engine_itf = self.stub_base.add(0x1050);
        let addr_engine_itf_vtbl = self.stub_base.add(0x150);
        let addr_player_obj = self.stub_base.add(0x1100);
        let addr_player_obj_vtbl = self.stub_base.add(0x200);
        let addr_play_itf = self.stub_base.add(0x1150);
        let addr_play_itf_vtbl = self.stub_base.add(0x250);
        let addr_bq_itf = self.stub_base.add(0x1200);
        let addr_bq_itf_vtbl = self.stub_base.add(0x300);
        let addr_volume_itf = self.stub_base.add(0x1300);
        let addr_volume_itf_vtbl = self.stub_base.add(0x400);
        let addr_output_mix_obj = self.stub_base.add(0x1400);
        let addr_output_mix_vtbl = self.stub_base.add(0x500);

        // Objects -> Vtbl pointers
        mem.write_u32(addr_engine_obj, addr_engine_obj_vtbl.as_u32())?;
        mem.write_u32(addr_engine_itf, addr_engine_itf_vtbl.as_u32())?;
        mem.write_u32(addr_player_obj, addr_player_obj_vtbl.as_u32())?;
        mem.write_u32(addr_play_itf, addr_play_itf_vtbl.as_u32())?;
        mem.write_u32(addr_bq_itf, addr_bq_itf_vtbl.as_u32())?;
        mem.write_u32(addr_volume_itf, addr_volume_itf_vtbl.as_u32())?;
        mem.write_u32(addr_output_mix_obj, addr_output_mix_vtbl.as_u32())?;

        let stub_realize = self.stub_base.add((AudioFuncId::SlObjectRealize as u32) * 8).as_u32();
        let stub_get_interface = self.stub_base.add((AudioFuncId::SlObjectGetInterface as u32) * 8).as_u32();
        let stub_destroy = self.stub_base.add((AudioFuncId::SlObjectDestroy as u32) * 8).as_u32();
        let stub_create_player = self.stub_base.add((AudioFuncId::SlEngineCreateAudioPlayer as u32) * 8).as_u32();
        let stub_create_mix = self.stub_base.add((AudioFuncId::SlEngineCreateOutputMix as u32) * 8).as_u32();
        let stub_set_play_state = self.stub_base.add((AudioFuncId::SlPlaySetPlayState as u32) * 8).as_u32();
        let stub_get_play_state = self.stub_base.add((AudioFuncId::SlPlayGetPlayState as u32) * 8).as_u32();
        let stub_enqueue = self.stub_base.add((AudioFuncId::SlBqEnqueue as u32) * 8).as_u32();
        let stub_clear = self.stub_base.add((AudioFuncId::SlBqClear as u32) * 8).as_u32();
        let stub_get_state = self.stub_base.add((AudioFuncId::SlBqGetState as u32) * 8).as_u32();
        let stub_register_cb = self.stub_base.add((AudioFuncId::SlBqRegisterCallback as u32) * 8).as_u32();
        let stub_set_volume = self.stub_base.add((AudioFuncId::SlVolumeSetVolumeLevel as u32) * 8).as_u32();
        let stub_get_volume = self.stub_base.add((AudioFuncId::SlVolumeGetVolumeLevel as u32) * 8).as_u32();

        // Engine Obj Vtbl (SLObjectItf)
        mem.write_u32(addr_engine_obj_vtbl, stub_realize)?;
        mem.write_u32(addr_engine_obj_vtbl.add(0x0C), stub_get_interface)?;
        mem.write_u32(addr_engine_obj_vtbl.add(0x18), stub_destroy)?;

        // Engine Itf Vtbl (SLEngineItf)
        mem.write_u32(addr_engine_itf_vtbl.add(0x08), stub_create_player)?;
        mem.write_u32(addr_engine_itf_vtbl.add(0x1C), stub_create_mix)?;

        // Player Obj Vtbl (SLObjectItf)
        mem.write_u32(addr_player_obj_vtbl, stub_realize)?;
        mem.write_u32(addr_player_obj_vtbl.add(0x0C), stub_get_interface)?;
        mem.write_u32(addr_player_obj_vtbl.add(0x18), stub_destroy)?;

        // Play Itf Vtbl (SLPlayItf)
        mem.write_u32(addr_play_itf_vtbl, stub_set_play_state)?;
        mem.write_u32(addr_play_itf_vtbl.add(0x04), stub_get_play_state)?;

        // BufferQueue Itf Vtbl (SLAndroidSimpleBufferQueueItf)
        mem.write_u32(addr_bq_itf_vtbl, stub_enqueue)?;
        mem.write_u32(addr_bq_itf_vtbl.add(0x04), stub_clear)?;
        mem.write_u32(addr_bq_itf_vtbl.add(0x08), stub_get_state)?;
        mem.write_u32(addr_bq_itf_vtbl.add(0x0C), stub_register_cb)?;

        // Volume Itf Vtbl (SLVolumeItf)
        mem.write_u32(addr_volume_itf_vtbl, stub_set_volume)?;
        mem.write_u32(addr_volume_itf_vtbl.add(0x04), stub_get_volume)?;

        // Output Mix Obj Vtbl
        mem.write_u32(addr_output_mix_vtbl, stub_realize)?;
        mem.write_u32(addr_output_mix_vtbl.add(0x0C), stub_get_interface)?;
        mem.write_u32(addr_output_mix_vtbl.add(0x18), stub_destroy)?;

        Ok(())
    }

    /// Handles an incoming OpenSL ES or AAudio SVC call
    pub fn handle_svc(
        &mut self,
        svc_imm: u32,
        cpu: &mut CpuState,
        mem: &mut impl Memory,
    ) -> Result<bool, MemoryError> {
        if (svc_imm & 0xFF0000) != AUDIO_SVC_MAGIC {
            return Ok(false);
        }

        let func_id = svc_imm & 0xFFFF;
        match AudioFuncId::from_u32(func_id) {
            Some(AudioFuncId::SlCreateEngine) => {
                let p_engine = GuestAddr::new(cpu.reg(Reg::R0));
                if p_engine.as_u32() != 0 {
                    mem.write_u32(p_engine, self.stub_base.add(0x1000).as_u32())?;
                }
                cpu.set_reg(Reg::R0, SL_RESULT_SUCCESS);
            }
            Some(AudioFuncId::SlObjectRealize) => {
                cpu.set_reg(Reg::R0, SL_RESULT_SUCCESS);
            }
            Some(AudioFuncId::SlObjectGetInterface) => {
                let iid = cpu.reg(Reg::R1);
                let p_itf = GuestAddr::new(cpu.reg(Reg::R2));
                if p_itf.as_u32() != 0 {
                    let itf_addr = if iid == self.stub_base.add(0x600).as_u32() {
                        self.stub_base.add(0x1050)
                    } else if iid == self.stub_base.add(0x610).as_u32() {
                        self.stub_base.add(0x1150)
                    } else if iid == self.stub_base.add(0x620).as_u32()
                        || iid == self.stub_base.add(0x630).as_u32()
                    {
                        self.stub_base.add(0x1200)
                    } else if iid == self.stub_base.add(0x640).as_u32() {
                        self.stub_base.add(0x1300)
                    } else {
                        let obj = cpu.reg(Reg::R0);
                        if obj == self.stub_base.add(0x1000).as_u32() {
                            self.stub_base.add(0x1050)
                        } else if obj == self.stub_base.add(0x1100).as_u32() {
                            self.stub_base.add(0x1150)
                        } else {
                            self.stub_base.add(0x1200)
                        }
                    };
                    mem.write_u32(p_itf, itf_addr.as_u32())?;
                }
                cpu.set_reg(Reg::R0, SL_RESULT_SUCCESS);
            }
            Some(AudioFuncId::SlObjectDestroy) => {
                cpu.set_reg(Reg::R0, SL_RESULT_SUCCESS);
            }
            Some(AudioFuncId::SlEngineCreateAudioPlayer) => {
                let p_player = GuestAddr::new(cpu.reg(Reg::R1));
                if p_player.as_u32() != 0 {
                    mem.write_u32(p_player, self.stub_base.add(0x1100).as_u32())?;
                }
                cpu.set_reg(Reg::R0, SL_RESULT_SUCCESS);
            }
            Some(AudioFuncId::SlEngineCreateOutputMix) => {
                let p_mix = GuestAddr::new(cpu.reg(Reg::R1));
                if p_mix.as_u32() != 0 {
                    mem.write_u32(p_mix, self.stub_base.add(0x1400).as_u32())?;
                }
                cpu.set_reg(Reg::R0, SL_RESULT_SUCCESS);
            }
            Some(AudioFuncId::SlPlaySetPlayState) => {
                let state = cpu.reg(Reg::R1);
                self.set_play_state(state);
                cpu.set_reg(Reg::R0, SL_RESULT_SUCCESS);
            }
            Some(AudioFuncId::SlPlayGetPlayState) => {
                let p_state = GuestAddr::new(cpu.reg(Reg::R1));
                if p_state.as_u32() != 0 {
                    mem.write_u32(p_state, self.play_state)?;
                }
                cpu.set_reg(Reg::R0, SL_RESULT_SUCCESS);
            }
            Some(AudioFuncId::SlBqEnqueue) => {
                let buffer_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let size = cpu.reg(Reg::R2) as usize;
                let res = self.enqueue_buffer(mem, buffer_addr, size)?;
                cpu.set_reg(Reg::R0, res);
            }
            Some(AudioFuncId::SlBqClear) => {
                self.clear_queue();
                cpu.set_reg(Reg::R0, SL_RESULT_SUCCESS);
            }
            Some(AudioFuncId::SlBqGetState) => {
                let p_state = GuestAddr::new(cpu.reg(Reg::R1));
                if p_state.as_u32() != 0 {
                    mem.write_u32(p_state, self.buffer_queue.len() as u32)?;
                    mem.write_u32(p_state.add(4), self.total_buffers_enqueued as u32)?;
                }
                cpu.set_reg(Reg::R0, SL_RESULT_SUCCESS);
            }
            Some(AudioFuncId::SlBqRegisterCallback) => {
                let cb = GuestAddr::new(cpu.reg(Reg::R1));
                let ctx = GuestAddr::new(cpu.reg(Reg::R2));
                self.register_callback(cb, ctx);
                cpu.set_reg(Reg::R0, SL_RESULT_SUCCESS);
            }
            Some(AudioFuncId::SlVolumeSetVolumeLevel) => {
                let level = cpu.reg(Reg::R1) as i16 as i32;
                self.set_volume_millibels(level);
                cpu.set_reg(Reg::R0, SL_RESULT_SUCCESS);
            }
            Some(AudioFuncId::SlVolumeGetVolumeLevel) => {
                let p_level = GuestAddr::new(cpu.reg(Reg::R1));
                if p_level.as_u32() != 0 {
                    mem.write_u16(p_level, self.volume_millibels as i16 as u16)?;
                }
                cpu.set_reg(Reg::R0, SL_RESULT_SUCCESS);
            }
            Some(AudioFuncId::AAudioCreateStreamBuilder) => {
                cpu.set_reg(Reg::R0, 1);
            }
            Some(AudioFuncId::AAudioStreamBuilderSetSampleRate) => {
                let rate = cpu.reg(Reg::R1);
                self.format.sample_rate_hz = rate;
                self.resampler.set_rates(rate, 48000);
                cpu.set_reg(Reg::R0, 0);
            }
            Some(AudioFuncId::AAudioStreamBuilderSetChannelCount) => {
                let ch = cpu.reg(Reg::R1) as u16;
                self.format.channels = ch;
                cpu.set_reg(Reg::R0, 0);
            }
            Some(AudioFuncId::AAudioStreamBuilderSetFormat) => {
                cpu.set_reg(Reg::R0, 0);
            }
            Some(AudioFuncId::AAudioStreamBuilderOpenStream) => {
                let p_stream = GuestAddr::new(cpu.reg(Reg::R1));
                if p_stream.as_u32() != 0 {
                    mem.write_u32(p_stream, 1)?;
                }
                cpu.set_reg(Reg::R0, 0);
            }
            Some(AudioFuncId::AAudioStreamRequestStart) => {
                self.set_play_state(SL_PLAYSTATE_PLAYING);
                cpu.set_reg(Reg::R0, 0);
            }
            Some(AudioFuncId::AAudioStreamRequestPause) => {
                self.set_play_state(SL_PLAYSTATE_PAUSED);
                cpu.set_reg(Reg::R0, 0);
            }
            Some(AudioFuncId::AAudioStreamRequestStop) => {
                self.set_play_state(SL_PLAYSTATE_STOPPED);
                cpu.set_reg(Reg::R0, 0);
            }
            Some(AudioFuncId::AAudioStreamWrite) => {
                let buffer_addr = GuestAddr::new(cpu.reg(Reg::R1));
                let num_frames = cpu.reg(Reg::R2);
                let bytes = num_frames as usize
                    * self.format.channels as usize
                    * (self.format.bits_per_sample as usize / 8);
                let _ = self.enqueue_buffer(mem, buffer_addr, bytes)?;
                cpu.set_reg(Reg::R0, num_frames);
            }
            Some(AudioFuncId::AAudioStreamClose) => {
                #[cfg(target_os = "android")]
                self.stop_host_output_stream();
                cpu.set_reg(Reg::R0, 0);
            }
            Some(AudioFuncId::AAudioStreamBuilderDelete) => {
                cpu.set_reg(Reg::R0, 0);
            }
            None => {
                cpu.set_reg(Reg::R0, 0);
            }
        }

        Ok(true)
    }
}

impl Default for AudioBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolResolver for AudioBridge {
    fn resolve(&self, name: &str) -> Option<GuestAddr> {
        self.symbol_table.get(name).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use walzer32_core::FlatMemory;

    #[test]
    fn test_audio_play_state_and_callback() {
        let mut audio = AudioBridge::new();
        assert_eq!(audio.play_state, SL_PLAYSTATE_STOPPED);

        audio.set_play_state(SL_PLAYSTATE_PLAYING);
        assert_eq!(audio.play_state, SL_PLAYSTATE_PLAYING);

        audio.register_callback(GuestAddr::new(0x8000), GuestAddr::new(0x9000));
        assert_eq!(audio.callback_fn, GuestAddr::new(0x8000));
        assert_eq!(audio.callback_context, GuestAddr::new(0x9000));
        assert!(audio.has_callback());
    }

    #[test]
    fn test_audio_enqueue_and_consume() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);
        let mut audio = AudioBridge::new();

        // Write 4 stereo 16-bit PCM samples (16 bytes) at 0x1100
        let pcm = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        mem.write_bytes(GuestAddr::new(0x1100), &pcm).unwrap();

        let res = audio.enqueue_buffer(&mem, GuestAddr::new(0x1100), 16).unwrap();
        assert_eq!(res, SL_RESULT_SUCCESS);
        assert_eq!(audio.queued_count(), 1);
        assert_eq!(audio.total_buffers_enqueued, 1);

        let consumed = audio.consume_next_buffer().unwrap();
        assert_eq!(consumed.size_bytes, 16);
        assert_eq!(consumed.pcm_data, pcm);
        assert_eq!(audio.queued_count(), 0);
    }

    #[test]
    fn test_audio_ring_resample_and_playback() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x4000);
        let mut audio = AudioBridge::new();
        audio.set_format(AudioFormat {
            channels: 2,
            sample_rate_hz: 48000,
            bits_per_sample: 16,
        });

        // 8 stereo frames of 16-bit PCM = 32 bytes
        let mut samples = Vec::new();
        for i in 0..8 {
            samples.push((i * 100) as i16);
            samples.push((-(i * 100)) as i16);
        }
        let mut bytes = Vec::new();
        for &s in &samples {
            bytes.extend_from_slice(&s.to_le_bytes());
        }
        mem.write_bytes(GuestAddr::new(0x2000), &bytes).unwrap();

        audio.enqueue_buffer(&mem, GuestAddr::new(0x2000), bytes.len()).unwrap();
        assert_eq!(audio.available_frames(), 8);

        let mut out = [0i16; 16];
        let frames_read = audio.read_host_frames(&mut out);
        assert_eq!(frames_read, 8);
        assert_eq!(out, samples.as_slice());
        assert_eq!(audio.available_frames(), 0);
    }

    #[test]
    fn test_audio_volume_attenuation() {
        let mut audio = AudioBridge::new();
        audio.set_format(AudioFormat {
            channels: 2,
            sample_rate_hz: 48000,
            bits_per_sample: 16,
        });

        // -2000 mB = -20 dB = 0.1 gain multiplier
        audio.set_volume_millibels(-2000);
        let mult = audio.volume_multiplier();
        assert!((mult - 0.1).abs() < 0.01);

        let samples = [1000i16, -1000, 2000, -2000];
        audio.enqueue_pcm_samples(&samples);

        let mut out = [0i16; 4];
        let frames = audio.read_host_frames(&mut out);
        assert_eq!(frames, 2);
        assert_eq!(out[0], 100);
        assert_eq!(out[1], -100);
        assert_eq!(out[2], 200);
        assert_eq!(out[3], -200);
    }

    #[test]
    fn test_audio_opensles_stubs_and_svc() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x8000);
        let stub_base = GuestAddr::new(0x2000);
        let mut audio = AudioBridge::with_stub_base(stub_base);
        audio.install_stubs(&mut mem).unwrap();

        let mut cpu = CpuState::new();

        // 1. Test slCreateEngine(&engine)
        let engine_ptr = GuestAddr::new(0x5000);
        cpu.set_reg(Reg::R0, engine_ptr.as_u32());
        let res = audio.handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::SlCreateEngine as u32), &mut cpu, &mut mem).unwrap();
        assert!(res);
        assert_eq!(cpu.reg(Reg::R0), SL_RESULT_SUCCESS);
        let engine_obj = mem.read_u32(engine_ptr).unwrap();
        assert_eq!(engine_obj, stub_base.add(0x1000).as_u32());

        // 2. Test Realize
        cpu.set_reg(Reg::R0, engine_obj);
        audio.handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::SlObjectRealize as u32), &mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.reg(Reg::R0), SL_RESULT_SUCCESS);

        // 3. Test GetInterface for SL_IID_PLAY
        let play_itf_ptr = GuestAddr::new(0x5004);
        cpu.set_reg(Reg::R0, engine_obj);
        cpu.set_reg(Reg::R1, stub_base.add(0x610).as_u32()); // SL_IID_PLAY
        cpu.set_reg(Reg::R2, play_itf_ptr.as_u32());
        audio.handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::SlObjectGetInterface as u32), &mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.reg(Reg::R0), SL_RESULT_SUCCESS);
        let play_itf = mem.read_u32(play_itf_ptr).unwrap();
        assert_eq!(play_itf, stub_base.add(0x1150).as_u32());

        // 4. Test SetPlayState
        cpu.set_reg(Reg::R0, play_itf);
        cpu.set_reg(Reg::R1, SL_PLAYSTATE_PLAYING);
        audio.handle_svc(AUDIO_SVC_MAGIC | (AudioFuncId::SlPlaySetPlayState as u32), &mut cpu, &mut mem).unwrap();
        assert_eq!(cpu.reg(Reg::R0), SL_RESULT_SUCCESS);
        assert_eq!(audio.play_state, SL_PLAYSTATE_PLAYING);
    }
}
