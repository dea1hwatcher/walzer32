/// Real-Time Performance Telemetry and On-Screen HUD for Transd DBT.
///
/// Tracks instruction execution throughput (MIPS), JIT block compilation latency,
/// cache hit rates, chained fast jumps, frame render delta times (FPS), and arena memory.

#[derive(Debug, Clone)]
pub struct TelemetryManager {
    pub total_instructions: u64,
    pub total_blocks_compiled: u64,
    pub jit_cache_hits: u64,
    pub jit_cache_misses: u64,
    pub jit_chained_jumps: u64,
    pub tier2_superblocks_compiled: u64,
    pub smc_write_traps: u64,
    pub total_compilation_time_us: u64,
    pub total_frames_rendered: u64,
    pub arena_allocated_bytes: usize,
    pub jit_pool_allocated_bytes: usize,

    // Sliding window metrics
    pub last_frame_time_ms: f64,
    pub sliding_fps: f64,
    pub sliding_mips: f64,
}

impl Default for TelemetryManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryManager {
    pub fn new() -> Self {
        Self {
            total_instructions: 0,
            total_blocks_compiled: 0,
            jit_cache_hits: 0,
            jit_cache_misses: 0,
            jit_chained_jumps: 0,
            tier2_superblocks_compiled: 0,
            smc_write_traps: 0,
            total_compilation_time_us: 0,
            total_frames_rendered: 0,
            arena_allocated_bytes: 0,
            jit_pool_allocated_bytes: 0,
            last_frame_time_ms: 16.6,
            sliding_fps: 60.0,
            sliding_mips: 0.0,
        }
    }

    /// Records instruction batch execution
    pub fn record_instructions(&mut self, count: u64) {
        self.total_instructions += count;
    }

    /// Records block compilation latency
    pub fn record_compilation(&mut self, time_us: u64) {
        self.total_blocks_compiled += 1;
        self.total_compilation_time_us += time_us;
    }

    /// Records JIT cache hit
    pub fn record_cache_hit(&mut self) {
        self.jit_cache_hits += 1;
    }

    /// Records JIT cache miss
    pub fn record_cache_miss(&mut self) {
        self.jit_cache_misses += 1;
    }

    /// Records direct block-to-block chained dispatch
    pub fn record_chained_jump(&mut self) {
        self.jit_chained_jumps += 1;
    }

    /// Records compilation of a Tier-2 Superblock trace
    pub fn record_tier2_compilation(&mut self) {
        self.tier2_superblocks_compiled += 1;
    }

    /// Records an SMC write trap and dynamic cache invalidation
    pub fn record_smc_trap(&mut self) {
        self.smc_write_traps += 1;
    }

    /// Records a rendered frame with delta time in milliseconds
    pub fn record_frame(&mut self, delta_ms: f64) {
        self.total_frames_rendered += 1;
        self.last_frame_time_ms = delta_ms;
        if delta_ms > 0.0 {
            let instant_fps = 1000.0 / delta_ms;
            // Exponential moving average for smooth FPS
            self.sliding_fps = self.sliding_fps * 0.9 + instant_fps * 0.1;
        }
    }

    /// Updates memory footprint
    pub fn update_memory_usage(&mut self, arena_bytes: usize, jit_bytes: usize) {
        self.arena_allocated_bytes = arena_bytes;
        self.jit_pool_allocated_bytes = jit_bytes;
    }

    /// Updates computed MIPS from instructions executed over time
    pub fn update_mips(&mut self, insts: u64, elapsed_secs: f64) {
        if elapsed_secs > 0.0 {
            let mips = (insts as f64 / 1_000_000.0) / elapsed_secs;
            self.sliding_mips = mips;
        }
    }

    /// Computes percentage hit rate in JIT block cache (0.0 to 100.0)
    pub fn cache_hit_rate(&self) -> f64 {
        let total = self.jit_cache_hits + self.jit_cache_misses;
        if total == 0 {
            100.0
        } else {
            (self.jit_cache_hits as f64 / total as f64) * 100.0
        }
    }

    /// Computes average JIT compilation latency per basic block in microseconds
    pub fn avg_compilation_latency_us(&self) -> f64 {
        if self.total_blocks_compiled == 0 {
            0.0
        } else {
            self.total_compilation_time_us as f64 / self.total_blocks_compiled as f64
        }
    }

    /// Current frames per second
    pub fn current_fps(&self) -> f64 {
        self.sliding_fps
    }

    /// Current instruction execution rate in MIPS
    pub fn current_mips(&self) -> f64 {
        self.sliding_mips
    }

    /// Formats an on-screen ASCII Telemetry HUD overlay
    pub fn render_hud_overlay(&self) -> String {
        let arena_mb = self.arena_allocated_bytes as f64 / (1024.0 * 1024.0);
        let jit_mb = self.jit_pool_allocated_bytes as f64 / (1024.0 * 1024.0);

        format!(
            "┌──────────────────────────────────────────────────────────┐\n\
             │ TRANSD DBT ENGINE TELEMETRY HUD                          │\n\
             ├──────────────────────────────────────────────────────────┤\n\
             │ FPS: {:5.1} ({:4.1} ms)      MIPS: {:6.2}                   │\n\
             │ JIT Cache: {:5.1}% Hit     Chained Fast Jumps: {:9}    │\n\
             │ Compiled Blocks: {:7}   Avg Compile Time: {:4.1} µs     │\n\
             │ Total Insts: {:11}  Guest ABI: armeabi-v7a        │\n\
             │ Arena Memory: {:5.1} MB    JIT Code Size: {:4.1} MB         │\n\
             └──────────────────────────────────────────────────────────┘",
            self.sliding_fps,
            self.last_frame_time_ms,
            self.sliding_mips,
            self.cache_hit_rate(),
            self.jit_chained_jumps,
            self.total_blocks_compiled,
            self.avg_compilation_latency_us(),
            self.total_instructions,
            arena_mb,
            jit_mb
        )
    }

    /// Serializes metrics to structured JSON format for remote profiling
    pub fn render_json(&self) -> String {
        format!(
            "{{\n\
             \"fps\": {:.2},\n\
             \"frame_time_ms\": {:.2},\n\
             \"mips\": {:.2},\n\
             \"cache_hit_rate\": {:.2},\n\
             \"total_instructions\": {},\n\
             \"total_blocks_compiled\": {},\n\
             \"jit_cache_hits\": {},\n\
             \"jit_cache_misses\": {},\n\
             \"jit_chained_jumps\": {},\n\
             \"tier2_superblocks_compiled\": {},\n\
             \"smc_write_traps\": {},\n\
             \"avg_compile_time_us\": {:.2},\n\
             \"arena_allocated_bytes\": {},\n\
             \"jit_pool_allocated_bytes\": {}\n\
            }}",
            self.sliding_fps,
            self.last_frame_time_ms,
            self.sliding_mips,
            self.cache_hit_rate(),
            self.total_instructions,
            self.total_blocks_compiled,
            self.jit_cache_hits,
            self.jit_cache_misses,
            self.jit_chained_jumps,
            self.tier2_superblocks_compiled,
            self.smc_write_traps,
            self.avg_compilation_latency_us(),
            self.arena_allocated_bytes,
            self.jit_pool_allocated_bytes
        )
    }
}
