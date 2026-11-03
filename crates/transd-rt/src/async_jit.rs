use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use byteorder::{ByteOrder, LittleEndian};
use transd_core::{GuestAddr, Memory, MemoryError};
use transd_emitter_a64::{A64Compiler, CompiledBlock};
use transd_ir::{SuperblockOptimizer, TraceBuilder};

/// A thread-safe, self-contained snapshot of guest memory for background trace building.
/// Allows background workers to read instructions without acquiring locks on the main emulation memory.
#[derive(Clone, Debug)]
pub struct CodeSnapshot {
    pub base: GuestAddr,
    pub bytes: Vec<u8>,
}

impl CodeSnapshot {
    /// Captures a code window centered around `center` from the guest memory.
    /// Gracefully shrinks the window if segment boundaries or unmapped pages are reached.
    pub fn capture<M: Memory>(mem: &M, center: GuestAddr, window_size: usize) -> Option<Self> {
        let center_u = center.as_u32();
        let half = (window_size / 2).max(64) as u32;
        let start_u = center_u.saturating_sub(half) & !0x3;
        let target_len = window_size.max(128);

        // Attempt to read the full target window
        let mut buf = vec![0u8; target_len];
        if mem.read_bytes(GuestAddr::new(start_u), &mut buf).is_ok() {
            return Some(Self {
                base: GuestAddr::new(start_u),
                bytes: buf,
            });
        }

        // Fallback: try starting directly at center with progressively smaller sizes
        let mut fallback_len = target_len;
        while fallback_len >= 64 {
            let mut small_buf = vec![0u8; fallback_len];
            if mem.read_bytes(center, &mut small_buf).is_ok() {
                return Some(Self {
                    base: center,
                    bytes: small_buf,
                });
            }
            fallback_len /= 2;
        }

        None
    }
}

impl Memory for CodeSnapshot {
    fn read_u8(&self, addr: GuestAddr) -> Result<u8, MemoryError> {
        let b = self.base.as_u32();
        let a = addr.as_u32();
        if a >= b && (a as usize) < (b as usize + self.bytes.len()) {
            Ok(self.bytes[(a - b) as usize])
        } else {
            Err(MemoryError::Unmapped(addr))
        }
    }

    fn read_u16(&self, addr: GuestAddr) -> Result<u16, MemoryError> {
        let b = self.base.as_u32();
        let a = addr.as_u32();
        if a >= b && (a as usize + 2) <= (b as usize + self.bytes.len()) {
            let off = (a - b) as usize;
            Ok(LittleEndian::read_u16(&self.bytes[off..off + 2]))
        } else {
            Err(MemoryError::Unmapped(addr))
        }
    }

    fn read_u32(&self, addr: GuestAddr) -> Result<u32, MemoryError> {
        let b = self.base.as_u32();
        let a = addr.as_u32();
        if a >= b && (a as usize + 4) <= (b as usize + self.bytes.len()) {
            let off = (a - b) as usize;
            Ok(LittleEndian::read_u32(&self.bytes[off..off + 4]))
        } else {
            Err(MemoryError::Unmapped(addr))
        }
    }

    fn read_u64(&self, addr: GuestAddr) -> Result<u64, MemoryError> {
        let b = self.base.as_u32();
        let a = addr.as_u32();
        if a >= b && (a as usize + 8) <= (b as usize + self.bytes.len()) {
            let off = (a - b) as usize;
            Ok(LittleEndian::read_u64(&self.bytes[off..off + 8]))
        } else {
            Err(MemoryError::Unmapped(addr))
        }
    }

    fn write_u8(&mut self, addr: GuestAddr, _val: u8) -> Result<(), MemoryError> {
        Err(MemoryError::PermissionDenied { addr, write: true })
    }

    fn write_u16(&mut self, addr: GuestAddr, _val: u16) -> Result<(), MemoryError> {
        Err(MemoryError::PermissionDenied { addr, write: true })
    }

    fn write_u32(&mut self, addr: GuestAddr, _val: u32) -> Result<(), MemoryError> {
        Err(MemoryError::PermissionDenied { addr, write: true })
    }

    fn write_u64(&mut self, addr: GuestAddr, _val: u64) -> Result<(), MemoryError> {
        Err(MemoryError::PermissionDenied { addr, write: true })
    }

    fn read_bytes(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), MemoryError> {
        let b = self.base.as_u32();
        let a = addr.as_u32();
        if a >= b && (a as usize + buf.len()) <= (b as usize + self.bytes.len()) {
            let off = (a - b) as usize;
            buf.copy_from_slice(&self.bytes[off..off + buf.len()]);
            Ok(())
        } else {
            Err(MemoryError::Unmapped(addr))
        }
    }

    fn write_bytes(&mut self, addr: GuestAddr, _buf: &[u8]) -> Result<(), MemoryError> {
        Err(MemoryError::PermissionDenied { addr, write: true })
    }
}

/// Configuration parameters for asynchronous background JIT compilation.
#[derive(Debug, Clone)]
pub struct AsyncJitConfig {
    /// Number of worker threads dedicated to trace compilation (default: 2)
    pub worker_threads: usize,
    /// Maximum queue depth before new requests are dropped to prevent memory pressure
    pub max_queue_depth: usize,
    /// Size in bytes of the code window snapshotted for trace compilation (default: 4096)
    pub code_window_size: usize,
    /// Maximum basic blocks per traced superblock (default: 8)
    pub max_trace_blocks: usize,
    /// Maximum instructions per traced superblock (default: 128)
    pub max_trace_insts: usize,
}

impl Default for AsyncJitConfig {
    fn default() -> Self {
        Self {
            worker_threads: 2,
            max_queue_depth: 128,
            code_window_size: 4096,
            max_trace_blocks: 8,
            max_trace_insts: 128,
        }
    }
}

/// Compilation request sent from the emulation thread to the background worker pool.
#[derive(Clone, Debug)]
pub struct CompilationJob {
    pub entry: GuestAddr,
    pub is_thumb: bool,
    pub code: CodeSnapshot,
}

/// Finished compilation product ready to be committed to executable memory.
#[derive(Debug)]
pub struct CompilationResult {
    pub entry: GuestAddr,
    pub is_thumb: bool,
    pub compiled: CompiledBlock,
    pub compile_duration_us: u64,
}

/// Real-time metrics for asynchronous background JIT operations.
#[derive(Debug, Clone, Default)]
pub struct AsyncJitStats {
    pub jobs_enqueued: u64,
    pub jobs_completed: u64,
    pub jobs_dropped: u64,
    pub dedup_filtered: u64,
    pub failed_compilations: u64,
    pub total_compile_us: u64,
    pub in_flight: usize,
    pub worker_count: usize,
}

struct QueueState {
    queue: VecDeque<CompilationJob>,
    in_flight: HashSet<GuestAddr>,
    failed: HashSet<GuestAddr>,
}

pub struct CompilationQueue {
    inner: Mutex<QueueState>,
    cond: Condvar,
    stats_enqueued: AtomicU64,
    stats_dropped: AtomicU64,
    stats_dedup: AtomicU64,
    stats_completed: AtomicU64,
    stats_failed: AtomicU64,
    stats_compile_us: AtomicU64,
}

impl CompilationQueue {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(QueueState {
                queue: VecDeque::new(),
                in_flight: HashSet::new(),
                failed: HashSet::new(),
            }),
            cond: Condvar::new(),
            stats_enqueued: AtomicU64::new(0),
            stats_dropped: AtomicU64::new(0),
            stats_dedup: AtomicU64::new(0),
            stats_completed: AtomicU64::new(0),
            stats_failed: AtomicU64::new(0),
            stats_compile_us: AtomicU64::new(0),
        }
    }

    /// Enqueues a compilation job with deduplication and capacity bounds check.
    /// Returns true if enqueued; false if deduplicated or dropped.
    pub fn enqueue(&self, job: CompilationJob, max_depth: usize) -> bool {
        let mut state = self.inner.lock().unwrap();

        // 1. Deduplication: Check if this block is already compiling or queued
        if state.in_flight.contains(&job.entry) || state.failed.contains(&job.entry) {
            self.stats_dedup.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // 2. Capacity check
        if state.queue.len() >= max_depth {
            self.stats_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        state.in_flight.insert(job.entry);
        state.queue.push_back(job);
        self.stats_enqueued.fetch_add(1, Ordering::Relaxed);
        self.cond.notify_one();
        true
    }

    /// Pops the next job from the queue, blocking until one is available or shutdown is flagged.
    pub fn pop(&self, shutdown: &AtomicBool) -> Option<CompilationJob> {
        let mut state = self.inner.lock().unwrap();
        loop {
            if shutdown.load(Ordering::Acquire) {
                return None;
            }
            if let Some(job) = state.queue.pop_front() {
                return Some(job);
            }
            state = self.cond.wait(state).unwrap();
        }
    }

    /// Finishes processing a job, releasing its in-flight lock and recording success/failure.
    pub fn finish_job(&self, entry: GuestAddr, success: bool, duration_us: u64) {
        let mut state = self.inner.lock().unwrap();
        state.in_flight.remove(&entry);
        if success {
            self.stats_completed.fetch_add(1, Ordering::Relaxed);
            self.stats_compile_us.fetch_add(duration_us, Ordering::Relaxed);
        } else {
            state.failed.insert(entry);
            self.stats_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Returns the number of jobs currently in queue and in flight.
    pub fn in_flight_count(&self) -> usize {
        let state = self.inner.lock().unwrap();
        state.in_flight.len()
    }

    /// Clears any pending queue items and reset in-flight state.
    pub fn clear(&self) {
        let mut state = self.inner.lock().unwrap();
        state.queue.clear();
        state.in_flight.clear();
        state.failed.clear();
    }
}

/// Asynchronous Multi-Core Background JIT Compilation Manager.
/// Offloads heavy trace building, superblock optimization, and AArch64 code emission
/// to a dedicated pool of worker threads, guaranteeing zero jank on the emulation thread.
pub struct AsyncJit {
    config: AsyncJitConfig,
    queue: Arc<CompilationQueue>,
    results_rx: Receiver<CompilationResult>,
    shutdown: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl AsyncJit {
    pub fn new(config: AsyncJitConfig) -> Self {
        let queue = Arc::new(CompilationQueue::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (results_tx, results_rx) = channel();
        let mut workers = Vec::with_capacity(config.worker_threads);

        for i in 0..config.worker_threads {
            let q = Arc::clone(&queue);
            let s = Arc::clone(&shutdown);
            let tx = results_tx.clone();
            let max_blocks = config.max_trace_blocks;
            let max_insts = config.max_trace_insts;

            let handle = std::thread::Builder::new()
                .name(format!("transd-jit-{i}"))
                .spawn(move || {
                    while let Some(job) = q.pop(&s) {
                        let t0 = Instant::now();
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            if let Ok(mut sb) = TraceBuilder::build_trace_with_limit(
                                &job.code,
                                job.entry,
                                job.is_thumb,
                                max_blocks,
                                max_insts,
                            ) {
                                if (sb.block_count > 1 || sb.is_loop) && !sb.insts.is_empty() {
                                    SuperblockOptimizer::optimize(&mut sb);
                                    if sb.insts.is_empty() { return None; }
                                    let compiled = A64Compiler::compile_superblock(&sb);
                                    let compile_us = t0.elapsed().as_micros() as u64;
                                    return Some(CompilationResult {
                                        entry: job.entry,
                                        is_thumb: job.is_thumb,
                                        compiled,
                                        compile_duration_us: compile_us.max(1),
                                    });
                                }
                            }
                            None
                        }));

                        match result {
                            Ok(Some(res)) => {
                                let duration = res.compile_duration_us;
                                let entry = res.entry;
                                let _ = tx.send(res);
                                q.finish_job(entry, true, duration);
                            }
                            _ => {
                                q.finish_job(job.entry, false, t0.elapsed().as_micros() as u64);
                            }
                        }
                    }
                })
                .expect("Failed to spawn background JIT worker thread");

            workers.push(handle);
        }

        Self {
            config,
            queue,
            results_rx,
            shutdown,
            workers,
        }
    }

    /// Access configuration parameters
    pub fn config(&self) -> &AsyncJitConfig {
        &self.config
    }

    /// Clears any pending compilation jobs in the queue
    pub fn clear(&self) {
        self.queue.clear();
    }

    /// Enqueues a block entry for asynchronous background trace compilation.
    /// Returns true if successfully queued, false if deduplicated or dropped due to backpressure.
    pub fn enqueue(&self, entry: GuestAddr, is_thumb: bool, code: CodeSnapshot) -> bool {
        let job = CompilationJob {
            entry,
            is_thumb,
            code,
        };
        self.queue.enqueue(job, self.config.max_queue_depth)
    }

    /// Non-blocking drain of all completed superblocks compiled by background workers.
    pub fn drain_results(&mut self) -> Vec<CompilationResult> {
        let mut results = Vec::new();
        while let Ok(res) = self.results_rx.try_recv() {
            results.push(res);
        }
        results
    }

    /// Non-blocking poll for a single completed result if available.
    pub fn try_recv(&mut self) -> Option<CompilationResult> {
        self.results_rx.try_recv().ok()
    }

    /// Waits until all queued and in-flight compilation jobs are finished (or timeout).
    /// Returns true if all jobs finished, false on timeout.
    pub fn wait_for_idle(&self, timeout: Duration) -> bool {
        let start = Instant::now();
        while self.queue.in_flight_count() > 0 {
            if start.elapsed() >= timeout {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        true
    }

    /// Returns current runtime telemetry and statistics for the background JIT pool.
    pub fn stats(&self) -> AsyncJitStats {
        AsyncJitStats {
            jobs_enqueued: self.queue.stats_enqueued.load(Ordering::Relaxed),
            jobs_completed: self.queue.stats_completed.load(Ordering::Relaxed),
            jobs_dropped: self.queue.stats_dropped.load(Ordering::Relaxed),
            dedup_filtered: self.queue.stats_dedup.load(Ordering::Relaxed),
            failed_compilations: self.queue.stats_failed.load(Ordering::Relaxed),
            total_compile_us: self.queue.stats_compile_us.load(Ordering::Relaxed),
            in_flight: self.queue.in_flight_count(),
            worker_count: self.workers.len(),
        }
    }

    /// Shuts down all background worker threads cleanly and joins them.
    pub fn shutdown(&mut self) {
        if !self.shutdown.swap(true, Ordering::Release) {
            self.queue.cond.notify_all();
            for handle in self.workers.drain(..) {
                let _ = handle.join();
            }
        }
    }
}

impl Drop for AsyncJit {
    fn drop(&mut self) {
        self.shutdown();
    }
}
