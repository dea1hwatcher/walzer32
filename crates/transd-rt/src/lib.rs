pub mod aot_cache;
pub mod async_jit;
pub mod cache;
pub mod engine;
pub mod futex;
pub mod jit_memory;
pub mod jit_pool;
pub mod signals;
pub mod syscall;
pub mod telemetry;
pub mod thread;
pub mod tombstone;
pub mod vfs;

pub use aot_cache::{
    calculate_crc32, calculate_sha256, AotBlockRecord, AotCacheError, AotCacheHeader, AotDiskCache,
    AotScanner, AOT_CACHE_MAGIC, AOT_CACHE_VERSION, AOT_HEADER_SIZE, AOT_TARGET_ARCH_AARCH64,
};
pub use async_jit::{
    AsyncJit, AsyncJitConfig, AsyncJitStats, CodeSnapshot, CompilationJob, CompilationQueue,
    CompilationResult,
};
pub use cache::{ConcurrentJitCache, JitCache};
pub use engine::{DbtEngine, DefaultSyscallHandler, EngineError, EngineStepResult, SyscallHandler};
pub use futex::{FutexError, FutexManager, FUTEX_WAIT, FUTEX_WAKE, FUTEX_REQUEUE};
pub use jit_memory::{JitPage, flush_icache, PAGE_SIZE};
pub use jit_pool::{CommittedBlock, HostCodePtr, JitPool};
pub use signals::{FaultOrigin, SignalManager};
pub use syscall::{futex_op, nr, SyscallArgs};
pub use telemetry::TelemetryManager;
pub use thread::{DEFAULT_THREAD_STACK_SIZE, MAIN_THREAD_TID, ThreadDescriptor, ThreadManager};
pub use tombstone::{
    BacktraceFrame, CodeDumpLine, LibraryInfo, StackDumpLine, TombstoneReport, TombstoneSignal,
};
pub use vfs::{read_cstring_from_mem, OpenFile, Stat64, VirtualFileSystem};
