/// Multi-Threaded Guest Context and Thread Lifecycle Management for Walzer32 DBT.
///
/// Under ARM64 Android, games create threads via `pthread_create` / `sys_clone`.
/// Each guest thread requires:
///   1. Its own independent `CpuState` (336 bytes, repr(C)).
///   2. Unique thread ID (TID) and thread-local storage (`tls_ptr` via CP15).
///   3. A dedicated guest stack page (1 MB default, 8-byte aligned).
///   4. Shared access to `SharedMemory`, `ConcurrentJitCache`, and `FutexManager`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use walzer32_core::{CpuState, GuestAddr, Reg};

pub const DEFAULT_THREAD_STACK_SIZE: usize = 1024 * 1024; // 1 MB
pub const MAIN_THREAD_TID: u32 = 1000;

/// State descriptor of a guest thread
#[derive(Debug, Clone)]
pub struct ThreadDescriptor {
    pub tid: u32,
    pub entry: GuestAddr,
    pub arg: u32,
    pub stack_base: GuestAddr,
    pub stack_size: usize,
    pub tls_ptr: u32,
    pub finished: bool,
    pub exit_code: Option<u32>,
}

/// Thread manager allocating stacks, TIDs, and managing guest thread handles
pub struct ThreadManager {
    next_tid: u32,
    stack_arena_cur: GuestAddr,
    threads: Arc<Mutex<HashMap<u32, ThreadDescriptor>>>,
    pub handles: Vec<JoinHandle<()>>,
}

impl Default for ThreadManager {
    fn default() -> Self {
        Self::new(GuestAddr::new(0x2700_0000))
    }
}

impl ThreadManager {
    pub fn new(stack_arena_base: GuestAddr) -> Self {
        let mut threads = HashMap::new();
        // Register main thread
        threads.insert(
            MAIN_THREAD_TID,
            ThreadDescriptor {
                tid: MAIN_THREAD_TID,
                entry: GuestAddr::new(0),
                arg: 0,
                stack_base: stack_arena_base,
                stack_size: DEFAULT_THREAD_STACK_SIZE,
                tls_ptr: 0,
                finished: false,
                exit_code: None,
            },
        );

        Self {
            next_tid: 1001,
            stack_arena_cur: stack_arena_base.add(DEFAULT_THREAD_STACK_SIZE as u32),
            threads: Arc::new(Mutex::new(threads)),
            handles: Vec::new(),
        }
    }

    /// Allocates a new stack region in guest address space for a child thread
    pub fn alloc_stack(&mut self, size: usize) -> GuestAddr {
        let aligned_size = (size + 4095) & !4095;
        let stack_bottom = self.stack_arena_cur;
        self.stack_arena_cur = stack_bottom.add(aligned_size as u32);
        // Stack grows downward; top of stack is stack_bottom + size
        stack_bottom.add(aligned_size as u32 - 16)
    }

    /// Allocates a new Thread ID
    pub fn next_tid(&mut self) -> u32 {
        let tid = self.next_tid;
        self.next_tid += 1;
        tid
    }

    /// Creates a pre-configured CpuState for a new child thread
    pub fn create_thread_cpu(
        &self,
        entry: GuestAddr,
        arg: u32,
        sp: GuestAddr,
        tls_ptr: u32,
    ) -> CpuState {
        let mut cpu = CpuState::new();
        cpu.set_pc(entry);
        cpu.set_reg(Reg::R0, arg);
        cpu.set_sp(sp.as_u32());
        cpu.tls_ptr = tls_ptr;
        cpu
    }

    /// Registers a newly created child thread
    pub fn register_thread(
        &self,
        tid: u32,
        entry: GuestAddr,
        arg: u32,
        stack_base: GuestAddr,
        stack_size: usize,
        tls_ptr: u32,
    ) {
        let mut map = self.threads.lock().unwrap();
        map.insert(
            tid,
            ThreadDescriptor {
                tid,
                entry,
                arg,
                stack_base,
                stack_size,
                tls_ptr,
                finished: false,
                exit_code: None,
            },
        );
    }

    /// Records thread termination
    pub fn mark_finished(&self, tid: u32, exit_code: u32) {
        let mut map = self.threads.lock().unwrap();
        if let Some(t) = map.get_mut(&tid) {
            t.finished = true;
            t.exit_code = Some(exit_code);
        }
    }

    pub fn active_thread_count(&self) -> usize {
        let map = self.threads.lock().unwrap();
        map.values().filter(|t| !t.finished).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_manager_alloc_stack_and_tid() {
        let mut mgr = ThreadManager::new(GuestAddr::new(0x2000_0000));
        assert_eq!(mgr.active_thread_count(), 1);

        let tid1 = mgr.next_tid();
        assert_eq!(tid1, 1001);

        let stack1 = mgr.alloc_stack(DEFAULT_THREAD_STACK_SIZE);
        assert!(stack1.as_u32() > 0x2000_0000);

        let cpu = mgr.create_thread_cpu(GuestAddr::new(0x8000), 42, stack1, 0x1234_5678);
        assert_eq!(cpu.pc(), GuestAddr::new(0x8000));
        assert_eq!(cpu.reg(Reg::R0), 42);
        assert_eq!(cpu.sp(), stack1.as_u32());
        assert_eq!(cpu.tls_ptr, 0x1234_5678);

        mgr.register_thread(tid1, GuestAddr::new(0x8000), 42, stack1, DEFAULT_THREAD_STACK_SIZE, 0x1234_5678);
        assert_eq!(mgr.active_thread_count(), 2);

        mgr.mark_finished(tid1, 0);
        assert_eq!(mgr.active_thread_count(), 1);
    }
}
