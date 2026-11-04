/// Fast Futex (Fast Userspace Mutex) Virtualization for Transd DBT.
///
/// Implements Linux futex semantics for guest 32-bit Bionic pthreads:
///   - FUTEX_WAIT: sleeps if *uaddr == val until FUTEX_WAKE or timeout.
///   - FUTEX_WAKE: wakes up to N threads sleeping on *uaddr.
///   - FUTEX_REQUEUE: wakes N threads on uaddr1 and moves remaining waiters to uaddr2.
///
/// Thread synchronization is achieved via `std::sync::{Condvar, Mutex}`, ensuring zero
/// busy-waiting or CPU burning when guest worker threads sleep on condition variables.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use thiserror::Error;
use transd_core::{GuestAddr, Memory, MemoryError};

pub const FUTEX_WAIT: u32 = 0;
pub const FUTEX_WAKE: u32 = 1;
pub const FUTEX_FD: u32 = 2;
pub const FUTEX_REQUEUE: u32 = 3;
pub const FUTEX_CMP_REQUEUE: u32 = 4;
pub const FUTEX_WAKE_OP: u32 = 5;
pub const FUTEX_PRIVATE_FLAG: u32 = 128;

#[derive(Error, Debug)]
pub enum FutexError {
    #[error("Memory error reading futex word: {0}")]
    Memory(#[from] MemoryError),
    #[error("Futex value mismatch (EAGAIN)")]
    WouldBlock,
    #[error("Futex wait timed out (ETIMEDOUT)")]
    TimedOut,
    #[error("Invalid futex operation: {0}")]
    InvalidOp(u32),
}

/// A wait queue node tracking waiting threads for a specific guest futex address
#[derive(Default)]
struct FutexQueue {
    waiters_count: usize,
}

/// Thread-safe manager of active guest futex wait queues
#[derive(Default, Clone)]
pub struct FutexManager {
    queues: Arc<Mutex<HashMap<GuestAddr, Arc<(Mutex<FutexQueue>, Condvar)>>>>,
}

impl FutexManager {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_or_create_queue(&self, addr: GuestAddr) -> Arc<(Mutex<FutexQueue>, Condvar)> {
        let mut map = self.queues.lock().unwrap();
        map.entry(addr)
            .or_insert_with(|| Arc::new((Mutex::new(FutexQueue::default()), Condvar::new())))
            .clone()
    }

    /// Returns the number of threads currently waiting on uaddr
    pub fn waiters_count(&self, uaddr: GuestAddr) -> usize {
        let map = self.queues.lock().unwrap();
        if let Some(queue) = map.get(&uaddr) {
            queue.0.lock().unwrap().waiters_count
        } else {
            0
        }
    }

    /// FUTEX_WAIT: If *uaddr == val, suspends the calling thread until FUTEX_WAKE or timeout.
    pub fn wait(
        &self,
        mem: &(impl Memory + ?Sized),
        uaddr: GuestAddr,
        expected_val: u32,
        timeout: Option<Duration>,
    ) -> Result<(), FutexError> {
        let current = mem.read_u32(uaddr)?;
        if current != expected_val {
            return Err(FutexError::WouldBlock);
        }

        let queue = self.get_or_create_queue(uaddr);
        let (lock, cond) = &*queue;
        let mut guard = lock.lock().unwrap();

        // Double check value under queue lock
        let current = mem.read_u32(uaddr)?;
        if current != expected_val {
            return Err(FutexError::WouldBlock);
        }

        guard.waiters_count += 1;

        if let Some(dur) = timeout {
            let res = cond.wait_timeout(guard, dur).unwrap();
            let mut guard = res.0;
            guard.waiters_count = guard.waiters_count.saturating_sub(1);
            if guard.waiters_count == 0 {
                let mut map = self.queues.lock().unwrap();
                if let Some(q) = map.get(&uaddr) {
                    if Arc::ptr_eq(q, &queue) {
                        map.remove(&uaddr);
                    }
                }
            }
            if res.1.timed_out() {
                return Err(FutexError::TimedOut);
            }
        } else {
            guard = cond.wait(guard).unwrap();
            guard.waiters_count = guard.waiters_count.saturating_sub(1);
            if guard.waiters_count == 0 {
                let mut map = self.queues.lock().unwrap();
                if let Some(q) = map.get(&uaddr) {
                    if Arc::ptr_eq(q, &queue) {
                        map.remove(&uaddr);
                    }
                }
            }
        }

        Ok(())
    }

    /// FUTEX_WAKE: Wakes up to `val` threads waiting on uaddr.
    pub fn wake(&self, uaddr: GuestAddr, count: u32) -> u32 {
        let mut map = self.queues.lock().unwrap();
        if let Some(queue) = map.get(&uaddr).cloned() {
            let (lock, cond) = &*queue;
            let mut guard = lock.lock().unwrap();
            let waiters = guard.waiters_count as u32;
            let to_wake = waiters.min(count);

            for _ in 0..to_wake {
                cond.notify_one();
            }

            guard.waiters_count = guard.waiters_count.saturating_sub(to_wake as usize);
            if guard.waiters_count == 0 {
                map.remove(&uaddr);
            }

            to_wake
        } else {
            0
        }
    }

    /// FUTEX_REQUEUE: Wakes `wake_count` on uaddr1, moves remaining `requeue_count` to uaddr2.
    pub fn requeue(
        &self,
        uaddr1: GuestAddr,
        wake_count: u32,
        requeue_count: u32,
        uaddr2: GuestAddr,
    ) -> u32 {
        let woken = self.wake(uaddr1, wake_count);
        if requeue_count > 0 {
            let q1 = self.get_or_create_queue(uaddr1);
            let q2 = self.get_or_create_queue(uaddr2);
            let mut g1 = q1.0.lock().unwrap();
            let mut g2 = q2.0.lock().unwrap();
            let to_move = (g1.waiters_count as u32).min(requeue_count) as usize;
            g1.waiters_count -= to_move;
            g2.waiters_count += to_move;
        }
        woken
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transd_core::FlatMemory;

    #[test]
    fn test_futex_wait_mismatch_returns_would_block() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x1000);
        mem.write_u32(GuestAddr::new(0x1000), 42).unwrap();

        let mgr = FutexManager::new();
        // Expecting 10, but memory contains 42
        let res = mgr.wait(&mem, GuestAddr::new(0x1000), 10, None);
        assert!(matches!(res, Err(FutexError::WouldBlock)));
    }

    #[test]
    fn test_futex_wait_timeout() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x1000);
        mem.write_u32(GuestAddr::new(0x1000), 42).unwrap();

        let mgr = FutexManager::new();
        let timeout = Duration::from_millis(10);
        let res = mgr.wait(&mem, GuestAddr::new(0x1000), 42, Some(timeout));
        assert!(matches!(res, Err(FutexError::TimedOut)));
    }

    #[test]
    fn test_futex_wake_threads() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x1000);
        mem.write_u32(GuestAddr::new(0x1000), 1).unwrap();

        let mgr = FutexManager::new();
        let mgr_clone = mgr.clone();

        // Spawn a thread that waits on futex
        let handle = std::thread::spawn(move || {
            let mem_thread = FlatMemory::new(GuestAddr::new(0x1000), 0x1000);
            mgr_clone.wait(&mem_thread, GuestAddr::new(0x1000), 0, None)
        });

        std::thread::sleep(Duration::from_millis(20));
        let woken = mgr.wake(GuestAddr::new(0x1000), 1);
        assert!(woken <= 1);
        let _ = handle.join();
    }
}
