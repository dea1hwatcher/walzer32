use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// ARMv7-A exclusive reservation granule (64 bytes, cache-line aligned)
pub const RESERVATION_GRANULE: u32 = 64;
pub const RESERVATION_MASK: u32 = !(RESERVATION_GRANULE - 1);
pub const INVALID_RESERVATION: u32 = 0xFFFF_FFFF;
pub const MAX_MONITORED_THREADS: usize = 64;

/// Global thread-safe exclusive monitor coordinating LDREX / STREX across multiple threads.
/// Modeled after ARM Architecture Reference Manual and Dynarmic exclusive monitor.
pub struct GlobalExclusiveMonitor {
    reservations: [AtomicU32; MAX_MONITORED_THREADS],
    active_mask: AtomicU64,
}

impl GlobalExclusiveMonitor {
    pub const fn new() -> Self {
        Self {
            reservations: [const { AtomicU32::new(INVALID_RESERVATION) }; MAX_MONITORED_THREADS],
            active_mask: AtomicU64::new(0),
        }
    }

    /// Returns the global exclusive monitor singleton
    pub fn global() -> &'static Self {
        static GLOBAL_MONITOR: GlobalExclusiveMonitor = GlobalExclusiveMonitor::new();
        &GLOBAL_MONITOR
    }

    /// Sets an exclusive reservation for `thread_id` at `addr` (rounded down to 64-byte granule)
    #[inline(always)]
    pub fn set_reservation(&self, thread_id: usize, addr: u32) {
        if thread_id < MAX_MONITORED_THREADS {
            let granule = addr & RESERVATION_MASK;
            self.reservations[thread_id].store(granule, Ordering::Release);
            self.active_mask.fetch_or(1u64 << thread_id, Ordering::Release);
        }
    }

    /// Checks if the reservation at `addr` (64-byte granule) is still held for `thread_id`.
    /// If held, atomically clears it and returns true; otherwise returns false.
    #[inline(always)]
    pub fn check_and_clear(&self, thread_id: usize, addr: u32) -> bool {
        if thread_id < MAX_MONITORED_THREADS {
            let granule = addr & RESERVATION_MASK;
            if self.reservations[thread_id]
                .compare_exchange(granule, INVALID_RESERVATION, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                self.active_mask.fetch_and(!(1u64 << thread_id), Ordering::Release);
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Clears any reservation held by `thread_id` (e.g. CLREX or context switch)
    #[inline(always)]
    pub fn clear_thread(&self, thread_id: usize) {
        if thread_id < MAX_MONITORED_THREADS {
            self.reservations[thread_id].store(INVALID_RESERVATION, Ordering::Release);
            self.active_mask.fetch_and(!(1u64 << thread_id), Ordering::Release);
        }
    }

    /// Invalidates all active reservations across all threads that fall within the same 64-byte granule.
    /// Fast path: returns immediately if no threads currently have active reservations.
    #[inline(always)]
    pub fn clear_all(&self, addr: u32) {
        let mask = self.active_mask.load(Ordering::Acquire);
        if mask == 0 {
            return;
        }

        let granule = addr & RESERVATION_MASK;
        let mut bits = mask;
        while bits != 0 {
            let thread_id = bits.trailing_zeros() as usize;
            let bit = 1u64 << thread_id;
            bits &= !bit;

            if self.reservations[thread_id]
                .compare_exchange(granule, INVALID_RESERVATION, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                self.active_mask.fetch_and(!bit, Ordering::Release);
            }
        }
    }

    /// Resets all active reservations across all threads
    pub fn reset(&self) {
        for slot in &self.reservations {
            slot.store(INVALID_RESERVATION, Ordering::Release);
        }
        self.active_mask.store(0, Ordering::Release);
    }
}

impl Default for GlobalExclusiveMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exclusive_monitor_single_thread_granule() {
        let monitor = GlobalExclusiveMonitor::new();
        let tid = 0;

        // LDREX at 0x1004 (granule 0x1000)
        monitor.set_reservation(tid, 0x1004);

        // STREX at 0x1008 (same granule 0x1000) should succeed
        assert!(monitor.check_and_clear(tid, 0x1008));

        // Subsequent STREX should fail since reservation was consumed
        assert!(!monitor.check_and_clear(tid, 0x1008));
    }

    #[test]
    fn test_exclusive_monitor_multi_thread_invalidation() {
        let monitor = GlobalExclusiveMonitor::new();
        let thread0 = 0;
        let _thread1 = 1;

        // Thread 0 LDREX at 0x2004
        monitor.set_reservation(thread0, 0x2004);

        // Thread 1 writes to 0x2020 (same 64-byte granule: 0x2000..0x203F)
        monitor.clear_all(0x2020);

        // Thread 0's STREX must fail!
        assert!(!monitor.check_and_clear(thread0, 0x2004));
    }

    #[test]
    fn test_exclusive_monitor_different_granule_no_interference() {
        let monitor = GlobalExclusiveMonitor::new();
        let thread0 = 0;

        // Thread 0 LDREX at 0x3000
        monitor.set_reservation(thread0, 0x3000);

        // Thread 1 writes to 0x3040 (next 64-byte granule)
        monitor.clear_all(0x3040);

        // Thread 0's STREX must still succeed!
        assert!(monitor.check_and_clear(thread0, 0x3000));
    }

    #[test]
    fn test_exclusive_monitor_clrex() {
        let monitor = GlobalExclusiveMonitor::new();
        let tid = 2;

        monitor.set_reservation(tid, 0x4000);
        monitor.clear_thread(tid);
        assert!(!monitor.check_and_clear(tid, 0x4000));
    }
}
