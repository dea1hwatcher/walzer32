use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Single-Producer Single-Consumer (SPSC) Lock-Free Audio Ring Buffer.
/// Provides zero-allocation, wait-free PCM sample streaming between DBT emulation
/// thread and audio hardware callback thread.
pub struct AudioRingBuffer<T: Copy + Default> {
    buffer: Box<[UnsafeCell<T>]>,
    capacity: usize,
    mask: usize,
    head: AtomicUsize,
    tail: AtomicUsize,
    underrun_count: AtomicU64,
    overrun_count: AtomicU64,
}

unsafe impl<T: Copy + Default + Send> Send for AudioRingBuffer<T> {}
unsafe impl<T: Copy + Default + Sync> Sync for AudioRingBuffer<T> {}

impl<T: Copy + Default> AudioRingBuffer<T> {
    /// Creates a new lock-free ring buffer with capacity rounded up to power of two
    pub fn new(requested_capacity: usize) -> Self {
        let capacity = requested_capacity.max(2).next_power_of_two();
        let mask = capacity - 1;

        let mut vec = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            vec.push(UnsafeCell::new(T::default()));
        }

        Self {
            buffer: vec.into_boxed_slice(),
            capacity,
            mask,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            underrun_count: AtomicU64::new(0),
            overrun_count: AtomicU64::new(0),
        }
    }

    /// Pushes a slice of samples into the buffer.
    /// Returns the number of samples successfully written.
    pub fn push_slice(&self, data: &[T]) -> usize {
        if data.is_empty() {
            return 0;
        }

        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);

        let used = head.wrapping_sub(tail);
        let available = self.capacity.saturating_sub(used);
        let to_write = data.len().min(available);

        if to_write < data.len() {
            self.overrun_count.fetch_add(1, Ordering::Relaxed);
        }

        if to_write == 0 {
            return 0;
        }

        for (i, &item) in data[..to_write].iter().enumerate() {
            let idx = (head.wrapping_add(i)) & self.mask;
            unsafe {
                *self.buffer[idx].get() = item;
            }
        }

        self.head.store(head.wrapping_add(to_write), Ordering::Release);
        to_write
    }

    /// Pops samples into `out`.
    /// Returns the number of actual samples read.
    /// If fewer samples than requested are available, remaining output slots are filled with T::default() (silence).
    pub fn pop_slice(&self, out: &mut [T]) -> usize {
        if out.is_empty() {
            return 0;
        }

        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);

        let available = head.wrapping_sub(tail);
        let to_read = out.len().min(available);

        if to_read < out.len() {
            self.underrun_count.fetch_add(1, Ordering::Relaxed);
        }

        for (i, slot) in out[..to_read].iter_mut().enumerate() {
            let idx = (tail.wrapping_add(i)) & self.mask;
            unsafe {
                *slot = *self.buffer[idx].get();
            }
        }

        // Fill remaining with silence (default)
        for slot in out[to_read..].iter_mut() {
            *slot = T::default();
        }

        self.tail.store(tail.wrapping_add(to_read), Ordering::Release);
        to_read
    }

    /// Number of samples currently available to read
    #[inline]
    pub fn available_read(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail)
    }

    /// Number of free sample slots currently available to write
    #[inline]
    pub fn available_write(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        self.capacity.saturating_sub(head.wrapping_sub(tail))
    }

    /// Total capacity of the ring buffer in samples
    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Resets the ring buffer pointers
    pub fn clear(&self) {
        let tail = self.tail.load(Ordering::Relaxed);
        self.head.store(tail, Ordering::Release);
    }

    /// Total number of buffer underruns encountered
    #[inline]
    pub fn underrun_count(&self) -> u64 {
        self.underrun_count.load(Ordering::Relaxed)
    }

    /// Total number of buffer overruns encountered
    #[inline]
    pub fn overrun_count(&self) -> u64 {
        self.overrun_count.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_ring_buffer_basic_push_pop() {
        let ring = AudioRingBuffer::<i16>::new(16);
        assert_eq!(ring.capacity(), 16);
        assert_eq!(ring.available_read(), 0);
        assert_eq!(ring.available_write(), 16);

        let input = [10i16, 20, 30, 40, 50];
        let written = ring.push_slice(&input);
        assert_eq!(written, 5);
        assert_eq!(ring.available_read(), 5);

        let mut output = [0i16; 5];
        let read = ring.pop_slice(&mut output);
        assert_eq!(read, 5);
        assert_eq!(output, input);
        assert_eq!(ring.available_read(), 0);
    }

    #[test]
    fn test_ring_buffer_underrun_silence_fill() {
        let ring = AudioRingBuffer::<i16>::new(16);
        let input = [100i16, 200];
        ring.push_slice(&input);

        let mut output = [0i16; 4];
        let read = ring.pop_slice(&mut output);
        assert_eq!(read, 2);
        assert_eq!(output[0], 100);
        assert_eq!(output[1], 200);
        assert_eq!(output[2], 0); // Silence fill
        assert_eq!(output[3], 0); // Silence fill
        assert_eq!(ring.underrun_count(), 1);
    }

    #[test]
    fn test_ring_buffer_concurrent_spsc() {
        let ring = Arc::new(AudioRingBuffer::<i16>::new(1024));
        let count = 50_000;

        let producer_ring = Arc::clone(&ring);
        let producer = thread::spawn(move || {
            let mut chunk = [0i16; 64];
            let mut val: i16 = 0;
            let mut sent = 0;
            while sent < count {
                for item in chunk.iter_mut() {
                    *item = val;
                    val = val.wrapping_add(1);
                }
                let mut offset = 0;
                while offset < chunk.len() {
                    let written = producer_ring.push_slice(&chunk[offset..]);
                    offset += written;
                    if written == 0 {
                        thread::yield_now();
                    }
                }
                sent += chunk.len();
            }
        });

        let consumer_ring = Arc::clone(&ring);
        let consumer = thread::spawn(move || {
            let mut chunk = [0i16; 64];
            let mut expected: i16 = 0;
            let mut received = 0;
            while received < count {
                let read = consumer_ring.pop_slice(&mut chunk);
                for &val in &chunk[..read] {
                    assert_eq!(val, expected);
                    expected = expected.wrapping_add(1);
                }
                received += read;
                if read == 0 {
                    thread::yield_now();
                }
            }
        });

        producer.join().unwrap();
        consumer.join().unwrap();
    }
}
