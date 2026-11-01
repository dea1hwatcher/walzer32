use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Cache line padded wrapper to eliminate false sharing between producer and consumer threads.
#[repr(align(64))]
#[derive(Debug)]
pub struct CachePadded<T>(pub T);

impl<T> std::ops::Deref for CachePadded<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for CachePadded<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Single-Producer Single-Consumer (SPSC) Lock-Free Audio Ring Buffer.
/// Provides zero-allocation, wait-free PCM sample streaming between DBT emulation
/// thread and audio hardware callback thread.
pub struct AudioRingBuffer<T: Copy + Default> {
    buffer: Box<[UnsafeCell<T>]>,
    capacity: usize,
    mask: usize,
    head: CachePadded<AtomicUsize>,
    tail: CachePadded<AtomicUsize>,
    underrun_count: AtomicU64,
    overrun_count: AtomicU64,
    last_sample: CachePadded<UnsafeCell<T>>,
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
            head: CachePadded(AtomicUsize::new(0)),
            tail: CachePadded(AtomicUsize::new(0)),
            underrun_count: AtomicU64::new(0),
            overrun_count: AtomicU64::new(0),
            last_sample: CachePadded(UnsafeCell::new(T::default())),
        }
    }

    /// Pushes a slice of samples into the buffer via contiguous block copying.
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

        let start_idx = head & self.mask;
        let chunk1_len = (self.capacity - start_idx).min(to_write);
        let chunk2_len = to_write - chunk1_len;

        unsafe {
            let buf_ptr = self.buffer.as_ptr() as *mut T;
            let src_ptr = data.as_ptr();

            // First contiguous block: start_idx .. start_idx + chunk1_len
            std::ptr::copy_nonoverlapping(src_ptr, buf_ptr.add(start_idx), chunk1_len);

            // Second contiguous block (wrapped around to ring index 0)
            if chunk2_len > 0 {
                std::ptr::copy_nonoverlapping(src_ptr.add(chunk1_len), buf_ptr, chunk2_len);
            }
        }

        self.head.store(head.wrapping_add(to_write), Ordering::Release);
        to_write
    }

    /// Pops samples into `out` via contiguous block copying.
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

        if to_read > 0 {
            let start_idx = tail & self.mask;
            let chunk1_len = (self.capacity - start_idx).min(to_read);
            let chunk2_len = to_read - chunk1_len;

            unsafe {
                let buf_ptr = self.buffer.as_ptr() as *const T;
                let dst_ptr = out.as_mut_ptr();

                std::ptr::copy_nonoverlapping(buf_ptr.add(start_idx), dst_ptr, chunk1_len);
                if chunk2_len > 0 {
                    std::ptr::copy_nonoverlapping(buf_ptr, dst_ptr.add(chunk1_len), chunk2_len);
                }

                *self.last_sample.get() = *dst_ptr.add(to_read - 1);
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

    /// Ratio of ring buffer capacity currently occupied [0.0 .. 1.0]
    #[inline]
    pub fn watermark_fill_ratio(&self) -> f32 {
        self.available_read() as f32 / self.capacity as f32
    }

    /// Latency of currently queued audio in milliseconds
    #[inline]
    pub fn latency_ms(&self, sample_rate_hz: u32, channels: u16) -> f32 {
        if sample_rate_hz == 0 || channels == 0 {
            return 0.0;
        }
        let frames = self.available_read() / (channels as usize);
        (frames as f32 * 1000.0) / (sample_rate_hz as f32)
    }
}

impl AudioRingBuffer<i16> {
    /// Pops samples into `out` with linear ramp-down underrun concealment (PLC).
    /// Suppresses audible DC click / pop artifacts when buffer underrun occurs.
    pub fn pop_slice_with_concealment(&self, out: &mut [i16]) -> usize {
        if out.is_empty() {
            return 0;
        }

        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);

        let available = head.wrapping_sub(tail);
        let to_read = out.len().min(available);

        if to_read > 0 {
            let start_idx = tail & self.mask;
            let chunk1_len = (self.capacity - start_idx).min(to_read);
            let chunk2_len = to_read - chunk1_len;

            unsafe {
                let buf_ptr = self.buffer.as_ptr() as *const i16;
                let dst_ptr = out.as_mut_ptr();

                std::ptr::copy_nonoverlapping(buf_ptr.add(start_idx), dst_ptr, chunk1_len);
                if chunk2_len > 0 {
                    std::ptr::copy_nonoverlapping(buf_ptr, dst_ptr.add(chunk1_len), chunk2_len);
                }

                *self.last_sample.get() = *dst_ptr.add(to_read - 1);
            }
        }

        // Apply smooth attenuation decay (fade-out concealment) on underrun
        if to_read < out.len() {
            self.underrun_count.fetch_add(1, Ordering::Relaxed);

            let last_val = unsafe { *self.last_sample.get() as f32 };
            let missing = out.len() - to_read;
            let fade_len = missing.min(32);

            for i in 0..fade_len {
                let factor = 1.0 - ((i + 1) as f32 / (fade_len as f32));
                out[to_read + i] = (last_val * factor) as i16;
            }
            for slot in out[to_read + fade_len..].iter_mut() {
                *slot = 0;
            }

            unsafe {
                *self.last_sample.get() = 0;
            }
        }

        self.tail.store(tail.wrapping_add(to_read), Ordering::Release);
        to_read
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
    fn test_ring_buffer_wrap_around_block_copy() {
        let ring = AudioRingBuffer::<i16>::new(8);
        // Push 6, pop 4 -> head at 6, tail at 4
        let in1 = [1i16, 2, 3, 4, 5, 6];
        assert_eq!(ring.push_slice(&in1), 6);
        let mut out1 = [0i16; 4];
        assert_eq!(ring.pop_slice(&mut out1), 4);
        assert_eq!(out1, [1, 2, 3, 4]);

        // Now available to write = 6. Let's push 5 elements: indices 6, 7 wrap around to 0, 1, 2
        let in2 = [10i16, 20, 30, 40, 50];
        assert_eq!(ring.push_slice(&in2), 5);

        // Pop all remaining (7 elements)
        let mut out2 = [0i16; 7];
        assert_eq!(ring.pop_slice(&mut out2), 7);
        assert_eq!(out2, [5, 6, 10, 20, 30, 40, 50]);
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
    fn test_ring_buffer_underrun_concealment_fade() {
        let ring = AudioRingBuffer::<i16>::new(16);
        let input = [1000i16, 2000];
        ring.push_slice(&input);

        let mut output = [0i16; 10];
        let read = ring.pop_slice_with_concealment(&mut output);
        assert_eq!(read, 2);
        assert_eq!(output[0], 1000);
        assert_eq!(output[1], 2000);
        // Concealment ramp down: values after 2000 must decrease towards 0
        assert!(output[2] > 0 && output[2] < 2000);
        assert!(output[3] > 0 && output[3] < output[2]);
        assert_eq!(ring.underrun_count(), 1);
    }

    #[test]
    fn test_ring_buffer_watermark_and_latency() {
        let ring = AudioRingBuffer::<i16>::new(1024);
        let samples = vec![100i16; 480]; // 240 frames of stereo audio
        ring.push_slice(&samples);

        assert_eq!(ring.available_read(), 480);
        // At 48,000 Hz stereo, 240 frames is 5.0 milliseconds
        let latency = ring.latency_ms(48000, 2);
        assert!((latency - 5.0).abs() < 0.01);
        assert!((ring.watermark_fill_ratio() - (480.0 / 1024.0)).abs() < 0.01);
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
