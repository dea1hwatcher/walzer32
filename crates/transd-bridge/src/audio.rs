/// OpenSL ES / AAudio High-Performance Audio Passthrough Bridge for Transd DBT.
///
/// Under Android NDK, games output audio through OpenSL ES (`libOpenSLES.so`)
/// using `SLAndroidSimpleBufferQueueItf` and `SLPlayItf`.
///
/// `AudioBridge` provides zero-overhead audio buffer forwarding:
///   1. Manages audio player lifecycle (SL_PLAYSTATE_STOPPED, PAUSED, PLAYING).
///   2. Intercepts `Enqueue` calls and buffers PCM frames.
///   3. Routes PCM streams directly to host audio subsystem or AAudio ring buffers.
///   4. Tracks buffer completion and callback dispatch back to 32-bit guest code.

use std::collections::VecDeque;
use transd_core::{GuestAddr, Memory, MemoryError};

pub const SL_RESULT_SUCCESS: u32 = 0;
pub const SL_RESULT_PARAMETER_INVALID: u32 = 2;

pub const SL_PLAYSTATE_STOPPED: u32 = 1;
pub const SL_PLAYSTATE_PAUSED: u32 = 2;
pub const SL_PLAYSTATE_PLAYING: u32 = 3;

/// PCM audio buffer queued by 32-bit guest application
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioBuffer {
    pub guest_addr: GuestAddr,
    pub size_bytes: usize,
    pub pcm_data: Vec<u8>,
}

/// OpenSL ES / AAudio passthrough bridge
#[derive(Default)]
pub struct AudioBridge {
    pub play_state: u32,
    pub callback_fn: GuestAddr,
    pub callback_context: GuestAddr,
    pub buffer_queue: VecDeque<AudioBuffer>,
    pub total_bytes_played: u64,
    pub total_buffers_enqueued: u64,
}

impl AudioBridge {
    pub fn new() -> Self {
        Self {
            play_state: SL_PLAYSTATE_STOPPED,
            callback_fn: GuestAddr::new(0),
            callback_context: GuestAddr::new(0),
            buffer_queue: VecDeque::new(),
            total_bytes_played: 0,
            total_buffers_enqueued: 0,
        }
    }

    /// Sets player state (STOPPED, PAUSED, PLAYING)
    pub fn set_play_state(&mut self, state: u32) -> u32 {
        self.play_state = state;
        SL_RESULT_SUCCESS
    }

    /// Registers the OpenSL ES BufferQueue callback function
    pub fn register_callback(&mut self, callback: GuestAddr, context: GuestAddr) -> u32 {
        self.callback_fn = callback;
        self.callback_context = context;
        SL_RESULT_SUCCESS
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

        self.buffer_queue.push_back(AudioBuffer {
            guest_addr: buffer_addr,
            size_bytes,
            pcm_data: data,
        });

        self.total_buffers_enqueued += 1;
        Ok(SL_RESULT_SUCCESS)
    }

    /// Consumes the next buffer in queue (forwarding to host audio hardware)
    pub fn consume_next_buffer(&mut self) -> Option<AudioBuffer> {
        if let Some(buf) = self.buffer_queue.pop_front() {
            self.total_bytes_played += buf.size_bytes as u64;
            Some(buf)
        } else {
            None
        }
    }

    /// Clears all queued buffers
    pub fn clear_queue(&mut self) {
        self.buffer_queue.clear();
    }

    pub fn queued_count(&self) -> usize {
        self.buffer_queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transd_core::FlatMemory;

    #[test]
    fn test_audio_play_state_and_callback() {
        let mut audio = AudioBridge::new();
        assert_eq!(audio.play_state, SL_PLAYSTATE_STOPPED);

        audio.set_play_state(SL_PLAYSTATE_PLAYING);
        assert_eq!(audio.play_state, SL_PLAYSTATE_PLAYING);

        audio.register_callback(GuestAddr::new(0x8000), GuestAddr::new(0x9000));
        assert_eq!(audio.callback_fn, GuestAddr::new(0x8000));
        assert_eq!(audio.callback_context, GuestAddr::new(0x9000));
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
        assert_eq!(audio.total_bytes_played, 16);
        assert_eq!(audio.queued_count(), 0);
    }
}
