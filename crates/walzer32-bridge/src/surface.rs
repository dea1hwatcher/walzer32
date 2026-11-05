use std::collections::VecDeque;
use walzer32_core::GuestAddr;

pub const GUEST_SURFACE_HANDLE: u32 = 0x3000_0001;

/// Touch input event forwarded from Android UI to 32-bit guest
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TouchEvent {
    pub action: u32,
    pub x: f32,
    pub y: f32,
    pub pointer_id: u32,
}

/// Key input event forwarded from Android UI to 32-bit guest
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    pub action: u32,
    pub key_code: u32,
}

/// Manages ANativeWindow lifecycle, viewport dimensions, and user input marshalling
#[derive(Debug, Default)]
pub struct SurfaceBridge {
    pub host_window_ptr: usize,
    pub guest_handle: u32,
    pub width: u32,
    pub height: u32,
    pub is_active: bool,
    pub draw_frame_fn: Option<GuestAddr>,
    pub touch_queue: VecDeque<TouchEvent>,
    pub key_queue: VecDeque<KeyEvent>,
}

impl SurfaceBridge {
    pub fn new() -> Self {
        Self::default()
    }

    /// Handles SurfaceCreated lifecycle event from Android Java SurfaceView
    pub fn on_surface_created(&mut self, host_window_ptr: usize, width: u32, height: u32) {
        self.host_window_ptr = host_window_ptr;
        self.guest_handle = GUEST_SURFACE_HANDLE;
        self.width = width;
        self.height = height;
        self.is_active = true;
    }

    /// Handles SurfaceChanged viewport dimension updates
    pub fn on_surface_changed(&mut self, width: u32, height: u32) {
        self.width = width;
        self.height = height;
    }

    /// Handles SurfaceDestroyed event when Activity pauses or surface is destroyed
    pub fn on_surface_destroyed(&mut self) {
        self.host_window_ptr = 0;
        self.is_active = false;
    }

    /// Register a 32-bit guest render / tick function
    pub fn register_draw_frame_fn(&mut self, addr: GuestAddr) {
        self.draw_frame_fn = Some(addr);
    }

    /// Pushes a touch event into the input queue (capacity limited to 256 events)
    pub fn push_touch_event(&mut self, event: TouchEvent) {
        if self.touch_queue.len() >= 256 {
            self.touch_queue.pop_front();
        }
        self.touch_queue.push_back(event);
    }

    /// Polls the next touch event for guest consumption
    pub fn pop_touch_event(&mut self) -> Option<TouchEvent> {
        self.touch_queue.pop_front()
    }

    /// Pushes a key event into the input queue
    pub fn push_key_event(&mut self, event: KeyEvent) {
        if self.key_queue.len() >= 256 {
            self.key_queue.pop_front();
        }
        self.key_queue.push_back(event);
    }

    /// Polls the next key event for guest consumption
    pub fn pop_key_event(&mut self) -> Option<KeyEvent> {
        self.key_queue.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_surface_bridge_lifecycle() {
        let mut bridge = SurfaceBridge::new();
        assert!(!bridge.is_active);

        // Created with mock host pointer
        bridge.on_surface_created(0xDEAD_BEEF_CAFE, 1920, 1080);
        assert!(bridge.is_active);
        assert_eq!(bridge.host_window_ptr, 0xDEAD_BEEF_CAFE);
        assert_eq!(bridge.guest_handle, GUEST_SURFACE_HANDLE);
        assert_eq!(bridge.width, 1920);
        assert_eq!(bridge.height, 1080);

        // Changed
        bridge.on_surface_changed(2560, 1440);
        assert_eq!(bridge.width, 2560);
        assert_eq!(bridge.height, 1440);

        // Destroyed
        bridge.on_surface_destroyed();
        assert!(!bridge.is_active);
        assert_eq!(bridge.host_window_ptr, 0);
    }

    #[test]
    fn test_surface_input_queues() {
        let mut bridge = SurfaceBridge::new();

        bridge.push_touch_event(TouchEvent {
            action: 0, // ACTION_DOWN
            x: 100.0,
            y: 200.0,
            pointer_id: 0,
        });

        let ev = bridge.pop_touch_event().unwrap();
        assert_eq!(ev.action, 0);
        assert_eq!(ev.x, 100.0);
        assert_eq!(ev.y, 200.0);
        assert!(bridge.pop_touch_event().is_none());

        bridge.push_key_event(KeyEvent {
            action: 0,
            key_code: 4, // KEYCODE_BACK
        });

        let key_ev = bridge.pop_key_event().unwrap();
        assert_eq!(key_ev.key_code, 4);
        assert!(bridge.pop_key_event().is_none());
    }
}
