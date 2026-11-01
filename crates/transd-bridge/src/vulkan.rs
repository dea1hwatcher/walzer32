/// Vulkan 1.0/1.1/1.2 Passthrough Bridge for Transd DBT.
///
/// Handles structural impedance matching between 32-bit ARM guest and 64-bit host:
///   1. 32-bit Vulkan structures have 4-byte pointer alignment and 4-byte pointers.
///   2. 64-bit Vulkan structures have 8-byte pointer alignment and 8-byte pointers.
///   3. Dispatchable and non-dispatchable Vulkan handles (VkInstance, VkDevice, etc.)
///      are 64-bit on host; Transd maintains a bidirectional 32-bit handle map.

use std::collections::HashMap;
use transd_core::{GuestAddr, Memory, MemoryError};

pub const VK_SUCCESS: i32 = 0;
pub const VK_NOT_READY: i32 = 1;
pub const VK_TIMEOUT: i32 = 2;
pub const VK_ERROR_OUT_OF_HOST_MEMORY: i32 = -1;
pub const VK_ERROR_INITIALIZATION_FAILED: i32 = -3;
pub const VK_ERROR_DEVICE_LOST: i32 = -4;

// Vulkan Structure Types (sTypes)
pub const VK_STRUCTURE_TYPE_APPLICATION_INFO: u32 = 0;
pub const VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO: u32 = 1;
pub const VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO: u32 = 2;
pub const VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO: u32 = 3;
pub const VK_STRUCTURE_TYPE_SUBMIT_INFO: u32 = 4;

/// 32-bit Guest Representation of VkApplicationInfo (28 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VkApplicationInfo32 {
    pub s_type: u32,
    pub p_next: GuestAddr,
    pub p_application_name: GuestAddr,
    pub application_version: u32,
    pub p_engine_name: GuestAddr,
    pub engine_version: u32,
    pub api_version: u32,
}

impl VkApplicationInfo32 {
    pub fn read(mem: &impl Memory, addr: GuestAddr) -> Result<Self, MemoryError> {
        Ok(Self {
            s_type: mem.read_u32(addr)?,
            p_next: GuestAddr::new(mem.read_u32(addr.add(4))?),
            p_application_name: GuestAddr::new(mem.read_u32(addr.add(8))?),
            application_version: mem.read_u32(addr.add(12))?,
            p_engine_name: GuestAddr::new(mem.read_u32(addr.add(16))?),
            engine_version: mem.read_u32(addr.add(20))?,
            api_version: mem.read_u32(addr.add(24))?,
        })
    }
}

/// 32-bit Guest Representation of VkInstanceCreateInfo (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VkInstanceCreateInfo32 {
    pub s_type: u32,
    pub p_next: GuestAddr,
    pub flags: u32,
    pub p_application_info: GuestAddr,
    pub enabled_layer_count: u32,
    pub pp_enabled_layer_names: GuestAddr,
    pub enabled_extension_count: u32,
    pub pp_enabled_extension_names: GuestAddr,
}

impl VkInstanceCreateInfo32 {
    pub fn read(mem: &impl Memory, addr: GuestAddr) -> Result<Self, MemoryError> {
        Ok(Self {
            s_type: mem.read_u32(addr)?,
            p_next: GuestAddr::new(mem.read_u32(addr.add(4))?),
            flags: mem.read_u32(addr.add(8))?,
            p_application_info: GuestAddr::new(mem.read_u32(addr.add(12))?),
            enabled_layer_count: mem.read_u32(addr.add(16))?,
            pp_enabled_layer_names: GuestAddr::new(mem.read_u32(addr.add(20))?),
            enabled_extension_count: mem.read_u32(addr.add(24))?,
            pp_enabled_extension_names: GuestAddr::new(mem.read_u32(addr.add(28))?),
        })
    }
}

/// 32-bit Guest Representation of VkDeviceCreateInfo (40 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VkDeviceCreateInfo32 {
    pub s_type: u32,
    pub p_next: GuestAddr,
    pub flags: u32,
    pub queue_create_info_count: u32,
    pub p_queue_create_infos: GuestAddr,
    pub enabled_layer_count: u32,
    pub pp_enabled_layer_names: GuestAddr,
    pub enabled_extension_count: u32,
    pub pp_enabled_extension_names: GuestAddr,
    pub p_enabled_features: GuestAddr,
}

impl VkDeviceCreateInfo32 {
    pub fn read(mem: &impl Memory, addr: GuestAddr) -> Result<Self, MemoryError> {
        Ok(Self {
            s_type: mem.read_u32(addr)?,
            p_next: GuestAddr::new(mem.read_u32(addr.add(4))?),
            flags: mem.read_u32(addr.add(8))?,
            queue_create_info_count: mem.read_u32(addr.add(12))?,
            p_queue_create_infos: GuestAddr::new(mem.read_u32(addr.add(16))?),
            enabled_layer_count: mem.read_u32(addr.add(20))?,
            pp_enabled_layer_names: GuestAddr::new(mem.read_u32(addr.add(24))?),
            enabled_extension_count: mem.read_u32(addr.add(28))?,
            pp_enabled_extension_names: GuestAddr::new(mem.read_u32(addr.add(32))?),
            p_enabled_features: GuestAddr::new(mem.read_u32(addr.add(36))?),
        })
    }
}

/// 32-bit Guest Representation of VkSubmitInfo (36 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VkSubmitInfo32 {
    pub s_type: u32,
    pub p_next: GuestAddr,
    pub wait_semaphore_count: u32,
    pub p_wait_semaphores: GuestAddr,
    pub p_wait_dst_stage_mask: GuestAddr,
    pub command_buffer_count: u32,
    pub p_command_buffers: GuestAddr,
    pub signal_semaphore_count: u32,
    pub p_signal_semaphores: GuestAddr,
}

impl VkSubmitInfo32 {
    pub fn read(mem: &impl Memory, addr: GuestAddr) -> Result<Self, MemoryError> {
        Ok(Self {
            s_type: mem.read_u32(addr)?,
            p_next: GuestAddr::new(mem.read_u32(addr.add(4))?),
            wait_semaphore_count: mem.read_u32(addr.add(8))?,
            p_wait_semaphores: GuestAddr::new(mem.read_u32(addr.add(12))?),
            p_wait_dst_stage_mask: GuestAddr::new(mem.read_u32(addr.add(16))?),
            command_buffer_count: mem.read_u32(addr.add(20))?,
            p_command_buffers: GuestAddr::new(mem.read_u32(addr.add(24))?),
            signal_semaphore_count: mem.read_u32(addr.add(28))?,
            p_signal_semaphores: GuestAddr::new(mem.read_u32(addr.add(32))?),
        })
    }
}

/// Vulkan Passthrough Bridge managing 32-bit <-> 64-bit handle translation and forwarding
#[derive(Default)]
pub struct VulkanBridge {
    next_handle32: u32,
    /// 32-bit guest handle -> 64-bit host handle
    handle_map_32_to_64: HashMap<u32, u64>,
    /// 64-bit host handle -> 32-bit guest handle
    handle_map_64_to_32: HashMap<u64, u32>,
    /// Tracked draw and submit calls for verification and telemetry
    pub submit_count: u64,
    pub draw_count: u64,
}

impl VulkanBridge {
    pub fn new() -> Self {
        Self {
            next_handle32: 100,
            handle_map_32_to_64: HashMap::new(),
            handle_map_64_to_32: HashMap::new(),
            submit_count: 0,
            draw_count: 0,
        }
    }

    /// Registers a 64-bit host handle and returns a 32-bit handle safe for guest memory
    pub fn register_host_handle(&mut self, host_handle: u64) -> u32 {
        if let Some(&handle32) = self.handle_map_64_to_32.get(&host_handle) {
            return handle32;
        }
        let handle32 = self.next_handle32;
        self.next_handle32 += 1;
        self.handle_map_32_to_64.insert(handle32, host_handle);
        self.handle_map_64_to_32.insert(host_handle, handle32);
        handle32
    }

    /// Resolves a 32-bit guest handle back to the host 64-bit Vulkan handle
    pub fn resolve_guest_handle(&self, handle32: u32) -> Option<u64> {
        self.handle_map_32_to_64.get(&handle32).copied()
    }

    /// Intercepts vkCreateInstance from guest 32-bit ARM code
    pub fn vk_create_instance(
        &mut self,
        mem: &mut impl Memory,
        p_create_info: GuestAddr,
        p_instance: GuestAddr,
    ) -> Result<i32, MemoryError> {
        let create_info = VkInstanceCreateInfo32::read(mem, p_create_info)?;
        if create_info.s_type != VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO {
            return Ok(VK_ERROR_INITIALIZATION_FAILED);
        }

        // On real Android host, this would call host libvulkan.so vkCreateInstance
        // Mock a 64-bit host instance pointer
        let mock_host_instance: u64 = 0x7FFF_8000_1000;
        let handle32 = self.register_host_handle(mock_host_instance);

        // Write 32-bit handle into guest pointer
        mem.write_u32(p_instance, handle32)?;
        Ok(VK_SUCCESS)
    }

    /// Intercepts vkQueueSubmit from guest 32-bit ARM code
    pub fn vk_queue_submit(
        &mut self,
        mem: &impl Memory,
        queue_handle32: u32,
        submit_count: u32,
        p_submits: GuestAddr,
    ) -> Result<i32, MemoryError> {
        if self.resolve_guest_handle(queue_handle32).is_none() {
            return Ok(VK_ERROR_DEVICE_LOST);
        }

        for i in 0..submit_count {
            let submit_addr = p_submits.add(i * 36);
            let submit = VkSubmitInfo32::read(mem, submit_addr)?;
            if submit.s_type != VK_STRUCTURE_TYPE_SUBMIT_INFO {
                return Ok(VK_ERROR_INITIALIZATION_FAILED);
            }
            self.submit_count += 1;
        }

        Ok(VK_SUCCESS)
    }

    /// Intercepts vkCmdDraw
    pub fn vk_cmd_draw(
        &mut self,
        _cmd_buf_handle32: u32,
        _vertex_count: u32,
        _instance_count: u32,
        _first_vertex: u32,
        _first_instance: u32,
    ) {
        self.draw_count += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transd_core::FlatMemory;

    #[test]
    fn test_vulkan_handle_translation() {
        let mut bridge = VulkanBridge::new();
        let host_handle = 0xDEAD_BEEF_CAFE_BABE_u64;
        let handle32 = bridge.register_host_handle(host_handle);

        assert_eq!(bridge.resolve_guest_handle(handle32), Some(host_handle));
        // Idempotent
        assert_eq!(bridge.register_host_handle(host_handle), handle32);
    }

    #[test]
    fn test_vulkan_create_instance_passthrough() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);
        let mut bridge = VulkanBridge::new();

        // Setup VkInstanceCreateInfo32 at 0x1100
        let p_create_info = GuestAddr::new(0x1100);
        mem.write_u32(p_create_info, VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO).unwrap();
        mem.write_u32(p_create_info.add(4), 0).unwrap(); // pNext = NULL
        mem.write_u32(p_create_info.add(8), 0).unwrap(); // flags = 0
        mem.write_u32(p_create_info.add(12), 0).unwrap(); // pApplicationInfo = NULL
        mem.write_u32(p_create_info.add(16), 0).unwrap(); // enabledLayerCount = 0
        mem.write_u32(p_create_info.add(20), 0).unwrap();
        mem.write_u32(p_create_info.add(24), 0).unwrap();
        mem.write_u32(p_create_info.add(28), 0).unwrap();

        let p_instance = GuestAddr::new(0x1500);
        let res = bridge.vk_create_instance(&mut mem, p_create_info, p_instance).unwrap();
        assert_eq!(res, VK_SUCCESS);

        let created_handle32 = mem.read_u32(p_instance).unwrap();
        assert!(created_handle32 >= 100);
        assert!(bridge.resolve_guest_handle(created_handle32).is_some());
    }

    #[test]
    fn test_vulkan_queue_submit() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x2000);
        let mut bridge = VulkanBridge::new();

        let queue32 = bridge.register_host_handle(0x1234_5678_u64);

        // Setup VkSubmitInfo32 at 0x1200
        let p_submit = GuestAddr::new(0x1200);
        mem.write_u32(p_submit, VK_STRUCTURE_TYPE_SUBMIT_INFO).unwrap();
        mem.write_u32(p_submit.add(4), 0).unwrap();
        mem.write_u32(p_submit.add(8), 0).unwrap(); // waitSemaphoreCount = 0
        mem.write_u32(p_submit.add(12), 0).unwrap();
        mem.write_u32(p_submit.add(16), 0).unwrap();
        mem.write_u32(p_submit.add(20), 1).unwrap(); // cmdBufferCount = 1
        mem.write_u32(p_submit.add(24), 0x1300).unwrap();
        mem.write_u32(p_submit.add(28), 0).unwrap();
        mem.write_u32(p_submit.add(32), 0).unwrap();

        let res = bridge.vk_queue_submit(&mem, queue32, 1, p_submit).unwrap();
        assert_eq!(res, VK_SUCCESS);
        assert_eq!(bridge.submit_count, 1);
    }
}
